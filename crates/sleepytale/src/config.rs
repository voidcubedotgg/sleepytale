use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// `HytaleServer.DEFAULT_PORT`.
const DEFAULT_PORT: u16 = 5520;
const MAX_SERVER_NAME: usize = 253;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Address players connect to. The proxy owns this port in every state.
    ///
    /// An unspecified IPv6 address serves IPv4 clients too, which matches the server's own
    /// pair of channels. A v4-only bind costs every client that resolves the hostname to
    /// IPv6 first a full handshake timeout before it retries over IPv4.
    pub listen: SocketAddr,

    /// Address the backend binds. Must differ from `listen`, and should stay on
    /// loopback — relayed traffic arrives from the proxy, so exposing it publicly
    /// would let players bypass the proxy entirely.
    pub backend: SocketAddr,

    pub server: ServerConfig,

    /// Backends keyed by the name in a client's QUIC ClientHello. Each route is a full
    /// backend configuration, so it uses the same infrastructure adapter lifecycle as
    /// the default server. Unknown or unreadable names use `backend` and `server`.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub routes: BTreeMap<String, BackendConfig>,

    /// Shut the backend down after this long with no active sessions.
    #[serde(with = "humantime_secs")]
    pub idle_timeout: Duration,

    /// Give up waking the backend if it has not logged its boot line by then.
    #[serde(with = "humantime_secs")]
    pub boot_timeout: Duration,

    /// Drop a relay session after this long without a datagram.
    ///
    /// Must exceed the server's own `maxIdleTimeout` (its configured play timeout) or
    /// the proxy will reap connections that are merely quiet, and undercount players.
    #[serde(with = "humantime_secs")]
    pub session_timeout: Duration,

    /// How long the backend gets to exit on SIGTERM before it is killed.
    #[serde(with = "humantime_secs")]
    pub shutdown_grace: Duration,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendProvider {
    /// Run the server as a local child process.
    #[default]
    Process,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ServerConfig {
    /// Infrastructure provider that runs the backend.
    pub provider: BackendProvider,

    /// Program to run, usually `java`.
    pub command: String,

    /// Arguments before the proxy appends `-b <backend>`.
    pub args: Vec<String>,

    /// Working directory for the child process.
    pub working_dir: PathBuf,

    /// Forward this proxy's standard input to the server console.
    pub forward_stdin: bool,
}

/// One private server endpoint and the adapter that manages it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendConfig {
    pub backend: SocketAddr,
    #[serde(flatten)]
    pub server: ServerConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, DEFAULT_PORT)),
            backend: SocketAddr::from(([127, 0, 0, 1], DEFAULT_PORT + 1)),
            server: ServerConfig::default(),
            routes: BTreeMap::new(),
            idle_timeout: Duration::from_secs(900),
            boot_timeout: Duration::from_secs(300),
            session_timeout: Duration::from_secs(90),
            shutdown_grace: Duration::from_secs(10),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            provider: BackendProvider::Process,
            command: "java".to_string(),
            args: vec!["-jar".to_string(), "HytaleServer.jar".to_string()],
            working_dir: PathBuf::from("."),
            forward_stdin: true,
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let config: Config =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.listen != self.backend,
            "listen and backend must differ; the proxy and the server cannot share {}",
            self.listen
        );
        anyhow::ensure!(
            self.listen.port() != 0,
            "listen port must be fixed, not 0 — players need a stable port to reconnect to"
        );
        anyhow::ensure!(
            !self.server.command.is_empty(),
            "server.command must not be empty"
        );
        let mut names = BTreeMap::new();
        let mut backends = BTreeMap::new();
        backends.insert(self.backend, "default backend".to_string());
        for (name, route) in &self.routes {
            anyhow::ensure!(
                (1..=MAX_SERVER_NAME).contains(&name.len()),
                "route names must be 1 to {MAX_SERVER_NAME} characters; {name:?} is {}",
                name.len()
            );
            anyhow::ensure!(
                route.backend != self.listen,
                "route {name:?} points at {}, which is the proxy's own listen address",
                self.listen
            );
            if let Some(other) = names.insert(normalize(name), name) {
                anyhow::bail!("routes {other:?} and {name:?} are the same server name");
            }
            if let Some(other) = backends.insert(route.backend, format!("route {name:?}")) {
                anyhow::bail!(
                    "{other} and route {name:?} use the same backend address {}",
                    route.backend
                );
            }
            anyhow::ensure!(
                !route.server.command.is_empty(),
                "route {name:?}.command must not be empty"
            );
        }
        Ok(())
    }

    pub fn default_backend(&self) -> BackendConfig {
        BackendConfig {
            backend: self.backend,
            server: self.server.clone(),
        }
    }

    pub fn routes(&self) -> Routes {
        Routes {
            default: self.default_backend(),
            table: self
                .routes
                .iter()
                .map(|(name, backend)| (normalize(name), backend.clone()))
                .collect(),
        }
    }
}

impl BackendConfig {
    /// Full arguments for this server, with its private bind address appended.
    pub fn server_args(&self) -> Vec<String> {
        let mut args = self.server.args.clone();
        args.push("-b".to_string());
        args.push(self.backend.to_string());
        args
    }
}

/// Resolves the name in a ClientHello to a backend adapter configuration.
#[derive(Debug, Clone)]
pub struct Routes {
    default: BackendConfig,
    table: BTreeMap<String, BackendConfig>,
}

impl Routes {
    pub fn resolve(&self, server_name: Option<&str>) -> BackendConfig {
        server_name
            .map(normalize)
            .and_then(|name| self.table.get(&name).cloned())
            .unwrap_or_else(|| self.default.clone())
    }

    pub fn all(&self) -> impl Iterator<Item = BackendConfig> + '_ {
        std::iter::once(&self.default)
            .chain(self.table.values())
            .cloned()
    }
}

fn normalize(name: &str) -> String {
    name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase()
}

/// Durations as plain seconds — a proxy config has no need for a duration grammar.
mod humantime_secs {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(value: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(value.as_secs())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        Ok(Duration::from_secs(u64::deserialize(d)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid_and_do_not_collide() {
        let config = Config::default();
        config.validate().unwrap();
        assert_eq!(config.listen.port(), DEFAULT_PORT);
        assert_ne!(config.listen.port(), config.backend.port());
    }

    #[test]
    fn bind_override_is_appended_to_server_args() {
        let config = Config::default();
        let args = config.default_backend().server_args();
        assert_eq!(&args[args.len() - 2..], &["-b", "127.0.0.1:5521"]);
    }

    #[test]
    fn rejects_a_backend_sharing_the_public_port() {
        let mut config = Config::default();
        config.backend = config.listen;
        assert!(config.validate().is_err());
    }

    #[test]
    fn round_trips_through_toml() {
        let config = Config::default();
        let text = toml::to_string(&config).unwrap();
        let parsed: Config = toml::from_str(&text).unwrap();
        assert_eq!(parsed.idle_timeout, config.idle_timeout);
        assert_eq!(parsed.listen, config.listen);
        assert_eq!(parsed.server.command, config.server.command);
        assert_eq!(parsed.server.provider, BackendProvider::Process);
    }

    #[test]
    fn provider_defaults_to_process() {
        let config: Config = toml::from_str("listen = \"0.0.0.0:5520\"\n").unwrap();
        assert_eq!(config.server.provider, BackendProvider::Process);
    }

    #[test]
    fn routes_resolve_names_and_keep_complete_backend_configuration() {
        let mut config = Config::default();
        config.routes.insert(
            "Play.Hytale.com.".into(),
            BackendConfig {
                backend: "127.0.0.1:5531".parse().unwrap(),
                server: ServerConfig {
                    command: "creative-server".into(),
                    ..ServerConfig::default()
                },
            },
        );
        config.validate().unwrap();
        let routes = config.routes();
        let route = routes.resolve(Some("play.hytale.com"));
        assert_eq!(route.backend, "127.0.0.1:5531".parse().unwrap());
        assert_eq!(route.server.command, "creative-server");
        assert_eq!(routes.resolve(None).backend, config.backend);
    }

    #[test]
    fn route_toml_uses_the_same_adapter_fields_as_the_default_backend() {
        let config: Config = toml::from_str(
            r#"
                [routes."creative.example.com"]
                backend = "127.0.0.1:5531"
                command = "java"
                args = ["-jar", "CreativeServer.jar"]
                working_dir = "./creative"
                forward_stdin = false
            "#,
        )
        .unwrap();
        config.validate().unwrap();
        assert_eq!(
            config
                .routes()
                .resolve(Some("creative.example.com"))
                .backend,
            "127.0.0.1:5531".parse().unwrap()
        );
    }

    #[test]
    fn unknown_keys_are_rejected_rather_than_silently_ignored() {
        let text = "listen = \"0.0.0.0:5520\"\nnonsense = true\n";
        assert!(toml::from_str::<Config>(text).is_err());
    }
}
