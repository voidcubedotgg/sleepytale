use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// `HytaleServer.DEFAULT_PORT`.
const DEFAULT_PORT: u16 = 5520;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ServerConfig {
    /// Program to run, usually `java`.
    pub command: String,

    /// Arguments before the proxy appends `-b <backend>`.
    pub args: Vec<String>,

    /// Working directory for the child process.
    pub working_dir: PathBuf,

    /// Forward this proxy's standard input to the server console.
    pub forward_stdin: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, DEFAULT_PORT)),
            backend: SocketAddr::from(([127, 0, 0, 1], DEFAULT_PORT + 1)),
            server: ServerConfig::default(),
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
        Ok(())
    }

    /// Full argument list for the child, with the bind override appended so the backend
    /// cannot contend with the proxy for the public port.
    pub fn server_args(&self) -> Vec<String> {
        let mut args = self.server.args.clone();
        args.push("-b".to_string());
        args.push(self.backend.to_string());
        args
    }
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
        let args = config.server_args();
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
    }

    #[test]
    fn unknown_keys_are_rejected_rather_than_silently_ignored() {
        let text = "listen = \"0.0.0.0:5520\"\nnonsense = true\n";
        assert!(toml::from_str::<Config>(text).is_err());
    }
}
