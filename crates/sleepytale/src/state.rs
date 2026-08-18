//! Lifecycle management for all SNI-routed backends.

use crate::config::{BackendConfig, Config, Routes};
use crate::infra::console::ConsoleInput;
use crate::infra::{self, Backend};
use crate::knock::is_quic_initial;
use crate::relay::Relay;
use crate::sni;
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tokio::time::{Duration, Instant, MissedTickBehavior, interval};

const TICK: Duration = Duration::from_secs(5);
const MAX_DATAGRAM: usize = 64 * 1024;

pub struct Proxy {
    config: Config,
}

enum Lifecycle {
    Sleeping,
    Waking(JoinHandle<Result<Box<dyn Backend>>>),
    Running(Box<dyn Backend>),
}

struct ManagedBackend {
    config: BackendConfig,
    lifecycle: Lifecycle,
    empty_since: Option<Instant>,
}

impl ManagedBackend {
    fn new(config: BackendConfig) -> Self {
        Self {
            config,
            lifecycle: Lifecycle::Sleeping,
            empty_since: None,
        }
    }
}

impl Proxy {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    pub async fn run(&self, shutdown: impl Future<Output = ()>) -> Result<()> {
        tokio::pin!(shutdown);
        let public = Arc::new(bind_public(self.config.listen).await?);
        let console = self.console()?;
        let routes = self.config.routes();
        let mut backends: BTreeMap<SocketAddr, ManagedBackend> = routes
            .all()
            .map(|route| (route.backend, ManagedBackend::new(route)))
            .collect();
        let relay = Arc::new(Relay::new(Arc::clone(&public), self.config.session_timeout));

        tracing::info!(listen = %self.config.listen, routes = self.config.routes.len(), "sleeping");
        let mut ticker = interval(TICK);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut buf = vec![0; MAX_DATAGRAM];

        loop {
            tokio::select! {
                () = shutdown.as_mut() => break,
                _ = ticker.tick() => self.tick(&relay, &mut backends).await?,
                received = public.recv_from(&mut buf) => match received {
                    Ok((len, client)) => self.handle_datagram(
                        client, &buf[..len], &routes, &relay, &mut backends, console.clone(),
                    ).await?,
                    Err(error) => tracing::debug!(%error, "public socket read failed"),
                },
            }
        }

        relay.clear().await;
        for backend in backends.values_mut() {
            match std::mem::replace(&mut backend.lifecycle, Lifecycle::Sleeping) {
                Lifecycle::Running(mut backend) => backend.stop().await?,
                Lifecycle::Waking(task) => {
                    task.abort();
                    let _ = task.await;
                }
                Lifecycle::Sleeping => {}
            }
        }
        Ok(())
    }

    fn console(&self) -> Result<Option<Arc<ConsoleInput>>> {
        let interactive = std::iter::once(&self.config.server)
            .chain(self.config.routes.values().map(|route| &route.server))
            .filter(|server| server.forward_stdin)
            .count();
        anyhow::ensure!(
            interactive <= 1,
            "only one backend may set forward_stdin = true"
        );
        if interactive == 1 {
            Ok(Some(Arc::new(ConsoleInput::start()?)))
        } else {
            Ok(None)
        }
    }

    async fn handle_datagram(
        &self,
        client: SocketAddr,
        datagram: &[u8],
        routes: &Routes,
        relay: &Relay,
        backends: &mut BTreeMap<SocketAddr, ManagedBackend>,
        console: Option<Arc<ConsoleInput>>,
    ) -> Result<()> {
        // Later QUIC datagrams are encrypted, so the source-address session owns the
        // route after its first packet. Only a new address needs an SNI lookup.
        let target = relay.session_backend(client).await.unwrap_or_else(|| {
            routes
                .resolve(sni::peek_server_name(datagram).as_deref())
                .backend
        });
        let managed = backends
            .get_mut(&target)
            .context("selected backend is not configured")?;
        match &managed.lifecycle {
            Lifecycle::Running(_) => {
                if let Err(error) = relay.forward_to_backend(client, target, datagram).await {
                    tracing::debug!(%client, %error, "forwarding failed");
                }
            }
            Lifecycle::Sleeping if is_quic_initial(datagram) => {
                tracing::info!(%client, backend = %target, "client knocked; waking backend");
                let config = self.config.clone();
                let backend = managed.config.clone();
                let backend_console = backend.server.forward_stdin.then_some(console).flatten();
                managed.lifecycle = Lifecycle::Waking(tokio::spawn(async move {
                    let mut adapter = infra::create_backend(&config, &backend, backend_console)?;
                    let deadline = adapter.start().await?;
                    adapter.wait_until_ready(deadline).await?;
                    Ok(adapter)
                }));
            }
            Lifecycle::Sleeping | Lifecycle::Waking(_) => {
                tracing::debug!(%client, backend = %target, bytes = datagram.len(), "dropping a datagram while backend is unavailable");
            }
        }
        Ok(())
    }

    async fn tick(
        &self,
        relay: &Relay,
        backends: &mut BTreeMap<SocketAddr, ManagedBackend>,
    ) -> Result<()> {
        relay.reap_idle().await;
        for managed in backends.values_mut() {
            if let Lifecycle::Waking(task) = &managed.lifecycle
                && task.is_finished()
            {
                let Lifecycle::Waking(task) =
                    std::mem::replace(&mut managed.lifecycle, Lifecycle::Sleeping)
                else {
                    unreachable!()
                };
                match task.await.context("joining backend startup task")? {
                    Ok(backend) => {
                        tracing::info!(backend = %managed.config.backend, "backend ready");
                        managed.lifecycle = Lifecycle::Running(backend);
                        managed.empty_since = Some(Instant::now());
                    }
                    Err(error) => {
                        tracing::error!(backend = %managed.config.backend, %error, "backend failed to start")
                    }
                }
            }
            if let Lifecycle::Running(backend) = &mut managed.lifecycle {
                if backend.has_exited()? {
                    tracing::warn!(backend = %managed.config.backend, "backend exited on its own");
                    managed.lifecycle = Lifecycle::Sleeping;
                    continue;
                }
                if relay.session_count_for(managed.config.backend).await == 0 {
                    let since = *managed.empty_since.get_or_insert_with(Instant::now);
                    if since.elapsed() >= self.config.idle_timeout {
                        tracing::info!(backend = %managed.config.backend, idle = ?since.elapsed(), "no players; stopping backend");
                        let Lifecycle::Running(mut backend) =
                            std::mem::replace(&mut managed.lifecycle, Lifecycle::Sleeping)
                        else {
                            unreachable!()
                        };
                        backend.stop().await?;
                    }
                } else {
                    managed.empty_since = None;
                }
            }
        }
        Ok(())
    }
}

async fn bind_public(addr: SocketAddr) -> Result<UdpSocket> {
    let domain = socket2::Domain::for_address(addr);
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))
        .context("creating the public socket")?;
    if addr.is_ipv6() && addr.ip().is_unspecified() {
        socket
            .set_only_v6(false)
            .context("enabling IPv4-mapped clients on the public socket")?;
    }
    socket
        .set_nonblocking(true)
        .context("setting non-blocking")?;
    socket
        .bind(&addr.into())
        .with_context(|| format!("binding {addr}"))?;
    UdpSocket::from_std(socket.into()).context("handing the public socket to tokio")
}
