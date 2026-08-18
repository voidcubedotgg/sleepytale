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
                _ = ticker.tick() => self.tick(&relay, &mut backends).await,
                received = public.recv_from(&mut buf) => match received {
                    Ok((len, client)) => {
                        if let Err(error) = self.handle_datagram(
                            client, &buf[..len], &routes, &relay, &mut backends, console.clone(),
                        ).await {
                            tracing::warn!(%client, %error, "dropping a datagram");
                        }
                    }
                    Err(error) => tracing::debug!(%error, "public socket read failed"),
                },
            }
        }

        relay.clear().await;
        for managed in backends.values_mut() {
            let addr = managed.config.backend;
            match std::mem::replace(&mut managed.lifecycle, Lifecycle::Sleeping) {
                Lifecycle::Running(mut backend) => stop_backend(addr, &mut backend).await,
                // Aborting would drop the adapter, and `kill_on_drop` only reaches the
                // direct child; `stop` is the one path that signals the whole process
                // group. Let startup finish, then stop what it produced.
                Lifecycle::Waking(task) => {
                    match tokio::time::timeout(self.config.shutdown_grace, task).await {
                        Ok(Ok(Ok(mut backend))) => stop_backend(addr, &mut backend).await,
                        Ok(Ok(Err(error))) => {
                            tracing::error!(backend = %addr, %error, "backend failed to start")
                        }
                        Ok(Err(error)) => {
                            tracing::error!(backend = %addr, %error, "backend startup task failed")
                        }
                        Err(_) => tracing::warn!(
                            backend = %addr,
                            "gave up waiting for a waking backend; it may outlive the proxy"
                        ),
                    }
                }
                Lifecycle::Sleeping => {}
            }
        }
        Ok(())
    }

    /// Start the shared console reader when a backend wants stdin. `Config::validate`
    /// has already established that at most one of them does.
    fn console(&self) -> Result<Option<Arc<ConsoleInput>>> {
        let interactive = std::iter::once(&self.config.server)
            .chain(self.config.routes.values().map(|route| &route.server))
            .any(|server| server.forward_stdin);
        if interactive {
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

    /// Advance every backend's lifecycle.
    ///
    /// Errors are scoped to the backend that produced them: one broken route must not
    /// stop the others from being managed, nor end the proxy.
    async fn tick(&self, relay: &Relay, backends: &mut BTreeMap<SocketAddr, ManagedBackend>) {
        relay.reap_idle().await;
        for managed in backends.values_mut() {
            let addr = managed.config.backend;
            if let Lifecycle::Waking(task) = &managed.lifecycle
                && task.is_finished()
            {
                let Lifecycle::Waking(task) =
                    std::mem::replace(&mut managed.lifecycle, Lifecycle::Sleeping)
                else {
                    unreachable!()
                };
                match task.await {
                    Ok(Ok(backend)) => {
                        tracing::info!(backend = %addr, "backend ready");
                        managed.lifecycle = Lifecycle::Running(backend);
                        managed.empty_since = Some(Instant::now());
                    }
                    Ok(Err(error)) => {
                        tracing::error!(backend = %addr, %error, "backend failed to start")
                    }
                    Err(error) => {
                        tracing::error!(backend = %addr, %error, "backend startup task failed")
                    }
                }
            }
            if let Lifecycle::Running(backend) = &mut managed.lifecycle {
                match backend.has_exited() {
                    Ok(false) => {}
                    Ok(true) => {
                        tracing::warn!(backend = %addr, "backend exited on its own");
                        managed.lifecycle = Lifecycle::Sleeping;
                        // Sessions resolve by source address before the route table, so
                        // leaving them pinned would forward to a backend that is gone.
                        managed.empty_since = None;
                        relay.drop_sessions_for(addr).await;
                        continue;
                    }
                    Err(error) => {
                        tracing::error!(backend = %addr, %error, "checking whether the backend exited");
                        continue;
                    }
                }
                if relay.session_count_for(addr).await == 0 {
                    let since = *managed.empty_since.get_or_insert_with(Instant::now);
                    if since.elapsed() >= self.config.idle_timeout {
                        tracing::info!(backend = %addr, idle = ?since.elapsed(), "no players; stopping backend");
                        let Lifecycle::Running(mut backend) =
                            std::mem::replace(&mut managed.lifecycle, Lifecycle::Sleeping)
                        else {
                            unreachable!()
                        };
                        managed.empty_since = None;
                        stop_backend(addr, &mut backend).await;
                    }
                } else {
                    managed.empty_since = None;
                }
            }
        }
    }
}

/// Stop one backend, logging rather than propagating — a failure to stop concerns only
/// that backend.
async fn stop_backend(addr: SocketAddr, backend: &mut Box<dyn Backend>) {
    if let Err(error) = backend.stop().await {
        tracing::error!(backend = %addr, %error, "stopping the backend");
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
