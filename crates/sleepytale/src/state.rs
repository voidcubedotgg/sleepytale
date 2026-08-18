//! Lifecycle management for all SNI-routed backends.
//!
//! ```text
//! Sleeping   the backend is not running; a QUIC Initial routed to it starts it
//! Waking     Initials for that backend are held while it boots; everything else is dropped
//! Running    held Initials are delivered, then datagrams are relayed to the backend
//!            no sessions for idle_timeout -> stop the backend -> Sleeping
//! ```
//!
//! One socket serves every backend in every state, so the public port is never released
//! and there is no window where the address is unbound. What changes per backend is only
//! what the proxy does with a datagram routed to it: ignore it, hold it, or relay it.
//!
//! Nothing is ever sent back from Sleeping or Waking. The proxy does not terminate the
//! QUIC handshake, so it cannot answer one either — see [`crate::knock`]. What it can do
//! is deliver the client's own Initial late: a connection attempt that arrives mid-boot is
//! held and forwarded the moment the backend is ready, so the client does not have to
//! retransmit for the connection to succeed.

use crate::config::{BackendConfig, Config, Routes};
use crate::infra::console::ConsoleInput;
use crate::infra::{self, Backend};
use crate::knock::is_quic_initial;
use crate::relay::Relay;
use crate::sni;
use anyhow::{Context, Result};
use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tokio::time::{Duration, Instant, MissedTickBehavior, interval};

const TICK: Duration = Duration::from_secs(5);
const MAX_DATAGRAM: usize = 64 * 1024;

/// How many distinct clients can have an Initial held during one backend's boot.
///
/// Only the newest Initial per address is kept, so this bounds the hold to a handful of
/// datagrams however long the boot runs. Clients past the cap are simply not held; they
/// still connect the moment they retransmit against the running relay.
const MAX_HELD_CLIENTS: usize = 8;

/// Client Initials received while a backend was booting, newest per address.
type HeldInitials = HashMap<SocketAddr, Vec<u8>>;

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
    held: HeldInitials,
}

impl ManagedBackend {
    fn new(config: BackendConfig) -> Self {
        Self {
            config,
            lifecycle: Lifecycle::Sleeping,
            empty_since: None,
            held: HeldInitials::new(),
        }
    }

    /// Hold a client's Initial until this backend is ready, reporting whether it was kept.
    ///
    /// Only the newest Initial per address is kept: an older one from the same client is a
    /// retransmission of the same connection attempt, so the newest is the one worth
    /// delivering. A client already held never counts against the cap again.
    fn hold(&mut self, client: SocketAddr, datagram: &[u8]) -> bool {
        if !self.held.contains_key(&client) && self.held.len() >= MAX_HELD_CLIENTS {
            return false;
        }
        self.held.insert(client, datagram.to_vec());
        true
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
                // The knock is the client's live connection attempt, not just a signal
                // that someone is there: hold it so the boot it triggered can serve it.
                managed.hold(client, datagram);
            }
            Lifecycle::Waking(_) if is_quic_initial(datagram) => {
                if managed.hold(client, datagram) {
                    tracing::debug!(
                        %client,
                        backend = %target,
                        bytes = datagram.len(),
                        "holding an Initial until the backend is ready"
                    );
                } else {
                    tracing::debug!(
                        %client,
                        backend = %target,
                        bytes = datagram.len(),
                        "dropping an Initial; too many clients are already held"
                    );
                }
            }
            // Anything that is not an Initial belongs to a connection that does not exist
            // yet, and the backend would have nothing to match it against.
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
                        deliver_held(relay, addr, std::mem::take(&mut managed.held)).await;
                    }
                    Ok(Err(error)) => {
                        managed.held.clear();
                        tracing::error!(backend = %addr, %error, "backend failed to start")
                    }
                    Err(error) => {
                        managed.held.clear();
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

/// Deliver the Initials held while a backend was booting.
///
/// A client is sitting in a handshake with a deadline of its own, and it does not
/// necessarily retransmit. If the Initial that started the boot is never delivered, the
/// player's first attempt fails even though the server came up well within their client's
/// patience. A delivery failure concerns only that client, so it is logged, not raised.
async fn deliver_held(relay: &Relay, backend: SocketAddr, held: HeldInitials) {
    for (client, datagram) in held {
        match relay.forward_to_backend(client, backend, &datagram).await {
            Ok(()) => tracing::debug!(
                %client,
                %backend,
                bytes = datagram.len(),
                "delivered an Initial held during boot"
            ),
            Err(error) => {
                tracing::debug!(%client, %backend, %error, "could not deliver a held Initial")
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

/// Bind the public port, serving both address families from one socket where possible.
///
/// The real server opens an IPv4 and an IPv6 channel (`QUICTransport`, "Using IPv4/IPv6
/// Datagram Channel"). A client resolving a name to both families tries IPv6 first, so a
/// v4-only proxy costs every cold connect the client's full ten-second handshake timeout
/// before it falls back.
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::oneshot;
    use tokio::time::{sleep, timeout};

    #[tokio::test]
    async fn sleeping_proxy_releases_promptly_on_shutdown() {
        let config = Config {
            listen: "127.0.0.1:57121".parse().unwrap(),
            ..Config::default()
        };

        let (stop, stopped) = oneshot::channel();
        let proxy = Proxy::new(config);
        let task = tokio::spawn(async move {
            proxy
                .run(async move {
                    let _ = stopped.await;
                })
                .await
        });

        // Give the proxy enough time to acquire its UDP socket before stopping it.
        sleep(Duration::from_millis(25)).await;
        stop.send(()).unwrap();
        timeout(Duration::from_secs(1), task)
            .await
            .expect("sleeping proxy did not stop promptly")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn an_unspecified_ipv6_bind_also_serves_ipv4_clients() {
        let public = bind_public("[::]:57122".parse().unwrap()).await.unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(b"hello", "127.0.0.1:57122").await.unwrap();

        let mut buf = [0u8; 16];
        let (len, from) = timeout(Duration::from_secs(1), public.recv_from(&mut buf))
            .await
            .expect("an IPv4 client could not reach the dual-stack socket")
            .unwrap();
        assert_eq!(&buf[..len], b"hello");
        assert_eq!(from.ip().to_canonical(), client.local_addr().unwrap().ip());
    }

    /// An Initial-shaped datagram, padded to the 1200 bytes a real client sends.
    fn initial() -> Vec<u8> {
        let mut datagram = vec![0u8; 1200];
        datagram[0] = 0xc3; // long header, fixed bit, Initial
        datagram[1..5].copy_from_slice(&[0, 0, 0, 1]); // QUIC v1
        datagram
    }

    /// A proxy whose "server" is a shell script that prints the boot banner after `boot`,
    /// so waking runs its real path (process spawn, banner scan) on a predictable clock.
    fn shell_proxy(backend: SocketAddr, boot: Duration) -> Proxy {
        let mut config = Config {
            backend,
            ..Config::default()
        };
        config.server.command = "sh".to_string();
        config.server.args = vec![
            "-c".to_string(),
            format!(
                "sleep {}; echo 'Hytale Server Booted!'; sleep 30",
                boot.as_secs_f32()
            ),
        ];
        config.server.forward_stdin = false;
        config.boot_timeout = Duration::from_secs(5);
        config.shutdown_grace = Duration::from_millis(200);
        Proxy::new(config)
    }

    /// The proxy's own state, built the way `run()` builds it, so a test can drive
    /// `handle_datagram` and `tick` directly without racing the select loop.
    struct Harness {
        proxy: Proxy,
        routes: Routes,
        relay: Arc<Relay>,
        backends: BTreeMap<SocketAddr, ManagedBackend>,
    }

    impl Harness {
        async fn new(proxy: Proxy) -> Self {
            let public = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let routes = proxy.config.routes();
            let backends = routes
                .all()
                .map(|route| (route.backend, ManagedBackend::new(route)))
                .collect();
            let relay = Arc::new(Relay::new(public, proxy.config.session_timeout));
            Self {
                proxy,
                routes,
                relay,
                backends,
            }
        }

        async fn feed(&mut self, client: SocketAddr, datagram: &[u8]) {
            self.proxy
                .handle_datagram(
                    client,
                    datagram,
                    &self.routes,
                    &self.relay,
                    &mut self.backends,
                    None,
                )
                .await
                .unwrap();
        }

        /// Tick until the backend leaves `Waking`, the way the 5s ticker eventually would.
        async fn tick_until_running(&mut self, addr: SocketAddr) {
            for _ in 0..500 {
                self.proxy.tick(&self.relay, &mut self.backends).await;
                if let Lifecycle::Running(_) = self.backends[&addr].lifecycle {
                    return;
                }
                sleep(Duration::from_millis(20)).await;
            }
            panic!("the shell backend never reached Running");
        }

        async fn shutdown(&mut self) {
            self.relay.clear().await;
            for managed in self.backends.values_mut() {
                let addr = managed.config.backend;
                if let Lifecycle::Running(mut backend) =
                    std::mem::replace(&mut managed.lifecycle, Lifecycle::Sleeping)
                {
                    stop_backend(addr, &mut backend).await;
                }
            }
        }
    }

    /// The connection attempt that woke a backend must reach it once it is up.
    ///
    /// This is the whole point of waking: the client is sitting in a handshake with a
    /// deadline of its own, and it does not necessarily retransmit. If the Initial that
    /// started the boot is never delivered, the player's first attempt fails even though
    /// the server came up well within their client's patience.
    #[tokio::test]
    async fn the_initial_that_woke_a_backend_reaches_it() {
        let backend_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend_socket.local_addr().unwrap();
        let mut harness = Harness::new(shell_proxy(backend_addr, Duration::ZERO)).await;

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let knock = initial();

        harness.feed(client_addr, &knock).await;
        harness.tick_until_running(backend_addr).await;

        let mut buf = vec![0u8; 2048];
        let (len, _) = timeout(Duration::from_secs(5), backend_socket.recv_from(&mut buf))
            .await
            .expect("the Initial that woke the backend never reached it")
            .unwrap();
        assert_eq!(&buf[..len], &knock[..], "the client's own bytes, unaltered");

        harness.shutdown().await;
    }

    /// An Initial that arrives *during* the boot is held too, and the newest one per client
    /// wins — an earlier one from the same address is only a retransmission of the same
    /// attempt, so delivering the stale copy would be pointless.
    #[tokio::test]
    async fn an_initial_arriving_mid_boot_is_held_and_delivered() {
        let backend_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend_socket.local_addr().unwrap();
        let mut harness = Harness::new(shell_proxy(backend_addr, Duration::from_millis(500))).await;

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        // Distinguishable from the knock, so the assertion proves the newer one won.
        let mut retransmit = initial();
        retransmit[5..9].copy_from_slice(b"HELD");

        harness.feed(client_addr, &initial()).await;
        harness.feed(client_addr, &retransmit).await;
        assert!(
            matches!(
                harness.backends[&backend_addr].lifecycle,
                Lifecycle::Waking(_)
            ),
            "the backend should still be booting"
        );
        assert_eq!(harness.backends[&backend_addr].held.len(), 1);

        harness.tick_until_running(backend_addr).await;

        let mut buf = vec![0u8; 2048];
        let (len, _) = timeout(Duration::from_secs(5), backend_socket.recv_from(&mut buf))
            .await
            .expect("the Initial held during boot never reached the backend")
            .unwrap();
        assert_eq!(
            &buf[..len],
            &retransmit[..],
            "the newest Initial for this client should win"
        );

        harness.shutdown().await;
    }

    /// A held Initial is a bounded courtesy, not a queue: past the cap a new client is
    /// simply not held, and connects on its own retransmission once the relay is up.
    #[tokio::test]
    async fn holding_initials_is_capped_per_backend() {
        let backend_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend_socket.local_addr().unwrap();
        let mut harness = Harness::new(shell_proxy(backend_addr, Duration::from_secs(30))).await;

        for port in 0..MAX_HELD_CLIENTS + 4 {
            let client: SocketAddr = format!("127.0.0.1:{}", 40000 + port).parse().unwrap();
            harness.feed(client, &initial()).await;
        }
        assert_eq!(harness.backends[&backend_addr].held.len(), MAX_HELD_CLIENTS);

        harness.shutdown().await;
    }

    /// Anything that is not an Initial cannot start or join a connection, so it is dropped
    /// rather than held — the backend would have nothing to match it against.
    #[tokio::test]
    async fn a_non_initial_neither_wakes_a_backend_nor_is_held() {
        let backend_addr: SocketAddr = "127.0.0.1:57123".parse().unwrap();
        let mut harness = Harness::new(shell_proxy(backend_addr, Duration::ZERO)).await;

        let client: SocketAddr = "127.0.0.1:40100".parse().unwrap();
        harness.feed(client, b"not a QUIC Initial").await;

        assert!(matches!(
            harness.backends[&backend_addr].lifecycle,
            Lifecycle::Sleeping
        ));
        assert!(harness.backends[&backend_addr].held.is_empty());
    }
}
