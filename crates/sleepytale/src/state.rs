//! The proxy's lifecycle: sleeping, waking, running.
//!
//! ```text
//! Sleeping   the public socket is quiet; a QUIC Initial starts the backend
//! Waking     Initials are held while the backend boots; everything else is dropped
//! Running    held Initials are delivered, then datagrams are relayed to the backend
//!            no sessions for idle_timeout -> stop the backend -> Sleeping
//! ```
//!
//! One socket serves all three states, so the public port is never released and there is
//! no window where the address is unbound. What changes between states is only what the
//! proxy does with a datagram: ignore it, hold it, or relay it.
//!
//! Nothing is ever sent back from Sleeping or Waking. The proxy does not terminate the
//! QUIC handshake, so it cannot answer one either — see [`crate::knock`]. What it can do
//! is deliver the client's own Initial late: a connection attempt that arrives mid-boot is
//! held and forwarded the moment the backend is ready, so the client does not have to
//! retransmit for the connection to succeed.

use crate::config::Config;
use crate::infra::console::ConsoleInput;
use crate::infra::{self, Backend};
use crate::knock::is_quic_initial;
use crate::relay::Relay;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::UdpSocket;
use tokio::time::{Duration, Instant, MissedTickBehavior, interval};

/// How often the relay checks for expired sessions and idle shutdown.
const TICK: Duration = Duration::from_secs(5);

const MAX_DATAGRAM: usize = 64 * 1024;

/// How many distinct clients can have an Initial held during one boot.
///
/// Only the newest Initial per address is kept, so this bounds the hold to a handful of
/// datagrams however long the boot runs. Clients past the cap are simply not held; they
/// still connect the moment they retransmit against the running relay.
const MAX_HELD_CLIENTS: usize = 8;

/// Client Initials received while the backend was booting, newest per address.
type HeldInitials = HashMap<SocketAddr, Vec<u8>>;

pub struct Proxy {
    config: Config,
}

impl Proxy {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    /// Run until `shutdown` resolves.
    pub async fn run(&self, shutdown: impl Future<Output = ()>) -> Result<()> {
        tokio::pin!(shutdown);
        let public = Arc::new(bind_public(self.config.listen).await?);
        let console = match self.config.server.forward_stdin {
            true => Some(Arc::new(ConsoleInput::start()?)),
            false => None,
        };

        loop {
            // --- Sleeping: ignore the port until someone dials in. ---
            tracing::info!(listen = %self.config.listen, "sleeping");
            let Some(knock) = self.wait_for_knock(&public, &mut shutdown).await? else {
                return Ok(());
            };

            // --- Waking: boot the backend, holding Initials until it is ready. ---
            let (backend, held) = match self
                .wake(&public, knock, console.clone(), &mut shutdown)
                .await?
            {
                Wake::Running(backend, held) => (backend, held),
                Wake::Shutdown => return Ok(()),
                Wake::Failed => continue,
            };

            // --- Running: relay until idle. ---
            match self.serve(&public, backend, held, &mut shutdown).await? {
                Stop::Shutdown => return Ok(()),
                Stop::BackendGone | Stop::Idle => {}
            }
        }
    }

    /// Wait for a client to try to connect.
    ///
    /// Returns the Initial that woke the proxy, or `None` when the proxy is stopping. The
    /// datagram is carried out so it can be delivered once the backend is up: it is the
    /// client's live connection attempt, not just a signal that someone knocked.
    async fn wait_for_knock(
        &self,
        public: &UdpSocket,
        shutdown: &mut std::pin::Pin<&mut impl Future<Output = ()>>,
    ) -> Result<Option<(SocketAddr, Vec<u8>)>> {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        loop {
            let received = tokio::select! {
                () = shutdown.as_mut() => return Ok(None),
                received = public.recv_from(&mut buf) => received,
            };
            // A read error here is per-datagram, not fatal: Linux reports a queued ICMP
            // port-unreachable from a client that vanished as ECONNREFUSED on the next
            // recv. Giving up would close the public port for good, so this matches the
            // other two read loops and keeps waiting.
            let (len, from) = match received {
                Ok(received) => received,
                Err(e) => {
                    tracing::debug!(error = %e, "public socket read failed");
                    continue;
                }
            };

            if is_quic_initial(&buf[..len]) {
                tracing::info!(%from, "client knocked; waking the backend");
                return Ok(Some((from, buf[..len].to_vec())));
            }
            tracing::debug!(%from, bytes = len, "ignoring a datagram that is not a QUIC Initial");
        }
    }

    /// Boot the backend, holding the client Initials that arrive meanwhile.
    ///
    /// Only the newest Initial per address is kept: an older one from the same client is a
    /// retransmission of the same connection attempt, so the newest is the one worth
    /// delivering. Everything else is dropped — it belongs to a connection that no longer
    /// exists, and the backend would have nothing to match it against.
    async fn wake(
        &self,
        public: &UdpSocket,
        knock: (SocketAddr, Vec<u8>),
        console: Option<Arc<ConsoleInput>>,
        shutdown: &mut std::pin::Pin<&mut impl Future<Output = ()>>,
    ) -> Result<Wake> {
        let mut held: HeldInitials = HashMap::new();
        let (from, datagram) = knock;
        held.insert(from, datagram);

        let mut backend = match infra::create_backend(&self.config, console) {
            Ok(backend) => backend,
            Err(e) => {
                tracing::error!(error = %e, "could not create the backend");
                return Ok(Wake::Failed);
            }
        };

        let deadline = match backend.start().await {
            Ok(deadline) => deadline,
            Err(e) => {
                tracing::error!(error = %e, "could not start the backend");
                return Ok(Wake::Failed);
            }
        };

        let mut buf = vec![0u8; MAX_DATAGRAM];
        let ready = loop {
            tokio::select! {
                () = &mut *shutdown => {
                    backend.stop().await?;
                    return Ok(Wake::Shutdown);
                }
                // Rebuilt after every datagram below. Its boot deadline is absolute, so
                // a client retrying its Initial cannot keep a hung backend alive.
                result = backend.wait_until_ready(deadline) => break result,
                received = public.recv_from(&mut buf) => {
                    match received {
                        Ok((len, from)) => {
                            let holding = is_quic_initial(&buf[..len])
                                && (held.contains_key(&from) || held.len() < MAX_HELD_CLIENTS);
                            if holding {
                                held.insert(from, buf[..len].to_vec());
                                tracing::debug!(
                                    %from,
                                    bytes = len,
                                    "holding an Initial until the backend is ready"
                                );
                            } else {
                                tracing::debug!(
                                    %from,
                                    bytes = len,
                                    "dropping a datagram while the backend boots"
                                );
                            }
                        }
                        Err(e) => tracing::debug!(error = %e, "public socket read failed"),
                    }
                }
            }
        };

        match ready {
            Ok(()) => Ok(Wake::Running(backend, held)),
            Err(e) => {
                tracing::error!(error = %e, "backend failed to start");
                backend.stop().await?;
                Ok(Wake::Failed)
            }
        }
    }

    /// Relay traffic until the server goes idle, dies, or the proxy is shut down.
    ///
    /// `held` carries the Initials collected while the backend was booting; they are
    /// delivered before the relay starts reading, so a client that connected mid-boot does
    /// not have to retransmit for its attempt to reach the server.
    async fn serve(
        &self,
        public: &Arc<UdpSocket>,
        mut backend: Box<dyn Backend>,
        held: HeldInitials,
        shutdown: &mut std::pin::Pin<&mut impl Future<Output = ()>>,
    ) -> Result<Stop> {
        // Nothing is drained here. Datagrams queued on the socket at this instant arrived
        // in the last few microseconds and belong to a live connection attempt; an earlier
        // version dropped them on the theory that they might belong to an attempt the
        // client had already abandoned, which cost every wake a full extra client retry
        // cycle for a collision that can't happen (an abandoned attempt uses different
        // connection IDs, so it can't corrupt a live one — worst case the backend gets a
        // half-open connection that expires on its own, the same as ordinary jitter).
        let relay = Arc::new(Relay::new(
            Arc::clone(public),
            self.config.backend,
            self.config.session_timeout,
        ));
        tracing::info!(backend = %self.config.backend, "running");

        for (from, datagram) in &held {
            match relay.forward_to_backend(*from, datagram).await {
                Ok(()) => tracing::debug!(
                    %from,
                    bytes = datagram.len(),
                    "delivered an Initial held during boot"
                ),
                Err(e) => tracing::debug!(%from, error = %e, "could not deliver a held Initial"),
            }
        }

        let stop = Arc::new(AtomicBool::new(false));
        let pump = {
            let public = Arc::clone(public);
            let relay = Arc::clone(&relay);
            let stop = Arc::clone(&stop);
            tokio::spawn(async move {
                let mut buf = vec![0u8; MAX_DATAGRAM];
                while !stop.load(Ordering::Relaxed) {
                    let (len, from) = match public.recv_from(&mut buf).await {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::debug!(error = %e, "public socket read failed");
                            continue;
                        }
                    };
                    if let Err(e) = relay.forward_to_backend(from, &buf[..len]).await {
                        tracing::debug!(%from, error = %e, "forwarding failed");
                    }
                }
            })
        };

        let outcome = self.watch(&relay, &mut *backend, shutdown).await;

        stop.store(true, Ordering::Relaxed);
        pump.abort();
        let _ = pump.await;
        relay.clear().await;

        backend.stop().await?;
        outcome
    }

    /// Poll for idle shutdown, backend death, or proxy shutdown.
    async fn watch(
        &self,
        relay: &Relay,
        backend: &mut dyn Backend,
        shutdown: &mut std::pin::Pin<&mut impl Future<Output = ()>>,
    ) -> Result<Stop> {
        let mut ticker = interval(TICK);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        // Grace before the first idle check, so a cold start is not shut straight back
        // down while the waking player is still connecting.
        let mut empty_since = Some(Instant::now());

        loop {
            tokio::select! {
                () = shutdown.as_mut() => return Ok(Stop::Shutdown),
                _ = ticker.tick() => {}
            }

            if backend.has_exited()? {
                tracing::warn!("backend exited on its own");
                return Ok(Stop::BackendGone);
            }

            match relay.reap_idle().await {
                0 => {
                    let since = *empty_since.get_or_insert_with(Instant::now);
                    if since.elapsed() >= self.config.idle_timeout {
                        tracing::info!(idle = ?since.elapsed(), "no players; stopping backend");
                        return Ok(Stop::Idle);
                    }
                }
                n => {
                    if empty_since.take().is_some() {
                        tracing::debug!(players = n, "no longer idle");
                    }
                }
            }
        }
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

#[derive(Debug, PartialEq, Eq)]
enum Stop {
    Idle,
    BackendGone,
    Shutdown,
}

enum Wake {
    // Boxed: a concrete backend dwarfs the other two variants, and this is built once per wake.
    Running(Box<dyn Backend>, HeldInitials),
    Failed,
    Shutdown,
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

    /// A `Backend` that is already "ready" the instant it exists — `serve()` never calls
    /// `start`/`wait_until_ready` itself, so this only needs to satisfy the trait.
    struct StubBackend;

    impl Backend for StubBackend {
        fn start<'a>(&'a mut self) -> crate::infra::BoxFuture<'a, Result<std::time::Instant>> {
            Box::pin(async { Ok(std::time::Instant::now()) })
        }
        fn wait_until_ready<'a>(
            &'a mut self,
            _deadline: std::time::Instant,
        ) -> crate::infra::BoxFuture<'a, Result<()>> {
            Box::pin(async { Ok(()) })
        }
        fn has_exited(&mut self) -> Result<bool> {
            Ok(false)
        }
        fn stop<'a>(&'a mut self) -> crate::infra::BoxFuture<'a, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    /// Regression test for the Waking→Running handoff: a datagram already sitting on the
    /// public socket the instant `serve()` starts must reach the backend, not be dropped.
    /// This used to fail — `serve()` drained and discarded exactly this datagram on the
    /// theory that it might belong to an attempt the client had already abandoned, which
    /// in practice meant the datagram that would have completed the connection right after
    /// boot was thrown away instead.
    #[tokio::test]
    async fn a_datagram_queued_at_the_handoff_is_relayed_not_dropped() {
        let public = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let public_addr = public.local_addr().unwrap();
        let backend_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend_socket.local_addr().unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&[0xaa; 32], public_addr).await.unwrap();
        // Give the kernel a moment to enqueue it before `serve()` (and thus its relay pump)
        // ever starts reading — otherwise this wouldn't reproduce "already queued".
        sleep(Duration::from_millis(10)).await;

        let config = Config {
            backend: backend_addr,
            ..Config::default()
        };
        let proxy = Proxy::new(config);

        let (stop, stopped) = oneshot::channel();
        let task = {
            let public = Arc::clone(&public);
            tokio::spawn(async move {
                let shutdown = async move {
                    let _ = stopped.await;
                };
                tokio::pin!(shutdown);
                proxy
                    .serve(
                        &public,
                        Box::new(StubBackend),
                        HeldInitials::new(),
                        &mut shutdown,
                    )
                    .await
            })
        };

        let mut buf = [0u8; 64];
        let (len, _) = timeout(
            Duration::from_millis(500),
            backend_socket.recv_from(&mut buf),
        )
        .await
        .expect("the datagram queued before `serve()` started was never relayed")
        .unwrap();
        assert_eq!(&buf[..len], &[0xaa; 32]);

        stop.send(()).unwrap();
        timeout(Duration::from_secs(1), task)
            .await
            .expect("serve did not shut down promptly")
            .unwrap()
            .unwrap();
    }

    /// An Initial-shaped datagram, padded to the 1200 bytes a real client sends.
    fn initial() -> Vec<u8> {
        let mut datagram = vec![0u8; 1200];
        datagram[0] = 0xc3; // long header, fixed bit, Initial
        datagram[1..5].copy_from_slice(&[0, 0, 0, 1]); // QUIC v1
        datagram
    }

    /// A proxy whose "server" is a shell script that prints the boot banner after `boot`,
    /// so `wake()` runs its real path (process spawn, banner scan) on a predictable clock.
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

    /// Run `wake` then `serve` the way `run()` does, so the held Initials cross the handoff.
    async fn wake_then_serve(
        proxy: Proxy,
        public: Arc<UdpSocket>,
        knock: (SocketAddr, Vec<u8>),
        stopped: oneshot::Receiver<()>,
    ) -> Result<Stop> {
        let shutdown = async move {
            let _ = stopped.await;
        };
        tokio::pin!(shutdown);
        let (backend, held) = match proxy.wake(&public, knock, None, &mut shutdown).await? {
            Wake::Running(backend, held) => (backend, held),
            Wake::Failed => panic!("the shell backend should have booted"),
            Wake::Shutdown => panic!("shut down before the backend was ready"),
        };
        proxy.serve(&public, backend, held, &mut shutdown).await
    }

    /// The connection attempt that woke the proxy must reach the backend once it is up.
    ///
    /// This is the whole point of waking: the client is sitting in a handshake with a
    /// deadline of its own, and it does not necessarily retransmit. If the Initial that
    /// started the boot is never delivered, the player's first attempt fails even though
    /// the server came up well within their client's patience.
    #[tokio::test]
    async fn the_initial_that_woke_the_proxy_reaches_the_backend() {
        let public = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let backend_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let proxy = shell_proxy(backend_socket.local_addr().unwrap(), Duration::ZERO);

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let knock = initial();

        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(wake_then_serve(
            proxy,
            Arc::clone(&public),
            (client_addr, knock.clone()),
            stopped,
        ));

        let mut buf = vec![0u8; 2048];
        let (len, _) = timeout(Duration::from_secs(5), backend_socket.recv_from(&mut buf))
            .await
            .expect("the Initial that woke the proxy never reached the backend")
            .unwrap();
        assert_eq!(&buf[..len], &knock[..], "the client's own bytes, unaltered");

        stop.send(()).unwrap();
        timeout(Duration::from_secs(5), task)
            .await
            .expect("serve did not shut down promptly")
            .unwrap()
            .unwrap();
    }

    /// An Initial that arrives *during* the boot is held too, and the newest one per client
    /// wins — an earlier one from the same address is only a retransmission of the same
    /// attempt, so delivering the stale copy would be pointless.
    #[tokio::test]
    async fn an_initial_arriving_mid_boot_is_held_and_delivered() {
        let public = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let public_addr = public.local_addr().unwrap();
        let backend_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let proxy = shell_proxy(
            backend_socket.local_addr().unwrap(),
            Duration::from_millis(500),
        );

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        // Distinguishable from the knock, so the assertion proves the newer one won.
        let mut retransmit = initial();
        retransmit[5..9].copy_from_slice(b"HELD");

        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(wake_then_serve(
            proxy,
            Arc::clone(&public),
            (client_addr, initial()),
            stopped,
        ));

        // Land inside the boot window, while `wake` is still waiting for the banner.
        sleep(Duration::from_millis(100)).await;
        client.send_to(&retransmit, public_addr).await.unwrap();

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

        stop.send(()).unwrap();
        timeout(Duration::from_secs(5), task)
            .await
            .expect("serve did not shut down promptly")
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
}
