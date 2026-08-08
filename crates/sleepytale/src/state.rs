//! The proxy's lifecycle: sleeping, waking, running.
//!
//! ```text
//! Sleeping   the public socket is quiet; a QUIC Initial starts the backend
//! Waking     datagrams are dropped while the backend boots; the client retries
//! Running    datagrams are relayed to the backend
//!            no sessions for idle_timeout -> stop the backend -> Sleeping
//! ```
//!
//! One socket serves all three states, so the public port is never released and there is
//! no window where the address is unbound. What changes between states is only what the
//! proxy does with a datagram: ignore it, drop it, or relay it.
//!
//! Nothing is ever sent back from Sleeping or Waking. See [`crate::knock`] for why
//! silence is the only response this client handles well.

use crate::config::Config;
use crate::console::ConsoleInput;
use crate::knock::is_quic_initial;
use crate::relay::Relay;
use crate::supervisor::Supervisor;
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::UdpSocket;
use tokio::time::{Duration, Instant, MissedTickBehavior, interval};

/// How often the relay checks for expired sessions and idle shutdown.
const TICK: Duration = Duration::from_secs(5);

const MAX_DATAGRAM: usize = 64 * 1024;

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
            if !self.wait_for_knock(&public, &mut shutdown).await? {
                return Ok(());
            }

            // --- Waking: boot the backend, dropping traffic until it is ready. ---
            let supervisor = match self.wake(&public, console.clone(), &mut shutdown).await? {
                Wake::Running(supervisor) => *supervisor,
                Wake::Shutdown => return Ok(()),
                Wake::Failed => continue,
            };

            // --- Running: relay until idle. ---
            match self.serve(&public, supervisor, &mut shutdown).await? {
                Stop::Shutdown => return Ok(()),
                Stop::BackendGone | Stop::Idle => {}
            }
        }
    }

    /// Wait for a client to try to connect.
    /// Returns `true` after a knock, or `false` when the proxy is stopping.
    async fn wait_for_knock(
        &self,
        public: &UdpSocket,
        shutdown: &mut std::pin::Pin<&mut impl Future<Output = ()>>,
    ) -> Result<bool> {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        loop {
            let received = tokio::select! {
                () = shutdown.as_mut() => return Ok(false),
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
                return Ok(true);
            }
            tracing::debug!(%from, bytes = len, "ignoring a datagram that is not a QUIC Initial");
        }
    }

    /// Boot the backend. Knocks that arrive meanwhile are dropped: the client retransmits
    /// its Initial and retries the whole connection, so one of those attempts lands on the
    /// relay once the backend is ready.
    async fn wake(
        &self,
        public: &UdpSocket,
        console: Option<Arc<ConsoleInput>>,
        shutdown: &mut std::pin::Pin<&mut impl Future<Output = ()>>,
    ) -> Result<Wake> {
        let mut supervisor = match Supervisor::spawn(&self.config, console).await {
            Ok(supervisor) => supervisor,
            Err(e) => {
                tracing::error!(error = %e, "could not start the backend");
                return Ok(Wake::Failed);
            }
        };

        let mut buf = vec![0u8; MAX_DATAGRAM];
        let ready = loop {
            tokio::select! {
                () = &mut *shutdown => {
                    supervisor.stop(&self.config).await?;
                    return Ok(Wake::Shutdown);
                }
                // Rebuilt after every datagram below. Its boot deadline is absolute, so
                // a client retrying its Initial cannot keep a hung backend alive.
                result = supervisor.wait_until_ready(&self.config) => break result,
                received = public.recv_from(&mut buf) => {
                    match received {
                        Ok((len, from)) => tracing::debug!(
                            %from,
                            bytes = len,
                            "dropping a datagram while the backend boots"
                        ),
                        Err(e) => tracing::debug!(error = %e, "public socket read failed"),
                    }
                }
            }
        };

        match ready {
            Ok(()) => Ok(Wake::Running(Box::new(supervisor))),
            Err(e) => {
                tracing::error!(error = %e, "backend failed to start");
                supervisor.stop(&self.config).await?;
                Ok(Wake::Failed)
            }
        }
    }

    /// Relay traffic until the server goes idle, dies, or the proxy is shut down.
    async fn serve(
        &self,
        public: &Arc<UdpSocket>,
        mut supervisor: Supervisor,
        shutdown: &mut std::pin::Pin<&mut impl Future<Output = ()>>,
    ) -> Result<Stop> {
        let relay = Arc::new(Relay::new(
            Arc::clone(public),
            self.config.backend,
            self.config.session_timeout,
        ));
        tracing::info!(backend = %self.config.backend, "running");

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

        let outcome = self.watch(&relay, &mut supervisor, shutdown).await;

        stop.store(true, Ordering::Relaxed);
        pump.abort();
        let _ = pump.await;
        relay.clear().await;

        supervisor.stop(&self.config).await?;
        outcome
    }

    /// Poll for idle shutdown, backend death, or proxy shutdown.
    async fn watch(
        &self,
        relay: &Relay,
        supervisor: &mut Supervisor,
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

            if supervisor.has_exited()? {
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
    // Boxed: a `Supervisor` dwarfs the other two variants, and this is built once per wake.
    Running(Box<Supervisor>),
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
