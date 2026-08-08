//! Blind UDP relay used while the backend is running.
//!
//! The proxy never decrypts anything here. QUIC and TLS terminate at the backend, so the
//! client's certificate is the one the server hashes for the `cnf.x5t#S256` binding and
//! `--auth-mode=authenticated` keeps working. Decoding the stream would require
//! terminating TLS, which would break exactly that.
//!
//! Sessions are keyed by the client's source address. That is sound because the server
//! disables QUIC connection migration (`QUICTransport.java:185`,
//! `.activeMigration(false)`), so a connection's address is stable for its lifetime.
//! One QUIC connection is one player — the Chunks, WorldMap and Voice channels are extra
//! streams on that same connection, not new connections.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::Instant;

/// QUIC datagrams stay under the path MTU; the server advertises 64000 as its maximum
/// UDP payload, so this covers anything it will send.
const MAX_DATAGRAM: usize = 64 * 1024;

struct Session {
    /// Socket dedicated to this client, so backend replies demultiplex by port.
    upstream: Arc<UdpSocket>,
    return_path: JoinHandle<()>,
    last_seen: Instant,
}

/// Relay state shared between the client-facing loop and the reaper.
pub struct Relay {
    public: Arc<UdpSocket>,
    backend: SocketAddr,
    session_timeout: std::time::Duration,
    sessions: Mutex<HashMap<SocketAddr, Session>>,
}

impl Relay {
    pub fn new(
        public: Arc<UdpSocket>,
        backend: SocketAddr,
        session_timeout: std::time::Duration,
    ) -> Self {
        Self {
            public,
            backend,
            session_timeout,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Number of live sessions — the proxy's estimate of the player count.
    ///
    /// An upper bound: a connection that fails authentication, or a scan that completes
    /// a QUIC handshake, counts until it times out. That can only delay an idle
    /// shutdown, never trigger one wrongly.
    #[cfg(test)]
    async fn session_count(&self) -> usize {
        self.sessions.lock().await.len()
    }

    /// Forward one datagram from a client, opening a session if this is a new address.
    pub async fn forward_to_backend(&self, from: SocketAddr, datagram: &[u8]) -> Result<()> {
        let upstream = self.session_for(from).await?;
        upstream
            .send_to(datagram, self.backend)
            .await
            .with_context(|| format!("relaying {} bytes to the backend", datagram.len()))?;
        Ok(())
    }

    async fn session_for(&self, client: SocketAddr) -> Result<Arc<UdpSocket>> {
        let mut sessions = self.sessions.lock().await;

        if let Some(session) = sessions.get_mut(&client) {
            session.last_seen = Instant::now();
            return Ok(Arc::clone(&session.upstream));
        }

        // Bind on the same family as the backend so send_to cannot fail on mismatch.
        let bind: SocketAddr = match self.backend {
            SocketAddr::V4(_) => ([0, 0, 0, 0], 0).into(),
            SocketAddr::V6(_) => (std::net::Ipv6Addr::UNSPECIFIED, 0).into(),
        };
        let upstream = Arc::new(
            UdpSocket::bind(bind)
                .await
                .context("binding an upstream socket for a new session")?,
        );

        tracing::info!(
            %client,
            upstream = %upstream.local_addr().map(|a| a.to_string()).unwrap_or_default(),
            sessions = sessions.len() + 1,
            "session opened"
        );

        let return_path = self.spawn_return_path(client, Arc::clone(&upstream));
        sessions.insert(
            client,
            Session {
                upstream: Arc::clone(&upstream),
                last_seen: Instant::now(),
                return_path,
            },
        );

        // The backend sees this ephemeral address rather than the player's real one, so
        // log the mapping — it is the only place the association survives.
        Ok(upstream)
    }

    /// Pump backend replies for one session back to its client.
    fn spawn_return_path(&self, client: SocketAddr, upstream: Arc<UdpSocket>) -> JoinHandle<()> {
        let public = Arc::clone(&self.public);
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DATAGRAM];
            loop {
                let len = match upstream.recv(&mut buf).await {
                    Ok(len) => len,
                    Err(e) => {
                        tracing::debug!(%client, error = %e, "upstream socket closed");
                        return;
                    }
                };
                if let Err(e) = public.send_to(&buf[..len], client).await {
                    tracing::debug!(%client, error = %e, "failed to reach client");
                    return;
                }
            }
        })
    }

    /// Drop sessions that have gone quiet. Returns how many remain.
    ///
    /// Closing the upstream socket ends its return-path task, since `recv` then fails.
    pub async fn reap_idle(&self) -> usize {
        let now = Instant::now();
        let mut sessions = self.sessions.lock().await;

        sessions.retain(|client, session| {
            let idle = now.duration_since(session.last_seen);
            if idle >= self.session_timeout {
                tracing::info!(%client, ?idle, "session expired");
                session.return_path.abort();
                false
            } else {
                true
            }
        });

        sessions.len()
    }

    /// Drop every session, e.g. when the backend is going away.
    pub async fn clear(&self) {
        let mut sessions = self.sessions.lock().await;
        if !sessions.is_empty() {
            tracing::info!(count = sessions.len(), "closing all sessions");
        }
        for session in sessions.values() {
            session.return_path.abort();
        }
        sessions.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    async fn any_socket() -> Arc<UdpSocket> {
        Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap())
    }

    #[tokio::test]
    async fn a_datagram_reaches_the_backend_and_the_reply_reaches_the_client() {
        let backend = any_socket().await;
        let backend_addr = backend.local_addr().unwrap();

        let public = any_socket().await;
        let public_addr = public.local_addr().unwrap();
        let relay = Relay::new(Arc::clone(&public), backend_addr, Duration::from_secs(30));

        // Stand in for a player.
        let client = any_socket().await;
        let client_addr = client.local_addr().unwrap();

        relay
            .forward_to_backend(client_addr, b"hello")
            .await
            .unwrap();

        let mut buf = [0u8; 64];
        let (len, from) = backend.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"hello");
        assert_ne!(
            from, client_addr,
            "the backend sees the proxy, not the client"
        );

        // Reply travels back down the same session.
        backend.send_to(b"world", from).await.unwrap();
        let (len, from) = client.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"world");
        assert_eq!(
            from, public_addr,
            "the client sees the proxy, not the backend"
        );
    }

    #[tokio::test]
    async fn two_clients_get_separate_sessions() {
        let backend = any_socket().await;
        let relay = Relay::new(
            any_socket().await,
            backend.local_addr().unwrap(),
            Duration::from_secs(30),
        );

        let a = any_socket().await.local_addr().unwrap();
        let b = any_socket().await.local_addr().unwrap();
        relay.forward_to_backend(a, b"a").await.unwrap();
        relay.forward_to_backend(b, b"b").await.unwrap();
        assert_eq!(relay.session_count().await, 2);

        // Repeat traffic reuses the session rather than opening another.
        relay.forward_to_backend(a, b"a again").await.unwrap();
        assert_eq!(relay.session_count().await, 2);
    }

    #[tokio::test]
    async fn quiet_sessions_are_reaped() {
        let backend = any_socket().await;
        let relay = Relay::new(
            any_socket().await,
            backend.local_addr().unwrap(),
            Duration::from_millis(50),
        );

        let client = any_socket().await.local_addr().unwrap();
        relay.forward_to_backend(client, b"x").await.unwrap();
        assert_eq!(relay.reap_idle().await, 1, "still fresh");

        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(relay.reap_idle().await, 0, "expired after the timeout");
        assert_eq!(relay.session_count().await, 0);
    }

    #[tokio::test]
    async fn traffic_keeps_a_session_alive() {
        let backend = any_socket().await;
        let relay = Relay::new(
            any_socket().await,
            backend.local_addr().unwrap(),
            Duration::from_millis(100),
        );
        let client = any_socket().await.local_addr().unwrap();

        for _ in 0..4 {
            relay.forward_to_backend(client, b"tick").await.unwrap();
            tokio::time::sleep(Duration::from_millis(40)).await;
            assert_eq!(relay.reap_idle().await, 1);
        }
    }

    #[tokio::test]
    async fn clear_drops_everything() {
        let backend = any_socket().await;
        let relay = Relay::new(
            any_socket().await,
            backend.local_addr().unwrap(),
            Duration::from_secs(30),
        );
        relay
            .forward_to_backend(any_socket().await.local_addr().unwrap(), b"x")
            .await
            .unwrap();
        relay.clear().await;
        assert_eq!(relay.session_count().await, 0);
    }
}
