# sleepytale — on-demand Hytale server proxy

## Context

Run a Hytale server only while someone is playing. A proxy owns the public port, wakes
the Java process when a player knocks, relays traffic while it runs, and shuts it down
once empty.

**Implemented and passing** (`cargo test --workspace`, strict Clippy):

- `crates/sleepytale` — the proxy: the three-state machine, the knock test, the relay, and
  the backend supervisor.

The generated protocol crates (`hytale-protocol`, `hytale-protocol-runtime`, the `xtask`
codegen, and the `tools/interop` harness) now live in their own repository. The proxy never
decoded a packet, so nothing here depended on them.

### The constraint that shapes this

The client's access token is bound to its mTLS certificate:
`CertificateUtil.validateCertificateBinding` compares `cnf.x5t#S256` against
SHA-256 of the cert on the server's own TLS connection
(`CoreServer/.../auth/JWTValidator.java:210`, `auth/CertificateUtil.java:52-83`).

**A proxy that terminates TLS and forwards credentials cannot pass this** — the server
would hash the proxy's certificate, not the client's, and the proxy never sees the
client's private key. Terminating and re-authenticating would mean the proxy becomes the
authenticated server and the backend drops to `--auth-mode=insecure`, which is a much
bigger change than this feature warrants.

So the proxy **must never terminate QUIC**. It relays raw UDP datagrams; the client's TLS
session runs end-to-end with the backend and `AUTHENTICATED` mode keeps working untouched.

### Why the proxy never answers a knock

It has no useful thing to say. `ServerDisconnect` is sent pre-auth
(`InitialPacketHandler.disconnect`, `io/handlers/InitialPacketHandler.java:72-79`), so the
proxy *can* send one — and client 0.5.7 does not render it. Measured against a build that
did: its `ServerDisconnect` bytes decode cleanly under the shipped Java codec (`id=2`,
`type=Disconnect`, reason intact, no trailing bytes); the client read it and closed the
connection itself 4ms later with application code 0, then showed
`QuicheException: Connection closed` on its loading screen instead of the reason. Nothing
sent over the wire changes that.

Completing the handshake and then staying quiet is worse: the client sits on the loading
screen indefinitely, because its retry is driven by a handshake timeout.

Silence is the one response it handles well. With no answer at all the client times out
after ten seconds and dials again — and its Initial retransmissions, which start about a
second in, reach the relay the moment the backend is ready. A boot faster than the
client's patience is therefore invisible: the player waits at "Connecting" and joins,
with nothing to click.

---

## Architecture

Three states over one public UDP socket (default `[::]:5520`, `HytaleServer.DEFAULT_PORT`).
The backend is spawned with `-b 127.0.0.1:5521` so the two never contend for the port.

```
Sleeping   socket is quiet; a datagram shaped like a QUIC Initial spawns the Java child
           anything else is ignored, so a departing player cannot wake the server

Waking     datagrams are dropped; the client retransmits and retries
           watch child stdout for "Hytale Server Booted!"

Running    datagrams are relayed to 127.0.0.1:5521, one ephemeral socket per client
           zero active sessions for `idle_timeout` -> stop the child, back to Sleeping
```

The socket is bound once for the whole run and never handed over, so there is no window
where the public address is unbound and no rebinding to lose a datagram to. What changes
between states is only what the proxy does with a datagram: ignore it, drop it, or relay
it.

The wake trigger is the shape of a QUIC v1 Initial: long header, packet type 0, version 1,
and the 1200-byte minimum a client Initial is padded to (`RFC 9000 §17.2.2`, `§14.1`). No
decryption, and nothing the proxy has to keep in sync with the protocol.

It binds an unspecified IPv6 address so one socket serves both families, matching the
server's own pair of channels (`QUICTransport`: "Using IPv4/IPv6 Datagram Channel"). A
v4-only bind costs every client that resolves the hostname to IPv6 first a full
ten-second handshake timeout before it falls back — visible in the client log as two
`Opening Quiche Connection` lines ten seconds apart.

If the backend cannot spawn, fails to boot, or exits unexpectedly, the proxy returns to
Sleeping instead of exiting, and the next connection attempt retries the wake.

---

## Crates

`crates/sleepytale` contains:

- `config.rs` — public bind addr, backend bind addr, java command + args, idle timeout,
  boot timeout, session timeout, shutdown grace, and console-input forwarding.
- `state.rs` — the three-state machine and sole owner of the public socket, which it binds
  dual-stack once and keeps for the process's lifetime.
- `knock.rs` — the QUIC Initial test that decides whether a datagram is worth waking for,
  and the reasoning for answering nothing.
- `relay.rs` — the Running-state datagram pump. Session table keyed by client
  `SocketAddr`; each session owns an ephemeral UDP socket toward the backend and a
  last-seen instant.
- `supervisor.rs` — spawns the Java child in its own Unix process group, mirrors its
  stdout/stderr to the proxy terminal, detects readiness by matching `Hytale Server Booted!`
  (`HytaleServer.java:517`), and stops it with SIGTERM then SIGKILL after a bounded grace
  period. Ctrl-C belongs to the proxy, not the Java child.
- `console.rs` — one terminal reader for the whole run, handing input to whichever backend
  is attached (for `/auth login` and other server commands). It reads on a plain OS thread:
  `tokio::io::stdin` blocks the runtime's blocking pool, and dropping a runtime waits for
  that read, so Ctrl-C used to leave the proxy parked until a key was pressed.

Deps: `tokio`, `socket2`, `tracing`, `serde`/`toml`, `clap`. The proxy speaks no protocol:
QUIC is encrypted end-to-end and it holds no keys, so decoding is not available to it and
nothing here has to be kept in sync with the game's packets.

### Why session count works as a player count

The server sets `activeMigration(false)` (`io/transport/QUICTransport.java:185`), so a
client's address is stable for the life of its connection — keying on the source
`SocketAddr` is sound. One QUIC connection is one player; the auxiliary Chunks/WorldMap/
Voice channels are extra *streams* on that same connection, not new connections.

Sessions expire on silence. The server's own `maxIdleTimeout` is the configured play
timeout, so the proxy's session TTL should sit just above it to avoid reaping live
connections.

---

## Known limitations, accepted

- **The backend sees `127.0.0.1:<ephemeral>`, not real client addresses.** Anything
  IP-based on the server (logging, IP bans, rate limiting) is blinded. The proxy logs the
  address mapping so it can be recovered out of band. This is inherent to relaying; the
  only fix is stepping out of the path, which needs a backend plugin for player counts.
- **Session count is an upper bound on players.** A connection that fails auth, or a port
  scan that completes a QUIC handshake, counts until it times out. It only ever delays a
  shutdown, never causes a wrongful one.
- **A cold start shows no explanation.** The player sees "Connecting" and, if the boot
  outruns the client's two attempts, its own "failed to connect" screen; clicking again
  works. The proxy cannot say why, because the client discards pre-auth disconnect
  reasons during loading.
- **Any QUIC Initial wakes the backend.** A scanner that sends one costs a boot. The
  alternative is speaking enough of the protocol to demand a valid `Connect`, which means
  completing a handshake the client would then hang on.

---

## Verification

1. **Automated, complete:** `cargo test --workspace` and
   `cargo clippy --workspace --all-targets -- -D warnings`. Coverage includes session
   expiry and allocation, relay round trips, Java boot/exit/timeout/shutdown behavior, the
   QUIC Initial test, an IPv4 client reaching the dual-stack socket, Ctrl-C-equivalent
   shutdown while Sleeping, and a SIGINT to the real binary while it is relaying with
   console input attached.
2. **Wake against a real client**: cold start, connect once with the real client, confirm
   the child process starts and that the client connects on its first attempt rather than
   after a ten-second IPv6 fallback.
3. **End-to-end wake**: cold start, connect, and confirm the player reaches the world
   without a manual retry while the boot fits inside the client's attempts. This is the check that proves relaying preserves
   `AUTHENTICATED` auth — if cert binding were broken, the join would fail with
   `invalidAccessToken` in the server log.
4. **Idle shutdown**: disconnect, confirm sessions drain and the child is stopped after
   `idle_timeout`, and that the proxy rebinds and can wake again.
5. **Two concurrent players**: confirm both relay independently and the count reaches 2.

---

## Out of scope

Inspecting or rewriting gameplay packets. The relay is deliberately blind — decoding the
stream would require terminating TLS, which breaks certificate binding. Should
packet-level features be wanted later, including a cold-start message the client actually
renders, that is the "proxy authenticates as the player / backend runs insecure"
architecture, and a separate decision.
