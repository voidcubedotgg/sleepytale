# sleepytale

Runs a Hytale server only while someone is playing.

sleepytale owns the public UDP port. While the server is down it stays silent; the first
QUIC Initial from a client boots the backend, and the client's own retry lands on the
running server. Once up it relays raw UDP, so QUIC and mTLS run end-to-end and
`--auth-mode=authenticated` is unaffected. After `idle_timeout` with no sessions, the
backend is stopped and the port goes quiet again.

```
Sleeping   public socket is quiet; a QUIC Initial starts the backend
Waking     datagrams are dropped while the backend boots; the client retries
Running    datagrams are relayed to the backend
```

## Usage

```sh
cargo build --release
./target/release/sleepytale --config dev.toml
```

`--print-config` prints the effective configuration as TOML and exits. Logging follows
`RUST_LOG` (default `sleepytale=info,backend=info`); the backend's stdout is mirrored
byte-for-byte.

## Configuration

All keys are optional; durations are plain seconds.

| Key | Default | Meaning |
| --- | --- | --- |
| `listen` | `[::]:5520` | Address players connect to. Unspecified IPv6 also serves IPv4 clients. |
| `backend` | `127.0.0.1:5521` | Address the server binds. Must differ from `listen`; keep it on loopback. |
| `idle_timeout` | `900` | Stop the backend after this long with no active sessions. |
| `boot_timeout` | `300` | Give up waking if the boot banner has not appeared. |
| `session_timeout` | `90` | Drop a relay session after this long without a datagram. Must exceed the server's `maxIdleTimeout`. |
| `shutdown_grace` | `10` | Time the backend gets to exit on SIGTERM before it is killed. |
| `server.command` | `java` | Program to run. |
| `server.args` | `["-jar", "HytaleServer.jar"]` | Arguments; `-b <backend>` is appended. |
| `server.working_dir` | `.` | Working directory for the child process. |
| `server.forward_stdin` | `true` | Forward this process's stdin to the server console. |

```toml
idle_timeout = 30

[server]
command = "java"
args = ["-Xmx8G", "-jar", "HytaleServer.jar", "--assets", "Assets.zip"]
working_dir = "./hytale"
```

Readiness comes from the server's own boot banner (`Hytale Server Booted!`), not from
probing the port.

## Releases

Tagging `v*` publishes static musl tarballs for `x86_64-unknown-linux-musl` and
`aarch64-unknown-linux-musl`. The binary has no runtime dependencies beyond the Java the
server itself needs.

## Player counting

Idle shutdown counts live QUIC connections, not decoded packets. The server sets
`activeMigration(false)`, so a client's address is stable for the life of its connection:
one source `SocketAddr` is one player, and the auxiliary Chunks/WorldMap/Voice channels are
extra streams on that same connection rather than new ones. Keep `session_timeout` above
the server's own `maxIdleTimeout` or quiet players are reaped early and undercounted.
