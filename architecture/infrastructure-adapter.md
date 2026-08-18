# Infrastructure adapter

The infrastructure adapter hides *how* the Hytale backend runs from the rest of
`sleepytale`. The proxy only cares that it can start the backend, wait for it to
be ready, notice when it exits, and stop it cleanly. Whether the backend is a
local process, a Docker container, a Kubernetes pod, or a cloud UDP service is a
provider detail.

## Responsibility boundary

The adapter owns everything on the *backend side* of the relay:

- provisioning the runtime resource,
- collecting readiness evidence (the `Hytale Server Booted!` banner),
- detecting unexpected exit,
- graceful shutdown.

It does **not** own:

- the public UDP socket,
- relaying datagrams,
- session management,
- idle-timeout logic.

Those stay in the proxy state machine so every provider shares the same
sleep/wake/running lifecycle.

## The `Backend` trait

All providers implement a single object-safe trait in `crates/sleepytale/src/infra/mod.rs`:

```rust
pub trait Backend: Send {
    fn start(&mut self) -> BoxFuture<Result<Instant>>;
    fn wait_until_ready(&mut self, deadline: Instant) -> BoxFuture<Result<()>>;
    fn has_exited(&mut self) -> Result<bool>;
    fn stop(&mut self) -> BoxFuture<Result<()>>;
}
```

Methods return pinned boxed futures rather than `async fn` so the trait remains
object-safe; the state machine stores `Box<dyn Backend>` and does not need to
know the concrete provider type.

### Lifecycle contract

1. **`start`** — begin provisioning. On success it returns an absolute
   `Instant` deadline by which the backend must become ready. The caller passes
   that same deadline back to `wait_until_ready`.
2. **`wait_until_ready`** — block until the backend reports readiness, the
   deadline expires, or the backend exits early. This is rebuilt on every
   incoming datagram during the `Waking` state, so the deadline must be absolute
   (not per-call) to prevent a retrying client from keeping a hung backend alive.
3. **`has_exited`** — cheap poll used in the `Running` state to detect that the
   backend died on its own.
4. **`stop`** — request shutdown and wait for the resource to disappear. For the
   process provider this means SIGTERM, a grace period, then SIGKILL to
   the whole process group.

## Current provider: process

`infra/process.rs` (`ProcessBackend`) runs the server as a local child process.
It keeps the existing behaviour:

- mirrors stdout/stderr to the terminal,
- scans stdout for `Hytale Server Booted!`,
- puts the child in its own process group so SIGINT does not reach both the
  proxy and the JVM,
- signals the whole process group on stop so launcher-shell grandchildren die
  too,
- optionally forwards the proxy's stdin to the server console via
  `infra/console.rs`.

Console forwarding lives under `infra/` because it is a process-specific
mechanism. A Docker provider would instead attach to the container's stdin; a
Kubernetes provider might use `kubectl exec` or not support interactive console
at all.

## Configuration seam

`config::BackendProvider` selects the adapter. Today it has one variant:

```rust
#[serde(rename_all = "snake_case")]
pub enum BackendProvider {
    Process,
}
```

The factory `infra::create_backend` matches on `config.server.provider` and
returns `Box<dyn Backend>`. Existing configs continue to work because the field
defaults to `"process"`.

```toml
[server]
provider = "process"
command = "java"
args = ["-jar", "HytaleServer.jar"]
```

## Adding a provider

To add Docker, Podman, Kubernetes, Fly.io, etc.:

1. Add a variant to `config::BackendProvider`.
2. Implement `Backend` in `infra/<provider>.rs`.
3. Add the match arm in `infra::create_backend`.
4. Update `README.md` and this document.

Provider-specific configuration should live in `ServerConfig` (or a future
`BackendConfig`) and be ignored by providers that do not use it. Keep the trait
surface small: if a provider cannot support console input, it simply does not
use `ConsoleInput`; if it cannot detect the boot banner from logs, it must
implement an equivalent readiness check that satisfies the same contract.

## Design notes

- **Object-safe trait with boxed futures** avoids a dependency on `async-trait`
  and keeps the state machine generic over `Box<dyn Backend>`.
- **`std::time::Instant` deadlines** keep the trait provider-agnostic; adapters
  convert to `tokio::time::Instant` only when calling Tokio timeouts internally.
- **`start` returns the deadline** rather than storing it inside the backend so
  the caller controls timeout semantics and the deadline is explicit at each
  `wait_until_ready` call.
- **No trait method for logs/streams** — log collection is an implementation
  detail. The process adapter scans stdout; a Kubernetes adapter would stream
  pod logs; a cloud adapter might poll an HTTP health endpoint. The only thing
  the proxy sees is `wait_until_ready` succeeding or failing.
