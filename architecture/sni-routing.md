# SNI routing

sleepytale can run several Hytale servers behind one public UDP address. Routing is
performed from the TLS `server_name` in the client's first QUIC Initial packet; no TLS
or QUIC endpoint is terminated at the proxy.

## Packet path

```text
client Initial
    │
    ▼
public UDP socket ──► decrypt QUIC Initial ──► read ClientHello server_name
                                                    │
                         no readable/matching name ─┴──► default backend
                                                    │
                                                    ▼
                                      configured BackendConfig
                                                    │
                                                    ▼
                                 infrastructure adapter lifecycle
                                                    │ ready
                                                    ▼
                             per-client upstream UDP socket ──► backend
```

QUIC Initial protection uses publicly derivable keys: the client's destination
connection ID plus the version-specific initial salt. `sni.rs` removes header
protection, authenticates and decrypts the Initial, reassembles its CRYPTO frames, and
reads the ClientHello `server_name` extension. It supports QUIC v1 and v2.

The packet is never modified. Once a session opens, its client source address is bound
to the selected backend. Every later datagram is opaque to the router and is relayed to
that same backend. This preserves Hytale's end-to-end QUIC, TLS, and mTLS behaviour.

## Fallback and failure behaviour

- An absent, malformed, fragmented, unrecognised-version, or unauthenticated Initial
  has no route name and uses the default backend.
- Route-name matching is case-insensitive and ignores one trailing dot.
- A sleeping route wakes only for a plausible QUIC v1 or v2 Initial. While it is waking,
  datagrams are dropped; the client retransmits its Initial after the backend is ready.
- A session remains pinned to its first route until it expires. An SNI change cannot
  move an existing connection.

This deliberately makes routing best-effort rather than blocking connections whose
ClientHello cannot fit in the first datagram. The default backend is the safe fallback.

## Route configuration and lifecycle

The top-level `backend` and `server` remain the default route. Each entry in `routes`
is a `BackendConfig`: a private bind address plus the same adapter fields as `server`.

```toml
[routes."creative.example.com"]
backend = "127.0.0.1:5531"
provider = "process"
command = "java"
args = ["-jar", "CreativeServer.jar"]
working_dir = "./creative"
forward_stdin = false
```

At startup the proxy creates one lifecycle slot per configured backend address. A route
transitions independently through `Sleeping`, `Waking`, and `Running`. Its
`BackendConfig` is passed to `infra::create_backend`, so process, container, or future
providers all share the router without router-specific provider logic. Each running
route is stopped after `idle_timeout` with no sessions routed to it.

Configuration rejects duplicate normalised route names, a route using the public listen
address, any backend address shared by the default route or another named route, and a
backend port of 0 — the server would bind an ephemeral port the proxy cannot forward to.
Since terminal input has one source, at most one configured backend may set
`forward_stdin = true`.

## Boundaries

The routing layer owns SNI parsing, choosing a backend configuration, and preserving a
session's selection. The relay owns UDP forwarding and session expiry. Infrastructure
adapters own provisioning, readiness, exit detection, and shutdown for the selected
backend. Keeping those boundaries separate lets a future adapter change how a backend
runs without changing packet handling.
