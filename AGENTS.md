## Rust quality (agents)

Use Microsoft's [Pragmatic Rust Guidelines](https://microsoft.github.io/rust-guidelines/) as a quality reference. The [condensed agent pack](https://microsoft.github.io/rust-guidelines/agents/all.txt) is available for deep Rust API, FFI, or unsafe refactors; attaching it is optional, not required for every task.

Prioritize, in order:
1. Unsafe code and correctness.
2. Hot-path performance.
3. Avoid AI anti-patterns: one implementation path, no meta-design docs in user-facing docs, and no tautological tests.