//! Infrastructure adapter layer.
//!
//! The proxy does not care whether the Hytale backend is a local process, a Docker
//! container, a Kubernetes pod, or a UDP service in the cloud. It only needs to:
//!
//! 1. start the backend,
//! 2. wait for a readiness signal (the Hytale boot banner),
//! 3. notice when it has exited,
//! 4. stop it cleanly.
//!
//! Each provider implements [`Backend`]. The rest of the proxy talks to backends through
//! that trait, not through process-specific APIs.

use anyhow::Result;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;

use crate::config::{BackendProvider, Config};
use crate::infra::console::ConsoleInput;

pub mod console;
pub mod process;

/// Alias for an owned, pinned, `Send` future returned by a backend method.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Provider-agnostic handle to a running Hytale backend.
///
/// The trait is object-safe so the proxy state machine can hold `Box<dyn Backend>`
/// without knowing which provider is in use. Methods return pinned boxed futures
/// rather than `async fn` because native async-in-trait is not object-safe.
pub trait Backend: Send {
    /// Begin starting the backend (spawn a process, create a container, scale a
    /// deployment, etc.).
    ///
    /// On success returns the absolute deadline by which the backend must report
    /// readiness. The caller passes this same deadline to [`wait_until_ready`].
    fn start<'a>(&'a mut self) -> BoxFuture<'a, Result<Instant>>;

    /// Wait for the backend to be ready to receive traffic, or for `deadline` to pass.
    fn wait_until_ready<'a>(
        &'a mut self,
        deadline: Instant,
    ) -> BoxFuture<'a, Result<()>>;

    /// Has the backend already exited?
    fn has_exited(&mut self) -> Result<bool>;

    /// Stop the backend cleanly.
    fn stop<'a>(&'a mut self) -> BoxFuture<'a, Result<()>>;
}

/// Build the configured backend adapter.
///
/// Today only the local-process provider exists; this is the seam where Docker,
/// Kubernetes, and cloud providers will be selected from configuration.
pub fn create_backend(
    config: &Config,
    console: Option<Arc<ConsoleInput>>,
) -> Result<Box<dyn Backend>> {
    match config.server.provider {
        BackendProvider::Process => Ok(Box::new(process::ProcessBackend::new(config, console)?)),
    }
}
