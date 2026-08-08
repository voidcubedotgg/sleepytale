//! Forwards the proxy's own console input to whichever backend is currently running.
//!
//! The read happens on a plain OS thread rather than through `tokio::io::stdin`. Tokio
//! runs that read on its blocking pool, and dropping the runtime waits for outstanding
//! blocking work — so once a backend had been started, Ctrl-C left the proxy parked in a
//! terminal read until someone pressed Enter. A detached thread is simply abandoned when
//! the process exits.
//!
//! One reader serves every wake cycle: two readers would race for the same terminal, and
//! each backend only lives for part of the proxy's lifetime.

use anyhow::{Context, Result};
use std::io::Read;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::process::ChildStdin;
use tokio::sync::{Mutex, mpsc};

pub struct ConsoleInput {
    /// Standard input of the backend that is running right now, if any.
    current: Arc<Mutex<Attached>>,
}

/// The attached backend, plus a counter that changes on every attach and detach.
///
/// The forwarding task takes the pipe out of the mutex for the duration of a write, so
/// [`detach`](ConsoleInput::detach) never has to wait on one. The counter tells the task
/// whether the backend it borrowed is still the current one when it puts the pipe back.
#[derive(Default)]
struct Attached {
    stdin: Option<ChildStdin>,
    generation: u64,
}

impl Attached {
    fn replace(&mut self, stdin: Option<ChildStdin>) {
        self.stdin = stdin;
        self.generation = self.generation.wrapping_add(1);
    }
}

impl ConsoleInput {
    /// Start reading the terminal. Input is discarded until a backend is attached.
    pub fn start() -> Result<Self> {
        let current: Arc<Mutex<Attached>> = Arc::new(Mutex::new(Attached::default()));
        let (lines, mut incoming) = mpsc::unbounded_channel::<Vec<u8>>();

        std::thread::Builder::new()
            .name("console-input".to_string())
            .spawn(move || {
                let mut terminal = std::io::stdin().lock();
                let mut buf = [0_u8; 4096];
                loop {
                    match terminal.read(&mut buf) {
                        Ok(0) => return,
                        Ok(count) => {
                            if lines.send(buf[..count].to_vec()).is_err() {
                                return;
                            }
                        }
                        Err(error) => {
                            tracing::debug!(%error, "stopped reading proxy stdin");
                            return;
                        }
                    }
                }
            })
            .context("spawning the console input thread")?;

        let target = Arc::clone(&current);
        tokio::spawn(async move {
            while let Some(chunk) = incoming.recv().await {
                // The pipe leaves the mutex for the write. A backend that has stopped
                // draining its stdin blocks `write_all` until the pipe drains — holding
                // the lock across that would block `detach`, which shutdown calls before
                // it signals the child, deadlocking the two against each other.
                let (Some(mut stdin), generation) = ({
                    let mut backend = target.lock().await;
                    (backend.stdin.take(), backend.generation)
                }) else {
                    continue;
                };

                let outcome = stdin.write_all(&chunk).await;

                let mut backend = target.lock().await;
                if backend.generation != generation {
                    // Detached or re-attached while we were writing; the pipe we hold is
                    // stale, so dropping it is what closes the old backend's end.
                    continue;
                }
                match outcome {
                    Ok(()) => backend.stdin = Some(stdin),
                    Err(error) => {
                        tracing::debug!(%error, "stopped forwarding console input to the backend");
                    }
                }
            }
        });

        Ok(Self { current })
    }

    /// Send subsequent console input to this backend.
    pub async fn attach(&self, stdin: ChildStdin) {
        self.current.lock().await.replace(Some(stdin));
    }

    /// Stop forwarding, closing the backend's end of the pipe.
    pub async fn detach(&self) {
        self.current.lock().await.replace(None);
    }
}
