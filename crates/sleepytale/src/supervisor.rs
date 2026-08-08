//! Owns the Hytale server child process.
//!
//! Readiness comes from the server's own boot banner rather than from probing the port.
//! `HytaleServer.java:517` logs `"Hytale Server Booted! [tags] took ..."` once every
//! module is up and the transport is bound, which is exactly the moment relaying becomes
//! safe. Probing the UDP port would report ready far too early — QUIC binds before the
//! world finishes loading.

use crate::config::Config;
use crate::console::ConsoleInput;
use anyhow::{Context, Result, bail};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStdout, Command};
use tokio::sync::Notify;
use tokio::time::{Instant, timeout, timeout_at};

/// Substring of the server's boot banner. Matching a substring rather than the whole
/// line keeps this working through the ANSI colour codes the server prefixes.
const BOOT_MARKER: &str = "Hytale Server Booted!";

pub struct Supervisor {
    child: Child,
    booted: Arc<AtomicBool>,
    boot_notify: Arc<Notify>,
    console: Option<Arc<ConsoleInput>>,
    started_at: Instant,
}

impl Supervisor {
    /// Spawn the server and start pumping its output into tracing.
    ///
    /// Returns as soon as the process exists; call [`wait_until_ready`] to wait for the
    /// boot banner. `console`, when present, forwards the proxy's terminal input to the
    /// server console for the lifetime of this child.
    pub async fn spawn(config: &Config, console: Option<Arc<ConsoleInput>>) -> Result<Self> {
        let args = config.server_args();
        tracing::info!(
            command = %config.server.command,
            args = ?args,
            dir = %config.server.working_dir.display(),
            "starting backend"
        );

        let mut command = Command::new(&config.server.command);
        command
            .args(&args)
            .current_dir(&config.server.working_dir)
            .stdin(match console.is_some() {
                true => Stdio::piped(),
                false => Stdio::null(),
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // The child must not outlive an abrupt proxy exit holding the backend port.
            .kill_on_drop(true);

        // The proxy, not Java, owns Ctrl-C. Without a separate process group the
        // terminal delivers SIGINT to both, which can leave Java half-shut-down while
        // the proxy is also trying to supervise it.
        #[cfg(unix)]
        command.process_group(0);

        let mut child = command
            .spawn()
            .with_context(|| format!("spawning `{}`", config.server.command))?;

        let booted = Arc::new(AtomicBool::new(false));
        let boot_notify = Arc::new(Notify::new());

        let stdout = child.stdout.take().context("child stdout was not piped")?;
        mirror_stdout(stdout, Arc::clone(&booted), Arc::clone(&boot_notify));

        let stderr = child.stderr.take().context("child stderr was not piped")?;
        tokio::spawn(async move {
            let mut stderr = stderr;
            let mut terminal = tokio::io::stderr();
            if let Err(error) = tokio::io::copy(&mut stderr, &mut terminal).await {
                tracing::debug!(%error, "stopped mirroring backend stderr");
            }
        });

        if let (Some(console), Some(stdin)) = (&console, child.stdin.take()) {
            console.attach(stdin).await;
        }

        Ok(Self {
            child,
            booted,
            boot_notify,
            console,
            started_at: Instant::now(),
        })
    }

    /// Wait for the boot banner, the process to die, or `boot_timeout`.
    ///
    /// The deadline is absolute — `boot_timeout` after the child was spawned, not after
    /// this call. The caller races this future against its socket reads and rebuilds it
    /// on every datagram, so a relative timeout would be restarted by each retrying
    /// client and a backend that hangs during boot would never be given up on.
    pub async fn wait_until_ready(&mut self, config: &Config) -> Result<()> {
        if self.booted.load(Ordering::Acquire) {
            return Ok(());
        }

        // Check the flag again after registering, so a banner between the first check
        // and `notified` cannot be missed.
        let booted = self.boot_notify.notified();
        tokio::pin!(booted);
        if self.booted.load(Ordering::Acquire) {
            return Ok(());
        }

        let outcome = timeout_at(self.started_at + config.boot_timeout, async {
            tokio::select! {
                () = &mut booted => Ok(()),
                status = self.child.wait() => match status {
                    Ok(status) => bail!("backend exited during startup with {status}"),
                    Err(e) => Err(anyhow::Error::from(e).context("waiting on backend")),
                },
            }
        })
        .await;

        match outcome {
            Ok(result) => result?,
            Err(_) => bail!(
                "backend did not report `{BOOT_MARKER}` within {:?}",
                config.boot_timeout
            ),
        }

        tracing::info!(took = ?self.started_at.elapsed(), "backend ready");
        Ok(())
    }

    /// Has the process already exited?
    pub fn has_exited(&mut self) -> Result<bool> {
        self.child
            .try_wait()
            .context("checking backend status")
            .map(|status| status.is_some())
    }

    /// Ask the backend to stop, then kill it if it overstays `shutdown_grace`.
    ///
    /// The server flushes worlds to disk on SIGTERM, so the grace period matters —
    /// killing early risks losing recent chunk writes.
    pub async fn stop(mut self, config: &Config) -> Result<()> {
        if let Some(console) = self.console.take() {
            console.detach().await;
        }
        if self
            .child
            .try_wait()
            .context("checking backend status before shutdown")?
            .is_some()
        {
            tracing::debug!("backend already exited");
            return Ok(());
        }
        let Some(pid) = self.child.id() else {
            tracing::debug!("backend already exited");
            return Ok(());
        };

        tracing::info!(pid, "stopping backend");
        signal_terminate(pid)?;

        match timeout(config.shutdown_grace, self.child.wait()).await {
            Ok(Ok(status)) => {
                tracing::info!(%status, "backend stopped");
            }
            Ok(Err(e)) => return Err(anyhow::Error::from(e).context("waiting on backend")),
            Err(_) => {
                tracing::warn!(
                    grace = ?config.shutdown_grace,
                    "backend ignored the stop request; killing"
                );
                kill_backend(&mut self.child, pid).await?;
            }
        }
        Ok(())
    }
}

/// Mirror the server's stdout byte-for-byte while scanning its output for readiness.
fn mirror_stdout(stdout: ChildStdout, booted: Arc<AtomicBool>, boot_notify: Arc<Notify>) {
    tokio::spawn(async move {
        let mut stdout = stdout;
        let mut terminal = tokio::io::stdout();
        let mut buf = [0_u8; 8192];
        let mut tail = Vec::with_capacity(BOOT_MARKER.len());

        loop {
            let count = match stdout.read(&mut buf).await {
                Ok(0) => return,
                Ok(count) => count,
                Err(error) => {
                    tracing::debug!(%error, "stopped mirroring backend stdout");
                    return;
                }
            };

            if let Err(error) = terminal.write_all(&buf[..count]).await {
                tracing::debug!(%error, "stopped writing backend stdout to the terminal");
                return;
            }

            tail.extend_from_slice(&buf[..count]);
            if tail
                .windows(BOOT_MARKER.len())
                .any(|window| window == BOOT_MARKER.as_bytes())
                && !booted.swap(true, Ordering::AcqRel)
            {
                boot_notify.notify_waiters();
            }
            let keep = BOOT_MARKER.len().saturating_sub(1);
            if tail.len() > keep {
                tail.drain(..tail.len() - keep);
            }
        }
    });
}

#[cfg(unix)]
fn signal_terminate(pid: u32) -> Result<()> {
    // SIGTERM lets the server run its shutdown hook and flush worlds; tokio's `kill()`
    // sends SIGKILL, which would not.
    signal_group(pid, libc::SIGTERM)
}

/// Signal the backend's whole process group.
///
/// `spawn` puts the child in a new group, so with the usual `sh -c "... java ..."`
/// launcher the shell is the group leader and the JVM is a member of it. Signalling the
/// leader alone leaves the JVM running and still holding the backend port, so the next
/// wake fails to bind. The negative pid reaches every member; it is the child's own pgid
/// because `process_group(0)` made it the leader.
#[cfg(unix)]
fn signal_group(pid: u32, signal: libc::c_int) -> Result<()> {
    // SAFETY: `pid` comes directly from `tokio::process::Child::id`; kill has no
    // memory-safety preconditions. Its return value is checked below.
    let result = unsafe { libc::kill(-(pid as libc::pid_t), signal) };
    if result == -1 {
        let error = std::io::Error::last_os_error();
        // ESRCH means the group is already gone, which is the outcome we wanted.
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error).context("signalling the backend process group");
        }
    }
    Ok(())
}

#[cfg(unix)]
async fn kill_backend(child: &mut Child, pid: u32) -> Result<()> {
    // Same reason as SIGTERM: `child.kill()` would only reach the group leader.
    signal_group(pid, libc::SIGKILL)?;
    child.wait().await.context("reaping the killed backend")?;
    Ok(())
}

#[cfg(not(unix))]
fn signal_terminate(_pid: u32) -> Result<()> {
    // Windows has no SIGTERM equivalent for a non-console child; `stop` falls through to
    // the grace timeout and then kills.
    Ok(())
}

#[cfg(not(unix))]
async fn kill_backend(child: &mut Child, _pid: u32) -> Result<()> {
    child.kill().await.context("killing backend")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::Duration;

    fn shell_config(script: &str) -> Config {
        let mut config = Config::default();
        config.server.command = "sh".to_string();
        config.server.args = vec!["-c".to_string(), script.to_string()];
        config.server.working_dir = PathBuf::from(".");
        config.server.forward_stdin = false;
        config.boot_timeout = Duration::from_secs(5);
        config.shutdown_grace = Duration::from_secs(2);
        config
    }

    #[tokio::test]
    async fn detects_the_boot_banner() {
        // `-b <addr>` is appended by server_args and ignored by the shell script.
        let config = shell_config(
            "echo starting; echo '\\033[32m         Hytale Server Booted! [x] took 1s'; sleep 30",
        );
        let mut supervisor = Supervisor::spawn(&config, None).await.unwrap();
        supervisor.wait_until_ready(&config).await.unwrap();
        supervisor.stop(&config).await.unwrap();
    }

    #[tokio::test]
    async fn reports_a_backend_that_dies_while_starting() {
        let config = shell_config("echo loading; exit 3");
        let mut supervisor = Supervisor::spawn(&config, None).await.unwrap();
        let err = supervisor.wait_until_ready(&config).await.unwrap_err();
        assert!(
            err.to_string().contains("exited during startup"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn times_out_when_the_banner_never_arrives() {
        let mut config = shell_config("sleep 30");
        config.boot_timeout = Duration::from_millis(300);
        let mut supervisor = Supervisor::spawn(&config, None).await.unwrap();
        let err = supervisor.wait_until_ready(&config).await.unwrap_err();
        assert!(err.to_string().contains("did not report"), "{err}");
    }

    #[tokio::test]
    async fn kills_a_backend_that_ignores_sigterm() {
        let mut config = shell_config("trap '' TERM; echo 'Hytale Server Booted!'; sleep 30");
        config.shutdown_grace = Duration::from_millis(300);
        let mut supervisor = Supervisor::spawn(&config, None).await.unwrap();
        supervisor.wait_until_ready(&config).await.unwrap();
        supervisor.stop(&config).await.unwrap();
    }

    /// A launcher script that spawns the real server is the normal setup, so stopping
    /// must reach the grandchild — otherwise it keeps holding the backend port.
    #[cfg(unix)]
    #[tokio::test]
    async fn stopping_reaches_a_grandchild_of_the_launcher() {
        let pidfile =
            std::env::temp_dir().join(format!("sleepytale-grandchild-{}", std::process::id()));
        let _ = std::fs::remove_file(&pidfile);
        let mut config = shell_config(&format!(
            "trap '' TERM; sleep 30 & echo $! > {}; echo 'Hytale Server Booted!'; wait",
            pidfile.display()
        ));
        config.shutdown_grace = Duration::from_millis(300);

        let mut supervisor = Supervisor::spawn(&config, None).await.unwrap();
        supervisor.wait_until_ready(&config).await.unwrap();
        let grandchild: i32 = std::fs::read_to_string(&pidfile)
            .expect("the launcher did not record its child's pid")
            .trim()
            .parse()
            .unwrap();
        assert!(
            alive(grandchild),
            "the grandchild was not running to begin with"
        );

        supervisor.stop(&config).await.unwrap();
        let _ = std::fs::remove_file(&pidfile);

        for _ in 0..40 {
            if !alive(grandchild) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        // Do not leave it behind for the next run if the assertion is about to fail.
        unsafe { libc::kill(grandchild, libc::SIGKILL) };
        panic!("grandchild {grandchild} survived the backend shutdown");
    }

    #[cfg(unix)]
    fn alive(pid: i32) -> bool {
        // SAFETY: signal 0 performs the permission and existence checks without
        // delivering anything; kill has no memory-safety preconditions.
        unsafe { libc::kill(pid, 0) == 0 }
    }
}
