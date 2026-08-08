//! sleepytale — runs a Hytale server only while someone is playing.
//!
//! The proxy owns the public port. While the server is down it stays silent and boots the
//! backend on the first connection attempt; the client's own retry then lands on the
//! running server. Once up it relays raw UDP, so QUIC and mTLS run end-to-end and
//! `--auth-mode=authenticated` is unaffected.

mod config;
mod console;
mod knock;
mod relay;
mod state;
mod supervisor;

use anyhow::{Context, Result};
use clap::Parser;
use config::Config;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "sleepytale", about, version)]
struct Cli {
    /// Configuration file. Falls back to built-in defaults when omitted.
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Print the effective configuration as TOML and exit.
    #[arg(long)]
    print_config: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "sleepytale=info,backend=info".into()),
        )
        .init();

    let cli = Cli::parse();
    let config = match &cli.config {
        Some(path) => Config::load(path)?,
        None => {
            let config = Config::default();
            config.validate()?;
            config
        }
    };

    if cli.print_config {
        print!(
            "{}",
            toml::to_string_pretty(&config).context("rendering config")?
        );
        return Ok(());
    }

    tracing::info!(
        listen = %config.listen,
        backend = %config.backend,
        idle_timeout = ?config.idle_timeout,
        "sleepytale starting"
    );

    state::Proxy::new(config).run(shutdown_signal()).await
}

/// Resolves on Ctrl-C, or SIGTERM when a service manager stops us.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(term) => term,
            Err(e) => {
                tracing::error!(error = %e, "cannot listen for SIGTERM");
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
    tracing::info!("shutting down");
}
