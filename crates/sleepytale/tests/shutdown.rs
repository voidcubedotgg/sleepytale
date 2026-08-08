//! Drives the real binary through a wake and stops it, asserting the process exits.

use std::io::Write;
use std::time::{Duration, Instant};

/// A minimal client Initial: enough for the proxy to recognise a connection attempt.
fn quic_initial() -> Vec<u8> {
    let mut datagram = vec![0u8; 1200];
    datagram[0] = 0xc3;
    datagram[1..5].copy_from_slice(&[0, 0, 0, 1]);
    datagram
}

/// The proxy must exit on SIGINT while relaying.
///
/// It once did not: console input was read through `tokio::io::stdin`, whose blocking read
/// outlives the runtime it was spawned from, so dropping the runtime waited for a key
/// press that never came.
///
/// The console input this test pushes through is deliberately larger than a pipe buffer.
/// The backend here never reads its stdin, so the forwarding write parks — and shutdown
/// begins by detaching the console, which once meant waiting on that same write.
#[tokio::test]
async fn stops_while_running_with_console_input_attached() {
    let binary = env!("CARGO_BIN_EXE_sleepytale");
    let scratch = tempfile::tempdir().expect("creating a scratch directory");
    let config_path = scratch.path().join("config.toml");
    // Port 0 is rejected by the config, so pick one that is unlikely to be taken.
    let listen = "127.0.0.1:57131";
    std::fs::write(
        &config_path,
        format!(
            r#"
listen = "{listen}"
backend = "127.0.0.1:57132"
boot_timeout = 30
[server]
command = "sh"
args = ["-c", "echo 'Hytale Server Booted!'; sleep 600"]
working_dir = "."
forward_stdin = true
"#
        ),
    )
    .unwrap();

    let mut proxy = std::process::Command::new(binary)
        .arg("-c")
        .arg(&config_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("starting the proxy");
    // Hold the write end open so the console reader stays parked in a blocking read.
    let mut proxy_stdin = proxy.stdin.take().unwrap();

    tokio::time::sleep(Duration::from_millis(500)).await;
    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(&quic_initial(), listen).await.unwrap();
    // Long enough for the fake backend to report its banner and the relay to take over.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Past any pipe buffer, so the forwarding write is still parked at SIGINT.
    proxy_stdin
        .write_all(&vec![b'\n'; 256 * 1024])
        .expect("the proxy stopped reading its own stdin");
    tokio::time::sleep(Duration::from_millis(200)).await;

    let pid = proxy.id() as i32;
    // SAFETY: `pid` is this process's own child and has not been reaped.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGINT) }, 0);

    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = proxy.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "the proxy did not exit within 10s of SIGINT"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert!(status.success(), "proxy exited with {status}");
}
