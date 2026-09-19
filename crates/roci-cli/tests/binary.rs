//! Integration test that runs the real `roci` binary so the `#[tokio::main]`
//! entrypoint (`main` → `run` → `serve`) is exercised end to end. Under
//! `cargo llvm-cov`, the binary is instrumented and this child process's
//! coverage merges into the report.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::time::Duration;

/// Locate the compiled `roci` binary. Cargo sets `CARGO_BIN_EXE_roci` for
/// integration tests of the crate that defines the binary, pointing at the
/// instrumented binary under `cargo llvm-cov`.
fn roci_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_roci"))
}

#[test]
fn binary_serves_v2_then_shuts_down_on_sigint() {
    let bin = roci_bin();
    assert!(bin.exists(), "roci binary not found at {}", bin.display());
    let storage = tempfile::tempdir().unwrap();
    // Use a fixed loopback port unlikely to collide in CI.
    let port = 5599;
    let mut child = Command::new(&bin)
        .arg("--listen")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--storage-root")
        .arg(storage.path())
        .spawn()
        .expect("spawn roci");

    // Poll /v2/ until the server answers.
    let addr = format!("127.0.0.1:{port}");
    let mut ready = false;
    for _ in 0..50 {
        if let Ok(mut s) = TcpStream::connect(&addr) {
            let _ = s.write_all(b"GET /v2/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
            let mut buf = String::new();
            let _ = s.read_to_string(&mut buf);
            if buf.contains("200") {
                ready = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(ready, "roci did not answer /v2/ with 200");

    // Graceful shutdown via SIGINT so main()/run()/serve() return Ok(()).
    #[cfg(unix)]
    {
        let pid = child.id() as i32;
        // SAFETY-free: use the `kill` command to avoid an unsafe libc call
        // (crates here are #![forbid(unsafe_code)]).
        let _ = Command::new("kill")
            .arg("-INT")
            .arg(pid.to_string())
            .status();
    }
    let _ = child.wait();
}
