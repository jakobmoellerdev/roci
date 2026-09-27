//! End-to-end test running the real `roci` binary.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::time::Duration;

fn roci_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_roci"))
}

#[test]
fn binary_serves_v2_then_shuts_down_on_sigint() {
    let bin = roci_bin();
    assert!(bin.exists(), "roci binary not found at {}", bin.display());
    let storage = tempfile::tempdir().unwrap();
    let port = 5599;
    let mut child = Command::new(&bin)
        .arg("--listen")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--storage-root")
        .arg(storage.path())
        .spawn()
        .expect("spawn roci");

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

    #[cfg(unix)]
    {
        let pid = child.id() as i32;
        // Use `kill` command to avoid unsafe libc call.
        let _ = Command::new("kill")
            .arg("-INT")
            .arg(pid.to_string())
            .status();
    }
    let _ = child.wait();
}
