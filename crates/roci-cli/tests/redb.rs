//! Quick smoke test that the `--features redb` build accepts
//! `storage.metadata.engine = "redb"` and starts serving.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::time::Duration;

fn roci_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_roci"))
}

#[test]
fn redb_engine_starts() {
    let bin = roci_bin();
    assert!(bin.exists(), "roci binary not found at {}", bin.display());
    let storage = tempfile::tempdir().unwrap();
    let config_dir = tempfile::tempdir().unwrap();
    let config_path = config_dir.path().join("roci.toml");

    let port = 5598;
    std::fs::write(
        &config_path,
        format!(
            r#"
[http]
listen = "127.0.0.1:{port}"

[storage]
root = "{root}"

[storage.metadata]
engine = "redb"
"#,
            root = storage.path().display(),
        ),
    )
    .unwrap();

    let mut child = Command::new(&bin)
        .arg("--config")
        .arg(&config_path)
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

    // Shut it down
    #[cfg(unix)]
    {
        let pid = child.id() as i32;
        let _ = Command::new("kill")
            .arg("-INT")
            .arg(pid.to_string())
            .status();
    }
    let _ = child.wait();

    assert!(ready, "roci with engine=redb did not answer /v2/ with 200");

    // Verify the redb file was created
    assert!(
        storage.path().join("roci-meta.redb").exists(),
        "roci-meta.redb should have been created"
    );
}
