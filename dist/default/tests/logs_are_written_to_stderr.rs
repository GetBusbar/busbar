// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Busbar's log stream is stderr, always, as in 1.5.5: a server serving HTTP (no plane in stdio line
//! mode) writes its log lines to stderr and nothing at all to stdout, so stdout stays free for a
//! plane that serves its protocol there (`--mcp-stdio`, whose stdout `mcp_stdio_serve` pins).

#![cfg(unix)]

mod common;

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn a_serving_gateway_logs_to_stderr_and_writes_nothing_to_stdout() {
    let dir = std::env::temp_dir().join(format!("busbar-log-stream-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let data_port = common::boot::free_port();
    let admin_port = common::boot::free_port();
    std::fs::write(dir.join("providers.yaml"), "{}\n").unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            "listen: \"127.0.0.1:{data_port}\"\nadmin_listen: \"127.0.0.1:{admin_port}\"\n\
             store: {{module: memory}}\nadmin_require_mtls: false\nauth:\n  chain: []\nproviders: {{}}\nmodels: {{}}\n"
        ),
    )
    .unwrap();

    let stdout_path = dir.join("stdout.log");
    let stderr_path = dir.join("stderr.log");
    let mut child = Command::new(common::boot::exe())
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .env("RUST_LOG", "info")
        .stdin(Stdio::null())
        .stdout(std::fs::File::create(&stdout_path).unwrap())
        .stderr(std::fs::File::create(&stderr_path).unwrap())
        .spawn()
        .expect("spawn busbar");
    let read = |path: &std::path::Path| std::fs::read_to_string(path).unwrap_or_default();

    let deadline = Instant::now() + Duration::from_secs(30);
    while !common::boot::log_shows_data_and_admin_listening(&read(&stderr_path)) {
        if let Some(status) = child.try_wait().expect("try_wait") {
            panic!(
                "busbar exited before listening (status {status:?});\nstdout:\n{}\nstderr:\n{}",
                read(&stdout_path),
                read(&stderr_path)
            );
        }
        assert!(
            Instant::now() < deadline,
            "the boot log lines must reach stderr within 30s;\nstdout:\n{}\nstderr:\n{}",
            read(&stdout_path),
            read(&stderr_path)
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();

    let (stdout, stderr) = (read(&stdout_path), read(&stderr_path));
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        stderr.contains("busbar starting"),
        "the log stream is stderr: {stderr}"
    );
    assert!(
        stdout.is_empty(),
        "logging writes nothing to stdout, got:\n{stdout}"
    );
}
