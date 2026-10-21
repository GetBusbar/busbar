// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! EXACTLY ONE PROBER PER MEMBER, proven on the real binary (status row 83, PR 4a; BUSBAR-1.6.0.md
//! l.1189, F23 l.4641, B item 14): a provider configured `health: { mode: active, interval_secs: 1 }`
//! is probed once per tick by the kernel's probe unit on the provider-pool door's sealed egress
//! (`root::serve::arm_probes`), as 1.5.5's one health loop probed each lane once per interval. A
//! second prober (the retired engine's `spawn_probers` running beside the kernel's) doubles the
//! count, and no prober at all leaves it at zero; this cell reads both failures.
//!
//! The count is of WORK, not of time: the upstream counts the probe requests it receives, and the
//! window is many ticks long, so a slow tick costs a probe at the low end and never invents one at
//! the high end.
#![cfg(unix)]
// Needs the plane that serves the `pools` map: a build without it has no member to probe.
#![cfg(linked_section_pools)]

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The configured probe interval, in seconds.
const INTERVAL_SECS: u64 = 1;
/// The probed member's catalog entry, `{upstream_port}` and `{interval_secs}` filled in per run.
const PROVIDERS: &str = include_str!("../../../testing/root-fixtures/health-probe-providers.yaml");
/// The counting window, in ticks of [`INTERVAL_SECS`].
const WINDOW_TICKS: u64 = 6;

#[test]
fn an_active_member_is_probed_once_per_tick() {
    let dir = fixture_dir();
    let probes = Arc::new(AtomicUsize::new(0));
    let upstream_port = spawn_counting_upstream(Arc::clone(&probes));
    let data_port = common::boot::free_port();
    let admin_port = common::boot::free_port();
    write_configs(&dir, data_port, admin_port, upstream_port);

    let log_path = dir.join("out.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let log_err = log.try_clone().unwrap();
    let mut child = Command::new(common::boot::exe())
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .env("MOCK_KEY", "x")
        .env("RUST_LOG", "warn")
        .stdout(log)
        .stderr(log_err)
        .spawn()
        .expect("spawn busbar");

    let deadline = Instant::now() + Duration::from_secs(30);
    let mut booted = false;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("try_wait") {
            panic!(
                "busbar exited before listening (status {status:?}); log:\n{}",
                read_log(&log_path)
            );
        }
        if healthz_ok(data_port) {
            booted = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        booted,
        "busbar did not start answering on {data_port} within 30s; log:\n{}",
        read_log(&log_path)
    );

    // The first probe opens the window, so the boot's own duration is never counted.
    let first = Instant::now() + Duration::from_secs(30);
    while probes.load(Ordering::SeqCst) == 0 && Instant::now() < first {
        std::thread::sleep(Duration::from_millis(20));
    }
    let at_open = probes.load(Ordering::SeqCst);
    std::thread::sleep(Duration::from_secs(INTERVAL_SECS * WINDOW_TICKS));
    let in_window = probes.load(Ordering::SeqCst) - at_open;

    let _ = child.kill();
    let _ = child.wait();

    // RED (no prober): the member is never probed.
    assert!(
        at_open > 0 && in_window >= 2,
        "the active member was not probed: {at_open} before the window, {in_window} in it; log:\n{}",
        read_log(&log_path)
    );
    // RED (two probers): a second loop beside the kernel's doubles the count past one per tick.
    assert!(
        in_window as u64 <= WINDOW_TICKS + 1,
        "{in_window} probes in {WINDOW_TICKS} ticks: more than one prober runs for the member; \
         log:\n{}",
        read_log(&log_path)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ── fixture ──────────────────────────────────────────────────────────────────────────────────────

fn fixture_dir() -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let d = std::env::temp_dir().join(format!(
        "busbar-probe-once-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write_configs(dir: &Path, data_port: u16, admin_port: u16, upstream_port: u16) {
    // The catalog entry, kept as data beside the other root fixtures: the dialect the mock speaks is
    // the fixture's word, never the composition root's.
    std::fs::write(
        dir.join("providers.yaml"),
        PROVIDERS
            .replace("{upstream_port}", &upstream_port.to_string())
            .replace("{interval_secs}", &INTERVAL_SECS.to_string()),
    )
    .unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            r#"listen: "127.0.0.1:{data_port}"
admin_listen: "127.0.0.1:{admin_port}"
advanced:
  allow_destinations: ["127.0.0.1"]
store: {{module: memory}}
admin_require_mtls: false
auth:
  chain: []
providers:
  mock:
    api_key: {{ env: MOCK_KEY }}
models:
  test-model:
    provider: mock
"#
        ),
    )
    .unwrap();
}

/// An upstream that counts every request it receives and answers each with a minimal chat
/// completion. No client traffic is sent, so every request it sees is a probe.
fn spawn_counting_upstream(count: Arc<AtomicUsize>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut stream) = conn else { continue };
            let count = Arc::clone(&count);
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut content_length = 0usize;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    let lower = line.to_ascii_lowercase();
                    if let Some(v) = lower.strip_prefix("content-length:") {
                        content_length = v.trim().parse().unwrap_or(0);
                    }
                    if line == "\r\n" || line == "\n" {
                        break;
                    }
                }
                let mut body = vec![0u8; content_length];
                let _ = reader.read_exact(&mut body);
                count.fetch_add(1, Ordering::SeqCst);
                let payload = br#"{"id":"chatcmpl-probe","object":"chat.completion","created":0,"model":"test-model","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    payload.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(payload);
                let _ = stream.flush();
            });
        }
    });
    port
}

fn healthz_ok(port: u16) -> bool {
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    if stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut buf = String::new();
    let _ = stream.read_to_string(&mut buf);
    buf.starts_with("HTTP/1.1 200")
}

fn read_log(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}
