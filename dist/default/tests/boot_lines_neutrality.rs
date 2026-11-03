// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![cfg(unix)]
#![cfg(linked_section_pools)]

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

fn fixture_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-boot-lines-neutrality-{}-{}",
        std::process::id(),
        {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            format!(
                "{}-{}-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos()),
                line!(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            )
        }
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn free_port() -> u16 {
    common::boot::free_port()
}

fn write_configs(dir: &Path, data_port: u16, admin_port: u16) {
    std::fs::write(
        dir.join("providers.yaml"),
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n",
    )
    .unwrap();

    let key_hex = Command::new(common::boot::exe())
        .arg("--generate-signing-key")
        .output()
        .expect("run --generate-signing-key");
    assert!(key_hex.status.success(), "generate-signing-key failed");
    std::fs::write(dir.join("signing.key"), &key_hex.stdout).unwrap();

    std::fs::write(
        dir.join("config.yaml"),
        format!(
            r#"listen: "127.0.0.1:{data_port}"
admin_listen: "127.0.0.1:{admin_port}"
store: {{module: memory}}
admin_require_mtls: false
advanced:
  allow_destinations: ["127.0.0.1"]
  worker_threads: 2
identity-providers:
  admin-tokens:
    module: admin-tokens
    token: {{ env: BUSBAR_ADMIN_TOKEN }}
auth:
  chain:
    - keys
  signing_key: {{ file: "{key}" }}
  admin_auth:
    - admin-tokens
groups:
  g:
    limits:
      - {{ budget: 1000000, per: day }}
providers:
  mock:
    api_key: {{ env: MOCK_KEY }}
models:
  test-model:
    provider: mock
pools:
  op:
    members:
      - model: test-model
    on_exhausted: least_bad
"#,
            key = dir.join("signing.key").display(),
        ),
    )
    .unwrap();
}

fn blank_volatile(line: &str) -> String {
    let mut out = String::new();

    let ts_re_match = |s: &str| -> Option<usize> {
        if s.len() < 20 {
            return None;
        }
        let b = s.as_bytes();
        let ok_digit = |i: usize| b.get(i).is_some_and(|c| c.is_ascii_digit());
        if (0..4).all(ok_digit)
            && b[4] == b'-'
            && (5..7).all(ok_digit)
            && b[7] == b'-'
            && (8..10).all(ok_digit)
            && b[10] == b'T'
            && (11..13).all(ok_digit)
            && b[13] == b':'
            && (14..16).all(ok_digit)
            && b[16] == b':'
            && (17..19).all(ok_digit)
        {
            let mut i = 19;
            if b.get(i) == Some(&b'.') {
                i += 1;
                while b.get(i).is_some_and(u8::is_ascii_digit) {
                    i += 1;
                }
            }
            if b.get(i) == Some(&b'Z') {
                i += 1;
            }
            return Some(i);
        }
        None
    };
    let mut rest = line;
    if let Some(n) = ts_re_match(rest) {
        out.push_str("<TS>");
        rest = &rest[n..];
    }
    out.push_str(rest);
    let line = out;

    let line = {
        let mut s = String::new();
        let mut rest = line.as_str();
        loop {
            if let Some(pos) = rest.find("version=\"") {
                s.push_str(&rest[..pos]);
                s.push_str("version=\"<V>\"");
                let after = &rest[pos + 9..];
                match after.find('"') {
                    Some(end) => rest = &after[end + 1..],
                    None => {
                        break;
                    }
                }
            } else {
                s.push_str(rest);
                break;
            }
        }
        s
    };

    let mut line = line;
    if let Some(pos) = line.find("diag=BUSBAR-") {
        let after = &line[pos + "diag=BUSBAR-".len()..];
        let digits = after.chars().take_while(char::is_ascii_digit).count();
        let start = if line[..pos].ends_with(' ') {
            pos - 1
        } else {
            pos
        };
        line.replace_range(start..pos + "diag=BUSBAR-".len() + digits, "");
    }
    line
}

#[test]
fn boot_lines_match_1_5_5_shape() {
    let dir = fixture_dir();
    let data_port = free_port();
    let admin_port = free_port();
    write_configs(&dir, data_port, admin_port);

    let log_path = dir.join("out.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let log_err = log.try_clone().unwrap();

    let mut child = Command::new(common::boot::exe())
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .env("MOCK_KEY", "x")
        .env("BUSBAR_ADMIN_TOKEN", "boot-lines-test-admin-token")
        .env("RUST_LOG", "info")
        .stdout(log)
        .stderr(log_err)
        .spawn()
        .expect("spawn busbar");

    let booted = wait_for(Duration::from_secs(30), || {
        if let Some(status) = child.try_wait().expect("try_wait") {
            panic!(
                "busbar exited before listening (status {status:?}); log:\n{}",
                read_to_string(&log_path)
            );
        }
        common::boot::log_shows_data_and_admin_listening(&read_to_string(&log_path))
    });
    assert!(
        booted,
        "busbar did not reach 'listening' (data and admin) within 30s; log:\n{}",
        read_to_string(&log_path)
    );

    let data_ready = wait_for(Duration::from_secs(30), || healthz_ok(data_port));
    assert!(
        data_ready,
        "data listener on 127.0.0.1:{data_port} never answered /healthz within 30s; log:\n{}",
        read_to_string(&log_path)
    );
    let admin_ready = wait_for(Duration::from_secs(30), || healthz_ok(admin_port));
    assert!(
        admin_ready,
        "admin listener on 127.0.0.1:{admin_port} never answered /healthz within 30s; log:\n{}",
        read_to_string(&log_path)
    );

    let pid = child.id().to_string();
    let killed = Command::new("kill")
        .arg("-TERM")
        .arg(&pid)
        .status()
        .expect("send SIGTERM")
        .success();
    assert!(killed, "kill -TERM {pid} failed");

    let exited = wait_for(Duration::from_secs(60), || {
        child.try_wait().expect("try_wait").is_some()
    });
    if !exited {
        let _ = child.kill();
        panic!(
            "busbar did not drain within 60s of SIGTERM; log:\n{}",
            read_to_string(&log_path)
        );
    }

    let log_text = read_to_string(&log_path);
    let mut lines: Vec<String> = log_text
        .lines()
        .map(strip_ansi)
        .filter(|l| l.contains("INFO") || l.contains("WARN") || l.contains("ERROR"))
        .map(|l| blank_volatile(&l))
        .collect();

    sort_consecutive_runs(&mut lines, |l| l.contains("pool exhaustion policy pool="));

    sort_consecutive_runs(&mut lines, |l| l.contains("INFO busbar listening listen="));

    let expected = vec![
        "<TS>  INFO busbar starting version=\"<V>\"".to_string(),
        "<TS>  INFO config is mutable; admin-API changes persist to the configured Store (restart durability follows that Store) overlay=configured Store".to_string(),
        "<TS>  INFO metadata protection: 11 hosts blocked (--print-metadata-blocklist to view)"
            .to_string(),
        "<TS>  INFO plugins: disabled (plugins.enabled is false; tarballs in the directory are inert)"
            .to_string(),
        "<TS>  INFO pool exhaustion policy pool=op on_exhausted=LeastBad".to_string(),
        "<TS>  WARN store: in-memory (ephemeral) - keys, groups' usage, and ledgers reset on restart; configure a durable store plugin for persistence".to_string(),
        "<TS>  INFO reliability state (breakers, cooldowns, latency, hard-down) starts fresh on boot and is re-learned from live traffic".to_string(),
        "<TS>  INFO native API surface mounted transport=\"json/v1\" prefix=/api/v1/admin".to_string(),
        format!("<TS>  INFO busbar listening listen=127.0.0.1:{data_port}"),
        format!("<TS>  INFO busbar listening listen=127.0.0.1:{admin_port}"),
        "<TS>  INFO shutdown signal received; draining in-flight requests".to_string(),
        "<TS>  INFO budget shutdown flush completed flushed=0".to_string(),
        "<TS>  INFO metering shutdown flush completed flushed=0".to_string(),
    ];

    let mut expected = expected;
    sort_consecutive_runs(&mut expected, |l| {
        l.contains("INFO busbar listening listen=")
    });

    assert_eq!(
        lines, expected,
        "boot INFO+ line set/order drifted from the 1.5.5 shape (raw log follows):\n{log_text}"
    );

    assert!(
        !dir.join("busbar-overlay.json").exists(),
        "the configured Store owns mutable configuration; no retired JSON overlay is created"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn allow_all_metadata_boot_line_is_the_warn() {
    let dir = fixture_dir();
    let data_port = free_port();
    let admin_port = free_port();
    write_configs(&dir, data_port, admin_port);
    let config = dir.join("config.yaml");
    let mut text = read_to_string(&config);
    text.push_str("security:\n  allow_all_metadata: true\n");
    std::fs::write(&config, text).unwrap();

    let log_path = dir.join("out.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let log_err = log.try_clone().unwrap();
    let mut child = Command::new(common::boot::exe())
        .env("BUSBAR_CONFIG", &config)
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .env("MOCK_KEY", "x")
        .env("BUSBAR_ADMIN_TOKEN", "boot-lines-test-admin-token")
        .env("RUST_LOG", "info")
        .stdout(log)
        .stderr(log_err)
        .spawn()
        .expect("spawn busbar");

    let booted = wait_for(Duration::from_secs(30), || {
        if let Some(status) = child.try_wait().expect("try_wait") {
            panic!(
                "busbar exited before listening (status {status:?}); log:\n{}",
                read_to_string(&log_path)
            );
        }
        common::boot::log_shows_data_and_admin_listening(&read_to_string(&log_path))
    });
    let _ = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status();
    if !wait_for(Duration::from_secs(60), || {
        child.try_wait().expect("try_wait").is_some()
    }) {
        let _ = child.kill();
        let _ = child.wait();
    }
    let log_text = read_to_string(&log_path);
    assert!(booted, "busbar did not reach 'listening'; log:\n{log_text}");

    let metadata_lines: Vec<String> = log_text
        .lines()
        .map(strip_ansi)
        .map(|l| blank_volatile(&l))
        .filter(|l| l.contains("metadata protection"))
        .collect();
    assert_eq!(
        metadata_lines,
        vec![
            "<TS>  WARN metadata protection DISABLED — all cloud-metadata endpoints reachable"
                .to_string()
        ],
        "the allow_all_metadata boot line is the documented WARN; log:\n{log_text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

fn sort_consecutive_runs(lines: &mut Vec<String>, pred: impl Fn(&str) -> bool) {
    let mut out = Vec::with_capacity(lines.len());
    let mut run: Vec<String> = Vec::new();
    for line in lines.drain(..) {
        if pred(&line) {
            run.push(line);
        } else {
            if !run.is_empty() {
                run.sort();
                out.append(&mut run);
            }
            out.push(line);
        }
    }
    if !run.is_empty() {
        run.sort();
        out.append(&mut run);
    }
    *lines = out;
}

fn healthz_ok(port: u16) -> bool {
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(2))).ok();
    if stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut buf = Vec::new();
    if stream.read_to_end(&mut buf).is_err() {
        return false;
    }
    let text = String::from_utf8_lossy(&buf);
    text.starts_with("HTTP/1.1 200") || text.starts_with("HTTP/1.0 200")
}

fn wait_for(budget: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    cond()
}

fn strip_ansi(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for c2 in chars.by_ref() {
                if c2 == 'm' {
                    break;
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

fn read_to_string(path: &Path) -> String {
    let mut s = String::new();
    if let Ok(mut f) = std::fs::File::open(path) {
        let _ = f.read_to_string(&mut s);
    }
    s
}
