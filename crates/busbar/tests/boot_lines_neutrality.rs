// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! NEUTRALITY: a 1.5.5-shaped config (no `mcp:`/`agents:`/`streams:` section) must boot with the SAME
//! log lines at INFO and above as the published 1.5.5 binary — no new boot line at INFO just because a
//! later plane is compiled in, and no plane line at all unless that plane is configured (see
//! `docs/design/ARCHITECTURE.md` Appendix B, and the shadow-oracle `neutrality|boot-lines` cell this
//! test pins as a fast, always-on regression guard beside it).
//!
//! Boots the REAL binary, captures stdout (busbar's default log destination outside `--mcp-stdio`),
//! SIGTERMs it, and asserts the exact ORDERED set of INFO/WARN/ERROR lines after blanking the three
//! fields that are expected to vary run-to-run: the timestamp, the version literal, and a
//! `diag=BUSBAR-nnnn` suffix. The one line-group whose RELATIVE order is itself nondeterministic on
//! the same binary — the per-pool "pool exhaustion policy" lines, walked off a `HashMap` — is sorted
//! before comparison, exactly as `testing/shadow-oracle/normalize.py`'s `boot.exhaustion-order` rule
//! does for the oracle's own recording of this same cell.
#![cfg(unix)]
#![cfg(feature = "proto-llm")]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

fn fixture_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-boot-lines-neutrality-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

/// A 1.5.5-SHAPED config: no `mcp:`/`agents:`/`streams:` section, governance ON (a keyed `auth.chain`,
/// so the store/reliability lines fire the same way the oracle's baseline does), a plugin dir that is
/// present but disabled (the "plugins: disabled" INFO line), one pool with `on_exhausted: least_bad`
/// (the restored "pool exhaustion policy" line — a single pool, so no ordering ambiguity to sort), and
/// `advanced.worker_threads: 2` so the thread-per-core data plane is small and fast to drain.
fn write_configs(dir: &Path, data_port: u16, admin_port: u16) {
    std::fs::write(
        dir.join("providers.yaml"),
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n  api_key_env: MOCK_KEY\n",
    )
    .unwrap();
    // A REAL ed25519 signing secret, minted through the binary's own `--generate-signing-key` (the
    // same mint `oracle_write_config` uses) — a placeholder string would fail `auth.signing_key`
    // resolution at boot (BUSBAR-9007), which is a different cell, not this one.
    let key_hex = Command::new(env!("CARGO_BIN_EXE_busbar"))
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
admin_require_mtls: false
advanced:
  worker_threads: 2
identity-providers:
  admin-tokens:
    module: admin-tokens
    token: {{ env: BUSBAR_ADMIN_TOKEN }}
auth:
  chain:
    - keys
  signing_key: {{ file: "{key}" }}
  admin_auth: [admin-tokens]
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

/// A `diag=BUSBAR-nnnn` suffix (any digit run), a `busbar <VERSION>`/`version="x.y.z"` literal, or an
/// RFC3339-ish timestamp — the three fields the shadow-oracle's own capture/normalize pipeline blanks
/// before an old-vs-new boot-line diff means anything (`testing/shadow-oracle/capture-exec.py`'s
/// `scrub`, `normalize.py`'s `ver.string`).
fn blank_volatile(line: &str) -> String {
    let mut out = String::new();
    // timestamp: a leading RFC3339-ish token at the start of the line (tracing_subscriber's default
    // fmt prefixes every line with one), e.g. `2026-09-05T07:00:37.362252Z`.
    let ts_re_match = |s: &str| -> Option<usize> {
        // crude fixed-width RFC3339 match: YYYY-MM-DDTHH:MM:SS(.fraction)?Z?
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

    // version literal: `busbar X.Y.Z` or `version="X.Y.Z"`.
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

    // diag=BUSBAR-nnnn suffix (with its leading space, so removal leaves no double space).
    let mut line = line;
    if let Some(pos) = line.find("diag=BUSBAR-") {
        let after = &line[pos + "diag=BUSBAR-".len()..];
        let digits = after.chars().take_while(char::is_ascii_digit).count();
        let start = if line[..pos].ends_with(' ') { pos - 1 } else { pos };
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

    let mut child = Command::new(env!("CARGO_BIN_EXE_busbar"))
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
        read_to_string(&log_path).contains("busbar listening")
    });
    assert!(
        booted,
        "busbar did not reach 'listening' within 30s; log:\n{}",
        read_to_string(&log_path)
    );

    // Wait for BOTH listeners to actually answer `/healthz` before SIGTERM, rather than sleeping a
    // fixed duration. Under `cargo test --workspace` load (many crates' test binaries competing for
    // CPU) a fixed sleep is not long enough for a slow-scheduled worker thread to finish standing up
    // its listener and log its own "busbar listening" line before the signal lands, so the captured
    // log is missing a line the un-loaded run always has — a false failure, not a real drift. Polling
    // the actual readiness signal (a live TCP accept + HTTP response on each port) is load-robust
    // without weakening what gets compared: the ordered-set assertion below is unchanged.
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

    // Capture UNTIL THE PROCESS EXITS, not for a fixed window: the log is only read below, after this
    // returns, so a slow-draining process under load still has every line it will ever write present
    // by the time the comparison runs. The budget itself is generous (not zero-cost, but this test
    // only runs once) precisely so CPU contention from concurrently running crates cannot turn a slow
    // but correct drain into a false failure.
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

    // `boot.exhaustion-order` precedent (testing/shadow-oracle/normalize.py): sort any consecutive
    // run of "pool exhaustion policy" lines in place — their relative order is a `HashMap` walk, not a
    // contract. This fixture has exactly one such pool, so this is a no-op safety net, not load-bearing.
    sort_consecutive_runs(&mut lines, |l| l.contains("pool exhaustion policy pool="));
    // The data listener's "busbar listening" line is logged from its own per-core worker thread while
    // the admin listener's is logged from the control thread right after spawning it — a genuine
    // thread race, not a HashMap walk, but the SAME "sort before comparing" treatment applies: which
    // one lands first in the log is not a contract, only that there is exactly one of each.
    sort_consecutive_runs(&mut lines, |l| l.contains("INFO busbar listening listen="));

    let expected = vec![
        "<TS>  INFO busbar starting version=\"<V>\"".to_string(),
        format!(
            "<TS>  INFO config is mutable; admin-API changes persist to the overlay backend (durable across restart) overlay={}",
            dir.join("busbar-overlay.json").display()
        ),
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
        "<TS>  INFO budget counters flushed on shutdown flushed=0".to_string(),
        "<TS>  INFO metering rows flushed on shutdown flushed=0".to_string(),
    ];
    // Same treatment as `lines`: the two "busbar listening" lines' relative order is a thread race,
    // not a contract — sort both sides the same way so the assertion pins the SET, not a coin flip.
    let mut expected = expected;
    sort_consecutive_runs(&mut expected, |l| l.contains("INFO busbar listening listen="));

    assert_eq!(
        lines, expected,
        "boot INFO+ line set/order drifted from the 1.5.5 shape (raw log follows):\n{log_text}"
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

/// A single best-effort `GET /healthz` against `127.0.0.1:port`, over a raw blocking TCP socket
/// rather than an async client, so this plain `#[test]` does not need a tokio runtime just to probe
/// readiness. `/healthz` is unauthenticated and side-effect-free (see `endpoints::healthz`'s own
/// doc), so this cannot perturb the boot-line sequence under test. Any I/O failure (connection
/// refused because the listener has not bound yet, a reset mid-handshake, ...) is reported as "not
/// ready" rather than propagated, since "not yet listening" is the expected steady state until boot
/// completes.
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

/// Strip ANSI SGR escape sequences (`\x1b[...m`) — tracing's default fmt layer colors level/field
/// names even when writing to a plain file (not a tty), exactly as the shadow-oracle capture pipeline
/// observes (`capture-exec.py`'s `exec.ansi` rule).
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
