// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! STORE-OR-RAM (1.5.3) end-to-end proof: a real busbar process writes NO side-car state file.
//!
//! Before the state-file removal, the periodic snapshotter's first tick (which
//! fires immediately after boot) AND the graceful-shutdown write both wrote `busbar-state.json`
//! (or `$BUSBAR_STATE_FILE`), which the next boot restored — that is exactly what carried learned
//! reliability state (breakers, cooldowns, latency EWMAs, hard-down latches) across a restart. This
//! test boots the REAL binary through to "listening", sends `SIGTERM`, waits for a clean drain, and
//! asserts NO state file exists at either the env-override path or the default-next-to-config path.
//! A green run proves the snapshotter and the shutdown write are gone, so reliability state is
//! RAM-only (re-learned on the next boot) and the old file-restore path cannot exist.
//!
//! Unix-only: it drives the process lifecycle with `SIGTERM`, the signal busbar's graceful shutdown
//! listens for.
#![cfg(unix)]
// The fixture boots a REAL busbar with an LLM provider (`protocol: anthropic`); a `--no-default-features`
// build has no wire codec compiled in and fail-closes at boot (BUSBAR-9007), which is correct product
// behavior, not a regression. The state-file invariant under test is plane-independent, but this proof
// of it requires a bootable server, so it is gated on the LLM plane. Full-feature builds still run it.
#![cfg(feature = "proto-llm")]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

/// A fresh, isolated fixture directory (pid + nanos, like the cli_validate harness).
fn fixture_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-no-state-persist-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A minimal config that boots a full server: ephemeral ports (`:0`) so parallel runs never collide,
/// admin mTLS guard waived (`admin_require_mtls: false`) and open auth so no secrets are needed, memory store (default).
fn write_configs(dir: &Path) {
    std::fs::write(
        dir.join("providers.yaml"),
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n  api_key_env: MOCK_KEY\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        r#"listen: "127.0.0.1:0"
admin_listen: "127.0.0.1:0"
admin_require_mtls: false
auth:
  chain: []
providers:
  mock:
    api_key: { env: MOCK_KEY }
models:
  test-model:
    provider: mock
"#,
    )
    .unwrap();
}

/// A real busbar process, booted through to "listening", then stopped with SIGTERM, writes no state
/// file at either the `$BUSBAR_STATE_FILE` override path or the default `busbar-state.json` beside
/// the config. (Both paths are checked so a future default-path regression is caught too.)
#[test]
fn a_running_busbar_writes_no_state_file() {
    let dir = fixture_dir();
    write_configs(&dir);
    let state_file = dir.join("state.json"); // the pre-removal $BUSBAR_STATE_FILE override target
    let default_state_file = dir.join("busbar-state.json"); // the pre-removal default-next-to-config

    // Combined stdout+stderr → a log file we poll for the boot marker (tracing writes to stdout).
    let log_path = dir.join("out.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let log_err = log.try_clone().unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_busbar"))
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .env("BUSBAR_STATE_FILE", &state_file)
        .env("MOCK_KEY", "x")
        .env("RUST_LOG", "info")
        .stdout(log)
        .stderr(log_err)
        .spawn()
        .expect("spawn busbar");

    // Wait for the boot marker, failing loudly if the process dies first (so a boot failure can
    // never masquerade as a green "no file written").
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

    // Under the OLD code the snapshotter's immediate first tick has already written the file by now.
    std::thread::sleep(Duration::from_millis(400));

    // Graceful stop via SIGTERM (busbar's shutdown signal) — the OLD code's at-signal + post-drain
    // writes both ran here.
    let pid = child.id().to_string();
    let killed = Command::new("kill")
        .arg("-TERM")
        .arg(&pid)
        .status()
        .expect("send SIGTERM")
        .success();
    assert!(killed, "kill -TERM {pid} failed");

    // Wait for the process to actually exit (bounded); a stuck process is a test failure, not a hang.
    let exited = wait_for(Duration::from_secs(15), || {
        child.try_wait().expect("try_wait").is_some()
    });
    if !exited {
        let _ = child.kill();
        panic!(
            "busbar did not exit within 15s of SIGTERM; log:\n{}",
            read_to_string(&log_path)
        );
    }

    assert!(
        !state_file.exists(),
        "$BUSBAR_STATE_FILE was written at {} — the state-file mechanism must be gone",
        state_file.display()
    );
    assert!(
        !default_state_file.exists(),
        "the default busbar-state.json was written at {} — no state file must ever be written",
        default_state_file.display()
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Poll `cond` until it returns true or `budget` elapses; returns whether it became true.
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

/// Read a file to a String, tolerating a not-yet-flushed/partial log (returns what's there).
fn read_to_string(path: &Path) -> String {
    let mut s = String::new();
    if let Ok(mut f) = std::fs::File::open(path) {
        let _ = f.read_to_string(&mut s);
    }
    s
}
