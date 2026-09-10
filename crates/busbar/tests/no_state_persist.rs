// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! STORE-OR-RAM (1.5.3) end-to-end proof: a real busbar process writes NO side-car state file.
//!
//! Before the state-file removal, the periodic snapshotter's first tick (which
//! fires immediately after boot) AND the graceful-shutdown write both wrote `busbar-state.json`
//! (or `$BUSBAR_STATE_FILE`), which the next boot restored — that is exactly what carried learned
//! reliability state (breakers, cooldowns, latency EWMAs, hard-down latches) across a restart. This
//! test boots the REAL binary through to "listening", sends `SIGTERM`, waits for a clean drain, and
//! asserts the fixture directory tree is byte-for-byte the same SET OF FILES it was before boot.
//! A green run proves the snapshotter and the shutdown write are gone, so reliability state is
//! RAM-only (re-learned on the next boot) and the old file-restore path cannot exist.
//!
//! The proof is an ENUMERATION, not a pair of filenames. "No file called `busbar-state.json`" and
//! "no file" are different claims, and only the second is the invariant: a reintroduced snapshotter
//! under any other name is the same regression, and a check that names the two paths the old code
//! used would report green while it happened.
//!
//! Unix-only: it drives the process lifecycle with `SIGTERM`, the signal busbar's graceful shutdown
//! listens for.
#![cfg(unix)]
// The fixture boots a REAL busbar with an LLM provider (`protocol: anthropic`); a `--no-default-features`
// build has no wire codec compiled in and fail-closes at boot (BUSBAR-9007), which is correct product
// behavior, not a regression. The state-file invariant under test is plane-independent, but this proof
// of it requires a bootable server, so it is gated on the LLM plane. Full-feature builds still run it.
#![cfg(feature = "proto-llm")]

use std::collections::BTreeSet;
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

/// A real busbar process, booted through to "listening", then stopped with SIGTERM, adds NOTHING to
/// the directory it was pointed at — compared as a whole tree, so a state file under any name is
/// caught, with the two paths the removed mechanism used named afterwards for a legible message.
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

    // The fixture tree as the process will find it. Everything here is ours: the two configs and
    // the log we just opened. Anything the run adds to this set is state the process persisted.
    let before = tree(&dir);

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
    //
    // BOTH LISTENERS, not the first one to speak. `busbar listening` is logged once per LISTENER
    // and `run()` brings the two planes up in a fixed order — the per-core data workers first, the
    // second socket bound only after them — so the bare message means "one plane is up", not "boot
    // finished". This test's claim is about what a REAL, FULLY BOOTED busbar writes to disk, and
    // the two writes the removed mechanism performed (the snapshotter's immediate first tick and
    // the shutdown write) both live past that point; a `SIGTERM` delivered while the second
    // listener is still coming up stops a half-booted process, and a half-booted process is not
    // the thing under test. So the gate counts the lines rather than looking for one.
    //
    // Exactly two are expected at INFO: `serve_thread_per_core` logs the data plane's line from
    // worker 0 only (every other worker's identical fact is DEBUG), and the second listener logs
    // its own. Counted, rather than matched against the addresses, because this fixture asks the
    // OS for both ports (`:0`) and so does not know them — and because the child writes ANSI field
    // styling between the `listen` field name and its value, which is why matching that field's
    // text is the wrong tool here as well.
    let booted = wait_for(Duration::from_secs(30), || {
        if let Some(status) = child.try_wait().expect("try_wait") {
            panic!(
                "busbar exited before listening (status {status:?}); log:\n{}",
                read_to_string(&log_path)
            );
        }
        listening_lines(&read_to_string(&log_path)) >= 2
    });
    assert!(
        booted,
        "busbar did not reach 'listening' on BOTH planes within 30s (saw {} of the 2 expected \
         lines); log:\n{}",
        listening_lines(&read_to_string(&log_path)),
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

    // THE GATE: the tree is exactly as the process found it. A new file under any name — the two
    // paths the removed mechanism used, or a third nobody has thought of yet — is persisted state.
    let after = tree(&dir);
    let added: Vec<_> = after.difference(&before).collect();
    assert!(
        added.is_empty(),
        "the run left {} new file(s) in the fixture tree; reliability state must be RAM-only, so a \
         busbar process must add nothing to the directory it was pointed at: {added:?}\nlog:\n{}",
        added.len(),
        read_to_string(&log_path)
    );

    // The two paths the removed mechanism used, named so a regression at either reads as itself
    // rather than as an anonymous entry in the set above. The enumeration is what makes the gate
    // total; these two make its most likely failure legible.
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

/// Every file path under `dir`, recursively, relative to `dir`.
///
/// The gate asks "did the process leave anything behind", and only an enumeration can answer that.
/// Naming the paths the old code happened to use answers a narrower question — the next state file
/// under a different name walks straight past a two-filename check — so the proof is the set of
/// files that exist after the run, compared against the set that existed before it.
fn tree(dir: &Path) -> BTreeSet<PathBuf> {
    let mut out = BTreeSet::new();
    collect(dir, dir, &mut out);
    out
}

fn collect(root: &Path, dir: &Path, out: &mut BTreeSet<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(root, &path, out);
        } else if let Ok(rel) = path.strip_prefix(root) {
            out.insert(rel.to_path_buf());
        }
    }
}

/// Poll `cond` until it returns true or `budget` elapses; returns whether it became true.
/// How many `busbar listening` lines the boot log carries so far — one per LISTENER, which is what
/// distinguishes "a plane is up" from "the server is up".
fn listening_lines(log: &str) -> usize {
    log.lines()
        .filter(|l| l.contains("busbar listening"))
        .count()
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

/// Read a file to a String, tolerating a not-yet-flushed/partial log (returns what's there).
fn read_to_string(path: &Path) -> String {
    let mut s = String::new();
    if let Ok(mut f) = std::fs::File::open(path) {
        let _ = f.read_to_string(&mut s);
    }
    s
}
