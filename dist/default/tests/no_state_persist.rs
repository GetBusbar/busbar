// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![cfg(unix)]
#![cfg(linked_section_pools)]

mod common;

use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

fn fixture_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-no-state-persist-{}-{}",
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

fn write_configs(dir: &Path) {
    std::fs::write(
        dir.join("providers.yaml"),
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        r#"listen: "127.0.0.1:0"
admin_listen: "127.0.0.1:0"
advanced:
  allow_destinations: ["127.0.0.1"]
store: {module: memory}
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

#[test]
fn a_running_busbar_writes_no_state_file() {
    let dir = fixture_dir();
    write_configs(&dir);
    let state_file = dir.join("state.json");
    let default_state_file = dir.join("busbar-state.json");

    let log_path = dir.join("out.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let log_err = log.try_clone().unwrap();

    let before = tree(&dir);

    let mut child = Command::new(common::boot::exe())
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .env("BUSBAR_STATE_FILE", &state_file)
        .env("MOCK_KEY", "x")
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

    std::thread::sleep(Duration::from_millis(400));

    let pid = child.id().to_string();
    let killed = Command::new("kill")
        .arg("-TERM")
        .arg(&pid)
        .status()
        .expect("send SIGTERM")
        .success();
    assert!(killed, "kill -TERM {pid} failed");

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

    let after = tree(&dir);
    let added: Vec<_> = after.difference(&before).collect();
    assert!(
        added.is_empty(),
        "the run left {} new file(s) in the fixture tree; reliability state must be RAM-only, so a \
         busbar process must add nothing to the directory it was pointed at: {added:?}\nlog:\n{}",
        added.len(),
        read_to_string(&log_path)
    );

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

fn read_to_string(path: &Path) -> String {
    let mut s = String::new();
    if let Ok(mut f) = std::fs::File::open(path) {
        let _ = f.read_to_string(&mut s);
    }
    s
}
