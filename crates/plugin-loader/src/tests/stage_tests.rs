// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/plugin-loader/src/stage.rs`.

use super::*;

/// The per-process staging dir is private (0700 on unix), named with the pid, and stable
/// while staged files are live.
#[test]
fn staging_dir_is_private_and_pid_named() {
    let mut state = staging_state().lock().unwrap_or_else(|p| p.into_inner());
    let dir = ensure_staging_dir(&mut state).expect("staging dir");
    assert!(dir.exists());
    let name = dir.file_name().unwrap().to_str().unwrap();
    assert!(name.starts_with(STAGING_PREFIX));
    assert!(name.contains(&std::process::id().to_string()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "staging dir must be 0700, got {mode:o}");
    }
    // A second call returns the SAME directory while it exists.
    assert_eq!(ensure_staging_dir(&mut state).unwrap(), dir);
}

/// Dropping a `Staged::TempFile` removes the file (unload-then-remove is enforced by holder
/// field order; here we assert the removal half).
#[test]
fn temp_file_staging_cleans_up_on_drop() {
    let path = stage_temp_file(b"pretend library bytes").expect("stage");
    assert!(path.exists());
    drop(Staged::TempFile { path: path.clone() });
    assert!(!path.exists(), "staged file must be removed on drop");
}

/// The dead-pid sweep removes a staging dir whose pid is dead, and leaves the live (current)
/// process's dir alone.
///
/// Unix-only: on non-unix `pid_alive` deliberately reports every pid alive (see its doc
/// comment — Windows relies on the locked-DLL failure mode instead), so the sweep never
/// removes anything there and `removed >= 1` is unsatisfiable by design, not by defect.
#[cfg(unix)]
#[test]
fn sweep_removes_dead_pid_dirs_only() {
    // A dir for a pid that is certainly dead (pid_max on linux is < 2^22 by default; u32::MAX
    // range pids do not exist on any supported platform).
    let dead = std::env::temp_dir().join(format!("{STAGING_PREFIX}4294967294-deadbeef"));
    let _ = std::fs::remove_dir_all(&dead);
    std::fs::create_dir_all(dead.join("sub")).unwrap();
    std::fs::write(dead.join("sub/lib.so"), b"junk").unwrap();

    // Our own live dir must survive the sweep: hold a real staged file so the shared state
    // keeps the directory alive for the duration of this test.
    let held = Staged::TempFile {
        path: stage_temp_file(b"keepalive bytes").expect("stage keepalive"),
    };
    let own = {
        let state = staging_state().lock().unwrap_or_else(|p| p.into_inner());
        state
            .dir
            .clone()
            .expect("staging dir exists while a file is live")
    };

    let removed = sweep_dead_staging();
    assert!(removed >= 1, "the dead-pid dir must be swept");
    assert!(!dead.exists(), "dead-pid staging dir removed");
    assert!(
        own.exists(),
        "own (live-pid) staging dir survives the sweep"
    );
    drop(held);
}

/// pid_alive is true for ourselves and false for an absurd pid (unix).
#[cfg(unix)]
#[test]
fn pid_liveness() {
    assert!(pid_alive(std::process::id()));
    assert!(!pid_alive(4_294_967_294));
}
