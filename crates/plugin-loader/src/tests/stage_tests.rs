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
    // It lives in the ONE dedicated, owner-only parent, not at the top of the temp dir.
    let parent = staging_parent_in(&std::env::temp_dir());
    assert_eq!(dir.parent(), Some(parent.as_path()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&parent).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "staging parent must be 0700, got {mode:o}");
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

    // The sweep walks the SHARED staging parent, and so does every OTHER busbar-shaped process
    // on the host (a parallel run of this same test binary, a booting busbar — main.rs sweeps at
    // startup). A dead-pid fixture dir placed there is therefore legitimate prey for a CONCURRENT
    // sweeper, and this test used to flake exactly that way under parallel load: a sibling swept
    // the fixed-name fixture first, `sweep_dead_staging()` here found nothing, and `removed >= 1`
    // failed with the sweep working perfectly. Two changes close it without weakening what is
    // proven:
    //   * a RANDOM suffix, so a sibling running this test can never create/remove the same path;
    //   * a RETRY when — and only when — the fixture vanished without this call removing it, which
    //     has exactly one cause (a concurrent sweeper won the race) and re-running the experiment
    //     is the correct response to it. A fixture that still EXISTS after our sweep is the real
    //     defect and fails immediately, every attempt.
    let mut proven = false;
    for _ in 0..5 {
        // A dir for a pid that is certainly dead (pid_max on linux is < 2^22 by default; u32::MAX
        // range pids do not exist on any supported platform).
        let dead = staging_parent_in(&std::env::temp_dir())
            .join(format!("{STAGING_PREFIX}4294967294-{}", random_hex(8)));
        std::fs::create_dir_all(dead.join("sub")).unwrap();
        std::fs::write(dead.join("sub/lib.so"), b"junk").unwrap();

        let removed = sweep_dead_staging();
        assert!(
            !dead.exists(),
            "a dead-pid staging dir survived the sweep — the sweep is broken"
        );
        assert!(
            own.exists(),
            "own (live-pid) staging dir survives the sweep"
        );
        if removed >= 1 {
            proven = true;
            break;
        }
        // removed == 0 with the fixture gone: a concurrent sweeper (sibling test process or a
        // booting busbar) removed it before this call walked the dir. Run the experiment again.
    }
    assert!(
        proven,
        "five consecutive sweeps each found the fixture already removed by a concurrent sweeper; \
         either this host is running a pathological number of busbar processes or `removed` is \
         miscounted"
    );
    drop(held);
}

/// A private temp root for a sweep test: the sweep is pointed at it through
/// `sweep_dead_staging_under`, so no concurrent sweeper on the host can touch its fixtures.
fn private_root(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("busbar-sweep-{tag}-{}", random_hex(8)));
    std::fs::create_dir_all(&root).unwrap();
    root
}

/// Plugin#4 regression: a dead-pid-named SYMLINK inside the staging parent is SKIPPED by the
/// sweep, never acted on. The sweep classifies the entry with `symlink_metadata` (no-follow), so a
/// symlink is not a directory to it: the link is left in place and its target is never traversed.
#[cfg(unix)]
#[test]
fn sweep_skips_symlinked_dead_pid_entry() {
    use std::os::unix::fs::symlink;

    let root = private_root("symlink");
    let parent = ensure_staging_parent(&root).expect("parent");
    // A victim dir OUTSIDE staging, holding a canary that must never be touched.
    let victim = root.join("victim");
    std::fs::create_dir_all(&victim).unwrap();
    let canary = victim.join("canary");
    std::fs::write(&canary, b"do not delete").unwrap();

    // A symlink in the parent named like a DEAD-pid staging dir, pointing at the victim.
    let link = parent.join(format!("{STAGING_PREFIX}4294967294-{}", random_hex(8)));
    symlink(&victim, &link).unwrap();

    let removed = sweep_dead_staging_under(&root, &mut list_dir_names);

    assert_eq!(removed, 0);
    assert!(
        link.symlink_metadata().is_ok(),
        "the sweep removed a symlink instead of skipping it — it treated a symlink as a staging dir"
    );
    assert!(
        canary.exists(),
        "the sweep followed a symlink into the victim directory"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// LOADER-SWEEP regression: the boot sweep must NOT iterate the OS temp directory. A temp root
/// holding 10,000 unrelated entries (plus the staging parent) is swept through a COUNTING lister;
/// the sweep may list the dedicated parent only, and must see only the parent's own entries. The
/// pre-fix sweep listed the temp root itself, so it iterated all 10,000 (boot unbounded on a huge
/// `$TMPDIR`). Iteration is counted, never timed.
#[cfg(unix)]
#[test]
fn sweep_lists_only_the_staging_parent_not_the_temp_root() {
    let root = private_root("bounded");
    for i in 0..10_000 {
        std::fs::write(root.join(format!("unrelated-{i}")), b"").unwrap();
    }
    let parent = ensure_staging_parent(&root).expect("parent");
    let dead = parent.join(format!("{STAGING_PREFIX}4294967294-{}", random_hex(8)));
    std::fs::create_dir_all(dead.join("sub")).unwrap();

    let mut listed_dirs: Vec<PathBuf> = Vec::new();
    let mut entries_seen = 0usize;
    let mut counting = |dir: &std::path::Path| {
        listed_dirs.push(dir.to_path_buf());
        let names = list_dir_names(dir)?;
        entries_seen += names.len();
        Ok(names)
    };
    let removed = sweep_dead_staging_under(&root, &mut counting);

    assert_eq!(
        listed_dirs,
        vec![parent.clone()],
        "the sweep must list the dedicated staging parent and nothing else"
    );
    assert_eq!(
        entries_seen, 1,
        "the sweep iterated {entries_seen} entries; only the parent's single staging dir may be \
         seen, never the 10,000 unrelated temp-root entries"
    );
    assert_eq!(removed, 1);
    assert!(!dead.exists(), "the dead-pid dir in the parent is removed");
    let _ = std::fs::remove_dir_all(&root);
}

/// Inside the dedicated parent: a dead pid's dir is removed; this process's own dir and a
/// different LIVE process's dir (our parent process) are kept. A pre-1.6.0 top-level
/// `busbar-plugins-<dead-pid>-*` in the temp root is NOT swept (the legacy layout is dropped so the
/// full temp-root scan never comes back).
#[cfg(unix)]
#[test]
fn sweep_in_parent_removes_dead_keeps_live() {
    let root = private_root("liveness");
    let parent = ensure_staging_parent(&root).expect("parent");
    let dead = parent.join(format!("{STAGING_PREFIX}4294967294-{}", random_hex(8)));
    std::fs::create_dir_all(dead.join("sub")).unwrap();
    std::fs::write(dead.join("sub/lib.so"), b"junk").unwrap();
    let own = parent.join(format!(
        "{STAGING_PREFIX}{}-{}",
        std::process::id(),
        random_hex(8)
    ));
    std::fs::create_dir_all(&own).unwrap();
    let live_pid = std::os::unix::process::parent_id();
    assert!(
        pid_alive(live_pid),
        "precondition: our parent process is alive"
    );
    let live = parent.join(format!("{STAGING_PREFIX}{live_pid}-{}", random_hex(8)));
    std::fs::create_dir_all(&live).unwrap();
    let legacy = root.join(format!("{STAGING_PREFIX}4294967294-{}", random_hex(8)));
    std::fs::create_dir_all(&legacy).unwrap();

    let removed = sweep_dead_staging_under(&root, &mut list_dir_names);

    assert_eq!(removed, 1, "exactly the one dead-pid dir is removed");
    assert!(!dead.exists(), "dead-pid staging dir must be removed");
    assert!(own.exists(), "this process's staging dir must be kept");
    assert!(live.exists(), "a live process's staging dir must be kept");
    assert!(legacy.exists(), "legacy top-level layout is not swept");
    let _ = std::fs::remove_dir_all(&root);
}

/// The parent is refused (not staged under, not swept) when it is a symlink or not ours: a
/// symlinked parent aimed at a directory holding a dead-pid-named dir must leave it untouched.
#[cfg(unix)]
#[test]
fn symlinked_staging_parent_is_refused_and_not_swept() {
    use std::os::unix::fs::symlink;
    let root = private_root("parentlink");
    let elsewhere = root.join("elsewhere");
    let victim = elsewhere.join(format!("{STAGING_PREFIX}4294967294-{}", random_hex(8)));
    std::fs::create_dir_all(&victim).unwrap();
    symlink(&elsewhere, staging_parent_in(&root)).unwrap();

    assert!(
        ensure_staging_parent(&root).is_err(),
        "a symlinked parent is refused"
    );
    let mut listed = 0usize;
    let removed = sweep_dead_staging_under(&root, &mut |d| {
        listed += 1;
        list_dir_names(d)
    });
    assert_eq!(
        (removed, listed),
        (0, 0),
        "a symlinked parent is never listed"
    );
    assert!(victim.exists());
    let _ = std::fs::remove_dir_all(&root);
}

/// An existing parent of ours with a loosened mode is tightened back to owner-only.
#[cfg(unix)]
#[test]
fn loose_staging_parent_is_tightened_to_0700() {
    use std::os::unix::fs::PermissionsExt as _;
    let root = private_root("loose");
    let parent = staging_parent_in(&root);
    std::fs::create_dir(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o777)).unwrap();
    ensure_staging_parent(&root).expect("adopt own parent");
    let mode = std::fs::metadata(&parent).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
    let _ = std::fs::remove_dir_all(&root);
}

/// pid_alive is true for ourselves and false for an absurd pid (unix).
#[cfg(unix)]
#[test]
fn pid_liveness() {
    assert!(pid_alive(std::process::id()));
    assert!(!pid_alive(4_294_967_294));
}
