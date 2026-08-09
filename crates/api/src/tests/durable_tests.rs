// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/api/src/durable.rs`.

use super::{
    create_dir_all, fault_arm, fault_parent_fsynced, fault_parents_fsynced, fault_reset,
    holding_dir, plant_decoy_arm, write, write_with, DurableOpts, FaultStep,
};
use std::path::{Path, PathBuf};

// Linux ENOSPC=28, EIO=5; macOS shares these values. Injected via `from_raw_os_error`.
const ENOSPC: i32 = 28;
const EIO: i32 = 5;

/// Serializes the ONE test in this file that mutates process-global CWD
/// (`success_relative_path_fsyncs_dot`) against itself. MUST be module-level, not
/// function-local — a function-local `static` is scoped to that function and contends with
/// nothing (the bug this lock previously had). Still not sufficient on its own: no test
/// OUTSIDE this file that resolves a relative path takes this lock. See that test's doc comment.
static CWD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// A private scratch directory, removed on drop, so each case is hermetic and leaves nothing.
struct Scratch {
    dir: PathBuf,
}
impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "busbar-durable-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Scratch { dir }
    }
    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
    /// Any leftover durable temp (`.<name>.<pid>-<seq>.tmp`) for `name` in the dir?
    fn has_durable_temp(&self, name: &str) -> bool {
        let prefix = format!(".{name}.");
        std::fs::read_dir(&self.dir).unwrap().any(|e| {
            let n = e.unwrap().file_name();
            let n = n.to_string_lossy();
            n.starts_with(&prefix) && n.ends_with(".tmp")
        })
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The injected-failure matrix — for every step × {ENOSPC, EIO}, the write returns `Err`,
/// the target is UNCHANGED (prior contents, or still absent), and NO durable temp remains (the
/// RAII guard ran on every early-return path). The temp assertion catches a leaked `.tmp` on a
/// pre-rename error; the "target unchanged" is the whole-family integrity guarantee.
#[test]
fn fault_matrix_returns_err_untouched_target_no_temp_leak() {
    let sc = Scratch::new("matrix");
    let steps = [
        FaultStep::Create,
        FaultStep::Write,
        FaultStep::Flush,
        FaultStep::Fsync,
        FaultStep::Rename,
    ];
    for &step in &steps {
        for &errno in &[ENOSPC, EIO] {
            // Case A: target ABSENT before the failed write → must stay absent, no temp.
            let target = sc.path("absent.json");
            let _ = std::fs::remove_file(&target);
            fault_reset();
            fault_arm(step, errno);
            let r = write(&target, b"new payload");
            assert!(
                r.is_err(),
                "step {step:?} errno {errno}: expected Err on injected fault"
            );
            assert_eq!(
                r.unwrap_err().raw_os_error(),
                Some(errno),
                "step {step:?}: the injected errno must surface"
            );
            assert!(
                !target.exists(),
                "step {step:?} errno {errno}: an absent target must stay absent on failure"
            );
            assert!(
                !sc.has_durable_temp("absent.json"),
                "step {step:?} errno {errno}: no durable temp may leak"
            );

            // Case B: target has PRIOR contents → must be byte-for-byte unchanged, no temp.
            let target = sc.path("prior.json");
            std::fs::write(&target, b"OLD CONTENTS").unwrap();
            fault_reset();
            fault_arm(step, errno);
            let r = write(&target, b"NEW CONTENTS that must not land");
            assert!(r.is_err(), "step {step:?}: expected Err");
            assert_eq!(
                std::fs::read(&target).unwrap(),
                b"OLD CONTENTS",
                "step {step:?} errno {errno}: prior contents must survive a failed write"
            );
            assert!(
                !sc.has_durable_temp("prior.json"),
                "step {step:?} errno {errno}: no durable temp may leak"
            );
        }
    }
}

/// Success on an ABSOLUTE path round-trips and leaves no temp.
#[test]
fn success_absolute_path_roundtrips_no_temp() {
    let sc = Scratch::new("abs");
    let target = sc.path("cfg.json");
    fault_reset();
    write(&target, b"payload-A").unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"payload-A");
    // Overwrite: still atomic, still no temp, new contents win.
    write(&target, b"payload-B").unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"payload-B");
    assert!(!sc.has_durable_temp("cfg.json"));
}

/// The primitive `holding_dir` uses to resolve a RELATIVE path's parent to "." — the pure,
/// deterministic form of the property `success_relative_path_fsyncs_dot` below also exercises
/// through a real CWD round-trip. Covers it with NO filesystem/CWD mutation at all, so it can
/// never be a cross-test hazard.
#[test]
fn holding_dir_resolves_a_relative_path_to_dot() {
    assert_eq!(holding_dir(Path::new("relative.json")), Path::new("."));
    assert_eq!(
        holding_dir(Path::new("a/b/relative.json")),
        Path::new("a/b")
    );
    assert_eq!(
        holding_dir(Path::new("/abs/relative.json")),
        Path::new("/abs")
    );
}

/// Success on a RELATIVE path round-trips AND the parent fsync was attempted on the
/// resolved "." — the assertion that catches a skipped relative-path parent fsync.
///
/// `CWD_LOCK` MUST be a module-level (not function-local) static: a `static` declared inside a
/// function body is scoped to that function and contends with nothing, which is the same defect
/// `store::now_for_test`'s doc documents elsewhere in this crate. Even hoisted, this lock only
/// serializes CWD mutation AGAINST ITSELF — no OTHER test in this binary that resolves a
/// relative path takes it, so the window between `set_current_dir` calls below is still a real
/// (if currently unexercised) cross-file hazard. The deterministic alternative is
/// `holding_dir_resolves_a_relative_path_to_dot` above, which needs no CWD mutation at all;
/// this test is kept because it also exercises the write()/fsync ROUND TRIP, which the pure
/// unit test above does not cover.
#[test]
fn success_relative_path_fsyncs_dot() {
    let _g = CWD_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let sc = Scratch::new("rel");
    let prev = std::env::current_dir().unwrap();
    std::env::set_current_dir(&sc.dir).unwrap();
    fault_reset();

    // A bare file name is a relative path whose parent is empty → primitive resolves it to ".".
    let r = write(Path::new("relative.json"), b"rel-payload");
    let fsynced = fault_parent_fsynced();
    std::env::set_current_dir(&prev).unwrap(); // restore CWD before asserting

    r.unwrap();
    assert_eq!(
        fsynced.as_deref(),
        Some(Path::new(".")),
        "a relative path must fsync the parent resolved to \".\""
    );
    assert_eq!(
        std::fs::read(sc.path("relative.json")).unwrap(),
        b"rel-payload"
    );
    assert!(!sc.has_durable_temp("relative.json"));
}

/// A pre-existing stale temp of a DIFFERENT (crashed-run) name is irrelevant under the
/// primitive's per-call-unique naming — a fresh write succeeds and ignores the foreign leftover.
/// And for the `exclusive` posture, a stale temp of our OWN about-to-use name does not wedge
/// (pre-removed).
#[test]
fn stale_foreign_temp_is_ignored() {
    let sc = Scratch::new("stale");
    let target = sc.path("k.json");
    // A foreign leftover from a prior crash (a plausible old fixed name).
    std::fs::write(sc.path(".k.json.tmp"), b"crashed-run leftover").unwrap();
    fault_reset();
    write(&target, b"fresh").unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"fresh");
    // The foreign temp is untouched (different name) — proves we didn't collide on it.
    assert_eq!(
        std::fs::read(sc.path(".k.json.tmp")).unwrap(),
        b"crashed-run leftover"
    );
}

/// The `exclusive` + `mode` posture (the signing key): the published file is 0600 on
/// unix, and a pre-planted temp of our own name is cleared rather than wedging (anti-wedge), while
/// O_EXCL still refuses to ADOPT a foreign temp we did not clear.
#[test]
#[cfg(unix)]
fn exclusive_mode_publishes_0600_and_survives_stale_own_temp() {
    use std::os::unix::fs::PermissionsExt as _;
    let sc = Scratch::new("excl");
    let target = sc.path("signing.key");
    let opts = DurableOpts {
        mode: Some(0o600),
        exclusive: true,
    };
    fault_reset();
    // First write establishes the file 0600.
    write_with(&target, b"deadbeef", opts).unwrap();
    let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "exclusive+mode must publish 0600");
    write_with(&target, b"cafebabe", opts).unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"cafebabe");
    assert!(!sc.has_durable_temp("signing.key"));
}

/// THE ANTI-WEDGE PRE-REMOVAL. `exclusive` opens the temp with `O_EXCL`, so a leftover at the
/// exact about-to-use name from a crashed run would make every subsequent write fail `EEXIST`
/// forever -- the signing key could never be rotated again. The `remove_file(&tmp)` that
/// prevents it is awkward to exercise from outside: the temp name embeds a pid and an atomic
/// counter, so no test can name the file it needs to plant.
///
/// `plant_decoy_arm` plants INSIDE the primitive, at the exact path it computed, so this case
/// fails with `EEXIST` the moment the pre-removal is dropped.
#[test]
fn exclusive_pre_removal_clears_a_temp_left_by_a_crashed_run() {
    let sc = Scratch::new("wedge");
    let target = sc.path("signing.key");
    let opts = DurableOpts {
        mode: Some(0o600),
        exclusive: true,
    };
    fault_reset();
    write_with(&target, b"first", opts).unwrap();

    plant_decoy_arm();
    write_with(&target, b"rotated", opts)
        .expect("a temp left by a crashed run must not wedge the exclusive write");
    assert_eq!(
        std::fs::read(&target).unwrap(),
        b"rotated",
        "the rotation published, and published OUR bytes -- never the decoy's"
    );
    assert!(
        !sc.has_durable_temp("signing.key"),
        "the temp was consumed by the rename; nothing leaks"
    );
}

/// THE REMOVE SIDE of the durability contract. Installing an artifact fsyncs the holding
/// directory so its entry survives a power loss; removing one used to skip that (a bare
/// `remove_file` at the plugin-delete call site), which is the asymmetric half -- a crash right
/// after a delete could resurrect the artifact and load it on the next boot. Asserted the same
/// way the write side is: by observing the directory the primitive actually fsync'd, including
/// the RELATIVE-path resolution to "." that a call site cannot dodge.
#[test]
fn remove_unlinks_and_fsyncs_the_holding_dir() {
    let sc = Scratch::new("remove");
    let target = sc.path("plugin-1.0.0.tar.gz");
    fault_reset();
    write(&target, b"artifact").unwrap();

    super::remove(&target).expect("the unlink succeeds");
    assert!(!target.exists(), "the artifact is gone");
    assert_eq!(
        fault_parent_fsynced().as_deref(),
        Some(sc.dir.as_path()),
        "the REMOVAL's directory entry must be fsync'd, exactly as the install's is"
    );

    // A missing target is a real error, not a silent success -- the caller's 404 check is a
    // separate concern and must not be papered over here.
    assert!(
        super::remove(&target).is_err(),
        "removing nothing is an error"
    );
}

/// Concurrent writers to the SAME target — the final file is exactly ONE writer's payload
/// intact (no torn interleave), and no durable temp leaks. Covers the unique-naming race the old
/// fixed `.overlay.tmp`/`.json.tmp` names allowed.
#[test]
fn concurrent_writers_no_torn_file_no_temp_leak() {
    let sc = Scratch::new("concurrent");
    let target = sc.path("shared.json");
    // Distinct fixed-length payloads so a torn interleave would be detectable.
    let payloads: Vec<Vec<u8>> = (0..8u8).map(|i| vec![b'A' + i; 4096]).collect();
    std::thread::scope(|s| {
        for p in &payloads {
            let target = target.clone();
            s.spawn(move || {
                // Each thread must clear its own thread-local fault state (none armed here).
                fault_reset();
                write(&target, p).unwrap();
            });
        }
    });
    let final_bytes = std::fs::read(&target).unwrap();
    assert!(
        payloads.contains(&final_bytes),
        "the final file must be exactly one writer's payload intact (no torn interleave)"
    );
    assert!(
        !sc.has_durable_temp("shared.json"),
        "no durable temp may leak after concurrent writers"
    );
}
/// `std::fs::create_dir_all` leaves each new directory's own ENTRY non-durable, so the first
/// artifact written into a freshly created plugins dir could vanish along with the directory on
/// power loss — even though the file's contents and its holding directory were both fsynced.
/// The primitive must fsync one PARENT per directory it creates, walking the whole missing
/// ancestry, and must leave already-existing directories alone.
#[test]
fn create_dir_all_fsyncs_the_parent_of_every_directory_it_creates() {
    let sc = Scratch::new("mkdir-ancestors");
    fault_reset();

    let leaf = sc.dir.join("a").join("b").join("c");
    create_dir_all(&leaf).unwrap();
    assert!(leaf.is_dir());
    assert_eq!(
        fault_parents_fsynced(),
        vec![sc.dir.clone(), sc.dir.join("a"), sc.dir.join("a").join("b"),],
        "one parent fsync per created directory, shallowest first"
    );

    // Re-running over an existing tree creates nothing, so it must fsync nothing.
    fault_reset();
    create_dir_all(&leaf).unwrap();
    assert!(
        fault_parents_fsynced().is_empty(),
        "an already-durable directory must not be re-fsynced"
    );

    // Only the MISSING suffix is created, so only its parents are fsynced.
    fault_reset();
    let deeper = leaf.join("d");
    create_dir_all(&deeper).unwrap();
    assert_eq!(fault_parents_fsynced(), vec![leaf.clone()]);
}
