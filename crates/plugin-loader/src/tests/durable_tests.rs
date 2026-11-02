// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::durable::hooks::{
    fault_arm, fault_reset, parent_fsynced as fault_parent_fsynced,
    parents_fsynced as fault_parents_fsynced, plant_decoy_arm, FaultStep,
};
use crate::durable::{create_dir_all, holding_dir, write, write_with, DurableOpts};
use std::path::{Path, PathBuf};

const ENOSPC: i32 = 28;
const EIO: i32 = 5;

const EINVAL: i32 = 22;

static CWD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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

#[test]
fn success_absolute_path_roundtrips_no_temp() {
    let sc = Scratch::new("abs");
    let target = sc.path("cfg.json");
    fault_reset();
    write(&target, b"payload-A").unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"payload-A");

    write(&target, b"payload-B").unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"payload-B");
    assert!(!sc.has_durable_temp("cfg.json"));
}

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

#[test]
fn success_relative_path_fsyncs_dot() {
    let _g = CWD_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let sc = Scratch::new("rel");
    let prev = std::env::current_dir().unwrap();
    std::env::set_current_dir(&sc.dir).unwrap();
    fault_reset();

    let r = write(Path::new("relative.json"), b"rel-payload");
    let fsynced = fault_parent_fsynced();
    std::env::set_current_dir(&prev).unwrap();

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

#[test]
fn stale_foreign_temp_is_ignored() {
    let sc = Scratch::new("stale");
    let target = sc.path("k.json");

    std::fs::write(sc.path(".k.json.tmp"), b"crashed-run leftover").unwrap();
    fault_reset();
    write(&target, b"fresh").unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"fresh");

    assert_eq!(
        std::fs::read(sc.path(".k.json.tmp")).unwrap(),
        b"crashed-run leftover"
    );
}

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

    write_with(&target, b"deadbeef", opts).unwrap();
    let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "exclusive+mode must publish 0600");
    write_with(&target, b"cafebabe", opts).unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"cafebabe");
    assert!(!sc.has_durable_temp("signing.key"));
}

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

#[test]
fn remove_unlinks_and_fsyncs_the_holding_dir() {
    let sc = Scratch::new("remove");
    let target = sc.path("plugin-1.0.0.tar.gz");
    fault_reset();
    write(&target, b"artifact").unwrap();

    fault_reset();

    crate::durable::remove(&target).expect("the unlink succeeds");
    assert!(!target.exists(), "the artifact is gone");
    assert_eq!(
        fault_parent_fsynced().as_deref(),
        Some(sc.dir.as_path()),
        "the REMOVAL's directory entry must be fsync'd, exactly as the install's is"
    );

    assert!(
        crate::durable::remove(&target).is_err(),
        "removing nothing is an error"
    );
}

#[test]
fn concurrent_writers_no_torn_file_no_temp_leak() {
    let sc = Scratch::new("concurrent");
    let target = sc.path("shared.json");

    let payloads: Vec<Vec<u8>> = (0..8u8).map(|i| vec![b'A' + i; 4096]).collect();
    std::thread::scope(|s| {
        for p in &payloads {
            let target = target.clone();
            s.spawn(move || {
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

#[test]
fn create_dir_all_fsyncs_the_parent_of_every_directory_it_creates() {
    let sc = Scratch::new("mkdir-ancestors");
    fault_reset();

    let leaf = sc.dir.join("a").join("b").join("leaf");
    create_dir_all(&leaf).unwrap();
    assert!(leaf.is_dir());
    assert_eq!(
        fault_parents_fsynced(),
        vec![sc.dir.clone(), sc.dir.join("a"), sc.dir.join("a").join("b"),],
        "one parent fsync per created directory, shallowest first"
    );

    fault_reset();
    create_dir_all(&leaf).unwrap();
    assert!(
        fault_parents_fsynced().is_empty(),
        "an already-durable directory must not be re-fsynced"
    );

    fault_reset();
    let deeper = leaf.join("d");
    create_dir_all(&deeper).unwrap();
    assert_eq!(fault_parents_fsynced(), vec![leaf.clone()]);
}

#[test]
fn create_dir_all_propagates_a_genuine_non_already_exists_error() {
    let sc = Scratch::new("mkdir-through-file");
    let blocker = sc.path("blocker-file");
    std::fs::write(&blocker, b"not a directory").unwrap();

    let child = blocker.join("child");
    let err = create_dir_all(&child).expect_err(
        "creating a directory UNDER an existing plain file must fail, not silently succeed",
    );
    assert_ne!(
        err.kind(),
        std::io::ErrorKind::AlreadyExists,
        "the real failure reason must survive, not be reported as AlreadyExists: {err:?}"
    );
    assert!(
        !child.exists(),
        "no directory may have been created on the failed path"
    );
}

#[test]
fn create_dir_all_concurrent_racers_all_succeed_on_the_same_new_path() {
    let sc = Scratch::new("mkdir-race");
    let target = std::sync::Arc::new(sc.dir.join("race-a").join("race-b").join("race-c"));

    let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let target = target.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                create_dir_all(&target)
            })
        })
        .collect();

    for h in handles {
        h.join()
            .unwrap()
            .expect("every racing caller must observe success, including the race losers");
    }
    assert!(target.is_dir());
}

#[test]
fn a_publish_whose_directory_fsync_fails_is_an_error() {
    let scratch = Scratch::new("dirfsync-publish");
    let target = scratch.path("overlay.json");
    fault_reset();
    fault_arm(FaultStep::DirSync, EIO);
    let err = write(&target, b"new contents")
        .expect_err("a directory fsync that failed is not a durable publish");
    assert_eq!(
        err.raw_os_error(),
        Some(EIO),
        "the fsync's own error surfaces"
    );

    assert_eq!(std::fs::read(&target).unwrap(), b"new contents");
}

#[test]
fn a_removal_whose_directory_fsync_fails_is_an_error() {
    let scratch = Scratch::new("dirfsync-remove");
    let target = scratch.path("plugin.tar.gz");
    std::fs::write(&target, b"artifact").unwrap();
    fault_reset();
    fault_arm(FaultStep::DirSync, EIO);
    let err = crate::durable::remove(&target).expect_err("the removal was not made durable");
    assert_eq!(err.raw_os_error(), Some(EIO));
}

#[test]
fn a_created_directory_whose_parent_fsync_fails_is_an_error() {
    let scratch = Scratch::new("dirfsync-mkdir");
    fault_reset();
    fault_arm(FaultStep::DirSync, EIO);
    let err = create_dir_all(&scratch.path("plugins"))
        .expect_err("the new directory's entry was not made durable");
    assert_eq!(err.raw_os_error(), Some(EIO));
}

#[test]
fn a_directory_fsync_the_filesystem_does_not_support_is_not_an_error() {
    let scratch = Scratch::new("dirfsync-unsupported");
    let target = scratch.path("state.json");
    fault_reset();
    fault_arm(FaultStep::DirSync, EINVAL);
    write(&target, b"contents").expect("an unsupported directory fsync is not a failure");
    assert_eq!(std::fs::read(&target).unwrap(), b"contents");
}
