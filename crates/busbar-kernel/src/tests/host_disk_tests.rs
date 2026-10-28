// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::mechanism::call::Outcome;
use std::path::PathBuf;

/// A fresh directory for one test.
fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-disk-lane-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn dest(path: &Path, rotate_at: Option<u64>) -> DiskDest {
    DiskDest {
        key: "path".into(),
        path: path.display().to_string(),
        rotate_at,
        rotate: DiskRotate::Rename {
            keep: busbar_contract::services::DISK_KEEP,
        },
    }
}

/// A destination rotated as 1.5.5 rotated it: truncated in place.
fn truncating(path: &Path, rotate_at: Option<u64>) -> DiskDest {
    DiskDest {
        rotate: DiskRotate::Truncate,
        ..dest(path, rotate_at)
    }
}

/// 1.5.5's ROTATION (v1.5.5 `crates/busbar/src/export/file.rs:96-108`, "roll over by truncation rather
/// than a rename"; Q128 arch u50): a due file is truncated in place and the append lands from empty;
/// no archive is ever written, and, as 1.5.5 reported nothing of it, no rotation is reported. RED
/// before the host honoured `DiskRotate::Truncate`: the file was renamed to `.1`.
#[test]
fn a_due_file_truncates_in_place_under_truncate() {
    let d = dir("truncate");
    let file = d.join("log.jsonl");
    let to = truncating(&file, Some(4));
    assert!(!append(&to, b"abc\n").rotated, "an absent file is not due");
    let second = append(&to, b"def\n");
    assert_eq!((second.step, second.rotated, second.faults), (0, false, 0));
    assert_eq!(std::fs::read(&file).unwrap(), b"def\n");
    assert!(!d.join("log.jsonl.1").exists(), "no archive is written");
    let _ = std::fs::remove_dir_all(&d);
}

/// 1.5.5's WRITE: each append creates the file when absent and adds the bytes after what is
/// there, unchanged — the file is the concatenation of every append, byte for byte.
#[test]
fn appends_create_the_file_and_land_whole_in_order() {
    let d = dir("order");
    let file = d.join("log.jsonl");
    let to = dest(&file, None);
    for line in [&b"{\"a\":1}\n"[..], b"{\"b\":2}\n{\"c\":3}\n"] {
        assert_eq!(
            append(&to, line),
            DiskReport {
                step: 0,
                rotated: false,
                faults: 0,
                error: "",
            }
        );
    }
    assert_eq!(
        std::fs::read(&file).unwrap(),
        b"{\"a\":1}\n{\"b\":2}\n{\"c\":3}\n"
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// An unopenable path (its directory is missing) is a FAILED open, in the operating system's words;
/// nothing is created.
#[test]
fn an_unopenable_path_fails_the_open_step() {
    let d = dir("open");
    let file = d.join("missing-dir").join("log.jsonl");
    let report = append(&dest(&file, None), b"x\n");
    assert_eq!(report.step, DISK_OPEN_FAILED);
    assert!(!report.error.is_empty());
    assert!(!file.exists());
    let _ = std::fs::remove_dir_all(&d);
}

/// ROTATION IS THE HOST'S: a file already at the destination's threshold is renamed to `<path>.1`
/// (older archives shifted up) BEFORE the append, which then starts the live file afresh; below the
/// threshold nothing rotates.
#[test]
fn a_due_file_rotates_by_rename_before_the_append() {
    let d = dir("rotate");
    let file = d.join("log.jsonl");
    let to = dest(&file, Some(4));
    assert!(!append(&to, b"abc\n").rotated, "an absent file is not due");
    let second = append(&to, b"def\n");
    assert!(second.rotated && second.faults == 0 && second.step == 0);
    assert_eq!(std::fs::read(&file).unwrap(), b"def\n");
    assert_eq!(std::fs::read(d.join("log.jsonl.1")).unwrap(), b"abc\n");
    let third = append(&to, b"ghi\n");
    assert!(third.rotated);
    assert_eq!(std::fs::read(d.join("log.jsonl.2")).unwrap(), b"abc\n");
    assert_eq!(std::fs::read(d.join("log.jsonl.1")).unwrap(), b"def\n");
    assert_eq!(std::fs::read(&file).unwrap(), b"ghi\n");
    let _ = std::fs::remove_dir_all(&d);
}

/// KEEP 0 IS 1.5.5'S ROLLOVER (v1.5.5 `crates/busbar/src/export/file.rs` 96-108: "roll over by
/// truncation rather than a rename"): a due file that keeps no archives is TRUNCATED IN PLACE —
/// the same inode, no `<path>.1` or any other file beside it — and the append starts it afresh,
/// reported as no rotation. Below the threshold it appends as ever. RED before: keep 0 was
/// clamped to one archive, the live file renamed to `<path>.1` and a new inode created.
#[test]
fn a_due_keep_zero_destination_truncates_in_place_and_keeps_no_archive() {
    let d = dir("keep0");
    let file = d.join("log.jsonl");
    let to = DiskDest {
        rotate: DiskRotate::declared(Some(0)),
        ..dest(&file, Some(8))
    };
    let first = append(&to, b"abc\n");
    assert_eq!((first.step, first.rotated, first.faults), (0, false, 0));
    assert_eq!(append(&to, b"def\n").step, 0);
    assert_eq!(std::fs::read(&file).unwrap(), b"abc\ndef\n");
    #[cfg(unix)]
    let before = {
        use std::os::unix::fs::MetadataExt as _;
        std::fs::metadata(&file).unwrap().ino()
    };
    let due = append(&to, b"ghi\n");
    assert_eq!((due.step, due.rotated, due.faults), (0, false, 0));
    assert_eq!(std::fs::read(&file).unwrap(), b"ghi\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        assert_eq!(
            std::fs::metadata(&file).unwrap().ino(),
            before,
            "the live file is truncated in place, never replaced"
        );
    }
    let mut names: Vec<String> = std::fs::read_dir(&d)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, ["log.jsonl"], "no archive, nothing else written");
    let _ = std::fs::remove_dir_all(&d);
}

/// THE HOST'S POLICY from a manifest's `keep`: `0` truncates in place, `n` renames keeping `n`
/// archives, and none declared takes 1.5.5's truncation.
#[test]
fn a_declared_keep_maps_to_the_hosts_rotation() {
    assert_eq!(DiskRotate::declared(Some(0)), DiskRotate::Truncate);
    assert_eq!(
        DiskRotate::declared(Some(3)),
        DiskRotate::Rename { keep: 3 }
    );
    assert_eq!(DiskRotate::declared(None), DiskRotate::Truncate);
}

/// Retention: at `keep` archives the oldest is dropped, never more than `keep` kept.
#[test]
fn rotation_keeps_at_most_keep_archives() {
    let d = dir("keep");
    let file = d.join("log");
    let path = file.display().to_string();
    for i in 0..5 {
        std::fs::write(&file, format!("{i}")).unwrap();
        let (renamed, faults) = rotate(&path, 2);
        assert!(renamed);
        assert_eq!(faults, 0);
    }
    assert_eq!(std::fs::read_to_string(format!("{path}.1")).unwrap(), "4");
    assert_eq!(std::fs::read_to_string(format!("{path}.2")).unwrap(), "3");
    assert!(!Path::new(&format!("{path}.3")).exists());
    let _ = std::fs::remove_dir_all(&d);
}

/// KEEP N, DEFAULT 9 (owner signed 2026-10-27): a destination rotated by rename at its size keeps
/// `<path>.1` .. `<path>.9`, newest first; the tenth rotation drops only the oldest archive, and
/// every rotation is reported (`rotated`), so no line goes without a report.
#[test]
fn a_rename_rotation_keeps_nine_archives_and_drops_only_the_oldest() {
    let d = dir("keep9");
    let file = d.join("log.jsonl");
    let to = DiskDest {
        rotate: DiskRotate::declared(Some(busbar_contract::services::DISK_KEEP)),
        ..dest(&file, Some(3))
    };
    for i in 0..11_u8 {
        let report = append(&to, format!("{i:02}\n").as_bytes());
        assert_eq!((report.step, report.faults), (0, 0), "append {i}");
        assert_eq!(
            report.rotated,
            i > 0,
            "append {i}: every due file is rotated and reported"
        );
    }
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "10\n");
    for n in 1..=9_u8 {
        let archived = std::fs::read_to_string(d.join(format!("log.jsonl.{n}"))).unwrap();
        assert_eq!(archived, format!("{:02}\n", 10 - n), "archive {n}");
    }
    assert!(
        !d.join("log.jsonl.10").exists(),
        "never more than nine archives: the oldest (`00`) was dropped"
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// A rename that cannot happen (no live file) is reported as the rename step, and nothing else.
#[test]
fn a_failed_rename_is_reported_and_nothing_is_truncated() {
    let d = dir("rename");
    let (renamed, faults) = rotate(&d.join("absent").display().to_string(), 3);
    assert!(!renamed);
    assert_eq!(faults, DISK_RENAME_FAILED);
    let _ = std::fs::remove_dir_all(&d);
}

/// THE LANE: an append submitted runs off the caller's thread and its report reaches the caller's
/// `Later` as the stored READY answer; appends land in submission order.
#[test]
fn the_lane_runs_appends_in_order_and_answers_through_later() {
    let d = dir("lane");
    let file = d.join("log.jsonl");
    let lane = DiskLane::default();
    let (tx, rx) = std::sync::mpsc::channel();
    for n in 0..20 {
        let tx = tx.clone();
        let later: Later = Box::new(move |s| {
            let _ = tx.send(s);
        });
        assert!(lane
            .submit(dest(&file, None), format!("{n}\n").into_bytes(), later)
            .is_ok());
    }
    for _ in 0..20 {
        let stored = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the lane answers");
        assert_eq!(stored.outcome, Outcome::Ready);
        assert_eq!(DiskReport::of(&stored).step, 0);
    }
    let want: String = (0..20).map(|n| format!("{n}\n")).collect();
    assert_eq!(std::fs::read_to_string(&file).unwrap(), want);
    let _ = std::fs::remove_dir_all(&d);
}

/// A JOB runs ON THE LANE THREAD, in order with the appends (THE DESIGN §11.11 R4 as the OWNER
/// amended it: a disk-declared secret source's config-time resolve runs here), and a job that
/// panics is its own failure: the appends behind it still land.
#[test]
fn a_job_runs_on_the_lane_thread_and_a_panicking_one_leaves_the_lane_running() {
    let d = dir("job");
    let file = d.join("log.jsonl");
    let lane = DiskLane::default();
    let (tx, rx) = std::sync::mpsc::channel();
    let ran_on = tx.clone();
    lane.run(Box::new(move || {
        let _ = ran_on.send(std::thread::current().name().map(str::to_string));
    }))
    .expect("the lane takes the job");
    assert_eq!(
        rx.recv_timeout(std::time::Duration::from_secs(10))
            .expect("the job ran"),
        Some(LANE_THREAD.to_string())
    );
    assert_ne!(std::thread::current().name(), Some(LANE_THREAD));

    lane.run(Box::new(|| panic!("a job that panics")))
        .expect("the lane takes the job");
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let later: Later = Box::new(move |s| {
        let _ = done_tx.send(s);
    });
    assert!(lane
        .submit(dest(&file, None), b"after\n".to_vec(), later)
        .is_ok());
    let stored = done_rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("the lane still answers after a job panicked");
    assert_eq!(stored.outcome, Outcome::Ready);
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "after\n");
    drop(tx);
    let _ = std::fs::remove_dir_all(&d);
}

/// AN APPEND WHOSE COMPLETION PANICS FAILS ONLY ITSELF (Q128 arch u32 #39; the per-append
/// fail-closed rule above): the appends behind it still land and still answer.
///
/// RED before the fix: the Append arm called `later` with no `catch_unwind`, so the panic ended the
/// lane thread; every later submit answered LANE_GONE and nothing restarted the lane.
#[test]
fn an_append_whose_completion_panics_leaves_the_lane_running() {
    let d = dir("later-panic");
    let file = d.join("log.jsonl");
    let lane = DiskLane::default();
    let panicking: Later = Box::new(|_| panic!("a completion that panics"));
    assert!(lane
        .submit(dest(&file, None), b"first\n".to_vec(), panicking)
        .is_ok());
    let (tx, rx) = std::sync::mpsc::channel();
    let later: Later = Box::new(move |s| {
        let _ = tx.send(s);
    });
    // The submit may race the panicking completion: before the fix it is refused LANE_GONE at once
    // or never answered; either is the lane lost.
    let submitted = lane.submit(dest(&file, None), b"second\n".to_vec(), later);
    assert!(submitted.is_ok(), "the lane still takes appends");
    let stored = rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("the lane still answers after a completion panicked");
    assert_eq!(stored.outcome, Outcome::Ready);
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "first\nsecond\n");
    let _ = std::fs::remove_dir_all(&d);
}
