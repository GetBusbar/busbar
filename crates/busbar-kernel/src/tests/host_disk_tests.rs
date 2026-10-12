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
        keep: busbar_contract::services::DISK_KEEP,
    }
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
