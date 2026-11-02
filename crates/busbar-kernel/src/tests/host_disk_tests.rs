// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::mechanism::call::Outcome;
use std::path::PathBuf;

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

fn truncating(path: &Path, rotate_at: Option<u64>) -> DiskDest {
    DiskDest {
        rotate: DiskRotate::Truncate,
        ..dest(path, rotate_at)
    }
}

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

#[test]
fn a_declared_keep_maps_to_the_hosts_rotation() {
    assert_eq!(DiskRotate::declared(Some(0)), DiskRotate::Truncate);
    assert_eq!(
        DiskRotate::declared(Some(3)),
        DiskRotate::Rename { keep: 3 }
    );
    assert_eq!(DiskRotate::declared(None), DiskRotate::Truncate);
}

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

#[test]
fn a_failed_rename_is_reported_and_nothing_is_truncated() {
    let d = dir("rename");
    let (renamed, faults) = rotate(&d.join("absent").display().to_string(), 3);
    assert!(!renamed);
    assert_eq!(faults, DISK_RENAME_FAILED);
    let _ = std::fs::remove_dir_all(&d);
}

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
        Some("busbar-disk-secrets".to_string())
    );
    assert_ne!(std::thread::current().name(), Some(LANE_THREAD));

    lane.run(Box::new(|| panic!("a job that panics")))
        .expect("the lane takes the job");
    let (healthy_tx, healthy) = std::sync::mpsc::channel();
    lane.run(Box::new(move || {
        let _ = healthy_tx.send(());
    }))
    .expect("a panic does not disconnect secret admission");
    healthy
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("the secret worker survives its job's panic");
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

    let submitted = lane.submit(dest(&file, None), b"second\n".to_vec(), later);
    assert!(submitted.is_ok(), "the lane still takes appends");
    let stored = rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("the lane still answers after a completion panicked");
    assert_eq!(stored.outcome, Outcome::Ready);
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "first\nsecond\n");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_blocked_disk_job_does_not_block_ordered_appends_or_their_completions() {
    let d = dir("blocked-resolve");
    let file = d.join("log.jsonl");
    let lane = DiskLane::default();
    let (entered_tx, entered) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel();
    let (finished_tx, finished) = std::sync::mpsc::channel();
    lane.run(Box::new(move || {
        let _ = entered_tx.send(());
        let _ = released.recv();
        let _ = finished_tx.send(());
    }))
    .unwrap();
    let running = entered.recv_timeout(std::time::Duration::from_secs(10));
    let (drained_tx, drained) = std::sync::mpsc::channel();
    let mut queued = true;
    for n in 0..LANE_BOUND {
        let tx = drained_tx.clone();
        queued &= lane
            .run(Box::new(move || {
                if n + 1 == LANE_BOUND {
                    let _ = tx.send(());
                }
            }))
            .is_ok();
    }
    let full = lane.run(Box::new(|| {}));
    let (done_tx, done) = std::sync::mpsc::channel();
    let mut submitted = true;
    for bytes in [b"first\n".as_slice(), b"second\n"] {
        let tx = done_tx.clone();
        submitted &= lane
            .submit(
                dest(&file, None),
                bytes.to_vec(),
                Box::new(move |report| {
                    let _ = tx.send(report);
                }),
            )
            .is_ok();
    }
    let first = submitted.then(|| done.recv_timeout(std::time::Duration::from_secs(2)));
    let second = submitted.then(|| done.recv_timeout(std::time::Duration::from_secs(2)));

    let _ = release.send(());
    let cleaned = finished.recv_timeout(std::time::Duration::from_secs(10));
    let backlog_cleaned = drained.recv_timeout(std::time::Duration::from_secs(10));
    if first.as_ref().is_some_and(Result::is_err) {
        let _ = done.recv_timeout(std::time::Duration::from_secs(10));
    }
    if second.as_ref().is_some_and(Result::is_err) {
        let _ = done.recv_timeout(std::time::Duration::from_secs(10));
    }
    let bytes = std::fs::read(&file);
    drop(lane);
    let _ = std::fs::remove_dir_all(&d);
    running.expect("the disk job entered its blocking callback");
    cleaned.expect("the callback is released before the test ends");
    backlog_cleaned.expect("the bounded backlog is drained before the test ends");
    assert!(queued, "the existing bound admits the queued jobs");
    assert_eq!(
        full,
        Err(LANE_FULL),
        "blocking jobs retain bounded admission"
    );
    assert!(submitted, "appends retain their own queue admission");
    assert_eq!(
        first
            .expect("first append was admitted")
            .expect("append completes while the disk job is blocked")
            .outcome,
        Outcome::Ready
    );
    assert_eq!(
        second
            .expect("second append was admitted")
            .expect("second append completes while the disk job is blocked")
            .outcome,
        Outcome::Ready
    );
    assert_eq!(bytes.unwrap(), b"first\nsecond\n");
}

#[test]
fn full_secret_admission_drops_reentrant_custody_without_blocking_appends() {
    use std::sync::Arc;

    struct Reenter {
        lane: Arc<DiskLane>,
        file: PathBuf,
        answer: std::sync::mpsc::Sender<Result<(), DiskReport>>,
        completed: std::sync::mpsc::Sender<Outcome>,
    }
    impl Drop for Reenter {
        fn drop(&mut self) {
            let done = self.completed.clone();
            let result = self.lane.submit(
                dest(&self.file, None),
                b"from-drop\n".to_vec(),
                Box::new(move |stored| {
                    let _ = done.send(stored.outcome);
                }),
            );
            let _ = self.answer.send(result);
        }
    }

    let d = dir("reentrant-secret-refusal");
    let file = d.join("log.jsonl");
    let lane = Arc::new(DiskLane::default());
    let (entered_tx, entered) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel();
    lane.run(Box::new(move || {
        let _ = entered_tx.send(());
        let _ = released.recv_timeout(std::time::Duration::from_secs(30));
    }))
    .unwrap();
    let running = entered.recv_timeout(std::time::Duration::from_secs(10));
    let mut admitted = true;
    for _ in 0..LANE_BOUND {
        admitted &= lane.run(Box::new(|| {})).is_ok();
    }
    let (answer, answered) = std::sync::mpsc::channel();
    let (completed, completion) = std::sync::mpsc::channel();
    let reenter = Reenter {
        lane: Arc::clone(&lane),
        file: file.clone(),
        answer,
        completed,
    };

    let submitter = std::thread::spawn(move || lane.run(Box::new(move || drop(reenter))));
    let reentered = answered.recv_timeout(std::time::Duration::from_secs(2));
    let appended = completion.recv_timeout(std::time::Duration::from_secs(2));
    let _ = release.send(());
    running.expect("the controlled secret job entered");
    assert!(admitted, "the declared queue bound remains available");
    assert!(reentered.expect("reentrant Drop returns").is_ok());
    assert_eq!(
        appended.expect("the reentrant append completes"),
        Outcome::Ready
    );
    assert_eq!(submitter.join().unwrap(), Err(LANE_FULL));
    assert_eq!(std::fs::read(&file).unwrap(), b"from-drop\n");
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn an_append_completion_can_submit_another_whole_append() {
    let d = dir("reentrant-completion");
    let file = d.join("log.jsonl");
    let lane = std::sync::Arc::new(DiskLane::default());
    let inside = std::sync::Arc::clone(&lane);
    let next = dest(&file, None);
    let (answer, answered) = std::sync::mpsc::channel();
    lane.submit(
        dest(&file, None),
        b"first\n".to_vec(),
        Box::new(move |first| {
            let done = answer.clone();
            let result = inside.submit(
                next,
                b"second\n".to_vec(),
                Box::new(move |second| {
                    let _ = done.send((first.outcome, second.outcome));
                }),
            );
            assert!(result.is_ok());
        }),
    )
    .unwrap();
    assert_eq!(
        answered
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap(),
        (Outcome::Ready, Outcome::Ready)
    );
    assert_eq!(std::fs::read(&file).unwrap(), b"first\nsecond\n");
    let _ = std::fs::remove_dir_all(d);
}
