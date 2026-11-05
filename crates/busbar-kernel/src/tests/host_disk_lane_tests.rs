// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::Duration;

const WAIT: Duration = Duration::from_secs(5);

pub(crate) struct HeldDestination {
    release: Sender<()>,
    finished: Receiver<()>,
}

impl Drop for HeldDestination {
    fn drop(&mut self) {
        let _ = self.release.send(());
        let _ = self.finished.recv_timeout(WAIT);
    }
}

// Hold the real worker inside completion, with the same destination custody as
// during its synchronous append. RAII releases the gate even if an assertion fails.
pub(crate) fn hold_destination(lane: &DiskLane, dest: DiskDest) -> HeldDestination {
    let (entered_tx, entered) = channel();
    let (release, released) = channel();
    let (finished_tx, finished) = channel();
    lane.submit(
        dest,
        Vec::new(),
        Box::new(move |_| {
            let _ = entered_tx.send(());
            let _ = released.recv_timeout(Duration::from_secs(30));
            let _ = finished_tx.send(());
        }),
    )
    .unwrap();
    let held = HeldDestination { release, finished };
    entered
        .recv_timeout(WAIT)
        .expect("controlled destination entered");
    held
}

fn destination(path: &Path) -> DiskDest {
    DiskDest {
        key: "path".into(),
        path: path.display().to_string(),
        rotate_at: Some(1),
        rotate: DiskRotate::Rename { keep: 2 },
    }
}

fn scratch(name: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "busbar-destination-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn blocked_destination_preserves_its_fifo_and_rotation_while_another_file_completes() {
    let root = scratch("isolation");
    let a = root.join("a.jsonl");
    let b = root.join("b.jsonl");
    let lane = DiskLane::default();
    let held = hold_destination(&lane, destination(&a));
    let (done, answers) = channel();
    for n in 1..=2 {
        let mut dest = destination(&a);
        // Different manifest keys for the same configured path share custody.
        dest.key = format!("key-{n}");
        let done = done.clone();
        lane.submit(
            dest,
            format!("{n}\n").into_bytes(),
            Box::new(move |report| {
                let _ = done.send((n, DiskReport::of(&report)));
            }),
        )
        .unwrap();
    }
    let (other, completed) = channel();
    lane.submit(
        destination(&b),
        b"other\n".to_vec(),
        Box::new(move |report| {
            let _ = other.send(DiskReport::of(&report));
        }),
    )
    .unwrap();
    let independent = completed.recv_timeout(WAIT);
    let no_overtake = answers.try_recv();
    let before = std::fs::read(&a).unwrap();
    drop(held);
    let first = answers.recv_timeout(WAIT).unwrap();
    let second = answers.recv_timeout(WAIT).unwrap();
    assert_eq!(
        independent
            .expect("unrelated append completes while A is blocked")
            .step,
        0
    );
    assert!(matches!(
        no_overtake,
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    assert!(
        before.is_empty(),
        "same destination must not overtake its active job"
    );
    assert_eq!((first.0, first.1.step, first.1.rotated), (1, 0, false));
    assert_eq!((second.0, second.1.step, second.1.rotated), (2, 0, true));
    assert_eq!(std::fs::read(&a).unwrap(), b"2\n");
    assert_eq!(std::fs::read(root.join("a.jsonl.1")).unwrap(), b"1\n");
    assert_eq!(std::fs::read(&b).unwrap(), b"other\n");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn saturated_destination_refuses_and_drops_custody_outside_the_lock() {
    struct Reenter {
        lane: Arc<DiskLane>,
        dest: DiskDest,
        done: Sender<DiskReport>,
    }
    impl Drop for Reenter {
        fn drop(&mut self) {
            let done = self.done.clone();
            self.lane
                .submit(
                    self.dest.clone(),
                    b"healthy\n".to_vec(),
                    Box::new(move |report| {
                        let _ = done.send(DiskReport::of(&report));
                    }),
                )
                .unwrap();
        }
    }
    let root = scratch("saturation");
    let a = destination(&root.join("a"));
    let lane = Arc::new(DiskLane::default());
    let held = hold_destination(&lane, a.clone());
    let (done, drained) = channel();
    for _ in 0..DESTINATION_BOUND {
        let done = done.clone();
        lane.submit(
            a.clone(),
            b"a".to_vec(),
            Box::new(move |_| {
                let _ = done.send(());
            }),
        )
        .unwrap();
    }
    let (answer, answered) = channel();
    let reenter = Reenter {
        lane: Arc::clone(&lane),
        dest: destination(&root.join("b")),
        done: answer,
    };
    let submitter_lane = Arc::clone(&lane);
    let submitter = std::thread::spawn(move || {
        submitter_lane.submit(a, vec![0; 16], Box::new(move |_| drop(reenter)))
    });
    let healthy = answered.recv_timeout(WAIT);
    drop(held);
    for _ in 0..DESTINATION_BOUND {
        drained.recv_timeout(WAIT).unwrap();
    }
    assert_eq!(submitter.join().unwrap(), Err(refused(LANE_FULL)));
    assert_eq!(
        healthy
            .expect("reentrant refusal Drop can submit another destination")
            .step,
        0
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn dropping_the_executor_drains_accepted_custody_and_destination_churn_is_bounded() {
    let root = scratch("lifecycle");
    let lane = DiskLane::default();
    let (done, completed) = channel();
    for n in 0..DESTINATION_LIMIT * 2 {
        let done = done.clone();
        lane.submit(
            destination(&root.join(format!("{n}"))),
            b"x".to_vec(),
            Box::new(move |report| {
                let _ = done.send(DiskReport::of(&report));
            }),
        )
        .unwrap();
        assert_eq!(completed.recv_timeout(WAIT).unwrap().step, 0);
    }
    let path = destination(&root.join("drain"));
    let held = hold_destination(&lane, path.clone());
    let (done, completed) = channel();
    lane.submit(
        path,
        b"retained\n".to_vec(),
        Box::new(move |report| {
            let _ = done.send(DiskReport::of(&report));
        }),
    )
    .unwrap();
    drop(lane);
    drop(held);
    assert_eq!(completed.recv_timeout(WAIT).unwrap().step, 0);
    assert_eq!(std::fs::read(root.join("drain")).unwrap(), b"retained\n");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn all_workers_and_destination_slots_remain_bounded_under_saturation() {
    let root = scratch("all-slots");
    let lane = DiskLane::default();
    let held: Vec<_> = (0..APPEND_WORKERS)
        .map(|n| hold_destination(&lane, destination(&root.join(format!("active-{n}")))))
        .collect();
    let (done, completed) = channel();
    for n in APPEND_WORKERS..DESTINATION_LIMIT {
        let done = done.clone();
        lane.submit(
            destination(&root.join(format!("queued-{n}"))),
            b"x".to_vec(),
            Box::new(move |report| {
                let _ = done.send(DiskReport::of(&report));
            }),
        )
        .unwrap();
    }
    assert!(
        matches!(
            completed.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ),
        "no extra worker bypasses the bound"
    );
    assert_eq!(
        lane.submit(
            destination(&root.join("overflow")),
            b"x".to_vec(),
            Box::new(|_| {})
        ),
        Err(refused(LANE_FULL))
    );
    drop(held);
    for _ in APPEND_WORKERS..DESTINATION_LIMIT {
        assert_eq!(completed.recv_timeout(WAIT).unwrap().step, 0);
    }
    // Drained queues free admission; the worker pool is reused, not grown per path.
    let (done, completed) = channel();
    lane.submit(
        destination(&root.join("overflow")),
        b"x".to_vec(),
        Box::new(move |report| {
            let _ = done.send(DiskReport::of(&report));
        }),
    )
    .unwrap();
    assert_eq!(completed.recv_timeout(WAIT).unwrap().step, 0);
    std::fs::remove_dir_all(root).unwrap();
}
