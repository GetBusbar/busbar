// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use std::sync::atomic::AtomicUsize;
use std::sync::mpsc;

/// An item that counts its refreshes and is due again after `every`, optionally parked on a gate
/// the first time it runs.
struct Counting {
    every: Duration,
    runs: AtomicUsize,
    gate: Mutex<Option<mpsc::Receiver<()>>>,
    entered: Mutex<Option<mpsc::SyncSender<()>>>,
    deadline: Option<Instant>,
}

impl Counting {
    fn new(every: Duration) -> Arc<Self> {
        Arc::new(Self {
            every,
            runs: AtomicUsize::new(0),
            gate: Mutex::new(None),
            entered: Mutex::new(None),
            deadline: None,
        })
    }

    fn runs(&self) -> usize {
        self.runs.load(Ordering::SeqCst)
    }
}

impl Refreshable for Counting {
    fn refresh(&self, now: Instant) -> Instant {
        self.runs.fetch_add(1, Ordering::SeqCst);
        if let Some(entered) = self.entered.lock().unwrap().take() {
            let _ = entered.send(());
        }
        let gate = self.gate.lock().unwrap().take();
        if let Some(gate) = gate {
            let _ = gate.recv();
        }
        now + self.every
    }

    fn deadline(&self) -> Option<Instant> {
        self.deadline
    }
}

fn weak(item: &Arc<Counting>) -> Weak<dyn Refreshable> {
    Arc::downgrade(item) as Weak<dyn Refreshable>
}

fn eventually(what: &str, check: impl Fn() -> bool) {
    let until = Instant::now() + Duration::from_secs(10);
    while Instant::now() < until {
        if check() {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("{what}");
}

#[test]
fn a_hung_refresh_never_holds_back_another_items_renewal() {
    let refresher = Refresher::start("test-refresh-hung", WORKERS).expect("threads start");
    let hung = Counting::new(Duration::from_secs(3600));
    let (release, gate) = mpsc::channel();
    let (entered_tx, entered) = mpsc::sync_channel(1);
    *hung.gate.lock().unwrap() = Some(gate);
    *hung.entered.lock().unwrap() = Some(entered_tx);
    refresher.keep(weak(&hung), Instant::now());
    entered
        .recv_timeout(Duration::from_secs(10))
        .expect("the hung item runs");

    let healthy = Counting::new(Duration::from_millis(20));
    refresher.keep(weak(&healthy), Instant::now());
    eventually("the healthy item renews while another hangs", || {
        healthy.runs() >= 5
    });
    assert_eq!(hung.runs(), 1, "a running item is never queued twice");
    release.send(()).expect("release the hung item");
}

#[test]
fn due_items_run_earliest_deadline_first() {
    let refresher = Refresher::start("test-refresh-order", 1).expect("a thread starts");
    let blocker = Counting::new(Duration::from_secs(3600));
    let (release, gate) = mpsc::channel();
    let (entered_tx, entered) = mpsc::sync_channel(1);
    *blocker.gate.lock().unwrap() = Some(gate);
    *blocker.entered.lock().unwrap() = Some(entered_tx);
    refresher.keep(weak(&blocker), Instant::now());
    entered
        .recv_timeout(Duration::from_secs(10))
        .expect("the one worker is busy");

    let now = Instant::now();
    let order = Arc::new(Mutex::new(Vec::new()));
    struct Ordered {
        name: &'static str,
        deadline: Instant,
        order: Arc<Mutex<Vec<&'static str>>>,
    }
    impl Refreshable for Ordered {
        fn refresh(&self, now: Instant) -> Instant {
            self.order.lock().unwrap().push(self.name);
            now + Duration::from_secs(3600)
        }
        fn deadline(&self) -> Option<Instant> {
            Some(self.deadline)
        }
    }
    let late = Arc::new(Ordered {
        name: "late",
        deadline: now + Duration::from_secs(60),
        order: Arc::clone(&order),
    });
    let soon = Arc::new(Ordered {
        name: "soon",
        deadline: now + Duration::from_secs(5),
        order: Arc::clone(&order),
    });
    refresher.keep(Arc::downgrade(&late) as Weak<dyn Refreshable>, now);
    refresher.keep(Arc::downgrade(&soon) as Weak<dyn Refreshable>, now);
    release.send(()).expect("free the worker");
    eventually("both run", || order.lock().unwrap().len() == 2);
    assert_eq!(*order.lock().unwrap(), vec!["soon", "late"]);
}

#[test]
fn a_dropped_item_is_forgotten() {
    let refresher = Refresher::start("test-refresh-drop", 1).expect("a thread starts");
    let item = Counting::new(Duration::from_millis(10));
    refresher.keep(weak(&item), Instant::now());
    eventually("it runs", || item.runs() >= 1);
    drop(item);
    eventually("the book forgets it", || refresher.live() == 0);
}

#[test]
fn a_fingerprint_is_keyed_and_part_aware() {
    let fingerprint =
        |parts: &[&[u8]]| fingerprint(parts.iter().copied()).expect("the process is keyed");
    let one = fingerprint(&[b"ab".as_slice(), b"c".as_slice()]);
    let two = fingerprint(&[b"a".as_slice(), b"bc".as_slice()]);
    assert_ne!(one, two, "part boundaries count");
    assert_eq!(one, fingerprint(&[b"ab".as_slice(), b"c".as_slice()]));
    let plain: [u8; 32] = crate::hashing::Sha256::digest(b"abc");
    assert_ne!(
        fingerprint(&[b"abc".as_slice()]),
        plain,
        "never the bare digest"
    );
}

#[test]
fn a_throttle_passes_one_per_window_and_counts_the_rest() {
    let t = Throttle::new(Duration::from_secs(60));
    let now = Instant::now();
    assert_eq!(t.pass("vault", now), Some(0));
    assert_eq!(t.pass("vault", now + Duration::from_secs(1)), None);
    assert_eq!(t.pass("vault", now + Duration::from_secs(2)), None);
    assert_eq!(t.pass("file", now), Some(0), "per key");
    assert_eq!(
        t.pass("vault", now + Duration::from_secs(61)),
        Some(2),
        "the next pass carries what was held back"
    );
}
