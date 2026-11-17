// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! DES-454 r3.1 §2 and §5: the rotation item, its reads, its pool and its reports (T3, T4, T8, T11-T13,
//! T15-T18, T21, T26, T31). Every test uses its own labels, so the process health book is shared safely.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use busbar_contract::secret::RelendCause;
use busbar_contract::secret_ref::{SecretRef, SourceReference};
use busbar_contract::secure::SecureVec;

use super::*;
use crate::custody::{CustodyDenied, Leased, RoundValues};

/// Every report, by test label.
struct Captured {
    diags: Mutex<Vec<(String, String)>>,
    audits: Mutex<Vec<(String, &'static str)>>,
}

static CAPTURED: Captured = Captured {
    diags: Mutex::new(Vec::new()),
    audits: Mutex::new(Vec::new()),
};

impl Report for Captured {
    fn diag(
        &self,
        _: &'static crate::diagnostics::Diagnostic,
        _: tracing::Level,
        _: &str,
        fields: &[(&'static str, String)],
    ) {
        let field = |name: &str| {
            fields
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        self.diags
            .lock()
            .unwrap()
            .push((field("instance"), field("cause")));
    }
    fn info(&self, _: &str, _: &[(&'static str, String)]) {}
    fn audit(&self, _: &str, resource: &str, outcome: &'static str) {
        self.audits
            .lock()
            .unwrap()
            .push((resource.to_owned(), outcome));
    }
}

fn causes(label: &str) -> Vec<String> {
    CAPTURED
        .diags
        .lock()
        .unwrap()
        .iter()
        .filter(|(instance, _)| instance == label)
        .map(|(_, cause)| cause.clone())
        .collect()
}

fn audits(label: &str) -> Vec<&'static str> {
    let resource = format!("plugin:{label}");
    CAPTURED
        .audits
        .lock()
        .unwrap()
        .iter()
        .filter(|(r, _)| *r == resource)
        .map(|(_, outcome)| *outcome)
        .collect()
}

fn reference(name: &str) -> SourceReference {
    let json = format!(r#"{{"module":"vault","settings":{{"name":"{name}"}}}}"#);
    let parsed: SecretRef = busbar_contract::json::parse(json.as_bytes()).expect("a reference");
    parsed.source().expect("a source").clone()
}

fn sha(value: &str) -> [u8; 32] {
    busbar_contract::crypto::sha256_parts(&[value.as_bytes()])
}

/// A source: answers its current value (or a scripted sequence first), counts reads, and can hold a read.
struct Source {
    value: Mutex<String>,
    script: Mutex<Vec<String>>,
    lease: Option<Duration>,
    reads: AtomicUsize,
    gate: Mutex<Option<Receiver<()>>>,
}

impl Source {
    fn new(value: &str, lease: Option<Duration>) -> Arc<Self> {
        Arc::new(Source {
            value: Mutex::new(value.to_owned()),
            script: Mutex::new(Vec::new()),
            lease,
            reads: AtomicUsize::new(0),
            gate: Mutex::new(None),
        })
    }

    fn set(&self, value: &str) {
        *self.value.lock().unwrap() = value.to_owned();
    }

    fn hold(&self) -> Sender<()> {
        let (release, gate) = channel();
        *self.gate.lock().unwrap() = Some(gate);
        release
    }

    fn reads(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }
}

impl Reader for Source {
    fn read(&self, _: &SourceReference, _: Instant) -> Result<Leased, CustodyDenied> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        if let Some(gate) = self.gate.lock().unwrap().take() {
            let _ = gate.recv_timeout(Duration::from_secs(10));
        }
        let scripted = {
            let mut script = self.script.lock().unwrap();
            (!script.is_empty()).then(|| script.remove(0))
        };
        let value = scripted.unwrap_or_else(|| self.value.lock().unwrap().clone());
        Ok(Leased {
            value: SecureVec::from(value.as_bytes()),
            until: self.lease.map(|lease| Instant::now() + lease),
        })
    }
}

/// An instance binding: holds a digest, swaps by taking the round's value, counts swaps.
struct Bound {
    label: String,
    action: Action,
    id: [u8; 32],
    held: Mutex<[u8; 32]>,
    swaps: AtomicUsize,
    alive: AtomicBool,
    latch: Mutex<()>,
    swapping: Mutex<Option<Receiver<()>>>,
}

impl Bound {
    fn new(label: &str, action: Action, id: [u8; 32], held: &str) -> Arc<Self> {
        opened(label);
        Arc::new(Bound {
            label: label.to_owned(),
            action,
            id,
            held: Mutex::new(sha(held)),
            swaps: AtomicUsize::new(0),
            alive: AtomicBool::new(true),
            latch: Mutex::new(()),
            swapping: Mutex::new(None),
        })
    }

    fn swaps(&self) -> usize {
        self.swaps.load(Ordering::SeqCst)
    }
}

impl Subscriber for Bound {
    fn label(&self) -> &str {
        &self.label
    }
    fn alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }
    fn action(&self) -> Action {
        self.action
    }
    fn differs(&self, round: &RoundValues) -> Result<bool, RelendCause> {
        let value = round
            .value(&self.id)
            .expect("the round holds the item's source");
        Ok(
            busbar_contract::crypto::sha256_parts(&[value.as_slice()])
                != *self.held.lock().unwrap(),
        )
    }
    fn swap(&self, round: &RoundValues) -> Result<(), RelendCause> {
        assert_eq!(self.action, Action::Swap, "only an export swaps");
        if let Some(gate) = self.swapping.lock().unwrap().take() {
            let _ = gate.recv_timeout(Duration::from_secs(10));
        }
        let value = round
            .value(&self.id)
            .expect("the round holds the item's source");
        *self.held.lock().unwrap() = busbar_contract::crypto::sha256_parts(&[value.as_slice()]);
        self.swaps.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn latch(&self) -> &Mutex<()> {
        &self.latch
    }
}

fn pool(threads: usize) -> Arc<Pool> {
    Pool::start("rotation-test", threads).expect("the pool starts")
}

fn item(name: &str, source: &Arc<Source>, pool: &Arc<Pool>) -> Arc<Item> {
    Item::build(
        reference(name),
        Arc::clone(source) as Arc<dyn Reader>,
        Arc::clone(pool),
        &CAPTURED,
        RELEND_POLL_DEADLINE,
    )
    .expect("encodes")
}

fn wait_until(what: &str, done: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(Instant::now() < deadline, "timed out: {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// T18: due times. Floor, lease end plus one second, unleased at about 30 s.
#[test]
fn due_times_follow_the_lease_the_floor_and_the_spread() {
    let now = Instant::now();
    assert_eq!(
        due(now, Some(now + Duration::from_secs(60)), 0.5),
        now + Duration::from_secs(61)
    );
    assert_eq!(
        due(now, Some(now + Duration::from_secs(1)), 0.5),
        now + RELEND_FLOOR
    );
    assert_eq!(
        due(now, Some(now - Duration::from_secs(9)), 0.5),
        now + RELEND_FLOOR
    );
    for unit in [0.0, 0.5, 1.0] {
        let wait = due(now, None, unit) - now;
        assert!(
            (Duration::from_secs(27)..=Duration::from_secs(33)).contains(&wait),
            "{wait:?}"
        );
    }
}

/// T18: a config apply makes an item due now, whatever it last scheduled.
#[test]
fn due_now_makes_a_scheduled_item_poll_at_once() {
    let pool = pool(1);
    let source = Source::new("sk-live-0018-due", None);
    let item = item("t18", &source, &pool);
    let bound = Bound::new("export.t18", Action::Swap, item.id(), "sk-live-0018-due");
    item.subscribe(bound);
    let now = Instant::now();
    item.refresh(now);
    wait_until("the first poll", || lock(&item.state).next.is_some());
    assert!(item.refresh(Instant::now()) > Instant::now() + Duration::from_secs(20));
    item.due_now();
    let at = Instant::now();
    assert_eq!(
        item.refresh(at),
        at + RELEND_FLOOR,
        "a poll is submitted at once"
    );
    wait_until("the second poll", || source.reads() == 2);
}

/// T4: unleased, two reads that disagree apply nothing; two that agree apply once.
#[test]
fn unleased_changes_apply_only_when_two_reads_agree() {
    let pool = pool(1);
    let source = Source::new("bravo-9K4m-unleased", None);
    let item = item("t4", &source, &pool);
    let bound = Bound::new("export.t4", Action::Swap, item.id(), "alpha-7Q2x-unleased");
    item.subscribe(Arc::clone(&bound) as Arc<dyn Subscriber>);
    let next = item.poll(Instant::now());
    assert!(
        next <= Instant::now() + RELEND_FLOOR,
        "the confirming read is a floor away"
    );
    assert_eq!(
        bound.swaps(),
        0,
        "one read never applies an unleased change"
    );
    source.set("charlie-3T8p-unleased");
    item.poll(Instant::now());
    assert_eq!(bound.swaps(), 0, "a disagreeing read applies nothing");
    item.poll(Instant::now());
    assert_eq!(bound.swaps(), 1, "two agreeing reads apply");
    assert_eq!(*bound.held.lock().unwrap(), sha("charlie-3T8p-unleased"));
    assert_eq!(source.reads(), 3);
    assert_eq!(
        audits("export.t4"),
        vec![crate::audit_ring::OUTCOME_APPLIED]
    );
}

/// T4: three disagreeing polls in a row report `unstable`, and still apply nothing.
#[test]
fn three_disagreeing_polls_report_unstable() {
    let pool = pool(1);
    let source = Source::new("delta-1111-unstable", None);
    let item = item("t4u", &source, &pool);
    let bound = Bound::new("export.t4u", Action::Swap, item.id(), "alpha-0000-unstable");
    item.subscribe(Arc::clone(&bound) as Arc<dyn Subscriber>);
    for value in [
        "delta-1111-unstable",
        "delta-2222-unstable",
        "delta-3333-unstable",
        "delta-4444-unstable",
    ] {
        source.set(value);
        item.poll(Instant::now());
    }
    assert_eq!(bound.swaps(), 0);
    assert_eq!(causes("export.t4u"), vec!["unstable".to_owned()]);
    assert_eq!(
        health("export.t4u").map(|h| h.cause),
        Some(RelendCause::Unstable)
    );
}

/// T26: a leased answer applies on the first read, one read per poll.
#[test]
fn a_leased_change_applies_on_the_first_read() {
    let pool = pool(1);
    let source = Source::new("bravo-9K4m-leased", Some(Duration::from_secs(120)));
    let item = item("t26", &source, &pool);
    let bound = Bound::new("export.t26", Action::Swap, item.id(), "alpha-7Q2x-leased");
    item.subscribe(Arc::clone(&bound) as Arc<dyn Subscriber>);
    let next = item.poll(Instant::now());
    assert_eq!((bound.swaps(), source.reads()), (1, 1));
    assert!(
        next > Instant::now() + Duration::from_secs(100),
        "next due after the lease"
    );
}

/// T3: a blank, whitespace or 3-byte rotated value is never opened; degraded `unresolvable`.
#[test]
fn a_blank_or_short_value_is_never_opened() {
    let pool = pool(1);
    for (n, value) in ["", "   \t", "abc"].into_iter().enumerate() {
        let label = format!("export.t3-{n}");
        let source = Source::new(value, Some(Duration::from_secs(60)));
        let item = item(&format!("t3-{n}"), &source, &pool);
        let bound = Bound::new(&label, Action::Swap, item.id(), "alpha-7Q2x-before");
        item.subscribe(Arc::clone(&bound) as Arc<dyn Subscriber>);
        item.poll(Instant::now());
        assert_eq!(bound.swaps(), 0, "{value:?} was opened");
        assert_eq!(
            health(&label).map(|h| h.cause),
            Some(RelendCause::Unresolvable)
        );
    }
}

/// T12, T15, T16: every non-export kind degrades `reload-required`, keeps what it holds, never swaps, and
/// nothing is audited `applied`. T17: the process store says `restart-required`.
#[test]
fn non_export_kinds_degrade_until_reload_or_restart() {
    let pool = pool(1);
    let source = Source::new("bravo-9K4m-reload", Some(Duration::from_secs(60)));
    let item = item("t16", &source, &pool);
    let mut bound = Vec::new();
    for kind in ["hook", "transport", "plane", "store", "secret", "auth"] {
        let b = Bound::new(
            &format!("{kind}.t16"),
            Action::Reload,
            item.id(),
            "alpha-7Q2x-reload",
        );
        item.subscribe(Arc::clone(&b) as Arc<dyn Subscriber>);
        bound.push(b);
    }
    let core = Bound::new(
        "store.t17-core",
        Action::Restart,
        item.id(),
        "alpha-7Q2x-reload",
    );
    item.subscribe(Arc::clone(&core) as Arc<dyn Subscriber>);
    item.poll(Instant::now());
    item.poll(Instant::now());
    for b in &bound {
        assert_eq!(b.swaps(), 0);
        assert_eq!(
            *b.held.lock().unwrap(),
            sha("alpha-7Q2x-reload"),
            "it keeps A"
        );
        assert_eq!(
            health(&b.label).map(|h| h.cause),
            Some(RelendCause::ReloadRequired)
        );
        assert_eq!(
            causes(&b.label),
            vec!["reload-required".to_owned()],
            "rate-limited"
        );
        assert!(!audits(&b.label).contains(&crate::audit_ring::OUTCOME_APPLIED));
    }
    assert_eq!(
        health("store.t17-core").map(|h| h.cause),
        Some(RelendCause::RestartRequired)
    );
    // T15: after the reload, the new instance holds B and its label reports nothing.
    let reloaded = Bound::new("hook.t16", Action::Reload, item.id(), "bravo-9K4m-reload");
    bound[0].alive.store(false, Ordering::SeqCst);
    item.subscribe(Arc::clone(&reloaded) as Arc<dyn Subscriber>);
    assert_eq!(health("hook.t16"), None);
    item.poll(Instant::now());
    assert_eq!(health("hook.t16"), None);
}

/// T11: a source that returns to what the instance holds clears the report, audited `applied` how=`recovered`.
#[test]
fn a_recovery_is_audited_applied() {
    let pool = pool(1);
    let source = Source::new("", Some(Duration::from_secs(60)));
    let item = item("t11", &source, &pool);
    let bound = Bound::new("export.t11", Action::Swap, item.id(), "alpha-7Q2x-recover");
    item.subscribe(Arc::clone(&bound) as Arc<dyn Subscriber>);
    item.poll(Instant::now());
    assert!(health("export.t11").is_some());
    source.set("alpha-7Q2x-recover");
    item.poll(Instant::now());
    assert_eq!(health("export.t11"), None);
    assert_eq!(
        audits("export.t11"),
        vec![
            crate::audit_ring::OUTCOME_DEGRADED,
            crate::audit_ring::OUTCOME_APPLIED
        ]
    );
}

/// T21: one source bound by N instances gets one read per poll.
#[test]
fn n_subscribers_share_one_read() {
    let pool = pool(1);
    let source = Source::new("bravo-9K4m-shared", Some(Duration::from_secs(60)));
    let item = item("t21", &source, &pool);
    let bound: Vec<_> = (0..8)
        .map(|n| {
            let b = Bound::new(
                &format!("export.t21-{n}"),
                Action::Swap,
                item.id(),
                "alpha-7Q2x-shared",
            );
            item.subscribe(Arc::clone(&b) as Arc<dyn Subscriber>);
            b
        })
        .collect();
    item.poll(Instant::now());
    assert_eq!(source.reads(), 1);
    assert!(bound.iter().all(|b| b.swaps() == 1));
}

/// T31: an instance latched by one poll is skipped by another and retried next time; both end committed.
#[test]
fn a_latched_instance_is_skipped_and_retried() {
    let pool = pool(2);
    let s1 = Source::new("bravo-9K4m-latch1", Some(Duration::from_secs(60)));
    let i1 = item("t31-1", &s1, &pool);
    let bound = Bound::new("export.t31", Action::Swap, i1.id(), "alpha-7Q2x-latch1");
    i1.subscribe(Arc::clone(&bound) as Arc<dyn Subscriber>);
    let (release, gate) = channel();
    *bound.swapping.lock().unwrap() = Some(gate);
    let first = {
        let i1 = Arc::clone(&i1);
        std::thread::spawn(move || i1.poll(Instant::now()))
    };
    wait_until("the first swap holds the latch", || {
        bound.latch.try_lock().is_err()
    });
    i1.poll(Instant::now());
    assert_eq!(bound.swaps(), 0, "the latched instance was skipped");
    release.send(()).unwrap();
    first.join().unwrap();
    assert_eq!(bound.swaps(), 1, "one reopen at a time");
}

/// T8: ten rotating sources whose reads block never hold the refresher (refresh only schedules), and at most
/// RELEND_CONCURRENCY polls run at once.
#[test]
fn blocked_reads_never_hold_the_refresher_and_the_pool_is_capped() {
    let pool = pool(RELEND_CONCURRENCY);
    let mut releases = Vec::new();
    let mut items = Vec::new();
    for n in 0..10 {
        let source = Source::new("bravo-9K4m-blocked", Some(Duration::from_secs(60)));
        releases.push(source.hold());
        let item = item(&format!("t8-{n}"), &source, &pool);
        item.subscribe(Bound::new(
            &format!("export.t8-{n}"),
            Action::Swap,
            item.id(),
            "alpha-7Q2x-blocked",
        ));
        items.push(item);
    }
    let started = Instant::now();
    for item in &items {
        item.refresh(Instant::now());
    }
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "refresh never waits on a poll"
    );
    std::thread::sleep(Duration::from_millis(100));
    assert!(pool.most_at_once() <= RELEND_CONCURRENCY);
    for release in releases {
        let _ = release.send(());
    }
    wait_until("every poll", || {
        items.iter().all(|i| lock(&i.state).in_flight.is_none())
    });
    assert_eq!(pool.most_at_once(), RELEND_CONCURRENCY);
}

/// T13: a poll that holds its permit past the deadline, and one that waits for a permit past it, both show
/// `deadline` in health; the next completed round clears both.
#[test]
fn a_stalled_or_starved_poll_shows_deadline_and_clears_after() {
    let pool = pool(1);
    let short = Duration::from_millis(200);
    let held = Source::new("alpha-7Q2x-stall", Some(Duration::from_secs(60)));
    let waiting = Source::new("alpha-7Q2x-starve", Some(Duration::from_secs(60)));
    let build = |name: &str, source: &Arc<Source>| {
        Item::build(
            reference(name),
            Arc::clone(source) as Arc<dyn Reader>,
            Arc::clone(&pool),
            &CAPTURED,
            short,
        )
        .expect("encodes")
    };
    let a = build("t13-held", &held);
    let b = build("t13-wait", &waiting);
    a.subscribe(Bound::new(
        "export.t13-held",
        Action::Swap,
        a.id(),
        "alpha-7Q2x-stall",
    ));
    b.subscribe(Bound::new(
        "export.t13-wait",
        Action::Swap,
        b.id(),
        "alpha-7Q2x-starve",
    ));
    let release = held.hold();
    a.refresh(Instant::now());
    wait_until("a holds the only permit", || held.reads() == 1);
    b.refresh(Instant::now());
    std::thread::sleep(short * 2);
    a.refresh(Instant::now());
    b.refresh(Instant::now());
    assert_eq!(
        health("export.t13-held").map(|h| h.cause),
        Some(RelendCause::Deadline)
    );
    assert_eq!(
        health("export.t13-wait").map(|h| h.cause),
        Some(RelendCause::Deadline)
    );
    release.send(()).unwrap();
    wait_until("both rounds end", || {
        lock(&a.state).in_flight.is_none() && lock(&b.state).in_flight.is_none()
    });
    assert_eq!(health("export.t13-held"), None, "a's round completed");
    assert_eq!(waiting.reads(), 0, "b gave up its starved round");
    b.due_now();
    b.refresh(Instant::now());
    wait_until("b's next round", || {
        lock(&b.state).in_flight.is_none() && waiting.reads() == 1
    });
    assert_eq!(health("export.t13-wait"), None);
}

/// I4: a config apply makes the picked kept items due now on the refresher; others keep their time.
#[test]
fn the_refresher_makes_picked_items_due_now() {
    struct Counted(AtomicUsize);
    impl Refreshable for Counted {
        fn refresh(&self, now: Instant) -> Instant {
            self.0.fetch_add(1, Ordering::SeqCst);
            now + Duration::from_secs(3_600)
        }
    }
    let refresher = crate::refresh::Refresher::start("due-now-test", 1).expect("starts");
    let picked = Arc::new(Counted(AtomicUsize::new(0)));
    let other = Arc::new(Counted(AtomicUsize::new(0)));
    let (picked_dyn, other_dyn): (Arc<dyn Refreshable>, Arc<dyn Refreshable>) =
        (Arc::clone(&picked) as _, Arc::clone(&other) as _);
    let later = Instant::now() + Duration::from_secs(3_600);
    refresher.keep(Arc::downgrade(&picked_dyn), later);
    refresher.keep(Arc::downgrade(&other_dyn), later);
    let target = Arc::as_ptr(&picked).cast::<()>();
    refresher.due_now(&|item| Arc::as_ptr(item).cast::<()>() == target);
    wait_until("the picked item ran", || {
        picked.0.load(Ordering::SeqCst) == 1
    });
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(other.0.load(Ordering::SeqCst), 0);
}

/// T1: a refused export rotation keeps what the instance holds and reports degraded 8028 (`reopen-failed`),
/// audited degraded and never applied; the next poll retries.
#[test]
fn a_refused_swap_keeps_the_instance_and_reports_degraded() {
    struct Refusing(Arc<Bound>);
    impl Subscriber for Refusing {
        fn label(&self) -> &str {
            self.0.label()
        }
        fn alive(&self) -> bool {
            true
        }
        fn action(&self) -> Action {
            Action::Swap
        }
        fn differs(&self, round: &RoundValues) -> Result<bool, RelendCause> {
            self.0.differs(round)
        }
        fn swap(&self, _: &RoundValues) -> Result<(), RelendCause> {
            Err(RelendCause::ReopenFailed)
        }
        fn latch(&self) -> &Mutex<()> {
            self.0.latch()
        }
    }
    let pool = pool(1);
    let source = Source::new("bravo-9K4m-refused", Some(Duration::from_secs(60)));
    let item = item("t1", &source, &pool);
    let bound = Bound::new("export.t1", Action::Swap, item.id(), "alpha-7Q2x-refused");
    item.subscribe(Arc::new(Refusing(Arc::clone(&bound))));
    item.poll(Instant::now());
    item.poll(Instant::now());
    assert_eq!(
        *bound.held.lock().unwrap(),
        sha("alpha-7Q2x-refused"),
        "it keeps A"
    );
    assert_eq!(
        health("export.t1").map(|h| h.cause),
        Some(RelendCause::ReopenFailed)
    );
    assert_eq!(causes("export.t1"), vec!["reopen-failed".to_owned()]);
    assert_eq!(
        audits("export.t1"),
        vec![crate::audit_ring::OUTCOME_DEGRADED]
    );
    assert_eq!(source.reads(), 2, "each poll retries");
}
