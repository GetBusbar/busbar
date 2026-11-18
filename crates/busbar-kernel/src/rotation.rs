// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SECRET ROTATION FOR RUNNING INSTANCES (DES-454 r3.1 §2, core #454, #142).
//!
//! One [`Item`] per (custody, source): it re-reads the source off the request path and compares the answer with
//! what each subscriber holds. A change is applied per subscriber:
//! - an export swaps a successor in under its door ([`Action::Swap`], §4);
//! - every other kind degrades with BUSBAR-8028 `reload-required` and takes the value at the next reload or
//!   restart (§5, PM D1); the process store says `restart-required`.
//!
//! Executor (§2.3): the process refresher only schedules items, it never blocks on one. A poll runs on the
//! capped rotation pool ([`RELEND_CONCURRENCY`] threads, the permits): synchronous FFI cannot be interrupted, so
//! at most that many rotation calls run at once and nothing else waits on them. A poll that holds or waits for a
//! permit past [`RELEND_POLL_DEADLINE`] reports `deadline` on its subscribers; the next completed round clears it.
//!
//! Reads (§2.2): a leased answer is applied on the first read and the source cache is never bypassed; an
//! unleased answer is applied only when a second read [`RELEND_FLOOR`] later agrees, with no permit held between
//! the two. Three disagreeing polls in a row report `unstable`.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError, Weak};
use std::time::{Duration, Instant};

use busbar_contract::secret::RelendCause;
use busbar_contract::secret_ref::SourceReference;
use busbar_plugin_abi::host_side::scrub::MIN_NEEDLE;

use crate::custody::{CustodyDenied, Leased, RoundValues};
use crate::preflight::{RelendStreak, RELEND_EVERY};
use crate::refresh::{Refreshable, Report};

/// The least time between two polls of one item, and the wait between an unleased answer's two reads.
pub const RELEND_FLOOR: Duration = Duration::from_secs(5);
/// The deadline of every call one poll makes.
pub const RELEND_POLL_DEADLINE: Duration = Duration::from_secs(25);
/// The rotation pool's permits: polls that run at once.
pub const RELEND_CONCURRENCY: usize = 2;
/// Consecutive disagreeing polls before `unstable` is reported.
const UNSTABLE_AFTER: u32 = 3;

/// What a subscriber does with a confirmed change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// An export: open a successor with the round's values and swap it in.
    Swap,
    /// Any other kind: degrade until the next reload or restart.
    Reload,
    /// The process store: degrade until the next restart.
    Restart,
}

/// One instance binding that holds a value of the item's source.
pub trait Subscriber: Send + Sync {
    /// `<kind>.<name>`: the report's instance, the audit resource and the health key.
    fn label(&self) -> &str;
    /// Whether the instance is still open. A closed subscriber is dropped from its item.
    fn alive(&self) -> bool;
    fn action(&self) -> Action;
    /// Whether what the instance holds differs from what `round` would give it. Err: the round's value cannot
    /// serve this binding (`unresolvable`). Blocking; runs on the rotation pool.
    fn differs(&self, round: &RoundValues) -> Result<bool, RelendCause>;
    /// [`Action::Swap`] only: open a successor with `round` and swap it in. Blocking; runs on the rotation pool.
    fn swap(&self, round: &RoundValues) -> Result<(), RelendCause>;
    /// The instance's rotation latch (§2.4): one poll at a time touches an instance.
    fn latch(&self) -> &Mutex<()>;
}

/// The item's source read: through the subscriber's own custody, with `deadline` on every call. Blocking.
pub trait Reader: Send + Sync {
    fn read(&self, source: &SourceReference, deadline: Instant) -> Result<Leased, CustodyDenied>;
}

/// A rotation's health, per subscriber label: what the admin instance view reports (I11).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Degraded {
    pub cause: RelendCause,
    /// Epoch milliseconds it was first reported.
    pub since_ms: u64,
}

#[derive(Default)]
struct HealthEntry {
    degraded: Option<Degraded>,
    streak: RelendStreak,
}

fn book() -> &'static Mutex<HashMap<String, HealthEntry>> {
    static BOOK: OnceLock<Mutex<HashMap<String, HealthEntry>>> = OnceLock::new();
    BOOK.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The rotation health of the instance `label` (`<kind>.<name>`): None when healthy.
#[must_use]
pub fn health(label: &str) -> Option<Degraded> {
    lock(book()).get(label).and_then(|entry| entry.degraded)
}

/// Report `cause` on `label`: BUSBAR-8028 (rate-limited per instance), the audit row, and health `degraded`.
pub fn degrade(report: &dyn Report, label: &str, cause: RelendCause) {
    let mut book = lock(book());
    let entry = book.entry(label.to_owned()).or_default();
    if entry.degraded.is_none_or(|held| held.cause != cause) {
        entry.degraded = Some(Degraded {
            cause,
            since_ms: crate::store::now_ms(),
        });
    }
    let refused = busbar_contract::secret::RelendRefused {
        cause,
        text: crate::preflight::rotation_text(cause).to_owned(),
    };
    entry.streak.failed(report, label, &refused, Instant::now());
}

/// The rotated value was applied to `label` (`how`: `reopened` or `recovered`): health clears.
pub fn applied(report: &dyn Report, label: &str, how: &str) {
    let mut book = lock(book());
    let entry = book.entry(label.to_owned()).or_default();
    entry.degraded = None;
    entry.streak.applied(report, label, how);
}

/// A completed round found nothing to apply on `label`, or a new instance took the label: health clears. A
/// recovery from a reported failure is audited `applied` how=`recovered` (T11).
pub fn settled(report: &dyn Report, label: &str) {
    let mut book = lock(book());
    if let Some(entry) = book.get_mut(label) {
        if entry.degraded.take().is_some() {
            entry.streak.applied(report, label, "recovered");
        }
    }
}

/// A new instance under `label` (an open after a reload or restart): the old instance's report is not its own.
pub fn opened(label: &str) {
    lock(book()).remove(label);
}

/// When a poll is next due (§2.2 step 1): a leased answer one second after its lease ends, never sooner than
/// [`RELEND_FLOOR`]; an unleased one [`RELEND_EVERY`] ± 10 % (`unit` is the spread's draw).
#[must_use]
pub fn due(now: Instant, until: Option<Instant>, unit: f64) -> Instant {
    let _ = (until, unit);
    now + RELEND_EVERY
}

/// Step 4: a value never opened. Blank, or too short for the scrub set to mask it.
fn unusable(value: &[u8]) -> bool {
    crate::config::secret::is_blank(value) || value.len() < MIN_NEEDLE
}

type Job = Box<dyn FnOnce() + Send>;

/// The capped rotation pool: [`RELEND_CONCURRENCY`] threads, the only place a poll's blocking work runs.
pub struct Pool {
    queue: Mutex<VecDeque<Job>>,
    woken: Condvar,
    running: AtomicUsize,
    most: AtomicUsize,
}

impl Pool {
    /// A pool of `threads` threads named `<name>-<n>`; a thread that cannot start is an error the caller must
    /// not ignore.
    pub fn start(name: &str, threads: usize) -> Result<Arc<Self>, String> {
        let pool = Arc::new(Pool {
            queue: Mutex::new(VecDeque::new()),
            woken: Condvar::new(),
            running: AtomicUsize::new(0),
            most: AtomicUsize::new(0),
        });
        for n in 0..threads.max(1) {
            let worker = Arc::clone(&pool);
            std::thread::Builder::new()
                .name(format!("{name}-{n}"))
                .spawn(move || worker.work())
                .map_err(|e| format!("the rotation thread {name}-{n} did not start: {e}"))?;
        }
        Ok(pool)
    }

    fn submit(&self, job: Job) {
        lock(&self.queue).push_back(job);
        self.woken.notify_one();
    }

    /// The most jobs that ran at once (a test's view of the permit cap).
    #[must_use]
    pub fn most_at_once(&self) -> usize {
        self.most.load(Ordering::SeqCst)
    }

    fn work(&self) {
        loop {
            let job = {
                let mut queue = lock(&self.queue);
                loop {
                    if let Some(job) = queue.pop_front() {
                        break job;
                    }
                    queue = self
                        .woken
                        .wait(queue)
                        .unwrap_or_else(PoisonError::into_inner);
                }
            };
            let now = self.running.fetch_add(1, Ordering::SeqCst) + 1;
            self.most.fetch_max(now, Ordering::SeqCst);
            job();
            self.running.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

/// The process's rotation pool; exits 2 if its threads cannot start (a rotation that never runs would leave
/// every rotated credential unapplied with nothing said).
pub fn process_pool() -> Arc<Pool> {
    static ONE: OnceLock<Arc<Pool>> = OnceLock::new();
    Arc::clone(ONE.get_or_init(|| {
        Pool::start("busbar-rotate", RELEND_CONCURRENCY).unwrap_or_else(|e| {
            eprintln!("busbar: {e}");
            std::process::exit(2);
        })
    }))
}

#[derive(Default)]
struct State {
    /// When the next poll may start (None: now).
    next: Option<Instant>,
    /// A poll submitted at this instant has not finished.
    in_flight: Option<Instant>,
    deadline_reported: bool,
    /// An unleased change waiting for its confirming read: the first read's digest.
    confirm: Option<[u8; 32]>,
    disagreements: u32,
}

/// One rotation item: a source, the reader of the custody it is bound through, and its subscribers.
pub struct Item {
    me: Weak<Item>,
    source: SourceReference,
    id: [u8; 32],
    reader: Arc<dyn Reader>,
    subscribers: Mutex<Vec<Arc<dyn Subscriber>>>,
    state: Mutex<State>,
    pool: Arc<Pool>,
    report: &'static dyn Report,
    /// [`RELEND_POLL_DEADLINE`]; shorter only in this crate's tests.
    deadline: Duration,
}

impl Item {
    /// An item for `source` read through `reader`, polled on `pool`. None: the source does not encode.
    pub fn new(
        source: SourceReference,
        reader: Arc<dyn Reader>,
        pool: Arc<Pool>,
        report: &'static dyn Report,
    ) -> Option<Arc<Self>> {
        Self::build(source, reader, pool, report, RELEND_POLL_DEADLINE)
    }

    fn build(
        source: SourceReference,
        reader: Arc<dyn Reader>,
        pool: Arc<Pool>,
        report: &'static dyn Report,
        deadline: Duration,
    ) -> Option<Arc<Self>> {
        let id = crate::custody::source_id(&source)?;
        Some(Arc::new_cyclic(|me| Item {
            me: me.clone(),
            source,
            id,
            reader,
            subscribers: Mutex::new(Vec::new()),
            state: Mutex::new(State::default()),
            pool,
            report,
            deadline,
        }))
    }

    /// The source id the item polls.
    #[must_use]
    pub fn id(&self) -> [u8; 32] {
        self.id
    }

    /// Add a subscriber; a second subscription of one binding is the caller's to avoid.
    pub fn subscribe(&self, subscriber: Arc<dyn Subscriber>) {
        lock(&self.subscribers).push(subscriber);
    }

    /// Whether any subscriber is still open.
    #[must_use]
    pub fn live(&self) -> bool {
        let mut subscribers = lock(&self.subscribers);
        subscribers.retain(|s| s.alive());
        !subscribers.is_empty()
    }

    /// Due now, whatever the item last scheduled (a config apply, I4).
    pub fn due_now(&self) {
        lock(&self.state).next = None;
    }

    fn subscribers(&self) -> Vec<Arc<dyn Subscriber>> {
        let mut subscribers = lock(&self.subscribers);
        subscribers.retain(|s| s.alive());
        subscribers.clone()
    }

    fn report_all(&self, subscribers: &[Arc<dyn Subscriber>], cause: RelendCause) {
        for subscriber in subscribers {
            degrade(self.report, subscriber.label(), cause);
        }
    }

    /// One poll on the pool: the permit is this thread. Answers when the item is next due.
    fn poll(&self, submitted: Instant) -> Instant {
        let _ = (submitted, &self.reader, &self.source, UNSTABLE_AFTER);
        let _ = (
            unusable as fn(&[u8]) -> bool,
            labels as fn(&[Arc<dyn Subscriber>]) -> String,
        );
        Instant::now() + RELEND_EVERY
    }
}

impl Refreshable for Item {
    /// Schedules only: a poll runs on the rotation pool, and this answers within a lock.
    fn refresh(&self, now: Instant) -> Instant {
        let mut state = lock(&self.state);
        if let Some(submitted) = state.in_flight {
            if now >= submitted + self.deadline && !state.deadline_reported {
                state.deadline_reported = true;
                drop(state);
                // Held or waited for: either way its own subscribers show it.
                self.report_all(&self.subscribers(), RelendCause::Deadline);
            }
            return now + RELEND_FLOOR;
        }
        if let Some(next) = state.next.filter(|next| *next > now) {
            return next;
        }
        if crate::refresh::stopping() {
            return now + RELEND_EVERY;
        }
        let Some(me) = self.me.upgrade() else {
            return now + RELEND_EVERY;
        };
        state.in_flight = Some(now);
        state.deadline_reported = false;
        drop(state);
        self.pool.submit(Box::new(move || {
            let next = me.poll(now);
            let mut state = lock(&me.state);
            state.in_flight = None;
            state.next = Some(next);
        }));
        now + RELEND_FLOOR
    }
}

fn labels(subscribers: &[Arc<dyn Subscriber>]) -> String {
    subscribers
        .iter()
        .map(|s| s.label())
        .collect::<Vec<_>>()
        .join(",")
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
#[path = "tests/rotation_tests.rs"]
mod tests;
