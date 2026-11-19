// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST'S ONE REFRESHER: every value the host holds on a lease and renews off the request path
//! (a plane member's upstream credential, a spawned program's environment, a plugin instance's own
//! lent credentials) is kept here and renewed by a small bounded pool.
//!
//! - An item is kept as a `Weak`, so it dies with the build that made it.
//! - [`WORKERS`] threads take due items earliest deadline first. An item is never queued twice,
//!   and one hung item holds one worker, never the others' renewals.
//! - Each item schedules itself: [`Refreshable::refresh`] answers when it is next due.
//! - A thread that cannot start is an error to whoever asked for the refresher ([`keep`]): what
//!   it would have kept fresh is refused, with the reason. A refresher that silently never runs
//!   would let every lease lapse with nothing said.
//! - [`begin_stopping`] latches the process's drain: no item starts after it, and an item that is
//!   mid-flight reports at debug and commits nothing.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, PoisonError, Weak};
use std::time::{Duration, Instant};

/// How many refreshes run at once.
pub const WORKERS: usize = 4;

/// One value the refresher keeps.
pub trait Refreshable: Send + Sync {
    /// Make one attempt now; answer when the item is next due.
    fn refresh(&self, now: Instant) -> Instant;

    /// When what the item holds runs out: due items run earliest deadline first.
    fn deadline(&self) -> Option<Instant> {
        None
    }
}

struct Kept {
    item: Weak<dyn Refreshable>,
    due: Instant,
    running: bool,
}

#[derive(Default)]
struct Book {
    kept: Vec<Kept>,
}

struct Inner {
    book: Mutex<Book>,
    woken: Condvar,
}

/// A refresher: a book of kept items and the threads that renew them.
pub struct Refresher {
    inner: Arc<Inner>,
}

impl Refresher {
    /// A refresher with `workers` threads named `<name>-<n>`; a thread that cannot start is an
    /// error the caller must not ignore (the process refresher exits 2 on it).
    pub fn start(name: &str, workers: usize) -> Result<Self, String> {
        let inner = Arc::new(Inner {
            book: Mutex::new(Book::default()),
            woken: Condvar::new(),
        });
        for n in 0..workers.max(1) {
            let inner = Arc::clone(&inner);
            std::thread::Builder::new()
                .name(format!("{name}-{n}"))
                .spawn(move || work(&inner))
                .map_err(|e| format!("the refresher thread {name}-{n} did not start: {e}"))?;
        }
        Ok(Self { inner })
    }

    /// Keep `item`, first due at `due`.
    pub fn keep(&self, item: Weak<dyn Refreshable>, due: Instant) {
        self.inner
            .book
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .kept
            .push(Kept {
                item,
                due,
                running: false,
            });
        self.inner.woken.notify_all();
    }

    /// How many live items are kept (a test's view).
    #[must_use]
    pub fn live(&self) -> usize {
        self.inner
            .book
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .kept
            .iter()
            .filter(|k| k.item.strong_count() > 0)
            .count()
    }
}

fn work(inner: &Inner) {
    let mut book = inner.book.lock().unwrap_or_else(PoisonError::into_inner);
    loop {
        let now = Instant::now();
        book.kept.retain(|k| k.running || k.item.strong_count() > 0);
        let picked = if stopping() {
            None
        } else {
            pick(&mut book, now)
        };
        if let Some((index, item)) = picked {
            book.kept[index].running = true;
            let weak = Arc::downgrade(&item);
            drop(book);
            let due = item.refresh(Instant::now());
            drop(item);
            book = inner.book.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(kept) = book
                .kept
                .iter_mut()
                .find(|k| k.running && Weak::ptr_eq(&k.item, &weak))
            {
                kept.running = false;
                kept.due = due;
            }
            inner.woken.notify_all();
            continue;
        }
        let next = book.kept.iter().filter(|k| !k.running).map(|k| k.due).min();
        book = match next {
            Some(at) if !stopping() => {
                inner
                    .woken
                    .wait_timeout(book, at.saturating_duration_since(now))
                    .unwrap_or_else(PoisonError::into_inner)
                    .0
            }
            _ => {
                inner
                    .woken
                    .wait_timeout(book, Duration::from_secs(60))
                    .unwrap_or_else(PoisonError::into_inner)
                    .0
            }
        };
    }
}

/// An item's pick order: its deadline (none sorts last), then its due instant.
type PickKey = (Option<Instant>, Instant);

/// The due, idle item with the earliest deadline (no deadline sorts last), then the earliest due.
fn pick(book: &mut Book, now: Instant) -> Option<(usize, Arc<dyn Refreshable>)> {
    let mut best: Option<(usize, Arc<dyn Refreshable>, PickKey)> = None;
    for (index, kept) in book.kept.iter().enumerate() {
        if kept.running || kept.due > now {
            continue;
        }
        let Some(item) = kept.item.upgrade() else {
            continue;
        };
        let key = (item.deadline(), kept.due);
        let better = best.as_ref().is_none_or(|(_, _, b)| earlier(key, *b));
        if better {
            best = Some((index, item, key));
        }
    }
    best.map(|(index, item, _)| (index, item))
}

fn earlier(a: PickKey, b: PickKey) -> bool {
    match (a.0, b.0) {
        (Some(x), Some(y)) if x != y => x < y,
        (Some(_), None) => true,
        (None, Some(_)) => false,
        _ => a.1 < b.1,
    }
}

/// THE PROCESS'S REFRESHER, its workers started the first time it is reached. If a worker cannot
/// start, the reason is the answer, now and on every later call (the start is tried once): the
/// caller refuses what needed the refresher, and the process leaves, if it must, through the
/// root's one exit path, never from here.
pub fn process() -> Result<&'static Refresher, &'static str> {
    static ONE: OnceLock<Result<Refresher, String>> = OnceLock::new();
    ONE.get_or_init(|| Refresher::start("busbar-refresh", WORKERS))
        .as_ref()
        .map_err(String::as_str)
}

/// Keep `item` in the process's refresher, first due at `due`; the reason if the refresher's
/// workers did not start (nothing is kept, so the caller must not hand out what it would have
/// kept fresh).
pub fn keep(item: Weak<dyn Refreshable>, due: Instant) -> Result<(), &'static str> {
    process()?.keep(item, due);
    Ok(())
}

static STOPPING: AtomicBool = AtomicBool::new(false);

/// Latch the process's drain: the refresher starts nothing more, and a refresh in flight commits
/// nothing and reports at debug.
pub fn begin_stopping() {
    STOPPING.store(true, Ordering::SeqCst);
}

/// Whether the process is draining.
#[must_use]
pub fn stopping() -> bool {
    STOPPING.load(Ordering::SeqCst)
}

pub use busbar_contract::redacted::fingerprint;

/// A RATE LIMIT keyed by name: at most one pass per `window` per key, counting what it held back.
pub struct Throttle {
    window: Duration,
    last: Mutex<HashMap<String, (Instant, u32)>>,
}

impl Throttle {
    /// A throttle that passes one per `window` per key.
    #[must_use]
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            last: Mutex::new(HashMap::new()),
        }
    }

    /// `Some(held back since the last pass)` when `key` may pass at `now`; `None` (and one more
    /// held back) when it passed within the window.
    pub fn pass(&self, key: &str, now: Instant) -> Option<u32> {
        let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
        if last.len() > 4096 {
            let window = self.window;
            last.retain(|_, (at, _)| now.saturating_duration_since(*at) < window);
        }
        match last.get_mut(key) {
            Some((at, held)) if now.saturating_duration_since(*at) < self.window => {
                *held = held.saturating_add(1);
                None
            }
            Some((at, held)) => {
                let folded = std::mem::take(held);
                *at = now;
                Some(folded)
            }
            None => {
                last.insert(key.to_string(), (now, 0));
                Some(0)
            }
        }
    }
}

/// WHERE A REFRESH REPORTS: the operator's log (a coded diagnostic, or an uncoded INFO) and the
/// audit trail. The host's is `HostReport`; a test captures instead.
pub trait Report: Send + Sync {
    /// A coded diagnostic at `level`.
    fn diag(
        &self,
        diag: &'static crate::diagnostics::Diagnostic,
        level: tracing::Level,
        message: &str,
        fields: &[(&'static str, String)],
    );
    /// An uncoded INFO line (a recovery).
    fn info(&self, message: &str, fields: &[(&'static str, String)]);
    /// An audit record by `busbar` itself.
    fn audit(&self, action: &str, resource: &str, outcome: &'static str);
}

#[cfg(test)]
#[path = "tests/refresh_tests.rs"]
mod tests;
