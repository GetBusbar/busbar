// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! AN IN-MEMORY LOG DOUBLE: a `tracing` subscriber that records the WARN-and-above events (WARN,
//! ERROR) emitted while it is installed, so a test can assert that a particular diagnostic fired —
//! its message and its structured fields — without a global subscriber or any output.
//! [`WarnCapture::capturing_debug`] lowers the threshold to DEBUG for a diagnostic that emits at
//! debug.
//!
//! Driving idiom:
//! ```ignore
//! let cap = busbar_contract::testkit::WarnCapture::default();
//! tracing::subscriber::with_default(cap.clone(), || { /* code under test */ });
//! assert!(cap.contains("expected substring"));
//! ```
//! `with_default` installs a THREAD-LOCAL subscriber: the code under test must run synchronously on
//! the same thread as the closure (a current-thread runtime driven with `block_on` INSIDE the
//! closure, never a multi-threaded runtime), or the capture comes back empty.
//!
//! SERIALIZATION. Although `with_default` is thread-local, `tracing`'s callsite interest and its
//! max-level hint are cached PROCESS-GLOBALLY, so two captures running in parallel can blind each
//! other. Every `WarnCapture` therefore holds a REENTRANT process-global gate from construction until
//! it (and every clone of it) drops, so at most one test's captures are live at a time. The gate is
//! reentrant per thread, so one test may hold several captures at once without deadlocking itself.
//!
//! INTEREST. A callsite first evaluated with no subscriber installed is cached "never", after which no
//! later capture can see it. So the FIRST capture built in a process installs a bare subscriber that
//! is interested in everything and records nothing as the GLOBAL default, and rebuilds the interest
//! cache once; the capture itself is still the thread-local subscriber above.

use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread::ThreadId;
use tracing::span::{Attributes, Id, Record};
use tracing::subscriber::Interest;
use tracing::{Event, Level, Metadata, Subscriber};

/// The in-memory capture. Clones share one record and one gate hold.
#[derive(Clone, Debug)]
pub struct WarnCapture {
    messages: Arc<Mutex<Vec<String>>>,
    /// The least-severe level admitted: `WARN` (the default) or `DEBUG`.
    max_level: Level,
    _gate: Arc<GateHold>,
}

impl Default for WarnCapture {
    fn default() -> Self {
        Self::at(Level::WARN)
    }
}

impl WarnCapture {
    /// A capture that admits DEBUG-and-above (DEBUG, INFO, WARN, ERROR).
    pub fn capturing_debug() -> Self {
        Self::at(Level::DEBUG)
    }

    fn at(max_level: Level) -> Self {
        ensure_capture_interest();
        Self {
            messages: Arc::default(),
            max_level,
            _gate: GateHold::acquire(),
        }
    }

    /// Every captured event so far, each as `"{message} {field}={value} ..."`.
    pub fn messages(&self) -> Vec<String> {
        self.messages.lock().map(|m| m.clone()).unwrap_or_default()
    }

    /// True when some captured event contains `needle`.
    pub fn contains(&self, needle: &str) -> bool {
        self.messages().iter().any(|m| m.contains(needle))
    }

    /// How many captured events contain `needle` (a warn-once latch asserts this stays at 1).
    pub fn count(&self, needle: &str) -> usize {
        self.messages()
            .iter()
            .filter(|m| m.contains(needle))
            .count()
    }
}

/// Renders one event's `message` and every other field, flattened into `key=value` pairs.
#[derive(Default)]
struct Rendered {
    message: String,
    fields: String,
}

impl Rendered {
    fn record(&mut self, field: &tracing::field::Field, rendered: String) {
        if field.name() == "message" {
            self.message = rendered;
        } else {
            if !self.fields.is_empty() {
                self.fields.push(' ');
            }
            self.fields
                .push_str(&format!("{}={}", field.name(), rendered));
        }
    }
}

impl tracing::field::Visit for Rendered {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.record(field, format!("{value:?}"));
    }
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.record(field, value.to_string());
    }
}

impl Subscriber for WarnCapture {
    fn register_callsite(&self, _: &'static Metadata<'static>) -> Interest {
        // Never let a thread-local capture cache a callsite as disabled for the whole process.
        Interest::sometimes()
    }
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        // `Level` orders ERROR < WARN < INFO < DEBUG < TRACE (lower = more severe).
        *metadata.level() <= self.max_level
    }
    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }
    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, event: &Event<'_>) {
        if *event.metadata().level() > self.max_level {
            return;
        }
        let mut rendered = Rendered::default();
        event.record(&mut rendered);
        if let Ok(mut messages) = self.messages.lock() {
            messages.push(format!("{} {}", rendered.message, rendered.fields));
        }
    }
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
}

/// The global default the first capture installs: interested in every callsite, records nothing.
struct Interested;

impl Subscriber for Interested {
    fn register_callsite(&self, _: &'static Metadata<'static>) -> Interest {
        Interest::always()
    }
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }
    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, _: &Event<'_>) {}
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
}

/// Make every callsite's interest permanently "yes", once per process (see the module note). A
/// binary that already set a global default is past the failure mode this closes, so its error is
/// ignored.
fn ensure_capture_interest() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = tracing::subscriber::set_global_default(Interested);
        tracing::callsite::rebuild_interest_cache();
    });
}

/// The gate's state: the owner thread and its reentrancy count, or `None` when free. Its mutex is
/// held only for the bookkeeping, never across the code under test.
struct CaptureGate {
    state: Mutex<Option<(ThreadId, usize)>>,
    cv: Condvar,
}

fn capture_gate() -> &'static CaptureGate {
    static GATE: OnceLock<CaptureGate> = OnceLock::new();
    GATE.get_or_init(|| CaptureGate {
        state: Mutex::new(None),
        cv: Condvar::new(),
    })
}

/// One reentrant level of the gate, released when the capture and all its clones drop.
#[derive(Debug)]
struct GateHold;

impl GateHold {
    /// Acquire a level, blocking while a DIFFERENT thread holds the gate.
    fn acquire() -> Arc<Self> {
        let gate = capture_gate();
        let me = std::thread::current().id();
        let mut st = gate.state.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            match *st {
                None => {
                    *st = Some((me, 1));
                    break;
                }
                Some((owner, n)) if owner == me => {
                    *st = Some((owner, n + 1));
                    break;
                }
                _ => st = gate.cv.wait(st).unwrap_or_else(|e| e.into_inner()),
            }
        }
        Arc::new(GateHold)
    }
}

impl Drop for GateHold {
    fn drop(&mut self) {
        let gate = capture_gate();
        let mut st = gate.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((owner, n)) = *st {
            if n <= 1 {
                *st = None;
                gate.cv.notify_all();
            } else {
                *st = Some((owner, n - 1));
            }
        }
    }
}
