//! The half-open probe journal sink. The architecture (ARCHITECTURE.md §4.1) requires every
//! probe-worthy state transition to be journaled; 1.5.5 had no such journal (a probe's outcome was
//! observable only via the in-memory FSM and `/stats`), so this is new surface area for the
//! breaker unit, not a port — it is deliberately a trait, not a concrete writer, so the unit that
//! owns the real journal (`busbar-unit-wal` / the audit unit, per §4.1) can implement it without
//! this crate depending on that unit's I/O, serialization, or journal-record framing.
//!
//! `// contract:` the event shape below (pool/destination as bare strings and `u64`s) is a
//! placeholder for whatever locator types `busbar-contract` settles on; a caller of this crate
//! narrows them at the call site today.

/// One journal-worthy breaker event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeEvent {
    /// A single-flight recovery probe was won: the cell moved Open → HalfOpen.
    Won {
        /// The pool this cell belongs to (the default cell uses `""`).
        pool: String,
        /// The destination identifier.
        destination: u64,
        /// The owner-token epoch the winner must present to release the probe.
        epoch: u64,
        /// Unix seconds.
        now: u64,
    },
    /// A won probe's outcome was a success: the cell closed (HalfOpen → Closed).
    Succeeded {
        /// The pool this cell belongs to.
        pool: String,
        /// The destination identifier.
        destination: u64,
        /// Unix seconds.
        now: u64,
    },
    /// A won probe's outcome was a failure: the cell reopened (HalfOpen → Open) with a fresh
    /// cooldown.
    Failed {
        /// The pool this cell belongs to.
        pool: String,
        /// The destination identifier.
        destination: u64,
        /// The new cooldown deadline, Unix seconds.
        cooldown_until: u64,
        /// Unix seconds.
        now: u64,
    },
    /// A won probe was abandoned without recording any outcome (the caller never dispatched).
    Released {
        /// The pool this cell belongs to.
        pool: String,
        /// The destination identifier.
        destination: u64,
        /// The owner-token epoch that was released.
        epoch: u64,
        /// Unix seconds.
        now: u64,
    },
}

/// A sink for [`ProbeEvent`]s. Implementations decide durability, batching, and format; this
/// crate's own FSM calls a sink synchronously and does not retry or buffer on its behalf.
pub trait JournalSink: Send + Sync {
    /// Record one probe-lifecycle event.
    fn record(&self, event: ProbeEvent);
}

/// A [`JournalSink`] that discards every event. The default when a caller has not wired a real
/// journal in (e.g. in a test, or before the audit unit's seam lands).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopJournal;

impl JournalSink for NoopJournal {
    fn record(&self, _event: ProbeEvent) {}
}
