//! The protocol-agnostic disposition classifier — Stage 2 of the two-stage pipeline that turns an
//! upstream error into the fact the breaker state machine acts on — and the `grpc-status` table.
//!
//! Stage 1b, the HTTP-status ladder and the operator `error_map`, is [`crate::normalize`]: the
//! served path's normalizer, and the ONLY one (of two implementations of one thing, the served one
//! is the base). This module used to carry a second copy over its own raw-error and signal
//! types, reached only through [`crate::port::classify_upstream`]; that copy is deleted and the port
//! reads the served one. The signal types are the contract's.
//!
//! The "operator `error_map` points at an unrecognized class" diagnostic is delivered through an
//! injectable [`Diagnostics`] sink rather than `tracing::warn!`, since this crate takes no logging
//! dependency. `// contract:` a caller wires a real sink in; [`NoopDiagnostics`] preserves the
//! "silently ignored" behavior for the return value.

/// The status class and the disposition, as the contract owns them.
///
/// This unit used to declare both, byte-for-byte the substrate's, and keep the metric labels in
/// step with the egress unit's by hand. The rows live in `busbar_contract::upstream` now — the one
/// crate this unit and the planes whose dialects read the class can both name — and this module
/// keeps its historical paths as re-exports so every caller matching on `classify::StatusClass`
/// still does.
pub use busbar_contract::upstream::{Disposition, StatusClass};

use busbar_contract::upstream::CanonicalSignal;

/// A sink for the one diagnostic this module raises: an operator `error_map` entry names a string
/// that is not a recognized [`StatusClass`]. `// contract:` a real deployment wires this to its own
/// logging/metrics seam; [`NoopDiagnostics`] is the default and matches 1.5.5's behavior for the
/// classification RESULT (the mapping is still silently ignored either way — only the side-channel
/// warning is pluggable here instead of a hardwired `tracing::warn!`).
pub trait Diagnostics {
    /// Called at most once per distinct unrecognized value in a process's lifetime (dedup is the
    /// caller's job in the reference `WarnOnceDiagnostics`, mirroring 1.5.5's warn-once-per-value).
    fn unrecognized_error_map_value(&self, value: &str);
}

/// A [`Diagnostics`] sink that does nothing. The default when a caller has not wired one in.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopDiagnostics;

impl Diagnostics for NoopDiagnostics {
    fn unrecognized_error_map_value(&self, _value: &str) {}
}

/// A [`Diagnostics`] adapter that forwards each distinct unrecognized value to an inner sink AT
/// MOST ONCE per process lifetime, deduplicating repeat calls for the same value itself so the
/// inner sink (e.g. a real `tracing::warn!`-backed one the composition root binds) never has to.
/// An unrecognized value is warned about once and then ignored: the classification RESULT is
/// unaffected either way (the mapping is still silently ignored) — only how many times the
/// side-channel warning fires.
pub struct WarnOnceDiagnostics<S: Diagnostics> {
    seen: std::sync::Mutex<std::collections::HashSet<String>>,
    inner: S,
}

impl<S: Diagnostics> WarnOnceDiagnostics<S> {
    /// Wrap `inner`, deduplicating by the exact unrecognized string.
    pub fn new(inner: S) -> Self {
        Self {
            seen: std::sync::Mutex::new(std::collections::HashSet::new()),
            inner,
        }
    }
}

impl<S: Diagnostics> Diagnostics for WarnOnceDiagnostics<S> {
    fn unrecognized_error_map_value(&self, value: &str) {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        if seen.insert(value.to_string()) {
            drop(seen);
            self.inner.unrecognized_error_map_value(value);
        }
    }
}

/// A shared [`Diagnostics`] sink is still one: this is what lets a caller keep a handle on the
/// concrete sink (e.g. to assert on it in a test, or to fan it out elsewhere) while also handing
/// an owned value to [`crate::port::classify_upstream`].
impl<S: Diagnostics + ?Sized> Diagnostics for std::sync::Arc<S> {
    fn unrecognized_error_map_value(&self, value: &str) {
        (**self).unrecognized_error_map_value(value);
    }
}

/// Classify a [`CanonicalSignal`] into a [`Disposition`]: the disposition column of the contract's
/// table, read for the signal's class.
pub fn classify(sig: &CanonicalSignal) -> Disposition {
    sig.class.disposition()
}

/// Every `grpc-status` code paired with the [`StatusClass`] this unit reads it as, as data.
///
/// gRPC's numbering is its own: nothing here is derived from an HTTP status, and the two tables
/// disagree on purpose where the protocols do. Three groupings carry the money decisions:
///
/// - `RESOURCE_EXHAUSTED` is the upstream's quota, not the caller's mistake, so it is a rate limit
///   (transient, and the upstream's own wait is the cooldown floor) — the same reading 1.5.5 gave
///   HTTP `429`. The transport's coarse class calls it a client error because the coarse class has
///   only three buckets; this table is what the breaker acts on.
/// - `UNAUTHENTICATED` and `PERMISSION_DENIED` are a withdrawn or rejected credential, which takes
///   every sibling lane naming this destination down with it — hard down, exactly as 1.5.5 read
///   HTTP `401`/`403`.
/// - `INVALID_ARGUMENT`, `NOT_FOUND` and their neighbours are the caller's own request being wrong,
///   so the destination is healthy and nothing is recorded against it.
///
/// `OK` has a row too, for the same reason the HTTP fallback has a non-error arm: an answer that
/// classified as a failure but carries `OK` is not evidence against the destination, so it records
/// nothing rather than being counted as an outage.
pub const GRPC_STATUS_TABLE: &[(u8, StatusClass)] = &[
    (GRPC_OK, StatusClass::ClientError),
    (GRPC_CANCELLED, StatusClass::ClientError),
    (GRPC_UNKNOWN, StatusClass::ServerError),
    (GRPC_INVALID_ARGUMENT, StatusClass::ClientError),
    (GRPC_DEADLINE_EXCEEDED, StatusClass::Timeout),
    (GRPC_NOT_FOUND, StatusClass::ClientError),
    (GRPC_ALREADY_EXISTS, StatusClass::ClientError),
    (GRPC_PERMISSION_DENIED, StatusClass::Auth),
    (GRPC_RESOURCE_EXHAUSTED, StatusClass::RateLimit),
    (GRPC_FAILED_PRECONDITION, StatusClass::ClientError),
    (GRPC_ABORTED, StatusClass::ServerError),
    (GRPC_OUT_OF_RANGE, StatusClass::ClientError),
    (GRPC_UNIMPLEMENTED, StatusClass::ClientError),
    (GRPC_INTERNAL, StatusClass::ServerError),
    (GRPC_UNAVAILABLE, StatusClass::ServerError),
    (GRPC_DATA_LOSS, StatusClass::ServerError),
    (GRPC_UNAUTHENTICATED, StatusClass::Auth),
];

/// `grpc-status: 0` — the call succeeded.
pub const GRPC_OK: u8 = 0;
/// `grpc-status: 1` — the call was cancelled, usually by the caller itself.
pub const GRPC_CANCELLED: u8 = 1;
/// `grpc-status: 2` — an upstream failure it could not attribute.
pub const GRPC_UNKNOWN: u8 = 2;
/// `grpc-status: 3` — the caller's argument was wrong.
pub const GRPC_INVALID_ARGUMENT: u8 = 3;
/// `grpc-status: 4` — the upstream did not answer in time.
pub const GRPC_DEADLINE_EXCEEDED: u8 = 4;
/// `grpc-status: 5` — the entity the caller named does not exist.
pub const GRPC_NOT_FOUND: u8 = 5;
/// `grpc-status: 6` — the entity the caller asked to create already exists.
pub const GRPC_ALREADY_EXISTS: u8 = 6;
/// `grpc-status: 7` — the credential is not allowed to do this.
pub const GRPC_PERMISSION_DENIED: u8 = 7;
/// `grpc-status: 8` — a quota or per-upstream resource is spent.
pub const GRPC_RESOURCE_EXHAUSTED: u8 = 8;
/// `grpc-status: 9` — the upstream's state rejects the operation.
pub const GRPC_FAILED_PRECONDITION: u8 = 9;
/// `grpc-status: 10` — the upstream aborted the call over its own concurrency.
pub const GRPC_ABORTED: u8 = 10;
/// `grpc-status: 11` — the caller read or wrote past a valid range.
pub const GRPC_OUT_OF_RANGE: u8 = 11;
/// `grpc-status: 12` — the method the caller asked for is not implemented.
pub const GRPC_UNIMPLEMENTED: u8 = 12;
/// `grpc-status: 13` — the upstream broke an invariant of its own.
pub const GRPC_INTERNAL: u8 = 13;
/// `grpc-status: 14` — the upstream is not available right now.
pub const GRPC_UNAVAILABLE: u8 = 14;
/// `grpc-status: 15` — unrecoverable data loss or corruption at the upstream.
pub const GRPC_DATA_LOSS: u8 = 15;
/// `grpc-status: 16` — the credential is missing or was not accepted.
pub const GRPC_UNAUTHENTICATED: u8 = 16;

/// Read one `grpc-status` code as a [`StatusClass`], through [`GRPC_STATUS_TABLE`] and nothing else.
///
/// A code gRPC has not defined is not evidence about the destination in either direction, so it
/// takes the same answer an unexpected status does on the HTTP side: the caller's fault, recorded
/// against nobody. Inventing an outage from a number no specification names would trip a live lane
/// on a typo.
#[must_use]
pub fn grpc_status_class(code: u8) -> StatusClass {
    let mut i = 0;
    while i < GRPC_STATUS_TABLE.len() {
        let (row, class) = GRPC_STATUS_TABLE[i];
        if row == code {
            return class;
        }
        i += 1;
    }
    StatusClass::ClientError
}
