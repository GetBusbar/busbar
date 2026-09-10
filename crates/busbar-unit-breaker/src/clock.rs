//! The composition root's clock helper, kept here only so the root has one spelling of the value
//! this crate's `now: u64` parameters expect: whole seconds since the Unix epoch, saturating to `0`
//! rather than panicking if the system clock reads before the epoch. Moved from
//! `busbar-substrate::store::now`.
//!
//! NOTHING IN THIS CRATE CALLS IT, and nothing in this crate may. Every decision here — the breaker
//! FSM in [`crate::cell`], the `Retry-After` conversion in [`crate::classify`] — takes `now` as a
//! parameter, so a decision is a function of the values it was handed and replaying the same inputs
//! gives the same answer. A helper that reads the clock is a thing a caller invokes; the moment a
//! decision invokes it, the decision stops being reproducible and the crate stops being a unit.

/// The current time, in whole seconds since the Unix epoch.
pub fn unix_time_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// The same instant, in whole NANOSECONDS since the Unix epoch — the jitter seed
/// [`crate::cell::BreakerCell::compute_cooldown_with_retry_after`] mixes, and the one reading in
/// this crate's vocabulary that seconds cannot stand in for. 1.5.5 read it inside the cooldown
/// computation itself (`1.5.5's store, breaker.rs:518-524`); the reading moves out
/// here, to the root's side of the seam, and the value is handed down. Two cells tripping in the
/// same second must not draw the same jitter, which is the whole reason the band exists.
pub fn unix_time_nanos() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}
