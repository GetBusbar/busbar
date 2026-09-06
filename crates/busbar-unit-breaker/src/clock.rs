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
