//! The one wall clock this crate reads. Moved from `busbar-substrate::store::now`
//! (1.5.5's `crates/busbar-substrate/src/store.rs:139-146`): whole seconds since the Unix epoch,
//! saturating to `0` rather than panicking if the system clock reads before the epoch.
//!
//! Every state-machine function in [`crate::cell`] takes `now: u64` as a parameter rather than
//! calling this directly, so tests can drive the FSM against a fixed or fake clock; this function
//! is what a real caller feeds in.

/// The current time, in whole seconds since the Unix epoch.
pub fn unix_time_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
