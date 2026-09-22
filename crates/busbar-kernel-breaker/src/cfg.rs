//! The resolved runtime breaker configuration the state machine evaluates.
//!
//! Moved byte-identical from `busbar-substrate::store::{BreakerCfg, TripConfig, TripMode}`
//! (1.5.5's `crates/busbar-substrate/src/store.rs:205-259`). Plain data — no serialization or
//! config-grammar concerns live here; a config-owning crate lowers its own grammar into this type.

/// Which signal decides when a cell trips from closed to open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TripMode {
    /// Trip when the fraction of errors in the sliding window reaches `threshold`.
    ErrorRate,
    /// Trip after `consecutive_n` failures in a row, ignoring the sliding window.
    Consecutive,
}

/// Trip thresholds for one breaker cell.
#[derive(Debug, Clone, PartialEq)]
pub struct TripConfig {
    /// Which of the two trip signals below is evaluated.
    pub mode: TripMode,
    /// Width, in seconds, of the sliding outcome window `ErrorRate` mode reads.
    pub window_s: u64,
    /// Fraction of errors in the window (0.0..=1.0) that trips the cell in `ErrorRate` mode.
    pub threshold: f64,
    /// Minimum outcomes required in the window before `ErrorRate` mode will even consider tripping.
    pub min_requests: usize,
    /// Number of consecutive failures that trips the cell in `Consecutive` mode.
    pub consecutive_n: u32,
}

impl Default for TripConfig {
    fn default() -> Self {
        Self {
            mode: TripMode::ErrorRate,
            window_s: 30,
            threshold: 0.5,
            min_requests: 5,
            consecutive_n: 3,
        }
    }
}

/// Breaker configuration for one pool (or the lane's default cell).
#[derive(Debug, Clone, PartialEq)]
pub struct BreakerCfg {
    /// The cooldown applied on a fresh trip (streak == 0), before jitter.
    pub base_cooldown_secs: u64,
    /// The ceiling every escalated cooldown is clamped to. A separate, caller-supplied
    /// `max_honored_retry_after_secs` (see
    /// [`BreakerCell::compute_cooldown_with_retry_after`](crate::cell::BreakerCell::compute_cooldown_with_retry_after))
    /// is the absolute ceiling on an honored upstream Retry-After, which may legitimately exceed
    /// this cap.
    pub max_cooldown_secs: u64,
    /// Whether an upstream `Retry-After` value is honored as a floor under the computed cooldown.
    pub honor_retry_after: bool,
    /// The trip thresholds this cell evaluates.
    pub trip: TripConfig,
    /// Whether a transient failure that did NOT breach the trip threshold still benches the cell for
    /// a cooldown. `true` on a pool with failover siblings (a sub-threshold blip can be shed to a
    /// sibling); `false` on a degenerate single-member cell, where benching the only member after one
    /// blip would refuse every subsequent caller for no gain.
    pub bench_below_trip_threshold: bool,
}

impl Default for BreakerCfg {
    fn default() -> Self {
        Self {
            base_cooldown_secs: 15,
            max_cooldown_secs: 120,
            honor_retry_after: true,
            trip: TripConfig::default(),
            bench_below_trip_threshold: true,
        }
    }
}
