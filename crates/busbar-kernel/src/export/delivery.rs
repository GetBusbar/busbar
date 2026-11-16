// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The export pump's delivery identity, custody counting and per-instance breaker cell (IF §8.5 round 33, §49).
//!
//! - `delivery` names one line set: minted from one process-wide counter seeded once from busbar-crypto (never a
//!   clock, 0 skipped). A resend keeps it with `attempt` + 1; after ACK{accepted} the prefix keeps it and the rest
//!   is a new line set with a fresh id and `attempt` = the parent's + 1.
//! - Custody is counted in `export_custody_total{instance, stream, level}`. An APPEND is ACCEPTED (the disk lane
//!   writes without a sync). Required custody is ACCEPTED on every stream but CONTENT, which has no producer in
//!   1.6.0, so a counted answer is never confirmed or paused.
//! - One `busbar-kernel-breaker` cell per export instance: 5 consecutive FAILED other than F_BUSY open it, one
//!   half-open probe follows; a Retry-After above 300 s holds it open for the stated time.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

use busbar_contract::crypto::RngError;
use busbar_contract::export_stream::ExportStream;
use busbar_kernel_breaker::cell::{BreakerCell, ProbeAdmit};
use busbar_kernel_breaker::cfg::{BreakerCfg, TripConfig, TripMode};
use busbar_plugin_abi::export::{CUSTODY_ACCEPTED, CUSTODY_DURABLE, CUSTODY_INDEXED};
use busbar_plugin_abi::fail::failed::F_BUSY;

/// The metric family custody answers are counted in.
pub const EXPORT_CUSTODY_TOTAL: &str = "busbar_export_custody_total";
/// Consecutive FAILED answers (F_BUSY excluded) that open an export instance's breaker cell.
pub const BREAKER_OPENS_AFTER: u32 = 5;
/// The longest Retry-After the retry schedule honours as a wait; above it the cell is held open instead.
pub const RETRY_AFTER_CLAMP_S: u64 = 300;

/// The process-wide delivery id counter.
#[derive(Debug)]
pub struct DeliveryIds {
    next: AtomicU64,
}

impl DeliveryIds {
    /// A counter starting at `seed` (tests; production seeds once through [`process_ids`]).
    pub const fn from_seed(seed: u64) -> Self {
        Self {
            next: AtomicU64::new(seed),
        }
    }

    /// The next id; never 0 (the counter wraps past it). Unique for 2^64 - 1 mints.
    pub fn mint(&self) -> u64 {
        loop {
            let id = self.next.fetch_add(1, Ordering::Relaxed);
            if id != 0 {
                return id;
            }
        }
    }
}

static PROCESS_IDS: OnceLock<DeliveryIds> = OnceLock::new();

/// The one counter of this process, seeded from busbar-crypto on first use. A failed draw seeds nothing and is
/// retried by the next call; the pump does not deliver without an id.
pub fn process_ids() -> Result<&'static DeliveryIds, RngError> {
    if let Some(ids) = PROCESS_IDS.get() {
        return Ok(ids);
    }
    let seed = busbar_contract::crypto::u64()?;
    Ok(PROCESS_IDS.get_or_init(|| DeliveryIds::from_seed(seed)))
}

/// One line set as the pump hands it to `ExportPort::deliver`: `(id, i)` is a stable key for line `i`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Delivery {
    pub id: u64,
    /// 1 on the first send; above 1 = possibly a duplicate.
    pub attempt: u32,
}

impl Delivery {
    /// A new line set's first send.
    pub fn first(ids: &DeliveryIds) -> Self {
        Self {
            id: ids.mint(),
            attempt: 1,
        }
    }

    /// The same line set again (FAILED, a deadline, or CUSTODY_NONE from `confirm`).
    pub fn resend(self) -> Self {
        Self {
            id: self.id,
            attempt: self.attempt.saturating_add(1),
        }
    }

    /// After ACK{accepted} of `lines` lines: None = every line is taken; else (lines kept under this id, the rest).
    /// The rest is a new line set with a fresh id and `attempt` = this one's + 1. With nothing taken the line set
    /// is unchanged, so it is resent under the same id.
    pub fn after_ack(
        self,
        accepted: u64,
        lines: usize,
        ids: &DeliveryIds,
    ) -> Option<(usize, Delivery)> {
        let kept = usize::try_from(accepted).map_or(lines, |a| a.min(lines));
        match kept {
            k if k == lines => None,
            0 => Some((0, self.resend())),
            k => Some((
                k,
                Delivery {
                    id: ids.mint(),
                    attempt: self.attempt.saturating_add(1),
                },
            )),
        }
    }
}

/// The `level` label of a counted custody answer; None for CUSTODY_NONE (a `confirm` answer only) and for
/// undefined levels.
pub const fn custody_level_token(level: u32) -> Option<&'static str> {
    match level {
        CUSTODY_ACCEPTED => Some("accepted"),
        CUSTODY_DURABLE => Some("durable"),
        CUSTODY_INDEXED => Some("indexed"),
        _ => None,
    }
}

/// Counts one delivery's custody answer (an APPEND is counted CUSTODY_ACCEPTED by the caller). Nothing else
/// follows in 1.6.0: required custody is ACCEPTED on every produced stream, so no answer is confirmed or paused.
pub fn count_custody(instance: &str, stream: ExportStream, level: u32) {
    let Some(level) = custody_level_token(level) else {
        return;
    };
    metrics::counter!(
        EXPORT_CUSTODY_TOTAL,
        "instance" => instance.to_owned(),
        "stream" => stream.as_token(),
        "level" => level
    )
    .increment(1);
}

/// What a delivery told the breaker about the sink's backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// ACK or APPEND.
    Delivered,
    /// FAILED with its code and the backend's Retry-After.
    Failed {
        code: u32,
        retry_after_s: Option<u64>,
    },
    /// REFUSED, FAULT or a call error: not a fact about the backend's health.
    NotHealth,
}

/// What the pump may do now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admit {
    Ready,
    /// This caller holds the one half-open probe; report it with [`ExportBreaker::probe_done`].
    Probe(u64),
    /// Open until this Unix second.
    Held {
        until: u64,
    },
}

/// One export instance's breaker cell. Times are Unix seconds, read once by the caller.
pub struct ExportBreaker {
    cell: BreakerCell,
    /// Trips on [`BREAKER_OPENS_AFTER`] consecutive failures; a Retry-After is the retry schedule's (K3).
    trip: BreakerCfg,
    /// The hold for a Retry-After above the clamp: open for exactly the stated time.
    hold: BreakerCfg,
}

impl ExportBreaker {
    pub fn new() -> Self {
        let trip = BreakerCfg {
            base_cooldown_secs: 30,
            max_cooldown_secs: RETRY_AFTER_CLAMP_S,
            honor_retry_after: false,
            trip: TripConfig {
                mode: TripMode::Consecutive,
                consecutive_n: BREAKER_OPENS_AFTER,
                ..TripConfig::default()
            },
            bench_below_trip_threshold: false,
        };
        let hold = BreakerCfg {
            honor_retry_after: true,
            ..trip.clone()
        };
        Self {
            cell: BreakerCell::new(),
            trip,
            hold,
        }
    }

    /// Whether the pump may deliver now. A won probe must be reported with [`Self::probe_done`].
    pub fn admit(&self, now: u64) -> Admit {
        match self.cell.acquire(now) {
            ProbeAdmit::ReadyNoProbe => Admit::Ready,
            ProbeAdmit::ProbeWon(epoch) => Admit::Probe(epoch),
            ProbeAdmit::Denied(_) => Admit::Held {
                until: self.cell.cooldown_until(),
            },
        }
    }

    /// Feeds one non-probe delivery's outcome.
    pub fn record(&self, now: u64, outcome: Outcome) {
        match outcome {
            Outcome::Delivered => {
                self.cell.record_success(now);
            }
            Outcome::Failed { code: F_BUSY, .. } | Outcome::NotHealth => {}
            Outcome::Failed {
                retry_after_s: Some(wait),
                ..
            } if wait > RETRY_AFTER_CLAMP_S => self.cell.open(now, &self.hold, Some(wait), wait),
            Outcome::Failed { .. } => {
                self.cell
                    .record_failure(now, &self.trip, None, RETRY_AFTER_CLAMP_S);
            }
        }
    }

    /// Reports the half-open probe: a delivery closes the cell, a FAILED reopens it, anything else hands the
    /// probe back undispatched.
    pub fn probe_done(&self, epoch: u64, now: u64, outcome: Outcome) {
        match outcome {
            Outcome::Failed { code: F_BUSY, .. } | Outcome::NotHealth => {
                self.cell.release_probe_owned(epoch)
            }
            Outcome::Delivered | Outcome::Failed { .. } => self.record(now, outcome),
        }
    }
}

impl Default for ExportBreaker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "tests/delivery_tests.rs"]
mod tests;
