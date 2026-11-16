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

use busbar_contract::crypto::RngError;
use busbar_contract::export_stream::ExportStream;

/// The metric family custody answers are counted in.
pub const EXPORT_CUSTODY_TOTAL: &str = "busbar_export_custody_total";
/// Consecutive FAILED answers (F_BUSY excluded) that open an export instance's breaker cell.
pub const BREAKER_OPENS_AFTER: u32 = 5;
/// The longest Retry-After the retry schedule honours as a wait; above it the cell is held open instead.
pub const RETRY_AFTER_CLAMP_S: u64 = 300;

/// The process-wide delivery id counter.
#[derive(Debug)]
pub struct DeliveryIds {
    _seed: u64,
}

impl DeliveryIds {
    /// A counter starting at `seed` (tests; production seeds once through [`process_ids`]).
    pub const fn from_seed(seed: u64) -> Self {
        Self { _seed: seed }
    }

    /// The next id; never 0.
    pub fn mint(&self) -> u64 {
        todo!()
    }
}

/// The one counter of this process, seeded from busbar-crypto on first use.
pub fn process_ids() -> Result<&'static DeliveryIds, RngError> {
    todo!()
}

/// One line set as the pump hands it to `ExportPort::deliver`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Delivery {
    pub id: u64,
    /// 1 on the first send; above 1 = possibly a duplicate.
    pub attempt: u32,
}

impl Delivery {
    pub fn first(ids: &DeliveryIds) -> Self {
        let _ = ids;
        todo!()
    }

    pub fn resend(self) -> Self {
        todo!()
    }

    pub fn after_ack(
        self,
        accepted: u64,
        lines: usize,
        ids: &DeliveryIds,
    ) -> Option<(usize, Delivery)> {
        let _ = (accepted, lines, ids);
        todo!()
    }
}

/// The `level` label of a counted custody answer; None for CUSTODY_NONE and undefined levels.
pub const fn custody_level_token(level: u32) -> Option<&'static str> {
    let _ = level;
    None
}

/// Counts one delivery's custody answer.
pub fn count_custody(instance: &str, stream: ExportStream, level: u32) {
    let _ = (instance, stream, level);
    todo!()
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

/// One export instance's breaker cell.
pub struct ExportBreaker {}

impl ExportBreaker {
    pub fn new() -> Self {
        todo!()
    }

    pub fn admit(&self, now: u64) -> Admit {
        let _ = now;
        todo!()
    }

    pub fn record(&self, now: u64, outcome: Outcome) {
        let _ = (now, outcome);
        todo!()
    }

    pub fn probe_done(&self, epoch: u64, now: u64, outcome: Outcome) {
        let _ = (epoch, now, outcome);
        todo!()
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
