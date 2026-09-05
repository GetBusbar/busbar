// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What happens after the power goes out.
//!
//! A node that dies mid-unit leaves holds open in the journal and nobody to settle them. On the
//! next boot this module reads those records back, MATERIALISES each hold — the one way a hold
//! exists without having passed the door, which is why the token that does it lives in this file
//! and nowhere else — and settles it through the same table every live unit settles through.
//!
//! The table's two recovery rows say the whole thing:
//!
//! - The record shows the unit had DISPATCHED: something was sent, so something may be owed. Post
//!   the last checkpointed accrual — zero if it never checkpointed — and mark the posting recovered.
//! - The record shows it had NOT dispatched: nothing left the node, so nothing is owed. Post zero
//!   and mark it void.
//!
//! Neither row guesses upward. A crash is not evidence of consumption.
//!
//! The other half of recovery is the journal's own tail. A machine that dies mid-write leaves a
//! partial record behind, so the reader is written to expect one: every record carries its length
//! and a checksum, the reader stops at the first record that does not check out, and the tail is
//! truncated there. A torn tail is normal. A torn record in the MIDDLE is not, and says so.

use busbar_caps::{
    Canary, Hold, LedgerToken, MeterClassId, Outcome, Posted, PrincipalId, ReasonCode,
    QuantitySource, RecoveryToken, StepName, UnitKey, Usage, UsageLine, UsageToken,
};

use crate::slice::Epoch;
use crate::teller::{settle_amount, Evidence, Kernel};

/// A hold as the journal wrote it.
// contract: HoldRecord — the journal entry the write-ahead-log unit appends at the door
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoldRecord {
    /// Which unit.
    pub unit: UnitKey,
    /// Whose it was.
    pub principal: PrincipalId,
    /// What the door reserved.
    pub reserved: u64,
    /// What the last checkpoint recorded as spent.
    pub checkpointed: u64,
    /// Whether a dispatch record was durable before the crash.
    pub dispatched: bool,
    /// The lease epoch the node held when it opened the hold.
    pub lease_epoch: Epoch,
}

/// Bring one hold back from its record.
///
/// The recovered hold carries the checkpointed accrual, and knows it was recovered, so the posting
/// it eventually produces is marked without anyone having to remember to mark it.
pub fn materialize(kernel: &Kernel, record: &HoldRecord) -> Hold {
    Hold::materialize(
        &RecoveryToken::mint(kernel.seal()),
        record.principal.clone(),
        record.reserved,
        record.checkpointed,
    )
}

/// Bring a hold back and settle it, in one step, per the table.
pub fn settle(kernel: &Kernel, record: &HoldRecord, canary: &Canary) -> Posted {
    let hold = materialize(kernel, record);
    let evidence = Evidence {
        recovered: true,
        dispatched: record.dispatched,
        checkpointed: record.checkpointed,
        ..Evidence::default()
    };
    // A recovered unit has no live end of its own: it stopped where it stopped. The outcome it is
    // settled under is the one the record supports, and the table reads the recovery rows first, so
    // the outcome here changes nothing about the amount.
    let outcome = Outcome::Failed(StepName::Route, ReasonCode::TaskLost);
    let (amount, flags) = settle_amount(&outcome, &evidence);
    // One line, and the record holds sixteen: this report is within the bound by construction.
    let usage = Usage::estimate(
        &UsageToken::mint(kernel.seal()),
        vec![UsageLine {
            class: MeterClassId::new("nano_units"),
            quantity: amount,
            // The sweep never saw a destination report anything: this figure is the accrual the
            // journal recorded, which is the kernel's own count, and the whole report is an
            // estimate for the same reason.
            source: QuantitySource::Count,
            estimated: true,
        }],
    )
    .expect("one usage line is always within the record's bound");
    let posted = Posted::settle(hold, &usage, &LedgerToken::mint(kernel.seal())).flagged(flags);
    canary.settled();
    posted
}

/// Settle every hold left open by a dead incarnation.
///
/// Every open hold whose lease epoch is behind the current one is recovered, regardless of how
/// young it is: a hold from an incarnation that is gone has nobody to finish it, and "wait and see"
/// is how an unsettled hold becomes a permanently unposted one.
pub fn recover_all(
    kernel: &Kernel,
    records: &[HoldRecord],
    current_epoch: Epoch,
    canary: &Canary,
) -> Vec<Posted> {
    records
        .iter()
        .filter(|record| record.lease_epoch < current_epoch)
        .map(|record| settle(kernel, record, canary))
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// The journal tail
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// The fixed header every journal record carries: its length, then a checksum of its payload.
pub const RECORD_HEADER_BYTES: usize = 8;

/// How a scan of the journal's tail ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TailVerdict {
    /// Every record checked out. The journal ends cleanly.
    Clean,
    /// The last record was cut off mid-write. Normal after a crash: truncate and carry on.
    Torn,
}

/// What the reader found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tail {
    /// How many whole records were read.
    pub records: usize,
    /// How many bytes of the file are good.
    pub valid_bytes: usize,
    /// Whether the tail was torn.
    pub verdict: TailVerdict,
}

/// Read the journal's frames and stop at the first one that does not check out.
///
/// A record is a four-byte length, a four-byte checksum, and that many bytes of payload. A tail
/// that is short, or whose checksum fails, is a machine that died mid-write: the file is truncated
/// to the last good record and the node carries on. That is the whole recovery of a torn tail, and
/// it is deliberately the simplest thing that can be right.
pub fn truncate_torn_tail(bytes: &[u8]) -> Tail {
    let mut at = 0usize;
    let mut records = 0usize;
    loop {
        if at == bytes.len() {
            break Tail {
                records,
                valid_bytes: at,
                verdict: TailVerdict::Clean,
            };
        }
        if at + RECORD_HEADER_BYTES > bytes.len() {
            break Tail {
                records,
                valid_bytes: at,
                verdict: TailVerdict::Torn,
            };
        }
        let length =
            u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]) as usize;
        let expected =
            u32::from_le_bytes([bytes[at + 4], bytes[at + 5], bytes[at + 6], bytes[at + 7]]);
        let payload_end = at + RECORD_HEADER_BYTES + length;
        if payload_end > bytes.len() {
            break Tail {
                records,
                valid_bytes: at,
                verdict: TailVerdict::Torn,
            };
        }
        if crc32(&bytes[at + RECORD_HEADER_BYTES..payload_end]) != expected {
            break Tail {
                records,
                valid_bytes: at,
                verdict: TailVerdict::Torn,
            };
        }
        records += 1;
        at = payload_end;
    }
}

/// Frame a payload the way [`truncate_torn_tail`] reads it.
pub fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(RECORD_HEADER_BYTES + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&crc32(payload).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// The ordinary checksum, computed a bit at a time so this file carries no table and no dependency.
pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for byte in bytes {
        crc ^= *byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// The points a machine can die at
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// A place in a unit's life where the power can go out.
///
/// The battery kills the process at every one of these and checks the node comes back saying the
/// right thing. They are listed here rather than in the test so that the list is part of the
/// design: adding a durability point to the loop means adding a row here, and the row says what
/// recovery owes the customer if the machine dies there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillPoint {
    /// Between the arrival gate and the plane's decode.
    BeforeDecode,
    /// Between any two adjacent steps before the door.
    BetweenPreDoorSteps,
    /// After the idempotency key was claimed and before the hold was durable. The claim is voided
    /// at recovery, so the client's retry is not answered with somebody else's answer.
    BetweenClaimAndHold,
    /// After the hold was durable and before anything was dispatched.
    AfterHoldBeforeDispatch,
    /// Between two legs of a route.
    BetweenLegs,
    /// After the response was relayed and before the settle record was durable.
    AfterRelayBeforeSettle,
    /// In the middle of the write itself, leaving a torn record.
    MidWrite,
}

/// What the node owes after dying at a point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Owed {
    /// Nothing happened. Post zero, marked void.
    Nothing,
    /// Something was dispatched. Post the last checkpoint, marked recovered.
    LastCheckpoint,
    /// The tail is torn: truncate to the last good record, then decide as above.
    TruncateThenDecide,
}

/// The answer for each point, as a table rather than a habit.
pub fn owed_after(point: KillPoint) -> Owed {
    match point {
        KillPoint::BeforeDecode
        | KillPoint::BetweenPreDoorSteps
        | KillPoint::BetweenClaimAndHold
        | KillPoint::AfterHoldBeforeDispatch => Owed::Nothing,
        KillPoint::BetweenLegs | KillPoint::AfterRelayBeforeSettle => Owed::LastCheckpoint,
        KillPoint::MidWrite => Owed::TruncateThenDecide,
    }
}

/// Whether an idempotency claim taken before a crash has to be voided at recovery.
///
/// It does, at every point before the hold was durable: a claim with no hold behind it is a key
/// that would answer a retry with a unit that never ran.
pub fn voids_claim(point: KillPoint) -> bool {
    matches!(
        point,
        KillPoint::BetweenClaimAndHold | KillPoint::BeforeDecode | KillPoint::BetweenPreDoorSteps
    )
}
