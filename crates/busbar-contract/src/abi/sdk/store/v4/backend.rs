// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Plugin-side primitive persistence adapter. Product policy belongs to the host.

type Host = KindGenericHost<crate::plugin::markers::StoreKind>;

use crate::abi::sdk::conn::Host as KindGenericHost;
use crate::abi::sdk::store::{Op, Step};
use crate::persistence::*;
use crate::redacted::OwnerSeal;

/// The validated `(slot, seq)` of one commit, decoded from the wire candidate (N1).
///
/// A slotted send names `slot < MAX_SLOTS` with `seq >= 1`; a self-fenced send names
/// `SLOT_SELF_FENCED` with `seq == 0`. Anything else is refused before any read, so a
/// store never sizes per-writer state from an unchecked slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitSlot {
    slot: u32,
    seq: u64,
}

impl CommitSlot {
    /// Validate wire slot fields; `None` means the send must be refused untouched.
    #[must_use]
    pub fn decode(slot: u32, seq: u64) -> Option<Self> {
        let valid = if slot == SLOT_SELF_FENCED {
            seq == 0
        } else {
            slot < MAX_SLOTS && seq >= 1
        };
        valid.then_some(Self { slot, seq })
    }

    /// The queue slot, or `None` for a self-fenced send (no slot row is read or written).
    #[must_use]
    pub fn slot(self) -> Option<u32> {
        (self.slot != SLOT_SELF_FENCED).then_some(self.slot)
    }

    /// The lease sequence; zero for a self-fenced send.
    #[must_use]
    pub fn seq(self) -> u64 {
        self.seq
    }
}

/// A commit's definitive answer and its serialization observation.
#[derive(Debug)]
pub struct Committed<O> {
    /// Serialization observation; on an equal-sequence replay, the slot row's.
    pub observed_at: ClockObservation,
    /// The verdict. `Applied` carries empty bytes: results are never echoed.
    pub decision: Decision<O>,
}

/// Mandatory native Store v4 operations. Pending continuations live in `Op`.
///
/// The backend must preserve the contract's atomicity, fencing and slot-row semantics.
/// It must never infer rollback from cancellation. `info` becomes fixed after connect.
pub trait Backend: Send + Sync + Sized + 'static {
    /// Custody seal minted by this plugin, independent of kernel custody.
    type Owner: OwnerSeal + Send + Sync + 'static;
    /// The plugin's seal for requests copied into its wiping custody.
    fn owner(&self) -> &Self::Owner;
    /// Explicit per-instance allocation admission budget (including descriptor workspace).
    /// Supply this from settings or a documented host limit; no SDK default is imposed.
    fn input_budget(&self) -> usize;
    /// Parse settings without backend mutation.
    fn validate(settings: &[u8]) -> Result<(), String>;
    /// Construct an instance; network work belongs in `connect`.
    fn open(settings: &[u8], secrets: &[&[u8]], host: Option<Host>) -> Result<Self, String>;
    /// Complete connection/admission. May retain state and a connection in `op`.
    fn connect(&self, op: &mut Op<'_>) -> Step<Result<(), String>>;
    /// Recheck the exact inspected/recovery binding before adopting the prepared
    /// instance into OPEN. Never initialize another native session or weaken to connect.
    fn connect_prepared(
        &self,
        op: &mut Op<'_>,
        binding: &crate::persistence::lifecycle::OpenBinding,
    ) -> Step<Result<(), String>>;
    /// Inspect/retain/reconcile native pre-open lifecycle work. No logical migration
    /// or serving authority is inferred from a completed native request.
    fn bootstrap(
        &self,
        op: &mut Op<'_>,
        request: &crate::persistence::lifecycle::Request<Self::Owner>,
    ) -> Step<
        Result<
            crate::persistence::lifecycle::Response<Self::Owner>,
            crate::persistence::lifecycle::Error,
        >,
    >;
    /// Facts for this connected instance, immutable for its lifetime.
    fn info(&self) -> BackendInfo;
    /// Coherent exact-address read.
    fn read(
        &self,
        op: &mut Op<'_>,
        request: &Read,
    ) -> Step<Result<ReadResult<Self::Owner>, Failure>>;
    /// Ordered generation-checked page.
    fn scan(&self, op: &mut Op<'_>, request: &Scan) -> Step<Result<Page<Self::Owner>, Failure>>;
    /// Atomic effects and slot row (STORE-TRANSACTIONS §2.5): STALE below the recorded
    /// sequence, the recorded verdict replayed at an equal one, FENCED when the epoch is
    /// not admitted, and every evaluated verdict recorded. Self-fenced sends skip the row.
    fn commit(
        &self,
        op: &mut Op<'_>,
        request: &PreparedCandidate<Self::Owner>,
        slot: CommitSlot,
    ) -> Step<Result<Committed<Self::Owner>, Failure>>;
    /// Authoritative dataset clock.
    fn clock(&self, op: &mut Op<'_>, dataset: DatasetId)
        -> Step<Result<ClockObservation, Failure>>;
}
