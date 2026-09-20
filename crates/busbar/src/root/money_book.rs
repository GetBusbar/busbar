// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The money-book pass-through SEAM (1.6.0 wave W1.a — DECISION #26 S2, additive/dormant).
//!
//! ## What this is, and what it deliberately is not
//!
//! One trait, [`MoneyBook`], names the money-RECORDING operations that today live in three
//! places at once: the ledger unit's settlement arithmetic (`busbar-unit-ledger`), the durable
//! row shapes and their rate-limit ledger (`busbar-api`), and the per-plane row builders that
//! assemble a [`MeteringRow`] out of what a completed unit consumed. Bringing those under one
//! trait is what lets the W3 fold collapse rates+usage+ledger into a single `busbar-kernel-ledger`
//! WITHOUT the exit arms having to name three crates: they will name the seam, and the seam will
//! name whatever implements it.
//!
//! This wave does NOT perform that fold. It sets it up. [`PassThroughBook`] is the ONE
//! implementation, and every method delegates to the EXISTING code — `Ledger::settle_recording`,
//! `Ledger::post`, `UsageLedger::apply_delta`, and the field-for-field row assembly the planes do
//! today. The seam is DORMANT: nothing on the serving path routes through it, so the money oracle
//! is byte-identical by construction (the shipped bytes are the shipped functions, untouched). The
//! trait exists so that a later commit can re-source the implementation from `busbar-kernel-ledger`
//! and flip each exit arm onto it one at a time, oracle-proven, exactly as the S1 dispatch seam
//! flips planes onto the loop one at a time.
//!
//! ## Why the seam is stateless-by-argument, not stateful-by-field
//!
//! Each method takes its collaborators explicitly — the `Ledger` to move, the `UsageLedger` to
//! fold into, the neutral facts to build a row from. The pass-through holds no state, exactly as
//! the S1 `RegisteredUnits` seam takes `root: &ProductionUnits` rather than owning root state. A
//! plane composes over the book by reference and owns none of it; a book implementation that owned
//! the ledger would be a second place the books could move, which is the one thing the ledger
//! unit's take-by-value settlement exists to make impossible.
//!
//! ## The neutral facts are how a per-plane builder rides this seam without naming a plane
//!
//! A plane's own row builder (`busbar_llm::unit::meter::metering_row`, and its a2a/mcp twins)
//! reads plane-internal types — a `UsageSink`, a `Lane` — that the composition root cannot and must
//! not name (#77: money types carry no plugin/plane field). So the seam takes NEUTRAL facts:
//! [`MeteringFacts`] carries the two names a row is keyed by, the raw per-tier counts, and the two
//! request counters — the exact fields a plane already projects before it fills a [`MeteringRow`].
//! In the fold, each plane hands these facts to the one builder; today the builder reproduces the
//! plane's field mapping byte-for-byte, and the tests lock that it does.

use busbar_api::{AuditRecord, MeteringRow, UsageDelta, UsageLedger};
use busbar_caps::{Hold, LedgerToken, Posted, Usage};
use busbar_unit_ledger::settle::{Ledger, Settlement};
use busbar_unit_ledger::totals::{TotalsKey, WindowStart};

/// The raw per-tier counts a completed unit consumed, in the four reserved classes.
///
/// Named from the neutral reserved-unit spellings (`busbar_api::UNIT_*`), never a dialect's wire
/// field, because every plane's reader already normalizes onto them: `input` is UNCACHED input and
/// the two cache tiers are ADDITIVE, so the four partition what any provider reported.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MeterCounts {
    /// Uncached input tokens.
    pub input: u64,
    /// Output tokens.
    pub output: u64,
    /// Cache-read tokens.
    pub cache_read: u64,
    /// Cache-write (cache-creation) tokens.
    pub cache_write: u64,
}

/// Everything the seam needs to assemble one [`MeteringRow`] — the neutral projection a plane makes
/// before it fills the row today. No amount, no rate, no card: raw counts and the two names the row
/// is keyed by, exactly the shape #77 keeps free of any plane identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeteringFacts {
    /// The virtual key this usage is attributed to.
    pub key_id: String,
    /// The SERVING lane's configured model name — the accounting key rates are written against,
    /// after any failover; never the wire name a lane sent upstream.
    pub model: String,
    /// The serving lane's provider name.
    pub provider: String,
    /// The per-tier counts this response consumed.
    pub counts: MeterCounts,
    /// Admitted requests this row accumulates (never refunded).
    pub requests: u64,
    /// Billable requests (admitted minus non-2xx refunds) — the flat-fee base.
    pub billable_requests: u64,
    /// The key's group at the time of use, denormalized onto the row; empty = no group.
    pub key_group_at_use: String,
    /// The price table in force when the usage occurred; empty = not tracked.
    pub pricing_version: String,
}

/// Everything the seam needs to assemble one durable [`AuditRecord`]. Plain metadata, never a
/// secret: the hash chain is computed engine-side and rides through verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditFacts {
    /// Monotonic sequence number (1-based within a process lineage; continues across restart).
    pub seq: u64,
    /// Unix seconds the mutation was attempted.
    pub ts: u64,
    /// `noun.verb` action.
    pub action: String,
    /// The resource acted on. Never a secret.
    pub resource: String,
    /// Stable outcome token (`applied` | `rejected`).
    pub outcome: String,
    /// The authenticated principal id that attempted the mutation.
    pub principal: String,
    /// The preceding entry's `hash` (empty for the first entry of a lineage).
    pub prev_hash: String,
    /// The tamper-evidence digest over this entry's fields (computed + verified engine-side).
    pub hash: String,
}

/// The one act that closes a unit's money, as a trait — the shared surface the exit arms will
/// compose behind once the W3 fold gives it a `busbar-kernel-ledger` implementation.
///
/// Every method here has a byte-identical pass-through in [`PassThroughBook`]. Adding an arm to
/// this trait is adding an operation the fold must carry; nothing else in the tree should grow a
/// private notion of how the books move.
pub trait MoneyBook {
    /// Settle a hold against what the unit's usage priced at, moving the books and reporting the
    /// residual it released and the overdraft it noted. The hold is consumed. Pass-through:
    /// [`Ledger::settle_recording`].
    ///
    /// The eight arguments mirror `Ledger::settle_recording` arg-for-arg — the seam re-sources the
    /// implementation, it does not reshape the call — so it carries that method's own allow.
    #[allow(clippy::too_many_arguments)]
    fn settle(
        &self,
        ledger: &mut Ledger,
        key: &TotalsKey,
        window: WindowStart,
        hold: Hold,
        priced_nanos: u128,
        usage: &Usage,
        token: &LedgerToken,
    ) -> Settlement;

    /// Move the books for a posting the exit path already built (it owned the hold and consumed it
    /// there). The same act as [`MoneyBook::settle`] from the side that hands over a posting.
    /// Pass-through: [`Ledger::post`].
    fn post(
        &self,
        ledger: &mut Ledger,
        key: &TotalsKey,
        window: WindowStart,
        posted: Posted,
    ) -> Settlement;

    /// Fold a signed usage delta into the rate-limit ledger, flooring every counter at 0.
    /// Pass-through: [`UsageLedger::apply_delta`].
    fn apply_usage(&self, ledger: &mut UsageLedger, delta: &UsageDelta);

    /// Assemble the raw per-(key, model, provider) metering row from neutral facts — the terminal
    /// shape every per-plane `units_*` row builder produces, with no amount and no rate on it.
    fn metering_row(&self, facts: &MeteringFacts) -> MeteringRow;

    /// Assemble one durable audit record from neutral facts. A dumb envelope: the digest is
    /// computed engine-side and carried through verbatim.
    fn audit_record(&self, facts: &AuditFacts) -> AuditRecord;
}

/// The ONE implementation this wave ships: every method is the current crates' own code, reached
/// through the seam instead of by name. It holds no state and is a zero-sized value, so a caller
/// composes over it by reference and the seam adds nothing to any hot path.
///
/// It is DORMANT. The serving path still calls `Ledger::settle_recording`, `UsageLedger::apply_delta`
/// and the planes' own row builders directly; this type is constructed only by its own tests until a
/// later commit routes an exit arm through it. That is what keeps the money oracle byte-identical
/// while the seam exists.
#[derive(Debug, Clone, Copy, Default)]
pub struct PassThroughBook;

impl MoneyBook for PassThroughBook {
    #[allow(clippy::too_many_arguments)]
    fn settle(
        &self,
        ledger: &mut Ledger,
        key: &TotalsKey,
        window: WindowStart,
        hold: Hold,
        priced_nanos: u128,
        usage: &Usage,
        token: &LedgerToken,
    ) -> Settlement {
        ledger.settle_recording(key, window, hold, priced_nanos, usage, token)
    }

    fn post(
        &self,
        ledger: &mut Ledger,
        key: &TotalsKey,
        window: WindowStart,
        posted: Posted,
    ) -> Settlement {
        ledger.post(key, window, posted)
    }

    fn apply_usage(&self, ledger: &mut UsageLedger, delta: &UsageDelta) {
        ledger.apply_delta(delta);
    }

    fn metering_row(&self, facts: &MeteringFacts) -> MeteringRow {
        MeteringRow {
            key_id: facts.key_id.clone(),
            model: facts.model.clone(),
            provider: facts.provider.clone(),
            tokens_input: facts.counts.input,
            tokens_output: facts.counts.output,
            tokens_cache_read: facts.counts.cache_read,
            tokens_cache_write: facts.counts.cache_write,
            requests: facts.requests,
            billable_requests: facts.billable_requests,
            key_group_at_use: facts.key_group_at_use.clone(),
            pricing_version: facts.pricing_version.clone(),
        }
    }

    fn audit_record(&self, facts: &AuditFacts) -> AuditRecord {
        AuditRecord {
            seq: facts.seq,
            ts: facts.ts,
            action: facts.action.clone(),
            resource: facts.resource.clone(),
            outcome: facts.outcome.clone(),
            principal: facts.principal.clone(),
            prev_hash: facts.prev_hash.clone(),
            hash: facts.hash.clone(),
        }
    }
}

#[cfg(test)]
#[path = "tests/money_book.rs"]
mod tests;
