// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store seam: the disaster-recovery primitives named in the architecture document's
//! irreducible set (`chain_break`, `store_restore`, `reseal_epoch_floor`), plus the store-backed
//! sealed idempotency cache the new credential-minting verbs use (distinct from
//! [`crate::idempotency::IdempotencyCache`], which is the PER-NODE, in-process cache the two legacy
//! replayable operations use — see the architecture document's holds/keys/recovery section: "the
//! new credential-minting verbs use the store-backed sealed cache").
//!
//! Every method here is `// contract:` — this crate has no store dependency of its own (it depends
//! on `busbar-caps` only), so the actual durable operation is always the integrator's.

use busbar_caps::AdminToken;

use crate::refusal::{ReasonCode, Refusal, RefusalStep};

/// A store-layer error. Mapped the same fail-closed way [`crate::governance::GovernanceError`] is.
#[derive(Debug)]
pub enum StoreError {
    /// The named resource does not exist.
    NotFound,
    /// The underlying store failed; details are for the integrator's own logs only.
    Failed,
}

impl StoreError {
    /// The refusal a store failure becomes, mapped the same fail-closed way
    /// [`crate::governance::GovernanceError::into_refusal`] maps a governance failure.
    pub fn into_refusal(self) -> Refusal {
        let reason = match self {
            StoreError::NotFound => ReasonCode::NotFound,
            StoreError::Failed => ReasonCode::StoreError,
        };
        Refusal::new(RefusalStep::Verify, reason)
    }
}

/// The store seam.
pub trait Store {
    /// `// contract:` deliberately break the journal chain (disaster recovery). Off-node CLI also
    /// exists on a stopped node; this is the ADMIN-VERB path, admitted only under the
    /// irreducible-set rules in `crate::posture`.
    fn chain_break(&self, admin: &AdminToken) -> Result<(), StoreError>;

    /// `// contract:` restore the store from a named backup.
    fn store_restore(&self, admin: &AdminToken, backup_ref: &str) -> Result<(), StoreError>;

    /// `// contract:` reseal the epoch floor after a chain break or restore.
    fn reseal_epoch_floor(&self, admin: &AdminToken) -> Result<(), StoreError>;

    /// `// contract:` the store-backed sealed idempotency cache for the NEW credential-minting
    /// verbs (`set_operator_key`, `export_keyset`'s recipient-sealed export, and any future
    /// credential-minting new verb) — TTL `max(600s, longest finite cap window +
    /// max_unit_duration)`, per the architecture document. (The `dispute_max_age` clamp the earlier
    /// formula carried went with the dispute verbs: nothing here holds a dispute open, so nothing
    /// here has a dispute's age to bound a replay slot by.) Returns the previously
    /// committed response bytes for a replay, or `None` on first sighting (in which case the
    /// integrator is expected to have already reserved the slot before this call returns,
    /// mirroring [`crate::idempotency::IdempotencyCache`]'s reservation discipline, but over
    /// durable storage instead of an in-process map).
    fn replay_new_verb(&self, key: &(String, String)) -> Result<Option<Vec<u8>>, StoreError>;

    /// `// contract:` commit a new-verb replay slot.
    fn commit_new_verb_replay(
        &self,
        key: &(String, String),
        response: &[u8],
    ) -> Result<(), StoreError>;
}

/// WHO PUT A ROW IN THE RATE HISTORY.
///
/// A back-dated row re-prices work already done, so a row records the act that produced it. This is
/// provenance, not policy: nothing in a lookup reads it, and nothing here decides anything by it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateRowAuthor {
    /// Derived from the deployment's rate card, at boot or at a config apply.
    Config {
        /// The policy epoch the config was applied under.
        policy_epoch: u64,
    },
    /// Appended by the signed `amend_rate_history` admin verb.
    Amend {
        /// The fingerprint of the operator key that signed the amendment.
        operator_fingerprint: String,
        /// A digest of the operator's stated reason.
        reason_hash: [u8; 32],
    },
}

/// ONE DATED RATE ROW: what one unit of one class costs on one lane, from one instant onward.
///
/// There is no `effective_until`, and its absence is the model. A row runs until a later row for the
/// same cell supersedes it; an end date stored on a row would be a second place for the same fact to
/// live, and two places for one fact is two answers waiting to disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatedRateRow {
    /// The lane the traffic is served on — the history's key for a destination.
    pub lane: String,
    /// The declared meter class the quantity belongs to, in the config/wire spelling.
    pub class: String,
    /// The ISO-4217 code this row prices in. Rows in different currencies are different rows: there
    /// is no pivot and no cross-rate anywhere on this seam.
    pub currency: [u8; 3],
    /// The price of ONE unit of the class, in nano-units of the currency's minor unit. An integer,
    /// so no decimal touches money after the single conversion at the config boundary.
    pub nanos_per_unit: u64,
    /// The first instant this row answers for, inclusive, in wall-clock milliseconds. It MAY be in
    /// the past: that is a retroactive reprice, and it costs nothing to allow because price is never
    /// stored — every read derives money afresh from the rows in force.
    pub effective_from: u64,
    /// Who added the row.
    pub author: RateRowAuthor,
}

/// The sequence number the history files a row under — what a caller records to say which row it
/// added, and the tie-break when two rows share an `effective_from`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RateRowSeq(pub u64);

/// THE RATE-HISTORY SEAM — `amend_rate_history`'s whole effect, and the only money verb.
///
/// Its own trait rather than a method on [`Store`], because the rate history is not the record store
/// and an implementor of one is under no obligation to be an implementor of the other. Adding a
/// method to [`Store`] would have made every existing binding of that trait a compile error for a
/// fact it does not hold.
///
/// **This is a SEAM STANDING IN FOR A TYPE THAT IS NOT ON THE TREE YET.** The rate table itself is
/// the money work's — `RateTable`/`RateRow`/`RowAuthor`/`RowSeq` in the cost unit — and
/// [`DatedRateRow`], [`RateRowAuthor`] and [`RateRowSeq`] above are field-for-field the shapes it
/// defines, down to the `Config`/`Amend` split on the author, so binding this trait to that table's
/// one mutator is a move rather than a translation. When that type lands, this seam is the single
/// place the integrator points at it.
pub trait RateHistory {
    /// `// contract:` ADD A DATED ROW to the rate history.
    ///
    /// The only mutator, and ADD-ONLY: no row is ever edited and no row is ever removed. That is
    /// what makes the history an audit trail rather than a current price list, and it is why this
    /// verb is not a correction — an appended row is visible, dated, attributed and superseded, so
    /// what it did can always be read back, which is not true of anything that moved a posted
    /// figure.
    ///
    /// Returns the sequence number the history filed the row under. This is the ADMIN-VERB path,
    /// admitted only under the irreducible-set rules in [`crate::posture`].
    fn amend_rate_history(
        &self,
        admin: &AdminToken,
        row: &DatedRateRow,
    ) -> Result<RateRowSeq, StoreError>;
}

#[cfg(test)]
#[path = "tests/store_tests.rs"]
mod tests;
