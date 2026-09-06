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
    /// THIS COMPOSITION HAS NO STORE. Not a failure: a node whose integrator wired no store has
    /// nothing that could have succeeded, and there is no retry that would change it.
    ///
    /// A separate variant because [`StoreError::Failed`] is a promise of the opposite — that the
    /// store exists and did not answer — and it is served as unavailability, which tells an operator
    /// to retry and to page somebody. An operator running a disaster-recovery ceremony against a
    /// node that has no store would follow that advice forever. What is true is that the operation
    /// is not available HERE, which is what the irreducible set's other path — the off-node CLI on a
    /// stopped node — exists for.
    Unconfigured,
}

impl StoreError {
    /// The refusal a store failure becomes, mapped the same fail-closed way
    /// [`crate::governance::GovernanceError::into_refusal`] maps a governance failure.
    pub fn into_refusal(self) -> Refusal {
        let reason = match self {
            // An absent store and an absent row are one answer to a caller: there is nothing here.
            // The DIFFERENCE between them is a fact about the deployment rather than about the
            // request, and a caller cannot act on it either way.
            StoreError::NotFound | StoreError::Unconfigured => ReasonCode::NotFound,
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
    /// credential-minting new verb) — TTL `min(dispute_max_age, max(600s, longest finite cap
    /// window + max_unit_duration))`, per the architecture document. Returns the previously
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
