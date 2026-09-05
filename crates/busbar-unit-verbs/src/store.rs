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

/// A store-layer error. Mapped the same fail-closed way [`crate::governance::GovernanceError`] is.
#[derive(Debug)]
pub enum StoreError {
    /// The named resource does not exist.
    NotFound,
    /// The underlying store failed; details are for the integrator's own logs only.
    Failed,
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
