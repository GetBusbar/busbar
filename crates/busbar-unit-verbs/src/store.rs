// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store seam — the ONE mutation seam the admin control surface reaches through.
//!
//! Three groups of method live here, and they are one trait on purpose:
//!
//! 1. The disaster-recovery primitives (`chain_break`, `store_restore`, `reseal_epoch_floor`).
//! 2. The store-backed sealed idempotency cache (distinct from
//!    [`crate::idempotency::IdempotencyCache`], which is the PER-NODE, in-process cache the two
//!    legacy replayable operations use).
//! 3. The 1.6.0 verbs whose effect MOVES something — money, policy or a plane record.
//!
//! ## Why the third group is here rather than beside the thing it moves
//!
//! Because the control surface must name exactly one seam and no domain type. A surface holding a
//! ledger handle beside its read-only view would have two ways to reach the books, and the
//! read-only one exists precisely to make the other impossible to acquire by accident. So the
//! effects arrive here, behind the trait the recovery verbs already use, and the surface names
//! `dyn Store` and nothing else — no ledger, no policy, no record store.
//!
//! ## Why they take and return opaque bytes
//!
//! This crate depends on `busbar-caps` and nothing else: it has no money type, no serializer and no
//! opinion about a currency. A method here that named an amount would be this crate acquiring one.
//! So a mutating verb takes the request bytes and answers with the response bytes, exactly as
//! [`crate::governance::Governance::execute_new_verb`] does, and what this crate contributes is
//! ADMISSION — scope, rate class, and the replay probe — which it can do without understanding a
//! single field of either.
//!
//! Every method is `// contract:`: the actual durable operation is always the integrator's.

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
    /// exists on a stopped node; this is the ADMIN-VERB path, admitted by the caller's scope.
    fn chain_break(&self, admin: &AdminToken) -> Result<(), StoreError>;

    /// `// contract:` restore the store from a named backup.
    fn store_restore(&self, admin: &AdminToken, backup_ref: &str) -> Result<(), StoreError>;

    /// `// contract:` reseal the epoch floor after a chain break or restore.
    fn reseal_epoch_floor(&self, admin: &AdminToken) -> Result<(), StoreError>;

    /// `// contract:` post a correcting entry against one balance — the `adjust` verb.
    ///
    /// `request` is the verb's request body and the answer is the verb's response body, both
    /// opaque here for the reason the module doc gives. The integrator moves the row and renders
    /// the figure; this crate has already decided the call may happen at all.
    ///
    /// The default REFUSES rather than succeeding silently. An integrator that has not bound a
    /// ledger cannot adjust one, and a default that answered `Ok` would report a correction that
    /// never landed — the one failure mode a money verb must not have. It is also what keeps this
    /// addition additive: every existing implementor compiles unchanged and refuses, which is true
    /// of it.
    fn adjust(&self, admin: &AdminToken, request: &[u8]) -> Result<Vec<u8>, StoreError> {
        let _ = (admin, request);
        Err(StoreError::Failed)
    }

    /// `// contract:` resolve an unreconciled slice — the `resolve_slice` verb. Same shape, same
    /// refusing default, and for the same reason.
    fn resolve_slice(&self, admin: &AdminToken, request: &[u8]) -> Result<Vec<u8>, StoreError> {
        let _ = (admin, request);
        Err(StoreError::Failed)
    }

    /// `// contract:` decide an open dispute — the `resolve_dispute` verb. Same shape, same
    /// refusing default, and for the same reason.
    fn resolve_dispute(&self, admin: &AdminToken, request: &[u8]) -> Result<Vec<u8>, StoreError> {
        let _ = (admin, request);
        Err(StoreError::Failed)
    }

    /// `// contract:` the store-backed sealed idempotency cache for the mutating new verbs —
    /// TTL 600 s flat, per the owner's ruling. Returns the previously
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
