// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kernel-verb store face and the idempotency replay window.
//!
//! This is the ABI face the admin verb-execution unit (which owns the verb *semantics*) and a
//! loaded store's adapter in `busbar-plugin-loader` both bind to. It lives on the contract — the
//! ONE ABI crate, DECISIONS #38 — so the two sides reach one face here rather than naming each
//! other's crate (DECISIONS #40): the execution unit implements the verb over a `dyn Store`, the
//! plugin-loader adapter answers it, and neither depends on the other.
//!
//! The store seam here is the disaster-recovery primitives named in the architecture document's
//! irreducible set (`chain_break`, `store_restore`, `reseal_epoch_floor`), plus the store-backed
//! sealed idempotency cache the new credential-minting verbs use. Every method is a `// contract:`
//! seam: the actual durable operation is always the integrator's.

use crate::caps::{AdminVerb, Grant};

/// Replay window (seconds) — 600 s, exactly `IDEMPOTENCY_TTL_SECS` in 1.5.5/1.6.0-legacy admin.
///
/// The per-node, in-process idempotency-replay cache in the admin verb-execution unit ages its
/// slots against this window, and a loaded store's sealed replay cache answers for the same one, so
/// a deployment whose store predates the durable cache gets the same replay window either way.
pub const IDEMPOTENCY_TTL_SECS: u64 = 600;

/// A store-layer error. The admin verb-execution unit maps it the same fail-closed way it maps a
/// governance failure.
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
    /// irreducible-set posture rules.
    fn chain_break(&self, admin: &Grant<AdminVerb>) -> Result<(), StoreError>;

    /// `// contract:` restore the store from a named backup.
    fn store_restore(&self, admin: &Grant<AdminVerb>, backup_ref: &str) -> Result<(), StoreError>;

    /// `// contract:` reseal the epoch floor after a chain break or restore.
    fn reseal_epoch_floor(&self, admin: &Grant<AdminVerb>) -> Result<(), StoreError>;

    /// `// contract:` the store-backed sealed idempotency cache for the NEW credential-minting
    /// verbs (`set_operator_key`, `export_keyset`'s recipient-sealed export, and any future
    /// credential-minting new verb) — TTL `min(dispute_max_age, max(600s, longest finite cap
    /// window + max_unit_duration))`, per the architecture document. Returns the previously
    /// committed response bytes for a replay, or `None` on first sighting (in which case the
    /// integrator is expected to have already reserved the slot before this call returns,
    /// mirroring the in-process `IdempotencyCache`'s reservation discipline, but over durable
    /// storage instead of an in-process map).
    fn replay_new_verb(&self, key: &(String, String)) -> Result<Option<Vec<u8>>, StoreError>;

    /// `// contract:` commit a new-verb replay slot.
    fn commit_new_verb_replay(
        &self,
        key: &(String, String),
        response: &[u8],
    ) -> Result<(), StoreError>;
}
