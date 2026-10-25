// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kernel-verb store face and the idempotency replay window.
//!
//! This is the ABI face the admin verb-execution unit (which owns the verb *semantics*) and a
//! loaded store's adapter both bind to. It lives on the contract — the ONE ABI crate, DECISIONS
//! #38 — so the two sides reach one face here rather than naming each other's crate (DECISIONS
//! #40): the execution unit implements the verb over a `dyn Store`, the loaded store's adapter
//! answers it, and neither depends on the other.
//!
//! The store seam here is the disaster-recovery primitives named in the architecture document's
//! irreducible set (`chain_break`, `store_restore`). Every method is a
//! `// contract:` seam: the actual durable operation is always the integrator's.

use crate::caps::{AdminVerb, Grant};

/// Replay window (seconds) — 600 s, exactly `IDEMPOTENCY_TTL_SECS` in 1.5.5/1.6.0-legacy admin.
///
/// The admin idempotency-replay cache ages its slots against this window, and an `Idempotency-Key`
/// claimed in the configured store lapses with it.
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

    /// `// contract:` restore the store from a named backup. An integrator whose store has no restore
    /// operation answers [`StoreError::Failed`] and restores nothing; it never acknowledges a restore
    /// that did not happen.
    fn store_restore(&self, admin: &Grant<AdminVerb>, backup_ref: &str) -> Result<(), StoreError>;
}
