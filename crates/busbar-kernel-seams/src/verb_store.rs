// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kernel-verb store face and the idempotency replay window.

use busbar_contract::caps::{AdminVerb, Grant};

/// Replay window (seconds) — 600 s, exactly `IDEMPOTENCY_TTL_SECS` in 1.5.5/1.6.0-legacy admin.
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
    fn chain_break(&self, admin: &Grant<AdminVerb>) -> Result<(), StoreError>;

    /// `// contract:` restore the store from a named backup. An integrator whose store has no restore
    fn store_restore(&self, admin: &Grant<AdminVerb>, backup_ref: &str) -> Result<(), StoreError>;
}
