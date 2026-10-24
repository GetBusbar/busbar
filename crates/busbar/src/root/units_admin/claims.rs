// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE ADMIN IDEMPOTENCY CACHE'S CLAIMS, ON THE NODE'S ONE JOURNAL** (item 271's writer side).

use std::sync::{Arc, Mutex};

use busbar_contract::caps::{DurableWrite, Grant, StepName};
use busbar_kernel_ledger::totals::{BucketId, BucketScope, CapDimension, TotalsKey};

use crate::root::durability::{Durability, PostingStamp, Settling};

/// The bucket every admin idempotency claim is journalled on: reserved away from every metering
/// balance, so a claim can never be mistaken for, or matched against, a real hold.
pub const ADMIN_CLAIM_BUCKET: &str = "admin-idempotency";

/// Adapts the node's one journal to [`busbar_core_admin::idempotency::ClaimJournal`]: a claim the
/// admin idempotency cache takes is journalled through [`Durability::journal_claim`], on
/// [`ADMIN_CLAIM_BUCKET`] scoped per actor, window `u64::MAX` (never a `budget_window` result).
///
/// An admin mint or rotate never opens a hold behind its claim, so the boot's recovery finds every
/// one of these unheld and voids it: the same fact the in-process cache already states by starting
/// empty on every restart. It changes nothing a client sees; it makes the chain say what was
/// already true.
pub struct RootClaimJournal {
    book: Arc<Mutex<Durability>>,
    token: Grant<DurableWrite>,
}

impl std::fmt::Debug for RootClaimJournal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RootClaimJournal").finish_non_exhaustive()
    }
}

impl RootClaimJournal {
    /// The adapter over `book`, appending under `token`.
    #[must_use]
    pub fn new(book: Arc<Mutex<Durability>>, token: Grant<DurableWrite>) -> Self {
        RootClaimJournal { book, token }
    }
}

impl busbar_core_admin::idempotency::ClaimJournal for RootClaimJournal {
    fn journal_claim(&self, key: &(String, String), now: u64) {
        let totals_key = TotalsKey::new(
            BucketId::new(ADMIN_CLAIM_BUCKET),
            CapDimension::Requests,
            BucketScope::Pool(key.0.clone()),
        );
        let at = Settling {
            key: &totals_key,
            window: u64::MAX,
            durability: &self.token,
            step: StepName::Route,
            stamp: PostingStamp {
                rate_card_version: 0,
                wall: now,
                mono: now,
            },
        };
        let claim = format!("{}:{}", key.0, key.1);
        let mut durability = self.book.lock().unwrap_or_else(|p| p.into_inner());
        // A durability loss here is retained and re-offered by the log like any other append (see
        // `Durability::journal_claim`); it is never a refusal of the mint or rotate that took the
        // claim, exactly as `journal_dispatch`'s failure is never a refusal of the dispatch.
        let _ = durability.journal_claim(&at, &claim);
    }
}
