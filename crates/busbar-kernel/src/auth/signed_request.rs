// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One signed-verification occurrence, transported through its actual request to registration.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::governance::current_credential::VerifiedKeyAuthority;

struct Occurrence {
    authority: Arc<VerifiedKeyAuthority>,
    claimed: AtomicBool,
}

/// Clones carry the same take-once occurrence; a key or subject cannot construct this value.
#[derive(Clone)]
pub struct SignedRequestAuthority(Arc<Occurrence>);

impl SignedRequestAuthority {
    pub fn original_key(&self) -> &Arc<crate::governance::VirtualKey> {
        self.0.authority.original_key()
    }

    pub(super) fn verified(authority: VerifiedKeyAuthority) -> Self {
        Self(Arc::new(Occurrence {
            authority: Arc::new(authority),
            claimed: AtomicBool::new(false),
        }))
    }

    /// Called only while the actual new UnitRecord slot is vacant. Never attaches to an old unit.
    pub(crate) fn claim(&self) -> Option<Arc<VerifiedKeyAuthority>> {
        self.0
            .claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| self.0.authority.clone())
    }
}

impl std::fmt::Debug for SignedRequestAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedRequestAuthority")
            .finish_non_exhaustive()
    }
}

impl PartialEq for SignedRequestAuthority {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
