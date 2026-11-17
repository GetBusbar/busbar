// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Original native fee debt receipt (FEE-DEBT r1, d0c0f410). The existing budget flusher is the
//! only executor; this module holds its private capture evidence and the nonparticipating
//! observer a native ordinary admission funds before its first charge.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, Weak};

/// Per-GovState producer identity. Cell incarnations are minted here, never accepted from callers.
#[derive(Default)]
pub(crate) struct FeeDebtProducer {
    identity: Arc<()>,
    incarnations: AtomicU64,
    association: OnceLock<Weak<dyn FeeDebtAssociate>>,
}

impl FeeDebtProducer {
    /// A distinct nonzero incarnation for one installed cell; exhaustion refuses.
    pub(crate) fn next_incarnation(&self) -> Option<u64> {
        self.incarnations
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .ok()?
            .checked_add(1)
    }

    pub(crate) fn identity(&self) -> &Arc<()> {
        &self.identity
    }
}

/// The trusted original observer owner (the Node terminal book), bound once at assembly.
pub trait FeeDebtAssociate: Send + Sync {}
