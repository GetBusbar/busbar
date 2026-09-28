// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR'S KERNEL-SIDE ACTS A PLANE ASKS FOR (#43/#71): a plane reports units and the kernel
//! holds and meters, so the hold a plane's admission carries is opened here, never in the plane.

use busbar_contract::caps::{Admission, Admittance, Grant, Hold, PrincipalId, ReasonCode, Refusal};

/// The admission of a unit the door admitted at zero: its own hold, reserving nothing, for this
/// principal, opened with the admittance grant the loop lent for this call.
pub fn admitted_at_zero(admit_token: &Grant<Admittance>, principal: PrincipalId) -> Admission {
    Admission::Own(Hold::open(admit_token, principal, 0))
}

/// THE NODE'S ONE UNIT-KEY ALLOCATOR, from 1. A unit's identity is the kernel's to mint: a plane
/// that needs a key for a table it keeps (a served session's open calls) takes it from here.
#[derive(Debug, Default)]
pub struct UnitKeyMint(std::sync::atomic::AtomicU64);

impl UnitKeyMint {
    /// The next key, unique on this node.
    pub fn mint(&self) -> busbar_contract::ids::UnitKey {
        let n = self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        busbar_contract::ids::UnitKey::new(n + 1)
    }
}

/// The door's admission answer, in the ADMIT step's terms: the verdict, whether the charge landed,
/// and the pool it landed on when a budget downgrade re-pooled it.
#[derive(Debug)]
pub struct AdmitVerdict {
    /// `Ok` when the door admitted the unit; the refusal when a budget in its chain had no headroom.
    pub verdict: Result<(), Refusal>,
    /// Whether the charge LANDED. An admission without a grant (governance off, no resolved key)
    /// charged nothing, so a non-2xx end must not refund it.
    pub charged: bool,
    /// `Some` when `on_exhaust: downgrade` re-pooled the admission onto this pool.
    pub effective_pool: Option<String>,
}

/// Read the door's admission outcome as the ADMIT step's verdict. `Ok` carries the grant (absent
/// when the door admitted without charging) and the downgrade pool; `Err` carries the refusal's
/// `Retry-After`, in whole seconds, as the door rendered it. A refusal here is always a budget in
/// the chain without headroom: the door refuses for no other reason.
pub fn admit_verdict(
    outcome: Result<(Option<&crate::plane_host::AdmitHandle>, Option<String>), Option<u32>>,
) -> AdmitVerdict {
    match outcome {
        Ok((grant, effective_pool)) => AdmitVerdict {
            verdict: Ok(()),
            charged: grant.is_some(),
            effective_pool,
        },
        Err(retry_after) => {
            let mut refusal = Refusal::new(ReasonCode::OverBudget);
            if let Some(secs) = retry_after {
                refusal = refusal.retry_after(secs);
            }
            AdmitVerdict {
                verdict: Err(refusal),
                charged: false,
                effective_pool: None,
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/door_tests.rs"]
mod door_tests;
