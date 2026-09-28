// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR'S KERNEL-SIDE ACTS A PLANE ASKS FOR (#43/#71): a plane reports units and the kernel
//! holds and meters, so the hold a plane's admission carries is opened here, never in the plane.

use busbar_contract::caps::{Admission, Admittance, Grant, Hold, PrincipalId};

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
