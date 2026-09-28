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
