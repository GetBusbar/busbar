// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::caps::{Hold, PrincipalId};

pub struct TestDoor;

impl busbar_kernel::inflight::ArrivalDoor for TestDoor {
    fn arrival_hold(
        &self,
        principal: PrincipalId,
        token: &busbar_contract::caps::Grant<busbar_contract::caps::Admittance>,
    ) -> Hold {
        Hold::open(token, principal)
    }
}
