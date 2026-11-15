// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::caps::PrincipalId;

pub fn principal() -> PrincipalId {
    PrincipalId::new("acct:battery")
}
