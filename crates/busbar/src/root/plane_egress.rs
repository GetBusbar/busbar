// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OUTBOUND HALF OF THE ROOT'S CONNECTOR (`BUSBAR-1.6.0.md` Part 3, section 12 "The route
//! pump"): what a plane instance's egress walk dials through. The kernel's `plane_driver::Egress`
//! takes a connection table by the contract's `PollConns`; the root hands it the process's one
//! Connector (`crate::root::connector`) and declares each plane instance's outbound needs on it.

use std::sync::Arc;

use busbar_contract::conn::{InstanceId, NeedId, PollConns};

/// The connection table every plane instance's egress dials through: the process's one Connector.
#[must_use]
pub fn conns() -> Arc<dyn PollConns> {
    Arc::clone(crate::root::connector::the()) as Arc<dyn PollConns>
}

/// Declare `caller`'s outbound `needs` (need, transport scheme) on the one Connector: the only
/// needs its egress may open.
pub fn declare(caller: InstanceId, needs: &[(NeedId, &str)]) {
    let connector = crate::root::connector::the();
    for (need, scheme) in needs {
        connector.declare_over(caller, *need, scheme);
    }
}
