// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The capabilities on the way out: the sealed destination and the handle that stands for key

use crate::caps::capability::Dial;
use crate::caps::step::LaneId;
use crate::caps::token::Grant;

/// A destination the trust unit judged and sealed.
///
/// Sealing is what makes it a capability: the egress unit will dial what this says and nothing
/// else, and after the outbound request is decorated the lane is checked again against this value,
/// so a decoration cannot quietly move the unit to a cheaper or a different lane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDestination {
    lane: LaneId,
}

impl VerifiedDestination {
    /// Seal a destination. Only the trust unit can, and only after its per-kind rule passed.

    pub fn seal(_token: &Grant<Dial>, lane: LaneId) -> Self {
        VerifiedDestination { lane }
    }

    /// The priced axis this destination sits on.
    pub fn lane(&self) -> &LaneId {
        &self.lane
    }
}

/// The handle that stands for resolved transport key material.
pub use crate::TransportKeyHandle;
