// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The capabilities on the way out: the sealed destination and the handle that stands for key
//! material.
//!
//! The secret placeholder ([`SecretSlot`](crate::SecretSlot)) and the one-shot secret placeholder
//! ([`SecretOnce`](crate::SecretOnce)) live in the destination module (`dest.rs`).

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
    // contract: the destination KIND (upstream, session upstream, client, kernel verb, nested
    // plane, plane record, peer, upgrade) lands here when the contract crate's DestinationFacts
    // exists; the lane is what the money side needs and is enough to seal against today.
}

impl VerifiedDestination {
    /// Seal a destination. Only the trust unit can, and only after its per-kind rule passed.
    ///
    /// The lane is named, not spelled: a configured lane's name is a runtime string and
    /// [`LaneId`] is a borrowed static one, so the name comes from the composition root's
    /// registration interner (the kernel's `Registration::lane`) rather than from a literal
    /// at the sealing site. That is what lets a deployment's own lanes be sealed at all, and it is
    /// why this signature does not take a `String`: a lane id minted per unit would be a leak per
    /// request, which is the one thing the interning rule exists to forbid.
    pub fn seal(_token: &Grant<Dial>, lane: LaneId) -> Self {
        VerifiedDestination { lane }
    }

    /// The priced axis this destination sits on.
    pub fn lane(&self) -> &LaneId {
        &self.lane
    }
}

/// The handle that stands for resolved transport key material.
///
/// Defined once, in `busbar-contract`, because the transports and the egress unit consume it and
/// may not name this crate; re-exported here because the transport-key unit that builds it is lent
/// its [`Grant`](crate::caps::Grant)`<KeyHandle>` by the loop. `TransportKeyHandle::issue` takes that grant, so this is
/// one type with one constructor rather than two types that nothing bridges.
pub use crate::TransportKeyHandle;
