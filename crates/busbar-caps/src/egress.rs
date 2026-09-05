// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The capabilities on the way out: the sealed destination, the decoration that authenticates an
//! outbound request, the handle that stands for key material, and the one-shot secret placeholder.
//!
//! Everything here has the same shape as everything else in the crate — a private constructor and a
//! token that opens it — but these four are the ones that touch secrets, so their `Debug` output
//! never shows what they carry.

use crate::step::{LaneId, UnitKey};
use crate::token::{AdminToken, EgressAuthToken, TransportKeyToken};

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
    pub fn seal(_token: &crate::token::TrustToken, lane: LaneId) -> Self {
        VerifiedDestination { lane }
    }

    /// The priced axis this destination sits on.
    pub fn lane(&self) -> &LaneId {
        &self.lane
    }
}

/// A place in an outbound request where a secret has to be substituted.
///
/// The slot names the location; it never carries the secret. The egress-auth unit substitutes every
/// slot itself, which is why the secret never exists anywhere a plane could see it.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretSlot {
    location: String,
}

impl SecretSlot {
    /// Declare a slot. Egress-auth unit only.
    pub fn declare(_token: &EgressAuthToken, location: impl Into<String>) -> Self {
        SecretSlot {
            location: location.into(),
        }
    }

    /// Where the substitution happens.
    pub fn location(&self) -> &str {
        &self.location
    }
}

impl std::fmt::Debug for SecretSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretSlot")
            .field("location", &self.location)
            .finish()
    }
}

/// How an outbound request is authenticated.
///
/// Either the request is decorated in place — envelope fields from a closed allow-list, an optional
/// body signature, and the slots to substitute — or the scheme needs a handshake of its own, in
/// which case the decoration says how many frames and bytes it may take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthDecoration {
    /// Decorate the request in place.
    Decorate {
        /// The envelope fields to set. Never a field the lane locator reads.
        fields: Vec<(String, String)>,
        /// Whether the body is signed.
        body_signature: bool,
        /// The secret slots the egress-auth unit will substitute.
        slots: Vec<SecretSlot>,
    },
    /// Run a bounded handshake before the request goes.
    Handshake {
        /// The most frames the handshake may take.
        max_frames: u32,
        /// The most bytes it may take.
        max_bytes: u32,
    },
}

impl AuthDecoration {
    /// Build a decoration. Egress-auth unit only.
    pub fn decorate(
        _token: &EgressAuthToken,
        fields: Vec<(String, String)>,
        body_signature: bool,
        slots: Vec<SecretSlot>,
    ) -> Self {
        AuthDecoration::Decorate {
            fields,
            body_signature,
            slots,
        }
    }

    /// Build a handshake decoration. Egress-auth unit only.
    pub fn handshake(_token: &EgressAuthToken, max_frames: u32, max_bytes: u32) -> Self {
        AuthDecoration::Handshake {
            max_frames,
            max_bytes,
        }
    }
}

/// An opaque stand-in for resolved transport key material.
///
/// It is a registry handle and never the key itself: the transport-key unit resolves the secret,
/// keeps it, and hands out one of these. Nothing downstream can turn a handle back into bytes, and
/// its `Debug` says so.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct TransportKeyHandle {
    id: u64,
}

impl TransportKeyHandle {
    /// Hand out a handle for a resolved key. Transport-key unit only.
    pub fn issue(_token: &TransportKeyToken, id: u64) -> Self {
        TransportKeyHandle { id }
    }

    /// The registry id the handle stands for. Not key material.
    pub fn id(&self) -> u64 {
        self.id
    }
}

impl std::fmt::Debug for TransportKeyHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TransportKeyHandle(#{} <no material>)", self.id)
    }
}

/// A minted secret that may appear exactly once, at one declared place, in one unit.
///
/// The nonce is bound to the unit that minted it and to the location it is allowed to appear at. If
/// the encoded bytes do not contain it exactly once at that location, the unit fails and the mint
/// is reversed — which is the whole point: a credential-minting verb cannot leak its output into a
/// log, a fact, or a second copy of the response.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretOnce {
    nonce: u128,
    unit: UnitKey,
    target: String,
}

impl SecretOnce {
    /// Mint the placeholder. Verbs unit only.
    pub fn mint(
        _token: &AdminToken,
        nonce: u128,
        unit: UnitKey,
        target: impl Into<String>,
    ) -> Self {
        SecretOnce {
            nonce,
            unit,
            target: target.into(),
        }
    }

    /// The unit the placeholder is bound to.
    pub fn unit(&self) -> UnitKey {
        self.unit
    }

    /// The one location it may appear at.
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Whether a nonce seen in the encoded bytes is this one.
    pub fn matches(&self, nonce: u128) -> bool {
        self.nonce == nonce
    }
}

impl std::fmt::Debug for SecretOnce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretOnce")
            .field("unit", &self.unit)
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}
