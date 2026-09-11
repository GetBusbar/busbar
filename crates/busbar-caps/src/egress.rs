// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The capabilities on the way out: the sealed destination, the decoration that authenticates an
//! outbound request, the handle that stands for key material, and the one-shot secret placeholder.
//!
//! Everything here has the same shape as everything else in the crate — a private constructor and a
//! token that opens it — but these four are the ones that touch secrets, so their `Debug` output
//! never shows what they carry.

use crate::step::{LaneId, MeterClassId, UnitKey};
use crate::token::{AdminToken, EgressAuthToken};

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
    /// registration interner ([`busbar_contract::Registration::lane`]) rather than from a literal
    /// at the sealing site. That is what lets a deployment's own lanes be sealed at all, and it is
    /// why this signature does not take a `String`: a lane id minted per unit would be a leak per
    /// request, which is the one thing the interning rule exists to forbid.
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

/// The handle that stands for resolved transport key material.
///
/// Defined once, in `busbar-contract`, because the transports and the egress unit consume it and
/// may not name this crate; re-exported here because the transport-key unit that builds it is lent
/// its [`crate::TransportKeyToken`] by the loop. `TransportKeyHandle::issue` takes that token, so this is
/// one type with one constructor rather than two types that nothing bridges.
pub use busbar_contract::TransportKeyHandle;

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

/// WHICH BODY, AND NEVER THE BODY: the id one routed answer's stream is held under.
///
/// A lease number and nothing else. The same shape as the key handle above and for the same
/// reason: a value that names a resource is a value a log line, a fact map or a journal record can
/// carry without carrying what it names. The bytes stay where the transport put them — the
/// connection's own slab and the spill buffer — and the per-unit arena, which is 4 KiB and is the
/// one resource handle a plugin is given, never sees them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BodyLease(u64);

impl BodyLease {
    /// Name one body stream.
    #[must_use]
    pub const fn new(id: u64) -> Self {
        BodyLease(id)
    }

    /// The lease number, as the record and the audit row carry it.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// ONE DIMENSION OF WHAT A FINISHED BODY CARRIED, against a class the plane declared.
///
/// The tariff's `units` noun and not an amount. A quantity against a declared key travels; what a
/// quantity is worth is the cost unit's answer and is not said here, which is what keeps a plane
/// out of the pricing it is measured by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompletedUnits {
    /// Which declared class the quantity is in.
    pub class: MeterClassId,
    /// How many of the class's own units the body carried.
    pub units: u64,
}

/// WHAT THE BODY CARRIED ONCE IT FINISHED, per dimension the plane declared.
///
/// Read by the Meter step off the hold below, so no plane re-derives a count the stream already
/// produced: the figure the meter reports is the figure the relay counted while it ran, and there
/// is no second reading of the same body for the two to disagree about.
///
/// Bounded by [`MAX_USAGE_LINES`](crate::MAX_USAGE_LINES), because the report this feeds is.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Completion {
    frames: u64,
    bytes: u64,
    dimensions: Vec<CompletedUnits>,
}

impl Completion {
    /// What one finished body carried.
    ///
    /// # Errors
    /// [`UsageError::TooManyLines`](crate::UsageError) when the plane declared more dimensions than
    /// the fixed-size usage record can settle.
    pub fn of(
        frames: u64,
        bytes: u64,
        dimensions: Vec<CompletedUnits>,
    ) -> Result<Self, crate::UsageError> {
        if dimensions.len() > crate::MAX_USAGE_LINES {
            return Err(crate::UsageError::TooManyLines);
        }
        Ok(Completion {
            frames,
            bytes,
            dimensions,
        })
    }

    /// How many frames of the answer went by.
    #[must_use]
    pub fn frames(&self) -> u64 {
        self.frames
    }

    /// How many bytes of it did.
    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Every dimension the plane declared, as the relay counted it.
    #[must_use]
    pub fn dimensions(&self) -> &[CompletedUnits] {
        &self.dimensions
    }

    /// How many units one declared class carried, where the body carried that class at all.
    #[must_use]
    pub fn units(&self, class: MeterClassId) -> Option<u64> {
        self.dimensions
            .iter()
            .find(|d| d.class == class)
            .map(|d| d.units)
    }
}
