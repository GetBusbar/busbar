// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUTH POINTS: the one vocabulary a transport and an auth meet on (THE DESIGN, "Auth
//! points and guest lists", step 1). A transport never names an auth and an auth never names a
//! transport: a transport declares the points it offers, an auth style declares the points it
//! needs, and the host calls the auth at each point through its handle. Defined here, once;
//! `abi::transport` re-exports it and never redefines it. Only the owner and the ARCHITECT add a
//! point, and a new point changes the auth and transport kind ABIs.
//!
//! | point | the transport calls | the auth sees |
//! |---|---|---|
//! | [`AuthPoint::Peer`] | once per connection, at connect or spawn | peer facts |
//! | [`AuthPoint::Head`] | once per request, when the head is final | method, target, authority, field lines |
//! | [`AuthPoint::HeadBody`] | once per request, with the whole body held (bounded) | the head and the body |
//! | [`AuthPoint::Frame`] | reserved: named, not built until a style needs it | — |
//!
//! Points are ordered `Peer` < `Head` < `HeadBody`. `HeadBody` includes the head, so a set never
//! holds both ([`super::check_points`]).

/// [`AuthPoints`] bit of [`AuthPoint::Peer`].
pub const POINT_PEER: u32 = 1;
/// [`AuthPoints`] bit of [`AuthPoint::Head`].
pub const POINT_HEAD: u32 = 2;
/// [`AuthPoints`] bit of [`AuthPoint::HeadBody`].
pub const POINT_HEAD_BODY: u32 = 4;
/// [`AuthPoints`] bit of [`AuthPoint::Frame`]: RESERVED. No set may hold it yet
/// ([`super::check_points`] refuses it).
pub const POINT_FRAME: u32 = 8;

/// One auth point. Its value is its [`AuthPoints`] bit, so the order is the design's:
/// `Peer` < `Head` < `HeadBody`.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuthPoint {
    /// Once per connection, at connect or spawn: the peer facts (the TLS peer certificate from the
    /// connector, a spawn environment).
    Peer = POINT_PEER,
    /// Once per request, when the head is final: method, target, authority and field lines.
    Head = POINT_HEAD,
    /// Once per request, with the whole body held (bounded by the size gate): the head and the
    /// body.
    HeadBody = POINT_HEAD_BODY,
    /// Reserved: named, not built until a style needs it.
    Frame = POINT_FRAME,
}

impl AuthPoint {
    /// The point a single bit names; `None` for any other value (no bit, several bits, an unknown
    /// bit). [`AuthPoint::Frame`] is named, so its bit answers it.
    #[must_use]
    pub const fn from_bit(bit: u32) -> Option<Self> {
        match bit {
            POINT_PEER => Some(Self::Peer),
            POINT_HEAD => Some(Self::Head),
            POINT_HEAD_BODY => Some(Self::HeadBody),
            POINT_FRAME => Some(Self::Frame),
            _ => None,
        }
    }

    /// The point's [`AuthPoints`] bit.
    #[must_use]
    pub const fn bit(self) -> u32 {
        self as u32
    }
}

/// A set of auth points, as a style or a transport declares it: [`POINT_PEER`] |
/// [`POINT_HEAD`] | [`POINT_HEAD_BODY`]. A set read off the ABI is judged by
/// [`super::check_points`] before any use.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct AuthPoints(pub u32);

impl AuthPoints {
    /// No point.
    pub const EMPTY: Self = Self(0);
    /// `{Peer}`.
    pub const PEER: Self = Self(POINT_PEER);
    /// `{Head}`.
    pub const HEAD: Self = Self(POINT_HEAD);
    /// `{HeadBody}`.
    pub const HEAD_BODY: Self = Self(POINT_HEAD_BODY);

    /// The bits.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Whether the set holds `point`.
    #[must_use]
    pub const fn has(self, point: AuthPoint) -> bool {
        self.0 & point.bit() != 0
    }

    /// Whether the set is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}
