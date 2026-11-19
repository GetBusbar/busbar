// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The open vocabulary: the keys a plugin declares and the kernel dispatches on.

use core::fmt;

macro_rules! declare_id {
    ($($(#[$meta:meta])* $name:ident => $what:literal;)*) => {
        $(
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
        pub struct $name(&'static str);

        impl $name {
            #[doc = concat!("Name ", $what, ".")]
            #[must_use]
            pub const fn new(key: &'static str) -> Self {
                Self(key)
            }

            /// The declared name.
            #[must_use]
            pub const fn as_str(&self) -> &'static str {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.0)
            }
        }
        )*
    };
}

declare_id! {
    /// One class of operation a plane declares, priced through the lanes it permits.
    OpClassId => "an operation class";
    /// One read-only introspection verb a plane declares.
    AdminVerbId => "a plane admin verb";
    /// One claim a plane declares, named so policy can be written against it.
    ///
    /// The scope step's lookup key is the pair `(claim, operation class)`, so the claim needs a
    /// name of its own: without one a plane's operations can be declared but never scoped, because
    /// there is no way to say which of its claims a policy entry is about.
    ClaimKey => "a declared claim";
    /// One class of metered quantity.
    ///
    /// A meter class is the unit of both pricing and capping: the cap-dimension shape below is
    /// closed over an open key, so any declared class is cappable without a new variant.
    MeterClassId => "a meter class";
    /// One record schema a plane declares for its kernel-held durable records.
    RecordSchemaId => "a record schema";
    /// A transport's registry identity.
    ///
    /// This is a registry name and never key material; the opaque key handle is the only thing
    /// that carries a key.
    TransportId => "a transport";
    /// The priced axis: a config-declared name per plane and upstream.
    ///
    /// The type index calls the lane the rate card's first key. It is carried on a verified
    /// destination, located in the request by the admit facts, located in the response by the
    /// plane's own facts, and all three readings are compared through the lane-alias map.
    LaneId => "a lane";
    /// One credential scheme key.
    SchemeKey => "an auth scheme";
    /// One alternative a plane may narrow a claim's scheme to.
    SchemeAlt => "a declared scheme alternative";
}

/// A stream inside one connection.
///
/// One-shot transports use a single stream; multiplexed transports number theirs. The kernel keys
/// the open-unit slot on the session, the stream and the direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct StreamId(pub u64);

impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "stream {}", self.0)
    }
}

/// A session's identity, minted by the kernel at unit zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct SessionId(pub u64);

/// A unit's node-local identity, minted by the kernel when it builds the unit.
///
/// This is the key the in-flight table, the journal and every capability type name a unit by. It
/// lives here rather than in the capability crate because a unit is the contract's object: the
/// capability types are keyed on it, they do not own it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct UnitKey(u64);

impl UnitKey {
    /// Name a unit.
    #[must_use]
    pub const fn new(key: u64) -> Self {
        Self(key)
    }

    /// The key as the journal writes it.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for UnitKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unit {}", self.0)
    }
}

/// An upstream's index within one session.
///
/// Returned by the session plane when it opens an upstream. The crate-graph section bounds the
/// count per session; an index outside that range never reaches a verified destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct UpstreamIdx(pub u8);

/// Who a unit is for.
///
/// The auth kind resolves this; a plane never sees a credential and never mints a principal. The
/// anonymous principal is the kernel's own and has no bucket.
///
/// The name is shared text: it is made once, when the principal is named, and every copy of the
/// principal after that (the unit's hold, its records, its audit line) shares it.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct PrincipalId(crate::kept::Text);

impl PrincipalId {
    /// Name a principal: the one place its name is made.
    #[must_use]
    pub fn new(id: impl AsRef<str>) -> Self {
        Self(crate::kept::Text::from(std::sync::Arc::<str>::from(
            id.as_ref(),
        )))
    }

    /// The anonymous principal: the kernel's own, carried by a round that has established no
    #[must_use]
    pub fn anonymous() -> Self {
        Self(crate::kept::Text::fixed("anonymous"))
    }

    /// The identity as the audit row prints it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// The identity as shared text: a record that keeps the principal's name shares this one.
    #[must_use]
    pub fn text(&self) -> &crate::kept::Text {
        &self.0
    }
}

// Written by hand so it prints `PrincipalId("name")`, exactly as it did when it held a `String`.
impl fmt::Debug for PrincipalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PrincipalId")
            .field(&self.0.as_str())
            .finish()
    }
}

impl fmt::Display for PrincipalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.as_str())
    }
}

/// Which side of a meter class's bytes a quantity comes from.
///
/// The plugin-kinds table calls this the class family, and it says the rate card may price a class
/// but may never re-family it. The input-side families partition the same bytes; the kernel-side
/// families sit outside that partition and outside the response estimate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum ClassDirection {
    /// Sized from the ingress-derived estimate.
    Input,
    /// Sized from the response ceiling.
    Response,
    /// Ingress bytes served from an upstream cache.
    CacheRead,
    /// Ingress bytes written to an upstream cache.
    CacheWrite,
    /// Sized by the kernel's own rule, outside the ingress partition.
    Kernel,
}

/// How wide a bucket's cap reaches.
///
/// A scope-limited bucket draws only when its scope equals the effective pool name, and a draw on
/// a scope the unit did not route through is released at the routing step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum BucketScope {
    /// Every pool.
    All,
    /// One named pool, validated against the configured pools.
    Pool(&'static str),
}

/// One bucket in a principal's chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub struct BucketRef {
    /// The bucket's identity as the refusal text prints it.
    pub id: &'static str,
    /// How wide the bucket's cap reaches.
    pub scope: BucketScope,
    /// Whether the bucket caps anything at all; an uncapped bucket is an attribution bucket.
    pub capped: bool,
}

/// One class's share of a unit's estimate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ClassEstimate {
    /// The class being estimated.
    pub class: MeterClassId,
    /// The estimated quantity, in the class's own units.
    pub quantity: u64,
}

/// What the admission step sizes a hold against.
///
/// The estimate is per class. The whole ingress-derived figure is assigned to the single most
/// expensive class of the input partition and zero to the others, so the sum across classes here
/// equals the maximum the hold has to cover, and the metering step settles to the split the
/// upstream actually reported.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Estimate {
    /// One line per class the unit may consume.
    pub per_class: crate::bounded::BoundedVec<ClassEstimate, { crate::bounded::MAX_USAGE_LINES }>,
}
