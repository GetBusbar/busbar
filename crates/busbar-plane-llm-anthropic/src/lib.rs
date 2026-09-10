//! The `anthropic` dialect of the `llm` plane — one wire vocabulary, and nothing else.
//!
//! ## What a dialect crate is
//!
//! A DECLARATION and a DELEGATION, in that order of importance.
//!
//! The declaration is the whole point: the ladder rungs that say which arriving bytes are this
//! vendor's, the row that says where it keeps the model, the client's response ceiling and the
//! four metered quantities, the credential its clients present and the egress scheme its upstreams
//! expect. All of it is a constant, all of it is read once at registration, and none of it is
//! spelled anywhere in `busbar-plane-llm`.
//!
//! The delegation is four lines each. The translation is the PLANE'S, reached with this crate's own
//! row as the argument, so there is no second copy of the wire format here to drift from the first.
//!
//! ## What this crate is the first to do
//!
//! It is detected by HEADER before it is detected by path. Two version headers name this vendor at
//! rung 2 and its key header at rung 4 — both above every path rung the plane walks — and the path
//! at rung 11 is reached only by a request that sent none of them. The two earlier dialect crates
//! declared path rungs alone, so this is the crate that proves the registry's merged walk
//! interleaves a header rung at its number the way it interleaves a path rung.
//!
//! It is also the one dialect of the six whose upstreams REFUSE a request that names no response
//! ceiling. That is a column of its row, and the plane's crossing reads it off the row it is
//! already holding; the plane does not ask a by-name question that only ever mattered for this
//! vendor.
//!
//! ## What it is not
//!
//! It holds nothing across calls, opens nothing, reads no clock but the one the context hands it,
//! and names no crate but its plane and the contract. It has no session of its own — the session
//! state is the plane's, handed in and taken back — and no facts of its own, because what a request
//! MEANS is the plane's reading and what it is SPELLED as is this crate's.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod claims;
pub mod dialect;
pub mod meta;

use busbar_contract::plugin::{AbiVersion, Kind, Plugin};
use busbar_plane_llm::LlmPlane;

/// The `anthropic` dialect, holding the plane it translates for.
///
/// IT CARRIES ITS PLANE, and that is the registration direction stated as a type. The four codec
/// methods of the contract's dialect trait take `&self` and nothing else, so the plane a dialect
/// runs its translation through has to be somewhere; carrying it means a dialect value cannot exist
/// without naming the plane it belongs to, which is exactly the edge the kind allows. The reverse —
/// a plane holding a dialect — is the edge the kind refuses, and the registry holds this crate's
/// declarations as DATA rather than as a value of this type for that reason.
///
/// The plane is `Copy` and holds only borrowed, sealed slices, so this is a value with no interior
/// mutability and the purity battery walks it to say so.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Anthropic {
    plane: LlmPlane,
}

impl Anthropic {
    /// The dialect, translating for one plane.
    ///
    /// Construction is the whole of registration on this side: there is no `install`, because a
    /// dialect that could be pointed at a second plane after a boot proved the claim ladder
    /// disjoint would be a dialect whose claims in force are not the claims that were proved.
    #[must_use]
    pub const fn new(plane: LlmPlane) -> Self {
        Self { plane }
    }

    /// The plane this dialect translates for.
    #[must_use]
    pub const fn plane(&self) -> &LlmPlane {
        &self.plane
    }
}

impl Plugin for Anthropic {
    fn key(&self) -> &'static str {
        <Self as busbar_contract::dialect::DialectMeta>::KEY
    }

    fn kind(&self) -> Kind {
        Kind::Dialect
    }

    fn abi(&self) -> AbiVersion {
        busbar_contract::plugin::DIALECT_ABI
    }
}
