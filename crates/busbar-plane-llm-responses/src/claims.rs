//! The rung this dialect adds to its plane's detection ladder.
//!
//! ## Why the rung number is the plane's and not this crate's
//!
//! A rung is a statement about a CONTEST — "these bytes are mine rather than that dialect's" — so
//! its number only means anything against the same scale every other dialect is numbered on. This
//! crate declares rung 10 because that is where this claim sat in the one ladder the plane has
//! always walked, and moving it would change which dialect answers a request that two could read.
//! The merge in [`busbar_plane_llm::registry`] interleaves a registered rung at the number it
//! declares rather than appending it, so a rung declared here wins and loses exactly the contests it
//! won and lost before this crate existed.
//!
//! ## Why the claim is built with the plane's builder
//!
//! [`busbar_plane_llm::claims::claim`] is what fills in the transport, the credential scheme and
//! the alternative set. Restating those here would be this crate declaring a second answer to a
//! question the plane already answers for every one of its dialects — and the first request that
//! arrived on a transport the plane did not think it claimed would be the one that noticed.
//!
//! ## The one rung, and why it is one
//!
//! This surface is a SINGLE path. It is not the vendor's chat path and it is not one of the
//! widely-copied non-chat paths — no other vendor spells `/v1/responses` — so the whole of what this
//! dialect claims is one suffix, and it sits at ten: below the header rungs, which are stronger
//! evidence than any path, and below the other vendors' tighter path families, because those are
//! paths a request can only have if it is theirs. A dialect that claims one surface declares one
//! rung, and the crate is not smaller than the pattern for it.

use busbar_contract::grammar::Selector;
use busbar_plane_llm::claims::{claim, LadderClaim};

busbar_contract::claims_from_ladder! {
    /// This dialect's rungs, in ascending rung order.
    ///
    /// ASCENDING IS REQUIRED, not merely tidy: the plane's merged walk takes the smallest unvisited
    /// rung from each source and stops scanning a source the moment it can no longer win, which is
    /// only sound for a source that is itself ordered. One rung ascends trivially; the conformance
    /// battery asserts it anyway, because the second rung is the one nobody checks.
    LADDER,
    /// The same rung one field narrower, as the declaration constant wants it.
    CLAIMS,
    LadderClaim,
    claim,

    // Rung 10: one vendor's second, newer request surface, on a path no other vendor spells.
    10 => "responses", Selector::PathSuffix("/v1/responses"),
}
