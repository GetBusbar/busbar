//! The rungs this dialect adds to its plane's detection ladder.
//!
//! ## Why the rung numbers are the plane's and not this crate's
//!
//! A rung is a statement about a CONTEST — "these bytes are mine rather than that dialect's" — so
//! its number only means anything against the same scale every other dialect is numbered on. This
//! crate declares rungs 7 and 14 because that is where these two claims sat in the one ladder the
//! plane has always walked, and moving them would change which dialect answers a request that two
//! could read. The merge in [`busbar_plane_llm::registry`] interleaves a registered rung at the
//! number it declares rather than appending it, so a rung declared here wins and loses exactly the
//! contests it won and lost before this crate existed.
//!
//! ## Why the claims are built with the plane's builder
//!
//! [`busbar_plane_llm::claims::claim`] is what fills in the transport, the credential scheme and
//! the alternative set. Restating those here would be this crate declaring a second answer to a
//! question the plane already answers for every one of its dialects — and the first request that
//! arrived on a transport the plane did not think it claimed would be the one that noticed.
//!
//! ## The two rungs, and why they are not one
//!
//! Rung 7 is the chat surface, and it is TIGHT: `/v1/chat/completions` is this vendor's own path,
//! and it sits above the other vendors' chat paths for the ordinary reason a more specific claim
//! sits above a less specific one.
//!
//! Rung 14 is the LOOSEST rung the plane has, and it is loose on purpose: these are the non-chat
//! surfaces of a vocabulary that other vendors copy path-for-path, so a request reaching them has
//! already failed to be claimed by anything tighter. The audio surface is named ONE PATH AT A TIME
//! rather than as the `/v1/audio/` prefix, because two of that prefix's three paths —
//! `transcriptions` and `speech` — are the voice plane's by the architecture's own plane inventory,
//! and a prefix claim here would overlap the voice plane's claims on the request instead of
//! dividing them. What is left is the audio path no other plane claims.

use busbar_contract::grammar::Selector;
use busbar_plane_llm::claims::{claim, LadderClaim};

busbar_contract::claims_from_ladder! {
    /// This dialect's rungs, in ascending rung order.
    ///
    /// ASCENDING IS REQUIRED, not merely tidy: the plane's merged walk takes the smallest unvisited
    /// rung from each source and stops scanning a source the moment it can no longer win, which is
    /// only sound for a source that is itself ordered. The conformance battery asserts it.
    LADDER,
    /// The same rungs one field narrower, as the declaration constant wants them.
    CLAIMS,
    LadderClaim,
    claim,

    // Rung 7: the widely-copied chat surface, on this vendor's own path.
    7 => "openai", Selector::PathSuffix("/v1/chat/completions"),

    // Rung 14: the loosest rung — the non-chat surfaces of the widely-copied dialect.
    14 => "openai", Selector::PathSuffix("/v1/embeddings"),
    14 => "openai", Selector::PathSuffix("/v1/moderations"),
    14 => "openai", Selector::PathContains("/v1/images/"),
    14 => "openai", Selector::PathSuffix("/v1/audio/translations"),
}
