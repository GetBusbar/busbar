//! The rungs this dialect adds to its plane's detection ladder.
//!
//! ## Why the rung numbers are the plane's and not this crate's
//!
//! A rung is a statement about a CONTEST — "these bytes are mine rather than that dialect's" — so
//! its number only means anything against the same scale every other dialect is numbered on. This
//! crate declares rungs 2, 4 and 11 because those are where these claims sat in the one ladder the
//! plane has always walked, and moving them would change which dialect answers a request that two
//! could read. The merge in [`busbar_plane_llm::registry`] interleaves a registered rung at the
//! number it declares rather than appending it, so a rung declared here wins and loses exactly the
//! contests it won and lost before this crate existed.
//!
//! ## Why the claims are built with the plane's builder
//!
//! [`busbar_plane_llm::claims::claim`] is what fills in the transport, the credential scheme and
//! the alternative set. Restating those here would be this crate declaring a second answer to a
//! question the plane already answers for every one of its dialects.
//!
//! ## The three rungs, and why a header outranks a path
//!
//! Rung 2 is two version headers no other vendor's clients send; either names this dialect on its
//! own. Rung 4 is the key header — a header a second vendor's clients could in principle send,
//! which is why it sits BELOW rung 2 and is not the tightest evidence, and above every path rung
//! because a client that presented this vendor's credential form said more about itself than any
//! path spelling can. Rung 11 is the path, and it is loose on purpose: `/v1/messages` names this
//! dialect only because nothing tighter claimed the request, which is what a request with no
//! vendor header looks like. The number is well below the other vendors' tight path families
//! (5, 6, 8, 9, 10) so a request carrying one of those AND this substring routes to the vendor
//! whose path it really is.

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

    // Rung 2: two vendor-specific version headers, either of which names the dialect on its own.
    2 => "anthropic", Selector::HeaderPresent("anthropic-version"),
    2 => "anthropic", Selector::HeaderPresent("anthropic-beta"),

    // Rung 4: a key header two vendors could in principle send, which is why it sits below rung 2.
    4 => "anthropic", Selector::HeaderPresent("x-api-key"),

    // Rung 11: a path that names this dialect only because nothing tighter claimed it.
    11 => "anthropic", Selector::PathContains("/v1/messages"),
}
