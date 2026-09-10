//! The rungs this dialect adds to its plane's detection ladder.
//!
//! ## Why the rung numbers are the plane's and not this crate's
//!
//! A rung is a statement about a CONTEST — "these bytes are mine rather than that dialect's" — so
//! its number only means anything against the same scale every other dialect is numbered on. This
//! crate declares rungs 3, 5 and 6 because those are where these claims sat in the one ladder the
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
//! ## The three rungs, and why the loosest path family sits ABOVE the tight chat suffixes
//!
//! Rung 3 is the vendor's key header, which no other vendor's clients send. Rung 5 is the five
//! action suffixes of the model-scoped surface — a request naming `:generateContent` can only be
//! this vendor's. Rung 6 is the model-scoped surface WITHOUT an action, on either API version, as
//! a path pattern with a tail: `/v1/models/{anything}` is this vendor's whatever the tail spells,
//! which is looser than rung 5 and still tighter than a chat suffix another vendor could share,
//! and that is why 6 sits below 5 and above 7. The eight claims are three rungs because a rung is
//! ONE contest and a contest can be satisfied by several spellings.

use busbar_contract::grammar::{PathSeg, Selector};
use busbar_plane_llm::claims::{claim, LadderClaim};

/// A path pattern that matches the whole model-scoped surface of one API version.
const V1_MODELS: &[PathSeg] = &[PathSeg::Lit("v1"), PathSeg::Lit("models"), PathSeg::Tail];

/// A path pattern that matches the whole model-scoped surface of the preview API version.
const V1BETA_MODELS: &[PathSeg] = &[
    PathSeg::Lit("v1beta"),
    PathSeg::Lit("models"),
    PathSeg::Tail,
];

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

    // Rung 3: a vendor-specific key header.
    3 => "gemini", Selector::HeaderPresent("x-goog-api-key"),

    // Rung 5: the action suffixes of the model-scoped surface.
    5 => "gemini", Selector::PathContains(":generateContent"),
    5 => "gemini", Selector::PathContains(":streamGenerateContent"),
    5 => "gemini", Selector::PathContains(":embedContent"),
    5 => "gemini", Selector::PathContains(":batchEmbedContents"),
    5 => "gemini", Selector::PathContains(":predict"),

    // Rung 6: the model-scoped surface without an action suffix, on either version.
    6 => "gemini", Selector::PathPattern(V1_MODELS),
    6 => "gemini", Selector::PathPattern(V1BETA_MODELS),
}
