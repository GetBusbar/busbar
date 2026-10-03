// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AGENT CARD, mirrored in busbar-owned structs, and the two hashes computed over it.
//!
//! ## Mirrored, not generated
//!
//! These structs are busbar's, transcribed from the A2A specification. They are deliberately not a
//! third party's generated wire types: the protocol is versioned and moving, and a generated type
//! would let a specification revision ripple out of the reader and into the registry, the catalogue
//! cache and the audit records. Mirroring contains a revision to the edge.
//!
//! `#[serde(default)]` throughout, and unknown members are IGNORED rather than refused, because an
//! upstream on a newer protocol revision must not become unreadable the moment it adds a member. The
//! fingerprint is what notices a change; the parser's job is only to read the fields busbar acts on.
//!
//! ## Two hashes, and they are not the same hash
//!
//! [`signing_payload`] is what a card's JWS signature covers: the canonical card with the
//! `signatures` member removed, because a signature cannot cover itself.
//!
//! [`fingerprint`] is what an operator APPROVES and what drift is measured against: the canonical
//! WHOLE card, signatures included. Fingerprinting the busbar-owned projection instead would mean
//! any member busbar does not model could change without registering as drift, which is exactly the
//! silent rug-pull the pin exists to catch. So both hashes are taken over the document AS RECEIVED,
//! and the structs below are for reading it, never for re-serializing it.

use serde_json::Value;

use super::pin::CardPin;
use busbar_kernel::trust::Observation;

/// The card's hashes and their refusal: the plane's ([`busbar_plane_a2a::a2a::card`]), the one home
/// of the card digests.
pub(crate) use busbar_plane_a2a::a2a::card::{
    fingerprint, signing_payload, skill_digests, CardError,
};

/// The canonical discovery path from protocol v0.3 onward. The CODEC's, because `busbar-plane-a2a`
/// claims this path and may not name this crate; a path a plane could only copy is a path the two
/// halves can come to disagree about. The LEGACY sibling below stays here — nothing claims it, it is
/// only tolerated on a fetch.
pub(crate) use busbar_plane_a2a::WELL_KNOWN_CARD_PATH;

/// The path the protocol used BEFORE v0.3. Both are tolerated on every fetch: the path moved between
/// revisions, and an upstream pinned to an older `protocolVersion` is still serving the old one.
pub(crate) const WELL_KNOWN_CARD_PATH_LEGACY: &str = "/.well-known/agent.json";

// The card's structs: the plane's, one home ([`busbar_plane_a2a::a2a::agent_card`]).
pub(crate) use busbar_plane_a2a::a2a::agent_card::AgentCard;

/// Turn a fetched card into the plane-neutral [`Observation`] the trust machine consumes: the
/// identity the endpoint presented, and what it offered.
///
/// `pin` is built by the caller because only the caller knows which mechanism this registration
/// uses and, for a signed card, which out-of-band issuer key verified it. The card cannot be asked
/// what it is rooted in: a document that names its own trust root is naming its own trust root.
pub(crate) fn observation(
    card: &Value,
    pin: Option<CardPin>,
) -> Result<Observation<CardPin>, CardError> {
    Ok(Observation {
        pin,
        capabilities: skill_digests(card)?,
    })
}

/// Read the members busbar acts on. Unknown members are ignored; see the module docs.
pub(crate) fn parse(card: &Value) -> Result<AgentCard, CardError> {
    // Every field carries `#[serde(default)]`, so the only way this fails is a member present with
    // the wrong TYPE, which is a malformed card rather than an unknown one.
    busbar_plane_a2a::a2a::agent_card::parse(card).ok_or(CardError::NotAnObject)
}

#[cfg(all(test, feature = "test-support"))]
#[path = "tests/card_tests.rs"]
mod card_tests;
