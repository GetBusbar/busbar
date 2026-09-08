// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MOUNTING A DECLARED SURFACE: any plane's, and none of them by name.
//!
//! ## What this module is for
//!
//! A protocol served over this transport used to need a crate: the route table, the
//! verb-to-operation map, the media types, the streaming decision and the loop drive all lived
//! beside the codec that knew what the bytes meant, and every new protocol brought another copy of
//! all five. None of those five is about a protocol. They are about how bytes are ADDRESSED, and a
//! plane can declare that — `busbar_contract_transport::surface` is the vocabulary and this module
//! is the reader.
//!
//! So: hand this a [`WireSurface`] and a driver, and it mounts the surface. Which surface it is, it
//! does not know and may not ask. There is no protocol name in this file and none in this crate; the
//! test beside it asserts that over the crate's own source and its own manifest, so the rule is
//! checkable rather than a matter of who reviewed the diff.
//!
//! ## The three steps this module owns, and the one it does not
//!
//! 1. **Address.** [`resolve`] takes what the transport read off the request — the target, the
//!    request method — and finds the operation the declaration says it names, together with the
//!    captures the template yielded and the credential bar the row declares. A target that resolves
//!    to nothing is [`Unaddressed`], which is a 404 and not a refusal: there is no unit, so there is
//!    nothing to refuse.
//! 2. **Publish.** [`published_facts`] builds the fact list this arrival carries: the kernel's own
//!    reserved keys FIRST, then whatever captures the template yielded under their declared names. A
//!    capture named the same as a reserved key does not shadow it — every location resolved further
//!    in is resolved against these, and a request whose `path` fact was not the path would be a
//!    request answered about somewhere else.
//! 3. **Frame the answer.** [`status_of`] maps the closed outcome vocabulary onto this wire's own
//!    numbering, and the media type comes off the declaration. The BYTES are never this module's.
//!
//! And the one it does not: **running the unit.** That is [`UnitDriver::drive`], and everything it
//! takes — the arena, the context, the plane call, the loop, the ending, the ledger — is on the far
//! side of that seam. See `busbar_contract_transport::driver` for why the tree draws it there and
//! not here: core drives plugins, and a transport that called the loop would be a plugin naming
//! core.
//!
//! ## What this transport therefore does NOT know
//!
//! Which plane answered. What the unit cost. What step refused it, if one did. Whether an arena was
//! exhausted. It knows that bytes arrived, which declared address they named, and — from the eight
//! words the driver answers with — which status its own wire should put on the way out.

use std::collections::HashMap;

use busbar_contract_transport::driver::{Answer, Arrival, Outcome, UnitDriver};
use busbar_contract_transport::registry::facts as tfacts;
use busbar_contract_transport::surface::{
    resolve_target, Bar, Capture, Dispatch, Operation, WireSurface,
};

// ── what arrived ────────────────────────────────────────────────────────────────────────────────

/// One request, as this transport read it off the wire and before any plane is chosen.
///
/// Every field is something the bottom layer saw. Nothing here is derived and nothing is a protocol
/// fact: a target, a request method, the authority the caller named, the peer the connection came
/// from, and the body.
#[derive(Clone, Copy, Debug)]
pub struct Request<'r> {
    /// The request target, query and fragment included, exactly as it arrived.
    pub target: &'r str,
    /// The request method.
    pub method: &'r str,
    /// The authority the request named, where it named one.
    pub authority: Option<&'r str>,
    /// The peer's source address as the bottom layer saw it.
    pub peer: &'r str,
    /// The credential the caller presented, exactly as it arrived.
    ///
    /// Whole and unstripped: the scheme word travels with it, because deciding what a scheme means is
    /// the authentication chain's and a transport that stripped one would be interpreting a
    /// credential it may not read. `None` is a request that presented none, which is a posture a
    /// declaration can legitimately admit — see [`Bar::Open`].
    pub credential: Option<&'r str>,
    /// What the caller said it will accept back, where it said anything.
    pub accepts: Option<&'r str>,
    /// The media type the caller said its body is, where it said anything.
    pub media: Option<&'r str>,
    /// The request body.
    pub body: &'r [u8],
}

/// Which of the declaration's addresses an arrival matched.
#[derive(Clone, Debug)]
pub struct Addressed<'s> {
    /// The operation the declaration says this address names.
    ///
    /// `None` on a document mount: the mount is declared, the operation is not addressed by the
    /// target, and it is the PLANE that reads which one it is out of the document. That is the
    /// division this whole module is built on — the transport addresses, the plane means.
    pub operation: Option<&'s Operation>,
    /// The dispatch row that matched, where a row did.
    pub dispatch: Option<&'s Dispatch>,
    /// The captures the template yielded, in declaration order.
    pub captures: Vec<Capture<'s>>,
    /// The credential bar this address declares.
    pub bar: Bar,
}

/// Why an arrival could not be addressed.
///
/// One value, and it is not a refusal. A target no declaration names is a target this node does not
/// serve: there is no unit, nothing was decoded, no principal was resolved and nothing may be
/// charged. Answering it as a refusal would put a unit in the ledger for a request that never
/// existed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unaddressed;

/// Address one arrival against a declared surface.
///
/// Two questions in one, in the order the declaration decides:
///
/// 1. does a target row match, in the surface's own most-specific-first order? If so that is the
///    answer, captures and bar included.
/// 2. is the target one of a binding's declared document mounts? If so the operation is the
///    document's to name, and the bar is the STRICTEST any of that binding's document rows declares
///    — fail-closed, because the bar has to be known before the credential step and the document has
///    not been read yet.
///
/// # Errors
///
/// The target is neither a declared route nor a declared mount.
pub fn resolve<'s>(
    surface: &'s WireSurface,
    request: &Request<'s>,
) -> Result<Addressed<'s>, Unaddressed> {
    if let Some((operation, dispatch, captures)) =
        resolve_target(surface, request.target, request.method)
    {
        return Ok(Addressed {
            operation: Some(operation),
            dispatch: Some(dispatch),
            bar: dispatch.bar(),
            captures,
        });
    }
    let binding = busbar_contract_transport::surface::binding_at(surface, request.target)
        .ok_or(Unaddressed)?;
    Ok(Addressed {
        operation: None,
        dispatch: None,
        captures: Vec::new(),
        bar: document_bar(surface, binding.name),
    })
}

/// The strictest bar any document row of one binding declares.
///
/// Fail-closed on purpose, and stated rather than assumed: a binding with no document row at all
/// answers `Credential`. The alternative reading — "nothing said it needs one, so it does not" —
/// turns an incomplete declaration into an open door, which is the one direction this decision must
/// never be wrong in.
#[must_use]
pub fn document_bar(surface: &WireSurface, binding: &str) -> Bar {
    let mut saw_one = false;
    for operation in surface.operations {
        for d in operation.dispatch {
            if let Dispatch::Document {
                binding: b,
                bar: row,
                ..
            } = d
            {
                if *b == binding {
                    saw_one = true;
                    if *row == Bar::Credential {
                        return Bar::Credential;
                    }
                }
            }
        }
    }
    if saw_one {
        Bar::Open
    } else {
        Bar::Credential
    }
}

/// The operation a class name addresses.
///
/// The tie-back a document binding needs on the way back out: the transport could not know the
/// operation before the document was read, and the driver hands the resolved one back on the answer.
#[must_use]
pub fn operation_of<'s>(surface: &'s WireSurface, op: &str) -> Option<&'s Operation> {
    surface.operations.iter().find(|o| o.op == op)
}

// ── what this transport publishes about an arrival ──────────────────────────────────────────────

/// The reserved fact keys a mounted request publishes.
///
/// Declared, so the registration check that catches a transport publishing a reserved key it never
/// declared has something to compare against.
pub const MOUNT_FACTS: &[&str] = &[
    tfacts::PATH,
    tfacts::METHOD,
    tfacts::AUTHORITY,
    tfacts::PEER,
    tfacts::CREDENTIAL,
    tfacts::ACCEPTS,
    tfacts::MEDIA,
];

/// Build the fact list one arrival carries, reserved keys first.
///
/// The ORDER is the load-bearing part and is why this is a list rather than a map. A declaration is
/// free to name a capture `path`, and every location resolved further in is resolved against these
/// facts — so a capture that could shadow the request target would be a unit answered about
/// somewhere other than where it was sent. Reserved first, first match wins, and a capture that
/// collides is simply never reached.
///
/// Values borrow the request and the captures, so nothing here is copied and nothing outlives the
/// arrival it describes.
#[must_use]
pub fn published_facts<'a>(
    request: &'a Request<'a>,
    captures: &'a [Capture<'a>],
) -> Vec<(&'a str, &'a str)> {
    let mut facts: Vec<(&'a str, &'a str)> = Vec::with_capacity(MOUNT_FACTS.len() + captures.len());
    facts.push((tfacts::PATH, request.target));
    facts.push((tfacts::METHOD, request.method));
    if let Some(authority) = request.authority {
        facts.push((tfacts::AUTHORITY, authority));
    }
    facts.push((tfacts::PEER, request.peer));
    // THE THREE A REQUEST CARRIES ABOUT ITSELF rather than about where it was sent. They are pushed
    // only where the request actually carried them, because an ABSENT fact and an EMPTY one are
    // different statements: a plane reading an empty credential would be reading a credential that
    // was presented and is blank, and a caller that presented none did not present a blank one.
    //
    // They are reserved keys and therefore ordered before the captures, for the same reason the four
    // above are: a declaration is free to name a capture `credential`, and a unit authenticated
    // against a template capture instead of against what the caller sent would be a door opened by
    // whoever wrote the route.
    if let Some(credential) = request.credential {
        facts.push((tfacts::CREDENTIAL, credential));
    }
    if let Some(accepts) = request.accepts {
        facts.push((tfacts::ACCEPTS, accepts));
    }
    if let Some(media) = request.media {
        facts.push((tfacts::MEDIA, media));
    }
    for c in captures {
        facts.push((c.name, c.value));
    }
    facts
}

/// The captures a matched template yielded, as a map, for a caller that wants one.
///
/// Offered beside [`published_facts`] rather than instead of it, and the difference is the whole
/// reason the fact list is ordered: a map is the right shape for "what did the template capture"
/// and the wrong shape for "what does this arrival publish", because the second question has a
/// precedence in it and a map has none.
#[must_use]
pub fn captures_map<'a>(captures: &'a [Capture<'a>]) -> HashMap<&'a str, &'a str> {
    captures.iter().map(|c| (c.name, c.value)).collect()
}

// ── running one arrival, on the far side of the seam ────────────────────────────────────────────

/// Hand one addressed arrival to the driver, and take back what the plane wrote.
///
/// Two lines of work and one line of principle. The work is assembling the arrival — the facts this
/// transport publishes, the bytes, the composed stack, what the addressing produced. The principle
/// is that this function does not run anything: it hands over, and the arena, the context, the plane
/// call and the loop are all on the other side.
///
/// Named for the handing over rather than for the running, because the name is the seam. No kind's
/// ABI exposes `mount`, `serve`, `bind` or `on_upgrade`: each names something the kernel does, and
/// a plugin offering a function by one of those names is offering to do it instead. This body was
/// always innocent — it builds an arrival and gives it away — but the signature is what a caller
/// reaches for, and one reaching for `serve` on a transport is reaching for the wrong seam.
///
/// The composed chain travels because a claim's transport is compared against the TOP of it, and a
/// stack that reported itself wrongly would let a request matched as one layer be served as another.
#[must_use]
pub fn hand_to_driver<'a>(
    driver: &dyn UnitDriver,
    surface: &WireSurface,
    request: &'a Request<'a>,
    addressed: &'a Addressed<'a>,
    key: &'static str,
    chain: &'a [&'static str],
) -> Answer {
    let facts = published_facts(request, &addressed.captures);
    driver.drive(
        Arrival {
            facts: &facts,
            body: request.body,
            transport: key,
            chain,
            operation: addressed.operation,
            bar: addressed.bar,
        },
        surface,
    )
}

/// This wire's own status for one outcome.
///
/// Eight words in, one number out, and the mapping is the same for every plane because it is a
/// statement about what happened to the REQUEST rather than about what the request was. A protocol
/// that wants a finer word than these puts it in its answer body, which the plane wrote and this
/// module does not read.
#[must_use]
pub fn status_of(outcome: Outcome) -> u16 {
    match outcome {
        Outcome::Completed => 200,
        // 401 and 403 are the two doors about WHO is calling, and they are answered separately for
        // the reason the specification separates them: one tells a caller its credential was not
        // accepted, the other that it was accepted and does not cover this. Collapsing them sends a
        // caller with a bad token to go and fix its permissions.
        Outcome::Unauthenticated => 401,
        Outcome::Forbidden => 403,
        Outcome::NotFound => 404,
        Outcome::Throttled => 429,
        // 504 rather than 408: the deadline that expired is one this node was waiting on, not one
        // the client failed to meet. 408 would blame the caller for the node's own wait.
        Outcome::TimedOut => 504,
        // 499 is not in the standard and is what this family of proxies has always used for "the
        // exchange ended before an answer existed". Nothing downstream reads it as a class it does
        // not belong to: it is 4xx, and the exchange really was ended from the caller's side.
        Outcome::Cancelled => 499,
        Outcome::Unavailable => 503,
    }
}

/// The status a target no declaration names is answered with.
///
/// Separate from [`status_of`] because it is a different KIND of answer: no unit existed, so there
/// is no outcome to map. A surface that answered this through the outcome vocabulary would have to
/// invent a ninth word meaning "there was never a unit", which is not something that happened to a
/// unit.
pub const UNADDRESSED_STATUS: u16 = 404;

#[cfg(test)]
#[path = "tests/mount.rs"]
mod tests;
