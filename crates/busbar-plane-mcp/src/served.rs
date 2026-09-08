// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHAT AN ANSWER IS, for the operations this plane answers out of its own declarations and its own
//! records — moved here from inside the protocol's server.
//!
//! ## What moved, and why it could
//!
//! Four methods are the first through the loop, and the four are not alike. Two of them —
//! `initialize` and `ping` — are answered by the existing server from COMPILE-TIME CONSTANTS: no
//! catalogue, no registry, no clock, no session. They were written inside a console serve loop
//! (`busbar-mcp`'s `stdio_serve`), which is the one place in the tree that could not be reached
//! without opening a process's standard input. That is a wire fact living inside an I/O loop, and
//! this module is where it belongs: it is what the bytes MEAN, and it is a `fn` over nothing.
//!
//! The other two — `tools/list` and `tools/call` — are not pure, and this module does not pretend
//! they are. What moved for them is the part that IS: the classification of which state an answer is
//! composed from, the caching hints the cacheable answers carry, and the shape the answer is
//! assembled into. What did NOT move is every reach — the catalogue read, the sightings read, the
//! grant walk, the quarantine filter, the hop — because a plane performs no input and no output.
//! Those are declared here as [`Reads`], which names the record legs the KERNEL runs on this plane's
//! behalf, and they are run by the root over the store.
//!
//! ## The rule this module is written under
//!
//! If a byte differs between what this module produces and what the existing server produces, the
//! existing server is the answer and this module has the bug. Every constant below is PINNED by a
//! test that reads that server's own source, because this crate may not name it — a copy that is
//! checked is not a second opinion.

use busbar_contract::ids::{OpClassId, RecordSchemaId};

use crate::{ops, records};

/// The name this node publishes itself under, on every document that names a server.
///
/// One constant for the two documents that carry it, because they are two statements of one fact:
/// a node whose handshake said one name and whose discovery said another would be two servers to
/// any client that read both.
pub const SERVER_NAME: &str = "busbar";

/// The revision this build implements, as the wire spells it.
///
/// The codec's own, not a copy: three crates must agree on this string and the compiler holds the
/// equality rather than a comment.
pub const PROTOCOL_VERSION: &str = busbar_mcp_codec::codec::PROTOCOL_VERSION;

/// Who may keep a cacheable answer. One reader per caller, because every cacheable answer of this
/// protocol is computed from the CALLER's own grant — a shared cache would hand one caller's
/// entitlement to another.
pub const CACHE_SCOPE: &str = "private";

/// How long a cacheable answer may be kept without asking again.
///
/// Zero, and it is a declaration rather than an omission: the answers are grant-scoped and the grant
/// can move at any moment, so the honest lifetime is none. The hint is still written, because a
/// client that reads no hint at all cannot tell a deliberate zero from a server that forgot.
pub const CACHE_TTL_MS: i64 = 0;

/// The state one served operation is composed from.
///
/// A CLASSIFICATION and not a fetch. Every arm names what the kernel must have run before this
/// plane's answer can be assembled, in the plane's own record vocabulary — so the root reads which
/// legs to run off the declaration rather than off a table it keeps beside it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reads {
    /// Nothing at all. The answer is a function of this build and of no caller, no registration and
    /// no record. There is no leg to run and no state that could make two callers' answers differ.
    Nothing,
    /// The catalogue snapshot, as it stood when this unit arrived, minus what is quarantined.
    ///
    /// Two schemas and not one: what was approved, and what has since been demoted. A listing
    /// composed from the first alone advertises the operator's approved shape for a server that has
    /// stopped serving it that way.
    CatalogueSnapshot,
    /// The ONE registration the request names, and the demotion row beside it — the server
    /// registry, as this plane reaches it.
    ///
    /// A call is the one operation that needs a named entry rather than a listing: the catalogue
    /// entry says whether this caller may reach the named tool and what shape it was approved at,
    /// and the demotion row says whether the server behind it has been taken out of service.
    ///
    /// **A gap, named rather than hidden.** [`crate::records::SCHEMA_SETTINGS`] is where a
    /// registration's own applied configuration belongs, and this plane's plan for a call does not
    /// read it: how the server is reached still comes from the registration table the root holds.
    /// That is where the reach is today, and moving it is a later stage's work, not a leg this
    /// module can invent.
    ServerRegistry,
}

impl Reads {
    /// The record legs this reading is composed of.
    ///
    /// A SUBSET of the plan [`crate::plane`] returns for the classes that read this way, never a
    /// second copy of it: the plan is the single source for what a unit runs, and this names the
    /// part of it an answer is composed FROM. The test below asserts the containment in the one
    /// direction it holds, so a reading that named a leg the plan never runs is red here rather than
    /// an answer assembled from a record nobody read.
    #[must_use]
    pub fn legs(self) -> &'static [(RecordSchemaId, &'static str)] {
        match self {
            Reads::Nothing => &[],
            Reads::CatalogueSnapshot => &[
                (records::SCHEMA_CATALOGUE, records::OP_SCAN),
                (records::SCHEMA_DEMOTION, records::OP_SCAN),
            ],
            Reads::ServerRegistry => &[
                (records::SCHEMA_CATALOGUE, records::OP_GET),
                (records::SCHEMA_DEMOTION, records::OP_GET),
            ],
        }
    }
}

/// What one operation class reads, where this plane declares an answer for it.
///
/// `None` for a class this stage does not answer through the loop. That is a declaration and not a
/// gap: the composition root's served set is derived from this function, so an operation with no
/// reading here is one the mount hands straight to the surface that already answers it.
#[must_use]
pub fn reads(op: OpClassId) -> Option<Reads> {
    match op {
        ops::OP_INITIALIZE | ops::OP_PING => Some(Reads::Nothing),
        ops::OP_TOOLS_LIST => Some(Reads::CatalogueSnapshot),
        ops::OP_TOOL_CALL => Some(Reads::ServerRegistry),
        _ => None,
    }
}

/// Every operation class this module composes an answer for, in declaration order.
///
/// The FIRST four through the loop. It is a list rather than a predicate because the composition
/// root prints it at boot and the mount's own shadow predicate is built from it — and a set two
/// readers derive separately is a set they can derive differently.
pub const ANSWERED: &[OpClassId] = &[
    ops::OP_INITIALIZE,
    ops::OP_PING,
    ops::OP_TOOLS_LIST,
    ops::OP_TOOL_CALL,
];

/// Add the caching hints to a result that is CACHEABLE.
///
/// One function so the pair cannot drift apart across the cacheable answers, for the same reason the
/// error envelope is one function for its status-and-code pair: a hint that says one scope in one
/// place and another elsewhere is a hint no client can act on.
///
/// A result that is not a document is handed back untouched. There is nothing to hint ABOUT, and
/// wrapping one here would change a shape the caller is going to read.
#[must_use]
pub fn cache_hints(value: serde_json::Value) -> serde_json::Value {
    let mut value = value;
    if let Some(object) = value.as_object_mut() {
        object.insert("cacheScope".into(), CACHE_SCOPE.into());
        object.insert("ttlMs".into(), CACHE_TTL_MS.into());
    }
    value
}

/// The `initialize` answer: the console-era negotiation, as this build answers it.
///
/// busbar implements ONE revision and this result says so — `protocolVersion` names it, so a
/// legacy-era client either speaks it from here on or disconnects, which is the negotiation
/// completing in either direction. No session is created because the revision has none to create.
///
/// The version is a PARAMETER and not `env!("CARGO_PKG_VERSION")`, and that is the one thing that
/// changed in the move. The number belongs to the NODE, and reading it out of whichever crate the
/// function happens to live in is how a function that moves crates changes a byte on the wire.
///
/// Nothing here is read from a caller, a registration or a clock: two callers get the same document,
/// and so does the same caller twice.
#[must_use]
pub fn initialize_result(node_version: &str) -> serde_json::Value {
    serde_json::json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {
            "tools": { "listChanged": true },
            "prompts": { "listChanged": true },
            "resources": { "listChanged": true, "subscribe": true },
            "completions": {},
            "logging": {},
        },
        "serverInfo": {
            "name": SERVER_NAME,
            "version": node_version,
        },
        "instructions": instructions(),
    })
}

/// The sentence the handshake hands a client about what it has connected to.
///
/// Its own function because it is the one member of the handshake that is FORMATTED rather than
/// written, and a format string reproduced at a second call site is a second wording.
#[must_use]
pub fn instructions() -> String {
    format!(
        "This server speaks MCP revision {PROTOCOL_VERSION}: no handshake is required, and every \
         request states its protocol version and client capabilities in `params._meta`."
    )
}

/// The `ping` answer: the empty document.
///
/// It is a function rather than a constant expression at each call site for the reason every other
/// answer here is one — there is exactly one place this protocol's answer to `ping` is written down,
/// and a second `json!({})` somewhere else is a second place for it to stop being empty.
#[must_use]
pub fn ping_result() -> serde_json::Value {
    serde_json::json!({})
}

/// The `tools/list` answer, over the tools the caller may see.
///
/// The LIST is the argument, and that is the whole of the split. Which tools a caller may see is an
/// entitlement walk over a grant, then a trust filter over the drift sightings, then a render — none
/// of which is a plane's to do, and all of which is composed from the record legs [`Reads`] names.
/// What this function owns is the shape the answers are handed back in, which is a wire fact.
///
/// A caller whose grant reaches nothing gets the empty list rather than an error. That is
/// deliberate: an error would tell a caller that something exists behind the grant, and the empty
/// list is what the existing server answers.
#[must_use]
pub fn tools_list_result(tools: Vec<serde_json::Value>) -> serde_json::Value {
    cache_hints(serde_json::json!({ "tools": tools }))
}

/// The `tools/call` answer, over what the server that was reached said.
///
/// NOT cached and deliberately not: a call is an effect, and a hint inviting a client to reuse the
/// answer would invite it to skip the effect. The existing server writes no hint here either, which
/// is the pin.
///
/// The discriminator is NOT stamped here. It is stamped once, by [`crate::jsonrpc::success`], over
/// every answer this plane writes — and stamping it here as well would be the one member of the
/// envelope written in two places.
#[must_use]
pub fn tool_call_result(upstream: serde_json::Value) -> serde_json::Value {
    upstream
}

#[cfg(test)]
#[path = "tests/served.rs"]
mod tests;
