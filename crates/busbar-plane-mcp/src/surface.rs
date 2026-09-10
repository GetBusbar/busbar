// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The served surface, as data: every operation, and every way a caller can address it.
//!
//! ## Why this is a declaration and not a server
//!
//! This plane already says what bytes MEAN. What it could not say, until this module, is how a
//! caller REACHES an operation — which document member names it, which mount that document is
//! posted to, which request method carries it, and whether the answer is one document or a run of
//! them. Every one of those was written inside the protocol's own server, which is what made a wire
//! protocol a crate.
//!
//! They are declared here, in the plane-agnostic vocabulary
//! the contract's transport half (`surface`) defines, and a transport mounts them without knowing what
//! protocol they belong to. Nothing here opens anything, holds anything or reads anything: it is a
//! `const`.
//!
//! ## This protocol names its operation in the BODY, so every row is a document row
//!
//! There is no target binding here and the absence is the declaration, not an omission. This
//! protocol has exactly one request path and every operation is posted to it; the path names the
//! MOUNT and the `method` member names the operation. A protocol whose operations were addressed by
//! their target would declare [`Dispatch::Target`] rows, and this one has none because it has no
//! such addresses to declare.
//!
//! ## TWO BINDINGS, AND WHICH METHODS EACH ONE CARRIES IS THE POINT OF THE FILE
//!
//! The document binding is the mounted request surface. The console binding is a locally launched
//! server's own frames, which arrive on a named stream and never on a path.
//!
//! **They do not carry the same vocabulary, and that is the protocol's fact rather than this
//! crate's convenience.** `initialize` and `ping` are the stateful-era verbs: they are meaningful
//! only where a persistent connection exists, the codec's own dispatch table
//! (the codec's `IMPLEMENTED_METHODS`) does not carry them, and the mounted surface
//! answers them `-32601` today. The published conformance suite asserts that it does. So they are
//! declared on the console binding ALONE — which is exactly where the existing server answers them
//! — and a surface that declared them on the document binding would be this crate turning a
//! `-32601` into an answer, which is the one thing it may not do.
//!
//! Being able to say that AS DATA is the whole reason a surface is a declaration: the alternative
//! is a method table with a comment beside two of its rows.
//!
//! ## Where the strings come from
//!
//! The mount is [`crate::claims::DEFAULT_MOUNT`], the stream name is
//! [`crate::claims::CONSOLE_STREAM`], the operation classes are [`crate::ops`]'s and every method
//! name is the row's own. Nothing is spelled twice here that is spelled anywhere else, and the
//! tests below walk [`crate::ops::METHODS`] against this table in both directions — so a method
//! added to the vocabulary and not declared here is red, and a row here naming a method the
//! vocabulary does not carry is red too.

use busbar_contract::surface::{
    resolve_document, Answering, Bar, BindingDecl, Dispatch, Operation, WireSurface,
};

use crate::{claims, ops};

/// The document binding's name: the mounted request surface, where a posted envelope's `method`
/// member names the operation.
pub const BINDING_DOCUMENT: &str = "jsonrpc";

/// The console binding's name: the frames of a locally launched server, which arrive on a named
/// stream and carry no path at all.
///
/// The binding is named for the ROLE it serves, never for the carrier underneath it: a binding name
/// is this plane's own vocabulary, and spelling it after a wire would be the plane naming a
/// transport instance in the one table a reader treats as the plane's own words.
pub const BINDING_CONSOLE: &str = "console";

/// The member of a posted document that names the operation.
pub const METHOD_MEMBER: &str = "method";

/// The media type every request body of this protocol carries.
pub const MEDIA_JSON: &str = "application/json";

/// The media type a streamed answer carries.
pub const MEDIA_EVENT_STREAM: &str = "text/event-stream";

/// The request method a document is posted with. The mounted surface answers this one and no other;
/// the two it also routes are the legacy-verb refusal, which is an answer about the method rather
/// than an operation of the protocol.
const POST: &str = "POST";

/// The same mount with the trailing separator a great many clients send.
///
/// Not cosmetic and not a guess: a client handed `/mcp` as a BASE URL resolves a request for
/// `/` against it and sends `/mcp/`. A mount declared only one way leaves that spelling answering
/// 404.
const MOUNT_SLASH: &str = "/mcp/";

/// One operation reachable on BOTH bindings, which is every operation of the served vocabulary
/// except the two console-era verbs.
const fn both(name: &'static str) -> [Dispatch; 2] {
    [
        Dispatch::Document {
            binding: BINDING_DOCUMENT,
            method: POST,
            member: METHOD_MEMBER,
            name,
            bar: Bar::Credential,
        },
        Dispatch::Document {
            binding: BINDING_CONSOLE,
            method: POST,
            member: METHOD_MEMBER,
            name,
            bar: Bar::Credential,
        },
    ]
}

/// One operation reachable on the console binding ALONE.
///
/// The credential bar is still declared, and it is the same bar: a locally launched server is handed
/// its credential when it starts rather than carrying one on a request, which is the environment
/// alternative [`crate::claims`] declares — a different CARRIER for the same bar, not an open
/// surface.
const fn console(name: &'static str) -> Dispatch {
    Dispatch::Document {
        binding: BINDING_CONSOLE,
        method: POST,
        member: METHOD_MEMBER,
        name,
        bar: Bar::Credential,
    }
}

/// Ask the server what it is and what it supports.
const D_DISCOVER: &[Dispatch] = &[both("server/discover")[0], both("server/discover")[1]];

/// The console-era handshake. One address, and it is the console binding's.
const D_INITIALIZE: &[Dispatch] = &[console("initialize")];

/// The console-era liveness verb. One address, for the same reason.
const D_PING: &[Dispatch] = &[console("ping")];

/// List the tools this caller may use.
const D_TOOLS_LIST: &[Dispatch] = &[both("tools/list")[0], both("tools/list")[1]];

/// Call one tool.
const D_TOOL_CALL: &[Dispatch] = &[both("tools/call")[0], both("tools/call")[1]];

/// List the prompts this caller may use.
const D_PROMPTS_LIST: &[Dispatch] = &[both("prompts/list")[0], both("prompts/list")[1]];

/// Render one prompt.
const D_PROMPT_GET: &[Dispatch] = &[both("prompts/get")[0], both("prompts/get")[1]];

/// List the resources this caller may read.
const D_RESOURCES_LIST: &[Dispatch] = &[both("resources/list")[0], both("resources/list")[1]];

/// List the resource templates this caller may fill in.
const D_RESOURCE_TEMPLATES_LIST: &[Dispatch] = &[
    both("resources/templates/list")[0],
    both("resources/templates/list")[1],
];

/// Read one resource.
const D_RESOURCE_READ: &[Dispatch] = &[both("resources/read")[0], both("resources/read")[1]];

/// Complete a partially written argument.
const D_COMPLETION: &[Dispatch] = &[
    both("completion/complete")[0],
    both("completion/complete")[1],
];

/// Read one long-running task back.
const D_TASK_GET: &[Dispatch] = &[both("tasks/get")[0], both("tasks/get")[1]];

/// Hand a long-running task what it asked for.
const D_TASK_UPDATE: &[Dispatch] = &[both("tasks/update")[0], both("tasks/update")[1]];

/// Ask for one long-running task to stop.
const D_TASK_CANCEL: &[Dispatch] = &[both("tasks/cancel")[0], both("tasks/cancel")[1]];

/// Hold open a stream of catalogue changes.
const D_SUBSCRIPTIONS_LISTEN: &[Dispatch] = &[
    both("subscriptions/listen")[0],
    both("subscriptions/listen")[1],
];

/// The notices this node acts on.
///
/// One operation class and three addresses, because that is what they are: a notice carries no
/// identifier and obliges no answer, and which of the three arrived is a fact the decoded facts
/// carry rather than a class of its own.
const D_NOTIFICATION: &[Dispatch] = &[
    both("notifications/roots/list_changed")[0],
    both("notifications/roots/list_changed")[1],
    both("notifications/tools/list_changed")[0],
    both("notifications/tools/list_changed")[1],
    both("notifications/resources/updated")[0],
    both("notifications/resources/updated")[1],
];

/// One unary operation over JSON.
const fn unary(op: &'static str, dispatch: &'static [Dispatch]) -> Operation {
    Operation {
        op,
        dispatch,
        answering: Answering::Unary,
        request_media: MEDIA_JSON,
        response_media: MEDIA_JSON,
    }
}

/// One streamed operation: a JSON request, an event stream back.
const fn streamed(op: &'static str, dispatch: &'static [Dispatch]) -> Operation {
    Operation {
        op,
        dispatch,
        answering: Answering::Stream,
        request_media: MEDIA_JSON,
        response_media: MEDIA_EVENT_STREAM,
    }
}

/// THE SURFACE.
///
/// The operation order carries no precedence here, and that is worth stating rather than leaving to
/// be inferred: every row is a document row, a document address is an exact member value, and two
/// exact values cannot overlap. The check the vocabulary runs at boot still applies — it is what
/// says no two rows occupy one address — and the ordering below is the vocabulary's own, so a reader
/// comparing this table against [`crate::ops::METHODS`] reads them in the same order.
///
/// ## What is deliberately NOT declared here
///
/// * **The discovery document.** `/.well-known/oauth-protected-resource/mcp` is claimed by this
///   plane ([`crate::claims`]) and served by the existing codec, and it is not an operation of this
///   vocabulary: no operation class names it and its answer is not composed from anything the loop
///   would run. Declaring it under some other class would mount a route that answered a catalogue
///   listing to a caller asking which authorization server to go to.
/// * **The three verbs an UPSTREAM sends back mid-call** — `sampling/createMessage`, `roots/list`
///   and `elicitation/create`. They are in the method vocabulary because a paired server sends them,
///   and they are not on the SERVED surface because no client may send them: the decode step refuses
///   a provider method arriving from a caller, and a row here would be an address to something that
///   is always refused.
/// * **The three console-era session verbs** — `logging/setLevel`, `resources/subscribe` and
///   `resources/unsubscribe`. They are answered by the existing console loop out of state it holds
///   for the life of one process, and this plane declares no operation class for any of them. They
///   are named here so their absence is a finding with a shape rather than a gap.
pub const SURFACE: WireSurface = WireSurface {
    bindings: &[
        BindingDecl {
            name: BINDING_DOCUMENT,
            transport: claims::TRANSPORT,
            mounts: &[claims::DEFAULT_MOUNT, MOUNT_SLASH],
        },
        // No mount, and that is what a console binding IS: its frames arrive on the named stream
        // `claims::CONSOLE_STREAM` rather than at a path, so there is no target for a mount to match
        // and declaring one would be a route nothing could ever address.
        BindingDecl {
            name: BINDING_CONSOLE,
            transport: claims::CONSOLE_TRANSPORT,
            mounts: &[],
        },
    ],
    operations: &[
        unary(ops::OP_DISCOVER.as_str(), D_DISCOVER),
        unary(ops::OP_INITIALIZE.as_str(), D_INITIALIZE),
        unary(ops::OP_PING.as_str(), D_PING),
        unary(ops::OP_TOOLS_LIST.as_str(), D_TOOLS_LIST),
        unary(ops::OP_TOOL_CALL.as_str(), D_TOOL_CALL),
        unary(ops::OP_PROMPTS_LIST.as_str(), D_PROMPTS_LIST),
        unary(ops::OP_PROMPT_GET.as_str(), D_PROMPT_GET),
        unary(ops::OP_RESOURCES_LIST.as_str(), D_RESOURCES_LIST),
        unary(
            ops::OP_RESOURCE_TEMPLATES_LIST.as_str(),
            D_RESOURCE_TEMPLATES_LIST,
        ),
        unary(ops::OP_RESOURCE_READ.as_str(), D_RESOURCE_READ),
        unary(ops::OP_COMPLETION.as_str(), D_COMPLETION),
        unary(ops::OP_TASK_GET.as_str(), D_TASK_GET),
        unary(ops::OP_TASK_UPDATE.as_str(), D_TASK_UPDATE),
        unary(ops::OP_TASK_CANCEL.as_str(), D_TASK_CANCEL),
        streamed(
            ops::OP_SUBSCRIPTIONS_LISTEN.as_str(),
            D_SUBSCRIPTIONS_LISTEN,
        ),
        unary(ops::OP_NOTIFICATION.as_str(), D_NOTIFICATION),
    ],
};

/// The binding one claim transport is served under, where this surface declares one.
///
/// A NAMED QUESTION on the surface's own declaration, for the reason [`crate::claims::declares`] is
/// one: the caller that needs this is the composition root, which holds a claim key and must not
/// compare it against a wire carrier. The streamed transport answers with the document binding's
/// name, because a streamed answer is the same posted document framed differently rather than a
/// second address.
#[must_use]
pub fn binding_for(transport: &str) -> Option<&'static str> {
    if transport == claims::TRANSPORT || transport == claims::STREAM_TRANSPORT {
        return Some(BINDING_DOCUMENT);
    }
    if claims::is_console(transport) {
        return Some(BINDING_CONSOLE);
    }
    None
}

/// The vocabulary row one method has ON one claim transport, where this surface declares it there.
///
/// THE JOIN, and the reason both halves exist. [`crate::ops::row_for`] answers what a method MEANS
/// and this answers whether it can be SAID here — and the two are different questions with
/// different answers for exactly two methods. A decode step that asked only the first would answer
/// `initialize` on the mounted request surface, which is a `-32601` today and which the published
/// conformance suite asserts is a `-32601`.
#[must_use]
pub fn row_on(method: &str, transport: &str) -> Option<&'static ops::MethodRow> {
    let binding = binding_for(transport)?;
    resolve_document(&SURFACE, binding, method)?;
    ops::row_for(method)
}

#[cfg(test)]
#[path = "tests/surface.rs"]
mod tests;
