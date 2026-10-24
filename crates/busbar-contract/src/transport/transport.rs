// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `Transport` axis — the CHANNEL a framed operation rides.
//!
//! ```text
//! codec   = matrix[protocol][operation]      // the codec never learns the transport
//! framing = transport.frame(codec)           // this module, and deliberately thin
//! ```
//!
//! A closed set of channels: adding one is a compile error at every exhaustive match and at every
//! site that builds a framed cell. The axis names channels, never a plane's bindings: which wire
//! formats a plane speaks over a channel is that plane's own declaration (its `wire_format_names`),
//! and the contract names no plane (THE DESIGN, the kinds: "kernel, contract and cleanliness crates × every
//! kind instance = 0").
//!
//! The enum carries no `Serialize`/`Deserialize` and no `repr`: it is not on the wire. Only
//! [`Transport::name`]'s strings are frozen, because they are a bounded metric and tracing label.

/// Wire-format names shared by the plane declarations that state them and the readers that compare
/// against them, spelled once so a declaration and a reader cannot spell one format two ways.
///
/// They are words, not planes: a plane declares the formats it speaks, and these are three of the
/// words it may use. `busbar_kernel::plane::WIRE_*` re-exports them at their historical path.
pub mod plane {
    /// JSON-RPC 2.0: an envelope where a BODY MEMBER names the operation.
    pub const WIRE_JSONRPC: &str = "jsonrpc";

    /// HTTP+JSON: the same exchange with the REQUEST LINE naming the operation instead of a body
    /// member. A served card's upper-cased `HTTP+JSON` is this word lower-cased and nothing else.
    pub const WIRE_HTTP_JSON: &str = "http+json";

    /// The call-per-path binary wire format, as a wire-format name: lower-case here, upper-cased
    /// once by the plane that advertises it.
    pub const WIRE_GRPC: &str = "grpc";
}

/// The channels busbar's framed operations ride. Closed set — adding one is a compile error at
/// every exhaustive match and at every site that builds a framed cell.
///
/// There is no upstream-wire hand-off on this axis: a caller that selects a channel dials it itself.
///
/// ```compile_fail
/// // The axis hands back no plane-shaped wire: there is no wire enum and no selector.
/// let _ = busbar_contract::transport::transport::Transport::WebSocket.upstream_wire();
/// ```
///
/// ```compile_fail
/// let _ = busbar_contract::transport::transport::UpstreamWireKind::Duplex;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    /// ONE HTTP request in, ONE HTTP response out. The response may be buffered or stream-framed;
    /// that choice belongs to the codec and the ingress writer, not here.
    Http,
    /// A CHILD PROCESS with a pipe on each side of it: newline-delimited messages on its stdin and
    /// stdout. Outbound only: busbar is the parent, never itself launched as the child.
    ///
    /// None of what the request-response channel gets from the shared connection pool — a
    /// destination, a connection, a resolver to check — exists here, which is why it is its own
    /// channel rather than a flavour of another.
    Stdio,
    /// A FULL-DUPLEX FRAMED CONNECTION — one long-lived socket carrying framed messages in BOTH
    /// directions at once, rather than the one-request-one-response exchange the request-response
    /// channel models. Each side may send a frame at any time without a prior request from the
    /// other, so "which frame answers which" is not a property the channel can assume.
    WebSocket,
}

impl Transport {
    /// Every transport, so a site that must cover all of them cannot silently cover some: a variant
    /// absent from here is a variant nothing enumerates.
    ///
    /// Its readers are tests: what it buys is that the axis is enumerable, so adding a variant with
    /// a duplicate or off-vocabulary name is a failing test rather than a metric label nobody
    /// notices is wrong.
    #[cfg_attr(not(test), allow(dead_code))]
    pub const ALL: &'static [Transport] =
        &[Transport::Http, Transport::Stdio, Transport::WebSocket];

    /// Stable identifier — a bounded metric/tracing label, exactly like
    /// [`OpVerb::name`](crate::operation::OpVerb::name): the label that says which channel a
    /// request rode.
    pub fn name(self) -> &'static str {
        match self {
            Transport::Http => "http",
            Transport::Stdio => "stdio",
            Transport::WebSocket => "websocket",
        }
    }
}

#[cfg(test)]
#[path = "tests/transport_tests.rs"]
mod tests;
