// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `Transport` axis — the CHANNEL a framed operation rides, and the third axis of the matrix.
//!
//! ```text
//! codec   = matrix[protocol][operation]      // UNCHANGED — the codec never learns the transport
//! framing = transport.frame(codec)           // this module, and deliberately thin
//! ```
//!
//! ## WHY THERE IS AN AXIS HERE AT ALL
//!
//! The six LLM protocols are six DIALECTS over ONE channel, so transport never varied and was never
//! modelled. A2A is ONE dialect over THREE (JSON-RPC, HTTP+JSON, gRPC), and gRPC is not the axum
//! catch-all at all. MCP has the same question already latent: `mcp/client/stdio.rs` ships a
//! crash-loop supervisor that is DEAD CODE today, because "a `tools:` entry carrying a stdio
//! transport has no dispatch arm yet". A transport axis is where that arm goes. Without one it
//! becomes a second dispatch path beside the matrix — which is precisely how `mcp/` came to hold
//! 13,069 lines of a core that already existed.
//!
//! ## WHY IT IS A TOP-LEVEL MODULE, BESIDE `operation.rs`
//!
//! An axis of the matrix is not owned by any cell of it. `Operation` sits at `operation.rs` for the
//! same reason, and the two files should be read as a pair: both are coarse, closed tags whose whole
//! value is that adding a variant is a compile error at every site that must now decide something.
//! Putting `Transport` under `proto/` would make it a protocol's property (it is not — that is the
//! entire point of A2A's three bindings of ONE agent), and putting it under `handlers/` would make
//! it a codec's property (it is not — the codec must never learn it).
//!
//! ## THE SECOND VARIANT ARRIVED, AND IT IS `Stdio`
//!
//! The paragraph below is kept as written because it recorded a decision, and the decision held:
//! the axis landed with one variant, the shape was proven by the one that existed, and `Stdio` was
//! added afterwards by driving a real request down it rather than by anticipating one. What that
//! bought is [`Transport::mcp_wire`] — the ONE match on this axis in the tree — and the deleted
//! `mcp/client/stdio.rs` supervisor coming back with a caller instead of an `#![allow(dead_code)]`.
//!
//! ## ONE VARIANT, ON PURPOSE
//!
//! This lands the axis with a single variant for what exists today and nothing else. `Stdio` and
//! `Grpc` are later units and are deliberately absent: an enum with two speculative variants nobody
//! has driven a request through is a design nobody has tested. If the shape is wrong it is wrong
//! here, where the cost is one enum and the sites the compiler names — the same "prove the interface
//! with one subclass" move that landed the parent IR.
//!
//! ## THE ONE QUESTION THIS STEP DELIBERATELY DOES NOT ANSWER
//!
//! A2A's spec calls JSON-RPC and HTTP+JSON two *transports* of one agent, but by the rule this tree
//! already applies they differ only in which member names the operation — and `handlers/mcp.rs`
//! states in its own header that a JSON-RPC envelope is the protocol's DIALECT, "exactly as
//! `{"messages": […]}` is OpenAI's", carried by the codec. Both readings cannot be right. This step
//! does not settle it, because settling it needs a second armed binding to read the answer off
//! rather than an argument: the TCK scores each armed leg separately, so if the legs must be
//! LABELLED separately then [`Transport::Http`] splits at that point. That split costs one enum
//! variant plus the sites the compiler names, which is the property this step exists to buy.

use crate::handlers::{OpDispatch, OperationHandler};
use crate::operation::Operation;

/// The channels busbar's framed operations ride. Closed set — adding one is a compile error at
/// every exhaustive match and at every site that builds a framed cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Transport {
    /// ONE HTTP request in, ONE HTTP response out — the exchange every cell in the tree uses
    /// today: the six LLM protocols' POSTs and `handlers/mcp.rs`'s streamable-HTTP `/mcp`. The
    /// response may be buffered, SSE-framed or binary event-stream framed; that choice belongs to
    /// the codec and the ingress writer, not here, which is why one variant covers all seven cells.
    Http,
    /// A CHILD PROCESS with a pipe on each side of it: newline-delimited JSON-RPC on its stdin and
    /// stdout, which is what MCP's stdio transport is. OUTBOUND ONLY in this build — busbar is the
    /// parent and the MCP server is the child; busbar is never itself launched as one. See
    /// `mcp/client/stdio.rs` for why that direction and not the other.
    ///
    /// The variant that makes the axis earn its keep. Everything [`Transport::Http`] gets for free
    /// from the shared `reqwest` pool — a destination, a connection, a resolver to SSRF-check, a
    /// peer that was already running — is absent here, and a channel with none of those properties
    /// is precisely the thing that would have become a second dispatch path if it had nowhere to
    /// hang.
    Stdio,
}

impl Transport {
    /// Stable identifier — a bounded metric/tracing label, exactly like [`Operation::name`]. It is
    /// the label that says WHICH LEG a request arrived on, which is what makes a per-transport
    /// conformance number readable from busbar's own telemetry once a second transport arms.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Transport::Http => "http",
            Transport::Stdio => "stdio",
        }
    }

    /// THE MCP CLIENT LEG'S ARM — the one and only place the transport's identity is asked on the
    /// path that calls an upstream MCP server, and the reason there is no second one.
    ///
    /// `structure-lint.sh` bans the agnostic core from comparing a transport, and this is what
    /// replaces the comparison it bans: the axis answers "which channel" ONCE and hands back a
    /// vtable, so `mcp/upstream.rs` sends bytes and cannot tell an HTTP POST from a write to a
    /// child's stdin. A `match` in the dispatcher instead would have forked selection, credential
    /// planning, timeout handling and error reporting the moment the second arm landed — which is
    /// the shape the header above calls "a second dispatch path beside the matrix".
    ///
    /// The returned wire is ZERO-SIZED and `'static`: everything per-upstream (sockets, children,
    /// deadlines) rides on `WireLeg`, so this is a table lookup and not a construction.
    pub(crate) fn mcp_wire(self) -> &'static dyn crate::mcp::client::wire::McpWire {
        match self {
            Transport::Http => &crate::mcp::client::transport::HttpTransport,
            Transport::Stdio => &crate::mcp::client::stdio::StdioWire,
        }
    }

    /// `framing = transport.frame(codec)` — the framed cell of the matrix, and the only thing that
    /// builds one. The codec is handed in whole and is not consulted, wrapped or re-implemented: a
    /// transport decides how the codec's bytes reach and leave a peer, never what those bytes say.
    ///
    /// For [`Transport::Http`] the framing is IDENTITY — an HTTP request body IS the codec's request
    /// wire and an HTTP response body IS the codec's response wire — and that is the honest half of
    /// this step. A one-variant axis whose one variant does nothing is exactly what it should be:
    /// the seam is proven to exist and to cost nothing before anything depends on it, the same
    /// posture `OperationHandler::extract_error` took with chat delegating to the reader vtable.
    pub(crate) const fn frame(
        self,
        operation: Operation,
        codec: &'static dyn OperationHandler,
    ) -> OpDispatch {
        OpDispatch {
            operation,
            transport: self,
            op_handler: codec,
        }
    }
}

#[cfg(test)]
#[path = "tests/transport_tests.rs"]
mod tests;
