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
//! ## THREE VARIANTS. THE TWO NEW ONES WERE BOUGHT, NOT GUESSED.
//!
//! The axis landed with ONE variant for what existed and nothing else, on the argument that an enum
//! with speculative variants nobody has driven a request through is a design nobody has tested.
//! `Stdio` and `Grpc` are still absent for exactly that reason: no request rides either. A2A's two
//! served bindings do, which is the whole of why they are here.
//!
//! ## THE QUESTION THE FIRST STEP DEFERRED, AND THE ANSWER THE INSTRUMENT GAVE
//!
//! A2A's spec calls JSON-RPC and HTTP+JSON two *transports* of one agent, but by the rule this tree
//! already applies they differ only in which member names the operation — and `handlers/mcp.rs`
//! states in its own header that a JSON-RPC envelope is the protocol's DIALECT, "exactly as
//! `{"messages": […]}` is OpenAI's", carried by the codec. Both readings cannot be right. The first
//! step did not settle it, and said exactly what would: *the TCK scores each armed leg separately,
//! so if the legs must be LABELLED separately then [`Transport::Http`] splits at that point.*
//!
//! **They must, and it did.** The official A2A TCK reports `jsonrpc:` and `http_json:` as separate
//! rows over ONE requirement set, and a requirement FAILS if any armed leg fails it. "Which leg did
//! this request arrive on" is therefore a fact busbar's own telemetry has to be able to state, and
//! one label covering both cannot state it. So [`Transport::Http`] split into itself plus
//! [`Transport::JsonRpc`] and [`Transport::HttpJson`], and it cost what the first step predicted:
//! the enum variants plus the sites the compiler named.
//!
//! **The split is not a rename of the old variant, and that distinction is load-bearing.**
//! [`Transport::Http`] still carries the six LLM protocols' POSTs, unchanged and unrelabelled: no
//! instrument scores them as separate legs of one requirement, which is the only thing that made
//! A2A's two need separate names, and moving them would have changed a live metric label to prove a
//! point about tidiness. What moved is the A2A plane, which had no `Transport` at all before this.
//!
//! **The names are the plane's wire-format names, not a second vocabulary.**
//! [`Transport::JsonRpc`] and [`Transport::HttpJson`] answer `jsonrpc` and `http+json` — the two
//! entries of `Plane::A2a.wire_format_names()`, read from the same two constants. That is what lets
//! this plane label its own requests now that it no longer can be labelled at the ingress boundary
//! (`Plane::sole_wire_format` answers `None` for a plane with two dialects), and it is why the
//! label an operator reads in Prometheus is the same word the served agent card advertises.

use crate::handlers::{OpDispatch, OperationHandler};
use crate::operation::Operation;

/// The channels busbar's framed operations ride. Closed set — adding one is a compile error at
/// every exhaustive match and at every site that builds a framed cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Transport {
    /// ONE HTTP request in, ONE HTTP response out — the exchange every cell in the tree uses
    /// today: the six LLM protocols' POSTs and `handlers/mcp.rs`'s streamable-HTTP `/mcp`. The
    /// response may be buffered, SSE-framed or binary event-stream framed; that choice belongs to
    /// the codec and the ingress writer, not here, which is why one variant covers all six cells.
    Http,
    /// A2A'S JSON-RPC BINDING — one HTTP POST carrying a `{jsonrpc, id, method, params}` envelope,
    /// where A BODY MEMBER names the operation. The `JSONRPC` entry of an agent card's
    /// `supportedInterfaces[]`, and the leg the TCK scores as `jsonrpc:`.
    JsonRpc,
    /// A2A'S HTTP+JSON BINDING — the same HTTP exchange, with THE REQUEST LINE naming the operation
    /// instead of a body member. `POST /message:send` rather than `{"method":"SendMessage"}`,
    /// `GET /tasks/{id}` rather than `{"method":"GetTask","params":{"id":…}}`.
    ///
    /// A separate variant rather than a flag on [`Transport::JsonRpc`] because the specification
    /// models the two as distinct bindings of ONE agent and the conformance instrument scores each
    /// as its own leg of every requirement. What rides them is otherwise IDENTICAL: A2A section 11.3
    /// makes the REST request body the JSON-RPC `params` VERBATIM and the REST success body the
    /// `result` VERBATIM. That is why arming this one is re-framing rather than translation, and
    /// why the cell below it never learns which of the two it is being spoken over.
    HttpJson,
}

impl Transport {
    /// Every transport, so a site that must cover all of them cannot silently cover some. The same
    /// role `Plane::ALL` plays for its axis: a variant absent from here is a variant nothing
    /// enumerates.
    ///
    /// Its readers are TESTS today, and that is stated rather than hidden behind a production use
    /// invented to justify it. What it buys is that the axis is ENUMERABLE — the label-uniqueness
    /// check and the "these two legs are the A2A plane's two wire formats" check both walk it, so
    /// adding a fourth variant with a duplicate or off-vocabulary name is a failing test rather
    /// than a metric label nobody notices is wrong.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const ALL: &'static [Transport] =
        &[Transport::Http, Transport::JsonRpc, Transport::HttpJson];

    /// Stable identifier — a bounded metric/tracing label, exactly like [`Operation::name`]. It is
    /// the label that says WHICH LEG a request arrived on, which is what makes a per-transport
    /// conformance number readable from busbar's own telemetry now that a second transport is armed.
    ///
    /// The two A2A legs answer their PLANE'S wire-format names, read from the same two constants
    /// `Plane::A2a.wire_format_names()` is built from, rather than from strings spelled again here.
    /// That is what makes the metric label, the plane's dialect list and the `protocolBinding` a
    /// served card advertises one vocabulary instead of three that agree today.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Transport::Http => "http",
            Transport::JsonRpc => crate::plane::WIRE_JSONRPC,
            Transport::HttpJson => crate::plane::WIRE_HTTP_JSON,
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
