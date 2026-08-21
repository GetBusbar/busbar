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
//! catch-all at all. MCP had the same question latent, and this release ANSWERED it by BUYING the
//! arm rather than by subtraction: [`Transport::Stdio`] dispatches to a real child-process
//! supervisor at `mcp/client/stdio.rs`, and the tokio `process` feature is back in
//! `crates/busbar/Cargo.toml` with the argument its own comment used to demand — a caller.
//!
//! That history is worth keeping, because it is the axis earning its keep twice. The supervisor was
//! written once, had NOTHING dispatch to it, and was deleted along with the `process` feature for
//! exactly that reason. What brought it back was this axis: a place for the arm to hang. Without one
//! it becomes a second dispatch path beside the matrix — which is precisely how `mcp/` came to hold
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
//! ## FIVE VARIANTS. THE FOUR NEW ONES WERE BOUGHT, NOT GUESSED.
//!
//! The paragraph below is kept as written because it recorded a decision, and the decision held:
//! the axis landed with one variant, the shape was proven by the one that existed, and every later
//! variant was added by driving a real request down it rather than by anticipating one. A2A's three
//! bindings arrived on the commits that armed them. `Stdio` arrived the same way, and what it bought
//! is [`Transport::mcp_wire`] — the ONE match on this axis in the tree — and the deleted
//! `mcp/client/stdio.rs` supervisor coming back with a caller instead of an `#![allow(dead_code)]`.
//!
//! ## ONE VARIANT, ON PURPOSE
//!
//! The axis landed with ONE variant for what existed and nothing else, on the argument that an enum
//! with speculative variants nobody has driven a request through is a design nobody has tested.
//! A2A's three served bindings ride requests, which is the whole of why they are here — and each
//! arrived on the commit that armed it, not ahead of it.
//!
//! What the extra variants BUY is the thing the one-variant step could only claim. A2A is one
//! dialect over several channels, and the channels differ in ways no codec can be asked to know: an
//! HTTP request body IS the codec's request wire, and a gRPC request body is a length-prefixed
//! protobuf frame carrying a message whose canonical JSON mapping is that wire. That difference is
//! FRAMING, it lives here, and the A2A codec below it never learns which channel spoke.
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
//! [`Transport::JsonRpc`], [`Transport::HttpJson`] and [`Transport::Grpc`] answer `jsonrpc`,
//! `http+json` and `grpc` — the three entries of `Plane::A2a.wire_format_names()`, read from the
//! same three constants. That is what lets this plane label its own requests now that it no longer
//! can be labelled from the PLANE at the ingress boundary (`Plane::sole_wire_format` answers `None`
//! for a plane with several dialects), and it is why the label an operator reads in Prometheus is
//! the same word the served agent card advertises.
//!
//! **Two of the three share a door and one has its own, and that is why both labelling mechanisms
//! exist.** `jsonrpc` and `http+json` are both spoken at `/a2a`, so the boundary cannot tell them
//! apart and `a2a::receive::invoke` labels them from inside with the leg it was handed. gRPC is
//! spoken at `/lf.a2a.v1.A2AService`, a door of its own, so `PlaneDispatch::wire_format_of` can name
//! it from the claim before any handler runs — which is what still counts a refusal that reaches no
//! handler at all.

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
    /// ONE gRPC call in, one message or one message STREAM out — the A2A specification's third
    /// binding, served at the path the `.proto`'s own package and service name dictate
    /// (`/lf.a2a.v1.A2AService/*`) rather than at any path busbar chose.
    ///
    /// It is a variant rather than a flavour of [`Transport::Http`] even though it rides HTTP/2,
    /// because the two differ in exactly the thing this axis exists to name: the FRAMING. On
    /// `Http` the request body is the codec's request wire; here it is a length-prefixed protobuf
    /// frame whose message must be transcoded to that wire before any codec sees it, and the reply
    /// must be transcoded back and terminated with a `grpc-status` trailer rather than an HTTP
    /// status. Nothing below this line knows that, which is the property being bought.
    Grpc,
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
    /// Every transport, so a site that must cover all of them cannot silently cover some. The same
    /// role `Plane::ALL` plays for its axis: a variant absent from here is a variant nothing
    /// enumerates.
    ///
    /// Its readers are TESTS today, and that is stated rather than hidden behind a production use
    /// invented to justify it. What it buys is that the axis is ENUMERABLE — the label-uniqueness
    /// check and the "these legs are the A2A plane's wire formats" check both walk it, so adding a
    /// variant with a duplicate or off-vocabulary name is a failing test rather than a metric label
    /// nobody notices is wrong.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const ALL: &'static [Transport] = &[
        Transport::Http,
        Transport::JsonRpc,
        Transport::HttpJson,
        Transport::Grpc,
        Transport::Stdio,
    ];

    /// Stable identifier — a bounded metric/tracing label, exactly like [`Operation::name`]. It is
    /// the label that says WHICH LEG a request arrived on, which is what makes a per-transport
    /// conformance number readable from busbar's own telemetry now that a second transport is armed.
    ///
    /// The three A2A legs answer their PLANE'S wire-format names, read from the same three constants
    /// `Plane::A2a.wire_format_names()` is built from, rather than from strings spelled again here.
    /// That is what makes the metric label, the plane's dialect list and the `protocolBinding` a
    /// served card advertises one vocabulary instead of three that agree today.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Transport::Http => "http",
            Transport::JsonRpc => crate::plane::WIRE_JSONRPC,
            Transport::HttpJson => crate::plane::WIRE_HTTP_JSON,
            // The A2A card's `protocolBinding` for this leg is `GRPC` and the plane's wire-format
            // name is `grpc`; one lower-case spelling, so a per-transport conformance number read
            // off busbar's telemetry and one read off the TCK's own stdout name the same leg.
            Transport::Grpc => crate::plane::WIRE_GRPC,
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
    // The one match on the transport axis, and it hands back an MCP client wire — a type that only
    // exists when the MCP plane is compiled in. It is called ONLY from `crate::mcp` (the client
    // legs), so with `plane-mcp` off it is dead; gating it here removes the last non-mcp source that
    // would name an `mcp` type, without relocating the match off the transport axis.
    #[cfg(feature = "plane-mcp")]
    pub(crate) fn mcp_wire(self) -> &'static dyn crate::mcp::client::wire::McpWire {
        match self {
            Transport::Http => &crate::mcp::client::transport::HttpTransport,
            Transport::Stdio => &crate::mcp::client::stdio::StdioWire,
            // The three A2A bindings. They are legs of the AGENT plane's own ingress and no
            // `tools:` entry can be configured onto one — `mcp/config.rs` accepts
            // `streamable_http` and `stdio` and nothing else, so a value that would reach here is
            // refused at boot with a named error rather than at first dispatch. The arm is loud
            // rather than falling back to `HttpTransport`, because a silent fallback would turn a
            // future config-grammar mistake into an MCP call quietly dispatched over the wrong
            // channel, which is the exact failure this vtable exists to make impossible.
            Transport::JsonRpc | Transport::HttpJson | Transport::Grpc => {
                unreachable!(
                    "transport `{}` is an A2A ingress binding and is never an MCP client leg; \
                     mcp/config.rs refuses any other `transport:` value at boot",
                    self.name()
                )
            }
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
