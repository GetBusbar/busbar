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
//! is [`Transport::upstream_wire`] — the ONE match on this axis in the tree — and the deleted
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
//!
//! ## AND THEN THE AXES CAME APART, WHICH IS WHAT THE SECTION ABOVE WAS DESCRIBING WITHOUT SAYING IT
//!
//! Read the two paragraphs above again. They argue, correctly and at length, that `jsonrpc` and
//! `http+json` are *the same channel* — same socket, same path, same door, "the boundary cannot tell
//! them apart" — and that what separates them is which member names the operation. That is not a
//! statement about a transport. It is a statement about FRAMING, made in a file whose whole subject
//! is which channel carried the bytes, and the enum below held both kinds of word in one closed set
//! because there was nowhere else to put the second kind.
//!
//! There is now. **The two axes are two enums:** [`TransportFamily`] here — http, grpc, stdio,
//! websocket, four channels and nothing else — and [`crate::plane::WireFraming`] with the three
//! wire-format names, because how a plane frames its messages is something the PLANE declares.
//! [`Transport`] is the pair of them: a LEG, which is the thing a request really arrives on.
//!
//! Nothing about the wire moved. All six legs keep their spelling, all six keep their label, and
//! `name()` derives each from the two axes rather than from a list — a leg that declares a framing
//! is named by it, a leg that declares none is named by its channel. What changed is what an edit
//! costs: A2A's fourth binding is a member of the framing enum and touches no channel, and a fifth
//! channel is a member of the family enum and touches no dialect. Under the old shape both of those
//! were the same edit to the same set, which is the mechanism by which a plane's vocabulary ended up
//! inside something called `Transport`.
//!
//! **The variant counts in the two headings above are history and are left as written.** They record
//! decisions that held; they are not a description of the type below.

/// THE CHANNEL a framed operation rides. Closed over ONE axis — which socket, pipe or process the
/// bytes travel through — and over nothing else.
///
/// **What is NOT here, and why the split happened.** This enum used to hold `JsonRpc` and `HttpJson`
/// beside `Http` and `Stdio`. Those two are not channels: they are A2A's two ways of FRAMING a
/// message, spoken down the same HTTP socket, at the same path, differing only in whether a body
/// member or the request line names the operation. A closed set holding a channel next to a dialect
/// makes the two the same kind of word, and a set like that grows an arm every time either axis
/// gains a member. They live on the axis that owns them now — [`crate::plane::WireFraming`] — and a
/// leg is the PAIR, which is what [`Transport`] became.
///
/// Adding a channel is a compile error at every exhaustive match over this axis, and at no site that
/// only cares about framing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportFamily {
    /// ONE HTTP request in, ONE HTTP response out — the exchange every cell in the tree uses today:
    /// the six LLM protocols' POSTs, `handlers/mcp.rs`'s streamable-HTTP `/mcp`, and BOTH of A2A's
    /// JSON-framed bindings. The response may be buffered, SSE-framed or binary event-stream framed;
    /// that choice belongs to the codec and the ingress writer, not here.
    Http,
    /// A gRPC CALL — one message or one message STREAM out, served at the path the `.proto`'s own
    /// package and service name dictate (`/lf.a2a.v1.A2AService/*`) rather than at any path busbar
    /// chose.
    ///
    /// A channel of its own rather than a flavour of [`TransportFamily::Http`] even though it rides
    /// HTTP/2, because it is a different door: its own path space, its own connection semantics, and
    /// a `grpc-status` trailer rather than an HTTP status. What its bytes are SHAPED as is the other
    /// axis's answer, [`crate::plane::WireFraming::Proto`].
    Grpc,
    /// A CHILD PROCESS with a pipe on each side of it: newline-delimited JSON-RPC on its stdin and
    /// stdout, which is what MCP's stdio transport is. OUTBOUND ONLY in this build — busbar is the
    /// parent and the MCP server is the child; busbar is never itself launched as one. See
    /// `mcp/client/stdio.rs` for why that direction and not the other.
    ///
    /// The channel that makes the axis earn its keep. Everything [`TransportFamily::Http`] gets for
    /// free from the shared `reqwest` pool — a destination, a connection, a resolver to SSRF-check, a
    /// peer that was already running — is absent here, and a channel with none of those properties
    /// is precisely the thing that would have become a second dispatch path if it had nowhere to
    /// hang.
    Stdio,
    /// A FULL-DUPLEX FRAMED CONNECTION — one long-lived socket carrying framed messages in BOTH
    /// directions at once, rather than the one-request-one-response exchange
    /// [`TransportFamily::Http`] models. The byte-duplex carrier that
    /// `busbar_substrate::ingress::byte_duplex` pumps: a message `Stream`/`Sink<Vec<u8>>` pair served
    /// until the stream ends, with each side free to send a frame at any time without a prior request
    /// from the other.
    ///
    /// A channel rather than a flavour of [`TransportFamily::Http`] because it is symmetric and
    /// open-ended, so "which frame answers which" is not a property the transport can assume. ARMED
    /// under the `runtime` capability: the neutral WS transport is real on both legs — the ingress
    /// WS-upgrade acceptor (`crate::ingress::duplex_ws`) presents an upgraded socket as the
    /// `serve_messages` channel, and the egress WS dialer (`crate::egress::duplex_ws`) dials an
    /// upstream `wss://` THROUGH `net_guard` and hands back the same channel. A duplex caller selects
    /// this channel and lets the transport open the socket.
    WebSocket,
}

impl TransportFamily {
    /// Every channel, so a site that must cover all of them cannot silently cover some.
    #[cfg_attr(not(test), allow(dead_code))]
    pub const ALL: &'static [TransportFamily] = &[
        TransportFamily::Http,
        TransportFamily::Grpc,
        TransportFamily::Stdio,
        TransportFamily::WebSocket,
    ];

    /// Stable identifier for the channel, and the label a leg falls back to when it declares no
    /// framing of its own — which is why these four spellings are the ones already in every
    /// dashboard.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            TransportFamily::Http => "http",
            TransportFamily::Grpc => "grpc",
            TransportFamily::Stdio => "stdio",
            TransportFamily::WebSocket => "websocket",
        }
    }
}

/// A LEG — one channel and one framing, together, because that pair is what a request actually
/// arrives on and what telemetry has to be able to name.
///
/// It is a PAIR and no longer one closed enum spanning both axes, and the difference is not
/// cosmetic: arming a fourth A2A binding is now a member of [`crate::plane::WireFraming`] and
/// touches no channel, and arming a fifth channel is a member of [`TransportFamily`] and touches no
/// dialect. The old shape made both of those the same edit to the same closed set, which is how a
/// plane's wire vocabulary came to sit in an enum called `Transport` in the first place.
///
/// The six named legs below are the six the tree serves, spelled exactly as they always were, each
/// answering exactly the label it always answered. They are associated constants rather than
/// variants deliberately: which legs are armed is a fact about today, while the two axes are the
/// vocabulary — and only the vocabulary should be closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Transport {
    family: TransportFamily,
    framing: crate::plane::WireFraming,
}

// The six armed legs keep the exact spelling every caller in the tree already uses. Renaming them to
// SCREAMING_CASE would be a rename across six crates to buy a capitalisation, and would bury the one
// thing this diff is: the two axes coming apart.
#[allow(non_upper_case_globals)]
impl Transport {
    /// ONE HTTP request in, ONE HTTP response out, carrying the plane's own body: the six LLM
    /// protocols' POSTs and `handlers/mcp.rs`'s streamable-HTTP `/mcp`. Labelled `http`.
    ///
    /// Unchanged and unrelabelled by A2A's two JSON-framed legs sitting beside it: no instrument
    /// scores these as separate legs of one requirement, which is the only thing that made A2A's two
    /// need separate names.
    pub const Http: Transport = Transport {
        family: TransportFamily::Http,
        framing: crate::plane::WireFraming::Native,
    };
    /// A2A'S JSON-RPC BINDING — one HTTP POST carrying a `{jsonrpc, id, method, params}` envelope,
    /// where A BODY MEMBER names the operation. The `JSONRPC` entry of an agent card's
    /// `supportedInterfaces[]`, and the leg the TCK scores as `jsonrpc:`. Labelled `jsonrpc`.
    pub const JsonRpc: Transport = Transport {
        family: TransportFamily::Http,
        framing: crate::plane::WireFraming::JsonRpc,
    };
    /// A2A'S HTTP+JSON BINDING — the same HTTP exchange over the same channel, with THE REQUEST LINE
    /// naming the operation instead of a body member. `POST /message:send` rather than
    /// `{"method":"SendMessage"}`. Labelled `http+json`.
    ///
    /// A separate leg rather than a flag because the specification models the two as distinct
    /// bindings of ONE agent and the conformance instrument scores each as its own leg of every
    /// requirement. That they share a FAMILY is the point, and is now sayable: the socket cannot tell
    /// them apart, which is exactly why `a2a::receive::invoke` labels them from inside with the leg
    /// it was handed. What rides them is otherwise IDENTICAL — A2A section 11.3 makes the REST
    /// request body the JSON-RPC `params` VERBATIM and the REST success body the `result` VERBATIM.
    pub const HttpJson: Transport = Transport {
        family: TransportFamily::Http,
        framing: crate::plane::WireFraming::HttpJson,
    };
    /// A2A'S gRPC BINDING — its own channel, its own path space, protobuf framing. Labelled `grpc`,
    /// which is the one spelling a channel and a framing share.
    pub const Grpc: Transport = Transport {
        family: TransportFamily::Grpc,
        framing: crate::plane::WireFraming::Proto,
    };
    /// MCP'S STDIO LEG — a child process with a pipe on each side of it. Labelled `stdio`.
    ///
    /// Its framing is [`crate::plane::WireFraming::Native`] and not `JsonRpc`, and that is a reading
    /// rather than an oversight: what rides the pipe IS newline-delimited JSON-RPC, but so is what
    /// rides streamable-HTTP `/mcp`, and neither is DECLARED on the framing axis. The three named
    /// framings exist only because an outside instrument scores them as separate legs of one
    /// requirement set; nothing scores MCP that way, so MCP's body stays the plane's own and this leg
    /// is labelled by its channel.
    pub const Stdio: Transport = Transport {
        family: TransportFamily::Stdio,
        framing: crate::plane::WireFraming::Native,
    };
    /// THE FULL-DUPLEX LEG — one long-lived socket carrying framed messages in both directions.
    /// Labelled `websocket`.
    pub const WebSocket: Transport = Transport {
        family: TransportFamily::WebSocket,
        framing: crate::plane::WireFraming::Native,
    };
}

/// THE TWO MCP CLIENT WIRES a [`Transport`] can select — the neutral hand-off
/// [`Transport::upstream_wire`] returns so the transport axis answers "which channel" without naming
/// the MCP plane's wire vtable, which the plane maps to `&dyn McpWire` on its own side
/// (`mcp/client/wire.rs`). A closed core enum rather than the plane's types, so the axis names no MCP
/// plane type while the wire TYPES stay in the plane that owns them.
// Read on the MCP client leg (`dispatch`) AND on the full-duplex leg (`runtime`, the duplex plane's
// WS dialer): both resolve "which upstream wire" off this axis. With BOTH capabilities compiled out
// there is no upstream wire to select, so it is gated exactly as [`Transport::upstream_wire`] is.
#[cfg(any(feature = "dispatch", feature = "runtime"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamWireKind {
    /// The streamable-HTTP POST wire (`mcp/client/transport.rs`'s `HttpTransport`).
    StreamableHttp,
    /// The child-process stdin/stdout wire (`mcp/client/stdio.rs`'s `StdioWire`).
    Stdio,
    /// A BIDIRECTIONAL FRAMED BYTE WIRE — the full-duplex channel shape [`Transport::WebSocket`]
    /// selects, distinct from the two request/response wires above because bytes flow both ways over
    /// one open connection. ARMED under the `runtime` capability: the neutral WS egress dialer
    /// (`crate::egress::duplex_ws`) is the site that maps this discriminant to a real guarded socket,
    /// so a duplex caller that selects `Transport::WebSocket` resolves the axis to a live wire. The
    /// MCP client leg (`mcp/client/wire.rs`) still has no `Duplex` arm — it never selects it.
    Duplex,
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
    pub const ALL: &'static [Transport] = &[
        Transport::Http,
        Transport::JsonRpc,
        Transport::HttpJson,
        Transport::Grpc,
        Transport::Stdio,
        Transport::WebSocket,
    ];

    /// WHICH CHANNEL this leg rides. A transport fact, and the only question the transport axis is
    /// entitled to answer.
    #[must_use]
    pub fn family(self) -> TransportFamily {
        self.family
    }

    /// WHAT THE MESSAGES ARE FRAMED AS on this leg. A plane's declaration about itself, which is why
    /// the vocabulary lives with the wire-format names rather than here.
    #[must_use]
    pub fn framing(self) -> crate::plane::WireFraming {
        self.framing
    }

    /// Stable identifier — a bounded metric/tracing label, exactly like [`Operation::name`]. It is
    /// the label that says WHICH LEG a request arrived on, which is what makes a per-leg conformance
    /// number readable from busbar's own telemetry now that more than one leg is armed.
    ///
    /// **Derived from the two axes, in that order, and total over both.** A leg that DECLARES a
    /// framing is named by it, because a declared framing is precisely a leg an outside instrument
    /// scores on its own; a leg that declares none is named by its channel. That rule reproduces all
    /// six existing labels exactly — `http`, `jsonrpc`, `http+json`, `grpc`, `stdio`, `websocket` —
    /// and it keeps the property the old match had: neither axis can gain a member without this
    /// function answering for it.
    ///
    /// The declared framings answer their PLANE'S wire-format names, read from the same three
    /// constants `Plane::A2a.wire_format_names()` is built from rather than from strings spelled
    /// again here. That is what makes the metric label, the plane's dialect list and the
    /// `protocolBinding` a served card advertises one vocabulary instead of three that agree today.
    /// (The A2A card's `protocolBinding` for the gRPC leg is `GRPC` and the wire-format name is
    /// `grpc` — one lower-case spelling, so a number read off busbar's telemetry and one read off the
    /// TCK's own stdout name the same leg.)
    #[must_use]
    pub fn name(self) -> &'static str {
        match self.framing.wire_format_name() {
            Some(declared) => declared,
            None => self.family.name(),
        }
    }

    /// THE MCP CLIENT LEG'S ARM — the one and only place the transport's identity is asked on the
    /// path that calls an upstream MCP server, and the reason there is no second one.
    ///
    /// the `structure-lint` gate bans the agnostic core from comparing a transport, and this is what
    /// replaces the comparison it bans: the axis answers "which channel" ONCE and hands back a
    /// NEUTRAL discriminant, so `mcp/client/wire.rs` maps that to its own zero-sized vtable and
    /// `mcp/upstream.rs` sends bytes without this axis naming the plane's wire types. A `match` in
    /// the dispatcher instead would have forked selection, credential planning, timeout handling and
    /// error reporting the moment the second arm landed — the shape the header calls "a second
    /// dispatch path beside the matrix".
    ///
    /// The match on the transport axis stays HERE, where it is legitimate; only the mapping from this
    /// discriminant to the plane's `&'static dyn McpWire` vtable moved into the plane, so the axis no
    /// longer names an MCP plane type. `None` for the three A2A ingress bindings — they are never an
    /// MCP client leg, and `mcp/config.rs` refuses any `transport:` that is not `streamable_http` or
    /// `stdio` at boot, so a `None` here is a config-grammar defect the plane makes loud rather than a
    /// silent wrong channel.
    // Read by the MCP client leg (`mcp/client/wire.rs`, `dispatch`) AND by the full-duplex leg (the
    // duplex plane's WS dialer, `runtime`): both resolve "which upstream wire" off the axis here. With
    // BOTH capabilities compiled out it is dead, so it is gated on their union.
    #[cfg(any(feature = "dispatch", feature = "runtime"))]
    pub fn upstream_wire(self) -> Option<UpstreamWireKind> {
        // A DECLARED framing is an INGRESS binding — the three exist because a conformance instrument
        // scores what arrives, and busbar never dials an upstream in one of them. So the question is
        // asked of the CHANNEL, and only for a leg that declares nothing on the other axis. That
        // reproduces the previous answers exactly, including `None` for all three A2A bindings, and
        // says WHY rather than listing them.
        if self.framing.wire_format_name().is_some() {
            return None;
        }
        match self.family {
            TransportFamily::Http => Some(UpstreamWireKind::StreamableHttp),
            TransportFamily::Stdio => Some(UpstreamWireKind::Stdio),
            // The full-duplex framed wire the axis names neutrally. ARMED under `runtime`: the neutral
            // WS egress dialer (`crate::egress::duplex_ws`) maps this discriminant to a real guarded
            // socket, so a duplex caller that selects `Transport::WebSocket` resolves the axis to a
            // live wire rather than an unreachable. The MCP client leg never selects it.
            TransportFamily::WebSocket => Some(UpstreamWireKind::Duplex),
            TransportFamily::Grpc => None,
        }
    }
}

#[cfg(test)]
#[path = "tests/transport_tests.rs"]
mod tests;
