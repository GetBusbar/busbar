// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE WIRE VTABLE — how one already-built JSON-RPC message reaches an MCP peer and how the answer
//! comes back, with the choice of channel made ONCE and never asked again.
//!
//! ## Why a vtable and not a `match` on the dispatch path
//!
//! [`busbar_substrate::transport::Transport`] is an axis of the matrix, and `structure-lint.sh` bans the core
//! from comparing one: a dispatch path that can see which transport it is on forks at every step it
//! takes afterwards. So the axis answers the question once —
//! [`busbar_substrate::transport::Transport::upstream_wire`] is the only `match` on it in the tree — and hands back
//! an implementation of this trait. `mcp/upstream.rs` calls [`McpWire::send`] and cannot tell an
//! HTTP POST from a child process's stdin, which is the property that keeps stdio from becoming a
//! second dispatch path beside the first.
//!
//! ## What a wire may and may not do
//!
//! A wire moves BYTES. It does not build the request, read the response's meaning, decide whether
//! the caller was allowed to make it, or mint anything: those are `jsonrpc`, `egress` and
//! `dispatch`, and every one of them runs before a wire is reached. The two implementations are
//! `super::transport::HttpTransport` and `super::stdio::StdioWire`.

use super::jsonrpc::OutboundRequest;
use super::pool::McpConnectionPool;
use super::ssrf::{SsrfPolicy, SsrfRefusal};
use std::time::Duration;

/// What came back from an upstream, before JSON-RPC parsing.
///
/// `status` is an HTTP status for the HTTP wire and a SYNTHETIC `200` for stdio, which has no status
/// line: a stdio peer that answered at all answered, and a peer that did not is a
/// [`TransportError`] rather than a status code. The field stays because the JSON-RPC layer quotes
/// it in its malformed-response diagnostics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TransportResponse {
    pub(crate) status: u16,
    pub(crate) body: Vec<u8>,
    /// THE TRANSPORT-LAYER IDENTITY OF THE PEER THAT ANSWERED THIS LEG: the `sha256/…` SPKI pin
    /// [`busbar_substrate::egress::seam::Buffered::peer_spki`] observed on the TLS hop, verbatim.
    ///
    /// `None` on stdio (no TLS hop exists to observe) and on an HTTP leg that ran over plaintext or
    /// whose certificate could not be walked. `super::super::connect::refresh` is this field's
    /// consumer: a `cert_spki`/`mtls`-pinned registration's declared pin is compared against THIS
    /// value, never against itself, which is what makes the pin an observed fact rather than an
    /// operator's assertion echoed back as its own proof.
    pub(crate) peer_spki: Option<String>,
}

/// Why a transport-level send failed. Kept distinct from a JSON-RPC error: an upstream that answered
/// `-32601` is reachable and healthy, and an upstream that could not be reached is neither. Folding
/// them would make a breaker count protocol disagreements as outages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TransportError {
    /// The destination failed the dispatch-time SSRF check, or a redirect was refused.
    Refused(SsrfRefusal),
    /// The destination could not be REACHED AT ALL: a refused/reset connect, DNS failure, or a TLS
    /// handshake that never completed. Distinct from [`TransportError::Io`] because NOTHING LEFT
    /// BUSBAR — the peer never received a byte of the request — which is the one wire failure the
    /// failover seam's `Stage::BeforeFirstByte` rule may reroute within a pool without any risk of
    /// a duplicate effect. Everything ambiguous (a timeout after connect, a reset mid-response)
    /// stays `Io`, deliberately: the request MAY have landed, so a reroute of it is a retry.
    Unreachable(String),
    /// The connection failed, timed out, or the body could not be read whole — AFTER the
    /// destination was reached, so the request may have been received and acted on.
    Io(String),
    /// A SUPERVISED peer declined to be dispatched to: it is not up yet, it is in restart backoff,
    /// or it crash-looped and the breaker quarantined it. Distinct from [`TransportError::Io`]
    /// because busbar made no attempt to reach anything — the refusal is busbar's own supervision
    /// policy talking, and the operator's remedy is to fix the child or re-approve it, not the
    /// network.
    Supervision(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::Refused(r) => write!(f, "{r}"),
            TransportError::Unreachable(m) => {
                write!(f, "MCP upstream could not be reached: {m}")
            }
            TransportError::Io(m) => write!(f, "MCP upstream transport error: {m}"),
            TransportError::Supervision(m) => write!(f, "MCP upstream is not serving: {m}"),
        }
    }
}

/// Everything a wire needs about ONE leg that is not in the request itself.
///
/// One struct rather than a widening argument list because the two wires need disjoint halves of it
/// — HTTP uses the pool and the addressing policy, stdio uses the server id and the spawn recipe —
/// and a positional signature that grows a parameter per transport is the fork this seam exists to
/// prevent.
pub(crate) struct WireLeg<'a> {
    /// The engine-owned pool: pinned HTTP clients, and the live stdio children.
    pub(crate) pool: &'a McpConnectionPool,
    /// The addressing posture for the dispatch-time SSRF check. Unused by stdio, which reaches no
    /// address — see `super::stdio` for what stands in its place.
    pub(crate) policy: SsrfPolicy,
    /// The wall-clock budget for this leg. Applied by BOTH wires: a child process that stops
    /// answering is exactly as capable of holding a concurrency slot forever as a hung socket.
    pub(crate) timeout: Duration,
    /// The registration id. The stdio child pool's key, so one operator registration owns one child
    /// rather than one per in-flight call.
    pub(crate) server: &'a str,
    /// The operator's spawn recipe, present only on a registration whose transport is stdio.
    pub(crate) command: Option<&'a super::stdio::StdioCommand>,
    /// THE PER-SERVER GRANTS for the three authority asks a peer can make — sampling, elicitation,
    /// roots. All false unless an operator set them.
    ///
    /// On the leg rather than captured anywhere, and read at the moment each message is judged, for
    /// the reason `super::jsonrpc::InputRequiredLoop::may_satisfy` takes them as a parameter: there
    /// is no handshake to authorise once, so a revocation has to bite on the next message rather
    /// than at the end of a stream that has no end. See `super::peer`.
    pub(crate) grants: crate::mcp::config::ServerRequestGrants,
}

/// ONE CHANNEL a built JSON-RPC message can ride.
///
/// Implementors are ZERO-SIZED and hold no per-upstream state: the sockets live in the pool, the
/// children live in the pool, and the trust lives in the catalogue. A wire is a function with a
/// context handed to it, which is what lets [`wire_for`] return a `&'static` one.
#[async_trait::async_trait]
pub(crate) trait McpWire: Send + Sync {
    /// Send one JSON-RPC message and read the answer, bounded by `leg.timeout`.
    async fn send(
        &self,
        leg: &WireLeg<'_>,
        req: &OutboundRequest,
    ) -> Result<TransportResponse, TransportError>;

    /// Send one JSON-RPC NOTIFICATION: no `id`, no answer, and NOTHING IS READ.
    ///
    /// ## Why this is a second trait method and not `send` with the result thrown away
    ///
    /// On stdio the distinction is not cosmetic, it is correctness. A child's stdout is one byte
    /// stream, and a notification produces no line on it. A `send` that wrote a notification and
    /// then waited for a line would either time out — retiring a perfectly healthy child, because
    /// this transport treats a timeout as a crash by design — or, worse, consume the NEXT thing the
    /// child said and hand it back as the answer to a message that has no answer. Every subsequent
    /// call on that child would then be served the previous one's response.
    ///
    /// On HTTP the difference is smaller and still real: a notification is answered `202` with an
    /// empty body, and parsing that as a JSON-RPC response is a guaranteed `Malformed`.
    ///
    /// So the distinction is on the VTABLE, decided once by [`super::verb::UpstreamVerb::
    /// is_notification`], rather than at each call site — where it would be one `if` per verb and
    /// twenty-three chances to get it wrong.
    ///
    /// Called from `super::issue::issue`, which has no inbound caller yet — see that module. The
    /// allow is on this method alone.
    #[allow(dead_code)]
    async fn notify(&self, leg: &WireLeg<'_>, req: &OutboundRequest) -> Result<(), TransportError>;
}

/// RESOLVE A [`Transport`](busbar_substrate::transport::Transport) TO ITS MCP CLIENT WIRE — the plane half of
/// the split the axis makes in [`busbar_substrate::transport::Transport::upstream_wire`]. The axis answers WHICH
/// channel with a neutral discriminant (so it names no plane type); this maps that discriminant to
/// the plane's own zero-sized `&'static dyn McpWire` vtable. The `None` arm is loud for the reason the
/// old `match` was: an A2A binding is never an MCP client leg, and `mcp/config.rs` refuses any
/// `transport:` that is not `streamable_http` or `stdio` at boot, so a value reaching it here is a
/// config-grammar defect, never a silently wrong channel.
pub(crate) fn wire_for(transport: busbar_substrate::transport::Transport) -> &'static dyn McpWire {
    use busbar_substrate::transport::UpstreamWireKind;
    match transport.upstream_wire() {
        Some(UpstreamWireKind::StreamableHttp) => &super::transport::HttpTransport,
        Some(UpstreamWireKind::Stdio) => &super::stdio::StdioWire,
        Some(UpstreamWireKind::Duplex) => unreachable!(
            "transport `{}` is a full-duplex framed wire, not an MCP client leg in this build; \
             mcp/config.rs refuses any `transport:` that is not `streamable_http` or `stdio` at boot",
            transport.name()
        ),
        None => unreachable!(
            "transport `{}` is an A2A ingress binding and is never an MCP client leg; \
             mcp/config.rs refuses any other `transport:` value at boot",
            transport.name()
        ),
    }
}

/// SEND ONE LEG AND COUNT IT — the client direction's observability seam, and the ONLY way this
/// tree reaches [`McpWire::send`].
///
/// ## Why the count lives here and not at each caller
///
/// `busbar_upstream_attempts_total` and `busbar_upstream_failures_total` are the families the MODEL
/// plane's client leg has always emitted (`proxy::engine`), and until this function existed the MCP
/// client leg emitted NOTHING — not an under-labelled series, no series. An operator could see every
/// request arriving at busbar's MCP door and had no signal whatever about the upstream calls busbar
/// itself originated: a registered server that had stopped answering was invisible on `/metrics`.
///
/// The same argument `busbar_substrate::plane::observe` makes for putting the ingress count on the MOUNT rather
/// than in each handler applies to the egress: there are two callers today (`mcp::upstream::call`
/// and `mcp::client::issue::issue`) and a count at each of them is two sites that have to stay in
/// agreement, plus a third the next verb author forgets. So the seam is the wire, the two callers
/// stop naming `wire_for()` themselves, and a leg that is not counted is a leg that did not happen.
///
/// ## The label pair, and why it is the model plane's and not a new one
///
/// `pool` is the operator's REGISTRATION ID (`leg.server`) and `lane` is the transport axis's own
/// word (`busbar_substrate::transport::Transport::name()`) — both operator-configured, neither caller-supplied,
/// so the series count is bounded by the config file exactly as `pool` is on the model plane. A
/// registration is one upstream, so its pool has one lane, and naming the CHANNEL there is what makes
/// `busbar_upstream_failures_total{pool="fs"}` distinguishable between a child process that keeps
/// dying and an HTTPS peer that keeps timing out.
///
/// ## Which failures are counted, and why not all of them
///
/// [`TransportError::Io`] and [`TransportError::Unreachable`] — the socket failed, the connect was
/// refused, DNS or TLS never completed, the deadline expired, or a child died mid-exchange. That is
/// availability, which is what this family means on the model plane too.
///
/// The two are ONE fact to this counter and two facts to the failover seam, and conflating those
/// two audiences is the bug this note exists to prevent. `Unreachable` was split out of `Io` so the
/// seam could tell a hop that duplicates nothing from a hop that might; NOTHING about that split
/// says the peer was healthier. A registration whose every leg is refused at connect is the most
/// down an upstream can be, and it is exactly the failure mode pooled reroute makes routine — so a
/// rule that counted only `Io` would silently stop reporting the failures this feature generates,
/// while still counting their attempts, and an operator's error rate would fall as the outage
/// spread. Both are `DISPOSITION_TRANSIENT`: the peer may come back, and neither says whose fault
/// it was.
///
/// * [`TransportError::Refused`] is busbar's OWN dispatch-time refusal (the SSRF guard, a malformed
///   target). Nothing left busbar and the upstream answered nothing, so counting it would report an
///   outage at a peer that was never contacted. (`Unreachable` is the opposite case despite the
///   similar words: busbar did try to reach the peer and the network answered.)
/// * [`TransportError::Supervision`] is busbar's own fast answer from the crash-loop supervisor, and
///   the crash that armed the supervisor was already counted here as the `Io` failure of the
///   exchange it killed. Counting the refusal too is double accounting.
///
/// A JSON-RPC error inside a 2xx is not counted either: an upstream that answered `-32601` is
/// reachable and healthy, which is the distinction [`TransportError`]'s own note is about.
pub(crate) async fn send(
    transport: busbar_substrate::transport::Transport,
    leg: &WireLeg<'_>,
    req: &OutboundRequest,
) -> Result<TransportResponse, TransportError> {
    busbar_substrate::telemetry::upstream_attempt_on(leg.server, transport.name());
    let out = wire_for(transport).send(leg, req).await;
    if let Err(TransportError::Io(_) | TransportError::Unreachable(_)) = &out {
        busbar_substrate::telemetry::upstream_failure_on(
            leg.server,
            transport.name(),
            busbar_substrate::proxy::DISPOSITION_TRANSIENT,
        );
    }
    out
}

/// DELIVER ONE NOTIFICATION AND COUNT IT — [`send`]'s one-way sibling, counted by the same rule.
///
/// A notification is a leg busbar originated and a peer that cannot be written to is a peer that is
/// down, so it belongs on the same two series. Nothing is read back, so there is no answer to
/// classify beyond the transport's own verdict.
#[allow(dead_code)]
pub(crate) async fn notify(
    transport: busbar_substrate::transport::Transport,
    leg: &WireLeg<'_>,
    req: &OutboundRequest,
) -> Result<(), TransportError> {
    busbar_substrate::telemetry::upstream_attempt_on(leg.server, transport.name());
    let out = wire_for(transport).notify(leg, req).await;
    if let Err(TransportError::Io(_) | TransportError::Unreachable(_)) = &out {
        busbar_substrate::telemetry::upstream_failure_on(
            leg.server,
            transport.name(),
            busbar_substrate::proxy::DISPOSITION_TRANSIENT,
        );
    }
    out
}
