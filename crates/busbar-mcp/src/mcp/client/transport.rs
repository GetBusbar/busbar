// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STREAMABLE-HTTP STATELESS TRANSPORT (`2026-07-28`) — the primary target, and the seam the
//! second transport would plug in beside it. There is no second transport in this build.
//!
//! ## What "stateless" removes, and what that buys
//!
//! There is no `initialize`, so there is nothing to hand shake; no `Mcp-Session-Id`, so there is
//! nothing to pin a client to one server instance; no GET stream, so there is nothing to resume.
//! Every request is self-describing (`params._meta` carries the protocol version and the client's
//! capabilities), which is why a plain round-robin load balancer in front of an upstream is fine and
//! why busbar's own connection reuse carries no authority: a reused socket negotiated nothing, so
//! there is nothing on it a revocation would have to invalidate.
//!
//! The one thing that survives from the streaming design is the RESPONSE content type: `text/event-
//! stream` is a permitted answer to a POST. So the reader accepts either, and an SSE answer is
//! reduced to the last `data:` payload — the JSON-RPC response the stream was carrying. Anything
//! else in the stream is progress notification, which this transport has no caller for yet.
//!
//! ## Every send is guarded, and the guard is not optional
//!
//! [`HttpTransport::send`] goes through `super::pool`, which resolves-then-pins before it hands back
//! a client, so the destination cannot be one the SSRF check never saw. It then refuses a 3xx
//! explicitly, in addition to the client's `redirect: none`, for the reason `super::ssrf` gives: two
//! mechanisms, because one of them stops the request being made and the other stops a redirect being
//! silently reported as a parse failure.
//!
//! ## The response body is CAPPED
//!
//! An upstream MCP server is not trusted. `busbar_core::proxy::read_capped` is the engine's existing
//! primitive for exactly this and is reused rather than re-hand-rolled, so the cap, the truncation
//! signal and the transport-error signal are the same three the rest of the engine reports.

use busbar_core::egress::seam::{self, HopSpec};

use super::jsonrpc::OutboundRequest;
use super::wire::{McpWire, TransportError, TransportResponse, WireLeg};

/// The streamable-HTTP transport. Holds no per-upstream state: the pool holds the sockets and the
/// catalogue holds the trust, so this is a function with a pool attached.
#[derive(Debug, Default)]
pub(crate) struct HttpTransport;

/// The vtable arm [`busbar_core::transport::Transport::Http`] hands an MCP leg to. It unpacks the parts of
/// the leg an HTTP send needs and forwards to the inherent [`HttpTransport::send`], which the
/// refresh path in `mcp::connect` reaches through the same vtable.
///
/// The leg is forwarded WHOLE rather than unpacked into the three fields an HTTP POST needs,
/// because the INBOUND half of this wire — the server-originated frames on an SSE answer — needs
/// the registration they arrived from and the pool's refresh triggers to put an accepted one in.
#[async_trait::async_trait]
impl McpWire for HttpTransport {
    async fn send(
        &self,
        leg: &WireLeg<'_>,
        req: &OutboundRequest,
    ) -> Result<TransportResponse, TransportError> {
        HttpTransport::send(leg, req).await
    }

    /// A NOTIFICATION over streamable HTTP is an ordinary POST whose response body is discarded.
    ///
    /// The STATUS is still checked, because the two facts a notification's response carries are the
    /// only two busbar can learn: it was accepted, or the peer refused it. A `4xx`/`5xx` swallowed
    /// here would make "busbar told the upstream" a claim with no evidence behind it — which is the
    /// shape of a notification path that silently does nothing.
    async fn notify(&self, leg: &WireLeg<'_>, req: &OutboundRequest) -> Result<(), TransportError> {
        let response = HttpTransport::send(leg, req).await?;
        if !(200..300).contains(&response.status) {
            return Err(TransportError::Io(format!(
                "the upstream refused a JSON-RPC notification with HTTP {}; a notification has no \
                 reply, so the status is the only evidence it was accepted",
                response.status
            )));
        }
        Ok(())
    }
}

impl HttpTransport {
    /// Send one JSON-RPC message and read the answer.
    pub(crate) async fn send(
        leg: &WireLeg<'_>,
        req: &OutboundRequest,
    ) -> Result<TransportResponse, TransportError> {
        // THE PLANE POOL GUARD, PLANE-SIDE AND UNCHANGED: resolve-then-pin (the SSRF check + typed
        // `SsrfRefusal`) before any hop, so the destination cannot be one the check never saw. The
        // returned client is not used to run the hop any more — the hostless egress seam builds its
        // own client host-side to the SAME `build_pinned_client` posture — but the pool still owns the
        // guard, the pin and the pinned `target` this send connects to.
        let (_client, target) = leg
            .pool
            .client_for(&req.url, leg.policy)
            .await
            .map_err(TransportError::Refused)?;

        let cap = busbar_core::proxy::max_upstream_buffered_bytes();
        // OWNED inputs for the blocking hop — the seam's `HopSpec` borrows these, and `leg` (with its
        // pool triggers and the `UPSTREAM_PROGRESS` task-local) must NOT cross into `spawn_blocking`,
        // so the SSE frame handling stays async-side below where `leg` is live.
        let url = req.url.clone();
        let headers = req.headers.clone();
        let body = req.body.clone();
        // THE LEG'S DEADLINE, on the desc. The seam applies `timeout_ms` to the request itself (and its
        // connect-head wait), so — exactly as the request-level timeout did before — the leg's own
        // budget binds THIS send rather than whatever deadline first built the cached client.
        let timeout = leg.timeout;
        // mcp URLs are IP-literals so `resolved_addr_kind = 0` re-resolution would be the identity, but
        // hand the pinned address over anyway (belt-and-suspenders: the host connects HERE and looks up
        // nothing), keeping SNI/cert-name on the URL host.
        let resolved = target.socket_addr().ip();

        // THE HOP ONLY, on the blocking pool. `spawn_blocking` keeps the seam's per-open thread+runtime
        // off the dispatch reactor worker; the guard above and the SSE handling below stay on the async
        // side. Wire bytes are the same `build_pinned_client` reqwest codec (h2/ALPN/TLS unchanged).
        let hop = tokio::task::spawn_blocking(move || {
            let spec = HopSpec {
                verb: "POST",
                url: &url,
                headers: &headers,
                body: &body,
                // The SSRF pool guard already judged this hop plane-side; the host re-judges nothing
                // when a pinned address is supplied, so these stances are moot here.
                allow_private: true,
                allow_plaintext: true,
                client_identity_ref: 0,
                trust_anchor_ref: 0,
                timeout,
                resolved_addr: Some(resolved),
            };
            seam::with_hostless(|scope| seam::buffered(scope, &spec, cap))
        })
        .await
        .map_err(|e| TransportError::Io(format!("the upstream hop task failed to run: {e}")))?;

        let buffered = hop.map_err(|f| {
            // A CONNECT-phase failure (refused, DNS, TLS handshake) means the request was never
            // transmitted, so the failover seam may reroute it without duplicating anything;
            // everything else (a timeout after connect) stays `Io`. The seam mirrors reqwest's own
            // `is_connect()` classifier into `EgressFailClass::Connect`, and its `cause` is the SAME
            // url-free flattened chain this transport built by hand — `without_url()` then the source
            // chain — so the operator line is byte-identical.
            match f.class {
                busbar_plugin::hot::EgressFailClass::Connect => {
                    TransportError::Unreachable(f.cause)
                }
                _ => TransportError::Io(f.cause),
            }
        })?;

        let status = buffered.status;
        let location = buffered.location;
        super::ssrf::refuse_redirect(status, location.as_deref())
            .map_err(TransportError::Refused)?;
        let is_sse = buffered
            .content_type
            .as_deref()
            .map(|ct| ct.starts_with("text/event-stream"))
            .unwrap_or(false);
        let raw = buffered.body;
        match buffered.end {
            busbar_core::proxy::ReadEnd::Complete => {}
            busbar_core::proxy::ReadEnd::Truncated => {
                return Err(TransportError::Io(format!(
                    "upstream response exceeded the {cap}-byte cap; a truncated JSON-RPC response \
                     is not parsed"
                )))
            }
            busbar_core::proxy::ReadEnd::TransportError => {
                return Err(TransportError::Io(
                    "upstream connection failed mid-response; a partial JSON-RPC response is not \
                     parsed"
                        .to_string(),
                ))
            }
        }
        let body = if is_sse {
            // EVERY SERVER-ORIGINATED FRAME IS CLASSIFIED AND HANDLED BEFORE THE REST IS DISCARDED.
            // Everything ahead of the final frame used to be dropped here — and a dropped frame is
            // not a handled frame. See [`read_server_frames`].
            read_server_frames(leg, &raw);
            last_sse_data(&raw)
        } else {
            raw
        };
        Ok(TransportResponse { status, body })
    }
}

// ── WHAT AN UPSTREAM SAYS BACK, ON THIS CARRIER ─────────────────────────────────────────────────
//
// Revision `2026-07-28` removed the standalone GET stream; it did not remove server-to-client
// messages. They ride the SSE response of a POST busbar made, and that response is this leg's whole
// inbound surface.
//
// THE CLASSIFIER IS NOT HERE. `super::peer::classify` is the one table that decides what a peer's
// message IS, and `super::peer::ServerNotification::effect` is the one table that decides what
// busbar DOES about it — both shared with the stdio leg, which reads the same messages off a
// child's stdout. Two carriers, one meaning. A second table here would be a second answer to "may
// this notification move busbar's catalogue", and the one that got fixed would not be the one that
// was wrong.
//
// WHAT DIFFERS BETWEEN THE CARRIERS, and it is exactly one thing: stdio ANSWERS a peer's request,
// because a child's stdin is a channel busbar can write a reply on and a child left waiting on one
// is a child that hangs. An SSE response body is not a channel — it is the answer to a POST that has
// already been sent — so a request arriving here CANNOT be answered, and it is refused by being
// recorded and dropped. That is a transport fact, and it lives in the transport rather than as a
// branch on the axis somewhere that can see both.

/// Classify and handle every server-originated frame in an SSE body, in arrival order.
///
/// Returns what it classified, so a test can read exactly what the transport read from exactly the
/// bytes the transport read it from. The return value is unused on the dispatch path: the EFFECTS
/// are the point, and they are observable where they land — the progress channel, and the pool's
/// refresh triggers.
pub(crate) fn read_server_frames(leg: &WireLeg<'_>, raw: &[u8]) -> Vec<super::peer::ServerMessage> {
    use super::peer::{NotificationEffect, ServerMessage};
    let mut seen = Vec::new();
    for frame in sse_frames(raw) {
        // `None` is the RESPONSE this POST was made for. It is not a server message and it is not
        // consumed here — `last_sse_data` returns it to the caller, which correlates it against the
        // id it sent. Making a response consumable in this loop would create a second place one can
        // be taken, which is the desynchronisation `super::peer`'s header exists to prevent.
        let Some(message) = super::peer::classify(&frame) else {
            continue;
        };
        match &message {
            ServerMessage::Notification(n) => match n.effect() {
                // THE TIMING, NEVER THE CONTENT. The frame's body is not read: an accepted trigger
                // records the SERVER'S NAME and the authoritative `tools/list` is re-fetched and
                // re-hashed by the sweep exactly as a scheduled refresh would do it.
                NotificationEffect::BringRefreshForward => {
                    let accepted = leg
                        .pool
                        .triggers
                        .signal(leg.server, busbar_core::store::now_ms());
                    tracing::debug!(
                        server = %leg.server,
                        notification = ?n,
                        accepted,
                        "mcp http: peer signalled a catalogue change"
                    );
                }
                // `resources/updated`: the refresh trigger EXACTLY as above, plus the one field
                // read — the announced uri, recorded for the server-leg relay and believed
                // nowhere. See `super::pool::ResourceUpdates` for the bounds.
                NotificationEffect::RelayResourceUpdate => {
                    let accepted = leg
                        .pool
                        .triggers
                        .signal(leg.server, busbar_core::store::now_ms());
                    if let Some(uri) = frame.pointer("/params/uri").and_then(|u| u.as_str()) {
                        leg.pool.updates.record(leg.server, uri);
                    }
                    tracing::debug!(
                        server = %leg.server,
                        notification = ?n,
                        accepted,
                        "mcp http: peer announced a resource update"
                    );
                }
                // THE WHOLE FRAME, and it is safe to relay verbatim for one reason only: this arm
                // is reached ONLY for `notifications/progress`, which `super::peer`'s closed table
                // decides. An arm that relayed whatever notification arrived would let an upstream
                // inject arbitrary JSON-RPC into busbar's answer to its own caller.
                //
                // Silent when there is no slot: a leg outside `ingress`'s scope simply has nowhere
                // to put a progress frame, which is the correct answer rather than an error.
                NotificationEffect::RelayProgress => {
                    let _ = super::super::UPSTREAM_PROGRESS.try_with(|slot| {
                        if let Ok(mut ch) = slot.lock() {
                            ch.frames.push(frame.clone());
                        }
                    });
                }
                NotificationEffect::Log => tracing::debug!(
                    server = %leg.server,
                    notification = ?n,
                    "mcp http: peer notification recorded"
                ),
            },
            ServerMessage::UnknownNotification(method) => tracing::debug!(
                server = %leg.server,
                method = %method,
                "mcp http: peer sent a notification busbar does not implement; dropped"
            ),
            // A REQUEST, ON A CARRIER WITH NO REPLY CHANNEL. Recorded and dropped — and, critically,
            // never adopted as the answer to what busbar actually asked, which is what a reader that
            // took the first frame of the stream would do. The three authority asks are refused here
            // by the absence of any way to satisfy them, which is a stronger refusal than the grant
            // gate stdio applies: over this carrier busbar cannot say yes even if an operator
            // granted it.
            ServerMessage::Request { verb, .. } => tracing::debug!(
                server = %leg.server,
                verb = ?verb,
                "mcp http: peer sent a request on an SSE response body, which carries no reply \
                 channel; recorded and not answered"
            ),
            ServerMessage::UnknownRequest { method, .. } => tracing::debug!(
                server = %leg.server,
                method = %method,
                "mcp http: peer sent an unknown request on an SSE response body; recorded and not \
                 answered"
            ),
        }
        seen.push(message);
    }
    seen
}

/// Every `data:` payload in an SSE body, parsed, in arrival order.
///
/// Multi-line `data:` fields are NOT joined here — `last_sse_data` owns that rule for the frame it
/// returns. A frame this cannot parse is skipped rather than reported: a peer that writes a
/// non-JSON `data:` line has said nothing busbar can act on, and the RESPONSE is judged separately
/// by the JSON-RPC reader, which is the right layer for that complaint.
fn sse_frames(raw: &[u8]) -> Vec<serde_json::Value> {
    String::from_utf8_lossy(raw)
        .lines()
        .filter_map(|l| l.strip_prefix("data:"))
        .filter_map(|d| serde_json::from_str::<serde_json::Value>(d.trim()).ok())
        .collect()
}

/// Every `notifications/progress` frame in an SSE body, in arrival order.
///
/// Expressed over the SHARED classifier rather than over a method-name test of its own, so "which
/// frames may reach busbar's caller" is decided in exactly one place — `super::peer`'s effect table
/// — and this function cannot come to disagree with the transport about it.
#[cfg_attr(any(not(test), feature = "extracted"), allow(dead_code))]
pub(crate) fn progress_frames(raw: &[u8]) -> Vec<serde_json::Value> {
    use super::peer::{NotificationEffect, ServerMessage};
    sse_frames(raw)
        .into_iter()
        .filter(|frame| {
            matches!(
                super::peer::classify(frame),
                Some(ServerMessage::Notification(n)) if n.effect() == NotificationEffect::RelayProgress
            )
        })
        .collect()
}

/// The payload of the LAST `data:` field in an SSE body.
///
/// Last rather than first: a POST answered as a stream may carry progress notifications ahead of the
/// response, and the response is what the stream was opened to deliver. Taking the first would
/// deliver a notification and call it a result.
///
/// Multi-line `data:` fields are joined with `\n`, which is what the SSE grammar says they mean. A
/// body with no `data:` at all yields empty, which the JSON-RPC parser then reports as malformed —
/// the right layer for that complaint.
fn last_sse_data(raw: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(raw);
    let mut current: Option<Vec<String>> = None;
    let mut last: Option<Vec<String>> = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("data:") {
            current
                .get_or_insert_with(Vec::new)
                .push(rest.strip_prefix(' ').unwrap_or(rest).to_string());
        } else if line.is_empty() {
            if let Some(done) = current.take() {
                last = Some(done);
            }
        }
    }
    if let Some(done) = current.take() {
        last = Some(done);
    }
    last.map(|parts| parts.join("\n").into_bytes())
        .unwrap_or_default()
}

#[cfg(all(test, not(feature = "extracted")))]
#[path = "tests/transport_tests.rs"]
mod transport_tests;

// THE INBOUND HALF of this wire: what an upstream says back on the SSE answer, and what busbar does
// about it. It hangs off the transport rather than off `super::peer` because the CLASSIFIER is
// proven there, shared with stdio — what is proven here is the CARRIER: that the frames are found on
// an SSE body, that the effects land, and that the answer to the POST survives them all intact.
#[cfg(all(test, not(feature = "extracted")))]
#[path = "tests/http_peer_tests.rs"]
mod http_peer_tests;
