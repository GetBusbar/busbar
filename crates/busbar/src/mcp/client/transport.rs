// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STREAMABLE-HTTP STATELESS TRANSPORT (`2026-07-28`) — the primary target, and the seam the
//! stdio transport plugs into beside it.
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
//! An upstream MCP server is not trusted. `crate::proxy::read_capped` is the engine's existing
//! primitive for exactly this and is reused rather than re-hand-rolled, so the cap, the truncation
//! signal and the transport-error signal are the same three the rest of the engine reports.

use super::jsonrpc::OutboundRequest;
use super::pool::McpConnectionPool;
use super::ssrf::{SsrfPolicy, SsrfRefusal};
use std::time::Duration;

/// What came back from an upstream, before JSON-RPC parsing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TransportResponse {
    pub(crate) status: u16,
    pub(crate) body: Vec<u8>,
}

/// Why a transport-level send failed. Kept distinct from a JSON-RPC error: an upstream that answered
/// `-32601` is reachable and healthy, and an upstream that could not be reached is neither. Folding
/// them would make a breaker count protocol disagreements as outages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TransportError {
    /// The destination failed the dispatch-time SSRF check, or a redirect was refused.
    Refused(SsrfRefusal),
    /// The connection failed, timed out, or the body could not be read whole.
    Io(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::Refused(r) => write!(f, "{r}"),
            TransportError::Io(m) => write!(f, "MCP upstream transport error: {m}"),
        }
    }
}

/// The streamable-HTTP transport. Holds no per-upstream state: the pool holds the sockets and the
/// catalogue holds the trust, so this is a function with a pool attached.
#[derive(Debug, Default)]
pub(crate) struct HttpTransport;

impl HttpTransport {
    /// Send one JSON-RPC message and read the answer.
    pub(crate) async fn send(
        pool: &McpConnectionPool,
        req: &OutboundRequest,
        policy: SsrfPolicy,
        timeout: Duration,
    ) -> Result<TransportResponse, TransportError> {
        let (client, _target) = pool
            .client_for(&req.url, policy, timeout)
            .await
            .map_err(TransportError::Refused)?;
        let mut builder = client.post(&req.url);
        for (name, value) in &req.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        let resp = builder
            .body(req.body.clone())
            .send()
            .await
            // `without_url()`: a reqwest error's Display carries the URL, and an operator may have
            // embedded userinfo in it. Same treatment the OAuth minter gives its errors.
            .map_err(|e| TransportError::Io(e.without_url().to_string()))?;
        let status = resp.status().as_u16();
        let location = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        super::ssrf::refuse_redirect(status, location.as_deref())
            .map_err(TransportError::Refused)?;
        let is_sse = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|ct| ct.starts_with("text/event-stream"))
            .unwrap_or(false);
        let cap = crate::proxy::max_upstream_buffered_bytes();
        let (raw, read_end) = crate::proxy::read_capped(resp, cap).await;
        match read_end {
            crate::proxy::ReadEnd::Complete => {}
            crate::proxy::ReadEnd::Truncated => {
                return Err(TransportError::Io(format!(
                    "upstream response exceeded the {cap}-byte cap; a truncated JSON-RPC response \
                     is not parsed"
                )))
            }
            crate::proxy::ReadEnd::TransportError => {
                return Err(TransportError::Io(
                    "upstream connection failed mid-response; a partial JSON-RPC response is not \
                     parsed"
                        .to_string(),
                ))
            }
        }
        let body = if is_sse {
            // CAPTURE THE PROGRESS BEFORE DISCARDING THE REST. Everything ahead of the final frame
            // used to be dropped here, progress included — and the loss was documented rather than
            // fixed (`last_sse_data`'s own comment). Progress is the one non-final frame busbar's
            // caller is entitled to, so it is lifted into the per-request slot on the way past.
            //
            // Silent when there is no slot: a request outside `ingress`'s scope simply has nowhere
            // to put them, which is the correct answer rather than an error.
            let progress = progress_frames(&raw);
            if !progress.is_empty() {
                let _ = super::super::UPSTREAM_PROGRESS.try_with(|slot| {
                    if let Ok(mut v) = slot.lock() {
                        v.extend(progress);
                    }
                });
            }
            last_sse_data(&raw)
        } else {
            raw.to_vec()
        };
        Ok(TransportResponse { status, body })
    }
}

/// Every `notifications/progress` frame in an SSE body, in arrival order.
///
/// Only that method: a stream may carry other notifications, and relaying whatever happened to be
/// there would let an upstream inject arbitrary JSON-RPC into busbar's answer to its own caller.
/// This is an allowlist of exactly one method for exactly that reason.
pub(crate) fn progress_frames(raw: &[u8]) -> Vec<serde_json::Value> {
    String::from_utf8_lossy(raw)
        .lines()
        .filter_map(|l| l.strip_prefix("data:"))
        .filter_map(|d| serde_json::from_str::<serde_json::Value>(d.trim()).ok())
        .filter(|v| v.get("method").and_then(|m| m.as_str()) == Some("notifications/progress"))
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

#[cfg(test)]
#[path = "tests/transport_tests.rs"]
mod transport_tests;
