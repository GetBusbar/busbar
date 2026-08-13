// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE WIRE VTABLE — how one already-built JSON-RPC message reaches an MCP peer and how the answer
//! comes back, with the choice of channel made ONCE and never asked again.
//!
//! ## Why a vtable and not a `match` on the dispatch path
//!
//! [`crate::transport::Transport`] is an axis of the matrix, and `structure-lint.sh` bans the core
//! from comparing one: a dispatch path that can see which transport it is on forks at every step it
//! takes afterwards. So the axis answers the question once —
//! [`crate::transport::Transport::mcp_wire`] is the only `match` on it in the tree — and hands back
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
}

/// ONE CHANNEL a built JSON-RPC message can ride.
///
/// Implementors are ZERO-SIZED and hold no per-upstream state: the sockets live in the pool, the
/// children live in the pool, and the trust lives in the catalogue. A wire is a function with a
/// context handed to it, which is what lets [`crate::transport::Transport::mcp_wire`] return a
/// `&'static` one.
#[async_trait::async_trait]
pub(crate) trait McpWire: Send + Sync {
    /// Send one JSON-RPC message and read the answer, bounded by `leg.timeout`.
    async fn send(
        &self,
        leg: &WireLeg<'_>,
        req: &OutboundRequest,
    ) -> Result<TransportResponse, TransportError>;
}
