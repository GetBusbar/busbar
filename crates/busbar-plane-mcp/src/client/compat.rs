// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CLIENT HALF OF THE SESSION REVISIONS: how busbar, calling an upstream, speaks
//! `2025-11-25`, `2025-06-18` or `2024-11-05` when the upstream does not speak the stateless
//! `2026-07-28` revision busbar sends by default (OWNER 2026-09-29 compat scope; MCP-COMPAT C5).
//!
//! Every request busbar issues is built once, in the stateless shape, by [`super::jsonrpc`] and
//! [`super::verb`]. This module does not build a second set: it LOWERS a built request into a
//! session revision ([`lower_request`]) and reads the upstream's answers back. The ladder itself
//! (stateless, then `initialize`, then the event stream, moving only on a refusal) is
//! [`crate::revision::next_step`]; [`probe_outcome`] is what feeds it.
//!
//! Pure: no I/O, no clock, no randomness. The caller owns the connection and the memory of what
//! each upstream negotiated ([`crate::session::UpstreamTable`]).

use serde_json::Value;

use super::jsonrpc::OutboundRequest;
use crate::codec::{
    CODE_INVALID_PARAMS, CODE_INVALID_REQUEST, CODE_METHOD_NOT_FOUND,
    CODE_UNSUPPORTED_PROTOCOL_VERSION, H_MCP_METHOD, H_MCP_NAME, H_PROTOCOL_VERSION,
    META_CLIENT_CAPABILITIES, META_PROTOCOL_VERSION,
};
use crate::revision::{Revision, StepOutcome};

/// The response header an upstream names its session in, and the request header busbar carries it
/// back in.
pub const H_SESSION: &str = crate::adapt::H_SESSION_ID;

/// Reads what a stateless request's answer says about the upstream's revision.
///
/// A status in `400..500`, or a JSON-RPC error that says the method, the request shape or the
/// revision is not understood, is a refusal of the revision and moves the ladder. A `5xx`, or no
/// answer, says nothing about the revision. Anything else answered.
#[must_use]
pub fn probe_outcome(status: u16, body: &[u8]) -> StepOutcome {
    if (500..600).contains(&status) {
        return StepOutcome::Unreachable;
    }
    if (400..500).contains(&status) {
        return StepOutcome::Refused4xx;
    }
    let code = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v.pointer("/error/code").and_then(Value::as_i64));
    match code {
        Some(c)
            if c == CODE_METHOD_NOT_FOUND
                || c == CODE_INVALID_REQUEST
                || c == CODE_INVALID_PARAMS
                || c == CODE_UNSUPPORTED_PROTOCOL_VERSION =>
        {
            StepOutcome::Refused4xx
        }
        _ => StepOutcome::Answered,
    }
}

/// The `initialize` request, sent to `url` with the credential `template` carries. `client_version`
/// is the caller's own version string (the plane reads no build metadata).
#[must_use]
pub fn initialize_request(
    template: &OutboundRequest,
    url: &str,
    asked: Revision,
    request_id: u64,
    client_version: &str,
) -> OutboundRequest {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "method": crate::adapt::METHOD_INITIALIZE,
        "params": {
            "protocolVersion": asked.wire(),
            "capabilities": {},
            "clientInfo": { "name": "busbar", "version": client_version },
        },
    });
    session_envelope(template, url, &body, None, None)
}

/// `notifications/initialized`, completing the opening of `revision`'s session.
#[must_use]
pub fn initialized_notification(
    template: &OutboundRequest,
    url: &str,
    revision: Revision,
    session: Option<&str>,
) -> OutboundRequest {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": crate::adapt::METHOD_INITIALIZED,
    });
    session_envelope(template, url, &body, Some(revision), session)
}

/// The revision an `initialize` answer names, when this plane can carry it. `None` is an upstream
/// busbar must not continue with: the spec's rule for a client offered a revision it cannot speak.
#[must_use]
pub fn offered_revision(body: &[u8]) -> Option<Revision> {
    let v: Value = serde_json::from_slice(body).ok()?;
    crate::revision::accept_offered(v.pointer("/result/protocolVersion")?.as_str()?)
}

/// LOWERS a stateless request into `revision`: the stateless `_meta` members go (a session
/// revision states them once, in `initialize`), the stateless mirror headers go, the version
/// header names `revision` (where the revision has one) and the session header names `session`.
/// The URL is `url` (the endpoint, or a `2024-11-05` message address). The credential and every
/// other header `req` carries are kept.
#[must_use]
pub fn lower_request(
    req: &OutboundRequest,
    url: &str,
    revision: Revision,
    session: Option<&str>,
) -> OutboundRequest {
    let mut body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
    if let Some(params) = body.get_mut("params").and_then(Value::as_object_mut) {
        let empty = params
            .get_mut("_meta")
            .and_then(Value::as_object_mut)
            .map(|meta| {
                meta.remove(META_PROTOCOL_VERSION);
                meta.remove(META_CLIENT_CAPABILITIES);
                meta.is_empty()
            })
            .unwrap_or(false);
        if empty {
            params.remove("_meta");
        }
    }
    session_envelope(req, url, &body, Some(revision), session)
}

/// The shared session-revision envelope: `template`'s headers without the stateless mirror, plus
/// the version and session headers `revision` and `session` call for.
fn session_envelope(
    template: &OutboundRequest,
    url: &str,
    body: &Value,
    revision: Option<Revision>,
    session: Option<&str>,
) -> OutboundRequest {
    let mut headers: Vec<(String, String)> = template
        .headers
        .iter()
        .filter(|(k, _)| {
            k != H_PROTOCOL_VERSION
                && k != H_MCP_METHOD
                && k != H_MCP_NAME
                && k != H_SESSION
                && !k.starts_with("mcp-param-")
        })
        .cloned()
        .collect();
    if let Some(r) = revision.filter(|r| r.requires_version_header()) {
        headers.push((H_PROTOCOL_VERSION.to_string(), r.wire().to_string()));
    }
    if let Some(s) = session {
        headers.push((H_SESSION.to_string(), s.to_string()));
    }
    OutboundRequest {
        url: url.to_string(),
        headers,
        body: serde_json::to_vec(body).unwrap_or_default(),
    }
}

/// Why a `2024-11-05` stream's message address was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressRefused {
    /// The address names another origin than the registered endpoint's. Following it would let
    /// the upstream point busbar's POSTs, credential and all, at a host the operator never
    /// registered.
    CrossOrigin,
    /// The address is not a path or an absolute address busbar can read.
    Malformed,
}

/// The `(scheme, authority)` of an absolute address, or `None`.
fn origin_of(url: &str) -> Option<(&str, &str)> {
    let (scheme, rest) = url.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    if scheme.is_empty() || authority.is_empty() {
        return None;
    }
    Some((scheme, authority))
}

/// THE MESSAGE ADDRESS a `2024-11-05` stream's `endpoint` event names, resolved against the
/// registered endpoint `base`. A path is joined to `base`'s origin; an absolute address must have
/// exactly `base`'s origin. Anything else is refused.
///
/// # Errors
/// [`AddressRefused`] for another origin or an unreadable address.
pub fn message_address(base: &str, event_data: &str) -> Result<String, AddressRefused> {
    let data = event_data.trim();
    if data.is_empty() || data.chars().any(char::is_whitespace) || data.starts_with("//") {
        return Err(AddressRefused::Malformed);
    }
    let (scheme, authority) = origin_of(base).ok_or(AddressRefused::Malformed)?;
    if data.starts_with('/') {
        return Ok(format!("{scheme}://{authority}{data}"));
    }
    match origin_of(data) {
        Some(o) if o.0.eq_ignore_ascii_case(scheme) && o.1.eq_ignore_ascii_case(authority) => {
            Ok(data.to_string())
        }
        Some(_) => Err(AddressRefused::CrossOrigin),
        None => Err(AddressRefused::Malformed),
    }
}

/// One event read off an event stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamEvent {
    /// The `event:` name, when the event named one.
    pub event: Option<String>,
    /// The `id:`, when the event carried one.
    pub id: Option<String>,
    /// The `data:` lines, joined with `\n`.
    pub data: String,
}

/// AN INCREMENTAL EVENT-STREAM READER: bytes in, whole events out, the unfinished tail kept.
/// Bounded: a tail that grows past `max_pending` bytes without completing an event is dropped and
/// [`Self::overflowed`] says so, so a peer that never ends an event cannot grow busbar's memory.
#[derive(Debug)]
pub struct EventReader {
    pending: Vec<u8>,
    max_pending: usize,
    overflowed: bool,
}

impl EventReader {
    /// A reader holding at most `max_pending` bytes of an unfinished event.
    #[must_use]
    pub fn new(max_pending: usize) -> Self {
        Self {
            pending: Vec::new(),
            max_pending,
            overflowed: false,
        }
    }

    /// Whether an unfinished event was ever dropped for exceeding the bound.
    #[must_use]
    pub const fn overflowed(&self) -> bool {
        self.overflowed
    }

    /// Feeds `chunk` and returns every event it completed, in order. Comment lines and events with
    /// neither a name nor data are skipped.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<StreamEvent> {
        // A carriage return only ever ends a line here, so it is dropped as it arrives and every
        // line end reads as `\n`.
        self.pending
            .extend(chunk.iter().copied().filter(|b| *b != b'\r'));
        let mut out = Vec::new();
        while let Some(end) = self.pending.windows(2).position(|w| w == b"\n\n") {
            let raw: Vec<u8> = self.pending.drain(..end + 2).collect();
            let raw = String::from_utf8_lossy(&raw[..end]);
            let mut event = StreamEvent {
                event: None,
                id: None,
                data: String::new(),
            };
            let mut data: Vec<&str> = Vec::new();
            for line in raw.lines() {
                if line.starts_with(':') {
                    continue;
                }
                let (field, value) = line.split_once(':').unwrap_or((line, ""));
                let value = value.strip_prefix(' ').unwrap_or(value);
                match field {
                    "event" => event.event = Some(value.to_string()),
                    "id" => event.id = Some(value.to_string()),
                    "data" => data.push(value),
                    _ => {}
                }
            }
            event.data = data.join("\n");
            if event.event.is_some() || !event.data.is_empty() {
                out.push(event);
            }
        }
        if self.pending.len() > self.max_pending {
            self.pending.clear();
            self.overflowed = true;
        }
        out
    }
}

/// What one event on a `2024-11-05` stream means to the client holding it.
#[derive(Clone, Debug, PartialEq)]
pub enum LinkEffect {
    /// The `endpoint` event named the message address: POSTs may start.
    Ready(String),
    /// The `endpoint` event named an address busbar will not POST to. The link is unusable.
    Refused(AddressRefused),
    /// The answer to a request this link is waiting on, by its id's JSON text.
    Answer {
        /// The request id, as JSON text.
        id: String,
        /// The whole JSON-RPC response, as sent.
        body: Vec<u8>,
    },
    /// A request or notification from the upstream, for the peer classifier.
    FromPeer(Value),
    /// Nothing busbar acts on: a repeat `endpoint`, a response nobody waits for, a body that is
    /// not JSON.
    Ignored,
}

/// THE CLIENT STATE OF ONE `2024-11-05` STREAM: the message address once named, and the ids of the
/// requests waiting for an answer on it. Bounded: at most `max_waiting` requests wait at once.
#[derive(Debug)]
pub struct EventStreamLink {
    base: String,
    address: Option<String>,
    waiting: std::collections::BTreeSet<String>,
    max_waiting: usize,
}

impl EventStreamLink {
    /// A link to the stream opened at `base`, holding at most `max_waiting` open requests.
    #[must_use]
    pub fn new(base: &str, max_waiting: usize) -> Self {
        Self {
            base: base.to_string(),
            address: None,
            waiting: std::collections::BTreeSet::new(),
            max_waiting: max_waiting.max(1),
        }
    }

    /// The message address, once the stream named an acceptable one.
    #[must_use]
    pub fn address(&self) -> Option<&str> {
        self.address.as_deref()
    }

    /// Registers a request by its `id` before it is POSTed. `false` when the link already holds
    /// `max_waiting` requests or the id is already waiting.
    pub fn expect(&mut self, id: &Value) -> bool {
        if self.waiting.len() >= self.max_waiting {
            return false;
        }
        self.waiting.insert(id.to_string())
    }

    /// Stops waiting for `id` (its caller gave up).
    pub fn abandon(&mut self, id: &Value) {
        self.waiting.remove(&id.to_string());
    }

    /// Reads one event.
    pub fn on_event(&mut self, event: &StreamEvent) -> LinkEffect {
        if event.event.as_deref() == Some("endpoint") {
            if self.address.is_some() {
                return LinkEffect::Ignored;
            }
            return match message_address(&self.base, &event.data) {
                Ok(a) => {
                    self.address = Some(a.clone());
                    LinkEffect::Ready(a)
                }
                Err(r) => LinkEffect::Refused(r),
            };
        }
        if !matches!(
            event.event.as_deref(),
            None | Some(crate::adapt::EVENT_MESSAGE)
        ) {
            return LinkEffect::Ignored;
        }
        let Ok(v) = serde_json::from_str::<Value>(&event.data) else {
            return LinkEffect::Ignored;
        };
        if v.get("method").is_some() {
            return LinkEffect::FromPeer(v);
        }
        let Some(id) = v.get("id").map(Value::to_string) else {
            return LinkEffect::Ignored;
        };
        if self.waiting.remove(&id) {
            LinkEffect::Answer {
                id,
                body: event.data.clone().into_bytes(),
            }
        } else {
            LinkEffect::Ignored
        }
    }
}

#[cfg(test)]
#[path = "tests/compat_tests.rs"]
mod tests;
