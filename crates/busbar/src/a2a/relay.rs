// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RELAY: the hop that turns an admitted A2A task submission into a request the backend agent
//! actually receives, and its reply — one answer or a stream of them — into the caller's answer.
//!
//! Everything above this module DECIDED. [`super::inbound::authorize`] said who may reach which
//! agent, [`super::catalogue`] said for what shape of work, [`super::meter`] said whose budget, and
//! [`super::taskstore`] recorded that a dispatch happened. None of that reached the backend. This
//! is the module that does, and being the one that opens a socket is what makes the properties
//! below its own rather than somebody else's.
//!
//! ## 1. THE CALLER'S BUSBAR KEY NEVER LEAVES, AND THE SIGNATURE IS THE MECHANISM
//!
//! A registered agent's backend is a different party. The caller's busbar key authenticated them TO
//! busbar and authorised them against busbar's scopes; it means nothing to that party and handing it
//! over gives them a working busbar credential belonging to someone else.
//!
//! [`RelayCall`] therefore has NO FIELD through which an inbound credential could arrive — not a
//! header map, not a `VirtualKey`, not an "extra headers" escape hatch. The first draft of this
//! module was the obvious one, a proxy that forwarded the inbound request's headers minus the
//! hop-by-hop set, and it is the deletion of that field that fixed it. A future edit that wanted to
//! forward one would have to ADD a field, which is a change a reviewer sees.
//!
//! That is a claim about intent, so it is not the whole defence: the tests scan every byte this
//! module asks to have sent for the caller's REAL token in five encodings, with a control requiring
//! the scanner to find the credential that IS legitimately forwarded on the same wire.
//!
//! **And the scan alone was not sufficient either.** Run against the forwarding first draft with an
//! outbound credential configured, it was GREEN — because the leased credential overwrote the
//! forwarded `authorization` header on its way past. The twin that runs with NO credential
//! configured is what caught it. A single-configuration scan would have shipped the leak.
//!
//! ## 2. THE NAME IS RESOLVED ONCE, BY THE GUARD, AND THE JUDGED ADDRESS IS WHAT CONNECTS
//!
//! This module does not open its own client. It reuses [`super::fetch::resolve_and_pin`] — the same
//! guard the card fetch goes through — and hands the surviving address to the transport, which pins
//! it. A relay that handed the URL to `reqwest` and let the client resolve the host would reinstate
//! the second lookup, which is the whole of DNS rebinding, and would pass every test that does not
//! reach a socket. See [`super::transport`] for what the transport does about it.
//!
//! ## 3. THE TRUST DECISION IS RE-ASKED AFTER THE GUARD AND BEFORE THE SOCKET
//!
//! Admission happened under a registry read that is already in the past by the time this module
//! resolves a name. Re-verification runs on its own schedule and can DEMOTE a registration at any
//! instant — that is the entire point of the re-verification cadence and the rug-pull defence, and a
//! demotion that only takes effect on the
//! NEXT request is a demotion the in-flight request escapes. So [`RelayCall::gate`] is consulted
//! against the LIVE registry immediately before the transport call, and a registration that is no
//! longer `Approved` never reaches the wire. The gate cannot make the decision more open: it is the
//! same [`super::registry::AgentRegistration::is_delegable`] the catalogue and `authorize` ask.
//!
//! ## 4. A BACKEND FAILURE IS A BUSBAR-ATTRIBUTED ERROR
//!
//! The tempting shape is to hand the caller the Task envelope busbar already opened and let them
//! poll. That is WORSE than an error: the caller is told the work was accepted, the task sits in
//! `submitted` forever, and the operator's first evidence is a support ticket. So every way the hop
//! can fail — the guard, the gate, the lease, the transport, a non-2xx, an oversized body, an
//! unparseable body, a JSON-RPC error from the backend — is a [`RelayRefusal`], and the ingress
//! renders it as a `502` naming the task busbar recorded.
//!
//! An INTERRUPT is not a failure. `input-required` and `auth-required` come back to the caller as
//! themselves; see [`RelayReply::reported_state`] and the ingress's own note.
//!
//! ## 5. THE REPLY COMES BACK UNDER BUSBAR'S IDENTITY
//!
//! The backend's own task and context ids are ITS names for this work. The caller's later reads are
//! scoped against busbar's store, which keys on the id busbar issued, so carrying the backend's id
//! through would hand the caller a handle that resolves to nothing. [`RelayReply::result`] is the
//! backend's answer verbatim and [`rewrite_identity`] substitutes the two identity fields;
//! everything else — status, artifacts, history, parts — is passed through untouched, because busbar
//! is CONTENT-BLIND on this plane and rewriting a caller's payload is not a gateway's job.

use std::net::IpAddr;

use super::creds::{Lease, LeaseError};
use super::fetch::{FetchPolicy, FetchRefusal, HttpResponse, Resolver};
use super::task::TaskState;

/// The HTTP round trip the relay makes, as a seam.
///
/// Deliberately NOT a method on [`super::fetch::Transport`]. That trait is the card fetch's, its
/// implementations are card-fetch fixtures, and adding a `post` to it would have given five test
/// doubles a method none of them has any business answering. The security contract is the same one
/// and is restated because it is the whole reason the argument exists: `addr` is the PINNED ADDRESS
/// and an implementation MUST connect to it rather than re-resolving `url`.
///
/// `Send + Sync` because the plane holds one for the process's life and every request reads it.
pub(crate) trait RelayTransport: Send + Sync {
    fn post(
        &self,
        url: &reqwest::Url,
        addr: IpAddr,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<HttpResponse, String>;

    /// THE STREAMING HOP. Same pin, same headers, same body; the difference is that the reply is
    /// handed to `on_chunk` AS IT ARRIVES rather than buffered whole.
    ///
    /// The status is returned FIRST, before any chunk, because a streaming relay that has already
    /// written bytes to its caller cannot then change its mind and answer a 502 — so the decision
    /// "is this a stream at all" has to be made on the response head. An implementation returns
    /// `Err` for a transport failure and `Ok(status)` with no chunks for a non-2xx.
    fn post_stream(
        &self,
        url: &reqwest::Url,
        addr: IpAddr,
        headers: &[(String, String)],
        body: &[u8],
        on_chunk: &mut (dyn FnMut(&[u8]) -> ChunkFlow + Send),
    ) -> Result<StreamHead, String>;
}

/// What the chunk sink says about continuing. A sink whose receiver has gone away asks the hop to
/// STOP rather than being written to forever: a caller that disconnected mid-stream must not leave
/// busbar holding a blocking thread against an upstream that is happy to keep talking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ChunkFlow {
    Continue,
    Stop,
}

/// The head of a streaming reply: what the backend answered before any body arrived.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StreamHead {
    pub(crate) status: u16,
    /// The backend's `content-type`, lower-cased, or empty. Read because a backend that answers a
    /// `message/stream` with `application/json` has answered a NON-stream, and relaying that to a
    /// caller as `text/event-stream` would be busbar inventing a framing the backend never used.
    pub(crate) content_type: String,
    /// The body, for a reply the backend did NOT stream. Empty on a real stream: those bytes went
    /// to `on_chunk`.
    pub(crate) body: Vec<u8>,
}

/// THE RELAY'S SEAMS, HELD TOGETHER, for the reason [`super::transport::LiveCardFetch`] gives for
/// holding its own two: a caller that picked up a resolver and a transport from different places
/// could pair a real transport with a fixture resolver, which is the one combination that would
/// look tested and connect wherever the client felt like.
pub(crate) trait RelaySeam: Send + Sync {
    fn resolver(&self) -> &dyn Resolver;
    fn transport(&self) -> &dyn RelayTransport;
    fn policy(&self) -> &FetchPolicy;
}

/// THE LIVE TRUST DECISION, as a seam, asked immediately before the socket.
///
/// A trait rather than a captured boolean, because a boolean is a decision that was true once. The
/// production implementation reads the plane's registry under its own lock at the moment it is
/// asked, so a re-verification sweep that demoted the registration a microsecond ago is visible
/// here.
pub(crate) trait DelegationGate: Send + Sync {
    /// `Ok(())` only while the named registration is still `Approved`. Any other answer names the
    /// state it is in now, so the refusal an operator reads says what changed.
    fn still_delegable(&self, agent_id: &str) -> Result<(), NotDelegable>;
}

/// The registration is no longer a legal delegation target. Carries what it is NOW.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NotDelegable {
    pub(crate) agent_id: String,
    pub(crate) state: crate::trust::TrustState,
    pub(crate) reason: Option<String>,
}

impl std::fmt::Display for NotDelegable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "agent `{}` is no longer a delegation target ({:?})",
            self.agent_id, self.state
        )?;
        match &self.reason {
            Some(r) => write!(f, ": {r}"),
            None => Ok(()),
        }
    }
}

/// ONE RELAYED SUBMISSION, and the argument list is the security property.
///
/// Every field is either operator-written (`agent_id`, `backend_url`), busbar's own (`lease`,
/// `gate`), or the caller's CONTENT (`body`). There is no field for the caller's credential, and
/// see the module note for why the absence is the mechanism rather than a comment.
pub(crate) struct RelayCall<'a> {
    /// The busbar-local agent id. Operator-written, and the value the lease is checked against.
    pub(crate) agent_id: &'a str,
    /// The backend agent's real A2A endpoint. Guarded and pinned here, never returned to a caller.
    pub(crate) backend_url: &'a str,
    /// BUSBAR'S OWN credential for this backend, leased for this hop. `None` is a legitimate
    /// configuration and means the hop carries no credential — never that it carries the caller's.
    pub(crate) lease: Option<&'a Lease>,
    /// THE LIVE TRUST DECISION, re-asked after the guard and before the socket. See the module note.
    pub(crate) gate: &'a dyn DelegationGate,
    /// THE GUARD POLICY FOR THIS REGISTRATION — `A2aPlane::fetch_policy_for(agent_id)`, never the
    /// plane-wide default.
    ///
    /// It is carried on the CALL rather than read off the seam, and that is the whole of a defect
    /// this field exists to close. `RelaySeam::policy()` answers with the plane's default, which is
    /// fail-closed and knows nothing about any registration; the card fetch, `connect`, `approve`
    /// and the re-verification sweep all narrow it by the registration's `allow_private:` first.
    /// The relay did not, so a registration an operator had marked `allow_private: true` was
    /// fetched, verified and approved over its plaintext loopback endpoint — and then every task
    /// submitted to it was refused by the relay's guard, quoting the very knob that was already set.
    /// One operator line, two answers, decided by which code path asked.
    pub(crate) policy: &'a FetchPolicy,
    /// The caller's request, VERBATIM. busbar is content-blind on this plane.
    pub(crate) body: &'a [u8],
}

/// THE REQUEST THE RELAY IS ABOUT TO SEND: everything, in one value.
///
/// One struct rather than a builder chain because it is what the adversarial no-leak scan reads,
/// and a test that has to reconstruct a request from a builder's intermediate state is a test that
/// can miss the field the builder added last.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OutboundRelayRequest {
    pub(crate) url: String,
    /// Header name/value pairs, lower-cased names, in the order they will be written.
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

impl OutboundRelayRequest {
    /// EVERY byte this request will put on the wire, concatenated: URL, then each header name and
    /// value, then the body.
    ///
    /// This exists for the adversarial scan and for nothing else. Its value is that it is derived
    /// from the same fields the transport writes, so a field added to `OutboundRelayRequest`
    /// without being added here fails `relay_tests::every_field_of_the_outbound_request_is_scanned`
    /// — a scan that silently stops covering a new field is the exact false green the rule exists
    /// to prevent.
    ///
    /// `cfg(test)` because it has exactly one consumer and it is that scan. Shipping it would be
    /// shipping a function whose only purpose is to concatenate a credential into one buffer.
    #[cfg(test)]
    pub(crate) fn wire_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.url.as_bytes());
        for (name, value) in &self.headers {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(value.as_bytes());
        }
        out.extend_from_slice(&self.body);
        out
    }
}

/// WHY A HOP DID NOT PRODUCE AN ANSWER. Every arm is a busbar-attributed failure; none of them is a
/// state in which the caller is told the work was accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RelayRefusal {
    /// The SSRF guard refused the backend endpoint. Unreachable for an approved registration (a
    /// registration whose endpoint the guard refuses can never have had its card fetched, so it can
    /// never have been approved) and still handled, because "unreachable" is a claim about today's
    /// ordering.
    Guard(FetchRefusal),
    /// THE REGISTRATION WAS DEMOTED between admission and the socket. A 503, not a 502: it is a
    /// statement about the agent rather than about the hop.
    Demoted(NotDelegable),
    /// An outbound credential is configured and could not be presented.
    ///
    /// A REFUSAL rather than a silent unauthenticated hop: an operator who configured a credential
    /// meant the backend to see one, and calling without it is a different call than they asked for
    /// — one that will most likely be refused by the backend and reported as the backend's fault.
    Lease(LeaseError),
    /// The transport failed: connection refused, TLS refused, timed out, reset mid-body.
    Transport { url: String, err: String },
    /// The backend answered, with something other than 2xx.
    Status { url: String, status: u16 },
    /// The reply exceeded the policy ceiling. An unbounded read from an upstream is an unbounded
    /// allocation an upstream chooses the size of.
    BodyTooLarge { url: String, bytes: usize },
    /// The reply is not JSON, so it is not a JSON-RPC answer.
    NotJson { url: String, err: String },
    /// The backend answered with a JSON-RPC `error` member. The backend's own words are carried so
    /// an operator reading the log sees what it said, and they are NOT returned to the caller.
    ///
    /// `jsonrpc_code` is the SAME error as an integer, where the backend sent one A2A defines. It
    /// is carried separately from `code` because the two are different kinds of thing: `code` is for
    /// the log and may be any JSON value a backend chose to put there, and this is a protocol fact
    /// the ingress re-emits so a caller learns what actually happened. See
    /// `rpcerror::A2aError::from_code` for why the semantics travel and the prose does not.
    BackendError {
        code: String,
        message: String,
        jsonrpc_code: Option<i64>,
    },
}

impl RelayRefusal {
    /// The HTTP status this refusal presents as. 502 for everything that is a fault of the HOP, and
    /// 503 for the one arm that is a statement about the AGENT — which is the same code
    /// [`super::inbound::InboundRefusal::NotServing`] uses for the same fact, so a caller sees one
    /// answer for "this agent is not serving" whether the demotion landed before admission or
    /// between admission and the socket.
    pub(crate) fn status(&self) -> u16 {
        match self {
            RelayRefusal::Demoted(_) => 503,
            _ => 502,
        }
    }
}

impl std::fmt::Display for RelayRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelayRefusal::Guard(e) => write!(f, "the relay target was refused: {e}"),
            RelayRefusal::Demoted(e) => write!(f, "{e}"),
            RelayRefusal::Lease(e) => write!(f, "{e}"),
            RelayRefusal::Transport { url, err } => {
                write!(f, "the relayed submission to `{url}` failed: {err}")
            }
            RelayRefusal::Status { url, status } => {
                write!(f, "the backend agent at `{url}` answered HTTP {status}")
            }
            RelayRefusal::BodyTooLarge { url, bytes } => write!(
                f,
                "the backend agent at `{url}` replied with {bytes} bytes, over the configured \
                 ceiling"
            ),
            RelayRefusal::NotJson { url, err } => write!(
                f,
                "the backend agent at `{url}` replied with something that is not JSON: {err}"
            ),
            RelayRefusal::BackendError { code, message, .. } => {
                write!(f, "the backend agent refused the task: [{code}] {message}")
            }
        }
    }
}

/// A HOP THAT PRODUCED AN ANSWER.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RelayReply {
    /// The backend's JSON-RPC `result`, VERBATIM. [`rewrite_identity`] substitutes the two identity
    /// fields and everything else passes through; see the module note on content-blindness.
    pub(crate) result: serde_json::Value,
    /// The state the backend says the task is in, as this plane's own canonical type reads it.
    ///
    /// `Working` when the backend named none, which is the honest default: the submission was
    /// accepted and the backend did not say it had finished.
    pub(crate) reported_state: TaskState,
}

/// The `Content-Type` a JSON-RPC submission carries, and the only one this relay sends.
const CONTENT_TYPE: &str = "application/json";

/// The `Accept` a STREAMING submission carries. Both types, in preference order: a backend that
/// declared `streaming` may still answer a single JSON document for a task it finished instantly,
/// and an `Accept` naming only the stream would make that legal answer a 406.
const ACCEPT_STREAM: &str = "text/event-stream, application/json";

/// The media type an SSE stream is framed in, on both the hop and the caller's side.
pub(crate) const SSE_CONTENT_TYPE: &str = "text/event-stream";

/// BUILD THE OUTBOUND REQUEST. Separated from [`relay`] so the scan can read the request as a value
/// rather than having to intercept a socket.
///
/// Every header on the result is one of exactly three things: a constant, the operator's leased
/// credential, or nothing. There is no fourth source, because there is no argument that could be
/// one.
pub(crate) fn build_request(
    url: &reqwest::Url,
    agent_id: &str,
    lease: Option<&Lease>,
    body: &[u8],
    streaming: bool,
    now_ms: u64,
) -> Result<OutboundRelayRequest, LeaseError> {
    let mut headers = vec![
        ("content-type".to_string(), CONTENT_TYPE.to_string()),
        (
            "accept".to_string(),
            if streaming {
                ACCEPT_STREAM.to_string()
            } else {
                CONTENT_TYPE.to_string()
            },
        ),
    ];
    if let Some(lease) = lease {
        // `header_for` checks BOTH that the lease was minted for this agent and that it is still
        // live. Both checks live on the lease rather than here, so a call site cannot forget one.
        let (name, value) = lease.header_for(agent_id, now_ms)?;
        headers.push((name.to_ascii_lowercase(), value));
    }
    Ok(OutboundRelayRequest {
        url: url.to_string(),
        headers,
        body: body.to_vec(),
    })
}

/// THE PREAMBLE EVERY HOP SHARES: guard the target, re-ask the trust question, build the request.
///
/// One function rather than two copies, because the ORDER is the design and a second copy is a
/// second place for the gate to be forgotten. The unary and streaming relays differ in what they do
/// with the socket and in nothing before it.
fn prepare<'a>(
    call: &RelayCall<'a>,
    seam: &dyn RelaySeam,
    streaming: bool,
    now_ms: u64,
) -> Result<(super::fetch::PinnedTarget, OutboundRelayRequest), RelayRefusal> {
    // ── THE GUARD. One resolution, every answered address judged, one pinned address out. ──
    // `call.policy`, NOT `seam.policy()`. The seam answers with the plane's fail-closed default and
    // knows nothing about any registration; the call carries the one the operator's `allow_private:`
    // narrowed, which is what every other reader of that line already uses.
    let target = super::fetch::resolve_and_pin(call.backend_url, seam.resolver(), call.policy)
        .map_err(RelayRefusal::Guard)?;

    // ── THE LIVE TRUST DECISION, after the guard and before the socket. See the module note. ──
    call.gate
        .still_delegable(call.agent_id)
        .map_err(RelayRefusal::Demoted)?;

    let request = build_request(
        &target.url,
        call.agent_id,
        call.lease,
        call.body,
        streaming,
        now_ms,
    )
    .map_err(RelayRefusal::Lease)?;
    Ok((target, request))
}

/// RELAY ONE TASK SUBMISSION to the backend agent, and bring the answer back.
///
/// Synchronous, like the card fetch seam it shares a transport with. The ingress calls it on a
/// blocking thread rather than on a runtime worker; see the note at its call site.
pub(crate) fn relay(
    call: &RelayCall<'_>,
    seam: &dyn RelaySeam,
    now_ms: u64,
) -> Result<RelayReply, RelayRefusal> {
    let (target, request) = prepare(call, seam, false, now_ms)?;

    // The PINNED ADDRESS goes to the transport beside the URL. The transport connects to the
    // address and sends the URL's host as `Host` and as TLS SNI; see `transport.rs`.
    let resp = seam
        .transport()
        .post(&target.url, target.addr, &request.headers, &request.body)
        .map_err(|err| RelayRefusal::Transport {
            url: target.url.to_string(),
            err,
        })?;

    if !(200..300).contains(&resp.status) {
        // Including a 3xx. A redirect on a task submission is a fresh, fully untrusted URL that the
        // guard has never seen, and following one would perform the next hop with no guard at all.
        return Err(RelayRefusal::Status {
            url: target.url.to_string(),
            status: resp.status,
        });
    }
    if resp.body.len() > call.policy.max_body_bytes {
        return Err(RelayRefusal::BodyTooLarge {
            url: target.url.to_string(),
            bytes: resp.body.len(),
        });
    }
    read_reply(&resp.body, target.url.as_str())
}

/// Read one JSON-RPC answer off a completed body.
fn read_reply(body: &[u8], url: &str) -> Result<RelayReply, RelayRefusal> {
    let envelope: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| RelayRefusal::NotJson {
            url: url.to_string(),
            err: e.to_string(),
        })?;

    // A JSON-RPC `error` is a FAILED HOP, not a result to hand back. A 200 carrying an error member
    // is the shape in which a backend refusal would otherwise arrive looking like success.
    if let Some(err) = envelope.get("error").filter(|e| !e.is_null()) {
        return Err(RelayRefusal::BackendError {
            code: err
                .get("code")
                .map_or_else(|| "unknown".to_string(), ToString::to_string),
            message: err
                .get("message")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string(),
            jsonrpc_code: err.get("code").and_then(serde_json::Value::as_i64),
        });
    }

    let result = envelope
        .get("result")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let reported_state = reported_task_state(&result);
    Ok(RelayReply {
        result,
        reported_state,
    })
}

/// THE PAYLOAD INSIDE A JSON-RPC `result`, in either of the shapes A2A has used.
///
/// A2A v0.3 makes the `result` the Task (or Message) itself. v1.0 WRAPS it — `{"task": {…}}`,
/// `{"message": {…}}` — which is the shape the pinned control agent and the official TCK speak.
/// busbar is content-blind on this plane and does not translate between them; it only has to know
/// WHERE the payload is, because the two things it does to a backend answer (substitute its own
/// task identity, read the state the backend reported) are both about the payload and neither is
/// about the wrapper.
///
/// A wrapper is recognised by carrying `task` or `message` AS AN OBJECT. Nothing else is treated as
/// one: a v0.3 Task has neither member at its top level, so the two shapes cannot be confused.
/// THE FOUR WRAPPER MEMBERS A2A v1.0 DEFINES, and what each one names its task by.
///
/// The identity member is NOT the same across them and that is not an inconsistency in A2A: a
/// `Task` IS the task, so its identifier is `id`; a `Message` and the two update events are ABOUT a
/// task, so they name it with `taskId` and carry their own identifier separately. Writing `id` into
/// an update event invents a member its schema forbids and leaves the real one — the member a
/// caller correlates a stream by — still naming the backend's task.
const WRAPPERS: [(&str, &str); 4] = [
    ("task", "id"),
    ("message", "taskId"),
    ("statusUpdate", "taskId"),
    ("artifactUpdate", "taskId"),
];

fn wrapper_of(result: &serde_json::Value) -> Option<(&'static str, &'static str)> {
    WRAPPERS
        .into_iter()
        .find(|(member, _)| result.get(member).is_some_and(serde_json::Value::is_object))
}

fn payload_of(result: &serde_json::Value) -> &serde_json::Value {
    match wrapper_of(result) {
        Some((member, _)) => result.get(member).expect("just found"),
        None => result,
    }
}

/// The task state a `result` (or a streamed event) reports, defaulting to `Working`.
///
/// THE WIRE TOKEN, NOT THE STORE TOKEN. `TaskState::parse` reads what busbar WROTE and is strict on
/// purpose — an unknown token there is a row a downgrade must not guess about. This reads what a
/// BACKEND said, and A2A has two spellings for every state: v0.3's `input-required` and v1.0's
/// `TASK_STATE_INPUT_REQUIRED`. Reading only the first recorded every task a v1.0 backend completed
/// as `working`, so busbar's own rows disagreed with the answer it had just handed the caller.
/// Anything unreadable stays `Working`: a relay that guessed `completed` from a token it could not
/// read would close a task that is still running.
pub(crate) fn reported_task_state(result: &serde_json::Value) -> TaskState {
    let Some(token) = payload_of(result)
        .pointer("/status/state")
        .and_then(serde_json::Value::as_str)
    else {
        return TaskState::Working;
    };
    if let Ok(state) = TaskState::parse(token) {
        return state;
    }
    // v1.0's enum spelling: `TASK_STATE_` + the state in SCREAMING_SNAKE_CASE.
    match token.strip_prefix("TASK_STATE_") {
        Some(rest) => TaskState::parse(&rest.to_ascii_lowercase().replace('_', "-"))
            .unwrap_or(TaskState::Working),
        None => TaskState::Working,
    }
}

/// SUBSTITUTE BUSBAR'S TASK IDENTITY onto a backend answer, leaving everything else alone.
///
/// One function used by BOTH the unary reply and every streamed event, because two copies is two
/// chances for the streaming path to leak the backend's own task id — the id a caller would then
/// present to `GetTask` and be told does not exist.
pub(crate) fn rewrite_identity(
    result: &mut serde_json::Value,
    task_id: &str,
    context_id: &str,
    matched_skill: Option<&str>,
) {
    if !result.is_object() {
        *result = serde_json::json!({ "kind": "task" });
    }
    // THE PAYLOAD, not the wrapper, and BY ITS OWN IDENTITY MEMBER. See `WRAPPERS`: writing
    // `id`/`contextId` beside a `task` member rather than inside it left the backend's own ids in
    // the document a caller reads — which is the failure this function's whole purpose is to
    // prevent — and added two members the schema forbids.
    let (wrapper, id_member) = match wrapper_of(result) {
        Some((member, id_member)) => (Some(member), id_member),
        // A bare `result` is the v0.3 shape: the Task itself, identified by `id`.
        None => (None, "id"),
    };
    let payload = match wrapper {
        Some(member) => result.get_mut(member).expect("just found"),
        None => result,
    };
    let Some(obj) = payload.as_object_mut() else {
        return;
    };
    // A `Message` names a task only when it belongs to one. Adding `taskId` to a standalone
    // message would assert a relationship the backend did not.
    if id_member != "taskId" || wrapper != Some("message") || obj.contains_key("taskId") {
        obj.insert(
            id_member.to_string(),
            serde_json::Value::String(task_id.to_string()),
        );
    }
    obj.insert(
        "contextId".to_string(),
        serde_json::Value::String(context_id.to_string()),
    );
    // A status-update event nests the ids one level down as well, and an event that carries
    // busbar's id at the top and the backend's inside it is worse than one that carries neither:
    // it reads as correct.
    if let Some(status) = obj.get_mut("status").and_then(|s| s.as_object_mut()) {
        if let Some(msg) = status.get_mut("message").and_then(|m| m.as_object_mut()) {
            if msg.contains_key("taskId") {
                msg.insert(
                    "taskId".to_string(),
                    serde_json::Value::String(task_id.to_string()),
                );
            }
            if msg.contains_key("contextId") {
                msg.insert(
                    "contextId".to_string(),
                    serde_json::Value::String(context_id.to_string()),
                );
            }
        }
    }
    // THE MATCHED SKILL IS METADATA. It used to be inserted as a top-level `skill` member, which
    // A2A's `Task` does not define — so a conformant client validating the envelope rejects it, and
    // busbar has invented a field in somebody else's schema. `metadata` is the member the
    // specification provides for exactly this, and the key is namespaced so it cannot collide with
    // whatever the backend put there.
    if let Some(skill) = matched_skill {
        let metadata = obj
            .entry("metadata")
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
        if !metadata.is_object() {
            *metadata = serde_json::Value::Object(serde_json::Map::new());
        }
        if let Some(metadata) = metadata.as_object_mut() {
            metadata.insert(
                "busbar/skill".to_string(),
                serde_json::Value::String(skill.to_string()),
            );
        }
    }
}

// ══ THE STREAMING HALF ═══════════════════════════════════════════════════════════════════════════

/// ONE EVENT OFF THE BACKEND'S STREAM, after busbar has read it.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RelayEvent {
    /// The event, re-framed as SSE and ready to write to the caller. Identity already substituted.
    pub(crate) sse: Vec<u8>,
    /// The task state this event reports, if it reported one.
    pub(crate) state: Option<TaskState>,
    /// Whether this event carried an artifact chunk, which is what advances the resume cursor.
    pub(crate) artifact: bool,
}

/// THE SSE FRAME READER: bytes in, whole events out.
///
/// A separate type rather than a closure because an SSE stream does NOT arrive one event per chunk.
/// A single TCP read can carry three events, half an event, or the tail of one and the head of the
/// next, and a reader that assumed a chunk was an event would corrupt a caller's stream under
/// exactly the conditions that are hardest to reproduce. So bytes accumulate here and an event is
/// emitted only on the blank line that terminates it.
#[derive(Default)]
pub(crate) struct SseReader {
    buf: Vec<u8>,
}

impl SseReader {
    /// Feed a chunk and take every COMPLETE event it finished.
    pub(crate) fn feed(&mut self, chunk: &[u8]) -> Vec<String> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        // Normalised on `\n\n`; a CRLF stream is handled by stripping the `\r` off each line when
        // the fields are read, which is what the specification's own parser does.
        while let Some(pos) = find(&self.buf, b"\n\n") {
            let frame = self.buf.drain(..pos + 2).collect::<Vec<u8>>();
            if let Ok(s) = String::from_utf8(frame) {
                out.push(s);
            }
        }
        out
    }

    /// How many bytes are held waiting for a terminator. The ceiling check reads this: a backend
    /// that streams megabytes with no blank line is an unbounded allocation it chose the size of.
    pub(crate) fn pending(&self) -> usize {
        self.buf.len()
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// The `data:` payload of one SSE frame, concatenated across continuation lines as the specification
/// requires.
fn sse_data(frame: &str) -> Option<String> {
    let mut data = String::new();
    let mut any = false;
    for line in frame.lines() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        let Some(rest) = line.strip_prefix("data:") else {
            continue;
        };
        if any {
            data.push('\n');
        }
        any = true;
        data.push_str(rest.strip_prefix(' ').unwrap_or(rest));
    }
    any.then_some(data)
}

/// READ ONE BACKEND EVENT and re-frame it for the caller under busbar's identity.
///
/// A frame that is not JSON, or carries no `result`, is passed through UNCHANGED rather than
/// dropped: busbar is content-blind, an SSE stream legitimately carries comments and keep-alives,
/// and a relay that silently swallowed what it could not parse would turn a backend's own protocol
/// extension into an unexplained gap in the caller's stream.
pub(crate) fn read_event(
    frame: &str,
    task_id: &str,
    context_id: &str,
    matched_skill: Option<&str>,
) -> RelayEvent {
    let Some(data) = sse_data(frame) else {
        return RelayEvent {
            sse: frame.as_bytes().to_vec(),
            state: None,
            artifact: false,
        };
    };
    let Ok(mut envelope) = serde_json::from_str::<serde_json::Value>(&data) else {
        return RelayEvent {
            sse: frame.as_bytes().to_vec(),
            state: None,
            artifact: false,
        };
    };
    let Some(result) = envelope.get_mut("result") else {
        return RelayEvent {
            sse: frame.as_bytes().to_vec(),
            state: None,
            artifact: false,
        };
    };
    let artifact = result.get("artifact").is_some() || result.get("artifacts").is_some();
    let state = result
        .pointer("/status/state")
        .and_then(serde_json::Value::as_str)
        .and_then(|s| TaskState::parse(s).ok());
    rewrite_identity(result, task_id, context_id, matched_skill);
    RelayEvent {
        sse: frame_sse(&envelope),
        state,
        artifact,
    }
}

/// Render one JSON value as a complete SSE event.
fn frame_sse(value: &serde_json::Value) -> Vec<u8> {
    format!("data: {value}\n\n").into_bytes()
}

/// What a streaming hop produced, once its head was read.
pub(crate) enum RelayStream {
    /// The backend really streamed. Events were delivered to the sink as they arrived.
    Streamed,
    /// The backend answered a single JSON document to a streaming request, which is legal for a
    /// task it completed immediately. The caller gets the unary shape.
    Unary(Box<RelayReply>),
}

/// RELAY ONE STREAMING TASK SUBMISSION, handing each event to `sink` as it arrives.
///
/// `sink` returns [`ChunkFlow::Stop`] when the caller has gone away; the hop stops there rather
/// than draining an upstream into a receiver nobody is reading.
pub(crate) fn relay_stream(
    call: &RelayCall<'_>,
    seam: &dyn RelaySeam,
    task_id: &str,
    context_id: &str,
    matched_skill: Option<&str>,
    now_ms: u64,
    sink: &mut (dyn FnMut(RelayEvent) -> ChunkFlow + Send),
) -> Result<RelayStream, RelayRefusal> {
    let (target, request) = prepare(call, seam, true, now_ms)?;
    let cap = call.policy.max_body_bytes;

    let mut reader = SseReader::default();
    let mut streamed_any = false;
    let mut overflow = false;
    let head = {
        let mut on_chunk = |chunk: &[u8]| -> ChunkFlow {
            for frame in reader.feed(chunk) {
                streamed_any = true;
                if sink(read_event(&frame, task_id, context_id, matched_skill)) == ChunkFlow::Stop {
                    return ChunkFlow::Stop;
                }
            }
            // THE CEILING APPLIES TO WHAT IS UNTERMINATED, not to the stream's total length: a
            // stream is legitimately unbounded over time, and a single event that never ends is
            // not.
            if reader.pending() > cap {
                overflow = true;
                return ChunkFlow::Stop;
            }
            ChunkFlow::Continue
        };
        seam.transport()
            .post_stream(
                &target.url,
                target.addr,
                &request.headers,
                &request.body,
                &mut on_chunk,
            )
            .map_err(|err| RelayRefusal::Transport {
                url: target.url.to_string(),
                err,
            })?
    };

    if !(200..300).contains(&head.status) {
        return Err(RelayRefusal::Status {
            url: target.url.to_string(),
            status: head.status,
        });
    }
    if overflow {
        return Err(RelayRefusal::BodyTooLarge {
            url: target.url.to_string(),
            bytes: cap.saturating_add(1),
        });
    }
    if streamed_any || head.content_type.starts_with(SSE_CONTENT_TYPE) {
        return Ok(RelayStream::Streamed);
    }
    // NOT A STREAM. The backend answered a single document; hand back the unary shape rather than
    // re-framing a non-stream as one.
    read_reply(&head.body, target.url.as_str()).map(|r| RelayStream::Unary(Box::new(r)))
}

// ONE HARNESS, shared by both test modules below. A second harness is a second thing that can stop
// matching what the production router does, and the defect this area exists to catch is invisible
// to any test that does not go through `crate::build_router`.
#[cfg(test)]
#[path = "tests/relay_harness.rs"]
mod relay_harness;

#[cfg(test)]
#[path = "tests/relay_tests.rs"]
mod relay_tests;

#[cfg(test)]
#[path = "tests/relay_stream_tests.rs"]
mod relay_stream_tests;
