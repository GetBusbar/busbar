// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RELAY: the hop that turns an admitted A2A task submission into a request the backend agent
//! actually receives, and its reply — one answer or a stream of them — into the caller's answer.
//!
//! Everything above this module DECIDED. [`super::inbound::authorize`] said who may reach which
//! agent, [`super::registry`]'s catalogue said for what shape of work, [`super::meter`] said whose budget, and
//! [`busbar_core::plane::taskstore`] recorded that a dispatch happened. None of that reached the backend. This
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
//! This module does not open its own client. It reuses [`super::fetch::guard_hop`], and through it
//! [`busbar_substrate::net_guard::resolve_and_pin`] — the same
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
//!
//! ## 6. THE REPLY IS CORRELATED TO THE REQUEST BUSBAR SENT, ON BOTH PATHS
//!
//! Content-blind is not the same as envelope-blind. Until this was written the hop read `error` and
//! `result` straight off whatever came back: no `jsonrpc` member check, and the response `id` never
//! read at all. A backend — or anything sharing that socket with it — could answer this hop with
//! the reply to a different one and busbar would record it as this task's result and serve it.
//!
//! And the two paths did not even agree on what to do with the id they never checked: the unary
//! path answered the caller under busbar's own `ctx.rpc_id`, while the streamed path passed the
//! BACKEND's id through verbatim, so on a stream the backend chose the value busbar's caller
//! correlated on. The unary path was right. Both now read the envelope through
//! [`busbar_substrate::ingress::jsonrpc::read_response`] — the same reader the MCP client direction uses, and
//! the response-side sibling of the request reader both ingresses share — and an answer that names
//! a different request is [`RelayRefusal::Uncorrelated`], never a result.

use std::net::IpAddr;

use super::creds::{Lease, LeaseError};
use super::fetch::{FetchPolicy, FetchRefusal, HttpResponse, Resolver};
use super::task::TaskState;
use busbar_substrate::net_guard::PinnedTarget;

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
    /// ONE UNARY HOP. `http_method` is the request line's verb, and it is an ARGUMENT rather than a
    /// constant because A2A's HTTP+JSON binding reads with `GET` and withdraws with `DELETE` — a
    /// seam that could only `POST` would make busbar a client that spells every operation as a
    /// submission, which is a different request from the one the specification defines.
    fn send(
        &self,
        http_method: &str,
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

/// What the chunk sink says about continuing — the neutral host-owned [`busbar_substrate::egress::ChunkFlow`],
/// re-exported under this plane's historical name. A sink whose receiver has gone away asks the hop
/// to STOP rather than being written to forever: a caller that disconnected mid-stream must not
/// leave busbar holding a blocking thread against an upstream that is happy to keep talking.
pub(crate) use busbar_substrate::egress::ChunkFlow;

pub(crate) use busbar_substrate::egress::StreamHead;
/// The head of a streaming reply: what the backend answered before any body arrived — the neutral
/// host-owned [`busbar_substrate::egress::StreamHead`], re-exported under this plane's historical name so the
/// relay call sites read unchanged. It lives in [`busbar_core::egress`] because the streaming round trip
/// is the same one whatever framing sits on top of it.
pub(crate) use busbar_substrate::proxy::sse::{sse_data, SseReader};

/// THE RELAY'S SEAMS, HELD TOGETHER, for the reason [`super::transport::LiveCardFetch`] gives for
/// holding its own two: a caller that picked up a resolver and a transport from different places
/// could pair a real transport with a fixture resolver, which is the one combination that would
/// look tested and connect wherever the client felt like.
///
/// THERE IS NO `policy()` HERE, AND ITS ABSENCE IS LOAD-BEARING. This trait used to hand out the
/// plane's [`super::fetch::FetchPolicy`], and the ONE caller that ever asked was `pushdeliver`,
/// reading `allow_plaintext` off it to decide whether a push callback had to be `https`. That knob
/// is gone — HTTPS-only for push callbacks is structural, not defaulted — and with it the only
/// reason a seam had to expose a policy at all. A seam that cannot be asked for a policy is a
/// delivery path that cannot be told to relax one.
pub(crate) trait RelaySeam: Send + Sync {
    fn resolver(&self) -> &dyn Resolver;
    fn transport(&self) -> &dyn RelayTransport;
}

/// THE LIVE TRUST DECISION, as a seam, asked immediately before the socket.
///
/// A trait rather than a captured boolean, because a boolean is a decision that was true once. The
/// production implementation reads the plane's registry under its own lock at the moment it is
/// asked, so a re-verification sweep that demoted the registration a microsecond ago is visible
/// here.
pub(crate) trait DelegationGate: Send + Sync {
    /// `Ok(())` only while the named registration is still `Approved` **and** the registry is still
    /// at the generation the request was admitted under. Any other answer names the state it is in
    /// now, so the refusal an operator reads says what changed.
    ///
    /// `admitted` is carried in rather than read here for the reason the whole gate exists: a
    /// generation read at this moment would be the live one compared against itself.
    fn still_delegable(&self, agent_id: &str, admitted: u64) -> Result<(), NotDelegable>;
}

/// The registration is no longer a legal delegation target. Carries what it is NOW.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NotDelegable {
    pub(crate) agent_id: String,
    pub(crate) state: busbar_substrate::trust::TrustState,
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
    /// THE REGISTRY GENERATION THIS SUBMISSION WAS ADMITTED UNDER.
    ///
    /// Carried on the CALL rather than re-read at the gate, and that is the whole of what it buys: a
    /// value re-read at the gate is the live one compared against itself. Recorded at admission, so
    /// a config apply, a re-verification sweep or a breaker trip that lands between admission and
    /// the socket refuses THIS hop rather than the next one.
    pub(crate) admitted_generation: u64,
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
    /// THE `id` THIS HOP IS ANSWERING, established by [`busbar_substrate::ingress::jsonrpc::read`] at the
    /// ingress: a string or a number, never `null` and never absent.
    ///
    /// It is the id the BACKEND's answer must carry, and it is that only because `body` above goes
    /// out verbatim — so the id busbar sends to the backend IS the id busbar's own caller sent. If
    /// this relay ever rewrites the outbound envelope, these become two different facts and this
    /// field becomes two fields; the property is stated here because it is the assumption the
    /// correlation rests on, and an unstated assumption is one a later edit breaks silently.
    pub(crate) rpc_id: &'a serde_json::Value,
    /// THE `A2A-Version` THIS HOP DECLARES, at `Major.Minor`.
    ///
    /// busbar is a CLIENT here, and A2A section 3.3 says a client MUST send this header with each
    /// request; an absent or empty one means `0.3`. The value is the one busbar's own edge already
    /// negotiated from the caller — see `super::receive::Wire::negotiated_version` — because the
    /// body below goes out VERBATIM and the two dialects spell every method differently. Sending a
    /// v1.0 caller's `SendMessage` with no version declares `0.3` by omission and then speaks
    /// `1.0`, and a backend that believes the omission refuses a request busbar had just accepted
    /// as valid.
    pub(crate) a2a_version: &'a str,
    /// WHICH OF A2A'S THREE BINDINGS THIS HOP SPEAKS, as a framing rather than as a tag.
    ///
    /// Selected by LOOKUP from the backend's own card ([`framing_for`]), never by a branch: the
    /// hop below is ONE implementation and this is the only thing that varies across the three.
    /// See the `THE OUTBOUND BINDING` note further down for why re-framing is all that is owed.
    pub(crate) framing: &'a dyn OutboundFraming,
    /// THE ONE CORE BREAKER's cell for THIS TARGET — consulted in [`prepare`] immediately after
    /// the demotion gate and before the socket, so trust is still asked first and all three
    /// bindings inherit the admission by construction. The hop's outcome is recorded against the
    /// same cell on the way out. `None` (the originate direction, which the audit scopes out of
    /// this unit) admits everything and records nothing.
    pub(crate) breakers: Option<RelayBreaker>,
    /// THE NEUTRAL HOST SEAM this hop admits, settles and records its breaker through — the
    /// [`EngineHost`](busbar_substrate::plane_host::EngineHost) minted over the hop's admitted engine
    /// snapshot. [`prepare`]'s un-pooled admit WINS its probe through `host.breaker_admit` over
    /// [`host_scope`](Self::host_scope) (CLUSTER-1: the plane holds only the POD id, never a
    /// `PlaneAdmission`), [`record_hop_outcome`] settles/records through the same seam, and a refusal
    /// reads its `Retry-After` from `host.breaker_retry_after_secs`. Threaded (with `host_scope`) from
    /// the request path; `None` only where no scoped seam is wired.
    pub(crate) host: Option<&'a dyn busbar_substrate::plane_host::EngineHost>,
    /// THE ONE HOST SCOPE THIS HOP'S ADMIT AND SETTLE SHARE (§4 a2a scope unification). Created
    /// BEFORE `select_member` and moved onto the blocking relay thread, it is the single arena both
    /// the pooled WALK admit (pre-admitted upstream, its id in [`admission`](Self::admission)) and the
    /// un-pooled [`prepare`] admit (through [`host`](Self::host)) register their settle-capable
    /// probe hold into — so [`record_hop_outcome`] settles through it by a host
    /// [`AdmissionId`](busbar_plugin::hot::AdmissionId) in the same scope (the CLUSTER-1 inversion).
    /// `None` only where no scoped seam is wired.
    pub(crate) host_scope: Option<&'a busbar_substrate::plane_host::DispatchScope>,
    /// THE HOST ADMISSION ID FOR A PRE-ADMITTED (pooled WALK) HOP — the id the walk's probe hold was
    /// registered under in [`host_scope`](Self::host_scope) before this call was built.
    /// [`AdmissionId::NONE`](busbar_plugin::hot::AdmissionId::NONE) for an un-pooled hop (whose id
    /// [`prepare`] mints directly through the host `breaker_admit` seam) and in the originate direction.
    pub(crate) admission: busbar_plugin::hot::AdmissionId,
}

/// The breaker cell one relayed hop admits against and records into — plane-qualified key plus
/// pool lane, carried as ONE value so the ingress's selection (`failover::walk` over
/// `agent_pools:`) and the relay's recording cannot address two different cells.
#[derive(Clone)]
pub(crate) struct RelayBreaker {
    /// `"agent:<agent-id>"` for an un-pooled registration (the degenerate cell), `"agent:<pool>"`
    /// for a pool member.
    pub(crate) key: String,
    /// The member's position in its pool's `members:` list; 0 degenerate.
    pub(crate) lane: usize,
    /// `true` when the INGRESS already admitted this dispatch (the pooled fresh-submission walk
    /// holds the probe across the hop). [`prepare`] must then NOT admit again: a second admission
    /// against a HalfOpen cell would lose the single-flight race to our own probe and refuse the
    /// very dispatch the walk just selected.
    pub(crate) pre_admitted: bool,
}

impl RelayBreaker {
    /// The degenerate single-member cell for an un-pooled agent — the breaker unit's shape,
    /// unchanged. The cell store is reached through the hop's `host` seam, so this carries only the
    /// `(key, lane)` identity.
    pub(crate) fn degenerate(agent_id: &str) -> Self {
        RelayBreaker {
            key: busbar_substrate::store::agent_key(agent_id),
            lane: 0,
            pre_admitted: false,
        }
    }
}

/// THE REQUEST THE RELAY IS ABOUT TO SEND: everything, in one value.
///
/// One struct rather than a builder chain because it is what the adversarial no-leak scan reads,
/// and a test that has to reconstruct a request from a builder's intermediate state is a test that
/// can miss the field the builder added last.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OutboundRelayRequest {
    /// THE REQUEST LINE'S VERB. `POST` on the JSON-RPC and gRPC bindings, and whatever A2A section
    /// 11.3 binds the operation to on HTTP+JSON.
    pub(crate) http_method: &'static str,
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
    #[cfg(all(test, not(busbar_a2a_native)))]
    pub(crate) fn wire_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.http_method.as_bytes());
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
    /// THE BACKEND'S ANSWER DOES NOT NAME THE REQUEST BUSBAR SENT: a mismatched `id`, `"id": null`,
    /// or no `id` member at all.
    ///
    /// A refusal and not a pass-through, on BOTH the unary and the streamed path. See the module
    /// note "THE REPLY IS CORRELATED": an answer busbar cannot attribute is an answer to somebody
    /// else's question, and relaying it is how caller A is served backend-conversation B's result.
    /// The backend's payload is deliberately not carried into the refusal — it is another
    /// conversation's content and this string reaches an operator's log.
    Uncorrelated { url: String, reason: String },
    /// THE REQUEST COULD NOT BE FRAMED FOR THE BINDING THE BACKEND SPEAKS, or its answer could not
    /// be read back out of that binding's frame.
    ///
    /// A busbar-attributed 502 like every other arm here, and deliberately NOT a refusal aimed at
    /// the caller: a caller who sent a perfectly good `GetTask` is not at fault because the agent an
    /// operator registered publishes a binding on which busbar cannot spell it. The `binding` and
    /// `method` are both named because an operator reading this needs to know WHICH of the three
    /// legs refused and for which operation — "the relay could not frame the request" names
    /// neither.
    Unframable {
        binding: &'static str,
        method: String,
        reason: String,
    },
    /// THE AGENT'S BREAKER IS OPEN: the backend has been failing and busbar refused to dispatch —
    /// the call NEVER LEFT, which is why the ingress renders a fresh submission as the spec's own
    /// `rejected` ("we did not accept this work"), never `failed` ("we tried and it broke").
    /// `retry_after_secs` is the cell's EXACT remaining cooldown, not a guess.
    BreakerOpen {
        agent_id: String,
        retry_after_secs: u64,
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
            // Both are statements about the AGENT rather than about the hop — one from the trust
            // axis, one from the availability axis — and a caller sees one answer for "this agent
            // is not serving" whichever axis said so.
            RelayRefusal::Demoted(_) | RelayRefusal::BreakerOpen { .. } => 503,
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
            RelayRefusal::Uncorrelated { url, reason } => write!(
                f,
                "the backend agent at `{url}` answered something busbar cannot correlate to the \
                 request it sent, so it is refused rather than relayed: {reason}"
            ),
            RelayRefusal::Unframable {
                binding,
                method,
                reason,
            } => write!(
                f,
                "`{method}` could not be carried to this backend over its `{binding}` binding: \
                 {reason}"
            ),
            RelayRefusal::BreakerOpen {
                agent_id,
                retry_after_secs,
            } => write!(
                f,
                "agent `{agent_id}` is unavailable: its circuit breaker is open after repeated \
                 backend failures; busbar did not dispatch this request. Retry after \
                 {retry_after_secs}s"
            ),
        }
    }
}

/// A HOP THAT PRODUCED AN ANSWER.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RelayReply {
    /// The backend's JSON-RPC `result`, VERBATIM. [`rewrite_identity`] substitutes the two identity
    /// fields and everything else passes through; see the module note on content-blindness.
    pub(crate) result: serde_json::Value,
    /// THE BACKEND'S OWN TASK ID, before the substitution. See [`backend_task_id`].
    pub(crate) backend_task_id: Option<String>,
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

// ══ THE OUTBOUND BINDING: ONE HOP, THREE FRAMINGS ════════════════════════════════════════════════
//
// busbar is an A2A CLIENT here, and A2A defines THREE bindings of one agent. A backend an operator
// registered may publish any of them, and until this section existed busbar spoke exactly one: every
// hop went out as a JSON-RPC envelope, so a registered agent serving the HTTP+JSON or gRPC binding
// was unreachable through busbar by any sequence of operator actions.
//
// ## WHY THIS IS RE-FRAMING AND NOT A SECOND CLIENT
//
// A2A section 11.3 defines the REST binding BY REFERENCE to the JSON-RPC one: **the request body IS
// the JSON-RPC `params` verbatim, and the success body IS the `result` verbatim.** A2A v1.0's JSON
// representation of a gRPC message IS that message's ProtoJSON, which is the same document again.
// So all three bindings carry the SAME `(method, params) -> result` and differ only in
//
//   * where the method's NAME goes — a body member, the request line, or the `:path` pseudo-header;
//   * how the payload is WRAPPED — a JSON-RPC envelope, a bare document, or a length-prefixed
//     protobuf frame.
//
// That is FRAMING, and it is exactly the split `busbar_core::transport`'s header states: `framing =
// transport.frame(codec)`, with the codec never learning which channel spoke. So [`relay`] and
// [`relay_stream`] below are ONE implementation — one guard, one live trust gate, one lease, one
// correlation, one identity substitution — and the only thing that varies across the three legs is
// the [`OutboundFraming`] they are handed.
//
// ## THE BINDING IS SELECTED BY LOOKUP, NEVER BY A BRANCH
//
// [`framing_for`] maps the backend card's `protocolBinding` word onto a framing. There is no
// `if transport ==` on this path and there is no place for one — which is the same rule the
// receiving side already lives under (`super::rest`'s header: "which framing applies is settled by
// WHICH HANDLER THE ROUTER PICKED, before any code runs"), applied to the direction that picks its
// own.
//
// ## THE OPERATOR'S URL IS THE BASE. THE CARD SAYS *HOW*, NEVER *WHERE*.
//
// A card declares an interface's URL as well as its binding, and following that URL would let an
// upstream re-point busbar's outbound hop at a host the operator never wrote down. The SSRF guard
// would judge it, so it is not a hole — but it is an upstream choosing busbar's peer, which is the
// rug-pull the whole pinning apparatus exists to refuse one member up. So the base URL is always the
// operator's `backend_url` and the binding decides only what is APPENDED to it: the operation's path
// on HTTP+JSON, the service path on gRPC, nothing at all on JSON-RPC.

/// The A2A card word for each binding, as `AgentInterface.protocolBinding` spells it. These are the
/// specification's tokens, so they are compared case-insensitively but never re-spelt.
pub(crate) const BINDING_JSONRPC: &str = "JSONRPC";
pub(crate) const BINDING_HTTP_JSON: &str = "HTTP+JSON";
pub(crate) const BINDING_GRPC: &str = "GRPC";

/// ONE REQUEST, FRAMED FOR ONE BINDING: everything about it that the binding decided.
pub(crate) struct FramedRequest {
    /// The request line's verb.
    pub(crate) http_method: &'static str,
    pub(crate) url: reqwest::Url,
    /// The `content-type` this framing sends, or `None` for a request with no body at all (a REST
    /// `GET` or `DELETE`) — where a media type would be describing a document that is not there.
    pub(crate) content_type: Option<&'static str>,
    /// The `accept` this framing sends.
    pub(crate) accept: &'static str,
    pub(crate) body: Vec<u8>,
}

/// THE CALLER'S REQUEST, READ ONCE, in the three forms the framings need it in.
///
/// `verbatim` is the caller's own bytes and is what the JSON-RPC framing sends — content-blindness
/// is a property of that binding and re-serializing would spend it for nothing. The other two
/// bindings cannot be couriers (they have to author a different document), so they read `method`
/// and `params`, which is the same admission `super::grpc`'s header makes for the receiving
/// direction.
pub(crate) struct Outbound<'a> {
    pub(crate) verbatim: &'a [u8],
    pub(crate) method: &'a str,
    pub(crate) params: &'a serde_json::Value,
}

/// WHOLE FRAMES OUT OF A STREAMED BODY, in the JSON-RPC dialect [`read_event`] reads.
///
/// A trait rather than a concrete reader because the three bindings do not agree on what a frame IS:
/// JSON-RPC and HTTP+JSON stream SSE (and differ only in whether the `data:` payload is an envelope
/// or the bare event), and gRPC streams length-prefixed protobuf messages with no SSE anywhere. What
/// they DO agree on is what comes out — one SSE frame carrying one JSON-RPC response — so
/// [`read_event`] is one implementation reading one dialect, and the re-framing happens here.
pub(crate) trait FrameReader: Send {
    /// Feed a chunk and take every COMPLETE frame it finished, already re-framed.
    fn feed(&mut self, chunk: &[u8]) -> Vec<String>;
    /// How many bytes are held waiting for a terminator, for the ceiling check.
    fn pending(&self) -> usize;
}

/// ONE OF A2A'S THREE BINDINGS, AS THE OUTBOUND HOP SEES IT.
///
/// `Send + Sync` and reached as a `&'static dyn`: the three are stateless values, so a framing is a
/// vtable rather than an object anybody has to build.
pub(crate) trait OutboundFraming: Send + Sync {
    /// The card word this framing answers to. Carried so a refusal names the leg.
    fn word(&self) -> &'static str;

    /// The axis label for this leg, for telemetry. A STATEMENT OF FACT at a known arrival, which is
    /// what `busbar_core::transport`'s own note says naming a variant is for; nothing compares it.
    fn leg(&self) -> busbar_substrate::transport::Transport;

    /// Compose the wire request. `base` is the operator's guarded, pinned endpoint.
    fn compose(
        &self,
        base: &reqwest::Url,
        call: &Outbound<'_>,
        streaming: bool,
    ) -> Result<FramedRequest, String>;

    /// Re-frame a COMPLETED answer into the JSON-RPC envelope [`read_reply`] reads.
    ///
    /// Returning the envelope rather than the `result` is what keeps the reader ONE reader: the
    /// correlation, the `jsonrpc` member check and the `error` arm are the same three rules on all
    /// three legs, and a binding that handed back a bare payload would have had to re-implement
    /// them or skip them.
    fn read_answer(
        &self,
        method: &str,
        body: &[u8],
        rpc_id: &serde_json::Value,
    ) -> Result<Vec<u8>, String>;

    /// The frame reader for a STREAMED answer on this binding.
    fn reader(&self, method: &str, rpc_id: &serde_json::Value) -> Box<dyn FrameReader>;
}

/// THE LOOKUP. An unknown word is `None` — a registration whose card declares a binding this build
/// cannot speak is refused at the hop with the word named, rather than silently relayed as JSON-RPC
/// to a peer that does not speak it.
pub(crate) fn framing_for(word: &str) -> Option<&'static dyn OutboundFraming> {
    let word = word.trim().to_ascii_uppercase();
    if word == BINDING_JSONRPC {
        return Some(&JsonRpcFraming);
    }
    if word == BINDING_HTTP_JSON {
        return Some(&HttpJsonFraming);
    }
    if word == BINDING_GRPC {
        return Some(&GrpcFraming);
    }
    None
}

/// THE JSON-RPC FRAMING AS A VALUE, for tests that need one to hand to [`build_request`] or to a
/// [`RelayCall`].
///
/// `#[cfg(all(test, not(busbar_a2a_native)))]` deliberately. Production never reaches for "the default": [`binding_of`] reads a
/// word off the registration's card and [`framing_for`] resolves it, and a production `default_…`
/// beside those two would be a third answer to "which binding is this hop" that no card ever
/// authorised — which is exactly the shape a fail-open acquires.
#[cfg(all(test, not(busbar_a2a_native)))]
pub(crate) fn default_framing() -> &'static dyn OutboundFraming {
    &JsonRpcFraming
}

/// THE BINDING A REGISTRATION'S CACHED CARD DECLARES, or [`BINDING_JSONRPC`] where it declares none.
///
/// The FIRST entry of `supportedInterfaces` is the agent's preferred one, which is A2A's own rule,
/// so this reads in order and takes the first word busbar can speak rather than the first word
/// present — an agent that lists gRPC first and JSON-RPC second is reachable on the second by a
/// build that speaks it, and a build that speaks neither refuses by name at the hop.
pub(crate) fn binding_of(card: Option<&serde_json::Value>) -> String {
    let Some(interfaces) = card
        .and_then(|c| c.get("supportedInterfaces"))
        .and_then(serde_json::Value::as_array)
    else {
        return BINDING_JSONRPC.to_string();
    };
    let words: Vec<&str> = interfaces
        .iter()
        .filter_map(|i| i.get("protocolBinding"))
        .filter_map(serde_json::Value::as_str)
        .filter(|w| !w.trim().is_empty())
        .collect();
    if words.is_empty() {
        return BINDING_JSONRPC.to_string();
    }
    words
        .iter()
        .find(|w| framing_for(w).is_some())
        // NOT a fallback to JSON-RPC. A card that declares interfaces and none of them is one busbar
        // speaks must reach `framing_for` and be refused BY NAME; answering `JSONRPC` here would send
        // an envelope to a peer that has just said it does not speak one.
        .map_or_else(|| words[0].to_string(), |w| (*w).to_string())
}

// ── The JSON-RPC framing: the courier. ──────────────────────────────────────────────────────────

struct JsonRpcFraming;

impl OutboundFraming for JsonRpcFraming {
    fn word(&self) -> &'static str {
        BINDING_JSONRPC
    }

    fn leg(&self) -> busbar_substrate::transport::Transport {
        busbar_substrate::transport::Transport::JsonRpc
    }

    fn compose(
        &self,
        base: &reqwest::Url,
        call: &Outbound<'_>,
        streaming: bool,
    ) -> Result<FramedRequest, String> {
        Ok(FramedRequest {
            http_method: "POST",
            url: base.clone(),
            content_type: Some(CONTENT_TYPE),
            accept: if streaming {
                ACCEPT_STREAM
            } else {
                CONTENT_TYPE
            },
            // VERBATIM. The whole property of this binding: the caller's bytes, unread and
            // un-normalised, so a member busbar does not model still reaches the backend.
            body: call.verbatim.to_vec(),
        })
    }

    fn read_answer(
        &self,
        _method: &str,
        body: &[u8],
        _rpc_id: &serde_json::Value,
    ) -> Result<Vec<u8>, String> {
        Ok(body.to_vec())
    }

    fn reader(&self, _method: &str, _rpc_id: &serde_json::Value) -> Box<dyn FrameReader> {
        Box::new(SseReader::default())
    }
}

impl FrameReader for SseReader {
    fn feed(&mut self, chunk: &[u8]) -> Vec<String> {
        SseReader::feed(self, chunk)
    }
    fn pending(&self) -> usize {
        SseReader::pending(self)
    }
}

// ── The HTTP+JSON framing: section 11.3, applied in the direction that composes. ─────────────────

/// WHERE ONE OPERATION LIVES ON THE REST BINDING: the request line, and which members of `params`
/// the request line and the query string consume.
///
/// The INVERSE of `super::rest`'s route table, and it has to be an inverse rather than a copy: that
/// module reads a request line and composes `params`, this one reads `params` and composes a request
/// line. The two are checked against each other by `rest_client_tests`, which drives a composed
/// request straight back through busbar's own REST routes — a client and a server that agree only
/// with themselves is the failure the relay harness's `backend_ok_for` note already paid for once.
struct RestOp {
    http_method: &'static str,
    /// The path, relative to the operator's endpoint. `{member}` is substituted from `params`.
    path: &'static str,
    /// The `params` members that ride the query string instead.
    query: &'static [&'static str],
    /// Does whatever is LEFT of `params` travel as the request body?
    ///
    /// `false` for the reads and the delete, where A2A's request line carries the whole request and
    /// a body would be a document the specification does not define. A leftover member on one of
    /// those is a request this binding cannot carry, and it is refused rather than dropped.
    body: bool,
}

/// THE ELEVEN OPERATIONS, in A2A v1.0's spelling, each with its REST row.
///
/// The v1.0 names are `super::rest::method`'s constants rather than fresh literals: one spelling per
/// wire word in the tree, and the server binding and the client binding provably name the same
/// eleven operations.
fn rest_op(method: &str) -> Option<RestOp> {
    use super::rest::method as m;
    let op = match canonical_method(method)? {
        m::SEND_MESSAGE => RestOp {
            http_method: "POST",
            path: "/message:send",
            query: &[],
            body: true,
        },
        m::SEND_STREAMING_MESSAGE => RestOp {
            http_method: "POST",
            path: "/message:stream",
            query: &[],
            body: true,
        },
        m::GET_TASK => RestOp {
            http_method: "GET",
            path: "/tasks/{id}",
            query: &["historyLength"],
            body: false,
        },
        m::LIST_TASKS => RestOp {
            http_method: "GET",
            path: "/tasks",
            query: &[
                "contextId",
                "status",
                "pageSize",
                "pageToken",
                "historyLength",
                "statusTimestampAfter",
                "includeArtifacts",
            ],
            body: false,
        },
        m::CANCEL_TASK => RestOp {
            http_method: "POST",
            path: "/tasks/{id}:cancel",
            query: &[],
            body: false,
        },
        m::SUBSCRIBE_TO_TASK => RestOp {
            http_method: "POST",
            path: "/tasks/{id}:subscribe",
            query: &[],
            body: false,
        },
        m::CREATE_PUSH_CONFIG => RestOp {
            http_method: "POST",
            path: "/tasks/{taskId}/pushNotificationConfigs",
            query: &[],
            body: true,
        },
        m::LIST_PUSH_CONFIGS => RestOp {
            http_method: "GET",
            path: "/tasks/{taskId}/pushNotificationConfigs",
            query: &["pageSize", "pageToken"],
            body: false,
        },
        m::GET_PUSH_CONFIG => RestOp {
            http_method: "GET",
            path: "/tasks/{taskId}/pushNotificationConfigs/{id}",
            query: &[],
            body: false,
        },
        m::DELETE_PUSH_CONFIG => RestOp {
            http_method: "DELETE",
            path: "/tasks/{taskId}/pushNotificationConfigs/{id}",
            query: &[],
            body: false,
        },
        m::GET_EXTENDED_AGENT_CARD => RestOp {
            http_method: "GET",
            path: "/extendedAgentCard",
            query: &[],
            body: false,
        },
        // `canonical_method` is total over the eleven, so this arm is unreachable — written rather
        // than `unreachable!()` because a panic on a routing hot path is a panic waiting for the day
        // somebody adds a twelfth name to the table above and not to this one.
        _ => return None,
    };
    Some(op)
}

/// THE OPERATION A METHOD NAME NAMES, in A2A v1.0's spelling, from EITHER dialect.
///
/// This plane speaks two protocol versions and every reader on it already handles both — see
/// `super::local::verb_of` and `super::receive::shape_of`. The two non-JSON-RPC bindings are v1.0
/// constructs, so a v0.3 caller's `tasks/get` has to be recognised as `GetTask` before it can be
/// framed for one; a table that read only the v1.0 spelling would refuse every v0.3 caller at the
/// hop with "no such operation", which is busbar failing to carry a request it had just admitted.
fn canonical_method(method: &str) -> Option<&'static str> {
    use super::rest::method as m;
    Some(match method {
        "SendMessage" | "message/send" => m::SEND_MESSAGE,
        "SendStreamingMessage" | "message/stream" => m::SEND_STREAMING_MESSAGE,
        "GetTask" | "tasks/get" => m::GET_TASK,
        "ListTasks" | "tasks/list" => m::LIST_TASKS,
        "CancelTask" | "tasks/cancel" => m::CANCEL_TASK,
        "SubscribeToTask" | "tasks/resubscribe" => m::SUBSCRIBE_TO_TASK,
        "CreateTaskPushNotificationConfig" | "tasks/pushNotificationConfig/set" => {
            m::CREATE_PUSH_CONFIG
        }
        "GetTaskPushNotificationConfig" | "tasks/pushNotificationConfig/get" => m::GET_PUSH_CONFIG,
        "ListTaskPushNotificationConfigs" | "tasks/pushNotificationConfig/list" => {
            m::LIST_PUSH_CONFIGS
        }
        "DeleteTaskPushNotificationConfig" | "tasks/pushNotificationConfig/delete" => {
            m::DELETE_PUSH_CONFIG
        }
        "GetExtendedAgentCard" | "agent/getAuthenticatedExtendedCard" => m::GET_EXTENDED_AGENT_CARD,
        _ => return None,
    })
}

struct HttpJsonFraming;

impl OutboundFraming for HttpJsonFraming {
    fn word(&self) -> &'static str {
        BINDING_HTTP_JSON
    }

    fn leg(&self) -> busbar_substrate::transport::Transport {
        busbar_substrate::transport::Transport::HttpJson
    }

    fn compose(
        &self,
        base: &reqwest::Url,
        call: &Outbound<'_>,
        streaming: bool,
    ) -> Result<FramedRequest, String> {
        let op = rest_op(call.method).ok_or_else(|| {
            format!(
                "`{}` is not one of the eleven operations A2A's HTTP+JSON binding defines",
                call.method
            )
        })?;
        // A `params` that is not an object cannot have a path member taken out of it, and every
        // operation on this binding either has one or has no request document at all.
        let empty = serde_json::Map::new();
        let members = call.params.as_object().unwrap_or(&empty);
        let mut left = members.clone();

        // ── THE PATH. Substituted from `params`, and a missing member is a refusal rather than an
        //    empty segment: `/tasks//pushNotificationConfigs` addresses nothing, and sending it
        //    would turn a malformed request into a 404 from a backend that never saw the problem.
        let mut path = String::new();
        let mut rest = op.path;
        while let Some(open) = rest.find('{') {
            path.push_str(&rest[..open]);
            let close = rest[open..]
                .find('}')
                .ok_or_else(|| format!("the route template `{}` is malformed", op.path))?
                + open;
            let name = &rest[open + 1..close];
            let value = left
                .remove(name)
                .ok_or_else(|| format!("`{}` names no `{name}` to address", call.method))?;
            let value = value.as_str().map(str::to_string).unwrap_or_else(|| {
                // A JSON number is a legal id on the wire and `to_string` renders it without the
                // quotes a `Value`'s Display would keep for a string.
                value.to_string()
            });
            if value.is_empty() {
                return Err(format!("`{}`'s `{name}` is empty", call.method));
            }
            path.push_str(&percent(&value));
            rest = &rest[close + 1..];
        }
        path.push_str(rest);

        let mut url = base.clone();
        // JOINED ONTO THE OPERATOR'S PATH rather than replacing it. `Url::join` would treat a
        // leading `/` as absolute and throw away the `/a2a` an operator wrote, so the two are
        // concatenated with exactly one separator between them.
        let joined = format!("{}{path}", base.path().trim_end_matches('/'));
        url.set_path(&joined);
        {
            let mut query = url.query_pairs_mut();
            query.clear();
            for name in op.query {
                if let Some(value) = left.remove(*name) {
                    query.append_pair(name, &scalar(&value));
                }
            }
        }
        // `query_pairs_mut` writes an empty `?` when nothing was appended; an empty query string is
        // not the same request as no query string.
        if url.query() == Some("") {
            url.set_query(None);
        }

        // ── THE BODY. Section 11.3: it IS the remaining `params`, verbatim.
        if !op.body && !left.is_empty() {
            let mut names: Vec<&String> = left.keys().collect();
            names.sort();
            return Err(format!(
                "`{}` carries {names:?}, which A2A's HTTP+JSON binding has nowhere to put on a \
                 `{}` request",
                call.method, op.http_method
            ));
        }
        let body = if op.body {
            serde_json::to_vec(&serde_json::Value::Object(left))
                .map_err(|e| format!("the request params could not be rendered: {e}"))?
        } else {
            Vec::new()
        };
        Ok(FramedRequest {
            http_method: op.http_method,
            url,
            content_type: op.body.then_some(CONTENT_TYPE),
            accept: if streaming {
                ACCEPT_STREAM
            } else {
                CONTENT_TYPE
            },
            body,
        })
    }

    /// Section 11.3 again, in the other direction: the success body IS the `result`. It is WRAPPED
    /// back into a JSON-RPC envelope so the one reader reads it — see [`OutboundFraming::read_answer`].
    fn read_answer(
        &self,
        _method: &str,
        body: &[u8],
        rpc_id: &serde_json::Value,
    ) -> Result<Vec<u8>, String> {
        // A2A binds `DeleteTaskPushNotificationConfig` to an EMPTY 200 body. Its JSON-RPC answer is
        // `"result": null`, so an empty body is that answer rather than a malformed one; treating it
        // as a parse failure would make the one operation with nothing to say the one that always
        // fails.
        let result = if body.iter().all(u8::is_ascii_whitespace) {
            serde_json::Value::Null
        } else {
            serde_json::from_slice::<serde_json::Value>(body)
                .map_err(|e| format!("the answer is not JSON: {e}"))?
        };
        envelope_bytes(rpc_id, result)
    }

    fn reader(&self, _method: &str, rpc_id: &serde_json::Value) -> Box<dyn FrameReader> {
        Box::new(RestSseReader {
            inner: SseReader::default(),
            rpc_id: rpc_id.clone(),
        })
    }
}

/// One JSON-RPC success envelope, as bytes.
fn envelope_bytes(
    rpc_id: &serde_json::Value,
    result: serde_json::Value,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": rpc_id,
        "result": result,
    }))
    .map_err(|e| format!("the answer could not be re-framed: {e}"))
}

/// A query-string value. The inverse of `super::rest::json_scalar`: a string goes as itself and
/// anything else goes as its JSON rendering, so `historyLength: 5` becomes `historyLength=5` rather
/// than `historyLength="5"`.
fn scalar(value: &serde_json::Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), str::to_string)
}

/// Percent-encode one path SEGMENT's worth of text.
///
/// Hand-written against an ALLOWLIST rather than reached for from a crate: the set of characters
/// that may appear unescaped in a path segment is small and closed, and everything outside it is
/// escaped. A blocklist here would be a way for a task id containing `/` or `?` to re-point the
/// request line, which is a caller choosing busbar's outbound path.
fn percent(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for b in raw.bytes() {
        let safe = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~');
        if safe {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// THE REST BINDING'S STREAM, RE-FRAMED EVENT BY EVENT.
///
/// A2A's REST binding streams SSE whose `data:` payload is the BARE event — that is `super::rest`'s
/// own rule for the direction that serves it, and this is its inverse. Each payload is wrapped back
/// into a JSON-RPC response so [`read_event`] reads one dialect on all three legs.
///
/// A frame whose payload is not JSON, or that carries no `data:` at all, passes through UNCHANGED:
/// a stream legitimately carries comments and keep-alives, and re-framing what it cannot read would
/// turn a backend's own extension into a corrupted frame.
struct RestSseReader {
    inner: SseReader,
    rpc_id: serde_json::Value,
}

impl FrameReader for RestSseReader {
    fn feed(&mut self, chunk: &[u8]) -> Vec<String> {
        self.inner
            .feed(chunk)
            .into_iter()
            .map(|frame| match sse_data(&frame) {
                Some(data) => match serde_json::from_str::<serde_json::Value>(&data) {
                    Ok(event) => format!(
                        "data: {}\n\n",
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": self.rpc_id,
                            "result": event,
                        })
                    ),
                    Err(_) => frame,
                },
                None => frame,
            })
            .collect()
    }

    fn pending(&self) -> usize {
        self.inner.pending()
    }
}

// ── The gRPC framing: the SDK's own conversions, in the direction that sends. ────────────────────

/// The `content-type` a gRPC request and its answer carry.
const GRPC_CONTENT_TYPE: &str = "application/grpc+proto";

/// The length-prefix every gRPC message carries: one compression flag byte and a four-byte
/// big-endian length.
const GRPC_PREFIX: usize = 5;

struct GrpcFraming;

impl OutboundFraming for GrpcFraming {
    fn word(&self) -> &'static str {
        BINDING_GRPC
    }

    fn leg(&self) -> busbar_substrate::transport::Transport {
        busbar_substrate::transport::Transport::Grpc
    }

    /// The rpc's own path under the service `a2a.proto` declares, and one length-prefixed message.
    ///
    /// The path is built from [`super::serve::GRPC_MOUNT_PATH`] — the SAME string busbar's own gRPC
    /// binding is served at and `PlaneDispatch` claims — so the client direction and the server
    /// direction cannot drift apart about what the service is called.
    fn compose(
        &self,
        base: &reqwest::Url,
        call: &Outbound<'_>,
        _streaming: bool,
    ) -> Result<FramedRequest, String> {
        let rpc = canonical_method(call.method).ok_or_else(|| {
            format!(
                "`{}` is not one of the eleven rpcs A2A's gRPC service declares",
                call.method
            )
        })?;
        let mut url = base.clone();
        // ABSOLUTE, not joined onto the operator's path. A gRPC `:path` is the fully-qualified
        // service and rpc and nothing else — a server routes on it exactly, so prefixing it with
        // whatever path an operator wrote for the JSON-RPC endpoint would address nothing.
        url.set_path(&format!("{}/{rpc}", super::serve::GRPC_MOUNT_PATH));
        url.set_query(None);
        Ok(FramedRequest {
            http_method: "POST",
            url,
            content_type: Some(GRPC_CONTENT_TYPE),
            accept: GRPC_CONTENT_TYPE,
            body: grpc_encode(rpc, call.params)?,
        })
    }

    /// One length-prefixed message in, one JSON-RPC envelope out. The answer's TYPE is the rpc's,
    /// which is why the method is an argument here: a protobuf frame carries no self-description,
    /// so a reader that did not know which rpc it answered could not decode it at all.
    fn read_answer(
        &self,
        method: &str,
        body: &[u8],
        rpc_id: &serde_json::Value,
    ) -> Result<Vec<u8>, String> {
        let rpc = canonical_method(method)
            .ok_or_else(|| format!("`{method}` is not an rpc of A2A's gRPC service"))?;
        let (len, _) = grpc_split(body)?
            .ok_or_else(|| "the peer's gRPC answer carried no complete message".to_string())?;
        envelope_bytes(
            rpc_id,
            grpc_decode(rpc, &body[GRPC_PREFIX..GRPC_PREFIX + len])?,
        )
    }

    fn reader(&self, method: &str, rpc_id: &serde_json::Value) -> Box<dyn FrameReader> {
        Box::new(GrpcFrameReader {
            buf: Vec::new(),
            rpc: canonical_method(method).unwrap_or(method).to_string(),
            rpc_id: rpc_id.clone(),
        })
    }
}

/// ONE LENGTH-PREFIXED gRPC MESSAGE, from the ProtoJSON `params` A2A v1.0 says the request IS.
///
/// The conversions are the SDK's — `a2a_pb::protojson_conv` — and they are the SAME ones
/// `super::grpc` uses to read a request in the other direction. That is the whole reason this is
/// short: the translation exists exactly once per direction, so there is one reader and one writer
/// and nothing to diverge.
fn grpc_encode(rpc: &str, params: &serde_json::Value) -> Result<Vec<u8>, String> {
    use super::rest::method as m;
    let params = params.clone();
    match rpc {
        m::SEND_MESSAGE | m::SEND_STREAMING_MESSAGE => {
            grpc_frame::<a2a::SendMessageRequest>(params)
        }
        m::GET_TASK => grpc_frame::<a2a::GetTaskRequest>(params),
        m::LIST_TASKS => grpc_frame::<a2a::ListTasksRequest>(params),
        m::CANCEL_TASK => grpc_frame::<a2a::CancelTaskRequest>(params),
        m::SUBSCRIBE_TO_TASK => grpc_frame::<a2a::SubscribeToTaskRequest>(params),
        m::CREATE_PUSH_CONFIG => grpc_frame::<a2a::TaskPushNotificationConfig>(params),
        m::GET_PUSH_CONFIG => grpc_frame::<a2a::GetTaskPushNotificationConfigRequest>(params),
        m::LIST_PUSH_CONFIGS => grpc_frame::<a2a::ListTaskPushNotificationConfigsRequest>(params),
        m::DELETE_PUSH_CONFIG => grpc_frame::<a2a::DeleteTaskPushNotificationConfigRequest>(params),
        m::GET_EXTENDED_AGENT_CARD => grpc_frame::<a2a::GetExtendedAgentCardRequest>(params),
        other => Err(format!("`{other}` is not an rpc of A2A's gRPC service")),
    }
}

/// THE ANSWER TO ONE RPC, as the ProtoJSON document A2A v1.0 says the `result` IS.
fn grpc_decode(rpc: &str, message: &[u8]) -> Result<serde_json::Value, String> {
    use super::rest::method as m;
    match rpc {
        m::SEND_MESSAGE => grpc_read::<a2a::SendMessageResponse>(message),
        m::SEND_STREAMING_MESSAGE | m::SUBSCRIBE_TO_TASK => {
            grpc_read::<a2a::StreamResponse>(message)
        }
        m::GET_TASK | m::CANCEL_TASK => grpc_read::<a2a::Task>(message),
        m::LIST_TASKS => grpc_read::<a2a::ListTasksResponse>(message),
        m::CREATE_PUSH_CONFIG | m::GET_PUSH_CONFIG => {
            grpc_read::<a2a::TaskPushNotificationConfig>(message)
        }
        m::LIST_PUSH_CONFIGS => grpc_read::<a2a::ListTaskPushNotificationConfigsResponse>(message),
        // `google.protobuf.Empty`. The JSON-RPC answer to this verb is `null` and there is nothing
        // in the frame to transcode, which is the same statement `super::grpc` makes serving it.
        m::DELETE_PUSH_CONFIG => Ok(serde_json::Value::Null),
        m::GET_EXTENDED_AGENT_CARD => grpc_read::<a2a::AgentCard>(message),
        other => Err(format!("`{other}` is not an rpc of A2A's gRPC service")),
    }
}

/// ProtoJSON in, one length-prefixed protobuf frame out.
fn grpc_frame<T>(params: serde_json::Value) -> Result<Vec<u8>, String>
where
    T: a2a_pb::protojson_conv::ProtoJsonPayload,
{
    use prost::Message as _;
    let native: T = a2a_pb::protojson_conv::from_value(params)
        .map_err(|e| format!("the request could not be rendered as protobuf: {e}"))?;
    let proto = T::to_proto(&native);
    let len = proto.encoded_len();
    let mut out = Vec::with_capacity(GRPC_PREFIX + len);
    // The compression flag. Zero: busbar sends no `grpc-encoding`, so a compressed frame would be
    // one the peer was never told to expect.
    out.push(0);
    out.extend_from_slice(
        &u32::try_from(len)
            .map_err(|_| "the request is too large for one gRPC frame".to_string())?
            .to_be_bytes(),
    );
    proto
        .encode(&mut out)
        .map_err(|e| format!("the protobuf frame could not be written: {e}"))?;
    Ok(out)
}

/// One length-prefixed protobuf frame in, the ProtoJSON `result` out.
fn grpc_read<T>(message: &[u8]) -> Result<serde_json::Value, String>
where
    T: a2a_pb::protojson_conv::ProtoJsonPayload,
{
    use prost::Message as _;
    let proto = <T as a2a_pb::protojson_conv::ProtoJsonPayload>::Proto::decode(message)
        .map_err(|e| format!("the answer is not a readable protobuf message: {e}"))?;
    let native =
        T::try_from_proto(&proto).map_err(|e| format!("the answer could not be read: {e}"))?;
    a2a_pb::protojson_conv::to_value(&native)
        .map_err(|e| format!("the answer could not be rendered: {e}"))
}

/// The payload of one length-prefixed gRPC frame at the head of `buf`, and how many bytes it
/// consumed. `None` while the frame is still arriving.
///
/// A COMPRESSED frame is an error rather than a skip: busbar sends no `grpc-accept-encoding`, so a
/// peer that compressed anyway has answered in a framing busbar cannot read, and passing an
/// undecompressed body to the protobuf reader would produce a parse error blaming the wrong thing.
fn grpc_split(buf: &[u8]) -> Result<Option<(usize, usize)>, String> {
    if buf.len() < GRPC_PREFIX {
        return Ok(None);
    }
    if buf[0] != 0 {
        return Err("the peer compressed a gRPC frame busbar did not offer to decompress".into());
    }
    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    if buf.len() < GRPC_PREFIX + len {
        return Ok(None);
    }
    Ok(Some((len, GRPC_PREFIX + len)))
}

/// THE gRPC SERVER-STREAM, RE-FRAMED MESSAGE BY MESSAGE.
///
/// A gRPC stream is a sequence of length-prefixed messages on one HTTP/2 body, with no SSE anywhere
/// — so this reader is genuinely different from the other two, and that difference is the whole
/// reason [`FrameReader`] is a trait. What it EMITS is the same as theirs: one SSE frame carrying
/// one JSON-RPC response, so [`read_event`] stays one implementation reading one dialect.
struct GrpcFrameReader {
    buf: Vec<u8>,
    rpc: String,
    rpc_id: serde_json::Value,
}

impl FrameReader for GrpcFrameReader {
    fn feed(&mut self, chunk: &[u8]) -> Vec<String> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        // A malformed frame STOPS the reader rather than being skipped: the length prefix is how
        // the next frame is found, so a frame busbar cannot read is a stream busbar has lost its
        // place in, and guessing where the next one starts is how a caller is served somebody
        // else's bytes.
        while let Ok(Some((len, consumed))) = grpc_split(&self.buf) {
            let message = self.buf[GRPC_PREFIX..GRPC_PREFIX + len].to_vec();
            self.buf.drain(..consumed);
            let Ok(event) = grpc_decode(&self.rpc, &message) else {
                break;
            };
            out.push(format!(
                "data: {}\n\n",
                serde_json::json!({ "jsonrpc": "2.0", "id": self.rpc_id, "result": event })
            ));
        }
        out
    }

    fn pending(&self) -> usize {
        self.buf.len()
    }
}

/// BUILD THE OUTBOUND REQUEST. Separated from [`relay`] so the scan can read the request as a value
/// rather than having to intercept a socket.
///
/// Every header on the result is one of exactly three things: a constant, the protocol version
/// busbar's own edge negotiated, or the operator's leased credential. There is no fourth source,
/// and in particular nothing of the CALLER's request travels here — the defect that rule exists to
/// prevent is the caller's own credential going out on the backend hop.
pub(crate) fn build_request(
    framed: FramedRequest,
    agent_id: &str,
    lease: Option<&Lease>,
    a2a_version: &str,
    now_ms: u64,
) -> Result<OutboundRelayRequest, LeaseError> {
    let mut headers = Vec::new();
    // A REQUEST WITH NO DOCUMENT CARRIES NO MEDIA TYPE. A REST `GET` or `DELETE` sends no body, and
    // a `content-type` on one describes a document that is not there.
    if let Some(content_type) = framed.content_type {
        headers.push(("content-type".to_string(), content_type.to_string()));
    }
    headers.push(("accept".to_string(), framed.accept.to_string()));
    // A CONSTANT IN SHAPE, THE CALLER'S IN VALUE. It is not a fourth source of header material
    // in the sense the note above refuses: nothing of the caller's REQUEST travels here, only
    // the protocol version busbar's own edge already negotiated and admitted, restated so the
    // backend is told which dialect the relayed method is written in.
    headers.push(("a2a-version".to_string(), a2a_version.to_string()));
    if let Some(lease) = lease {
        // `header_for` checks BOTH that the lease was minted for this agent and that it is still
        // live. Both checks live on the lease rather than here, so a call site cannot forget one.
        let (name, value) = lease.header_for(agent_id, now_ms)?;
        headers.push((name.to_ascii_lowercase(), value));
    }
    Ok(OutboundRelayRequest {
        http_method: framed.http_method,
        url: framed.url.to_string(),
        headers,
        body: framed.body,
    })
}

/// THE CALLER'S ENVELOPE, READ ONCE PER HOP.
///
/// The JSON-RPC framing never looks at either member — it sends `body` verbatim — so this parse is
/// pure cost on the binding that is the common case. It is done anyway, once, in the shared
/// preamble rather than inside the two framings that need it, because the alternative is each
/// framing parsing for itself and the caller's bytes being read a different number of times
/// depending on which binding a backend happened to publish.
fn outbound_of(body: &[u8]) -> (String, serde_json::Value) {
    let envelope: serde_json::Value =
        serde_json::from_slice(body).unwrap_or(serde_json::Value::Null);
    (
        super::local::method_of(&envelope).to_string(),
        envelope
            .get("params")
            .cloned()
            .unwrap_or(serde_json::Value::Null),
    )
}

/// RECORD ONE HOP'S OUTCOME against the agent's breaker cell — this plane's Stage-1 normalizer
/// (see docs/circuit-breaker.md's two-stage pipeline), Stage 2 being the one core `breaker::classify`
/// inside `PlaneBreakers::record_signal`. `refusal: None` is a hop that produced an answer.
///
/// The `settle` [`AdmissionId`](busbar_plugin::hot::AdmissionId) is the shared-scope handle this hop's
/// outcome is FOLDED THROUGH (CLUSTER-1 breaker inversion): when a [`host_scope`](RelayCall::host_scope)
/// owns this hop's probe, the classified outcome is settled through it over `settle` — the same arena
/// the walk-admit registered into. Without a shared scope (originate / unit tests that admit directly)
/// the classified outcome records IN PLACE against the local probe. The disposition is byte-identical
/// either way: [`busbar_core::plane_host::breaker::failure_signal`] is the inverse of the host's `classify`,
/// so a settle folds through the SAME `record_signal` the in-place call runs.
///
/// CLASSIFICATION stays here — where the refusal's transport/status structure still exists (Stage 1) —
/// and only the SETTLE moves to the scope. What records and what deliberately does not:
/// - `Transport` → `Network`; `Status` → classified from the HTTP status (401/403 → hard down,
///   5xx/429 → transient, true 4xx → ClientFault, never a penalty).
/// - `BodyTooLarge` / `NotJson` / `Uncorrelated` → `ServerError`: the backend answered 2xx and the
///   answer was unusable, which is the upstream misbehaving on the wire.
/// - `BackendError` records a SUCCESS: the backend was reachable and answered a well-formed A2A
///   error — a task-level failure from a backend that answered is the WORK failing, not the wire.
/// - `Guard` / `Lease` / `Unframable` are busbar-side (nothing reached the backend); `Demoted` is
///   TRUST, not health; `BreakerOpen` is the cell already speaking. None of them record — through a
///   shared scope this means the probe is left UNSETTLED so the scope's drop releases it.
fn record_hop_outcome(
    call: &RelayCall<'_>,
    settle: busbar_plugin::hot::AdmissionId,
    refusal: Option<&RelayRefusal>,
) {
    let Some(target) = call.breakers.as_ref() else {
        return;
    };
    // STAGE 1 — classify the fine canonical outcome where the refusal's structure still exists.
    let outcome = classify_hop(refusal);
    // STAGE 2 — settle where the scope is. With the shared host scope owning this hop's probe, fold the
    // outcome through the host `breaker_settle` seam over `settle` (the CLUSTER-1 inversion); otherwise
    // record in place against the `(key, lane)` cell through the host `breaker_record_*` seam.
    match (call.host, call.host_scope) {
        (Some(host), Some(scope)) if !settle.is_none() => match outcome {
            HopOutcome::Success => {
                host.breaker_settle(
                    scope,
                    settle,
                    &busbar_substrate::plane_host::breaker::success_signal(),
                );
            }
            HopOutcome::Failure(cs) => {
                host.breaker_settle(
                    scope,
                    settle,
                    &busbar_substrate::plane_host::breaker::failure_signal(&cs),
                );
            }
            // Not an upstream health signal: leave the probe UNSETTLED so the shared scope's drop
            // releases it — the "record nothing" disposition, held to the scope's lifetime.
            HopOutcome::Nothing => {}
        },
        // No live admission in the scope to settle (never won, or already consumed): record in place
        // against the cell through the host seam.
        (Some(host), _) => match outcome {
            HopOutcome::Success => host.breaker_record_success(&target.key, target.lane),
            HopOutcome::Failure(cs) => {
                host.breaker_record_signal(&target.key, target.lane, &cs);
            }
            HopOutcome::Nothing => {}
        },
        // No host seam wired at all: nothing to record against.
        (None, _) => {}
    }
}

/// The fine canonical outcome one hop's [`RelayRefusal`] means to the breaker — built where the
/// refusal's transport/status structure still exists (Stage 1), then either recorded in place or
/// folded through the shared host scope by [`record_hop_outcome`].
enum HopOutcome {
    /// Close the half-open probe / dilute the error window (a hop that produced an answer, or a
    /// well-formed backend A2A error — the WORK failing, not the wire).
    Success,
    /// A wire/answer failure to fold, carried as the plane's own canonical signal.
    Failure(busbar_substrate::breaker::CanonicalSignal),
    /// A busbar-side refusal that is not an upstream health signal — record nothing.
    Nothing,
}

/// Stage-1 classification of one hop's [`RelayRefusal`] (see [`record_hop_outcome`] for the rationale
/// of each arm). Pure: it reads the refusal's structure and yields the canonical outcome, recording
/// nothing itself.
fn classify_hop(refusal: Option<&RelayRefusal>) -> HopOutcome {
    match refusal {
        None | Some(RelayRefusal::BackendError { .. }) => HopOutcome::Success,
        Some(RelayRefusal::Transport { .. }) => {
            HopOutcome::Failure(busbar_substrate::breaker::CanonicalSignal {
                class: busbar_substrate::breaker::StatusClass::Network,
                provider_signal: None,
                retry_after: None,
            })
        }
        Some(RelayRefusal::Status { status, .. }) => {
            HopOutcome::Failure(busbar_substrate::breaker::normalize_raw_error(
                &busbar_substrate::breaker::RawUpstreamError::from_status(*status),
                &std::collections::HashMap::new(),
            ))
        }
        Some(
            RelayRefusal::BodyTooLarge { .. }
            | RelayRefusal::NotJson { .. }
            | RelayRefusal::Uncorrelated { .. },
        ) => HopOutcome::Failure(busbar_substrate::breaker::CanonicalSignal {
            class: busbar_substrate::breaker::StatusClass::ServerError,
            provider_signal: None,
            retry_after: None,
        }),
        Some(
            RelayRefusal::Guard(_)
            | RelayRefusal::Demoted(_)
            | RelayRefusal::Lease(_)
            | RelayRefusal::Unframable { .. }
            | RelayRefusal::BreakerOpen { .. },
        ) => HopOutcome::Nothing,
    }
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
    admit_id: &mut busbar_plugin::hot::AdmissionId,
) -> Result<(reqwest::Url, PinnedTarget, OutboundRelayRequest), RelayRefusal> {
    // ── THE GUARD. One resolution, every answered address judged, one pinned address out. It is
    //    `busbar_core::net_guard`'s, reached through the card fetch's hop door, so a relayed submission
    //    and a card fetch cannot be guarded to two different standards.
    // `call.policy`, NOT `seam.policy()`. The seam answers with the plane's fail-closed default and
    // knows nothing about any registration; the call carries the one the operator's `allow_private:`
    // narrowed, which is what every other reader of that line already uses.
    let (url, pin) = super::fetch::guard_hop(call.backend_url, seam.resolver(), call.policy)
        .map_err(RelayRefusal::Guard)?;

    // ── THE LIVE TRUST DECISION, after the guard and before the socket. See the module note. ──
    call.gate
        .still_delegable(call.agent_id, call.admitted_generation)
        .map_err(RelayRefusal::Demoted)?;

    // ── THE BREAKER, immediately after the demotion gate and before the socket — trust first,
    //    then availability, per the audit's ordering. One admission here covers JsonRpc, HttpJson
    //    and Grpc by construction: this preamble is beneath the transport axis, the same argument
    //    `transport.rs` already makes. On refusal the request NEVER LEFT busbar; the ingress
    //    renders a fresh submission `rejected` with its task id. A `pre_admitted` target — a pooled
    //    fresh submission whose member `select_member`'s walk already selected AND admitted through
    //    the host seam — is not admitted a second time: the walk holds the probe, and re-admitting a
    //    HalfOpen cell would lose the single-flight race to our own token.
    if let Some(target) = call.breakers.as_ref() {
        if !target.pre_admitted {
            // CLUSTER-1 inversion, unified onto the host seam: WIN the probe THROUGH the host
            // `breaker_admit` seam over the hop's shared scope, which registers the settle-capable
            // hold in that scope and mints the POD id — so the plane holds ONLY the id, never a
            // `PlaneAdmission`. `record_hop_outcome` settles this hop over `*admit_id` through the same
            // scope; an abandoned hop releases the probe when the scope drops. On refusal the request
            // NEVER LEFT busbar and the `Retry-After` is read from the same host seam.
            let (Some(host), Some(scope)) = (call.host, call.host_scope) else {
                // A breaker cell with no scoped host seam is a wiring bug on this path (every hop that
                // carries a `RelayBreaker` also carries the seam it admits through); fail closed.
                return Err(RelayRefusal::BreakerOpen {
                    agent_id: call.agent_id.to_string(),
                    retry_after_secs: 1,
                });
            };
            match host.breaker_admit(scope, target.key.as_bytes(), target.lane as u32) {
                Ok(id) => *admit_id = id,
                Err(_) => {
                    return Err(RelayRefusal::BreakerOpen {
                        agent_id: call.agent_id.to_string(),
                        retry_after_secs: host.breaker_retry_after_secs(&target.key, target.lane),
                    })
                }
            }
        }
    }

    // ── THE FRAMING, and it is the ONLY thing that varies across A2A's three bindings. Everything
    //    above this line — the guard, the pin, the live trust decision — and everything below it in
    //    the two hops is one implementation. See `THE OUTBOUND BINDING`.
    let (method, params) = outbound_of(call.body);
    let framed = call
        .framing
        .compose(
            &url,
            &Outbound {
                verbatim: call.body,
                method: &method,
                params: &params,
            },
            streaming,
        )
        .map_err(|reason| RelayRefusal::Unframable {
            binding: call.framing.word(),
            method: method.clone(),
            reason,
        })?;
    // THE LEG, NAMED. A statement of fact at a known point, which is what `busbar_core::transport`'s own
    // note says naming a variant is for; nothing on this path compares it.
    tracing::debug!(
        agent = call.agent_id,
        transport = framed_leg(call.framing),
        method = %method,
        "a2a: relaying on the backend's own binding"
    );
    // The FRAMED url, not the operator's: a REST hop addresses the operation and a gRPC hop
    // addresses the rpc, and a refusal that quoted the base would name a URL busbar never asked for.
    let framed_url = framed.url.clone();
    let request = build_request(framed, call.agent_id, call.lease, call.a2a_version, now_ms)
        .map_err(RelayRefusal::Lease)?;
    // THE LEG IS ABOUT TO HAPPEN, so it is counted here: everything above this line is busbar's own
    // refusal (the guard, the live trust decision, an unframable method, a lease that would not
    // build) and none of it reaches a backend, so counting an attempt for one of those would report
    // traffic at an agent busbar never contacted. See `count_leg_failure` for the other half.
    busbar_substrate::telemetry::upstream_attempt_on(call.agent_id, framed_leg(call.framing));
    Ok((framed_url, pin, request))
}

/// COUNT ONE FAILED RELAY LEG on `busbar_upstream_failures_total`, and hand the refusal straight
/// back — a pass-through so the two hops can count without either of them growing a branch.
///
/// ## Why this family and not one of its own
///
/// These are the two series the MODEL plane's client leg has always emitted (`proxy::engine`), and
/// until this function existed the A2A relay leg emitted NOTHING. An operator watching `/metrics`
/// saw every task arriving at busbar's A2A door and had no signal at all about the hops busbar
/// itself originated: a backend agent that had stopped answering was invisible. `pool` is the
/// operator's own `agent_def` id and `lane` is the binding word off the closed transport axis —
/// both bounded by the config file, neither caller-supplied.
///
/// ## Only [`RelayRefusal::Transport`]
///
/// That is the socket failing or the deadline expiring: availability, which is what this family
/// means on the model plane. `Status` is a backend that ANSWERED (it is reachable, and a task it
/// refuses is work-level), `BodyTooLarge` and `Unframable` are busbar's own reading of an answer
/// that arrived, and `Guard`/`Demoted`/`Lease` never reach a socket at all — the same rule
/// `crate::mcp::client::wire::send` applies to its own transport-error variants. Note in
/// particular the half of that rule this plane inherits without having the vocabulary for it: a
/// hop that could not reach the backend AT ALL is availability and IS counted, even though it is
/// the one failure the reroute seam is allowed to move; not-yet-sent means safe to move, never
/// healthy.
fn count_leg_failure(call: &RelayCall<'_>, refusal: RelayRefusal) -> RelayRefusal {
    if matches!(refusal, RelayRefusal::Transport { .. }) {
        busbar_substrate::telemetry::upstream_failure_on(
            call.agent_id,
            framed_leg(call.framing),
            busbar_substrate::proxy::DISPOSITION_TRANSIENT,
        );
    }
    refusal
}

/// The axis label for one framing. A one-line helper so the `tracing` call above reads as a label
/// rather than as a chain, and so the axis value is fetched in exactly one place on this path.
fn framed_leg(framing: &dyn OutboundFraming) -> &'static str {
    framing.leg().name()
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
    // THE HOST ID THIS HOP SETTLES OVER (CLUSTER-1): the pre-admitted WALK id when this is a pooled
    // fresh submission, or the un-pooled admit `prepare` mints through the host `breaker_admit` seam.
    // Stays `NONE` when the hop carries no breaker cell (the originate direction).
    let mut settle = call.admission;
    let outcome = relay_once(call, seam, now_ms, &mut settle);
    record_hop_outcome(call, settle, outcome.as_ref().err());
    outcome
}

/// The unary hop's body, split out so [`relay`] can record the outcome on EVERY exit path — the
/// `?`s below are the reason a wrapper exists rather than a record call per return.
fn relay_once(
    call: &RelayCall<'_>,
    seam: &dyn RelaySeam,
    now_ms: u64,
    admit_id: &mut busbar_plugin::hot::AdmissionId,
) -> Result<RelayReply, RelayRefusal> {
    let (url, pin, request) = prepare(call, seam, false, now_ms, admit_id)?;

    // The PINNED ADDRESS goes to the transport beside the URL. The transport connects to the
    // address and sends the URL's host as `Host` and as TLS SNI; see `transport.rs`.
    let resp = seam
        .transport()
        .send(
            request.http_method,
            &url,
            pin.addr(),
            &request.headers,
            &request.body,
        )
        .map_err(|err| {
            count_leg_failure(
                call,
                RelayRefusal::Transport {
                    url: url.to_string(),
                    err,
                },
            )
        })?;

    if !(200..300).contains(&resp.status) {
        // Including a 3xx. A redirect on a task submission is a fresh, fully untrusted URL that the
        // guard has never seen, and following one would perform the next hop with no guard at all.
        return Err(RelayRefusal::Status {
            url: url.to_string(),
            status: resp.status,
        });
    }
    if resp.body.len() > call.policy.max_body_bytes {
        return Err(RelayRefusal::BodyTooLarge {
            url: url.to_string(),
            bytes: resp.body.len(),
        });
    }
    // ── THE ANSWER, RE-FRAMED BACK INTO ONE DIALECT. Section 11.3 makes the REST success body the
    //    `result` verbatim and A2A v1.0 makes a gRPC message's ProtoJSON the same document, so both
    //    are wrapped back into the JSON-RPC envelope `read_reply` reads. ONE reader, so the
    //    correlation, the `jsonrpc` member check and the `error` arm are the same three rules on
    //    every leg rather than three copies of them.
    let (method, _) = outbound_of(call.body);
    let envelope = call
        .framing
        .read_answer(&method, &resp.body, call.rpc_id)
        .map_err(|reason| RelayRefusal::Unframable {
            binding: call.framing.word(),
            method,
            reason,
        })?;
    read_reply(&envelope, url.as_str(), call.rpc_id)
}

/// Read one JSON-RPC answer off a completed body, AS THE ANSWER TO `rpc_id`.
///
/// The envelope rules are [`busbar_substrate::ingress::jsonrpc::read_response`]'s — the same reader the MCP
/// client direction uses, and the response-side sibling of the request reader both ingresses share.
/// Before it this function read `error` and `result` straight off the value: no `jsonrpc` member
/// check, and the `id` member never read at all, so a backend could answer this hop with the reply
/// to a different one and busbar would hand it to the caller as their task's result.
fn read_reply(
    body: &[u8],
    url: &str,
    rpc_id: &serde_json::Value,
) -> Result<RelayReply, RelayRefusal> {
    use busbar_substrate::ingress::jsonrpc::{read_response, NotAnAnswerKind, Reply};

    let envelope: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| RelayRefusal::NotJson {
            url: url.to_string(),
            err: e.to_string(),
        })?;

    let reply = read_response(&envelope, rpc_id).map_err(|e| match e.kind {
        NotAnAnswerKind::Uncorrelated => RelayRefusal::Uncorrelated {
            url: url.to_string(),
            reason: e.reason,
        },
        // "It is JSON, and it is not a JSON-RPC response" is what `NotJson` already means to every
        // operator reading it, and its `err` field is where the reason belongs.
        NotAnAnswerKind::NotAResponse => RelayRefusal::NotJson {
            url: url.to_string(),
            err: e.reason,
        },
    })?;

    // A JSON-RPC `error` is a FAILED HOP, not a result to hand back. A 200 carrying an error member
    // is the shape in which a backend refusal would otherwise arrive looking like success.
    let result = match reply {
        Reply::Error { code, message } => {
            return Err(RelayRefusal::BackendError {
                jsonrpc_code: code.as_ref().and_then(serde_json::Value::as_i64),
                code: code.map_or_else(|| "unknown".to_string(), |c| c.to_string()),
                message,
            })
        }
        Reply::Result(result) => result,
    };
    let reported_state = reported_task_state(&result);
    let backend_task_id = backend_task_id(&result);
    Ok(RelayReply {
        result,
        backend_task_id,
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

/// THE BACKEND'S OWN TASK ID, read off a payload BEFORE [`rewrite_identity`] replaces it.
///
/// busbar issues its own task identity and substitutes it into every answer, for the reason the
/// module note gives: a caller's later reads resolve against busbar's store. That substitution has
/// an INVERSE, and without it the identity busbar issues is one busbar cannot resolve - a caller
/// handed `a2a-planner-…` and asking `GetTask` for it reaches a backend that has never heard of it.
/// This is the half that makes the inverse possible: the id to translate BACK to.
pub(crate) fn backend_task_id(result: &serde_json::Value) -> Option<String> {
    let id_member = wrapper_of(result).map_or("id", |(_, m)| m);
    payload_of(result)
        .get(id_member)
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
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
    read_task_state(payload_of(result)).unwrap_or(TaskState::Working)
}

/// THE STATE ONE TASK DOCUMENT REPORTS, or `None` when it reports none this build can read.
///
/// The STRICT reading, and the difference from [`reported_task_state`] is the whole reason it
/// exists. That one must produce a state because it is recording the outcome of a hop that
/// definitely happened, so it falls back to `Working`. A reader that is REFRESHING rows from a list
/// must not: an entry whose state it could not read is an entry it learnt nothing from, and
/// defaulting there would move a submitted task to `working` on the strength of a token nobody
/// understood.
pub(crate) fn read_task_state(payload: &serde_json::Value) -> Option<TaskState> {
    payload
        .pointer("/status/state")
        .and_then(serde_json::Value::as_str)
        .and_then(wire_state)
}

/// ONE READING OF A BACKEND'S STATE TOKEN, in either A2A vocabulary. `None` for a token this build
/// does not know, which the two callers answer differently and correctly: the unary path falls back
/// to `Working` because it must record something, and the streaming path records nothing at all
/// because an event that reported no state it could read did not report a transition.
fn wire_state(token: &str) -> Option<TaskState> {
    if let Ok(state) = TaskState::parse(token) {
        return Some(state);
    }
    // v1.0's enum spelling: `TASK_STATE_` + the state in SCREAMING_SNAKE_CASE.
    TaskState::parse(
        &token
            .strip_prefix("TASK_STATE_")?
            .to_ascii_lowercase()
            .replace('_', "-"),
    )
    .ok()
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
    /// THE BACKEND'S OWN TASK ID, before the substitution. See [`backend_task_id`].
    pub(crate) backend_task_id: Option<String>,
}

/// READ ONE BACKEND EVENT and re-frame it for the caller under busbar's identity.
///
/// A frame that is not JSON, or that carries neither `result` nor `error`, is passed through
/// UNCHANGED rather than dropped: busbar is content-blind, an SSE stream legitimately carries
/// comments and keep-alives, and a relay that silently swallowed what it could not parse would turn
/// a backend's own protocol extension into an unexplained gap in the caller's stream.
///
/// ## A FRAME THAT *IS* A JSON-RPC RESPONSE IS CORRELATED, and that closes the one real asymmetry
///
/// The unary path answers the caller under `ctx.rpc_id` — busbar's own reading of the caller's
/// envelope. This path used to pass the backend's `id` through VERBATIM, and the two are only
/// equal by the accident that the relay forwards the caller's body unchanged. So on a stream the
/// BACKEND chose the `id` busbar's caller correlated on, which is the same defect
/// [`rewrite_identity`] exists to close one field over: the module note says the backend's ids are
/// ITS names for this work and must not reach the caller, and the `id` member was the one it
/// missed. The unary path was right; this one was wrong, and it is fixed here rather than by making
/// the unary path pass the backend's id through.
///
/// A frame that names a different request is an `Err`. Not dropped, and not passed on: dropping it
/// would hide from the caller that something answered their stream that was not their backend's
/// answer, and passing it on is the defect. The hop is refused, which on the first event is still a
/// status the ingress can choose and after it ends the task as `failed` — see `relay_stream`.
pub(crate) fn read_event(
    frame: &str,
    rpc_id: &serde_json::Value,
    task_id: &str,
    context_id: &str,
    matched_skill: Option<&str>,
) -> Result<RelayEvent, String> {
    use busbar_substrate::ingress::jsonrpc::{read_response, Reply};

    let verbatim = || {
        Ok(RelayEvent {
            sse: frame.as_bytes().to_vec(),
            state: None,
            artifact: false,
            backend_task_id: None,
        })
    };
    let Some(data) = sse_data(frame) else {
        return verbatim();
    };
    let Ok(mut envelope) = serde_json::from_str::<serde_json::Value>(&data) else {
        return verbatim();
    };
    // WHAT MAKES A FRAME A RESPONSE, and therefore what makes it correlatable: it carries a
    // `result` or a non-null `error`. Anything else is a keep-alive or a backend's own extension —
    // content busbar does not read and does not gate.
    let is_response = envelope.get("result").is_some()
        || envelope.get("error").filter(|e| !e.is_null()).is_some();
    if !is_response {
        return verbatim();
    }
    let reply = read_response(&envelope, rpc_id).map_err(|e| e.reason)?;
    // The correlation just proved the backend's id equals `rpc_id`; setting it explicitly makes the
    // streamed answer byte-identical to the unary one rather than equal-by-argument, so the caller
    // cannot tell the two paths apart by the shape of the id they get back.
    if let Some(obj) = envelope.as_object_mut() {
        obj.insert("id".to_string(), rpc_id.clone());
    }
    // An `error` frame is relayed as it stands, with only the identity substituted: mid-stream, the
    // status is already spent and a backend's own error is content the caller is owed. The unary
    // path's `BackendError` refusal has no equivalent here for that reason, and that difference is
    // about WHEN the answer is committed, not about what the two paths believe an envelope is.
    let Reply::Result(_) = reply else {
        return Ok(RelayEvent {
            sse: frame_sse(&envelope),
            state: None,
            artifact: false,
            backend_task_id: None,
        });
    };
    let Some(result) = envelope.get_mut("result") else {
        return verbatim();
    };
    // THROUGH THE PAYLOAD, in both shapes. v1.0 wraps the event - `{"artifactUpdate": {…}}`,
    // `{"statusUpdate": {…}}` - so reading `result.artifact` and `result.status.state` directly saw
    // neither: every streamed artifact left the resume cursor where it was, and every state
    // transition on a stream went unrecorded and undelivered to any registered push callback.
    let payload = payload_of(result);
    let artifact = payload.get("artifact").is_some()
        || payload.get("artifacts").is_some()
        || result.get("artifactUpdate").is_some();
    // `Working` is the fallback for "reported nothing", and this asks a narrower question - DID it
    // report one - so the fallback is not usable here and the pointer is read directly.
    let state = payload
        .pointer("/status/state")
        .and_then(serde_json::Value::as_str)
        .and_then(wire_state);
    let backend = backend_task_id(result);
    rewrite_identity(result, task_id, context_id, matched_skill);
    Ok(RelayEvent {
        sse: frame_sse(&envelope),
        backend_task_id: backend,
        state,
        artifact,
    })
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
    // Same shape as [`relay`]: the host id carries the shared-scope handle, and every exit path records.
    let mut settle = call.admission;
    let outcome = relay_stream_once(
        call,
        seam,
        task_id,
        context_id,
        matched_skill,
        now_ms,
        sink,
        &mut settle,
    );
    record_hop_outcome(call, settle, outcome.as_ref().err());
    outcome
}

/// [`relay_stream`]'s body; see [`relay_once`] for why the wrapper split exists.
#[allow(clippy::too_many_arguments)] // the public fn's list plus the admit-id out-param.
fn relay_stream_once(
    call: &RelayCall<'_>,
    seam: &dyn RelaySeam,
    task_id: &str,
    context_id: &str,
    matched_skill: Option<&str>,
    now_ms: u64,
    sink: &mut (dyn FnMut(RelayEvent) -> ChunkFlow + Send),
    admit_id: &mut busbar_plugin::hot::AdmissionId,
) -> Result<RelayStream, RelayRefusal> {
    let (url, pin, request) = prepare(call, seam, true, now_ms, admit_id)?;
    let cap = call.policy.max_body_bytes;

    // THE BINDING'S OWN FRAME READER. Whatever it reads — SSE with an envelope payload, SSE with a
    // bare one, or length-prefixed protobuf — what it EMITS is one dialect, so `read_event` below is
    // one implementation.
    let (method, _) = outbound_of(call.body);
    let mut reader = call.framing.reader(&method, call.rpc_id);
    let mut streamed_any = false;
    let mut overflow = false;
    // AN UNCORRELATED FRAME STOPS THE HOP. Recorded rather than returned from the closure because
    // the closure's only vocabulary is `ChunkFlow`, and the refusal has to survive to the decision
    // below — where it outranks "the stream ended normally", exactly as `overflow` does.
    let mut uncorrelated: Option<String> = None;
    let head = {
        let mut on_chunk = |chunk: &[u8]| -> ChunkFlow {
            for frame in reader.feed(chunk) {
                streamed_any = true;
                let event =
                    match read_event(&frame, call.rpc_id, task_id, context_id, matched_skill) {
                        Ok(event) => event,
                        Err(reason) => {
                            uncorrelated = Some(reason);
                            return ChunkFlow::Stop;
                        }
                    };
                if sink(event) == ChunkFlow::Stop {
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
                &url,
                pin.addr(),
                &request.headers,
                &request.body,
                &mut on_chunk,
            )
            .map_err(|err| {
                count_leg_failure(
                    call,
                    RelayRefusal::Transport {
                        url: url.to_string(),
                        err,
                    },
                )
            })?
    };

    if !(200..300).contains(&head.status) {
        return Err(RelayRefusal::Status {
            url: url.to_string(),
            status: head.status,
        });
    }
    if overflow {
        return Err(RelayRefusal::BodyTooLarge {
            url: url.to_string(),
            bytes: cap.saturating_add(1),
        });
    }
    // BEFORE the "did it stream?" question, because a stream that put an answer to another request
    // on the wire is a refused hop whatever else it did — and `Streamed` is an `Ok`, so asking in
    // the other order would report the hop as successful.
    if let Some(reason) = uncorrelated {
        return Err(RelayRefusal::Uncorrelated {
            url: url.to_string(),
            reason,
        });
    }
    if streamed_any || head.content_type.starts_with(SSE_CONTENT_TYPE) {
        return Ok(RelayStream::Streamed);
    }
    // NOT A STREAM. The backend answered a single document; hand back the unary shape rather than
    // re-framing a non-stream as one — through the SAME re-framing the unary hop uses, because a
    // one-document answer to a streaming request is a unary answer and the binding it arrived on
    // has not changed.
    let envelope = call
        .framing
        .read_answer(&method, &head.body, call.rpc_id)
        .map_err(|reason| RelayRefusal::Unframable {
            binding: call.framing.word(),
            method: method.clone(),
            reason,
        })?;
    read_reply(&envelope, url.as_str(), call.rpc_id).map(|r| RelayStream::Unary(Box::new(r)))
}

// ONE HARNESS, shared by both test modules below. A second harness is a second thing that can stop
// matching what the production router does, and the defect this area exists to catch is invisible
// to any test that does not go through `busbar_core::build_router`.
#[cfg(all(test, not(busbar_a2a_native)))]
#[path = "tests/relay_harness.rs"]
mod relay_harness;

#[cfg(all(test, not(busbar_a2a_native)))]
#[path = "tests/relay_tests.rs"]
mod relay_tests;

// KILL-THE-UPSTREAM — the breaker's trip + fast-fail on this plane, all three bindings, through
// the same harness/router as the batteries above. It hangs here because the mount is `prepare`.
#[cfg(all(test, not(busbar_a2a_native)))]
#[path = "tests/breaker_fastfail_tests.rs"]
mod breaker_fastfail_tests;

// KILL-THE-UPSTREAM-MID-POOL — the failover seam mounted at admission time: `agent_pools:`
// reroute of fresh submissions, task pinning, the card-fingerprint pin rule, and the client-fault
// disposition, against twin recorded backends through the real router.
#[cfg(all(test, not(busbar_a2a_native)))]
#[path = "tests/reroute_pool_tests.rs"]
mod reroute_pool_tests;

#[cfg(all(test, not(busbar_a2a_native)))]
#[path = "tests/relay_stream_tests.rs"]
mod relay_stream_tests;

// THIS PLANE'S CLIENT LEG ON `/metrics`. Mounted here for the same reason the blocks below are: it
// needs `relay_harness`, because the claim is about a hop that went out through the production
// ingress and a series emitted with no backend to reach would prove only that a macro increments.
#[cfg(all(test, not(busbar_a2a_native)))]
#[path = "tests/relay_leg_metrics_tests.rs"]
mod relay_leg_metrics_tests;

// THE `id` MEMBER on the receiving plane. Mounted HERE rather than from `ingress.rs`, where it
// belongs by subject, for the one reason that outweighs tidiness: it needs `relay_harness`, and the
// harness comment two blocks up is the whole argument against standing up a second one. Its sibling
// is `mcp/tests/envelope_id_tests.rs`; the two assert the same list against the same reader.
#[cfg(all(test, not(busbar_a2a_native)))]
#[path = "tests/envelope_id_tests.rs"]
mod envelope_id_tests;

// THE `id` MEMBER ON THE WAY BACK — the delegating direction's half of the file above, and mounted
// here for the same reason: it needs `relay_harness`, and a second harness is a second thing that
// can stop matching what the production router does. Its sibling on the MCP client direction is the
// correlation block at the end of `mcp/client/tests/transport_tests.rs`, which reads the same two
// facts off a real loopback socket.
#[cfg(all(test, not(busbar_a2a_native)))]
#[path = "tests/response_id_tests.rs"]
mod response_id_tests;

// THE REQUEST'S MEDIA TYPE AND ITS `A2A-Version` — the two facts busbar reads off the HTTP request
// line rather than out of the caller's envelope, and therefore the two this content-blind plane
// answers for ITSELF. Mounted here for the same reason as the two blocks above: the claim is that a
// refusal happens BEFORE any hop, and only the shared harness can see whether a hop happened.
#[cfg(all(test, not(busbar_a2a_native)))]
#[path = "tests/wire_headers_tests.rs"]
mod wire_headers_tests;

// THE OPERATOR'S HOOK GATE ON THIS PLANE — `agents.hooks:` — and it is mounted here for the reason
// every block above is: the claim is that the refusal happens BEFORE ANY HOP, and the shared
// harness's recording seam is the only thing that can see whether one was composed. A test that
// asserted only on the status code would pass just as happily against a gate that fires after the
// backend has already been asked.
#[cfg(all(test, not(busbar_a2a_native)))]
#[path = "tests/hook_gate_tests.rs"]
mod hook_gate_tests;

// THE SERVED HALF OF THE COVERAGE MATRIX — one test per `busbar-as-server` cell of
// `qa/method-inventory.json`, on the binding whose cell it claims. Mounted here for the reason every
// block above is: it needs `relay_harness`, and a second harness is a second thing that can stop
// matching what the production router does. The cells it claims were previously established only by
// the official TCK's stdout — a real instrument, and the right one, but one that lives outside this
// repository and that `cargo test` cannot run; the eleven JSON-RPC cells had no in-tree instrument
// at all.
#[cfg(all(test, not(busbar_a2a_native)))]
#[path = "tests/served_methods_tests.rs"]
mod served_methods_tests;
// BUSBAR AS AN A2A **CLIENT**, over all three bindings. Mounted here for the reason every block
// above is: the claim is about A REQUEST ON THE WIRE, and only the shared harness can see one.
#[cfg(all(test, not(busbar_a2a_native)))]
#[path = "tests/client_leg_tests.rs"]
mod client_leg_tests;

// THE FRONT DOOR'S AUDIT CHAIN, DRIVEN. Mounted here for the reason every block above is: it needs
// `relay_harness`, because the claim is that A REAL INBOUND TASK leaves chained evidence, and only a
// test that goes through `busbar_core::build_router` can make it. The cell this closes was previously
// green on a chain a test built in-process — evidence that would have survived the front door
// chaining nothing at all.
#[cfg(all(test, not(busbar_a2a_native)))]
#[path = "tests/front_door_chain_tests.rs"]
mod front_door_chain_tests;

// THE CALLBACK SUBSTITUTION — busbar registering ITS OWN callback with a backend, so the backend
// never learns the caller's. Mounted here for the reason every block above is: the claim is about a
// REQUEST ON THE WIRE (and, for the no-leak scan, about every byte of one), and only the shared
// harness's recording seam can see one.
#[cfg(all(test, not(busbar_a2a_native)))]
#[path = "tests/pushback_tests.rs"]
mod pushback_tests;
