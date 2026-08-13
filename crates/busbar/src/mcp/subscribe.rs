// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `subscriptions/listen` — THE SERVER-TO-CLIENT CHANNEL OF REVISION `2026-07-28`.
//!
//! ## Why this file exists, and why it is not a GET stream
//!
//! Every earlier revision gave a server one way to say something its client had not asked for: a
//! standing `GET` stream, opened once, resumed with `Last-Event-ID`, held for the life of a session.
//! This revision deleted all three of those things — the stream, the resumption and the session —
//! and `super::ingress::legacy_verb` answers `405` to the verb that used to open it, which is what
//! the specification says a server SHOULD do.
//!
//! Reading that as "so a server can no longer notify a client" is the mistake this module corrects,
//! and it is the reason four notification names sat in the tree as a codec with nothing to carry
//! them. The revision did not remove the channel; it MOVED it, from a transport verb onto a method.
//! `subscriptions/listen` is a POST like any other — same admission, same audience-bound token, same
//! per-request `_meta` — whose response happens to be a long-lived stream of notifications instead
//! of one document. The client says which categories it wants; the server acknowledges the subset it
//! will actually deliver; everything after that is a notification tagged with the subscription's id.
//!
//! ## THE ACKNOWLEDGEMENT IS A NARROWING, AND THAT IS THE HONEST PART
//!
//! `notifications/subscriptions/acknowledged` carries a filter, not a receipt, and the filter it
//! carries is the ACCEPTED subset rather than the requested one. That distinction is the whole
//! reason the message has a body: a server that echoed the request back would tell a client it was
//! subscribed to things that will never arrive, and the client would wait rather than fall back.
//!
//! busbar therefore accepts exactly what it can deliver, which is the three list-changed categories
//! and nothing else. `resourceSubscriptions` is REFUSED — narrowed away in the acknowledgement — and
//! that is a statement about what busbar can observe rather than about effort. A resource's CONTENTS
//! change at the upstream that owns it; busbar fronts that upstream and is told nothing when it
//! happens, so the only way to emit `notifications/resources/updated` truthfully would be to poll
//! every subscribed resource on every registered upstream, which is a load busbar would be imposing
//! on somebody else's server on a client's say-so. Advertising it and delivering nothing would be
//! worse than narrowing it away, because a narrowed category is one a client can see it did not get.
//!
//! ## WHAT COUNTS AS A CHANGE, AND WHOSE CHANGE IT IS
//!
//! The catalogue is an immutable snapshot behind an atomic swap, carrying a monotonic pin generation
//! ([`super::catalogue::Catalogue::generation`]). A generation move is the cheap gate — one
//! atomic load per poll — and it is deliberately not the answer on its own, because a generation
//! moves for the whole deployment while a subscription belongs to ONE CALLER.
//!
//! So a moved generation is followed by a comparison of the catalogue THIS CALLER CAN SEE, under the
//! same grant predicate that scopes `tools/list`. Two callers holding two different grants get two
//! different catalogues from the same registry (owner ruling 2), and it follows that they get two
//! different answers to "did it change". A registration this caller may not reach must not wake this
//! caller's stream: doing so would leak the existence of another tenant's inventory through timing,
//! which is the same boundary `discover` refuses to cross by advertising counts rather than names.
//!
//! ## WHY IT POLLS, STATED RATHER THAN APOLOGISED FOR
//!
//! There is no change-notification channel on the snapshot handle, and adding one would put a
//! broadcast sender on the hot path of every config reload for the benefit of a surface most
//! deployments never open. A generation compare is an atomic load; the grant-scoped change key runs
//! only when that load says something moved. The cost of the poll is therefore one load per
//! [`POLL_INTERVAL`], and the cost of the real work is paid only when there is real work.
//!
//! ## THE STREAM IS BOUNDED, AND IT ENDS BY SAYING SO
//!
//! A subscription with no end is a connection a client cannot tell from a hung one. At
//! [`MAX_LIFETIME`] the stream emits `SubscriptionsListenResult` — the revision's own "this
//! subscription ended gracefully" answer, carrying the same subscription id — and closes. A client
//! that still wants one opens another, which under a stateless revision costs exactly one POST and
//! carries no state forward.

use std::time::{Duration, Instant};

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use rmcp::model::{
    ConstString, PromptListChangedNotificationMethod, ResourceListChangedNotificationMethod,
    SubscriptionFilter, SubscriptionsAcknowledgedNotificationMethod,
    SubscriptionsListenRequestMethod, SubscriptionsListenResult, SubscriptionsListenResultMeta,
    ToolListChangedNotificationMethod,
};

/// The wire name of this method, off the SDK's own const-string type rather than spelled again.
pub(crate) const METHOD_SUBSCRIPTIONS_LISTEN: &str = SubscriptionsListenRequestMethod::VALUE;

/// How often the pin generation is re-read. Short enough that a client learns of a registration
/// change within a human's idea of "immediately", long enough that a held stream is one atomic load
/// four times a second and nothing else.
const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// How long one subscription is held before it is closed with a graceful result. See the module
/// header: an unbounded stream is indistinguishable from a hung one.
///
/// **THIS BOUND IS LOAD-BEARING FOR AUTHORISATION, NOT ONLY FOR LIVENESS — DO NOT RAISE IT WITHOUT
/// MEETING THAT ARGUMENT.** The caller's key is FROZEN at open (see [`grant_of`]), so a key that is
/// revoked, tombstoned or re-scoped mid-stream keeps being honoured until the stream ends. This
/// constant is therefore the ONLY thing bounding how long a dead credential can still be served:
/// the exposure window IS this number. Five minutes is defensible; an hour would not be, and
/// "unbounded, since we send keep-alives anyway" would mean a revoked key never stops working.
/// Raising it is a security change, not a tuning change, and the honest way to buy a longer stream
/// is to re-resolve the key per poll first — see the characterisation test
/// `a_revoked_key_keeps_being_served_until_the_lifetime_bound`, which pins today's behaviour.
const MAX_LIFETIME: Duration = Duration::from_secs(300);

/// How often a stream that has nothing to say writes an SSE comment. Not a protocol message —
/// comment lines carry no `data:` and every SSE reader drops them — but the bytes are what stops an
/// idle proxy between busbar and its caller from reclaiming a connection that is working correctly.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// The catalogue kinds busbar can observe changing, and the notification each one becomes.
///
/// A closed set, and it is closed on what is OBSERVABLE rather than on what is nameable — see the
/// module header on `resourceSubscriptions`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Tools,
    Prompts,
    Resources,
}

impl Kind {
    /// Every kind, so a new arm cannot be added without appearing in the loop that emits.
    const ALL: [Kind; 3] = [Kind::Tools, Kind::Prompts, Kind::Resources];

    /// The wire method name, off `rmcp`'s const-string types.
    fn method(self) -> &'static str {
        match self {
            Kind::Tools => ToolListChangedNotificationMethod::VALUE,
            Kind::Prompts => PromptListChangedNotificationMethod::VALUE,
            Kind::Resources => ResourceListChangedNotificationMethod::VALUE,
        }
    }

    /// Whether the ACCEPTED filter opted this kind in.
    fn wanted(self, filter: &SubscriptionFilter) -> bool {
        let f = match self {
            Kind::Tools => filter.tools_list_changed,
            Kind::Prompts => filter.prompts_list_changed,
            Kind::Resources => filter.resources_list_changed,
        };
        f == Some(true)
    }
}

/// Narrow a requested filter to what busbar will actually deliver.
///
/// Written as an explicit construction rather than as `SubscriptionFilter::intersection` with a
/// constant, because what busbar can deliver is not a fixed value to intersect against: it is a
/// statement per category, and `resourceSubscriptions` is dropped for a different reason than an
/// unrequested list-changed is. Two reasons that read the same in a diff is how one of them gets
/// quietly changed.
fn accept(requested: &SubscriptionFilter) -> SubscriptionFilter {
    let mut accepted = SubscriptionFilter::new();
    accepted.tools_list_changed = requested.tools_list_changed.filter(|v| *v);
    accepted.prompts_list_changed = requested.prompts_list_changed.filter(|v| *v);
    accepted.resources_list_changed = requested.resources_list_changed.filter(|v| *v);
    // `resourceSubscriptions` is narrowed away unconditionally — see the module header. It is left
    // `None` rather than set to an empty list: an empty list is "you subscribed to no resources",
    // which is a different statement from "this server does not deliver that category at all".
    accepted
}

/// A CHANGE KEY for one grant-scoped catalogue slice: two runs that produce the same value saw the
/// same list, and a different value means the client should re-read.
///
/// DELIBERATELY NOT CALLED A FINGERPRINT, and deliberately not a cryptographic digest. `a2a::card`
/// has a `fingerprint`, and that one IS a trust pin — a SHA-256 over a canonical document, which an
/// approval is bound to. This value is trusted for nothing: the inputs are busbar's own catalogue
/// rather than an attacker's, a collision costs a client one missed re-read of a list it can re-read
/// at any time, and nothing downstream compares it across a boundary. FNV-1a says that at the call
/// site; SHA-256 would say the opposite and would be wrong.
fn change_key(mut parts: Vec<&str>) -> u64 {
    parts.sort_unstable();
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for part in parts {
        for byte in part.as_bytes().iter().chain(std::iter::once(&0u8)) {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    hash
}

/// The three change keys of what ONE CALLER can see, taken together so a single walk of the
/// snapshot answers all three.
fn change_keys(
    catalogue: &super::catalogue::Catalogue,
    grant: &dyn Fn(&str, &str) -> bool,
) -> [u64; 3] {
    let tools = catalogue.tools_for(grant);
    // The SCHEMA HASH rides in the tool change key and the name alone does not. A tool whose
    // arguments changed shape under an unchanged name is exactly the case a client must re-read
    // `tools/list` for, and it is the case a membership-only comparison cannot see.
    let mut tool_parts: Vec<&str> = Vec::with_capacity(tools.len() * 2);
    for tool in &tools {
        tool_parts.push(tool.namespaced.as_str());
        tool_parts.push(tool.schema_hash.as_deref().unwrap_or(""));
    }
    [
        change_key(tool_parts),
        change_key(
            catalogue
                .prompts_for(grant)
                .iter()
                .map(|p| p.namespaced.as_str())
                .collect(),
        ),
        change_key(
            catalogue
                .resources_for(grant)
                .iter()
                .map(|r| r.namespaced.as_str())
                .collect(),
        ),
    ]
}

/// The `params._meta` every frame on this stream carries, built through the SDK's own type so the
/// key is the SDK's spelling rather than a second copy of it here.
///
/// The subscription id IS the listen request's own JSON-RPC id, which is what
/// [`SubscriptionsListenResultMeta::new`] takes: under a revision with no sessions, the request that
/// opened the stream is the only durable name the stream has, and minting a second identifier would
/// give a client two names for one thing and no way to relate them.
fn subscription_meta(id: &serde_json::Value) -> serde_json::Value {
    let request_id: Option<rmcp::model::RequestId> = serde_json::from_value(id.clone()).ok();
    request_id
        .map(SubscriptionsListenResultMeta::new)
        .and_then(|m| serde_json::to_value(m).ok())
        .unwrap_or_else(|| serde_json::json!({}))
}

/// One JSON-RPC notification envelope, tagged with the subscription it belongs to.
///
/// **No `id`, ever.** JSON-RPC 2.0 section 4.1 makes the absence of `id` the definition of a
/// notification, and an id here would oblige a client to answer something busbar is not waiting for.
/// The tag goes in `params._meta`, which is where the revision's own scenario looks for it.
fn notification(
    method: &str,
    meta: &serde_json::Value,
    extra: serde_json::Value,
) -> serde_json::Value {
    let mut params = match extra {
        serde_json::Value::Object(map) => map,
        _ => serde_json::Map::new(),
    };
    params.insert("_meta".to_string(), meta.clone());
    serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": serde_json::Value::Object(params),
    })
}

/// What the stream is doing between polls. An explicit phase rather than a flag, so "the
/// acknowledgement has not been sent yet" cannot be confused with "nothing has changed yet" — the
/// first of those is a MUST about ordering and the second is ordinary quiet.
enum Phase {
    /// Nothing has been written. The acknowledgement is owed, and it is owed FIRST.
    Acknowledge,
    /// Acknowledged; watching the generation.
    Watch { generation: u64, seen: [u64; 3] },
    /// The final result has been written. The next poll ends the stream.
    Ended,
}

struct Listen {
    handle: std::sync::Arc<crate::state::AppHandle>,
    gov: crate::governance::GovCtx,
    accepted: SubscriptionFilter,
    meta: serde_json::Value,
    id: serde_json::Value,
    phase: Phase,
    deadline: Instant,
    last_write: Instant,
}

/// The grant predicate, rebuilt per poll from the key the stream was opened with.
///
/// **WHAT IS RE-READ AND WHAT IS FROZEN — and the difference matters more than the rebuild does.**
/// The CATALOGUE is genuinely live: [`Listen::step`] loads the handle every poll, so a registration
/// that appears or disappears is reflected within [`POLL_INTERVAL`]. The KEY is NOT. `gov` is an
/// `Arc<VirtualKey>` cloned into the stream at open — a SNAPSHOT resolved once at ingress by the
/// auth middleware — and nothing below re-resolves it against the store.
///
/// So rebuilding this closure per poll re-evaluates the grant against FRESH CATALOGUE ENTRIES but
/// against a STALE KEY, and the two revocations behave differently:
///
/// * An APPROVAL withdrawn from the catalogue bites within [`POLL_INTERVAL`] — the entry stops
///   being visible and the caller stops being woken for it.
/// * The KEY ITSELF being deleted, disabled, tombstoned or re-scoped does NOT bite at all. Note
///   that [`busbar_api::VirtualKey::scope_allowed`] consults `allowed_scopes` only: it does not
///   look at `enabled` and does not call `is_live()`, so even a tombstoned key answers here exactly
///   as it did at open.
///
/// The only thing bounding that is [`MAX_LIFETIME`], which is why that constant carries a warning
/// against being raised. Closing this properly needs a standing-permission re-resolution primitive
/// rather than a local patch — the auth chain that produced this key is async and consumes the
/// presented credential, which the stream deliberately does not retain — so this comment states the
/// gap rather than papering over it, and
/// `a_revoked_key_keeps_being_served_until_the_lifetime_bound` pins it as a characterisation test.
///
/// A free function rather than a method, because the caller holds `&mut` on the phase while it holds
/// this — two disjoint fields, which the borrow checker allows and a `&self` method does not.
fn grant_of(gov: &crate::governance::GovCtx) -> impl Fn(&str, &str) -> bool + '_ {
    move |kind: &str, value: &str| {
        gov.key
            .as_ref()
            .is_none_or(|k| k.scope_allowed(kind, value))
    }
}

impl Listen {
    /// Produce the next chunk of the stream, `Some("")` for "nothing to say yet", or `None` to close
    /// it.
    fn step(&mut self) -> Option<String> {
        let app = self.handle.load();
        let catalogue = &app.mcp_catalogue;
        let grant = grant_of(&self.gov);
        let now = Instant::now();
        match &mut self.phase {
            Phase::Acknowledge => {
                let seen = change_keys(catalogue, &grant);
                let params = serde_json::json!({
                    "notifications": serde_json::to_value(&self.accepted)
                        .unwrap_or_else(|_| serde_json::json!({})),
                });
                let frame = event(&notification(
                    SubscriptionsAcknowledgedNotificationMethod::VALUE,
                    &self.meta,
                    params,
                ));
                self.phase = Phase::Watch {
                    generation: catalogue.generation(),
                    seen,
                };
                self.last_write = now;
                Some(frame)
            }
            Phase::Watch { generation, seen } => {
                if now >= self.deadline {
                    // The revision's own "this subscription ended gracefully" answer, correlated to
                    // the request that opened the stream — so a client can tell a deliberate close
                    // from a dropped connection, which is the only reason to write anything at all
                    // rather than simply closing the socket.
                    let request_id: Option<rmcp::model::RequestId> =
                        serde_json::from_value(self.id.clone()).ok();
                    let result = request_id
                        .map(SubscriptionsListenResult::complete)
                        .and_then(|r| serde_json::to_value(r).ok())
                        .unwrap_or_else(|| serde_json::json!({ "resultType": "complete" }));
                    let frame = event(&serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": self.id,
                        "result": result,
                    }));
                    self.phase = Phase::Ended;
                    return Some(frame);
                }
                let live = catalogue.generation();
                let mut out = String::new();
                if live != *generation {
                    *generation = live;
                    let fresh = change_keys(catalogue, &grant);
                    for (index, kind) in Kind::ALL.into_iter().enumerate() {
                        if fresh[index] == seen[index] || !kind.wanted(&self.accepted) {
                            continue;
                        }
                        out.push_str(&event(&notification(
                            kind.method(),
                            &self.meta,
                            serde_json::json!({}),
                        )));
                    }
                    *seen = fresh;
                }
                if !out.is_empty() {
                    self.last_write = now;
                    return Some(out);
                }
                // NOTHING HAPPENED, which is the ordinary case and is not nothing to write: an idle
                // connection is reclaimed by intermediaries that cannot tell it from a dead one.
                if now.duration_since(self.last_write) >= KEEPALIVE_INTERVAL {
                    self.last_write = now;
                    return Some(": keepalive\n\n".to_string());
                }
                Some(String::new())
            }
            Phase::Ended => None,
        }
    }
}

/// One SSE `message` event. The same framing [`super::sse`] writes, and deliberately the same
/// function shape: two spellings of an event frame is two places for the blank-line terminator to be
/// forgotten.
fn event(value: &serde_json::Value) -> String {
    format!(
        "event: message\ndata: {}\n\n",
        serde_json::to_string(value).unwrap_or_else(|_| "null".to_string())
    )
}

/// SERVE one `subscriptions/listen`.
///
/// The response is a stream WHATEVER THE `Accept` LIST SAID, and that is not the preference rule
/// being ignored — it is the one request for which there is no other answer. `super::sse` negotiates
/// between two legal framings of the SAME single document; a subscription has no single document to
/// frame, so `application/json` is not an alternative representation of it, it is a refusal to
/// answer. A client that did not want a stream should not have asked to listen.
pub(crate) fn listen(
    ctx: &super::method::Ctx<'_>,
    params: Option<&serde_json::Value>,
    id: Option<serde_json::Value>,
) -> Response {
    // The SDK's parameter type is the acceptance test, for the reason the subscription codec in
    // `crate::handlers::mcp` states: a hand-read `params.notifications.toolsListChanged` accepts
    // shapes the specification does not, and each acceptance is a difference between what busbar
    // serves and what the protocol says.
    let requested: SubscriptionFilter = params
        .and_then(|p| p.get("notifications"))
        .cloned()
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default();
    let accepted = accept(&requested);
    if !Kind::ALL.into_iter().any(|k| k.wanted(&accepted)) {
        // A STREAM THAT CAN DELIVER NOTHING IS NOT A NARROWER STREAM, it is a connection held open
        // to say nothing, and a client waiting on one waits for ever. Refusing is the answer that
        // lets it fall back; acknowledging an empty filter and then going silent is the answer that
        // looks identical to a server that is merely quiet.
        return super::ingress::error_response(
            StatusCode::BAD_REQUEST,
            id,
            super::ingress::code::INVALID_PARAMS,
            "`params.notifications` opts in to no category this server delivers. busbar delivers \
             `toolsListChanged`, `promptsListChanged` and `resourcesListChanged`; \
             `resourceSubscriptions` is not delivered, because a resource's contents change at the \
             upstream that owns it and busbar is not told when they do.",
            None,
        );
    }
    // Never `None` on this path — `ingress` has already refused a notification and a null id — and
    // carried as `Option` only because every method in the table takes one. `Null` here would
    // produce a subscription with no name, which the SDK's own result type refuses to build.
    let id = id.unwrap_or(serde_json::Value::Null);
    let now = Instant::now();
    let mut state = Listen {
        handle: ctx.handle.clone(),
        gov: ctx.gov.clone(),
        accepted,
        meta: subscription_meta(&id),
        id,
        phase: Phase::Acknowledge,
        deadline: now + MAX_LIFETIME,
        last_write: now,
    };
    // THE FIRST CHUNK IS PRODUCED BEFORE THE RESPONSE IS BUILT, so the acknowledgement is on the
    // wire the instant the headers are. A stream whose first frame is computed lazily is a stream
    // whose "first message MUST be the acknowledgement" holds only if nothing else ever races it.
    let first = state.step().unwrap_or_default();
    let tail = futures::stream::unfold(state, |mut state| async move {
        loop {
            let chunk = state.step()?;
            if !chunk.is_empty() {
                return Some((Ok::<_, std::convert::Infallible>(chunk), state));
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    });
    let head = futures::stream::once(async move { Ok::<_, std::convert::Infallible>(first) });
    let body = axum::body::Body::from_stream(futures::StreamExt::chain(head, tail));
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/event-stream")
        // Same reasoning as `super::sse`: what rides this stream is computed under the CALLER'S
        // GRANT, and a cache reads the header rather than the body.
        .header("cache-control", "no-cache, no-store")
        .body(body)
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

#[cfg(test)]
#[path = "tests/subscribe_tests.rs"]
mod subscribe_tests;
