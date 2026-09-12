// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `subscriptions/listen` — THE SERVER-TO-CLIENT CHANNEL OF REVISION `2026-07-28`.
//!
//! ## Why this file exists, and why it is not a GET stream
//!
//! Every earlier revision gave a server one way to say something its client had not asked for: a
//! standing `GET` stream, opened once, resumed with `Last-Event-ID`, held for the life of a session.
//! This revision deleted all three of those things — the stream, the resumption and the session —
//! and `super::envelope::legacy_verb` answers `405` to the verb that used to open it, which is what
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
//! busbar accepts the three list-changed categories, and — since the relay landed —
//! `resourceSubscriptions`, NARROWED PER URI to what this caller is entitled to see. The category
//! was refused outright for as long as the sentence "busbar fronts that upstream and is told
//! nothing when a resource's contents change" was true, and that sentence stopped being true the
//! day the client leg learned to read a peer's `notifications/resources/updated`
//! ([`crate::mcp::client::peer::ServerNotification::ResourcesUpdated`]): busbar IS told, by the
//! upstream's own announcement, with no polling imposed on anybody. The announcement is recorded —
//! `(server, uri)`, bounded, the uri believed nowhere — in
//! [`crate::mcp::client::pool::ResourceUpdates`], and this stream relays it to a subscriber only
//! when the uri resolves, under THE SUBSCRIBER'S OWN grant re-derived on the poll, to an
//! operator-declared resource of the SAME server that announced it. A uri the caller cannot see is
//! narrowed out of the acknowledgement at open and out of the delivery on every poll — the same
//! tenant boundary the change keys hold for the list-changed categories.
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
//! ## WHAT IS RE-CHECKED WHILE IT IS OPEN, AND WHAT THE BOUND IS FOR
//!
//! A subscription is a decision made at open and trusted while open, so the question that matters is
//! what is re-asked per poll. All of it: the CATALOGUE is re-read from the live handle, and the
//! PRINCIPAL is RE-RESOLVED from the live registry by id through [`busbar_substrate::trust::validate::Standing`].
//!
//! Holding the resolved key instead would have been the natural shape and it is the defect this
//! guards: a `PlaneRequestCtx` cloned into the stream carries an `Arc<VirtualKey>` resolved at ingress, so an
//! approval revoked underneath the stream would bite in one poll while the KEY being deleted,
//! disabled or re-scoped would not bite at all. The stream now holds the ID and looks the principal
//! up on every poll — an in-memory index read, which is what makes it affordable four times a
//! second — and closes the stream the moment it stops resolving live.
//!
//! [`MAX_LIFETIME`] is still load-bearing and is not a consolation for that: it is the hard bound on
//! everything a poll CANNOT re-derive, and it is passed to the `Standing` so the two numbers are
//! provably one number.
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
use busbar_contract::counterparty::Verdict;
use busbar_plane_mcp::subscribe::{self as compose, Poll};
use rmcp::model::SubscriptionFilter;

/// How often the pin generation is re-read. Short enough that a client learns of a registration
/// change within a human's idea of "immediately", long enough that a held stream is one atomic load
/// four times a second and nothing else.
const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// How long one subscription is held before it is closed with a graceful result. See the module
/// header: an unbounded stream is indistinguishable from a hung one.
///
/// **THIS BOUND IS LOAD-BEARING FOR AUTHORISATION, NOT ONLY FOR LIVENESS — DO NOT RAISE IT WITHOUT
/// MEETING THAT ARGUMENT.** The caller's key is FROZEN at open (see [`caller_of`]), so a key that is
/// revoked, tombstoned or re-scoped mid-stream keeps being honoured until the stream ends. This
/// constant is therefore the ONLY thing bounding how long a dead credential can still be served:
/// the exposure window IS this number. Five minutes is defensible; an hour would not be, and
/// "unbounded, since we send keep-alives anyway" would mean a revoked key never stops working.
/// Raising it is a security change, not a tuning change, and the honest way to buy a longer stream
/// is to re-resolve the key per poll first — see the characterisation test
/// `a_revoked_key_keeps_being_served_until_the_lifetime_bound`, which pins today's behaviour.
const MAX_LIFETIME: Duration = Duration::from_secs(300);

/// How often a stream that has nothing to say writes an SSE comment. The BYTES are the plane's
/// ([`compose::KEEPALIVE`]) because they are bytes on this wire; WHEN they are written is here,
/// because it is a clock read and the plane reads no clock. What they stop is an idle proxy between
/// busbar and its caller reclaiming a connection that is working correctly.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

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
///
/// A CATALOGUE WALK UNDER A GRANT, which is why it stayed on this side of the seam when the frames
/// left: what a caller may see is a read of the live registry, and the plane is handed the ANSWER.
/// The array is in `compose::Kind::ALL` order, and that ordering is the contract between the walk
/// and the loop that emits — pinned by a cell rather than by this sentence.
fn change_keys(
    catalogue: &super::catalogue::Catalogue,
    caller: &busbar_substrate::catalogue::Caller<'_>,
) -> [u64; 3] {
    let tools = catalogue.tools_for(caller);
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
                .prompts_for(caller)
                .iter()
                .map(|p| p.namespaced.as_str())
                .collect(),
        ),
        change_key(
            catalogue
                .resources_for(caller)
                .iter()
                .map(|r| r.namespaced.as_str())
                .collect(),
        ),
    ]
}

/// THE CALLER'S REQUESTED CATEGORIES, off the SDK's own parameter type and onto the plane's.
///
/// The SDK type is the ACCEPTANCE TEST and that is why the parse stays here: a hand-read
/// `params.notifications.toolsListChanged` accepts shapes the specification does not, and each
/// acceptance is a difference between what busbar serves and what the protocol says. What crosses
/// the seam is the four members the wire has, which the plane narrows and then writes.
fn requested_of(filter: &SubscriptionFilter) -> compose::Filter {
    compose::Filter {
        tools_list_changed: filter.tools_list_changed,
        prompts_list_changed: filter.prompts_list_changed,
        resources_list_changed: filter.resources_list_changed,
        resource_subscriptions: filter.resource_subscriptions.clone(),
    }
}

struct Listen {
    /// THE NEUTRAL HOST SEAM, held for the stream's life and now the SOLE engine seam — the `AppHandle`
    /// field is gone. Cloned from `ctx.host` (a `from_handle` host) at open: the host reaches a poll
    /// makes (`principal_standing`, `clock_now_secs`) are engine-snapshot independent, and the per-poll
    /// catalogue/pool reads go through `runtime_live` off this host, which re-loads the CURRENT
    /// snapshot so a revoked key stops being served on the next poll.
    host: std::sync::Arc<dyn busbar_substrate::plane_host::EngineHost>,
    /// THE PRINCIPAL'S ID AND THE BOUND, never the principal. See the module header: a resolved key
    /// carried into a `'static` stream is an identity believed for five minutes.
    standing: busbar_substrate::trust::validate::Standing,
    /// THE FRAME COMPOSER — the accepted filter, the subscription tag and the phase, on the plane
    /// that names this wire. Every byte this stream writes is one of its answers.
    composer: compose::Listen,
    last_write: Instant,
    /// This stream's position in [`crate::mcp::client::pool::ResourceUpdates`] — the newest
    /// sequence at OPEN, so a subscription relays what upstreams announce AFTER it exists rather
    /// than replaying a history it never asked for. Each stream holds its own, which is why the
    /// ring is read by cursor rather than drained.
    cursor: u64,
}

/// The grant predicate, rebuilt per poll from the key RE-RESOLVED for that poll.
///
/// Neither the key nor the predicate is captured, which is stronger than the rule the input-required
/// loop states: that loop re-derives the grant from a key read once, and this re-derives the key too.
///
/// **AND A FIELD CHECK HERE WOULD HAVE BEEN A PLACEBO, which is why the fix is not one.** The
/// tempting local patch was to have this closure consult `enabled`/`is_live()` alongside
/// [`busbar_api::VirtualKey::scope_allowed`] — which reads `allowed_scopes` alone and looks at
/// neither. It would have changed nothing: those fields lived on the SAME frozen snapshot, so they
/// reported "live" for the whole life of the stream however long ago the store row said otherwise.
/// Only re-reading the key closes it, which is what [`busbar_substrate::trust::validate::Standing`] does and
/// why the fix is a core primitive rather than an extra `&&` on this line.
///
/// A free function rather than a method, because the caller holds `&mut` on the composer while it
/// holds this — two disjoint fields, which the borrow checker allows and a `&self` method does not.
///
/// It builds a `Caller` rather than a grant closure so that the per-frame catalogue read asks the
/// same ordered gate every other catalogue read asks, identity step included.
fn caller_of<'a>(
    host: &std::sync::Arc<dyn busbar_substrate::plane_host::EngineHost>,
    key: Option<&'a std::sync::Arc<busbar_api::VirtualKey>>,
    generation: u64,
) -> busbar_substrate::catalogue::Caller<'a> {
    busbar_substrate::catalogue::Caller {
        key: key.map(|k| &**k),
        now: host.clock_now_secs(),
        // AT ADMISSION for the FRAME, not for the stream. This value is re-built on every poll from
        // the generation the frame is being computed against, so the catalogue read cannot be judged
        // against a snapshot other than the one it is reading. The stream's own relationship to the
        // generation is `Snapshot::Watching`, held by `Standing` and re-asked above.
        generation: busbar_substrate::trust::validate::Generations::at_admission(generation),
    }
}

/// THE STANDING'S ANSWER, READ AS A VERDICT — plan line 9's verdict read, and the whole of what
/// this seam translates.
///
/// `Standing::still_permitted` walks expiry, then generation, then identity, and the arm it stops at
/// IS the step that refused: that walk is the fold, performed once, and re-folding asserted facts
/// here would be a SECOND decision that could disagree with it. So nothing is re-decided — what
/// changes is the VOCABULARY the answer is read in. A lapse used to be matched arm by arm where the
/// frame was written, in `busbar_substrate::trust::validate::{Lapsed, Refusal}`; it is now one closed
/// [`Verdict`] from `busbar_contract::counterparty`, the vocabulary the verify step's own fold
/// answers in, so the word a refused client reads and
/// the word an operator's ledger filters on are the same word by construction rather than by
/// agreement.
///
/// `None` is the BOUND, which is not a verdict: a counterparty vocabulary has no word for "this
/// response has been open long enough", because that is a fact about the response and not about the
/// party at the other end. It becomes the revision's graceful close.
fn verdict_of(lapsed: &busbar_substrate::trust::validate::Lapsed) -> Option<(Verdict, String)> {
    use busbar_substrate::trust::validate::Lapsed;
    match lapsed {
        Lapsed::Expired => None,
        Lapsed::Identity(refusal) => Some((Verdict::IdentityNotLive, refusal.to_string())),
        Lapsed::Generation(refusal) => Some((Verdict::GenerationMoved, refusal.to_string())),
    }
}

impl Listen {
    /// Produce the next chunk of the stream, `Some("")` for "nothing to say yet", or `None` to close
    /// it.
    ///
    /// EVERY BYTE IS THE PLANE'S and every READ is this crate's, which is the whole shape of this
    /// function: re-read the live snapshot once, re-ask the standing, walk the caller's catalogue,
    /// judge what an upstream announced — then hand the answers over as one [`Poll`] and write what
    /// comes back.
    fn step(&mut self) -> Option<String> {
        // ENDED IS ENDED, and this is checked FIRST rather than left to the composer.
        //
        // The re-check underneath it answers the same way every time it is asked, so a stream whose
        // permission has lapsed would re-emit its closing frame on every poll for ever instead of
        // closing — a refusal that never ends is a connection a client cannot tell from a working
        // one, which is the exact failure the graceful close exists to avoid. Found by
        // `a_revoked_key_stops_being_served_on_the_next_poll`'s final assertion, which is why that
        // assertion is not decoration.
        if self.composer.ended() {
            return None;
        }
        // The LIVE runtime, re-read ONCE per poll off the host's retained handle, then reused for
        // both the catalogue reads and the resource-update pool read below so all observe the SAME
        // re-loaded snapshot — byte-identical to the former single `self.handle.load()`. This is what
        // makes `a_revoked_key_stops_being_served_on_the_next_poll` bite on the next poll.
        let rt = super::runtime_live(&self.host);
        // D1: the neutral host seam the stream holds — the clock reads (the permission re-ask and the
        // per-frame catalogue `Caller`) ride it. Threaded in at open (cloned from `ctx.host`): the
        // `principal_standing` re-ask resolves against the process-shared LIVE governance registry (the
        // `Arc` survives config swaps) and the clock is engine-snapshot independent.
        let host = self.host.clone();
        let catalogue = &rt.catalogue;
        let now = Instant::now();
        // THE STANDING PERMISSION, RE-ASKED. A principal that has stopped resolving live ends the
        // stream on THIS frame rather than at the bound, which is the whole of the fix.
        let chunk = match host.principal_standing(
            &self.standing,
            catalogue.generation(),
            host.clock_now_secs(),
        ) {
            Err(lapsed) => match verdict_of(&lapsed) {
                Some((verdict, sentence)) => self.composer.step(Poll::Refused {
                    verdict,
                    sentence: &sentence,
                })?,
                None => self.composer.step(Poll::Complete)?,
            },
            Ok(key) => {
                let caller = caller_of(&host, key.as_ref(), catalogue.generation());
                let keys = change_keys(catalogue, &caller);
                let updates = match self.composer.subscribed() {
                    None => Vec::new(),
                    Some(uris) => relay(&mut self.cursor, uris, &rt, catalogue, &caller),
                };
                self.composer.step(Poll::Allowed {
                    generation: catalogue.generation(),
                    keys,
                    updates: &updates,
                })?
            }
        };
        if !chunk.is_empty() {
            self.last_write = now;
            return Some(chunk);
        }
        // NOTHING HAPPENED, which is the ordinary case and is not nothing to write: an idle
        // connection is reclaimed by intermediaries that cannot tell it from a dead one.
        if now.duration_since(self.last_write) >= KEEPALIVE_INTERVAL {
            self.last_write = now;
            return Some(compose::KEEPALIVE.to_string());
        }
        Some(String::new())
    }
}

/// THE RESOURCE-UPDATE RELAY'S JUDGEMENT — upstream announcements recorded by the client leg,
/// narrowed to the uris this poll may deliver. The FRAME is the plane's; this is the grant read
/// under it.
///
/// Judged per event, per poll, against THREE facts at once, each of which is load-bearing: the
/// subscriber ASKED for this uri (the accepted list, handed in), the uri resolves under the
/// subscriber's LIVE grant to an operator-declared resource (the same ordered gate `resources/read`
/// asks, re-derived this poll so a narrowed grant bites here), and the resolved resource belongs to
/// THE SERVER THAT ANNOUNCED it — an upstream cannot speak for another registration's inventory.
///
/// The cursor moves whether or not anything matched: an event judged and refused is an event
/// handled, not one to re-judge for ever.
///
/// A free function over `&mut u64` rather than a method, because the accepted list is borrowed out
/// of the composer while the cursor is written — two disjoint fields.
fn relay(
    cursor: &mut u64,
    asked: &[String],
    rt: &super::McpRuntime,
    catalogue: &super::catalogue::Catalogue,
    caller: &busbar_substrate::catalogue::Caller<'_>,
) -> Vec<String> {
    let (events, latest) = rt.pool.updates.since(*cursor);
    *cursor = latest;
    let mut out = Vec::new();
    for (server, uri) in events {
        if !asked.iter().any(|u| u == &uri) {
            continue;
        }
        let entitled = matches!(
            catalogue.resource_by_uri(caller, &uri),
            super::catalogue::ResourceLookup::One(entry) if entry.server == server
        );
        if !entitled {
            continue;
        }
        out.push(uri);
    }
    out
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
    // `busbar_substrate::handlers::mcp` states: a hand-read `params.notifications.toolsListChanged` accepts
    // shapes the specification does not, and each acceptance is a difference between what busbar
    // serves and what the protocol says.
    let requested: SubscriptionFilter = params
        .and_then(|p| p.get("notifications"))
        .cloned()
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default();
    // The entitlement AT OPEN, for the acknowledgement's narrowing: the same ordered gate
    // `resources/read` asks, under this caller's grant against the live snapshot. Re-asked per
    // poll at delivery — this read only decides what the acknowledgement may NAME.
    let accepted = {
        let rt = super::runtime_of(&ctx.host);
        let catalogue = &rt.catalogue;
        let caller = caller_of(&ctx.host, ctx.gov.key.as_ref(), catalogue.generation());
        compose::accept(&requested_of(&requested), |uri| {
            matches!(
                catalogue.resource_by_uri(&caller, uri),
                super::catalogue::ResourceLookup::One(_)
            )
        })
    };
    if accepted.delivers_nothing() {
        // A STREAM THAT CAN DELIVER NOTHING IS NOT A NARROWER STREAM, it is a connection held open
        // to say nothing, and a client waiting on one waits for ever. Refusing is the answer that
        // lets it fall back; acknowledging an empty filter and then going silent is the answer that
        // looks identical to a server that is merely quiet.
        return super::envelope::error_response(
            StatusCode::BAD_REQUEST,
            id,
            super::envelope::code::INVALID_PARAMS,
            "`params.notifications` opts in to no category this server delivers for you. busbar \
             delivers `toolsListChanged`, `promptsListChanged`, `resourcesListChanged`, and \
             `resourceSubscriptions` for uris your grant reaches — a subscription naming only \
             resources you cannot read is a stream with nothing to say.",
            None,
        );
    }
    // Never `None` on this path — `ingress` has already refused a notification and a null id — and
    // carried as `Option` only because every method in the table takes one. `Null` here would
    // produce a subscription with no name, which the plane's own tag refuses to build.
    let id = id.unwrap_or(serde_json::Value::Null);
    let now = Instant::now();
    let mut state = Listen {
        host: ctx.host.clone(),
        // THE ID AND THE BOUND. `MAX_LIFETIME` is handed to the standing permission as well as used
        // for the deadline below so the cap on what a poll cannot re-check and the cap on the stream
        // are provably the same number rather than two that agree today.
        standing: busbar_substrate::trust::validate::Standing::opened(
            ctx.gov.key(),
            // WATCHING, not pinned: a generation move is what this response exists to report, and
            // every frame it writes is re-derived from the live snapshot. Pinning it would make the
            // subscription end on the first change it was opened to hear about.
            busbar_substrate::trust::validate::Snapshot::Watching,
            MAX_LIFETIME,
        ),
        composer: compose::Listen::opened(id, accepted),
        last_write: now,
        // From NOW: announcements recorded before this subscription existed are not replayed.
        cursor: super::runtime_of(&ctx.host).pool.updates.latest(),
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

#[cfg(all(test, feature = "test-support"))]
#[path = "tests/subscribe_tests.rs"]
mod subscribe_tests;
