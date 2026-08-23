// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE A2A RECEIVING HOT PATH: the router that turns this plane's decisions into a served request.
//!
//! Everything below this module already existed and was tested; none of it had a caller. This is
//! the caller. The order is fixed and each step is the previous one's precondition:
//!
//! 1. AUTHENTICATE — done before a handler here runs, by the shared auth middleware. What makes it
//!    an A2A authentication rather than a data-plane one is [`crate::plane::PlaneAdmission`]: the
//!    middleware reads this mount's admission facts and threads its audience into the token
//!    verifier, which refuses a token whose `aud` is absent or different.
//! 2. AUTHORISE — [`super::inbound::authorize`], whose decision is `scope_allowed("agent", id)`.
//! 3. CATALOGUE — [`super::registry::inbound_catalogue`], which answers whether this caller may
//!    see this agent for the SHAPE of work it is asking for, and names the skill that matched.
//! 4. DISPATCH — the [`super::inbound::Dispatch`] naming the backend, and a durable task recording
//!    that it happened.
//! 5. METER — [`super::meter::Attribution`] for who is billed, and the shared governance ledger for
//!    the spend itself, labelled with this plane's own key.
//! 6. AUDIT — one admin-audit record per call, plus this plane's per-task provenance chain.
//!
//! ## THE CREDENTIAL KIND IS A FACT ABOUT THE MOUNT, NOT A ROW IN A TABLE
//!
//! [`super::inbound::authorize`] refuses anything whose credential kind is not `a2a_inbound`, and
//! the value it names cannot be a `CredentialMeta.kind`: that type admits a kind ONLY if its
//! verification path resolves a row from a wire-supplied public identifier, and this plane's
//! credential is a bearer token, which resolves no row — it is verified by signature and then looked
//! up by its own authenticated subject.
//!
//! The way out is not to widen that rule. It is that "this credential was minted for the A2A plane"
//! is established by the AUDIENCE the verifier already checked, so the fact is available here
//! without any credential-row concept at all. [`credential_kind_of`] therefore derives the kind from
//! whether this mount is audience-bound, rather than passing a constant: on a mount with no
//! admission facts nothing has checked an audience, so no request is an `a2a_inbound` request and
//! `authorize` refuses every one of them. The check stays real at its only production call site.

use axum::response::{IntoResponse, Response};
use std::sync::Arc;

use super::inbound::{Dispatch, CREDENTIAL_KIND_A2A_INBOUND};
use super::words::{plane_absent, refuse_admission, A2aWords};
use crate::diagnostics::{
    diag_debug, diag_error, diag_warn, A2A_AGENT_BINDING_UNSPEAKABLE,
    A2A_BREAKER_REFUSAL_UNRECORDED, A2A_FAILURE_UNRECORDED, A2A_INBOUND_TASK_UNOPENED,
    A2A_INBOUND_TASK_UNRECORDED, A2A_INTERRUPTED_TASK_UNRESUMED, A2A_OUTBOUND_CRED_UNLEASED,
    A2A_OWN_CARD_BUILD_FAILED, A2A_PUSH_NOTIFY_UNDELIVERED, A2A_REFUSE_SERVE_CARD,
    A2A_RELAYED_OUTCOME_UNRECORDED, A2A_RELAYED_STREAM_REFUSED, A2A_RELAYED_SUBMISSION_FAILED,
    A2A_RELAY_THREAD_INCOMPLETE, A2A_STREAM_EMPTY, A2A_STREAM_RELAY_INCOMPLETE,
};
use crate::plane::taskstore;
use crate::state::{App, CurrentApp};

/// The audit action every inbound call on this plane records under.
pub(super) const AUDIT_ACTION: &str = "agent.call";

/// THE CREDENTIAL KIND THIS MOUNT CONFERS. `a2a_inbound` only when the plane is audience-bound;
/// otherwise the empty string, which [`super::inbound::authorize`] refuses.
///
/// See the module doc for why this is derived rather than asserted. In one line: an audience-bound
/// mount is the only place a token can have been checked against this plane's resource indicator,
/// so it is the only place the presented credential is an A2A inbound credential.
fn credential_kind_of(app: &App) -> &'static str {
    let bound = app
        .planes
        .mount_of(crate::plane::Plane::A2a)
        .and_then(|mount| app.planes.admission_for(mount))
        .is_some();
    if bound {
        CREDENTIAL_KIND_A2A_INBOUND
    } else {
        ""
    }
}

/// BUSBAR'S OWN AGENT CARD at `/.well-known/agent-card.json`, unauthenticated.
///
/// The A2A protocol specification makes serving an Agent Card a MUST, and this is the path a
/// stock A2A client
/// asks for first. See [`super::serve::self_card`] for why it is auth-exempt and, more importantly,
/// for what is deliberately left out of it — this endpoint cannot ask who is calling, so it must
/// not name the agents busbar fronts.
pub(crate) async fn well_known_card(CurrentApp(app): CurrentApp) -> Response {
    let Some(plane) = crate::a2a::runtime(&app) else {
        return plane_absent();
    };
    // NO PUBLIC URL, NO CARD. A deployment with no receiving side is not an A2A server, and a card
    // whose `url` was guessed would point callers somewhere busbar does not answer.
    let Some(public_url) = plane.public_url() else {
        return no_receiving_side();
    };
    // Signed by the same key that signs the fronted cards, read from the same place, so what an
    // external caller pins busbar by is one key rather than one per path.
    let signer = crate::a2a::sign::card_signer(&app);
    match super::serve::self_card(public_url, signer.as_ref()) {
        Ok(doc) => (
            [
                (axum::http::header::CACHE_CONTROL, "public, max-age=3600"),
                (
                    axum::http::header::CONTENT_TYPE,
                    "application/json; charset=utf-8",
                ),
            ],
            axum::Json(doc),
        )
            .into_response(),
        // A card busbar cannot build is a 500, not an empty 200. The one failure that reaches here
        // is a `public_url` that will not parse, and answering with a hollow document would publish
        // a card asserting an endpoint nobody can reach.
        Err(e) => {
            diag_error!(A2A_OWN_CARD_BUILD_FAILED, error = %e, "could not build busbar's own agent card");
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({
                    "error": { "code": "internal", "message": "the agent card could not be built" }
                })),
            )
                .into_response()
        }
    }
}

/// Everything the admitted half of a request needs, resolved under ONE read of the registry.
///
/// A single lock acquisition rather than one per step, because `authorize` and the catalogue must
/// agree about the same registry state: two acquisitions could straddle a re-verification sweep and
/// admit against one registration while cataloguing against another.
pub(super) struct Admitted {
    pub(super) dispatch: Dispatch,
    matched_skill: Option<String>,
    /// THE REGISTRY GENERATION THIS REQUEST WAS ADMITTED UNDER, read under the same lock the
    /// admission was decided under. Carried to the relay gate, where a move is a refusal.
    pub(super) generation: u64,
    /// The registration's OUTBOUND CREDENTIAL HANDLE, cloned out under the same registry read that
    /// authorised the call. A handle and its lease policy, never a secret: the secret is resolved at
    /// relay time by [`super::creds::mint_from`], whose signature has no parameter an inbound
    /// caller's credential could arrive through.
    ///
    /// Cloned rather than re-read because a second acquisition could straddle a config apply and
    /// mint a credential for a registration that is not the one this call was authorised against.
    pub(super) outbound_cred: Option<super::creds::OutboundCredential>,
}

/// THE ADMISSION SEQUENCE, steps 2 and 3, under one registry read.
///
/// The error is BOXED because an axum `Response` is large and this is the refusal path: paying an
/// allocation on a request that is being turned away is cheaper than widening every `Result` on the
/// admitted path by the size of a response nobody on it will ever carry.
fn admit(
    app: &App,
    key: &busbar_api::VirtualKey,
    agent_id: &str,
    shape: &super::registry::TaskShape,
    now_secs: u64,
) -> Result<Admitted, Box<Response>> {
    let Some(plane) = crate::a2a::runtime(app) else {
        return Err(Box::new(plane_absent()));
    };
    let kind = credential_kind_of(app);
    // READ ONCE, under the same acquisition as the registry itself, so the value carried forward is
    // the generation the decision below was actually taken on.
    let generation = plane.generation();
    let caller = crate::catalogue::Caller {
        key: Some(key),
        now: now_secs,
        generation: crate::trust::validate::Generations::at_admission(generation),
    };
    plane.with_registrations(|regs| {
        // 2. AUTHORISE. `Dispatch` is owned, so it escapes this closure; `Candidate` borrows the
        //    guard's slice and cannot, which is why the skill is cloned out below rather than
        //    returned.
        let dispatch = super::inbound::authorize(key, kind, agent_id, regs, generation, now_secs)
            .map_err(|r| Box::new(refuse_admission(&r)))?;

        // 3. CATALOGUE. Authorisation says the caller may reach this agent AT ALL; the catalogue
        //    says whether it may reach it for the work it is actually asking for. Both run: a
        //    caller with a grant on an agent whose card declares none of the requested capability
        //    is refused here rather than dispatched into a backend that will not serve it.
        let wanted = super::registry::Wanted {
            shape: shape.clone(),
            delegating_from: None,
        };
        let matched = super::registry::inbound_catalogue(&caller, regs, &wanted)
            .into_iter()
            .find(|c| c.item.agent_id == dispatch.agent_id)
            .map(|c| c.fit.clone());
        let outbound_cred = regs
            .iter()
            .find(|r| r.agent_id == dispatch.agent_id)
            .and_then(|r| r.outbound_cred.clone());

        match matched {
            Some(matched_skill) => Ok(Admitted {
                dispatch,
                matched_skill,
                generation,
                outbound_cred,
            }),
            None => {
                // The catalogue excluded it. `explain` re-derives WHY for the one registration,
                // so the refusal names a reason instead of an empty list.
                let reason = regs
                    .iter()
                    .find(|r| r.agent_id == dispatch.agent_id)
                    .and_then(|r| super::registry::explain(r, &caller, &wanted).err())
                    .map_or_else(
                        || "the agent is not in this caller's catalogue".to_string(),
                        |e| format!("{e:?}"),
                    );
                Err(Box::new(
                    (
                        axum::http::StatusCode::FORBIDDEN,
                        axum::Json(super::rpcerror::body(
                            &serde_json::Value::Null,
                            super::rpcerror::A2aError::UnsupportedOperation,
                            reason,
                        )),
                    )
                        .into_response(),
                ))
            }
        }
    })
}

/// WHICH FRONTED AGENT `POST /a2a` IS FOR — answered by THIS CALLER'S CATALOGUE.
///
/// ## Why this endpoint exists at all
///
/// busbar's own Agent Card, at `/.well-known/agent-card.json`, publishes exactly one interface:
/// `<public_url>/a2a`, a `JSONRPC` binding. That is what a stock A2A client reads and where it
/// posts — the client never sees `/a2a/agents/{id}`, because a card that enumerated the fronted
/// agents from an unauthenticated path would hand a stranger the internal agent inventory, which
/// `serve::self_card` refuses to do and should keep refusing.
///
/// Nothing was mounted there. Every conformant client therefore discovered busbar, read its card,
/// posted to the endpoint that card advertises, and got a `404` — from busbar's generic fallback,
/// in busbar's generic error shape. Against the official A2A TCK that is 40 of the 48 MUST failures
/// on the JSON-RPC transport, all reading `Operation failed: the requested resource was not found`.
/// Publishing an endpoint nobody serves is worse than publishing none.
///
/// ## Why the CATALOGUE and not a name in the request
///
/// This is the sibling plane's shape, deliberately. `/mcp` is ONE endpoint and the upstream that
/// serves a call is resolved from what the caller asked for, filtered by what that caller's key
/// grants — `mcp::catalogue`. `super::registry::inbound_catalogue` is the same function for this
/// plane and was written for exactly this: it takes the caller's key and a [`TaskShape`] and
/// answers which registrations are trusted, granted, and structurally able to serve that shape. It
/// had one caller, which passed a name and then filtered the answer down to it.
///
/// ## AMBIGUITY IS A REFUSAL, never a guess
///
/// One candidate dispatches. NONE is a refusal. MORE THAN ONE is also a refusal, and that is the
/// decision worth defending: quietly picking the first of several would send a caller's work to a
/// vendor they did not choose, and the caller has no way to tell it happened. A deployment fronting
/// several agents that can all serve one shape has a caller who must say which — and that caller
/// has an unambiguous address for it, `POST /a2a/agents/{id}`, which the refusal names.
fn select(
    app: &App,
    key: &busbar_api::VirtualKey,
    shape: &super::registry::TaskShape,
) -> Result<String, Box<Response>> {
    let Some(plane) = crate::a2a::runtime(app) else {
        return Err(Box::new(plane_absent()));
    };
    let caller = crate::catalogue::Caller {
        key: Some(key),
        now: crate::store::now(),
        generation: crate::trust::validate::Generations::at_admission(plane.generation()),
    };
    let wanted = super::registry::Wanted {
        shape: shape.clone(),
        delegating_from: None,
    };
    let mut ids = plane.with_registrations(|regs| {
        super::registry::inbound_catalogue(&caller, regs, &wanted)
            .into_iter()
            .map(|c| c.item.agent_id.clone())
            .collect::<Vec<_>>()
    });
    match ids.len() {
        1 => Ok(ids.remove(0)),
        // The SAME answer a caller with no grant gets for a named agent, and for the same reason:
        // "there is nothing here for you" and "there is something here you may not have" must not
        // be distinguishable, or this endpoint is an inventory oracle for an unauthorised caller.
        0 => Err(Box::new(super::rpcerror::respond(
            &serde_json::Value::Null,
            super::rpcerror::A2aError::UnsupportedOperation,
            "no agent this key may reach can serve this shape of task",
        ))),
        n => Err(Box::new(super::rpcerror::respond(
            &serde_json::Value::Null,
            super::rpcerror::A2aError::InvalidParams,
            format!(
                "{n} agents this key may reach can serve this shape of task, so this endpoint \
                 cannot choose one for you. Address the agent directly at \
                 `/a2a/agents/{{id}}` — the ids are: {}",
                ids.join(", ")
            ),
        ))),
    }
}

/// THE PLANE'S OWN ENDPOINT — `POST /a2a`, the one busbar's Agent Card publishes.
///
/// Identical to [`agent_rpc`] in everything except how the agent is named. See [`select`].
pub(crate) async fn plane_rpc(
    CurrentApp(app): CurrentApp,
    axum::extract::Extension(gov): axum::extract::Extension<crate::governance::GovCtx>,
    axum::extract::Extension(principal): axum::extract::Extension<crate::auth::AuthPrincipal>,
    wire: Wire,
    body: axum::body::Bytes,
) -> Response {
    invoke(
        app,
        gov,
        principal,
        FromCatalogue,
        wire,
        crate::transport::Transport::JsonRpc,
        body,
    )
    .await
}

/// The A2A protocol versions THIS ENDPOINT SPEAKS, in the `Major.Minor` spelling the specification
/// negotiates in.
///
/// Both, and each because the tree can be pointed at for it rather than because it sounds
/// generous. `shape_of` reads the v0.3 streaming methods (`message/stream`, `tasks/resubscribe`)
/// AND the v1.0 renames (`SendStreamingMessage`, `SubscribeToTask`); [`super::relay`] reads a bare
/// v0.3 `result` and a v1.0 `{"task": …}` wrapper; [`super::idmap`] rewrites `id`, `taskId` and
/// v1.0's `task_id`. Everything else on this plane is relayed verbatim and is version-agnostic by
/// construction. A version this list claims that no code reads would be a document asserting a
/// property nothing implements, which is the defect this plane keeps finding.
///
/// ORDERED OLDEST-FIRST, and the order is READ rather than incidental: `serve::published_interfaces`
/// reverses it so the card's ordered `supportedInterfaces` — whose first entry the specification
/// makes the preferred one — steers a client at the newest version this endpoint admits.
pub(crate) const SUPPORTED_A2A_VERSIONS: &[&str] = &["0.3", "1.0"];

/// The media type A2A's JSON-RPC binding names. Compared as a MEDIA TYPE, never as a header string:
/// `application/json; charset=utf-8` is the same media type and a great many clients send it.
const JSON_MEDIA_TYPE: &str = "application/json";

/// WHETHER A DECLARED MEDIA TYPE IS ONE THIS ENDPOINT READS.
///
/// `application/json` is A2A's JSON-RPC binding (specification section 9.1). `application/a2a+json`
/// is the spelling section 11.1 says SHOULD be used, and refusing it would refuse the protocol's own
/// preferred media type — the independent battery in `testing/a2a-harness` sends exactly that on
/// every call, which is how the first draft of this predicate was caught before it shipped.
///
/// So the rule is the RFC 6839 structured-syntax suffix rather than a two-name list: anything ending
/// `+json` is JSON by the registration's own definition, and a future `application/a2a-v2+json` is
/// admitted without anybody having to remember this function exists. What is refused is a media type
/// that does not claim to be JSON at all, which is the only case the caller can act on.
fn is_json_media_type(media: &str) -> bool {
    media.eq_ignore_ascii_case(JSON_MEDIA_TYPE)
        || media
            .rsplit_once('+')
            .is_some_and(|(_, suffix)| suffix.eq_ignore_ascii_case("json"))
}

/// THE THREE HEADERS THIS PLANE READS OFF AN INBOUND REQUEST, and deliberately the only three.
///
/// A `HeaderMap` is NOT extracted, here or anywhere on this path, and that is a security property
/// rather than a style: the first draft of the relay extracted one and the caller's own credential
/// went out on the backend hop (see step 7 in [`invoke`]). An extractor that can only ever hold
/// these owned strings cannot forward a further header by accident, because there is no further
/// header in it to forward. **The property is about what this type CANNOT hold, not about the
/// number three** — [`Wire::origin`] joined it when the shared ingress gained its DNS-rebinding
/// refusal, and it joined as one more `Option<String>` for exactly that reason.
pub(crate) struct Wire {
    /// The request's `Content-Type`, as sent. `None` when the caller sent none.
    content_type: Option<String>,
    /// The requested `A2A-Version`. `None` when absent; `Some("")` when present and empty, which
    /// the specification defines as `0.3` rather than as a refusal.
    version: Option<String>,
    /// The caller's `Origin`, when it sent one. Read here rather than judged here: the verdict is
    /// `crate::ingress::protocol::origin_admitted`'s, once, for every JSON-RPC plane.
    origin: Option<String>,
}

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for Wire {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        // A header whose bytes are not UTF-8 reads as absent rather than as a refusal: neither of
        // these two carries a value that could legitimately be non-ASCII, so a non-UTF-8 one is a
        // broken client, and the request still has to satisfy every gate below this one.
        let read = |name: &str| {
            parts
                .headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        Ok(Wire {
            content_type: read("content-type"),
            version: read("a2a-version"),
            origin: read("origin"),
        })
    }
}

impl Wire {
    /// THE SAME TWO FACTS, AS THE gRPC BINDING SUPPLIES THEM.
    ///
    /// [`Wire`]'s fields are private because the extractor is the security property — an extractor
    /// that can hold only these two owned strings cannot forward a third header by accident. That
    /// property survives here: this constructor takes the two facts and nothing else, so the gRPC
    /// binding has no more of the caller's request in its hands than the HTTP one does.
    ///
    /// The content type is `None` rather than `application/grpc`, and the distinction is the whole
    /// point of [`Wire::refuse`]'s first gate: that gate asks "is the body this endpoint is about to
    /// parse JSON?", and by the time this exists the protobuf frame has already been decoded and
    /// re-rendered AS JSON by the caller of this function. Declaring the gRPC media type here would
    /// have the JSON reader refuse a body it can read, in the name of a header that describes a
    /// framing this value is downstream of.
    pub(super) fn for_grpc(version: String) -> Self {
        Wire {
            content_type: None,
            version: Some(version),
            // NO ORIGIN ON A gRPC LEG. `Origin` is a browser header and the rebinding attack it
            // defends against is a browser attack; a gRPC frame arrives from a client that has no
            // such concept, so declaring one here would invent a fact about the request.
            origin: None,
        }
    }

    /// The caller's `Origin` header, as sent. A FACT, never a verdict — see the field.
    fn origin(&self) -> Option<&str> {
        self.origin.as_deref()
    }

    /// THE REFUSAL THIS REQUEST'S HEADERS EARN, or `None` when they earn none.
    ///
    /// `Null` as the JSON-RPC `id` throughout, and that is the specification's instruction rather
    /// than laziness: the body has not been read at this point, so the id has not been determined,
    /// and JSON-RPC 2.0 section 5 says an answer sent before the id is known MUST carry `null`.
    /// THE VERSION THIS REQUEST NEGOTIATED, at the `Major.Minor` granularity the specification
    /// negotiates at, and `0.3` when the caller named none — A2A's own default for an absent or
    /// empty header.
    ///
    /// It exists because busbar is a CLIENT on the next hop, and A2A section 3.3 says a client
    /// MUST send `A2A-Version` with each request. busbar reads the header at its own edge and
    /// answers for it there ([`Wire::refuse`]), which is right: busbar is the server the caller
    /// connected to. But terminating it is not the same as forgetting it. The relay forwards the
    /// caller's `method` VERBATIM, and the two dialects spell every method differently — a v1.0
    /// caller's `SendMessage` arrives at the backend as `SendMessage`. A hop that carries a v1.0
    /// method while sending no version at all is telling the backend "0.3" by omission and then
    /// speaking 1.0, and a backend that believes the omission refuses the request it was sent.
    ///
    /// That is not hypothetical. It is what the official TCK saw the moment the conformance rig's
    /// fronted agent was changed from one that ignores the header to one that reads it: 62 of 114
    /// MUSTs met became 24, with the backend answering `VERSION_NOT_SUPPORTED` to methods busbar
    /// had itself just accepted as valid 1.0.
    fn negotiated_version(&self) -> &'static str {
        let asked = self.version.as_deref().unwrap_or_default().trim();
        if asked.is_empty() {
            return "0.3";
        }
        let mut parts = asked.split('.');
        let major_minor = match (parts.next(), parts.next()) {
            (Some(major), Some(minor)) => format!("{major}.{minor}"),
            _ => asked.to_string(),
        };
        // `refuse` runs first and rejects anything not in this set, so a value that reaches here is
        // always one of them. The fallback is `0.3` rather than a panic because a version busbar
        // does not speak must never be repeated onto a hop as though it did.
        SUPPORTED_A2A_VERSIONS
            .iter()
            .copied()
            .find(|v| *v == major_minor)
            .unwrap_or("0.3")
    }

    fn refuse(&self) -> Option<Response> {
        if let Some(ct) = self.content_type.as_deref() {
            // The media type is everything before the first `;`, case-insensitively. A caller that
            // sent NO `Content-Type` has not sent a WRONG one and is not refused here — the body
            // still has to parse as JSON, which is the check that already existed and which stays
            // the floor. Tightening that would be a new way to break callers that work today, so
            // it is stated here rather than left to be discovered.
            let media = ct.split(';').next().unwrap_or_default().trim();
            if !is_json_media_type(media) {
                return Some(super::rpcerror::respond(
                    &serde_json::Value::Null,
                    super::rpcerror::A2aError::ContentTypeNotSupported,
                    format!(
                        "this endpoint reads `{JSON_MEDIA_TYPE}` and any `+json` media type; the \
                         request declared `{media}`"
                    ),
                ));
            }
        }

        // ABSENT OR EMPTY IS `0.3`, which is A2A's own rule for a caller that names no version and
        // not a leniency invented here. Every client written before the header existed sends
        // neither, and refusing them would be this gate breaking the compatibility it is about.
        let asked = self.version.as_deref().unwrap_or_default().trim();
        if asked.is_empty() {
            return None;
        }
        // NEGOTIATION IS ON `Major.Minor`: the specification's own granularity. A caller asking for
        // `1.0.7` is asking for `1.0`, and a comparison against the whole string would refuse it
        // for naming a patch level nobody negotiates.
        let mut parts = asked.split('.');
        let major_minor = match (parts.next(), parts.next()) {
            (Some(major), Some(minor)) => format!("{major}.{minor}"),
            _ => asked.to_string(),
        };
        if SUPPORTED_A2A_VERSIONS.contains(&major_minor.as_str()) {
            return None;
        }
        Some(super::rpcerror::respond(
            &serde_json::Value::Null,
            super::rpcerror::A2aError::VersionNotSupported,
            format!(
                "this endpoint speaks A2A {}; the request asked for `{asked}`",
                SUPPORTED_A2A_VERSIONS.join(" and ")
            ),
        ))
    }
}

/// SERVE THE AGENT CARD — `GET /a2a/agents/{agent_id}`.
///
/// Authenticated rather than open, and that is deliberate: the card names an agent this deployment
/// fronts, and which agents exist is exactly what a caller with no grant on them must not learn.
/// The refusal taxonomy does the rest — a caller with no grant gets the same 403 whether or not the
/// agent exists, and only a caller that could reach it gets the 404.
pub(crate) async fn card(
    CurrentApp(app): CurrentApp,
    axum::extract::Extension(gov): axum::extract::Extension<crate::governance::GovCtx>,
    axum::extract::Path(agent_id): axum::extract::Path<String>,
) -> Response {
    let Some(plane) = crate::a2a::runtime(&app) else {
        return plane_absent();
    };
    let Some(key) = gov.key.as_ref() else {
        return governance_required();
    };
    let Some(public_url) = plane.public_url() else {
        return no_receiving_side();
    };

    // A card read asks for no particular work, so the shape is the empty one: every filter that
    // depends on the requested capability is vacuous and only trust, scope and a cached card decide.
    let shape = super::registry::TaskShape::default();
    let admitted = match admit(&app, key, &agent_id, &shape, crate::store::now()) {
        Ok(a) => a,
        Err(resp) => return *resp,
    };

    let cached = plane.with_registrations(|regs| {
        regs.iter()
            .find(|r| r.agent_id == admitted.dispatch.agent_id)
            .and_then(|r| r.cached_card.clone())
    });
    let Some(cached) = cached else {
        // Trusted, in scope, and nothing has been fetched yet. Not an error in the caller's
        // request — the re-verification job has simply not looked yet.
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({
                "error": {
                    "code": "unavailable",
                    "message": "no agent card has been fetched for this registration yet"
                }
            })),
        )
            .into_response();
    };

    // BUSBAR SIGNS WHAT BUSBAR SERVES. The vendor's signature cannot survive the rewrite, so the
    // served card carries busbar's own — which is what gives an external caller something to pin
    // busbar by.
    let signer = crate::a2a::sign::card_signer(&app);
    match super::serve::rewrite_card(
        &cached,
        &admitted.dispatch.backend_url,
        public_url,
        &admitted.dispatch.agent_id,
        signer.as_ref(),
    ) {
        Ok(card) => (axum::http::StatusCode::OK, axum::Json(card)).into_response(),
        Err(e) => {
            // A leak refusal is a REFUSAL TO SERVE, never a warning: a served card that names the
            // backend hands a caller the way around every control busbar applies. It is a
            // server-side fault, so it answers 502 and the detail stays in the log.
            diag_warn!(A2A_REFUSE_SERVE_CARD, agent = %admitted.dispatch.agent_id, error = %e, "a2a: refusing to serve an agent card");
            (
                axum::http::StatusCode::BAD_GATEWAY,
                axum::Json(serde_json::json!({
                    "error": { "code": "upstream_error", "message": "the agent card could not be served" }
                })),
            )
                .into_response()
        }
    }
}

/// This plane cannot admit anyone without governance: its whole admission story is an audience on a
/// busbar-minted token plus that key's `agent` scopes, and neither exists when governance is off.
/// Said plainly rather than by silently admitting everyone.
fn governance_required() -> Response {
    (
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        axum::Json(super::rpcerror::body(
            &serde_json::Value::Null,
            super::rpcerror::A2aError::Internal,
            "the A2A plane requires governance: an inbound caller is admitted by its key's \
             `agent` scopes, and there are no keys here",
        )),
    )
        .into_response()
}

/// `agents:` configured for the DELEGATING direction alone — no `public_url`, so no receiving side.
pub(super) fn no_receiving_side() -> Response {
    (
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        axum::Json(super::rpcerror::body(
            &serde_json::Value::Null,
            super::rpcerror::A2aError::UnsupportedOperation,
            "this deployment fronts agents for delegation only: it has no `public_url`, so it \
             serves no inbound A2A surface",
        )),
    )
        .into_response()
}

/// THE INBOUND CALL — `POST /a2a/agents/{agent_id}`.
///
/// Admits, catalogues, authorises the EGRESS, guards the caller's push callback, opens (or RESUMES)
/// a durable task, meters the hop against the presenting key, audits it, AND RELAYS IT TO THE
/// BACKEND AGENT — then carries the backend's reply back under busbar's own task identity, as one
/// answer or as a stream of them, or answers a busbar-attributed error and ends the task.
///
/// The handler deliberately does NOT extract a `HeaderMap`. See step 7 below.
pub(crate) async fn agent_rpc(
    CurrentApp(app): CurrentApp,
    axum::extract::Extension(gov): axum::extract::Extension<crate::governance::GovCtx>,
    axum::extract::Extension(principal): axum::extract::Extension<crate::auth::AuthPrincipal>,
    axum::extract::Path(agent_id): axum::extract::Path<String>,
    wire: Wire,
    body: axum::body::Bytes,
) -> Response {
    invoke(
        app,
        gov,
        principal,
        Named(agent_id),
        wire,
        crate::transport::Transport::JsonRpc,
        body,
    )
    .await
}

/// WHICH FRONTED AGENT A SUBMISSION IS FOR, and the two ways a caller can say it.
///
/// The mounted endpoints differ in this and in NOTHING else — same admission, same catalogue,
/// same meter, same audit, same relay — which is why the difference is a two-variant value passed
/// into one function rather than handlers that happen to look alike. A second copy of the
/// sequence is a second place for the egress gate or the push-callback guard to go missing.
pub(super) enum Target {
    /// `POST /a2a/agents/{id}` — the caller named the agent in the path.
    Named(String),
    /// `POST /a2a`, and every HTTP+JSON path under it — the plane's own endpoint, the one busbar's
    /// Agent Card publishes. The agent is resolved from THIS CALLER'S CATALOGUE for the shape of
    /// work asked for. See [`select`].
    FromCatalogue,
}
use Target::{FromCatalogue, Named};

/// THE INBOUND CALL, EVERY ENDPOINT AND EVERY BINDING, ONE SEQUENCE.
///
/// `transport` is the leg the request arrived on — [`crate::transport::Transport::JsonRpc`],
/// [`crate::transport::Transport::HttpJson`] or [`crate::transport::Transport::Grpc`] — and it is
/// carried as a VALUE, never compared. It is read in exactly one place, the metric label at the end
/// of this function, and the reason it has to be carried at all is a consequence the second binding
/// made unavoidable: `plane::observe` can only name the binding a DOOR declares, and two of this
/// plane's three are spoken at the same door. Which of them named the operation is a fact only this
/// plane's own reader has, so this plane labels its own requests from inside, with the leg they came
/// in on — which is what makes a per-binding number readable from busbar's own telemetry rather than
/// only from a conformance suite's stdout.
pub(super) async fn invoke(
    app: Arc<App>,
    gov: crate::governance::GovCtx,
    principal: crate::auth::AuthPrincipal,
    target: Target,
    wire: Wire,
    transport: crate::transport::Transport,
    body: axum::body::Bytes,
) -> Response {
    let started = std::time::Instant::now();
    let observed = Arc::clone(&app);
    let mut answered = invoke_inner(app, gov, principal, target, wire, body).await;
    crate::telemetry::request_finished(
        &observed,
        crate::plane::Plane::A2a.key(),
        transport.name(),
        // The same sentinel `plane::observe` stamps, and for the same reason it states there: the
        // routing target is client-supplied and an unbounded label value is a memory-exhaustion DoS
        // one valid credential can drive.
        crate::proxy::POOL_LABEL_UNRESOLVED,
        crate::telemetry::outcome_of(answered.status().as_u16()),
        started.elapsed().as_secs_f64(),
    );
    // AND THE BOUNDARY IS TOLD, so it does not count this request a second time under the binding
    // its door declares. Everything the boundary still covers — the audience-bound `401`, a `413`, a
    // `404` — reached no handler and therefore carries no marker, which is exactly the set it is
    // there for.
    answered
        .extensions_mut()
        .insert(crate::plane::observe::Counted);
    answered
}

/// The sequence itself. Split from [`invoke`] only so the label above is emitted on EVERY exit —
/// there are a dozen early returns below, and a metric emitted at each of them is a metric that
/// will one day be missing from the thirteenth.
async fn invoke_inner(
    app: Arc<App>,
    gov: crate::governance::GovCtx,
    principal: crate::auth::AuthPrincipal,
    target: Target,
    wire: Wire,
    body: axum::body::Bytes,
) -> Response {
    // ── THE TWO FACTS OFF THE REQUEST LINE, JUDGED BEFORE THE BODY IS PARSED. ───────────────────
    //
    // busbar is content-blind about the caller's ENVELOPE and is not content-blind about the HTTP
    // request carrying it. busbar terminated this connection; busbar is the server the client
    // discovered, authenticated to and addressed. A media type this endpoint does not read and a
    // protocol version this endpoint does not speak are therefore busbar's answers to give, and
    // relaying either to a backend and forwarding its cheerful reply tells the caller it was
    // understood when nothing understood it.
    //
    // BEFORE THE JSON PARSE, because the order IS the behaviour: a request with a wrong media type
    // usually also carries a body that is not JSON, and a gate placed after the parse answers
    // `Parse` (-32700) forever and never reaches -32005. The caller is then told to fix its body
    // when the thing to fix is a header. `crate::ingress::protocol::serve` runs step 3 — this
    // value — before its own parse for exactly that reason; it is the one pre-parse step that is
    // genuinely a protocol's.
    //
    // GOVERNANCE IS FOLDED IN AHEAD OF IT, keeping the order this plane has always had: without
    // governance there is no key, and this plane's whole admission story is an audience on a
    // busbar-minted token plus that key's `agent` scopes.
    let wire_refusal = if gov.key.is_none() {
        Some(governance_required())
    } else {
        wire.refuse()
    };
    // ADMITTED, AND THEREFORE RESTATED ON THE NEXT HOP. busbar answers for this header at its own
    // edge and then speaks it downstream; see `Wire::negotiated_version` for why terminating it is
    // not the same as forgetting it.
    let a2a_version = wire.negotiated_version();
    let origin = wire.origin().map(str::to_string);
    // A SECOND HANDLE ON THE SAME BYTES, not a second copy: `Bytes` is refcounted. The shared
    // sequence borrows the body to parse it and the relay needs to own it afterwards, and one
    // `Arc` bump is the whole cost of letting both have it.
    let relayed = body.clone();

    // STEPS 1, 2, 4, 5, 6, 7, 8 AND 13 ARE CORE'S. This plane states none of them any more, and
    // step 2 — the `Origin` / DNS-rebinding refusal — is one it never stated at all: it arrived
    // here by being core's, which is the entire argument for the concern having one home.
    crate::ingress::protocol::serve(
        &A2aWords,
        crate::ingress::protocol::Request {
            present: crate::a2a::runtime(&app).is_some(),
            origin: origin.as_deref(),
            // NO OPERATOR ALLOWLIST ON THIS PLANE, so loopback and nothing else. A2A is an
            // agent-to-agent protocol: its clients are servers and agents, which send no `Origin`
            // at all and are therefore untouched by this. A browser-driven A2A console would need
            // a listed origin, and the day one exists this is where the operator's list arrives —
            // as DATA, into the rule that already decides it, not as a second check.
            allowed_origins: &[],
            wire_refusal,
            body: &body,
        },
        // A2A carries no notification this plane observes: JSON-RPC notifications on this dialect
        // are answered `202` and nothing in the deployment moves.
        |_, _| {},
        |envelope, rpc_id, _method| async move {
            Some(
                admitted(
                    app,
                    gov,
                    principal,
                    target,
                    a2a_version,
                    envelope,
                    rpc_id,
                    relayed,
                )
                .await,
            )
        },
    )
    .await
}

/// EVERYTHING AFTER THE ENVELOPE: this plane's own vocabulary and its verb dispatch — steps 9 to
/// 12 of the measurement in `crate::ingress::protocol`.
///
/// `rpc_id` and `envelope` arrive ALREADY DECIDED by the shared reader: the id is a string or a
/// number by construction, never `null` and never a notification's absence. A second reading of
/// either here would be a second answer to a question that is already answered.
// EIGHT ARGUMENTS, and each is a fact the shared sequence established that this one needs: the
// snapshot, the caller, the target, the negotiated version, the envelope, its id and the bytes as
// they arrived. Grouping them into a struct would be a type that exists to satisfy a lint and has
// exactly one construction site; the ABI's `Wire` is where they converge when the protocols leave
// core (`design/protocol-plugin-abi.md` section 1), and inventing a different one first is churn
// that convergence deletes.
#[allow(clippy::too_many_arguments)]
async fn admitted(
    app: Arc<App>,
    gov: crate::governance::GovCtx,
    principal: crate::auth::AuthPrincipal,
    target: Target,
    a2a_version: &'static str,
    envelope: serde_json::Value,
    rpc_id: serde_json::Value,
    // THE BYTES AS THEY ARRIVED. Carried alongside the parsed envelope, never re-derived from it:
    // this plane relays a submission VERBATIM when `idmap` has nothing to rewrite, and
    // re-serialising the parsed value would change a body busbar promised to pass through.
    body: axum::body::Bytes,
) -> Response {
    // ── PHASE-1.5 HOST PLUMBING (ADDITIVE, not yet used by any capability inversion). ─────────────
    //
    // Hold the async-capable dispatch guard for the whole `admitted` future so a host handle is
    // reachable at every synchronous host admit/settle site on this plane and the per-dispatch arena
    // reclaims on any exit (return/cancel/panic). Borrows `app`, stack-pins an empty arena (no
    // per-dispatch heap); the guard is `Send`, so this future stays `Send`. The SPAWN_BLOCKING relay
    // hops need a `Send + 'static` route instead — that is the `SendHostDispatch` threaded into
    // `unary_hop`/`stream_hop` below. CLUSTER-4 admits this call's budget through `host`'s arena.
    let host = crate::plane_host::HostDispatch::new(&app);
    // Re-read rather than threaded: `wire_refusal` above already refused every request that has no
    // key, so this branch is unreachable and is a clean refusal rather than an unwrap because it
    // is on a request path.
    let Some(key) = gov.key.as_ref() else {
        return governance_required();
    };
    let now = crate::store::now();

    // ── THE ONE VERB THAT NAMES NO AGENT. ───────────────────────────────────────────────────────
    //
    // `GetExtendedAgentCard` asks busbar about ITSELF, so it is answered before the catalogue
    // selects an agent, before admission judges one, and before the meter opens a hold against one
    // — none of which has a subject on this call. Every other local verb is answered after all
    // three, because every other one names a task, and a task names an agent.
    //
    // It is not free of authorisation for being early: the route is `RouteAuth::Key`, `gov.key` was
    // required above, and the ANSWER is computed from this caller's own catalogue. A caller with no
    // grants gets a card with nothing in it.
    if matches!(
        super::local::method_of(&envelope),
        "GetExtendedAgentCard" | "agent/getAuthenticatedExtendedCard"
    ) {
        return super::route::extended_agent_card(&app, key, &rpc_id);
    }

    let shape = shape_of(&envelope);
    let agent_id = match &target {
        Named(id) => id.clone(),
        FromCatalogue => match select(&app, key, &shape) {
            Ok(id) => id,
            Err(resp) => return *resp,
        },
    };
    let context_id = envelope
        .get("params")
        .and_then(|p| p.get("message"))
        .and_then(|m| m.get("contextId"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();

    let admitted = match admit(&app, key, &agent_id, &shape, now) {
        Ok(a) => a,
        Err(resp) => return *resp,
    };
    let actor = principal.actor_id().to_string();
    let resource = format!("agent:{}", admitted.dispatch.agent_id);

    // ── THE OPERATOR'S HOOK GATE — `agents.hooks:` and `agents.<agent>.hooks:`. ─────────────────
    //
    // The twin of the MCP plane's dispatch gate, through the SAME seam
    // (`crate::hooks::gate::decide`) with the same projection and the same verdict type. Not a
    // second implementation of hooks for a second plane: a hook is a decision about one request,
    // and the only thing this arm supplies that the seam cannot work out is the pair of facts only
    // this plane knows — which agent the submission resolved to, and what its dialect is called.
    //
    // PLACED AFTER admission (the agent is what the attach is keyed on, so there is nothing to look
    // up before it) and BEFORE the meter, the egress gate, the callback guard and the task row.
    // Everything after this line either spends the caller's budget, leases busbar's own credential,
    // or mints durable state; a refusal must cost none of them.
    //
    // EVERY VERB, not only `message/send`. A gate an operator attached to an agent is a statement
    // about that agent, and a plane that fired it for submissions but not for the task verbs would
    // be a plane where the control's scope depends on which method a caller happened to use.
    if let Some(gates) = app.a2a_agent_gates.get(&admitted.dispatch.agent_id) {
        // THE A2A SUBMISSION AS THE INVOKE IR: a caller names a target and hands it arguments,
        // which is what `ir::invoke` says it carries (`it carries A2A message/send alongside MCP
        // tools/call`). The target is the METHOD and the arguments are `params` — which is where a
        // message's `parts` live, so the prose a screening gate exists to read is inside the
        // projection rather than summarised beside it.
        let facts = crate::ir::invoke::InvokeReq {
            tool: super::local::method_of(&envelope).to_string(),
            arguments: envelope
                .get("params")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
            extra: Default::default(),
        };
        let verdict = crate::hooks::gate::decide(
            gates,
            &crate::hooks::gate::GateSubject {
                facts: &facts,
                container: &admitted.dispatch.agent_id,
                ingress_protocol: crate::plane::Plane::A2a.key(),
                request_id: app.next_request_id(),
                key: Some(key.as_ref()),
                // Incremental scan: the A2A session is the `contextId` (this plane extracts no
                // `HeaderMap`, so the context IS the session), core-hashed. Gated on operator opt-in
                // AND a non-empty `contextId` — an empty one stays `None` (full re-scan), never a
                // cleared-set shared across contexts.
                incremental: (app.incremental_scan && !context_id.is_empty()).then(|| {
                    crate::hooks::gate::IncrementalScan {
                        store: &app.session_store,
                        session: crate::session::SessionKey(crate::store::fnv1a_u64(context_id)),
                        now_ms: crate::store::now_ms(),
                    }
                }),
            },
        )
        .await;
        if let crate::hooks::gate::GateVerdict::Reject {
            status,
            message,
            hook,
        } = verdict
        {
            crate::admin::audit::AUDIT.record_by(
                AUDIT_ACTION,
                &resource,
                crate::admin::audit::OUTCOME_REJECTED,
                &actor,
            );
            tracing::info!(
                agent = %admitted.dispatch.agent_id,
                hook,
                status,
                "a2a submission refused by a hook gate"
            );
            // THE HOOK'S STATUS, IN THIS PLANE'S ERROR VOCABULARY. A2A section 5.4 binds a JSON-RPC
            // code and a ProtoJSON body to every refusal, and a body in another plane's shape is a
            // body the TCK rejects by schema — so the code stays `UnsupportedOperation` (this
            // plane's binding for "busbar will not do this for you") and carries the hook's own
            // message, while the HTTP status is the gate's clamped one. Exactly what the egress
            // gate below already does with its own refusal.
            return (
                axum::http::StatusCode::from_u16(status)
                    .unwrap_or(axum::http::StatusCode::FORBIDDEN),
                axum::Json(super::rpcerror::body(
                    &rpc_id,
                    super::rpcerror::A2aError::UnsupportedOperation,
                    message,
                )),
            )
                .into_response();
        }
    }

    // 5. METER, before the work rather than after: an over-budget caller is refused instead of
    //    served and billed. The pool name is this plane's own resource spelling, so an `agent`
    //    line is distinguishable from a pool line in the same ledger. Governance MUST be present for
    //    this plane to admit/meter at all — the admission and the meter both ride the host seam below,
    //    but this plane still refuses outright when governance is absent (the LLM path admits an empty
    //    chain; a2a does not), so the guard stays even though the binding is now consumed host-side.
    let Some(_gov_state) = app.governance.as_ref() else {
        return governance_required();
    };
    // ADMIT through the host govern seam (CLUSTER-4). The grant `try_admit` yields is registered in
    // `host`'s dispatch arena and released when this future ends — return, client-cancel, or panic —
    // the EXACT lifetime the named `_hold` grant had (the guard drops at the end of `admitted`). The
    // `Facts` carry this caller's REAL `(key.id, key.group)`, so the host reconstructs the same
    // enforcement chain `try_admit(&app.cost, key, &resource)` walks; `resource` is the pool. This
    // refusal already discards `LimitBlocked`'s detail (a fixed "budget is spent" reply), so a bare
    // `Deny` is behavior-identical.
    let admitted_budget = host.with_host(|hctx, vt| {
        let facts = busbar_plugin::hot::Facts::with_attribution(
            0, // no tokens reserved: `try_admit` charges the flat per-request fee, not tokens.
            0, // budget_remaining ≥ tokens (0 ≥ 0), so the POD gate is a no-op; the chain decides.
            0,
            0,
            0,
            resource.as_bytes(),
            key.id.as_bytes(),
            key.group.as_deref().map(str::as_bytes),
        );
        (vt.govern_admit.unwrap())(hctx, &*facts as *const busbar_plugin::hot::Facts)
    });
    if admitted_budget == busbar_plugin::hot::Decision::Deny {
        crate::admin::audit::AUDIT.record_by(
            AUDIT_ACTION,
            &resource,
            crate::admin::audit::OUTCOME_REJECTED,
            &actor,
        );
        return (
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            axum::Json(super::rpcerror::body(
                &rpc_id,
                super::rpcerror::A2aError::UnsupportedOperation,
                "this key's budget is spent",
            )),
        )
            .into_response();
    }

    // ── THE VERBS BUSBAR ANSWERS ITSELF. ────────────────────────────────────────────────────────
    //
    // AFTER admission and the meter — a locally-answered call is still this caller's call against
    // this caller's budget, and answering it for free would make `ListTasks` the one unmetered verb
    // on the plane — and BEFORE the egress gate, the callback guard and the task-open block, all
    // three of which are about A HOP. None of these verbs makes one: no credential of busbar's is
    // leased, and no task row is opened, which matters most for the two that name no task busbar
    // holds (`ListTasks`, and a subscribe to an id busbar never issued). Relayed, each of those
    // minted a durable row per call for work that does not exist.
    //
    // `super::local` documents, verb by verb, why the answer is a fact about BUSBAR rather than
    // about the backend. Everything not listed there still relays, unread.
    if let Some(verb) = super::local::verb_of(super::local::method_of(&envelope)) {
        let principal = admitted.dispatch.billed_key_id.clone();
        let local = match verb {
            super::local::LocalVerb::ListTasks => {
                // ── THE POLL `super::local` SAID THIS WAS NOT. The rows stay busbar's and the
                //    answer stays busbar's, for every reason that section gives; what changes is
                //    that they are refreshed from the agent FIRST, so a task the backend moved on
                //    out of band is not invisible until somebody happens to read it. Nothing from
                //    the backend's answer is rendered — see `refresh_listed_tasks` for the scoping
                //    rule that makes a shared backend's list unable to move another tenant's row.
                super::originate::refresh_listed_tasks(
                    &app,
                    &admitted,
                    key,
                    &principal,
                    a2a_version,
                    now,
                )
                .await;
                Some(super::local::list_tasks(&envelope, &rpc_id, &principal))
            }
            super::local::LocalVerb::CreatePushConfig(dialect) => {
                let Some(seam) = plane_of(&app).map(|p| p.relay_seam()) else {
                    return plane_absent();
                };
                Some(
                    super::local::create_push_config(
                        dialect, &envelope, &rpc_id, &principal, seam, now,
                    )
                    .await,
                )
            }
            super::local::LocalVerb::GetPushConfig(dialect) => Some(super::local::get_push_config(
                dialect, &envelope, &rpc_id, &principal,
            )),
            super::local::LocalVerb::ListPushConfigs(dialect) => Some(
                super::local::list_push_configs(dialect, &envelope, &rpc_id, &principal),
            ),
            super::local::LocalVerb::DeletePushConfig(_) => Some(super::local::delete_push_config(
                &envelope, &rpc_id, &principal, now,
            )),
            // THE ONLY PARTIAL ONE. `None` means the task is live and this caller's, so the events
            // are the backend's and the call relays unchanged.
            super::local::LocalVerb::Subscribe => {
                super::local::subscribe_refusal(&envelope, &rpc_id, &principal)
            }
        };
        if let Some(response) = local {
            // ── BUSBAR'S OWN CALLBACK, MIRRORED ONTO THE BACKEND. ───────────────────────────────
            //
            // The ANSWER above stays busbar's, for every reason `super::local` gives: the
            // caller's config is a record busbar keeps, addressed by an id busbar issued, and
            // delivered by busbar. What is added here is the OTHER HALF of that argument, which was
            // missing and whose absence was a functional hole rather than a caution — a backend
            // that was never told anything never reported anything, so a task interrupted and
            // finished out of band delivered NOTHING to a caller that had registered a callback
            // precisely so it would not have to poll.
            //
            // So busbar registers ITS OWN callback, on the BACKEND's own task id, carrying a token
            // that addresses this one task. The caller's URL and the caller's credential do not
            // appear on the hop at all — see `super::pushback`, which composes it, and the scan in
            // its tests that reads every byte.
            //
            // ONLY ON A SUCCESSFUL LOCAL ANSWER. A `TaskNotFound` or a refused config named no
            // registration worth mirroring, and arming a backend for a request busbar just refused
            // would be busbar acting on a caller's behalf after telling it no.
            if response.status() == axum::http::StatusCode::OK {
                if let Some(mirrored) = super::pushback::mirrored_verb(verb) {
                    if let Some(task) = addressed_task(&envelope, &principal) {
                        super::originate::mirror_push_config(
                            &app,
                            &admitted,
                            key,
                            mirrored,
                            &task,
                            a2a_version,
                            now,
                        )
                        .await;
                    }
                }
            }
            // AUDITED LIKE ANY OTHER ADMITTED CALL, under the same action and resource spelling, so
            // a locally-answered verb is not invisible in the record just because no socket opened.
            crate::admin::audit::AUDIT.record_by(
                AUDIT_ACTION,
                &resource,
                crate::admin::audit::OUTCOME_APPLIED,
                &actor,
            );
            return response;
        }
    }

    // ── THE EGRESS GATE (`creds::authorise_egress`). ────────────────────────────────────────────
    //
    // Run BEFORE any task row exists, because it is a statement about the caller rather than about
    // the work: a caller that may not cause busbar to spend a credential on this agent must be
    // refused without a task being opened and billed for it.
    //
    // It asks the same `scope_allowed("agent", …)` question `authorize` already asked, and that is
    // deliberate rather than redundant. `authorize` answers "may this caller INVOKE this fronted
    // agent"; this answers "may busbar's OWN credential be spent on this backend on this caller's
    // behalf" — the transitive confused deputy, which only exists because busbar is both directions
    // at once. The grant it returns is the ONLY way to reach `creds::mint_from`, so a delegating
    // call site that skips it does not compile.
    let grant = match super::creds::authorise_egress(key, &admitted.dispatch.agent_id, now) {
        Ok(g) => g,
        Err(e) => {
            crate::admin::audit::AUDIT.record_by(
                AUDIT_ACTION,
                &resource,
                crate::admin::audit::OUTCOME_REJECTED,
                &actor,
            );
            return (
                axum::http::StatusCode::FORBIDDEN,
                axum::Json(super::rpcerror::body(
                    &rpc_id,
                    super::rpcerror::A2aError::UnsupportedOperation,
                    e.to_string(),
                )),
            )
                .into_response();
        }
    };

    // ── THE CALLER'S PUSH-NOTIFICATION CALLBACK, SSRF-GUARDED BEFORE IT IS STORED. ─────────────
    //
    // A caller-supplied URL that busbar's own process will fetch is the textbook SSRF primitive, so
    // it is validated against the addresses it resolves to RIGHT NOW and refused as the CALLER's
    // fault (400) rather than the backend's. Stored only after it passes; `taskstore` deliberately
    // does not validate, so this is the one place the decision is made.
    //
    // AND THE CREDENTIAL BESIDE IT, out of the SAME config object the URL came from. A config
    // naming a credential busbar cannot put on a header is refused as the CALLER's fault too,
    // rather than accepted and quietly delivered bare — a receiver told it would be authenticated,
    // whose deliveries then arrive without the header, rejects every one of them and cannot see
    // why.
    let callback_auth = match callback_config(&envelope)
        .map(super::local::delivery_auth)
        .transpose()
    {
        Ok(a) => a.flatten(),
        Err(message) => {
            return super::rpcerror::respond(
                &rpc_id,
                super::rpcerror::A2aError::InvalidParams,
                message,
            );
        }
    };
    let callback = match callback_of(&envelope) {
        None => None,
        Some(url) => {
            let Some(seam) = plane_of(&app).map(|p| p.relay_seam()) else {
                return plane_absent();
            };
            match validate_callback(url, seam).await {
                Ok(pinned) => Some(pinned),
                Err(message) => {
                    return super::rpcerror::respond(
                        &rpc_id,
                        super::rpcerror::A2aError::InvalidParams,
                        message,
                    );
                }
            }
        }
    };

    // ── RESUME, OR OPEN. ───────────────────────────────────────────────────────────────────────
    //
    // A2A is asynchronous by design and an interrupt is its NORMAL path, not an edge case. A
    // follow-up message on a `contextId` that already has an INTERRUPTED task of this caller's on
    // this agent RESUMES that task rather than opening a second one. Opening a second would give
    // the caller a new handle for work that is already half done, orphan the first row forever, and
    // bill the same piece of work twice.
    // ── A REQUEST THAT NAMES A TASK IS ABOUT THAT TASK. ───────────────────────────────────────
    //
    // `GetTask`, `CancelTask`, `SubscribeToTask` and the push-config verbs name a task in their
    // params, and that task ALREADY EXISTS. busbar opened a fresh durable row for every one of them
    // and then stamped the NEW row's id onto the answer, so a caller asking about task A was told
    // about task B - both busbar ids, for the same underlying work:
    //
    //   CORE-GET-001: GetTask returned task ID 'a2a-conformance-61d1929…',
    //                 expected 'a2a-conformance-522818d…'
    //
    // The row growth is the other half of the same mistake: a caller polling a long-running task
    // once a second minted a durable task row per poll.
    //
    // ONLY WHEN THE CALLER OWNS IT. `addressed_task` resolves through `taskstore::get_scoped`, so
    // naming somebody else's task id is not a way to read or cancel their work: it resolves to
    // nothing, the ordinary path runs, and the backend answers about an id it does not hold.
    let addressed = addressed_task(&envelope, &admitted.dispatch.billed_key_id);

    // ── THE POOL, if the caller-named agent is an `agent_pools:` member — resolved ONCE and read
    //    by everything below: the resume lookup (a task the walk routed to the twin must still be
    //    resumable through the name the caller knows), the fresh-submission walk, and the pinning
    //    of task-scoped verbs to the member that accepted the task.
    let pool = super::route::pool_of(&app, &admitted.dispatch.agent_id);

    let resumed = if addressed.is_some() || context_id.is_empty() {
        None
    } else if let Some((_, cfg)) = pool {
        // ANY member's interrupted task on this context resumes — and resumes AT that member (the
        // pinning reads the task's own `agent_id`). Most recent across members, like the
        // single-agent lookup.
        let mut c: Vec<super::task::Task> = cfg
            .members
            .iter()
            .filter_map(|m| resumable_task(&admitted.dispatch.billed_key_id, context_id, m))
            .collect();
        c.sort_by_key(|t| t.updated_at);
        c.pop()
    } else {
        resumable_task(
            &admitted.dispatch.billed_key_id,
            context_id,
            &admitted.dispatch.agent_id,
        )
    };

    let (task_id, context_id, is_resume) = match (&addressed, &resumed) {
        // Named, owned, and already open. Neither a resume nor a new row: a read is not a state
        // change, and the resume path's move to `working` would turn a poll of a completed task
        // into an attempt to resurrect it.
        (Some(t), _) => (t.task_id.clone(), t.context_id.clone(), false),
        (None, Some(t)) => (t.task_id.clone(), t.context_id.clone(), true),
        (None, None) => {
            let id = format!(
                "a2a-{}-{}",
                admitted.dispatch.agent_id,
                uuid_like(&body, now)
            );
            let ctx = if context_id.is_empty() {
                id.clone()
            } else {
                context_id.to_string()
            };
            (id, ctx, false)
        }
    };
    let request_id = task_id.clone();

    // The plane, fetched ONCE for the member selection below and every later reader (the lease,
    // the binding, the seam). The refusal is identical wherever it fires.
    let Some(plane) = plane_of(&app) else {
        return plane_absent();
    };

    // ── THE TARGET MEMBER — the failover seam, mounted at ADMISSION TIME. The three rules (a
    //    fresh submission to a pooled agent WALKS the pool; an addressed/resumed task is PINNED
    //    to the member that accepted it; an un-pooled agent keeps its degenerate cell) live in
    //    `super::route`, whose module header carries the full argument.
    let pinned_member: Option<String> = addressed
        .as_ref()
        .or(resumed.as_ref())
        .map(|t| t.agent_id.clone());
    // THE ONE HOST SCOPE THIS HOP'S ADMIT AND SETTLE SHARE (§4 a2a scope unification). Created BEFORE
    // `select_member` so the pooled WALK admit below joins the SAME `Send + 'static` arena the blocking
    // relay's settle later runs under — no longer two scopes (the async-frame `_host` for the walk and
    // a `spawn_blocking` `hop_host` for the settle) with nothing spanning both. It is moved onto the
    // blocking thread with the hop and reclaims at hop end; on an early return before the hop it drops
    // here, releasing any registered walk probe owner-checked — exactly as the bare hold used to.
    let hop_host = crate::plane_host::SendHostDispatch::new(std::sync::Arc::clone(&app));
    let selected_member = super::route::select_member(
        &app,
        &plane,
        key,
        credential_kind_of(&app),
        &admitted.dispatch.agent_id,
        admitted.generation,
        pinned_member.as_deref(),
        super::local::method_of(&envelope),
        now,
    );
    let target_agent = selected_member.agent_id;
    let hop_breaker = selected_member.breaker;
    let walk_refusal = selected_member.walk_refusal;
    let pin_mismatch = selected_member.pin_mismatch;
    // THE WALK'S PROBE HOLD JOINS THE SHARED SCOPE. A pooled fresh submission whose member the walk
    // already admitted rides its probe here as a SETTLE-CAPABLE admission, so the hop's settle and its
    // record share one arena and the same host `AdmissionId`. The recorded outcome consumes it and the
    // scope-drop release is then a no-op; an abandoned hop hands it back when `hop_host` drops. NONE
    // when the walk won nothing (un-pooled/pinned hops admit later, inside `prepare`). PREP: registered
    // settle-capable but not yet settled through the host.
    let walk_admission_id = match selected_member.admission {
        Some(admission) => {
            let settling = crate::plane_host::breaker::settling_admission(
                std::sync::Arc::clone(&hop_breaker.breakers),
                hop_breaker.key.clone(),
                hop_breaker.lane,
                admission,
            );
            hop_host.scope().register_settling_admission(settling)
        }
        None => busbar_plugin::hot::AdmissionId::NONE,
    };

    // ── VERIFY-ON-CALL. Re-verify the agent this hop will actually delegate to, within `verify_ttl`,
    //    single-flight, fail-closed — BEFORE the relay preamble's live `still_delegable` gate compares
    //    it. A moved fingerprint or an unreachable card demotes the registration here, and the gate
    //    then refuses; there is no background sweep. See `verify_agent_on_call`.
    verify_agent_on_call(&app, &plane, &target_agent).await;
    // The re-verification mutates the registry and so bumps its generation; the hop's admitted
    // generation is re-read AFTER it so the pre-socket gate does not refuse the call for busbar's OWN
    // re-verification — while still catching a config apply that lands between here and the socket, and
    // while `still_delegable` re-validates the live (re-verified) registration's trust state regardless.
    let hop_generation = plane.generation();

    // WHO IS BILLED, recorded as this plane's own statement rather than inferred later. Receiving
    // covers the downstream L2 spend this call causes and never the callee's internal spend — a
    // distinction `Attribution` makes unconstructible rather than documented.
    let attribution = super::meter::Attribution::receiving(
        &admitted.dispatch.billed_key_id,
        &admitted.dispatch.agent_id,
        &context_id,
        &task_id,
    );

    // THE HOP'S OWN ATTRIBUTION, and it is a different statement from the one above. busbar meters
    // THE HOP IT MADE — who delegated, to which registered agent, under which `contextId`, with
    // what terminal state — and NOT the callee's internal tool and model spend, which never touches
    // busbar's plane. `covers_callee_internal_spend` is `false` here and on the receiving arm, with
    // no constructor anywhere that can set it true, so "the hop, not the black box behind it" is a
    // property of the type rather than a sentence somebody has to remember.
    let hop = super::meter::Attribution::delegating(
        &admitted.dispatch.billed_key_id,
        &agent_id,
        // The member the hop ACTUALLY reaches — the walked twin on a rerouted fresh submission,
        // the pinned member on a task-scoped verb. This is also what `record_dispatch` stamps on
        // the task row, which is the pinning's whole mechanism.
        &target_agent,
        &context_id,
        &task_id,
    );

    if is_resume {
        // BACK TO `working`, which chains a `task.resumed` provenance event. The transition table
        // refuses this from a terminal state, so a caller cannot resurrect finished work by
        // re-using its `contextId`.
        if let Err(e) = host.with_host(|h, _| {
            taskstore::TASKS.transition(
                h,
                &task_id,
                super::task::TaskState::Working,
                now,
                &request_id,
            )
        }) {
            diag_warn!(A2A_INTERRUPTED_TASK_UNRESUMED, task = %task_id, error = %e, "a2a: an interrupted task could not be resumed");
            return (
                axum::http::StatusCode::CONFLICT,
                axum::Json(super::rpcerror::body(
                    &rpc_id,
                    super::rpcerror::A2aError::TaskNotCancelable,
                    "this task cannot be resumed",
                )),
            )
                .into_response();
        }
    } else if addressed.is_none() {
        // 4. DISPATCH, recorded durably. The task and its provenance chain are opened BEFORE the
        //    outcome is known, which is the point: a task that ends by the process dying still has a
        //    row saying it was submitted and to whom it was dispatched.
        let task = match super::task::Task::submitted(
            &task_id,
            &context_id,
            &attribution.billed_key_id,
            super::task::Direction::Inbound,
            now,
        ) {
            Ok(t) => t,
            Err(e) => {
                // Error-once latch: a store that cannot open an inbound task is a STABLE condition
                // (a store outage persists across every inbound submission), and this path runs per
                // request. Error on the TRANSITION into the failing state; hold subsequent failures
                // at debug so a store outage cannot spam the log.
                static INBOUND_TASK_UNOPENED_WARNED: std::sync::atomic::AtomicBool =
                    std::sync::atomic::AtomicBool::new(false);
                if !INBOUND_TASK_UNOPENED_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    diag_error!(A2A_INBOUND_TASK_UNOPENED, error = ?e, "a2a: could not open an inbound task");
                } else {
                    diag_debug!(A2A_INBOUND_TASK_UNOPENED, error = ?e, "a2a: could not open an inbound task");
                }
                return plane_absent();
            }
        };
        if let Err(e) = host.with_host(|h, _| taskstore::TASKS.submit(h, &task, &request_id)) {
            // Error-once latch: a store that refuses the submit is a STABLE condition (a store
            // outage persists across every inbound submission), and this path runs per request.
            // Error on the TRANSITION into the failing state; hold subsequent failures at debug so
            // a store outage cannot spam the log.
            static INBOUND_TASK_UNRECORDED_WARNED: std::sync::atomic::AtomicBool =
                std::sync::atomic::AtomicBool::new(false);
            if !INBOUND_TASK_UNRECORDED_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                diag_error!(A2A_INBOUND_TASK_UNRECORDED, error = %e, "a2a: the inbound task could not be recorded");
            } else {
                diag_debug!(A2A_INBOUND_TASK_UNRECORDED, error = %e, "a2a: the inbound task could not be recorded");
            }
            return (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                axum::Json(super::rpcerror::body(
                    &rpc_id,
                    super::rpcerror::A2aError::Internal,
                    "the task could not be recorded",
                )),
            )
                .into_response();
        }
        // THE PER-TASK HASH-CHAIN EVENT FOR THE HOP: who delegated, to which registered agent,
        // recorded BEFORE the socket rather than after it, so a hop that never returns still left a
        // chained record saying it was made.
        let _ = host.with_host(|h, _| {
            taskstore::TASKS.record_dispatch(
                h,
                &task_id,
                hop.target_agent_id.as_deref().unwrap_or(&agent_id),
                now,
                &request_id,
            )
        });
    }

    if let Some(pinned) = callback.as_ref() {
        let _ = taskstore::TASKS.set_push_callback(&task_id, Some(pinned.url.clone()), now);
        // THE ADDRESSES THE GUARD JUST JUDGED, kept so the FIRST delivery is a `revalidate` — the
        // fresh answer must pass the guard AND still overlap this set — rather than a bare
        // `validate`. Process-local: see `pushdeliver::pins` for why it is not, and must not be
        // read as, a durable pin.
        super::pushdeliver::remember(&task_id, pinned);
        // AND THE CREDENTIAL THE CALLER ASKED BUSBAR TO PRESENT AT THAT URL. Registered here as
        // well as on the CRUD verb for the reason the guard is: a config supplied INLINE on a
        // submission and one registered by `CreateTaskPushNotificationConfig` are the same fact
        // reached by two spellings, and honouring the credential on only one of them would make
        // whether a receiver is authenticated depend on which method the caller happened to use.
        super::pushdeliver::remember_auth(&task_id, callback_auth.as_ref());
    }

    // METER through the host meter_charge seam (CLUSTER-4). A pure request meter with no token split
    // (component `Queries` → `None`), so the recorded (key_id, model, provider) row is byte-identical
    // to the in-place `record_metering(&hop.billed_key_id, &resource, Plane::A2a.key(), None, ..)`:
    // the attribution tail carries those exact three words, and the amount-0 charge validates an empty
    // breakdown and always accrues one request. Fire-and-forget, exactly as the direct call was.
    let _ = host.with_host(|hctx, vt| {
        let usage = busbar_plugin::hot::Usage::with_attribution(
            busbar_plugin::hot::UsageComponent::Queries,
            0,
            0,
            busbar_plugin::hot::AdmissionId::NONE,
            hop.billed_key_id.as_bytes(),
            resource.as_bytes(),
            crate::plane::Plane::A2a.key().as_bytes(),
        );
        (vt.meter_charge.unwrap())(hctx, &*usage as *const busbar_plugin::hot::Usage)
    });

    // 6. AUDIT. One record per admitted call, under this plane's own action and resource spelling.
    crate::admin::audit::AUDIT.record_by(
        AUDIT_ACTION,
        &resource,
        crate::admin::audit::OUTCOME_APPLIED,
        &actor,
    );

    // 7. RELAY. Everything above this line DECIDED; this is the line that reaches the backend.
    //
    // The caller's request headers are NOT read here and are not in scope: the handler does not
    // extract a `HeaderMap` at all, so there is nothing on this path to accidentally forward. The
    // first draft did extract one, and the credential the caller authenticated with went straight
    // out on the hop — masked, in the configured-credential case, by the leased header overwriting
    // it, which is why the no-credential twin exists in `tests/relay_tests.rs`.
    //
    // Milliseconds, because a lease is minted and checked in milliseconds while `crate::store::now`
    // counts seconds. Converted once, here, rather than at each of the call sites that would
    // otherwise each have to remember.
    let now_ms = now.saturating_mul(1_000);
    let seam = plane.relay_seam();
    let gate: Arc<dyn super::relay::DelegationGate> =
        Arc::new(super::plane::LiveGate(Arc::clone(&plane)));

    // THE TARGET MEMBER'S OWN FACTS — its backend URL, its credential handle, and the egress
    // grant re-derived FOR THAT MEMBER when the hop was re-targeted; see `route::hop_facts` for
    // why busbar's credential is never leased for a backend the caller's grant does not cover.
    let (target_backend_url, target_cred, grant) = match super::route::hop_facts(
        &plane,
        key,
        &admitted,
        &target_agent,
        grant,
        &rpc_id,
        &resource,
        &actor,
        now,
    ) {
        Ok(f) => f,
        Err(refusal) => {
            return refusal.map(|resp| *resp).unwrap_or_else(|| {
                fail_task(&app, &seam, &rpc_id, &task_id, &request_id, now, 502)
            })
        }
    };

    // BUSBAR'S OWN CREDENTIAL FOR THIS BACKEND, or none — and it can only be minted against the
    // grant obtained above. A configured credential that will not resolve is a REFUSAL and not a
    // quiet unauthenticated hop: an operator who configured one meant the backend to see one.
    let lease = match target_cred.as_ref() {
        Some(cred) => match super::creds::mint_from(&grant, cred, &app.secret_resolver, now_ms) {
            Ok(lease) => Some(lease),
            Err(e) => {
                diag_warn!(A2A_OUTBOUND_CRED_UNLEASED, agent = %target_agent, error = %e, "a2a: the outbound credential could not be leased");
                return fail_task(&app, &seam, &rpc_id, &task_id, &request_id, now, 502);
            }
        },
        None => None,
    };

    // ── WHICH BINDING THIS BACKEND SPEAKS. Read off the card busbar already fetched, verified and
    //    pinned for this registration — never off the request, and never off a URL the card
    //    supplied. See `relay`'s `THE OUTBOUND BINDING` note: the card says HOW, the operator's
    //    `url:` says WHERE.
    let binding = super::relay::binding_of(
        plane
            .with_registrations(|regs| {
                regs.iter()
                    .find(|r| r.agent_id == target_agent)
                    .and_then(|r| r.cached_card.clone())
            })
            .as_ref(),
    );
    let Some(framing) = super::relay::framing_for(&binding) else {
        // REFUSED BY NAME, and refused HERE rather than relayed as JSON-RPC anyway. A backend that
        // publishes only a binding this build cannot speak is unreachable, and saying so names the
        // word an operator has to act on; sending it an envelope it never offered to read would
        // produce a `400` from the backend and an operator hunting the wrong end of the hop.
        diag_warn!(
            A2A_AGENT_BINDING_UNSPEAKABLE,
            agent = %admitted.dispatch.agent_id,
            binding = %binding,
            "a2a: the registered agent's card declares no binding busbar can speak"
        );
        return refuse_hop_early(
            &rpc_id,
            &super::relay::RelayRefusal::Unframable {
                binding: "unknown",
                method: super::local::method_of(&envelope).to_string(),
                reason: format!(
                    "the agent's card declares `{binding}`, which is not one of A2A's three \
                     bindings this build speaks"
                ),
            },
        );
    };

    let hop_ctx = HopContext {
        app: Arc::clone(&app),
        seam: Arc::clone(&seam),
        framing,
        agent_id: target_agent.clone(),
        addressed: addressed.is_some(),
        backend_url: target_backend_url,
        // THE ONE READING OF THE OPERATOR'S `allow_private:` LINE, obtained where every other
        // caller obtains it. Reaching for `seam.policy()` inside the relay instead is the defect
        // `relay::RelayCall::policy` documents.
        policy: plane.fetch_policy_for(&target_agent),
        task_id: task_id.clone(),
        context_id: context_id.clone(),
        matched_skill: admitted.matched_skill.clone(),
        admitted_generation: hop_generation,
        request_id,
        a2a_version,
        breaker: hop_breaker,
        walk_admission_id,
        now,
        now_ms,
        // Established by the envelope reader at the top of this handler, where `null` and absent
        // were still distinguishable. It is a string or a number, never `null`.
        rpc_id,
    };

    // ── THE WALK'S REFUSAL, fired AFTER the task row exists so the caller keeps an id to poll —
    //    through the exact rendering the degenerate breaker refusal decided (`rejected` + 503 +
    //    Retry-After naming the POOL, because the pool is the unit with nothing left).
    if let Some(refusal) = walk_refusal {
        return refuse_hop(&hop_ctx, &refusal);
    }
    if let Some(reason) = pin_mismatch {
        return super::route::render_pin_mismatch(
            &hop_ctx.app,
            &hop_ctx.seam,
            &hop_ctx.rpc_id,
            &hop_ctx.task_id,
            &hop_ctx.request_id,
            hop_ctx.addressed,
            hop_ctx.now,
            reason,
        );
    }

    // THE INVERSE OF THE IDENTITY SUBSTITUTION. busbar issues its own task ids and puts them in
    // every answer; a caller reading one and asking `GetTask` for it had that id forwarded, unchanged,
    // to a backend that has never heard of it. See `super::idmap`: this is the only direction that
    // was missing, and `None` - a request naming no task busbar issued - forwards the caller's OWN
    // BYTES rather than a re-serialization, so nothing else in the envelope is normalised.
    //
    // SCOPED TO THIS CALLER, and that is what makes the `addressed_task` note above TRUE rather than
    // merely intended. `addressed_task` refuses to resolve another principal's id, but the relayed
    // BODY is composed here, and it used to be composed from the same id with no principal in scope
    // — so a second key naming the first key's task had that id translated to the backend's, the
    // backend answered about it, and the answer came back wearing busbar's id. `GetTask` and
    // `CancelTask` crossed the boundary `ListTasks` held. Now an id this caller does not own is left
    // exactly as an id that never existed is left, and the two answers are the same answer.
    let relayed_body = super::idmap::translate_request(&envelope, &admitted.dispatch.billed_key_id)
        .unwrap_or_else(|| body.to_vec());

    // `hop_host` (the ONE shared host scope, created before `select_member` and now holding the walk's
    // probe) is MOVED onto the blocking relay thread with the hop: its arena reclaims when the hop's
    // closure ends — AFTER the outcome was recorded, so the walk probe's release is a no-op — and the
    // un-pooled `prepare` admit re-homes its own probe into the SAME scope. One scope spans both.
    if shape.requires_streaming {
        stream_hop(hop_ctx, seam, gate, lease, relayed_body, hop_host).await
    } else {
        unary_hop(hop_ctx, seam, gate, lease, relayed_body, hop_host).await
    }
}

/// Everything one hop needs that is neither a seam nor a secret. One struct because the two hop
/// shapes need the same eleven facts and an eleven-argument function is a function whose arguments
/// get transposed.
struct HopContext {
    /// THE LIVE ENGINE SNAPSHOT the hop was admitted on, carried so the POST-hop and DETACHED task
    /// writes — `record_state`, `refuse_hop`, `end_task`, the stream watcher, `notify_push` — can each
    /// open a fresh `Send + 'static` host route (`SendHostDispatch`) to reach the durable `task_event`
    /// seam. The per-hop `SendHostDispatch` is consumed by the `spawn_blocking` relay closure, so the
    /// writes that run AFTER the hop cannot borrow it; they clone this `Arc<App>` and open their own.
    app: Arc<App>,
    /// THE PLANE'S OUTBOUND SEAM, carried so the code that records a task's outcome can also
    /// DELIVER it. A push notification is the same fact as the state transition and belongs at the
    /// same instant; reaching for the plane again from `record_state` would be reading the world
    /// twice to learn one thing.
    seam: Arc<dyn super::relay::RelaySeam>,
    agent_id: String,
    backend_url: String,
    /// THE GUARD POLICY FOR THIS REGISTRATION, narrowed by its `allow_private:` exactly as the card
    /// fetch, `connect`, `approve` and the sweep narrow theirs. See `relay::RelayCall::policy`.
    policy: super::fetch::FetchPolicy,
    task_id: String,
    context_id: String,
    matched_skill: Option<String>,
    request_id: String,
    /// THE `A2A-Version` THIS HOP DECLARES, negotiated at busbar's own edge from the caller's
    /// header. See `Wire::negotiated_version`.
    a2a_version: &'static str,
    /// THE TASK ALREADY EXISTED AND THE CALLER NAMED IT. A failing hop must not then END it: a
    /// `GetTask` that the backend refuses is a failed READ, and burning the caller's live task row
    /// for it would destroy work that is still running.
    addressed: bool,
    /// THE REGISTRY GENERATION ADMISSION DECIDED UNDER, carried to the pre-socket gate. See
    /// `relay::RelayCall::admitted_generation`.
    admitted_generation: u64,
    /// WHICH OF A2A'S THREE BINDINGS THE BACKEND SPEAKS, as the framing that composes the hop.
    ///
    /// Resolved ONCE, off the registration's own cached card, and carried rather than looked
    /// up again in each hop: the two hops must not be able to reach different answers about which
    /// binding one request goes out on. `&'static` because the three framings are stateless
    /// vtables, so carrying one costs a pointer and there is nothing to build.
    framing: &'static dyn super::relay::OutboundFraming,
    /// The breaker cell this hop admits against and records into — plane-qualified key + pool
    /// lane, resolved by the member selection (`super::route`) and cloned into each hop's
    /// `RelayCall`.
    breaker: super::relay::RelayBreaker,
    /// THE SHARED-SCOPE HOST ADMISSION ID FOR A PRE-ADMITTED (pooled WALK) HOP — the id the walk's
    /// probe hold was registered under in the one `hop_host` scope before the hop was built, threaded
    /// onto the blocking relay's `RelayCall`. `AdmissionId::NONE` for an un-pooled/pinned hop (whose
    /// probe `prepare` admits and re-homes itself into the shared host scope).
    walk_admission_id: busbar_plugin::hot::AdmissionId,
    now: u64,
    now_ms: u64,
    rpc_id: serde_json::Value,
}

/// The plane, if this deployment has one.
pub(super) fn plane_of(app: &App) -> Option<Arc<super::plane::A2aPlane>> {
    crate::a2a::runtime_arc(app)
}

/// VERIFY-ON-CALL for one A2A delegation: re-verify `agent_id`'s card within `verify_ttl`,
/// single-flight, fail-closed, BEFORE the relay's live trust gate compares it.
///
/// The single-flight, the freshness bound and the fail-closed ordering are [`crate::trust::verify`]'s,
/// once, for every plane; this plane's FETCH is [`super::plane::A2aPlane::reverify_agent`] — the
/// signed-card read and verification against the operator's out-of-band root, on a blocking thread. A
/// failed re-verification records `Error`, which the relay preamble's `still_delegable` gate then
/// refuses. Skipped only when the boot transports are absent (a test app, or a deployment that fronts
/// nothing to delegate with), in which case the recorded sighting governs exactly as it did before
/// verify-on-call — production always publishes the transports at boot.
/// FOLD the blocking reverify's join result into the pass to act on, FAIL-CLOSED on a panic.
///
/// `Ok` returns the pass for the caller to report on. `Err` is a `JoinError` — a PANIC in the blocking
/// reverify, which is a FAILED contact, never a silent pass. Dropping it (the old `.ok().flatten()`)
/// left `pass = None`, no diagnostic, and the single-flight epoch STILL advancing: the subject looked
/// "checked" and the next delegation proceeded against unchanged trust state — a fail-OPEN. So this
/// reports the subject UNREACHABLE (latching the outage diagnostic), then RE-RAISES, matching the
/// fetch closure's own contract that a panic "surfaces": the fetch does not complete, the epoch does
/// not advance, and the in-flight hop refuses rather than dispatching against a snapshot no
/// re-verification ever confirmed.
fn fold_reverify_join(
    joined: Result<Option<super::verify::Pass>, tokio::task::JoinError>,
    gate: &crate::trust::verify::VerifyGate,
    subject: &str,
) -> Option<super::verify::Pass> {
    match joined {
        Ok(pass) => pass,
        Err(join_err) => {
            gate.report(crate::plane::Plane::A2a, subject, false, true);
            std::panic::resume_unwind(join_err.into_panic());
        }
    }
}

async fn verify_agent_on_call(app: &Arc<App>, plane: &Arc<super::plane::A2aPlane>, agent_id: &str) {
    // Downcast the opaque handle back to this plane's transport bundle — `App` carries it type-erased.
    let Some(cards) = app
        .a2a_cards
        .get()
        .cloned()
        .and_then(|c| c.downcast::<super::transport::LiveCardFetch>().ok())
    else {
        return;
    };
    let Some((_, policy)) = plane.verify_state_of(agent_id) else {
        return;
    };
    let now_ms = crate::store::now_ms();
    let ledger_plane = Arc::clone(plane);
    let ledger_id = agent_id.to_string();
    let fetch_plane = Arc::clone(plane);
    let fetch_id = agent_id.to_string();
    let report_id = agent_id.to_string();
    let gate = Arc::clone(&app.a2a_verify);
    app.a2a_verify
        .ensure_fresh(
            agent_id,
            &policy,
            now_ms,
            || {
                ledger_plane
                    .verify_state_of(&ledger_id)
                    .map(|(l, _)| l)
                    .unwrap_or_default()
            },
            || async move {
                // OFF THE REACTOR: a card fetch is a blocking socket read behind the SSRF guard.
                let joined = tokio::task::spawn_blocking(move || {
                    fetch_plane.reverify_agent(&fetch_id, cards.resolver(), &*cards, now_ms)
                })
                .await;
                let pass = fold_reverify_join(joined, &gate, &report_id);
                if let Some(pass) = pass {
                    let unreachable = pass.refusal.is_some();
                    let drifted = pass.settled.as_ref().is_some_and(|s| s.drift_observed);
                    gate.report(crate::plane::Plane::A2a, &report_id, drifted, unreachable);
                }
            },
        )
        .await;
}

/// THE UNARY HOP: one submission, one answer.
///
/// ON A BLOCKING THREAD. The relay seam is synchronous — it is the card fetch's transport, and that
/// transport blocks a thread per hop by design. Calling it inline here would block an axum worker
/// for the whole of a backend agent's think time, which on this plane is the one call that can
/// legitimately take a minute.
async fn unary_hop(
    ctx: HopContext,
    seam: Arc<dyn super::relay::RelaySeam>,
    gate: Arc<dyn super::relay::DelegationGate>,
    lease: Option<super::creds::Lease>,
    body: Vec<u8>,
    // The `Send + 'static` host route for the blocking relay call (an ADDITIVE, currently-unused route). Moved
    // into the `spawn_blocking` closure below so the breaker admit/settle inside `relay` can reach a
    // host handle without carrying the `!Send` `HostCtx` across the task boundary. CLUSTER-1 flips
    // `relay`'s in-place breaker calls onto it; until then it is held-in-the-closure-but-unused.
    host: crate::plane_host::SendHostDispatch,
) -> Response {
    let agent_id = ctx.agent_id.clone();
    let backend_url = ctx.backend_url.clone();
    let relay_policy = ctx.policy.clone();
    let admitted_generation = ctx.admitted_generation;
    let framing = ctx.framing;
    let now_ms = ctx.now_ms;
    // The id the hop's answer must name. `body` goes out verbatim, so the id busbar sends to the
    // backend IS this one — see `RelayCall::rpc_id`.
    let rpc_id = ctx.rpc_id.clone();
    let a2a_version = ctx.a2a_version;
    let breaker = ctx.breaker.clone();
    // The pre-admitted WALK id (if this is a pooled fresh submission); its probe already rides in
    // `host`'s shared scope. NONE for an un-pooled/pinned hop, whose probe `prepare` re-homes itself.
    let walk_admission_id = ctx.walk_admission_id;
    let relayed = tokio::task::spawn_blocking(move || {
        // The ONE shared host scope rides onto the blocking thread; its arena reclaims when this
        // closure ends (reclaim at HOP end, after the outcome was recorded). Both the walk admit
        // (already registered) and `prepare`'s un-pooled admit settle by a host AdmissionId here.
        let hop_host = host;
        super::relay::relay(
            &super::relay::RelayCall {
                agent_id: &agent_id,
                backend_url: &backend_url,
                lease: lease.as_ref(),
                gate: gate.as_ref(),
                admitted_generation,
                body: &body,
                rpc_id: &rpc_id,
                policy: &relay_policy,
                a2a_version,
                framing,
                breakers: Some(breaker),
                host_scope: Some(hop_host.scope()),
                admission: walk_admission_id,
            },
            seam.as_ref(),
            now_ms,
        )
    })
    .await;

    let reply = match relayed {
        Ok(Ok(reply)) => reply,
        Ok(Err(refusal)) => return refuse_hop(&ctx, &refusal),
        Err(join) => {
            diag_error!(A2A_RELAY_THREAD_INCOMPLETE, task = %ctx.task_id, error = %join, "a2a: the relay thread did not complete");
            return fail_task(
                &ctx.app,
                &ctx.seam,
                &ctx.rpc_id,
                &ctx.task_id,
                &ctx.request_id,
                ctx.now,
                502,
            );
        }
    };

    record_state(&ctx, reply.reported_state);
    // WHAT THE BACKEND CALLS THIS TASK, remembered BEFORE the substitution erases it, so the
    // caller's later reads of the id busbar is about to hand them can be translated back.
    if let Some(backend_id) = reply.backend_task_id.as_deref() {
        super::idmap::remember(&ctx.task_id, backend_id);
    }

    // THE REPLY, UNDER BUSBAR'S IDENTITY. The backend's `id`/`contextId` are ITS names for this
    // work; the caller's later reads resolve against busbar's store. Everything else is passed
    // through untouched, because busbar is content-blind on this plane.
    let mut result = reply.result;
    super::relay::rewrite_identity(
        &mut result,
        &ctx.task_id,
        &ctx.context_id,
        ctx.matched_skill.as_deref(),
    );
    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": ctx.rpc_id,
            "result": result,
        })),
    )
        .into_response()
}

/// THE STREAMING HOP: the backend's events, re-framed under busbar's identity, written to
/// the caller as they arrive.
///
/// The head decision cannot be deferred. Once a byte has been written to the caller the response
/// status is spent, so this waits for the FIRST event before committing to a `200 text/event-stream`
/// — and every failure that can happen before that first event (the guard, the gate, the lease, a
/// non-2xx, a backend that answered a document rather than a stream) is still a status this handler
/// gets to choose.
async fn stream_hop(
    ctx: HopContext,
    seam: Arc<dyn super::relay::RelaySeam>,
    gate: Arc<dyn super::relay::DelegationGate>,
    lease: Option<super::creds::Lease>,
    body: Vec<u8>,
    // The `Send + 'static` host route for the blocking relay call (an ADDITIVE, currently-unused route). See
    // `unary_hop`; the streaming hop's `relay` runs on the same `spawn_blocking` thread and takes the
    // same route so its breaker admit/settle can reach a host handle. Held-in-the-closure-but-unused.
    host: crate::plane_host::SendHostDispatch,
) -> Response {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);

    let task_id = ctx.task_id.clone();
    let context_id = ctx.context_id.clone();
    let matched_skill = ctx.matched_skill.clone();
    let request_id = ctx.request_id.clone();
    let agent_id = ctx.agent_id.clone();
    let backend_url = ctx.backend_url.clone();
    let relay_policy = ctx.policy.clone();
    let admitted_generation = ctx.admitted_generation;
    let framing = ctx.framing;
    let now = ctx.now;
    let now_ms = ctx.now_ms;
    // The same id the unary path answers under, and now the same id every STREAMED event is
    // correlated against and answered under. That the two paths use one value is the fix: the
    // streamed path used to let the backend supply it.
    let rpc_id = ctx.rpc_id.clone();
    // A SECOND HANDLE ON THE SEAM for the sink below. The stream's state changes are the caller's
    // push notifications, and a sink that could not reach the seam would deliver on the unary path
    // and silently not on the streaming one — a difference no test that stops at the transport can
    // see.
    let notify_seam = Arc::clone(&seam);
    let a2a_version = ctx.a2a_version;
    let breaker = ctx.breaker.clone();
    // The pre-admitted WALK id (if pooled); its probe already rides in `host`'s shared scope.
    let walk_admission_id = ctx.walk_admission_id;

    // THE CURSOR RESUMES WHERE THE TASK LEFT OFF rather than at zero. On a resumed stream, starting
    // at zero would spend the first N advances re-asserting a position the store already holds —
    // harmless, because the store refuses to rewind, but it would make the cursor stop counting
    // this stream's chunks and start counting from scratch, which is the number a resubscribe reads.
    let mut cursor: u64 = taskstore::TASKS
        .get_unscoped(&ctx.task_id)
        .map_or(0, |t| t.artifact_cursor);
    let handle = tokio::task::spawn_blocking(move || {
        // The ONE shared host scope rides onto the blocking thread; its arena reclaims when this
        // closure ends (reclaim at HOP end, after the outcome was recorded). Both the walk admit and
        // `prepare`'s un-pooled admit settle by a host AdmissionId here.
        let hop_host = host;
        let mut sink = |ev: super::relay::RelayEvent| -> super::relay::ChunkFlow {
            // THE PAIRING, off the stream too. A streaming submission is the one case where the
            // caller is MOST likely to follow up by id - a resubscribe, a cancel - and a mapping
            // recorded only on the unary path would leave exactly that case broken.
            if let Some(backend_id) = ev.backend_task_id.as_deref() {
                super::idmap::remember(&task_id, backend_id);
            }
            // THE TASK'S STATE MOVES AS THE STREAM MOVES, not once at the end. A stream that ends
            // by the process dying must leave the last state it actually reported, not `submitted`.
            if let Some(state) = ev.state {
                // ALREADY ON A BLOCKING THREAD, so the delivery is made inline rather than spawned:
                // this closure IS the `spawn_blocking` the unary path has to create. Delivering in
                // order also means the receiver sees the states in the order they happened.
                if let Ok(task) = hop_host.with_host(|h, _| {
                    taskstore::TASKS.transition(h, &task_id, state, now, &request_id)
                }) {
                    if task.push_callback.is_some() {
                        if let Err(e) = hop_host.with_host(|h, _| {
                            super::pushdeliver::deliver(h, notify_seam.as_ref(), &task)
                        }) {
                            diag_debug!(A2A_PUSH_NOTIFY_UNDELIVERED, task = %task.task_id, error = %e, "a2a: the push notification was not delivered");
                        }
                    }
                }
            }
            if ev.artifact {
                cursor = cursor.saturating_add(1);
                // The resubscribe resume point, advanced durably per chunk. Monotonic in the store,
                // so a duplicate delivery cannot rewind it.
                let _ = hop_host.with_host(|h, _| {
                    taskstore::TASKS.advance_cursor(h, &task_id, cursor, now, &request_id)
                });
            }
            // A caller that has gone away closes the receiver, and the hop stops there rather than
            // draining an upstream into a channel nobody is reading.
            //
            // NOT `blocking_send`, AND THAT IS THE WHOLE OF A DEFECT THAT MADE EVERY STREAMING
            // REQUEST FAIL. This closure looks like it runs on a plain blocking thread — it is
            // created inside `spawn_blocking` — but it is CALLED from inside
            // `transport::on_a_dedicated_runtime`, i.e. from within a current-thread
            // `Runtime::block_on` that is driving the backend's response body. tokio refuses to
            // block a thread that is driving a runtime, so `blocking_send` panicked on the FIRST
            // event of EVERY stream and the caller got
            // `502 … a2a task stream relay: the worker thread panicked`.
            //
            // `futures::executor::block_on` waits on the same future without tokio's guard. It
            // still blocks this thread, which is correct and is the point: BACKPRESSURE IS KEPT.
            // The channel stays bounded, so a caller that reads slowly slows the upstream read
            // rather than growing an unbounded queue in busbar — which is what switching to an
            // unbounded channel would have traded away to make the panic go away. There is no
            // deadlock: what this thread waits for is the CONSUMER, which is an axum task on a
            // different runtime and is not waiting on anything here.
            if futures::executor::block_on(tx.send(ev.sse)).is_err() {
                return super::relay::ChunkFlow::Stop;
            }
            super::relay::ChunkFlow::Continue
        };
        super::relay::relay_stream(
            &super::relay::RelayCall {
                agent_id: &agent_id,
                backend_url: &backend_url,
                lease: lease.as_ref(),
                gate: gate.as_ref(),
                admitted_generation,
                body: &body,
                rpc_id: &rpc_id,
                policy: &relay_policy,
                a2a_version,
                framing,
                breakers: Some(breaker),
                host_scope: Some(hop_host.scope()),
                admission: walk_admission_id,
            },
            seam.as_ref(),
            &task_id,
            &context_id,
            matched_skill.as_deref(),
            now_ms,
            &mut sink,
        )
    });

    // THE FIRST EVENT IS THE COMMITMENT. Nothing before it has been written to the caller, so a
    // refusal is still expressible; after it, the answer is a stream and a failure can only be a
    // truncated one plus a log line and a `failed` task.
    let Some(first) = rx.recv().await else {
        return match handle.await {
            Ok(Ok(super::relay::RelayStream::Unary(reply))) => {
                // The backend answered a single document to a streaming request, which is legal for
                // a task it finished immediately. The caller gets the unary shape rather than a
                // one-event stream busbar invented.
                record_state(&ctx, reply.reported_state);
                if let Some(backend_id) = reply.backend_task_id.as_deref() {
                    super::idmap::remember(&ctx.task_id, backend_id);
                }
                let mut result = reply.result;
                super::relay::rewrite_identity(
                    &mut result,
                    &ctx.task_id,
                    &ctx.context_id,
                    ctx.matched_skill.as_deref(),
                );
                (
                    axum::http::StatusCode::OK,
                    axum::Json(serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": ctx.rpc_id,
                        "result": result,
                    })),
                )
                    .into_response()
            }
            // A stream that produced no event at all is not a served task. Reported as a hop
            // failure rather than as an empty 200, which would tell the caller the work was done.
            Ok(Ok(super::relay::RelayStream::Streamed)) => {
                diag_debug!(A2A_STREAM_EMPTY, task = %ctx.task_id, "a2a: the backend's stream carried no event");
                fail_task(
                    &ctx.app,
                    &ctx.seam,
                    &ctx.rpc_id,
                    &ctx.task_id,
                    &ctx.request_id,
                    ctx.now,
                    502,
                )
            }
            Ok(Err(refusal)) => refuse_hop(&ctx, &refusal),
            Err(join) => {
                diag_error!(A2A_RELAY_THREAD_INCOMPLETE, task = %ctx.task_id, error = %join, "a2a: the relay thread did not complete");
                fail_task(
                    &ctx.app,
                    &ctx.seam,
                    &ctx.rpc_id,
                    &ctx.task_id,
                    &ctx.request_id,
                    ctx.now,
                    502,
                )
            }
        };
    };

    // COMMITTED. What is left of the hop is watched on a detached task purely so its outcome is
    // LOGGED and a broken stream ends the task rather than leaving it live forever.
    let watched_task = ctx.task_id.clone();
    let watched_request = ctx.request_id.clone();
    let watched_now = ctx.now;
    let watched_seam = Arc::clone(&ctx.seam);
    // DETACHED watcher: clone the admitted `Arc<App>` so the terminal transition can open its own
    // `Send + 'static` host route to the durable seam (the per-hop route was consumed by the relay).
    let watched_app = Arc::clone(&ctx.app);
    tokio::spawn(async move {
        match handle.await {
            Ok(Ok(_)) => {}
            Ok(Err(refusal)) => {
                diag_debug!(A2A_RELAYED_STREAM_REFUSED, task = %watched_task, error = %refusal, "a2a: the relayed stream ended in a refusal");
                // A BROKEN STREAM IS A TERMINAL FAILURE and the caller is told, for the same
                // reason `fail_task` tells them: silence and "still working" are the same thing to
                // a receiver, and this is the case where they are most different.
                let recorded = crate::plane_host::SendHostDispatch::new(Arc::clone(&watched_app))
                    .with_host(|h, _| {
                        taskstore::TASKS.transition(
                            h,
                            &watched_task,
                            super::task::TaskState::Failed,
                            watched_now,
                            &watched_request,
                        )
                    });
                if let Ok(task) = recorded {
                    notify_push(Arc::clone(&watched_app), &watched_seam, task);
                }
            }
            Err(join) => {
                diag_error!(A2A_STREAM_RELAY_INCOMPLETE, task = %watched_task, error = %join, "a2a: the streaming relay thread did not complete");
            }
        }
    });

    // `futures::stream::unfold` rather than a macro crate: the workspace already depends on
    // `futures`, and a new dependency for six lines of state machine is a new dependency.
    let stream = futures::stream::unfold((Some(first), rx), |(pending, mut rx)| async move {
        if let Some(first) = pending {
            return Some((
                Ok::<_, std::io::Error>(axum::body::Bytes::from(first)),
                (None, rx),
            ));
        }
        let chunk = rx.recv().await?;
        Some((Ok(axum::body::Bytes::from(chunk)), (None, rx)))
    });
    axum::response::Response::builder()
        .status(axum::http::StatusCode::OK)
        .header(
            axum::http::header::CONTENT_TYPE,
            super::relay::SSE_CONTENT_TYPE,
        )
        .header(axum::http::header::CACHE_CONTROL, "no-store")
        .body(axum::body::Body::from_stream(stream))
        .unwrap_or_else(|_| plane_absent())
}

/// RECORD WHAT THE BACKEND SAID THE TASK IS NOW.
///
/// `Submitted` is skipped: it is where the task already is, and the transition table refuses a move
/// to it, so recording it would log an error for a hop that behaved.
fn record_state(ctx: &HopContext, state: super::task::TaskState) {
    if state == super::task::TaskState::Submitted {
        return;
    }
    // POST-hop: the per-hop `SendHostDispatch` was consumed by the relay closure, so a fresh
    // `Send + 'static` host route is opened over a clone of the admitted `Arc<App>` to reach the
    // durable `task_event` seam.
    let recorded =
        crate::plane_host::SendHostDispatch::new(Arc::clone(&ctx.app)).with_host(|h, _| {
            taskstore::TASKS.transition(h, &ctx.task_id, state, ctx.now, &ctx.request_id)
        });
    match recorded {
        // THE STATE CHANGED, SO THE CALLER IS TOLD. This is the line that was missing: a caller
        // could register a push callback, have it validated, pinned and persisted, and then never
        // hear anything, because nothing on this plane ever connected to it.
        Ok(task) => notify_push(Arc::clone(&ctx.app), &ctx.seam, task),
        Err(e) => {
            // Reported, never fatal: the hop SUCCEEDED and the caller is owed its answer. A store
            // that refused the transition is an operator problem, not a reason to discard a
            // completed piece of work the caller has already been billed for.
            // Error-once latch: a store outage persists across every relayed outcome and this path
            // runs per request. Error on the transition; hold subsequent failures at debug.
            static RELAYED_OUTCOME_UNRECORDED_WARNED: std::sync::atomic::AtomicBool =
                std::sync::atomic::AtomicBool::new(false);
            if !RELAYED_OUTCOME_UNRECORDED_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                diag_error!(A2A_RELAYED_OUTCOME_UNRECORDED, task = %ctx.task_id, error = %e, "a2a: the relayed task's outcome could not be recorded");
            } else {
                diag_debug!(A2A_RELAYED_OUTCOME_UNRECORDED, task = %ctx.task_id, error = %e, "a2a: the relayed task's outcome could not be recorded");
            }
        }
    }
}

/// DELIVER THIS TASK'S PUSH NOTIFICATION, if it has a callback, without making the caller wait.
///
/// DETACHED, and that is a decision rather than a convenience. The caller's answer is already
/// determined and the receiver is the caller's OWN infrastructure: holding busbar's response open
/// while somebody else's webhook thinks would let a caller slow busbar down by being slow itself.
///
/// ON A BLOCKING THREAD, because the guard performs a real name lookup and the transport blocks a
/// thread per hop — the same reason the relay and the registration-time guard do.
///
/// A task with no callback never spawns anything: the overwhelmingly common case costs one
/// `Option` test.
pub(super) fn notify_push(
    app: Arc<App>,
    seam: &Arc<dyn super::relay::RelaySeam>,
    task: super::task::Task,
) {
    if task.push_callback.is_none() {
        return;
    }
    let seam = Arc::clone(seam);
    tokio::task::spawn_blocking(move || {
        let task_id = task.task_id.clone();
        // DETACHED: open a `Send + 'static` host route on the blocking thread so the delivery's chained
        // outcome (`record_push_delivery`) reaches the durable `task_event` seam; the raw `HostCtx`
        // never crosses the `spawn_blocking` boundary (it is materialized INSIDE `with_host`).
        let delivered = crate::plane_host::SendHostDispatch::new(app)
            .with_host(|h, _| super::pushdeliver::deliver(h, seam.as_ref(), &task));
        match delivered {
            Ok(()) => tracing::debug!(task = %task_id, "a2a: push notification delivered"),
            // NEVER fatal to the task, and never retried into a hammer. The outcome is recorded and
            // the caller's poll will find it; a webhook that is down is the caller's problem to
            // read in this log line.
            Err(e) => {
                diag_debug!(A2A_PUSH_NOTIFY_UNDELIVERED, task = %task_id, error = %e, "a2a: the push notification was not delivered")
            }
        }
    });
}

/// RENDER A HOP REFUSAL. The refusal's own words go to the LOG, where they name the backend and the
/// reason; the caller gets a busbar-attributed status and the id of the task busbar recorded.
///
/// A DEMOTED registration does NOT fail the task. The work never started, the agent is what changed,
/// and burning the caller's task row for an operator's suspension would make a resume impossible
/// once the agent is restored.
/// A HOP REFUSED BEFORE THERE IS A [`HopContext`] TO REFUSE IT AGAINST.
///
/// One case reaches this and it is [`super::relay::RelayRefusal::Unframable`] on the binding
/// lookup: the registration's card names a wire format this build does not speak, which is known
/// before anything about the hop is decided. It is the SAME status the refusal itself carries, so a
/// caller cannot tell "refused before the context existed" from "refused at the socket" — the fault
/// is busbar's either way and the distinction is an internal one.
fn refuse_hop_early(rpc_id: &serde_json::Value, refusal: &super::relay::RelayRefusal) -> Response {
    (
        axum::http::StatusCode::from_u16(refusal.status())
            .unwrap_or(axum::http::StatusCode::BAD_GATEWAY),
        axum::Json(super::rpcerror::body(
            rpc_id,
            super::rpcerror::A2aError::InvalidAgentResponse,
            refusal.to_string(),
        )),
    )
        .into_response()
}

fn refuse_hop(ctx: &HopContext, refusal: &super::relay::RelayRefusal) -> Response {
    diag_debug!(A2A_RELAYED_SUBMISSION_FAILED, agent = %ctx.agent_id, task = %ctx.task_id, error = %refusal, "a2a: the relayed task submission failed");
    if let super::relay::RelayRefusal::BreakerOpen {
        retry_after_secs, ..
    } = refusal
    {
        // THE BREAKER REFUSED BEFORE THE SOCKET — the breaker-across-planes ruling, owner-
        // decided: a FRESH submission yields `rejected`, the spec's own word for "we did not accept
        // this work" (`failed` would claim busbar tried), and the caller keeps a task id to poll —
        // the row predates the hop, so the id resolves. An ADDRESSED task is different: the task
        // exists at exactly one backend and a tripped backend must not end it, so the verb gets the
        // refusal and the row keeps its last-known state, readable from busbar's own store. Either
        // way: `503` + an EXACT `Retry-After` from the cell's own deadline.
        if !ctx.addressed {
            let recorded = crate::plane_host::SendHostDispatch::new(Arc::clone(&ctx.app))
                .with_host(|h, _| {
                    taskstore::TASKS.transition(
                        h,
                        &ctx.task_id,
                        super::task::TaskState::Rejected,
                        ctx.now,
                        &ctx.request_id,
                    )
                });
            match recorded {
                Ok(task) => notify_push(Arc::clone(&ctx.app), &ctx.seam, task),
                Err(e) => {
                    // Error-once latch: a store outage persists across every breaker refusal and
                    // this path runs per request. Error on the transition; hold the rest at debug.
                    static BREAKER_REFUSAL_UNRECORDED_WARNED: std::sync::atomic::AtomicBool =
                        std::sync::atomic::AtomicBool::new(false);
                    if !BREAKER_REFUSAL_UNRECORDED_WARNED
                        .swap(true, std::sync::atomic::Ordering::Relaxed)
                    {
                        diag_error!(A2A_BREAKER_REFUSAL_UNRECORDED, task = %ctx.task_id, error = %e, "a2a: a breaker-refused task could not be recorded as rejected");
                    } else {
                        diag_debug!(A2A_BREAKER_REFUSAL_UNRECORDED, task = %ctx.task_id, error = %e, "a2a: a breaker-refused task could not be recorded as rejected");
                    }
                }
            }
        }
        let mut resp = (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(super::rpcerror::about_task(
                &ctx.rpc_id,
                super::rpcerror::A2aError::UnsupportedOperation,
                refusal.to_string(),
                &ctx.task_id,
            )),
        )
            .into_response();
        if let Ok(v) = axum::http::HeaderValue::from_str(&retry_after_secs.to_string()) {
            resp.headers_mut()
                .insert(axum::http::header::RETRY_AFTER, v);
        }
        return resp;
    }
    if ctx.addressed {
        // A FAILED READ IS NOT A FAILED TASK. The caller named a task that already exists and asked
        // about it; the hop failing says something about this request, not about that work. Ending
        // it here would let a transient backend blip destroy a live task the caller is waiting on -
        // the same reasoning that keeps a `Demoted` refusal from burning one.
        let err = match refusal {
            super::relay::RelayRefusal::BackendError {
                jsonrpc_code: Some(code),
                ..
            } => super::rpcerror::A2aError::from_code(*code)
                .unwrap_or(super::rpcerror::A2aError::InvalidAgentResponse),
            _ => super::rpcerror::A2aError::InvalidAgentResponse,
        };
        return (
            axum::http::StatusCode::from_u16(err.http_status())
                .unwrap_or(axum::http::StatusCode::BAD_GATEWAY),
            axum::Json(super::rpcerror::about_task(
                &ctx.rpc_id,
                err,
                "the backend agent refused this request",
                &ctx.task_id,
            )),
        )
            .into_response();
    }
    match refusal {
        super::relay::RelayRefusal::Demoted(_) => (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(super::rpcerror::about_task(
                &ctx.rpc_id,
                super::rpcerror::A2aError::UnsupportedOperation,
                "this agent is not currently serving",
                &ctx.task_id,
            )),
        )
            .into_response(),
        // THE BACKEND'S OWN ERROR SEMANTICS, CARRIED. A backend that answered a well-formed A2A
        // error said something specific — "no such task", "not cancelable" — and collapsing every
        // one of them into `InvalidAgentResponseError` reports a caller's typo as a gateway fault.
        // The CODE travels because it is a protocol fact; the backend's prose does not, and the
        // `ErrorInfo` reason is re-derived from the code through busbar's own table rather than
        // echoed, so nothing the backend wrote reaches the caller.
        super::relay::RelayRefusal::BackendError {
            jsonrpc_code: Some(code),
            ..
        } => match super::rpcerror::A2aError::from_code(*code) {
            Some(err) => {
                end_task(&ctx.app, &ctx.seam, &ctx.task_id, &ctx.request_id, ctx.now);
                (
                    axum::http::StatusCode::from_u16(err.http_status())
                        .unwrap_or(axum::http::StatusCode::BAD_GATEWAY),
                    axum::Json(super::rpcerror::about_task(
                        &ctx.rpc_id,
                        err,
                        "the backend agent refused this task",
                        &ctx.task_id,
                    )),
                )
                    .into_response()
            }
            // A code A2A does not define is not a code busbar may re-emit: to a client it is
            // indistinguishable from one the specification will define later.
            None => fail_task(
                &ctx.app,
                &ctx.seam,
                &ctx.rpc_id,
                &ctx.task_id,
                &ctx.request_id,
                ctx.now,
                refusal.status(),
            ),
        },
        _ => fail_task(
            &ctx.app,
            &ctx.seam,
            &ctx.rpc_id,
            &ctx.task_id,
            &ctx.request_id,
            ctx.now,
            refusal.status(),
        ),
    }
}

/// END THE TASK AS `failed` AND ANSWER A BUSBAR-ATTRIBUTED ERROR.
///
/// Two acts that must not come apart. Answering the error without ending the task leaves a row
/// claiming work is in flight that nothing will ever finish; ending the task without answering the
/// error hands the caller a Task envelope for work that never started. The refusal names the TASK
/// so the caller can correlate it with the record busbar kept, and never the backend, because
/// publishing the backend is publishing the way around every control busbar applies.
/// END THE TASK AS `failed`, AND TELL ANY REGISTERED CALLBACK. The half of [`fail_task`] that is
/// about the RECORD rather than about the answer, split out because a refusal that carries the
/// backend's own error code renders its answer differently and must still end the task identically.
fn end_task(
    app: &Arc<App>,
    seam: &Arc<dyn super::relay::RelaySeam>,
    task_id: &str,
    request_id: &str,
    now: u64,
) {
    let recorded = crate::plane_host::SendHostDispatch::new(Arc::clone(app)).with_host(|h, _| {
        taskstore::TASKS.transition(h, task_id, super::task::TaskState::Failed, now, request_id)
    });
    match recorded {
        // A FAILURE IS A TERMINAL STATE AND THE CALLER WANTS IT MOST. A push callback that only
        // ever fired on success would leave the one case a caller actually needs to be woken for —
        // work that will never finish — as silence indistinguishable from work still in progress.
        Ok(task) => notify_push(Arc::clone(app), seam, task),
        Err(e) => {
            // Error-once latch: a store outage persists across every terminal failure and this
            // path runs per request. Error on the transition; hold subsequent failures at debug.
            static FAILURE_UNRECORDED_WARNED: std::sync::atomic::AtomicBool =
                std::sync::atomic::AtomicBool::new(false);
            if !FAILURE_UNRECORDED_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                diag_error!(A2A_FAILURE_UNRECORDED, task = %task_id, error = %e, "a2a: a failed task could not be recorded as failed");
            } else {
                diag_debug!(A2A_FAILURE_UNRECORDED, task = %task_id, error = %e, "a2a: a failed task could not be recorded as failed");
            }
        }
    }
}

fn fail_task(
    app: &Arc<App>,
    seam: &Arc<dyn super::relay::RelaySeam>,
    rpc_id: &serde_json::Value,
    task_id: &str,
    request_id: &str,
    now: u64,
    status: u16,
) -> Response {
    end_task(app, seam, task_id, request_id, now);
    (
        axum::http::StatusCode::from_u16(status).unwrap_or(axum::http::StatusCode::BAD_GATEWAY),
        axum::Json(super::rpcerror::about_task(
            rpc_id,
            super::rpcerror::A2aError::InvalidAgentResponse,
            "the backend agent did not complete this task",
            task_id,
        )),
    )
        .into_response()
}

/// EVERY PLACE A2A SPELLS "the callback to call when this task moves", in both revisions.
///
/// v0.3 puts a `PushNotificationConfig` at `configuration.pushNotificationConfig`. v1.0 puts a
/// `TaskPushNotificationConfig` at `configuration.taskPushNotificationConfig`, whose own callback
/// sits either directly on it or under a nested `pushNotificationConfig`, depending on which shape
/// the client serialises.
const CALLBACK_POINTERS: [&str; 3] = [
    "/params/configuration/pushNotificationConfig/url",
    "/params/configuration/taskPushNotificationConfig/url",
    "/params/configuration/taskPushNotificationConfig/pushNotificationConfig/url",
];

/// The CONFIG OBJECTS those three URLs sit in, in the same order, so the URL and the credential
/// beside it are read out of ONE object rather than by two independent pointer lists that could
/// pick the URL from one spelling and the credential from another.
const CALLBACK_CONFIG_POINTERS: [&str; 3] = [
    "/params/configuration/pushNotificationConfig",
    "/params/configuration/taskPushNotificationConfig",
    "/params/configuration/taskPushNotificationConfig/pushNotificationConfig",
];

/// THE CALLER'S PUSH-NOTIFICATION CALLBACK URL, if it registered one.
///
/// ONE SPELLING WAS READ AND THERE ARE THREE, and the two that were not read were a hole rather
/// than an omission. This plane is content-blind and forwards the caller's envelope VERBATIM, so a
/// callback busbar did not RECOGNISE was not merely unguarded — it was handed to the backend agent,
/// which registered it and called it. The whole point of guarding here rather than leaving it to
/// the backend is stated in `local.rs`: a callback busbar holds is a callback busbar's SSRF guard
/// judges, and one the backend holds is called around it.
///
/// So a v1.0 caller could hand busbar `http://localhost:PORT/webhook` — precisely the loopback
/// target `pushnotify::is_internal_addr` exists to refuse — and have it called, because the guard
/// was reading a JSON pointer that request does not contain. Observed against the official TCK
/// with a fronted agent that implements push, in that agent's own log:
///
/// ```text
/// a2a.server.tasks.base_push_notification_sender:
///   Push-notification sent for task_id=… to URL: http://localhost:63936/webhook
/// ```
///
/// while busbar's own guard had refused nothing, having seen nothing. Reading every spelling closes
/// it: the URL is now found, guarded, and refused where it must be.
fn callback_of(envelope: &serde_json::Value) -> Option<String> {
    CALLBACK_POINTERS.into_iter().find_map(|p| {
        envelope
            .pointer(p)
            .and_then(serde_json::Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    })
}

/// THE INLINE PUSH-NOTIFICATION CONFIG OBJECT, in whichever of the three spellings it arrived in.
///
/// The one whose `url` [`callback_of`] would pick: the selection walks the same list in the same
/// order and takes the first entry that actually carries a non-empty `url`, so the credential this
/// returns is the credential registered ALONGSIDE the URL busbar is about to guard, never one from
/// a sibling spelling a client also happened to serialise.
fn callback_config(envelope: &serde_json::Value) -> Option<&serde_json::Value> {
    CALLBACK_CONFIG_POINTERS.into_iter().find_map(|p| {
        envelope.pointer(p).filter(|cfg| {
            cfg.get("url")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|u| !u.is_empty())
        })
    })
}

/// SSRF-VALIDATE ONE CALLBACK against the addresses it resolves to right now.
///
/// The resolution goes through the RELAY SEAM's resolver rather than a second one, so the answer
/// this guard judges comes from the same place every other outbound decision on this plane reads —
/// and so a test can install one resolver and have it govern both.
///
/// ON A BLOCKING THREAD, because `Resolver` is a synchronous seam and the production one performs a
/// real name lookup. A lookup inline here would hold an axum worker for as long as a nameserver
/// feels like taking, which a caller chooses by choosing the host.
pub(crate) async fn validate_callback(
    url: String,
    seam: Arc<dyn super::relay::RelaySeam>,
) -> Result<super::pushnotify::PinnedCallback, String> {
    tokio::task::spawn_blocking(move || {
        let host = super::pushnotify::host_of(&url).map_err(|e| e.to_string())?;
        // The literal case never needs a resolver and must not be made to depend on one;
        // `validate` judges a literal on its own and ignores what is passed here.
        let resolved = if host.parse::<std::net::IpAddr>().is_ok() {
            Vec::new()
        } else {
            seam.resolver().resolve(&host).unwrap_or_default()
        };
        super::pushnotify::validate(&url, &resolved).map_err(|e| e.to_string())
    })
    .await
    .unwrap_or_else(|_| Err("the push callback could not be validated".to_string()))
}

/// THE TASK A REQUEST NAMES, if this caller owns one by that id.
///
/// SCOPED, through [`taskstore::TaskRegistry::get_scoped`], so a caller naming somebody
/// else's task id resolves to nothing and takes the ordinary path — it is not a way to read, cancel
/// or subscribe to another principal's work, and the answer it gets is the backend's opinion of an
/// id the backend does not hold, which is the same answer a made-up id gets.
///
/// The member names are [`super::idmap`]'s, because they are the same fact: the ids this reads are
/// exactly the ids that translation rewrites.
fn addressed_task(envelope: &serde_json::Value, principal: &str) -> Option<super::task::Task> {
    let params = envelope.get("params")?.as_object()?;
    for member in super::idmap::TASK_ID_MEMBERS {
        let Some(named) = params.get(member).and_then(serde_json::Value::as_str) else {
            continue;
        };
        if let Ok(task) = taskstore::TASKS.get_scoped(principal, named) {
            return Some(task);
        }
    }
    None
}

/// AN INTERRUPTED TASK OF THIS CALLER'S, ON THIS AGENT, UNDER THIS `contextId` — the resume target.
///
/// Scoped to the PRINCIPAL through `list_scoped`, so a caller cannot resume somebody else's task by
/// guessing a `contextId`. The most recently updated one wins where a context somehow has two, which
/// is the only ordering that cannot resume a task that has since been superseded.
fn resumable_task(principal: &str, context_id: &str, agent_id: &str) -> Option<super::task::Task> {
    let mut candidates: Vec<super::task::Task> = taskstore::TASKS
        .list_scoped(principal)
        .into_iter()
        .filter(|t| {
            t.context_id == context_id && t.agent_id == agent_id && t.state.is_interrupted()
        })
        .collect();
    candidates.sort_by_key(|t| t.updated_at);
    candidates.pop()
}

/// DOES THIS METHOD NAME ASK FOR A STREAM? Both eras of the name, and neither is preferred.
///
/// A2A v0.3 names the streaming methods `message/stream` and `tasks/resubscribe`; v1.0 renames them
/// `SendStreamingMessage` and `SubscribeToTask` — the vocabulary the official TCK and `a2a-go` v2.4
/// speak. busbar is content-blind on this plane and relays the envelope verbatim, so this is the
/// ONLY place the method name decides anything about the transport, and reading one vocabulary
/// means a caller in the other era has its stream dispatched down the unary path with its
/// `capabilities.streaming` filter never applying.
///
/// Listed rather than pattern-matched loosely, so a third spelling is a deliberate edit. Named
/// rather than inlined so `local_tests::every_a2a_method_is_read_identically_under_both_of_its_live_json_rpc_names`
/// can drive it: an asymmetry between the two eras is the failure worth locking out, and it cannot
/// be locked out against an expression buried in a struct literal.
fn reads_as_streaming(method: &str) -> bool {
    method.ends_with("/stream")
        || method == "tasks/resubscribe"
        || method == "SendStreamingMessage"
        || method == "SubscribeToTask"
}

#[cfg(test)]
pub(crate) fn reads_as_streaming_for_test(method: &str) -> bool {
    reads_as_streaming(method)
}

/// The SHAPE of work an inbound envelope is asking for, as the catalogue's filter reads it.
///
/// Read from the request rather than assumed, because the catalogue's whole job is to refuse an
/// agent whose card does not declare what this call needs. An envelope that names nothing
/// constrains nothing, which is the empty shape.
fn shape_of(envelope: &serde_json::Value) -> super::registry::TaskShape {
    let params = envelope.get("params");
    let cfg = params.and_then(|p| p.get("configuration"));
    super::registry::TaskShape {
        skill: params
            .and_then(|p| p.get("metadata"))
            .and_then(|m| m.get("skill"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        // BOTH SPELLINGS OF "THIS IS A STREAM": see [`reads_as_streaming`].
        requires_streaming: envelope
            .get("method")
            .and_then(serde_json::Value::as_str)
            .is_some_and(reads_as_streaming),
        requires_push_notifications: cfg.and_then(|c| c.get("pushNotificationConfig")).is_some(),
        input_modes: Vec::new(),
        output_modes: cfg
            .and_then(|c| c.get("acceptedOutputModes"))
            .and_then(serde_json::Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default(),
    }
}

/// A per-call identifier derived from the request bytes and the clock. Not a UUID and not claiming
/// to be one: it only has to be unique enough to key a task row, and deriving it here avoids adding
/// a dependency for a value nothing outside this process interprets.
fn uuid_like(body: &[u8], now: u64) -> String {
    use std::hash::{Hash, Hasher};
    // A PROCESS-WIDE MONOTONIC COUNTER, and it is the only ingredient that guarantees anything.
    //
    // The body and the clock are DERIVED from the request, so two callers submitting the same
    // envelope in the same second derive the same id — and the second `submit` then replaces the
    // first caller's row, which is a task quietly ceasing to exist and, on a shared `contextId`,
    // one principal being handed another's task handle. That was not hypothetical: the relay's
    // resume tests found it, because they are the first tests to submit twice.
    //
    // The stack address that used to stand in for entropy did not: it is the address of a temporary
    // in this frame, and two calls at the same stack depth get the same one.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let mut h = std::collections::hash_map::DefaultHasher::new();
    body.hash(&mut h);
    now.hash(&mut h);
    SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        .hash(&mut h);
    // The process's own identity, so two processes writing to ONE durable store do not collide on
    // a counter that each of them starts at zero.
    std::process::id().hash(&mut h);
    format!("{:016x}", h.finish())
}

/// The plane's mounted routes, or an unchanged router when this deployment fronts no agents.
///
/// The gate is the plane's dispatch slot plus an admission: a deployment with no `agents:` section
/// has no slot (this is not called), and one with no `public_url` has no RECEIVING side. Either way
/// NOTHING is mounted — no route in the table, nothing for the auth middleware to consult, and "is
/// this deployment an A2A server?" stays a question the mounted surface answers rather than a flag
/// somebody has to trust. The slot is granted as `&dyn Any` and downcast to the plane's own type;
/// no `Store`/`GovCtx`/`audit::Chain` reaches this seam.
pub(crate) fn mount(
    router: crate::core_routes::CoreRouter,
    slot: &dyn std::any::Any,
) -> crate::core_routes::CoreRouter {
    use busbar_plugin_loader::{RouteAuth, RouteMethod};
    let plane = slot
        .downcast_ref::<super::plane::A2aPlane>()
        .expect("the a2a plane's mount slot is an A2aPlane");
    if plane.admission().is_none() {
        return router;
    }
    // AND THE SECOND BINDING, at the same mount and behind the same gate. `serve::self_card`
    // advertises HTTP+JSON because `Plane::A2a` names it as a wire format, and a card advertising
    // an interface nothing serves is the exact defect `serve` refuses one member down — so the card
    // entry and these routes arm together, or a deployment with no receiving side has neither.
    let router = super::rest::mount(router);
    router
        .route(
            super::serve::METADATA_PATH,
            RouteMethod::Get,
            RouteAuth::None,
            crate::ingress::protocol::metadata_handler::<A2aWords>,
        )
        // THE DISCOVERY PATH THE SPECIFICATION MANDATES. Auth-exempt for the reason given on
        // `serve::self_card`: this document is what tells a caller which credential to present, so
        // demanding one to read it is circular. It is mounted alongside the RFC 9728 metadata path
        // because they are the same kind of thing — the two documents a client reads BEFORE it has
        // a token.
        .route(
            super::card::WELL_KNOWN_CARD_PATH,
            RouteMethod::Get,
            RouteAuth::None,
            well_known_card,
        )
        .route(
            format!("{}/agents/{{agent_id}}", super::serve::MOUNT_PATH),
            RouteMethod::Get,
            RouteAuth::Key,
            card,
        )
        .route(
            format!("{}/agents/{{agent_id}}", super::serve::MOUNT_PATH),
            RouteMethod::Post,
            RouteAuth::Key,
            agent_rpc,
        )
        // THE ENDPOINT BUSBAR'S OWN AGENT CARD PUBLISHES. `serve::self_card` advertises
        // `<public_url>/a2a` as this deployment's `JSONRPC` interface and nothing was mounted
        // there, so every conformant client that discovered busbar posted into a 404. See
        // [`select`] for how the agent is resolved and why it is the catalogue's answer.
        .route(
            super::serve::MOUNT_PATH.to_string(),
            RouteMethod::Post,
            RouteAuth::Key,
            plane_rpc,
        )
        // AND THE SAME PATH WITH A TRAILING SLASH. Not cosmetic, and not a guess: an HTTP client
        // given `http://host/a2a` as a BASE URL resolves a request for `/` against it and sends
        // `/a2a/` — that is what `httpx` does, which is what the official A2A TCK's JSON-RPC client
        // is built on, and it is what a great many SDKs do. Axum matches paths exactly, so
        // `/a2a` alone leaves the single most likely spelling of this endpoint answering 404.
        .route(
            format!("{}/", super::serve::MOUNT_PATH),
            RouteMethod::Post,
            RouteAuth::Key,
            plane_rpc,
        )
        // BUSBAR'S OWN CALLBACK — the address it hands a BACKEND, so the backend never learns the
        // caller's. `RouteAuth::None` because the party calling it is a fronted AGENT, which holds
        // no busbar key and must not be issued one for this; the handler authenticates the request
        // itself against the per-task token busbar minted, in constant time. See
        // `super::pushback`, which carries the whole argument.
        .route(
            format!(
                "{}{}",
                super::serve::MOUNT_PATH,
                super::pushback::PUSH_PATH_SUFFIX
            ),
            RouteMethod::Post,
            RouteAuth::None,
            super::pushback::push_notification,
        )
        // THE gRPC BINDING, mounted the same way and therefore declaring the same bar.
        //
        // It is a `CoreRouter::route` and not a `route_service`, and that is the whole answer to
        // "how does a tonic service satisfy `CoreRouteTable`": it does not enter the tree as a
        // pre-built router at all. `super::grpc::serve` is an ordinary axum handler that builds the
        // generated `A2aServiceServer` per request, around this request's already-authenticated
        // principal — so this line declares `RouteAuth::Key` in the act that wires it, exactly like
        // the four above it, and there is no router in the tree that the table does not describe.
        //
        // The PATH is the `.proto`'s, not busbar's: a gRPC client is handed an authority and derives
        // the path from the service descriptor, so this binding cannot be served under
        // `MOUNT_PATH`. `PlaneDispatch` claims it for this plane for the same reason every other
        // path here is claimed — that is where the RFC 8707 audience check finds its audience.
        .route(
            super::grpc::route_path(),
            RouteMethod::Post,
            RouteAuth::Key,
            super::grpc::serve,
        )
}

#[cfg(test)]
#[path = "tests/ingress_tests.rs"]
mod ingress_tests;
