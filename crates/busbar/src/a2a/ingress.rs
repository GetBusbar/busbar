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
//! 3. CATALOGUE — [`super::catalogue::inbound_catalogue`], which answers whether this caller may
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

use super::inbound::{Dispatch, InboundRefusal, CREDENTIAL_KIND_A2A_INBOUND};
use crate::state::{App, CurrentApp};

/// The audit action every inbound call on this plane records under.
const AUDIT_ACTION: &str = "agent.call";

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

/// A refusal, rendered. The body names the reason token and never the backend: `InboundRefusal`'s
/// own `Display` is written to be safe to return, and `Dispatch::backend_url` never leaves here.
fn refuse(refusal: &InboundRefusal) -> Response {
    // THE PLANE'S OWN ERROR ENVELOPE, and the HTTP status the refusal already chose. An admission
    // refusal has no A2A error type of its own, so it takes the nearest binding
    // (`UnsupportedOperationError`) with the real reason in the message — see `rpcerror`'s note on
    // why an invented code in the A2A range would be worse than a near one.
    let status = axum::http::StatusCode::from_u16(refusal.status())
        .unwrap_or(axum::http::StatusCode::FORBIDDEN);
    (
        status,
        axum::Json(super::rpcerror::body(
            &serde_json::Value::Null,
            super::rpcerror::A2aError::UnsupportedOperation,
            refusal.to_string(),
        )),
    )
        .into_response()
}

/// The RFC 9728 protected-resource metadata document for the A2A plane.
///
/// Mounted `RouteAuth::None`, for the reason the sibling plane's is: every caller who needs this
/// document is by definition one that does not have a token yet, so requiring one would be a
/// discovery loop with no entrance.
pub(crate) async fn metadata(CurrentApp(app): CurrentApp) -> Response {
    let Some(admission) = app.a2a.as_ref().and_then(|p| p.admission()) else {
        return not_found();
    };
    // `resource` is the audience a client must have its authorization server mint for, and it is
    // compared byte-for-byte against the `aud` of every token presented under this mount. Both sides
    // read it from `A2aPlane::admission`, so there is no second spelling of it anywhere.
    let doc = serde_json::json!({
        "resource": admission.audience,
        "bearer_methods_supported": ["header"],
    });
    (
        [
            (axum::http::header::CACHE_CONTROL, "public, max-age=3600"),
            (
                axum::http::header::CONTENT_TYPE,
                "application/json; charset=utf-8",
            ),
        ],
        axum::Json(doc),
    )
        .into_response()
}

/// BUSBAR'S OWN AGENT CARD at `/.well-known/agent-card.json`, unauthenticated.
///
/// The A2A protocol specification makes serving an Agent Card a MUST, and this is the path a
/// stock A2A client
/// asks for first. See [`super::serve::self_card`] for why it is auth-exempt and, more importantly,
/// for what is deliberately left out of it — this endpoint cannot ask who is calling, so it must
/// not name the agents busbar fronts.
pub(crate) async fn well_known_card(CurrentApp(app): CurrentApp) -> Response {
    let Some(plane) = app.a2a.as_ref() else {
        return not_found();
    };
    // NO PUBLIC URL, NO CARD. A deployment with no receiving side is not an A2A server, and a card
    // whose `url` was guessed would point callers somewhere busbar does not answer.
    let Some(public_url) = plane.public_url() else {
        return no_receiving_side();
    };
    // Signed by the same key that signs the fronted cards, read from the same place, so what an
    // external caller pins busbar by is one key rather than one per path.
    let signer = app.governance.as_ref().and_then(|g| g.a2a_card_signer());
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
            tracing::error!(error = %e, "could not build busbar's own agent card");
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

/// 404 in this plane's envelope. Used where the mount exists but the plane does not, which is
/// unreachable while the mount and the config are created in one act, and is still answered rather
/// than unwrapped because this is a request path.
fn not_found() -> Response {
    super::rpcerror::respond(
        &serde_json::Value::Null,
        super::rpcerror::A2aError::Internal,
        "this deployment has no A2A plane",
    )
}

/// Everything the admitted half of a request needs, resolved under ONE read of the registry.
///
/// A single lock acquisition rather than one per step, because `authorize` and the catalogue must
/// agree about the same registry state: two acquisitions could straddle a re-verification sweep and
/// admit against one registration while cataloguing against another.
struct Admitted {
    dispatch: Dispatch,
    matched_skill: Option<String>,
    /// The registration's OUTBOUND CREDENTIAL HANDLE, cloned out under the same registry read that
    /// authorised the call. A handle and its lease policy, never a secret: the secret is resolved at
    /// relay time by [`super::creds::mint_from`], whose signature has no parameter an inbound
    /// caller's credential could arrive through.
    ///
    /// Cloned rather than re-read because a second acquisition could straddle a config apply and
    /// mint a credential for a registration that is not the one this call was authorised against.
    outbound_cred: Option<super::creds::OutboundCredential>,
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
    shape: &super::catalogue::TaskShape,
    now_secs: u64,
) -> Result<Admitted, Box<Response>> {
    let Some(plane) = app.a2a.as_ref() else {
        return Err(Box::new(not_found()));
    };
    let kind = credential_kind_of(app);
    plane.with_registrations(|regs| {
        // 2. AUTHORISE. `Dispatch` is owned, so it escapes this closure; `Candidate` borrows the
        //    guard's slice and cannot, which is why the skill is cloned out below rather than
        //    returned.
        let dispatch = super::inbound::authorize(key, kind, agent_id, regs, now_secs)
            .map_err(|r| Box::new(refuse(&r)))?;

        // 3. CATALOGUE. Authorisation says the caller may reach this agent AT ALL; the catalogue
        //    says whether it may reach it for the work it is actually asking for. Both run: a
        //    caller with a grant on an agent whose card declares none of the requested capability
        //    is refused here rather than dispatched into a backend that will not serve it.
        let matched = super::catalogue::inbound_catalogue(key, regs, shape)
            .into_iter()
            .find(|c| c.registration.agent_id == dispatch.agent_id)
            .map(|c| c.matched_skill.clone());
        let outbound_cred = regs
            .iter()
            .find(|r| r.agent_id == dispatch.agent_id)
            .and_then(|r| r.outbound_cred.clone());

        match matched {
            Some(matched_skill) => Ok(Admitted {
                dispatch,
                matched_skill,
                outbound_cred,
            }),
            None => {
                // The catalogue excluded it. `explain` re-derives WHY for the one registration,
                // so the refusal names a reason instead of an empty list.
                let reason = regs
                    .iter()
                    .find(|r| r.agent_id == dispatch.agent_id)
                    .and_then(|r| super::catalogue::explain(r, key, shape, None).err())
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
/// grants — `mcp::catalogue`. `super::catalogue::inbound_catalogue` is the same function for this
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
    shape: &super::catalogue::TaskShape,
) -> Result<String, Box<Response>> {
    let Some(plane) = app.a2a.as_ref() else {
        return Err(Box::new(not_found()));
    };
    let mut ids = plane.with_registrations(|regs| {
        super::catalogue::inbound_catalogue(key, regs, shape)
            .into_iter()
            .map(|c| c.registration.agent_id.clone())
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
/// Identical to [`rpc`] in everything except how the agent is named. See [`select`].
pub(crate) async fn plane_rpc(
    CurrentApp(app): CurrentApp,
    axum::extract::Extension(gov): axum::extract::Extension<crate::governance::GovCtx>,
    axum::extract::Extension(principal): axum::extract::Extension<crate::auth::AuthPrincipal>,
    wire: Wire,
    body: axum::body::Bytes,
) -> Response {
    invoke(app, gov, principal, FromCatalogue, wire, body).await
}

/// The A2A protocol versions THIS ENDPOINT SPEAKS, in the `Major.Minor` spelling the specification
/// negotiates in.
///
/// Both, and each because the tree can be pointed at for it rather than because it sounds
/// generous. `shape_of` reads the v0.3 streaming methods (`message/stream`, `tasks/resubscribe`)
/// AND the v1.0 renames (`SendStreamingMessage`, `SubscribeToTask`); [`super::relay`] reads a bare
/// v0.3 `result` and a v1.0 `{"task": …}` wrapper; [`super::idmap`] rewrites `id`, `taskId` and
/// v1.0's `task_id`. Everything else on this plane is relayed verbatim and is version-agnostic by
/// construction. A version this list claims that no code reads would be exactly the defect
/// `serve::self_card` refuses to commit with `extendedAgentCard: false` — a document asserting a
/// property nothing implements.
const SUPPORTED_A2A_VERSIONS: &[&str] = &["0.3", "1.0"];

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

/// THE TWO HEADERS THIS PLANE READS OFF AN INBOUND REQUEST, and deliberately the only two.
///
/// A `HeaderMap` is NOT extracted, here or anywhere on this path, and that is a security property
/// rather than a style: the first draft of the relay extracted one and the caller's own credential
/// went out on the backend hop (see step 7 in [`invoke`]). An extractor that can only ever hold
/// these two owned strings cannot forward a third header by accident, because there is no third
/// header in it to forward.
pub(crate) struct Wire {
    /// The request's `Content-Type`, as sent. `None` when the caller sent none.
    content_type: Option<String>,
    /// The requested `A2A-Version`. `None` when absent; `Some("")` when present and empty, which
    /// the specification defines as `0.3` rather than as a refusal.
    version: Option<String>,
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
        })
    }
}

impl Wire {
    /// THE REFUSAL THIS REQUEST'S HEADERS EARN, or `None` when they earn none.
    ///
    /// `Null` as the JSON-RPC `id` throughout, and that is the specification's instruction rather
    /// than laziness: the body has not been read at this point, so the id has not been determined,
    /// and JSON-RPC 2.0 section 5 says an answer sent before the id is known MUST carry `null`.
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
    let Some(plane) = app.a2a.as_ref() else {
        return not_found();
    };
    let Some(key) = gov.key.as_ref() else {
        return governance_required();
    };
    let Some(public_url) = plane.public_url() else {
        return no_receiving_side();
    };

    // A card read asks for no particular work, so the shape is the empty one: every filter that
    // depends on the requested capability is vacuous and only trust, scope and a cached card decide.
    let shape = super::catalogue::TaskShape::default();
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
    let signer = app.governance.as_ref().and_then(|g| g.a2a_card_signer());
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
            tracing::error!(agent = %admitted.dispatch.agent_id, error = %e, "a2a: refusing to serve an agent card");
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
fn no_receiving_side() -> Response {
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
pub(crate) async fn rpc(
    CurrentApp(app): CurrentApp,
    axum::extract::Extension(gov): axum::extract::Extension<crate::governance::GovCtx>,
    axum::extract::Extension(principal): axum::extract::Extension<crate::auth::AuthPrincipal>,
    axum::extract::Path(agent_id): axum::extract::Path<String>,
    wire: Wire,
    body: axum::body::Bytes,
) -> Response {
    invoke(app, gov, principal, Named(agent_id), wire, body).await
}

/// WHICH FRONTED AGENT A SUBMISSION IS FOR, and the two ways a caller can say it.
///
/// The two mounted endpoints differ in this and in NOTHING else — same admission, same catalogue,
/// same meter, same audit, same relay — which is why the difference is a two-variant value passed
/// into one function rather than two handlers that happen to look alike. A second copy of the
/// sequence is a second place for the egress gate or the push-callback guard to go missing.
enum Target {
    /// `POST /a2a/agents/{id}` — the caller named the agent in the path.
    Named(String),
    /// `POST /a2a` — the plane's own endpoint, the one busbar's Agent Card publishes. The agent is
    /// resolved from THIS CALLER'S CATALOGUE for the shape of work asked for. See [`select`].
    FromCatalogue,
}
use Target::{FromCatalogue, Named};

/// THE INBOUND CALL, both endpoints, one sequence.
async fn invoke(
    app: Arc<App>,
    gov: crate::governance::GovCtx,
    principal: crate::auth::AuthPrincipal,
    target: Target,
    wire: Wire,
    body: axum::body::Bytes,
) -> Response {
    if app.a2a.is_none() {
        return not_found();
    }
    let Some(key) = gov.key.as_ref() else {
        return governance_required();
    };
    let now = crate::store::now();

    // ── THE TWO FACTS OFF THE REQUEST LINE, JUDGED BEFORE ANYTHING ELSE. ────────────────────────
    //
    // busbar is content-blind about the caller's ENVELOPE and is not content-blind about the HTTP
    // request carrying it. busbar terminated this connection; busbar is the server the client
    // discovered, authenticated to and addressed. A media type this endpoint does not read and a
    // protocol version this endpoint does not speak are therefore busbar's answers to give, and
    // relaying either to a backend and forwarding its cheerful reply tells the caller it was
    // understood when nothing understood it.
    //
    // FIRST, and before the JSON parse, because the order IS the behaviour: a request with a wrong
    // media type usually also carries a body that is not JSON, and a gate placed after the parse
    // answers `Parse` (-32700) forever and never reaches -32005. The caller is then told to fix its
    // body when the thing to fix is a header.
    if let Some(refusal) = wire.refuse() {
        return refusal;
    }

    let Ok(envelope) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return super::rpcerror::respond(
            &serde_json::Value::Null,
            super::rpcerror::A2aError::Parse,
            "the request body is not JSON",
        );
    };

    // ── THE JSON-RPC ENVELOPE, READ BY THE READER THE MCP PLANE USES. ───────────────────────────
    //
    // This plane had NO envelope validation before: no `jsonrpc` version check, no `method` check,
    // and `rpc_id` was `envelope.get("id").cloned().unwrap_or(Value::Null)` — a single
    // `unwrap_or` that destroyed the difference between a request whose id is `null` (which no
    // caller can correlate) and a NOTIFICATION, which has no id member and which JSON-RPC 2.0 section 4.1
    // says a server MUST NOT answer at all. Both were served `200` and a success result, and a
    // notification's answer came back under an id the caller never sent.
    //
    // The defect was REPORTED against the MCP plane. It was here too, in a second implementation of
    // the same concern, which is exactly the failure mode `structure-lint`'s plane-coherence check
    // exists to name. Hence one reader, not two fixes. See `crate::ingress::jsonrpc` for the
    // clauses, and for the argument for refusing `"id": null` on a plane whose own specification
    // only discourages it.
    //
    // THE SHARED READER DECIDES; THIS PLANE RENDERS. The decision — request, notification, or not a
    // JSON-RPC message — is the reader's, so both planes make it the same way. The WIRE is this
    // plane's: A2A section 5.4 binds its own status and its own ProtoJSON error body to each code, and a
    // refusal rendered in the MCP plane's shape would be a body the TCK rejects by schema. Hence
    // `read` for the verdict and [`super::rpcerror::respond`] for the answer.
    //
    // BEFORE ADMISSION, THE CATALOGUE, THE METER AND THE EGRESS GATE, on purpose: an envelope this
    // plane will not honour must not open a task, spend a caller's budget or cause busbar's own
    // credential to be leased for a backend hop.
    let rpc_id = match crate::ingress::jsonrpc::read(&envelope) {
        Ok(crate::ingress::jsonrpc::Envelope::Request { id, .. }) => id,
        // section 4.1: "The Server MUST NOT reply to a Notification." A2A defines no notification method,
        // so there is nothing to do with one either — but "nothing to do" is still not "answer it".
        Ok(crate::ingress::jsonrpc::Envelope::Notification { .. }) => {
            return crate::ingress::jsonrpc::accepted()
        }
        Err(invalid) => {
            return super::rpcerror::respond(
                &invalid.id,
                super::rpcerror::A2aError::InvalidRequest,
                invalid.message,
            )
        }
    };

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

    // 5. METER, before the work rather than after: an over-budget caller is refused instead of
    //    served and billed. The pool name is this plane's own resource spelling, so an `agent`
    //    line is distinguishable from a pool line in the same ledger.
    let Some(gov_state) = app.governance.as_ref() else {
        return governance_required();
    };
    let _hold = match gov_state.try_admit(&app.cost, key, &resource, now) {
        Ok(grant) => grant,
        Err(_) => {
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
    };

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
    let callback = match callback_of(&envelope) {
        None => None,
        Some(url) => {
            let Some(seam) = plane_of(&app).map(|p| p.relay_seam()) else {
                return not_found();
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

    let resumed = if addressed.is_some() || context_id.is_empty() {
        None
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
        &admitted.dispatch.agent_id,
        &context_id,
        &task_id,
    );

    if is_resume {
        // BACK TO `working`, which chains a `task.resumed` provenance event. The transition table
        // refuses this from a terminal state, so a caller cannot resurrect finished work by
        // re-using its `contextId`.
        if let Err(e) = super::taskstore::TASKS.transition(
            &task_id,
            super::task::TaskState::Working,
            now,
            &request_id,
        ) {
            tracing::error!(task = %task_id, error = %e, "a2a: an interrupted task could not be resumed");
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
                tracing::error!(error = ?e, "a2a: could not open an inbound task");
                return not_found();
            }
        };
        if let Err(e) = super::taskstore::TASKS.submit(&task, &request_id) {
            tracing::error!(error = %e, "a2a: the inbound task could not be recorded");
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
        let _ = super::taskstore::TASKS.record_dispatch(
            &task_id,
            hop.target_agent_id.as_deref().unwrap_or(&agent_id),
            now,
            &request_id,
        );
    }

    if let Some(pinned) = callback.as_ref() {
        let _ = super::taskstore::TASKS.set_push_callback(&task_id, Some(pinned.url.clone()), now);
        // THE ADDRESSES THE GUARD JUST JUDGED, kept so the FIRST delivery is a `revalidate` — the
        // fresh answer must pass the guard AND still overlap this set — rather than a bare
        // `validate`. Process-local: see `pushdeliver::pins` for why it is not, and must not be
        // read as, a durable pin.
        super::pushdeliver::remember(&task_id, pinned);
    }

    gov_state.record_metering(
        &hop.billed_key_id,
        &resource,
        crate::plane::Plane::A2a.key(),
        None,
        now,
    );

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
    let Some(plane) = plane_of(&app) else {
        return not_found();
    };
    let seam = plane.relay_seam();
    let gate: Arc<dyn super::relay::DelegationGate> =
        Arc::new(super::plane::LiveGate(Arc::clone(&plane)));

    // BUSBAR'S OWN CREDENTIAL FOR THIS BACKEND, or none — and it can only be minted against the
    // grant obtained above. A configured credential that will not resolve is a REFUSAL and not a
    // quiet unauthenticated hop: an operator who configured one meant the backend to see one.
    let lease = match admitted.outbound_cred.as_ref() {
        Some(cred) => match super::creds::mint_from(&grant, cred, &app.secret_resolver, now_ms) {
            Ok(lease) => Some(lease),
            Err(e) => {
                tracing::error!(agent = %admitted.dispatch.agent_id, error = %e, "a2a: the outbound credential could not be leased");
                return fail_task(&seam, &rpc_id, &task_id, &request_id, now, 502);
            }
        },
        None => None,
    };

    let hop_ctx = HopContext {
        seam: Arc::clone(&seam),
        agent_id: admitted.dispatch.agent_id.clone(),
        addressed: addressed.is_some(),
        backend_url: admitted.dispatch.backend_url.clone(),
        // THE ONE READING OF THE OPERATOR'S `allow_private:` LINE, obtained where every other
        // caller obtains it. Reaching for `seam.policy()` inside the relay instead is the defect
        // `relay::RelayCall::policy` documents.
        policy: plane.fetch_policy_for(&admitted.dispatch.agent_id),
        task_id: task_id.clone(),
        context_id: context_id.clone(),
        matched_skill: admitted.matched_skill.clone(),
        request_id,
        now,
        now_ms,
        // Established by the envelope reader at the top of this handler, where `null` and absent
        // were still distinguishable. It is a string or a number, never `null`.
        rpc_id,
    };

    // THE INVERSE OF THE IDENTITY SUBSTITUTION. busbar issues its own task ids and puts them in
    // every answer; a caller reading one and asking `GetTask` for it had that id forwarded, unchanged,
    // to a backend that has never heard of it. See `super::idmap`: this is the only direction that
    // was missing, and `None` - a request naming no task busbar issued - forwards the caller's OWN
    // BYTES rather than a re-serialization, so nothing else in the envelope is normalised.
    let relayed_body = super::idmap::translate_request(&envelope).unwrap_or_else(|| body.to_vec());

    if shape.requires_streaming {
        stream_hop(hop_ctx, seam, gate, lease, relayed_body).await
    } else {
        unary_hop(hop_ctx, seam, gate, lease, relayed_body).await
    }
}

/// Everything one hop needs that is neither a seam nor a secret. One struct because the two hop
/// shapes need the same eleven facts and an eleven-argument function is a function whose arguments
/// get transposed.
struct HopContext {
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
    /// THE TASK ALREADY EXISTED AND THE CALLER NAMED IT. A failing hop must not then END it: a
    /// `GetTask` that the backend refuses is a failed READ, and burning the caller's live task row
    /// for it would destroy work that is still running.
    addressed: bool,
    now: u64,
    now_ms: u64,
    rpc_id: serde_json::Value,
}

/// The plane, if this deployment has one.
fn plane_of(app: &App) -> Option<Arc<super::plane::A2aPlane>> {
    app.a2a.as_ref().map(Arc::clone)
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
) -> Response {
    let agent_id = ctx.agent_id.clone();
    let backend_url = ctx.backend_url.clone();
    let relay_policy = ctx.policy.clone();
    let now_ms = ctx.now_ms;
    // The id the hop's answer must name. `body` goes out verbatim, so the id busbar sends to the
    // backend IS this one — see `RelayCall::rpc_id`.
    let rpc_id = ctx.rpc_id.clone();
    let relayed = tokio::task::spawn_blocking(move || {
        super::relay::relay(
            &super::relay::RelayCall {
                agent_id: &agent_id,
                backend_url: &backend_url,
                lease: lease.as_ref(),
                gate: gate.as_ref(),
                body: &body,
                rpc_id: &rpc_id,
                policy: &relay_policy,
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
            tracing::error!(task = %ctx.task_id, error = %join, "a2a: the relay thread did not complete");
            return fail_task(
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
) -> Response {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);

    let task_id = ctx.task_id.clone();
    let context_id = ctx.context_id.clone();
    let matched_skill = ctx.matched_skill.clone();
    let request_id = ctx.request_id.clone();
    let agent_id = ctx.agent_id.clone();
    let backend_url = ctx.backend_url.clone();
    let relay_policy = ctx.policy.clone();
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

    // THE CURSOR RESUMES WHERE THE TASK LEFT OFF rather than at zero. On a resumed stream, starting
    // at zero would spend the first N advances re-asserting a position the store already holds —
    // harmless, because the store refuses to rewind, but it would make the cursor stop counting
    // this stream's chunks and start counting from scratch, which is the number a resubscribe reads.
    let mut cursor: u64 = super::taskstore::TASKS
        .get_unscoped(&ctx.task_id)
        .map_or(0, |t| t.artifact_cursor);
    let handle = tokio::task::spawn_blocking(move || {
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
                if let Ok(task) =
                    super::taskstore::TASKS.transition(&task_id, state, now, &request_id)
                {
                    if task.push_callback.is_some() {
                        if let Err(e) = super::pushdeliver::deliver(notify_seam.as_ref(), &task) {
                            tracing::warn!(task = %task.task_id, error = %e, "a2a: the push notification was not delivered");
                        }
                    }
                }
            }
            if ev.artifact {
                cursor = cursor.saturating_add(1);
                // The resubscribe resume point, advanced durably per chunk. Monotonic in the store,
                // so a duplicate delivery cannot rewind it.
                let _ = super::taskstore::TASKS.advance_cursor(&task_id, cursor, now, &request_id);
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
                body: &body,
                rpc_id: &rpc_id,
                policy: &relay_policy,
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
                tracing::warn!(task = %ctx.task_id, "a2a: the backend's stream carried no event");
                fail_task(
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
                tracing::error!(task = %ctx.task_id, error = %join, "a2a: the relay thread did not complete");
                fail_task(
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
    tokio::spawn(async move {
        match handle.await {
            Ok(Ok(_)) => {}
            Ok(Err(refusal)) => {
                tracing::warn!(task = %watched_task, error = %refusal, "a2a: the relayed stream ended in a refusal");
                // A BROKEN STREAM IS A TERMINAL FAILURE and the caller is told, for the same
                // reason `fail_task` tells them: silence and "still working" are the same thing to
                // a receiver, and this is the case where they are most different.
                if let Ok(task) = super::taskstore::TASKS.transition(
                    &watched_task,
                    super::task::TaskState::Failed,
                    watched_now,
                    &watched_request,
                ) {
                    notify_push(&watched_seam, task);
                }
            }
            Err(join) => {
                tracing::error!(task = %watched_task, error = %join, "a2a: the streaming relay thread did not complete");
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
        .unwrap_or_else(|_| not_found())
}

/// RECORD WHAT THE BACKEND SAID THE TASK IS NOW.
///
/// `Submitted` is skipped: it is where the task already is, and the transition table refuses a move
/// to it, so recording it would log an error for a hop that behaved.
fn record_state(ctx: &HopContext, state: super::task::TaskState) {
    if state == super::task::TaskState::Submitted {
        return;
    }
    match super::taskstore::TASKS.transition(&ctx.task_id, state, ctx.now, &ctx.request_id) {
        // THE STATE CHANGED, SO THE CALLER IS TOLD. This is the line that was missing: a caller
        // could register a push callback, have it validated, pinned and persisted, and then never
        // hear anything, because nothing on this plane ever connected to it.
        Ok(task) => notify_push(&ctx.seam, task),
        Err(e) => {
            // Reported, never fatal: the hop SUCCEEDED and the caller is owed its answer. A store
            // that refused the transition is an operator problem, not a reason to discard a
            // completed piece of work the caller has already been billed for.
            tracing::error!(task = %ctx.task_id, error = %e, "a2a: the relayed task's outcome could not be recorded");
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
fn notify_push(seam: &Arc<dyn super::relay::RelaySeam>, task: super::task::Task) {
    if task.push_callback.is_none() {
        return;
    }
    let seam = Arc::clone(seam);
    tokio::task::spawn_blocking(move || {
        let task_id = task.task_id.clone();
        match super::pushdeliver::deliver(seam.as_ref(), &task) {
            Ok(()) => tracing::debug!(task = %task_id, "a2a: push notification delivered"),
            // NEVER fatal to the task, and never retried into a hammer. The outcome is recorded and
            // the caller's poll will find it; a webhook that is down is the caller's problem to
            // read in this log line.
            Err(e) => {
                tracing::warn!(task = %task_id, error = %e, "a2a: the push notification was not delivered")
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
fn refuse_hop(ctx: &HopContext, refusal: &super::relay::RelayRefusal) -> Response {
    tracing::warn!(agent = %ctx.agent_id, task = %ctx.task_id, error = %refusal, "a2a: the relayed task submission failed");
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
                end_task(&ctx.seam, &ctx.task_id, &ctx.request_id, ctx.now);
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
                &ctx.seam,
                &ctx.rpc_id,
                &ctx.task_id,
                &ctx.request_id,
                ctx.now,
                refusal.status(),
            ),
        },
        _ => fail_task(
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
fn end_task(seam: &Arc<dyn super::relay::RelaySeam>, task_id: &str, request_id: &str, now: u64) {
    match super::taskstore::TASKS.transition(
        task_id,
        super::task::TaskState::Failed,
        now,
        request_id,
    ) {
        // A FAILURE IS A TERMINAL STATE AND THE CALLER WANTS IT MOST. A push callback that only
        // ever fired on success would leave the one case a caller actually needs to be woken for —
        // work that will never finish — as silence indistinguishable from work still in progress.
        Ok(task) => notify_push(seam, task),
        Err(e) => {
            tracing::error!(task = %task_id, error = %e, "a2a: a failed task could not be recorded as failed");
        }
    }
}

fn fail_task(
    seam: &Arc<dyn super::relay::RelaySeam>,
    rpc_id: &serde_json::Value,
    task_id: &str,
    request_id: &str,
    now: u64,
    status: u16,
) -> Response {
    end_task(seam, task_id, request_id, now);
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

/// THE CALLER'S PUSH-NOTIFICATION CALLBACK URL, if it registered one.
fn callback_of(envelope: &serde_json::Value) -> Option<String> {
    envelope
        .pointer("/params/configuration/pushNotificationConfig/url")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
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
async fn validate_callback(
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
        super::pushnotify::validate(&url, &resolved, false).map_err(|e| e.to_string())
    })
    .await
    .unwrap_or_else(|_| Err("the push callback could not be validated".to_string()))
}

/// THE TASK A REQUEST NAMES, if this caller owns one by that id.
///
/// SCOPED, through [`super::taskstore::TaskRegistry::get_scoped`], so a caller naming somebody
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
        if let Ok(task) = super::taskstore::TASKS.get_scoped(principal, named) {
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
    let mut candidates: Vec<super::task::Task> = super::taskstore::TASKS
        .list_scoped(principal)
        .into_iter()
        .filter(|t| {
            t.context_id == context_id && t.agent_id == agent_id && t.state.is_interrupted()
        })
        .collect();
    candidates.sort_by_key(|t| t.updated_at);
    candidates.pop()
}

/// The SHAPE of work an inbound envelope is asking for, as the catalogue's filter reads it.
///
/// Read from the request rather than assumed, because the catalogue's whole job is to refuse an
/// agent whose card does not declare what this call needs. An envelope that names nothing
/// constrains nothing, which is the empty shape.
fn shape_of(envelope: &serde_json::Value) -> super::catalogue::TaskShape {
    let params = envelope.get("params");
    let cfg = params.and_then(|p| p.get("configuration"));
    super::catalogue::TaskShape {
        skill: params
            .and_then(|p| p.get("metadata"))
            .and_then(|m| m.get("skill"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        // BOTH SPELLINGS OF "THIS IS A STREAM". A2A v0.3 names the streaming methods
        // `message/stream` and `tasks/resubscribe`; v1.0 renames them `SendStreamingMessage` and
        // `SubscribeToTask` — the vocabulary the official TCK and `a2a-go` v2.4 speak. busbar is
        // content-blind on this plane and relays the envelope verbatim, so the ONLY place the
        // method name is read is here, and reading only one vocabulary means a v1.0 caller's
        // stream is dispatched down the unary path and its `capabilities.streaming` filter never
        // applies. Both are listed rather than pattern-matched loosely, so a third spelling is a
        // deliberate edit.
        requires_streaming: envelope
            .get("method")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|m| {
                m.ends_with("/stream")
                    || m == "tasks/resubscribe"
                    || m == "SendStreamingMessage"
                    || m == "SubscribeToTask"
            }),
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
/// The gate is `app.a2a` plus an admission: a deployment with no `agents:` section has no plane, and
/// one with no `public_url` has no RECEIVING side. Either way NOTHING is mounted — no route in the
/// table, nothing for the auth middleware to consult, and "is this deployment an A2A server?"
/// stays a question the mounted surface answers rather than a flag somebody has to trust.
pub(crate) fn mount(
    router: crate::core_routes::CoreRouter,
    plane: Option<&Arc<super::plane::A2aPlane>>,
) -> crate::core_routes::CoreRouter {
    use busbar_plugin_loader::{RouteAuth, RouteMethod};
    let Some(plane) = plane else { return router };
    if plane.admission().is_none() {
        return router;
    }
    router
        .route(
            super::serve::METADATA_PATH,
            RouteMethod::Get,
            RouteAuth::None,
            metadata,
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
            rpc,
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
}

#[cfg(test)]
#[path = "tests/ingress_tests.rs"]
mod ingress_tests;
