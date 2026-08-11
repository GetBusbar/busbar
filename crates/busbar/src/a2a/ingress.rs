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
    let status = axum::http::StatusCode::from_u16(refusal.status())
        .unwrap_or(axum::http::StatusCode::FORBIDDEN);
    (
        status,
        axum::Json(serde_json::json!({
            "error": { "code": "refused", "message": refusal.to_string() }
        })),
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
    (
        axum::http::StatusCode::NOT_FOUND,
        axum::Json(serde_json::json!({ "error": { "code": "not_found" } })),
    )
        .into_response()
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
                        axum::Json(serde_json::json!({
                            "error": { "code": "refused", "message": reason }
                        })),
                    )
                        .into_response(),
                ))
            }
        }
    })
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
        axum::Json(serde_json::json!({
            "error": {
                "code": "unavailable",
                "message": "the A2A plane requires governance: an inbound caller is admitted by \
                            its key's `agent` scopes, and there are no keys here"
            }
        })),
    )
        .into_response()
}

/// `agents:` configured for the DELEGATING direction alone — no `public_url`, so no receiving side.
fn no_receiving_side() -> Response {
    (
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        axum::Json(serde_json::json!({
            "error": {
                "code": "unavailable",
                "message": "this deployment fronts agents for delegation only: it has no \
                            `public_url`, so it serves no inbound A2A surface"
            }
        })),
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
    body: axum::body::Bytes,
) -> Response {
    if app.a2a.is_none() {
        return not_found();
    }
    let Some(key) = gov.key.as_ref() else {
        return governance_required();
    };
    let now = crate::store::now();

    let Ok(envelope) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({
                "error": { "code": "invalid_request", "message": "the request body is not JSON" }
            })),
        )
            .into_response();
    };
    let shape = shape_of(&envelope);
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
                axum::Json(serde_json::json!({
                    "error": { "code": "budget_exhausted", "message": "this key's budget is spent" }
                })),
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
                axum::Json(serde_json::json!({
                    "error": { "code": "refused", "message": e.to_string() }
                })),
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
                    return (
                        axum::http::StatusCode::BAD_REQUEST,
                        axum::Json(serde_json::json!({
                            "error": { "code": "invalid_request", "message": message }
                        })),
                    )
                        .into_response();
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
    let resumed = if context_id.is_empty() {
        None
    } else {
        resumable_task(
            &admitted.dispatch.billed_key_id,
            context_id,
            &admitted.dispatch.agent_id,
        )
    };

    let (task_id, context_id, is_resume) = match &resumed {
        Some(t) => (t.task_id.clone(), t.context_id.clone(), true),
        None => {
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
                axum::Json(serde_json::json!({
                    "error": { "code": "conflict", "message": "this task cannot be resumed" }
                })),
            )
                .into_response();
        }
    } else {
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
                axum::Json(serde_json::json!({
                    "error": { "code": "unavailable", "message": "the task could not be recorded" }
                })),
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
                return fail_task(&seam, &task_id, &request_id, now, 502, "upstream_error");
            }
        },
        None => None,
    };

    let hop_ctx = HopContext {
        seam: Arc::clone(&seam),
        agent_id: admitted.dispatch.agent_id.clone(),
        backend_url: admitted.dispatch.backend_url.clone(),
        task_id: task_id.clone(),
        context_id: context_id.clone(),
        matched_skill: admitted.matched_skill.clone(),
        request_id,
        now,
        now_ms,
        rpc_id: envelope
            .get("id")
            .cloned()
            .unwrap_or(serde_json::Value::Null),
    };

    if shape.requires_streaming {
        stream_hop(hop_ctx, seam, gate, lease, body.to_vec()).await
    } else {
        unary_hop(hop_ctx, seam, gate, lease, body.to_vec()).await
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
    task_id: String,
    context_id: String,
    matched_skill: Option<String>,
    request_id: String,
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
    let now_ms = ctx.now_ms;
    let relayed = tokio::task::spawn_blocking(move || {
        super::relay::relay(
            &super::relay::RelayCall {
                agent_id: &agent_id,
                backend_url: &backend_url,
                lease: lease.as_ref(),
                gate: gate.as_ref(),
                body: &body,
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
                &ctx.task_id,
                &ctx.request_id,
                ctx.now,
                502,
                "upstream_error",
            );
        }
    };

    record_state(&ctx, reply.reported_state);

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
    let now = ctx.now;
    let now_ms = ctx.now_ms;
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
            if tx.blocking_send(ev.sse).is_err() {
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
                    &ctx.task_id,
                    &ctx.request_id,
                    ctx.now,
                    502,
                    "upstream_error",
                )
            }
            Ok(Err(refusal)) => refuse_hop(&ctx, &refusal),
            Err(join) => {
                tracing::error!(task = %ctx.task_id, error = %join, "a2a: the relay thread did not complete");
                fail_task(
                    &ctx.seam,
                    &ctx.task_id,
                    &ctx.request_id,
                    ctx.now,
                    502,
                    "upstream_error",
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
    match refusal {
        super::relay::RelayRefusal::Demoted(_) => (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({
                "error": {
                    "code": "unavailable",
                    "message": "this agent is not currently serving",
                    "taskId": ctx.task_id,
                }
            })),
        )
            .into_response(),
        _ => fail_task(
            &ctx.seam,
            &ctx.task_id,
            &ctx.request_id,
            ctx.now,
            refusal.status(),
            "upstream_error",
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
fn fail_task(
    seam: &Arc<dyn super::relay::RelaySeam>,
    task_id: &str,
    request_id: &str,
    now: u64,
    status: u16,
    code: &'static str,
) -> Response {
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
    (
        axum::http::StatusCode::from_u16(status).unwrap_or(axum::http::StatusCode::BAD_GATEWAY),
        axum::Json(serde_json::json!({
            "error": {
                "code": code,
                "message": "the backend agent did not complete this task",
                "taskId": task_id,
            }
        })),
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
        requires_streaming: envelope
            .get("method")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|m| m.ends_with("/stream")),
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
}

#[cfg(test)]
#[path = "tests/ingress_tests.rs"]
mod ingress_tests;
