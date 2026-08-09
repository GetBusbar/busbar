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

        match matched {
            Some(matched_skill) => Ok(Admitted {
                dispatch,
                matched_skill,
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
/// Admits, catalogues, opens a durable task, meters the call against the presenting key and audits
/// it. What it does NOT do is relay the body to the backend: see the module's own note in
/// `a2a/mod.rs` about which half of this plane is mounted.
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

    // WHO IS BILLED, recorded as this plane's own statement rather than inferred later. Receiving
    // covers the downstream L2 spend this call causes and never the callee's internal spend — a
    // distinction `Attribution` makes unconstructible rather than documented.
    let task_id = format!(
        "a2a-{}-{}",
        admitted.dispatch.agent_id,
        uuid_like(&body, now)
    );
    let context_id = if context_id.is_empty() {
        task_id.clone()
    } else {
        context_id.to_string()
    };
    let attribution = super::meter::Attribution::receiving(
        &admitted.dispatch.billed_key_id,
        &admitted.dispatch.agent_id,
        &context_id,
        &task_id,
    );

    // 4. DISPATCH, recorded durably. The task and its provenance chain are opened BEFORE the
    //    outcome is known, which is the point: a task that ends by the process dying still has a
    //    row saying it was submitted and to whom it was dispatched.
    let request_id = task_id.clone();
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
    let _ = super::taskstore::TASKS.record_dispatch(
        &task_id,
        &admitted.dispatch.agent_id,
        now,
        &request_id,
    );

    gov_state.record_metering(
        &attribution.billed_key_id,
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

    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": envelope.get("id").cloned().unwrap_or(serde_json::Value::Null),
            "result": {
                "id": task_id,
                "contextId": context_id,
                "status": { "state": super::task::TaskState::Submitted.as_str() },
                "kind": "task",
                "skill": admitted.matched_skill,
            }
        })),
    )
        .into_response()
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
    let mut h = std::collections::hash_map::DefaultHasher::new();
    body.hash(&mut h);
    now.hash(&mut h);
    std::sync::atomic::AtomicU64::new(0).as_ptr().hash(&mut h);
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
