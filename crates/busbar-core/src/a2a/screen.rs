// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE A2A FRONT DOOR'S HOOK SCREENING — the operator's tap and the operator's gate, at one point,
//! off one subject.
//!
//! ## Why this is a module and not eight lines in `receive.rs`
//!
//! It became a UNIT the moment the tap joined the gate here. Before that there was one control with
//! one branch; now there are two controls that must agree, by construction, about WHAT THE REQUEST
//! WAS — a tap that saw a different projection from the gate's would be an audit record of a
//! request nobody screened. The way to make them unable to disagree is to build the subject ONCE
//! and hand the same borrow to both, and a shared construction with two consumers is a function.
//!
//! It also keeps `receive.rs` under the impl-file cap that `scripts/structure-lint.sh` enforces,
//! which is the same argument one level down: the front door's job is to admit, meter and relay,
//! and the screening step is a thing it CALLS rather than a thing it contains.
//!
//! ## The ordering, which is the load-bearing part
//!
//! Called AFTER admission (the agent is what an attach is keyed on, so there is nothing to look up
//! before it) and BEFORE the meter, the egress gate, the callback guard and the task row.
//! Everything after it either spends the caller's budget, leases busbar's own credential, or mints
//! durable state; a refusal must cost none of them.
//!
//! The TAP fires BEFORE the verdict, so an audit tap sees the submissions that were REFUSED as well
//! as the ones that were relayed. It is spawned detached and can affect neither the verdict nor the
//! answer.
//!
//! EVERY VERB, not only `message/send`. A gate an operator attached to an agent is a statement
//! about that agent, and a plane that fired it for submissions but not for the task verbs would be
//! a plane where the control's scope depends on which method a caller happened to use.

use axum::response::{IntoResponse, Response};

use crate::state::App;

/// Run the front door's taps and gate over one submission.
///
/// Returns `Some(response)` ONLY when a gate refused, in which case the caller must return it
/// unchanged and do nothing else. `None` means "not refused" — it does not mean "no hook ran".
pub(super) async fn screen_the_submission(
    app: &App,
    envelope: &serde_json::Value,
    agent_id: &str,
    key: &busbar_api::VirtualKey,
    rpc_id: &serde_json::Value,
    resource: &str,
    actor: &str,
) -> Option<Response> {
    let attached_gates = app.a2a_agent_gates.get(agent_id);
    if attached_gates.is_none() && app.tap_hooks.is_empty() {
        return None;
    }

    // THE A2A SUBMISSION AS THE INVOKE IR: a caller names a target and hands it arguments, which is
    // what `ir::invoke` says it carries (`it carries A2A message/send alongside MCP tools/call`).
    // The target is the METHOD and the arguments are `params` — which is where a message's `parts`
    // live, so the prose a screening gate exists to read is inside the projection rather than
    // summarised beside it.
    let facts = crate::ir::invoke::InvokeReq {
        tool: super::local::method_of(envelope).to_string(),
        arguments: envelope
            .get("params")
            .cloned()
            .unwrap_or(serde_json::Value::Null),
        extra: Default::default(),
    };
    // ONE subject, TWO consumers — see the module header. The tap is shown the projection the gate
    // is shown, built by the same function from the same `IrFacts`.
    let subject = crate::hooks::subject::RequestSubject {
        facts: &facts,
        container: agent_id,
        ingress_protocol: crate::plane::Plane::A2a.key(),
        request_id: app.next_request_id(),
        key: Some(key),
    };
    crate::hooks::tap::fire(
        &app.tap_hooks,
        &subject,
        key.group.as_deref(),
        &app.groups_registry,
    );

    let gates = attached_gates?;
    let crate::hooks::gate::GateVerdict::Reject {
        status,
        message,
        hook,
    } = crate::hooks::gate::decide(gates, &subject).await
    else {
        return None;
    };

    crate::admin::audit::AUDIT.record_by(
        super::receive::AUDIT_ACTION,
        resource,
        crate::admin::audit::OUTCOME_REJECTED,
        actor,
    );
    tracing::info!(
        agent = %agent_id,
        hook,
        status,
        "a2a submission refused by a hook gate"
    );
    // THE HOOK'S STATUS, IN THIS PLANE'S ERROR VOCABULARY. A2A section 5.4 binds a JSON-RPC code
    // and a ProtoJSON body to every refusal, and a body in another plane's shape is a body the TCK
    // rejects by schema — so the code stays `UnsupportedOperation` (this plane's binding for
    // "busbar will not do this for you") and carries the hook's own message, while the HTTP status
    // is the gate's clamped one. Exactly what the egress gate does with its own refusal.
    Some(
        (
            axum::http::StatusCode::from_u16(status).unwrap_or(axum::http::StatusCode::FORBIDDEN),
            axum::Json(super::rpcerror::body(
                rpc_id,
                super::rpcerror::A2aError::UnsupportedOperation,
                message,
            )),
        )
            .into_response(),
    )
}
