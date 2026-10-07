// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PUBLIC ROUTE'S CALLER, VERIFIED UNDER THE SCHEME ITS PLANE NAMED (spec Part 3 "Inbound
//! webhooks"; ARCHITECT Q2 webhook receiver, 2026-10-06): before a door plane's `serve` answers a
//! public route that names an auth scheme (`abi::plane::AdminRoute::style`), the instances serving
//! that scheme (the App's `identity-providers:` entries, `InboundSchemes`) verify the request at the
//! `HeadBody` point, over the head and the whole body the data listener's size gate bounded; the
//! identity's replay key is claimed once (`busbar_kernel::auth::inbound`). Every denial answers 401
//! alike; an overloaded verifier 503. The lines the verifiers named are struck from the head the
//! plane is handed, so it never sees a signature, and it never sees a secret.

use axum::http::{HeaderMap, StatusCode};
use busbar_contract::abi::auth::AuthPoint;
use busbar_contract::auth_calls::{StripPlace, VerifyRequest};
use busbar_contract::redacted::Redacted;
use busbar_kernel::auth::inbound::{verify_inbound, InboundVerdict};
use busbar_kernel::plane_routes::PlaneReqCtx;

/// THE VERIFY: `ctx`'s request under `scheme`, over the generation `ctx` serves. `Ok` = the head
/// the plane is handed (the verifiers' lines struck); `Err` = the status the caller is answered.
pub async fn verified(scheme: &str, ctx: &PlaneReqCtx) -> Result<HeaderMap, StatusCode> {
    let Some(app) = ctx
        .engine
        .downcast_ref::<busbar_kernel::state::AppHandle>()
        .map(busbar_kernel::state::AppHandle::load)
    else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    let instances = app.inbound_schemes.instances(scheme);
    let now = busbar_kernel::store::now();
    let request = VerifyRequest {
        point: AuthPoint::HeadBody,
        conn: 0,
        unit: 0,
        credential: None,
        lines: ctx
            .headers
            .iter()
            .map(|(n, v)| (n.as_str().to_string(), Redacted::new(v.as_bytes().to_vec())))
            .collect(),
        peer: None,
        body: Some(ctx.body.to_vec()),
        method: ctx.method.as_str().to_string(),
        authority: ctx
            .headers
            .get(axum::http::header::HOST)
            .and_then(|h| h.to_str().ok())
            .unwrap_or_default()
            .to_string(),
        path: ctx.uri.path().to_string(),
        query: ctx.uri.query().map(str::to_string),
        timestamp: now,
    };
    let store = app.governance.as_ref().map(|g| g.store());
    match verify_inbound(&instances, &request, store.as_deref(), now).await {
        InboundVerdict::Identified { strips, .. } => {
            let mut head = ctx.headers.clone();
            for strip in strips.iter().filter(|s| s.place == StripPlace::Field) {
                head.remove(strip.name.as_ref());
            }
            Ok(head)
        }
        InboundVerdict::Denied => Err(StatusCode::UNAUTHORIZED),
        InboundVerdict::Overloaded => Err(StatusCode::SERVICE_UNAVAILABLE),
    }
}

/// THE CONFIGURATION'S ANSWER for every public route the served planes state: a scheme no
/// `identity-providers:` instance serves is refused at boot, naming the plane's route and the
/// scheme, never served unverified.
///
/// # Errors
///
/// The first route whose scheme nothing serves.
pub fn refuse_unserved(
    served: &crate::root::serve::Served,
    providers: &busbar_kernel::config::IdentityProviders,
) -> Result<(), String> {
    for plane in &served.planes {
        for route in plane
            .snapshot
            .admin_routes
            .iter()
            .filter(|r| !r.style.is_empty())
        {
            if !busbar_kernel::auth::inbound::configured(providers, &route.style) {
                return Err(format!(
                    "{}: its public route {} {} is verified under the auth scheme '{}', and no \
                     `identity-providers:` entry serves it (configure one whose module is \
                     `busbar-auth-{}`, its secret by reference)",
                    plane.instance, route.verb, route.target, route.style, route.style
                ));
            }
        }
    }
    Ok(())
}
