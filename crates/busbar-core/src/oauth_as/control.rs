// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OAUTH 2.1 CONTROL SURFACE'S REGISTRATION — the pairing of a declared route
//! table with the bodies behind it.
//!
//! ## Why this lives in `busbar-core` and not in the composition root
//!
//! It was written in the root, which is where it belongs: the root is the one place entitled to
//! name both a control crate's declaration and the neutral seam the node mounts it through. It is
//! HERE instead for one reason, and the reason is that there must be exactly ONE copy of this
//! translation. `busbar-core`'s own mount proof (`tests/mount_tests.rs`) builds a route table and
//! subtracts one from another, so it needs the decl too — and core cannot name the root. A second
//! copy written for the proof would be the drift this file's own tests exist to catch: the proof
//! would go green against a translation nothing serves.
//!
//! So it sits beside the OTHER transitional edge core still carries (the `oauth_as:` config
//! lowering, see this module's root), and moves to the root WITH it. The root still makes the
//! MOUNT DECISION — `main::register_control_surfaces` is the one write into the control axis, and a
//! build that does not make it serves no authorization server. See
//! docs/design/control-oauth2.md's staging section.
//!
//! ## Why the declaration is not in the surface crate
//!
//! `busbar-plane-mcp` and its siblings carry their own `PLANE_DECL`, because a plane may name
//! `busbar-substrate` — that is its row in `PLUGIN-TREE.md` §4. A CONTROL surface may not: its row
//! is `busbar-contract` and the crates of its own protocol, and nothing else. So
//! `busbar-control-oauth2` declares its routes in its own vocabulary
//! ([`busbar_control_oauth2::claims::ROUTES`] — an endpoint, a method, a bar and which body runs it,
//! all four as values) and this file is what translates that declaration into the neutral seam the
//! node mounts through. The composition root is the one place entitled to name both.
//!
//! Nothing here decides anything. Every path comes from the surface's own
//! [`busbar_control_oauth2::claims::Endpoint::path_of`], every method and every bar from the
//! surface's own row. If this file and the surface ever disagree about a route, this file is wrong.

use std::sync::Arc;

use busbar_control_oauth2::claims::{Bar, ControlRoute, Handler, Method, ROUTES};
use busbar_control_oauth2::{ControlRequest, OAuth2Control};
use busbar_substrate::control_routes::{ControlDecl, ControlReqCtx, ControlRouteSpec};

/// THE REGISTRATION. Installed by `main::register_control_surfaces`, read by the node's mount loop.
pub static CONTROL_DECL: ControlDecl = ControlDecl {
    key: busbar_control_oauth2::meta::KEY,
    routes: oauth2_routes,
};

/// Translate the surface's DECLARED table into the neutral one, against this generation's surface.
///
/// The `expect` is sound and is not a shortcut: a slot is only ever inserted under this decl's key
/// by the one line that builds this surface, so a slot of another type here would be a wiring bug in
/// the node rather than anything an operator or a request can cause — and a silent `return vec![]`
/// would answer it by serving no authorization server at all, which is the failure that looks like a
/// working deployment.
fn oauth2_routes(slot: &dyn std::any::Any) -> Vec<ControlRouteSpec> {
    let surface = slot
        .downcast_ref::<OAuth2Control>()
        .expect("the oauth2 control slot holds an OAuth2Control");
    let identity = surface.identity();
    ROUTES
        .iter()
        .map(|route| ControlRouteSpec {
            path: route.endpoint.path_of(identity).to_string(),
            method: method_of(route),
            auth: auth_of(route),
            handler: handler_of(route),
        })
        .collect()
}

/// The declared method, in the node's vocabulary. A total match rather than a fallback arm: a method
/// added to the surface's enum is a compile error here, which is the only way the two tables stay
/// one table.
fn method_of(route: &ControlRoute) -> busbar_plugin_loader::RouteMethod {
    match route.method {
        Method::Get => busbar_plugin_loader::RouteMethod::Get,
        Method::Post => busbar_plugin_loader::RouteMethod::Post,
    }
}

/// The declared bar, in the node's vocabulary — and this is the security-critical line of the file.
///
/// [`Bar::Operator`] becomes `RouteAuth::Admin`, which is what puts the consent screen behind the
/// node's EXISTING admin chain, enforced by the auth middleware before the body runs. It was
/// `RouteAuth::Admin` when the mount lived in `busbar-core`, and the whole point of mounting a
/// control route through the same `CoreRouter::route` call a plane route uses is that this row is
/// recorded identically. Total match, for the same reason as [`method_of`].
fn auth_of(route: &ControlRoute) -> busbar_plugin_loader::RouteAuth {
    match route.bar {
        Bar::Open => busbar_plugin_loader::RouteAuth::None,
        Bar::Operator => busbar_plugin_loader::RouteAuth::Admin,
    }
}

/// Wire the declared body. The three arms are the three bodies `busbar-control-oauth2` exposes;
/// nothing else in the process may be reached from a control route.
fn handler_of(route: &ControlRoute) -> busbar_substrate::control_routes::ControlRouteFn {
    match route.handler {
        Handler::Forward => {
            let declared = route.method;
            Arc::new(move |ctx: ControlReqCtx| {
                let (surface, request) = split(ctx);
                Box::pin(async move {
                    busbar_control_oauth2::routes::forward(&surface, declared, request).await
                })
            })
        }
        Handler::ConsentScreen => Arc::new(|ctx: ControlReqCtx| {
            let (surface, request) = split(ctx);
            Box::pin(async move {
                busbar_control_oauth2::routes::consent_screen(&surface, request).await
            })
        }),
        Handler::ConsentSubmit => Arc::new(|ctx: ControlReqCtx| {
            let (surface, request) = split(ctx);
            Box::pin(async move {
                busbar_control_oauth2::routes::consent_submit(&surface, request).await
            })
        }),
    }
}

/// The neutral per-request context, split into the surface and the request the bodies take.
///
/// The `Arc` is cloned rather than borrowed because the body is awaited inside a `'static` future;
/// the downcast carries the same `expect` as [`oauth2_routes`] and for the same reason.
fn split(ctx: ControlReqCtx) -> (Arc<OAuth2Control>, ControlRequest) {
    let surface = ctx
        .surface
        .downcast::<OAuth2Control>()
        .expect("the oauth2 control slot holds an OAuth2Control");
    (
        surface,
        ControlRequest {
            uri: ctx.uri,
            headers: ctx.headers,
            body: ctx.body,
        },
    )
}

#[cfg(test)]
#[path = "tests/control_tests.rs"]
mod tests;
