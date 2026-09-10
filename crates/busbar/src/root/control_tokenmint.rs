// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OAUTH ISSUER'S REGISTRY ROW — the composition's one line that mounts
//! `busbar-control-tokenmint`, the CONTROL-kind crate that used to be `busbar_core::oauth_as`.
//!
//! ## Why the row is here and not in the crate
//!
//! Every other registry row lives in the crate it declares (`busbar_mcp::PLANE_DECL`,
//! `busbar_voice::PLANE_DECL`), because a plane crate may name the substrate. A CONTROL crate may
//! not: `busbar-control-tokenmint`'s only busbar edge is `busbar-contract`, which is what
//! `kind-isolation` measures and what makes the crate reviewable as one thing. So the ROW —
//! the part that names `busbar_substrate::plane::registry::PlaneDecl`, `PlaneRouteSpec`,
//! `RouteAuth` — lives in the composition, which is allowed to name everything. The crate declares
//! its surface as DATA (`claims::ROUTES`), and this file translates that data into the neutral
//! route seam. Adding a route is a row in the crate's table; this file does not change.
//!
//! ## What crosses, and what does not
//!
//! `build` reads two NAMELESS slots off [`BuildCtx`] — the row's resolved section and the secret
//! that section named, already resolved — and nothing else about the deployment. It reads
//! `mcp_slot` for one further fact: the RFC 8707 `allowed_resources` list is busbar's OWN protected
//! resources, read back through the MCP row's `admission` seam exactly as `appbuild` used to read
//! it, so a token this server mints carries an `aud` this deployment actually protects rather than
//! whatever `resource` a client asked for.
//!
//! ## The bars are the legacy bars, by translation and not by retyping
//!
//! `Bar::Open` is `RouteAuth::None` and `Bar::Operator` is `RouteAuth::Admin` — the two values the
//! deleted `oauth_as::routes::mount` declared, mapped in one `match` so a third bar is a compile
//! error rather than a silently-open route. The `CoreRouteTable` row each spec records is the row
//! the old mount recorded, which is what the byte-identity judge
//! (`crates/busbar/tests/oauth_issuer_byte_identity.rs`) pins.

use std::any::Any;
use std::sync::Arc;

use busbar_control_tokenmint::claims::{Bar, Method, Route, ROUTES};
use busbar_control_tokenmint::config::Identity;
use busbar_control_tokenmint::TokenMint;
use busbar_plugin_loader::{RouteAuth, RouteMethod};
use busbar_substrate::plane::registry::{BuildCtx, PlaneDecl};
use busbar_substrate::plane_routes::{PlaneReqCtx, PlaneResponse, PlaneRouteSpec};

/// The registry key this row installs under, and the `oauth_as:` section that declares it.
const KEY: &str = "tokenmint";

/// THE ROW. Pushed in `register_planes()` exactly as the a2a / mcp / voice rows join.
///
/// Every plane-shaped field is the neutral absence a control surface declares: it claims no plane
/// path (`claims`), binds no audience (`admission`), speaks no wire format the plane axis names,
/// runs no boot hook and owns no config section (core still parses `oauth_as:`; the section's move
/// into the crate's own grammar is the step this row's `resolved_section` slot makes possible).
/// What it does declare is a SLOT and a ROUTE TABLE — which is the whole of what an unmetered
/// served surface is.
pub static PLANE_DECL: PlaneDecl = PlaneDecl {
    key: KEY,
    fallback: false,
    config_section: "oauth_as",
    // An authorization server grants nothing on busbar's own scope axis: what it grants is an OAuth
    // scope, to an OAuth client, and that vocabulary is the crate's.
    scope_kinds: &[],
    subject_noun: "authorization request",
    admin_noun: "authorization-request",
    audit_kind: "authorization_request",
    wire_format_names: || &[],
    // No plane claim: the routes below are DECLARED paths, not a plane door, so nothing here enters
    // the cross-plane claim seal and nothing here can overlap a plane's mount.
    claims: |_slot| Vec::new(),
    admission: |_slot| None,
    build: build_slot,
    routes: Some(routes),
    admin_routes: None,
    openapi: None,
    hydrate: None,
    start: None,
    config_validate: None,
    card_signing_domain: None,
    card_kid_prefix: None,
    named_def_list: None,
    named_def_get: None,
    registry_contains: None,
    reresolve_gates: None,
    #[cfg(feature = "openapi-schema")]
    openapi_schemas: None,
    on_swap: None,
    parse_section: None,
    parse_endpoint: None,
    lower_endpoint: None,
    build_runtime: None,
    viewer: None,
    retain_verify_gates: None,
    default_section: None,
    owned_config_sections: &[],
};

/// BUILD THE SURFACE for one config generation, or build nothing.
///
/// `None` is the zero-cost-when-off property, unchanged from the legacy `Option<AsPlane>`: no
/// server object, no store, no signing key, no sweeper — and, because `routes` is only consulted
/// for a row that produced a slot, no route and no `CoreRouteTable` entry either.
///
/// A refusal here is a PANIC and not a swallowed `None`, for the same reason the legacy path
/// returned a boot error: an authorization server that is half-configured ANSWERS, and what it
/// answers with is tokens. The slot seam has no error channel, so the refusal is taken where it
/// can still be seen — at boot, before a listener is bound.
fn build_slot(ctx: &BuildCtx) -> Option<Arc<dyn Any + Send + Sync>> {
    // The composition's own validated identity, crossing the seam type-erased. Mapped field for
    // field into the crate's `Identity` HERE, in the composition, because the crate's grammar is
    // the crate's: core derives it today (`oauth_as::config`), the crate derives it once the
    // section's parse moves through `parse_section`, and this row is the one place that knows both
    // spellings. Every value is carried, none is re-derived — a second derivation is a second
    // chance to disagree about a path a client has already discovered.
    let derived = ctx
        .resolved_section
        .and_then(<dyn Any>::downcast_ref::<busbar_core::oauth_as::config::AsIdentity>)?;
    let identity = Identity {
        issuer: derived.issuer.clone(),
        issuer_path: derived.issuer_path.clone(),
        metadata_path: derived.metadata_path.clone(),
        authorize_path: derived.authorize_path.clone(),
        token_path: derived.token_path.clone(),
        register_path: derived.register_path.clone(),
        jwks_path: derived.jwks_path.clone(),
        consent_path: derived.consent_path.clone(),
        default_grant: derived.default_grant.clone(),
        access_token_ttl: derived.access_token_ttl,
        key_id: derived.key_id.clone(),
    };
    // busbar's OWN protected resource is its MCP endpoint's canonical URI, read back through the
    // MCP row's `admission` seam — a `PlaneAdmission::audience` IS that canonical URI — so this row
    // names no MCP resource type. Empty when `mcp:` is absent or the MCP plane is compiled out.
    let protected_resources: Vec<String> = ctx
        .mcp_slot
        .as_ref()
        .and_then(|slot| {
            busbar_core::plane::registry::plane_decl_for_config_section(
                busbar_substrate::plane::config::NAMED_MAP_SECTIONS[2],
            )
            .and_then(|d| (d.admission)(slot.as_ref()))
        })
        .map(|adm| adm.audience)
        .into_iter()
        .collect();
    let surface = TokenMint::build(
        identity,
        ctx.resolved_secret,
        protected_resources,
        Arc::new(crate::root::control_tokenmint_fetch::GuardedFetch),
    )
    .unwrap_or_else(|e| panic!("oauth_as: {e}"));
    let surface = Arc::new(surface);
    // `Storage::sweep_expired` is the only thing that reclaims anything in `oauth-as`, and it runs
    // when it is called and never otherwise. Spawned here, once per generation — the same act, at
    // the same point of the boot, that `appbuild` used to perform by name.
    // The sweeper's FAULT SEAM. The crate reports the fault and the transition; the composition
    // decides what a fault IS on this node — which is the registered `OAUTH_AS_SWEEP_FAILED`
    // diagnostic an operator greps for, warned on the transition into the failing state and held at
    // debug on every tick after it, in the legacy handler's exact words.
    busbar_control_tokenmint::spawn_sweeper(
        Arc::clone(surface.server()),
        std::time::Duration::from_secs(60),
        Arc::new(|fault: busbar_control_tokenmint::SweepFault| {
            if fault.first {
                busbar_core::diag_warn!(
                    busbar_substrate_values::diagnostics::OAUTH_AS_SWEEP_FAILED,
                    error = %fault.error,
                    "oauth_as: sweeping expired records failed; retrying on the next tick"
                );
            } else {
                busbar_core::diag_debug!(
                    busbar_substrate_values::diagnostics::OAUTH_AS_SWEEP_FAILED,
                    error = %fault.error,
                    "oauth_as: sweeping expired records failed; retrying on the next tick"
                );
            }
        }),
    );
    Some(Arc::new(Slot(surface)))
}

/// THE SLOT'S TYPE, and it is a newtype rather than the surface itself for a reason worth one line:
/// the fold erases what `build` returns as `Arc<dyn Any>`, so a slot holding the surface DIRECTLY
/// hands `routes` a `&TokenMint` it cannot get an `Arc` back out of — and the per-request handler
/// closure has to own one. Holding the `Arc` inside a newtype keeps the one surface one object,
/// shared by every route, rather than the seam forcing a second.
struct Slot(Arc<TokenMint>);

/// TRANSLATE THE CRATE'S DECLARED TABLE into the neutral route seam — one spec per row of
/// `claims::ROUTES`, in the crate's own mount order, so a boot listing reads as it did.
fn routes(slot: &dyn Any) -> Vec<PlaneRouteSpec> {
    // A PANIC AND NOT AN EMPTY VEC. `routes` is only called for a key that produced a slot, and this
    // row is the only thing that puts one under that key — so a failed downcast is this file
    // disagreeing with itself. Returning no routes there leaves the issuer's seven paths unclaimed
    // and lets the protocol catch-all answer them 401, which is a silent mis-mount indistinguishable
    // from a deployment that is not an authorization server. It cost this rebuild one judge run.
    let slot = slot
        .downcast_ref::<Slot>()
        .expect("the issuer's slot is what this row's own `build` put there");
    ROUTES.iter().map(|route| spec_of(route, &slot.0)).collect()
}

/// One declared row, as one `PlaneRouteSpec`.
fn spec_of(route: &'static Route, surface: &Arc<TokenMint>) -> PlaneRouteSpec {
    let surface = Arc::clone(surface);
    let handler = route.handler;
    PlaneRouteSpec {
        path: route.path_of(surface.identity()),
        method: match route.method {
            Method::Get => RouteMethod::Get,
            Method::Post => RouteMethod::Post,
        },
        // The two bars the deleted mount declared, mapped in one `match`: a third bar is a compile
        // error here rather than a route that quietly opens.
        auth: match route.bar {
            Bar::Open => RouteAuth::None,
            Bar::Operator => RouteAuth::Admin,
        },
        handler: Arc::new(move |ctx: PlaneReqCtx| {
            let surface = Arc::clone(&surface);
            Box::pin(async move { answer(&surface, handler, ctx).await })
        }),
    }
}

/// Rebuild the crate's neutral `Request` from what the adapter parsed, answer, and frame.
///
/// The four values the crate reads — method, URI, headers, body — are the four the old typed
/// handler's `axum::extract::Request` carried, in the same bytes: the adapter buffered the body
/// under the SAME router body-size cap layer, and the URI is path + query exactly as it arrived.
async fn answer(
    surface: &TokenMint,
    handler: busbar_control_tokenmint::claims::Handler,
    ctx: PlaneReqCtx,
) -> PlaneResponse {
    let mut request = http::Request::builder()
        .method(match ctx.method {
            RouteMethod::Get => http::Method::GET,
            RouteMethod::Post => http::Method::POST,
            other => {
                // Unreachable: the two methods above are the only ones the table declares, and the
                // adapter mounts a route per declared method.
                debug_assert!(
                    false,
                    "the issuer declares GET and POST only, not {other:?}"
                );
                http::Method::GET
            }
        })
        .uri(ctx.uri.clone())
        .body(ctx.body.clone())
        .expect("method, uri and a buffered body always build a request");
    *request.headers_mut() = ctx.headers.clone();
    let response = surface.answer(handler, request).await;
    let (parts, body) = response.into_parts();
    let mut out = axum::response::Response::new(axum::body::Body::from(body));
    *out.status_mut() = parts.status;
    *out.version_mut() = parts.version;
    *out.headers_mut() = parts.headers;
    *out.extensions_mut() = parts.extensions;
    out
}
