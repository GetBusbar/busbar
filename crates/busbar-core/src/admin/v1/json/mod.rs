// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The JSON-REST adapter for Admin API **v1** — mounts `/api/v1/admin/*`.
//!
//! The version-specific WIRE layer for the JSON transport: it declares the v1 routes, owns the v1 JSON
//! envelope helpers, and maps each route to a shared `AdminService` call. It holds NO operation logic
//! — logic lives in `super::service`, the frozen types in `super::contract`. A GraphQL adapter for v1
//! is a sibling `super::graphql` over the SAME service. Releasing v2 copies the whole `v1/` directory
//! to `v2/`, changes only what differs, and mounts `/admin/v2/*` alongside; v1 keeps answering.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{header::CONTENT_TYPE, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post};
use axum::{extract::Path, extract::Query, Router};
use serde::Serialize;
use serde_json::json;

use super::contract::taxonomy::Cond;
use super::contract::{
    AdminError, PATH_ADMIN_AUTH, PATH_CONFIG_VALIDATE, PATH_GROUPS, PATH_HOOKS,
    PATH_PLUGINS_INSPECT,
};
use super::service::{
    build_with_group, build_with_hook, build_with_registry, build_without_group,
    build_without_hook, AdminService,
};
use crate::admin::audit;
use crate::admin::transport::AdminTransport;
use crate::state::AppHandle;

/// The JSON-REST adapter for v1: the `/api/v1/admin/*` resource API with the stable
/// `{"error":{"code","message"}}` envelope. Zero-sized — each request
/// builds an `AdminService` over the CURRENT snapshot from the router's `Arc<AppHandle>` state (so a
/// read after a config apply reflects the new config), and the mutation path swaps through the handle.
pub(crate) struct JsonV1;

impl AdminTransport for JsonV1 {
    fn name(&self) -> &'static str {
        "json/v1"
    }

    fn version(&self) -> &'static str {
        "v1"
    }

    fn area(&self) -> &'static str {
        "admin"
    }

    fn router(&self) -> Router<Arc<AppHandle>> {
        // Routes are RELATIVE — `admin::transport::mount` nests this router under the computed
        // `/api/<version>/<area>` prefix (the algorithmic mount grammar), so no path here can drift
        // from `contract::ADMIN_PREFIX`. Each handler pulls the `Arc<AppHandle>` state, loads the
        // current snapshot into a per-request `AdminService`, and maps the typed result onto the
        // JSON wire.
        #[cfg_attr(not(test), allow(clippy::let_and_return))]
        let router = Router::new()
            .route("/info", get(info))
            .route("/pools", get(list_pools))
            .route("/pools/{name}", get(get_pool))
            .route("/models", get(list_models))
            .route("/providers", get(list_providers))
            .route(PATH_HOOKS, get(list_hooks).post(register_hook))
            .route(
                "/hooks/{name}",
                get(get_hook).put(put_hook).delete(delete_hook),
            )
            .route("/hooks/{name}/health", get(hook_health))
            .route("/hooks/{name}/settings", patch(patch_hook_settings))
            .route("/hooks/{name}/schema", get(hook_schema))
            .route("/hooks/{name}/status", get(hook_status))
            // The 1.5.3 named-DEFINITION maps, mounted in ONE loop over `NamedMapSection::ALL` so
            // the admin surface mirrors the config grammar and a future section is additive.
            .merge(named_map::routes());
        // THE PLANES' TRUST VERBS, contributed through the registry rather than named here: the
        // operator verbs a plane adds ON TOP of its generic named-definition CRUD (MCP's
        // `connect`/`changes`/`health`, A2A's `connect`/`approve`). Each plane's `admin_routes`
        // owns the operator's standing decision about the upstream behind a registration; the
        // generic handler still owns the DEFINITION. Merged in DECLARATION ORDER (MCP before A2A),
        // so the two planes' operator surfaces are read together and the route order is stable.
        // Without these the `agents:`/`tools:` surfaces are CRUD only and no sequence of operator
        // actions can make a fronted agent or MCP server serve. The `admin_routes` fns are granted
        // only the router — never a `Store`/`GovCtx`/audit handle.
        let router = mount_plane_admin_routes(router);
        let router = router
            // Groups — the `groups:` limit-tree CRUD: runtime-mutable groups
            // → per-user budgets. Reads are read-only scope; mutations are full scope.
            .route(PATH_GROUPS, get(list_groups).post(register_group))
            .route(
                "/groups/{name}",
                get(get_group)
                    .put(put_group)
                    .patch(patch_group)
                    .delete(delete_group),
            )
            .route("/groups/{name}/usage", get(get_group_usage))
            // Per-section overlay RESET: DISCARD a section's overlay mutations and revert it to
            // base config.yaml. Full scope (the mutation fallthrough). section ∈ {groups, hooks}.
            .route(
                "/overlay/{section}",
                axum::routing::delete(reset_overlay_section),
            )
            .route("/plugins", get(list_plugins).post(install_plugin))
            .route(PATH_PLUGINS_INSPECT, post(inspect_plugin))
            .route("/plugins/reload", post(reload_plugins))
            .route("/plugins/rollback", post(rollback_plugin))
            .route("/plugins/{file}", axum::routing::delete(remove_plugin))
            .route("/plugins/{file}/schema", get(plugin_schema))
            .route("/auth", get(get_auth))
            .route(PATH_ADMIN_AUTH, get(get_admin_auth).put(put_auth))
            .route("/usage", get(get_usage))
            .route("/config", get(get_config))
            .route("/audit", get(get_audit))
            .route(PATH_CONFIG_VALIDATE, post(validate_config))
            .route("/config/versions", get(list_config_versions))
            .route("/config/versions/{v}", get(get_config_version))
            .route("/config/diff", get(config_diff))
            .route("/config/rollback", post(rollback_config))
            .route("/config/reload", post(reload_config))
            .route("/restart", post(restart))
            .route("/auth/cache/flush", post(flush_credential_cache))
            .route("/config/apply", post(apply_config))
            .route(
                "/config/settings",
                get(get_config_settings).put(put_config_settings),
            )
            .route("/openapi.json", get(openapi))
            // Virtual-key management — the keys resource of the SAME v1 admin surface. Handlers
            // live in `crate::admin` while they migrate into the layered service; mounting them
            // here (not in main.rs) keeps the whole admin surface one router under one prefix.
            .route(
                "/keys",
                post(crate::admin::create_key).get(crate::admin::list_keys),
            )
            .route(
                "/keys/{id}",
                get(crate::admin::get_key)
                    .delete(crate::admin::delete_key)
                    .patch(crate::admin::update_key),
            )
            .route("/keys/{id}/usage", get(crate::admin::key_usage))
            .route("/keys/{id}/rotate", post(crate::admin::rotate_key))
            // 1.5.0 signed-token keys: revoke a key (denylist, keep the binding) and rotate the
            // busbar key-signing key (revoke-all).
            .route("/keys/{id}/revoke", post(crate::admin::revoke_key))
            .route(
                "/signing-key/rotate",
                post(crate::admin::rotate_signing_key),
            )
            // EVERY response on this surface speaks the frozen envelope — including an unmatched
            // path (404 `not_found`) and a matched path with the wrong method (405
            // `method_not_allowed`). Without these, axum's nest semantics leak an empty-body 405
            // from the inner MethodRouter and fall unmatched paths through to the data plane's
            // vendor-native shaping.
            .fallback(|| async { err_json(&AdminError::not_found("resource")) })
            .method_not_allowed_fallback(|| async { err_json(&AdminError::MethodNotAllowed) });
        // TEST-SUPPORT: the taxonomy recording layer. `Router::layer` runs AFTER routing, so it sees
        // the `MatchedPath` (the operation) alongside the tag `err_json` stamped on the response —
        // the join `err_json` alone cannot make. Every test in the suite is therefore a driver for
        // the class-level drift check (see `contract::taxonomy::observed`). Present under the whole
        // `any(test, feature = "test-support")` surface — not `cfg(test)` alone — so when an extracted
        // plane crate builds ITS router through this same `build_router` (a `test-support` build of
        // busbar-core as its dependency), the plane trust verbs' emissions are recorded into the
        // process-wide substrate witness ledger the cross-plane drift audit reads.
        #[cfg(any(test, feature = "test-support"))]
        let router = router.layer(axum::middleware::from_fn(record_declared_error));
        router
    }
}

/// TEST-ONLY recording layer (see `JsonV1::router`). For every response carrying a taxonomy tag it
/// (a) PANICS when the endpoint's `declared_errors` does not list that emission — an UNDER-CLAIM,
/// failing the very test that triggered it, with no test-ordering dependency — and (b) witnesses the
/// emission so the class test can prove no declared entry is an OVER-CLAIM.
///
/// The under-claim comparison runs at the SAME `(operation, ErrKind, Cond)` granularity the
/// over-claim direction does, whenever the emission names its condition (`err_json_cond`). It used
/// to compare `ErrKind` alone, which made the guard blind to the exact defect it exists to catch: a
/// handler emitting a NEW condition under an ALREADY-DECLARED kind sailed through, because a
/// sibling condition on the same operation kept `.any(|d| d.kind == tag.kind)` true. Two such
/// emissions shipped undocumented in 1.5.0 behind that hole — the `AtKeyCap` 409 on
/// `PATCH /keys/{id}` (declared nowhere, but Conflict was declared for `GovernanceOff`) and the
/// delegated-mint 400 on `POST /keys` (which additionally reused the wrong `Cond`, so its
/// openapi.json prose described the rebind target instead). Both now fail the build at emission.
#[cfg(any(test, feature = "test-support"))]
async fn record_declared_error(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    use crate::admin::v1::contract::taxonomy;
    let Some(method) = taxonomy::method_tag(req.method()) else {
        return next.run(req).await;
    };
    let matched = req
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|m| m.as_str().to_string());
    let resp = next.run(req).await;
    let tag = resp.extensions().get::<taxonomy::observed::Tag>().copied();
    if let (Some(path), Some(tag)) = (matched, tag) {
        let rel = path
            .strip_prefix(crate::admin::v1::contract::ADMIN_PREFIX)
            .unwrap_or(&path);
        // UNDER-CLAIM IS FATAL, HERE, NOW. If a handler emitted something the endpoint's
        // declaration does not list, `openapi.json` would under-document the surface — so fail the
        // test that produced it rather than accumulating a report someone has to read. Every test in
        // the suite is a driver for this direction; there is no ordering dependency and no way to
        // add an undocumented error response without turning the build red.
        //
        // GRANULARITY. A `err_json_cond` emission names its condition, so it is matched on the FULL
        // `(kind, cond)` pair — matching on `kind` alone would let a new condition hide behind a
        // declared sibling of the same kind, which is exactly the hole this guard is for. An
        // untagged emission (`err_json`) can only be matched on `kind`; that residual weakness is
        // what `COND_WITNESS_DEBT` ledgers and shrinks from the over-claim side.
        let declared = taxonomy::declared_errors(method, rel);
        let matched_decl = match tag.cond {
            Some(cond) => declared
                .iter()
                .any(|d| d.kind == tag.kind && d.cond == cond),
            None => declared.iter().any(|d| d.kind == tag.kind),
        };
        assert!(
            matched_decl,
            "OpenAPI UNDER-CLAIM: {} {rel} emitted {:?}/{} ({}), which contract::taxonomy::\
             declared_errors does not declare — openapi.json would omit or mis-describe the {} \
             response. Declare it (with its Cond) or stop emitting it.",
            method.as_str().to_uppercase(),
            tag.kind,
            match tag.cond {
                Some(c) => format!("{c:?}"),
                None => "<untagged>".to_string(),
            },
            tag.kind.code(),
            tag.kind.status(),
        );
        taxonomy::observed::record(rel, method, tag);
    }
    resp
}

/// Build a per-request `AdminService` over the CURRENT snapshot loaded from the handle.
fn service(handle: &Arc<AppHandle>) -> AdminService {
    AdminService::new(handle.load())
}

/// Absolute admin path from a RELATIVE one — relocated to the neutral substrate
/// (`busbar_substrate::api::ap`) alongside `ADMIN_PREFIX`, re-exported here so `openapi_doc()` and
/// every in-core caller are unchanged.
#[cfg_attr(not(feature = "openapi-schema"), allow(unused_imports))]
pub use busbar_substrate::api::ap;

/// The config-plane mutation choke point. Every mutation — from any transport, in any module — runs
/// inside `txn::config_transaction`, which owns the (file-private) mutation lock, hands the body a
/// FRESH post-lock snapshot, forces store/disk work onto `spawn_blocking`, and applies the resulting
/// plan through `AppHandle::commit_and_swap`. See `txn.rs` for the four guarantees.
mod txn;
pub(crate) use txn::{config_transaction, Outcome};

/// The GENERIC named-DEFINITION map CRUD (`/identity-providers`, `/export`; `tools`/`agents` land
/// additively in 1.6.0). One handler set for every section of the 1.5.3 universal config
/// pattern — see the module header.
pub(crate) mod named_map;

// ── The plane admin-verb route-mount adapter (ADMIN-3) ───────────────────────────────────────────

/// MOUNT EVERY PLANE'S ADMIN TRUST VERBS onto the admin router — the ADMIN-3 mirror of the data
/// plane's `router::mount_plane_routes`. Iterates the plane decls in DECLARATION ORDER (MCP before
/// A2A, preserving the operator-visible route order), asks each for its neutral
/// [`busbar_substrate::admin_verbs::AdminRouteSpec`] list, and registers each spec at its VERBATIM
/// `(method, path)` so the auth middleware's `required_scope(method, path)` is byte-identical.
///
/// The `&dyn Any` a plane's `admin_routes` fn takes is the seam's shared shape (it mirrors
/// `PlaneDecl::routes`); the admin verbs' paths are static and their handlers read the request's own
/// snapshot through the host the shim mints per request, so no build-time slot value is needed — a
/// unit placeholder satisfies the signature.
fn mount_plane_admin_routes(mut router: Router<Arc<AppHandle>>) -> Router<Arc<AppHandle>> {
    for decl in crate::plane::registry::plane_decls() {
        if let Some(admin_routes) = decl.admin_routes {
            for spec in admin_routes(&() as &dyn std::any::Any) {
                router = mount_one_admin_spec(router, decl.key, spec);
            }
        }
    }
    router
}

/// Mount ONE neutral [`busbar_substrate::admin_verbs::AdminRouteSpec`] onto the admin router. This is
/// the single place a plane's admin verb touches `Arc<AppHandle>` / `ok_json` / `err_json` / the audit
/// chain: the shim loads the handle, mints the neutral host, builds an
/// [`busbar_substrate::admin_verbs::AdminReqCtx`], awaits the plane's own handler, and frames the
/// [`busbar_substrate::admin_verbs::AdminReply`] — mapping the neutral `PlaneVerbError` back onto
/// `AdminError` and, for an `Audited` verb, recording the audit row EXACTLY where the pre-seam
/// `connect` did (applied on a view, rejected on a look refusal, NOTHING on the resolve-time `404`).
fn mount_one_admin_spec(
    router: Router<Arc<AppHandle>>,
    plane: &'static str,
    spec: busbar_substrate::admin_verbs::AdminRouteSpec,
) -> Router<Arc<AppHandle>> {
    use busbar_substrate::admin_verbs::{AdminReqCtx, AdminRouteSpec};
    let AdminRouteSpec {
        method,
        path,
        scope: _,
        kind,
        handler,
    } = spec;
    let method_filter = crate::plugin_routes::method_filter_of(method);
    let shim = move |State(handle): State<Arc<AppHandle>>,
                     Path(name): Path<String>,
                     principal: Option<axum::Extension<crate::auth::AuthPrincipal>>,
                     headers: axum::http::HeaderMap,
                     body: axum::body::Bytes| {
        let handler = handler.clone();
        async move {
            let principal = principal.map(|axum::Extension(p)| p);
            // LOAD + MINT stays 100% core-side (the plane names neither `AppHandle` nor the host
            // factory). `from_handle` mirrors the data-plane adapter; the verbs here read only the BOUND
            // slot, so it is byte-identical to the pre-seam `engine_host(&handle.load())` mint.
            let host = crate::plane_host::engine_host_from_handle(&handle);
            let ctx = AdminReqCtx {
                host,
                name: name.clone(),
                body,
                headers,
                principal: principal.clone(),
            };
            finish_admin_reply(plane, &name, kind, principal, handler(ctx).await)
        }
    };
    router.route(&path, axum::routing::on(method_filter, shim))
}

/// Frame a plane handler's [`busbar_substrate::admin_verbs::AdminReply`] onto the wire, and record the
/// audit row for an `Audited` verb. The variants encode the pre-seam behaviour exactly: `Refused` is
/// the un-audited resolve-time refusal, `Applied`/`Rejected` are the audited look-time outcomes, and
/// `Prebuilt` is a verb that built its own envelope and audited itself (returned verbatim).
fn finish_admin_reply(
    plane: &'static str,
    name: &str,
    kind: busbar_substrate::admin_verbs::AdminVerbKind,
    principal: Option<crate::auth::AuthPrincipal>,
    reply: busbar_substrate::admin_verbs::AdminReply,
) -> Response {
    use busbar_substrate::admin_verbs::{AdminReply, AdminVerbKind};
    let record_audit = |outcome: &'static str| {
        if let AdminVerbKind::Audited { verb } = kind {
            let anon = crate::auth::AuthPrincipal(None);
            let p = principal.as_ref().unwrap_or(&anon);
            crate::admin::planeverbs::audit(plane, verb, name, outcome, p);
        }
    };
    match reply {
        AdminReply::Prebuilt(resp) => resp,
        AdminReply::Refused(e) => {
            err_json(&crate::admin::planeverbs::to_admin_error(plane, name, e))
        }
        AdminReply::Applied(body) => {
            record_audit(audit::OUTCOME_APPLIED);
            // Byte-identical to `ok_json(StatusCode::OK, &view)`: same status, same content type, and the
            // body was serialized handler-side by the SAME `serde_json::to_string(&view)` call.
            (
                StatusCode::OK,
                [(CONTENT_TYPE, crate::proxy::APPLICATION_JSON)],
                body,
            )
                .into_response()
        }
        AdminReply::Rejected(e) => {
            record_audit(audit::OUTCOME_REJECTED);
            err_json(&crate::admin::planeverbs::to_admin_error(plane, name, e))
        }
    }
}

// ── JSON wire helpers (v1) ───────────────────────────────────────────────────────────────────────

/// Serialize a successful view to the JSON body with the given status. `view` is any `contract` view
/// (`#[derive(Serialize)]`); the JSON projection is the derive, so a field added to a view appears
/// automatically (additive-only holds by construction).
pub fn ok_json<T: Serialize>(status: StatusCode, view: &T) -> Response {
    (
        status,
        [(CONTENT_TYPE, crate::proxy::APPLICATION_JSON)],
        serde_json::to_string(view).unwrap_or_else(|_| "{}".to_string()),
    )
        .into_response()
}

/// Project an `AdminError` onto the stable v1 JSON error envelope
/// `{"error":{"code":<stable>,"message":<human>}}` with the error's HTTP status. Tooling branches on
/// `code`; `message` is human-only.
pub fn err_json(e: &AdminError) -> Response {
    err_json_tagged(e, None)
}

/// `err_json`, but NAMING the taxonomy [`Cond`] that produced the error. Used at the shared seams
/// whose condition is fixed (malformed `If-Match`, malformed cursor, the keys surface), so the
/// class-level drift test can witness the declaration at CONDITION granularity, not just at
/// `ErrKind` granularity. The wire bytes are identical to `err_json` — the tag is `#[cfg(test)]`.
pub(crate) fn err_json_cond(e: &AdminError, cond: Cond) -> Response {
    err_json_tagged(e, Some(cond))
}

/// The one construction site of the v1 error envelope. In a TEST build it stamps the response with
/// the taxonomy [`observed::Tag`] so the router's recording layer — which knows the matched route,
/// which this function does not — can attribute the emission to an operation and check it against
/// `declared_errors`. In a release build the tag does not exist and this is the plain projection.
#[cfg_attr(not(any(test, feature = "test-support")), allow(unused_variables))]
fn err_json_tagged(e: &AdminError, cond: Option<Cond>) -> Response {
    let status = StatusCode::from_u16(e.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    #[cfg_attr(not(any(test, feature = "test-support")), allow(unused_mut))]
    let mut resp = (
        status,
        [(CONTENT_TYPE, crate::proxy::APPLICATION_JSON)],
        json!({"error": {"code": e.code(), "message": e.message()}}).to_string(),
    )
        .into_response();
    #[cfg(any(test, feature = "test-support"))]
    if let Some(kind) = crate::admin::v1::contract::taxonomy::err_kind_of(e) {
        resp.extensions_mut()
            .insert(crate::admin::v1::contract::taxonomy::observed::Tag { kind, cond });
    }
    resp
}

/// Map a service `Result<View, AdminError>` onto the JSON wire: `ok_json` on success (given status),
/// `err_json` on error. The single seam every v1 json handler funnels through.
fn respond<T: Serialize>(status: StatusCode, result: Result<T, AdminError>) -> Response {
    match result {
        Ok(view) => ok_json(status, &view),
        Err(e) => err_json(&e),
    }
}

/// Decode the opaque `?cursor=` into a start offset (0 when absent). A malformed/foreign cursor is a
/// 400 `invalid_request` — never a silent skip — so every cursor-paginated handler rejects it the same.
// The Err variant is an axum `Response` (the ready-to-return 400) — intentionally, so callers just
// `return` it; that makes the Result "large", which is fine for a per-request handler helper.
#[allow(clippy::result_large_err)]
fn cursor_offset(q: &std::collections::HashMap<String, String>) -> Result<usize, Response> {
    match q.get("cursor") {
        None => Ok(0),
        Some(c) => crate::admin::v1::contract::decode_offset_cursor(c).ok_or_else(|| {
            err_json_cond(
                &AdminError::Validation("invalid or foreign pagination cursor".into()),
                Cond::MalformedCursor,
            )
        }),
    }
}

/// Given a slice fetched with `limit + 1` starting at `start`, trim it IN PLACE to `limit` and return
/// the next opaque cursor iff the probe row existed (i.e. a further page remains). The one seam that
/// gives keys/audit/versions an identical `{items, next_cursor}` continuation.
///
/// PRECONDITION: `limit >= 1`. At `limit == 0` the cursor would encode `start + 0 == start` — a
/// cursor pointing at the exact offset it was just served from, so a cursor-following client loops
/// forever. Every caller clamps `limit` to at least 1 before reaching here.
fn page_cursor<T>(items: &mut Vec<T>, start: usize, limit: usize) -> Option<String> {
    if items.len() > limit {
        items.truncate(limit);
        Some(crate::admin::v1::contract::encode_offset_cursor(
            start.saturating_add(limit),
        ))
    } else {
        None
    }
}

/// Parse the optional `If-Match` header into the caller's expected config version (ONE
/// optimistic-concurrency mechanism across the whole surface — the RFC-7232 header, exactly as the
/// keys resource already speaks it; there is no body-level `expected_version` twin). Grammar: the
/// config-plane ETag is the config version quoted (`"42"`); a bare `42` is accepted leniently and
/// `*` (RFC: "any current representation") matches unconditionally, i.e. no guard. Anything else is
/// a 400 `invalid_request` — a malformed guard must never silently pass as "no guard".
// The Err variant is the ready-to-return 400 `Response` — intentional (callers just `return` it);
// a "large" Result is fine for a per-request handler helper.
#[allow(clippy::result_large_err)]
fn if_match_version(headers: &axum::http::HeaderMap) -> Result<Option<u64>, Response> {
    let Some(raw) = headers.get(axum::http::header::IF_MATCH) else {
        return Ok(None);
    };
    let s = raw.to_str().unwrap_or("").trim();
    if s == "*" {
        return Ok(None);
    }
    let bare = s.strip_prefix("W/").unwrap_or(s); // weak tags compare by value here
    let bare = bare.trim_matches('"');
    bare.parse::<u64>().map(Some).map_err(|_| {
        err_json_cond(
            &AdminError::Validation(
                "malformed If-Match: expected the config-plane ETag (a quoted config version, e.g. \
                 \"42\") or *"
                    .into(),
            ),
            Cond::MalformedIfMatch,
        )
    })
}

/// The stale-guard rejection every version-guarded mutation shares: the caller's `If-Match` version
/// vs the live one. `None` (absent / `*`) never rejects.
fn stale_if_match(expected: Option<u64>, current: u64) -> Option<AdminError> {
    match expected {
        // RETRYABLE: re-read the resource (fresh ETag) and retry — its own frozen code, split
        // from terminal `conflict`.
        Some(v) if v != current => Some(AdminError::VersionConflict(format!(
            "If-Match version {v} is stale (current is {current})"
        ))),
        _ => None,
    }
}

/// Stamp the config-plane `ETag` (`"<config_version>"`) onto a response — the token `If-Match`
/// guards against. Emitted on the version-guarded reads AND on every successful mutation (whose new
/// version the caller chains into its next `If-Match`).
fn with_config_etag(mut resp: Response, version: u64) -> Response {
    if let Ok(v) = axum::http::HeaderValue::from_str(&format!("\"{version}\"")) {
        resp.headers_mut().insert(axum::http::header::ETAG, v);
    }
    resp
}

// ── route handlers (thin: call the service, project onto the wire) ───────────────────────────────

mod handlers;
pub(crate) use handlers::*;
// The extracted MCP plane (`busbar-mcp`) contributes its trust verbs' typed response schemas through
// this exact helper (`admin_view::openapi_schemas`). It is relocated to the neutral substrate
// (`busbar_substrate::api::set_response_schema`) so the plane names it directly; re-exported here at
// its old path, gated the same as the helper itself, so in-core callers are unchanged.
#[cfg(feature = "openapi-schema")]
pub use busbar_substrate::api::set_response_schema;

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;
