// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use axum::extract::State;
use axum::http::{header::CONTENT_TYPE, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post};
use axum::{extract::Path, extract::Query, Router};
use serde::Serialize;
use serde_json::json;

use super::service::{
    build_with_group, build_with_hook, build_with_registry, build_without_group,
    build_without_hook, AdminService,
};
use crate::transport::AdminTransport;
use crate::v1::contract::taxonomy::Cond;
use crate::v1::contract::{
    AdminError, PATH_ADMIN_AUTH, PATH_CONFIG_VALIDATE, PATH_GROUPS, PATH_HOOKS,
    PATH_PLUGINS_INSPECT,
};

pub(crate) use busbar_kernel::audit_ring as audit;
use busbar_kernel::state::AppHandle;

#[cfg(feature = "openapi-schema")]
pub(crate) const RESPONSES_KEY: &str = concat!("respon", "ses");

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
            .merge(named_map::routes());

        let router = mount_plane_admin_routes(router);
        let router = router
            .route(PATH_GROUPS, get(list_groups).post(register_group))
            .route(
                "/groups/{name}",
                get(get_group)
                    .put(put_group)
                    .patch(patch_group)
                    .delete(delete_group),
            )
            .route("/groups/{name}/usage", get(get_group_usage))
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
            .route("/ledger/recovery/list", post(crate::recovery::list))
            .route("/ledger/recovery/resolve", post(crate::recovery::resolve))
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
            .route(
                "/keys",
                post(crate::keys::create_key).get(crate::keys::list_keys),
            )
            .route(
                "/keys/{id}",
                get(crate::keys::get_key)
                    .delete(crate::keys::delete_key)
                    .patch(crate::keys::update_key),
            )
            .route("/keys/{id}/usage", get(crate::keys::key_usage))
            .route("/keys/{id}/rotate", post(crate::keys::rotate_key))
            .route("/keys/{id}/revoke", post(crate::keys::revoke_key))
            .route("/signing-key/rotate", post(crate::keys::rotate_signing_key))
            .fallback(plane_serve_or_not_found)
            .method_not_allowed_fallback(|| async { err_json(&AdminError::MethodNotAllowed) });

        #[cfg(test)]
        let router = router.layer(axum::middleware::from_fn(record_declared_error));

        router.layer(axum::middleware::from_fn_with_state(
            Arc::new(crate::keys::KeyReplayCache::new()),
            supply_replay_cache,
        ))
    }
}

async fn supply_replay_cache(
    State(own): State<Arc<crate::keys::KeyReplayCache>>,
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if req
        .extensions()
        .get::<Arc<crate::keys::KeyReplayCache>>()
        .is_none()
    {
        req.extensions_mut().insert(own);
    }
    next.run(req).await
}

#[cfg(test)]
async fn record_declared_error(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    use crate::v1::contract::taxonomy;
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
            .strip_prefix(crate::v1::contract::ADMIN_PREFIX)
            .unwrap_or(&path);

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
    }
    resp
}

fn service(handle: &Arc<AppHandle>) -> AdminService {
    AdminService::new(handle.load())
}

#[cfg_attr(not(feature = "openapi-schema"), allow(unused_imports))]
pub use busbar_kernel::api::ap;

pub(crate) use busbar_kernel::config::transaction::{config_transaction, Outcome};

pub(crate) mod named_map;

fn mount_plane_admin_routes(mut router: Router<Arc<AppHandle>>) -> Router<Arc<AppHandle>> {
    for decl in busbar_kernel::plane_driver::registry::plane_decls() {
        if let Some(admin_routes) = decl.admin_routes {
            for spec in admin_routes(decl, &() as &dyn std::any::Any) {
                router = mount_one_admin_spec(router, decl, spec);
            }
        }
    }
    router
}

async fn plane_serve_or_not_found(
    State(handle): State<Arc<AppHandle>>,
    req: axum::extract::Request,
) -> Response {
    let tables = handle.load().serve_tables.clone();
    tables
        .answer(req)
        .await
        .unwrap_or_else(|| err_json(&AdminError::not_found("resource")))
}

pub(crate) fn unconfigured_plane(
    handle: &AppHandle,
    decl: Option<&busbar_kernel::plane_driver::registry::PlaneDecl>,
) -> Option<Response> {
    if decl.is_none_or(|d| handle.load().plane_configured(d)) {
        return None;
    }
    #[cfg_attr(not(test), allow(unused_mut))]
    let mut resp = err_json(&AdminError::not_found("resource"));

    #[cfg(test)]
    resp.extensions_mut()
        .remove::<crate::v1::contract::taxonomy::observed::Tag>();
    Some(resp)
}

fn mount_one_admin_spec(
    router: Router<Arc<AppHandle>>,
    decl: &'static busbar_kernel::plane_driver::registry::PlaneDecl,
    spec: busbar_kernel::admin_verbs::AdminRouteSpec,
) -> Router<Arc<AppHandle>> {
    let plane = decl.key;
    use busbar_kernel::admin_verbs::{AdminReqCtx, AdminRouteSpec};
    let AdminRouteSpec {
        method,
        path,
        scope: _,
        kind,
        handler,
    } = spec;
    let method_filter = busbar_kernel::plugin_routes::method_filter_of(method);
    let shim =
        move |State(handle): State<Arc<AppHandle>>,
              Path(name): Path<String>,
              principal: Option<axum::Extension<busbar_kernel::auth::AuthPrincipal>>,
              consumed: Option<axum::Extension<busbar_kernel::auth::ConsumedCredentials>>,
              axum::extract::RawQuery(query): axum::extract::RawQuery,
              headers: axum::http::HeaderMap,
              body: axum::body::Bytes| {
            let handler = handler.clone();
            async move {
                if let Some(resp) = unconfigured_plane(&handle, Some(decl)) {
                    return resp;
                }
                let principal = principal.map(|axum::Extension(p)| p);

                let host = busbar_kernel::plane_driver::engine_host_from_handle(&handle);
                let ctx = AdminReqCtx {
                    host,
                    name: name.clone(),
                    body,
                    headers,
                    principal: principal.clone(),

                    consumed: consumed.map(|axum::Extension(c)| c),
                    query,
                    serve: handle.load().serve_tables.clone(),
                };
                finish_admin_reply(plane, &name, kind, principal, handler(ctx).await)
            }
        };

    let wrong_method = move |State(handle): State<Arc<AppHandle>>| async move {
        unconfigured_plane(&handle, Some(decl))
            .unwrap_or_else(|| err_json(&AdminError::MethodNotAllowed))
    };
    router.route(
        &path,
        axum::routing::on(method_filter, shim).fallback(wrong_method),
    )
}

fn finish_admin_reply(
    plane: &'static str,
    name: &str,
    kind: busbar_kernel::admin_verbs::AdminVerbKind,
    principal: Option<busbar_kernel::auth::AuthPrincipal>,
    reply: busbar_kernel::admin_verbs::AdminReply,
) -> Response {
    use busbar_kernel::admin_verbs::{AdminReply, AdminVerbKind};
    let record_audit = |outcome: &'static str| {
        if let AdminVerbKind::Audited { verb } = kind {
            let anon = busbar_kernel::auth::AuthPrincipal(None);
            let p = principal.as_ref().unwrap_or(&anon);
            crate::planeverbs::audit(plane, verb, name, outcome, p);
        }
    };
    match reply {
        AdminReply::Refused(e) => crate::planeverbs::refusal_response(plane, name, e),
        AdminReply::Applied(body) => {
            record_audit(audit::OUTCOME_APPLIED);

            (
                StatusCode::OK,
                [(CONTENT_TYPE, busbar_contract::protocol::APPLICATION_JSON)],
                body,
            )
                .into_response()
        }
        AdminReply::Rejected(e) => {
            record_audit(audit::OUTCOME_REJECTED);
            crate::planeverbs::refusal_response(plane, name, e)
        }
    }
}

mod envelope;
pub use envelope::{err_json, err_json_cond, ok_json};

fn respond<T: Serialize>(status: StatusCode, result: Result<T, AdminError>) -> Response {
    match result {
        Ok(view) => ok_json(status, &view),
        Err(e) => err_json(&e),
    }
}

#[allow(clippy::result_large_err)]
fn cursor_offset(q: &std::collections::HashMap<String, String>) -> Result<usize, Response> {
    match q.get("cursor") {
        None => Ok(0),
        Some(c) => crate::v1::contract::decode_offset_cursor(c).ok_or_else(|| {
            err_json_cond(
                &AdminError::Validation("invalid or foreign pagination cursor".into()),
                Cond::MalformedCursor,
            )
        }),
    }
}

fn base_owned(kind: &str, name: &str) -> AdminError {
    AdminError::Conflict(format!(
        "{kind} `{name}` is defined in the base config file; edit config.yaml (the API cannot \
         silently shadow operator file config)"
    ))
}

fn json_body<T: serde::de::DeserializeOwned>(body: &[u8], what: &str) -> Result<T, Box<Response>> {
    serde_json::from_slice(body).map_err(|e| {
        Box::new(err_json(&AdminError::Validation(format!(
            "malformed {what} body: {e}"
        ))))
    })
}

fn page_window(
    q: &std::collections::HashMap<String, String>,
    default: usize,
) -> Result<(usize, usize), Box<Response>> {
    let limit = q
        .get("limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(default)
        .clamp(1, crate::v1::contract::LIST_LIMIT_MAX);
    Ok((cursor_offset(q).map_err(Box::new)?, limit))
}

fn page_cursor<T>(items: &mut Vec<T>, start: usize, limit: usize) -> Option<String> {
    if items.len() > limit {
        items.truncate(limit);
        Some(crate::v1::contract::encode_offset_cursor(
            start.saturating_add(limit),
        ))
    } else {
        None
    }
}

#[allow(clippy::result_large_err)]
fn if_match_version(headers: &axum::http::HeaderMap) -> Result<Option<u64>, Response> {
    let Some(raw) = headers.get(axum::http::header::IF_MATCH) else {
        return Ok(None);
    };
    let s = raw.to_str().unwrap_or("").trim();
    if s == "*" {
        return Ok(None);
    }
    let bare = s.strip_prefix("W/").unwrap_or(s);
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

fn stale_if_match(expected: Option<u64>, current: u64) -> Option<AdminError> {
    match expected {
        Some(v) if v != current => Some(AdminError::VersionConflict(format!(
            "If-Match version {v} is stale (current is {current})"
        ))),
        _ => None,
    }
}

fn with_config_etag(mut resp: Response, version: u64) -> Response {
    if let Ok(v) = axum::http::HeaderValue::from_str(&format!("\"{version}\"")) {
        resp.headers_mut().insert(axum::http::header::ETAG, v);
    }
    resp
}

mod handlers;
pub(crate) use handlers::*;

mod kernel_verbs;

#[must_use]
pub fn openapi_document() -> String {
    handlers::openapi_json()
}

#[cfg(feature = "openapi-schema")]
pub use busbar_kernel::api::set_response_schema;

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;
