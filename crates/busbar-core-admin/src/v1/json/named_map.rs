// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch};
use axum::Extension;
use axum::Router;

use super::{
    config_transaction, err_json, err_json_cond, if_match_version, respond, stale_if_match,
    with_config_etag, Outcome,
};
use crate::admin_state::AppAdmin as _;
use crate::v1::contract::taxonomy::Cond;
use crate::v1::contract::AdminError;
use crate::v1::named_def_views::SETTINGS_KEY;
use busbar_kernel::audit_ring as audit;
use busbar_kernel::config::named_map::NamedMapSection;
use busbar_kernel::state::{App, AppHandle};

pub(crate) fn routes() -> Router<Arc<AppHandle>> {
    let mut router = Router::new();
    for section in NamedMapSection::sections() {
        router = router.merge(
            Router::new()
                .route(
                    section.path_root().as_ref(),
                    get(list).fallback(wrong_method),
                )
                .route(
                    &item_path(section),
                    get(get_one).put(put).delete(delete).fallback(wrong_method),
                )
                .route(
                    &settings_path(section),
                    patch(patch_settings).fallback(wrong_method),
                )
                .route_layer(Extension(section)),
        );
    }
    router
}

fn item_path(section: NamedMapSection) -> String {
    format!("{}/{{name}}", section.path_root())
}

fn settings_path(section: NamedMapSection) -> String {
    format!("{}/settings", item_path(section))
}

async fn list(
    State(handle): State<Arc<AppHandle>>,
    Extension(section): Extension<NamedMapSection>,
) -> Response {
    if let Some(resp) = plane_gate(&handle, section) {
        return resp;
    }
    let version = handle.load().config_version;
    with_config_etag(
        respond(
            StatusCode::OK,
            super::service(&handle).list_named_defs(section).await,
        ),
        version,
    )
}

async fn get_one(
    State(handle): State<Arc<AppHandle>>,
    Path(name): Path<String>,
    Extension(section): Extension<NamedMapSection>,
) -> Response {
    if let Some(resp) = plane_gate(&handle, section) {
        return resp;
    }
    let version = handle.load().config_version;
    with_config_etag(
        respond(
            StatusCode::OK,
            super::service(&handle).get_named_def(section, &name).await,
        ),
        version,
    )
}

async fn wrong_method(
    State(handle): State<Arc<AppHandle>>,
    Extension(section): Extension<NamedMapSection>,
) -> Response {
    plane_gate(&handle, section).unwrap_or_else(|| err_json(&AdminError::MethodNotAllowed))
}

pub(super) fn plane_gate(handle: &AppHandle, section: NamedMapSection) -> Option<Response> {
    let decl = match section {
        NamedMapSection::Plane(key) => {
            busbar_kernel::plane_driver::registry::plane_decl_for_config_section(key)
        }
        _ => None,
    };
    super::unconfigured_plane(handle, decl)
}

enum Mutation {
    Replace(serde_json::Value),

    Settings(serde_json::Map<String, serde_json::Value>),

    Remove,
}

impl Mutation {
    fn verb(&self) -> &'static str {
        match self {
            Mutation::Replace(_) => "replace",
            Mutation::Settings(_) => "settings",
            Mutation::Remove => "delete",
        }
    }

    fn requires_existing(&self) -> bool {
        !matches!(self, Mutation::Replace(_))
    }
}

async fn put(
    State(handle): State<Arc<AppHandle>>,
    Extension(principal): Extension<busbar_kernel::auth::AuthPrincipal>,
    Path(name): Path<String>,
    headers: axum::http::HeaderMap,
    Extension(section): Extension<NamedMapSection>,
    body: axum::body::Bytes,
) -> Response {
    if let Some(resp) = plane_gate(&handle, section) {
        return resp;
    }
    let def: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return err_json_cond(
                &AdminError::Validation(format!(
                    "malformed {} definition body: {e}",
                    section.singular()
                )),
                Cond::MalformedBody,
            )
        }
    };
    apply(
        handle,
        principal,
        section,
        name,
        headers,
        Mutation::Replace(def),
    )
    .await
}

async fn patch_settings(
    State(handle): State<Arc<AppHandle>>,
    Extension(principal): Extension<busbar_kernel::auth::AuthPrincipal>,
    Path(name): Path<String>,
    headers: axum::http::HeaderMap,
    Extension(section): Extension<NamedMapSection>,
    body: axum::body::Bytes,
) -> Response {
    if let Some(resp) = plane_gate(&handle, section) {
        return resp;
    }
    let req: NamedSettingsReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return err_json_cond(
                &AdminError::Validation(format!("malformed settings body: {e}")),
                Cond::MalformedBody,
            )
        }
    };
    apply(
        handle,
        principal,
        section,
        name,
        headers,
        Mutation::Settings(req.settings),
    )
    .await
}

/// The `PATCH /api/v1/admin/<section>/{name}/settings` body: the whole replacement settings bag.
/// A sibling of the hooks surface's `PatchSettingsReq` (same shape, same semantics: `settings:` is
/// REPLACED, not deep-merged, so the stored bag is always exactly what the caller sent).
#[derive(serde::Deserialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct NamedSettingsReq {
    // settings-leak-lint: allow — INBOUND request body (`Deserialize` only). This is the operator
    pub(crate) settings: serde_json::Map<String, serde_json::Value>,
}

async fn delete(
    State(handle): State<Arc<AppHandle>>,
    Extension(principal): Extension<busbar_kernel::auth::AuthPrincipal>,
    Path(name): Path<String>,
    headers: axum::http::HeaderMap,
    Extension(section): Extension<NamedMapSection>,
) -> Response {
    if let Some(resp) = plane_gate(&handle, section) {
        return resp;
    }
    apply(handle, principal, section, name, headers, Mutation::Remove).await
}

type Rejection = (AdminError, Cond);

async fn apply(
    handle: Arc<AppHandle>,
    principal: busbar_kernel::auth::AuthPrincipal,
    section: NamedMapSection,
    name: String,
    headers: axum::http::HeaderMap,
    mutation: Mutation,
) -> Response {
    let actor = principal.actor_id().to_string();
    let card_origin = format!("{} write by {actor}", section.key());
    let action = format!("{}.{}", section.singular(), mutation.verb());
    let resource = format!("{}:{name}", section.singular());
    let reject = |e: &AdminError, cond: Cond, actor: &str| -> Response {
        audit::AUDIT.record_by(&action, &resource, audit::OUTCOME_REJECTED, actor);
        err_json_cond(e, cond)
    };

    let expected = match if_match_version(&headers) {
        Ok(v) => v,
        Err(resp) => {
            audit::AUDIT.record_by(&action, &resource, audit::OUTCOME_REJECTED, &actor);
            return resp;
        }
    };
    let current = handle.load();

    let (Some(config_path), Some(providers_path)) =
        (current.config_path.clone(), current.providers_path.clone())
    else {
        return reject(
            &AdminError::Validation(format!(
                "this busbar was started without config files (ephemeral mode); a `{}` mutation has \
                 no disk base to merge onto",
                section.key()
            )),
            Cond::NoDiskBase,
            &actor,
        );
    };

    if current.overlay_path.is_none() {
        audit::AUDIT.record_by(&action, &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&AdminError::Validation(
            busbar_kernel::config::overlay::NO_WRITABLE_OVERLAY_MSG.to_string(),
        ));
    }

    if mutation.requires_existing() && !section_contains(&current, section, &name) {
        return reject(
            &AdminError::not_found(format!("{} `{name}`", section.singular())),
            Cond::UnknownResource,
            &actor,
        );
    }
    if let Mutation::Replace(def) = &mutation {
        if let Err(e) = validate_definition(section, &name, def) {
            return reject(&e, Cond::InvalidConfig, &actor);
        }
    }
    if let Mutation::Settings(settings) = &mutation {
        if let Err(e) = crate::v1::service::validate_hook_settings_size(settings) {
            return reject(&e, Cond::InvalidConfig, &actor);
        }
    }

    let removes = matches!(mutation, Mutation::Remove);
    let txn_section = section;
    let txn_name = name.clone();
    let out = config_transaction(&handle, move |txn| {
        let current = txn.app();
        if let Some(e) = stale_if_match(expected, current.config_version) {
            return Err(e);
        }
        let snapshot = current.clone();


        Ok(txn.read_store(move || {
            let mut loaded = busbar_kernel::load_config_from_disk_with_store(
                &config_path,
                Some(&providers_path),
                false,
                busbar_kernel::config::EnvSubst::Strict,
                &*snapshot.root_rules,
                snapshot.overlay_path.clone(),
            )
            .map_err(AdminError::Validation)?;




            if txn_section.contains(&loaded.deploy, &txn_name) {
                return Ok(Outcome::Value(Err((
                    AdminError::Conflict(format!(
                        "{} `{txn_name}` is defined in the base config file; edit config.yaml (the \
                         API cannot silently shadow operator file config)",
                        txn_section.singular()
                    )),
                    Cond::BaseDefined,
                ))));
            }
            let mut doc = loaded.overlay_doc.clone().unwrap_or_default();
            let entries = doc.named_maps.entry(txn_section.key().to_string()).or_default();
            let next_def: Option<serde_json::Value> = match &mutation {
                Mutation::Replace(def) => Some(def.clone()),
                Mutation::Settings(settings) => {



                    let Some(existing) = entries.get(&txn_name) else {
                        return Ok(Outcome::Value(Err((
                            AdminError::not_found(format!(
                                "{} `{txn_name}`",
                                txn_section.singular()
                            )),
                            Cond::UnknownResource,
                        ))));
                    };
                    let mut def = existing.clone();
                    match def.as_object_mut() {
                        Some(obj) => {
                            obj.insert(
                                SETTINGS_KEY.to_string(),
                                serde_json::Value::Object(settings.clone()),
                            );
                        }
                        None => {
                            return Ok(Outcome::Value(Err((
                                AdminError::Validation(format!(
                                    "the stored `{}` definition for `{txn_name}` is not an object",
                                    txn_section.key()
                                )),
                                Cond::InvalidConfig,
                            ))))
                        }
                    }
                    Some(def)
                }
                Mutation::Remove => {



                    let referents = txn_section.referents(&loaded.deploy, &txn_name);
                    if !referents.is_empty() {
                        return Ok(Outcome::Value(Err((
                            AdminError::Conflict(format!(
                                "cannot delete {} `{txn_name}`: still referenced by {} — remove the \
                                 reference first",
                                txn_section.singular(),
                                referents.join(", ")
                            )),
                            Cond::StillReferenced,
                        ))));
                    }
                    None
                }
            };








            if let Some(def) = next_def.as_ref() {
                if let Err(e) = txn_section.validate_def(&txn_name, def) {
                    return Ok(Outcome::Value(Err((
                        AdminError::Validation(e),
                        Cond::InvalidConfig,
                    ))));
                }
            }



            if let Some(def) = next_def.as_ref() {
                if let Err(e) = check_trust_ceiling(txn_section, &snapshot, &txn_name, def) {
                    return Ok(Outcome::Value(Err(e)));
                }
            }
            match &next_def {
                Some(def) => {
                    entries.insert(txn_name.clone(), def.clone());
                }
                None => {
                    entries.remove(&txn_name);
                }
            }
            if entries.is_empty() {
                doc.named_maps.remove(txn_section.key());
            }



            loaded.overlay_doc = Some(doc.clone());
            let built = (|| {
                busbar_kernel::config::overlay::apply_root_to_deploy(&mut loaded.deploy, &doc);
                let mut cfg = busbar_kernel::config::resolve(&loaded.deploy, &loaded.defs)
                    .map_err(|errs| format!("config errors:\n  - {}", errs.join("\n  - ")))?;
                let base_hook_names: std::collections::HashSet<String> =
                    cfg.hooks.keys().cloned().collect();
                let base_group_names: std::collections::HashSet<String> =
                    cfg.groups.keys().cloned().collect();
                busbar_kernel::config::overlay::merge_into(&mut cfg, doc);
                busbar_kernel::build_app_from_config(
                    cfg,
                    loaded.deploy.plugins.clone(),

                    loaded.overlay_path,
                    base_hook_names,
                    base_group_names,
                    (Some(config_path), Some(providers_path)),
                    Some(&snapshot),
                    &snapshot.root_rules,
                )
            })();
            let (built, gov_rotate, limits) = match built {
                Ok(v) => v,

                Err(e) => {
                    return Ok(Outcome::Value(Err((
                        AdminError::Validation(e),
                        Cond::InvalidConfig,
                    ))))
                }
            };
            let installed = Arc::new(built);




            let awaiting_restart = busbar_kernel::plugin_routes::paths_awaiting_restart(
                &installed.plugin_routes,
                &snapshot.plugin_routes,
                &installed.boot_route_paths,
            );



            let awaiting_restart = (
                awaiting_restart,
                busbar_kernel::state::planes_awaiting_restart_added(&installed, &snapshot),
            );




            let persist_overlay = snapshot.overlay_path.clone();
            let persist_name = txn_name.clone();
            let persist_def = next_def.clone();
            Ok(Outcome::commit_rates_then(
                installed.clone(),
                move || {
                    busbar_kernel::config::overlay::persist_named_map(
                        persist_overlay.as_deref(),
                        txn_section,
                        &persist_name,
                        persist_def.as_ref(),
                    )
                    .map_err(|e| {
                        format!(
                            "the `{}` change persistence to the overlay was not confirmed: {e}; \
                             the running engine is unaffected",
                            txn_section.key()
                        )
                    })
                },
                limits,
                card_origin,
                move || {
                    if let Some(rotate) = gov_rotate {
                        rotate();
                    }
                    Ok(Outcome::Value(Ok((installed, awaiting_restart))))
                },
            ))
        }))
    })
    .await;

    let (installed, awaiting_restart) = match out {
        Ok(Ok(v)) => v,
        Ok(Err((e, cond))) => return reject(&e, cond, &actor),

        Err(e @ AdminError::VersionConflict(_)) => {
            return reject(&e, Cond::StaleIfMatch, &actor);
        }
        Err(e) => {
            audit::AUDIT.record_by(&action, &resource, audit::OUTCOME_REJECTED, &actor);
            return err_json(&e);
        }
    };
    audit::AUDIT.record_by(&action, &resource, audit::OUTCOME_APPLIED, &actor);
    installed.record_version(&actor, &format!("{action} {resource}"));
    let version = installed.config_version;
    if removes {
        return with_config_etag(StatusCode::NO_CONTENT.into_response(), version);
    }
    with_config_etag(
        respond(
            StatusCode::OK,
            super::service(&handle)
                .get_named_def(section, &name)
                .await
                .map(|def| MutatedDefView::new(def, awaiting_restart.0, awaiting_restart.1)),
        ),
        version,
    )
}

/// THE MUTATION RESPONSE for an upsert/settings write: the stored definition, PLUS the
/// restart-required signal when this mutation introduced a plugin route the running process cannot
/// serve.
///
/// `#[serde(flatten)]` keeps the definition's own fields exactly where they have always been, so the
/// signal is purely ADDITIVE — and both signal fields are omitted entirely when nothing is pending,
/// so the ordinary body is byte-identical to what it was. This is the `export:` named map's sibling of
/// `PUT /config/settings`'s `reload_to_apply`/`note` pair (`handlers::reload_to_apply_fields`), which
/// reports the same class of boot-frozen change for the single-value settings surface.
#[derive(serde::Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct MutatedDefView {
    #[serde(flatten)]
    def: crate::v1::contract::NamedDefView,
    /// The plugin-route PATHS this mutation declared that the process cannot serve until it restarts,
    /// because the axum router registers each path once, at boot, and a config apply swaps only
    /// `Arc<App>`; then the plane SECTIONS it first wrote whose plane the process did not open at
    /// boot (a plane is opened once, at process start, when its section is configured). Empty (and
    /// omitted) for every mutation that adds neither — including every REMOVAL, which genuinely
    /// does apply live.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    reload_to_apply: Vec<String>,
    /// The operator-facing sentence for [`Self::reload_to_apply`]; omitted with it.
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

impl MutatedDefView {
    fn new(
        def: crate::v1::contract::NamedDefView,
        paths: Vec<String>,
        planes: Vec<String>,
    ) -> Self {
        let note = restart_note(&paths, &planes);
        let mut reload_to_apply = paths;
        reload_to_apply.extend(planes);
        Self {
            def,
            reload_to_apply,
            note,
        }
    }
}

pub(crate) fn restart_note(paths: &[String], planes: &[String]) -> Option<String> {
    let routes = (!paths.is_empty()).then(|| {
        format!(
            "stored and applied, EXCEPT the newly declared route(s) {} — each plugin route path \
             is registered on the HTTP router once, at process start, and a config apply swaps \
             only the config snapshot, so a route that did not exist at boot keeps answering 404 \
             until the next RESTART (removing one, by contrast, takes effect immediately)",
            paths.join(", ")
        )
    });
    let planes = (!planes.is_empty()).then(|| {
        format!(
            "stored and validated, but the plane section(s) {} serve nothing until the next \
             RESTART — a plane is opened once, at process start, when its section is configured, \
             and this process started without it",
            planes.join(", ")
        )
    });
    match (routes, planes) {
        (Some(r), Some(p)) => Some(format!("{r}; {p}")),
        (r, p) => r.or(p),
    }
}

fn section_contains(app: &App, section: NamedMapSection, name: &str) -> bool {
    match section {
        NamedMapSection::IdentityProviders => app.identity_providers.contains_key(name),
        NamedMapSection::Export => app.export_defs.contains_key(name),

        NamedMapSection::Plane(_) => {
            busbar_kernel::plane_driver::registry::plane_decl_for_config_section(section.key())
                .and_then(|d| d.registry_contains.map(|f| (d, f)))
                .is_some_and(|(d, f)| f(d, app, name))
        }
    }
}

fn validate_definition(
    section: NamedMapSection,
    name: &str,
    def: &serde_json::Value,
) -> Result<(), AdminError> {
    if name.trim().is_empty() {
        return Err(AdminError::Validation(format!(
            "{} name must not be empty",
            section.singular()
        )));
    }
    if name.len() > crate::v1::service::MAX_HOOK_NAME_LEN {
        return Err(AdminError::Validation(format!(
            "{} name is {} chars; must be <= {}",
            section.singular(),
            name.len(),
            crate::v1::service::MAX_HOOK_NAME_LEN
        )));
    }
    let Some(obj) = def.as_object() else {
        return Err(AdminError::Validation(if section.requires_module() {
            format!(
                "a {} definition must be an object (`{{\"module\": …}}`)",
                section.singular()
            )
        } else {
            format!("a {} definition must be an object", section.singular())
        }));
    };

    let module = obj.get("module").and_then(|m| m.as_str()).unwrap_or("");
    if section.requires_module() && module.trim().is_empty() {
        return Err(AdminError::Validation(format!(
            "a {} must name its backing plugin via a non-empty `module:`",
            section.singular()
        )));
    }
    if !section.requires_module() && !module.trim().is_empty() {
        return Err(AdminError::Validation(format!(
            "a definition in `{}` is a remote endpoint, not a plugin instance, so it has no \
             `module:`",
            section.key()
        )));
    }
    if let Some(serde_json::Value::Object(settings)) = obj.get(SETTINGS_KEY) {
        crate::v1::service::validate_hook_settings_size(settings)?;
    }
    Ok(())
}

fn check_trust_ceiling(
    section: NamedMapSection,
    current: &App,
    name: &str,
    def: &serde_json::Value,
) -> Result<(), Rejection> {
    use crate::v1::contract::Scope;
    if !section.has_trust_ceiling() {
        return Ok(());
    }

    fn ceiling_of(token: Option<&str>) -> Scope {
        token.and_then(Scope::parse).unwrap_or(Scope::ReadOnly)
    }
    let requested_token = def.get("max_admin_scope").and_then(|v| v.as_str());
    let requested = ceiling_of(requested_token);

    let live_token = section.max_admin_scope(&current.identity_providers, name);
    let live = ceiling_of(live_token.as_deref());
    if live.allows(requested) {
        return Ok(());
    }
    Err((
        AdminError::Conflict(format!(
            "refusing to RAISE `identity-providers.{name}.max_admin_scope` to `{}` through the \
             admin API: the trust ceiling caps the admin authority obtainable through this identity \
             provider, so raising it is a privilege escalation this API does not perform. Lower it \
             here, or raise it in config.yaml (current ceiling: `{}`)",
            requested_token.unwrap_or(busbar_kernel::config::DEFAULT_MAX_ADMIN_SCOPE),
            live.as_str()
        )),
        Cond::TrustCeilingRaise,
    ))
}

#[cfg(feature = "openapi-schema")]
pub(crate) fn openapi_paths() -> Vec<(String, serde_json::Value)> {
    use super::RESPONSES_KEY;
    use serde_json::{json, Value};

    fn operation(
        summary: String,
        name_param: Option<&Value>,
        status: &str,
        description: impl Into<Value>,
    ) -> Value {
        let mut op = json!({
            "summary": summary,
            RESPONSES_KEY: { status: {"description": description.into()} }
        });
        if let Some(param) = name_param {
            op["parameters"] = json!([param]);
        }
        op
    }
    let name_param = json!({
        "name": "name", "in": "path", "required": true, "schema": {"type": "string"}
    });
    let name_param = Some(&name_param);

    const OK: &str = "200";
    let mut out = Vec::new();
    for section in NamedMapSection::sections() {
        let key = section.key();
        let singular = section.singular();
        out.push((
            super::ap(section.path_root().as_ref()),
            json!({
                "get": operation(
                    format!(
                        "Every `{key}:` DEFINITION (the 1.5.3 named-definition map: name -> \
                         {{module, settings, ...}}, referenced by bare name). Secrets are never \
                         projected"
                    ),
                    None,
                    OK,
                    "OK",
                )
            }),
        ));
        out.push((
            super::ap(&item_path(section)),
            json!({
                "get": operation(format!("One `{key}:` definition"), name_param, OK, "OK"),
                "put": operation(
                    format!(
                        "Create or REPLACE one `{key}:` definition (upsert), persisted to the \
                         config overlay and live after an atomic rebuild-and-swap. A \
                         base-config-defined entry is 409 (edit config.yaml){}",
                        if section.has_trust_ceiling() {
                            "; RAISING `max_admin_scope` is refused outright (the trust ceiling is \
                             operator file policy)"
                        } else {
                            ""
                        }
                    ),
                    name_param,
                    OK,
                    format!(
                        "The stored {singular} definition. Additionally carries `reload_to_apply` \
                         (+ a `note`) when the mutation declared a plugin ROUTE this process cannot \
                         serve: each route path is registered on the HTTP router once, at process \
                         start, and an apply swaps only the config snapshot, so a path that did not \
                         exist at boot (e.g. `/metrics` for a first `prometheus` exporter) answers \
                         404 until the next RESTART. Both fields are omitted when nothing is pending"
                    ),
                ),
                "delete": operation(
                    format!(
                        "Remove one `{key}:` definition, refused while another config section \
                         still references it by bare name"
                    ),
                    name_param,
                    "204",
                    "Removed",
                )
            }),
        ));
        out.push((
            super::ap(&settings_path(section)),
            json!({
                "patch": operation(
                    format!(
                        "Replace ONLY the opaque `settings:` bag of one `{key}:` definition; every \
                         other field is left byte-identical"
                    ),
                    name_param,
                    OK,
                    format!(
                        "The updated {singular} definition (same `reload_to_apply` restart signal as \
                         the PUT, when the mutation declares a route the router lacks)"
                    ),
                )
            }),
        ));
    }
    out
}

#[cfg(test)]
#[path = "tests/named_map_tests.rs"]
mod tests;
