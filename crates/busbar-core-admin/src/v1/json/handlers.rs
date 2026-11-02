use super::*;
use crate::admin_state::AppAdmin as _;

use busbar_kernel::diagnostics::{
    diag_error, diag_warn, ADMIN_AUTH_CHAIN_EMPTY, PLUGIN_ROLLBACK_PIN_PERSIST_FAILED,
    PLUGIN_ROLLBACK_REVERT_FAILED,
};

/// Unwrap a `Result<_, Response>` (or, with `boxed`, a `Result<_, Box<Response>>`) or return the
/// ready-made response from the handler.
macro_rules! ok_or_respond {
    (boxed $e:expr) => {
        match $e {
            Ok(v) => v,
            Err(resp) => return *resp,
        }
    };
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(resp) => return resp,
        }
    };
}

fn reject(action: &str, resource: &str, actor: &str, e: &AdminError) -> Response {
    audit::AUDIT.record_by(action, resource, audit::OUTCOME_REJECTED, actor);
    err_json(e)
}

pub(crate) async fn info(State(handle): State<Arc<AppHandle>>) -> Response {
    respond(StatusCode::OK, service(&handle).info().await)
}

pub(crate) async fn list_pools(
    State(handle): State<Arc<AppHandle>>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    match q.get("detail").map(String::as_str) {
        Some("true") => {
            return respond(StatusCode::OK, service(&handle).list_pools_detailed().await)
        }

        Some(other) if other != "false" => {
            return err_json(&AdminError::Validation(
                "invalid `detail`: expected true|false".into(),
            ))
        }
        _ => {}
    }
    respond(StatusCode::OK, service(&handle).list_pools().await)
}

pub(crate) async fn get_pool(
    State(handle): State<Arc<AppHandle>>,
    Path(name): Path<String>,
) -> Response {
    respond(StatusCode::OK, service(&handle).get_pool(&name).await)
}

pub(crate) async fn list_models(State(handle): State<Arc<AppHandle>>) -> Response {
    respond(StatusCode::OK, service(&handle).list_models().await)
}

pub(crate) async fn list_providers(State(handle): State<Arc<AppHandle>>) -> Response {
    respond(StatusCode::OK, service(&handle).list_providers().await)
}

pub(crate) async fn list_hooks(State(handle): State<Arc<AppHandle>>) -> Response {
    let version = handle.load().config_version;
    with_config_etag(
        respond(StatusCode::OK, service(&handle).list_hooks().await),
        version,
    )
}

pub(crate) async fn get_hook(
    State(handle): State<Arc<AppHandle>>,
    Path(name): Path<String>,
) -> Response {
    let version = handle.load().config_version;
    with_config_etag(
        respond(StatusCode::OK, service(&handle).get_hook(&name).await),
        version,
    )
}

pub(crate) async fn list_groups(
    State(handle): State<Arc<AppHandle>>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let (start, limit) =
        ok_or_respond!(boxed page_window(&q, crate::v1::contract::LIST_LIMIT_DEFAULT));
    let version = handle.load().config_version;
    with_config_etag(
        respond(
            StatusCode::OK,
            service(&handle).list_groups(start, limit).await,
        ),
        version,
    )
}

pub(crate) async fn get_group(
    State(handle): State<Arc<AppHandle>>,
    Path(name): Path<String>,
) -> Response {
    let version = handle.load().config_version;
    with_config_etag(
        respond(StatusCode::OK, service(&handle).get_group(&name).await),
        version,
    )
}

pub(crate) async fn get_group_usage(
    State(handle): State<Arc<AppHandle>>,
    Path(name): Path<String>,
) -> Response {
    respond(
        StatusCode::OK,
        service(&handle).get_group_usage(&name).await,
    )
}

pub(crate) async fn hook_health(
    State(handle): State<Arc<AppHandle>>,
    Path(name): Path<String>,
) -> Response {
    respond(StatusCode::OK, service(&handle).hook_health(&name).await)
}

pub(crate) async fn list_plugins(
    State(handle): State<Arc<AppHandle>>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let ptype = q.get("type").map(String::as_str).unwrap_or("");
    respond(StatusCode::OK, service(&handle).list_plugins(ptype).await)
}

/// The `POST /api/v1/admin/plugins` request body: install a SIGNED plugin tarball. The tarball
/// bytes ride as base64 (`tarball_b64`): a plugin artifact is opaque binary, so base64 keeps it a
/// clean JSON field. The engine RE-VERIFIES the contained signed manifest server-side against the
/// running `plugins.*` trust posture (the client is never trusted). `file` is the bare `.tar.gz`
/// filename to store it under (storage only; identity comes from the signed manifest inside).
#[derive(serde::Deserialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct InstallPluginReq {
    file: String,
    tarball_b64: String,
}

pub(crate) async fn install_plugin(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<busbar_kernel::auth::AuthPrincipal>,
    body: axum::body::Bytes,
) -> Response {
    use base64::Engine as _;
    let actor = principal.actor_id().to_string();
    let req: InstallPluginReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            audit::AUDIT.record_by(
                "plugin.install",
                "plugin:?",
                audit::OUTCOME_REJECTED,
                &actor,
            );
            return err_json(&AdminError::Validation(format!(
                "malformed plugin body: {e}"
            )));
        }
    };
    let resource = format!("plugin:{}", req.file);
    let tarball = match base64::engine::general_purpose::STANDARD.decode(req.tarball_b64.as_bytes())
    {
        Ok(b) => b,
        Err(e) => {
            audit::AUDIT.record_by("plugin.install", &resource, audit::OUTCOME_REJECTED, &actor);
            return err_json(&AdminError::Validation(format!(
                "tarball_b64 is not valid base64: {e}"
            )));
        }
    };

    let file = req.file.clone();
    let out = config_transaction(&handle, move |txn| {
        let snapshot = txn.app().clone();
        Ok(txn.store_write(move || {
            let view = AdminService::new(snapshot).install_store_plugin(&file, &tarball)?;

            Ok(Outcome::Value(view))
        }))
    })
    .await;
    match out {
        Ok(view) => {
            audit::AUDIT.record_by("plugin.install", &resource, audit::OUTCOME_APPLIED, &actor);
            ok_json(StatusCode::CREATED, &view)
        }
        Err(e) => reject("plugin.install", &resource, &actor, &e),
    }
}

/// `POST /api/v1/admin/plugins/inspect` request body. SAME shape as [`InstallPluginReq`]; `file`
/// is accepted for shape parity with the install flow a UI composes around the same upload, but is
/// otherwise UNUSED here: inspect never writes anything to disk, so there is no filename to bind
/// an install would need.
#[derive(serde::Deserialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct InspectPluginReq {
    #[allow(dead_code)]
    file: String,
    tarball_b64: String,
}

pub(crate) async fn inspect_plugin(
    State(handle): State<Arc<AppHandle>>,
    body: axum::body::Bytes,
) -> Response {
    use base64::Engine as _;
    let req: InspectPluginReq = ok_or_respond!(boxed json_body(&body, "plugin"));
    let tarball = match base64::engine::general_purpose::STANDARD.decode(req.tarball_b64.as_bytes())
    {
        Ok(b) => b,
        Err(e) => {
            return err_json(&AdminError::Validation(format!(
                "tarball_b64 is not valid base64: {e}"
            )));
        }
    };

    let service = service(&handle);
    match tokio::task::spawn_blocking(move || service.inspect_plugin(&tarball)).await {
        Ok(view) => respond(StatusCode::OK, view),
        Err(join_err) => {
            diag_error!(
                busbar_kernel::diagnostics::ADMIN_STORE_TASK_JOIN_FAILED,
                operation = "plugins.inspect",
                error = %join_err,
                "admin blocking task failed"
            );
            err_json(&AdminError::Internal)
        }
    }
}

pub(crate) async fn remove_plugin(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<busbar_kernel::auth::AuthPrincipal>,
    Path(file): Path<String>,
) -> Response {
    let actor = principal.actor_id().to_string();
    let resource = format!("plugin:{file}");

    let out = config_transaction(&handle, move |txn| {
        let snapshot = txn.app().clone();
        Ok(txn.store_write(move || {
            AdminService::new(snapshot).remove_store_plugin(&file)?;
            Ok(Outcome::Value(()))
        }))
    })
    .await;
    match out {
        Ok(()) => {
            audit::AUDIT.record_by("plugin.remove", &resource, audit::OUTCOME_APPLIED, &actor);
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => reject("plugin.remove", &resource, &actor, &e),
    }
}

pub(crate) async fn reload_plugins(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<busbar_kernel::auth::AuthPrincipal>,
) -> Response {
    let actor = principal.actor_id().to_string();
    let card_origin = format!("plugins/reload by {actor}");

    let out = busbar_kernel::config::transaction::config_reload_transaction(&handle, |txn| {
        let snapshot = txn.app().clone();
        Ok(txn.read_store(move || {
            if snapshot.config_path.is_none() || snapshot.providers_path.is_none() {
                let view = AdminService::new(snapshot).reload_store_plugins()?;
                return Ok(Outcome::Value((None, Ok(view))));
            }
            let (next, gov_rotate, limits) =
                rebuild_app_from_disk(&snapshot).map_err(AdminError::Validation)?;
            let installed = Arc::new(next);

            let projected = AdminService::new(installed.clone()).reload_store_plugins();

            Ok(Outcome::commit_rates_then(
                installed.clone(),
                || Ok(()),
                limits,
                card_origin,
                move || {
                    if let Some(rotate) = gov_rotate {
                        rotate();
                    }
                    Ok(Outcome::Value((Some(installed), projected)))
                },
            ))
        }))
    })
    .await;
    match out {
        Ok((Some(_), projected)) => {
            audit::AUDIT.record_by(
                "plugin.reload",
                "plugin:dir",
                audit::OUTCOME_APPLIED,
                &actor,
            );
            match projected {
                Ok(view) => ok_json(StatusCode::OK, &view),
                Err(e) => err_json(&e),
            }
        }

        Ok((None, projected)) => match projected {
            Ok(view) => {
                audit::AUDIT.record_by(
                    "plugin.reload",
                    "plugin:dir",
                    audit::OUTCOME_APPLIED,
                    &actor,
                );
                ok_json(StatusCode::OK, &view)
            }
            Err(e) => reject("plugin.reload", "plugin:dir", &actor, &e),
        },
        Err(e) => reject("plugin.reload", "plugin:dir", &actor, &e),
    }
}

/// The `POST /api/v1/admin/plugins/rollback` body: the target library FILENAME to roll DOWN to.
#[derive(serde::Deserialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct PluginRollbackReq {
    /// The plugin tarball FILENAME (in the plugins directory) carrying the prior version to pin to.
    file: String,
}

struct UnpublishedPluginPin(Option<Arc<busbar_kernel::config::overlay::OverlayStore>>);

impl UnpublishedPluginPin {
    fn release(mut self) {
        drop(self.0.take());
    }
}

impl Drop for UnpublishedPluginPin {
    fn drop(&mut self) {
        if let Some(overlay) = &self.0 {
            overlay.require_reload();
        }
    }
}

pub(crate) async fn rollback_plugin(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<busbar_kernel::auth::AuthPrincipal>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let actor = principal.actor_id().to_string();
    let card_origin = format!("plugins/rollback by {actor}");
    let expected = ok_or_respond!(if_match_version(&headers));
    let req: PluginRollbackReq = ok_or_respond!(boxed json_body(&body, "rollback"));
    let resource = format!("plugin:{}", req.file);
    let file = req.file.clone();
    let audit_resource = resource.clone();

    let out = config_transaction(&handle, move |txn| {
        let current = txn.app();
        if let Some(e) = stale_if_match(expected, current.config_version) {
            return Err(e);
        }


        let Some(overlay_path) = current.overlay_path.clone() else {
            return Err(AdminError::Validation(
                busbar_kernel::config::overlay::NO_WRITABLE_OVERLAY_MSG.to_string(),
            ));
        };
        let snapshot = current.clone();
        Ok(txn.store_write(move || {

            let prior_pins = match overlay_path.read_required().map_err(AdminError::Validation)? {
                Some(doc) => doc.plugin_versions,
                None => std::collections::BTreeMap::new(),
            };


            let (manifest, pins) = AdminService::new(snapshot.clone())
                .resolve_plugin_rollback(&file, &prior_pins)?;









            if let Err(e) =
                busbar_kernel::config::overlay::try_persist_plugin_versions(Some(&overlay_path), &pins)
            {
                diag_error!(PLUGIN_ROLLBACK_PIN_PERSIST_FAILED, plugin = %audit_resource, error = %e, "plugin rollback: persisting the version pin failed; nothing swapped");
                return Err(AdminError::Validation(format!(
                    "plugin rollback could not confirm the version pin in the overlay: {e}; \
                     the running engine still serves the current plugin"
                )));
            }
            let pin_publication = UnpublishedPluginPin(Some(overlay_path.clone()));
            let (next, gov_rotate, limits) = match rebuild_app_from_disk(&snapshot) {
                Ok(triple) => triple,
                Err(e) => {








                    if let Err(revert_err) = busbar_kernel::config::overlay::try_persist_plugin_versions(
                        Some(&overlay_path),
                        &prior_pins,
                    ) {
                        diag_error!(
                            PLUGIN_ROLLBACK_REVERT_FAILED,
                            plugin = %audit_resource, rebuild_error = %e, revert_error = %revert_err,
                            "plugin rollback rebuild failed AND reverting the persisted version pin \
                             failed; the running engine still serves the prior plugin, but the Store now \
                             carries the rolled-forward pin — fix the overlay before restarting"
                        );
                        return Err(AdminError::Internal);
                    }

                    pin_publication.release();
                    return Err(AdminError::Validation(e));
                }
            };
            let installed = Arc::new(next);


            Ok(Outcome::commit_rates_then(installed.clone(), move || {
                pin_publication.release();
                Ok(())
            }, limits, card_origin, move || {
                if let Some(rotate) = gov_rotate {
                    rotate();
                }
                Ok(Outcome::Value((installed, manifest)))
            }))
        }))
    })
    .await;
    match out {
        Ok((installed, manifest)) => {
            audit::AUDIT.record_by("plugin.rollback", &resource, audit::OUTCOME_APPLIED, &actor);
            installed.record_version(
                &actor,
                &format!("plugin.rollback {resource} -> {}", manifest.version),
            );
            with_config_etag(
                ok_json(
                    StatusCode::OK,
                    &crate::v1::contract::PluginRollbackView {
                        name: manifest.name,
                        file: req.file,
                        version: manifest.version,
                        publisher: manifest.publisher,
                        config_version: installed.config_version,
                        note: "rolled the plugin DOWN to the prior version and hot-swapped to it; the \
                               version pin is persisted (survives restart) and the anti-downgrade \
                               floor was lowered ONLY for this explicit, audited action — a silent \
                               replay of an old artifact is still refused.",
                    },
                ),
                installed.config_version,
            )
        }
        Err(e) => reject("plugin.rollback", &resource, &actor, &e),
    }
}

pub(crate) async fn get_auth(State(handle): State<Arc<AppHandle>>) -> Response {
    respond(StatusCode::OK, service(&handle).get_auth().await)
}

pub(crate) async fn get_admin_auth(State(handle): State<Arc<AppHandle>>) -> Response {
    let version = handle.load().config_version;
    with_config_etag(
        respond(StatusCode::OK, service(&handle).get_admin_auth().await),
        version,
    )
}

pub(crate) async fn get_usage(
    State(handle): State<Arc<AppHandle>>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let window = match q.get("window") {
        None => None,
        Some(v) => match v.parse::<u64>() {
            Ok(w) => Some(w),
            Err(_) => {
                return err_json(&AdminError::Validation(
                    "invalid `window`: expected a UTC-day bucket start epoch".into(),
                ))
            }
        },
    };

    let as_of = match q.get("as_of") {
        None => None,
        Some(v) => match busbar_kernel::cost::EntryKey::parse_hex(v) {
            Some(key) => Some(key),
            None => {
                return err_json(&AdminError::Validation(
                    "invalid `as_of`: expected a 40-hex-digit rate-card history entry key".into(),
                ))
            }
        },
    };
    respond(
        StatusCode::OK,
        service(&handle).get_usage(window, as_of).await,
    )
}

pub(crate) async fn get_config(State(handle): State<Arc<AppHandle>>) -> Response {
    let version = handle.load().config_version;
    with_config_etag(
        respond(StatusCode::OK, service(&handle).get_config().await),
        version,
    )
}

/// The `POST /api/v1/admin/hooks` request body: the hook name + its definition. Optimistic concurrency
/// rides the `If-Match` header — never a body field.
#[derive(serde::Deserialize)]
pub(crate) struct RegisterHookReq {
    name: String,
    config: busbar_kernel::config::HookCfg,
}

/// The `PUT /api/v1/admin/hooks/{name}` body: the replacement definition (the name rides the path;
/// optimistic concurrency rides `If-Match`).
#[derive(serde::Deserialize)]
pub(crate) struct PutHookReq {
    config: busbar_kernel::config::HookCfg,
}

/// The `POST /api/v1/admin/groups` request body: the group name + its definition (a `GroupCfg`
/// accepted VERBATIM — paste a `groups:` block from config.yaml). Optimistic concurrency rides the
/// `If-Match` header, never a body field.
#[derive(serde::Deserialize)]
pub(crate) struct RegisterGroupReq {
    name: String,
    config: busbar_kernel::config::GroupCfg,
}

/// The `PUT /api/v1/admin/groups/{name}` body: the replacement definition (name rides the path;
/// optimistic concurrency rides `If-Match`).
#[derive(serde::Deserialize)]
pub(crate) struct PutGroupReq {
    config: busbar_kernel::config::GroupCfg,
}

/// The `PATCH /api/v1/admin/groups/{name}` body: a PARTIAL update — only the fields present are
/// changed, the rest preserved from the current definition. The ergonomic "raise Alice's budget"
/// (send just `limits`) and "freeze a group" (send `enabled: false`) verb. `limits`/`child_default`
/// REPLACE their whole list when present (a list can't be field-merged). To CLEAR `parent` or
/// `child_default` (make a group a root / drop its template), use `PUT` with the full definition.
/// `deny_unknown_fields` so a typo'd field is a 400, never a silent no-op.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GroupPatchReq {
    #[serde(default)]
    parent: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    limits: Option<Vec<busbar_kernel::config::LimitCfg>>,
    #[serde(default)]
    child_default: Option<busbar_kernel::config::groups::ChildDefault>,
}

pub(crate) async fn register_hook(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<busbar_kernel::auth::AuthPrincipal>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let actor = principal.actor_id().to_string();
    let expected = ok_or_respond!(if_match_version(&headers));
    let req: RegisterHookReq = ok_or_respond!(boxed json_body(&body, "hook"));
    let name = req.name.clone();
    let resource = format!("hook:{name}");
    let cfg = req.config;

    let txn_name = name.clone();
    let out = config_transaction(&handle, move |txn| {
        let current = txn.app();

        if current.base_hook_names.contains(&txn_name) {
            return Err(base_owned("hook", &txn_name));
        }
        if let Some(e) = stale_if_match(expected, current.config_version) {
            return Err(e);
        }

        let existed = current.hook_registry.contains_key(&txn_name);

        let snapshot = current.clone();
        Ok(txn.read_store(move || {
            let installed = Arc::new(build_with_hook(&snapshot, &txn_name, cfg)?);

            let p = installed.clone();
            Ok(Outcome::commit(
                installed.clone(),
                move || {
                    busbar_kernel::config::overlay::persist(
                        p.overlay_path.as_deref(),
                        &p.hook_registry,
                        &p.global_hooks,
                        None,
                        Some(&txn_name),
                        &p.base_hook_names,
                    )
                    .map_err(|e| {
                        format!(
                            "hook persistence to the overlay was not confirmed: {e}; \
                             the running engine is unaffected"
                        )
                    })
                },
                (installed, existed),
            ))
        }))
    })
    .await;
    match out {
        Ok((installed, existed)) => {
            audit::AUDIT.record_by("hook.register", &resource, audit::OUTCOME_APPLIED, &actor);
            installed.record_version(&actor, &format!("hook.register {resource}"));

            with_config_etag(
                respond(
                    if existed {
                        StatusCode::OK
                    } else {
                        StatusCode::CREATED
                    },
                    service(&handle).get_hook(&name).await,
                ),
                installed.config_version,
            )
        }
        Err(e) => reject("hook.register", &resource, &actor, &e),
    }
}

pub(crate) async fn put_hook(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<busbar_kernel::auth::AuthPrincipal>,
    Path(name): Path<String>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let actor = principal.actor_id().to_string();
    let expected = ok_or_respond!(if_match_version(&headers));
    let req: PutHookReq = ok_or_respond!(boxed json_body(&body, "hook"));
    let resource = format!("hook:{name}");
    let cfg = req.config;
    let txn_name = name.clone();
    let out = config_transaction(&handle, move |txn| {
        let current = txn.app();
        if !current.hook_registry.contains_key(&txn_name) {
            return Err(AdminError::not_found(format!("hook `{txn_name}`")));
        }
        if current.base_hook_names.contains(&txn_name) {
            return Err(base_owned("hook", &txn_name));
        }
        if let Some(e) = stale_if_match(expected, current.config_version) {
            return Err(e);
        }

        let snapshot = current.clone();
        Ok(txn.read_store(move || {
            let installed = Arc::new(build_with_hook(&snapshot, &txn_name, cfg)?);

            let p = installed.clone();
            Ok(Outcome::commit(
                installed.clone(),
                move || {
                    busbar_kernel::config::overlay::persist(
                        p.overlay_path.as_deref(),
                        &p.hook_registry,
                        &p.global_hooks,
                        None,
                        Some(&txn_name),
                        &p.base_hook_names,
                    )
                    .map_err(|e| {
                        format!(
                            "hook persistence to the overlay was not confirmed: {e}; \
                             the running engine is unaffected"
                        )
                    })
                },
                installed,
            ))
        }))
    })
    .await;
    match out {
        Ok(installed) => {
            audit::AUDIT.record_by("hook.replace", &resource, audit::OUTCOME_APPLIED, &actor);
            installed.record_version(&actor, &format!("hook.replace {resource}"));
            with_config_etag(
                respond(StatusCode::OK, service(&handle).get_hook(&name).await),
                installed.config_version,
            )
        }
        Err(e) => reject("hook.replace", &resource, &actor, &e),
    }
}

pub(crate) async fn delete_hook(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<busbar_kernel::auth::AuthPrincipal>,
    Path(name): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let actor = principal.actor_id().to_string();
    let expected = ok_or_respond!(if_match_version(&headers));
    let resource = format!("hook:{name}");
    let txn_name = name.clone();
    let out = config_transaction(&handle, move |txn| {
        let current = txn.app();

        if !current.hook_registry.contains_key(&txn_name) {
            return Err(AdminError::not_found(format!("hook `{txn_name}`")));
        }

        if current.base_hook_names.contains(&txn_name) {
            return Err(base_owned("hook", &txn_name));
        }

        if let Some(e) = stale_if_match(expected, current.config_version) {
            return Err(e);
        }

        let snapshot = current.clone();
        Ok(txn.read_store(move || {
            let installed = Arc::new(build_without_hook(&snapshot, &txn_name)?);

            let p = installed.clone();
            Ok(Outcome::commit(
                installed.clone(),
                move || {
                    busbar_kernel::config::overlay::persist(
                        p.overlay_path.as_deref(),
                        &p.hook_registry,
                        &p.global_hooks,
                        Some(&txn_name),
                        None,
                        &p.base_hook_names,
                    )
                    .map_err(|e| {
                        format!(
                            "hook deletion persistence to the overlay was not confirmed: {e}; \
                             the running engine is unaffected"
                        )
                    })
                },
                installed,
            ))
        }))
    })
    .await;
    match out {
        Ok(installed) => {
            audit::AUDIT.record_by("hook.delete", &resource, audit::OUTCOME_APPLIED, &actor);
            installed.record_version(&actor, &format!("hook.delete {resource}"));

            with_config_etag(
                StatusCode::NO_CONTENT.into_response(),
                installed.config_version,
            )
        }
        Err(e) => reject("hook.delete", &resource, &actor, &e),
    }
}

pub(crate) use busbar_kernel::governance::group_provision::{
    persist_provisioned_group, plan_mint_group,
};

pub(crate) async fn register_group(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<busbar_kernel::auth::AuthPrincipal>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let actor = principal.actor_id().to_string();
    let expected = ok_or_respond!(if_match_version(&headers));
    let req: RegisterGroupReq = ok_or_respond!(boxed json_body(&body, "group"));
    let name = req.name.clone();
    let resource = format!("group:{name}");
    let cfg = req.config;
    let txn_name = name.clone();
    let out = config_transaction(&handle, move |txn| {
        let current = txn.app();

        if current.base_group_names.contains(&txn_name) {
            return Err(base_owned("group", &txn_name));
        }
        if let Some(e) = stale_if_match(expected, current.config_version) {
            return Err(e);
        }
        let existed = current.groups_registry.contains_key(&txn_name);
        let installed = Arc::new(build_with_group(current, &txn_name, cfg)?);

        let p = installed.clone();
        Ok(txn.commit(
            installed.clone(),
            move || persist_group(&p, &txn_name),
            (installed, existed),
        ))
    })
    .await;
    match out {
        Ok((installed, existed)) => {
            audit::AUDIT.record_by("group.create", &resource, audit::OUTCOME_APPLIED, &actor);
            record_group_version(&installed, &actor, &format!("group.create {resource}"));
            with_config_etag(
                respond(
                    if existed {
                        StatusCode::OK
                    } else {
                        StatusCode::CREATED
                    },
                    service(&handle).get_group(&name).await,
                ),
                installed.config_version,
            )
        }
        Err(e) => reject("group.create", &resource, &actor, &e),
    }
}

pub(crate) async fn put_group(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<busbar_kernel::auth::AuthPrincipal>,
    Path(name): Path<String>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let actor = principal.actor_id().to_string();
    let expected = ok_or_respond!(if_match_version(&headers));
    let req: PutGroupReq = ok_or_respond!(boxed json_body(&body, "group"));
    let resource = format!("group:{name}");
    let cfg = req.config;
    let txn_name = name.clone();
    let out = config_transaction(&handle, move |txn| {
        let current = txn.app();
        if !current.groups_registry.contains_key(&txn_name) {
            return Err(AdminError::not_found(format!("group `{txn_name}`")));
        }
        if current.base_group_names.contains(&txn_name) {
            return Err(base_owned("group", &txn_name));
        }
        if let Some(e) = stale_if_match(expected, current.config_version) {
            return Err(e);
        }
        let installed = Arc::new(build_with_group(current, &txn_name, cfg)?);

        let p = installed.clone();
        Ok(txn.commit(
            installed.clone(),
            move || persist_group(&p, &txn_name),
            installed,
        ))
    })
    .await;
    match out {
        Ok(installed) => {
            audit::AUDIT.record_by("group.replace", &resource, audit::OUTCOME_APPLIED, &actor);
            record_group_version(&installed, &actor, &format!("group.replace {resource}"));
            with_config_etag(
                respond(StatusCode::OK, service(&handle).get_group(&name).await),
                installed.config_version,
            )
        }
        Err(e) => reject("group.replace", &resource, &actor, &e),
    }
}

pub(crate) async fn patch_group(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<busbar_kernel::auth::AuthPrincipal>,
    Path(name): Path<String>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let actor = principal.actor_id().to_string();
    let expected = ok_or_respond!(if_match_version(&headers));
    let req: GroupPatchReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return err_json(&AdminError::Validation(format!(
                "malformed group patch: {e}"
            )))
        }
    };
    let resource = format!("group:{name}");
    let txn_name = name.clone();
    let out = config_transaction(&handle, move |txn| {
        let current = txn.app();
        let Some(existing) = current.groups_registry.get(&txn_name) else {
            return Err(AdminError::not_found(format!("group `{txn_name}`")));
        };
        if current.base_group_names.contains(&txn_name) {
            return Err(base_owned("group", &txn_name));
        }
        if let Some(e) = stale_if_match(expected, current.config_version) {
            return Err(e);
        }

        let merged = merge_group_patch(
            existing.clone(),
            req.parent,
            req.enabled,
            req.limits,
            req.child_default,
        );
        let installed = Arc::new(build_with_group(current, &txn_name, merged)?);

        let p = installed.clone();
        Ok(txn.commit(
            installed.clone(),
            move || persist_group(&p, &txn_name),
            installed,
        ))
    })
    .await;
    match out {
        Ok(installed) => {
            audit::AUDIT.record_by("group.patch", &resource, audit::OUTCOME_APPLIED, &actor);
            record_group_version(&installed, &actor, &format!("group.patch {resource}"));
            with_config_etag(
                respond(StatusCode::OK, service(&handle).get_group(&name).await),
                installed.config_version,
            )
        }
        Err(e) => reject("group.patch", &resource, &actor, &e),
    }
}

pub(crate) async fn delete_group(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<busbar_kernel::auth::AuthPrincipal>,
    Path(name): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let actor = principal.actor_id().to_string();
    let expected = ok_or_respond!(if_match_version(&headers));
    let resource = format!("group:{name}");
    let txn_name = name.clone();
    let out = config_transaction(&handle, move |txn| {
        let current = txn.app();
        if !current.groups_registry.contains_key(&txn_name) {
            return Err(AdminError::not_found(format!("group `{txn_name}`")));
        }

        if current.base_group_names.contains(&txn_name) {
            return Err(base_owned("group", &txn_name));
        }
        if let Some(e) = stale_if_match(expected, current.config_version) {
            return Err(e);
        }

        let snapshot = current.clone();
        Ok(txn.read_store(move || {
            let bound = crate::v1::service::count_keys_bound_to(&snapshot, &txn_name)?;
            let installed = Arc::new(build_without_group(&snapshot, &txn_name, bound)?);

            let p = installed.clone();
            Ok(Outcome::commit(
                installed.clone(),
                move || {
                    busbar_kernel::config::overlay::persist_groups(
                        p.overlay_path.as_deref(),
                        &p.groups_registry,
                        Some(&txn_name),
                        None,
                        &p.base_group_names,
                    )
                    .map_err(|e| {
                        format!(
                            "group deletion persistence to the overlay was not confirmed: {e}; \
                             the running engine is unaffected"
                        )
                    })
                },
                installed,
            ))
        }))
    })
    .await;
    match out {
        Ok(installed) => {
            audit::AUDIT.record_by("group.delete", &resource, audit::OUTCOME_APPLIED, &actor);
            record_group_version(&installed, &actor, &format!("group.delete {resource}"));

            if let Some(gov) = installed.governance.as_ref() {
                let dropped = gov.reclaim_group_cells(&name);
                if dropped > 0 {
                    tracing::debug!(
                        group = %name,
                        cells = dropped,
                        "reclaimed the deleted group's in-memory budget cells"
                    );
                }
            }
            with_config_etag(
                StatusCode::NO_CONTENT.into_response(),
                installed.config_version,
            )
        }
        Err(e) => reject("group.delete", &resource, &actor, &e),
    }
}

fn overlay_names_sentence(names: &[String]) -> String {
    match names {
        [] => String::new(),
        [one] => one.clone(),
        [a, b] => format!("{a} or {b}"),
        [head @ .., last] => format!("{}, or {last}", head.join(", ")),
    }
}

pub(crate) async fn reset_overlay_section(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<busbar_kernel::auth::AuthPrincipal>,
    Path(section): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    use busbar_kernel::config::overlay::OverlaySection;
    let actor = principal.actor_id().to_string();
    let card_origin = format!("overlay reset by {actor}");

    let served = |s: &OverlaySection| match s {
        OverlaySection::NamedMap(m) => super::named_map::plane_gate(&handle, *m).is_none(),
        _ => true,
    };
    let Some(section) = OverlaySection::parse(&section).filter(served) else {
        let names: Vec<String> = OverlaySection::all()
            .iter()
            .filter(|s| served(s))
            .map(|s| format!("`{}`", s.as_str()))
            .collect();
        return err_json(&AdminError::Validation(format!(
            "unknown overlay section `{section}`: expected {}",
            overlay_names_sentence(&names)
        )));
    };
    let resource = format!("overlay:{}", section.as_str());
    let expected = ok_or_respond!(if_match_version(&headers));

    let out = config_transaction(&handle, move |txn| {
        let current = txn.app();
        if let Some(e) = stale_if_match(expected, current.config_version) {
            return Err(e);
        }
        let snapshot = current.clone();
        Ok(txn.read_store(move || {




            let overlay_empty = match snapshot.overlay_path.as_deref() {
                None => true,
                Some(p) => match busbar_kernel::config::overlay::read_state(p) {
                    busbar_kernel::config::overlay::OverlayReadState::Absent => true,
                    busbar_kernel::config::overlay::OverlayReadState::Loaded(doc) => {
                        doc.section_is_empty(section)
                    }





                    busbar_kernel::config::overlay::OverlayReadState::Unreadable => {
                        return Err(AdminError::Validation(format!(
                            "the config overlay at '{}' is present but unreadable/corrupt; refusing \
                             to reset section `{}` (a reset probe over corrupt state cannot tell \
                             whether this section still carries live overrides). Fix or remove the \
                             Store overlay, or restore it from backup, before resetting",
                            p.display(),
                            section.as_str()
                        )));
                    }
                    busbar_kernel::config::overlay::OverlayReadState::VersionTooNew(v) => {
                        return Err(AdminError::Validation(format!(
                            "the config overlay at '{}' was written by a NEWER busbar (version {v}) \
                             than this one; refusing to reset section `{}` rather than silently \
                             ignoring overrides this process cannot understand",
                            p.display(),
                            section.as_str()
                        )));
                    }
                },
            };
            if overlay_empty {
                return Ok(Outcome::Value((snapshot.config_version, None)));
            }



            let (Some(config_path), Some(providers_path)) = (
                snapshot.config_path.clone(),
                snapshot.providers_path.clone(),
            ) else {
                return Err(AdminError::Validation(
                    "this busbar was started without config files (ephemeral mode); a per-section \
                     reset has no disk truth to revert to"
                        .into(),
                ));
            };
            let loaded_base = busbar_kernel::load_config_from_disk_with_store(
                &config_path,
                Some(&providers_path),
                false,
                busbar_kernel::config::EnvSubst::Strict,
                &*snapshot.root_rules,
                snapshot.overlay_path.clone(),
            )
            .map_err(AdminError::Validation)?;













            if let OverlaySection::NamedMap(nm) = section {
                let dangling: Vec<String> = loaded_base
                    .overlay_doc
                    .as_ref()
                    .and_then(|doc| doc.named_maps.get(nm.key()))
                    .map(|entries| {
                        entries
                            .keys()
                            .filter(|name| !nm.contains(&loaded_base.deploy, name))
                            .filter_map(|name| {
                                let referents = nm.referents(&loaded_base.deploy, name);
                                (!referents.is_empty())
                                    .then(|| format!("`{name}` (still referenced by {})", referents.join(", ")))
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                if !dangling.is_empty() {
                    return Err(AdminError::Conflict(format!(
                        "cannot reset the `{}` overlay section: base config.yaml would be left \
                         naming {} that the reset removes — {}. Remove the reference(s) from \
                         config.yaml first, or delete the definitions individually.",
                        nm.key(),
                        nm.singular(),
                        dangling.join("; ")
                    )));
                }
            }
            let built = Ok(loaded_base)
            .and_then(|mut loaded| {




                let cleared_doc = loaded.overlay_doc.take().map(|mut doc| {
                    doc.clear_section(section);
                    doc
                });


                if let Some(doc) = cleared_doc.as_ref() {
                    busbar_kernel::config::overlay::apply_root_to_deploy(&mut loaded.deploy, doc);
                }
                let mut cfg = busbar_kernel::config::resolve(&loaded.deploy, &loaded.defs)
                    .map_err(|errs| format!("config errors:\n  - {}", errs.join("\n  - ")))?;
                let base_hook_names: std::collections::HashSet<String> =
                    cfg.hooks.keys().cloned().collect();
                let base_group_names: std::collections::HashSet<String> =
                    cfg.groups.keys().cloned().collect();


                if let Some(doc) = cleared_doc {
                    busbar_kernel::config::overlay::merge_into(&mut cfg, doc);
                }
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
            })
            .map_err(AdminError::Validation)?;
            let (built, gov_rotate, limits) = built;
            let installed = Arc::new(built);









            let persist_overlay = snapshot.overlay_path.clone();
            let version = installed.config_version;


            Ok(Outcome::commit_rates_then(
                installed.clone(),
                move || {
                    busbar_kernel::config::overlay::clear_section(persist_overlay.as_deref(), section).map_err(
                        |e| {
                            format!(
                                "overlay section reset persistence was not confirmed: {e}; \
                                 the running engine is unaffected"
                            )
                        },
                    )
                },
                limits,
                card_origin,
                move || {
                    if let Some(rotate) = gov_rotate {
                        rotate();
                    }
                    Ok(Outcome::Value((version, Some(installed))))
                },
            ))
        }))
    })
    .await;
    match out {
        Ok((version, None)) => {
            audit::AUDIT.record_by("overlay.reset", &resource, audit::OUTCOME_APPLIED, &actor);
            with_config_etag(
                ok_json(
                    StatusCode::OK,
                    &json!({
                        "reset": section.as_str(),
                        "config_version": version,
                        "changed": false
                    }),
                ),
                version,
            )
        }
        Ok((version, Some(installed))) => {
            audit::AUDIT.record_by("overlay.reset", &resource, audit::OUTCOME_APPLIED, &actor);
            record_group_version(
                &installed,
                &actor,
                &format!("overlay.reset {} (revert to config.yaml)", section.as_str()),
            );
            with_config_etag(
                ok_json(
                    StatusCode::OK,
                    &json!({
                        "reset": section.as_str(),
                        "config_version": version,
                        "changed": true
                    }),
                ),
                version,
            )
        }
        Err(e) => {
            audit::AUDIT.record_by("overlay.reset", &resource, audit::OUTCOME_REJECTED, &actor);

            match &e {
                AdminError::Conflict(m) if m.contains("would be left naming") => {
                    err_json_cond(&e, Cond::StillReferenced)
                }
                _ => err_json(&e),
            }
        }
    }
}

fn merge_group_patch(
    mut base: busbar_kernel::config::GroupCfg,
    parent: Option<String>,
    enabled: Option<bool>,
    limits: Option<Vec<busbar_kernel::config::LimitCfg>>,
    child_default: Option<busbar_kernel::config::groups::ChildDefault>,
) -> busbar_kernel::config::GroupCfg {
    if let Some(p) = parent {
        base.parent = Some(p);
    }
    if let Some(en) = enabled {
        base.enabled = en;
    }
    if let Some(l) = limits {
        base.limits = l;
    }
    if let Some(cd) = child_default {
        base.child_default = Some(cd);
    }
    base
}

fn persist_group(installed: &busbar_kernel::state::App, name: &str) -> Result<(), String> {
    busbar_kernel::config::overlay::persist_groups(
        installed.overlay_path.as_deref(),
        &installed.groups_registry,
        None,
        Some(name),
        &installed.base_group_names,
    )
    .map_err(|e| {
        format!(
            "group persistence to the overlay was not confirmed: {e}; \
             the running engine is unaffected"
        )
    })
}

fn record_group_version(installed: &Arc<busbar_kernel::state::App>, actor: &str, summary: &str) {
    installed.record_version(actor, summary);
}

pub(crate) async fn get_audit(
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let (start, limit) =
        ok_or_respond!(boxed page_window(&q, crate::v1::contract::LIST_LIMIT_DEFAULT));
    let action = q.get("action").map(String::as_str);
    let resource = q.get("resource").map(String::as_str);

    let mut entries =
        busbar_kernel::audit::auditlog::AUDIT_LOG.list_filtered(start, limit + 1, action, resource);
    let next_cursor = page_cursor(&mut entries, start, limit);
    ok_json(
        StatusCode::OK,
        &json!({ "items": entries, "next_cursor": next_cursor }),
    )
}

pub(crate) async fn list_config_versions(
    State(handle): State<Arc<AppHandle>>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let (start, limit) =
        ok_or_respond!(boxed page_window(&q, crate::v1::contract::VERSIONS_LIMIT_DEFAULT));
    let mut versions = handle.load().versions().list(start, limit + 1);
    let next_cursor = page_cursor(&mut versions, start, limit);
    ok_json(
        StatusCode::OK,
        &json!({ "items": versions, "next_cursor": next_cursor }),
    )
}

pub(crate) async fn get_config_version(
    State(handle): State<Arc<AppHandle>>,
    Path(v): Path<String>,
) -> Response {
    let Ok(v) = v.parse::<u64>() else {
        return err_json(&AdminError::Validation(format!(
            "config version must be a non-negative integer; got `{v}`"
        )));
    };
    match handle.load().versions().get(v) {
        Some(cv) => {
            let registry = match decode_hook_registry(&cv.hook_registry) {
                Ok(r) => r,
                Err(e) => return err_json(&e),
            };
            let hooks: std::collections::BTreeMap<&String, _> = registry
                .iter()
                .map(|(name, cfg)| {
                    (
                        name,
                        crate::v1::service::project_hook_view(name, cfg, &cv.global_hooks),
                    )
                })
                .collect();
            ok_json(
                StatusCode::OK,
                &json!({
                    "version": cv.version,
                    "ts": cv.ts,
                    "principal": cv.principal,
                    "summary": cv.summary,
                    "hooks": hooks,
                    "global_hooks": cv.global_hooks,
                }),
            )
        }
        None => err_json(&AdminError::not_found(format!(
            "config version {v} (pruned or never recorded)"
        ))),
    }
}

fn decode_hook_registry(
    snapshot: &serde_json::Value,
) -> Result<std::collections::HashMap<String, busbar_kernel::config::HookCfg>, AdminError> {
    serde_json::from_value(snapshot.clone()).map_err(|_| AdminError::Internal)
}

pub(crate) async fn config_diff(
    State(handle): State<Arc<AppHandle>>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let (Some(from), Some(to)) = (
        q.get("from").and_then(|s| s.parse::<u64>().ok()),
        q.get("to").and_then(|s| s.parse::<u64>().ok()),
    ) else {
        return err_json(&AdminError::Validation(
            "`from` and `to` query params (version numbers) are required".into(),
        ));
    };
    let app = handle.load();

    let a = match app.versions().get(from) {
        Some(v) => v,
        None => {
            return err_json(&AdminError::not_found(format!(
                "config version {from} (pruned or never recorded)"
            )))
        }
    };
    let b = match app.versions().get(to) {
        Some(v) => v,
        None => {
            return err_json(&AdminError::not_found(format!(
                "config version {to} (pruned or never recorded)"
            )))
        }
    };
    let empty = serde_json::Map::new();
    let (ra, rb) = (
        a.hook_registry.as_object().unwrap_or(&empty),
        b.hook_registry.as_object().unwrap_or(&empty),
    );
    let mut added: Vec<&String> = rb.keys().filter(|k| !ra.contains_key(*k)).collect();
    let mut removed: Vec<&String> = ra.keys().filter(|k| !rb.contains_key(*k)).collect();

    let mut changed: Vec<&String> = ra
        .iter()
        .filter(|(k, va)| rb.get(*k).is_some_and(|vb| *va != vb))
        .map(|(k, _)| k)
        .collect();
    added.sort();
    removed.sort();
    changed.sort();
    let mut body = json!({
        "from": from,
        "to": to,
        "hooks": { "added": added, "removed": removed, "changed": changed },
    });
    if a.global_hooks != b.global_hooks {
        body["global_hooks"] = json!({ "from": a.global_hooks, "to": b.global_hooks });
    }
    ok_json(StatusCode::OK, &body)
}

/// The `PUT /api/v1/admin/admin-auth` body: the replacement admin auth chain.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct PutAuthBody {
    /// The ordered admin auth module chain. Empty is the explicit open dev posture.
    admin_auth: Vec<String>,
}

/// The `POST /api/v1/admin/auth/cache/flush` body. An absent body (or an absent `module`) flushes
/// every partition. Deliberately NOT `deny_unknown_fields`: the endpoint has always ignored extra
/// members, and tightening that would reject a call that works today.
#[derive(serde::Deserialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct FlushCacheReq {
    /// The auth module whose cache partition to flush. Omitted = flush all.
    #[serde(default)]
    module: Option<String>,
}

/// The `POST /api/v1/admin/config/rollback` request body. Optimistic concurrency rides `If-Match`.
#[derive(serde::Deserialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct RollbackReq {
    /// The retained version to restore.
    version: u64,
}

pub(crate) async fn rollback_config(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<busbar_kernel::auth::AuthPrincipal>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let actor = principal.actor_id().to_string();
    let expected = ok_or_respond!(if_match_version(&headers));
    let req: RollbackReq = ok_or_respond!(boxed json_body(&body, "rollback"));
    let resource = format!("config:v{}", req.version);
    let want = req.version;
    let out = config_transaction(&handle, move |txn| {
        let current = txn.app();
        if let Some(e) = stale_if_match(expected, current.config_version) {
            return Err(e);
        }
        let Some(target) = current.versions().get(want) else {
            return Err(AdminError::not_found(format!(
                "config version {want} (pruned or never recorded)"
            )));
        };

        let snapshot = current.clone();
        let registry = decode_hook_registry(&target.hook_registry)?;
        Ok(txn.read_store(move || {
            let installed = Arc::new(build_with_registry(
                &snapshot,
                registry,
                target.global_hooks,
            )?);

            let p = installed.clone();
            Ok(Outcome::commit(
                installed.clone(),
                move || {
                    busbar_kernel::config::overlay::persist(
                        p.overlay_path.as_deref(),
                        &p.hook_registry,
                        &p.global_hooks,
                        None,
                        None,
                        &p.base_hook_names,
                    )
                    .map_err(|e| {
                        format!(
                            "config rollback persistence to the overlay was not confirmed: {e}; \
                             the running engine is unaffected"
                        )
                    })
                },
                installed,
            ))
        }))
    })
    .await;
    match out {
        Ok(installed) => {
            audit::AUDIT.record_by("config.rollback", &resource, audit::OUTCOME_APPLIED, &actor);
            installed.record_version(&actor, &format!("config.rollback to v{}", req.version));
            with_config_etag(
                ok_json(
                    StatusCode::OK,
                    &json!({
                        "restored_version": req.version,
                        // The post-rollback version under the SAME name every other mutation uses.
                        "config_version": installed.config_version,
                    }),
                ),
                installed.config_version,
            )
        }
        Err(e) => reject("config.rollback", &resource, &actor, &e),
    }
}

pub(crate) async fn put_auth(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<busbar_kernel::auth::AuthPrincipal>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let expected = ok_or_respond!(if_match_version(&headers));
    let req: PutAuthBody = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(e) => return err_json(&AdminError::Validation(format!("invalid body: {e}"))),
    };
    let chain = req.admin_auth.clone();
    let out = config_transaction(&handle, move |txn| {
        let current = txn.app();
        if let Some(e) = stale_if_match(expected, current.config_version) {
            return Err(e);
        }






        if current.overlay_path.is_none() {
            return Err(AdminError::Validation(
                busbar_kernel::config::overlay::NO_WRITABLE_OVERLAY_MSG.to_string(),
            ));
        }



        let operator = busbar_kernel::config::operator_provider();
        let in_process = busbar_kernel::preflight::root_rows().in_process_auth;
        for name in &req.admin_auth {
            let known = current.admin_modules.operator.is(name)
                || in_process.is_some_and(|answers| answers(name));
            if !known {
                return Err(AdminError::Validation(format!(
                    "admin_auth names unknown module '{name}'; the built-in admin module is \
                     `{operator}` (external admin modules are registered at compile time)"
                )));
            }
        }
        let empty = req.admin_auth.is_empty();
        if empty {



            if EMPTY_CHAIN_REFUSED_LIVE {
                return Err(empty_chain_refusal(operator));
            }
            diag_warn!(
                ADMIN_AUTH_CHAIN_EMPTY,
                "PUT /api/v1/admin/admin-auth applied an EMPTY admin_auth chain — the admin API is \
                 now the open (anonymous, full-authority) dev posture"
            );
        }



        let mut next = (**current).clone();
        next.config_version = current.config_version.wrapping_add(1);
        next.admin_chain = req.admin_auth;



        let survives = empty
            || busbar_kernel::auth::dry_run_admin_scope(&next, &headers)
                .contains(crate::v1::contract::Scope::Full);
        if !survives {
            return Err(AdminError::Conflict(
                "the new admin_auth chain would not grant THIS caller full scope — refusing to lock \
                 you out. Authenticate with a credential the new chain accepts (at full scope) and \
                 retry, or change the chain in config.yaml and restart"
                    .into(),
            ));
        }


        let installed = Arc::new(next);
        Ok(txn.live_swap(installed.clone(), installed))
    })
    .await;
    let installed = match out {
        Ok(installed) => installed,
        Err(e) => {
            audit::AUDIT.record_by(
                "auth.admin_chain_put",
                "auth:admin_auth",
                audit::OUTCOME_REJECTED,
                principal.actor_id(),
            );
            return err_json(&e);
        }
    };
    audit::AUDIT.record_by(
        "auth.admin_chain_put",
        "auth:admin_auth",
        audit::OUTCOME_APPLIED,
        principal.actor_id(),
    );
    installed.record_version(principal.actor_id(), "auth.admin_chain_put");

    with_config_etag(
        ok_json(
            StatusCode::OK,
            &json!({
                "configured": !chain.is_empty(),
                "modules": chain,
                "applied": true,
                "config_version": installed.config_version,
                "note": "live until the next config reload/restart returns to disk truth; persist by updating config.yaml"
            }),
        ),
        installed.config_version,
    )
}

pub(crate) async fn flush_credential_cache(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<busbar_kernel::auth::AuthPrincipal>,
    body: axum::body::Bytes,
) -> Response {
    let app = handle.load();
    let module: Option<String> =
        if body.is_empty() {
            None
        } else {
            match serde_json::from_slice::<FlushCacheReq>(&body) {
                Ok(v) => v.module,
                Err(_) => return err_json(&AdminError::Validation(
                    "body must be JSON with an optional string `module` (the auth module whose \
                     partition to flush)"
                        .into(),
                )),
            }
        };
    let flushed = match app.flush_verified_credentials(module.as_deref()) {
        Ok(count) => count,
        Err(_) => {
            tracing::warn!("credential cache flush incomplete: an auth module failed to refresh; other modules may already have refreshed");
            return reject(
                "auth.cache_flush",
                module.as_deref().unwrap_or("*"),
                principal.actor_id(),
                &AdminError::Internal,
            );
        }
    };
    audit::AUDIT.record_by(
        "auth.cache_flush",
        module.as_deref().unwrap_or("*"),
        audit::OUTCOME_APPLIED,
        principal.actor_id(),
    );
    ok_json(StatusCode::OK, &json!({ "flushed": flushed }))
}

#[cold]
#[inline(never)]
pub(crate) fn rebuild_app_from_disk(
    current: &Arc<busbar_kernel::state::App>,
) -> Result<
    (
        busbar_kernel::state::App,
        Option<busbar_kernel::GovCredentialRotation>,
        busbar_kernel::InstalledLimits,
    ),
    String,
> {
    let (Some(config_path), Some(providers_path)) =
        (current.config_path.clone(), current.providers_path.clone())
    else {
        return Err(
            "this busbar was started without config files (ephemeral mode); reload has no \
                    disk truth to read"
                .into(),
        );
    };

    let overlay = match current.overlay_path.clone() {
        Some(store) => Some(store),
        None => {
            let base = busbar_kernel::load_config_from_disk_judged(
                &config_path,
                Some(&providers_path),
                false,
                busbar_kernel::config::EnvSubst::Strict,
                &*current.root_rules,
            )?;
            if base.config_locked {
                None
            } else {
                let calls = current
                    .governance
                    .as_ref()
                    .and_then(|gov| gov.store_calls())
                    .ok_or_else(|| {
                        "running config has no opened Store for config persistence".to_string()
                    })?;
                Some(busbar_kernel::config::overlay::OverlayStore::new(calls)?)
            }
        }
    };
    let mut loaded = busbar_kernel::load_config_from_disk_with_store(
        &config_path,
        Some(&providers_path),
        false,
        busbar_kernel::config::EnvSubst::Strict,
        &*current.root_rules,
        overlay,
    )?;

    if let Some(doc) = loaded.overlay_doc.as_ref() {
        busbar_kernel::config::overlay::apply_root_to_deploy(&mut loaded.deploy, doc);
    }
    let mut cfg = busbar_kernel::config::resolve(&loaded.deploy, &loaded.defs)
        .map_err(|errs| format!("config errors:\n  - {}", errs.join("\n  - ")))?;

    let base_hook_names: std::collections::HashSet<String> = cfg.hooks.keys().cloned().collect();
    let base_group_names: std::collections::HashSet<String> = cfg.groups.keys().cloned().collect();
    if let Some(doc) = loaded.overlay_doc {
        busbar_kernel::config::overlay::merge_into(&mut cfg, doc);
    }

    busbar_kernel::build_app_from_config(
        cfg,
        loaded.deploy.plugins.clone(),
        loaded.overlay_path,
        base_hook_names,
        base_group_names,
        (Some(config_path), Some(providers_path)),
        Some(current.as_ref()),
        &current.root_rules,
    )
}

pub(crate) async fn reload_config(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<busbar_kernel::auth::AuthPrincipal>,
) -> Response {
    let actor = principal.actor_id().to_string();
    let card_origin = format!("config/reload by {actor}");

    let out = busbar_kernel::config::transaction::config_reload_transaction(&handle, |txn| {
        let snapshot = txn.app().clone();
        Ok(txn.read_store(move || {
            let (next, gov_rotate, limits) =
                rebuild_app_from_disk(&snapshot).map_err(AdminError::Validation)?;

            let installed = Arc::new(next);

            Ok(Outcome::commit_rates_then(
                installed.clone(),
                || Ok(()),
                limits,
                card_origin,
                move || {
                    if let Some(rotate) = gov_rotate {
                        rotate();
                    }
                    Ok(Outcome::Value(installed))
                },
            ))
        }))
    })
    .await;
    match out {
        Ok(installed) => {
            audit::AUDIT.record_by(
                "config.reload",
                "config:disk",
                audit::OUTCOME_APPLIED,
                &actor,
            );
            installed.record_version(&actor, "config.reload (from disk)");
            let mut body = json!({ "reloaded": true, "config_version": installed.config_version });

            if let Some(note) =
                super::named_map::restart_note(&[], &installed.planes_awaiting_restart)
            {
                body["reload_to_apply"] = json!(installed.planes_awaiting_restart);
                body["note"] = json!(note);
            }
            with_config_etag(ok_json(StatusCode::OK, &body), installed.config_version)
        }
        Err(e) => reject("config.reload", "config:disk", &actor, &e),
    }
}

/// The `POST /api/v1/admin/restart` body. Absent is the same as `{}`.
#[derive(serde::Deserialize, Default)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct RestartReq {
    /// Proceed even though no supervisor was detected. Exiting only restarts busbar if something
    /// restarts it; without this an undetected supervisor is refused rather than risking the
    /// gateway staying down.
    #[serde(default)]
    confirm: bool,
}

pub(crate) async fn restart(
    axum::Extension(principal): axum::Extension<busbar_kernel::auth::AuthPrincipal>,
    body: axum::body::Bytes,
) -> Response {
    let actor = principal.actor_id().to_string();
    let req: RestartReq = if body.is_empty() {
        RestartReq::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(r) => r,
            Err(e) => {
                audit::AUDIT.record_by("admin.restart", "process", audit::OUTCOME_REJECTED, &actor);
                return err_json_cond(
                    &AdminError::Validation(format!("invalid body: {e}")),
                    Cond::MalformedBody,
                );
            }
        }
    };

    let supervised = crate::restart::supervisor_detected();
    if !supervised && !req.confirm {
        audit::AUDIT.record_by("admin.restart", "process", audit::OUTCOME_REJECTED, &actor);
        return err_json_cond(
            &AdminError::Conflict(
                "no process supervisor was detected, so exiting would leave busbar down; re-send                  with `confirm: true` if a supervisor will restart it"
                    .into(),
            ),
            Cond::NoSupervisor,
        );
    }

    if !crate::restart::can_restart() {
        audit::AUDIT.record_by("admin.restart", "process", audit::OUTCOME_REJECTED, &actor);
        return err_json_cond(
            &AdminError::Conflict("this process cannot restart itself".into()),
            Cond::NotRestartable,
        );
    }

    audit::AUDIT.record_by("admin.restart", "process", audit::OUTCOME_APPLIED, &actor);
    crate::restart::begin_drain();

    ok_json(
        StatusCode::ACCEPTED,
        &json!({
            "restarting": true,
            "supervisor_detected": supervised,
            "note": "draining now; in-flight requests finish first. The process exits when the \
                     drain completes and the supervisor restarts it."
        }),
    )
}

/// The `POST /api/v1/admin/config/apply` body: a full proposed config (validate's exact shape).
/// Optimistic concurrency rides `If-Match`.
///
/// `config` is carried as a raw [`serde_json::Value`] and parsed by the SAME pre-pass boot runs
/// (`busbar_kernel::config::deploy_from_deserializer`), exactly as [`ValidateConfigReq`] is: the
/// plane sections (each linked plane's declared section key) are lifted before the frozen
/// `deny_unknown_fields` `DeployCfg` parses the remainder. Apply accepts
/// the same config shape as boot,
/// including plane sections, and passes them
/// to each plane's refresh without restarting.
#[derive(serde::Deserialize)]
pub(crate) struct ApplyConfigReq {
    /// The deploy config (operator-owned `config.yaml` shape), pre-lift.
    config: serde_json::Value,
    /// The provider definitions (`providers.yaml` shape). Optional — empty validates/fails loudly
    /// on dangling references.
    #[serde(
        default,
        deserialize_with = "busbar_kernel::config::providers::catalog"
    )]
    providers: std::collections::HashMap<String, busbar_kernel::config::ProviderDef>,
}

pub(crate) async fn apply_config(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<busbar_kernel::auth::AuthPrincipal>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let actor = principal.actor_id().to_string();
    let card_origin = format!("config/apply by {actor}");
    let expected = ok_or_respond!(if_match_version(&headers));
    let req: ApplyConfigReq = ok_or_respond!(boxed json_body(&body, "config"));

    if let Some(refusal) = unloaded_plane_refusal(&handle, &req.config) {
        return err_json(&AdminError::Validation(refusal));
    }

    let req_deploy: busbar_kernel::config::DeployCfg =
        match busbar_kernel::config::deploy_from_deserializer(req.config) {
            Ok(d) => d,
            Err(e) => {
                return err_json(&AdminError::Validation(format!(
                    "malformed config body: {e}"
                )))
            }
        };
    let req_providers = req.providers;
    let out = config_transaction(&handle, move |txn| {
        let current = txn.app();
        if let Some(e) = stale_if_match(expected, current.config_version) {
            return Err(e);
        }

        if current.overlay_path.is_none() {
            return Err(AdminError::Validation(
                busbar_kernel::config::overlay::NO_WRITABLE_OVERLAY_MSG.to_string(),
            ));
        }

        let snapshot = current.clone();
        Ok(txn.read_store(move || {
            let overlay_doc = snapshot
                .overlay_path
                .as_deref()
                .map(busbar_kernel::config::overlay::OverlayStore::read_required)
                .transpose()
                .map_err(AdminError::Validation)?
                .flatten();
            let (mut deploy, providers) = (req_deploy, req_providers);
            if let Some(doc) = overlay_doc.as_ref() {
                busbar_kernel::config::overlay::apply_root_to_deploy(&mut deploy, doc);

                busbar_kernel::config::overlay::apply_plugin_versions_to_deploy(&mut deploy, doc);
            }
            let next = busbar_kernel::config::resolve(&deploy, &providers)
                .map_err(|errs| format!("config errors:\n  - {}", errs.join("\n  - ")))
                .and_then(|mut cfg| {
                    let base_hook_names: std::collections::HashSet<String> =
                        cfg.hooks.keys().cloned().collect();
                    let base_group_names: std::collections::HashSet<String> =
                        cfg.groups.keys().cloned().collect();
                    if let Some(doc) = overlay_doc {
                        busbar_kernel::config::overlay::merge_into(&mut cfg, doc);
                    }
                    busbar_kernel::build_app_from_config(
                        cfg,
                        deploy.plugins.clone(),
                        snapshot.overlay_path.clone(),
                        base_hook_names,
                        base_group_names,
                        (
                            snapshot.config_path.clone(),
                            snapshot.providers_path.clone(),
                        ),
                        Some(&snapshot),
                        &snapshot.root_rules,
                    )
                })
                .map_err(AdminError::Validation)?;
            let (next, gov_rotate, limits) = next;
            let installed = Arc::new(next);

            Ok(Outcome::commit_rates_then(
                installed.clone(),
                || Ok(()),
                limits,
                card_origin,
                move || {
                    if let Some(rotate) = gov_rotate {
                        rotate();
                    }
                    Ok(Outcome::Value(installed))
                },
            ))
        }))
    })
    .await;
    match out {
        Ok(installed) => {
            audit::AUDIT.record_by(
                "config.apply",
                "config:body",
                audit::OUTCOME_APPLIED,
                &actor,
            );
            installed.record_version(&actor, "config.apply (request body)");
            let mut body = json!({
                "applied": true,
                "config_version": installed.config_version,
                "note": "live until the next reload/restart returns to disk truth; persist \
                         by updating config.yaml",
            });

            if let Some(pending) =
                super::named_map::restart_note(&[], &installed.planes_awaiting_restart)
            {
                body["reload_to_apply"] = json!(installed.planes_awaiting_restart);
                body["note"] = json!(format!(
                    "live until the next reload/restart returns to disk truth; persist by \
                     updating config.yaml; {pending}"
                ));
            }
            with_config_etag(ok_json(StatusCode::OK, &body), installed.config_version)
        }
        Err(e) => reject("config.apply", "config:body", &actor, &e),
    }
}

fn unloaded_plane_refusal(handle: &AppHandle, config: &serde_json::Value) -> Option<String> {
    let keys: Vec<&str> = config
        .as_object()
        .into_iter()
        .flat_map(|o| o.keys().map(String::as_str))
        .collect();
    let app = handle.load();
    busbar_kernel::appbuild::RootRules::unloaded_plane_refusal(&*app.root_rules, &keys)
}

fn merge_root_settings(
    mut base: busbar_kernel::config::overlay::RootSettings,
    req: busbar_kernel::config::overlay::RootSettings,
) -> busbar_kernel::config::overlay::RootSettings {
    let busbar_kernel::config::overlay::RootSettings {
        listen,
        tls,
        admin_listen,
        admin_tls,
        admin_require_mtls,
        rate_card,
        per_request_fee,
        store,
        security,
        limits,
        advanced,
        health,
        routing,
    } = req;

    if listen.is_some() {
        base.listen = listen;
    }
    if tls.is_some() {
        base.tls = tls;
    }
    if admin_listen.is_some() {
        base.admin_listen = admin_listen;
    }
    if admin_tls.is_some() {
        base.admin_tls = admin_tls;
    }
    if admin_require_mtls.is_some() {
        base.admin_require_mtls = admin_require_mtls;
    }
    if rate_card.is_some() {
        base.rate_card = rate_card;
    }
    if per_request_fee.is_some() {
        base.per_request_fee = per_request_fee;
    }
    if store.is_some() {
        base.store = store;
    }

    macro_rules! merge_section {
        ($($field:ident),+ $(,)?) => {$(
            base.$field = match ($field, base.$field) {
                (Some(new), Some(old)) => Some(new.merge(old)),
                (Some(new), None) => Some(new),
                (None, old) => old,
            };
        )+};
    }
    merge_section!(security, limits, advanced, health, routing);
    base
}

fn reload_to_apply_fields(req: &busbar_kernel::config::overlay::RootSettings) -> Vec<String> {
    let busbar_kernel::config::overlay::RootSettings {
        listen,
        tls,
        admin_listen,
        admin_tls,
        admin_require_mtls,
        store,

        rate_card: _,
        per_request_fee: _,
        security: _,
        health: _,
        routing: _,

        limits,
        advanced,
    } = req;
    let mut out = Vec::new();
    let mut push = |set: bool, name: &str| {
        if set {
            out.push(name.to_string());
        }
    };
    push(listen.is_some(), "listen");
    push(tls.is_some(), "tls");
    push(admin_listen.is_some(), "admin_listen");
    push(admin_tls.is_some(), "admin_tls");
    push(admin_require_mtls.is_some(), "admin_require_mtls");
    push(store.is_some(), "store");

    if let Some(limits) = limits.as_ref() {
        let busbar_kernel::config::patch::LimitsPatch {
            upstream_request_timeout_secs,
            pool_max_idle_per_host,
            pool_idle_timeout_secs,
            max_inbound_concurrent,

            request_body_max_bytes: _,

            max_keys_per_principal: _,

            datagram_line_memory_bytes: _,
            max_auto_provisioned_groups: _,

            hook_content_max_bytes: _,
            hard_down_cooldown_secs: _,
            upstream_error_body_max_bytes: _,
            tls_handshake_timeout_secs: _,
            request_body_read_timeout_secs: _,
            max_honored_retry_after_secs: _,
            default_max_tokens: _,
            reasoning_effort_budgets: _,
        } = limits;
        push(
            upstream_request_timeout_secs.is_some(),
            "limits.upstream_request_timeout_secs",
        );
        push(
            pool_max_idle_per_host.is_some(),
            "limits.pool_max_idle_per_host",
        );
        push(
            pool_idle_timeout_secs.is_some(),
            "limits.pool_idle_timeout_secs",
        );
        push(
            max_inbound_concurrent.is_some(),
            "limits.max_inbound_concurrent",
        );
    }

    if let Some(advanced) = advanced.as_ref() {
        let busbar_kernel::config::patch::AdvancedPatch {
            response_headers,

            rate_sweep_interval: _,
            usage_flush_interval_ms: _,
        } = advanced;
        push(response_headers.is_some(), "advanced.response_headers");
    }
    out
}

fn current_root_settings(
    overlay_path: Option<&busbar_kernel::config::overlay::OverlayStore>,
    endpoint: &str,
) -> busbar_kernel::config::overlay::RootSettings {
    let Some(p) = overlay_path else {
        return busbar_kernel::config::overlay::RootSettings::default();
    };
    match busbar_kernel::config::overlay::read_state(p) {
        busbar_kernel::config::overlay::OverlayReadState::Absent => {
            busbar_kernel::config::overlay::RootSettings::default()
        }
        busbar_kernel::config::overlay::OverlayReadState::Loaded(doc) => {
            doc.root.unwrap_or_default()
        }
        busbar_kernel::config::overlay::OverlayReadState::Unreadable => {
            busbar_kernel::diagnostics::diag_warn!(
                busbar_kernel::diagnostics::CONFIG_SETTINGS_OVERLAY_UNREADABLE,
                endpoint,
                path = %p.display(),
                "{endpoint} read the config overlay while it was unreadable/corrupt; reporting NO \
                 root overrides, which may not reflect what is actually stored in the Store"
            );
            busbar_kernel::config::overlay::RootSettings::default()
        }
        busbar_kernel::config::overlay::OverlayReadState::VersionTooNew(v) => {
            busbar_kernel::diagnostics::diag_warn!(
                busbar_kernel::diagnostics::CONFIG_SETTINGS_OVERLAY_VERSION_TOO_NEW,
                endpoint,
                path = %p.display(),
                overlay_version = v,
                "{endpoint} read the config overlay while it was from a NEWER busbar; reporting NO \
                 root overrides, which may not reflect what is actually stored in the Store"
            );
            busbar_kernel::config::overlay::RootSettings::default()
        }
    }
}

pub(crate) async fn get_config_settings(State(handle): State<Arc<AppHandle>>) -> Response {
    let current = handle.load();

    let overlay_path = current.overlay_path.clone();

    let dispatch = tracing::dispatcher::get_default(|d| d.clone());
    let root = match tokio::task::spawn_blocking(move || {
        tracing::dispatcher::with_default(&dispatch, || {
            current_root_settings(overlay_path.as_deref(), "GET /config/settings")
        })
    })
    .await
    {
        Ok(root) => root,

        Err(e) => {
            busbar_kernel::diagnostics::diag_error!(
                busbar_kernel::diagnostics::CONFIG_SETTINGS_READ_TASK_JOIN_FAILED,
                error = %e,
                "GET /config/settings overlay read task failed to join"
            );
            return err_json(&AdminError::Internal);
        }
    };

    let mut settings = serde_json::to_value(&root).unwrap_or_else(|_| json!({}));
    crate::v1::service::redact_settings_bags(&mut settings);
    with_config_etag(
        ok_json(
            StatusCode::OK,
            &json!({
                "applied": false,
                "config_version": current.config_version,
                // settings-leak-lint: allow — the envelope member; `redact_settings_bags` above has
                // already reduced every bag inside `settings` to its key names.
                "settings": settings,
            }),
        ),
        current.config_version,
    )
}

const PERSIST_FIELD: &str = "persist";

pub(crate) async fn put_config_settings(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<busbar_kernel::auth::AuthPrincipal>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let actor = principal.actor_id().to_string();
    let card_origin = format!("config/settings by {actor}");
    let expected = ok_or_respond!(if_match_version(&headers));
    let mut raw: serde_json::Value = ok_or_respond!(boxed json_body(&body, "config settings"));
    let requested_persist = match raw.as_object_mut().and_then(|o| o.remove(PERSIST_FIELD)) {
        None => false,
        Some(serde_json::Value::Bool(b)) => b,
        Some(other) => {
            return err_json(&AdminError::Validation(format!(
                "config settings '{PERSIST_FIELD}' must be a boolean (got {other}); it asserts the \
                 change must be stored in the config overlay"
            )))
        }
    };
    let req: busbar_kernel::config::overlay::RootSettings = match serde_json::from_value(raw) {
        Ok(r) => r,
        Err(e) => {
            return err_json(&AdminError::Validation(format!(
                "malformed config settings body: {e}"
            )))
        }
    };
    let reload_to_apply = reload_to_apply_fields(&req);
    let want = req.clone();
    let out = config_transaction(&handle, move |txn| {
        let current = txn.app();
        if let Some(e) = stale_if_match(expected, current.config_version) {
            return Err(e);
        }

        let _ = requested_persist;
        if current.overlay_path.is_none() {
            return Err(AdminError::Validation(
                busbar_kernel::config::overlay::NO_WRITABLE_OVERLAY_MSG.to_string(),
            ));
        }

        let snapshot = current.clone();
        Ok(txn.read_store(move || {
            let (Some(config_path), Some(providers_path)) = (
                snapshot.config_path.clone(),
                snapshot.providers_path.clone(),
            ) else {
                return Err(AdminError::Validation(
                    "this busbar was started without config files (ephemeral mode); \
                     /config/settings has no disk base to merge onto"
                        .into(),
                ));
            };

            let current_doc = snapshot
                .overlay_path
                .as_deref()
                .map(busbar_kernel::config::overlay::OverlayStore::read_required)
                .transpose()
                .map_err(AdminError::Validation)?
                .flatten();
            let merged = merge_root_settings(
                current_doc.and_then(|doc| doc.root).unwrap_or_default(),
                want,
            );
            let merged_for_build = merged.clone();

            let next = busbar_kernel::load_config_from_disk_with_store(
                &config_path,
                Some(&providers_path),
                false,
                busbar_kernel::config::EnvSubst::Strict,
                &*snapshot.root_rules,
                snapshot.overlay_path.clone(),
            )
            .and_then(|mut loaded| {
                merged_for_build.apply_to_deploy(&mut loaded.deploy);

                if let Some(doc) = loaded.overlay_doc.as_ref() {
                    busbar_kernel::config::overlay::apply_pre_resolve_sections(
                        &mut loaded.deploy,
                        doc,
                    );
                }
                let mut cfg = busbar_kernel::config::resolve(&loaded.deploy, &loaded.defs)
                    .map_err(|errs| format!("config errors:\n  - {}", errs.join("\n  - ")))?;
                let base_hook_names: std::collections::HashSet<String> =
                    cfg.hooks.keys().cloned().collect();
                let base_group_names: std::collections::HashSet<String> =
                    cfg.groups.keys().cloned().collect();
                if let Some(doc) = loaded.overlay_doc {
                    busbar_kernel::config::overlay::merge_into(&mut cfg, doc);
                }
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
            })
            .map_err(AdminError::Validation)?;
            let (next, gov_rotate, limits) = next;
            let installed = Arc::new(next);

            let persist_overlay = snapshot.overlay_path.clone();
            let to_persist = merged.clone();

            Ok(Outcome::commit_rates_then(
                installed.clone(),
                move || {
                    busbar_kernel::config::overlay::persist_root(
                        persist_overlay.as_deref(),
                        &to_persist,
                    )
                    .map_err(|e| {
                        format!(
                            "config settings persistence to the overlay was not confirmed: {e}; \
                             the running engine is unaffected"
                        )
                    })
                },
                limits,
                card_origin,
                move || {
                    if let Some(rotate) = gov_rotate {
                        rotate();
                    }
                    Ok(Outcome::Value((installed, merged)))
                },
            ))
        }))
    })
    .await;
    match out {
        Ok((installed, merged)) => {
            audit::AUDIT.record_by(
                "config.settings",
                "config:settings",
                audit::OUTCOME_APPLIED,
                &actor,
            );
            record_group_version(&installed, &actor, "config.settings (root section applied)");

            let (reload_to_apply, note) = if reload_to_apply.is_empty() {
                (reload_to_apply, "applied live".to_string())
            } else {
                let note = format!(
                    "applied live except {} — stored in the overlay, effective on the next RESTART (a \
                     socket rebind / TLS bind is read once at process start, and the store backend is \
                     reused across a hot reload; none can hot-swap)",
                    reload_to_apply.join(", ")
                );
                (reload_to_apply, note)
            };

            let mut settings = serde_json::to_value(&merged).unwrap_or_else(|_| json!({}));
            crate::v1::service::redact_settings_bags(&mut settings);
            with_config_etag(
                ok_json(
                    StatusCode::OK,
                    &json!({
                        "applied": true,
                        "config_version": installed.config_version,
                        // settings-leak-lint: allow — the envelope member; `redact_settings_bags`
                        // above has already reduced every bag inside `settings` to its key names.
                        "settings": settings,
                        "reload_to_apply": reload_to_apply,
                        "note": note,
                    }),
                ),
                installed.config_version,
            )
        }
        Err(e) => reject("config.settings", "config:settings", &actor, &e),
    }
}

/// The `PATCH /api/v1/admin/hooks/{name}/settings` body. Optimistic concurrency rides `If-Match`.
#[derive(serde::Deserialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct PatchSettingsReq {
    // settings-leak-lint: allow — INBOUND request body (`Deserialize` only). This is the operator
    settings: serde_json::Map<String, serde_json::Value>,
}

pub(crate) async fn patch_hook_settings(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<busbar_kernel::auth::AuthPrincipal>,
    Path(name): Path<String>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let actor = principal.actor_id().to_string();
    let expected = ok_or_respond!(if_match_version(&headers));
    let req: PatchSettingsReq = ok_or_respond!(boxed json_body(&body, "settings"));

    if let Err(e) = crate::v1::service::validate_hook_settings_size(&req.settings) {
        return err_json(&e);
    }
    let current = handle.load();
    let resource = format!("hook:{name}");
    let Some(existing) = current.hook_registry.get(&name) else {
        audit::AUDIT.record_by("hook.settings", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&AdminError::not_found(format!("hook `{name}`")));
    };
    if current.base_hook_names.contains(&name) {
        audit::AUDIT.record_by("hook.settings", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&AdminError::Conflict(format!(
            "hook `{name}` is defined in the base config file; edit config.yaml"
        )));
    }
    if let Some(e) = stale_if_match(expected, current.config_version) {
        audit::AUDIT.record_by("hook.settings", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&e);
    }
    let mut updated = existing.clone();
    updated.settings = req.settings;
    let pre_push_version = current.config_version;
    let settings_version = pre_push_version.wrapping_add(1);

    let hook_env = current.hook_env.clone();
    if let Err(e) =
        busbar_kernel::hooks::push_configure(&updated, &name, settings_version, &hook_env).await
    {
        audit::AUDIT.record_by("hook.settings", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&AdminError::Validation(format!(
            "hook did not acknowledge the settings push: {e}"
        )));
    }

    let txn_name = name.clone();
    let out = config_transaction(&handle, move |txn| {
        let current = txn.app();
        if current.config_version != pre_push_version {
            return Err(AdminError::Conflict(
                "config changed during the settings push; retry".to_string(),
            ));
        }

        let snapshot = current.clone();
        Ok(txn.read_store(move || {
            let installed = Arc::new(build_with_hook(&snapshot, &txn_name, updated)?);

            let p = installed.clone();
            Ok(Outcome::commit(
                installed.clone(),
                move || {
                    busbar_kernel::config::overlay::persist(
                        p.overlay_path.as_deref(),
                        &p.hook_registry,
                        &p.global_hooks,
                        None,
                        Some(&txn_name),
                        &p.base_hook_names,
                    )
                    .map_err(|e| {
                        format!(
                            "hook settings persistence to the overlay was not confirmed: {e}; \
                             the running engine is unaffected"
                        )
                    })
                },
                installed,
            ))
        }))
    })
    .await;
    match out {
        Ok(installed) => {
            audit::AUDIT.record_by("hook.settings", &resource, audit::OUTCOME_APPLIED, &actor);
            installed.record_version(&actor, &format!("hook.settings {resource}"));
            with_config_etag(
                respond(StatusCode::OK, service(&handle).get_hook(&name).await),
                installed.config_version,
            )
        }
        Err(e) => {
            let committed = handle.load();
            if let Some(committed_hook) = committed.hook_registry.get(&name) {
                if let Err(re) = busbar_kernel::hooks::push_configure(
                    committed_hook,
                    &name,
                    committed.config_version,
                    &committed.hook_env,
                )
                .await
                {
                    tracing::debug!(
                        hook = %name,
                        error = %re,
                        "hook.settings rejected; reverting the running hook to committed settings \
                         failed — it will re-sync via the configure preamble on its next reconnect"
                    );
                }
            }
            audit::AUDIT.record_by("hook.settings", &resource, audit::OUTCOME_REJECTED, &actor);
            err_json(&e)
        }
    }
}

pub(crate) async fn plugin_schema(
    State(handle): State<Arc<AppHandle>>,
    Path(name): Path<String>,
) -> Response {
    let current = handle.load();

    if let Some(hook) = current.hook_registry.get(&name) {
        let described = busbar_kernel::hooks::fetch_schema(
            &name,
            hook,
            current.config_version,
            &current.hook_env,
        )
        .await;

        let loadable = current.hook_env.registry.resolve(&hook.plugin);
        let trust = loadable
            .as_ref()
            .map(|p| verdict_trust(&p.trust))
            .unwrap_or("unverified");

        let kind = loadable.as_ref().map(|p| p.kind.clone());
        let restart_required_default = kind.as_deref().map(|k| kind_restart_default(&current, k));
        if described.is_some() {
            return ok_json(
                StatusCode::OK,
                &json!({ "name": name, "schema": described, "schema_error": null, "trust": trust, "source": "describe", "kind": kind, "restart_required_default": restart_required_default }),
            );
        }

        let (schema, schema_error) = loadable
            .as_ref()
            .map(|p| manifest_schema(p.settings_schema.as_deref()))
            .unwrap_or((None, None));
        return ok_json(
            StatusCode::OK,
            &json!({ "name": name, "schema": schema, "schema_error": schema_error, "trust": trust, "source": "manifest", "kind": kind, "restart_required_default": restart_required_default }),
        );
    }
    let Some(loadable) = current.hook_env.registry.resolve(&name) else {
        return err_json(&AdminError::not_found(format!("plugin `{name}`")));
    };
    let trust = verdict_trust(&loadable.trust);
    let (schema, schema_error) = manifest_schema(loadable.settings_schema.as_deref());
    ok_json(
        StatusCode::OK,
        &json!({
            "name": name,
            "schema": schema,
            "schema_error": schema_error,
            "trust": trust,
            "source": "manifest",
            "kind": loadable.kind,
            "restart_required_default": kind_restart_default(&current, &loadable.kind),
        }),
    )
}

fn manifest_schema(settings_schema: Option<&str>) -> (Option<serde_json::Value>, Option<String>) {
    match settings_schema {
        None => (None, None),
        Some(s) => match serde_json::from_str::<serde_json::Value>(s) {
            Ok(v) => (Some(v), None),
            Err(e) => (
                None,
                Some(format!("manifest settings_schema is not valid JSON: {e}")),
            ),
        },
    }
}

fn verdict_trust(v: &busbar_contract::plugin_rows::Trust) -> &'static str {
    match v {
        busbar_contract::plugin_rows::Trust::Trusted { .. } => "trusted",
        busbar_contract::plugin_rows::Trust::Allowed { .. } => "unverified",
    }
}

fn kind_restart_default(app: &busbar_kernel::state::App, kind: &str) -> bool {
    app.plugin_admission.is_none_or(|a| a.restart_default(kind))
}

pub(crate) async fn hook_schema(
    State(handle): State<Arc<AppHandle>>,
    Path(name): Path<String>,
) -> Response {
    let current = handle.load();
    let Some(hook) = current.hook_registry.get(&name) else {
        return err_json(&AdminError::not_found(format!("hook `{name}`")));
    };
    let schema =
        busbar_kernel::hooks::fetch_schema(&name, hook, current.config_version, &current.hook_env)
            .await;
    ok_json(StatusCode::OK, &json!({ "name": name, "schema": schema }))
}

pub(crate) async fn hook_status(
    State(handle): State<Arc<AppHandle>>,
    Path(name): Path<String>,
) -> Response {
    let current = handle.load();
    let Some(hook) = current.hook_registry.get(&name) else {
        return err_json(&AdminError::not_found(format!("hook `{name}`")));
    };
    let desired_version = current.config_version;
    let reported =
        busbar_kernel::hooks::fetch_status(&name, hook, desired_version, &current.hook_env).await;
    let as_of = busbar_kernel::store::now();
    let body = match reported {
        Some(r) => {
            let drift_keys = busbar_kernel::hooks::settings_drift_keys(hook, r.settings.as_ref());
            let settings_drift = !drift_keys.is_empty();
            let version_drift = r.settings_version.is_some_and(|v| v != desired_version);
            let metrics = r
                .metrics
                .as_ref()
                .map(|m| {
                    busbar_contract::hook_wire::reply::parse_status_metrics(m)
                        .into_iter()
                        .map(|metric| {
                            let mut entry =
                                json!({"name": metric.name, "type": metric.kind, "value": metric.value});

                            for (k, v) in [
                                ("labels", metric.labels.map(|l| json!(l))),
                                ("quantiles", metric.quantiles.map(|q| json!(q))),
                                ("estimated", metric.estimated.map(serde_json::Value::from)),
                                ("ci_low", metric.ci_low.map(serde_json::Value::from)),
                                ("ci_high", metric.ci_high.map(serde_json::Value::from)),
                                ("help", metric.help.map(serde_json::Value::from)),
                                ("label", metric.label.map(serde_json::Value::from)),
                                ("unit", metric.unit.map(serde_json::Value::from)),
                                ("viz", metric.viz.map(serde_json::Value::from)),
                                ("max", metric.max.map(serde_json::Value::from)),
                            ] {
                                if let Some(v) = v {
                                    entry[k] = v;
                                }
                            }
                            entry
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            json!({
                "name": name,
                "desired": {
                    "settings_keys": crate::v1::service::settings_keys(&hook.settings),
                    "settings_version": desired_version,
                },
                "reported": {
                    "settings_keys": r.settings.as_ref().map(crate::v1::service::settings_keys),
                    "settings_version": r.settings_version,
                },
                "drift": settings_drift || version_drift,
                // WHICH desired keys the hook is not running — the drift signal an operator can act
                // on, carrying names the body already serves and no value from either bag.
                "drift_keys": drift_keys,
                "metrics": metrics,
                "as_of": as_of,
                "source": "live",
            })
        }
        None => json!({
            "name": name,
            "desired": {
                "settings_keys": crate::v1::service::settings_keys(&hook.settings),
                "settings_version": desired_version,
            },
            "reported": serde_json::Value::Null,
            "drift": serde_json::Value::Null,
            // Invariantly an array, same rationale as `metrics` below: no drift is KNOWN here, so
            // the list is empty rather than absent.
            "drift_keys": [],
            // `metrics` is INVARIANTLY an array — `[]` here (not `{}`) so a strict consumer decoding
            // it as an array never has to special-case the no-status branch.
            "metrics": [],
            "as_of": as_of,
            "source": "live",
            "note": "hook did not answer status (unsupported or unreachable)",
        }),
    };
    ok_json(StatusCode::OK, &body)
}

#[allow(dead_code)]
pub(crate) const V1_GET_PATHS: &[(&str, &str)] = &[
    (
        "/info",
        "Version, compiled-in plugin proof, uptime, topology",
    ),
    (
        "/pools",
        "Pool topology (members + weights). ?detail=true inlines live member status (one call, no N+1)",
    ),
    ("/models", "Model lanes + upstream providers"),
    ("/providers", "Distinct providers + lane counts"),
    (PATH_HOOKS, "Hook registry (definitions)"),
    (
        PATH_GROUPS,
        "Group registry: the limit tree (parent chain, limits, child_default budget template)",
    ),
    (
        "/plugins",
        "Plugin catalog by type (compiled-in + external + dynamic-library)",
    ),
    (
        "/auth",
        "Ingress auth chain + upstream-credential mode",
    ),
    (
        PATH_ADMIN_AUTH,
        "Admin-plane auth config (the admin surface guard)",
    ),
    (
        "/usage",
        "Metering: current UTC-day bucket ({window, as_of, currency, total, by_model, by_key}), raw token split + derived spend_micros",
    ),
    (
        "/config",
        "Effective running config snapshot (redacted)",
    ),
    (
        "/audit",
        "Admin audit log: every mutation with its outcome (newest first). Page: ?limit=, ?cursor=; returns {items, next_cursor}",
    ),
    (
        "/config/versions",
        "Config version history (newest first; id/ts/principal/summary). Page: ?limit=, ?cursor=; returns {items, next_cursor}",
    ),
    ("/openapi.json", "This OpenAPI 3.1 document"),
];

#[cfg(feature = "openapi-schema")]
#[cfg_attr(not(test), allow(dead_code))]
const OPENAPI_ADMIN_TOKEN_HEADER: &str = "x-admin-token";

#[cfg(feature = "openapi-schema")]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn openapi_doc() -> serde_json::Value {
    let mut paths = serde_json::Map::new();
    for (path, summary) in V1_GET_PATHS {
        paths.insert(
            ap(path),
            json!({
                "get": {
                    "summary": summary,
                    "security": [{"adminToken": []}],
                    RESPONSES_KEY: {
                        "200": {"description": "OK"},
                    }
                }
            }),
        );
    }

    for (path, item) in super::named_map::openapi_paths() {
        paths.insert(path, item);
    }

    if let Some(obj) = paths
        .get_mut(&ap(PATH_HOOKS))
        .and_then(|p| p.as_object_mut())
    {
        obj.insert(
            "post".to_string(),
            json!({
                "summary": "Register (or replace) a hook at runtime, live immediately",
                "security": [{"adminToken": []}],
                RESPONSES_KEY: {
                    "201": {"description": "Registered: the name is NEW (body is the hook definition)"},
                    "200": {"description": "Replaced: the name existed (same-grant re-register; body is the hook definition)"},
                }
            }),
        );
    }

    if let Some(obj) = paths
        .get_mut(&ap(PATH_GROUPS))
        .and_then(|p| p.as_object_mut())
    {
        obj.insert(
            "post".to_string(),
            json!({
                "summary": "Create (or replace) a group at runtime, live immediately (upsert)",
                "security": [{"adminToken": []}],
                RESPONSES_KEY: {
                    "201": {"description": "Created: the name is NEW (body is the group definition)"},
                    "200": {"description": "Replaced: the name existed (body is the group definition)"},
                }
            }),
        );
    }

    if let Some(obj) = paths
        .get_mut(&ap("/plugins"))
        .and_then(|p| p.as_object_mut())
    {
        obj.insert(
            "post".to_string(),
            json!({
                "summary": "Install a dynamic-library store plugin: upload the library (base64) + optional signed manifest; the engine RE-VERIFIES against the running trust posture, validates the store ABI, and writes it atomically into the plugins directory. Takes effect on the next store (re)load",
                "security": [{"adminToken": []}],
                RESPONSES_KEY: {
                    "201": {"description": "Installed: `{file, name, interface_version, trust, version?, publisher?, note}`"},
                }
            }),
        );
    }

    paths.insert(
        ap("/plugins/reload"),
        json!({
            "post": {
                "summary": "Re-scan the plugins directory and report the reconciled dynamic-library inventory (the sibling of config/reload). A store change takes effect on the next store (re)load",
                "security": [{"adminToken": []}],
                RESPONSES_KEY: {
                    "200": {"description": "`{plugins, note}`: the current dynamic-library inventory"}
                }
            }
        }),
    );
    paths.insert(
        ap("/plugins/rollback"),
        json!({
            "post": {
                "summary": "EXPLICIT, authenticated, audited rollback of a plugin to a PRIOR version (1.5.0). Validates the target artifact (structure + trust) with the anti-downgrade floor lowered to EXACTLY the target's own version; a lower or untrusted artifact still fails (a rollback authenticates the OPERATOR, never the bytes). Persists the version pin to the overlay (survives restart) and hot-swaps via the same rebuild-and-swap path as plugins/reload",
                "security": [{"adminToken": []}],
                RESPONSES_KEY: {
                    "200": {"description": "`{plugin, version, config_version, plugins}`: rolled back and hot-swapped"},
                }
            }
        }),
    );
    paths.insert(
        ap("/plugins/{file}"),
        json!({
            "delete": {
                "summary": "Remove a dynamic-library plugin (library + manifest sidecar) from the plugins directory. A loaded store keeps running until the next store (re)load",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "file", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                RESPONSES_KEY: {
                    "204": {"description": "Removed"},
                }
            }
        }),
    );
    paths.insert(
        ap("/plugins/{file}/schema"),
        json!({
            "get": {
                "summary": "The plugin's self-described settings JSON Schema, read from the SIGNED manifest's `settings_schema` field, which works for every plugin kind (store/secret/auth/hook), not just hooks. `hook` plugins keep the live describe-proxy behavior when describe answers (source: describe); a loaded hook whose describe answers null falls back server-side to the manifest baseline (source: manifest)",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "file", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                RESPONSES_KEY: {
                    "200": {"description": "`{name, schema, schema_error, trust, source}`: `schema` null (with `schema_error` null) when the manifest carries none; a manifest that SET `settings_schema` but failed to parse instead reports `schema_error` (never collapsed into the same null as \"no schema\"). `trust` is `trusted|unverified|rejected` (the catalog vocabulary). `source` is `describe` (a loaded hook answered live) or `manifest`"},
                }
            }
        }),
    );

    paths.insert(
        ap("/hooks/{name}"),
        json!({
            "get": {
                "summary": "One hook definition",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                RESPONSES_KEY: {
                    "200": {"description": "OK"},
                }
            },
            "put": {
                "summary": "Replace an overlay hook definition, live immediately (grants immutable)",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                RESPONSES_KEY: {
                    "200": {"description": "The replaced hook"},
                }
            },
            "delete": {
                "summary": "Remove a hook at runtime, live immediately",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                RESPONSES_KEY: {
                    "204": {"description": "Removed"},
                }
            }
        }),
    );
    paths.insert(
        ap("/groups/{name}"),
        json!({
            "get": {
                "summary": "One group definition (parent, enabled, limits, child_default)",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                RESPONSES_KEY: {
                    "200": {"description": "OK"},
                }
            },
            "put": {
                "summary": "Replace an overlay group definition, live immediately (limits rebuilt)",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                RESPONSES_KEY: {
                    "200": {"description": "The replaced group"},
                }
            },
            "patch": {
                "summary": "Partial update: change only the fields present (e.g. raise a budget, freeze a group)",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                RESPONSES_KEY: {
                    "200": {"description": "The updated group"},
                }
            },
            "delete": {
                "summary": "Remove an overlay group at runtime, live immediately",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                RESPONSES_KEY: {
                    "204": {"description": "Removed"},
                }
            }
        }),
    );
    paths.insert(
        ap("/pools/{name}"),
        json!({
            "get": {
                "summary": "Live per-member status of one pool (breaker/concurrency/latency)",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                RESPONSES_KEY: {
                    "200": {"description": "OK"},
                }
            }
        }),
    );
    paths.insert(
        ap("/groups/{name}/usage"),
        json!({
            "get": {
                "summary": "The group's derived current-window usage per (window, pool) enforcement bucket vs its caps: the self-service dashboard read (spend derives from the token ledger x the CURRENT rate card at read time)",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                RESPONSES_KEY: {
                    "200": {"description": "OK"},
                }
            }
        }),
    );

    for decl in busbar_kernel::plane_driver::registry::plane_decls() {
        if let Some(openapi) = decl.openapi {
            if let Some(obj) = openapi(decl).as_object() {
                for (path, item) in obj {
                    paths.insert(path.clone(), item.clone());
                }
            }
        }
    }
    paths.insert(
        ap("/hooks/{name}/health"),
        json!({
            "get": {
                "summary": "Best-effort hook transport reachability",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                RESPONSES_KEY: {
                    "200": {"description": "OK (`reachable` may be null for webhook/non-unix)"},
                }
            }
        }),
    );
    paths.insert(
        ap("/config/diff"),
        json!({
            "get": {
                "summary": "Structured hook-surface diff between two retained versions",
                "security": [{"adminToken": []}],
                "parameters": [
                    {"name": "from", "in": "query", "required": true, "schema": {"type": "integer"}},
                    {"name": "to", "in": "query", "required": true, "schema": {"type": "integer"}}
                ],
                RESPONSES_KEY: {
                    "200": {"description": "The diff (hooks added/removed/changed + global-wiring delta)"},
                }
            }
        }),
    );
    paths.insert(
        ap("/config/versions/{v}"),
        json!({
            "get": {
                "summary": "One retained config version, with its hook-surface snapshot",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "v", "in": "path", "required": true,
                    "schema": {"type": "integer"}
                }],
                RESPONSES_KEY: {
                    "200": {"description": "The version (metadata + hooks + global_hooks)"},
                }
            }
        }),
    );
    paths.insert(
        ap("/hooks/{name}/settings"),
        json!({
            "patch": {
                "summary": "Push an opaque settings map to the running hook; COMMIT ON ACK",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                RESPONSES_KEY: {
                    "200": {"description": "Acked + committed (the updated hook)"},
                }
            }
        }),
    );
    paths.insert(
        ap("/hooks/{name}/schema"),
        json!({
            "get": {
                "summary": "The hook's self-described settings JSON Schema (describe proxy)",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                RESPONSES_KEY: {
                    "200": {"description": "`{name, schema}` (`schema` null when the hook doesn't answer describe)"},
                }
            }
        }),
    );
    paths.insert(
        ap("/hooks/{name}/status"),
        json!({
            "get": {
                "summary": "The hook's OBSERVED state, live-queried: running settings + version (vs busbar's desired copy, with a drift verdict) and self-reported metrics. reported=null when the hook doesn't answer (fail-open)",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                RESPONSES_KEY: {
                    "200": {"description": "`{name, desired, reported, drift, metrics, as_of, source}`"},
                }
            }
        }),
    );
    paths.insert(
        ap("/config/apply"),
        json!({
            "post": {
                "summary": "Apply a full config from the request body, atomically (live until next reload/restart; health preserved by lane identity)",
                "security": [{"adminToken": []}],
                RESPONSES_KEY: {
                    "200": {"description": "`{applied, config_version, note}`"},
                }
            }
        }),
    );
    paths.insert(
        ap("/config/reload"),
        json!({
            "post": {
                "summary": "Re-read config.yaml/providers.yaml from disk and apply atomically (health state preserved by lane identity)",
                "security": [{"adminToken": []}],
                RESPONSES_KEY: {
                    "200": {"description": "`{reloaded, config_version}`"},
                }
            }
        }),
    );
    paths.insert(
        ap("/restart"),
        json!({
            "post": {
                "summary": "Restart busbar to apply the restart-scoped settings (listen, admin_listen, tls, admin_tls, admin_require_mtls, store). Drains first; the supervisor brings it back",
                "security": [{"adminToken": []}],
                RESPONSES_KEY: {
                    "202": {"description": "`{restarting, supervisor_detected, note}`: draining; in-flight requests finish first"},
                }
            }
        }),
    );
    paths.insert(
        ap("/config/settings"),
        json!({
            "get": {
                "summary": "Read the API-set single-value config overlay (root section: listen/tls/rate_card/store/security/limits/…), only the operator's overrides; base config.yaml stands for the rest",
                "security": [{"adminToken": []}],
                RESPONSES_KEY: {
                    "200": {"description": "`{applied:false, config_version, settings}` (settings = the current root overrides)"},
                }
            },
            "put": {
                "summary": "SET any single-value config section durably (1.5.0 full-config coverage): partial RootSettings merged onto the overlay, re-resolved + validated, swapped in. rate_card/per_request_fee/security/limits/… go live; listen/tls/admin_listen/admin_tls/admin_require_mtls/store are stored + flagged restart-to-apply (bound once at start / store reused across a hot reload). NEVER writes config.yaml",
                "security": [{"adminToken": []}],
                RESPONSES_KEY: {
                    "200": {"description": "`{applied:true, config_version, settings, reload_to_apply, note}`"},
                }
            }
        }),
    );
    if let Some(auth_path) = paths.get_mut(&ap(PATH_ADMIN_AUTH)) {
        auth_path["put"] = json!({
            "summary": "Replace the admin_auth chain at runtime, dry-run guarded (the calling credentials must hold full scope under the NEW chain, else 409). Live until the next reload/restart",
            "security": [{"adminToken": []}],
            RESPONSES_KEY: {
                "200": {"description": "The resource + apply metadata: `{configured, modules, applied, config_version, note}`"},
            }
        });
    }
    paths.insert(
        ap("/auth/cache/flush"),
        json!({
            "post": {
                "summary": "Flush the credential cache: one module's partition (`{module}`) or everything (empty body). Instant revocation of the cached-allow window",
                "security": [{"adminToken": []}],
                RESPONSES_KEY: {
                    "200": {"description": "`{flushed}`: entries dropped"},
                }
            }
        }),
    );
    paths.insert(
        ap("/config/rollback"),
        json!({
            "post": {
                "summary": "Restore a retained version's hook surface (re-validated; a NEW version)",
                "security": [{"adminToken": []}],
                RESPONSES_KEY: {
                    "200": {"description": "`{restored_version, config_version}`"},
                }
            }
        }),
    );

    let overlay_section_names: Vec<&'static str> =
        busbar_kernel::config::overlay::OverlaySection::all()
            .iter()
            .map(|s| s.as_str())
            .collect();
    paths.insert(
        ap("/overlay/{section}"),
        json!({
            "delete": {
                "summary": format!("DISCARD a section's overlay mutations and revert it to base config.yaml (section ∈ {}). Per-section reset: the OTHER sections' overlay survives. A NEW config version; an already-empty section is an idempotent no-op (changed:false)", overlay_section_names.join("|")),
                "security": [{"adminToken": []}],
                "parameters": [{"name": "section", "in": "path", "required": true, "schema": {"type": "string", "enum": overlay_section_names}}],
                RESPONSES_KEY: {
                    "200": {"description": "`{reset, config_version, changed}`: changed:false when the section had no overlay state"},
                }
            }
        }),
    );
    paths.insert(
        ap(PATH_CONFIG_VALIDATE),
        json!({
            "post": {
                "summary": "Dry-run validate a proposed config",
                "security": [{"adminToken": []}],
                RESPONSES_KEY: {
                    "200": {"description": "Verdict `{ok, errors}` (even for an invalid config)"},
                }
            }
        }),
    );
    paths.insert(
        ap(PATH_PLUGINS_INSPECT),
        json!({
            "post": {
                "summary": "Stateless read-only preview of a candidate plugin tarball: verify its signature, parse its manifest, and report its settings schema WITHOUT installing anything",
                "security": [{"adminToken": []}],
                RESPONSES_KEY: {
                    "200": {"description": "`{name, version, kind, schema, schema_error, trust, source, restart_required_default}`: the same shape `GET /plugins/{file}/schema` carries, plus `name`/`version`/`kind`; an untrusted/rejected candidate is reported (`trust`), never refused"},
                }
            }
        }),
    );

    paths.insert(
        ap("/keys"),
        json!({
            "get": {
                "summary": "List virtual keys (metadata only; never secrets). Filters: ?enabled=, ?prefix=, ?group= (keys bound to a group; a `user:<sub>` leaf's keys are one person's). Paginate: ?limit=, ?cursor= (opaque)",
                "security": [{"adminToken": []}],
                RESPONSES_KEY: {
                    "200": {"description": "`{items, next_cursor}`: the cursor page envelope (next_cursor null at end)"},
                }
            },
            "post": {
                "summary": "Mint a virtual key. The secret is returned EXACTLY once. Honors an `Idempotency-Key` header (per-principal ~10min replay)",
                "security": [{"adminToken": []}],
                RESPONSES_KEY: {
                    "201": {"description": "Created (body includes the once-shown secret)"},
                }
            }
        }),
    );
    paths.insert(
        ap("/keys/{id}"),
        json!({
            "get": {
                "summary": "One key's metadata + `ETag` (never the secret/hash)",
                "security": [{"adminToken": []}],
                "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}],
                RESPONSES_KEY: {
                    "200": {"description": "Key metadata (+ `ETag` header)"},
                }
            },
            "patch": {
                "summary": "Enable/disable a key or rebind its group. Optional `If-Match` for optimistic concurrency",
                "security": [{"adminToken": []}],
                "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}],
                RESPONSES_KEY: {
                    "200": {"description": "Updated metadata"},
                }
            },
            "delete": {
                "summary": "Revoke a key: it stops resolving immediately. Optional `If-Match` (the key's ETag)",
                "security": [{"adminToken": []}],
                "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}],
                RESPONSES_KEY: {
                    "204": {"description": "Revoked: No Content"},
                }
            }
        }),
    );
    paths.insert(
        ap("/keys/{id}/usage"),
        json!({
            "get": {
                "summary": "Current-window usage for one key (spend / tokens / requests)",
                "security": [{"adminToken": []}],
                "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}],
                RESPONSES_KEY: {
                    "200": {"description": "Budget-window counters + `rate_headroom` (fraction of the tightest RPM/TPM cap left; null = uncapped)"},
                }
            }
        }),
    );
    paths.insert(
        ap("/keys/{id}/rotate"),
        json!({
            "post": {
                "summary": "Mint a fresh secret in place (same id, budgets, usage). The new secret is shown once; the old stops resolving. Honors an `Idempotency-Key` header (per-principal, op+id-scoped, ~10min replay)",
                "security": [{"adminToken": []}],
                "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}],
                RESPONSES_KEY: {
                    "200": {"description": "Rotated (body includes the once-shown new secret; an Idempotency-Key retry replays it verbatim)"},
                }
            }
        }),
    );
    paths.insert(
        ap("/keys/{id}/revoke"),
        json!({
            "post": {
                "summary": "REVOKE a signed-token key: denylist it durably WITHOUT deleting the binding (GET /keys/{id} still shows the record; verify now fails). Idempotent: revoking an already-revoked key is 200. DELETE /keys/{id} is the revoke-AND-forget variant (1.5.0)",
                "security": [{"adminToken": []}],
                "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}],
                RESPONSES_KEY: {
                    "200": {"description": "`{revoked}`: the id, now denylisted"},
                }
            }
        }),
    );
    paths.insert(
        ap("/signing-key/rotate"),
        json!({
            "post": {
                "summary": "ROTATE the busbar key-signing key. Rotation is REVOKE-ALL by design: a new signing key means every token minted under the OLD key stops verifying, so every outstanding key must be re-minted. 1.5.0 is single-key, so this reports the intent + current kid; the actual swap is an operator action (replace auth.signing_key / the persisted key file and restart/reload every node in lockstep) (1.5.0)",
                "security": [{"adminToken": []}],
                RESPONSES_KEY: {
                    "200": {"description": "`{current_kid, revoke_all, message}`: the rotation intent + revoke-all warning"},
                }
            }
        }),
    );

    use crate::v1::contract::taxonomy;

    for (path, methods) in paths.iter_mut() {
        let Some(obj) = methods.as_object_mut() else {
            continue;
        };
        let rel = path
            .strip_prefix(crate::v1::contract::ADMIN_PREFIX)
            .unwrap_or(path)
            .to_string();
        for (method, op) in obj.iter_mut() {
            let Some(tag) = taxonomy::MethodTag::from_op_key(method) else {
                continue;
            };
            let Some(resps) = op.get_mut(RESPONSES_KEY).and_then(|r| r.as_object_mut()) else {
                continue;
            };
            for (status, description) in taxonomy::declared_responses(tag, &rel) {
                resps.insert(status, json!({ "description": description }));
            }
        }
    }

    for (path, methods) in paths.iter_mut() {
        if let Some(obj) = methods.as_object_mut() {
            for (method, op) in obj.iter_mut() {
                let m = match method.as_str() {
                    "get" => axum::http::Method::GET,
                    "post" => axum::http::Method::POST,
                    "put" => axum::http::Method::PUT,
                    "patch" => axum::http::Method::PATCH,
                    "delete" => axum::http::Method::DELETE,
                    _ => continue,
                };
                if let Some(op) = op.as_object_mut() {
                    let scope = crate::v1::contract::required_scope(&m, path);
                    op.insert("x-busbar-required-scope".to_string(), json!(scope.as_str()));

                    op.insert(
                        "security".to_string(),
                        json!([{"adminToken": []}, {"bearerAuth": []}]),
                    );

                    if let Some(resps) = op.get_mut(RESPONSES_KEY).and_then(|r| r.as_object_mut()) {
                        resps.entry("401").or_insert(json!(
                            {"description": "Missing/invalid admin credential (error code `unauthorized`)"}
                        ));
                        resps.entry("403").or_insert(json!({"description": format!(
                            "Authenticated but under-scoped: requires `{}` (error code `forbidden`)",
                            scope.as_str()
                        )}));
                        if m != axum::http::Method::GET && m != axum::http::Method::HEAD {
                            resps.entry("429").or_insert(json!(
                                {"description": "Per-principal mutation budget exhausted (error code `rate_limited`; `Retry-After` header)"}
                            ));
                        }
                        resps.entry("500").or_insert(json!(
                            {"description": "Internal failure (error code `internal`); the detail is logged server-side, never returned"}
                        ));

                        if crate::admin_codec::verbs::resolve(m.as_str(), path).is_some() {
                            resps.entry("503").or_insert(json!(
                                {"description": "The node could not take the request into its administrative loop, or could not record what the operation would do (error code `unavailable`)"}
                            ));
                        }
                    }
                }
            }
        }
    }

    type QueryParam = (&'static str, &'static str, bool);
    const QUERY_PARAMS: &[(&str, &[QueryParam])] = &[
        (
            "/keys",
            &[
                ("enabled", "Filter by enabled state (`true`|`false`)", false),
                ("prefix", "Filter by key-id prefix", false),
                (
                    "group",
                    "Filter by bound group (a `user:<sub>` leaf's keys are one person's)",
                    false,
                ),
                ("limit", "Page size (default 200, max 1000)", false),
                (
                    "cursor",
                    "Opaque continuation cursor from `next_cursor`",
                    false,
                ),
                (
                    "include",
                    "Set to `tombstoned` to include hard-deleted keys, which are otherwise \
                     omitted (each row's `state` reads `\"tombstoned\"`)",
                    false,
                ),
            ],
        ),
        (
            "/audit",
            &[
                (
                    "action",
                    "Filter by exact action (e.g. `hook.register`)",
                    false,
                ),
                (
                    "resource",
                    "Filter by exact resource (e.g. `hook:x`)",
                    false,
                ),
                ("limit", "Page size (default 200, max 1000)", false),
                (
                    "cursor",
                    "Opaque continuation cursor from `next_cursor`",
                    false,
                ),
            ],
        ),
        (
            "/config/versions",
            &[
                ("limit", "Page size (default 100, max 1000)", false),
                (
                    "cursor",
                    "Opaque continuation cursor from `next_cursor`",
                    false,
                ),
            ],
        ),
        (
            "/plugins",
            &[(
                "type",
                "Plugin type: `auth` | `hooks` | `store` (required)",
                true,
            )],
        ),
        (
            "/usage",
            &[
                (
                    "window",
                    "A PAST UTC-day bucket start epoch (default: current bucket). The response is always ONE bucket; spend_micros is a read-time estimate; bill from the raw token split, never store spend_micros as a ledger charge",
                    false,
                ),
                (
                    "as_of",
                    "A known rate-card history entry key as 40 hexadecimal digits (default: the \
                     history as it stands). Each row is priced at its own instant through the \
                     inclusive key boundary, which remains stable when earlier entries arrive. \
                     Unknown keys and numeric list positions are refused. Distinct from the numeric \
                     `as_of` FIELD in the response, which is the instant the read was taken",
                    false,
                ),
            ],
        ),
        (
            "/pools",
            &[(
                "detail",
                "`true` inlines each member's live status (same row shape as /pools/{name})",
                false,
            )],
        ),
    ];
    for (path, params) in QUERY_PARAMS {
        if let Some(op) = paths
            .get_mut(&ap(path))
            .and_then(|p| p.get_mut("get"))
            .and_then(|op| op.as_object_mut())
        {
            let list: Vec<serde_json::Value> = params
                .iter()
                .map(|(name, desc, required)| {
                    let schema = if *path == "/usage" && *name == "as_of" {
                        json!({"type": "string", "pattern": "^[0-9a-fA-F]{40}$"})
                    } else {
                        json!({"type": "string"})
                    };
                    json!({"name": name, "in": "query", "required": required,
                           "schema": schema, "description": desc})
                })
                .collect();
            match op.get_mut("parameters").and_then(|p| p.as_array_mut()) {
                Some(existing) => existing.extend(list),
                None => {
                    op.insert("parameters".to_string(), json!(list));
                }
            }
        }
    }

    const IF_MATCH_GUARDED: &[(&str, &str)] = &[
        (PATH_HOOKS, "post"),
        (PATH_GROUPS, "post"),
        ("/hooks/{name}", "put"),
        ("/hooks/{name}", "delete"),
        ("/hooks/{name}/settings", "patch"),
        ("/groups/{name}", "put"),
        ("/groups/{name}", "patch"),
        ("/groups/{name}", "delete"),
        (PATH_ADMIN_AUTH, "put"),
        ("/config/apply", "post"),
        ("/config/settings", "put"),
        ("/config/rollback", "post"),
        ("/plugins/rollback", "post"),
        ("/overlay/{section}", "delete"),
        ("/keys/{id}", "patch"),
        ("/keys/{id}", "delete"),
    ];

    let mut if_match_guarded: Vec<(String, &'static str)> = IF_MATCH_GUARDED
        .iter()
        .map(|(p, m)| ((*p).to_string(), *m))
        .collect();
    for section in busbar_kernel::config::named_map::NamedMapSection::sections() {
        let root = section.path_root();
        if_match_guarded.push((format!("{root}/{{name}}"), "put"));
        if_match_guarded.push((format!("{root}/{{name}}"), "delete"));
        if_match_guarded.push((format!("{root}/{{name}}/settings"), "patch"));
    }
    for (path, method) in &if_match_guarded {
        if let Some(op) = paths
            .get_mut(&ap(path))
            .and_then(|p| p.get_mut(*method))
            .and_then(|op| op.as_object_mut())
        {
            let param = json!({
                "name": "If-Match", "in": "header", "required": false,
                "schema": {"type": "string"},
                "description": "Optimistic concurrency: the resource's ETag from a prior read \
                                (or the ETag returned by the previous mutation). Stale = 409 \
                                `version_conflict` (re-read and retry), nothing changes; absent \
                                or `*` = unconditional."
            });
            match op.get_mut("parameters").and_then(|p| p.as_array_mut()) {
                Some(params) => params.push(param),
                None => {
                    op.insert("parameters".to_string(), json!([param]));
                }
            }
        }
    }

    use crate::v1::schema as sview;
    let mut gen = schemars::generate::SchemaSettings::draft2020_12()
        .with(|s| {
            s.definitions_path = "/components/schemas".into();
            s.meta_schema = None;
        })
        .for_serialize()
        .into_generator();

    let mut req_gen = schemars::generate::SchemaSettings::draft2020_12()
        .with(|s| {
            s.definitions_path = "/components/schemas".into();
            s.meta_schema = None;
        })
        .for_deserialize()
        .into_generator();

    fn set_content(op: &mut serde_json::Value, status: &str, schema: serde_json::Value) {
        let Some(resps) = op.get_mut(RESPONSES_KEY).and_then(|r| r.as_object_mut()) else {
            return;
        };
        let entry = resps
            .entry(status.to_string())
            .or_insert_with(|| json!({"description": "OK"}));
        if let Some(obj) = entry.as_object_mut() {
            obj.insert(
                "content".to_string(),
                json!({"application/json": {"schema": schema}}),
            );
        }
    }

    macro_rules! op {
        ($rel:expr, $method:literal) => {
            paths.get_mut(&ap($rel)).and_then(|p| p.get_mut($method))
        };
    }
    /// Attach a REQUEST BODY schema to `<rel>.<method>`. `body!` derives it from a type; `body_raw!`
    /// takes a hand-written one, for the bodies that are opaque config documents (see below).
    macro_rules! body {
        ($rel:expr, $method:literal, $t:ty) => {{
            let schema = req_gen.subschema_for::<$t>();
            let schema = serde_json::to_value(schema).unwrap_or_else(|_| json!({}));
            body_raw!($rel, $method, schema);
        }};
    }
    macro_rules! body_raw {
        ($rel:expr, $method:literal, $schema:expr) => {{
            if let Some(op) = op!($rel, $method) {
                if let Some(obj) = op.as_object_mut() {
                    obj.insert(
                        "requestBody".to_string(),
                        json!({
                            "required": true,
                            "content": {"application/json": {"schema": $schema}}
                        }),
                    );
                }
            }
        }};
    }
    /// Sibling of `body!` for the one endpoint whose handler genuinely treats an absent body as the
    /// type's `Default` — `POST /restart` (see its doc comment: "Absent is the same as `{}`"). Every
    /// OTHER body-taking endpoint's handler requires the body, so `body!`/`body_raw!` stay
    /// `"required": true`; this macro exists so a future genuinely-optional body has somewhere to go
    /// without re-checking every other call site's handler.
    macro_rules! body_optional {
        ($rel:expr, $method:literal, $t:ty) => {{
            let schema = req_gen.subschema_for::<$t>();
            let schema = serde_json::to_value(schema).unwrap_or_else(|_| json!({}));
            if let Some(op) = op!($rel, $method) {
                if let Some(obj) = op.as_object_mut() {
                    obj.insert(
                        "requestBody".to_string(),
                        json!({
                            "required": false,
                            "content": {"application/json": {"schema": schema}}
                        }),
                    );
                }
            }
        }};
    }

    macro_rules! typed {
        ($rel:expr, $method:literal, $status:literal, $t:ty) => {{
            let schema = gen.subschema_for::<$t>();
            let schema = serde_json::to_value(schema).unwrap_or_else(|_| json!({}));
            if let Some(op) = op!($rel, $method) {
                set_content(op, $status, schema);
            }
        }};
    }

    use crate::v1::contract::{
        AdminAuthView, AuthView, ConfigValidateView, EffectiveConfigView, GroupView,
        HookHealthView, HookView, InfoView, ModelView, NamedDefView, Page, PluginInstallView,
        PluginReloadView, PluginView, PoolDetailView, PoolView, ProviderView, UsageView,
    };

    typed!("/info", "get", "200", InfoView);
    typed!("/pools", "get", "200", Page<PoolView>);
    typed!("/pools/{name}", "get", "200", PoolDetailView);
    typed!("/models", "get", "200", Page<ModelView>);
    typed!("/providers", "get", "200", Page<ProviderView>);

    typed!(PATH_HOOKS, "get", "200", Page<HookView>);
    typed!(PATH_HOOKS, "post", "201", HookView);
    typed!(PATH_HOOKS, "post", "200", HookView);
    typed!("/hooks/{name}", "get", "200", HookView);
    typed!("/hooks/{name}", "put", "200", HookView);
    typed!("/hooks/{name}/settings", "patch", "200", HookView);
    typed!("/hooks/{name}/health", "get", "200", HookHealthView);

    for decl in busbar_kernel::plane_driver::registry::plane_decls() {
        if let Some(schemas) = decl.openapi_schemas {
            schemas(decl, &mut gen, &mut req_gen, &mut paths);
        }
    }
    typed!("/hooks/{name}/schema", "get", "200", sview::HookSchemaView);
    typed!("/hooks/{name}/status", "get", "200", sview::HookStatusView);

    typed!(PATH_GROUPS, "get", "200", Page<GroupView>);
    typed!(PATH_GROUPS, "post", "201", GroupView);
    typed!(PATH_GROUPS, "post", "200", GroupView);
    typed!("/groups/{name}", "get", "200", GroupView);
    typed!("/groups/{name}", "put", "200", GroupView);
    typed!("/groups/{name}", "patch", "200", GroupView);
    typed!(
        "/groups/{name}/usage",
        "get",
        "200",
        crate::v1::contract::GroupUsageView
    );

    typed!("/auth", "get", "200", AuthView);
    typed!(PATH_ADMIN_AUTH, "get", "200", AdminAuthView);
    typed!(PATH_ADMIN_AUTH, "put", "200", sview::AdminAuthPutView);
    typed!("/auth/cache/flush", "post", "200", sview::CacheFlushView);

    typed!("/plugins", "get", "200", Page<PluginView>);
    typed!("/plugins", "post", "201", PluginInstallView);
    typed!("/plugins/reload", "post", "200", PluginReloadView);
    typed!(
        "/plugins/{file}/schema",
        "get",
        "200",
        sview::PluginSchemaView
    );

    typed!(PATH_PLUGINS_INSPECT, "post", "200", sview::PluginSchemaView);
    typed!(
        "/plugins/rollback",
        "post",
        "200",
        crate::v1::contract::PluginRollbackView
    );
    typed!("/usage", "get", "200", UsageView);
    typed!("/config", "get", "200", EffectiveConfigView);
    typed!(PATH_CONFIG_VALIDATE, "post", "200", ConfigValidateView);
    typed!("/config/apply", "post", "200", sview::ConfigApplyView);
    typed!("/config/settings", "get", "200", sview::ConfigSettingsView);
    typed!("/config/settings", "put", "200", sview::ConfigSettingsView);
    typed!("/config/reload", "post", "200", sview::ConfigReloadView);
    typed!("/restart", "post", "202", sview::RestartView);
    typed!("/config/rollback", "post", "200", sview::ConfigRollbackView);
    typed!(
        "/overlay/{section}",
        "delete",
        "200",
        sview::OverlayResetView
    );
    typed!("/config/diff", "get", "200", sview::ConfigDiffView);
    typed!(
        "/config/versions",
        "get",
        "200",
        sview::ConfigVersionPageView
    );
    typed!(
        "/config/versions/{v}",
        "get",
        "200",
        sview::ConfigVersionDetailView
    );
    typed!("/audit", "get", "200", sview::AuditPageView);

    typed!("/keys", "get", "200", sview::KeyPageView);
    typed!("/keys", "post", "201", sview::CreatedKeyView);
    typed!("/keys/{id}", "get", "200", sview::KeyView);
    typed!("/keys/{id}", "patch", "200", sview::KeyView);
    typed!("/keys/{id}/usage", "get", "200", sview::KeyMeteringView);
    typed!("/keys/{id}/rotate", "post", "200", sview::RotatedKeyView);
    typed!("/keys/{id}/revoke", "post", "200", sview::RevokeView);
    typed!(
        "/signing-key/rotate",
        "post",
        "200",
        sview::SigningKeyRotateView
    );

    for (path, method, op) in super::kernel_verbs::operations(&mut gen, &mut req_gen) {
        let item = paths.entry(path).or_insert_with(|| json!({}));
        if let Some(obj) = item.as_object_mut() {
            obj.insert(method, op);
        }
    }

    if let Some(op) = op!("/openapi.json", "get") {
        set_content(
            op,
            "200",
            json!({"type": "object", "description": "An OpenAPI 3.1 document (this document's shape)"}),
        );
    }

    let error_ref = json!({"$ref": "#/components/schemas/Error"});
    for methods in paths.values_mut() {
        let Some(methods) = methods.as_object_mut() else {
            continue;
        };
        for (method, op) in methods.iter_mut() {
            if method.starts_with("x-") {
                continue;
            }
            let Some(resps) = op.get_mut(RESPONSES_KEY).and_then(|r| r.as_object_mut()) else {
                continue;
            };
            for (status, resp) in resps.iter_mut() {
                let is_error = status.starts_with('4') || status.starts_with('5');
                if !is_error {
                    continue;
                }
                if let Some(obj) = resp.as_object_mut() {
                    obj.entry("content".to_string()).or_insert_with(
                        || json!({"application/json": {"schema": error_ref.clone()}}),
                    );
                }
            }
        }
    }

    body!(PATH_ADMIN_AUTH, "put", PutAuthBody);
    body!("/auth/cache/flush", "post", FlushCacheReq);
    body!("/plugins", "post", InstallPluginReq);
    body!(PATH_PLUGINS_INSPECT, "post", InspectPluginReq);
    body!("/plugins/rollback", "post", PluginRollbackReq);
    body!("/config/rollback", "post", RollbackReq);
    body_optional!("/restart", "post", RestartReq);
    body!("/hooks/{name}/settings", "patch", PatchSettingsReq);
    body!("/keys", "post", crate::keys::CreateKeyReq);
    body!("/keys/{id}", "patch", crate::keys::UpdateKeyReq);

    let config_doc = |what: &str| {
        json!({
            "type": "object",
            "description": format!(
                "{what} The accepted shape is the config file's own, documented in the \
                 configuration reference; it is not restated here because several of its types \
                 parse a wire shape that does not match their field layout."
            ),
            "additionalProperties": true
        })
    };
    let config_body = |what: &str| {
        json!({
            "type": "object",
            "properties": {
                "config": config_doc("A `config.yaml` deploy block, as JSON."),
                "providers": config_doc("A `providers.yaml` document, as JSON."),
            },
            "required": ["config"],
            "description": what,
            "additionalProperties": false
        })
    };
    body_raw!(
        "/config/apply",
        "post",
        config_body("Replace the running configuration.")
    );
    body_raw!(
        PATH_CONFIG_VALIDATE,
        "post",
        config_body("Validate a configuration without applying it.")
    );
    body_raw!(
        "/config/settings",
        "put",
        config_doc(
            "The settings sections to replace, keyed by section name. Durable by default (1.5.3): a \
             mutable config always stores the change in its overlay (survives restart), and a locked \
             config (`config.locked: true`) refuses ANY change with `400`. There is no \"apply in \
             memory only\" outcome. The optional top-level boolean `persist` is accepted for \
             back-compat and boolean-validated (a non-boolean is a 400 naming the field), but its \
             value has NO effect: persistence is unconditional on a mutable config and refusal is \
             unconditional on a locked one. Every other top-level key must be a known settings \
             section; an unknown key is a 400."
        )
    );
    body_raw!(
        PATH_GROUPS,
        "post",
        json!({
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "The group name."},
                "config": config_doc("A `groups:` entry, as JSON."),
            },
            "required": ["name", "config"],
            "additionalProperties": false
        })
    );
    body_raw!(
        "/groups/{name}",
        "put",
        json!({
            "type": "object",
            "properties": {"config": config_doc("A `groups:` entry, as JSON.")},
            "required": ["config"],
            "additionalProperties": false
        })
    );
    body_raw!(
        "/groups/{name}",
        "patch",
        json!({
            "type": "object",
            "description": "A partial update: only the fields present are changed. `limits` and \
                            `child_default` REPLACE their whole value when present.",
            "properties": {
                "parent": {"type": ["string", "null"]},
                "enabled": {"type": ["boolean", "null"]},
                "limits": {"type": ["array", "null"], "items": config_doc("A `limits:` entry.")},
                "child_default": config_doc("A `child_default:` template."),
            },
            "additionalProperties": false
        })
    );
    body_raw!(
        PATH_HOOKS,
        "post",
        json!({
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "The hook name."},
                "config": config_doc("A `hooks:` entry, as JSON."),
            },
            "required": ["name", "config"],
            "additionalProperties": false
        })
    );
    body_raw!(
        "/hooks/{name}",
        "put",
        json!({
            "type": "object",
            "properties": {"config": config_doc("A `hooks:` entry, as JSON.")},
            "required": ["config"],
            "additionalProperties": false
        })
    );

    for section in busbar_kernel::config::named_map::NamedMapSection::sections() {
        let root = section.path_root();
        let item = format!("{root}/{{name}}");
        let settings = format!("{root}/{{name}}/settings");
        typed!(root.as_ref(), "get", "200", Page<NamedDefView>);
        typed!(&item, "get", "200", NamedDefView);
        typed!(&item, "put", "200", NamedDefView);
        typed!(&settings, "patch", "200", NamedDefView);
        body_raw!(
            &item,
            "put",
            config_doc(&format!(
                "One `{}:` DEFINITION, exactly as config.yaml spells it (`{{module, settings, \
                 ...}}`). Parsed into the section's `deny_unknown_fields` config struct, so an \
                 unknown key is the same loud reject the file would give.",
                section.key()
            ))
        );
        body!(&settings, "patch", super::named_map::NamedSettingsReq);
    }

    typed!(
        "/export/{name}",
        "delete",
        "200",
        super::named_map::PendingRestartRemovalView
    );

    let mut schemas = gen.definitions().clone();

    for (name, schema) in req_gen.definitions() {
        schemas.insert(name.clone(), schema.clone());
    }
    schemas.insert(
        "Error".to_string(),
        json!({
            "type": "object",
            "properties": {
                "error": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string",
                            "enum": ["not_found", "unauthorized", "method_not_allowed", "forbidden",
                                     "invalid_request", "version_conflict", "conflict",
                                     "rate_limited", "internal", "unpriced_class",
                                     "unavailable"]},
                        "message": {"type": "string"}
                    },
                    "required": ["code", "message"]
                }
            },
            "required": ["error"]
        }),
    );

    for decl in busbar_kernel::plane_driver::registry::plane_decls() {
        if decl.openapi.is_none() && decl.named_def_list.is_none() {
            continue;
        }
        let root = ap(&format!("/{}", decl.config_section));
        let nested = format!("{root}/");
        for (path, item) in paths.iter_mut() {
            if *path != root && !path.starts_with(&nested) {
                continue;
            }
            let Some(item) = item.as_object_mut() else {
                continue;
            };
            for (method, op) in item.iter_mut() {
                if method.starts_with("x-") {
                    continue;
                }
                if let Some(op) = op.as_object_mut() {
                    op.insert("x-busbar-plane".to_string(), json!(decl.config_section));
                }
            }
        }
    }

    for (path, item) in paths.iter_mut() {
        let Some(item) = item.as_object_mut() else {
            continue;
        };
        for method in ["get", "put", "post", "delete", "patch"] {
            if let Some(op) = item.get_mut(method).and_then(|v| v.as_object_mut()) {
                op.insert(
                    "operationId".to_string(),
                    json!(openapi_operation_id(method, path)),
                );
            }
        }
    }

    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Busbar Admin API",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "The frozen, additive-only /api/v1/admin surface. Errors use the stable \
                            envelope {\"error\":{\"code\",\"message\"}}; tooling branches on `code`.",
            // ADDITIVE, beside the 1.5.5 description rather than in it (that string is a byte a 1.5.5
            // client already has): how to read the marks the one document carries.
            "x-busbar-marks": {
                "scope": "ONE generated document, describing every administrative operation this \
                          build can serve; a node serves it filtered to the planes it configured.",
                "x-busbar-plane": "The operation is mounted only on a node whose config carries \
                                   that plane's `<section>:` block; elsewhere its path answers \
                                   `404 not_found` and the node's served `GET /openapi.json` \
                                   omits it (and every schema only it references).",
                "x-busbar-since": "Added in that release, and answered by the node's \
                                   administrative loop.",
                "money": "Every money figure is a JSON string holding a decimal integer; every \
                          count is a JSON number."
            }
        },
        "components": {
            "securitySchemes": {
                "adminToken": {"type": "apiKey", "in": "header", "name": OPENAPI_ADMIN_TOKEN_HEADER},
                "bearerAuth": {"type": "http", "scheme": "bearer",
                               "description": "The same operator credential via Authorization: Bearer"}
            },
            "schemas": schemas
        },
        "paths": paths
    })
}

#[cfg(feature = "openapi-schema")]
#[cfg_attr(not(test), allow(dead_code))]
fn openapi_operation_id(method: &str, path: &str) -> String {
    const PREFIX: &str = "/api/v1/admin";
    let trimmed = path.strip_prefix(PREFIX).unwrap_or(path);
    let mut id = capitalize(method);
    for seg in trimmed.trim_matches('/').split('/') {
        if seg.is_empty() {
            continue;
        }
        let seg = seg.trim_matches(|c| c == '{' || c == '}');
        for word in seg.split(|c: char| !c.is_ascii_alphanumeric()) {
            if !word.is_empty() {
                id.push_str(&capitalize(word));
            }
        }
    }
    id
}

#[cfg(feature = "openapi-schema")]
#[cfg_attr(not(test), allow(dead_code))]
fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + &chars.as_str().to_lowercase(),
        None => String::new(),
    }
}

static OPENAPI_JSON_GZ: &[u8] = include_bytes!("openapi.json.gz");

pub(crate) fn openapi_json() -> String {
    use std::io::Read;
    let mut out = String::new();
    flate2::read::GzDecoder::new(OPENAPI_JSON_GZ)
        .read_to_string(&mut out)
        .expect("embedded openapi.json.gz inflates (pinned by the drift tests)");
    out
}

pub(crate) async fn openapi(State(handle): State<Arc<AppHandle>>) -> Response {
    let app = handle.load();

    let served = tokio::task::spawn_blocking(move || {
        let configured = |section: &str| {
            busbar_kernel::plane_driver::registry::plane_decl_for_config_section(section)
                .is_some_and(|decl| app.plane_configured(decl))
        };
        let committed = openapi_json();
        openapi_for_configured_planes(&committed, configured).unwrap_or(committed)
    })
    .await;
    match served {
        Ok(body) => openapi_document_response(body),
        Err(join_err) => {
            diag_error!(
                busbar_kernel::diagnostics::ADMIN_STORE_TASK_JOIN_FAILED,
                operation = "openapi.json",
                error = %join_err,
                "admin blocking task failed"
            );
            err_json(&AdminError::Internal)
        }
    }
}

pub(super) fn openapi_document_response(body: String) -> Response {
    (
        StatusCode::OK,
        [(CONTENT_TYPE, busbar_contract::protocol::APPLICATION_JSON)],
        body,
    )
        .into_response()
}

pub(crate) fn openapi_for_configured_planes(
    committed: &str,
    configured: impl Fn(&str) -> bool,
) -> Option<String> {
    let mut doc: serde_json::Value = serde_json::from_str(committed).ok()?;
    let reachable_before = openapi_reachable_schemas(&doc);
    let mut dropped = false;
    let paths = doc.get_mut("paths")?.as_object_mut()?;
    for item in paths.values_mut() {
        let Some(item) = item.as_object_mut() else {
            continue;
        };
        item.retain(|method, op| {
            if method.starts_with("x-") {
                return true;
            }
            match op.get("x-busbar-plane").and_then(|p| p.as_str()) {
                Some(section) if !configured(section) => {
                    dropped = true;
                    false
                }
                _ => true,
            }
        });
    }
    if !dropped {
        return None;
    }
    paths.retain(|_, item| {
        item.as_object()
            .is_some_and(|o| o.keys().any(|k| !k.starts_with("x-")))
    });
    let reachable_after = openapi_reachable_schemas(&doc);
    if let Some(schemas) = doc
        .pointer_mut("/components/schemas")
        .and_then(|s| s.as_object_mut())
    {
        schemas
            .retain(|name, _| !reachable_before.contains(name) || reachable_after.contains(name));
    }
    serde_json::to_string_pretty(&doc)
        .ok()
        .map(|text| format!("{text}\n"))
}

fn openapi_reachable_schemas(doc: &serde_json::Value) -> std::collections::BTreeSet<String> {
    fn refs(v: &serde_json::Value, out: &mut Vec<String>) {
        match v {
            serde_json::Value::Object(map) => {
                if let Some(r) = map.get("$ref").and_then(|r| r.as_str()) {
                    if let Some(name) = r.strip_prefix("#/components/schemas/") {
                        out.push(name.to_string());
                    }
                }
                map.values().for_each(|v| refs(v, out));
            }
            serde_json::Value::Array(items) => items.iter().for_each(|v| refs(v, out)),
            _ => {}
        }
    }
    let schemas = doc.pointer("/components/schemas");
    let mut pending = Vec::new();
    if let Some(paths) = doc.get("paths") {
        refs(paths, &mut pending);
    }
    let mut seen = std::collections::BTreeSet::new();
    while let Some(name) = pending.pop() {
        if seen.insert(name.clone()) {
            if let Some(schema) = schemas.and_then(|s| s.get(&name)) {
                refs(schema, &mut pending);
            }
        }
    }
    seen
}

/// The `POST /api/v1/admin/config/validate` request body: a full proposed config — the `config.yaml`
/// deploy block + the `providers.yaml` definitions — mirroring the two files busbar loads at boot.
///
/// `config` is carried as a raw [`serde_json::Value`], NOT a plain-derived `DeployCfg`: the 1.6.0
/// pre-pass (`busbar_kernel::config::deploy_from_deserializer`) has to run on it first (see
/// `validate_config` below) to lift the 1.6.0-additive top-level keys (the planes' own sections,
/// `oauth_as`, plus `auth.policy`) out BEFORE the frozen `deny_unknown_fields` `DeployCfg`
/// parses the remainder — deriving `Deserialize` straight onto `DeployCfg` here would refuse any
/// of those keys as unknown, even though the exact same document loads clean from disk at boot
/// (DECISIONS #52: admin API and the config file are ONE schema).
#[derive(serde::Deserialize)]
pub(crate) struct ValidateConfigReq {
    /// The deploy config (operator-owned `config.yaml` shape), pre-lift.
    config: serde_json::Value,
    /// The provider definitions (`providers.yaml` shape), keyed by provider name. Optional: a config
    /// that references no providers.yaml entries validates against an empty def set (and reports the
    /// dangling references as errors).
    #[serde(
        default,
        deserialize_with = "busbar_kernel::config::providers::catalog"
    )]
    providers: std::collections::HashMap<String, busbar_kernel::config::ProviderDef>,
}

pub(crate) async fn validate_config(
    State(handle): State<Arc<AppHandle>>,
    body: axum::body::Bytes,
) -> Response {
    let req: ValidateConfigReq = ok_or_respond!(boxed json_body(&body, "config"));

    if let Some(refusal) = unloaded_plane_refusal(&handle, &req.config) {
        return err_json(&AdminError::Validation(refusal));
    }

    let deploy: busbar_kernel::config::DeployCfg =
        match busbar_kernel::config::deploy_from_deserializer(req.config) {
            Ok(d) => d,
            Err(e) => {
                return err_json(&AdminError::Validation(format!(
                    "malformed config body: {e}"
                )))
            }
        };
    respond(
        StatusCode::OK,
        service(&handle)
            .validate_config(deploy, req.providers)
            .await,
    )
}

const EMPTY_CHAIN_REFUSED_LIVE: bool = false;

fn empty_chain_refusal(operator: impl std::fmt::Display) -> AdminError {
    diag_warn!(
        ADMIN_AUTH_CHAIN_EMPTY,
        "PUT /api/v1/admin/admin-auth REFUSED an EMPTY admin_auth chain: the open \
         (anonymous, full-authority) dev posture must be set in config.yaml and applied at \
         restart, not through the live admin API"
    );
    AdminError::Validation(format!(
        "an empty admin_auth chain is the open (anonymous, full-authority) dev posture and \
         cannot be applied through the live admin API — set `admin_auth: []` in config.yaml \
         and restart to opt in. Otherwise name at least one admin module (e.g. \
         `{operator}`)"
    ))
}

#[cfg(test)]
#[path = "tests/patch_tests.rs"]
mod patch_tests;
