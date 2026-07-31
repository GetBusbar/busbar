use super::*;

/// `GET /api/v1/admin/info` — version, compiled-in plugin proof, uptime, topology.
pub(crate) async fn info(State(handle): State<Arc<AppHandle>>) -> Response {
    respond(StatusCode::OK, service(&handle).info().await)
}

/// `GET /api/v1/admin/pools` — pool topology read. `?detail=true` inlines each member's LIVE status
/// (same row shape as `GET /pools/{name}`) so a dashboard reads the whole topology-with-health in
/// ONE call instead of an M+1 fan-out (audit #7).
pub(crate) async fn list_pools(
    State(handle): State<Arc<AppHandle>>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    match q.get("detail").map(String::as_str) {
        Some("true") => {
            return respond(StatusCode::OK, service(&handle).list_pools_detailed().await)
        }
        // Strict: an unrecognized value is a loud 400, never a silently-ignored flag.
        Some(other) if other != "false" => {
            return err_json(&AdminError::Validation(
                "invalid `detail`: expected true|false".into(),
            ))
        }
        _ => {}
    }
    respond(StatusCode::OK, service(&handle).list_pools().await)
}

/// `GET /api/v1/admin/pools/{name}` — live per-member status of one pool (404 if unknown).
pub(crate) async fn get_pool(
    State(handle): State<Arc<AppHandle>>,
    Path(name): Path<String>,
) -> Response {
    respond(StatusCode::OK, service(&handle).get_pool(&name).await)
}

/// `GET /api/v1/admin/models` — model lanes + providers.
pub(crate) async fn list_models(State(handle): State<Arc<AppHandle>>) -> Response {
    respond(StatusCode::OK, service(&handle).list_models().await)
}

/// `GET /api/v1/admin/providers` — distinct providers + lane counts.
pub(crate) async fn list_providers(State(handle): State<Arc<AppHandle>>) -> Response {
    respond(StatusCode::OK, service(&handle).list_providers().await)
}

/// `GET /api/v1/admin/hooks` — the hook registry read (+ config-plane `ETag` for `If-Match` chaining).
pub(crate) async fn list_hooks(State(handle): State<Arc<AppHandle>>) -> Response {
    let version = handle.load().config_version;
    with_config_etag(
        respond(StatusCode::OK, service(&handle).list_hooks().await),
        version,
    )
}

/// `GET /api/v1/admin/hooks/{name}` — one hook definition (404 if unregistered; + config-plane `ETag`).
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

/// `GET /api/v1/admin/groups` — the `groups:` limit-tree read (+ config-plane `ETag` for `If-Match`
/// chaining, so a client reads then mutates without a second round-trip). Paginated by the shared
/// cursor envelope: `?limit=N` (cap 1000) + opaque `?cursor=`, response `{items, next_cursor}` —
/// the group tree grows at runtime (auto-provisioned leaves), so it is bounded like every other
/// growable admin collection (keys/audit/config-versions), never a single unbounded page.
pub(crate) async fn list_groups(
    State(handle): State<Arc<AppHandle>>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let limit = q
        .get("limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(crate::admin::v1::contract::LIST_LIMIT_DEFAULT)
        .clamp(1, crate::admin::v1::contract::LIST_LIMIT_MAX);
    let start = match cursor_offset(&q) {
        Ok(n) => n,
        Err(resp) => return resp,
    };
    let version = handle.load().config_version;
    with_config_etag(
        respond(
            StatusCode::OK,
            service(&handle).list_groups(start, limit).await,
        ),
        version,
    )
}

/// `GET /api/v1/admin/groups/{name}` — one group definition (404 if unknown; + config-plane `ETag`).
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

/// `GET /api/v1/admin/groups/{name}/usage` — the group's derived current-window usage per
/// enforcement bucket vs its caps.
pub(crate) async fn get_group_usage(
    State(handle): State<Arc<AppHandle>>,
    Path(name): Path<String>,
) -> Response {
    respond(
        StatusCode::OK,
        service(&handle).get_group_usage(&name).await,
    )
}

/// `GET /api/v1/admin/hooks/{name}/health` — best-effort transport reachability (404 if unregistered).
pub(crate) async fn hook_health(
    State(handle): State<Arc<AppHandle>>,
    Path(name): Path<String>,
) -> Response {
    respond(StatusCode::OK, service(&handle).hook_health(&name).await)
}

/// `GET /api/v1/admin/plugins?type=auth|hooks` — the plugin catalog for one type. A missing/unknown
/// `type` is an `invalid_request` (the two types are distinct engine contracts).
pub(crate) async fn list_plugins(
    State(handle): State<Arc<AppHandle>>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let ptype = q.get("type").map(String::as_str).unwrap_or("");
    respond(StatusCode::OK, service(&handle).list_plugins(ptype).await)
}

/// The `POST /api/v1/admin/plugins` request body: install a SIGNED plugin tarball. The tarball
/// bytes ride as base64 (`tarball_b64`) — a plugin artifact is opaque binary, so base64 keeps it a
/// clean JSON field. The engine RE-VERIFIES the contained signed manifest server-side against the
/// running `plugins.*` trust posture (the client is never trusted). `file` is the bare `.tar.gz`
/// filename to store it under (storage only — identity comes from the signed manifest inside).
#[derive(serde::Deserialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct InstallPluginReq {
    file: String,
    tarball_b64: String,
}

/// `POST /api/v1/admin/plugins` — INSTALL a signed plugin tarball (Full scope). Decodes the upload,
/// unpacks + structurally validates it IN MEMORY, RE-VERIFIES trust against the running `plugins.*`
/// posture, checks name/alias conflicts, and atomically writes the tarball into the plugins
/// directory. The uploaded code is NEVER executed by this endpoint (manifest-only inspection).
/// `201 Created` with the install result. The change takes effect on the next plugin (re)load,
/// not as a hot swap. Every attempt (success AND failure) is audited.
pub(crate) async fn install_plugin(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
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
    // ONE GLOBAL MUTATION DOMAIN for the plugins directory. `rollback_plugin` and `reload_plugins`
    // both validate an on-disk artifact and then REBUILD THE WHOLE APP by re-reading the entire
    // plugin set; a concurrent install that writes a tarball between those two steps makes the
    // rebuild load bytes nothing validated. Per-plugin locks cannot close this — the rebuild reads
    // every plugin, not one — so install joins the SAME `config_transaction` section every other
    // plugin/config mutation runs in. The tarball write is a `store_write`, so it executes on
    // `spawn_blocking` (a slow disk / large tarball never stalls the reactor) while the guard is
    // held: install-vs-rollback, install-vs-reload and install-vs-install are all serialized.
    let file = req.file.clone();
    let out = config_transaction(&handle, move |txn| {
        let snapshot = txn.app().clone();
        Ok(txn.store_write(move || {
            let view = AdminService::new(snapshot).install_store_plugin(&file, &tarball)?;
            // Installing does NOT hot-swap: the change takes effect on the next plugin (re)load, so
            // there is no plan to commit — only the filesystem write that just happened.
            Ok(Outcome::Value(view))
        }))
    })
    .await;
    match out {
        Ok(view) => {
            audit::AUDIT.record_by("plugin.install", &resource, audit::OUTCOME_APPLIED, &actor);
            ok_json(StatusCode::CREATED, &view)
        }
        Err(e) => {
            audit::AUDIT.record_by("plugin.install", &resource, audit::OUTCOME_REJECTED, &actor);
            err_json(&e)
        }
    }
}

/// `POST /api/v1/admin/plugins/inspect` request body. SAME shape as [`InstallPluginReq`] (question
/// #7 — "same request body shape as `POST /plugins`") — `file` is accepted for shape parity with
/// the install flow a UI composes around the same upload, but is otherwise UNUSED here: inspect
/// never writes anything to disk, so there is no filename to bind an install would need.
#[derive(serde::Deserialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct InspectPluginReq {
    #[allow(dead_code)]
    file: String,
    tarball_b64: String,
}

/// `POST /api/v1/admin/plugins/inspect` — a STATELESS, `read-only`-scope PREVIEW of a candidate
/// plugin tarball (plugin-settings-schema-SPEC.md checklist item 4, question #7): verifies the
/// tarball's signature, parses its manifest, and returns the SAME response shape `GET
/// /plugins/{name}/schema` carries. NEVER installs (no write to `plugins.dir`), NEVER
/// conflict-checks against the installed set. See [`AdminService::inspect_plugin`] for the
/// hardening this endpoint ships with — reachable by the weakest admin credential in the system, on
/// an attacker-controlled compressed archive, so it is treated as a parser attack surface, not
/// "just another stateless read".
pub(crate) async fn inspect_plugin(
    State(handle): State<Arc<AppHandle>>,
    body: axum::body::Bytes,
) -> Response {
    use base64::Engine as _;
    let req: InspectPluginReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return err_json(&AdminError::Validation(format!(
                "malformed plugin body: {e}"
            )));
        }
    };
    let tarball = match base64::engine::general_purpose::STANDARD.decode(req.tarball_b64.as_bytes())
    {
        Ok(b) => b,
        Err(e) => {
            return err_json(&AdminError::Validation(format!(
                "tarball_b64 is not valid base64: {e}"
            )));
        }
    };
    respond(StatusCode::OK, service(&handle).inspect_plugin(&tarball))
}

/// `DELETE /api/v1/admin/plugins/{file}` — REMOVE a dynamic-library plugin (Full scope): delete the
/// library + its manifest sidecar from the plugins directory. `404 not_found` if absent. `204 No
/// Content` on success. A currently-loaded store keeps running until the next store (re)load.
pub(crate) async fn remove_plugin(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    Path(file): Path<String>,
) -> Response {
    let actor = principal.actor_id().to_string();
    let resource = format!("plugin:{file}");
    // Same global mutation domain as install: a DELETE racing a rebuild-from-disk is the mirror
    // hazard of an install racing one — the rebuild would read a plugin set that changed under it.
    // The filesystem delete runs on `spawn_blocking`, under the guard.
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
        Err(e) => {
            audit::AUDIT.record_by("plugin.remove", &resource, audit::OUTCOME_REJECTED, &actor);
            err_json(&e)
        }
    }
}

/// `POST /api/v1/admin/plugins/reload` — HOT-SWAP the plugin layer LIVE (Full scope, audited) — the
/// sibling of `config/reload`, now a true hot reload rather than a report-only re-scan.
///
/// It re-runs the exact fail-closed plugin pipeline boot runs (re-read `config.yaml` + the persisted
/// overlay → resolve → three-phase `scan_and_validate` → open the hook transports) to build a FRESH
/// `App` snapshot carrying a NEW `PluginRegistry` and NEW hook-plugin instances, then `handle.swap`s
/// it. New requests immediately use the new plugin instances; in-flight requests finish on the OLD
/// snapshot, and when that snapshot drops its instances drop, their `Arc`-held `Library` handles drop,
/// and the old shared libraries unmap — no process restart. The core never goes down: any pipeline
/// failure (a bad new artifact — bad signature / abi out of range / open failure / conflict) is
/// FAIL-CLOSED — the swap is rejected, the OLD snapshot keeps serving, and the error names the fault.
///
/// The governance/store instance is REUSED across the swap (its keys/budgets/ledger must survive), so
/// this hot-reloads the registry + `kind: hook` transports; a `store` MODULE change still lands on a
/// dedicated store swap (the ledger cannot be silently re-hydrated under load). See the view `note`.
pub(crate) async fn reload_plugins(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
) -> Response {
    let actor = principal.actor_id().to_string();
    // Serialize against config applies/reloads AND against plugin install/remove — they all touch
    // the same plugins directory and rebuild-and-swap the App snapshot (: one global mutation
    // domain). The whole rebuild is disk I/O, so it is queued onto `spawn_blocking`.
    let out = config_transaction(&handle, |txn| {
        let snapshot = txn.app().clone();
        Ok(txn.read_store(move || {
            // EPHEMERAL mode (no disk config, e.g. tests/dev) has no disk truth to rebuild the
            // snapshot from — fall back to the report-only reconcile (the folder is still the source
            // of truth for the catalog), so an install→reload flow still works without persistence.
            // The LIVE hot swap needs disk truth.
            if snapshot.config_path.is_none() || snapshot.providers_path.is_none() {
                let view = AdminService::new(snapshot).reload_store_plugins()?;
                return Ok(Outcome::Value((None, Ok(view))));
            }
            let next = rebuild_app_from_disk(&snapshot).map_err(AdminError::Validation)?;
            let installed = Arc::new(next);
            // Project the inventory of the snapshot about to go live (the reconciled, loaded set).
            // A projection hiccup is reported but never rolls the swap back, exactly as before.
            let projected = AdminService::new(installed.clone()).reload_store_plugins();
            Ok(Outcome::swap(
                installed.clone(),
                (Some(installed), projected),
            ))
        }))
    })
    .await;
    match out {
        // Rebuild path: the swap succeeded, so the attempt is APPLIED regardless of the projection.
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
        // Ephemeral report-only path.
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
            Err(e) => {
                audit::AUDIT.record_by(
                    "plugin.reload",
                    "plugin:dir",
                    audit::OUTCOME_REJECTED,
                    &actor,
                );
                err_json(&e)
            }
        },
        Err(e) => {
            audit::AUDIT.record_by(
                "plugin.reload",
                "plugin:dir",
                audit::OUTCOME_REJECTED,
                &actor,
            );
            err_json(&e)
        }
    }
}

/// The `POST /api/v1/admin/plugins/rollback` body: the target library FILENAME to roll DOWN to.
#[derive(serde::Deserialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct PluginRollbackReq {
    /// The plugin tarball FILENAME (in the plugins directory) carrying the prior version to pin to.
    file: String,
}

/// `POST /api/v1/admin/plugins/rollback` — EXPLICIT, authenticated, audited rollback of a plugin to a
/// PRIOR version (Full scope, `If-Match`, 1.5.0 rollback-friendly versioning).
///
/// Anti-downgrade blocks only AUTOMATIC/silent downgrade (a replayed old artifact being auto-accepted
/// as "current"); it must NOT block an operator who pushed a bad plugin and needs to roll back. This
/// endpoint is that escape hatch, and it is deliberately NOT a blanket floor bypass. It (1)
/// authenticates the OPERATOR (Full scope) and rides `If-Match` for optimistic concurrency; (2)
/// validates the TARGET artifact (structure + trust) with the anti-downgrade floor lowered to EXACTLY
/// the target's own version — a lower artifact still fails, and an untrusted artifact still fails (a
/// rollback authenticates the operator, never the bytes); (3) PERSISTS the version pin to the overlay
/// (survives restart) and hot-swaps to the prior artifact via the same rebuild-and-swap path as
/// `plugins/reload`; and (4) audits EVERY attempt (applied or rejected).
///
/// An automatic path (boot/reload/apply) never lowers the floor — only this explicit, audited action
/// does (via the persisted pin) — so a silent replay of an old artifact is still refused.
pub(crate) async fn rollback_plugin(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let actor = principal.actor_id().to_string();
    let expected = match if_match_version(&headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let req: PluginRollbackReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return err_json(&AdminError::Validation(format!(
                "malformed rollback body: {e}"
            )))
        }
    };
    let resource = format!("plugin:{}", req.file);
    let file = req.file.clone();
    let audit_resource = resource.clone();
    // ONE section for validate → persist-pin → rebuild → swap. Because install/remove now enter the
    // SAME section, no concurrent write to the plugins directory can land between the artifact
    // this resolves and the artifact the rebuild reads back: the validate/rebuild pair is atomic.
    // Every step here is disk I/O, so the whole thing runs on `spawn_blocking`.
    let out = config_transaction(&handle, move |txn| {
        let current = txn.app();
        if let Some(e) = stale_if_match(expected, current.config_version) {
            return Err(e);
        }
        // A rollback must PERSIST its pin — an ephemeral (no-overlay) busbar has nowhere durable to
        // record the operator's decision, and a restart would silently re-upgrade. Refuse loudly.
        let Some(overlay_path) = current.overlay_path.clone() else {
            return Err(AdminError::Validation(
                "plugin rollback requires config persistence (BUSBAR_CONFIG_OVERLAY); without it \
                 the pin cannot be recorded and a restart would silently re-upgrade the plugin"
                    .into(),
            ));
        };
        let snapshot = current.clone();
        Ok(txn.store_write(move || {
            // The current persisted pins (empty if none) — the base we merge this rollback onto.
            let prior_pins = match crate::config::overlay::read(&overlay_path) {
                Some(doc) => doc.plugin_versions,
                None => std::collections::BTreeMap::new(),
            };
            // Resolve + validate the target and compute the merged pin map (fail-closed on a
            // bad/absent/untrusted target — nothing is persisted or swapped).
            let (manifest, pins) = AdminService::new(snapshot.clone())
                .resolve_plugin_rollback(&file, &prior_pins)?;
            // Persist the pin FIRST, so the rebuild (which re-reads the overlay) derives the lowered
            // floor and loads the prior artifact. Durability precedes the swap: if the process died
            // between here and the swap, a restart would come up already rolled back (the safe
            // direction). This persist is the WHOLE point of the rollback — a swallowed failure
            // would swap the LIVE engine to the prior plugin while disk still carries the
            // rolled-FORWARD state, so a restart would silently re-upgrade (defeating the operator's
            // explicit, audited decision) AND the rebuild below re-reads this overlay to derive the
            // lowered floor, so a non-persisted pin would rebuild against the wrong floor. Use the
            // Result-returning variant and FAIL CLOSED (nothing swapped) if it did not land.
            if let Err(e) =
                crate::config::overlay::try_persist_plugin_versions(Some(&overlay_path), &pins)
            {
                tracing::error!(plugin = %audit_resource, error = %e, "plugin rollback: persisting the version pin failed; nothing swapped");
                return Err(AdminError::Validation(format!(
                    "plugin rollback could not persist the version pin to the overlay: {e}; nothing \
                     was changed (the running engine still serves the current plugin)"
                )));
            }
            let next = match rebuild_app_from_disk(&snapshot) {
                Ok(next) => next,
                Err(e) => {
                    // The rebuild failed AFTER persisting the pin — the live snapshot is unchanged
                    // (old plugin still serving, fail-closed), but the pin is now on disk. Roll the
                    // pin back so a restart doesn't come up in a state the running engine rejected.
                    // The compensation MUST be robust: if reverting the pin ALSO fails, a
                    // silently-swallowed error would leave a stale rolled-forward pin on disk that a
                    // restart would honor — contradicting the running engine. Surface that as a
                    // distinct, louder error so the operator knows disk is out of sync and can fix
                    // the overlay before restarting.
                    if let Err(revert_err) = crate::config::overlay::try_persist_plugin_versions(
                        Some(&overlay_path),
                        &prior_pins,
                    ) {
                        tracing::error!(
                            plugin = %audit_resource, rebuild_error = %e, revert_error = %revert_err,
                            "plugin rollback rebuild failed AND reverting the persisted version pin \
                             failed; the running engine still serves the prior plugin, but disk now \
                             carries the rolled-forward pin — fix the overlay before restarting"
                        );
                        return Err(AdminError::Internal);
                    }
                    return Err(AdminError::Validation(e));
                }
            };
            let installed = Arc::new(next);
            // The pin is already durable (persisted above, before the rebuild), so the commit step
            // carries a no-op persist — the swap is the only thing left.
            Ok(Outcome::swap(installed.clone(), (installed, manifest)))
        }))
    })
    .await;
    match out {
        Ok((installed, manifest)) => {
            audit::AUDIT.record_by("plugin.rollback", &resource, audit::OUTCOME_APPLIED, &actor);
            installed.versions.record(
                installed.config_version,
                &actor,
                &format!("plugin.rollback {resource} -> {}", manifest.version),
                &installed.hook_registry,
                &installed.global_hooks,
            );
            with_config_etag(
                ok_json(
                    StatusCode::OK,
                    &crate::admin::v1::contract::PluginRollbackView {
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
        Err(e) => {
            audit::AUDIT.record_by(
                "plugin.rollback",
                &resource,
                audit::OUTCOME_REJECTED,
                &actor,
            );
            err_json(&e)
        }
    }
}

/// `GET /api/v1/admin/auth` — the ingress auth chain + upstream-credential mode (no secrets).
pub(crate) async fn get_auth(State(handle): State<Arc<AppHandle>>) -> Response {
    respond(StatusCode::OK, service(&handle).get_auth().await)
}

/// `GET /api/v1/admin/admin-auth` — the admin-plane auth config (the admin surface guard;
/// + config-plane `ETag` so a `PUT /api/v1/admin/admin-auth` can chain `If-Match` off this read).
pub(crate) async fn get_admin_auth(State(handle): State<Arc<AppHandle>>) -> Response {
    let version = handle.load().config_version;
    with_config_etag(
        respond(StatusCode::OK, service(&handle).get_admin_auth().await),
        version,
    )
}

/// `GET /api/v1/admin/usage` — the fleet METERING read: current UTC-day bucket, raw token split
/// per (model, provider) and per key + derived spend_micros (see the service/contract docs).
/// `?window=<bucket-start-epoch>` selects a PAST UTC-day bucket (default: current). The response
/// is ALWAYS one bucket — the pinned shape (see the contract doc).
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
    respond(StatusCode::OK, service(&handle).get_usage(window).await)
}

/// `GET /api/v1/admin/config` — the effective running config snapshot (redacted; no secrets;
/// + config-plane `ETag` so apply/rollback callers chain `If-Match` off this read).
pub(crate) async fn get_config(State(handle): State<Arc<AppHandle>>) -> Response {
    let version = handle.load().config_version;
    with_config_etag(
        respond(StatusCode::OK, service(&handle).get_config().await),
        version,
    )
}

/// The `POST /api/v1/admin/hooks` request body: the hook name + its definition. Optimistic concurrency
/// rides the `If-Match` header (H3) — never a body field.
#[derive(serde::Deserialize)]
pub(crate) struct RegisterHookReq {
    name: String,
    config: crate::config::HookCfg,
}

/// The `PUT /api/v1/admin/hooks/{name}` body: the replacement definition (the name rides the path;
/// optimistic concurrency rides `If-Match`).
#[derive(serde::Deserialize)]
pub(crate) struct PutHookReq {
    config: crate::config::HookCfg,
}

/// The `POST /api/v1/admin/groups` request body: the group name + its definition (a `GroupCfg`
/// accepted VERBATIM — paste a `groups:` block from config.yaml). Optimistic concurrency rides the
/// `If-Match` header, never a body field.
#[derive(serde::Deserialize)]
pub(crate) struct RegisterGroupReq {
    name: String,
    config: crate::config::GroupCfg,
}

/// The `PUT /api/v1/admin/groups/{name}` body: the replacement definition (name rides the path;
/// optimistic concurrency rides `If-Match`).
#[derive(serde::Deserialize)]
pub(crate) struct PutGroupReq {
    config: crate::config::GroupCfg,
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
    limits: Option<Vec<crate::config::LimitCfg>>,
    #[serde(default)]
    child_default: Option<crate::config::groups::ChildDefault>,
}

/// `POST /api/v1/admin/hooks` — register (or replace) a hook at RUNTIME. Validates the definition, builds
/// the next `App` snapshot with the hook wired + transports re-resolved, atomically `swap`s it in, and
/// returns `201` with the registered hook. A `global` hook is LIVE immediately (new requests see it);
/// in-flight requests finish on the old snapshot. Lanes/store are untouched — live breaker state is
/// preserved. This is the first API-driven config mutation.
pub(crate) async fn register_hook(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    axum::Extension(scope): axum::Extension<crate::auth::AdminScope>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let actor = principal.actor_id().to_string();
    let expected = match if_match_version(&headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let req: RegisterHookReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err_json(&AdminError::Validation(format!("malformed hook body: {e}"))),
    };
    // A hooks-register principal may not register a content-seeing / global (wired) hook.
    if let Some(e) = hooks_register_escalation(scope, &req.config) {
        audit::AUDIT.record_by(
            "hook.register",
            &format!("hook:{}", req.name),
            audit::OUTCOME_REJECTED,
            &actor,
        );
        return err_json(&e);
    }
    let name = req.name.clone();
    let resource = format!("hook:{name}");
    let cfg = req.config;
    // ONE critical section, entered through the single door: the base-hook guard, the If-Match
    // re-validation, the build, the persist and the swap all read the SAME fresh post-lock snapshot
    // (`txn.app()`) — there is no other snapshot in scope to read stale.
    let txn_name = name.clone();
    let out = config_transaction(&handle, move |txn| {
        let current = txn.app();
        // A base-config-defined hook may NOT be shadowed/redirected via the API — the same guard PUT
        // and PATCH enforce (put_hook / patch_hook_settings). Without it a narrow hooks-register token
        // could POST a same-shape definition over a base hook's name and silently redirect its
        // transport (e.g. point a base `pii-guard` gate at a hostile socket). Edit config.yaml for base
        // hooks.
        if current.base_hook_names.contains(&txn_name) {
            return Err(AdminError::Conflict(format!(
                "hook `{txn_name}` is defined in the base config file; edit config.yaml (the API \
                 cannot silently shadow operator file config)"
            )));
        }
        if let Some(e) = stale_if_match(expected, current.config_version) {
            return Err(e);
        }
        // Upsert status honesty: 201 only when the name is NEW; a same-grant re-register (an
        // idempotent refresh) is a 200 replace — standard upsert semantics, so POST/PUT overlap is
        // explicit.
        let existed = current.hook_registry.contains_key(&txn_name);
        let installed = Arc::new(build_with_hook(current, &txn_name, cfg)?);
        // PERSIST-then-SWAP, fail-closed: `commit` records the new hook state to the overlay FIRST;
        // only if disk takes it does the engine swap. A persist failure aborts the transaction and
        // swaps nothing (the running engine is untouched). Clear any tombstone for this name — a
        // re-register un-deletes it. Persist args are sourced from the CANDIDATE (`installed`),
        // which IS the state we are about to make live.
        let p = installed.clone();
        Ok(txn.commit(
            installed.clone(),
            move || {
                crate::config::overlay::persist(
                    p.overlay_path.as_deref(),
                    &p.hook_registry,
                    &p.global_hooks,
                    None,
                    Some(&txn_name),
                    &p.base_hook_names,
                )
                .map_err(|e| {
                    format!(
                        "hook could not be persisted to the overlay: {e}; nothing was changed (the \
                         running engine is unaffected)"
                    )
                })
            },
            (installed, existed),
        ))
    })
    .await;
    match out {
        Ok((installed, existed)) => {
            audit::AUDIT.record_by("hook.register", &resource, audit::OUTCOME_APPLIED, &actor);
            installed.versions.record(
                installed.config_version,
                &actor,
                &format!("hook.register {resource}"),
                &installed.hook_registry,
                &installed.global_hooks,
            );
            // Project the registered hook from the NEW (post-swap) snapshot for the 201 body; the
            // new config-plane ETag rides along so the caller chains its next If-Match without a read.
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
        Err(e) => {
            audit::AUDIT.record_by("hook.register", &resource, audit::OUTCOME_REJECTED, &actor);
            err_json(&e)
        }
    }
}

/// `PUT /api/v1/admin/hooks/{name}` — REPLACE an existing hook definition at runtime (live, atomic
/// swap). `404 not_found` for an unregistered name (PUT replaces; POST creates). `409 conflict`
/// for a BASE-defined hook (operator file config is edited in the file, never silently shadowed
/// via the API) and for a grant change (`kind`/`prompt`/`user` are immutable —, enforced in
/// `build_with_hook`). Audited + versioned + overlay-persisted like every mutation.
pub(crate) async fn put_hook(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    axum::Extension(scope): axum::Extension<crate::auth::AdminScope>,
    Path(name): Path<String>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let actor = principal.actor_id().to_string();
    let expected = match if_match_version(&headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let req: PutHookReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err_json(&AdminError::Validation(format!("malformed hook body: {e}"))),
    };
    // A hooks-register principal may not replace a hook into a content-seeing / global form.
    if let Some(e) = hooks_register_escalation(scope, &req.config) {
        audit::AUDIT.record_by(
            "hook.replace",
            &format!("hook:{name}"),
            audit::OUTCOME_REJECTED,
            &actor,
        );
        return err_json(&e);
    }
    let resource = format!("hook:{name}");
    let cfg = req.config;
    let txn_name = name.clone();
    let out = config_transaction(&handle, move |txn| {
        let current = txn.app();
        if !current.hook_registry.contains_key(&txn_name) {
            // Audit the 404 like every other reject in this handler (and like DELETE's 404) —
            // otherwise an attacker can probe which hook names exist via the response code with no
            // audit trail.
            return Err(AdminError::not_found(format!("hook `{txn_name}`")));
        }
        if current.base_hook_names.contains(&txn_name) {
            return Err(AdminError::Conflict(format!(
                "hook `{txn_name}` is defined in the base config file; edit config.yaml (the API \
                 cannot silently shadow operator file config)"
            )));
        }
        if let Some(e) = stale_if_match(expected, current.config_version) {
            return Err(e);
        }
        let installed = Arc::new(build_with_hook(current, &txn_name, cfg)?);
        // PERSIST-then-SWAP, fail-closed (see hook.register / AppHandle::commit_and_swap).
        let p = installed.clone();
        Ok(txn.commit(
            installed.clone(),
            move || {
                crate::config::overlay::persist(
                    p.overlay_path.as_deref(),
                    &p.hook_registry,
                    &p.global_hooks,
                    None,
                    Some(&txn_name),
                    &p.base_hook_names,
                )
                .map_err(|e| {
                    format!(
                        "hook could not be persisted to the overlay: {e}; nothing was changed (the \
                         running engine is unaffected)"
                    )
                })
            },
            installed,
        ))
    })
    .await;
    match out {
        Ok(installed) => {
            audit::AUDIT.record_by("hook.replace", &resource, audit::OUTCOME_APPLIED, &actor);
            installed.versions.record(
                installed.config_version,
                &actor,
                &format!("hook.replace {resource}"),
                &installed.hook_registry,
                &installed.global_hooks,
            );
            with_config_etag(
                respond(StatusCode::OK, service(&handle).get_hook(&name).await),
                installed.config_version,
            )
        }
        Err(e) => {
            audit::AUDIT.record_by("hook.replace", &resource, audit::OUTCOME_REJECTED, &actor);
            err_json(&e)
        }
    }
}

/// `DELETE /api/v1/admin/hooks/{name}` — remove an API-registered hook at RUNTIME (live). Builds the next
/// snapshot without the hook (dropped from the registry + global wiring, transports re-resolved) and
/// swaps it in. `404 not_found` if the hook is unregistered; `409 conflict` if the hook is
/// base-config-defined (base hooks are file-owned and read-only via the API — the same posture as
/// PUT/PATCH; edit config.yaml to remove one). `204 No Content` on success.
pub(crate) async fn delete_hook(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    axum::Extension(scope): axum::Extension<crate::auth::AdminScope>,
    Path(name): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let actor = principal.actor_id().to_string();
    let expected = match if_match_version(&headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let resource = format!("hook:{name}");
    let txn_name = name.clone();
    let out = config_transaction(&handle, move |txn| {
        let current = txn.app();
        // EXISTENCE before the concurrency guard — the same status precedence PUT/PATCH use, so all
        // three verbs answer a stale guard on a nonexistent hook identically (404, not 409).
        if !current.hook_registry.contains_key(&txn_name) {
            return Err(AdminError::not_found(format!("hook `{txn_name}`")));
        }
        // Escalation guard, keyed on the EXISTING hook's grants — a non-Full (hooks-register)
        // principal may not DELETE a content-seeing (`prompt`/`user`) or `global: true` gate. Such a
        // hook can only have been created by a Full admin (register/put block a narrow token from
        // wiring one), and DELETING it TEARS DOWN that admin's security gate — the same escalation
        // register / put / patch already forbid. Without this a hooks-register token could remove an
        // operator's global `pii-guard` gate and reach content by the back door.
        //
        // BEFORE the staleness check, matching `put_hook`'s escalation guard (checked before the
        // transaction even opens): a principal that may never delete this hook must not be told
        // "retry with a fresher ETag" — 403 is terminal regardless of which version the client held.
        if let Some(existing) = current.hook_registry.get(&txn_name) {
            if let Some(e) = hooks_register_escalation(scope, existing) {
                return Err(e);
            }
        }
        // Base-config guard BEFORE the If-Match staleness check, matching the precedence `put_hook`
        // and `delete_group` establish on this resource: a base-config hook can NEVER be deleted via
        // the API, so that terminal `conflict` must win over the retryable `version_conflict`. The
        // prior order returned `version_conflict` for a stale-ETag DELETE on a base hook, trapping an
        // auto-retry-on-conflict client in a re-read/retry loop that never sees the terminal error.
        if current.base_hook_names.contains(&txn_name) {
            return Err(AdminError::Conflict(format!(
                "hook `{txn_name}` is defined in the base config file; edit config.yaml (the API \
                 cannot silently shadow operator file config)"
            )));
        }
        // Optimistic concurrency (H3): DELETE honors `If-Match` like every other config-plane
        // mutation (it previously had NO guard — the one mutation verb missing it).
        if let Some(e) = stale_if_match(expected, current.config_version) {
            return Err(e);
        }
        let installed = Arc::new(build_without_hook(current, &txn_name)?);
        // PERSIST-then-SWAP, fail-closed. Tombstone this name (arg `Some(&name)`) so the deletion
        // survives a restart even if the hook was base-defined.
        let p = installed.clone();
        Ok(txn.commit(
            installed.clone(),
            move || {
                crate::config::overlay::persist(
                    p.overlay_path.as_deref(),
                    &p.hook_registry,
                    &p.global_hooks,
                    Some(&txn_name),
                    None,
                    &p.base_hook_names,
                )
                .map_err(|e| {
                    format!(
                        "hook deletion could not be persisted to the overlay: {e}; nothing was \
                         changed (the running engine is unaffected)"
                    )
                })
            },
            installed,
        ))
    })
    .await;
    match out {
        Ok(installed) => {
            audit::AUDIT.record_by("hook.delete", &resource, audit::OUTCOME_APPLIED, &actor);
            installed.versions.record(
                installed.config_version,
                &actor,
                &format!("hook.delete {resource}"),
                &installed.hook_registry,
                &installed.global_hooks,
            );
            // 204 still carries the NEW config-plane ETag — a scripted delete chain needs no re-read.
            with_config_etag(
                StatusCode::NO_CONTENT.into_response(),
                installed.config_version,
            )
        }
        Err(e) => {
            audit::AUDIT.record_by("hook.delete", &resource, audit::OUTCOME_REJECTED, &actor);
            err_json(&e)
        }
    }
}

/// Resolve — and if needed AUTO-PROVISION — the group a `POST /keys` mint binds to (self-service
/// D2). The mint-time group contract, one place, shared by the key handler:
///
/// - group EXISTS, no `parent` given → bind as-is (`Ok(None)`, nothing to provision).
/// - group EXISTS, `parent` given → the given parent MUST equal the group's actual parent, else
///   `409 conflict` (a portal must not silently re-home an existing leaf under a different team).
/// - group MISSING, `parent` given → return the CANDIDATE `App` that creates it as a leaf under
///   `parent`, limits stamped from the nearest-ancestor `child_default` (inherit-only when none),
///   via the SAME `build_with_group` validate-at-the-door path every group write uses (so
///   validation / cost rebuild / base-shadow guard all hold).
/// - group MISSING, no `parent` → today's `400` (an unknown group with nowhere to root it).
///
/// PURE and SYNCHRONOUS: it decides against the snapshot it is handed and returns a plan. It takes
/// no lock and performs no swap — the caller runs it INSIDE `config_transaction`, so the existence
/// check, the provisioning swap and the key's store write share ONE continuous lock hold. The
/// earlier shape took the mutation lock itself and RELEASED it on return, which is exactly why the
/// mint had to re-acquire and re-verify the group by hand; there is nothing left to re-verify
/// because the lock is never released between the check and the bind. `parent` is capped at
/// `MAX_GROUP_NAME_LEN` (a registry key / audit row).
pub(crate) fn plan_mint_group(
    current: &Arc<crate::state::App>,
    group: &str,
    parent: Option<&str>,
    actor: &str,
) -> Result<Option<Arc<crate::state::App>>, AdminError> {
    // Fast path: the group already exists (existence is the ENFORCEMENT truth — `cost.group_named`,
    // the exact check every request admission uses — so a mint never binds a group the chain can't
    // resolve). If a `parent` was named it must match the existing parent (never silently re-home an
    // existing leaf); the parent value comes from the config registry, which agrees with the cost
    // model in production (both rebuilt together on every apply).
    if current.cost.group_named(group).is_some() {
        if let Some(want) = parent {
            let actual = current
                .groups_registry
                .get(group)
                .and_then(|g| g.parent.clone());
            if actual.as_deref() != Some(want) {
                return Err(AdminError::Conflict(format!(
                    "group `{group}` already exists with parent {}; the mint named parent `{want}` \
                     — a mint cannot re-home an existing group (PATCH the group to re-parent it, or \
                     drop `parent` to bind as-is)",
                    actual
                        .map(|p| format!("`{p}`"))
                        .unwrap_or_else(|| "<root>".into()),
                )));
            }
        }
        return Ok(None);
    }
    // The group does NOT exist. Without a `parent` there is nowhere to root it — today's 400 stands
    // (mirrors the pre-auto-provision message, but points at the self-service `parent:` field).
    let Some(parent) = parent else {
        return Err(AdminError::Validation(format!(
            "group '{group}' does not exist in the top-level groups block; either configure it \
             first, or pass `parent: <existing-group>` to auto-provision it as a leaf (e.g. \
             `parent: team-payments` creates {group} under team-payments and binds the key)"
        )));
    };
    if parent.len() > crate::admin::v1::service::MAX_GROUP_NAME_LEN {
        return Err(AdminError::Validation(format!(
            "parent name is {} chars; must be <= {}",
            parent.len(),
            crate::admin::v1::service::MAX_GROUP_NAME_LEN
        )));
    }
    // The named parent must exist — build_with_group's validate-at-the-door would reject a dangling
    // parent as a 400, but name it precisely here (the mint's parent, not an opaque tree error).
    // Existence via the enforcement truth (cost), matching the group existence check above.
    if current.cost.group_named(parent).is_none() {
        return Err(AdminError::Validation(format!(
            "cannot auto-provision `{group}`: its `parent: {parent}` does not exist in the \
             top-level groups block; name an existing team/org group"
        )));
    }
    // A base-config group name is file-owned — the additive overlay cannot durably shadow it, so a
    // mint must not materialize one at runtime (mirrors POST /groups). Vanishingly unlikely for a
    // `user:<sub>` leaf, but the guard is uniform across every write path.
    if current.base_group_names.contains(group) {
        return Err(AdminError::Conflict(format!(
            "group `{group}` is defined in the base config file; edit config.yaml (the API cannot \
             silently shadow operator file config)"
        )));
    }
    // ANTI-SPRAWL CEILING ON THE TREE'S SHAPE. `max_keys_per_principal` bounds
    // how many keys a group holds but says nothing about how many GROUPS exist, so a `mint`-scope
    // credential could grow the limit tree without bound — every auto-provisioned `user:<sub>` leaf
    // is a new enforcement bucket, a new version-log entry and a new persisted overlay row.
    // `limits.max_auto_provisioned_groups` (0 = unlimited, the default) caps the runtime group set
    // this path may grow. Checked HERE, inside the transaction, against the same fresh snapshot the
    // existence check reads, so N concurrent self-mints cannot jointly overshoot. Explicitly
    // configured groups are unaffected: only auto-provisioning is gated.
    let ceiling = current.max_auto_provisioned_groups;
    if ceiling > 0 && current.groups_registry.len() >= ceiling {
        return Err(AdminError::Conflict(format!(
            "cannot auto-provision `{group}`: this server already has {} group(s), at the \
             `limits.max_auto_provisioned_groups` ceiling of {ceiling}. Delete an unused group, \
             raise the ceiling, or bind the key to an existing group",
            current.groups_registry.len(),
        )));
    }
    let leaf = crate::config::groups::provision_child(&current.groups_registry, parent);
    match build_with_group(current, group, leaf) {
        Ok(next) => Ok(Some(Arc::new(next))),
        Err(e) => {
            // Same audit row the explicit `POST /groups` writes when its build is rejected.
            audit::AUDIT.record_by(
                "group.provision",
                &format!("group:{group}"),
                audit::OUTCOME_REJECTED,
                actor,
            );
            Err(e)
        }
    }
}

/// The overlay persist a mint's auto-provisioned group leaf commits (PERSIST-then-SWAP, fail-closed
/// — the same discipline and the same wording as an explicit `POST /groups`).
pub(crate) fn persist_provisioned_group(
    installed: Arc<crate::state::App>,
    group: String,
    actor: String,
) -> impl FnOnce() -> Result<(), String> + Send + 'static {
    move || {
        crate::config::overlay::persist_groups(
            installed.overlay_path.as_deref(),
            &installed.groups_registry,
            None,
            Some(&group),
            &installed.base_group_names,
        )
        .map_err(|e| {
            audit::AUDIT.record_by(
                "group.provision",
                &format!("group:{group}"),
                audit::OUTCOME_REJECTED,
                &actor,
            );
            format!("group could not be persisted to the overlay: {e}; nothing was changed")
        })
    }
}

/// `POST /api/v1/admin/groups` — create (or replace) a group at RUNTIME. Validate-at-the-door: the
/// mutated tree is re-validated (parent exists, acyclic, depth) — an invalid tree is a `400` that
/// changes nothing. `201` when the name is NEW, `200` on replace (upsert). `409` for a base-config
/// group (edit config.yaml; the API cannot silently shadow file config) or a stale `If-Match`.
/// Live immediately (limits rebuilt into the cost model, swapped in); persisted to the overlay so it
/// survives restart. Full scope (the `/groups` mutation fallthrough); the narrow delegated
/// `group-admin` scope for the self-service tool lands in Phase 2.
pub(crate) async fn register_group(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let actor = principal.actor_id().to_string();
    let expected = match if_match_version(&headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let req: RegisterGroupReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return err_json(&AdminError::Validation(format!(
                "malformed group body: {e}"
            )))
        }
    };
    let name = req.name.clone();
    let resource = format!("group:{name}");
    let cfg = req.config;
    let txn_name = name.clone();
    let out = config_transaction(&handle, move |txn| {
        let current = txn.app();
        // A base-config group is file-owned: the additive overlay cannot durably shadow it, and a
        // narrow token must not silently redirect a base group's limits. Edit config.yaml. (Mirrors
        // hooks.)
        if current.base_group_names.contains(&txn_name) {
            return Err(AdminError::Conflict(format!(
                "group `{txn_name}` is defined in the base config file; edit config.yaml (the API \
                 cannot silently shadow operator file config)"
            )));
        }
        if let Some(e) = stale_if_match(expected, current.config_version) {
            return Err(e);
        }
        let existed = current.groups_registry.contains_key(&txn_name);
        let installed = Arc::new(build_with_group(current, &txn_name, cfg)?);
        // PERSIST-then-SWAP, fail-closed. Persist the whole groups section; clear any tombstone
        // for this name (re-create un-deletes).
        let p = installed.clone();
        Ok(txn.commit(
            installed.clone(),
            move || {
                crate::config::overlay::persist_groups(
                    p.overlay_path.as_deref(),
                    &p.groups_registry,
                    None,
                    Some(&txn_name),
                    &p.base_group_names,
                )
                .map_err(|e| {
                    format!(
                        "group could not be persisted to the overlay: {e}; nothing was changed (the \
                         running engine is unaffected)"
                    )
                })
            },
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
        Err(e) => {
            audit::AUDIT.record_by("group.create", &resource, audit::OUTCOME_REJECTED, &actor);
            err_json(&e)
        }
    }
}

/// `PUT /api/v1/admin/groups/{name}` — REPLACE an existing group at runtime (live, atomic swap).
/// `404` for an unknown name (PUT replaces; POST creates). `409` for a base-config group or a stale
/// `If-Match`, `400` if the replacement breaks the tree. Audited + versioned + overlay-persisted.
pub(crate) async fn put_group(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    Path(name): Path<String>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let actor = principal.actor_id().to_string();
    let expected = match if_match_version(&headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let req: PutGroupReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return err_json(&AdminError::Validation(format!(
                "malformed group body: {e}"
            )))
        }
    };
    let resource = format!("group:{name}");
    let cfg = req.config;
    let txn_name = name.clone();
    let out = config_transaction(&handle, move |txn| {
        let current = txn.app();
        if !current.groups_registry.contains_key(&txn_name) {
            return Err(AdminError::not_found(format!("group `{txn_name}`")));
        }
        if current.base_group_names.contains(&txn_name) {
            return Err(AdminError::Conflict(format!(
                "group `{txn_name}` is defined in the base config file; edit config.yaml (the API \
                 cannot silently shadow operator file config)"
            )));
        }
        if let Some(e) = stale_if_match(expected, current.config_version) {
            return Err(e);
        }
        let installed = Arc::new(build_with_group(current, &txn_name, cfg)?);
        // PERSIST-then-SWAP, fail-closed.
        let p = installed.clone();
        Ok(txn.commit(
            installed.clone(),
            move || {
                crate::config::overlay::persist_groups(
                    p.overlay_path.as_deref(),
                    &p.groups_registry,
                    None,
                    Some(&txn_name),
                    &p.base_group_names,
                )
                .map_err(|e| {
                    format!(
                        "group could not be persisted to the overlay: {e}; nothing was changed (the \
                         running engine is unaffected)"
                    )
                })
            },
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
        Err(e) => {
            audit::AUDIT.record_by("group.replace", &resource, audit::OUTCOME_REJECTED, &actor);
            err_json(&e)
        }
    }
}

/// `PATCH /api/v1/admin/groups/{name}` — PARTIAL update: change only the fields present, preserve
/// the rest (the "raise Alice's budget" / "freeze this team" verb). Merges onto the current
/// definition then routes through the SAME `build_with_group` validation + cost rebuild as PUT, so
/// a partial edit that breaks the tree is a `400` that changes nothing. `404`/`409` semantics match
/// PUT (unknown name / base group / stale `If-Match`). Audited + versioned + overlay-persisted.
pub(crate) async fn patch_group(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    Path(name): Path<String>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let actor = principal.actor_id().to_string();
    let expected = match if_match_version(&headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
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
            return Err(AdminError::Conflict(format!(
                "group `{txn_name}` is defined in the base config file; edit config.yaml (the API \
                 cannot silently shadow operator file config)"
            )));
        }
        if let Some(e) = stale_if_match(expected, current.config_version) {
            return Err(e);
        }
        // Merge the provided fields onto the current definition; absent fields are preserved. The
        // base being merged onto is the FRESH post-lock definition, so a concurrent PUT cannot be
        // silently clobbered by a patch that read the group before the lock.
        let merged = merge_group_patch(
            existing.clone(),
            req.parent,
            req.enabled,
            req.limits,
            req.child_default,
        );
        let installed = Arc::new(build_with_group(current, &txn_name, merged)?);
        // PERSIST-then-SWAP, fail-closed.
        let p = installed.clone();
        Ok(txn.commit(
            installed.clone(),
            move || {
                crate::config::overlay::persist_groups(
                    p.overlay_path.as_deref(),
                    &p.groups_registry,
                    None,
                    Some(&txn_name),
                    &p.base_group_names,
                )
                .map_err(|e| {
                    format!(
                        "group could not be persisted to the overlay: {e}; nothing was changed (the \
                         running engine is unaffected)"
                    )
                })
            },
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
        Err(e) => {
            audit::AUDIT.record_by("group.patch", &resource, audit::OUTCOME_REJECTED, &actor);
            err_json(&e)
        }
    }
}

/// `DELETE /api/v1/admin/groups/{name}` — remove an API-created group at runtime (live). `404` if
/// unknown; `409` if base-config-defined (edit config.yaml) or if another group still names it as
/// `parent` (re-parent/remove the children first — never silently orphan them). `204` on success;
/// the name is tombstoned so the deletion survives a restart.
pub(crate) async fn delete_group(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    Path(name): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let actor = principal.actor_id().to_string();
    let expected = match if_match_version(&headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let resource = format!("group:{name}");
    let txn_name = name.clone();
    let out = config_transaction(&handle, move |txn| {
        let current = txn.app();
        if !current.groups_registry.contains_key(&txn_name) {
            return Err(AdminError::not_found(format!("group `{txn_name}`")));
        }
        // Base-config guard BEFORE the If-Match staleness check, matching the precedence `put_group`
        // and `patch_group` establish on this resource: a base-config group can NEVER be deleted via
        // the API, so that terminal `conflict` must win over the retryable `version_conflict`. The
        // prior order returned `version_conflict` for a stale-ETag DELETE on a base group, trapping
        // an auto-retry-on-conflict client in a re-read/retry loop that never sees the terminal
        // error.
        if current.base_group_names.contains(&txn_name) {
            return Err(AdminError::Conflict(format!(
                "group `{txn_name}` is defined in the base config file; edit config.yaml (the API \
                 cannot silently shadow operator file config)"
            )));
        }
        if let Some(e) = stale_if_match(expected, current.config_version) {
            return Err(e);
        }
        // The bound-key count is a synchronous, possibly plugin-backed `Store::list_keys()` scan of
        // EVERY key. It is queued as a store READ: the closure runs on `spawn_blocking` — so the
        // reactor keeps scheduling while a slow disk/DB answers — but still under the SAME guard, so
        // the count, the tree validation and the swap are one atomic section. Nothing in the
        // synchronous body above has a `&GovState`/`&dyn Store` to call this on, which is what makes
        // "blocking under the async lock" a compile-time impossibility rather than a convention.
        let snapshot = current.clone();
        Ok(txn.read_store(move || {
            let bound = crate::admin::v1::service::count_keys_bound_to(&snapshot, &txn_name)?;
            let installed = Arc::new(build_without_group(&snapshot, &txn_name, bound)?);
            // PERSIST-then-SWAP, fail-closed. Tombstone this name (arg `Some(&name)`) so the
            // deletion survives a restart (the overlay is additive otherwise).
            let p = installed.clone();
            Ok(Outcome::commit(
                installed.clone(),
                move || {
                    crate::config::overlay::persist_groups(
                        p.overlay_path.as_deref(),
                        &p.groups_registry,
                        Some(&txn_name),
                        None,
                        &p.base_group_names,
                    )
                    .map_err(|e| {
                        format!(
                            "group deletion could not be persisted to the overlay: {e}; nothing was \
                             changed (the running engine is unaffected)"
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
            with_config_etag(
                StatusCode::NO_CONTENT.into_response(),
                installed.config_version,
            )
        }
        Err(e) => {
            audit::AUDIT.record_by("group.delete", &resource, audit::OUTCOME_REJECTED, &actor);
            err_json(&e)
        }
    }
}

/// `DELETE /api/v1/admin/overlay/{section}` — DISCARD every overlay mutation for one section and revert
/// it to what base `config.yaml` declares. `section` ∈ {`groups`, `hooks`, `root`}; an unknown name is
/// a `400` `invalid_request`. This is the audited revert-to-config front door (D3: per-section, NOT
/// whole-overlay): it clears that section's overlay entries + tombstones, then rebuilds a complete
/// `App` from base config (disk truth re-read + resolved, the OTHER sections' overlay still merged) and
/// swaps it in — so a `groups` reset restores base group limits (cost model rebuilt), a `hooks` reset
/// restores base hooks (registry/gates/rewrites rebuilt), and a `root` reset restores base single-value
/// config (rate_card/store/security/limits/… — cost model + limits reprojected), each leaving the
/// sibling sections' runtime mutations untouched. Full scope; `If-Match` optimistic concurrency;
/// audited + versioned; the cleared
/// overlay is persisted so the revert survives a restart. A section with NO overlay state is a clean
/// no-op success (idempotent) — nothing changes, the version does not bump. Requires config files on
/// disk (the base truth to revert to); an ephemeral busbar has none, so reset is an `invalid_request`
/// there, exactly like `config/reload`.
pub(crate) async fn reset_overlay_section(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    Path(section): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    use crate::config::overlay::OverlaySection;
    let actor = principal.actor_id().to_string();
    // Validate the section name BEFORE the If-Match parse so an unknown section is always a plain
    // 400 (never masked by a header error). Unknown → invalid_request (the taxonomy's 400).
    let Some(section) = OverlaySection::parse(&section) else {
        return err_json(&AdminError::Validation(format!(
            "unknown overlay section `{section}`: expected `groups`, `hooks`, `root`, or \
             `plugin_versions`"
        )));
    };
    let resource = format!("overlay:{}", section.as_str());
    let expected = match if_match_version(&headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    // ONE section: the If-Match re-validation, the idempotent-no-op probe, the disk rebuild, the
    // overlay clear and the swap. The disk work (overlay read + `load_config_from_disk` + resolve +
    // build) is a store/disk READ, so it is queued onto `spawn_blocking` — it used to run inline on
    // a Tokio worker with the async mutation lock held, stalling the reactor for the whole rebuild.
    let out = config_transaction(&handle, move |txn| {
        let current = txn.app();
        if let Some(e) = stale_if_match(expected, current.config_version) {
            return Err(e);
        }
        let snapshot = current.clone();
        Ok(txn.read_store(move || {
            // IDEMPOTENT NO-OP: if this section carries no overlay state (no API-applied entries AND
            // no tombstones), the effective config already equals base for it — a reset changes
            // nothing, so short-circuit a 200 without bumping the version or re-running the boot
            // pipeline. This reads the overlay FILE, which is why it lives on the blocking side.
            let overlay_empty = match snapshot.overlay_path.as_deref() {
                None => true,
                Some(p) => match crate::config::overlay::read_state(p) {
                    crate::config::overlay::OverlayReadState::Absent => true,
                    crate::config::overlay::OverlayReadState::Loaded(doc) => {
                        doc.section_is_empty(section)
                    }
                    // A corrupt or too-new overlay is NOT "no overlay state". Reporting
                    // `changed:false` would claim this section already equals base while the live
                    // App may still carry it, and would skip the fail-closed `clear_section`
                    // entirely (the asymmetry `rollback_plugin` and every persist path already
                    // refuse on).
                    crate::config::overlay::OverlayReadState::Unreadable => {
                        return Err(AdminError::Validation(format!(
                            "the config overlay at '{}' is present but unreadable/corrupt; refusing \
                             to reset section `{}` (a reset probe over corrupt state cannot tell \
                             whether this section still carries live overrides). Fix or remove the \
                             overlay file, or restore it from backup, before resetting",
                            p.display(),
                            section.as_str()
                        )));
                    }
                    crate::config::overlay::OverlayReadState::VersionTooNew(v) => {
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
            // Re-run the BOOT disk-load pipeline to recover base `config.yaml` truth, then merge the
            // CURRENT overlay with this section CLEARED. Ephemeral mode has no disk truth to revert
            // to — the same 400 `config/reload` gives.
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
            let built = crate::load_config_from_disk(
                &config_path,
                &providers_path,
                false,
                crate::config::EnvSubst::Strict,
            )
            .and_then(|mut loaded| {
                // CLEAR the target section from the persisted overlay FIRST — that slice reverts to
                // base, the other slices stay live. The clear happens before both merge halves so a
                // `root` reset drops its DeployCfg-level overrides pre-resolve, and a `hooks`/
                // `groups` reset drops its registry entries post-resolve.
                let cleared_doc = loaded.overlay_doc.take().map(|mut doc| {
                    doc.clear_section(section);
                    doc
                });
                // Pre-resolve half: apply the (post-clear) root overrides onto the base DeployCfg,
                // so the limits projection + admin-mTLS boot-guard re-derive over the merged shape.
                if let Some(doc) = cleared_doc.as_ref() {
                    crate::config::overlay::apply_root_to_deploy(&mut loaded.deploy, doc);
                }
                let mut cfg = crate::config::resolve(&loaded.deploy, &loaded.defs)
                    .map_err(|errs| format!("config errors:\n  - {}", errs.join("\n  - ")))?;
                let base_hook_names: std::collections::HashSet<String> =
                    cfg.hooks.keys().cloned().collect();
                let base_group_names: std::collections::HashSet<String> =
                    cfg.groups.keys().cloned().collect();
                // Post-resolve half: merge the (post-clear) hooks + groups sections onto the
                // resolved config.
                if let Some(doc) = cleared_doc {
                    crate::config::overlay::merge_into(&mut cfg, doc);
                }
                crate::build_app_from_config(
                    cfg,
                    loaded.deploy.plugins.clone(),
                    // Preserve the LIVE overlay path (not the env-derived one
                    // `load_config_from_disk` returns) — the reset rewrites the same overlay file
                    // the running App uses, exactly as `config/apply` preserves
                    // `current.overlay_path`.
                    snapshot.overlay_path.clone(),
                    base_hook_names,
                    base_group_names,
                    (Some(config_path), Some(providers_path)),
                    Some(&snapshot),
                )
            })
            .map_err(AdminError::Validation)?;
            let installed = Arc::new(built);
            // PERSIST-THEN-SWAP (fail-closed), matching plugins/rollback's durability ordering:
            // write the section-cleared overlay to disk BEFORE swapping the live App. A prior
            // version swapped first and persisted after, so a crash in that window left the LIVE
            // engine reverted while disk still carried the un-cleared overlay — a restart would
            // silently re-apply the section the operator just reset (e.g. re-pin the
            // plugin_versions they cleared). Persisting first means a crash before the swap comes
            // up already reset (the safe direction). The installed App preserves
            // `current.overlay_path`, so it names the same overlay file. (The sibling section is
            // preserved verbatim by the read-modify-write inside `clear_section`.)
            let p = installed.clone();
            Ok(Outcome::commit(
                installed.clone(),
                move || {
                    crate::config::overlay::clear_section(p.overlay_path.as_deref(), section)
                        .map_err(|e| {
                            format!(
                                "overlay section reset could not be persisted: {e}; nothing was \
                                 changed (the running engine is unaffected)"
                            )
                        })
                },
                (installed.config_version, Some(installed)),
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
            err_json(&e)
        }
    }
}

/// Apply a partial group PATCH onto a base definition: a field that is `Some` REPLACES, `None`
/// PRESERVES. `limits`/`child_default` replace their whole list (a list can't be field-merged). The
/// pure, testable core of `patch_group`.
fn merge_group_patch(
    mut base: crate::config::GroupCfg,
    parent: Option<String>,
    enabled: Option<bool>,
    limits: Option<Vec<crate::config::LimitCfg>>,
    child_default: Option<crate::config::groups::ChildDefault>,
) -> crate::config::GroupCfg {
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

/// Record a config-version entry for a GROUP mutation. The `VersionLog` snapshot payload is the
/// hook surface (its rollback scope today); a group change still bumps `config_version` and lands an
/// audited, timestamped version row (so `GET /config/versions` shows the event honestly). Extending
/// the snapshot + `config/rollback` to restore groups is a tracked follow-up (task #100).
fn record_group_version(installed: &Arc<crate::state::App>, actor: &str, summary: &str) {
    installed.versions.record(
        installed.config_version,
        actor,
        summary,
        &installed.hook_registry,
        &installed.global_hooks,
    );
}

/// `GET /api/v1/admin/audit` — the admin audit log (most-recent-first), every mutation with its outcome.
/// Filters: `?action=hook.register`, `?resource=hook:x`. Paginated by the shared cursor envelope:
/// `?limit=N` (cap 1000) + opaque `?cursor=`, response `{items, next_cursor}` (next_cursor iff more).
pub(crate) async fn get_audit(
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let limit = q
        .get("limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(crate::admin::v1::contract::LIST_LIMIT_DEFAULT)
        .clamp(1, crate::admin::v1::contract::LIST_LIMIT_MAX);
    let start = match cursor_offset(&q) {
        Ok(n) => n,
        Err(resp) => return resp,
    };
    let action = q.get("action").map(String::as_str);
    let resource = q.get("resource").map(String::as_str);
    // Fetch one past the page to learn whether a further page exists, then trim to `limit`.
    let mut entries = audit::AUDIT.list_filtered(start, limit + 1, action, resource);
    let next_cursor = page_cursor(&mut entries, start, limit);
    ok_json(
        StatusCode::OK,
        &json!({ "items": entries, "next_cursor": next_cursor }),
    )
}

/// `GET /api/v1/admin/config/versions` — version history metadata, newest first. Paginated by the shared
/// cursor envelope: `?limit=N` (cap 1000) + opaque `?cursor=`, response `{items, next_cursor}`.
pub(crate) async fn list_config_versions(
    State(handle): State<Arc<AppHandle>>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let limit = q
        .get("limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(crate::admin::v1::contract::VERSIONS_LIMIT_DEFAULT)
        .clamp(1, crate::admin::v1::contract::LIST_LIMIT_MAX);
    let start = match cursor_offset(&q) {
        Ok(n) => n,
        Err(resp) => return resp,
    };
    let mut versions = handle.load().versions.list(start, limit + 1);
    let next_cursor = page_cursor(&mut versions, start, limit);
    ok_json(
        StatusCode::OK,
        &json!({ "items": versions, "next_cursor": next_cursor }),
    )
}

/// `GET /api/v1/admin/config/versions/{v}` — one retained version WITH its hook-surface snapshot.
/// The `{v}` segment is bound as a STRING and parsed here (not `Path<u64>`): a typed extractor
/// rejects a non-numeric segment with axum's OWN plain-text 400, escaping the frozen envelope —
/// parsing in-handler lets a malformed version speak `invalid_request` like every other 400.
pub(crate) async fn get_config_version(
    State(handle): State<Arc<AppHandle>>,
    Path(v): Path<String>,
) -> Response {
    let Ok(v) = v.parse::<u64>() else {
        return err_json(&AdminError::Validation(format!(
            "config version must be a non-negative integer; got `{v}`"
        )));
    };
    match handle.load().versions.get(v) {
        Some(cv) => {
            // Project the snapshot through the ONE wire HookView shape (against the SNAPSHOT's own
            // global wiring) — never the raw HookCfg file shape, so a consumer parses hooks with a
            // single schema whether it reads /hooks or a retained version.
            let hooks: std::collections::BTreeMap<&String, _> = cv
                .hook_registry
                .iter()
                .map(|(name, cfg)| {
                    (
                        name,
                        crate::admin::v1::service::project_hook_view(name, cfg, &cv.global_hooks),
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

/// `GET /api/v1/admin/config/diff?from=&to=` — structured hook-surface diff between two retained
/// versions: hook names added / removed / changed (definition differs), plus the global wiring of
/// each side when it changed.
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
    // Name exactly WHICH version is missing — "and/or" made a consumer re-probe both.
    let a = match app.versions.get(from) {
        Some(v) => v,
        None => {
            return err_json(&AdminError::not_found(format!(
                "config version {from} (pruned or never recorded)"
            )))
        }
    };
    let b = match app.versions.get(to) {
        Some(v) => v,
        None => {
            return err_json(&AdminError::not_found(format!(
                "config version {to} (pruned or never recorded)"
            )))
        }
    };
    let mut added: Vec<&String> = b
        .hook_registry
        .keys()
        .filter(|k| !a.hook_registry.contains_key(*k))
        .collect();
    let mut removed: Vec<&String> = a
        .hook_registry
        .keys()
        .filter(|k| !b.hook_registry.contains_key(*k))
        .collect();
    // "Changed" = present in both with a differing definition. HookCfg has no PartialEq (transport
    // objects don't); compare the serialized form — the definition IS its config shape.
    let mut changed: Vec<&String> = a
        .hook_registry
        .iter()
        .filter(|(k, va)| {
            b.hook_registry
                .get(*k)
                .is_some_and(|vb| serde_json::to_value(va).ok() != serde_json::to_value(vb).ok())
        })
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

/// The `POST /api/v1/admin/config/rollback` request body. Optimistic concurrency rides `If-Match` (H3).
#[derive(serde::Deserialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct RollbackReq {
    /// The retained version to restore.
    version: u64,
}

/// `POST /api/v1/admin/config/rollback` — restore a retained version's hook surface. The target is
/// RE-VALIDATED against current reality before the swap (a rollback that no longer resolves is
/// rejected, never blindly applied); the result is a NEW version (history is append-only — rolling
/// back never rewrites it), audited and overlay-persisted.
pub(crate) async fn rollback_config(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let actor = principal.actor_id().to_string();
    let expected = match if_match_version(&headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let req: RollbackReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return err_json(&AdminError::Validation(format!(
                "malformed rollback body: {e}"
            )))
        }
    };
    let resource = format!("config:v{}", req.version);
    let want = req.version;
    let out = config_transaction(&handle, move |txn| {
        let current = txn.app();
        if let Some(e) = stale_if_match(expected, current.config_version) {
            return Err(e);
        }
        let Some(target) = current.versions.get(want) else {
            return Err(AdminError::not_found(format!(
                "config version {want} (pruned or never recorded)"
            )));
        };
        let installed = Arc::new(build_with_registry(
            current,
            target.hook_registry,
            target.global_hooks,
        )?);
        // PERSIST-then-SWAP, fail-closed. A wholesale registry write (both tombstone args `None`);
        // the reconciliation inside `persist` drops any tombstone for a restored name so the
        // rollback survives a restart. Routed through the txn's commit so config.rollback shares the
        // same durability discipline as plugin.rollback (C4 ≡ C5).
        let p = installed.clone();
        Ok(txn.commit(
            installed.clone(),
            move || {
                crate::config::overlay::persist(
                    p.overlay_path.as_deref(),
                    &p.hook_registry,
                    &p.global_hooks,
                    None,
                    None,
                    &p.base_hook_names,
                )
                .map_err(|e| {
                    format!(
                        "config rollback could not be persisted to the overlay: {e}; nothing was \
                         changed (the running engine is unaffected)"
                    )
                })
            },
            installed,
        ))
    })
    .await;
    match out {
        Ok(installed) => {
            audit::AUDIT.record_by("config.rollback", &resource, audit::OUTCOME_APPLIED, &actor);
            installed.versions.record(
                installed.config_version,
                &actor,
                &format!("config.rollback to v{}", req.version),
                &installed.hook_registry,
                &installed.global_hooks,
            );
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
        Err(e) => {
            audit::AUDIT.record_by(
                "config.rollback",
                &resource,
                audit::OUTCOME_REJECTED,
                &actor,
            );
            err_json(&e)
        }
    }
}

/// `PUT /api/v1/admin/admin-auth` — replace the ADMIN auth chain (`admin_auth:`) at runtime. Pairs with
/// `GET /api/v1/admin/admin-auth`, which reports the same `admin_auth` chain (read-after-write coherent).
/// Body:
/// `{"admin_auth": ["module", ...]}`. Guarded three ways:
/// - every name must be a compiled-in admin module (a typo can never silently drop auth);
/// - optimistic concurrency via `If-Match` (409 `version_conflict` when stale — re-read and retry);
/// - **the D4 DRY-RUN GUARD**: the CALLING request's own credentials are re-evaluated against the
///   CANDIDATE chain, and unless they would still hold FULL scope under it the change is rejected
///   with 409 — you cannot lock yourself out with this endpoint. (A chain broken some other way
///   is fix-config + restart: sub-second, health persists.)
///
/// Applied live and atomically (config-version bump, audited); like `config/apply`, the change is
/// live until the next reload/restart returns to disk truth — persist by updating config.yaml.
pub(crate) async fn put_auth(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let expected = match if_match_version(&headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
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
        // Known-module validation (mirrors the boot rule): `admin-tokens` is the built-in; the
        // test-only stand-in exists in test builds only. An unknown name can never silently drop
        // auth.
        for name in &req.admin_auth {
            let known = name == "admin-tokens" || (cfg!(test) && name == "test-scope-module");
            if !known {
                return Err(AdminError::Validation(format!(
                    "admin_auth names unknown module '{name}'; the built-in admin module is \
                     `admin-tokens` (external admin modules are registered at compile time)"
                )));
            }
        }
        if req.admin_auth.is_empty() {
            tracing::warn!(
                "PUT /api/v1/admin/admin-auth applied an EMPTY admin_auth chain — the admin API is \
                 now the open (anonymous, full-authority) dev posture"
            );
        }
        // Candidate app with the new chain, built off the FRESH post-lock snapshot — so a config
        // mutation that landed while this request was parsing cannot be clobbered by a candidate
        // cloned from a pre-lock App.
        let mut next = (**current).clone();
        next.config_version = current.config_version.wrapping_add(1);
        next.admin_chain = req.admin_auth;
        // D4 DRY-RUN GUARD: this very request's carriers, evaluated under the CANDIDATE chain.
        let bearer = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(crate::auth::AuthMiddleware::extract_bearer_token);
        let header_tok = headers
            .get(crate::auth::X_ADMIN_TOKEN)
            .and_then(|v| v.to_str().ok())
            .filter(|t| !t.is_empty())
            .map(str::to_string);
        let survives = crate::auth::dry_run_admin_scope(&next, bearer.as_deref(), header_tok.as_deref())
            .contains(crate::admin::v1::contract::Scope::Full);
        if !survives {
            return Err(AdminError::Conflict(
                "the new admin_auth chain would not grant THIS caller full scope — refusing to lock \
                 you out. Authenticate with a credential the new chain accepts (at full scope) and \
                 retry, or change the chain in config.yaml and restart"
                    .into(),
            ));
        }
        // LIVE-only (documented in the response `note`): the admin chain is not overlay-persisted,
        // so this is a swap with a no-op persist — still the single swap site.
        let installed = Arc::new(next);
        Ok(txn.live_swap(installed.clone(), installed))
    })
    .await;
    let installed = match out {
        Ok(installed) => installed,
        Err(e) => {
            // Audit the rejected attempt (: every mutation attempt leaves a trail — uniform with
            // every other stale-If-Match rejection in this file, and with put_auth's own
            // dry-run-guard rejection).
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
    installed.versions.record(
        installed.config_version,
        principal.actor_id(),
        "auth.admin_chain_put",
        &installed.hook_registry,
        &installed.global_hooks,
    );
    // The response IS the resource (the same {configured, modules} shape GET /admin-auth returns,
    // so a Terraform provider uses the PUT response as post-state) + apply metadata.
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

/// `POST /api/v1/admin/auth/cache/flush` — INSTANT REVOCATION of the credential cache's
/// cached-allow window. Body `{"module": "<name>"}` flushes one module's
/// partition; no/empty body flushes everything. The deny path never needed this (`Reject` is
/// never cached); this closes the Identify window when a directory changes NOW.
pub(crate) async fn flush_credential_cache(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
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
    let flushed = match module.as_deref() {
        Some(m) => app.credential_cache.flush_module(m),
        None => app.credential_cache.flush_all(),
    };
    audit::AUDIT.record_by(
        "auth.cache_flush",
        module.as_deref().unwrap_or("*"),
        audit::OUTCOME_APPLIED,
        principal.actor_id(),
    );
    ok_json(StatusCode::OK, &json!({ "flushed": flushed }))
}

/// `POST /api/v1/admin/config/reload` — re-run the BOOT disk-load pipeline (config.yaml +
/// providers.yaml + env interpolation from the boot-time environment + overlay merge), validate,
/// build a complete new `App` reusing process-lifetime state (client pool, governance DB, version
/// history, rate windows) with every surviving lane's health RESTORED BY STABLE IDENTITY, and
/// atomically swap it in. A NORMAL admin call under the NORMAL admin auth chain — no second
/// credential path exists (D3). Invalid disk config = `invalid_request`, nothing changes. The
/// GitOps primitive: push config, call reload, no restart, no health amnesia.
/// Rebuild a fresh `App` snapshot from DISK TRUTH (base `config.yaml` + `providers.yaml`) merged with
/// the persisted OVERLAY, reusing `current`'s process-lifetime state (governance/store, version log,
/// limiters, health by stable identity). The shared core of `config/reload` AND `plugins/reload`: both
/// re-run the exact fail-closed boot pipeline (which re-scans the plugins dir into a NEW registry and
/// re-opens every hook transport), differing only in what they report. Returns the built `App` (the
/// caller wraps it in `Arc` and swaps) or a human-readable error (any failure changes nothing —
/// fail-closed, the old snapshot keeps serving). Requires disk config paths (ephemeral mode has no
/// disk truth to read).
pub(crate) fn rebuild_app_from_disk(
    current: &Arc<crate::state::App>,
) -> Result<crate::state::App, String> {
    let (Some(config_path), Some(providers_path)) =
        (current.config_path.clone(), current.providers_path.clone())
    else {
        return Err(
            "this busbar was started without config files (ephemeral mode); reload has no \
                    disk truth to read"
                .into(),
        );
    };
    let mut loaded = crate::load_config_from_disk(
        &config_path,
        &providers_path,
        false,
        crate::config::EnvSubst::Strict,
    )?;
    // 1.5.0 full-config coverage: apply the overlay's `root` section (single-value config) AND the
    // `plugin_versions` rollback pins onto the base `DeployCfg` BEFORE resolve, so the limits
    // projection + admin-mTLS boot-guard + the plugin trust FLOORS re-derive over the merged shape —
    // exactly as boot does. The hooks/groups sections merge POST-resolve below.
    if let Some(doc) = loaded.overlay_doc.as_ref() {
        crate::config::overlay::apply_root_to_deploy(&mut loaded.deploy, doc);
    }
    let mut cfg = crate::config::resolve(&loaded.deploy, &loaded.defs)
        .map_err(|errs| format!("config errors:\n  - {}", errs.join("\n  - ")))?;
    // Base hook + group names = the config-defined registry, pre-overlay (the admin API refuses
    // to PUT-replace / DELETE one); then merge the persisted overlay onto the resolved registry.
    let base_hook_names: std::collections::HashSet<String> = cfg.hooks.keys().cloned().collect();
    let base_group_names: std::collections::HashSet<String> = cfg.groups.keys().cloned().collect();
    if let Some(doc) = loaded.overlay_doc {
        crate::config::overlay::merge_into(&mut cfg, doc);
    }
    crate::build_app_from_config(
        cfg,
        loaded.deploy.plugins.clone(),
        loaded.overlay_path,
        base_hook_names,
        base_group_names,
        (Some(config_path), Some(providers_path)),
        Some(current.as_ref()),
    )
}

pub(crate) async fn reload_config(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
) -> Response {
    let actor = principal.actor_id().to_string();
    // The whole rebuild is DISK I/O (config.yaml + providers.yaml + the overlay, then resolve +
    // build). It is queued as a store read so it runs on `spawn_blocking`: before, this ran inline
    // on a Tokio worker with the async mutation lock held, so a slow/large config stalled the
    // reactor for every in-flight request, not just the other mutations.
    let out = config_transaction(&handle, |txn| {
        let snapshot = txn.app().clone();
        Ok(txn.read_store(move || {
            let next = rebuild_app_from_disk(&snapshot).map_err(AdminError::Validation)?;
            // LIVE-only, exactly as before: a reload IS disk truth, so there is nothing to persist.
            let installed = Arc::new(next);
            Ok(Outcome::swap(installed.clone(), installed))
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
            installed.versions.record(
                installed.config_version,
                &actor,
                "config.reload (from disk)",
                &installed.hook_registry,
                &installed.global_hooks,
            );
            with_config_etag(
                ok_json(
                    StatusCode::OK,
                    &json!({ "reloaded": true, "config_version": installed.config_version }),
                ),
                installed.config_version,
            )
        }
        Err(e) => {
            audit::AUDIT.record_by(
                "config.reload",
                "config:disk",
                audit::OUTCOME_REJECTED,
                &actor,
            );
            err_json(&e)
        }
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

/// `POST /api/v1/admin/restart` — apply the restart-scoped settings (`listen`, `admin_listen`,
/// `tls`, `admin_tls`, `admin_insecure`, `store`) by restarting, so an operator never needs a shell.
///
/// This drains through the SAME path a signal takes, so the final budget flush, the state snapshot
/// and the tracing shutdown all happen exactly as they do on SIGTERM. It is deliberately not an
/// in-process rebuild: the durable audit's sequence counters advance only via `fetch_max` so history
/// cannot be rewound, and only a process boundary resets them.
///
/// Responds BEFORE the drain begins. The drain closes the connection carrying this request, so an
/// operator who got no response could not tell a restart from a crash.
pub(crate) async fn restart(
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
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

    let supervised = crate::admin::restart::supervisor_detected();
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

    if !crate::admin::restart::can_restart() {
        audit::AUDIT.record_by("admin.restart", "process", audit::OUTCOME_REJECTED, &actor);
        return err_json_cond(
            &AdminError::Conflict("this process cannot restart itself".into()),
            Cond::NotRestartable,
        );
    }

    // Record the INTENT before draining: this entry is the operator's only durable evidence of who
    // asked and when, and the drain is about to take the connection that would have carried it.
    audit::AUDIT.record_by("admin.restart", "process", audit::OUTCOME_APPLIED, &actor);
    crate::admin::restart::begin_drain();

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
/// Optimistic concurrency rides `If-Match` (H3).
#[derive(serde::Deserialize)]
pub(crate) struct ApplyConfigReq {
    /// The deploy config (operator-owned `config.yaml` shape).
    config: crate::config::DeployCfg,
    /// The provider definitions (`providers.yaml` shape). Optional — empty validates/fails loudly
    /// on dangling references.
    #[serde(default)]
    providers: std::collections::HashMap<String, crate::config::ProviderDef>,
}

/// `POST /api/v1/admin/config/apply` — apply a FULL config carried in the request body, atomically:
/// resolve + validate (an invalid config is a 400 that changes nothing), build a complete new
/// `App` reusing process-lifetime state, carry every surviving lane's health BY STABLE IDENTITY
/// (D1), swap. The body-carried twin of `config/reload` (disk) — Terraform/CI push the config they
/// hold instead of writing files. NOTE: an applied config is LIVE but not written to disk — the
/// next reload/restart returns to disk truth (+overlay); the response says so.
pub(crate) async fn apply_config(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let actor = principal.actor_id().to_string();
    let expected = match if_match_version(&headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let req: ApplyConfigReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return err_json(&AdminError::Validation(format!(
                "malformed config body: {e}"
            )))
        }
    };
    let out = config_transaction(&handle, move |txn| {
        let current = txn.app();
        if let Some(e) = stale_if_match(expected, current.config_version) {
            return Err(e);
        }
        // Resolve + build reads plugin artifacts off disk, so it is queued onto `spawn_blocking`
        // rather than run inline under the async lock.
        let snapshot = current.clone();
        Ok(txn.read_store(move || {
            // The applied body layers UNDER the persisted overlay, exactly as reload/reset/boot/
            // `--validate` do. Apply was the sole rebuild path that skipped this, and it already
            // carried `overlay_path` forward — so it kept WRITING an overlay it refused to read,
            // and the next hook/group mutation persisted the truncated registry over it.
            let overlay_doc = snapshot
                .overlay_path
                .as_deref()
                .and_then(crate::config::overlay::read);
            let ApplyConfigReq {
                config: mut deploy,
                providers,
            } = req;
            if let Some(doc) = overlay_doc.as_ref() {
                crate::config::overlay::apply_root_to_deploy(&mut deploy, doc);
                // Without this an apply re-validates against the BASE floors and silently reverts a
                // live audited plugin rollback until the next restart re-applies the pin.
                crate::config::overlay::apply_plugin_versions_to_deploy(&mut deploy, doc);
            }
            let next = crate::config::resolve(&deploy, &providers)
                .map_err(|errs| format!("config errors:\n  - {}", errs.join("\n  - ")))
                .and_then(|mut cfg| {
                    // Base names are the APPLIED config's own registry, taken pre-merge so an
                    // overlay-only hook is not misread as base-defined (and so undeletable).
                    let base_hook_names: std::collections::HashSet<String> =
                        cfg.hooks.keys().cloned().collect();
                    let base_group_names: std::collections::HashSet<String> =
                        cfg.groups.keys().cloned().collect();
                    if let Some(doc) = overlay_doc {
                        crate::config::overlay::merge_into(&mut cfg, doc);
                    }
                    crate::build_app_from_config(
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
                    )
                })
                .map_err(AdminError::Validation)?;
            // LIVE-only (the response `note` says so): an applied config is not written to disk.
            let installed = Arc::new(next);
            Ok(Outcome::swap(installed.clone(), installed))
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
            installed.versions.record(
                installed.config_version,
                &actor,
                "config.apply (request body)",
                &installed.hook_registry,
                &installed.global_hooks,
            );
            with_config_etag(
                ok_json(
                    StatusCode::OK,
                    &json!({
                        "applied": true,
                        "config_version": installed.config_version,
                        "note": "live until the next reload/restart returns to disk truth; persist \
                                 by updating config.yaml",
                    }),
                ),
                installed.config_version,
            )
        }
        Err(e) => {
            audit::AUDIT.record_by(
                "config.apply",
                "config:body",
                audit::OUTCOME_REJECTED,
                &actor,
            );
            err_json(&e)
        }
    }
}

/// Merge a partial `RootSettings` request onto the current overlay root state: a field the request
/// sets (`Some`) REPLACES; a field it omits (`None`) is PRESERVED from the current overlay. The
/// partial-update semantics of `PUT /config/settings` — "raise the per-request fee" sends only
/// `per_request_fee`, leaving every other override untouched. To CLEAR the whole root section, use
/// `DELETE /overlay/root`.
fn merge_root_settings(
    mut base: crate::config::overlay::RootSettings,
    req: crate::config::overlay::RootSettings,
) -> crate::config::overlay::RootSettings {
    // WHOLE-VALUE sections: a listen address, a cert bundle, a store definition and a rate card are
    // atomic units, and `store.settings` is opaque plugin config busbar must not reinterpret.
    if req.listen.is_some() {
        base.listen = req.listen;
    }
    if req.tls.is_some() {
        base.tls = req.tls;
    }
    if req.admin_listen.is_some() {
        base.admin_listen = req.admin_listen;
    }
    if req.admin_tls.is_some() {
        base.admin_tls = req.admin_tls;
    }
    if req.admin_insecure.is_some() {
        base.admin_insecure = req.admin_insecure;
    }
    if req.rate_card.is_some() {
        base.rate_card = req.rate_card;
    }
    if req.per_request_fee.is_some() {
        base.per_request_fee = req.per_request_fee;
    }
    if req.store.is_some() {
        base.store = req.store;
    }
    // PER-FIELD sections: successive PUTs to different fields of one section must accumulate. A
    // whole-slot swap here would make the second PUT drop the first one's fields from the overlay,
    // which is the same defect as the apply-side revert, one layer down.
    macro_rules! merge_section {
        ($($field:ident),+ $(,)?) => {$(
            base.$field = match (req.$field, base.$field) {
                (Some(new), Some(old)) => Some(new.merge(old)),
                (Some(new), None) => Some(new),
                (None, old) => old,
            };
        )+};
    }
    merge_section!(
        security,
        limits,
        observability,
        advanced,
        metrics,
        health,
        routing
    );
    base
}

/// The RESTART-TO-APPLY fields a `PUT /config/settings` REQUEST touched: the process-level binds
/// (`listen`/`admin_listen` socket, `tls`/`admin_tls` bind, `admin_insecure` boot-guard waiver) are
/// read ONCE in `main()` at process start and bound to sockets that a live `arc-swap` — or even a
/// hot `POST /config/reload` — cannot rebind; the durable `store` backend is REUSED from the prior
/// snapshot on every apply/reload (an in-flight governance ledger cannot migrate backends live), so
/// it too only re-opens on a fresh process. Their new value is DURABLY STORED in the overlay but
/// takes effect on the next RESTART. Every OTHER field (`rate_card`/`per_request_fee`/`security`/
/// `limits`/…) applies live on the swap. Keyed on the REQUEST (only fields the operator just changed
/// are flagged), so a subsequent live-only edit does not re-flag an already-restart-pending bind.
fn reload_to_apply_fields(req: &crate::config::overlay::RootSettings) -> Vec<String> {
    let mut out = Vec::new();
    let mut push = |set: bool, name: &str| {
        if set {
            out.push(name.to_string());
        }
    };
    push(req.listen.is_some(), "listen");
    push(req.tls.is_some(), "tls");
    push(req.admin_listen.is_some(), "admin_listen");
    push(req.admin_tls.is_some(), "admin_tls");
    push(req.admin_insecure.is_some(), "admin_insecure");
    push(req.store.is_some(), "store");
    // Four `limits.*` fields are boot-frozen, via TWO independent mechanisms — flag them
    // individually (dotted, since `limits` is a nested `Option<LimitsPatch>`, not a top-level
    // `Option`) rather than the whole `limits` section, which would also mis-flag the
    // genuinely-live rest of `limits` (e.g. `tls_handshake_timeout_secs`).
    //
    // Mechanism 1 — `main.rs` REUSES the prior `UpstreamClients` across a config apply (the warm
    // connection pools are deliberately kept — rebuilding them on every apply would cold-start
    // every upstream on a rate-card tweak). Its `else` builder arm is the ONLY place these three
    // fields are read, so a PUT that touches them changes the STORED config but not the live
    // `reqwest::Client`.
    //
    // Mechanism 2 — `max_inbound_concurrent` is captured ONCE in `main()` and baked into a
    // `tower::limit::GlobalConcurrencyLimitLayer` on the DATA ROUTER at process start. A config
    // apply swaps only `Arc<App>` (`AppHandle::swap`); the router — and the semaphore's permit
    // count — is never rebuilt, so this field is frozen independently of the `UpstreamClients`
    // reuse above.
    //
    // DRIFT GUARD, same idiom as `config::patch::tests::every_patch_mirrors_every_field_of_its_section`:
    // this is an EXHAUSTIVE destructure of `LimitsPatch` (no `..`), so a field added there — which
    // itself cannot compile without appearing here — must be explicitly named BOOT-FROZEN (pushed
    // below) or GENUINELY LIVE (bound `_`, with a one-line reason) before this crate builds. That is
    // exactly the bug class `max_inbound_concurrent` fell into: a boot-frozen field silently absent
    // from a hand-maintained push list. A new boot-frozen field can no longer go unflagged by
    // omission; the compiler forces a decision.
    if let Some(limits) = req.limits.as_ref() {
        let crate::config::patch::LimitsPatch {
            upstream_request_timeout_secs,
            pool_max_idle_per_host,
            pool_idle_timeout_secs,
            max_inbound_concurrent,
            // GENUINELY LIVE — read per-request/per-connection off the `INSTALLED` snapshot that
            // `InstallGuard::install` refreshes on every apply (see `limits.rs`), or off the swapped
            // `Arc<App>` directly. NOT boot-captured, so a live `PUT` takes effect without a restart.
            request_body_max_bytes: _, // HALF-live: the egress translate cap is live via the
            // `INSTALLED` snapshot, but the inbound `DefaultBodyLimit` 413 threshold is boot-frozen
            // the same way as `max_inbound_concurrent` (`main.rs:3184`, in `apply_common_layers`,
            // reachable only from the boot/test-only router builders). Tracked as a known post-1.5.0
            // gap (documented, not flagged here — see docs/configuration.md) rather than fixed now:
            // fixing the coupling touches the request path and router layer stack, and flagging it
            // dotted would mis-state that the WHOLE field is stored-not-live when three of its four
            // consumers are live.
            max_keys_per_principal: _,
            max_auto_provisioned_groups: _,
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
    // Three `observability.*` fields are boot-frozen — same class as `limits.max_inbound_concurrent`
    // above, different mechanisms:
    //
    // `emit_server_timing` is captured ONCE in `main()` and baked as fixed middleware state into
    // `apply_common_layers` (via `from_fn_with_state`) when the router is built at process start; a
    // config apply never rebuilds the router.
    //
    // `request_log_webhook_url` is captured ONCE in `main()` and seeds a process-global
    // `OnceLock<Arc<String>>` (`observability::configure_webhook`) — `OnceLock::set` silently no-ops
    // on every call after the first, so the webhook target cannot change for the life of the process.
    //
    // `otlp_url` is captured ONCE in `main()` and passed to `observability::init_logging`, a one-shot
    // `tracing_subscriber::registry().try_init()` — a second call is a structural no-op (logs
    // "already initialized" and drops the new exporter).
    //
    // DRIFT GUARD, same idiom as above: an EXHAUSTIVE destructure of `ObservabilityPatch` (no `..`).
    // `max_inflight_webhook_deliveries` is NOT cleanly classifiable as boot-frozen (its `OnceLock`
    // is sized from config on FIRST webhook delivery, whichever moment that is post-boot, not
    // necessarily at boot — so an operator's PUT sometimes does take effect, if no delivery has
    // fired yet, and sometimes doesn't; flagging it unconditionally restart-scoped would be wrong in
    // the cases it IS still live). Left unflagged and undocumented as a known, lower-severity gap
    // rather than guessed at here; see docs/configuration.md.
    if let Some(observability) = req.observability.as_ref() {
        let crate::config::patch::ObservabilityPatch {
            emit_server_timing,
            request_log_webhook_url,
            otlp_url,
            // GENUINELY LIVE — read fresh on every call via `crate::limits::webhook_delivery_timeout_secs()`,
            // backed by the `INSTALLED` snapshot refreshed on every apply. Not cached, not boot-captured.
            webhook_delivery_timeout_secs: _,
            // See the doc comment above: state-dependent, neither cleanly live nor cleanly frozen.
            max_inflight_webhook_deliveries: _,
        } = observability;
        push(
            emit_server_timing.is_some(),
            "observability.emit_server_timing",
        );
        push(
            request_log_webhook_url.is_some(),
            "observability.request_log_webhook_url",
        );
        push(otlp_url.is_some(), "observability.otlp_url");
    }
    out
}

/// Read the current overlay `root` section (the operator's API-set single-value overrides), or an
/// empty `RootSettings` when persistence is disabled / the overlay is absent or carries no root
/// section. Shared by the GET/PUT `/config/settings` handlers.
///
/// A corrupt or too-new overlay renders as an empty `RootSettings` — "the operator has set no
/// overrides" — which is NOT wrong (nothing is mutated on this read), but a reader of the response
/// alone cannot tell "no overrides" from "overrides exist but this read couldn't see them".
/// `overlay::read`'s own warn/error already logs the cause, but genericly — it does not say which
/// endpoint's answer it is misreporting. `endpoint` attributes the misreport to THIS specific read.
fn current_root_settings(
    overlay_path: Option<&std::path::Path>,
    endpoint: &str,
) -> crate::config::overlay::RootSettings {
    let Some(p) = overlay_path else {
        return crate::config::overlay::RootSettings::default();
    };
    match crate::config::overlay::read_state(p) {
        crate::config::overlay::OverlayReadState::Absent => {
            crate::config::overlay::RootSettings::default()
        }
        crate::config::overlay::OverlayReadState::Loaded(doc) => doc.root.unwrap_or_default(),
        crate::config::overlay::OverlayReadState::Unreadable => {
            tracing::warn!(
                endpoint,
                path = %p.display(),
                "{endpoint} read the config overlay while it was unreadable/corrupt; reporting NO \
                 root overrides, which may not reflect what is actually stored on disk"
            );
            crate::config::overlay::RootSettings::default()
        }
        crate::config::overlay::OverlayReadState::VersionTooNew(v) => {
            tracing::warn!(
                endpoint,
                path = %p.display(),
                overlay_version = v,
                "{endpoint} read the config overlay while it was from a NEWER busbar; reporting NO \
                 root overrides, which may not reflect what is actually stored on disk"
            );
            crate::config::overlay::RootSettings::default()
        }
    }
}

/// `GET /api/v1/admin/config/settings` — read the API-set single-value config overlay (the `root`
/// section: `listen`/`tls`/`rate_card`/`store`/`security`/`limits`/…). Reports ONLY the operator's
/// overrides (the fields set via `PUT /config/settings`); base `config.yaml` stands for the rest.
/// Read scope; carries the config-plane `ETag` so a `PUT` can chain `If-Match` off this read. Never a
/// secret in the clear beyond what the operator themselves supplied (TLS refs are secret-references,
/// not raw key bytes).
pub(crate) async fn get_config_settings(State(handle): State<Arc<AppHandle>>) -> Response {
    let current = handle.load();
    let root = current_root_settings(current.overlay_path.as_deref(), "GET /config/settings");
    let settings = serde_json::to_value(&root).unwrap_or_else(|_| json!({}));
    with_config_etag(
        ok_json(
            StatusCode::OK,
            &json!({
                "applied": false,
                "config_version": current.config_version,
                "settings": settings,
            }),
        ),
        current.config_version,
    )
}

/// `PUT /api/v1/admin/config/settings` — SET any single-value config section via the API, durably
/// (1.5.0 full-config coverage). The body is a PARTIAL `RootSettings`: only the fields present are
/// changed (merged onto the current overlay root), the rest preserved — so the admin NEVER edits
/// `config.yaml` and persistence is ALWAYS the busbar-owned overlay. The merged root is applied onto
/// the base `DeployCfg` (re-read from disk), re-resolved + re-validated (an invalid result is a `400`
/// that changes NOTHING), built into a new `App`, and swapped in — so `rate_card`/`per_request_fee`/
/// `security`/`limits`/… go LIVE immediately. The process-level binds
/// (`listen`/`admin_listen`/`tls`/`admin_tls`/`admin_insecure`) and the durable `store` backend are
/// stored + flagged RESTART-TO-APPLY (they cannot hot-swap — sockets/TLS are bound once at process
/// start and the store backend is reused across a hot reload; a RESTART makes them live) — the
/// response's `reload_to_apply` names exactly which. Full scope; `If-Match` optimistic
/// concurrency; audited (every attempt) + versioned; overlay-persisted so it survives a restart.
/// Requires config files on disk (the base to merge onto); an ephemeral busbar has none, so this is a
/// `400 invalid_request` there, exactly like `config/reload`.
/// The one request-scoped control key on the `/config/settings` PUT body. Reserved: it is REMOVED
/// before the typed `RootSettings` parse, so `RootSettings`'s `deny_unknown_fields` still rejects
/// every other unknown key — including a typo of this one, which is the point (a silently-ignored
/// persistence request is the exact defect this field exists to fix; a query param would have hit
/// the in-tree `Query<HashMap<String,String>>` idiom, which drops an unknown key silently).
const PERSIST_FIELD: &str = "persist";

pub(crate) async fn put_config_settings(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let actor = principal.actor_id().to_string();
    let expected = match if_match_version(&headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let mut raw: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return err_json(&AdminError::Validation(format!(
                "malformed config settings body: {e}"
            )))
        }
    };
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
    let req: crate::config::overlay::RootSettings = match serde_json::from_value(raw) {
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
        // The caller EXPLICITLY required durability. `persist_root` on a `None` overlay path is a
        // silent no-op `Ok` (`overlay.rs`), so honouring the request is impossible and reporting
        // success would be the lie this endpoint used to tell. Refuse — the same precondition, and
        // the same reasoning, as `plugins/rollback`.
        if requested_persist && current.overlay_path.is_none() {
            return Err(AdminError::Validation(
                "\"persist\": true was requested, but this busbar has no config overlay \
                 (BUSBAR_CONFIG_OVERLAY is unset), so the change cannot be stored and would not \
                 survive a restart. Set BUSBAR_CONFIG_OVERLAY and retry, or omit \"persist\" to \
                 apply the change in memory only, or use POST /config/apply for a live-only change."
                    .into(),
            ));
        }
        // Everything below reads the overlay file and re-runs the disk-load pipeline, so it is
        // queued onto `spawn_blocking` — under the guard, off the reactor.
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
            // Merge the partial request onto the CURRENT overlay root (partial-update semantics).
            let merged = merge_root_settings(
                current_root_settings(snapshot.overlay_path.as_deref(), "PUT /config/settings"),
                want,
            );
            let merged_for_build = merged.clone();
            // Re-run the disk-load pipeline (base truth), apply the MERGED root onto the DeployCfg
            // BEFORE resolve (so the limits projection + admin-mTLS boot-guard re-derive over it),
            // then merge the CURRENT hooks/groups overlay sections POST-resolve — exactly the reload
            // mechanism, with the root section coming from the just-merged desired state rather than
            // the on-disk overlay.
            let next = crate::load_config_from_disk(
                &config_path,
                &providers_path,
                false,
                crate::config::EnvSubst::Strict,
            )
            .and_then(|mut loaded| {
                merged_for_build.apply_to_deploy(&mut loaded.deploy);
                // Apply the overlay's `plugin_versions` rollback pins onto the DeployCfg BEFORE
                // resolve, exactly as boot/reload/reset/`--validate` do
                // (`overlay::apply_root_to_deploy`). Without this the rebuild re-validates against
                // the BASE floors and re-loads the newer artifact, silently reverting a live audited
                // rollback until the next restart re-applies the persisted pin.
                if let Some(doc) = loaded.overlay_doc.as_ref() {
                    crate::config::overlay::apply_plugin_versions_to_deploy(
                        &mut loaded.deploy,
                        doc,
                    );
                }
                let mut cfg = crate::config::resolve(&loaded.deploy, &loaded.defs)
                    .map_err(|errs| format!("config errors:\n  - {}", errs.join("\n  - ")))?;
                let base_hook_names: std::collections::HashSet<String> =
                    cfg.hooks.keys().cloned().collect();
                let base_group_names: std::collections::HashSet<String> =
                    cfg.groups.keys().cloned().collect();
                if let Some(doc) = loaded.overlay_doc {
                    crate::config::overlay::merge_into(&mut cfg, doc);
                }
                crate::build_app_from_config(
                    cfg,
                    loaded.deploy.plugins.clone(),
                    snapshot.overlay_path.clone(),
                    base_hook_names,
                    base_group_names,
                    (Some(config_path), Some(providers_path)),
                    Some(&snapshot),
                )
            })
            .map_err(AdminError::Validation)?;
            let installed = Arc::new(next);
            // PERSIST-then-SWAP, fail-closed. Persist the merged root section (the sibling
            // hooks/groups sections are preserved verbatim by the read-modify-write).
            let p = installed.clone();
            let to_persist = merged.clone();
            Ok(Outcome::commit(
                installed.clone(),
                move || {
                    crate::config::overlay::persist_root(p.overlay_path.as_deref(), &to_persist)
                        .map_err(|e| {
                            format!(
                                "config settings could not be persisted to the overlay: {e}; \
                                 nothing was changed (the running engine is unaffected)"
                            )
                        })
                },
                (installed, merged),
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
            // `installed.overlay_path` is the SAME path the request started with — the reset/PUT
            // paths preserve it verbatim across a rebuild — so it is the authoritative answer to
            // "was there anywhere to persist this?" for the response we are about to build.
            let (reload_to_apply, note) = if installed.overlay_path.is_none() {
                // No overlay: `persist_root` was a no-op (it warns; see `overlay::persist_root`).
                // `reload_to_apply`'s published meaning is "durably stored but not yet live" — since
                // NOTHING was stored, listing fields there would be the precise lie this fix exists
                // to remove. Its own field names move into the note instead.
                let note = if reload_to_apply.is_empty() {
                    "applied live, IN MEMORY ONLY: this busbar has no config overlay \
                     (BUSBAR_CONFIG_OVERLAY is unset), so nothing was stored and every field here \
                     reverts on the next restart or POST /config/reload. Set BUSBAR_CONFIG_OVERLAY \
                     and re-send with \"persist\": true to store the change durably."
                        .to_string()
                } else {
                    format!(
                        "applied live, IN MEMORY ONLY: this busbar has no config overlay \
                         (BUSBAR_CONFIG_OVERLAY is unset), so nothing was stored and every field \
                         here reverts on the next restart or POST /config/reload. Fields {} cannot \
                         take effect without a restart, and a restart discards them. Set \
                         BUSBAR_CONFIG_OVERLAY and re-send with \"persist\": true to store the \
                         change durably.",
                        reload_to_apply.join(", ")
                    )
                };
                (Vec::new(), note)
            } else if reload_to_apply.is_empty() {
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
            let settings = serde_json::to_value(&merged).unwrap_or_else(|_| json!({}));
            with_config_etag(
                ok_json(
                    StatusCode::OK,
                    &json!({
                        "applied": true,
                        "config_version": installed.config_version,
                        "settings": settings,
                        "reload_to_apply": reload_to_apply,
                        "note": note,
                    }),
                ),
                installed.config_version,
            )
        }
        Err(e) => {
            audit::AUDIT.record_by(
                "config.settings",
                "config:settings",
                audit::OUTCOME_REJECTED,
                &actor,
            );
            err_json(&e)
        }
    }
}

/// The `PATCH /api/v1/admin/hooks/{name}/settings` body. Optimistic concurrency rides `If-Match` (H3).
#[derive(serde::Deserialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct PatchSettingsReq {
    settings: serde_json::Map<String, serde_json::Value>,
}

/// `PATCH /api/v1/admin/hooks/{name}/settings` — push an opaque settings map to the RUNNING hook and
/// COMMIT ON ACK (D2): busbar sends the `configure` message over the hook's transport, waits for
/// the versioned ack (5s deadline), and only then swaps in the registry update (grants untouched —
/// immutability holds by construction) + persists + audits + versions. A nack/timeout/error
/// commits NOTHING (`invalid_request` names the reason). Base-defined hooks are 409 (edit the
/// file). Socket hooks ALSO receive the committed settings as the configure preamble on every
/// future (re)connection, so a restarted hook never runs blind.
pub(crate) async fn patch_hook_settings(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    axum::Extension(scope): axum::Extension<crate::auth::AdminScope>,
    Path(name): Path<String>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let actor = principal.actor_id().to_string();
    let expected = match if_match_version(&headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let req: PatchSettingsReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return err_json(&AdminError::Validation(format!(
                "malformed settings body: {e}"
            )))
        }
    };
    // BOUND the settings map. It is persisted verbatim into the state file AND re-sent to the hook
    // as the configure preamble on EVERY (re)connection, so an unbounded map amplifies both the
    // snapshot size and per-reconnect wire traffic. Cap the serialized size and the key count as
    // defense-in-depth (admin-gated, but a compromised hooks-register token should not be able to
    // bloat the durable state / reconnect path). The caps are far past any real hook's settings.
    if let Err(e) = crate::admin::v1::service::validate_hook_settings_size(&req.settings) {
        return err_json(&e);
    }
    let current = handle.load();
    let resource = format!("hook:{name}");
    let Some(existing) = current.hook_registry.get(&name) else {
        // Audit the 404 like the other rejects here (and DELETE) — a missing audit row on the
        // unknown-name path lets a narrow token probe which hooks exist by response code alone.
        audit::AUDIT.record_by("hook.settings", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&AdminError::not_found(format!("hook `{name}`")));
    };
    // Escalation guard, keyed on the EXISTING hook's grants (PATCH changes settings, not
    // grants). A non-Full (hooks-register) principal may not push settings to a content-seeing
    // (`prompt`/`user`) or `global: true` hook — the same ceiling register_hook/put_hook enforce.
    // Without it a narrow token could retune a `prompt: rw` global gate it can neither create nor
    // replace, reaching a content-seeing hook by the back door.
    if let Some(e) = hooks_register_escalation(scope, existing) {
        audit::AUDIT.record_by("hook.settings", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&e);
    }
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
    // PUSH first, COMMIT on ack — a hook that never acked never sees committed state it doesn't
    // hold. The hook plugin env is captured here; the load()
    // that feeds the actual swap is re-taken AFTER the await, under the mutation lock.
    let hook_env = current.hook_env.clone();
    if let Err(e) = crate::hooks::push_configure(&updated, &name, settings_version, &hook_env).await
    {
        audit::AUDIT.record_by("hook.settings", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&AdminError::Validation(format!(
            "hook did not acknowledge the settings push: {e}"
        )));
    }
    // COMMIT under the mutation lock, guarding the configure-ack await window: if any config-plane
    // mutation landed while we were awaiting the ack, `current` is stale and swapping on it would
    // clobber that change (and reuse its version number). Re-validate the version under the lock;
    // a change means "config moved during your push" → 409, retry (the ack was for a now-stale
    // snapshot). Version unchanged ⇒ `current` is still the live snapshot, so the build is sound.
    // The network push above happened BEFORE the section — and the txn body is SYNCHRONOUS, so it
    // physically cannot be moved inside: "never hold the mutation lock across a network await" is
    // now a type, not a comment.
    let txn_name = name.clone();
    let out = config_transaction(&handle, move |txn| {
        let current = txn.app();
        if current.config_version != pre_push_version {
            return Err(AdminError::Conflict(
                "config changed during the settings push; retry".to_string(),
            ));
        }
        let installed = Arc::new(build_with_hook(current, &txn_name, updated)?);
        // PERSIST-then-SWAP, fail-closed.
        let p = installed.clone();
        Ok(txn.commit(
            installed.clone(),
            move || {
                crate::config::overlay::persist(
                    p.overlay_path.as_deref(),
                    &p.hook_registry,
                    &p.global_hooks,
                    None,
                    Some(&txn_name),
                    &p.base_hook_names,
                )
                .map_err(|e| {
                    format!(
                        "hook settings could not be persisted to the overlay: {e}; nothing was \
                         changed (the running engine is unaffected)"
                    )
                })
            },
            installed,
        ))
    })
    .await;
    match out {
        Ok(installed) => {
            audit::AUDIT.record_by("hook.settings", &resource, audit::OUTCOME_APPLIED, &actor);
            installed.versions.record(
                installed.config_version,
                &actor,
                &format!("hook.settings {resource}"),
                &installed.hook_registry,
                &installed.global_hooks,
            );
            with_config_etag(
                respond(StatusCode::OK, service(&handle).get_hook(&name).await),
                installed.config_version,
            )
        }
        Err(e) => {
            audit::AUDIT.record_by("hook.settings", &resource, audit::OUTCOME_REJECTED, &actor);
            err_json(&e)
        }
    }
}

/// `GET /api/v1/admin/plugins/{name}/schema` — the KIND-NEUTRAL settings-schema surface (name or
/// alias). For a `kind: hook` plugin, delegates to the exact same live `describe`-proxy
/// [`hook_schema`] already does (a loaded hook's own narrowing of its baseline). For `store` /
/// `secret` / `auth`, there is no runtime `describe` — those kinds are `dlopen`ed in-process with
/// no out-of-band preamble a hook's socket transport gets, so asking a live instance would need an
/// already-open, already-configured handle (the chicken-and-egg problem this endpoint exists to
/// avoid). Instead this reads `settings_schema` straight off the plugin's SIGNED, already-verified
/// manifest via `hook_env.registry` — no `dlopen`, no instance, works even for a plugin that has
/// never been loaded. `{"schema": null}` when the resolved manifest carries no schema (an older
/// plugin packed before this field existed) or the plugin/hook can't be resolved at all is instead
/// a `404` (distinct from "resolved but schema-less"). See
/// `busbarAI-private/design/plugin-settings-schema-SPEC.md`.
pub(crate) async fn plugin_schema(
    State(handle): State<Arc<AppHandle>>,
    Path(name): Path<String>,
) -> Response {
    let current = handle.load();
    // Hooks keep the live describe-proxy behavior unchanged when `describe` actually answers
    // (source: "describe") — but a loaded hook that answers `schema: null` is NOT evidence the
    // plugin has no real settings shape (question #3's "arm 3"): the handler falls back to the
    // manifest baseline server-side and reports `source: "manifest"` in that case, so busbar-ui
    // never has to implement the describe/manifest precedence rule itself. `source` reports which
    // path the response ACTUALLY came from, not merely which branch (loaded vs. not) was checked
    // first — a `source: "describe"` with `schema: null` is only correct when describe was asked
    // and truly had nothing to fall back to (no resolvable manifest either).
    if let Some(hook) = current.hook_registry.get(&name) {
        let described =
            crate::hooks::fetch_schema(&name, hook, current.config_version, &current.hook_env)
                .await;
        // The manifest baseline lives under the PLUGIN's name/alias (`hook.plugin`), not the
        // hook's own config-registry name — the two are commonly different strings (a hook is
        // registered as e.g. "fallback-hook" while backed by a plugin aliased "test-hook"), so
        // resolving by `name` here would silently never find the manifest at all. Best-effort:
        // a hook's plugin reference could in principle name something unresolvable — when it
        // does resolve, report the real verdict; when it doesn't, "unverified" is the
        // conservative label (never assert trust the manifest catalog can't back up).
        let loadable = current.hook_env.registry.resolve(&hook.plugin);
        let trust = loadable
            .map(|p| verdict_trust(&p.verdict))
            .unwrap_or("unverified");
        // `kind`/`restart_required_default` (plugin-settings-schema-SPEC.md question #14): the
        // kind-derived restart-scoping default, so busbar-ui does not have to hardcode the
        // kind->default table itself. `None` when the plugin cannot even be resolved to a
        // manifest — same posture `trust: "unverified"` already takes for the identical case.
        let kind = loadable.map(|p| p.manifest.kind.clone());
        let restart_required_default = kind
            .as_deref()
            .map(busbar_plugin_sign::kind_restart_default);
        if described.is_some() {
            return ok_json(
                StatusCode::OK,
                &json!({ "name": name, "schema": described, "schema_error": null, "trust": trust, "source": "describe", "kind": kind, "restart_required_default": restart_required_default }),
            );
        }
        // describe answered null (or the hook never answered at all) — fall back to the manifest
        // baseline, same as a never-loaded plugin, rather than reporting "no schema available"
        // when the manifest actually has one.
        let (schema, schema_error) = loadable.map(manifest_schema).unwrap_or((None, None));
        return ok_json(
            StatusCode::OK,
            &json!({ "name": name, "schema": schema, "schema_error": schema_error, "trust": trust, "source": "manifest", "kind": kind, "restart_required_default": restart_required_default }),
        );
    }
    let Some(loadable) = current.hook_env.registry.resolve(&name) else {
        return err_json(&AdminError::not_found(format!("plugin `{name}`")));
    };
    let trust = verdict_trust(&loadable.verdict);
    let (schema, schema_error) = manifest_schema(loadable);
    ok_json(
        StatusCode::OK,
        &json!({
            "name": name,
            "schema": schema,
            "schema_error": schema_error,
            "trust": trust,
            "source": "manifest",
            "kind": loadable.manifest.kind,
            "restart_required_default": busbar_plugin_sign::kind_restart_default(&loadable.manifest.kind),
        }),
    )
}

/// The manifest-baseline half of `GET /plugins/{name}/schema`: parse the SIGNED
/// `settings_schema` string (kept as text rather than a nested `serde_json::Value` so
/// `canonical_manifest_bytes`'s sorted-key re-serialization can never reorder keys inside it and
/// silently change what was signed) back into real JSON. A manifest that SET the field but whose
/// value fails to parse is a real authoring/packaging bug, distinct from a manifest that never set
/// it at all — `schema: null` alone would collapse the two, so a parse failure instead reports
/// `schema_error` and leaves `schema` null.
fn manifest_schema(
    loadable: &busbar_plugin_loader::LoadablePlugin,
) -> (Option<serde_json::Value>, Option<String>) {
    match loadable.manifest.settings_schema.as_deref() {
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

/// The catalog's own trust vocabulary (`"trusted" | "unverified" | "rejected"` — see
/// `docs/admin-api.md`'s plugin catalog and `service.rs`'s `evaluate()` mapping), applied to a
/// [`busbar_plugin_sign::Verdict`]. A `LoadablePlugin` (what `PluginRegistry::resolve` returns)
/// is never `"rejected"` — a rejected artifact is a `SkippedPlugin`, not a load candidate — but
/// the mapping stays total (not a partial match on `Trusted`/`Allowed` alone) so a future verdict
/// variant is a compile error here, not a silently-missing label.
fn verdict_trust(v: &busbar_plugin_sign::Verdict) -> &'static str {
    match v {
        busbar_plugin_sign::Verdict::Trusted { .. } => "trusted",
        busbar_plugin_sign::Verdict::Allowed { .. } => "unverified",
    }
}

/// `GET /api/v1/admin/hooks/{name}/schema` — proxy the hook's self-described settings JSON Schema
/// (the `describe` wire message). `{"schema": null}` when the hook/transport doesn't answer.
pub(crate) async fn hook_schema(
    State(handle): State<Arc<AppHandle>>,
    Path(name): Path<String>,
) -> Response {
    let current = handle.load();
    let Some(hook) = current.hook_registry.get(&name) else {
        return err_json(&AdminError::not_found(format!("hook `{name}`")));
    };
    let schema =
        crate::hooks::fetch_schema(&name, hook, current.config_version, &current.hook_env).await;
    ok_json(StatusCode::OK, &json!({ "name": name, "schema": schema }))
}

/// `GET /api/v1/admin/hooks/{name}/status` — the hook's OBSERVED state, live-queried over its
/// transport: the settings it is actually running + its version (vs busbar's DESIRED registry
/// copy, with a `drift` verdict) and its self-reported metrics (validated + bounded — a hostile
/// hook cannot flood; names/help are charset-enforced/sanitized so no content can ride a metric).
/// `reported: null` when the hook doesn't answer status (fail-open; the desired view still serves).
/// This is the control-plane read: a dashboard built on busbar sees what each plug is doing.
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
        crate::hooks::fetch_status(&name, hook, desired_version, &current.hook_env).await;
    let as_of = crate::store::now();
    let body = match reported {
        Some(r) => {
            // Drift: the hook runs a different settings version, or a DESIRED key is missing/
            // changed in its observed settings (extra self-managed keys are NOT drift).
            let settings_drift = r
                .settings
                .as_ref()
                .is_some_and(|obs| hook.settings.iter().any(|(k, v)| obs.get(k) != Some(v)));
            let version_drift = r.settings_version.is_some_and(|v| v != desired_version);
            let metrics = r
                .metrics
                .as_ref()
                .map(|m| {
                    crate::hooks::wire::parse_status_metrics(m)
                        .into_iter()
                        .map(|metric| {
                            let mut entry =
                                json!({"name": metric.name, "type": metric.kind, "value": metric.value});
                            // Optional members appear only when the hook sent them (absent ≠ null).
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
                "desired": {"settings": hook.settings, "settings_version": desired_version},
                "reported": {"settings": r.settings, "settings_version": r.settings_version},
                "drift": settings_drift || version_drift,
                "metrics": metrics,
                "as_of": as_of,
                "source": "live",
            })
        }
        None => json!({
            "name": name,
            "desired": {"settings": hook.settings, "settings_version": desired_version},
            "reported": serde_json::Value::Null,
            "drift": serde_json::Value::Null,
            // `metrics` is INVARIANTLY an array — `[]` here (not `{}`) so a strict consumer decoding
            // it as an array never has to special-case the no-status branch (busbar-ui review R5).
            "metrics": [],
            "as_of": as_of,
            "source": "live",
            "note": "hook did not answer status (unsupported or unreachable)",
        }),
    };
    ok_json(StatusCode::OK, &body)
}

/// The stable v1 GET endpoints (RELATIVE path, summary), the single source for both the
/// router-mount drift test and the OpenAPI `paths`. Paths are relative to `contract::ADMIN_PREFIX`
/// (no absolute path is hand-written anywhere — the `ap` helper derives them). Templated/POST
/// routes are documented separately in `openapi_doc`. Adding a GET endpoint means adding it here so
/// the doc + the drift guard both see it.
// Consumed by `openapi_doc()` (feature `openapi-schema`) and the router-resolve drift tests (which
// need the default auth features to build a router). In a `--no-default-features` build neither is
// compiled, so the const is genuinely unused there — allow it dead in every config (a plain `allow`
// never warns when it IS used, unlike `expect`).
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
        "Group registry — the limit tree (parent chain, limits, child_default budget template)",
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
        "Metering: current UTC-day bucket — {window, as_of, currency, total, by_model, by_key}, raw token split + derived spend_micros",
    ),
    (
        "/config",
        "Effective running config snapshot (redacted)",
    ),
    (
        "/audit",
        "Admin audit log — every mutation with its outcome (newest first). Page: ?limit=, ?cursor=; returns {items, next_cursor}",
    ),
    (
        "/config/versions",
        "Config version history (newest first; id/ts/principal/summary). Page: ?limit=, ?cursor=; returns {items, next_cursor}",
    ),
    ("/openapi.json", "This OpenAPI 3.1 document"),
];

/// Build the OpenAPI 3.1 document describing the v1 JSON-REST surface. Paths + methods + the stable
/// error envelope are the machine-readable contract (tooling generates clients + branches on the error
/// `code`). EVERY operation's success response (200/201) carries a typed body schema — a
/// `$ref` into `components.schemas`, derived by schemars from the real Rust response VIEW types (see
/// `contract` + `contract::schema`) so the schema always matches what serde actually serializes.
///
/// CI-ONLY (`#[cfg(feature = "openapi-schema")]`): schemars is not compiled into the shipped binary.
/// The generated doc is committed as `json/openapi.json` and served verbatim by the live handler
/// (`openapi()` via `include_str!`); the golden/drift test keeps the committed file byte-equal to
/// this function's output, so the static file can never drift from the code.
#[cfg(feature = "openapi-schema")]
// Invoked from the openapi tests + the CI artifact/drift jobs (all test targets); a non-test
// feature-on bin build has no caller, so allow it dead there.
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
                    "responses": {
                        "200": {"description": "OK"},
                    }
                }
            }),
        );
    }
    // Runtime hook registration: POST on the /hooks collection (merged onto its GET entry above).
    if let Some(obj) = paths
        .get_mut(&ap(PATH_HOOKS))
        .and_then(|p| p.as_object_mut())
    {
        obj.insert(
            "post".to_string(),
            json!({
                "summary": "Register (or replace) a hook at runtime — live immediately",
                "security": [{"adminToken": []}],
                "responses": {
                    "201": {"description": "Registered — the name is NEW (body is the hook definition)"},
                    "200": {"description": "Replaced — the name existed (same-grant re-register; body is the hook definition)"},
                }
            }),
        );
    }
    // Runtime group creation: POST on the /groups collection (merged onto its GET entry above).
    if let Some(obj) = paths
        .get_mut(&ap(PATH_GROUPS))
        .and_then(|p| p.as_object_mut())
    {
        obj.insert(
            "post".to_string(),
            json!({
                "summary": "Create (or replace) a group at runtime — live immediately (upsert)",
                "security": [{"adminToken": []}],
                "responses": {
                    "201": {"description": "Created — the name is NEW (body is the group definition)"},
                    "200": {"description": "Replaced — the name existed (body is the group definition)"},
                }
            }),
        );
    }
    // Plugin INSTALL: POST on the /plugins collection (merged onto its GET entry above).
    if let Some(obj) = paths
        .get_mut(&ap("/plugins"))
        .and_then(|p| p.as_object_mut())
    {
        obj.insert(
            "post".to_string(),
            json!({
                "summary": "Install a dynamic-library store plugin: upload the library (base64) + optional signed manifest; the engine RE-VERIFIES against the running trust posture, validates the store ABI, and writes it atomically into the plugins directory. Takes effect on the next store (re)load",
                "security": [{"adminToken": []}],
                "responses": {
                    "201": {"description": "Installed — `{file, name, interface_version, trust, version?, publisher?, note}`"},
                }
            }),
        );
    }
    // Plugin RELOAD + REMOVE (templated).
    paths.insert(
        ap("/plugins/reload"),
        json!({
            "post": {
                "summary": "Re-scan the plugins directory and report the reconciled dynamic-library inventory (the sibling of config/reload). A store change takes effect on the next store (re)load",
                "security": [{"adminToken": []}],
                "responses": {
                    "200": {"description": "`{plugins, note}` — the current dynamic-library inventory"}
                }
            }
        }),
    );
    paths.insert(
        ap("/plugins/rollback"),
        json!({
            "post": {
                "summary": "EXPLICIT, authenticated, audited rollback of a plugin to a PRIOR version (1.5.0). Validates the target artifact (structure + trust) with the anti-downgrade floor lowered to EXACTLY the target's own version — a lower or untrusted artifact still fails (a rollback authenticates the OPERATOR, never the bytes). Persists the version pin to the overlay (survives restart) and hot-swaps via the same rebuild-and-swap path as plugins/reload",
                "security": [{"adminToken": []}],
                "responses": {
                    "200": {"description": "`{plugin, version, config_version, plugins}` — rolled back and hot-swapped"},
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
                "responses": {
                    "204": {"description": "Removed"},
                }
            }
        }),
    );
    paths.insert(
        ap("/plugins/{file}/schema"),
        json!({
            "get": {
                "summary": "The plugin's self-described settings JSON Schema, read from the SIGNED manifest's `settings_schema` field — works for every plugin kind (store/secret/auth/hook), not just hooks. `hook` plugins keep the live describe-proxy behavior when describe answers (source: describe); a loaded hook whose describe answers null falls back server-side to the manifest baseline (source: manifest)",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "file", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                "responses": {
                    "200": {"description": "`{name, schema, schema_error, trust, source}` — `schema` null (with `schema_error` null) when the manifest carries none; a manifest that SET `settings_schema` but failed to parse instead reports `schema_error` (never collapsed into the same null as \"no schema\"). `trust` is `trusted|unverified|rejected` (the catalog vocabulary). `source` is `describe` (a loaded hook answered live) or `manifest`"},
                }
            }
        }),
    );
    // Templated + non-GET routes.
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
                "responses": {
                    "200": {"description": "OK"},
                }
            },
            "put": {
                "summary": "Replace an overlay hook definition — live immediately (grants immutable)",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                "responses": {
                    "200": {"description": "The replaced hook"},
                }
            },
            "delete": {
                "summary": "Remove a hook at runtime — live immediately",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                "responses": {
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
                "responses": {
                    "200": {"description": "OK"},
                }
            },
            "put": {
                "summary": "Replace an overlay group definition — live immediately (limits rebuilt)",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                "responses": {
                    "200": {"description": "The replaced group"},
                }
            },
            "patch": {
                "summary": "Partial update — change only the fields present (e.g. raise a budget, freeze a group)",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                "responses": {
                    "200": {"description": "The updated group"},
                }
            },
            "delete": {
                "summary": "Remove an overlay group at runtime — live immediately",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                "responses": {
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
                "responses": {
                    "200": {"description": "OK"},
                }
            }
        }),
    );
    paths.insert(
        ap("/groups/{name}/usage"),
        json!({
            "get": {
                "summary": "The group's derived current-window usage per (window, pool) enforcement bucket vs its caps — the self-service dashboard read (spend derives from the token ledger x the CURRENT rate card at read time)",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                "responses": {
                    "200": {"description": "OK"},
                }
            }
        }),
    );
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
                "responses": {
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
                "responses": {
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
                "responses": {
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
                "responses": {
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
                "responses": {
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
                "responses": {
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
                "responses": {
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
                "responses": {
                    "200": {"description": "`{reloaded, config_version}`"},
                }
            }
        }),
    );
    paths.insert(
        ap("/restart"),
        json!({
            "post": {
                "summary": "Restart busbar to apply the restart-scoped settings (listen, admin_listen, tls, admin_tls, admin_insecure, store). Drains first; the supervisor brings it back",
                "security": [{"adminToken": []}],
                "responses": {
                    "202": {"description": "`{restarting, supervisor_detected, note}` — draining; in-flight requests finish first"},
                }
            }
        }),
    );
    paths.insert(
        ap("/config/settings"),
        json!({
            "get": {
                "summary": "Read the API-set single-value config overlay (root section: listen/tls/rate_card/store/security/limits/…) — only the operator's overrides; base config.yaml stands for the rest",
                "security": [{"adminToken": []}],
                "responses": {
                    "200": {"description": "`{applied:false, config_version, settings}` (settings = the current root overrides)"},
                }
            },
            "put": {
                "summary": "SET any single-value config section durably (1.5.0 full-config coverage): partial RootSettings merged onto the overlay, re-resolved + validated, swapped in. rate_card/per_request_fee/security/limits/… go live; listen/tls/admin_listen/admin_tls/admin_insecure/store are stored + flagged restart-to-apply (bound once at start / store reused across a hot reload). NEVER writes config.yaml",
                "security": [{"adminToken": []}],
                "responses": {
                    "200": {"description": "`{applied:true, config_version, settings, reload_to_apply, note}`"},
                }
            }
        }),
    );
    if let Some(auth_path) = paths.get_mut(&ap(PATH_ADMIN_AUTH)) {
        auth_path["put"] = json!({
            "summary": "Replace the admin_auth chain at runtime — dry-run guarded (the calling credentials must hold full scope under the NEW chain, else 409). Live until the next reload/restart",
            "security": [{"adminToken": []}],
            "responses": {
                "200": {"description": "The resource + apply metadata: `{configured, modules, applied, config_version, note}`"},
            }
        });
    }
    paths.insert(
        ap("/auth/cache/flush"),
        json!({
            "post": {
                "summary": "Flush the credential cache — one module's partition (`{module}`) or everything (empty body). Instant revocation of the cached-allow window",
                "security": [{"adminToken": []}],
                "responses": {
                    "200": {"description": "`{flushed}` — entries dropped"},
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
                "responses": {
                    "200": {"description": "`{restored_version, config_version}`"},
                }
            }
        }),
    );
    paths.insert(
        ap("/overlay/{section}"),
        json!({
            "delete": {
                "summary": "DISCARD a section's overlay mutations and revert it to base config.yaml (section ∈ groups|hooks|root|plugin_versions). Per-section reset — the OTHER sections' overlay survives. A NEW config version; an already-empty section is an idempotent no-op (changed:false)",
                "security": [{"adminToken": []}],
                "parameters": [{"name": "section", "in": "path", "required": true, "schema": {"type": "string", "enum": ["groups", "hooks", "root", "plugin_versions"]}}],
                "responses": {
                    "200": {"description": "`{reset, config_version, changed}` — changed:false when the section had no overlay state"},
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
                "responses": {
                    "200": {"description": "Verdict `{ok, errors}` (even for an invalid config)"},
                }
            }
        }),
    );

    // Virtual-key management (mounted in the v1 router like everything else; handlers live in
    // crate::admin while they migrate into the service). The secret is shown ONCE at create/rotate
    // and never read back.
    paths.insert(
        ap("/keys"),
        json!({
            "get": {
                "summary": "List virtual keys (metadata only; never secrets). Filters: ?enabled=, ?prefix=, ?group= (keys bound to a group — a `user:<sub>` leaf's keys are one person's). Paginate: ?limit=, ?cursor= (opaque)",
                "security": [{"adminToken": []}],
                "responses": {
                    "200": {"description": "`{items, next_cursor}` — the cursor page envelope (next_cursor null at end)"},
                }
            },
            "post": {
                "summary": "Mint a virtual key. The secret is returned EXACTLY once. Honors an `Idempotency-Key` header (per-principal ~10min replay)",
                "security": [{"adminToken": []}],
                "responses": {
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
                "responses": {
                    "200": {"description": "Key metadata (+ `ETag` header)"},
                }
            },
            "patch": {
                "summary": "Enable/disable a key or rebind its group. Optional `If-Match` for optimistic concurrency",
                "security": [{"adminToken": []}],
                "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}],
                "responses": {
                    "200": {"description": "Updated metadata"},
                }
            },
            "delete": {
                "summary": "Revoke a key — it stops resolving immediately. Optional `If-Match` (the key's ETag)",
                "security": [{"adminToken": []}],
                "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}],
                "responses": {
                    "204": {"description": "Revoked — No Content"},
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
                "responses": {
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
                "responses": {
                    "200": {"description": "Rotated (body includes the once-shown new secret; an Idempotency-Key retry replays it verbatim)"},
                }
            }
        }),
    );
    paths.insert(
        ap("/keys/{id}/revoke"),
        json!({
            "post": {
                "summary": "REVOKE a signed-token key: denylist it durably WITHOUT deleting the binding (GET /keys/{id} still shows the record; verify now fails). Idempotent — revoking an already-revoked key is 200. DELETE /keys/{id} is the revoke-AND-forget variant (1.5.0)",
                "security": [{"adminToken": []}],
                "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}],
                "responses": {
                    "200": {"description": "`{revoked}` — the id, now denylisted"},
                }
            }
        }),
    );
    paths.insert(
        ap("/signing-key/rotate"),
        json!({
            "post": {
                "summary": "ROTATE the busbar key-signing key (S2). Rotation is REVOKE-ALL by design: a new signing key means every token minted under the OLD key stops verifying, so every outstanding key must be re-minted. 1.5.0 is single-key, so this reports the intent + current kid; the actual swap is an operator action (replace auth.signing_key / the persisted key file and restart/reload every node in lockstep) (1.5.0)",
                "security": [{"adminToken": []}],
                "responses": {
                    "200": {"description": "`{current_kid, revoke_all, message}` — the rotation intent + revoke-all warning"},
                }
            }
        }),
    );

    use crate::admin::v1::contract::taxonomy;

    // ── THE 4xx RESPONSE SET IS A PROJECTION, NOT PROSE (design D) ────────────────────────────
    // Every body-specific 400 / 403-escalation / 404 / 409 is ENUMERATED from the ONE declaration
    // in `contract::taxonomy::declared_errors` — the blocks above carry only their 2xx entries,
    // their summary and their parameters. Nothing error-shaped is hand-typed beside an endpoint any
    // more, so an endpoint cannot omit a status it emits (the class-level drift test in
    // `tests/tests.rs` fails the build) and cannot document one it doesn't. Descriptions come from
    // `Cond::phrase()`, so the same condition reads identically on every endpoint that declares it.
    // This runs BEFORE the algorithmic pass below so a declared `403` (the hook escalation,
    // whose phrasing is more specific) wins over the generic under-scope 403's `or_insert`.
    for (path, methods) in paths.iter_mut() {
        let Some(obj) = methods.as_object_mut() else {
            continue;
        };
        let rel = path
            .strip_prefix(crate::admin::v1::contract::ADMIN_PREFIX)
            .unwrap_or(path)
            .to_string();
        for (method, op) in obj.iter_mut() {
            let Some(tag) = taxonomy::MethodTag::from_op_key(method) else {
                continue; // an `x-*` path-item extension, not an operation
            };
            let Some(responses) = op.get_mut("responses").and_then(|r| r.as_object_mut()) else {
                continue;
            };
            for (status, description) in taxonomy::declared_responses(tag, &rel) {
                responses.insert(status, json!({ "description": description }));
            }
        }
    }

    // Stamp EVERY path+method with its required admin scope (`x-busbar-required-scope`) from the
    // SAME `required_scope` matrix the middleware enforces — the machine-readable authorization
    // matrix, drift-proof by construction because both readers share one function. The
    // matrix keys on the literal path shape; templated segments (`{name}`) sit inside the same
    // prefix the matcher tests, so the annotation is exact for every route documented here.
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
                    let scope = crate::admin::v1::contract::required_scope(&m, path);
                    op.insert("x-busbar-required-scope".to_string(), json!(scope.as_str()));
                    // Both accepted credential carriers, on every op.
                    op.insert(
                        "security".to_string(),
                        json!([{"adminToken": []}, {"bearerAuth": []}]),
                    );
                    // The always-possible responses, stamped algorithmically so no hand-written
                    // entry can forget them: 401 (bad/missing credential), 403
                    // (authenticated but under-scoped), 500 (any handler can fail internally), and
                    // 429 on every mutation (the per-principal mutation budget). These are the
                    // UNIVERSAL half of the taxonomy — `err_kind_of` classifies exactly these
                    // `AdminError` variants as algorithmic, so they are not declarable per endpoint
                    // (listing them per-op would be noise AND a new drift vector).
                    if let Some(responses) = op.get_mut("responses").and_then(|r| r.as_object_mut())
                    {
                        responses.entry("401").or_insert(json!(
                            {"description": "Missing/invalid admin credential (error code `unauthorized`)"}
                        ));
                        responses.entry("403").or_insert(json!({"description": format!(
                            "Authenticated but under-scoped: requires `{}` (error code `forbidden`)",
                            scope.as_str()
                        )}));
                        if m != axum::http::Method::GET && m != axum::http::Method::HEAD {
                            responses.entry("429").or_insert(json!(
                                {"description": "Per-principal mutation budget exhausted (error code `rate_limited`; `Retry-After` header)"}
                            ));
                        }
                        responses.entry("500").or_insert(json!(
                            {"description": "Internal failure (error code `internal`); the detail is logged server-side, never returned"}
                        ));
                    }
                }
            }
        }
    }

    // Machine-readable QUERY PARAMETERS for the list/filter GETs — previously prose-
    // only, so generated clients had no query surface. Stamped from one table.
    /// (name, description, required) — one documented query parameter.
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
            &[(
                "window",
                "A PAST UTC-day bucket start epoch (default: current bucket). The response is always ONE bucket; spend_micros is a read-time estimate — bill from the raw token split, never store spend_micros as a ledger charge",
                false,
            )],
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
                    json!({"name": name, "in": "query", "required": required,
                           "schema": {"type": "string"}, "description": desc})
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

    // Stamp the `If-Match` header parameter onto every version-guarded mutation (H3: the ONE
    // optimistic-concurrency mechanism across the surface). Driven by an explicit op list — NOT
    // "every mutation" — because the unguarded ops (validate: stateless dry-run; reload: returns to
    // disk truth unconditionally; cache/flush, key create/rotate: no versioned resource) must not
    // advertise a guard they don't enforce. Keys PATCH/DELETE guard on the KEY's own ETag; the
    // config-plane ops guard on the config-version ETag their reads emit.
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
    for (path, method) in IF_MATCH_GUARDED {
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

    // ── TYPED RESPONSE SCHEMAS ────────────────────────────────────────────────────────────────
    // Attach a `$ref` body schema to every operation's success response, and collect the referenced
    // component schemas from schemars — derived from the real Rust response VIEW types, so the doc's
    // response shapes always match what serde serializes. Driven by a table keyed on
    // (relative-path, method, status); `attach` resolves the type to a `#/components/schemas/<T>`
    // ref, records it in `gen`, and writes the `content` block.
    use crate::admin::v1::contract::schema as sview;
    let mut gen = schemars::generate::SchemaSettings::draft2020_12()
        .with(|s| {
            // OpenAPI 3.1 keeps component schemas under `#/components/schemas`; strip the per-schema
            // `$schema` meta (OpenAPI carries one document-level dialect, not one per component).
            s.definitions_path = "/components/schemas".into();
            s.meta_schema = None;
        })
        // The doc describes RESPONSES (what busbar SERIALIZES), so generate the serialize-contract
        // schema — this is what makes `skip_serializing_if` fields non-required, matching the wire.
        .for_serialize()
        .into_generator();

    // A SECOND generator for REQUEST bodies. Responses describe what busbar serializes, requests
    // what it accepts, and the two differ: `.for_deserialize()` is what makes a `#[serde(default)]`
    // field OPTIONAL. Generating request bodies off the serialize generator would mark every
    // defaulted field required — wrong in the opposite direction, and worse than saying nothing.
    let mut req_gen = schemars::generate::SchemaSettings::draft2020_12()
        .with(|s| {
            s.definitions_path = "/components/schemas".into();
            s.meta_schema = None;
        })
        .for_deserialize()
        .into_generator();

    /// Write `content: { application/json: { schema: <schema> } }` onto one operation's `<status>`
    /// response object (creating the response entry if the op didn't already document that status).
    fn set_content(op: &mut serde_json::Value, status: &str, schema: serde_json::Value) {
        let Some(responses) = op.get_mut("responses").and_then(|r| r.as_object_mut()) else {
            return;
        };
        let entry = responses
            .entry(status.to_string())
            .or_insert_with(|| json!({"description": "OK"}));
        if let Some(obj) = entry.as_object_mut() {
            obj.insert(
                "content".to_string(),
                json!({"application/json": {"schema": schema}}),
            );
        }
    }

    // Resolve an operation object (by relative path + method) for schema attachment.
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
    /// without re-auditing every other call site's handler (an out-of-scope pass — see the class-13/14
    /// design's open question).
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

    // Attach the `$ref` schema of type `$t` to `<rel>.<method>.responses.<status>`.
    macro_rules! typed {
        ($rel:expr, $method:literal, $status:literal, $t:ty) => {{
            let schema = gen.subschema_for::<$t>();
            let schema = serde_json::to_value(schema).unwrap_or_else(|_| json!({}));
            if let Some(op) = op!($rel, $method) {
                set_content(op, $status, schema);
            }
        }};
    }

    use crate::admin::v1::contract::{
        AdminAuthView, AuthView, ConfigValidateView, EffectiveConfigView, GroupView,
        HookHealthView, HookView, InfoView, ModelView, Page, PluginInstallView, PluginReloadView,
        PluginView, PoolDetailView, PoolView, ProviderView, UsageView,
    };

    // Info & topology.
    typed!("/info", "get", "200", InfoView);
    typed!("/pools", "get", "200", Page<PoolView>);
    typed!("/pools/{name}", "get", "200", PoolDetailView);
    typed!("/models", "get", "200", Page<ModelView>);
    typed!("/providers", "get", "200", Page<ProviderView>);
    // Hooks.
    typed!(PATH_HOOKS, "get", "200", Page<HookView>);
    typed!(PATH_HOOKS, "post", "201", HookView);
    typed!(PATH_HOOKS, "post", "200", HookView);
    typed!("/hooks/{name}", "get", "200", HookView);
    typed!("/hooks/{name}", "put", "200", HookView);
    typed!("/hooks/{name}/settings", "patch", "200", HookView);
    typed!("/hooks/{name}/health", "get", "200", HookHealthView);
    typed!("/hooks/{name}/schema", "get", "200", sview::HookSchemaView);
    typed!("/hooks/{name}/status", "get", "200", sview::HookStatusView);
    // Groups (the limit tree).
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
        crate::admin::v1::contract::GroupUsageView
    );
    // Auth & credentials.
    typed!("/auth", "get", "200", AuthView);
    typed!(PATH_ADMIN_AUTH, "get", "200", AdminAuthView);
    typed!(PATH_ADMIN_AUTH, "put", "200", sview::AdminAuthPutView);
    typed!("/auth/cache/flush", "post", "200", sview::CacheFlushView);
    // Plugins, usage, config.
    typed!("/plugins", "get", "200", Page<PluginView>);
    typed!("/plugins", "post", "201", PluginInstallView);
    typed!("/plugins/reload", "post", "200", PluginReloadView);
    typed!(
        "/plugins/{file}/schema",
        "get",
        "200",
        sview::PluginSchemaView
    );
    typed!(
        "/plugins/rollback",
        "post",
        "200",
        crate::admin::v1::contract::PluginRollbackView
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
    // Virtual keys.
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

    // The discovery endpoint returns THIS very OpenAPI 3.1 document — an arbitrary object. There is
    // no named struct for "an OpenAPI document"; an inline permissive object schema is the honest
    // description (fully modeling the OpenAPI meta-schema is out of scope + circular).
    if let Some(op) = op!("/openapi.json", "get") {
        set_content(
            op,
            "200",
            json!({"type": "object", "description": "An OpenAPI 3.1 document (this document's shape)"}),
        );
    }

    // The stable ERROR envelope. Reference it as the body of every documented ERROR status
    // (4xx/5xx) so a generated client decodes errors with the same typed model it decodes successes.
    // The `Error` component itself is the hand-written schema below (code enum + message), so the
    // schemars `ErrorBody` is NOT registered — we point error responses at `#/components/schemas/Error`.
    let error_ref = json!({"$ref": "#/components/schemas/Error"});
    for methods in paths.values_mut() {
        let Some(methods) = methods.as_object_mut() else {
            continue;
        };
        for (method, op) in methods.iter_mut() {
            if method.starts_with("x-") {
                continue;
            }
            let Some(responses) = op.get_mut("responses").and_then(|r| r.as_object_mut()) else {
                continue;
            };
            for (status, resp) in responses.iter_mut() {
                // 2xx bodies are the typed views attached above; 204 has no body; error statuses
                // (4xx/5xx) all speak the one envelope.
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

    // ── REQUEST BODIES ────────────────────────────────────────────────────────────────────────────
    // Every mutating operation either declares a body here or is listed as bodyless in the drift
    // test, which fails CI on any that is neither.

    // Derived from the request struct, so the schema cannot drift from what the handler accepts.
    body!(PATH_ADMIN_AUTH, "put", PutAuthBody);
    body!("/auth/cache/flush", "post", FlushCacheReq);
    body!("/plugins", "post", InstallPluginReq);
    body!("/plugins/rollback", "post", PluginRollbackReq);
    body!("/config/rollback", "post", RollbackReq);
    body_optional!("/restart", "post", RestartReq);
    body!("/hooks/{name}/settings", "patch", PatchSettingsReq);
    body!("/keys", "post", crate::admin::CreateKeyReq);
    body!("/keys/{id}", "patch", crate::admin::UpdateKeyReq);

    // The config-carrying bodies are declared by HAND, deliberately.
    //
    // These embed the config tree, where several types (`LimitCfg`, `HookRefEntry`, `PoolCfg`,
    // `AuthChainEntry`, `SecretRef`, …) have hand-written `Deserialize` impls whose accepted wire
    // shape has nothing to do with their field layout — `LimitCfg` parses a map with a DYNAMIC
    // metric key, `HookRefEntry` accepts either a bare string or a map. A derived schema would
    // publish the internal representation as though it were the wire contract: a confident lie,
    // with no compiler-enforced link back to the visitor that would catch the drift.
    //
    // So these say what is TRUE and no more: the body carries a config document, and the config
    // reference is its specification. Honest and stable beats precise and wrong.
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
            "The settings sections to replace, keyed by section name. The optional top-level \
             boolean `persist` asserts the change MUST be stored in the config overlay: with \
             `persist: true` a busbar that has no overlay refuses with `400 invalid_request` \
             instead of applying the change in memory only. Omitted or `false` means the change is \
             applied and stored where storage is available, and applied in memory only where it is \
             not (the response `note` says which); `false` never suppresses storage. Every other \
             top-level key must be a known settings section — an unknown key is a 400."
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

    // The generated component schemas (every `$ref`'d view type), merged with the hand-written
    // `Error` schema. The `Error` schema stays hand-written so its `code` enum is the frozen
    // AdminError taxonomy verbatim (the drift test `openapi_error_enum_matches_admin_error_codes`
    // locks it); schemars fills in every other referenced view.
    let mut schemas = gen.definitions().clone();
    // Request-body component schemas live in the same `components.schemas` map. The two generators
    // cannot collide today (no type is both a request struct and a response view) and the drift
    // test asserts every declared body resolves, which would catch it if one ever were.
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
                                     "rate_limited", "internal"]},
                        "message": {"type": "string"}
                    },
                    "required": ["code", "message"]
                }
            },
            "required": ["error"]
        }),
    );

    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Busbar Admin API",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "The frozen, additive-only /api/v1/admin surface. Errors use the stable \
                            envelope {\"error\":{\"code\",\"message\"}}; tooling branches on `code`."
        },
        "components": {
            "securitySchemes": {
                "adminToken": {"type": "apiKey", "in": "header", "name": crate::auth::X_ADMIN_TOKEN},
                "bearerAuth": {"type": "http", "scheme": "bearer",
                               "description": "The same operator credential via Authorization: Bearer"}
            },
            "schemas": schemas
        },
        "paths": paths
    })
}

/// The committed, typed OpenAPI 3.1 document — generated from `openapi_doc()` (feature `openapi-schema`)
/// and checked into the tree. The live handler serves THIS static string: schemars is a CI-only
/// dependency, so the release binary cannot regenerate the doc at runtime, and it never needs to —
/// the golden/drift test keeps this file byte-equal to `openapi_doc()`'s output, so serving the
/// static copy is identical to serving a freshly-generated one, minus the schemars code + cost.
pub(crate) const OPENAPI_JSON: &str = include_str!("openapi.json");

/// `GET /api/v1/admin/openapi.json` — the OpenAPI 3.1 schema of the v1 surface (the discovery contract).
/// Serves the committed, typed [`OPENAPI_JSON`] verbatim as `application/json` (no runtime generation —
/// see the constant's doc). Same status/content-type/body shape the generated path always produced.
pub(crate) async fn openapi() -> Response {
    (
        StatusCode::OK,
        [(CONTENT_TYPE, crate::proxy::APPLICATION_JSON)],
        OPENAPI_JSON,
    )
        .into_response()
}

/// The `POST /api/v1/admin/config/validate` request body: a full proposed config — the `config.yaml`
/// deploy block + the `providers.yaml` definitions — mirroring the two files busbar loads at boot.
#[derive(serde::Deserialize)]
pub(crate) struct ValidateConfigReq {
    /// The deploy config (operator-owned `config.yaml` shape).
    config: crate::config::DeployCfg,
    /// The provider definitions (`providers.yaml` shape), keyed by provider name. Optional: a config
    /// that references no providers.yaml entries validates against an empty def set (and reports the
    /// dangling references as errors).
    #[serde(default)]
    providers: std::collections::HashMap<String, crate::config::ProviderDef>,
}

/// `POST /api/v1/admin/config/validate` — dry-run validate a proposed config. A malformed body is an
/// `invalid_request`; a well-formed body always returns 200 with the `{ok, errors}` verdict.
pub(crate) async fn validate_config(
    State(handle): State<Arc<AppHandle>>,
    body: axum::body::Bytes,
) -> Response {
    let req: ValidateConfigReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return err_json(&AdminError::Validation(format!(
                "malformed config body: {e}"
            )))
        }
    };
    respond(
        StatusCode::OK,
        service(&handle)
            .validate_config(req.config, req.providers)
            .await,
    )
}

#[cfg(test)]
mod patch_tests {
    use super::merge_group_patch;
    use crate::config::groups::{ChildDefault, LimitMetric, LimitWindow};
    use crate::config::{GroupCfg, LimitCfg};

    fn budget(cents: u64) -> LimitCfg {
        LimitCfg {
            metric: LimitMetric::Budget,
            amount: cents,
            per: Some(LimitWindow::Month),
            scope: None,
            on_exhaust: None,
            downgrade_to: None,
        }
    }

    /// The raise-a-budget path: patching only `limits` replaces them and PRESERVES parent + enabled.
    #[test]
    fn patch_limits_preserves_other_fields() {
        let base = GroupCfg {
            parent: Some("team".into()),
            enabled: true,
            limits: vec![budget(3_000)],
            child_default: None,
        };
        let out = merge_group_patch(base, None, None, Some(vec![budget(5_000)]), None);
        assert_eq!(out.parent.as_deref(), Some("team"));
        assert!(out.enabled);
        assert_eq!(out.limits.len(), 1);
        assert_eq!(out.limits[0].amount, 5_000);
        assert!(out.child_default.is_none());
    }

    /// Freezing a group: patching only `enabled` flips it, leaving limits + parent intact.
    #[test]
    fn patch_enabled_only_freezes_without_touching_limits() {
        let base = GroupCfg {
            parent: Some("team".into()),
            enabled: true,
            limits: vec![budget(3_000)],
            child_default: Some(ChildDefault {
                limits: vec![budget(500)],
            }),
        };
        let out = merge_group_patch(base, None, Some(false), None, None);
        assert!(!out.enabled);
        assert_eq!(out.limits[0].amount, 3_000);
        assert_eq!(out.parent.as_deref(), Some("team"));
        let cd = out.child_default.expect("child_default preserved");
        assert_eq!(cd.limits[0].amount, 500);
    }

    /// An empty patch (all None) is an identity: nothing changes.
    #[test]
    fn empty_patch_is_identity() {
        let base = GroupCfg {
            parent: Some("p".into()),
            enabled: false,
            limits: vec![budget(1)],
            child_default: None,
        };
        let out = merge_group_patch(base.clone(), None, None, None, None);
        assert_eq!(out, base);
    }
}
