// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Additive document-edit mode for the existing root settings endpoint. The document layer is
//! below every established typed overlay, and a shadowed edit is refused before persistence.

use std::sync::Arc;

use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use busbar_kernel::config::document_patch::DocumentPatch;
use busbar_kernel::config::overlay::OverlayDoc;
use busbar_kernel::state::{App, AppHandle};
use serde_json::json;

use super::{
    config_transaction, err_json, if_match_version, ok_json, stale_if_match, with_config_etag,
    Outcome,
};
use crate::admin_state::AppAdmin as _;
use crate::v1::contract::AdminError;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DocumentRequest {
    #[serde(deserialize_with = "DocumentPatch::deserialize_request")]
    document_patch: DocumentPatch,
    /// Independent edits of the provider catalog, committed atomically with config.yaml edits.
    #[serde(
        default,
        deserialize_with = "DocumentPatch::deserialize_optional_request"
    )]
    providers_patch: Option<DocumentPatch>,
    /// Forget these exact prior document edits before applying the new edit; other overlays stay.
    #[serde(default)]
    reset_document_paths: Vec<String>,
    #[serde(default)]
    reset_providers_paths: Vec<String>,
    /// Explicit acknowledgement of the existing durable settings semantics.
    #[serde(default)]
    persist: Option<bool>,
}

/// Inspect just the mode key. IgnoredAny skips values without retaining a second raw secret tree.
pub(super) fn is_document_request(body: &[u8]) -> bool {
    fn present<'de, D: serde::Deserializer<'de>>(de: D) -> Result<bool, D::Error> {
        <serde::de::IgnoredAny as serde::Deserialize>::deserialize(de).map(|_| true)
    }
    #[derive(serde::Deserialize)]
    struct Mode {
        #[serde(default, deserialize_with = "present")]
        document_patch: bool,
    }
    serde_json::from_slice::<Mode>(body).is_ok_and(|mode| mode.document_patch)
}

/// A parent replacement, null, removal, or reset can change an authored list without any
/// numeric pointer segment. Bind every nonempty document edit to its consumed source instead
/// of maintaining a fragile enumeration of sequence-bearing kernel/plane fields.
fn requires_source_binding(patch: Option<&DocumentPatch>, resets: &[String]) -> bool {
    patch.is_some_and(|patch| patch.paths().next().is_some()) || !resets.is_empty()
}

/// Only sanitized values captured by the builder (plus mutable registries from this same Arc).
/// Never reconstruct an applied view by reading config.yaml or the desired Store overlay.
pub(super) fn configuration(app: &App) -> serde_json::Value {
    let Some(view) = app.configured_view.as_ref() else {
        return json!({"config_version": app.config_version, "state": "unavailable"});
    };
    let mut view = (**view).clone();
    view.refresh_mutable_registries(app);
    json!({
        "config_version": app.config_version,
        "state": if app.config_pending_restart.is_empty() && app.planes_awaiting_restart.is_empty() { "configured" } else { "restart_pending" },
        "source": "installed_generation",
        "config_locked": app.overlay_path.is_none(),
        "values": view,
        "reload_to_apply": app.config_pending_restart.iter().chain(&app.planes_awaiting_restart).collect::<Vec<_>>(),
    })
}

pub(super) async fn put(
    handle: Arc<AppHandle>,
    principal: busbar_kernel::auth::AuthPrincipal,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let expected = match if_match_version(&headers) {
        Ok(expected) => expected,
        Err(response) => return response,
    };
    let request: DocumentRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        // A malformed value may itself contain a credential. Do not echo serde's input excerpts.
        Err(_) => {
            return err_json(&AdminError::Validation(
                "invalid document_patch body; use document_patch, optional providers_patch, reset_document_paths, reset_providers_paths and persist".into(),
            ))
        }
    };
    if request.persist == Some(false) {
        return err_json(&AdminError::Validation(
            "document_patch is always durable".into(),
        ));
    }
    let actor = principal.actor_id().to_owned();
    let origin = format!("config/settings document patch by {actor}");
    let changed: Vec<String> = request
        .document_patch
        .paths()
        .map(str::to_owned)
        .chain(request.reset_document_paths.iter().cloned())
        .collect();
    let pending = restart_paths(&changed);
    let out = config_transaction(&handle, move |txn| {
        let snapshot = txn.app().clone();
        if let Some(error) = stale_if_match(expected, snapshot.config_version) {
            return Err(error);
        }
        let store = snapshot.overlay_path.clone().ok_or_else(|| AdminError::Validation(
            busbar_kernel::config::overlay::NO_WRITABLE_OVERLAY_MSG.into(),
        ))?;
        let config_path = snapshot.config_path.clone().ok_or_else(|| AdminError::Validation(
            "document_patch requires an operator config file as its base".into(),
        ))?;
        let providers_override = snapshot.providers_override.clone();
        Ok(txn.read_store(move || {
            let mut doc = store.read_required().map_err(AdminError::Validation)?.unwrap_or_default();
            if providers_override.is_some() && request.document_patch.overlaps_path("/providers_file")
                .map_err(|error| AdminError::Validation(error.to_string()))? {
                return Err(AdminError::Conflict(format!(
                    "providers_file is overridden by the process CLI at config version {}; remove that explicit override and restart before editing providers_file",
                    snapshot.config_version,
                )));
            }
            if let Some(path) = shadowed_path(&doc, &request.document_patch)? {
                return Err(AdminError::Conflict(format!(
                    "document edit conflicts with higher-priority override {path} at config version {}; use that section's existing admin route or explicitly reset its overlay first",
                    snapshot.config_version,
                )));
            }
            let prior = doc.document_patch.take().map(Ok)
                .unwrap_or_else(|| DocumentPatch::from_value(json!({})))
                .map_err(|error| AdminError::Validation(error.to_string()))?;
            doc.document_patch = Some(prior.without_paths(&request.reset_document_paths)
                .and_then(|prior| prior.updated(&request.document_patch))
                .map_err(|error| AdminError::Validation(error.to_string()))?);
            if request.providers_patch.is_some() || !request.reset_providers_paths.is_empty() {
                let prior = doc.providers_patch.take().map(Ok)
                    .unwrap_or_else(|| DocumentPatch::from_value(json!({})))
                    .map_err(|error| AdminError::Validation(error.to_string()))?;
                let prior = prior.without_paths(&request.reset_providers_paths)
                    .map_err(|error| AdminError::Validation(error.to_string()))?;
                doc.providers_patch = Some(match request.providers_patch.as_ref() {
                    Some(patch) => prior.updated(patch)
                        .map_err(|error| AdminError::Validation(error.to_string()))?,
                    None => prior,
                });
            }
            let check_config_source = requires_source_binding(doc.document_patch.as_ref(), &request.reset_document_paths)
                || requires_source_binding(Some(&request.document_patch), &[]);
            let check_catalog_source = requires_source_binding(doc.providers_patch.as_ref(), &request.reset_providers_paths)
                || requires_source_binding(request.providers_patch.as_ref(), &[]);
            let mut source_admission = if check_config_source || check_catalog_source {
                let fingerprints = snapshot.document_source_fingerprints.ok_or_else(|| AdminError::Conflict(
                    "installed generation has no operator-source binding; reload and refresh before document edits".into(),
                ))?;
                Some(busbar_kernel::config::document_patch::SourceAdmission::new(fingerprints, check_config_source, check_catalog_source))
            } else { None };
            let mut loaded = busbar_kernel::appbuild::load_config_from_disk_compacting_document_patches(
                &config_path,
                providers_override.as_deref(),
                false,
                busbar_kernel::config::EnvSubst::Strict,
                &*snapshot.root_rules,
                busbar_kernel::appbuild::DocumentPatchLoad {
                    patch: doc.document_patch.as_mut(), providers_patch: doc.providers_patch.as_mut(),
                    admission: source_admission.as_mut(),
                },
            ).map_err(|error| if source_admission.as_ref().is_some_and(|admission| admission.drifted()) {
                AdminError::Conflict("operator source changed since the installed generation; reload and refresh before document edits".into())
            } else { AdminError::Validation(error) })?;
            if loaded.deploy.advanced.worker_threads == Some(0) {
                return Err(AdminError::Validation("advanced.worker_threads must be positive".into()));
            }
            busbar_kernel::config::overlay::apply_root_to_deploy(&mut loaded.deploy, &doc);
            if let Some(patch) = request.providers_patch.as_ref() {
                if let Some(path) = patch.shadowed_catalog_path(&loaded.deploy.providers)
                    .map_err(|error| AdminError::Validation(error.to_string()))? {
                    return Err(AdminError::Conflict(format!(
                        "catalog edit conflicts with deployment override /providers{path} at config version {}; edit the deployment setting through document_patch or reset that explicit override first",
                        snapshot.config_version,
                    )));
                }
            }
            let mut cfg = busbar_kernel::config::resolve(&loaded.deploy, &loaded.defs)
                .map_err(|_| AdminError::Validation("patched configuration failed resolution".into()))?;
            let base_hook_names = cfg.hooks.keys().cloned().collect();
            let base_group_names = cfg.groups.keys().cloned().collect();
            busbar_kernel::config::overlay::merge_into(&mut cfg, doc.clone());
            let overlay = (!loaded.config_locked).then(|| store.clone());
            let (mut next, rotate, limits) = busbar_kernel::build_app_from_config(
                cfg,
                loaded.deploy.plugins.clone(),
                overlay,
                base_hook_names,
                base_group_names,
                (Some(config_path), Some(loaded.providers_path)),
                Some(&snapshot),
                &snapshot.root_rules,
            ).map_err(|_| AdminError::Validation("patched configuration failed runtime validation".into()))?;
            busbar_kernel::config::readback::ConfiguredView::capture_documents(
                &mut next, &loaded.deploy, &loaded.defs,
            );
            next.config_pending_restart.extend(pending);
            next.config_pending_restart.extend(busbar_kernel::plugin_routes::paths_awaiting_restart(
                &next.plugin_routes, &snapshot.plugin_routes, &next.boot_route_paths,
            ));
            let exports: std::collections::BTreeSet<_> = next.export_defs.keys()
                .chain(snapshot.export_defs.keys()).cloned().collect();
            for name in exports {
                if busbar_kernel::export::plugin::requires_restart(&name, next.export_defs.get(&name)) {
                    next.config_pending_restart.push(format!("export.{name}"));
                }
            }
            next.config_pending_restart.sort();
            next.config_pending_restart.dedup();
            let installed = Arc::new(next);
            Ok(Outcome::commit_rates_then(
                installed.clone(),
                move || busbar_kernel::config::overlay::write(&store, &doc),
                limits,
                origin,
                move || {
                    if let Some(rotate) = rotate { rotate(); }
                    Ok(Outcome::Value(installed))
                },
            ))
        }))
    }).await;
    match out {
        Ok(installed) => {
            super::audit::AUDIT.record_by(
                "config.document",
                "config:document",
                super::audit::OUTCOME_APPLIED,
                &actor,
            );
            installed.record_version(&actor, "config.document (Store document overlay)");
            with_config_etag(
                ok_json(
                    StatusCode::OK,
                    &json!({
                        "applied": true,
                        "persisted": true,
                        "config_version": installed.config_version,
                        "configuration": configuration(&installed),
                        "reload_to_apply": installed.config_pending_restart.iter().chain(&installed.planes_awaiting_restart).collect::<Vec<_>>(),
                        "note": "stored and installed as configuration; reload_to_apply paths require a process restart, and configured plugin values do not acknowledge asynchronous runtime refresh",
                    }),
                ),
                installed.config_version,
            )
        }
        Err(error) => {
            super::audit::AUDIT.record_by(
                "config.document",
                "config:document",
                super::audit::OUTCOME_REJECTED,
                &actor,
            );
            err_json(&error)
        }
    }
}

fn pointer(key: &str) -> String {
    format!("/{}", key.replace('~', "~0").replace('/', "~1"))
}

#[cfg(feature = "openapi-schema")]
pub(super) fn request_schema() -> serde_json::Value {
    json!({
        "type": "object", "required": ["document_patch"], "additionalProperties": false,
        "properties": {
            "document_patch": {
                "type": "object", "additionalProperties": false,
                "properties": {
                    "set": {"type": "object", "additionalProperties": true},
                    "remove": {"type": "array", "items": {"type": "string"}}
                },
                "description": "Lowest-priority Store overlay over config.yaml, parsed with boot's schema. RFC6901 paths; strict sequence indices replace existing entries, terminal - appends. Within one request, indices name the input snapshot; sets precede descending removals. Each subsequent request addresses the current authored document. Null is a value, removal is explicit. Omitted values including secrets survive. Overlapping paths and edits shadowed by existing typed overlays are refused. Restart-only fields are reported. Patch history is bounded to 4096 total operations and 1 MiB; pointer depth is at most 128. Limit violations reject the transaction."
            },
            "providers_patch": {"type": "object", "additionalProperties": false,
                "properties": {"set": {"type": "object", "additionalProperties": true}, "remove": {"type": "array", "items": {"type": "string"}}},
                "description": "Edits providers.yaml through its boot grammar in the same Store transaction. Paths start with catalog entry names. Deployment overrides that shadow an edit are refused."},
            "reset_providers_paths": {"type": "array", "items": {"type": "string"}, "description": "Forget only these exact prior catalog edits before merging providers_patch."},
            "reset_document_paths": {"type": "array", "items": {"type": "string"}, "description": "Forget only these exact prior document edits before merging the new edit; typed overlays are never removed."},
            "persist": {"type": "boolean", "const": true}
        }
    })
}

#[cfg(feature = "openapi-schema")]
pub(super) fn response_schema() -> serde_json::Value {
    json!({
        "type": "object", "required": ["applied", "persisted", "config_version", "configuration"],
        "properties": {
            "applied": {"type": "boolean"}, "persisted": {"type": "boolean"},
            "config_version": {"type": "integer", "format": "uint64", "minimum": 0},
            "configuration": {"type": "object", "description": "Sanitized installed configuration, bound to config_version/ETag. Configured values are not an acknowledgement of physical listener, Store, or asynchronous plugin activation."},
            "reload_to_apply": {"type": "array", "items": {"type": "string"}},
            "note": {"type": "string"}
        }
    })
}

fn shadowed_path(doc: &OverlayDoc, patch: &DocumentPatch) -> Result<Option<String>, AdminError> {
    let mut paths = Vec::new();
    if let Some(root) = &doc.root {
        macro_rules! roots { ($($field:ident),+ $(,)?) => { $(
            if root.$field.is_some() { paths.push(pointer(stringify!($field))); }
        )+ }; }
        roots!(
            listen,
            tls,
            admin_listen,
            admin_tls,
            admin_require_mtls,
            rate_card,
            per_request_fee,
            store
        );
        macro_rules! fields { ($($field:ident),+ $(,)?) => { $(
            if let Some(section) = &root.$field {
                paths.extend(DocumentPatch::object_field_paths(&pointer(stringify!($field)), section)
                    .map_err(|error| AdminError::Validation(error.to_string()))?);
            }
        )+ }; }
        fields!(security, limits, advanced, health, routing);
    }
    for name in doc.hooks.keys().chain(doc.deleted.iter()) {
        paths.push(format!("/hooks{}", pointer(name)));
    }
    if !doc.global_hooks.is_empty() {
        paths.push("/pools/hooks".into());
    }
    for name in doc.groups.keys().chain(doc.deleted_groups.iter()) {
        paths.push(format!("/groups{}", pointer(name)));
    }
    if !doc.plugin_versions.is_empty() {
        paths.push("/plugins".into());
    }
    for (section, entries) in &doc.named_maps {
        for name in entries.keys() {
            paths.push(format!("{}{}", pointer(section), pointer(name)));
        }
    }
    for path in paths {
        if patch
            .overlaps_path(&path)
            .map_err(|error| AdminError::Validation(error.to_string()))?
        {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

fn restart_paths(paths: &[String]) -> Vec<String> {
    const BOOT: &[&str] = &[
        "/listen",
        "/tls",
        "/admin_listen",
        "/admin_tls",
        "/admin_require_mtls",
        "/store",
        "/secrets",
        "/plugins",
        "/limits/upstream_request_timeout_secs",
        "/limits/pool_max_idle_per_host",
        "/limits/pool_idle_timeout_secs",
        "/limits/max_inbound_concurrent",
        "/advanced/response_headers",
        "/advanced/worker_threads",
        "/advanced/upstream_http1_only",
        "/advanced/upstream_h2_prior_knowledge",
    ];
    paths
        .iter()
        .filter(|path| {
            BOOT.iter().any(|boot| {
                path == boot
                    || path
                        .strip_prefix(boot)
                        .is_some_and(|suffix| suffix.starts_with('/'))
                    || boot
                        .strip_prefix(path.as_str())
                        .is_some_and(|suffix| suffix.starts_with('/'))
            })
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_binding_covers_sequence_roots_ancestors_null_and_resets() {
        for path in [
            "/pools",
            "/pools/work",
            "/pools/work/members",
            "/pools/work/hooks",
            "/pools/hooks",
            "/future-plane/list",
            "/listen",
        ] {
            for value in [json!([]), serde_json::Value::Null, json!({})] {
                let patch = DocumentPatch::from_value(json!({"set": {path: value}})).unwrap();
                assert!(
                    requires_source_binding(Some(&patch), &[]),
                    "source binding omitted set {path}"
                );
            }
            let patch = DocumentPatch::from_value(json!({"remove": [path]})).unwrap();
            assert!(
                requires_source_binding(Some(&patch), &[]),
                "source binding omitted remove {path}"
            );
            assert!(
                requires_source_binding(None, &[path.to_owned()]),
                "source binding omitted reset {path}"
            );
        }
        let empty = DocumentPatch::from_value(json!({})).unwrap();
        assert!(!requires_source_binding(Some(&empty), &[]));
        assert!(!requires_source_binding(None, &[]));
    }

    #[test]
    fn requests_cannot_supply_internal_ordered_store_stages() {
        for body in [
            json!({"document_patch": {"$stages": []}}),
            json!({"document_patch": {}, "providers_patch": {"$stages": []}}),
        ] {
            assert!(serde_json::from_value::<DocumentRequest>(body).is_err());
        }
        assert!(serde_json::from_value::<DocumentRequest>(
            json!({"document_patch": {"set": {"/pools/example/members/-": "example/model"}}})
        )
        .is_ok());
    }

    #[test]
    fn document_mode_is_explicit_and_cannot_mix_with_legacy_settings() {
        assert!(!is_document_request(
            br#"{"limits":{"request_body_max_bytes":12}}"#
        ));
        assert!(is_document_request(br#"{"document_patch":null}"#));
        assert!(is_document_request(
            br#"{"document_patch":{"set":{"/secret":"hidden"}}}"#
        ));
        assert!(serde_json::from_value::<DocumentRequest>(json!({
            "document_patch": {}, "limits": {"request_body_max_bytes": 12}
        }))
        .is_err());
        assert!(serde_json::from_value::<DocumentRequest>(json!({
            "document_patch": {}, "reset_document_paths": ["/listen"]
        }))
        .is_ok());
    }

    #[test]
    fn document_edits_refuse_shadowed_values_without_removing_typed_overrides() {
        let mut doc = OverlayDoc::default();
        doc.root = Some(
            serde_json::from_value(json!({"limits": {"request_body_max_bytes": 12}})).unwrap(),
        );
        let edit = |path: &str| DocumentPatch::from_value(json!({"set": {path: 19}})).unwrap();
        assert_eq!(
            shadowed_path(&doc, &edit("/limits/request_body_max_bytes"))
                .unwrap()
                .as_deref(),
            Some("/limits/request_body_max_bytes")
        );
        assert!(shadowed_path(&doc, &edit("/limits/default_max_tokens"))
            .unwrap()
            .is_none());
        assert!(shadowed_path(&doc, &edit("/providers/new/timeout"))
            .unwrap()
            .is_none());
        doc.named_maps
            .entry("export".into())
            .or_default()
            .insert("a/b".into(), json!({"module": "sink"}));
        assert_eq!(
            shadowed_path(&doc, &edit("/export/a~1b/settings/timeout"))
                .unwrap()
                .as_deref(),
            Some("/export/a~1b")
        );
        assert!(doc.root.is_some());
        assert_eq!(doc.named_maps["export"].len(), 1);
    }

    #[test]
    fn boot_changes_remain_explicitly_pending_and_live_limits_do_not() {
        let paths = [
            "/advanced/worker_threads",
            "/store/settings",
            "/limits/request_body_max_bytes",
            "/listen",
        ]
        .map(str::to_owned);
        assert_eq!(
            restart_paths(&paths),
            ["/advanced/worker_threads", "/store/settings", "/listen"]
        );
    }

    #[cfg(feature = "openapi-schema")]
    #[test]
    fn document_mode_schema_and_generic_route_are_published() {
        let schema = super::super::openapi_doc();
        let path = &schema["paths"]["/api/v1/admin/config/settings"];
        let body = &path["put"]["requestBody"]["content"]
            [busbar_contract::protocol::APPLICATION_JSON]["schema"];
        assert!(body.to_string().contains("document_patch"));
        assert!(body.to_string().contains("reset_document_paths"));
        assert!(
            schema["components"]["schemas"]["ConfigSettingsView"]["properties"]
                .get("configuration")
                .is_some()
        );
    }
}
