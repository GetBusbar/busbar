// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The core-owned instance edit mode of the existing config document transaction.
//! Discovery is metadata, never authority; the existing PutConfigSettings gate applies.

use std::sync::Arc;

use axum::response::Response;
use axum::Extension;
use busbar_contract::json::{JsonValueTrait as _, Value as WireValue};
use busbar_contract::plugin::Kind;
use busbar_kernel::config::document_patch::DocumentPatch;
use busbar_kernel::state::{App, AppHandle};
use serde_json::{json, Value};

use super::config_document::{self, DocumentRequest, EditAudit};
use super::generation::{self, OriginalConfigPrecondition};
use super::kinds::{self, Instance};
use super::settings_edit::SettingsEdit;
use crate::v1::contract::taxonomy::Cond;
use crate::v1::contract::AdminError;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    instance_edit: Edit,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Edit {
    kind: String,
    id: String,
    target_revision: String,
    edit: SettingsEdit,
}

pub(super) fn is_request(body: &[u8]) -> bool {
    fn present<'de, D: serde::Deserializer<'de>>(de: D) -> Result<bool, D::Error> {
        <serde::de::IgnoredAny as serde::Deserialize>::deserialize(de).map(|_| true)
    }
    #[derive(serde::Deserialize)]
    struct Mode {
        #[serde(default, deserialize_with = "present")]
        instance_edit: bool,
    }
    serde_json::from_slice::<Mode>(body).is_ok_and(|mode| mode.instance_edit)
}

fn escaped(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn source(instance: &Instance) -> Option<String> {
    let kind = Kind::ALL
        .into_iter()
        .find(|kind| kind.to_string() == instance.kind)?;
    match kind {
        Kind::Store if instance.id == Kind::Store.root() => {
            Some(format!("/{}/settings", kind.root()))
        }
        Kind::Secret | Kind::Auth | Kind::Hook | Kind::Export => Some(format!(
            "/{}/{}/settings",
            kind.root(),
            escaped(&instance.id)
        )),
        Kind::Store | Kind::Plane | Kind::Transport => None,
    }
}

fn unavailable(app: &App, instance: &Instance) -> Option<&'static str> {
    if source(instance).is_none() {
        Some("source_mapping_unavailable")
    } else if app.config_path.is_none() || app.providers_path.is_none() {
        Some("no_disk_base")
    } else if app.document_source_fingerprints.is_none() {
        Some("source_binding_unavailable")
    } else if app.overlay_path.is_none() {
        Some("config_locked")
    } else if !kinds::config_schema(app, instance).is_object() {
        Some("schema_unavailable")
    } else if kinds::image(app, instance).is_empty() {
        Some("image_unavailable")
    } else {
        None
    }
}

fn revision(app: &App, instance: &Instance, pointer: &str) -> String {
    let schema = kinds::config_schema(app, instance);
    let schema = busbar_contract::json::to_vec(&schema).expect("schema JSON serializes");
    let image = kinds::image(app, instance);
    let mut framed = b"busbar.instance.settings.1\0".to_vec();
    // Public identity/schema only. Never hash a hidden settings value into discovery.
    for component in [
        instance.kind.as_bytes(),
        instance.id.as_bytes(),
        instance.module.as_deref().unwrap_or_default().as_bytes(),
        image.as_bytes(),
        schema.as_slice(),
        pointer.as_bytes(),
    ] {
        framed.extend_from_slice(
            &u64::try_from(component.len())
                .expect("bounded public identity length fits u64")
                .to_be_bytes(),
        );
        framed.extend_from_slice(component);
    }
    busbar_contract::redacted::sha256_hex(&framed)
}

fn wire(value: Value) -> WireValue {
    busbar_contract::json::parse_value(&serde_json::to_vec(&value).expect("metadata serializes"))
        .expect("serialized metadata is JSON")
}

pub(super) fn discovery(app: &App, instance: &Instance) -> (WireValue, WireValue) {
    let reason = unavailable(app, instance);
    let management = wire(json!({
        "available":reason.is_none(), "reason":reason,
        "plugin_schema_scope":"lifecycle_settings"
    }));
    let actions = match source(instance).filter(|_| reason.is_none()) {
        Some(pointer) => json!([{
            "id":"settings", "method":"PUT", "href":"/api/v1/admin/config/settings",
            "operation_id":"PutConfigSettings", "verb":"put_config_settings",
            "required_scope":"full", "effect":"mutation", "request_mode":"instance_edit",
            "etag":generation::config_etag(app), "target_revision":revision(app,instance,&pointer),
            "source":{"document":"config","pointer":pointer,"authority":"kind_root"},
            "semantics":"explicit_top_level_set_remove", "input_schema":request_schema(),
            "output_schema_ref":"#/components/schemas/ConfigDocumentMutationView"
        }]),
        None => json!([]),
    };
    (management, wire(actions))
}

fn plan(app: &App, edit: Edit) -> Result<DocumentRequest, AdminError> {
    let instance = kinds::inventory(app)
        .into_iter()
        .find(|instance| instance.kind == edit.kind && instance.id == edit.id)
        .ok_or_else(|| AdminError::not_found("instance settings target"))?;
    if let Some(reason) = unavailable(app, &instance) {
        return Err(AdminError::Validation(format!(
            "instance settings are unavailable: {reason}"
        )));
    }
    let pointer = source(&instance).expect("availability checks source mapping");
    if edit.target_revision != revision(app, &instance, &pointer) {
        return Err(AdminError::Conflict(
            "instance image, schema or source changed; refresh and review the edit again".into(),
        ));
    }
    patch(&pointer, edit.edit).map(DocumentRequest::patch)
}

fn patch(pointer: &str, edit: SettingsEdit) -> Result<DocumentPatch, AdminError> {
    edit.validate()?;
    let Value::Object(values) =
        serde_json::to_value(edit.set.authoring(&busbar_kernel::seal::acquire()))
            .map_err(|_| AdminError::Internal)?
    else {
        return Err(AdminError::Internal);
    };
    let set: serde_json::Map<_, _> = values
        .into_iter()
        .map(|(name, value)| (format!("{pointer}/{}", escaped(&name)), value))
        .collect();
    let remove: Vec<_> = edit
        .remove
        .into_iter()
        .map(|name| format!("{pointer}/{}", escaped(&name)))
        .collect();
    // DocumentPatch takes custody before validation and wipes private values on every exit.
    DocumentPatch::from_value(json!({"set":set,"remove":remove}))
        .map_err(|error| AdminError::Validation(error.to_string()))
}

pub(super) async fn put(
    handle: Arc<AppHandle>,
    principal: busbar_kernel::auth::AuthPrincipal,
    original: Option<Extension<OriginalConfigPrecondition>>,
    headers: busbar_kernel::inbound::http_projection::AdminHeaders,
    body: axum::body::Bytes,
) -> Response {
    let Some(Extension(original)) = original else {
        return super::err_json(&AdminError::Internal);
    };
    if let Err(response) = original.require_strong() {
        return *response;
    }
    let mut keys = headers.get_all("idempotency-key").iter();
    if !keys
        .next()
        .is_some_and(|key| key.to_str().is_ok_and(generation::valid_idempotency_key))
        || keys.next().is_some()
    {
        return busbar_kernel::admin::gate::admin_error_envelope_with(
            400,
            "invalid_request",
            Some("invalid_request"),
            "instance settings require one valid Idempotency-Key",
            &json!({}),
        );
    }
    let expected = match super::if_match_version(&headers) {
        Ok(expected) => expected,
        Err(response) => return response,
    };
    let request: Request = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => {
            return super::err_json_cond(
                &AdminError::Validation("invalid instance_edit body".into()),
                Cond::MalformedBody,
            );
        }
    };
    let actor = principal.actor_id().to_string();
    let audit = EditAudit {
        action: "config.document",
        resource: format!(
            "kind:{}/instance:{}",
            escaped(&request.instance_edit.kind),
            escaped(&request.instance_edit.id)
        ),
        origin: format!("instance settings by {actor}"),
        note: "config.document (instance settings edit)".into(),
    };
    match config_document::apply(
        &handle,
        &actor,
        expected,
        audit,
        Box::new(move |app| plan(app, request.instance_edit).map(Some)),
    )
    .await
    {
        Ok(committed) => committed.response(),
        Err(response) => *response,
    }
}

pub(super) fn request_schema() -> Value {
    json!({
        "type":"object", "additionalProperties":false, "required":["instance_edit"],
        "properties":{"instance_edit":{
            "type":"object", "additionalProperties":false,
            "required":["kind","id","target_revision","edit"],
            "properties":{
                "kind":{"type":"string"}, "id":{"type":"string"},
                "target_revision":{"type":"string"},
                "edit":{"type":"object","additionalProperties":false,
                    "properties":{
                        "set":{"type":"object","additionalProperties":true,"maxProperties":256},
                        "remove":{"type":"array","items":{"type":"string"}}
                    }
                }
            }
        }},
        "description":"Discovered instance settings edit on the existing config transaction. New dispatch requires one strong current config ETag in If-Match and one Idempotency-Key. Omitted settings survive; set replaces complete top-level values; null is a value; remove is explicit. Requires current image/schema/source identity. The actual authoring parser, secret policy, source binding, typed overlay precedence and runtime validation remain authoritative. Store/secret changes can require restart; persisted configuration is not physical activation. Exact method/path/query/body replay retains the original outcome; an error receipt is not proof of no effect."
    })
}

#[cfg(feature = "openapi-schema")]
pub(super) fn management_schema() -> Value {
    json!({"type":"object","additionalProperties":false,
        "required":["available","reason","plugin_schema_scope"],
        "properties":{
            "available":{"type":"boolean"},
            "reason":{"enum":[null,"source_mapping_unavailable","no_disk_base",
                "source_binding_unavailable","config_locked","schema_unavailable","image_unavailable"]},
            "plugin_schema_scope":{"const":"lifecycle_settings"}
        },
        "description":"Availability describes a source mapping, not permission or guaranteed writability. Lifecycle schema is not the complete raw authoring grammar; source/precedence is revalidated at commit."
    })
}

#[cfg(feature = "openapi-schema")]
pub(super) fn action_schema() -> Value {
    json!({"type":"object","additionalProperties":false,
        "required":["id","method","href","operation_id","verb","required_scope","effect",
            "request_mode","etag","target_revision","source","semantics","input_schema","output_schema_ref"],
        "properties":{
            "id":{"const":"settings"},"method":{"const":"PUT"},
            "href":{"const":"/api/v1/admin/config/settings"},
            "operation_id":{"const":"PutConfigSettings"},"verb":{"const":"put_config_settings"},
            "required_scope":{"const":"full"},"effect":{"const":"mutation"},
            "request_mode":{"const":"instance_edit"},"etag":{"type":"string"},
            "target_revision":{"type":"string","pattern":"^[0-9a-f]{64}$"},
            "source":{"type":"object","additionalProperties":false,"required":["document","pointer","authority"],
                "properties":{"document":{"const":"config"},"pointer":{"type":"string"},"authority":{"const":"kind_root"}}},
            "semantics":{"const":"explicit_top_level_set_remove"},"input_schema":{"type":"object"},
            "output_schema_ref":{"const":"#/components/schemas/ConfigDocumentMutationView"}
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_contract::yaml::{Value as Yaml, ValueExt as _};

    #[test]
    fn instance_edit_preserves_hidden_siblings_and_escapes_each_key_as_one_segment() {
        let edit: SettingsEdit = serde_json::from_value(json!({
            "set":{"nested":{"new":9007199254740993u64},"literal/null":null,"~name":true},
            "remove":["old"]
        }))
        .unwrap();
        let patch = patch("/hooks/target/settings", edit).unwrap();
        let mut source: Yaml = busbar_contract::yaml::from_str(
            "hooks:\n  target:\n    module: example\n    settings:\n      hidden: PRIVATE_SENTINEL\n      nested: {old: 1}\n      old: 3\n  sibling: {module: untouched}\n",
        )
        .unwrap();
        patch.apply_to(&mut source).unwrap();
        assert_eq!(
            source
                .at("hooks")
                .at("target")
                .at("settings")
                .at("hidden")
                .as_str(),
            Some("PRIVATE_SENTINEL")
        );
        assert_eq!(
            source.at("hooks").at("sibling").at("module").as_str(),
            Some("untouched")
        );
        let serialized = busbar_contract::yaml::to_string(&source).unwrap();
        assert!(serialized.contains("9007199254740993"));
        assert!(patch.paths().any(|path| path.ends_with("/literal~1null")));
        assert!(patch.paths().any(|path| path.ends_with("/~0name")));
        assert_eq!(
            source
                .at("hooks")
                .at("target")
                .at("settings")
                .at("literal/null"),
            &Yaml::Null
        );
        assert_eq!(
            source
                .at("hooks")
                .at("target")
                .at("settings")
                .at("nested")
                .at("old"),
            &Yaml::Null
        );
    }

    #[test]
    fn instance_request_refuses_competing_modes_unknown_fields_and_overlap() {
        for body in [
            json!({"instance_edit":null}),
            json!({"instance_edit":{"kind":"hook","id":"h","target_revision":"r","settings":{}}}),
            json!({"instance_edit":{"kind":"hook","id":"h","target_revision":"r","edit":{"replace":{}}}}),
            json!({"document_patch":{},"instance_edit":{"kind":"hook","id":"h","target_revision":"r","edit":{}}}),
        ] {
            assert!(serde_json::from_value::<Request>(body).is_err());
        }
        let edit = serde_json::from_value(json!({"set":{"x":1},"remove":["x"]})).unwrap();
        assert!(patch("/hooks/h/settings", edit).is_err());
    }

    #[cfg(feature = "openapi-schema")]
    #[test]
    fn instance_contract_matches_compiled_operation_and_closed_request_schema() {
        let doc = super::super::openapi_doc();
        let op = &doc["paths"]["/api/v1/admin/config/settings"]["put"];
        assert_eq!(op["operationId"], "PutConfigSettings");
        assert_eq!(op["x-busbar-verb"], "put_config_settings");
        assert_eq!(op["x-busbar-required-scope"], "full");
        assert!(
            op["requestBody"]["content"]["application/json"]["schema"]["oneOf"]
                .as_array()
                .unwrap()
                .contains(&request_schema())
        );
        let request = jsonschema::validator_for(&request_schema()).unwrap();
        assert!(request.is_valid(&json!({"instance_edit":{
            "kind":"hook","id":"h","target_revision":"r","edit":{"set":{"exact":9007199254740993u64},"remove":[]}
        }})));
        assert!(!request.is_valid(&json!({"instance_edit":{
            "kind":"hook","id":"h","target_revision":"r","edit":{"settings":{}}
        }})));
        assert_eq!(
            doc["components"]["schemas"]["Describe"]["properties"]["management"],
            management_schema()
        );
        assert_eq!(
            doc["components"]["schemas"]["Describe"]["properties"]["actions"]["items"],
            action_schema()
        );
    }
}
