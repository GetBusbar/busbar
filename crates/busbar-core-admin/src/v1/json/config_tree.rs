// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `GET /config/tree` (ADMIN-API-1.6 §14.1): the whole configuration in one read, under the secret
//! rule (§14.2).
//!
//! `?view=declared|effective&layer=base|overlay|merged&section=<dotted key>`.
//!
//! - `effective` (the default) is the resolved generation: the kernel's safe readback of every
//!   section (plugin and plane sections included) and `process`, the command-line and
//!   environment inputs the process read. `layer` is `merged` only: a resolved generation has no
//!   layers.
//! - `declared` is the configuration as written: `base` is the operator's file as it stands on
//!   disk, `overlay` is the Store overlay's per-section documents, tombstones, document-patch
//!   paths and overlay version; `merged` (the default) serves both layers side by side.
//!
//! Every section passes through [`crate::v1::secret_rule`] before it is served, and the digests
//! are over the projected sections, never over a value. The ETag is the config ETag (the router
//! layer sets it for every `/config` resource); the read changes nothing.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{header::CONTENT_TYPE, StatusCode};
use axum::response::{IntoResponse, Response};
use busbar_contract::json::{JsonContainerTrait, JsonValueMutTrait, JsonValueTrait, Map, Value};
use busbar_kernel::state::{App, AppHandle};

use super::{err_json, err_json_cond};
use crate::v1::contract::taxonomy::Cond;
use crate::v1::contract::AdminError;
use crate::v1::secret_rule::Rule;

/// The query parameters this read takes; any other is refused.
const PARAMS: &[&str] = &["view", "layer", "section"];

/// The OpenAPI parameter objects of [`PARAMS`], as the generated document carries them.
#[cfg(feature = "openapi-schema")]
pub(crate) const QUERY_DOC: [&str; 3] = [
    r#"{"name":"view","in":"query","required":false,"schema":{"type":"string","enum":["effective","declared"]},"description":"`effective` (default): the resolved generation. `declared`: the configuration as written."}"#,
    r#"{"name":"layer","in":"query","required":false,"schema":{"type":"string","enum":["base","overlay","merged"]},"description":"With `view=declared`: `base` (the file as written), `overlay` (the Store overlay) or `merged` (both, the default). The effective view is `merged` only."}"#,
    r#"{"name":"section","in":"query","required":false,"schema":{"type":"string","pattern":"^[^.]+(\\.[^.]+)*$"},"description":"A dotted key (`limits.request_body_max_bytes`) narrowing the sections served; `404` when no layer holds it."}"#,
];

/// The documented shape of `GET /config/tree`.
#[cfg(feature = "openapi-schema")]
pub(crate) struct ConfigTreeView;

#[cfg(feature = "openapi-schema")]
impl schemars::JsonSchema for ConfigTreeView {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "ConfigTreeView".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "object",
            "required": ["view", "layer", "config_version", "config_generation"],
            "properties": {
                "view": {"enum": ["effective", "declared"]},
                "layer": {"enum": ["base", "overlay", "merged"]},
                "config_version": {"type": "integer", "minimum": 0},
                "config_generation": {"type": "integer", "minimum": 0},
                "state": {"type": "string", "description": "effective: `configured`, `restart_pending` or `unavailable`"},
                "meaning": {"type": "string"},
                "unavailable_from_resolved": {"type": "array", "items": {"type": "string"}},
                "reload_to_apply": {"type": "array", "items": {"type": "string"}},
                "sections": {
                    "type": "object",
                    "description": "effective: section name to its projected value; `process.inputs` lists the command-line and environment inputs ({name, source, set, shown, value})",
                    "additionalProperties": {}
                },
                "layers": {
                    "type": "object",
                    "description": "declared: `base` and/or `overlay`, each {state, source, digest, sections} (`overlay` adds `version`), or {state, reason} when not served",
                    "additionalProperties": {"type": "object"}
                },
                "digest": {
                    "type": "object",
                    "description": "AR-20: sha256 over the projected document and each projected section",
                    "properties": {
                        "document": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
                        "sections": {"type": "object", "additionalProperties": {"type": "string"}}
                    }
                }
            },
            "x-busbar-secret-position": {
                "type": "object",
                "required": ["set", "secret_ref"],
                "properties": {
                    "set": {"type": "boolean"},
                    "secret_ref": {"type": ["string", "null"], "description": "The reference text (`env:VAR`, `file:/path`, a secret module) when configured as one; null for an inline value"}
                }
            }
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum View {
    Declared,
    Effective,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Layer {
    Base,
    Overlay,
    Merged,
}

impl Layer {
    fn as_str(self) -> &'static str {
        match self {
            Layer::Base => "base",
            Layer::Overlay => "overlay",
            Layer::Merged => "merged",
        }
    }
}

struct TreeQuery {
    view: View,
    layer: Layer,
    section: Option<Vec<String>>,
}

fn invalid(what: &str) -> Response {
    err_json_cond(
        &AdminError::Validation(format!("invalid `{what}`")),
        Cond::InvalidQueryValue,
    )
}

impl TreeQuery {
    fn read(q: &HashMap<String, String>) -> Result<Self, Response> {
        if let Some(unknown) = q.keys().find(|k| !PARAMS.contains(&k.as_str())) {
            return Err(invalid(&format!(
                "{unknown}: /config/tree takes view, layer and section"
            )));
        }
        let view = match q.get("view").map(String::as_str) {
            None | Some("effective") => View::Effective,
            Some("declared") => View::Declared,
            Some(_) => return Err(invalid("view: expected declared|effective")),
        };
        let layer = match q.get("layer").map(String::as_str) {
            None | Some("merged") => Layer::Merged,
            Some("base") => Layer::Base,
            Some("overlay") => Layer::Overlay,
            Some(_) => return Err(invalid("layer: expected base|overlay|merged")),
        };
        if view == View::Effective && layer != Layer::Merged {
            return Err(invalid(
                "layer: the effective view is the resolved generation and has no layers; use \
                 view=declared to read the base or overlay layer",
            ));
        }
        let section = match q.get("section") {
            None => None,
            Some(dotted) => {
                let path: Vec<String> = dotted.split('.').map(str::to_owned).collect();
                if path.iter().any(String::is_empty) {
                    return Err(invalid(
                        "section: expected a dotted key such as limits.request_body_max_bytes",
                    ));
                }
                Some(path)
            }
        };
        Ok(Self {
            view,
            layer,
            section,
        })
    }
}

/// `GET /config/tree`.
pub(crate) async fn get(
    State(handle): State<Arc<AppHandle>>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let query = match TreeQuery::read(&q) {
        Ok(query) => query,
        Err(response) => return response,
    };
    let app = super::response_snapshot(handle.load()).await;
    let sugars = app
        .grammar
        .get()
        .map(|grammar| grammar.sugars.clone())
        .unwrap_or_default();
    let public = busbar_kernel::config::settings_public::public;
    let rule = Rule {
        sugars: &sugars,
        public: &public,
    };
    let mut body = Map::new();
    body.insert(
        "view",
        Value::from(match query.view {
            View::Declared => "declared",
            View::Effective => "effective",
        }),
    );
    body.insert("layer", Value::from(query.layer.as_str()));
    body.insert("config_version", Value::from(app.config_version));
    body.insert(
        "config_generation",
        Value::from(
            app.config_generation
                .load(std::sync::atomic::Ordering::Acquire),
        ),
    );
    let section = query.section.as_deref();
    let filtered = match query.view {
        View::Effective => effective(&app, &rule, section, &mut body),
        View::Declared => declared(&app, &rule, query.layer, section, &mut body).await,
    };
    if let Err(missing) = filtered {
        return err_json_cond(
            &AdminError::not_found(format!("config section `{missing}`")),
            Cond::UnknownResource,
        );
    }
    match busbar_contract::json::to_vec(&Value::from(body)) {
        Ok(bytes) => (
            StatusCode::OK,
            [(CONTENT_TYPE, busbar_contract::protocol::APPLICATION_JSON)],
            bytes,
        )
            .into_response(),
        Err(_) => err_json(&AdminError::Internal),
    }
}

/// Run `read` under the secret rule of `app`'s generation: the shorthand it admits and the plugin
/// settings each module declares public.
pub(super) fn under_rule<R>(app: &App, read: impl FnOnce(&Rule<'_>) -> R) -> R {
    let sugars = app
        .grammar
        .get()
        .map(|grammar| grammar.sugars.clone())
        .unwrap_or_default();
    let public = busbar_kernel::config::settings_public::public;
    read(&Rule {
        sugars: &sugars,
        public: &public,
    })
}

/// The resolved generation's sections under the secret rule, `process` among them: what the
/// effective tree serves and what `/kinds` describes every instance's `config` from.
pub(super) fn projected_sections(app: &App, rule: &Rule<'_>) -> Map {
    let (configuration, _) = super::config_document::configuration_and_restart(app);
    let mut configuration = foreign(&configuration);
    rule.project(&mut configuration);
    let mut sections = Map::new();
    if let Some(read) = configuration
        .get("values")
        .and_then(|values| values.get("sections"))
        .and_then(|s| s.as_object())
    {
        for (name, member) in read.iter() {
            sections.insert(name, member.clone());
        }
    }
    let mut process = process(app);
    rule.project(&mut process);
    sections.insert("process", process);
    sections
}

/// The resolved generation: the kernel's readback sections and `process`.
fn effective(
    app: &App,
    rule: &Rule<'_>,
    section: Option<&[String]>,
    body: &mut Map,
) -> Result<(), String> {
    let (configuration, restart) = super::config_document::configuration_and_restart(app);
    let mut configuration = foreign(&configuration);
    rule.project(&mut configuration);
    let state = configuration
        .get("state")
        .and_then(|s| s.as_str())
        .unwrap_or("unavailable")
        .to_owned();
    body.insert("state", Value::from(state.as_str()));
    let mut sections = Map::new();
    if let Some(values) = configuration.get("values").and_then(|v| v.as_object()) {
        for key in ["meaning", "unavailable_from_resolved"] {
            if let Some(member) = values.get(&key) {
                body.insert(key, member.clone());
            }
        }
        if let Some(read) = values.get(&"sections").and_then(|s| s.as_object()) {
            for (name, member) in read.iter() {
                sections.insert(name, member.clone());
            }
        }
    }
    let mut process = process(app);
    rule.project(&mut process);
    sections.insert("process", process);
    body.insert(
        "reload_to_apply",
        Value::from(
            restart
                .iter()
                .map(|s| Value::from(s.as_str()))
                .collect::<Vec<_>>(),
        ),
    );
    body.insert("digest", digest(&sections));
    body.insert("sections", select(sections, section)?);
    Ok(())
}

/// The configuration as written, by layer.
async fn declared(
    app: &App,
    rule: &Rule<'_>,
    layer: Layer,
    section: Option<&[String]>,
    body: &mut Map,
) -> Result<(), String> {
    let mut layers = Map::new();
    let mut found = section.is_none();
    if matches!(layer, Layer::Base | Layer::Merged) {
        let mut base = base_layer(app, rule).await;
        found |= narrow(&mut base, section);
        layers.insert("base", base);
    }
    if matches!(layer, Layer::Overlay | Layer::Merged) {
        let mut overlay = overlay_layer(app, rule).await;
        found |= narrow(&mut overlay, section);
        layers.insert("overlay", overlay);
    }
    body.insert("layers", Value::from(layers));
    if found {
        Ok(())
    } else {
        Err(section.map(|s| s.join(".")).unwrap_or_default())
    }
}

/// Narrow one layer's `sections` to `section`; whether the layer holds it. A layer that is not
/// available holds nothing and is left as it is.
fn narrow(layer: &mut Value, section: Option<&[String]>) -> bool {
    let Some(path) = section else {
        return true;
    };
    let Some(members) = layer.as_object_mut() else {
        return false;
    };
    let Some(sections) = members.remove(&"sections") else {
        return false;
    };
    let Some(sections) = sections.into_object() else {
        return false;
    };
    match select(sections, Some(path)) {
        Ok(narrowed) => {
            members.insert("sections", narrowed);
            true
        }
        Err(_) => {
            members.insert("sections", Value::from(Map::new()));
            false
        }
    }
}

/// The operator's file as it stands on disk, read as YAML (JSON is YAML).
async fn base_layer(app: &App, rule: &Rule<'_>) -> Value {
    let Some(path) = app.config_path.clone() else {
        return state(
            "unavailable",
            "this process was not started from a configuration file",
        );
    };
    let read = tokio::task::spawn_blocking(move || std::fs::read(path)).await;
    let Ok(Ok(bytes)) = read else {
        return state("unavailable", "the configuration file could not be read");
    };
    // The file may hold inline credentials: the text is wiped once the tree is projected.
    let text = busbar_contract::secure::SecureVec::from(bytes);
    let Ok(text) = std::str::from_utf8(&text) else {
        return state("unavailable", "the configuration file is not UTF-8");
    };
    let Ok(mut document) = busbar_contract::yaml::from_str::<Value>(text) else {
        return state(
            "unavailable",
            "the configuration file does not parse as written",
        );
    };
    rule.project(&mut document);
    let Some(sections) = document.into_object() else {
        return state("unavailable", "the configuration file is not a mapping");
    };
    let mut base = Map::new();
    base.insert("state", Value::from("available"));
    base.insert("source", Value::from("file"));
    base.insert("digest", digest(&sections));
    base.insert("sections", Value::from(sections));
    Value::from(base)
}

/// The Store overlay: per-section documents, tombstones, the paths a document patch edits (never
/// its values), and the overlay version.
async fn overlay_layer(app: &App, rule: &Rule<'_>) -> Value {
    let Some(store) = app.overlay_path.as_deref() else {
        return state("absent", "this busbar has no Store-backed config overlay");
    };
    let doc = match store.read_required_async().await {
        Ok(Some(doc)) => doc,
        Ok(None) => return state("absent", "the Store holds no config overlay"),
        Err(_) => return state("unavailable", "the Store could not read the config overlay"),
    };
    let seal = busbar_kernel::seal::acquire();
    #[derive(serde::Serialize)]
    struct Written<'a, H: serde::Serialize, R: serde::Serialize, N: serde::Serialize> {
        hooks: H,
        global_hooks: &'a [String],
        deleted: &'a [String],
        groups: &'a BTreeMap<String, busbar_kernel::config::GroupCfg>,
        deleted_groups: &'a [String],
        root: Option<R>,
        plugin_versions: &'a BTreeMap<String, String>,
        named_maps: &'a N,
    }
    let written = Written {
        hooks: doc
            .hooks
            .iter()
            .map(|(name, hook)| (name, hook.authoring(&seal)))
            .collect::<BTreeMap<_, _>>(),
        global_hooks: &doc.global_hooks,
        deleted: &doc.deleted,
        groups: &doc.groups,
        deleted_groups: &doc.deleted_groups,
        root: doc.root.as_ref().map(|root| root.authoring(&seal)),
        plugin_versions: &doc.plugin_versions,
        named_maps: &doc.named_maps,
    };
    let Ok(bytes) = busbar_contract::json::to_vec(&written) else {
        return state("unavailable", "the config overlay could not be read back");
    };
    let bytes = busbar_contract::secure::SecureVec::from(bytes);
    let Ok(mut document) = busbar_contract::json::parse_value(&bytes) else {
        return state("unavailable", "the config overlay could not be read back");
    };
    rule.project(&mut document);
    let Some(mut sections) = document.into_object() else {
        return state("unavailable", "the config overlay could not be read back");
    };
    for (key, patch) in [
        ("document_patch", doc.document_patch.as_ref()),
        ("providers_patch", doc.providers_patch.as_ref()),
    ] {
        if let Some(patch) = patch {
            let paths: Vec<Value> = patch.paths().map(Value::from).collect();
            let mut shown = Map::new();
            shown.insert("paths", Value::from(paths));
            shown.insert("values", Value::from("hidden"));
            sections.insert(key, Value::from(shown));
        }
    }
    let mut overlay = Map::new();
    overlay.insert("state", Value::from("available"));
    overlay.insert("source", Value::from("store"));
    overlay.insert("version", Value::from(doc.version));
    overlay.insert("digest", digest(&sections));
    overlay.insert("sections", Value::from(sections));
    Value::from(overlay)
}

/// The command-line and environment inputs the process read (COV §1 rows 74-81). Paths and every
/// input that can carry a credential show presence only; the rest show their value.
fn process(app: &App) -> Value {
    fn input(name: &str, source: &str, set: bool, value: Option<Value>) -> Value {
        let mut row = Map::new();
        row.insert("name", Value::from(name));
        row.insert("source", Value::from(source));
        row.insert("set", Value::from(set));
        row.insert(
            "shown",
            Value::from(if value.is_some() { "value" } else { "presence" }),
        );
        row.insert("value", value.unwrap_or_else(Value::new_null));
        Value::from(row)
    }
    let env_set = |name: &str| std::env::var_os(name).is_some();
    let env_value = |name: &str| std::env::var(name).ok().map(|v| Value::from(v.as_str()));
    let mut inputs = vec![
        input(
            "--config",
            "flag_or_env BUSBAR_CONFIG",
            app.config_path.is_some(),
            None,
        ),
        input(
            "--providers",
            "flag_or_env BUSBAR_PROVIDERS",
            app.providers_override.is_some(),
            None,
        ),
        input(
            "--ignore-overlay",
            "flag",
            busbar_kernel::appbuild::booted_with_ignore_overlay(),
            Some(Value::from(
                busbar_kernel::appbuild::booted_with_ignore_overlay(),
            )),
        ),
    ];
    for name in ["BUSBAR_CONFIG_OVERLAY", "BUSBAR_DATA_DIR"] {
        inputs.push(input(name, "env", env_set(name), None));
    }
    for name in [
        "BUSBAR_UPSTREAM_HTTP1_ONLY",
        "BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE",
        "BUSBAR_PROFILE",
        "BUSBAR_TIMING",
        "BUSBAR_INCREMENTAL_SCAN",
        "RUST_LOG",
    ] {
        inputs.push(input(name, "env", env_set(name), env_value(name)));
    }
    let mut process = Map::new();
    process.insert("inputs", Value::from(inputs));
    Value::from(process)
}

/// A layer that is not served, and why.
fn state(state: &str, why: &str) -> Value {
    let mut shown = Map::new();
    shown.insert("state", Value::from(state));
    shown.insert("reason", Value::from(why));
    Value::from(shown)
}

/// AR-20: `sha256` over the whole projected document and over each projected section.
fn digest(sections: &Map) -> Value {
    let mut by_section = Map::new();
    for (name, member) in sections.iter() {
        let bytes = busbar_contract::json::to_vec(member).unwrap_or_default();
        by_section.insert(
            name,
            Value::from(
                format!("sha256:{}", busbar_contract::redacted::sha256_hex(&bytes)).as_str(),
            ),
        );
    }
    let whole = busbar_contract::json::to_vec(sections).unwrap_or_default();
    let mut digest = Map::new();
    digest.insert(
        "document",
        Value::from(format!("sha256:{}", busbar_contract::redacted::sha256_hex(&whole)).as_str()),
    );
    digest.insert("sections", Value::from(by_section));
    Value::from(digest)
}

/// `sections` narrowed to the dotted `section`, nested as it sits in the document; `Err` names the
/// key that is not there.
fn select(sections: Map, section: Option<&[String]>) -> Result<Value, String> {
    let Some(path) = section else {
        return Ok(Value::from(sections));
    };
    let whole = Value::from(sections);
    let mut at = &whole;
    for key in path {
        at = at.get(key.as_str()).ok_or_else(|| path.join("."))?;
    }
    let mut narrowed = at.clone();
    for key in path.iter().rev() {
        let mut parent = Map::new();
        parent.insert(key.as_str(), narrowed);
        narrowed = Value::from(parent);
    }
    Ok(narrowed)
}

/// The kernel's readback value as this crate's JSON tree.
pub(super) fn foreign<T: serde::Serialize>(value: &T) -> Value {
    busbar_contract::json::to_vec(value)
        .ok()
        .and_then(|bytes| busbar_contract::json::parse_value(&bytes).ok())
        .unwrap_or_else(|| {
            let mut empty = Map::new();
            empty.insert("state", Value::from("unavailable"));
            Value::from(empty)
        })
}
