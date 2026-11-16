// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Discovery, the kind-generic surface (ADMIN-API-1.6 §5; owner direction CD-4, Console DISC).
//!
//! ```text
//! GET /kinds                                      what exists
//! GET /kinds/{kind}/instances                     what is running
//! GET /kinds/{kind}/instances/{id}                describe
//! GET /kinds/{kind}/instances/{id}/views/{view}   generic data
//! ```
//!
//! THE API SPEAKS KINDS (ARC-1, CON-6). `category` is the engine kind (the seven plugin kinds, plus
//! `core` for core's own subsystems); `kind` is the id a client routes on: a plane's registry key,
//! otherwise the category itself. Instances are read off the configuration each kind is configured
//! under ([`Kind::root`]) and off the plane registry, never off a plugin name: the plugin an
//! instance runs appears only as data, in its `plugin` member.
//!
//! Every `config` passes through the secret rule (§14.2). `/info.kinds_revision` is the `/kinds`
//! ETag: a digest over every (category, kind, instance, image, config digest), kept once per
//! generation.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use busbar_contract::json::{JsonContainerTrait, JsonValueTrait, Map, Value};
use busbar_contract::plugin::Kind;
use busbar_kernel::plane_driver::registry::PlaneDecl;
use busbar_kernel::state::{App, AppHandle};

use super::views::{self, Descriptor};
use super::{err_json, err_json_cond};
use crate::admin_state::AppAdmin as _;
use crate::v1::contract::taxonomy::Cond;
use crate::v1::contract::{AdminError, LIST_LIMIT_DEFAULT};

/// The closed category list (§5.2): the seven engine kinds and `core`.
pub(crate) const CATEGORIES: [&str; 8] = [
    "plane",
    "auth",
    "store",
    "secret",
    "export",
    "hook",
    "transport",
    "core",
];

/// What each core instance's `config` holds: the effective sections of its subsystem (§5.7).
const CORE_SECTIONS: [(&str, &[&str]); 9] = [
    (
        "process",
        &[
            "process",
            "listen",
            "public_url",
            "admin_listen",
            "tls",
            "admin_tls",
            "admin_require_mtls",
            "advanced",
            "security",
            "config",
            "providers_file",
            "plugins",
        ],
    ),
    (
        "routing",
        &[
            "models",
            "providers",
            "pools",
            "provider_catalog",
            "routing",
            "health",
            "plane_sections",
        ],
    ),
    ("units", &["global_hooks"]),
    ("limits", &["groups", "limits", "export_limits"]),
    ("ledger", &["per_request_fee", "rate_card"]),
    ("credentials", &["auth", "credentials", "oauth_as"]),
    ("durability", &[]),
    ("connector", &[]),
    ("trust", &[]),
];

/// The query parameters each read takes; any other is refused.
const LIST_PARAMS: &[&str] = &["category", "cursor", "limit"];
const PAGE_PARAMS: &[&str] = &["cursor", "limit"];
const VIEW_PARAMS: &[&str] = &["from_ms", "to_ms", "step_s", "filter", "cursor", "limit"];

/// One instance, as discovery reads it.
pub(crate) struct Instance {
    pub(crate) category: &'static str,
    pub(crate) kind: String,
    pub(crate) id: String,
    /// The module the operator configured it with: data, read for `plugin{}` and the image only.
    module: Option<String>,
    /// Its configuration under the secret rule.
    pub(crate) config: Value,
    plane: Option<&'static PlaneDecl>,
}

/// The category word of a plugin kind.
fn category_of(kind: Kind) -> &'static str {
    match kind {
        Kind::Plane => "plane",
        Kind::Transport => "transport",
        Kind::Auth => "auth",
        Kind::Store => "store",
        Kind::Secret => "secret",
        Kind::Hook => "hook",
        Kind::Export => "export",
    }
}

/// A plane's kind id: its registry key, folded to `[a-z][a-z0-9_]{0,31}`.
pub(crate) fn plane_kind(key: &str) -> String {
    let mut id: String = key
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .take(32)
        .collect();
    if !id.starts_with(|c: char| c.is_ascii_lowercase()) {
        id.insert(0, 'p');
        id.truncate(32);
    }
    id
}

fn module_of(config: &Value) -> Option<String> {
    config
        .get("module")
        .and_then(|m| m.as_str())
        .map(str::to_owned)
}

/// Every instance of the running generation, in (category, kind, id) order.
pub(crate) fn inventory(app: &App) -> Vec<Instance> {
    let sections = super::config_tree::under_rule(app, |rule| {
        super::config_tree::projected_sections(app, rule)
    });
    let mut out = Vec::new();
    for kind in Kind::ALL {
        let category = category_of(kind);
        match kind {
            Kind::Plane => {
                for decl in busbar_kernel::plane_driver::registry::plane_decls() {
                    if !app.plane_configured(decl) {
                        continue;
                    }
                    out.push(Instance {
                        category,
                        kind: plane_kind(decl.key),
                        id: decl.key.to_owned(),
                        module: None,
                        config: plane_config(&sections, decl),
                        plane: Some(decl),
                    });
                }
            }
            Kind::Store => {
                if let Some(store) = sections.get(&"store").filter(|s| s.is_object()) {
                    out.push(Instance {
                        category,
                        kind: category.to_owned(),
                        id: category.to_owned(),
                        module: module_of(store),
                        config: store.clone(),
                        plane: None,
                    });
                }
            }
            _ => {
                let Some(named) = sections.get(&kind.root()).and_then(|s| s.as_object()) else {
                    continue;
                };
                for (id, config) in named.iter() {
                    out.push(Instance {
                        category,
                        kind: category.to_owned(),
                        id: id.to_owned(),
                        module: module_of(config),
                        config: config.clone(),
                        plane: None,
                    });
                }
            }
        }
    }
    for (id, held) in CORE_SECTIONS {
        let mut config = Map::new();
        for section in held {
            if let Some(value) = sections.get(section) {
                config.insert(section, value.clone());
            }
        }
        out.push(Instance {
            category: "core",
            kind: "core".to_owned(),
            id: id.to_owned(),
            module: None,
            config: Value::from(config),
            plane: None,
        });
    }
    // Ordered by (kind, id) through an ordered container: no sort on the request path.
    out.into_iter()
        .map(|i| ((i.kind.clone(), i.id.clone()), i))
        .collect::<std::collections::BTreeMap<_, _>>()
        .into_values()
        .collect()
}

/// A plane's configuration: its declaring section and the sections it owns, as the generation
/// reads them back.
fn plane_config(sections: &Map, decl: &PlaneDecl) -> Value {
    let mut config = Map::new();
    for section in std::iter::once(&decl.config_section).chain(decl.owned_config_sections) {
        let value = sections.get(section).cloned().or_else(|| {
            sections
                .get(&"plane_sections")
                .and_then(|p| p.get(*section))
                .cloned()
        });
        if let Some(value) = value {
            config.insert(*section, value);
        }
    }
    Value::from(config)
}

fn sha(bytes: &[u8]) -> String {
    busbar_contract::redacted::sha256_hex(bytes)
}

fn digest_of(value: &Value) -> String {
    sha(&busbar_contract::json::to_vec(value).unwrap_or_default())
}

/// The image an instance runs, by the SHA-256 of its admitted archive, else its version.
fn image(app: &App, instance: &Instance) -> String {
    let Some(module) = instance.module.as_deref() else {
        return String::new();
    };
    let registry = &app.hook_env.registry;
    registry
        .archive_sha256(module)
        .or_else(|| registry.resolve(module).map(|row| row.version))
        .unwrap_or_default()
}

/// An instance's revision: what its list row's ETag and the deployment's `kinds_revision` are
/// built from.
fn revision(app: &App, instance: &Instance) -> String {
    sha(format!(
        "{}\n{}\n{}\n{}\n{}",
        instance.category,
        instance.kind,
        instance.id,
        image(app, instance),
        digest_of(&instance.config)
    )
    .as_bytes())
}

/// The digest over every instance of `app`: `/info.kinds_revision` and the `/kinds` ETag.
fn compute_revision(app: &App) -> String {
    let instances = inventory(app);
    let mut text = String::new();
    for kind in kinds_of(&instances) {
        text.push_str(&kind.0);
        text.push('\n');
    }
    for instance in &instances {
        text.push_str(&revision(app, instance));
        text.push('\n');
    }
    sha(text.as_bytes())[..32].to_owned()
}

/// `kinds_revision` for `app`'s generation, computed once per generation and kept.
pub(crate) fn kinds_revision(app: &App) -> String {
    let at = (
        app.config_generation
            .load(std::sync::atomic::Ordering::Acquire),
        app.config_version,
    );
    let kept = &app.admin_state().kinds_revision;
    if let Some((when, revision)) = kept
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
    {
        if *when == at {
            return revision.clone();
        }
    }
    let revision = compute_revision(app);
    *kept
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((at, revision.clone()));
    revision
}

/// Every kind that exists: each category's own kind, and one per registered plane. `(kind,
/// category)`, in kind order.
fn kinds_of(instances: &[Instance]) -> Vec<(String, &'static str)> {
    let mut kinds: std::collections::BTreeMap<String, &'static str> = CATEGORIES
        .iter()
        .filter(|c| **c != "plane")
        .map(|c| ((*c).to_owned(), *c))
        .collect();
    for decl in busbar_kernel::plane_driver::registry::plane_decls() {
        kinds.insert(plane_kind(decl.key), "plane");
    }
    for instance in instances {
        kinds.insert(instance.kind.clone(), instance.category);
    }
    kinds.into_iter().collect()
}

/// The views an instance offers. Core's routing subsystem serves its pools; the rest of core's
/// views arrive with the core instances (MR15) and plugin views with MIN-3 (MR16).
fn views_of(instance: &Instance) -> Vec<Descriptor> {
    if instance.category != "core" || instance.id != "routing" {
        return Vec::new();
    }
    let (kept, dropped) = views::admitted(&[pools_descriptor()]);
    debug_assert!(
        dropped.is_empty(),
        "core's own descriptors are valid: {}",
        dropped
            .iter()
            .map(|why| why.0.as_str())
            .collect::<Vec<_>>()
            .join("; ")
    );
    kept
}

fn pools_descriptor() -> Value {
    busbar_contract::json::json!({
        "view": "pools",
        "title": "Pool members",
        "shape": "table",
        "fields": [
            {"name": "pool", "label": "Pool", "type": "string", "unit": null, "format": null, "role": "dimension"},
            {"name": "model", "label": "Model", "type": "string", "unit": null, "format": null, "role": "id"},
            {"name": "weight", "label": "Weight", "type": "int", "unit": "count", "format": null, "role": "measure"},
            {"name": "usable", "label": "Usable", "type": "bool", "unit": null, "format": null, "role": "status"},
            {"name": "cooldown_remaining_seconds", "label": "Cooldown left", "type": "int", "unit": "s", "format": null, "role": "measure"},
            {"name": "available_concurrency", "label": "Free slots", "type": "int", "unit": "count", "format": null, "role": "measure"},
            {"name": "inflight", "label": "In flight", "type": "int", "unit": "count", "format": null, "role": "measure"},
            {"name": "latency_ms", "label": "Latency", "type": "float", "unit": "ms", "format": null, "role": "measure"},
            {"name": "ok", "label": "Succeeded", "type": "int", "unit": "count", "format": null, "role": "measure"},
            {"name": "err", "label": "Failed", "type": "int", "unit": "count", "format": null, "role": "measure"},
            {"name": "dead", "label": "Dead", "type": "bool", "unit": null, "format": null, "role": "status"},
            {"name": "trip_count", "label": "Trips", "type": "int", "unit": "count", "format": null, "role": "measure"},
            {"name": "last_trip_at", "label": "Last trip", "type": "time", "unit": null, "format": null, "role": "time"}
        ],
        "default_sort": "pool",
        "filters": ["pool", "model"],
        "time": null,
        "step_options": []
    })
}

/// The source rows of one view, as objects keyed by field name.
async fn view_items(app: Arc<App>, instance: &Instance, view: &str) -> Result<Vec<Value>, ()> {
    if instance.category == "core" && instance.id == "routing" && view == "pools" {
        let pools = crate::v1::service::AdminService::new(app)
            .list_pools_detailed()
            .await
            .map_err(|_| ())?;
        let mut rows = Vec::new();
        for pool in pools.items {
            let pool = super::config_tree::foreign(&pool);
            let name = pool.get("name").cloned().unwrap_or_default();
            for member in pool
                .get("members")
                .and_then(|m| m.as_array())
                .map(|m| m.to_vec())
                .unwrap_or_default()
            {
                let mut row = member.into_object().unwrap_or_default();
                row.insert("pool", name.clone());
                if let Some(at) = row.get(&"last_trip_at").and_then(|t| t.as_u64()) {
                    row.insert("last_trip_at", Value::from(at.saturating_mul(1000)));
                }
                rows.push(Value::from(row));
            }
        }
        return Ok(rows);
    }
    Err(())
}

fn plugin_of(app: &App, instance: &Instance) -> Value {
    if instance.category == "core" {
        return Value::new_null();
    }
    let module = match (&instance.module, instance.plane) {
        (Some(module), _) => module.as_str(),
        (None, Some(decl)) => decl.key,
        (None, None) => return Value::new_null(),
    };
    let row = app.hook_env.registry.resolve(module);
    let mut plugin = Map::new();
    plugin.insert(
        "name",
        Value::from(row.as_ref().map_or(module, |r| r.name.as_str())),
    );
    plugin.insert(
        "version",
        row.as_ref()
            .map_or_else(Value::new_null, |r| Value::from(r.version.as_str())),
    );
    plugin.insert(
        "publisher",
        match row.as_ref().map(|r| &r.trust) {
            Some(busbar_contract::plugin_rows::Trust::Trusted { publisher, .. }) => {
                Value::from(publisher.as_str())
            }
            _ => Value::new_null(),
        },
    );
    plugin.insert("key_fingerprint", Value::new_null());
    Value::from(plugin)
}

/// The admission check core holds for a plugin instance: whether its module resolved to an
/// admitted row (or is built in), and if a skipped plugin matches it, why it was skipped.
fn admission(app: &App, instance: &Instance) -> (&'static str, Value) {
    let Some(module) = instance.module.as_deref() else {
        return ("ok", Value::new_null());
    };
    let registry = &app.hook_env.registry;
    if registry.resolve(module).is_some() {
        return ("ok", Value::from("admitted"));
    }
    match registry.unresolved_reason(module) {
        Some(skipped) => (
            "failed",
            Value::from(format!("not admitted: {}", skipped.code).as_str()),
        ),
        None => ("ok", Value::from("built in")),
    }
}

fn now_secs() -> u64 {
    busbar_kernel::store::now()
}

fn health_row(check: &str, status: &str, detail: Value) -> Value {
    let mut row = Map::new();
    row.insert("check", Value::from(check));
    row.insert("status", Value::from(status));
    // The checks core holds are facts of the running generation, observed when it started.
    row.insert(
        "observed_at",
        Value::from(crate::v1::service::started_at().unwrap_or(0)),
    );
    row.insert("detail", detail);
    row.insert("text", Value::new_null());
    row.insert("plugin_diag", Value::new_null());
    Value::from(row)
}

fn health_of(app: &App, instance: &Instance) -> Vec<Value> {
    if instance.category == "core" {
        return Vec::new();
    }
    let (status, detail) = admission(app, instance);
    let mut health = vec![health_row("admission", status, detail)];
    if instance.category == "store" {
        health.push(health_row(
            "store",
            "ok",
            Value::from("serving this generation"),
        ));
    }
    health
}

/// The list row's `state`: core's word for the instance, from its health checks.
fn status_of(app: &App, instance: &Instance) -> Value {
    let failed = health_of(app, instance)
        .iter()
        .any(|check| check.get("status").and_then(|s| s.as_str()) == Some("failed"));
    let mut state = Map::new();
    state.insert("status", Value::from(if failed { "failed" } else { "ok" }));
    state.insert(
        "since",
        Value::from(crate::v1::service::started_at().unwrap_or(0)),
    );
    if failed {
        let mut reason = Map::new();
        reason.insert("code", Value::from("admission"));
        reason.insert(
            "message",
            Value::from("the instance's plugin is not admitted"),
        );
        reason.insert("text", Value::new_null());
        reason.insert("plugin_diag", Value::new_null());
        state.insert("reason", Value::from(reason));
    } else {
        state.insert("reason", Value::new_null());
    }
    Value::from(state)
}

/// The instance's `D_SCHEMA`, as declared, with `x-sensitive: true` beside every
/// `x-busbar-secret`.
fn config_schema(app: &App, instance: &Instance) -> Value {
    let Some(module) = instance.module.as_deref() else {
        return Value::new_null();
    };
    let Some(text) = app
        .hook_env
        .registry
        .resolve(module)
        .and_then(|row| row.settings_schema)
    else {
        return Value::new_null();
    };
    let Ok(mut schema) = busbar_contract::json::parse_value(text.as_bytes()) else {
        return Value::new_null();
    };
    mark_sensitive(&mut schema);
    schema
}

fn mark_sensitive(schema: &mut Value) {
    use busbar_contract::json::JsonValueMutTrait;
    if let Some(items) = schema.as_array_mut() {
        for item in items.iter_mut() {
            mark_sensitive(item);
        }
        return;
    }
    let Some(members) = schema.as_object_mut() else {
        return;
    };
    let secret = members
        .get(&"x-busbar-secret")
        .is_some_and(|s| s.as_bool() != Some(false) && !s.is_null());
    for (_, member) in members.iter_mut() {
        mark_sensitive(member);
    }
    if secret {
        members.insert("x-sensitive", Value::from(true));
    }
}

/// Links (§5.3): every position the schema annotates `x-busbar-ref: <category>` names a related
/// instance `{kind, id}`. Core knows only categories.
pub(crate) fn links(schema: &Value, config: &Value) -> Vec<Value> {
    let mut out = Vec::new();
    walk_links(schema, config, &mut out);
    out
}

fn walk_links(schema: &Value, config: &Value, out: &mut Vec<Value>) {
    if let Some(category) = schema.get("x-busbar-ref").and_then(|c| c.as_str()) {
        if CATEGORIES.contains(&category) {
            let ids: Vec<&str> = match config.as_array() {
                Some(items) => items.iter().filter_map(|i| i.as_str()).collect(),
                None => config.as_str().into_iter().collect(),
            };
            for id in ids {
                let mut link = Map::new();
                link.insert("kind", Value::from(category));
                link.insert("id", Value::from(id));
                out.push(Value::from(link));
            }
            return;
        }
    }
    if let (Some(properties), Some(members)) = (
        schema.get("properties").and_then(|p| p.as_object()),
        config.as_object(),
    ) {
        for (name, sub) in properties.iter() {
            if let Some(value) = members.get(&name) {
                walk_links(sub, value, out);
            }
        }
    }
    if let (Some(items), Some(values)) = (schema.get("items"), config.as_array()) {
        for value in values.iter() {
            walk_links(items, value, out);
        }
    }
}

/// `runtime.plane` (§5.3): what core holds about a plane instance, read off the registry, the
/// serve tables and the refresh report.
pub(crate) fn plane_runtime(app: &App, decl: &PlaneDecl) -> Value {
    let routes: Vec<Value> = app
        .serve_tables
        .published()
        .into_iter()
        .filter(|(instance, _)| instance == decl.key)
        .flat_map(|(_, routes)| routes)
        .map(|route| {
            let mut row = Map::new();
            row.insert("verb", Value::from(route.verb.as_str()));
            row.insert("target", Value::from(route.target.as_str()));
            row.insert(
                "public",
                Value::from(route.flags & busbar_contract::abi::plane::ROUTE_PUBLIC != 0),
            );
            row.insert("audit_verb", Value::from(route.audit_verb.as_str()));
            Value::from(row)
        })
        .collect();
    let refresh = app
        .plane_refresh
        .snapshot()
        .planes
        .into_iter()
        .rev()
        .find(|p| p.plane == decl.key)
        .map_or_else(Value::new_null, |p| super::config_tree::foreign(&p));
    let mut plane = Map::new();
    plane.insert("facts", plane_facts(decl));
    plane.insert("routes", Value::from(routes));
    plane.insert("collisions", Value::from(Vec::<Value>::new()));
    plane.insert("claims", Value::from(Vec::<Value>::new()));
    plane.insert("last_refresh", refresh);
    plane.insert("egress", Value::from(Vec::<Value>::new()));
    Value::from(plane)
}

/// A plane's declaration (what `/plane-facts` served before 1.6.0).
pub(crate) fn plane_facts(decl: &busbar_kernel::plane_driver::registry::PlaneDeclaration) -> Value {
    let words =
        |list: &[&str]| Value::from(list.iter().map(|w| Value::from(*w)).collect::<Vec<_>>());
    let mut facts = Map::new();
    facts.insert("plane", Value::from(decl.key));
    facts.insert("fallback", Value::from(decl.fallback));
    facts.insert("config_section", Value::from(decl.config_section));
    facts.insert("owned_config_sections", words(decl.owned_config_sections));
    facts.insert("scope_kinds", words(decl.scope_kinds));
    facts.insert("subject_noun", Value::from(decl.subject_noun));
    facts.insert("admin_noun", Value::from(decl.admin_noun));
    facts.insert("audit_kind", Value::from(decl.audit_kind));
    facts.insert(
        "card_signing",
        Value::from(decl.card_signing_domain.is_some()),
    );
    facts.insert(
        "billable_classes",
        Value::from(
            decl.billable_classes
                .iter()
                .map(|c| {
                    let mut row = Map::new();
                    row.insert("class", Value::from(c.class));
                    row.insert("family", Value::from(c.family));
                    Value::from(row)
                })
                .collect::<Vec<_>>(),
        ),
    );
    facts.insert("fee_units", words(decl.fee_units));
    facts.insert(
        "metric_families",
        Value::from(
            decl.metric_families
                .iter()
                .map(|m| {
                    let mut row = Map::new();
                    row.insert("name", Value::from(m.name));
                    row.insert("kind", Value::from(m.kind));
                    row.insert("label_keys", words(m.label_keys));
                    Value::from(row)
                })
                .collect::<Vec<_>>(),
        ),
    );
    facts.insert(
        "served_op_classes",
        Value::from(
            decl.served_op_classes
                .iter()
                .map(|s| {
                    let mut row = Map::new();
                    row.insert("op", Value::from(s.op.as_str()));
                    row.insert("name", Value::from(s.name));
                    Value::from(row)
                })
                .collect::<Vec<_>>(),
        ),
    );
    facts.insert("record_kinds", words(decl.record_kinds));
    Value::from(facts)
}

/// `runtime` (§5.3): closed, core-written for every plugin instance, `null` for core's own.
/// Members core does not hold yet are `null` until MIN-3 (MR16).
fn runtime_of(app: &App, instance: &Instance) -> Value {
    if instance.category == "core" {
        return Value::new_null();
    }
    let mut runtime = Map::new();
    for member in [
        "settings",
        "watchdog",
        "crossings",
        "dispatch",
        "open",
        "records",
        "scrub",
    ] {
        runtime.insert(member, Value::new_null());
    }
    runtime.insert(
        "plane",
        instance
            .plane
            .map_or_else(Value::new_null, |decl| plane_runtime(app, decl)),
    );
    Value::from(runtime)
}

fn quoted(revision: &str) -> String {
    format!("\"{revision}\"")
}

/// A list row (§5.3): `id`, `name`, `plugin`, `state`, `labels`, `etag`.
fn list_row(app: &App, instance: &Instance) -> Value {
    let mut row = Map::new();
    row.insert("id", Value::from(instance.id.as_str()));
    row.insert("name", Value::from(instance.id.as_str()));
    row.insert("plugin", plugin_of(app, instance));
    row.insert("state", status_of(app, instance));
    row.insert("labels", Value::from(Map::new()));
    row.insert(
        "etag",
        Value::from(quoted(&revision(app, instance)[..32]).as_str()),
    );
    Value::from(row)
}

/// Describe (§5.3): exactly the list-row members and `config`, `config_schema`, `state`,
/// `state_schema`, `runtime`, `health`, `links`, `views`, `actions`. `state` and `state_schema`
/// are the instance's own answer: core writes nothing into them, and before MIN-3 (plugins) and
/// the core instances (MR15) there is none, so they are `null`.
pub(crate) fn describe_of(app: &App, instance: &Instance) -> Value {
    let Some(mut members) = list_row(app, instance).into_object() else {
        return Value::new_null();
    };
    let schema = config_schema(app, instance);
    let settings = instance
        .config
        .get("settings_public")
        .cloned()
        .unwrap_or_else(|| instance.config.clone());
    members.insert("config", instance.config.clone());
    members.insert("links", Value::from(links(&schema, &settings)));
    members.insert("config_schema", schema);
    members.insert("state", Value::new_null());
    members.insert("state_schema", Value::new_null());
    members.insert("runtime", runtime_of(app, instance));
    members.insert("health", Value::from(health_of(app, instance)));
    members.insert(
        "views",
        Value::from(
            views_of(instance)
                .into_iter()
                .map(|d| d.served)
                .collect::<Vec<_>>(),
        ),
    );
    members.insert("actions", Value::from(Vec::<Value>::new()));
    Value::from(members)
}

fn invalid(what: &str) -> Response {
    err_json_cond(
        &AdminError::Validation(format!("invalid `{what}`")),
        Cond::InvalidQueryValue,
    )
}

fn unknown(what: String) -> Response {
    err_json_cond(&AdminError::not_found(what), Cond::UnknownResource)
}

fn refuse_unknown(q: &HashMap<String, String>, allowed: &[&str]) -> Option<Response> {
    q.keys()
        .find(|k| !allowed.contains(&k.as_str()))
        .map(|k| invalid(&format!("{k}: this read takes {}", allowed.join(", "))))
}

fn send(value: &Value, etag: Option<&str>) -> Response {
    let Ok(bytes) = busbar_contract::json::to_vec(value) else {
        return err_json(&AdminError::Internal);
    };
    let mut response = (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            busbar_contract::protocol::APPLICATION_JSON,
        )],
        bytes,
    )
        .into_response();
    if let Some(value) = etag.and_then(|e| HeaderValue::from_str(e).ok()) {
        response.headers_mut().insert(header::ETAG, value);
    }
    response
}

/// Whether `If-None-Match` names `etag` (weakly compared) or is `*`.
fn not_modified(headers: &axum::http::HeaderMap, etag: &str) -> bool {
    headers
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|tag| tag.trim().trim_start_matches("W/"))
        .any(|tag| tag == "*" || tag == etag)
}

fn page(items: Vec<Value>, next_cursor: Option<String>) -> Value {
    let mut body = Map::new();
    body.insert("items", Value::from(items));
    body.insert(
        "next_cursor",
        next_cursor.map_or_else(Value::new_null, |c| Value::from(c.as_str())),
    );
    Value::from(body)
}

/// `GET /kinds[?category=]`.
pub(crate) async fn list(
    State(handle): State<Arc<AppHandle>>,
    headers: axum::http::HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if let Some(refused) = refuse_unknown(&q, LIST_PARAMS) {
        return refused;
    }
    let category = q.get("category").map(String::as_str);
    if category.is_some_and(|c| !CATEGORIES.contains(&c)) {
        return invalid(&format!(
            "category: expected one of {}",
            CATEGORIES.join(", ")
        ));
    }
    let filter = super::cursor::filter_digest(&q, &["category"]);
    let w = match super::cursor::window(&q, "kinds", &filter, LIST_LIMIT_DEFAULT) {
        Ok(w) => w,
        Err(response) => return *response,
    };
    let app = super::response_snapshot(handle.load()).await;
    let instances = inventory(&app);
    let rows: Vec<Value> = kinds_of(&instances)
        .into_iter()
        .filter(|(_, c)| category.is_none_or(|wanted| wanted == *c))
        .map(|(kind, category)| kind_row(&kind, category, &instances))
        .collect();
    let paged = super::cursor::keyset(
        rows,
        &w,
        "kinds",
        &filter,
        |row| {
            row.get("kind")
                .and_then(|k| k.as_str())
                .unwrap_or_default()
                .to_owned()
        },
        false,
    );
    let revision = quoted(&kinds_revision(&app));
    if not_modified(&headers, &revision) {
        let mut response = StatusCode::NOT_MODIFIED.into_response();
        if let Ok(value) = HeaderValue::from_str(&revision) {
            response.headers_mut().insert(header::ETAG, value);
        }
        return response;
    }
    send(&page(paged.items, paged.next_cursor), Some(&revision))
}

/// One `/kinds` row (§5.2).
fn kind_row(kind: &str, category: &'static str, instances: &[Instance]) -> Value {
    let mine: Vec<&Instance> = instances.iter().filter(|i| i.kind == kind).collect();
    let mut display = Map::new();
    display.insert("label", Value::from(kind));
    display.insert("plural", Value::from(kind));
    display.insert("description", Value::from(kind));
    let views: Vec<Vec<Descriptor>> = mine.iter().map(|i| views_of(i)).collect();
    let uniform = views
        .windows(2)
        .all(|pair| digest_views(&pair[0]) == digest_views(&pair[1]));
    let mut row = Map::new();
    row.insert("kind", Value::from(kind));
    row.insert("category", Value::from(category));
    row.insert("display", Value::from(display));
    row.insert("instance_count", Value::from(mine.len()));
    row.insert(
        "views",
        Value::from(match views.first() {
            Some(first) if uniform => first.iter().map(|d| d.served.clone()).collect(),
            _ => Vec::new(),
        }),
    );
    let mut attributes = Map::new();
    attributes.insert("type", Value::from("object"));
    row.insert("record_attributes", Value::from(attributes));
    row.insert("descriptors_uniform", Value::from(uniform));
    let digest = digest_of(&Value::from(row.clone()));
    row.insert("etag", Value::from(quoted(&digest[..32]).as_str()));
    Value::from(row)
}

fn digest_views(views: &[Descriptor]) -> String {
    digest_of(&Value::from(
        views.iter().map(|d| d.served.clone()).collect::<Vec<_>>(),
    ))
}

/// `GET /kinds/{kind}/instances`.
pub(crate) async fn instances(
    State(handle): State<Arc<AppHandle>>,
    Path(kind): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if let Some(refused) = refuse_unknown(&q, PAGE_PARAMS) {
        return refused;
    }
    let op = format!("kinds.{kind}");
    let w = match super::cursor::window(&q, &op, "", LIST_LIMIT_DEFAULT) {
        Ok(w) => w,
        Err(response) => return *response,
    };
    let app = super::response_snapshot(handle.load()).await;
    let all = inventory(&app);
    if !kinds_of(&all).iter().any(|(k, _)| *k == kind) {
        return unknown(format!("kind `{kind}`"));
    }
    let rows: Vec<Value> = all
        .iter()
        .filter(|i| i.kind == kind)
        .map(|i| list_row(&app, i))
        .collect();
    let paged = super::cursor::keyset(
        rows,
        &w,
        &op,
        "",
        |row| {
            row.get("id")
                .and_then(|k| k.as_str())
                .unwrap_or_default()
                .to_owned()
        },
        false,
    );
    send(&page(paged.items, paged.next_cursor), None)
}

fn find(all: Vec<Instance>, kind: &str, id: &str) -> Result<Instance, Box<Response>> {
    all.into_iter()
        .find(|i| i.kind == kind && i.id == id)
        .ok_or_else(|| Box::new(unknown(format!("instance `{kind}/{id}`"))))
}

/// `GET /kinds/{kind}/instances/{id}`.
pub(crate) async fn describe(
    State(handle): State<Arc<AppHandle>>,
    Path((kind, id)): Path<(String, String)>,
) -> Response {
    let app = super::response_snapshot(handle.load()).await;
    match find(inventory(&app), &kind, &id) {
        Ok(instance) => send(&describe_of(&app, &instance), None),
        Err(response) => *response,
    }
}

/// `GET /kinds/{kind}/instances/{id}/views/{view}?from_ms&to_ms&step_s&filter&cursor&limit`.
pub(crate) async fn view(
    State(handle): State<Arc<AppHandle>>,
    Path((kind, id, view)): Path<(String, String, String)>,
    Query(pairs): Query<Vec<(String, String)>>,
) -> Response {
    if let Some((name, _)) = pairs
        .iter()
        .find(|(n, _)| !VIEW_PARAMS.contains(&n.as_str()))
    {
        return invalid(&format!(
            "{name}: a view read takes {}",
            VIEW_PARAMS.join(", ")
        ));
    }
    for (name, value) in &pairs {
        if matches!(name.as_str(), "from_ms" | "to_ms" | "step_s") && value.parse::<u64>().is_err()
        {
            return invalid(&format!("{name}: expected a non-negative integer"));
        }
    }
    let q: HashMap<String, String> = pairs
        .iter()
        .filter(|(n, _)| n == "cursor" || n == "limit")
        .cloned()
        .collect();
    let filter = super::cursor::filter_digest_of_pairs(&pairs);
    let op = format!("view.{kind}.{id}.{view}");
    let w = match super::cursor::window(&q, &op, &filter, LIST_LIMIT_DEFAULT) {
        Ok(w) => w,
        Err(response) => return *response,
    };
    let app = super::response_snapshot(handle.load()).await;
    let instance = match find(inventory(&app), &kind, &id) {
        Ok(instance) => instance,
        Err(response) => return *response,
    };
    let Some(descriptor) = views_of(&instance).into_iter().find(|d| d.view == view) else {
        return unknown(format!("view `{view}` of `{kind}/{id}`"));
    };
    let filters = match views::filters(&descriptor, &pairs) {
        Ok(filters) => filters,
        Err(why) => return invalid(&why),
    };
    let Ok(items) = view_items(app.clone(), &instance, &view).await else {
        return err_json(&AdminError::Unavailable(format!(
            "view `{view}` of `{kind}/{id}` could not be read"
        )));
    };
    let rows: Vec<(String, Value)> = items
        .iter()
        .map(|item| views::row(&descriptor, item))
        .filter(|row| views::matches(row, &filters))
        .enumerate()
        .map(|(at, row)| {
            (
                super::cursor::numeric_key(u64::try_from(at).unwrap_or(u64::MAX)),
                row,
            )
        })
        .collect();
    let paged = super::cursor::keyset(rows, &w, &op, &filter, |(key, _)| key.clone(), false);
    let fields = descriptor
        .served
        .get("fields")
        .cloned()
        .unwrap_or_else(|| Value::from(Vec::<Value>::new()));
    let mut body = Map::new();
    body.insert("fields", fields);
    body.insert(
        "rows",
        Value::from(
            paged
                .items
                .into_iter()
                .map(|(_, row)| row)
                .collect::<Vec<_>>(),
        ),
    );
    body.insert(
        "next_cursor",
        paged
            .next_cursor
            .map_or_else(Value::new_null, |c| Value::from(c.as_str())),
    );
    body.insert("as_of", Value::from(now_secs().saturating_mul(1000)));
    send(&Value::from(body), None)
}

/// The documented shapes of the four discovery reads (the generated OpenAPI document).
#[cfg(feature = "openapi-schema")]
pub(crate) mod doc {
    /// The parameter objects of `names`, as the generated document carries them.
    pub(crate) fn query<T: serde::de::DeserializeOwned>(names: &[&str]) -> Vec<T> {
        names
            .iter()
            .filter_map(|name| {
                let text = match *name {
                    "category" => r#"{"name":"category","in":"query","required":false,"schema":{"type":"string","enum":["plane","auth","store","secret","export","hook","transport","core"]},"description":"Only the kinds of this category."}"#,
                    "cursor" => r#"{"name":"cursor","in":"query","required":false,"schema":{"type":"string"},"description":"Opaque continuation cursor from `next_cursor`."}"#,
                    "limit" => r#"{"name":"limit","in":"query","required":false,"schema":{"type":"integer","minimum":1,"maximum":1000},"description":"Page size (default 200, max 1000)."}"#,
                    "from_ms" => r#"{"name":"from_ms","in":"query","required":false,"schema":{"type":"integer","minimum":0},"description":"Window start, Unix milliseconds."}"#,
                    "to_ms" => r#"{"name":"to_ms","in":"query","required":false,"schema":{"type":"integer","minimum":0},"description":"Window end, Unix milliseconds."}"#,
                    "step_s" => r#"{"name":"step_s","in":"query","required":false,"schema":{"type":"integer","minimum":0},"description":"Bucket width in seconds, one of the view's `step_options`."}"#,
                    "filter" => r#"{"name":"filter","in":"query","required":false,"schema":{"type":"string","pattern":"^[^:]+:.*$"},"description":"`<field>:<value>`, repeatable: an exact match on a dimension or id field."}"#,
                    _ => return None,
                };
                busbar_contract::json::parse_foreign(text.as_bytes()).ok()
            })
            .collect()
    }

    macro_rules! documented {
        ($name:ident, $schema:tt) => {
            pub(crate) struct $name;

            impl schemars::JsonSchema for $name {
                fn schema_name() -> std::borrow::Cow<'static, str> {
                    stringify!($name).into()
                }

                fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
                    schemars::json_schema!($schema)
                }
            }
        };
    }

    documented!(KindsPage, {
        "type": "object",
        "required": ["items", "next_cursor"],
        "additionalProperties": false,
        "properties": {
            "items": {"type": "array", "items": {
                "type": "object",
                "additionalProperties": false,
                "required": ["kind", "category", "display", "instance_count", "views", "record_attributes", "descriptors_uniform", "etag"],
                "properties": {
                    "kind": {"type": "string", "pattern": "^[a-z][a-z0-9_]{0,31}$"},
                    "category": {"enum": ["plane", "auth", "store", "secret", "export", "hook", "transport", "core"]},
                    "display": {"type": "object", "required": ["label", "plural", "description"], "properties": {"label": {"type": "string"}, "plural": {"type": "string"}, "description": {"type": "string"}}},
                    "instance_count": {"type": "integer", "minimum": 0},
                    "views": {"type": "array", "items": {"type": "object", "description": "A view descriptor"}},
                    "record_attributes": {"type": "object", "description": "JSON Schema of the facts a record of this kind carries"},
                    "descriptors_uniform": {"type": "boolean"},
                    "etag": {"type": "string"}
                }
            }},
            "next_cursor": {"type": ["string", "null"]}
        }
    });

    documented!(InstancesPage, {
        "type": "object",
        "required": ["items", "next_cursor"],
        "additionalProperties": false,
        "properties": {
            "items": {"type": "array", "items": {
                "type": "object",
                "additionalProperties": false,
                "required": ["id", "name", "plugin", "state", "labels", "etag"],
                "properties": {
                    "id": {"type": "string"},
                    "name": {"type": "string"},
                    "plugin": {"type": ["object", "null"], "properties": {"name": {"type": "string"}, "version": {"type": ["string", "null"]}, "publisher": {"type": ["string", "null"]}, "key_fingerprint": {"type": ["string", "null"]}}},
                    "state": {"type": "object", "required": ["status", "since", "reason"], "properties": {
                        "status": {"enum": ["ok", "degraded", "failed", "disabled", "starting"]},
                        "since": {"type": "integer", "minimum": 0},
                        "reason": {"type": ["object", "null"]}
                    }},
                    "labels": {"type": "object", "additionalProperties": {"type": "string"}},
                    "etag": {"type": "string"}
                }
            }},
            "next_cursor": {"type": ["string", "null"]}
        }
    });

    documented!(Describe, {
        "type": "object",
        "additionalProperties": false,
        "required": ["id", "name", "plugin", "labels", "etag", "config", "config_schema", "state", "state_schema", "runtime", "health", "links", "views", "actions"],
        "properties": {
            "id": {"type": "string"},
            "name": {"type": "string"},
            "plugin": {"type": ["object", "null"]},
            "labels": {"type": "object", "additionalProperties": {"type": "string"}},
            "etag": {"type": "string"},
            "config": {"description": "The instance's configuration under the secret rule: a secret position is {set, secret_ref}"},
            "config_schema": {"type": ["object", "null"]},
            "state": {"description": "The instance's own state answer; null before it has one"},
            "state_schema": {"type": ["object", "null"]},
            "runtime": {"type": ["object", "null"], "description": "Closed and core-written for a plugin instance: settings, watchdog, crossings, dispatch, open, records, scrub, plane (each null where it does not apply); null for a core instance"},
            "health": {"type": "array", "items": {"type": "object", "required": ["check", "status", "observed_at", "detail", "text", "plugin_diag"]}},
            "links": {"type": "array", "items": {"type": "object", "required": ["kind", "id"], "properties": {"kind": {"type": "string"}, "id": {"type": "string"}}}},
            "views": {"type": "array", "items": {"type": "object"}},
            "actions": {"type": "array", "maxItems": 0}
        }
    });

    documented!(ViewPage, {
        "type": "object",
        "additionalProperties": false,
        "required": ["fields", "rows", "next_cursor", "as_of"],
        "properties": {
            "fields": {"type": "array", "items": {"type": "object"}},
            "rows": {"type": "array", "items": {"type": "array"}},
            "next_cursor": {"type": ["string", "null"]},
            "as_of": {"type": "integer", "minimum": 0, "description": "Unix milliseconds"}
        }
    });
}

#[cfg(test)]
#[path = "tests/kinds_tests.rs"]
mod tests;
