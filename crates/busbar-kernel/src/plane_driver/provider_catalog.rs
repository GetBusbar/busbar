// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Immutable native provider routing facts, resolved before a serving configuration exists.
//! No plugin, credential, destination capability or money owner is opened here.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use busbar_contract::config::UpstreamCreds;
use busbar_contract::json::{self, SchemaCheck};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::providers::CORE_PROVIDER_KEYS;
use crate::config::{DeployCfg, ModelCfg, PoolCfg, PoolMember, ResolvedProviders};

/// Metadata copied from the admitted image of this exact configured instance.
#[derive(Clone, Debug)]
pub struct ProviderPlane {
    pub instance: String,
    pub image: String,
    pub dialects: BTreeSet<String>,
    pub schema: String,
}

/// Internal walk identity is separate from the configured scope used by admission/hooks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteKind {
    NamedPool(String),
    DirectModel(String),
}

/// A validated pool policy plus its routing domain, never an authorization receipt.
#[derive(Clone, Debug)]
pub struct CatalogPool {
    pub kind: RouteKind,
    pub config: PoolCfg,
}

/// One pool/member's exact native target. No secret, rate or host-origin data crosses to the plane.
#[derive(Clone, Debug)]
pub struct ResolvedMember {
    pub model: String,
    pub provider: String,
    pub dialect: String,
    pub wire_model: String,
    pub projection: Arc<str>,
    pub base_path: String,
    pub params: Vec<(Box<str>, Box<str>)>,
    pub credential_mode: UpstreamCreds,
    pub max_concurrent: Option<usize>,
    pub max_requests: i64,
    pub attempt_timeout_ms: Option<u64>,
    pub context_max: Option<usize>,
}

/// Only root can join these facts to actual routes, NativeBindings and admission owners.
#[derive(Clone, Debug)]
pub struct CatalogPlan {
    pub instance: String,
    pub image: String,
    pools: BTreeMap<String, CatalogPool>,
    selectors: BTreeMap<String, String>,
    targets: BTreeMap<(String, String), ResolvedMember>,
}

impl CatalogPlan {
    pub fn pools(&self) -> &BTreeMap<String, CatalogPool> {
        &self.pools
    }

    /// Resolve only an authored pool/model name. Unknown/empty input grants no default route.
    pub fn select(&self, configured: &str) -> Option<&str> {
        self.selectors.get(configured).map(String::as_str)
    }

    pub fn target(&self, pool: &str, qualified_member: &str) -> Option<&ResolvedMember> {
        self.targets
            .get(&(pool.to_owned(), qualified_member.to_owned()))
    }

    pub fn targets(&self) -> &BTreeMap<(String, String), ResolvedMember> {
        &self.targets
    }

    /// Auth selection shares a provider/dialect binding, while custody remains keyed by the
    /// complete selected pool/member route. This does not select or open an auth port.
    pub fn attempt_key(
        &self,
        pool: &str,
        member: &str,
    ) -> Option<crate::auth_bindings::AttemptKey> {
        let target = self.target(pool, member)?;
        Some((
            self.instance.as_str().into(),
            target.provider.as_str().into(),
            target.dialect.as_str().into(),
        ))
    }

    pub fn auth_members(&self) -> impl Iterator<Item = crate::auth_bindings::MemberView<'_>> {
        self.targets
            .values()
            .map(move |target| crate::auth_bindings::MemberView {
                member: &target.model,
                plane: &self.instance,
                image: &self.image,
                provider: &target.provider,
                dialect: Some(&target.dialect),
            })
    }
}

pub type ProviderCatalogs = BTreeMap<String, CatalogPlan>;

#[derive(Deserialize)]
struct SchemaShape {
    #[serde(default)]
    properties: BTreeMap<String, Value>,
    #[serde(default, rename = "patternProperties")]
    patterns: BTreeMap<String, Value>,
    #[serde(default)]
    required: Vec<String>,
}

struct PlaneSchema<'a> {
    plane: &'a ProviderPlane,
    shape: SchemaShape,
    check: SchemaCheck,
    ownership: SchemaCheck,
}

impl PlaneSchema<'_> {
    fn owns(&self, key: &str) -> bool {
        json::to_vec(&BTreeMap::from([(key, ())]))
            .is_ok_and(|bytes| self.ownership.is_valid(&bytes))
    }
}

impl SchemaShape {
    fn ownership(&self) -> Result<SchemaCheck, json::Error> {
        #[derive(Serialize)]
        struct Ownership<'a> {
            #[serde(rename = "type")]
            kind: &'static str,
            properties: BTreeMap<&'a str, bool>,
            #[serde(rename = "patternProperties")]
            patterns: BTreeMap<&'a str, bool>,
            #[serde(rename = "additionalProperties")]
            additional: bool,
        }
        let schema = Ownership {
            kind: "object",
            properties: self.properties.keys().map(|k| (k.as_str(), true)).collect(),
            patterns: self.patterns.keys().map(|k| (k.as_str(), true)).collect(),
            additional: false,
        };
        SchemaCheck::new(&json::to_vec(&schema)?)
    }
}

fn name_ok(name: &str) -> bool {
    !name.is_empty() && !name.chars().any(char::is_control)
}

fn dialect<'a>(model: &'a ModelCfg, providers: &'a ResolvedProviders) -> Option<&'a str> {
    let provider = providers.get(&model.provider)?;
    Some(
        model
            .protocol
            .as_deref()
            .unwrap_or_else(|| provider.dialect()),
    )
}

fn qualify(instance: &str, model: &str) -> String {
    format!("{instance}{}{model}", crate::governance::PLANE_LANE_SEP)
}

// Length-framed internal keys cannot alias an operator name or another routing domain.
fn walk_key(instance: &str, kind: &str, name: &str) -> String {
    format!("{}:{instance}:{kind}:{}:{name}", instance.len(), name.len())
}

fn source(deploy: &DeployCfg, provider: &str, key: &str) -> &'static str {
    if deploy.providers[provider].authored.keys.contains(key) {
        "config.yaml"
    } else {
        "providers.yaml"
    }
}

fn pointer_source(deploy: &DeployCfg, provider: &str, pointer: &str) -> &'static str {
    let mut parts = pointer
        .strip_prefix('/')
        .unwrap_or(pointer)
        .split('/')
        .map(|s| s.replace("~1", "/").replace("~0", "~"));
    let key = parts.next().unwrap_or_default();
    let entry = &deploy.providers[provider];
    if let Some(member) = parts.next() {
        // The only recursive merge is a string map. Its unchanged members retain their
        // catalog origin even if deployment authored another key of the same map.
        if key == "error_map" {
            if let Some(map) = &entry.error_map {
                return if map.contains_key(&member) {
                    "config.yaml"
                } else {
                    "providers.yaml"
                };
            }
        } else if let Some(map) = entry.options.get(&key).and_then(Value::as_object) {
            if map.values().all(Value::is_string) && !map.contains_key(&member) {
                return "providers.yaml";
            }
        }
    }
    source(deploy, provider, &key)
}

// Do not erase unknown/null required values: the image schema must still judge them. Only
// explicitly declared optional object properties are unset, including objects inside arrays.
fn omit_optional_nulls(value: &mut Value, schema: &Value) {
    match value {
        Value::Object(values) => {
            if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
                let required = schema.get("required").and_then(Value::as_array);
                values.retain(|key, value| {
                    !value.is_null()
                        || !properties.contains_key(key)
                        || required.is_some_and(|keys| keys.iter().any(|k| k.as_str() == Some(key)))
                });
                for (key, value) in values {
                    if let Some(child) = properties.get(key) {
                        omit_optional_nulls(value, child);
                    }
                }
            }
        }
        Value::Array(values) => {
            if let Some(items) = schema.get("items") {
                for value in values {
                    omit_optional_nulls(value, items);
                }
            }
        }
        _ => {}
    }
}

/// Resolve real models/pools and validate only the reached images' merged projections.
pub fn resolve(
    deploy: &DeployCfg,
    providers: &ResolvedProviders,
    pools: &HashMap<String, PoolCfg>,
    planes: &[ProviderPlane],
) -> Result<ProviderCatalogs, Vec<String>> {
    let mut errors = Vec::new();
    let mut schemas = Vec::new();
    let mut instances = BTreeSet::new();
    for plane in planes {
        if !name_ok(&plane.instance) || !instances.insert(&plane.instance) {
            errors.push("provider plane instance names must be nonempty and unique".into());
            continue;
        }
        match (
            json::parse_foreign::<SchemaShape>(plane.schema.as_bytes()),
            SchemaCheck::new(plane.schema.as_bytes()),
        ) {
            (Ok(shape), Ok(check)) => match shape.ownership() {
                Ok(ownership) => schemas.push(PlaneSchema {
                    plane,
                    shape,
                    check,
                    ownership,
                }),
                Err(_) => errors.push(format!(
                    "plane {}: invalid provider property declarations",
                    plane.instance
                )),
            },
            _ => errors.push(format!("plane {}: invalid provider schema", plane.instance)),
        }
    }
    for (name, provider) in providers {
        if provider.dialect().is_empty() {
            errors.push(format!(
                "providers.{name}.protocol: required core field is absent"
            ));
        }
        if provider.base_url.is_empty() {
            errors.push(format!(
                "providers.{name}.base_url: required core field is absent"
            ));
        }
    }
    for (name, model) in &deploy.models {
        if !name_ok(name) || deploy.pools.pools.contains_key(name) {
            errors.push(format!(
                "models.{name}: invalid or ambiguous model/pool name"
            ));
        }
        let Some(dialect) = dialect(model, providers) else {
            errors.push(format!("models.{name}.provider: no deployed provider"));
            continue;
        };
        if dialect.is_empty() || !schemas.iter().any(|s| s.plane.dialects.contains(dialect)) {
            errors.push(format!(
                "models.{name}.protocol: no configured provider plane declares the dialect"
            ));
        }
        if model.upstream_model.as_ref().is_some_and(|m| !name_ok(m)) {
            errors.push(format!("models.{name}.upstream_model: invalid model name"));
        }
    }
    let compatible = |schema: &PlaneSchema<'_>, name: &str| {
        deploy
            .models
            .get(name)
            .and_then(|m| dialect(m, providers))
            .is_some_and(|d| schema.plane.dialects.contains(d))
    };
    for (name, pool) in pools {
        if !name_ok(name)
            || pool.members.is_empty()
            || !schemas
                .iter()
                .any(|s| pool.members.iter().all(|m| compatible(s, m.name())))
        {
            errors.push(format!(
                "pools.{name}: no configured provider plane serves every member"
            ));
        }
        let mut members = BTreeSet::new();
        for member in &pool.members {
            if !members.insert(member.name()) {
                errors.push(format!("pools.{name}: duplicate member {}", member.name()));
            }
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }

    let empty_sugars = busbar_contract::secret_ref::Sugars::default();
    let sugars = deploy.grammar.get().map_or(&empty_sugars, |g| &g.sugars);
    let mut projections = BTreeMap::<(String, String), Arc<str>>::new();
    for (name, provider) in providers {
        let reached: Vec<_> = schemas
            .iter()
            .filter(|s| {
                deploy
                    .models
                    .iter()
                    .any(|(m, config)| config.provider == *name && compatible(s, m))
            })
            .collect();
        let unknown = |key: &str| !CORE_PROVIDER_KEYS.contains(&key);
        if reached.is_empty() {
            for key in deploy.providers[name]
                .authored
                .keys
                .iter()
                .filter(|k| unknown(k))
            {
                errors.push(format!(
                    "config.yaml providers.{name}.{key}: provider is not reached"
                ));
            }
            continue;
        }
        for key in provider.table.keys().filter(|k| unknown(k)) {
            if !reached.iter().any(|s| s.owns(key)) {
                errors.push(format!(
                    "{} providers.{name}.{key}: no reached image owns this property",
                    source(deploy, name, key)
                ));
            }
        }
        for schema in reached {
            let mut projection = serde_json::Map::new();
            for (key, value) in provider
                .table
                .iter()
                .filter(|(k, _)| unknown(k) && schema.owns(k))
            {
                // Optional null is a tombstone; required null is validated, never silently omitted.
                if !value.is_null() || schema.shape.required.contains(key) {
                    let mut value = value.clone();
                    if let Some(shape) = schema.shape.properties.get(key) {
                        omit_optional_nulls(&mut value, shape);
                    }
                    projection.insert(key.clone(), value);
                }
            }
            let projection = Value::Object(projection);
            if let Err(refusal) = crate::plugin_config::check_projection(&projection, sugars) {
                let pointer = match refusal {
                    crate::plugin_config::BindError::StraySecret { pointer } => pointer,
                    _ => "".into(),
                };
                errors.push(format!(
                    "{} providers.{name}{pointer}: StraySecret in plane projection",
                    pointer_source(deploy, name, &pointer)
                ));
                continue;
            }
            let bytes = json::to_vec(&projection)
                .map_err(|_| vec![format!("providers.{name}: projection encoding failed")])?;
            if let Err((pointer, keyword)) = schema.check.validation_paths(&bytes) {
                errors.push(format!(
                    "{} providers.{name}{pointer}: schema {keyword}",
                    pointer_source(deploy, name, &pointer)
                ));
                continue;
            }
            let text = String::from_utf8(bytes)
                .map_err(|_| vec!["provider projection is not UTF-8".into()])?;
            projections.insert(
                (schema.plane.instance.clone(), name.clone()),
                Arc::from(text),
            );
        }
    }
    // Definitions have already passed core Catalog grammar. Unreached menu options are untouched.
    if !errors.is_empty() {
        return Err(errors);
    }
    let mut catalogs = BTreeMap::new();
    for schema in &schemas {
        let plane = schema.plane;
        let mut plan = CatalogPlan {
            instance: plane.instance.clone(),
            image: plane.image.clone(),
            pools: BTreeMap::new(),
            selectors: BTreeMap::new(),
            targets: BTreeMap::new(),
        };
        for (name, pool) in pools {
            if pool.members.iter().all(|m| compatible(schema, m.name())) {
                add_pool(
                    &mut plan,
                    name,
                    RouteKind::NamedPool(name.clone()),
                    pool.clone(),
                    deploy,
                    providers,
                    &projections,
                )?;
            }
        }
        for (name, model) in &deploy.models {
            if compatible(schema, name) {
                let member = PoolMember {
                    model: name.clone(),
                    weight: 1,
                    context_max: None,
                    tier: None,
                    attempt_timeout_ms: model.attempt_timeout_ms,
                    reasoning: model.reasoning,
                    tags: Vec::new(),
                };
                add_pool(
                    &mut plan,
                    name,
                    RouteKind::DirectModel(name.clone()),
                    PoolCfg {
                        members: vec![member],
                        ..PoolCfg::default()
                    },
                    deploy,
                    providers,
                    &projections,
                )?;
            }
        }
        catalogs.insert(plane.instance.clone(), plan);
    }
    Ok(catalogs)
}

fn add_pool(
    plan: &mut CatalogPlan,
    name: &str,
    kind: RouteKind,
    pool: PoolCfg,
    deploy: &DeployCfg,
    providers: &ResolvedProviders,
    projections: &BTreeMap<(String, String), Arc<str>>,
) -> Result<(), Vec<String>> {
    let domain = match kind {
        RouteKind::NamedPool(_) => "pool",
        RouteKind::DirectModel(_) => "model",
    };
    let key = walk_key(&plan.instance, domain, name);
    for member in &pool.members {
        let model = &deploy.models[member.name()];
        let provider = &providers[&model.provider];
        let mut params = Vec::<(Box<str>, Box<str>)>::new();
        if let Some(path) = &provider.path {
            params.push(("path".into(), path.clone().into()));
        }
        if let Some(cap) = model.default_max_tokens {
            params.push(("default_max_tokens".into(), cap.to_string().into()));
        }
        if let Some(value) = member.reasoning.or(model.reasoning) {
            params.push(("reasoning".into(), value.to_string().into()));
        }
        if let Some(value) = model.prompt_caching {
            params.push(("prompt_caching".into(), value.to_string().into()));
        }
        if let Some(cap) = member.context_max {
            params.push(("context_max".into(), cap.to_string().into()));
        }
        let projection = projections
            .get(&(plan.instance.clone(), model.provider.clone()))
            .ok_or_else(|| vec!["validated provider projection is missing".into()])?;
        plan.targets.insert(
            (key.clone(), qualify(&plan.instance, member.name())),
            ResolvedMember {
                model: member.model.clone(),
                provider: model.provider.clone(),
                dialect: model
                    .protocol
                    .clone()
                    .unwrap_or_else(|| provider.dialect().to_owned()),
                wire_model: model
                    .upstream_model
                    .clone()
                    .unwrap_or_else(|| member.model.clone()),
                projection: Arc::clone(projection),
                base_path: provider.path_base.clone().unwrap_or_default(),
                params,
                credential_mode: pool
                    .upstream_credentials
                    .or(deploy.pools.all_pool_upstream_credentials)
                    .unwrap_or_default(),
                max_concurrent: model.max_concurrent,
                max_requests: model.max_requests,
                attempt_timeout_ms: member
                    .attempt_timeout_ms
                    .or(pool.attempt_timeout_ms)
                    .or(model.attempt_timeout_ms),
                context_max: member.context_max,
            },
        );
    }
    plan.selectors.insert(name.to_owned(), key.clone());
    plan.pools.insert(key, CatalogPool { kind, config: pool });
    Ok(())
}
