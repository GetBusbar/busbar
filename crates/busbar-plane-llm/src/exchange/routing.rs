// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE GENERATION'S ROUTING, as this plane resolves it from its own sections (step 2b, arch u26):
//! the entries the kernel's walk, breaker cells and counters key by, published on the snapshot
//! (`PlaneSnapshot.routing`) so the kernel reads them and never parses `models:` / `pools:` itself.
//!
//! THE FORM (agreed with the kernel's routing lane, coordinator-approved 2026-10-19):
//!
//! - one entry per `models:` key, every model including one no pool names: section `models`, path
//!   `[models, <model>]`, one member (the model's own lane, weight 1) — a request naming a model
//!   directly walks that lane alone;
//! - one entry per `pools:` key: section `pools`, path `[pools, <pool>]`, its members in the pool's
//!   order (each `{model, weight, tier, tags}`), the lanes `failover.exclusions` names, and
//!   `FACT_FAILOVER_TIMEOUT_SECS` / `FACT_FAILOVER_MAX_HOPS` when the pool writes a `failover:`
//!   block (1.5.5's serde defaults filling a sub-key it omits);
//! - a lane's own facts (`FACT_CONCURRENCY_CAP`, `FACT_MAX_REQUESTS`, `FACT_CONTEXT_WINDOW`) are
//!   stated identically on every member naming the lane; `FACT_ATTEMPT_TIMEOUT_MS` is the member's
//!   own value, else its model's.
//!
//! NOT STATED, and the kernel's: an entry's fallback (`on_exhausted`, a reserved sub-key the plane
//! never receives), its reserved `timeout`, `breaker` and `affinity`, and every probe fact (a
//! provider's `health` is a core key).

use std::collections::BTreeMap;

use busbar_contract::abi::plane::{
    FACT_ATTEMPT_TIMEOUT_MS, FACT_CONCURRENCY_CAP, FACT_CONTEXT_WINDOW, FACT_FAILOVER_MAX_HOPS,
    FACT_FAILOVER_TIMEOUT_SECS, FACT_MAX_REQUESTS,
};
use busbar_contract::abi::sdk::publish::{RouteEntrySpec, RouteMemberSpec};
use serde::Deserialize;
use serde_json::Value;

use super::shaping::sections;

/// A pool's `failover:` budget when it writes none of `timeout_secs` (1.5.5's serde default).
pub const DEFAULT_FAILOVER_TIMEOUT_SECS: u64 = 120;
/// A pool's `failover:` hop cap when it writes none of `max_hops` (1.5.5's serde default).
pub const DEFAULT_FAILOVER_MAX_HOPS: u64 = 3;

/// One model as routing reads it: the plane's lenient reading (the kernel's config validation
/// already refused what does not read), the fields a lane's routing states.
#[derive(Deserialize)]
struct ModelCfg {
    provider: String,
    #[serde(default)]
    upstream_model: Option<String>,
    /// 1.5.5's lifetime cap; absent or negative = no bound.
    #[serde(default)]
    max_requests: Option<i64>,
    #[serde(default)]
    max_concurrent: Option<u64>,
    #[serde(default)]
    attempt_timeout_ms: Option<u64>,
}

/// One pool member as written: a bare model name, or the rich object.
struct PoolMember {
    model: String,
    weight: u32,
    context_max: Option<u64>,
    tier: String,
    attempt_timeout_ms: Option<u64>,
    tags: Vec<String>,
}

#[derive(Deserialize)]
struct Failover {
    #[serde(default)]
    timeout_secs: Option<u64>,
    #[serde(default)]
    exclusions: Option<Vec<String>>,
    #[serde(default)]
    max_hops: Option<u64>,
}

fn pool_member(v: &Value) -> Option<PoolMember> {
    match v {
        Value::String(s) => Some(PoolMember {
            model: s.clone(),
            weight: 1,
            context_max: None,
            tier: String::new(),
            attempt_timeout_ms: None,
            tags: Vec::new(),
        }),
        Value::Object(o) => Some(PoolMember {
            model: o.get("model")?.as_str()?.to_string(),
            weight: match o.get("weight") {
                None | Some(Value::Null) => 1,
                Some(w) => u32::try_from(w.as_u64()?).ok()?,
            },
            context_max: o.get("context_max").and_then(Value::as_u64),
            tier: o
                .get("tier")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            attempt_timeout_ms: o.get("attempt_timeout_ms").and_then(Value::as_u64),
            tags: o
                .get("tags")
                .and_then(Value::as_array)
                .map(|t| {
                    t.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default(),
        }),
        _ => None,
    }
}

/// One lane's own facts, the same on every member naming it.
fn lane_facts(m: &ModelCfg, context_window: Option<u64>) -> Vec<(u16, u64)> {
    let mut facts = Vec::new();
    if let Some(n) = m.max_concurrent {
        facts.push((FACT_CONCURRENCY_CAP, n));
    }
    if let Some(n) = context_window {
        facts.push((FACT_CONTEXT_WINDOW, n));
    }
    // A negative `max_requests` is 1.5.5's "no bound": no fact.
    if let Some(n) = m.max_requests.and_then(|n| u64::try_from(n).ok()) {
        facts.push((FACT_MAX_REQUESTS, n));
    }
    facts
}

/// A member of `model`'s lane, its attempt bound `attempt_timeout_ms` (none stated = none).
fn member(
    model: &str,
    m: &ModelCfg,
    weight: u32,
    tier: String,
    tags: Vec<String>,
    context_window: Option<u64>,
    attempt_timeout_ms: Option<u64>,
) -> RouteMemberSpec {
    let mut facts = lane_facts(m, context_window);
    if let Some(ms) = attempt_timeout_ms {
        facts.push((FACT_ATTEMPT_TIMEOUT_MS, ms));
    }
    RouteMemberSpec {
        lane: model.to_string(),
        provider: m.provider.clone(),
        upstream: m.upstream_model.clone().unwrap_or_default(),
        weight,
        tier,
        tags,
        facts,
    }
}

/// THE GENERATION'S ROUTING from the settings object: one entry per model, then one per pool, each
/// in name order. A settings object that states no `models:` routes nothing (a blob dealt the
/// plane's own section alone).
///
/// # Errors
///
/// Why the `models:` or `pools:` settings do not read as routing: a model or member that does not
/// read, a member naming no model, or a `failover:` block that does not read.
pub fn of(settings: &Value) -> Result<Vec<RouteEntrySpec>, String> {
    let Some(models_value) = settings.get(sections::MODELS).filter(|v| !v.is_null()) else {
        return Ok(Vec::new());
    };
    let models: BTreeMap<String, ModelCfg> = serde_json::from_value(models_value.clone())
        .map_err(|e| format!("the `{}` settings do not read: {e}", sections::MODELS))?;
    let mut pools: Vec<(String, Vec<PoolMember>, Option<Failover>)> = Vec::new();
    if let Some(Value::Object(sec)) = settings.get(sections::POOLS) {
        for (name, pool) in sec {
            // The reserved keys of the section are settings, not pools: a pool has members.
            let Some(Value::Array(ms)) = pool.get("members") else {
                continue;
            };
            let members = ms
                .iter()
                .map(pool_member)
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| format!("pool '{name}' has a member that does not read"))?;
            let failover = match pool.get("failover") {
                None | Some(Value::Null) => None,
                Some(v) => Some(
                    serde_json::from_value::<Failover>(v.clone())
                        .map_err(|e| format!("pool '{name}' failover does not read: {e}"))?,
                ),
            };
            pools.push((name.clone(), members, failover));
        }
    }
    // A model's context window is one value across every pool that names it (the tables' own
    // rule, refused there when two pools disagree): the first stated value.
    let mut context: BTreeMap<&str, u64> = BTreeMap::new();
    for (_, members, _) in &pools {
        for m in members {
            // 0 is undeclared (the kernel's reading of the fact): never stated.
            if let Some(c) = m.context_max.filter(|c| *c > 0) {
                context.entry(m.model.as_str()).or_insert(c);
            }
        }
    }
    let mut out = Vec::with_capacity(models.len() + pools.len());
    for (name, m) in &models {
        out.push(RouteEntrySpec {
            section: sections::MODELS.to_string(),
            entry: name.clone(),
            path: vec![sections::MODELS.to_string(), name.clone()],
            members: vec![member(
                name,
                m,
                1,
                String::new(),
                Vec::new(),
                context.get(name.as_str()).copied(),
                m.attempt_timeout_ms,
            )],
            ..RouteEntrySpec::default()
        });
    }
    for (name, members, failover) in &pools {
        let mut route_members = Vec::with_capacity(members.len());
        for pm in members {
            let m = models
                .get(&pm.model)
                .ok_or_else(|| format!("pool '{name}' references unknown model '{}'", pm.model))?;
            route_members.push(member(
                &pm.model,
                m,
                pm.weight,
                pm.tier.clone(),
                pm.tags.clone(),
                context.get(pm.model.as_str()).copied(),
                pm.attempt_timeout_ms.or(m.attempt_timeout_ms),
            ));
        }
        let (facts, exclude) = match failover {
            Some(f) => (
                vec![
                    (
                        FACT_FAILOVER_TIMEOUT_SECS,
                        f.timeout_secs.unwrap_or(DEFAULT_FAILOVER_TIMEOUT_SECS),
                    ),
                    (
                        FACT_FAILOVER_MAX_HOPS,
                        f.max_hops.unwrap_or(DEFAULT_FAILOVER_MAX_HOPS),
                    ),
                ],
                f.exclusions.clone().unwrap_or_default(),
            ),
            None => (Vec::new(), Vec::new()),
        };
        out.push(RouteEntrySpec {
            section: sections::POOLS.to_string(),
            entry: name.clone(),
            path: vec![sections::POOLS.to_string(), name.clone()],
            exclude,
            facts,
            members: route_members,
            ..RouteEntrySpec::default()
        });
    }
    Ok(out)
}
