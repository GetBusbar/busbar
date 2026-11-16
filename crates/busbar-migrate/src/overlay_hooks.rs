// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The overlay's hooks (MIGRATE-ON-BOOT §A3 1c, r29), the one overlay-shape pass: 1.5.5's overlay
//! held each hook as its runtime `HookCfg` (wire `module`, alias `plugin`, with `at`, `global`,
//! `default`, `signals` and `on_error` always written), not config.yaml's hook definition. Each is
//! read as v1.5.5's `HookCfg` read it (`deny_unknown_fields`, 1.5.5's defaults) and written by
//! name into config.yaml `hooks:` as a 1.6.0 definition (the overlay wins, as `merge_into` did).
//!
//! The overlay's own keys `global_hooks`, `global`, `default`, `at` and `plugin` are read here
//! and never written: the global attachment becomes `pools.hooks:` (base order first, then the
//! overlay's list, then any `global: true` hook not yet in it, no duplicates); the tombstones
//! (`deleted`, applied last) remove a name from `hooks:`, `pools.hooks:` and every pool's
//! `hooks:`; a pool name left undefined is removed the same way (1.5.5 skipped it, 1.6.0 refuses
//! it); `default: true` has no 1.6.0 form and refuses only where it ordered a pool in 1.5.5.

use busbar_contract::json::{self, JsonContainerTrait, JsonValueTrait};
use busbar_contract::yaml::{MappingExt, Pairs, Value, ValueExt};

use crate::overlay::{text, to_yaml, unparseable};
use crate::Refusal;

/// The overlay's hook fields (top level).
pub(crate) const KEYS: [&str; 3] = ["hooks", "global_hooks", "deleted"];
/// v1.5.5 `HookCfg`'s fields (`module` read also as `plugin`).
const FIELDS: [&str; 17] = [
    "kind",
    "module",
    "plugin",
    "timeout_ms",
    "on_error",
    "prompt",
    "user",
    "priority",
    "at",
    "on_empty",
    "settings",
    "signals",
    "global",
    "default",
    "groups",
    "phase",
    "insecure_transport",
];
/// `HookStage`, the same words in both releases.
const STAGES: [&str; 4] = ["request", "candidate", "routing", "response"];
/// The reserved `on_error` terminals, written bare; any other name is `{hook: <name>}`.
const TERMINALS: [&str; 4] = ["nothing", "weighted", "reject", "first"];
/// The native ordering strategies a pool `hooks:` list names bare.
const STRATEGIES: [&str; 5] = ["weighted", "cheapest", "fastest", "least_busy", "usage"];
/// `pools:` keys that are section knobs, not pools.
const POOLS_SECTION: [&str; 2] = ["hooks", "upstream_credentials"];
/// v1.5.5's `DEFAULT_POLICY_TIMEOUT_MS`.
const DEFAULT_TIMEOUT_MS: u64 = 1;

/// One overlay hook as v1.5.5's `HookCfg` read it. Its `settings` stay in the overlay document,
/// borrowed (no readable bag is copied out), and are converted only when the definition is written.
struct Hook<'a> {
    name: String,
    kind: String,
    module: String,
    timeout_ms: u64,
    on_error: String,
    prompt: String,
    user: String,
    priority: u64,
    at: Option<String>,
    on_empty: Option<String>,
    settings: Option<&'a json::Value>,
    signals: Vec<String>,
    global: bool,
    default: bool,
    groups: Vec<String>,
    phase: Vec<String>,
    /// A 1.6.0 key an operator added beside `module` (TRANSPORT-SECURITY-POLICY §6): carried verbatim.
    insecure_transport: Option<&'a json::Value>,
}

/// Read `hooks.<name>` as v1.5.5's `HookCfg`; an entry 1.5.5 could not read refuses (the
/// unparseable-overlay case).
fn read<'a>(name: &str, value: &'a json::Value, o: &str) -> Result<Hook<'a>, Refusal> {
    let bad = |why: &str| unparseable(o, &format!("`hooks.{name}`: {why}"));
    let fields = value
        .as_object()
        .ok_or_else(|| bad("the hook is not an object"))?;
    for (key, _) in fields.iter() {
        if !FIELDS.contains(&key) {
            return Err(bad(&format!("unknown field `{key}`")));
        }
    }
    let module = match (fields.get(&"module"), fields.get(&"plugin")) {
        (Some(_), Some(_)) => return Err(bad("duplicate field `module` (also written `plugin`)")),
        (Some(module), None) | (None, Some(module)) => module
            .as_str()
            .ok_or_else(|| bad("`module` is not a string"))?
            .to_owned(),
        (None, None) => return Err(bad("missing field `module`")),
    };
    let word = |field: &str, words: &[&str]| -> Result<Option<String>, Refusal> {
        let Some(value) = fields.get(&field) else {
            return Ok(None);
        };
        match value.as_str() {
            Some(found) if words.contains(&found) => Ok(Some(found.to_owned())),
            _ => Err(bad(&format!(
                "`{field}` is not one of {}",
                words.join(" | ")
            ))),
        }
    };
    let nullable = |field: &str, words: &[&str]| -> Result<Option<String>, Refusal> {
        match fields.get(&field) {
            Some(value) if value.is_null() => Ok(None),
            _ => word(field, words),
        }
    };
    let number = |field: &str, default: u64| -> Result<u64, Refusal> {
        match fields.get(&field) {
            None => Ok(default),
            Some(value) => value
                .as_u64()
                .ok_or_else(|| bad(&format!("`{field}` is not an unsigned integer"))),
        }
    };
    let flag = |field: &str| -> Result<bool, Refusal> {
        match fields.get(&field) {
            None => Ok(false),
            Some(value) => value
                .as_bool()
                .ok_or_else(|| bad(&format!("`{field}` is not a boolean"))),
        }
    };
    let list = |field: &str, words: Option<&[&str]>| -> Result<Vec<String>, Refusal> {
        let Some(value) = fields.get(&field) else {
            return Ok(Vec::new());
        };
        let items = value
            .as_array()
            .ok_or_else(|| bad(&format!("`{field}` is not a list")))?;
        let mut out = Vec::new();
        for item in items {
            let item = item
                .as_str()
                .filter(|item| words.is_none_or(|words| words.contains(item)))
                .ok_or_else(|| bad(&format!("`{field}` holds an entry 1.5.5 did not read")))?;
            out.push(item.to_owned());
        }
        Ok(out)
    };
    let kind = word("kind", &["tap", "gate"])?.ok_or_else(|| bad("missing field `kind`"))?;
    let on_error = match fields.get(&"on_error") {
        None => TERMINALS[0].to_owned(),
        Some(value) => value
            .as_str()
            .ok_or_else(|| bad("`on_error` is not a string"))?
            .to_owned(),
    };
    let priority = number("priority", 0)?;
    if priority > u64::from(u16::MAX) {
        return Err(bad("`priority` is above 65535"));
    }
    let settings = match fields.get(&"settings") {
        None => None,
        Some(value) if value.is_object() => Some(value),
        Some(_) => return Err(bad("`settings` is not an object")),
    };
    Ok(Hook {
        name: name.to_owned(),
        kind,
        module,
        timeout_ms: number("timeout_ms", DEFAULT_TIMEOUT_MS)?,
        on_error,
        prompt: word("prompt", &["no", "ro", "rw"])?.unwrap_or_else(|| "no".to_owned()),
        user: word("user", &["no", "ro"])?.unwrap_or_else(|| "no".to_owned()),
        priority,
        at: nullable("at", &STAGES)?,
        on_empty: nullable("on_empty", &["weighted", "reject", "first"])?,
        settings,
        signals: list("signals", None)?,
        global: flag("global")?,
        default: flag("default")?,
        groups: list("groups", None)?,
        phase: list("phase", Some(STAGES.as_slice()))?,
        insecure_transport: fields.get(&"insecure_transport"),
    })
}

fn key(name: &str) -> Value {
    Value::Text(name.to_owned())
}

/// The 1.6.0 hook definition of an overlay hook: `module` = the plugin; `phase` by 1.5.5's
/// `fires_at_stage` precedence (a non-empty `phase`, else `[at]`, else omitted: the four core
/// stages in both releases); `on_error` always written (the releases' defaults differ), bare for
/// a terminal and `{hook: <name>}` otherwise; the rest copied as held, with empty lists and maps
/// and nulls dropped. `at`, `global`, `default` and `plugin` are never written.
fn definition(hook: &Hook<'_>, o: &str) -> Result<Value, Refusal> {
    let path = |field: &str| format!("hooks.{}.{field}", hook.name);
    let strings = |items: &[String], field: &str| -> Result<Value, Refusal> {
        let mut out = Vec::new();
        for item in items {
            out.push(text(item, &path(field), o)?);
        }
        Ok(Value::Array(out))
    };
    let mut out: Pairs = vec![(key("module"), text(&hook.module, &path("module"), o)?)];
    if let Some(settings) = hook.settings {
        match to_yaml(settings, &path("settings"), o)? {
            Value::Map(pairs) if pairs.is_empty() => {}
            settings => out.push((key("settings"), settings)),
        }
    }
    if !hook.groups.is_empty() {
        out.push((key("groups"), strings(&hook.groups, "groups")?));
    }
    if !hook.phase.is_empty() {
        out.push((key("phase"), strings(&hook.phase, "phase")?));
    } else if let Some(at) = &hook.at {
        out.push((key("phase"), Value::Array(vec![key(at)])));
    }
    out.push((key("kind"), key(&hook.kind)));
    out.push((key("timeout_ms"), Value::from(hook.timeout_ms)));
    let on_error = text(&hook.on_error, &path("on_error"), o)?;
    let on_error = if TERMINALS.contains(&hook.on_error.as_str()) {
        on_error
    } else {
        Value::Map(vec![(key("hook"), on_error)])
    };
    out.push((key("on_error"), on_error));
    if let Some(on_empty) = &hook.on_empty {
        out.push((key("on_empty"), key(on_empty)));
    }
    out.push((key("prompt"), key(&hook.prompt)));
    out.push((key("user"), key(&hook.user)));
    out.push((key("priority"), Value::from(hook.priority)));
    if !hook.signals.is_empty() {
        out.push((key("signals"), strings(&hook.signals, "signals")?));
    }
    if let Some(carried) = hook.insecure_transport {
        out.push((
            key("insecure_transport"),
            to_yaml(carried, &path("insecure_transport"), o)?,
        ));
    }
    Ok(Value::Map(out))
}

/// A list of names at the overlay's top level (`global_hooks`, `deleted`).
fn names(value: Option<&json::Value>, field: &str, o: &str) -> Result<Vec<String>, Refusal> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let items = value
        .as_array()
        .ok_or_else(|| unparseable(o, &format!("`{field}` is not a list")))?;
    let mut out = Vec::new();
    for item in items {
        let item = item
            .as_str()
            .ok_or_else(|| unparseable(o, &format!("`{field}` holds a non-string")))?;
        out.push(item.to_owned());
    }
    Ok(out)
}

/// config.yaml's `pools.hooks:` (1.5.5's global list).
fn base_global(pairs: &Pairs) -> Result<Vec<String>, Refusal> {
    let refused = || {
        Refusal::Config(
            "config.yaml `pools.hooks` is not a list of hook names; 1.5.5 did not boot it either"
                .to_owned(),
        )
    };
    let Some(Value::Map(pools)) = pairs.get_key("pools") else {
        return Ok(Vec::new());
    };
    match pools.get_key("hooks") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => {
            let mut out = Vec::new();
            for item in items {
                out.push(item.as_str().ok_or_else(refused)?.to_owned());
            }
            Ok(out)
        }
        Some(_) => Err(refused()),
    }
}

/// Write `pools.hooks:` (removed when empty).
fn set_global(pairs: &mut Pairs, attached: Vec<String>) {
    let pools = pairs.entry_or_insert_with("pools", || Value::Map(Vec::new()));
    if pools.is_null() {
        *pools = Value::Map(Vec::new());
    }
    let Value::Map(pools) = pools else {
        return;
    };
    if attached.is_empty() {
        pools.retain(|(name, _)| name.as_str() != Some("hooks"));
    } else {
        let list = attached.into_iter().map(Value::Text).collect();
        pools.insert_key("hooks", Value::Array(list));
    }
}

/// Run `each` over every pool's own `hooks:` list.
fn each_pool_list(pairs: &mut Pairs, mut each: impl FnMut(&str, &mut Vec<Value>)) {
    let Some(Value::Map(pools)) = pairs.get_key_mut("pools") else {
        return;
    };
    for (name, pool) in pools.iter_mut() {
        let Some(name) = name.as_str() else {
            continue;
        };
        if POOLS_SECTION.contains(&name) {
            continue;
        }
        let Value::Map(fields) = pool else {
            continue;
        };
        let Some(Value::Array(list)) = fields.get_key_mut("hooks") else {
            continue;
        };
        each(name, list);
    }
}

/// The pools whose `hooks:` names no ordering strategy (they inherited a `default: true` hook).
fn inheriting_pools(pairs: &Pairs) -> Vec<String> {
    let mut out = Vec::new();
    let Some(Value::Map(pools)) = pairs.get_key("pools") else {
        return out;
    };
    for (name, pool) in pools {
        let Some(name) = name.as_str() else {
            continue;
        };
        if POOLS_SECTION.contains(&name) || !pool.is_mapping() {
            continue;
        }
        let named = pool
            .get("hooks")
            .and_then(ValueExt::as_sequence)
            .is_some_and(|list| {
                list.iter()
                    .any(|item| item.as_str().is_some_and(|item| STRATEGIES.contains(&item)))
            });
        if !named {
            out.push(name.to_owned());
        }
    }
    out
}

/// Fold the overlay's hooks into config.yaml's tree (§A3 1c), in `merge_into`'s order: each hook
/// by name, the global attachment, the tombstones last; then the names left undefined and the
/// `default: true` rule.
///
/// # Errors
/// CONFIG for a hook 1.5.5 could not read, a `${` in a folded string, or a `default: true` gate
/// that was the base ordering of some pool in 1.5.5.
pub(crate) fn fold(
    pairs: &mut Pairs,
    doc: &json::Map,
    o: &str,
    report: &mut Vec<String>,
) -> Result<(), Refusal> {
    let mut hooks = Vec::new();
    if let Some(value) = doc.get(&"hooks") {
        let entries = value
            .as_object()
            .ok_or_else(|| unparseable(o, "`hooks` is not an object"))?;
        for (name, entry) in entries.iter() {
            hooks.push(read(name, entry, o)?);
        }
    }
    let global = names(doc.get(&"global_hooks"), "global_hooks", o)?;
    let deleted = names(doc.get(&"deleted"), "deleted", o)?;
    if hooks.is_empty() && global.is_empty() && deleted.is_empty() {
        return Ok(());
    }

    let had_defs = pairs.contains_key("hooks");
    let mut defs: Pairs = match pairs.get_key("hooks") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Map(defs)) => defs.clone(),
        Some(_) => {
            return Err(Refusal::Config(
                "config.yaml `hooks` is not a mapping; 1.5.5 did not boot it either".to_owned(),
            ))
        }
    };
    for hook in &hooks {
        defs.insert_key(hook.name.as_str(), definition(hook, o)?);
        report.push(format!(
            "overlay `{o}`: hook `{}` is written to `hooks` as a 1.6.0 definition",
            hook.name
        ));
    }

    let base = base_global(pairs)?;
    let mut attached = base.clone();
    for name in &global {
        text(name, "global_hooks", o)?;
        if !attached.contains(name) {
            attached.push(name.clone());
        }
    }
    for hook in &hooks {
        if hook.global && !attached.contains(&hook.name) {
            attached.push(hook.name.clone());
        }
    }

    for name in &deleted {
        defs.retain(|(key, _)| key.as_str() != Some(name.as_str()));
        attached.retain(|item| item != name);
        each_pool_list(pairs, |_, list| {
            list.retain(|item| item.as_str() != Some(name.as_str()));
        });
        report.push(format!(
            "overlay `{o}`: hook `{name}` is deleted (an admin-API deletion): removed from \
             `hooks`, `pools.hooks` and every pool's `hooks`"
        ));
    }

    let defined = |name: &str| {
        STRATEGIES.contains(&name) || defs.iter().any(|(key, _)| key.as_str() == Some(name))
    };
    attached.retain(|name| {
        let keep = defined(name.as_str());
        if !keep {
            report.push(format!(
                "overlay `{o}`: `{name}` is removed from `pools.hooks`: no hook of that name is \
                 defined after the fold (1.5.5 skipped it)"
            ));
        }
        keep
    });
    each_pool_list(pairs, |pool, list| {
        list.retain(|item| {
            let keep = item.as_str().is_none_or(defined);
            if !keep {
                report.push(format!(
                    "overlay `{o}`: `{}` is removed from `pools.{pool}.hooks`: no hook of that \
                     name is defined after the fold (1.5.5 skipped it)",
                    item.as_str().unwrap_or_default()
                ));
            }
            keep
        });
    });

    for hook in &hooks {
        if !hook.default || deleted.contains(&hook.name) {
            continue;
        }
        if hook.kind == "gate" && hook.prompt != "rw" {
            let pools = inheriting_pools(pairs);
            if !pools.is_empty() {
                return Err(Refusal::Config(format!(
                    "the 1.5.5 overlay {o} marks hook `{}` `default: true`, which made it the \
                     base ordering of pools {} in 1.5.5; 1.6.0 has no default-hook flag. On \
                     1.5.5, PUT the hook with `default: false` and name the base ordering in \
                     those pools' `hooks:` lists, then upgrade again; nothing was written",
                    hook.name,
                    pools.join(", ")
                )));
            }
        }
        report.push(format!(
            "overlay `{o}`: hook `{}`'s `default: true` is dropped (1.6.0 has no default-hook \
             flag, and 1.5.5 ordered no pool by it)",
            hook.name
        ));
    }

    if had_defs || !defs.is_empty() {
        pairs.insert_key("hooks", Value::Map(defs));
    }
    if attached != base {
        set_global(pairs, attached);
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/overlay_hooks_tests.rs"]
mod tests;
