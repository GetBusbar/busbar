// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The 1.4.x -> 1.5.0 CONFIG MIGRATOR (`busbar --migrate-config <old.yaml>`) and the LOUD
//! FAIL-CLOSED 1.x detector the boot/`--validate` path runs (P9).
//!
//! Contract redefinition context: the config format is an OPERATOR artifact outside the SemVer
//! freeze, changed only WITH a migration path and a loud fail-closed boot. This module is both
//! halves of that promise:
//!
//! - [`detect_legacy_markers`] recognizes a 1.x config by its structural markers (a `governance:`
//!   block, `auth.group_map:`, a top-level `hooks:` registry, `*_env` secret fields, `target:` in
//!   a pool member, `auth.mode:`) so boot and `--validate` REFUSE to start with a named error
//!   instead of half-parsing a config whose semantics silently flipped (the `allowed_pools: []`
//!   all->none flip, vanished per-key budgets).
//! - [`migrate_config`] mechanically converts every DETERMINISTIC 1.4.x change to the 1.5.0
//!   shape and prints TODO comments wherever a human must decide. ZERO side effects: the caller
//!   prints the new YAML + a change summary; nothing is written.
//!
//! The migrator works on the RAW file (env `${VAR}` references pass through untouched) over the
//! `serde_yaml::Value` tree, so it is total: an unrecognized structure passes through or gains a
//! TODO, never a panic.

use serde_yaml::{Mapping, Value};

/// 1.4.x's real default `governance.db_path` (`DEFAULT_GOVERNANCE_DB` in the retired v1.4.1
/// schema) -- what an operator's SQLite governance database is really at when they never set
/// `db_path` explicitly. Migration must reproduce this exact default, not a 1.5.0-side one, so a
/// config that omitted `db_path` still finds its real, existing database file after migration.
const DEFAULT_GOVERNANCE_DB_1_4: &str = "busbar-governance.db";

/// The named boot error for a detected 1.x config (P9.3). Every marker is listed so the operator
/// sees the full scope before running the migrator.
pub(crate) fn legacy_config_error(markers: &[String]) -> String {
    format!(
        "this looks like a busbar 1.x config; run `busbar --migrate-config <config.yaml>` and \
         review the flagged items. 1.x markers found:\n  - {}\n\
         The 1.5.0 config redesign moved these surfaces (governance dissolved into \
         store/rate_card/groups/advanced; group_map became auth.role_bindings; hooks became \
         inline refs; *_env fields became secret references; pool member target became model). \
         Booting a 1.x config under 1.5.0 rules would silently flip semantics (most critically \
         `allowed_pools: []`, which now means NO pools), so busbar refuses to start instead.",
        markers.join("\n  - ")
    )
}

/// Scan a parsed YAML document for 1.x structural markers. Empty = not a 1.x config (any residual
/// incompatibility then fails through the normal deny-unknown-fields parse errors, which name the
/// exact key). Called by boot AND `--validate` before `DeployCfg` deserializes, so nothing from
/// 1.x ever boots-and-flips.
pub(crate) fn detect_legacy_markers(doc: &Value) -> Vec<String> {
    let mut markers = Vec::new();
    let Some(root) = doc.as_mapping() else {
        return markers;
    };
    let get = |m: &Mapping, k: &str| -> Option<Value> { m.get(Value::from(k)).cloned() };

    if get(root, "governance").is_some() {
        markers.push(
            "`governance:` block (dissolved into store / rate_card / per_request_fee / groups / \
             advanced / auth)"
                .to_string(),
        );
    }
    if let Some(auth) = get(root, "auth").and_then(|v| v.as_mapping().cloned()) {
        if get(&auth, "mode").is_some() {
            markers
                .push("`auth.mode:` (replaced by auth.chain / auth.upstream_credentials)".into());
        }
        if get(&auth, "group_map").is_some() {
            markers.push(
                "`auth.group_map:` (replaced by auth.role_bindings, NESTED BY MODULE; its \
                 rate/budget caps move to a groups: entry)"
                    .into(),
            );
        }
        if get(&auth, "client_tokens").is_some() {
            markers.push("`auth.client_tokens:` (static tokens removed; mint signed keys)".into());
        }
        if get(&auth, "modules").is_some() {
            markers.push(
                "`auth.modules:` (per-module trust caps removed; max_admin_scope moves onto the \
                 chain entry, allowed_groups is gone)"
                    .into(),
            );
        }
        if get(&auth, "group_map").is_some() {
            markers.push(
                "`auth.group_map:` (replaced by auth.role_bindings, NESTED BY MODULE)".into(),
            );
        }
        if get(&auth, "chain")
            .and_then(|v| v.as_sequence().cloned())
            .is_some_and(|seq| {
                seq.iter()
                    .any(|e| matches!(e.as_str(), Some("tokens") | Some("static-tokens")))
            })
        {
            markers.push(
                "`auth.chain: [tokens]` (the static-token module was removed; the 1.5.0 signed-key \
                 verifier is `keys`)"
                    .into(),
            );
        }
    }
    // The 1.4.x `DeployCfg` carried these at the TOP LEVEL; 1.5.0 relocated them (group_map ->
    // auth.role_bindings, admin_auth -> auth.admin_auth), so their presence at the root is a 1.x
    // marker in its own right (a real 1.4.x config that used them would otherwise pass straight
    // through to a `deny_unknown_fields` rejection).
    if get(root, "group_map").is_some() {
        markers.push(
            "top-level `group_map:` (moved under auth as auth.role_bindings, nested by module)"
                .into(),
        );
    }
    if get(root, "admin_auth").is_some() {
        markers.push("top-level `admin_auth:` (moved under auth as auth.admin_auth)".into());
    }
    if get(root, "hooks").is_some() {
        markers.push(
            "top-level `hooks:` registry block (hook instances are now inline refs in \
             pools.<p>.hooks / global_hooks)"
                .into(),
        );
    }
    if let Some(providers) = get(root, "providers").and_then(|v| v.as_mapping().cloned()) {
        for (name, p) in &providers {
            if p.as_mapping()
                .is_some_and(|m| m.contains_key(Value::from("api_key_env")))
            {
                markers.push(format!(
                    "`providers.{}.api_key_env:` (secret fields are now secret references: \
                     api_key: {{ env: VAR }})",
                    name.as_str().unwrap_or("?")
                ));
            }
        }
    }
    if let Some(pools) = get(root, "pools").and_then(|v| v.as_mapping().cloned()) {
        for (name, p) in &pools {
            let members = p
                .as_mapping()
                .and_then(|m| get(m, "members"))
                .and_then(|v| v.as_sequence().cloned())
                .unwrap_or_default();
            if members.iter().any(|mem| {
                mem.as_mapping()
                    .is_some_and(|m| m.contains_key(Value::from("target")))
            }) {
                markers.push(format!(
                    "`pools.{}.members[].target:` (renamed to model)",
                    name.as_str().unwrap_or("?")
                ));
            }
            // 1.4.x `on_exhausted: { action: … }` -> 1.5.0 bare keyword / `{ fallback_pool }`. The
            // `action:` wrapper is the exact user-reported silent pass-through (`deny_unknown_fields`
            // rejects `action`), so it must be a named marker too.
            if p.as_mapping()
                .and_then(|m| get(m, "on_exhausted"))
                .and_then(|v| v.as_mapping().cloned())
                .is_some_and(|m| m.contains_key(Value::from("action")))
            {
                markers.push(format!(
                    "`pools.{}.on_exhausted.action:` (the action wrapper is gone; use a bare \
                     `reject`/`least_bad` or `{{ fallback_pool: <pool> }}`)",
                    name.as_str().unwrap_or("?")
                ));
            }
        }
    }
    markers
}

/// The output of one migration run: the new YAML text plus the change / TODO / warning ledgers
/// the CLI prints as the summary.
pub(crate) struct MigrateOutput {
    pub(crate) yaml: String,
    pub(crate) changes: Vec<String>,
    pub(crate) todos: Vec<String>,
    pub(crate) warnings: Vec<String>,
}

/// Mechanically migrate a 1.4.x config document to the 1.5.0 shape (P9.2). Deterministic changes
/// are applied; judgment calls become TODO entries; the `allowed_pools: []` semantic flip gets a
/// LOUD warning per occurrence. Total and side-effect free.
pub(crate) fn migrate_config(raw: &str) -> Result<MigrateOutput, String> {
    let doc: Value =
        serde_yaml::from_str(raw).map_err(|e| format!("input is not valid YAML: {e}"))?;
    let Value::Mapping(mut root) = doc else {
        return Err("input is not a YAML mapping (expected a busbar config document)".to_string());
    };
    let mut changes: Vec<String> = Vec::new();
    let mut todos: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    migrate_governance(&mut root, &mut changes, &mut todos);
    migrate_auth(&mut root, &mut changes, &mut todos, &mut warnings);
    // Runs AFTER migrate_governance/migrate_auth: both may have populated `auth.admin_auth` (the
    // governance.admin_token secret ref), and this folds the 1.4.x TOP-LEVEL `admin_auth:` list in
    // on top, letting the token-bearing entry win over a bare duplicate.
    migrate_admin_auth(&mut root, &mut changes);
    // 1.5.2 scope collapse: rewrite any retired `hooks-register`/`mint` admin scope to `full`
    // (loud per-site warning). Runs after the auth/admin_auth folds so every scope site exists.
    migrate_dropped_scopes(&mut root, &mut warnings);
    migrate_providers(&mut root, &mut changes);
    migrate_hooks_block(&mut root, &mut changes, &mut todos);
    migrate_pools(&mut root, &mut changes, &mut todos);
    migrate_observability(&mut root, &mut changes);

    let body = serde_yaml::to_string(&Value::Mapping(root))
        .map_err(|e| format!("could not serialize the migrated config: {e}"))?;
    // serde_yaml cannot attach comments to nodes, so the TODO/WARNING ledger renders as a header
    // comment block on the printed document (each entry names its config path).
    let mut yaml = String::new();
    yaml.push_str("# busbar 1.5.0 config, migrated by `busbar --migrate-config`.\n");
    yaml.push_str("# Review before deploying; `busbar --validate` must pass.\n");
    for w in &warnings {
        yaml.push_str(&format!("# WARNING(migrate): {w}\n"));
    }
    for t in &todos {
        yaml.push_str(&format!("# TODO(migrate): {t}\n"));
    }
    yaml.push('\n');
    yaml.push_str(&body);
    Ok(MigrateOutput {
        yaml,
        changes,
        todos,
        warnings,
    })
}

fn take(m: &mut Mapping, k: &str) -> Option<Value> {
    m.remove(Value::from(k))
}

fn as_map(v: Value) -> Mapping {
    match v {
        Value::Mapping(m) => m,
        _ => Mapping::new(),
    }
}

/// The module name an `auth.chain` / `auth.admin_auth` entry answers to: a bare string entry IS the
/// module name; a `{ <module>: {…} }` map entry's single key is. Used to dedup + locate entries
/// when folding the 1.4.x TOP-LEVEL `admin_auth:` list and `auth.modules` caps into the 1.5.0
/// `auth.admin_auth` / chain entries.
fn entry_module_name(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Mapping(m) => m.keys().next().and_then(|k| k.as_str().map(str::to_string)),
        _ => None,
    }
}

/// Set `max_admin_scope` on the chain entry for `module`, converting a bare `- <module>` string
/// entry into its `{ <module>: { max_admin_scope } }` map form (or merging into an existing map
/// entry). Returns whether an entry for `module` was found + updated.
fn set_max_admin_scope(seq: &mut [Value], module: &str, scope: Value) -> bool {
    for e in seq.iter_mut() {
        if entry_module_name(e).as_deref() != Some(module) {
            continue;
        }
        if !matches!(e, Value::Mapping(_)) {
            let mut outer = Mapping::new();
            outer.insert(Value::from(module), Value::Mapping(Mapping::new()));
            *e = Value::Mapping(outer);
        }
        if let Value::Mapping(m) = e {
            if let Some(Value::Mapping(body)) = m.get_mut(Value::from(module)) {
                body.insert("max_admin_scope".into(), scope);
            }
        }
        return true;
    }
    false
}

/// 1.5.2 SCOPE COLLAPSE: the four-variant admin-scope diamond collapsed to `{read-only, full}` —
/// the delegated `hooks-register` and `mint` tokens are RETIRED and no longer parse (config_validate
/// rejects them). An UPGRADING config that still names either (in an `auth.chain`/`auth.admin_auth`
/// entry's `max_admin_scope`, or a `role_bindings.<module>.<role>.admin_scope`) is rewritten to
/// `full` — the compat-over-hard-fail choice — with a loud per-site WARNING so the operator can
/// tighten it back to `read-only` if `full` is too broad.
fn migrate_dropped_scopes(root: &mut Mapping, warnings: &mut Vec<String>) {
    fn collapsed(v: &Value) -> bool {
        matches!(v.as_str(), Some("hooks-register") | Some("mint"))
    }
    let Some(Value::Mapping(auth)) = root.get_mut(Value::from("auth")) else {
        return;
    };
    // (a) chain-entry `max_admin_scope:` on `auth.chain` / `auth.admin_auth`.
    for list_key in ["chain", "admin_auth"] {
        if let Some(Value::Sequence(seq)) = auth.get_mut(Value::from(list_key)) {
            for entry in seq.iter_mut() {
                let Value::Mapping(outer) = entry else {
                    continue;
                };
                let module = outer
                    .keys()
                    .next()
                    .and_then(|k| k.as_str().map(str::to_string));
                let Some(module) = module else { continue };
                if let Some(Value::Mapping(body)) = outer.get_mut(Value::from(module.as_str())) {
                    if let Some(scope) = body.get_mut(Value::from("max_admin_scope")) {
                        if collapsed(scope) {
                            let old = scope.as_str().unwrap_or("").to_string();
                            *scope = Value::from("full");
                            warnings.push(format!(
                                "auth.{list_key} entry '{module}' max_admin_scope: {old} -> full \
                                 (the delegated {old} scope is retired in 1.5.2; tighten to \
                                 read-only if full is too broad)"
                            ));
                        }
                    }
                }
            }
        }
    }
    // (b) `role_bindings.<module>.<role>.admin_scope`.
    if let Some(Value::Mapping(rb)) = auth.get_mut(Value::from("role_bindings")) {
        for (module_k, roles) in rb.iter_mut() {
            let module = module_k.as_str().unwrap_or("").to_string();
            let Value::Mapping(roles) = roles else {
                continue;
            };
            for (role_k, binding) in roles.iter_mut() {
                let role = role_k.as_str().unwrap_or("").to_string();
                let Value::Mapping(binding) = binding else {
                    continue;
                };
                if let Some(scope) = binding.get_mut(Value::from("admin_scope")) {
                    if collapsed(scope) {
                        let old = scope.as_str().unwrap_or("").to_string();
                        *scope = Value::from("full");
                        warnings.push(format!(
                            "role_bindings.{module}.{role}.admin_scope: {old} -> full (the \
                             delegated {old} scope is retired in 1.5.2; tighten to read-only if \
                             full is too broad)"
                        ));
                    }
                }
            }
        }
    }
}

/// Fold a 1.4.x TOP-LEVEL `admin_auth: [<module>, …]` (a `Vec<String>` of module names) into the
/// 1.5.0 `auth.admin_auth` (nested under `auth`, a `Vec<AuthChainEntry>`). 1.5.0's `DeployCfg`
/// carries NO top-level `admin_auth`, so a real 1.4.x list passed straight through and tripped
/// `deny_unknown_fields`. Bare names carry over as bare entries; when `migrate_governance` already
/// produced an `admin-tokens` entry (bearing the `governance.admin_token` secret ref), the
/// token-bearing entry WINS and the bare duplicate is skipped.
fn migrate_admin_auth(root: &mut Mapping, changes: &mut Vec<String>) {
    let Some(top) = take(root, "admin_auth") else {
        return;
    };
    let names: Vec<Value> = match top {
        Value::Sequence(s) => s,
        other => vec![other],
    };
    let Value::Mapping(auth) = root
        .entry("auth".into())
        .or_insert_with(|| Value::Mapping(Mapping::new()))
    else {
        return;
    };
    let mut list = take(auth, "admin_auth")
        .and_then(|v| v.as_sequence().cloned())
        .unwrap_or_default();
    let mut present: std::collections::BTreeSet<String> =
        list.iter().filter_map(entry_module_name).collect();
    for name in names {
        match entry_module_name(&name) {
            Some(m) if present.insert(m.clone()) => list.push(name),
            Some(_) => {} // already present (e.g. the token-bearing admin-tokens entry) - skip dup
            None => list.push(name),
        }
    }
    if !list.is_empty() {
        auth.insert("admin_auth".into(), Value::Sequence(list));
    }
    changes.push(
        "top-level admin_auth -> auth.admin_auth (1.5.0 nests the admin chain under auth)".into(),
    );
}

/// Map a 1.4.x `budget_period` word to the 1.5.0 C8 window noun.
fn window_noun(period: &str) -> &'static str {
    match period {
        "daily" | "day" => "day",
        "monthly" | "month" => "month",
        "minute" => "minute",
        "hour" => "hour",
        _ => "total",
    }
}

/// `governance:` -> store / rate_card / per_request_fee / groups / advanced / auth.admin_auth.
fn migrate_governance(root: &mut Mapping, changes: &mut Vec<String>, todos: &mut Vec<String>) {
    let Some(gov) = take(root, "governance") else {
        return;
    };
    let mut gov = as_map(gov);

    // 1.4.x's ONLY durable governance backend was SQLite at `governance.db_path` (default
    // "busbar-governance.db") -- `GovernanceCfg` never had a `store` module-selector field (verified
    // against the real v1.4.1 schema), so gating this migration on a `store:` key that no real 1.4.x
    // config could ever contain silently dropped `db_path` for EVERY real config and left the
    // migrated document with no `store:` section at all -- which defaults to the EPHEMERAL in-memory
    // store, silently orphaning every existing key/budget/audit row in the operator's real database on
    // first restart. Tolerate a stray `store:` key if a hand-edited/forward-compat config has one, but
    // never let its ABSENCE suppress the migration: presence of `governance:` (this function already
    // returned early if absent) with 1.4.x's real, always-SQLite semantics is what must drive this.
    let stray_module = take(&mut gov, "store").and_then(|v| v.as_str().map(str::to_string));
    let db_path = take(&mut gov, "db_path").and_then(|v| v.as_str().map(str::to_string));
    let module = stray_module.unwrap_or_else(|| "sqlite".to_string());
    {
        let mut store = Mapping::new();
        store.insert("module".into(), module.clone().into());
        let mut settings = Mapping::new();
        match (module.as_str(), db_path) {
            ("memory", _) => {}
            ("sqlite", Some(p)) => {
                settings.insert("db_path".into(), p.into());
            }
            // No explicit db_path: 1.4.x's real default was "busbar-governance.db", not memory.
            ("sqlite", None) => {
                settings.insert("db_path".into(), DEFAULT_GOVERNANCE_DB_1_4.into());
            }
            (_, Some(p)) => {
                settings.insert("url".into(), p.into());
            }
            (_, None) => {}
        }
        if let Some(busy) = take(&mut gov, "sqlite_busy_timeout_ms") {
            settings.insert("busy_timeout_ms".into(), busy);
        }
        if !settings.is_empty() {
            store.insert("settings".into(), Value::Mapping(settings));
        }
        root.insert("store".into(), Value::Mapping(store));
        changes.push("governance.db_path -> store: { module: sqlite, settings: { db_path } } (1.4.x's only durable backend was SQLite)".into());
    }

    if let Some(card) = take(&mut gov, "rate_card") {
        root.insert("rate_card".into(), card);
        changes.push("governance.rate_card -> top-level rate_card".into());
    }
    if let Some(fee) = take(&mut gov, "price_per_request_cents") {
        root.insert("per_request_fee".into(), fee);
        changes.push("governance.price_per_request_cents -> per_request_fee".into());
    }
    if let Some(p1k) = take(&mut gov, "price_per_1k_tokens_cents") {
        // N cents per 1k tokens = 10*N micro-units per token, on every tier of every model.
        let n = p1k.as_f64().unwrap_or(0.0);
        let per_tier = n * 10.0;
        let mut card = as_map(root.remove(Value::from("rate_card")).unwrap_or_default());
        let model_names: Vec<String> = root
            .get(Value::from("models"))
            .and_then(|v| v.as_mapping())
            .map(|m| {
                m.keys()
                    .filter_map(|k| k.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        for m in &model_names {
            if !card.contains_key(Value::from(m.as_str())) {
                let mut entry = Mapping::new();
                for tier in [
                    "input_utok",
                    "output_utok",
                    "cache_read_utok",
                    "cache_write_utok",
                ] {
                    entry.insert(tier.into(), per_tier.into());
                }
                card.insert(m.as_str().into(), Value::Mapping(entry));
            }
        }
        root.insert("rate_card".into(), Value::Mapping(card));
        changes.push(
            "governance.price_per_1k_tokens_cents -> a rate_card entry per model (N cents/1k = \
             10N micro-units/token on every tier)"
                .into(),
        );
        todos.push(
            "rate_card: entries were synthesized from the flat price_per_1k_tokens_cents; \
             replace the uniform per-tier rates with each model's real prices"
                .into(),
        );
    }
    if let Some(groups) = take(&mut gov, "budget_groups") {
        let mut out = Mapping::new();
        if let Value::Mapping(gm) = groups {
            for (name, g) in gm {
                let mut g = as_map(g);
                let mut entry = Mapping::new();
                if let Some(parent) = take(&mut g, "parent") {
                    entry.insert("parent".into(), parent);
                }
                let amount = take(&mut g, "max_budget_cents").unwrap_or(Value::from(0));
                let period = take(&mut g, "budget_period")
                    .and_then(|v| v.as_str().map(str::to_string))
                    .unwrap_or_else(|| "total".into());
                let mut limit = Mapping::new();
                limit.insert("budget".into(), amount);
                limit.insert("per".into(), window_noun(&period).into());
                entry.insert(
                    "limits".into(),
                    Value::Sequence(vec![Value::Mapping(limit)]),
                );
                out.insert(name, Value::Mapping(entry));
            }
        }
        root.insert("groups".into(), Value::Mapping(out));
        changes.push(
            "governance.budget_groups -> top-level groups (budget caps became generic limits)"
                .into(),
        );
    }
    let mut advanced = Mapping::new();
    if let Some(v) = take(&mut gov, "rate_sweep_interval") {
        advanced.insert("rate_sweep_interval".into(), v);
    }
    if let Some(v) = take(&mut gov, "usage_flush_interval_ms") {
        advanced.insert("usage_flush_interval_ms".into(), v);
    }
    if !advanced.is_empty() {
        root.insert("advanced".into(), Value::Mapping(advanced));
        changes.push("governance.rate_sweep_interval / usage_flush_interval_ms -> advanced".into());
    }
    if let Some(token) = take(&mut gov, "admin_token") {
        // The old field held the (env-interpolated) token VALUE. The 1.5.0 shape is a secret
        // reference on the admin-tokens module; a `${VAR}` reference converts mechanically.
        let auth = root
            .entry("auth".into())
            .or_insert_with(|| Value::Mapping(Mapping::new()));
        if let Value::Mapping(auth) = auth {
            let secret_ref: Value = match token.as_str() {
                Some(s) if s.starts_with("${") && s.ends_with('}') => {
                    let var = &s[2..s.len() - 1];
                    let mut m = Mapping::new();
                    m.insert("env".into(), var.into());
                    Value::Mapping(m)
                }
                _ => {
                    todos.push(
                        "auth.admin_auth[admin-tokens].token: governance.admin_token held a \
                         literal value; move it into an env var or file and reference it \
                         (token: { env: VAR } or { file: /path })"
                            .into(),
                    );
                    let mut m = Mapping::new();
                    m.insert("env".into(), "BUSBAR_ADMIN_TOKEN".into());
                    Value::Mapping(m)
                }
            };
            let mut body = Mapping::new();
            body.insert("token".into(), secret_ref);
            let mut entry = Mapping::new();
            entry.insert("admin-tokens".into(), Value::Mapping(body));
            auth.insert(
                "admin_auth".into(),
                Value::Sequence(vec![Value::Mapping(entry)]),
            );
        }
        changes.push(
            "governance.admin_token -> auth.admin_auth: [ admin-tokens: { token: <secret-ref> } ]"
                .into(),
        );
    }
    // `enabled` was removed in 1.5.0 (governance is presence-driven).
    if take(&mut gov, "enabled").is_some() {
        changes.push("governance.enabled removed (governance is presence-driven)".into());
    }
    for (k, _) in &gov {
        todos.push(format!(
            "governance.{}: no mechanical 1.5.0 equivalent; consult the 1.5.0 CHANGELOG",
            k.as_str().unwrap_or("?")
        ));
    }
}

/// `auth.mode` / `auth.group_map` / `auth.client_tokens` -> chain / role_bindings / (removed).
fn migrate_auth(
    root: &mut Mapping,
    changes: &mut Vec<String>,
    todos: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    // `group_map:` lived TOP-LEVEL in the shipped 1.4.x `DeployCfg` (NOT under `auth:`). Pull it
    // from the top level first, then fall back to the nested `auth.group_map` an earlier
    // transitional shape used. Sourced up front, before the `auth` mutable borrow, so both
    // locations are reachable. A real 1.4.x config that only carried a top-level group_map used to
    // pass it straight through -> 1.5.0 `deny_unknown_fields` rejected the unknown `group_map` key.
    let mut group_map = take(root, "group_map");

    // Nothing auth-shaped to migrate and no group_map to home: leave the document untouched.
    if !matches!(root.get(Value::from("auth")), Some(Value::Mapping(_))) && group_map.is_none() {
        return;
    }
    let Value::Mapping(auth) = root
        .entry("auth".into())
        .or_insert_with(|| Value::Mapping(Mapping::new()))
    else {
        // `auth:` is PRESENT but not a mapping (e.g. `auth: null` / `auth: [...]` - a malformed
        // 1.4.x shape this migrator cannot mechanically merge bindings into). The zero-side-effect
        // contract this module documents ("never silently drop, pass through or TODO") applies to
        // `group_map` too: it was already pulled off `root` above, so returning here without putting
        // it somewhere would silently vanish it from the migrated document. Restore it verbatim at
        // the top level (a human can still see and hand-migrate it) and surface a loud TODO so
        // `--validate`/manual review does not miss it.
        if let Some(gm) = group_map {
            root.insert("group_map".into(), gm);
            todos.push(
                "group_map: could not migrate to auth.role_bindings because `auth:` is present \
                 but is not a mapping (malformed 1.4.x config); group_map was left at the top \
                 level UNCHANGED - fix `auth:` by hand, then re-run the migrator so it can nest \
                 these bindings under auth.role_bindings"
                    .into(),
            );
        }
        return;
    };
    if group_map.is_none() {
        group_map = take(auth, "group_map");
    }

    // `auth.chain`: the 1.4.x static-token module (`tokens` / `static-tokens`) is REMOVED in 1.5.0;
    // the data-plane signed-key verifier is `keys`. Rewrite it (deduped) so `--validate` does not
    // reject the chain, and surface the re-mint TODO (1.x bearer tokens stop working).
    if let Some(Value::Sequence(chain)) = auth.get_mut(Value::from("chain")) {
        let mut rewrote = false;
        let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut out: Vec<Value> = Vec::new();
        for e in std::mem::take(chain) {
            let mapped = match e.as_str() {
                Some("tokens") | Some("static-tokens") => {
                    rewrote = true;
                    Value::from("keys")
                }
                _ => e,
            };
            match mapped.as_str().map(str::to_string) {
                Some(k) => {
                    if seen.insert(k) {
                        out.push(mapped);
                    }
                }
                None => out.push(mapped),
            }
        }
        *chain = out;
        if rewrote {
            changes.push(
                "auth.chain: tokens -> keys (static tokens removed; mint signed keys)".into(),
            );
            todos.push(
                "auth.chain: the static-token module is GONE in 1.5.0; every caller needs a minted \
                 signed key (POST /api/v1/admin/keys) - 1.x bearer tokens stop working"
                    .into(),
            );
            // The `keys` verifier REQUIRES a signing key (1.5.1: no auto-generation), so a config
            // that migrated tokens -> keys will not `--validate` until the operator provides one.
            if !auth.contains_key(Value::from("signing_key")) {
                todos.push(
                    "auth.signing_key: required now that the chain uses `keys` (busbar no longer \
                     auto-generates one); run `busbar --generate-signing-key` and set \
                     auth.signing_key to a secret reference for it ({file: /path} or {env: VAR}, \
                     shared across a fleet)"
                        .into(),
                );
            }
        }
    }

    // `auth.modules` (per-module trust-boundary caps) is REMOVED in 1.5.0. `max_admin_scope` has a
    // deterministic home: the chain/admin entry for that module (`{ <module>: { max_admin_scope } }`),
    // so the admin-scope CEILING is never silently lost. `allowed_groups` (the group-assertion
    // allowlist) has no 1.5.0 equivalent -> a TODO, never a silent drop.
    if let Some(Value::Mapping(modules)) = take(auth, "modules") {
        for (mod_name, caps) in modules {
            let mod_name = mod_name.as_str().unwrap_or("?").to_string();
            let caps = as_map(caps);
            if let Some(scope) = caps.get(Value::from("max_admin_scope")).cloned() {
                let mut applied = false;
                for list in ["chain", "admin_auth"] {
                    if let Some(Value::Sequence(seq)) = auth.get_mut(Value::from(list)) {
                        if set_max_admin_scope(seq, &mod_name, scope.clone()) {
                            applied = true;
                            break;
                        }
                    }
                }
                if applied {
                    changes.push(format!(
                        "auth.modules.{mod_name}.max_admin_scope -> auth chain entry \
                         {{ {mod_name}: {{ max_admin_scope }} }}"
                    ));
                } else {
                    todos.push(format!(
                        "auth.modules.{mod_name}.max_admin_scope: module '{mod_name}' is in no \
                         chain; set max_admin_scope on its chain/admin_auth entry once you add it"
                    ));
                }
            }
            if caps.contains_key(Value::from("allowed_groups")) {
                todos.push(format!(
                    "auth.modules.{mod_name}.allowed_groups: the per-module group-assertion \
                     allowlist was REMOVED in 1.5.0 (bindings are nested by module in \
                     role_bindings); re-express that trust boundary in role_bindings.{mod_name} or \
                     the module's own plugin config"
                ));
            }
        }
        changes.push(
            "auth.modules removed (max_admin_scope folded into the chain entry; allowed_groups \
             dropped with a TODO)"
                .into(),
        );
    }

    if let Some(mode) = take(auth, "mode").and_then(|v| v.as_str().map(str::to_string)) {
        match mode.as_str() {
            "passthrough" => {
                auth.insert("upstream_credentials".into(), "passthrough".into());
                changes.push(
                    "auth.mode: passthrough -> auth.upstream_credentials: passthrough".into(),
                );
            }
            "none" => {
                changes.push(
                    "auth.mode: none removed (an omitted chain is the open front door)".into(),
                );
            }
            other => {
                auth.insert("chain".into(), Value::Sequence(vec!["keys".into()]));
                changes.push(format!(
                    "auth.mode: {other} -> auth.chain: [keys] (static tokens are removed; mint \
                     signed keys)"
                ));
                todos.push(
                    "auth.chain: the static-token allowlist is GONE in 1.5.0; every caller needs \
                     a minted signed key (POST /api/v1/admin/keys) - 1.x bearer tokens stop \
                     working"
                        .into(),
                );
            }
        }
    }
    if take(auth, "client_tokens").is_some() {
        todos.push(
            "auth.client_tokens removed: static tokens are gone in 1.5.0; mint signed keys for \
             each caller (POST /api/v1/admin/keys)"
                .into(),
        );
        changes.push("auth.client_tokens removed (static tokens are gone)".into());
    }
    let Some(gm) = group_map else {
        return;
    };
    // Which MODULE do the old flat bindings nest under? Mechanical when the chain names exactly
    // one external module; otherwise a placeholder + TODO.
    let chain_modules: Vec<String> = auth
        .get(Value::from("chain"))
        .and_then(|v| v.as_sequence())
        .map(|seq| {
            seq.iter()
                .filter_map(|e| match e {
                    Value::String(s) => Some(s.clone()),
                    Value::Mapping(m) => {
                        m.keys().next().and_then(|k| k.as_str().map(str::to_string))
                    }
                    _ => None,
                })
                .filter(|m| m != "keys" && m != "tokens" && m != "admin-tokens")
                .collect()
        })
        .unwrap_or_default();
    let module = match chain_modules.as_slice() {
        [one] => one.clone(),
        _ => {
            todos.push(
                "auth.role_bindings: could not determine WHICH auth module the old group_map \
                 roles belong to; replace the '<module>' placeholder with the asserting module's \
                 name (bindings are nested by module in 1.5.0)"
                    .into(),
            );
            "<module>".to_string()
        }
    };
    // `group_map:` itself may not be a mapping (e.g. `group_map: [foo]` / `group_map: null` - a
    // malformed 1.4.x shape, mirroring the `auth:`-not-a-mapping case above). The `if let
    // Value::Mapping(gm) = gm` below used to silently no-op on anything else: `bindings` stayed
    // empty, but execution fell straight through to unconditionally push an EMPTY
    // `auth.role_bindings.<module>: {}` plus a misleading "auth.group_map -> auth.role_bindings"
    // changelog entry, as if the (actually-dropped) data had migrated. Catch that shape here and
    // restore it verbatim (same "never silently drop" contract as the non-mapping `auth:` case)
    // with a loud TODO, instead of claiming a migration that never happened.
    let Value::Mapping(gm) = gm else {
        root.insert("group_map".into(), gm);
        todos.push(
            "group_map: could not migrate to auth.role_bindings because `group_map:` itself is \
             not a mapping (malformed 1.4.x config); group_map was left at the top level \
             UNCHANGED - fix `group_map:` by hand, then re-run the migrator so it can nest these \
             bindings under auth.role_bindings"
                .into(),
        );
        return;
    };
    let mut bindings = Mapping::new();
    let mut generated_groups: Mapping = Mapping::new();
    {
        for (role, b) in gm {
            let role_name = role.as_str().unwrap_or("?").to_string();
            let mut b = as_map(b);
            let mut binding = Mapping::new();
            if let Some(pools) = take(&mut b, "allowed_pools") {
                if pools.as_sequence().is_some_and(|s| s.is_empty()) {
                    warnings.push(format!(
                        "auth.role_bindings.{module}.{role_name}.allowed_pools: [] - the MEANING \
                         of an empty list FLIPPED in 1.5.0: it used to mean ALL pools, it now \
                         means NO pools. If this role should reach every pool, DELETE the \
                         allowed_pools line (omitted = all); if it should reach none, keep []."
                    ));
                }
                binding.insert("allowed_pools".into(), pools);
            }
            if let Some(g) = take(&mut b, "budget_group").or_else(|| take(&mut b, "group")) {
                binding.insert("group".into(), g);
            }
            if let Some(scope) = take(&mut b, "admin_scope") {
                binding.insert("admin_scope".into(), scope);
            }
            // Inline caps (rpm/tpm/budget) no longer live on a binding: generate a groups entry.
            let rpm = take(&mut b, "rpm_limit");
            let tpm = take(&mut b, "tpm_limit");
            let budget = take(&mut b, "max_budget_cents");
            let period = take(&mut b, "budget_period")
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_else(|| "total".into());
            if rpm.is_some() || tpm.is_some() || budget.is_some() {
                let gname = format!("migrated-{role_name}");
                let mut limits: Vec<Value> = Vec::new();
                if let Some(r) = rpm {
                    let mut l = Mapping::new();
                    l.insert("requests".into(), r);
                    l.insert("per".into(), "minute".into());
                    limits.push(Value::Mapping(l));
                }
                if let Some(t) = tpm {
                    let mut l = Mapping::new();
                    l.insert("tokens".into(), t);
                    l.insert("per".into(), "minute".into());
                    limits.push(Value::Mapping(l));
                }
                if let Some(bu) = budget {
                    let mut l = Mapping::new();
                    l.insert("budget".into(), bu);
                    l.insert("per".into(), window_noun(&period).into());
                    limits.push(Value::Mapping(l));
                }
                let mut entry = Mapping::new();
                entry.insert("limits".into(), Value::Sequence(limits));
                generated_groups.insert(gname.as_str().into(), Value::Mapping(entry));
                if !binding.contains_key(Value::from("group")) {
                    binding.insert("group".into(), gname.as_str().into());
                }
                todos.push(format!(
                    "groups.{gname}: generated from the old group_map role '{role_name}' inline \
                     caps; review the limits and consider merging it into your real group tree"
                ));
                changes.push(format!(
                    "auth.group_map.{role_name} caps -> generated groups.{gname}"
                ));
            }
            bindings.insert(role, Value::Mapping(binding));
        }
    }
    let mut nested = Mapping::new();
    nested.insert(module.as_str().into(), Value::Mapping(bindings));
    auth.insert("role_bindings".into(), Value::Mapping(nested));
    changes.push(format!(
        "auth.group_map -> auth.role_bindings.{module} (nested by module)"
    ));
    if !generated_groups.is_empty() {
        let groups = root
            .entry("groups".into())
            .or_insert_with(|| Value::Mapping(Mapping::new()));
        if let Value::Mapping(groups) = groups {
            for (k, v) in generated_groups {
                groups.insert(k, v);
            }
        }
    }
}

/// `providers.*.api_key_env: VAR` -> `api_key: { env: VAR }`.
fn migrate_providers(root: &mut Mapping, changes: &mut Vec<String>) {
    let Some(Value::Mapping(providers)) = root.get_mut(Value::from("providers")) else {
        return;
    };
    for (name, p) in providers.iter_mut() {
        let Value::Mapping(p) = p else { continue };
        if let Some(var) = take(p, "api_key_env") {
            let mut secret = Mapping::new();
            secret.insert("env".into(), var);
            p.insert("api_key".into(), Value::Mapping(secret));
            changes.push(format!(
                "providers.{}.api_key_env -> api_key: {{ env: ... }}",
                name.as_str().unwrap_or("?")
            ));
        }
    }
}

/// The top-level `hooks:` registry -> inline refs in pools.<p>.hooks / global_hooks.
fn migrate_hooks_block(root: &mut Mapping, changes: &mut Vec<String>, todos: &mut Vec<String>) {
    let Some(hooks) = take(root, "hooks") else {
        return;
    };
    let Value::Mapping(hooks) = hooks else {
        return;
    };
    changes.push("top-level hooks: registry dissolved into inline refs".into());
    // Build an inline module ref from a registry entry.
    let inline_ref = |name: &str, h: &Mapping, todos: &mut Vec<String>| -> Value {
        let mut r = Mapping::new();
        let mut settings = as_map(h.get(Value::from("settings")).cloned().unwrap_or_default());
        if let Some(url) = h.get(Value::from("webhook")).and_then(|v| v.as_str()) {
            r.insert("module".into(), "webhook".into());
            settings.insert("url".into(), url.into());
        } else if let Some(path) = h.get(Value::from("socket")).and_then(|v| v.as_str()) {
            r.insert("module".into(), "socket".into());
            settings.insert("path".into(), path.into());
        } else {
            todos.push(format!(
                "hook '{name}': no socket/webhook transport found; pick module: webhook \
                 (settings.url) or module: socket (settings.path)"
            ));
            r.insert("module".into(), "webhook".into());
        }
        if !settings.is_empty() {
            r.insert("settings".into(), Value::Mapping(settings));
        }
        for typed in [
            "kind",
            "timeout_ms",
            "on_error",
            "on_empty",
            "at",
            "prompt",
            "user",
            "priority",
        ] {
            if let Some(v) = h.get(Value::from(typed)) {
                r.insert(typed.into(), v.clone());
            }
        }
        Value::Mapping(r)
    };
    let is_true =
        |h: &Mapping, k: &str| h.get(Value::from(k)).and_then(|v| v.as_bool()) == Some(true);

    let mut placed: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    // 1a. The 1.4.x TOP-LEVEL `global_hooks:` was a `Vec<String>` of REGISTRY names; 1.5.0's is a
    // list of inline refs (same shape as a pool's `hooks:`). Resolve each name to its inline ref so
    // a bare registry name never survives to trip `--validate` (a bare non-strategy name is not a
    // valid 1.5.0 global-hook ref). Entries already in inline-ref (map) form pass through.
    let mut global_list: Vec<Value> = Vec::new();
    for entry in take(root, "global_hooks")
        .and_then(|v| v.as_sequence().cloned())
        .unwrap_or_default()
    {
        match entry {
            Value::String(name) => {
                if let Some(h) = hooks
                    .get(Value::from(name.as_str()))
                    .and_then(|v| v.as_mapping())
                {
                    global_list.push(inline_ref(&name, h, todos));
                    placed.insert(name.clone());
                    changes.push(format!("global_hooks: '{name}' -> inline module ref"));
                } else {
                    // Not a registry hook - leave it (a human decides), but do not lose it.
                    global_list.push(Value::String(name));
                }
            }
            other => global_list.push(other),
        }
    }
    // 1b. Registry entries flagged `global: true` -> global_hooks, unless already placed by 1a (so a
    // hook that is BOTH named in global_hooks AND `global: true` appears exactly once, not twice).
    for (name, h) in &hooks {
        let (Some(name), Some(h)) = (name.as_str(), h.as_mapping()) else {
            continue;
        };
        if is_true(h, "global") && !placed.contains(name) {
            global_list.push(inline_ref(name, h, todos));
            placed.insert(name.to_string());
            changes.push(format!("hooks.{name} (global) -> global_hooks inline ref"));
        }
        if is_true(h, "default") {
            todos.push(format!(
                "hook '{name}' was `default: true` (the pool base ordering); the flag is gone - \
                 add the hook (or a built-in strategy) to each pool's hooks: list explicitly"
            ));
        }
    }
    if !global_list.is_empty() {
        root.insert("global_hooks".into(), Value::Sequence(global_list));
    }
    // 2. pool hook-name references -> inline refs in that pool's hooks list.
    if let Some(Value::Mapping(pools)) = root.get_mut(Value::from("pools")) {
        for (pname, p) in pools.iter_mut() {
            let Value::Mapping(p) = p else { continue };
            let mut list: Vec<Value> = Vec::new();
            let existing = take(p, "hooks")
                .and_then(|v| v.as_sequence().cloned())
                .unwrap_or_default();
            for entry in existing {
                match entry {
                    Value::String(name) => {
                        if let Some(h) = hooks
                            .get(Value::from(name.as_str()))
                            .and_then(|v| v.as_mapping())
                        {
                            list.push(inline_ref(&name, h, todos));
                            placed.insert(name.clone());
                            changes.push(format!(
                                "pools.{}.hooks: '{name}' -> inline module ref",
                                pname.as_str().unwrap_or("?")
                            ));
                        } else {
                            // A built-in strategy name (weighted/cheapest/...) stays bare.
                            list.push(name.into());
                        }
                    }
                    other => list.push(other),
                }
            }
            if !list.is_empty() {
                p.insert("hooks".into(), Value::Sequence(list));
            }
        }
    }
    // 3. Anything registered but never placed needs a human decision.
    for (name, _) in &hooks {
        let Some(name) = name.as_str() else { continue };
        if !placed.contains(name) {
            todos.push(format!(
                "hook '{name}' was registered but referenced by no pool and not global; add it \
                 as an inline ref under the pool(s) it should gate, or drop it"
            ));
        }
    }
}

/// Pool member/breaker/failover mechanical renames + cost-off-members.
fn migrate_pools(root: &mut Mapping, changes: &mut Vec<String>, todos: &mut Vec<String>) {
    let Some(Value::Mapping(pools)) = root.get_mut(Value::from("pools")) else {
        return;
    };
    for (pname, p) in pools.iter_mut() {
        let pname = pname.as_str().unwrap_or("?").to_string();
        let Value::Mapping(p) = p else { continue };
        // The retired singular `policy:` key names a base ordering strategy: PREPEND it to the
        // pool's `hooks:` list (a bare built-in name stays bare). Runs here (always) rather than
        // in `migrate_hooks_block` (which returns early for a config with no `hooks:` registry),
        // so a pool `policy:` migrates whether or not the config had a hooks block.
        if let Some(policy) = take(p, "policy").and_then(|v| v.as_str().map(str::to_string)) {
            let mut list = take(p, "hooks")
                .and_then(|v| v.as_sequence().cloned())
                .unwrap_or_default();
            list.insert(0, policy.as_str().into());
            p.insert("hooks".into(), Value::Sequence(list));
            changes.push(format!("pools.{pname}.policy -> hooks: [{policy}, ...]"));
        }
        if let Some(Value::Sequence(members)) = p.get_mut(Value::from("members")) {
            for mem in members.iter_mut() {
                let Value::Mapping(mem) = mem else { continue };
                if let Some(target) = take(mem, "target") {
                    mem.insert("model".into(), target);
                    changes.push(format!("pools.{pname}.members[].target -> model"));
                }
                if take(mem, "cost_per_mtok").is_some() {
                    todos.push(format!(
                        "pools.{pname}.members[].cost_per_mtok removed: rate_card is the ONLY \
                         cost source in 1.5.0; price the member's model there"
                    ));
                    changes.push(format!(
                        "pools.{pname}.members[].cost_per_mtok removed (rate_card is the cost \
                         source)"
                    ));
                }
            }
        }
        if let Some(Value::Mapping(breaker)) = p.get_mut(Value::from("breaker")) {
            if let Some(Value::Mapping(trip)) = breaker.get_mut(Value::from("trip")) {
                if let Some(v) = take(trip, "window_s") {
                    trip.insert("window_secs".into(), v);
                    changes.push(format!(
                        "pools.{pname}.breaker.trip.window_s -> window_secs"
                    ));
                }
                if let Some(v) = take(trip, "n") {
                    trip.insert("consecutive_n".into(), v);
                    changes.push(format!("pools.{pname}.breaker.trip.n -> consecutive_n"));
                }
            }
        }
        if let Some(Value::Mapping(failover)) = p.get_mut(Value::from("failover")) {
            if let Some(v) = take(failover, "deadline_secs") {
                failover.insert("timeout_secs".into(), v);
                changes.push(format!(
                    "pools.{pname}.failover.deadline_secs -> timeout_secs"
                ));
            }
            if let Some(v) = take(failover, "cap") {
                failover.insert("max_hops".into(), v);
                changes.push(format!("pools.{pname}.failover.cap -> max_hops"));
            }
        }
        migrate_on_exhausted(&pname, p, changes, todos);
    }
}

/// Rewrite a 1.4.x `on_exhausted: { action: <string> }` to the 1.5.0 [`OnExhaustedCfg`] shape.
///
/// 1.4.x wrapped the behavior in an `action:` string with several accepted spellings
/// (`reject`/`503`/`status_503`/`status503`, `least_bad`/`least-bad`/`leastbad`,
/// `fallback_pool:<name>`). 1.5.0 uses `deny_unknown_fields` and takes a BARE keyword
/// (`reject` / `least_bad`) or a `{ fallback_pool: <name> }` map -- so the 1.4.x `{ action: … }`
/// wrapper is rejected at parse with the exact user-reported error ("unknown field `action`").
/// This was a SILENT pass-through (migrate reported changes but never touched `on_exhausted`), the
/// precise failure class this migrator exists to prevent. A value already in the 1.5.0 form (a bare
/// string, or a `{ fallback_pool }` map with no `action:` key) is left untouched (idempotent).
fn migrate_on_exhausted(
    pname: &str,
    p: &mut Mapping,
    changes: &mut Vec<String>,
    todos: &mut Vec<String>,
) {
    let Some(oe) = p.get(Value::from("on_exhausted")).cloned() else {
        return;
    };
    // Only the 1.4.x `{ action: … }` MAP form needs rewriting; the `action` key is its tell.
    let Some(action) = oe
        .as_mapping()
        .and_then(|m| m.get(Value::from("action")))
        .and_then(|v| v.as_str())
    else {
        return;
    };
    let action = action.trim().to_string();
    let new_val: Value = if let Some(pool) = action.strip_prefix("fallback_pool:") {
        let pool = pool.trim();
        if pool.is_empty() {
            todos.push(format!(
                "pools.{pname}.on_exhausted: the 1.4.x `fallback_pool:` action named NO pool; set \
                 `on_exhausted: {{ fallback_pool: <pool> }}` to a real pool (left as `reject`)"
            ));
            Value::from("reject")
        } else {
            let mut fb = Mapping::new();
            fb.insert("fallback_pool".into(), pool.into());
            Value::Mapping(fb)
        }
    } else {
        match action.as_str() {
            "reject" | "503" | "status_503" | "status503" => Value::from("reject"),
            "least_bad" | "least-bad" | "leastbad" => Value::from("least_bad"),
            "fallback_pool" | "fallback" | "failover" => {
                todos.push(format!(
                    "pools.{pname}.on_exhausted: the 1.4.x `{action}` action needs a target pool; \
                     set `on_exhausted: {{ fallback_pool: <pool> }}` (left as `reject`)"
                ));
                Value::from("reject")
            }
            other => {
                todos.push(format!(
                    "pools.{pname}.on_exhausted: unrecognized 1.4.x action `{other}`; the 1.5.0 \
                     options are `reject` | `least_bad` | {{ fallback_pool: <pool> }} (left as \
                     `reject`)"
                ));
                Value::from("reject")
            }
        }
    };
    p.insert("on_exhausted".into(), new_val);
    changes.push(format!(
        "pools.{pname}.on_exhausted: {{ action: {action} }} -> 1.5.0 bare keyword / {{ fallback_pool }}"
    ));
}

/// `observability.otlp_endpoint` -> `otlp_url` (C7).
fn migrate_observability(root: &mut Mapping, changes: &mut Vec<String>) {
    let Some(Value::Mapping(obs)) = root.get_mut(Value::from("observability")) else {
        return;
    };
    if let Some(v) = take(obs, "otlp_endpoint") {
        obs.insert("otlp_url".into(), v);
        changes.push("observability.otlp_endpoint -> otlp_url".into());
    }
}

#[cfg(test)]
#[path = "tests/migrate_tests.rs"]
mod tests;
