// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The 1.4.x -> 1.5.0 CONFIG MIGRATOR (`busbar --migrate-config <old.yaml>`) and the LOUD
//! FAIL-CLOSED 1.x detector the boot/`--validate` path runs.
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

/// The named boot error for a detected 1.x config. Every marker is listed so the operator
/// sees the full scope before running the migrator.
///
/// IT MUST ALSO SPEAK TO THE ALREADY-MIGRATED OPERATOR. `take_shaped` deliberately PRESERVES a
/// MALFORMED block rather than deleting it (deleting the operator's data and announcing a migration
/// of it was the worse bug), so a `governance:` written in the wrong shape survives into the
/// migrator's OUTPUT — and that output then trips this very detector. Telling that operator to "run
/// `--migrate-config`" is advice that cannot help: they just did, and running it again reproduces
/// the same file. So the message names that case explicitly and gives the action that actually
/// resolves it (the migrator already emitted a `TODO` naming the exact path).
pub(crate) fn legacy_config_error(markers: &[String]) -> String {
    format!(
        "this looks like a busbar 1.x config; run `busbar --migrate-config <config.yaml>` and \
         review the flagged items. 1.x markers found:\n  - {}\n\
         The 1.5.0 config redesign moved these surfaces (governance dissolved into \
         store/rate_card/groups/advanced; group_map became auth.role_bindings; hooks became \
         inline refs; *_env fields became secret references; pool member target became model). \
         Booting a 1.x config under 1.5.0 rules would silently flip semantics (most critically \
         `allowed_pools: []`, which now means NO pools), so busbar refuses to start instead.\n\
         ALREADY RAN THE MIGRATOR AND STILL SEEING THIS? Then the flagged block was written in a \
         shape the migrator could not read, so it was LEFT EXACTLY AS YOU WROTE IT rather than \
         being silently dropped, and it is still a 1.x marker. Running `--migrate-config` again \
         will produce the same file. Look for the `# TODO` the migrator emitted for that exact \
         path, then either fix the block into the shape the TODO names or delete it by hand.",
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
    // A top-level `hooks:` key is AMBIGUOUS and must be distinguished by SHAPE, not mere presence
    // (1.5.3): the NEW named-definition map (every entry names a non-empty `module:` and carries no
    // legacy `socket:`/`webhook:` transport) is VALID and passes straight through to the typed parse;
    // a genuine 1.x REGISTRY (a `socket:`/`webhook:` entry, or any entry lacking `module:`) still
    // LOUD-FAILS here, because booting it under 1.5.x rules would silently drop the retired transport.
    // `is_new_hook_defs` is the SAME shape check the migrator uses to stay idempotent, so the two
    // cannot drift.
    if let Some(Value::Mapping(hooks)) = get(root, "hooks") {
        if !is_new_hook_defs(&hooks) {
            markers.push(
                "top-level `hooks:` REGISTRY block with legacy socket:/webhook: entries (1.x \
                 transports removed; a 1.5.3 `hooks:` DEFINITION entry names a `module:` — a \
                 `kind: hook` plugin — and carries `groups:`/`phase:` scope)"
                    .into(),
            );
        }
    }
    // The removed top-level `global_hooks:` list (1.5.0/1.5.2): a real config carrying it would
    // otherwise trip `deny_unknown_fields` with no upgrade breadcrumb. It moved to the reserved
    // `pools.hooks:` all-pools attach (1.5.3).
    if get(root, "global_hooks").is_some() {
        markers.push(
            "top-level `global_hooks:` (removed 1.5.3 → the reserved `pools.hooks:` all-pools \
             attach list; run `busbar --migrate-config`)"
                .into(),
        );
    }
    // 1.5.3 observability→export lift-out: the top-level `metrics:` block and the
    // `observability.request_log_webhook_url` / `max_inflight_webhook_deliveries` /
    // `webhook_delivery_timeout_secs` keys are RETIRED into the built-in exporters. An un-migrated
    // config carrying any of them LOUD-FAILS here (before the typed parse) with the migrate
    // breadcrumb, so a lifted-out sink is never silently lost. Uses the SHARED
    // `crate::config::RETIRED_OBSERVABILITY_KEYS` table so the marker, the migrator, and the
    // `augment_config_error` hint cannot drift.
    if get(root, "metrics").is_some() {
        markers.push(
            "top-level `metrics:` block (retired 1.5.3 → export.prometheus.settings.{buffer_seconds, \
             key_gauge_limit})"
                .into(),
        );
    }
    if let Some(obs) = get(root, "observability").and_then(|v| v.as_mapping().cloned()) {
        for (old, new) in crate::config::RETIRED_OBSERVABILITY_KEYS {
            // `metrics` is the top-level block handled just above; the rest are `observability.*` keys.
            if *old != "metrics" && get(&obs, old).is_some() {
                markers.push(format!("`observability.{old}:` (retired 1.5.3 → {new})"));
            }
        }
    }
    // ── the 1.5.3 GRAMMAR-LOCK retirements ───────────────────────────────────────────────────────
    // Every one of these would otherwise reach the typed parse as a bare `deny_unknown_fields`
    // rejection with no upgrade breadcrumb (or, for `observability:`, as a whole block whose
    // deletion would silently drop a trace sink). Detected HERE, before the typed parse, so the
    // operator gets the named key + its new home + the `--migrate-config` pointer. Uses the SHARED
    // `crate::config::RETIRED_CONFIG_KEYS_1_5_3` table so the marker, the migrator and the
    // `augment_config_error` hint cannot drift.
    let retired_home = |key: &str| -> &'static str {
        crate::config::RETIRED_CONFIG_KEYS_1_5_3
            .iter()
            .find(|(old, _)| *old == key)
            .map_or("its 1.5.3 replacement", |(_, new)| new)
    };
    // The `observability:` BLOCK is DELETED outright. Its last field folded into `export:`.
    if get(root, "observability").is_some() {
        markers.push(format!(
            "top-level `observability:` block (DELETED 1.5.3 → {}); all telemetry egress is now the \
             single `export:` surface",
            retired_home("otlp_url")
        ));
    }
    // The boot-guard flag inverted.
    if get(root, "admin_insecure").is_some() {
        markers.push(format!(
            "top-level `admin_insecure:` (retired 1.5.3 → {})",
            retired_home("admin_insecure")
        ));
    }
    if let Some(auth) = get(root, "auth").and_then(|v| v.as_mapping().cloned()) {
        // The credential mode moved to the `pools:` section.
        if get(&auth, "upstream_credentials").is_some() {
            markers.push(format!(
                "`auth.upstream_credentials:` (retired 1.5.3 → {})",
                retired_home("upstream_credentials")
            ));
        }
        // The 1.5.2 hosted-login block folded into the provider definition.
        if get(&auth, "methods").is_some() {
            markers.push(format!(
                "`auth.methods:` (retired 1.5.3 → {})",
                retired_home("methods")
            ));
        }
        // An INLINE chain entry (`- ad: { settings: … }`) is gone — a chain is now a list of
        // bare NAMES referencing `identity-providers:`. A map-shaped entry in either chain is the
        // tell; a list of plain strings is already in the new shape (idempotent).
        for plane in ["chain", "admin_auth"] {
            if get(&auth, plane)
                .and_then(|v| v.as_sequence().cloned())
                .is_some_and(|seq| seq.iter().any(|e| e.is_mapping()))
            {
                markers.push(format!(
                    "`auth.{plane}:` carries INLINE module entries (retired 1.5.3 → define the \
                     provider once under `identity-providers:` and reference it by bare name)"
                ));
            }
        }
    }
    // The TYPE-KEYED `export:` block (`export: { prometheus: { settings: … } }`) became a NAMED
    // map (`export: { metrics: { module: prometheus, settings: … } }`). Distinguished by SHAPE, not
    // presence: an entry naming a `module:` is already the new form and passes through (idempotent).
    if let Some(Value::Mapping(export)) = get(root, "export") {
        if export.values().any(|v| {
            v.as_mapping()
                .is_some_and(|m| !m.contains_key(Value::from("module")))
        }) {
            markers.push(
                "top-level `export:` is TYPE-KEYED (retired 1.5.3 → a NAMED map `<name>: { module, \
                 settings }`, so the same module can back several instances)"
                    .to_string(),
            );
        }
    }
    // The first-party Valkey store plugin was RENAMED to Valkey — repo, crate, artifact,
    // manifest `name` AND config `alias`. A retired spelling in `store.module:` is not a "wrong
    // backend": nothing in the renamed artifact's manifest matches it, so the store the operator
    // asked for simply does not exist and boot dies on the loader's generic "does not match any
    // plugin", which names neither the rename nor the fix. Caught HERE instead, with the named
    // marker + the migrate breadcrumb. Driven by the SHARED
    // `crate::config::RETIRED_STORE_MODULES_1_5_3` table so this marker and `migrate_store_module`'s
    // rewrite cannot drift over WHICH spellings are retired.
    if let Some(store) = get(root, "store").and_then(|v| v.as_mapping().cloned()) {
        if let Some(module) = get(&store, "module").and_then(|v| v.as_str().map(str::to_string)) {
            if crate::config::RETIRED_STORE_MODULES_1_5_3.contains(&module.as_str()) {
                markers.push(format!(
                    "`store.module: {module}` (RENAMED 1.5.3 → `{}`; the first-party store plugin \
                     is Valkey — artifact `{}-<ver>-<target>.tar.gz`, manifest name `{}`. The old \
                     name/alias resolve against NOTHING, so this would fail at boot with a generic \
                     unresolved-plugin error; run `busbar --migrate-config`)",
                    crate::config::STORE_MODULE_VALKEY,
                    crate::config::STORE_MODULE_VALKEY_ASSET_STEM,
                    crate::config::STORE_MODULE_VALKEY_NAME,
                ));
            }
        }
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
pub struct MigrateOutput {
    pub yaml: String,
    pub changes: Vec<String>,
    pub todos: Vec<String>,
    pub warnings: Vec<String>,
}

/// Mechanically migrate a 1.4.x config document to the 1.5.0 shape. Deterministic changes
/// are applied; judgment calls become TODO entries; the `allowed_pools: []` semantic flip gets a
/// LOUD warning per occurrence. Total and side-effect free.
pub fn migrate_config(raw: &str) -> Result<MigrateOutput, String> {
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
    // 1.6.0 UNIFIED POOLS. Runs AFTER `migrate_pools` (which has already renamed `members[].target`
    // -> `model` and folded `policy:` -> `hooks:`), so this only ever sees the settled LLM pool
    // shape when it lifts rich members to the uniform grammar. It also folds the unreleased
    // 1.6.0-dev `tool_pools:`/`agent_pools:` sections into the ONE neutral `pools:` map.
    migrate_unified_pools(&mut root, &mut changes, &mut todos);
    // 1.5.3 HARD rename of the tap `at:` vocabulary. Runs AFTER migrate_hooks_block (which builds
    // the inline-ref lists carrying the `at:` field) so every hook ref exists to rewrite.
    migrate_hook_stages(&mut root, &mut changes);
    // 1.6.0 CLEAN SLATE: rewrite the retired hook-DEFINITION key spellings on the settled top-level
    // `hooks:` named map — `plugin:` → `module:` and the single-stage `at:` → `phase:`. Runs AFTER
    // migrate_hooks_block (which has already lifted every legacy registry/inline surface into that
    // map) so it sees the final definition shape; idempotent on a config already in the 1.6.0 spelling.
    migrate_hook_def_keys(&mut root, &mut changes);
    migrate_observability(&mut root, &mut changes);
    migrate_response_headers(&mut root, &mut changes, &mut todos);
    // 1.5.3 observability→export lift-out. Runs AFTER migrate_observability (otlp rename) and
    // migrate_response_headers (emit_server_timing move) so this only sees the retired webhook +
    // metrics keys, and rewrites them into the new `export:` surface in place.
    migrate_observability_export(&mut root, &mut changes);
    // ── the 1.5.3 GRAMMAR-LOCK migrations ────────────────────────────────────────────────────────
    // Order matters: `migrate_export_named_map` runs AFTER `migrate_observability_export` (which
    // writes the TYPE-KEYED `export.request-log-webhook` / `export.prometheus` this then renames into
    // the NAMED map) and BEFORE `migrate_observability_block` folds `otlp_url` in as a named
    // instance, so a single run of the migrator lands a 1.4.x config directly in the 1.5.3 shape.
    super::migrate_export::migrate_export_named_map(&mut root, &mut changes);
    super::migrate_export::migrate_observability_block(&mut root, &mut changes);
    // AFTER both of the above: every export instance is in its named form by now, so the projection
    // pass sees the final `module:` of each one.
    super::migrate_export::migrate_export_projection(&mut root, &mut changes, &mut todos);
    migrate_admin_require_mtls(&mut root, &mut changes);
    migrate_pools_upstream_credentials(&mut root, &mut changes);
    migrate_identity_providers(&mut root, &mut changes, &mut todos);
    // 1.5.3: the first-party Valkey store plugin's rename to Valkey. Independent of every
    // migration above (it touches only `store.module`), so its position in this list is free; it runs
    // last so `migrate_governance`'s `governance.store:` -> `store:` lift has already produced the
    // 1.5.x `store:` block a 1.4.x config's Valkey backend would land in.
    migrate_store_module(&mut root, &mut changes, &mut todos);
    // 1.6.0 verify-on-call: the per-MCP-server `refresh_ttl:` (a background sweep cadence, default 6h)
    // becomes `verify_ttl:` (max verification staleness on the `tools/call` path, default 5s). A pure
    // key rename, but the SEMANTICS changed, so it carries a loud warning per occurrence.
    migrate_mcp_verify_ttl(&mut root, &mut changes, &mut warnings);

    let body = serde_yaml::to_string(&Value::Mapping(root))
        .map_err(|e| format!("could not serialize the migrated config: {e}"))?;
    // The header is written ONLY when there is something a human must act on.
    //
    // A migration that needs no decisions should produce a file indistinguishable from one somebody
    // wrote by hand — a 1.5.0 config brought to 1.5.3 is almost entirely mechanical, and stamping
    // "migrated by a tool, review before deploying" across the top of a clean result is noise the
    // operator then has to decide whether to delete. It also aged badly: the banner said "1.5.0
    // config" long after the target moved to 1.5.3.
    //
    // When there ARE warnings or TODOs the header stays, because then the file genuinely is not
    // finished and the reader needs to know that before it reaches a cluster. serde_yaml cannot
    // attach comments to nodes, so the ledger renders as a header block, each entry naming its
    // config path.
    let mut yaml = String::new();
    if !warnings.is_empty() || !todos.is_empty() {
        yaml.push_str(&format!(
            "# busbar {} config, migrated by `busbar --migrate-config`.\n",
            crate::config::CONFIG_TARGET_VERSION
        ));
        yaml.push_str("# The items below need a decision; `busbar --validate` must pass.\n");
        for w in &warnings {
            yaml.push_str(&format!("# WARNING(migrate): {w}\n"));
        }
        for t in &todos {
            yaml.push_str(&format!("# TODO(migrate): {t}\n"));
        }
        yaml.push('\n');
    }
    yaml.push_str(&body);
    Ok(MigrateOutput {
        yaml,
        changes,
        todos,
        warnings,
    })
}

pub(super) fn take(m: &mut Mapping, k: &str) -> Option<Value> {
    m.remove(Value::from(k))
}

/// 1.6.0 verify-on-call: rename each `tools.servers.<id>.refresh_ttl:` to `verify_ttl:`.
///
/// The KEY is renamed and the VALUE is carried over unchanged, because a rescale would guess at what
/// the operator meant. But the meaning is not the same: `refresh_ttl` was a BACKGROUND SWEEP CADENCE
/// (how often a daemon re-hashed the upstream with nobody watching, default `6h`); `verify_ttl` is the
/// MAX VERIFICATION STALENESS ON THE CALL PATH (the longest an observation may be reused before a
/// `tools/call` re-verifies, default `5s`). A value that was a sensible sweep cadence — `6h`, say — is
/// a large, explicit security downgrade as a staleness bound: it lets a rug-pulled tool be dispatched
/// for up to that long before the call re-verifies. So every rename carries a loud warning naming the
/// server and the value, telling the operator to reconsider it (a few seconds is the new default;
/// `0` is strict-live).
fn migrate_mcp_verify_ttl(
    root: &mut Mapping,
    changes: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    let Some(Value::Mapping(tools)) = root.get_mut(Value::from("tools")) else {
        return;
    };
    let Some(Value::Mapping(servers)) = tools.get_mut(Value::from("servers")) else {
        return;
    };
    let mut renamed = false;
    for (id, def) in servers.iter_mut() {
        let Value::Mapping(def) = def else { continue };
        let Some(value) = def.remove(Value::from("refresh_ttl")) else {
            continue;
        };
        let shown = value.as_str().unwrap_or("<non-string>").to_string();
        def.insert("verify_ttl".into(), value);
        renamed = true;
        warnings.push(format!(
            "tools.servers.{}.refresh_ttl -> verify_ttl (value `{shown}` carried over). The meaning \
             CHANGED: `refresh_ttl` was a background sweep cadence (default 6h); `verify_ttl` is the \
             MAX staleness before a `tools/call` re-verifies the upstream live (default 5s). Your \
             value is now a drift-serving window on the request path — reconsider it: a few seconds \
             is the new default, `0` is strict-live, and a large value is an explicit security \
             downgrade.",
            id.as_str().unwrap_or("?")
        ));
    }
    if renamed {
        changes.push(
            "tools.servers.<id>.refresh_ttl -> verify_ttl (verify-on-call replaces the background \
             refresh daemon; see the per-server WARNING for the semantics change)"
                .into(),
        );
    }
}

fn as_map(v: Value) -> Mapping {
    match v {
        Value::Mapping(m) => m,
        _ => Mapping::new(),
    }
}

/// The outcome of a SHAPE-CHECKED take ([`take_mapping`] / [`take_sequence`]) — the one seam every
/// "remove this key, then look at its shape" site in this module goes through.
///
/// THE BUG CLASS THIS TYPE EXISTS TO KILL. The shape it replaced was written five different times as
/// some spelling of `take(root, "k").and_then(|v| v.as_sequence().cloned()).unwrap_or_default()` (or
/// `take(...)` + `let Some(Mapping) = … else { continue }`). Every one of them REMOVED the operator's
/// key from the document and then, if the value was not the expected shape, dropped it on the floor:
/// no `changes` entry, no `todos` entry, no warning. The migrated document simply no longer contained
/// what the operator wrote — and because an ABSENT key is usually a legal default, `busbar --validate`
/// then PASSED, so nothing downstream ever surfaced the loss either. (The concrete report: a pool
/// written as `pools: { frontier: { hooks: baa-gate } }` — the scalar form, which 1.5.3 rejects loudly
/// — came out of `--migrate-config` with its compliance gate silently gone.)
///
/// TWO PROPERTIES MAKE THE RECURRENCE STRUCTURAL, not a matter of remembering:
///
/// 1. **Take-on-match.** The key is removed ONLY when the shape matches. A wrong-shaped value is
///    never lifted out of the document in the first place, so there is no window in which a caller
///    could forget to put it back — and it keeps its original POSITION in the mapping, not a
///    restored-at-the-end one. The helper pushes the operator-facing TODO itself.
/// 2. **`Malformed` is a distinct variant, and there is no `unwrap_or_default`.** `Absent` and
///    `Malformed` cannot be conflated (conflating them is exactly what `unwrap_or_default()` did),
///    and because this enum is not `Option` a caller cannot silently swallow the third case: the
///    compiler makes them write the arm. A caller that then goes on to WRITE the same key back must
///    check `contains_key` first — see [`migrate_hooks_block`]'s final write.
#[must_use]
pub(super) enum Taken<T> {
    /// The key was present in the expected shape and has been REMOVED from the document.
    Got(T),
    /// The key was not present at all. Nothing was changed.
    Absent,
    /// The key was present in the WRONG shape. It has been LEFT EXACTLY AS WRITTEN, in place, and a
    /// TODO naming it was already pushed — the caller must not migrate it, and must not overwrite it.
    Malformed,
}

/// Shape-check `m[k]`, and remove-and-return it ONLY if it matches. See [`Taken`] for why this is
/// take-on-match rather than take-then-restore. `ctx` is the operator-facing path prefix for the TODO
/// (`"pools.frontier"`), `want` the shape noun (`"a mapping"` / `"a list"`).
pub(super) fn take_shaped(
    m: &mut Mapping,
    k: &str,
    want: &str,
    matches_shape: fn(&Value) -> bool,
    ctx: &str,
    todos: &mut Vec<String>,
) -> Taken<Value> {
    let Some(found) = m.get(Value::from(k)) else {
        return Taken::Absent;
    };
    if !matches_shape(found) {
        let shape = one_line(found);
        let path = if ctx.is_empty() {
            k.to_string()
        } else {
            format!("{ctx}.{k}")
        };
        todos.push(format!(
            "{path}: is not {want} (`{shape}`) — it was left EXACTLY as written and was NOT \
             migrated, because this migrator cannot mechanically convert that shape and will never \
             silently drop what you wrote. Fix it by hand and re-run `--migrate-config`."
        ));
        return Taken::Malformed;
    }
    // Shape confirmed: NOW remove it. (The `get` above borrowed `m`; that borrow ends here.)
    Taken::Got(m.remove(Value::from(k)).expect("just found"))
}

/// [`take_shaped`] for a MAPPING-valued key.
pub(super) fn take_mapping(
    m: &mut Mapping,
    k: &str,
    ctx: &str,
    todos: &mut Vec<String>,
) -> Taken<Mapping> {
    match take_shaped(m, k, "a mapping", |v| v.is_mapping(), ctx, todos) {
        Taken::Got(Value::Mapping(mm)) => Taken::Got(mm),
        Taken::Got(_) => unreachable!("shape was checked"),
        Taken::Absent => Taken::Absent,
        Taken::Malformed => Taken::Malformed,
    }
}

/// [`take_shaped`] for a SEQUENCE-valued key.
fn take_sequence(
    m: &mut Mapping,
    k: &str,
    ctx: &str,
    todos: &mut Vec<String>,
) -> Taken<Vec<Value>> {
    match take_shaped(m, k, "a list", |v| v.is_sequence(), ctx, todos) {
        Taken::Got(Value::Sequence(s)) => Taken::Got(s),
        Taken::Got(_) => unreachable!("shape was checked"),
        Taken::Absent => Taken::Absent,
        Taken::Malformed => Taken::Malformed,
    }
}

/// Render one YAML value as a SHORT single line, for a ledger entry that has to name the malformed
/// shape it found (`auth: null`, `auth: []`, `auth: yes`). Multi-line/long renderings are truncated —
/// a ledger line is a human-readable pointer at the operator's own document, not a copy of it.
pub(super) fn one_line(v: &Value) -> String {
    let s = serde_yaml::to_string(v).unwrap_or_else(|_| "?".into());
    let s = s.replace('\n', " ");
    let s = s.trim().to_string();
    if s.chars().count() > 60 {
        format!("{}…", s.chars().take(60).collect::<String>())
    } else {
        s
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

/// The window a period this migrator cannot express EXACTLY falls back to: the LONGEST window that
/// still ROLLS. Never `total` — `total` is the ALL-TIME window (`WINDOW_TOTAL => 0`), which never
/// rolls, so collapsing an unrecognized RECURRING period onto it silently converts the operator's
/// recurring cap into a LIFETIME cap that, once spent, blocks the group forever. Every use of this
/// fallback is accompanied by a TODO naming the period AND the window it landed on.
const APPROX_WINDOW: &str = "month";

/// Map a 1.4.x `budget_period` word to the 1.5.0 window noun (`minute` | `hour` | `day` |
/// `month` | `total` — the only five [`crate::config::groups::LimitWindow`] spells).
///
/// THE ONE RULE: a migration must never silently change what the operator wrote. So the mapping is
/// split three ways instead of a catch-all:
///
/// * EXACT — the 1.4.x word has a 1.5.3 window with the same meaning. Silent, amount untouched.
/// * APPROXIMATED — the word names a real recurring period 1.5.3 has NO window for (`weekly`,
///   `yearly`). It lands on [`APPROX_WINDOW`] and pushes a TODO naming both, because the AMOUNT the
///   operator wrote no longer means what it meant.
/// * UNRECOGNIZED — anything else (a typo, a period from a fork). Same fallback, same loud TODO.
///
/// The `_ => "total"` this replaced was the silent third case: `weekly` (a period the tree's own
/// tests name as 1.4.x) and `hourly` both collapsed to the ALL-TIME window with no ledger entry at
/// all, turning a recurring cap into a lifetime one. `ctx` names the limit being migrated so the
/// TODO points at a specific group.
///
/// AN APPROXIMATION MAY NEVER LOOSEN THE CAP. Landing a SHORTER period on `month` (`weekly`) errs
/// TIGHTER — a week's allowance now has to last a month — which is fail-closed and safe to leave to
/// the operator's TODO. Landing a LONGER one on `month` (`yearly`) errs LOOSER: carrying the amount
/// over unchanged turned `max_budget_cents: 1200000, budget_period: yearly` into 1,200,000 cents
/// PER MONTH, i.e. TWELVE TIMES the annual cap the operator wrote, silently in force from first
/// boot for anyone who does not act on the TODO. So the returned DIVISOR rescales a longer period's
/// amount proportionally (a year is 12 months): the migrated limit preserves SPEND PER UNIT TIME,
/// which is the only reading of "the same cap, expressed in a window we have" that does not hand
/// out budget the operator never authorised. The TODO says so explicitly, with both numbers.
///
/// Returns `(window, divisor)`; `divisor` is always >= 1 and is 1 for every non-rescaled case.
fn window_noun(period: &str, ctx: &str, todos: &mut Vec<String>) -> (&'static str, u64) {
    match period {
        // EXACT — every spelling that has a 1.5.3 window meaning exactly the same thing.
        "minute" | "minutely" | "per_minute" => ("minute", 1),
        "hour" | "hourly" | "per_hour" => ("hour", 1),
        "day" | "daily" | "per_day" => ("day", 1),
        "month" | "monthly" | "per_month" => ("month", 1),
        // The 1.4.x default when `budget_period:` is absent, and an explicit all-time cap. This is
        // the ONLY path that may legitimately produce the never-rolling window.
        "total" | "lifetime" | "all_time" | "alltime" | "never" => ("total", 1),
        // APPROXIMATED / UNRECOGNIZED — LOUD, always.
        other => {
            let shorter = matches!(other, "week" | "weekly" | "per_week");
            let longer = matches!(
                other,
                "year" | "yearly" | "annual" | "annually" | "per_year"
            );
            // How many APPROX_WINDOWs the operator's period spans. Only a LONGER period rescales:
            // a shorter one already errs tighter, and an unrecognized one has no known length, so
            // neither is touched (and both keep their loud TODO).
            let divisor: u64 = if longer { 12 } else { 1 };
            let why = if shorter || longer {
                format!("1.5.3 has no `{other}` window")
            } else {
                format!("`{other}` is not a period this migrator recognizes")
            };
            let effect = if divisor > 1 {
                format!(
                    "The AMOUNT was DIVIDED BY {divisor} (rounded DOWN, floor 1) so the cap still \
                     spends at the same rate per unit time: a `{other}` amount left unchanged on a \
                     {APPROX_WINDOW} window would be {divisor}x the budget you wrote, in force from \
                     the first boot. Check the rescaled number"
            )
            } else {
                format!(
                    "The AMOUNT was carried over UNCHANGED, so the cap now spends over a \
                     {APPROX_WINDOW} instead of a `{other}` (tighter, never looser). Re-scale it \
                     by hand"
                )
            };
            todos.push(format!(
                "{ctx}: budget_period `{other}` -> per: {APPROX_WINDOW} ({why}). {effect}, or \
                 split the group's limits across the windows 1.5.3 does have (minute | hour | day \
                 | month | total)."
            ));
            (APPROX_WINDOW, divisor)
        }
    }
}

/// Divide a migrated cap AMOUNT by `divisor` (see [`window_noun`]): the rescale that keeps an
/// approximated window from LOOSENING the operator's cap.
///
/// Rounds DOWN, never up — rounding up is the loosening direction this whole path exists to
/// forbid — with a FLOOR OF 1, because `budget: 0` is rejected by `config_validate::validate`
/// (`config_validate/mod.rs`, the `limit.amount == 0` arm, NOT `validate_groups`) and a migration
/// must not emit a config that refuses to boot. A non-integer / unreadable amount (nothing 1.4.x
/// could write, but the migrator never panics on a hand-edited document) passes through untouched
/// rather than being guessed at.
fn rescale_amount(amount: Value, divisor: u64) -> Value {
    if divisor <= 1 {
        return amount;
    }
    match amount.as_u64() {
        Some(n) => Value::from((n / divisor).max(1)),
        None => amount,
    }
}

/// `governance:` -> store / rate_card / per_request_fee / groups / advanced / auth.admin_auth.
fn migrate_governance(root: &mut Mapping, changes: &mut Vec<String>, todos: &mut Vec<String>) {
    // Take-on-match (see `Taken`): `as_map` on a taken value silently turned a non-mapping
    // `governance:` into an empty one — i.e. removed the operator's block and replaced it with
    // nothing. A malformed one now stays in the document (and `governance:` is retired in 1.5.x, so
    // `--validate` also rejects it loudly) with a TODO.
    let mut gov = match take_mapping(root, "governance", "", todos) {
        Taken::Got(m) => m,
        Taken::Absent | Taken::Malformed => return,
    };

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
        // NEVER SILENTLY DROP: `root.remove` takes the key whatever its shape,
        // so a `rate_card:` that is not a mapping is put BACK verbatim and the synthesis is SKIPPED —
        // replacing an operator's malformed-but-present card with a generated one would destroy the
        // prices they wrote. `None` (no card at all) is the normal path and synthesizes from scratch.
        let existing_card = match root.remove(Value::from("rate_card")) {
            None => Some(Mapping::new()),
            Some(Value::Mapping(m)) => Some(m),
            Some(other) => {
                let shape = one_line(&other);
                root.insert("rate_card".into(), other);
                todos.push(format!(
                    "rate_card: is not a mapping (`{shape}`) — it was left EXACTLY as written, so \
                     `governance.price_per_1k_tokens_cents` was NOT folded into it. Fix the block \
                     by hand (`rate_card: {{ <model>: {{ input_utok: … }} }}`) and price each \
                     model, or delete it and re-run the migration."
                ));
                None
            }
        };
        if let Some(mut card) = existing_card {
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
    }
    // Take-on-match (see `Taken`): the old `take` + `if let Value::Mapping` removed a non-mapping
    // `budget_groups:` and then wrote an EMPTY top-level `groups:` plus a "budget caps became
    // generic limits" changelog line — announcing a migration of data it had just dropped.
    if let Taken::Got(gm) = take_mapping(&mut gov, "budget_groups", "governance", todos) {
        let mut out = Mapping::new();
        {
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
                let ctx = format!("groups.{}", name.as_str().unwrap_or("?"));
                let (window, divisor) = window_noun(&period, &ctx, todos);
                limit.insert("budget".into(), rescale_amount(amount, divisor));
                limit.insert("per".into(), window.into());
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
                    let (window, divisor) = window_noun(&period, &format!("groups.{gname}"), todos);
                    l.insert("budget".into(), rescale_amount(bu, divisor));
                    l.insert("per".into(), window.into());
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

/// Convert an OLD hook `at:` scalar to the NEW `phase:` list, stage-renamed via the shared
/// [`crate::config::RENAMED_HOOK_STAGES`] table (`route`→`candidate`, `attempt`→`routing`,
/// `completion`→`response`). `None` when `at` is not a recognizable scalar.
fn at_to_phase(at: &Value) -> Option<Value> {
    let s = at.as_str()?;
    let renamed = crate::config::RENAMED_HOOK_STAGES
        .iter()
        .find(|(o, _)| *o == s)
        .map(|(_, n)| *n)
        .unwrap_or(s);
    Some(Value::Sequence(vec![Value::from(renamed)]))
}

/// Build a 1.5.3 hook DEFINITION mapping (`{ module, settings, kind, phase, … }`) from an OLD hook
/// entry — either a 1.x REGISTRY entry (a `socket:`/`webhook:` transport) or a 1.5.0/1.5.2 INLINE
/// ref (`{ module: … }`). `module:` is derived (webhook→`webhook`+`settings.url`,
/// socket→`socket`+`settings.path`, else the entry's own `module:`/`plugin:`); the tap `at:` becomes
/// the renamed `phase:` list; the retired `global:`/`default:`/`signals:` flags are dropped with a
/// todo. Total: an unrecognized shape still yields a best-effort def.
fn hook_entry_to_def(name: &str, entry: &Value, todos: &mut Vec<String>) -> Value {
    let m = entry.as_mapping().cloned().unwrap_or_default();
    let mut def = Mapping::new();
    let mut settings = as_map(m.get(Value::from("settings")).cloned().unwrap_or_default());
    if let Some(url) = m.get(Value::from("webhook")).and_then(|v| v.as_str()) {
        def.insert("module".into(), "webhook".into());
        settings.insert("url".into(), url.into());
    } else if let Some(path) = m.get(Value::from("socket")).and_then(|v| v.as_str()) {
        def.insert("module".into(), "socket".into());
        settings.insert("path".into(), path.into());
    } else if let Some(module) = m.get(Value::from("module")).and_then(|v| v.as_str()) {
        def.insert("module".into(), module.into());
    } else if let Some(plugin) = m.get(Value::from("plugin")).and_then(|v| v.as_str()) {
        def.insert("module".into(), plugin.into());
    } else {
        todos.push(format!(
            "hook '{name}': no module/socket/webhook/plugin transport found; set `module:` to a \
             `kind: hook` plugin"
        ));
        def.insert("module".into(), "webhook".into());
    }
    if !settings.is_empty() {
        def.insert("settings".into(), Value::Mapping(settings));
    }
    for k in [
        "kind",
        "timeout_ms",
        "on_error",
        "on_empty",
        "prompt",
        "user",
        "priority",
        "groups",
    ] {
        if let Some(v) = m.get(Value::from(k)) {
            def.insert(k.into(), v.clone());
        }
    }
    if let Some(phase) = m.get(Value::from("at")).and_then(at_to_phase) {
        def.insert("phase".into(), phase);
    } else if let Some(phase) = m.get(Value::from("phase")) {
        def.insert("phase".into(), phase.clone());
    } else if m.get(Value::from("kind")).and_then(|v| v.as_str()) == Some("tap") {
        // SEMANTICS-PRESERVING (1.5.3): a legacy TAP with no `at:` fired at the REQUEST stage only.
        // Under the frozen 1.5.3 rule an omitted `phase:` means ALL FOUR core stages, so migrating
        // such a tap without pinning the stage would silently take it from one firing per request to
        // four. Write the old default explicitly — a migration must never change behavior.
        def.insert(
            "phase".into(),
            Value::Sequence(vec![Value::from("request")]),
        );
    }
    if m.get(Value::from("default")).and_then(|v| v.as_bool()) == Some(true) {
        todos.push(format!(
            "hook '{name}': the retired `default: true` flag is gone; name the base ordering \
             strategy in each pool's `hooks:` list explicitly"
        ));
    }
    if m.contains_key(Value::from("signals")) {
        todos.push(format!(
            "hook '{name}': the `signals:` declaration did not carry over automatically; re-add it \
             under the named `hooks:` entry if the hook still needs it"
        ));
    }
    Value::Mapping(def)
}

/// Whether a `hooks:` map is ALREADY the 1.5.3 named-definition shape (every entry is a map naming a
/// non-empty `module:` and carrying NO legacy `socket:`/`webhook:` transport). Used to make the
/// migration IDEMPOTENT (a config already in the new shape passes through untouched) and to preserve
/// the 1.x-vs-1.5.3 distinction the loud-fail detector also uses.
fn is_new_hook_defs(hooks: &Mapping) -> bool {
    !hooks.is_empty()
        && hooks.iter().all(|(_, e)| {
            e.as_mapping().is_some_and(|em| {
                em.get(Value::from("module"))
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| !s.trim().is_empty())
                    && !em.contains_key(Value::from("socket"))
                    && !em.contains_key(Value::from("webhook"))
            })
        })
}

/// A deterministic unique name for an auto-lifted hook definition: `base`, then `base-2`, `base-3`, …
fn uniq_def_name(defs: &Mapping, base: &str) -> String {
    if !defs.contains_key(Value::from(base)) {
        return base.to_string();
    }
    let mut n = 2usize;
    loop {
        let candidate = format!("{base}-{n}");
        if !defs.contains_key(Value::from(candidate.as_str())) {
            return candidate;
        }
        n += 1;
    }
}

/// 1.5.3 NAMED-HOOKS migration: converge the OLD hook surfaces onto the new shape — the top-level
/// `hooks:` NAMED-DEFINITION map plus the reserved `pools.hooks:` all-pools attach and per-pool
/// bare-name references. Handles three legacy sources, idempotently:
///   * a 1.x `hooks:` REGISTRY (socket:/webhook: entries) → named definitions (same names).
///   * `global_hooks:` (bare registry names OR 1.5.0/1.5.2 inline instances) → the reserved
///     `pools.hooks:` all-pools list (inline instances lifted to a named def first, with a todo).
///   * inline pool-hook instances (`pools.X.hooks: [{ module: … }]`) → a named def + a bare-name
///     reference in that pool (with a todo).
///
/// A config already in the new shape (a `hooks:` map of `module:` defs) passes through untouched.
fn migrate_hooks_block(root: &mut Mapping, changes: &mut Vec<String>, todos: &mut Vec<String>) {
    // Take-on-match (see `Taken`): a `hooks:` that is not a mapping stays EXACTLY where the operator
    // wrote it, with a TODO, instead of being lifted out and dropped.
    let hooks_src = match take_mapping(root, "hooks", "", todos) {
        Taken::Got(m) => Some(m),
        Taken::Absent | Taken::Malformed => None,
    };
    let mut defs = Mapping::new();
    let mut all_pools: Vec<Value> = Vec::new();

    if let Some(src) = hooks_src {
        if is_new_hook_defs(&src) {
            // Already the 1.5.3 named-definition map: keep verbatim (idempotent).
            defs = src;
        } else {
            // 1.x REGISTRY: convert every entry to a named def; a `global: true` entry also joins the
            // all-pools attach.
            for (k, entry) in &src {
                let Some(name) = k.as_str() else { continue };
                defs.insert(k.clone(), hook_entry_to_def(name, entry, todos));
                if entry
                    .as_mapping()
                    .and_then(|m| m.get(Value::from("global")))
                    .and_then(|v| v.as_bool())
                    == Some(true)
                {
                    all_pools.push(Value::from(name));
                }
            }
            changes.push(
                "top-level 1.x hooks: registry -> named hooks: definition map (1.5.3)".into(),
            );
        }
    }

    // `global_hooks:` -> the reserved `pools.hooks:` all-pools attach.
    let global_hooks_src = match take_sequence(root, "global_hooks", "", todos) {
        Taken::Got(s) => s,
        // Absent is the normal path; Malformed left the operator's value in place with a TODO (and
        // `global_hooks:` is a RETIRED key in 1.5.3, so a leftover one also fails `--validate` loudly
        // — which is the point: it is no longer possible for it to just vanish).
        Taken::Absent | Taken::Malformed => Vec::new(),
    };
    for entry in global_hooks_src {
        match entry {
            Value::String(name) => {
                if !all_pools.iter().any(|v| v.as_str() == Some(name.as_str())) {
                    all_pools.push(Value::from(name.as_str()));
                }
                changes.push(format!(
                    "global_hooks '{name}' -> pools.hooks all-pools attach (1.5.3)"
                ));
            }
            Value::Mapping(m) => {
                let base = m
                    .get(Value::from("module"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("hook")
                    .to_string();
                let nm = uniq_def_name(&defs, &base);
                let def = hook_entry_to_def(&nm, &Value::Mapping(m), todos);
                defs.insert(Value::from(nm.as_str()), def);
                all_pools.push(Value::from(nm.as_str()));
                todos.push(format!(
                    "global_hooks inline instance lifted to a named hook '{nm}' + a pools.hooks \
                     all-pools reference; review the auto-generated name"
                ));
            }
            other => all_pools.push(other),
        }
    }

    // Inline pool-hook instances -> named def + bare-name reference in that pool.
    if let Some(Value::Mapping(pools)) = root.get_mut(Value::from("pools")) {
        let pool_names: Vec<Value> = pools.keys().cloned().collect();
        for pk in pool_names {
            if pk.as_str() == Some("hooks") {
                continue; // the reserved all-pools key, not a pool
            }
            let Some(Value::Mapping(p)) = pools.get_mut(&pk) else {
                continue;
            };
            let pool_ctx = format!("pools.{}", pk.as_str().unwrap_or("?"));
            let existing = match take_sequence(p, "hooks", &pool_ctx, todos) {
                Taken::Got(s) => s,
                // THE reported case: `pools.<x>.hooks: baa-gate` (the scalar form 1.5.3 rejects).
                // It stays in the document with a TODO — before this it was removed here and never
                // written back, and since an absent `hooks:` is a legal default `--validate` then
                // PASSED with the pool's rejecting compliance gate silently gone.
                Taken::Absent | Taken::Malformed => continue,
            };
            let mut new_list: Vec<Value> = Vec::new();
            for entry in existing {
                match entry {
                    Value::Mapping(m) => {
                        let base = m
                            .get(Value::from("module"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("hook")
                            .to_string();
                        let nm = uniq_def_name(&defs, &base);
                        let def = hook_entry_to_def(&nm, &Value::Mapping(m), todos);
                        defs.insert(Value::from(nm.as_str()), def);
                        new_list.push(Value::from(nm.as_str()));
                        todos.push(format!(
                            "pools.{}.hooks inline instance lifted to a named hook '{nm}' + a \
                             bare-name reference",
                            pk.as_str().unwrap_or("?")
                        ));
                    }
                    // A strategy keyword or an already-bare hook name passes through.
                    other => new_list.push(other),
                }
            }
            if !new_list.is_empty() {
                p.insert("hooks".into(), Value::Sequence(new_list));
            }
        }
    }

    if !defs.is_empty() {
        // The key is still present ⇒ `take_mapping` above found it MALFORMED and deliberately left
        // the operator's value in place. Writing here would destroy exactly what that arm preserved,
        // so it doesn't — it says so instead (`Taken`, property 2).
        if root.contains_key(Value::from("hooks")) {
            todos.push(format!(
                "hooks: {} hook definition(s) lifted from `global_hooks:`/inline pool hooks could \
                 NOT be written, because the top-level `hooks:` key is present in a shape this \
                 migrator cannot merge into and was left as you wrote it. Fix `hooks:` (a mapping \
                 of NAME -> {{ module: … }}) and re-run `--migrate-config`.",
                defs.len()
            ));
        } else {
            root.insert("hooks".into(), Value::Mapping(defs));
        }
    }
    if !all_pools.is_empty() {
        let pools = root
            .entry("pools".into())
            .or_insert_with(|| Value::Mapping(Mapping::new()));
        if let Value::Mapping(pm) = pools {
            // Merge with any existing reserved all-pools list (idempotent dedup).
            let mut merged = match take_sequence(pm, "hooks", "pools", todos) {
                Taken::Got(s) => s,
                Taken::Absent => Vec::new(),
                // A malformed reserved `pools.hooks:` stays as written; the attaches cannot be
                // merged into it, so say so rather than replacing the operator's value.
                Taken::Malformed => {
                    todos.push(
                        "pools.hooks: the all-pools hook attaches derived from this config could \
                         NOT be merged in, because `pools.hooks:` is present in a shape this \
                         migrator cannot merge into and was left as you wrote it. Fix it (a list \
                         of hook names) and re-run `--migrate-config`."
                            .into(),
                    );
                    return;
                }
            };
            for n in all_pools {
                let dup = n.as_str().is_some() && merged.iter().any(|v| v.as_str() == n.as_str());
                if !dup {
                    merged.push(n);
                }
            }
            pm.insert("hooks".into(), Value::Sequence(merged));
        }
    }
}

/// Pool member/breaker/failover mechanical renames + cost-off-members.
/// 1.5.4/1.6.0-dev → 1.6.0 UNIFIED `pools:`. Two mechanical moves, both zero-behaviour-change:
///
/// 1. FOLD `tool_pools:`/`agent_pools:` INTO `pools:`. These are unreleased (1.6.0-dev) and already
///    carry the uniform grammar (`members: [bare-name]` + `repeatable:`), so the fold is a plain map
///    merge into the ONE neutral `pools:` section. A pool-name collision across the three sections is
///    left for the operator (a todo) — it is a real ambiguity, not something the tool may silently pick.
/// 2. LIFT rich-object LLM `pools:` members to the uniform shape. A member that carries ONLY
///    `model` (+ `weight`) becomes a bare name, and any non-default weight is lifted to a pool-level
///    `weights: { name: n }` map. A member that also carries per-member capabilities
///    (`context_max`/`reasoning`/`tier`/`attempt_timeout_ms`/`tags`) is LEFT rich (still valid 1.6.0
///    grammar) with a todo pointing at where each capability now belongs (the `models:` noun, or a
///    single pool-level `tier:`/`attempt_timeout_ms:`) — lifting it blindly would drop or flatten a
///    per-member value, so the conservative move keeps behaviour byte-identical.
fn migrate_unified_pools(root: &mut Mapping, changes: &mut Vec<String>, todos: &mut Vec<String>) {
    // (1) Fold the two renamed sections into `pools:`.
    for section in ["tool_pools", "agent_pools"] {
        let Some(Value::Mapping(folded)) = take(root, section) else {
            continue;
        };
        // Ensure a `pools:` mapping exists to merge into.
        if !matches!(root.get(Value::from("pools")), Some(Value::Mapping(_))) {
            root.insert("pools".into(), Value::Mapping(Mapping::new()));
        }
        let Some(Value::Mapping(pools)) = root.get_mut(Value::from("pools")) else {
            // Unreachable given the insert above, but keep the section rather than dropping it.
            root.insert(section.into(), Value::Mapping(folded));
            continue;
        };
        // Un-foldable (name-collision) entries are collected and re-attached under the old section
        // key AFTER the `pools` borrow ends — `--validate` then rejects the stale section loudly.
        let mut collisions: Mapping = Mapping::new();
        for (name, def) in folded {
            if pools.contains_key(&name) {
                todos.push(format!(
                    "`{section}.{}` could not be folded into `pools:`: a pool of that name already \
                     exists. 1.6.0 has ONE neutral `pools:` map with globally-unique names — rename \
                     one of the two and re-run `--migrate-config`.",
                    name.as_str().unwrap_or("?")
                ));
                collisions.insert(name, def);
            } else {
                changes.push(format!(
                    "{section}.{} -> pools.{} (unified `pools:`)",
                    name.as_str().unwrap_or("?"),
                    name.as_str().unwrap_or("?")
                ));
                pools.insert(name, def);
            }
        }
        if !collisions.is_empty() {
            root.insert(section.into(), Value::Mapping(collisions));
        }
    }

    // (2) Lift rich LLM members to the uniform shape.
    let Some(Value::Mapping(pools)) = root.get_mut(Value::from("pools")) else {
        return;
    };
    // The reserved section-level keys are not pools.
    let reserved = ["hooks", "upstream_credentials"];
    for (pname, p) in pools.iter_mut() {
        let pname = pname.as_str().unwrap_or("?").to_string();
        if reserved.contains(&pname.as_str()) {
            continue;
        }
        let Value::Mapping(p) = p else { continue };
        let Some(Value::Sequence(members)) = p.get_mut(Value::from("members")) else {
            continue;
        };
        let mut lifted_weights: Mapping = Mapping::new();
        let mut any_lift = false;
        for mem in members.iter_mut() {
            // Already a bare name — nothing to lift.
            let Value::Mapping(m) = mem else { continue };
            let Some(model) = m
                .get(Value::from("model"))
                .and_then(|v| v.as_str())
                .map(str::to_string)
            else {
                continue;
            };
            let has_caps = [
                "context_max",
                "reasoning",
                "tier",
                "attempt_timeout_ms",
                "tags",
            ]
            .iter()
            .any(|k| m.contains_key(Value::from(*k)));
            if has_caps {
                todos.push(format!(
                    "pools.{pname}: member `{model}` carries per-member capabilities \
                     (context_max/reasoning move to the `models:` entry; a single tier / \
                     attempt_timeout_ms can move to the pool). Left as a rich member (valid 1.6.0) \
                     — flatten it by hand if you want the uniform bare-name grammar."
                ));
                continue;
            }
            // Weight-only (or model-only) member: lift to a bare name, and record any non-default
            // weight on the pool-level `weights:` map.
            if let Some(w) = m.get(Value::from("weight")).and_then(|v| v.as_u64()) {
                if w != 1 {
                    lifted_weights.insert(model.as_str().into(), Value::from(w));
                }
            }
            *mem = Value::from(model);
            any_lift = true;
        }
        if !lifted_weights.is_empty() {
            // Merge into an existing `weights:` if the operator already wrote one (operator's own
            // entries win — we only ADD the ones we lifted).
            match p.get_mut(Value::from("weights")) {
                Some(Value::Mapping(existing)) => {
                    for (k, v) in lifted_weights {
                        existing.entry(k).or_insert(v);
                    }
                }
                _ => {
                    p.insert("weights".into(), Value::Mapping(lifted_weights));
                }
            }
            changes.push(format!(
                "pools.{pname}.members[].weight -> pools.{pname}.weights (uniform members)"
            ));
        } else if any_lift {
            changes.push(format!(
                "pools.{pname}.members[] rich objects -> uniform bare names"
            ));
        }
    }
}

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
        // Take-on-match, in BOTH keys (see `Taken`). `policy:` is only removed once it is confirmed
        // to be a scalar name, and the prepend only happens once `hooks:` is confirmed absent or a
        // real list — so neither key can be lifted out and dropped, and a malformed `hooks:` is
        // never overwritten by a synthesized one-element list.
        let policy = p
            .get(Value::from("policy"))
            .and_then(|v| v.as_str())
            .map(str::to_string);
        if let Some(policy) = policy {
            let pool_ctx = format!("pools.{pname}");
            match take_sequence(p, "hooks", &pool_ctx, todos) {
                Taken::Got(mut list) => {
                    take(p, "policy");
                    list.insert(0, policy.as_str().into());
                    p.insert("hooks".into(), Value::Sequence(list));
                    changes.push(format!("pools.{pname}.policy -> hooks: [{policy}, ...]"));
                }
                Taken::Absent => {
                    take(p, "policy");
                    p.insert("hooks".into(), Value::Sequence(vec![policy.as_str().into()]));
                    changes.push(format!("pools.{pname}.policy -> hooks: [{policy}]"));
                }
                Taken::Malformed => todos.push(format!(
                    "pools.{pname}.policy: could not be folded into `hooks:` (see the `hooks:` todo \
                     above); BOTH keys were left EXACTLY as written. The retired `policy:` key is \
                     rejected by 1.5.3, so fix `hooks:` and re-run `--migrate-config`."
                )),
            }
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

/// `observability.otlp_endpoint` -> `otlp_url`.
fn migrate_observability(root: &mut Mapping, changes: &mut Vec<String>) {
    let Some(Value::Mapping(obs)) = root.get_mut(Value::from("observability")) else {
        return;
    };
    if let Some(v) = take(obs, "otlp_endpoint") {
        obs.insert("otlp_url".into(), v);
        changes.push("observability.otlp_endpoint -> otlp_url".into());
    }
}

/// 1.5.3 observability→export lift-out: mechanically rewrite the retired
/// `observability.request_log_webhook_url` (+ `max_inflight_webhook_deliveries` /
/// `webhook_delivery_timeout_secs`) → `export.request-log-webhook.settings.*`, and the top-level
/// `metrics:` block → `export.prometheus.settings.*`. Because the exporters are BUILT-IN (not
/// tarball plugins), this is a full mechanical rewrite (not just a printed TODO) — the config breaks
/// ONCE and the sink is preserved, not lost. Idempotent: a config already in the new shape has no
/// retired keys to move, so a second run is a no-op.
fn migrate_observability_export(root: &mut Mapping, changes: &mut Vec<String>) {
    // Ensure `export` exists as a mapping, returning a handle to splice a sub-exporter into.
    fn export_mut(root: &mut Mapping) -> &mut Mapping {
        let entry = root
            .entry("export".into())
            .or_insert_with(|| Value::Mapping(Mapping::new()));
        if !matches!(entry, Value::Mapping(_)) {
            *entry = Value::Mapping(Mapping::new());
        }
        match entry {
            Value::Mapping(m) => m,
            _ => unreachable!("just normalized to a mapping"),
        }
    }

    // (a) request-log webhook keys off `observability:`.
    let mut webhook_settings = Mapping::new();
    if let Some(Value::Mapping(obs)) = root.get_mut(Value::from("observability")) {
        if let Some(url) = take(obs, "request_log_webhook_url") {
            webhook_settings.insert("url".into(), url);
        }
        if let Some(v) = take(obs, "max_inflight_webhook_deliveries") {
            webhook_settings.insert("max_inflight_deliveries".into(), v);
        }
        if let Some(v) = take(obs, "webhook_delivery_timeout_secs") {
            webhook_settings.insert("delivery_timeout_secs".into(), v);
        }
        // An `observability:` mapping emptied to nothing is dropped so the migrated doc has no bare
        // `observability: {}` (which is valid but noise). Keep it if `otlp_url` (or anything) remains.
        if obs.is_empty() {
            root.remove(Value::from("observability"));
        }
    }
    if webhook_settings.contains_key(Value::from("url")) {
        let mut body = Mapping::new();
        body.insert("settings".into(), Value::Mapping(webhook_settings));
        export_mut(root).insert("request-log-webhook".into(), Value::Mapping(body));
        changes.push(
            "observability.request_log_webhook_url (+ webhook limits) -> \
             export.request-log-webhook.settings (built-in exporter)"
                .into(),
        );
    }

    // (b) the top-level `metrics:` block -> export.prometheus.settings.
    let removed_metrics = root.remove(Value::from("metrics"));
    if let Some(Value::Mapping(mut metrics)) = removed_metrics {
        let mut settings = Mapping::new();
        if let Some(v) = take(&mut metrics, "buffer_seconds") {
            settings.insert("buffer_seconds".into(), v);
        }
        if let Some(v) = take(&mut metrics, "key_gauge_limit") {
            settings.insert("key_gauge_limit".into(), v);
        }
        // Carry through any other keys verbatim (forward-compat) so nothing is silently dropped.
        for (k, v) in metrics {
            settings.insert(k, v);
        }
        let mut body = Mapping::new();
        body.insert("settings".into(), Value::Mapping(settings));
        export_mut(root).insert("prometheus".into(), Value::Mapping(body));
        changes.push("metrics: block -> export.prometheus.settings (built-in exporter)".into());
    } else if let Some(other) = removed_metrics {
        // Same class as the `observability:` arm above: the key IS retired, so a
        // malformed block is still deleted — but `root.remove` already took it, so the deletion must
        // be RECORDED or it happened invisibly.
        changes.push(format!(
            "metrics: block removed (RETIRED in 1.5.3; it was not a mapping — the value `{}` \
             carried no settings foldable into export.prometheus)",
            one_line(&other)
        ));
    }
}

/// `observability.emit_server_timing` -> `advanced.response_headers.server_timing` (every
/// busbar-injected response header unified under one opt-in `advanced.response_headers:` block).
/// Unlike `migrate_observability`'s same-section rename, this one CROSSES top-level sections, so it
/// removes the key from `observability` (if present) and inserts it under `advanced.response_headers`,
/// creating either mapping if it did not already exist.
fn migrate_response_headers(
    root: &mut Mapping,
    changes: &mut Vec<String>,
    todos: &mut Vec<String>,
) {
    if !matches!(
        root.get(Value::from("observability")),
        Some(Value::Mapping(m)) if m.contains_key(Value::from("emit_server_timing"))
    ) {
        return;
    }
    // Take-on-match (see `Taken`) BEFORE touching `observability:`: an `advanced:` that is not a
    // mapping used to be removed here and replaced with a freshly-built one — the operator's
    // `advanced:` value gone, with no todo. Now it stays as written, and the SOURCE key stays with
    // it (nothing is half-migrated).
    let mut advanced = match take_mapping(root, "advanced", "", todos) {
        Taken::Got(m) => m,
        Taken::Absent => Mapping::new(),
        Taken::Malformed => {
            todos.push(
                "observability.emit_server_timing: could not be folded into \
                 `advanced.response_headers.server_timing` (see the `advanced:` todo above); BOTH \
                 keys were left EXACTLY as written. Fix `advanced:` and re-run `--migrate-config`."
                    .into(),
            );
            return;
        }
    };
    let Some(Value::Mapping(obs)) = root.get_mut(Value::from("observability")) else {
        unreachable!("shape checked above");
    };
    let Some(v) = take(obs, "emit_server_timing") else {
        unreachable!("presence checked above");
    };
    let mut response_headers = as_map(
        advanced
            .remove(Value::from("response_headers"))
            .unwrap_or(Value::Mapping(Mapping::new())),
    );
    response_headers.insert("server_timing".into(), v);
    advanced.insert("response_headers".into(), Value::Mapping(response_headers));
    root.insert("advanced".into(), Value::Mapping(advanced));
    changes
        .push("observability.emit_server_timing -> advanced.response_headers.server_timing".into());
}

/// 1.5.3 HARD rename of the tap-stage `at:` vocabulary (`route`→`candidate`, `attempt`→`routing`,
/// `completion`→`response`). The 1.5.3 rename dropped `#[serde(alias)]`, so an un-migrated `at:`
/// value is a LOUD boot failure (`augment_config_error` names the new value); this rewrites the old
/// strings in place so a migrated config validates. Walks every hook inline ref — the top-level
/// `global_hooks:` list and each `pools.<name>.hooks:` list — and maps the old `at:` string using
/// the SHARED [`crate::config::RENAMED_HOOK_STAGES`] table so the migrator and the loud-fail hint
/// cannot drift.
fn migrate_hook_stages(root: &mut Mapping, changes: &mut Vec<String>) {
    fn rewrite_list(list: &mut [Value], location: &str, changes: &mut Vec<String>) {
        for entry in list {
            let Value::Mapping(m) = entry else { continue };
            let Some(old) = m.get(Value::from("at")).and_then(|v| v.as_str()) else {
                continue;
            };
            if let Some((_, new)) = crate::config::RENAMED_HOOK_STAGES
                .iter()
                .find(|(o, _)| *o == old)
            {
                changes.push(format!("{location}: hook stage `at: {old}` -> `at: {new}`"));
                m.insert("at".into(), Value::from(*new));
            }
        }
    }
    if let Some(Value::Sequence(globals)) = root.get_mut(Value::from("global_hooks")) {
        rewrite_list(globals, "global_hooks", changes);
    }
    if let Some(Value::Mapping(pools)) = root.get_mut(Value::from("pools")) {
        for (pname, p) in pools.iter_mut() {
            let Value::Mapping(p) = p else { continue };
            let Some(Value::Sequence(hooks)) = p.get_mut(Value::from("hooks")) else {
                continue;
            };
            let loc = format!("pools.{}.hooks", pname.as_str().unwrap_or("?"));
            rewrite_list(hooks, &loc, changes);
        }
    }
}

/// 1.6.0 CLEAN SLATE: rewrite the two retired hook-DEFINITION key spellings on every entry of the
/// top-level `hooks:` named map so a config using the pre-1.6.0 spellings validates on 1.6.0:
///   * `plugin:` → `module:` (the sole wire spelling now the `alias = "plugin"` is gone), unless
///     `module:` is already present (it wins — the operator's current statement of intent);
///   * `at: <stage>` → `phase: [<stage>]` (stage-renamed via [`crate::config::RENAMED_HOOK_STAGES`],
///     matching the overlay boot-migration), unless a non-empty `phase:` is already present, in which
///     case `at:` is dropped — the list is authoritative under the old `fires_at_stage` precedence.
///
/// IDEMPOTENT: an entry already spelled `module:`/`phase:` has nothing to rewrite. Complements
/// [`hook_entry_to_def`] (which performs the same conversion when LIFTING a legacy registry/inline
/// hook); this pass catches a `hooks:` map that was ALREADY the named-def shape yet still carried a
/// retired key, which `migrate_hooks_block` passes through untouched.
fn migrate_hook_def_keys(root: &mut Mapping, changes: &mut Vec<String>) {
    let Some(Value::Mapping(hooks)) = root.get_mut(Value::from("hooks")) else {
        return;
    };
    for (name, entry) in hooks.iter_mut() {
        let Value::Mapping(def) = entry else { continue };
        let hook_name = name.as_str().unwrap_or("?").to_string();
        // `plugin:` → `module:` (an existing `module:` wins).
        if let Some(plugin) = take(def, "plugin") {
            if !def.contains_key(Value::from("module")) {
                def.insert("module".into(), plugin);
                changes.push(format!("hooks.{hook_name}: `plugin:` -> `module:` (1.6.0)"));
            } else {
                changes.push(format!(
                    "hooks.{hook_name}: retired `plugin:` dropped (`module:` already set, 1.6.0)"
                ));
            }
        }
        // `at: <stage>` → `phase: [<stage>]` unless a non-empty `phase:` already stands.
        if let Some(at) = take(def, "at") {
            let phase_present = def
                .get(Value::from("phase"))
                .and_then(|v| v.as_sequence())
                .is_some_and(|s| !s.is_empty());
            if phase_present {
                changes.push(format!(
                    "hooks.{hook_name}: retired `at:` dropped (`phase:` already set, 1.6.0)"
                ));
            } else if let Some(phase) = at_to_phase(&at) {
                def.insert("phase".into(), phase);
                changes.push(format!(
                    "hooks.{hook_name}: single-stage `at: {}` -> `phase:` list (1.6.0)",
                    at.as_str().unwrap_or("?")
                ));
            }
        }
    }
}

/// 1.5.3: `admin_insecure: <bool>` -> `admin_require_mtls: <!bool>` (the flag INVERTED so the safe
/// posture is the default). IDEMPOTENT: no `admin_insecure` key ⇒ nothing to do; a config that
/// already carries `admin_require_mtls` keeps it (the retired key cannot coexist — it is a boot
/// marker — so there is no precedence question to answer).
fn migrate_admin_require_mtls(root: &mut Mapping, changes: &mut Vec<String>) {
    let Some(old) = take(root, "admin_insecure") else {
        return;
    };
    // Anything not literally `true` is treated as the guard being ON, which is the fail-SAFE read of
    // a malformed value (a waiver must be explicit).
    let insecure = old.as_bool().unwrap_or(false);
    root.insert("admin_require_mtls".into(), Value::from(!insecure));
    changes.push(format!(
        "admin_insecure: {insecure} -> admin_require_mtls: {} (INVERTED in 1.5.3 so the safe \
         posture is the default)",
        !insecure
    ));
}

/// 1.5.3: `auth.upstream_credentials:` -> the reserved `pools.upstream_credentials:` all-pools
/// default. IDEMPOTENT: no `auth.upstream_credentials` ⇒ nothing to move. An existing
/// `pools.upstream_credentials` WINS (it is already the new grammar, so it is the operator's most
/// recent statement of intent) and the retired key is dropped with a named change entry.
fn migrate_pools_upstream_credentials(root: &mut Mapping, changes: &mut Vec<String>) {
    let Some(Value::Mapping(auth)) = root.get_mut(Value::from("auth")) else {
        return;
    };
    let Some(mode) = take(auth, "upstream_credentials") else {
        return;
    };
    let pools = root
        .entry("pools".into())
        .or_insert_with(|| Value::Mapping(Mapping::new()));
    if !matches!(pools, Value::Mapping(_)) {
        *pools = Value::Mapping(Mapping::new());
    }
    if let Value::Mapping(pm) = pools {
        if pm.contains_key(Value::from("upstream_credentials")) {
            changes.push(
                "auth.upstream_credentials dropped: pools.upstream_credentials is already set (the \
                 1.5.3 home) and wins"
                    .into(),
            );
        } else {
            pm.insert("upstream_credentials".into(), mode);
            changes.push(
                "auth.upstream_credentials -> pools.upstream_credentials (the all-pools SCALAR \
                 default; override it per pool with `pools.<p>.upstream_credentials`)"
                    .into(),
            );
        }
    }
}

/// 1.5.3: rewrite a retired `store.module:` spelling of the first-party Valkey store plugin to
/// its current alias. The plugin was renamed WHOLESALE (repo, crate, artifact, manifest
/// `name`, config `alias`), so `redis` / `busbar-store-redis` / `busbar-store-redis-plugin` match
/// nothing in the renamed artifact's manifest and the store the operator asked for is simply gone.
/// Driven by the SHARED [`crate::config::RETIRED_STORE_MODULES_1_5_3`] table, so this rewrite and
/// [`detect_legacy_markers`]'s loud-fail cannot disagree about which spellings are retired.
///
/// The `settings:` bag rides through VERBATIM. The connection URL's `redis://` / `rediss://` scheme
/// is the upstream driver's own registered scheme — an unrenamable upstream identifier, not a
/// busbar-owned name — so touching it would break every working deployment.
///
/// IDEMPOTENT: a `store.module:` already on the new alias (or naming any other backend) is not in the
/// retired table, so a second run finds nothing to rewrite and records no change.
///
/// TAKE-ON-MATCH (see [`Taken`]), at BOTH levels. A `store:` that is not a mapping is left EXACTLY as
/// written, in place, with its own TODO — `take_mapping` never removes a `Malformed` value, so there
/// is nothing to restore. Inside the block the `module:` value is only removed once it has been
/// CONFIRMED to be a retired spelling; a `module:` this migrator does not understand is never lifted
/// out, so there is no window in which it could be dropped. That matters more here than almost
/// anywhere else in this module: an ABSENT `store:` is the legal `memory` default, so silently
/// losing the block would turn a durable deployment ephemeral AND still pass `busbar --validate`.
fn migrate_store_module(root: &mut Mapping, changes: &mut Vec<String>, todos: &mut Vec<String>) {
    let mut store = match take_mapping(root, "store", "", todos) {
        Taken::Got(m) => m,
        Taken::Absent | Taken::Malformed => return,
    };
    let retired = store
        .get(Value::from("module"))
        .and_then(|v| v.as_str())
        .filter(|m| crate::config::RETIRED_STORE_MODULES_1_5_3.contains(m))
        .map(str::to_string);
    if let Some(old) = retired {
        store.insert(
            "module".into(),
            Value::from(crate::config::STORE_MODULE_VALKEY),
        );
        changes.push(format!(
            "store.module: {old} -> {} (the first-party store plugin for this backend was RENAMED \
             in 1.5.3: artifact `{}-<ver>-<target>.tar.gz`, manifest name `{}`. Install the \
             renamed tarball — the old one no longer answers to any name in this config. Your \
             `settings.url` is UNCHANGED: `redis://` is the driver's own URL scheme, not a busbar \
             name.)",
            crate::config::STORE_MODULE_VALKEY,
            crate::config::STORE_MODULE_VALKEY_ASSET_STEM,
            crate::config::STORE_MODULE_VALKEY_NAME,
        ));
    }
    // Unconditional: `take_mapping` already REMOVED the block above, so every path out of this
    // function must put the operator's `store:` back — changed or not.
    root.insert("store".into(), Value::Mapping(store));
}

/// The name SUFFIX a split identity-provider definition gets, per the auth plane that forced the
/// split: `admin_auth` -> `<module>-admin` (the shape the 1.5.3 docs use), any other site -> the site
/// name itself. Deterministic, so re-running the migration on the same input yields the same names.
fn split_suffix(site: &str) -> &str {
    match site {
        "admin_auth" => "admin",
        other => other,
    }
}

/// 1.5.3: lift every INLINE `auth.chain:` / `auth.admin_auth:` entry and every
/// `auth.methods:` entry into the top-level `identity-providers:` NAMED-DEFINITION map, replacing the
/// chain entries with bare NAME references.
///
/// **The DEDUPE is the whole point.** One IdP that served both planes had to be written twice, once
/// per chain, with two independent copies of its settings. This produces ONE definition per MODULE and
/// points both chains at it — so the duplication the old grammar forced is gone after migrating, not
/// merely expressible.
///
/// SHAPE-CONVERGENT and IDEMPOTENT: a bare-string chain entry is already a name reference and passes
/// straight through, so a second run finds nothing to lift.
///
/// NEVER SILENTLY DROPS (the rule `migrate_auth` already states): `root.remove` takes
/// the key unconditionally, so every early return below RESTORES the value it took, unchanged, and
/// names it in the ledger. A malformed `auth: null` / `auth: []` / `auth: <scalar>` (real
/// hand-edited shapes) therefore survives the migration verbatim for the operator to fix, instead of
/// disappearing from the migrated document with no record.
fn migrate_identity_providers(
    root: &mut Mapping,
    changes: &mut Vec<String>,
    todos: &mut Vec<String>,
) {
    let removed_auth = root.remove(Value::from("auth"));
    let Some(Value::Mapping(mut auth)) = removed_auth else {
        if let Some(other) = removed_auth {
            let shape = one_line(&other);
            root.insert("auth".into(), other);
            todos.push(format!(
                "auth: is not a mapping (`{shape}`) — it was left EXACTLY as written and NOTHING \
                 was lifted out of it. 1.5.3 expects `auth: {{ chain: [...], admin_auth: [...] }}` \
                 with the providers defined under the top-level `identity-providers:` map; fix the \
                 block by hand, then re-run the migration."
            ));
        }
        return;
    };
    // Start from any EXISTING definitions so a partially-migrated config converges rather than
    // duplicating. Keyed by the definition NAME; `by_module` indexes them for the dedupe.
    let removed_defs = root.remove(Value::from("identity-providers"));
    let mut defs = match removed_defs {
        None => Mapping::new(),
        Some(Value::Mapping(m)) => m,
        // Same rule: a malformed `identity-providers:` is put BACK verbatim (together with the
        // `auth:` block this function had already taken) and nothing is lifted — overwriting it with
        // synthesized definitions would destroy whatever the operator meant to write there.
        Some(other) => {
            let shape = one_line(&other);
            root.insert("auth".into(), Value::Mapping(auth));
            root.insert("identity-providers".into(), other);
            todos.push(format!(
                "identity-providers: is not a mapping (`{shape}`) — it was left EXACTLY as written \
                 and no `auth.chain:`/`auth.admin_auth:`/`auth.methods:` entry was lifted into it. \
                 1.5.3 expects `identity-providers: {{ <name>: {{ module: … }} }}`; fix the block \
                 by hand, then re-run the migration."
            ));
            return;
        }
    };
    let mut by_module: Vec<(String, String)> = defs
        .iter()
        .filter_map(|(k, v)| {
            let name = k.as_str()?.to_string();
            let module = v.as_mapping()?.get(Value::from("module"))?.as_str()?;
            Some((module.to_string(), name))
        })
        .collect();

    // Lift one inline entry into a definition, REUSING the existing definition for that module when
    // one is already present AND its settings AGREE (the dedupe). Returns the NAME the site should
    // now reference. `site` names where the entry came from (`chain` / `admin_auth` / `methods`) and
    // is used only to name a SPLIT definition deterministically.
    //
    // THE SETTINGS RULE. The dedupe folds one module written on both planes into ONE
    // definition — but only when there is nothing to lose by folding:
    //   * this site carries NO `settings:` ⇒ reuse (nothing to lose);
    //   * an existing definition for this module has the IDENTICAL `settings:` ⇒ reuse (the win);
    //   * an existing definition for this module has NO `settings:` ⇒ reuse and ADOPT this site's;
    //   * otherwise the two sites CONFLICT (e.g. `oidc` with `issuer: data.example.com` on `chain`
    //     and `issuer: admin.example.com` on `admin_auth`) ⇒ emit a SECOND definition named
    //     `<module>-<site>` and reference IT from this site. Merging them would silently drop one
    //     plane's settings and authenticate that plane against the WRONG upstream; two definitions is
    //     the honest outcome, and it is flagged as a todo.
    let lift = |module: &str,
                body: &Mapping,
                site: &str,
                defs: &mut Mapping,
                by_module: &mut Vec<(String, String)>,
                changes: &mut Vec<String>,
                todos: &mut Vec<String>|
     -> String {
        let want = body.get(Value::from("settings"));
        let settings_of = |defs: &Mapping, name: &str| -> Option<Value> {
            defs.get(Value::from(name))
                .and_then(|d| d.as_mapping())
                .and_then(|d| d.get(Value::from("settings")))
                .cloned()
        };
        // Every definition already standing for this module, in insertion order.
        let candidates: Vec<String> = by_module
            .iter()
            .filter(|(m, _)| m == module)
            .map(|(_, n)| n.clone())
            .collect();
        // `auth.methods:` is EXEMPT from the split (freeze blocker): a method entry's flattened
        // settings are COMPLEMENTARY to the chain entry's for the same module (a `browser_login:`
        // plus the method's own keys), and the caller UNIONS them into the one definition on purpose.
        // Only the two CHAINS can state genuinely disagreeing settings for one module.
        let may_split = site != "methods";
        // The one to reuse, per the settings rule above: an exact settings match first, then (only
        // when this site brings settings) one that carries none and can adopt them.
        let reuse = if may_split {
            candidates
                .iter()
                .find(|n| want.is_none() || settings_of(defs, n).as_ref() == want)
                .or_else(|| candidates.iter().find(|n| settings_of(defs, n).is_none()))
                .cloned()
        } else {
            candidates.first().cloned()
        };
        if let Some(name) = reuse {
            // MERGE the second plane's typed fields into the ONE definition. A `token:` (admin-tokens)
            // or a `max_admin_scope:` written on only one of the two chains must survive the fold —
            // and so must a `settings:` bag the reused definition does not carry yet.
            if let Some(Value::Mapping(existing)) = defs.get_mut(Value::from(name.as_str())) {
                for key in ["max_admin_scope", "token", "settings"] {
                    if !existing.contains_key(Value::from(key)) {
                        if let Some(v) = body.get(Value::from(key)) {
                            existing.insert(key.into(), v.clone());
                        }
                    }
                }
            }
            changes.push(format!(
                "auth chain entry `{module}` -> the EXISTING identity-providers.{name} definition \
                 (define once, reference by name)"
            ));
            return name;
        }
        // A CONFLICTING second site (or the very first sighting of this module).
        let split = !candidates.is_empty();
        let base = if split {
            format!("{module}-{}", split_suffix(site))
        } else {
            // The definition NAME defaults to the module name — the minimal, least-surprising rename,
            // and exactly what the built-ins are referenced as.
            module.to_string()
        };
        let name = super::migrate_export::uniq_export_name(defs, &base);
        let mut def = Mapping::new();
        def.insert("module".into(), Value::from(module));
        for key in ["max_admin_scope", "token", "settings"] {
            if let Some(v) = body.get(Value::from(key)) {
                def.insert(key.into(), v.clone());
            }
        }
        defs.insert(Value::from(name.as_str()), Value::Mapping(def));
        by_module.push((module.to_string(), name.clone()));
        if split {
            changes.push(format!(
                "auth.{site} entry `{module}: {{ … }}` -> a SECOND identity-providers.{name} \
                 definition (its `settings:` differ from the existing `{module}` definition, so the \
                 two were NOT deduped)"
            ));
            todos.push(format!(
                "identity-providers.{name}: `{module}` was configured on more than one auth plane \
                 with DIFFERENT `settings:`, so the migrator kept BOTH — `{name}` carries the \
                 `auth.{site}` settings and is referenced from there; the other definition keeps \
                 the settings of the site that declared it first. Nothing was lost; rename them to \
                 whatever your `role_bindings:` should key off, or collapse them if the difference \
                 was accidental."
            ));
        } else {
            changes.push(format!(
                "auth chain entry `{module}: {{ … }}` -> identity-providers.{name} + a bare-name \
                 reference (1.5.3: define once, reference by name)"
            ));
        }
        name
    };

    for plane in ["chain", "admin_auth"] {
        let Some(Value::Sequence(seq)) = auth.get(Value::from(plane)).cloned() else {
            continue;
        };
        let mut names: Vec<Value> = Vec::new();
        for entry in seq {
            match entry {
                // Already a bare NAME reference — the new grammar.
                Value::String(s) => names.push(Value::from(s)),
                Value::Mapping(m) => {
                    let Some((module, body)) = m
                        .iter()
                        .next()
                        .and_then(|(k, v)| Some((k.as_str()?.to_string(), as_map(v.clone()))))
                    else {
                        continue;
                    };
                    let name = lift(
                        &module,
                        &body,
                        plane,
                        &mut defs,
                        &mut by_module,
                        changes,
                        todos,
                    );
                    names.push(Value::from(name.as_str()));
                }
                other => names.push(other),
            }
        }
        auth.insert(plane.into(), Value::Sequence(names));
    }

    // FREEZE BLOCKER: `auth.methods:` folds INTO the provider definition — `browser_login` plus the
    // method's flattened opaque settings are per-provider, so they belong on the definition and not in
    // a second parallel map that could disagree with it.
    if let Some(Value::Mapping(methods)) = take(&mut auth, "methods") {
        for (k, v) in methods {
            let Some(module) = k.as_str().map(str::to_string) else {
                continue;
            };
            let mut body = as_map(v);
            let browser_login = take(&mut body, "browser_login");
            // Everything else on a `methods:` entry was the module's flattened opaque settings.
            let mut settings = Mapping::new();
            settings.insert("settings".into(), Value::Mapping(body));
            let name = lift(
                &module,
                &settings,
                "methods",
                &mut defs,
                &mut by_module,
                changes,
                todos,
            );
            if let Some(Value::Mapping(def)) = defs.get_mut(Value::from(name.as_str())) {
                if let Some(bl) = browser_login {
                    def.insert("browser_login".into(), bl);
                }
                // MERGE the method's settings into the definition's, rather than replacing: the
                // chain entry for the same module may already have contributed its own.
                if let Some(Value::Mapping(from)) = settings.get(Value::from("settings")).cloned() {
                    let mut merged = match def.get(Value::from("settings")).cloned() {
                        Some(Value::Mapping(m)) => m,
                        _ => Mapping::new(),
                    };
                    for (sk, sv) in from {
                        merged.insert(sk, sv);
                    }
                    if !merged.is_empty() {
                        def.insert("settings".into(), Value::Mapping(merged));
                    }
                }
            }
            changes.push(format!(
                "auth.methods.{module} -> identity-providers.{name} (browser_login + settings are \
                 PER-PROVIDER in 1.5.3; the parallel methods map is gone)"
            ));
        }
    }

    // `role_bindings:` nests by the SAME string the chains reference. Because `lift` names each
    // definition after its module, an existing `role_bindings.<module>` table is already correct —
    // but say so, because a hand-RENAMED definition would need the bindings renamed with it.
    if auth.contains_key(Value::from("role_bindings")) && !defs.is_empty() {
        todos.push(
            "auth.role_bindings is nested by the IDENTITY-PROVIDER NAME in 1.5.3. The migrator named \
             each new definition after its module, so existing bindings still resolve — but if you \
             RENAME a definition in `identity-providers:`, rename its `role_bindings:` table to match."
                .into(),
        );
    }

    root.insert("auth".into(), Value::Mapping(auth));
    if !defs.is_empty() {
        root.insert("identity-providers".into(), Value::Mapping(defs));
    }
}

#[cfg(test)]
#[path = "tests/migrate_tests.rs"]
mod tests;
