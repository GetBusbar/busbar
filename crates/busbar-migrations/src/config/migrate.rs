// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::plugin::Kind;
use busbar_contract::yaml::{self, prelude::*};

#[path = "migrate_1_6.rs"]
mod upgrade_1_6;
pub(super) use upgrade_1_6::unfold_zero_cache_write;

pub(super) mod vocabulary {
    pub mod field {
        pub use super::super::legacy_markers::field::{
            ACTION, ADMIN_AUTH, ADMIN_INSECURE, API_KEY_ENV, AUTH, CHAIN, CLIENT_TOKENS,
            GLOBAL_HOOKS, GOVERNANCE, GROUP_MAP, MEMBERS, METHODS, METRICS, MODE, MODULE, MODULES,
            OBSERVABILITY, ON_EXHAUSTED, POOLS, SOCKET, TARGET, UPSTREAM_CREDENTIALS,
        };
        pub(crate) const ADMIN_REQUIRE_MTLS: &str = "admin_require_mtls";
        pub(crate) const ADMIN_SCOPE: &str = "admin_scope";
        pub const ADMIN_TOKEN: &str = "admin_token";
        pub const ADVANCED: &str = "advanced";
        pub const ALLOW_DESTINATIONS: &str = "allow_destinations";
        pub(crate) const ALLOWED_GROUPS: &str = "allowed_groups";
        pub(crate) const ALLOWED_POOLS: &str = "allowed_pools";
        pub const API_KEY: &str = "api_key";
        pub const AT: &str = "at";
        pub const BREAKER: &str = "breaker";
        pub const BROWSER_LOGIN: &str = "browser_login";
        pub const BUDGET: &str = "budget";
        pub(crate) const BUDGET_GROUP: &str = "budget_group";
        pub(crate) const BUDGET_GROUPS: &str = "budget_groups";
        pub(crate) const BUDGET_PERIOD: &str = "budget_period";
        pub(crate) const BUFFER_SECONDS: &str = "buffer_seconds";
        pub(crate) const BUSY_TIMEOUT_MS: &str = "busy_timeout_ms";
        pub(crate) const CACHE_READ_UTOK: &str = "cache_read_utok";
        pub(crate) const CACHE_WRITE_UTOK: &str = "cache_write_utok";
        pub const CAP: &str = "cap";
        pub(crate) const CONSECUTIVE_N: &str = "consecutive_n";
        pub(crate) const COST_PER_MTOK: &str = "cost_per_mtok";
        pub(crate) const DB_PATH: &str = "db_path";
        pub(crate) const DEADLINE_SECS: &str = "deadline_secs";
        pub const DEFAULT: &str = "default";
        pub(crate) const EMIT_SERVER_TIMING: &str = "emit_server_timing";
        pub const ENABLED: &str = "enabled";
        pub const ENV: &str = "env";
        pub const FAILOVER: &str = "failover";
        pub(crate) const FALLBACK_POOL: &str = "fallback_pool";
        pub const FETCH: &str = "fetch";
        pub const GLOBAL: &str = "global";
        pub const GROUP: &str = "group";
        pub const GROUPS: &str = "groups";
        pub const HOOKS: &str = "hooks";
        pub(crate) const INPUT_UTOK: &str = "input_utok";
        pub(crate) const KEY_GAUGE_LIMIT: &str = "key_gauge_limit";
        pub const KIND: &str = "kind";
        pub const LIMITS: &str = "limits";
        pub(crate) const MAX_ADMIN_SCOPE: &str = "max_admin_scope";
        pub(crate) const MAX_BUDGET_CENTS: &str = "max_budget_cents";
        pub(crate) const MAX_HOPS: &str = "max_hops";
        pub const MODEL: &str = "model";
        pub(crate) const MODELS: &str = "models";
        pub const N: &str = "n";
        pub(crate) const ON_EMPTY: &str = "on_empty";
        pub(crate) const ON_ERROR: &str = "on_error";
        pub(crate) const OUTPUT_UTOK: &str = "output_utok";
        pub const PARENT: &str = "parent";
        pub const PATH: &str = "path";
        pub const PER: &str = "per";
        pub(crate) const PER_REQUEST_FEE: &str = "per_request_fee";
        pub const PHASE: &str = "phase";
        pub const PLUGIN: &str = "plugin";
        pub const PLUGINS: &str = "plugins";
        pub const POLICY: &str = "policy";
        pub(crate) const PRICE_PER_1K_TOKENS_CENTS: &str = "price_per_1k_tokens_cents";
        pub(crate) const PRICE_PER_REQUEST_CENTS: &str = "price_per_request_cents";
        pub const PRIORITY: &str = "priority";
        pub const PROMPT: &str = "prompt";
        pub const PROVIDERS_FILE: &str = "providers_file";
        pub(crate) const RATE_CARD: &str = "rate_card";
        pub(crate) const RATE_SWEEP_INTERVAL: &str = "rate_sweep_interval";
        pub(crate) const REQUESTS: &str = "requests";
        pub(crate) const RESPONSE_HEADERS: &str = "response_headers";
        pub(crate) const ROLE_BINDINGS: &str = "role_bindings";
        pub(crate) const RPM_LIMIT: &str = "rpm_limit";
        pub(crate) const SERVER_TIMING: &str = "server_timing";
        pub const SETTINGS: &str = "settings";
        pub const SHA256: &str = "sha256";
        pub const SIGNALS: &str = "signals";
        pub(crate) const SIGNING_KEY: &str = "signing_key";
        pub(crate) const TIMEOUT_MS: &str = "timeout_ms";
        pub(crate) const TIMEOUT_SECS: &str = "timeout_secs";
        pub const TOKENS: &str = "tokens";
        pub const TOKEN: &str = "token";
        pub(crate) const TPM_LIMIT: &str = "tpm_limit";
        pub const TRIP: &str = "trip";
        pub const URL: &str = "url";
        pub(crate) const USAGE_FLUSH_INTERVAL_MS: &str = "usage_flush_interval_ms";
        pub const USER: &str = "user";
        pub(crate) const WINDOW_S: &str = "window_s";
        pub(crate) const WINDOW_SECS: &str = "window_secs";
    }
}

use vocabulary::field;

#[path = "legacy_markers.rs"]
mod legacy_markers;
pub use legacy_markers::{detect_legacy_markers, legacy_config_error};
use legacy_markers::{is_new_hook_defs, LEGACY_STATIC_TOKENS_MODULE, LEGACY_TOKENS_MODULE};

const LEGACY_MINUTE_PERIODS: &[&str] = &["minute", "minutely", "per_minute"];
const LEGACY_HOUR_PERIODS: &[&str] = &["hour", "hourly", "per_hour"];
const LEGACY_DAY_PERIODS: &[&str] = &["day", "daily", "per_day"];
const LEGACY_MONTH_PERIODS: &[&str] = &["month", "monthly", "per_month"];
const LEGACY_TOTAL_PERIODS: &[&str] = &["total", "lifetime", "all_time", "alltime", "never"];
const LEGACY_WEEK_PERIODS: &[&str] = &["week", "weekly", "per_week"];
const LEGACY_QUARTER_PERIODS: &[&str] = &["quarter", "quarterly", "per_quarter"];
const LEGACY_HALF_YEAR_PERIODS: &[&str] = &[
    "biannual",
    "biannually",
    "semiannual",
    "semiannually",
    "semi_annual",
    "half_year",
    "half_yearly",
    "per_half_year",
];
const LEGACY_YEAR_PERIODS: &[&str] = &["year", "yearly", "annual", "annually", "per_year"];

const EXHAUSTED_REJECT: &str = "reject";
const EXHAUSTED_LEAST_BAD: &str = "least_bad";
const LEGACY_REJECT_ACTIONS: &[&str] = &[EXHAUSTED_REJECT, "503", "status_503", "status503"];
const LEGACY_LEAST_BAD_ACTIONS: &[&str] = &[EXHAUSTED_LEAST_BAD, "least-bad", "leastbad"];
const LEGACY_TARGETLESS_FALLBACK_ACTIONS: &[&str] = &[field::FALLBACK_POOL, "fallback", "failover"];
const LEGACY_FALLBACK_ACTION_PREFIX: &str = "fallback_pool:";

const LEGACY_TAP_HOOK_KIND: &str = "tap";

const ADMIN_PROVIDER_SUFFIX: &str = "admin";
const UNNAMED_HOOK_STEM: &str = "hook";

const LEGACY_AUTH_MODE_PASSTHROUGH: &str = "passthrough";
const LEGACY_AUTH_MODE_NONE: &str = "none";

const LEGACY_CENTS_PER_THOUSAND_TO_MICRO_UNITS_PER_TOKEN: f64 = 10.0;

const LEGACY_UNREADABLE_TOKEN_PRICE_CENTS: f64 = 0.0;

const LEGACY_ABSENT_BUDGET_CENTS: i32 = 0;

const MONTHS_PER_QUARTER: u64 = 3;
const MONTHS_PER_HALF_YEAR: u64 = 6;
const MONTHS_PER_YEAR: u64 = 12;

const MIN_MIGRATED_BUDGET_AMOUNT: u64 = 1;

const MISSING_SIGNING_KEY: &str =
    "auth.signing_key: required now that the chain uses `keys` (busbar no longer \
     auto-generates one); run `busbar --generate-signing-key` and set \
     auth.signing_key to a secret reference for it. {file: /path} and {env: VAR} \
     are not built in: each needs an installed, admitted secret plugin that \
     declares it (busbar-secret-file for file, busbar-secret-env for env), \
     otherwise boot refuses; the key must be shared across a fleet";

pub(crate) fn legacy_store_text(key: &str) -> &'static str {
    crate::config::migration_table::text(key)
}

pub struct MigrateOutput {
    pub yaml: String,
    pub changes: Vec<String>,
    pub todos: Vec<String>,
    pub warnings: Vec<String>,
    /// Change lines a startup caller must log (at WARN) before it zeroizes `changes`: each holds
    /// only an authored key and fixed text, never a value from the environment or the Store.
    pub notices: Vec<String>,
}

/// What [`MigrateOutput::decision_paths`] names a TODO that states no `<path>: ` prefix.
const UNNAMED_DECISION: &str = "(unnamed decision)";

impl MigrateOutput {
    /// The configuration path each unresolved decision is about, in order and without
    /// duplicates. Every TODO is written `<path>: <reason>`; only the path is returned, so a
    /// refusal can name where the decisions are without repeating any reason or value.
    #[must_use]
    pub fn decision_paths(&self) -> Vec<&str> {
        let mut paths: Vec<&str> = Vec::new();
        for todo in &self.todos {
            let path = todo
                .split_once(": ")
                .map_or(UNNAMED_DECISION, |(path, _)| path);
            if !paths.contains(&path) {
                paths.push(path);
            }
        }
        paths
    }
}

#[cold]
#[inline(never)]
pub fn migrate_config(raw: &str) -> Result<MigrateOutput, String> {
    migrate_config_with(raw, &super::migrate_plugins::NoPlugins)
}

#[cold]
#[inline(never)]
pub fn migrate_config_with(
    raw: &str,
    host: &dyn super::migrate_plugins::MigrateHost,
) -> Result<MigrateOutput, String> {
    migrate_document(raw, host, true)
}

/// Structural bootstrap only: source-specific plugin and credential semantics require
/// independently established released-source provenance.
pub(super) fn migrate_structure(
    raw: &str,
    host: &dyn super::migrate_plugins::MigrateHost,
) -> Result<MigrateOutput, String> {
    migrate_document(raw, host, false)
}

fn migrate_document(
    raw: &str,
    host: &dyn super::migrate_plugins::MigrateHost,
    source_specific: bool,
) -> Result<MigrateOutput, String> {
    let doc: Value = yaml::from_str(raw).map_err(|e| format!("input is not valid YAML: {e}"))?;
    let Value::Map(mut root) = doc else {
        return Err("input is not a YAML mapping (expected a busbar config document)".to_string());
    };
    let mut changes: Vec<String> = Vec::new();
    let mut todos: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut notices: Vec<String> = Vec::new();
    let mut failures: Vec<String> = Vec::new();

    migrate_governance(&mut root, &mut changes, &mut todos);
    migrate_auth(&mut root, &mut changes, &mut todos, &mut warnings);

    migrate_admin_auth(&mut root, &mut changes, &mut todos);

    migrate_dropped_scopes(&mut root, &mut warnings);
    migrate_providers(&mut root, &mut changes);
    migrate_hooks_block(&mut root, &mut changes, &mut todos);
    migrate_pools(&mut root, &mut changes, &mut todos);

    check_top_level_pool_plane(&root, &mut todos);

    migrate_hook_stages(&mut root, &mut changes);

    migrate_hook_def_keys(&mut root, &mut changes);
    migrate_observability(&mut root, &mut changes);
    migrate_response_headers(&mut root, &mut changes, &mut todos);

    migrate_observability_export(&mut root, &mut changes);

    super::migrate_export::migrate_export_named_map(&mut root, &mut changes);
    super::migrate_export::migrate_observability_block(&mut root, &mut changes);

    super::migrate_export::migrate_export_projection(&mut root, &mut changes, &mut todos);
    migrate_admin_require_mtls(&mut root, &mut changes);
    migrate_pools_upstream_credentials(&mut root, &mut changes, &mut todos);
    migrate_identity_providers(&mut root, &mut changes, &mut todos);

    migrate_store_module(&mut root, &mut changes, &mut todos);
    super::former_names::migrate(&mut root, &mut changes, &mut todos);
    host.bind_grammar(root.get_key("plugins"));

    if source_specific {
        super::migrate_plugins::migrate(
            &mut root,
            host,
            &mut super::migrate_plugins::Ledger {
                changes: &mut changes,
                todos: &mut todos,
                failures: &mut failures,
            },
        );
    }
    if !failures.is_empty() {
        return Err(failures.join("; "));
    }

    migrate_store_required(&mut root, &mut changes);

    if source_specific {
        upgrade_1_6::migrate(&mut root, &mut changes, &mut warnings, &mut notices);
    } else {
        upgrade_1_6::migrate_bootstrap(&mut root, &mut changes, &mut notices);
    }

    let body = yaml::to_string(&Value::Map(root))
        .map_err(|e| format!("could not serialize the migrated config: {e}"))?;

    let mut yaml = String::new();
    if !warnings.is_empty() || !todos.is_empty() {
        let signing_key_only = warnings.is_empty()
            && matches!(todos.as_slice(), [todo] if todo == MISSING_SIGNING_KEY);
        if !signing_key_only {
            yaml.push_str(&format!(
                "# busbar {} config, migrated by `busbar --migrate-config`.\n",
                busbar_kernel::config::CONFIG_TARGET_VERSION
            ));
            yaml.push_str("# The items below need a decision; `busbar --validate` must pass.\n");
        }
        for w in &warnings {
            yaml.push_str(&format!("# WARNING(migrate): {w}\n"));
        }
        for t in &todos {
            yaml.push_str(&format!("# TODO(migrate): {t}\n"));
        }
        if !signing_key_only {
            yaml.push('\n');
        }
    }
    yaml.push_str(&body);
    Ok(MigrateOutput {
        yaml,
        changes,
        todos,
        warnings,
        notices,
    })
}

/// The released file overlay already contains resolved hook/group definitions. Only settings
/// migrations and the current root-unit/security conversion apply; older YAML grammar rewrites
/// must not drop overlay-only signals/default flags or turn global hooks into a pools section.
pub fn migrate_overlay_fragment(
    raw: &str,
    host: &dyn super::migrate_plugins::MigrateHost,
) -> Result<MigrateOutput, String> {
    let mut root: Pairs = yaml::mapping_from_str(raw)
        .map_err(|_| "overlay fragment is not a mapping")?
        .into();
    let (mut changes, mut todos, mut warnings, mut failures, mut notices) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
    migrate_store_module(&mut root, &mut changes, &mut todos);
    super::former_names::migrate(&mut root, &mut changes, &mut todos);
    super::migrate_plugins::migrate(
        &mut root,
        host,
        &mut super::migrate_plugins::Ledger {
            changes: &mut changes,
            todos: &mut todos,
            failures: &mut failures,
        },
    );
    if !failures.is_empty() {
        return Err(failures.join("; "));
    }
    upgrade_1_6::migrate(&mut root, &mut changes, &mut warnings, &mut notices);
    let yaml = yaml::to_string(&Value::Map(root))
        .map_err(|_| "cannot serialize converted overlay fragment")?;
    Ok(MigrateOutput {
        yaml,
        changes,
        todos,
        warnings,
        notices,
    })
}

/// Remove `key` exactly as 1.5.5's `serde_yaml::Mapping::remove` did: a `swap_remove`, the last
/// entry moving into the removed key's place, so a migrated document keeps 1.5.5's key order.
pub(super) fn swap_remove_key(m: &mut Pairs, key: impl Index) -> Option<Value> {
    let at = key.position(m.as_slice())?;
    Some(m.swap_remove(at).1)
}

pub(super) fn take(m: &mut Pairs, k: &str) -> Option<Value> {
    swap_remove_key(m, k)
}

fn migrate_store_required(root: &mut Pairs, changes: &mut Vec<String>) {
    let key = Kind::Store.root();
    let module = crate::config::migrated_store_module();
    match root.get_key_mut(key) {
        None => {
            let mut store = Pairs::new();
            store.insert_key(field::MODULE, module.into());
            root.insert_key(key, Value::Map(store));
            changes.push(format!(
                "{key}: inserted `{key}: {{module: {module}}}` (1.6.0 requires a `{key}:` block; \
                 a config without one ran on the in-memory store, which this keeps)"
            ));
        }
        Some(Value::Map(store)) if !store.contains_key(field::MODULE) => {
            store.insert_key(field::MODULE, module.into());
            changes.push(format!(
                "{key}.module: inserted `{module}` (1.6.0 requires the store to be named; a \
                 `{key}:` block without a module ran on the in-memory store, which this keeps)"
            ));
        }
        Some(_) => {}
    }
}

fn as_map(v: Value) -> Pairs {
    match v {
        Value::Map(m) => m,
        _ => Pairs::new(),
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
    Got(T),

    Absent,

    Malformed,
}

pub(super) fn take_shaped(
    m: &mut Pairs,
    k: &str,
    want: &str,
    matches_shape: fn(&Value) -> bool,
    ctx: &str,
    todos: &mut Vec<String>,
) -> Taken<Value> {
    let Some(found) = m.get_key(k) else {
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

    Taken::Got(swap_remove_key(m, k).expect("just found"))
}

pub(super) fn take_mapping(
    m: &mut Pairs,
    k: &str,
    ctx: &str,
    todos: &mut Vec<String>,
) -> Taken<Pairs> {
    match take_shaped(m, k, "a mapping", |v| v.is_mapping(), ctx, todos) {
        Taken::Got(Value::Map(mm)) => Taken::Got(mm),
        Taken::Got(_) => unreachable!("shape was checked"),
        Taken::Absent => Taken::Absent,
        Taken::Malformed => Taken::Malformed,
    }
}

fn take_sequence(m: &mut Pairs, k: &str, ctx: &str, todos: &mut Vec<String>) -> Taken<Vec<Value>> {
    match take_shaped(m, k, "a list", |v| v.is_sequence(), ctx, todos) {
        Taken::Got(Value::Array(s)) => Taken::Got(s),
        Taken::Got(_) => unreachable!("shape was checked"),
        Taken::Absent => Taken::Absent,
        Taken::Malformed => Taken::Malformed,
    }
}

pub(super) fn one_line(v: &Value) -> String {
    let s = yaml::to_string(v).unwrap_or_else(|_| "?".into());
    let s = s.replace('\n', " ");
    let s = s.trim().to_string();
    if s.chars().count() > 60 {
        format!("{}…", s.chars().take(60).collect::<String>())
    } else {
        s
    }
}

fn entry_module_name(v: &Value) -> Option<String> {
    match v {
        Value::Text(s) => Some(s.clone()),
        Value::Map(m) => m.keys().next().and_then(|k| k.as_str().map(str::to_string)),
        _ => None,
    }
}

fn set_max_admin_scope(seq: &mut [Value], module: &str, scope: Value) -> bool {
    for e in seq.iter_mut() {
        if entry_module_name(e).as_deref() != Some(module) {
            continue;
        }
        if !matches!(e, Value::Map(_)) {
            let mut outer = Pairs::new();
            outer.insert_key(module, Value::Map(Pairs::new()));
            *e = Value::Map(outer);
        }
        if let Value::Map(m) = e {
            if let Some(Value::Map(body)) = m.get_key_mut(module) {
                body.insert_key(field::MAX_ADMIN_SCOPE, scope);
            }
        }
        return true;
    }
    false
}

fn migrate_dropped_scopes(root: &mut Pairs, warnings: &mut Vec<String>) {
    fn collapsed(v: &Value) -> bool {
        matches!(v.as_str(), Some("hooks-register") | Some("mint"))
    }
    let Some(Value::Map(auth)) = root.get_key_mut(field::AUTH) else {
        return;
    };

    for list_key in [field::CHAIN, field::ADMIN_AUTH] {
        if let Some(Value::Array(seq)) = auth.get_key_mut(list_key) {
            for entry in seq.iter_mut() {
                let Value::Map(outer) = entry else {
                    continue;
                };
                let module = outer
                    .keys()
                    .next()
                    .and_then(|k| k.as_str().map(str::to_string));
                let Some(module) = module else { continue };
                if let Some(Value::Map(body)) = outer.get_key_mut(module.as_str()) {
                    if let Some(scope) = body.get_key_mut(field::MAX_ADMIN_SCOPE) {
                        if collapsed(scope) {
                            let old = scope.as_str().unwrap_or("").to_string();
                            *scope = Value::from("full");
                            warnings.push(
                                busbar_kernel::diagnostics::coded::migrate_admin_scope_widened(
                                    format_args!(
                                        "auth.{list_key} entry '{module}' max_admin_scope"
                                    ),
                                    old,
                                )
                                .into(),
                            );
                        }
                    }
                }
            }
        }
    }

    if let Some(Value::Map(rb)) = auth.get_key_mut(field::ROLE_BINDINGS) {
        for (module_k, roles) in rb.iter_mut() {
            let module = module_k.as_str().unwrap_or("").to_string();
            let Value::Map(roles) = roles else {
                continue;
            };
            for (role_k, binding) in roles.iter_mut() {
                let role = role_k.as_str().unwrap_or("").to_string();
                let Value::Map(binding) = binding else {
                    continue;
                };
                if let Some(scope) = binding.get_key_mut(field::ADMIN_SCOPE) {
                    if collapsed(scope) {
                        let old = scope.as_str().unwrap_or("").to_string();
                        *scope = Value::from("full");
                        warnings.push(
                            busbar_kernel::diagnostics::coded::migrate_admin_scope_widened(
                                format_args!("role_bindings.{module}.{role}.admin_scope"),
                                old,
                            )
                            .into(),
                        );
                    }
                }
            }
        }
    }
}

fn migrate_admin_auth(root: &mut Pairs, changes: &mut Vec<String>, todos: &mut Vec<String>) {
    if root.contains_key(field::ADMIN_AUTH)
        && root.get_key(field::AUTH).is_some_and(|auth| {
            (!auth.is_null() && !auth.is_mapping())
                || auth
                    .get(field::ADMIN_AUTH)
                    .is_some_and(|list| !list.is_sequence())
        })
    {
        todos.push("admin_auth: could not merge into malformed auth or auth.admin_auth; both values were left unchanged for manual migration".into());
        return;
    }
    let Some(top) = take(root, field::ADMIN_AUTH) else {
        return;
    };
    let names: Vec<Value> = match top {
        Value::Array(s) => s,
        other => vec![other],
    };
    let auth = root.entry_or_insert_with(field::AUTH, || Value::Map(Pairs::new()));
    if auth.is_null() {
        *auth = Value::Map(Pairs::new());
    }
    let Value::Map(auth) = auth else {
        return;
    };
    let mut list = take(auth, field::ADMIN_AUTH)
        .and_then(|v| v.as_sequence().cloned())
        .unwrap_or_default();
    let mut present: std::collections::BTreeSet<String> =
        list.iter().filter_map(entry_module_name).collect();
    for name in names {
        match entry_module_name(&name) {
            Some(m) if present.insert(m.clone()) => list.push(name),
            Some(_) => {}
            None => list.push(name),
        }
    }
    auth.insert_key(field::ADMIN_AUTH, Value::Array(list));
    changes.push(
        "top-level admin_auth -> auth.admin_auth (1.5.0 nests the admin chain under auth)".into(),
    );
}

const APPROX_WINDOW: &str = "month";

fn window_noun(period: &str, ctx: &str, todos: &mut Vec<String>) -> (&'static str, u64) {
    match period {
        word if LEGACY_MINUTE_PERIODS.contains(&word) => (
            busbar_kernel::config::groups::LimitWindow::Minute.as_str(),
            1,
        ),
        word if LEGACY_HOUR_PERIODS.contains(&word) => {
            (busbar_kernel::config::groups::LimitWindow::Hour.as_str(), 1)
        }
        word if LEGACY_DAY_PERIODS.contains(&word) => {
            (busbar_kernel::config::groups::LimitWindow::Day.as_str(), 1)
        }
        word if LEGACY_MONTH_PERIODS.contains(&word) => (
            busbar_kernel::config::groups::LimitWindow::Month.as_str(),
            1,
        ),

        word if LEGACY_TOTAL_PERIODS.contains(&word) => (
            busbar_kernel::config::groups::LimitWindow::Total.as_str(),
            1,
        ),

        other => {
            let months: Option<u64> = match other {
                word if LEGACY_WEEK_PERIODS.contains(&word) => Some(1),

                word if LEGACY_QUARTER_PERIODS.contains(&word) => Some(MONTHS_PER_QUARTER),
                word if LEGACY_HALF_YEAR_PERIODS.contains(&word) => Some(MONTHS_PER_HALF_YEAR),
                word if LEGACY_YEAR_PERIODS.contains(&word) => Some(MONTHS_PER_YEAR),

                _ => None,
            };

            let divisor: u64 = months.unwrap_or(1).max(1);
            let why = if months.is_some() {
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
            } else if months.is_some() {
                format!(
                    "The AMOUNT was carried over UNCHANGED, so the cap now spends over a \
                     {APPROX_WINDOW} instead of a `{other}` (tighter, never looser). Re-scale it \
                     by hand"
                )
            } else {
                format!(
                    "The AMOUNT was carried over UNCHANGED because this migrator could NOT determine \
                     how long a `{other}` is; if it is LONGER than a {APPROX_WINDOW} the migrated cap \
                     is now LOOSER than the one you wrote. RE-SCALE it by hand"
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

fn rescale_amount(amount: Value, divisor: u64) -> Value {
    if divisor <= 1 {
        return amount;
    }
    match amount.as_u64() {
        Some(n) => Value::from((n / divisor).max(MIN_MIGRATED_BUDGET_AMOUNT)),
        None => amount,
    }
}

fn migrate_governance(root: &mut Pairs, changes: &mut Vec<String>, todos: &mut Vec<String>) {
    let mut gov = match take_mapping(root, field::GOVERNANCE, "", todos) {
        Taken::Got(m) => m,
        Taken::Absent | Taken::Malformed => return,
    };
    if gov.contains_key(field::ADMIN_TOKEN)
        && root.get_key(field::AUTH).is_some_and(|auth| {
            (!auth.is_null() && !auth.is_mapping())
                || auth
                    .get(field::ADMIN_AUTH)
                    .is_some_and(|list| !list.is_sequence())
        })
    {
        root.insert_key(field::GOVERNANCE, Value::Map(gov));
        todos.push("governance.admin_token: could not merge into malformed auth or auth.admin_auth; governance and auth were left unchanged for manual migration".into());
        return;
    }
    if gov
        .get_key(field::BUDGET_GROUPS)
        .and_then(Value::as_mapping)
        .is_some_and(|groups| {
            groups.values().any(|group| {
                group.as_mapping().is_none_or(|fields| {
                    fields.keys().any(|key| {
                        !matches!(
                            key.as_str(),
                            Some(field::PARENT | field::MAX_BUDGET_CENTS | field::BUDGET_PERIOD)
                        )
                    })
                })
            })
        })
    {
        root.insert_key(field::GOVERNANCE, Value::Map(gov));
        todos.push("governance.budget_groups: an entry is not a mapping or contains unrecognized fields; governance was left unchanged for manual migration".into());
        return;
    }

    let stray_module = take(&mut gov, "store").and_then(|v| v.as_str().map(str::to_string));
    let db_path = take(&mut gov, field::DB_PATH).and_then(|v| v.as_str().map(str::to_string));
    let module = stray_module.unwrap_or_else(|| legacy_store_text("gov14_module").into());
    {
        let mut store = Pairs::new();
        store.insert_key(field::MODULE, module.clone().into());
        let mut settings = Pairs::new();
        match (module.as_str(), db_path) {
            (m, _) if m == crate::config::migrated_store_module() => {}

            (m, p) if m == legacy_store_text("gov14_module") => {
                let p = p.unwrap_or_else(|| legacy_store_text("gov14_db_path").into());
                settings.insert_key(field::DB_PATH, p.into());
            }
            (_, Some(p)) => {
                settings.insert_key(field::URL, p.into());
            }
            (_, None) => {}
        }
        if let Some(busy) = take(&mut gov, legacy_store_text("gov14_busy_timeout_key")) {
            settings.insert_key(field::BUSY_TIMEOUT_MS, busy);
        }
        if !settings.is_empty() {
            store.insert_key(field::SETTINGS, Value::Map(settings));
        }
        root.insert_key(Kind::Store.root(), Value::Map(store));
        changes.push(legacy_store_text("gov14_change").into());
    }

    if let Some(card) = take(&mut gov, field::RATE_CARD) {
        root.insert_key(field::RATE_CARD, card);
        changes.push("governance.rate_card -> top-level rate_card".into());
    }
    if let Some(fee) = take(&mut gov, field::PRICE_PER_REQUEST_CENTS) {
        root.insert_key(field::PER_REQUEST_FEE, fee);
        changes.push("governance.price_per_request_cents -> per_request_fee".into());
    }
    if let Some(p1k) = take(&mut gov, field::PRICE_PER_1K_TOKENS_CENTS) {
        let n = p1k.as_f64().unwrap_or(LEGACY_UNREADABLE_TOKEN_PRICE_CENTS);
        let per_tier = n * LEGACY_CENTS_PER_THOUSAND_TO_MICRO_UNITS_PER_TOKEN;

        let existing_card = match swap_remove_key(root, field::RATE_CARD) {
            None => Some(Pairs::new()),
            Some(Value::Map(m)) => Some(m),
            Some(other) => {
                let shape = one_line(&other);
                root.insert_key(field::RATE_CARD, other);
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
                .get_key(field::MODELS)
                .and_then(|v| v.as_mapping())
                .map(|m| {
                    m.keys()
                        .filter_map(|k| k.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            for m in &model_names {
                if !card.contains_key(m.as_str()) {
                    let mut entry = Pairs::new();
                    for tier in [
                        field::INPUT_UTOK,
                        field::OUTPUT_UTOK,
                        field::CACHE_READ_UTOK,
                        field::CACHE_WRITE_UTOK,
                    ] {
                        entry.insert_key(tier, per_tier.into());
                    }
                    card.insert_key(m.as_str(), Value::Map(entry));
                }
            }
            root.insert_key(field::RATE_CARD, Value::Map(card));
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

    if let Taken::Got(gm) = take_mapping(&mut gov, field::BUDGET_GROUPS, field::GOVERNANCE, todos) {
        let mut out = Pairs::new();
        {
            for (name, g) in gm {
                let mut g = as_map(g);
                let mut entry = Pairs::new();
                if let Some(parent) = take(&mut g, field::PARENT) {
                    entry.insert_key(field::PARENT, parent);
                }
                let amount = take(&mut g, field::MAX_BUDGET_CENTS)
                    .unwrap_or(Value::from(LEGACY_ABSENT_BUDGET_CENTS));
                let period = take(&mut g, field::BUDGET_PERIOD)
                    .and_then(|v| v.as_str().map(str::to_string))
                    .unwrap_or_else(|| {
                        busbar_kernel::config::groups::LimitWindow::Total
                            .as_str()
                            .into()
                    });
                let mut limit = Pairs::new();
                let ctx = format!("groups.{}", name.as_str().unwrap_or("?"));
                let (window, divisor) = window_noun(&period, &ctx, todos);
                limit.insert_key(field::BUDGET, rescale_amount(amount, divisor));
                limit.insert_key(field::PER, window.into());
                entry.insert_key(field::LIMITS, Value::Array(vec![Value::Map(limit)]));
                out.insert_key(name, Value::Map(entry));
            }
        }
        root.insert_key(field::GROUPS, Value::Map(out));
        changes.push(
            "governance.budget_groups -> top-level groups (budget caps became generic limits)"
                .into(),
        );
    }
    let mut advanced = Pairs::new();
    if let Some(v) = take(&mut gov, field::RATE_SWEEP_INTERVAL) {
        advanced.insert_key(field::RATE_SWEEP_INTERVAL, v);
    }
    if let Some(v) = take(&mut gov, field::USAGE_FLUSH_INTERVAL_MS) {
        advanced.insert_key(field::USAGE_FLUSH_INTERVAL_MS, v);
    }
    if !advanced.is_empty() {
        root.insert_key(field::ADVANCED, Value::Map(advanced));
        changes.push("governance.rate_sweep_interval / usage_flush_interval_ms -> advanced".into());
    }
    if let Some(token) = take(&mut gov, field::ADMIN_TOKEN) {
        let operator = busbar_kernel::config::operator_provider();
        // No operator words: there is no name to write the entry under, and an entry under "" is
        // never valid. Write nothing and leave the install remedy.
        if operator.is_empty() {
            todos.push(operator_install_todo());
        } else {
            let auth = root.entry_or_insert_with(field::AUTH, || Value::Map(Pairs::new()));
            if auth.is_null() {
                *auth = Value::Map(Pairs::new());
            }
            if let Value::Map(auth) = auth {
                let secret_ref: Value = match token.as_str() {
                    Some(s) if s.starts_with("${") && s.ends_with('}') => {
                        let var = &s[2..s.len() - 1];
                        let mut m = Pairs::new();
                        m.insert_key(field::ENV, var.into());
                        Value::Map(m)
                    }
                    _ => {
                        todos.push(busbar_kernel_identity::operator::literal_token_todo(
                            operator,
                        ));
                        let mut m = Pairs::new();
                        m.insert_key(field::ENV, "BUSBAR_ADMIN_TOKEN".into());
                        Value::Map(m)
                    }
                };
                let mut body = Pairs::new();
                body.insert_key(field::TOKEN, secret_ref);
                let mut entry = Pairs::new();
                entry.insert_key(operator, Value::Map(body));
                auth.insert_key(field::ADMIN_AUTH, Value::Array(vec![Value::Map(entry)]));
            }
            changes.push(busbar_kernel_identity::operator::migrated_token(operator));
        }
    }

    if take(&mut gov, field::ENABLED).is_some() {
        changes.push("governance.enabled removed (governance is presence-driven)".into());
    }
    for (k, _) in &gov {
        todos.push(format!(
            "governance.{}: no mechanical 1.5.0 equivalent; consult the 1.5.0 CHANGELOG",
            k.as_str().unwrap_or("?")
        ));
    }
}

/// The TODO left when `governance.admin_token` is found and this build names no operator credential:
/// the install remedy for the operator credential, which keeps only a SHA-256 of the token.
fn operator_install_todo() -> String {
    "governance.admin_token was not migrated: this build names no operator credential. Install the \
     first-party operator credential plugin, then give it `settings: {sha256: \"<SHA-256 of the \
     token>\"}` in identity-providers and list it in auth.admin_auth; the token itself is not \
     stored"
        .to_owned()
}

fn migrate_auth(
    root: &mut Pairs,
    changes: &mut Vec<String>,
    todos: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    let mut group_map = take(root, field::GROUP_MAP);

    if !matches!(root.get_key(field::AUTH), Some(Value::Map(_))) && group_map.is_none() {
        return;
    }
    let Value::Map(auth) = root.entry_or_insert_with(field::AUTH, || Value::Map(Pairs::new()))
    else {
        if let Some(gm) = group_map {
            root.insert_key(field::GROUP_MAP, gm);
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
        group_map = take(auth, field::GROUP_MAP);
    }

    if let Some(Value::Array(chain)) = auth.get_key_mut(field::CHAIN) {
        let mut rewrote = false;
        let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut out: Vec<Value> = Vec::new();
        for e in std::mem::take(chain) {
            let mapped = match e.as_str() {
                Some(LEGACY_TOKENS_MODULE) | Some(LEGACY_STATIC_TOKENS_MODULE) => {
                    rewrote = true;
                    Value::from(busbar_kernel::config::KEYS_MODULE)
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
        }
    }

    let chain_uses_keys = matches!(
        auth.get_key(field::CHAIN),
        Some(Value::Array(c)) if c.iter().any(|e| {
            e.as_str() == Some(busbar_kernel::config::KEYS_MODULE)
                || e.as_mapping().is_some_and(|m| m.contains_key(busbar_kernel::config::KEYS_MODULE))
        })
    );
    if chain_uses_keys && !auth.contains_key(field::SIGNING_KEY) {
        todos.push(MISSING_SIGNING_KEY.into());
    }

    if let Some(Value::Map(modules)) = take(auth, field::MODULES) {
        for (mod_name, caps) in modules {
            let mod_name = mod_name.as_str().unwrap_or("?").to_string();
            let caps = as_map(caps);
            if let Some(scope) = caps.get_key(field::MAX_ADMIN_SCOPE).cloned() {
                let mut applied = false;
                for list in [field::CHAIN, field::ADMIN_AUTH] {
                    if let Some(Value::Array(seq)) = auth.get_key_mut(list) {
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
            if caps.contains_key(field::ALLOWED_GROUPS) {
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

    if let Some(mode) = take(auth, field::MODE).and_then(|v| v.as_str().map(str::to_string)) {
        match mode.as_str() {
            LEGACY_AUTH_MODE_PASSTHROUGH => {
                auth.insert_key(
                    field::UPSTREAM_CREDENTIALS,
                    LEGACY_AUTH_MODE_PASSTHROUGH.into(),
                );
                changes.push(
                    "auth.mode: passthrough -> auth.upstream_credentials: passthrough".into(),
                );
            }
            LEGACY_AUTH_MODE_NONE => {
                changes.push(
                    "auth.mode: none removed (an omitted chain is the open front door)".into(),
                );
            }
            other => {
                auth.insert_key(
                    field::CHAIN,
                    Value::Array(vec![busbar_kernel::config::KEYS_MODULE.into()]),
                );
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
    if take(auth, field::CLIENT_TOKENS).is_some() {
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

    let chain_modules: Vec<String> = auth
        .get_key(field::CHAIN)
        .and_then(|v| v.as_sequence())
        .map(|seq| {
            seq.iter()
                .filter_map(|e| match e {
                    Value::Text(s) => Some(s.clone()),
                    Value::Map(m) => m.keys().next().and_then(|k| k.as_str().map(str::to_string)),
                    _ => None,
                })
                .filter(|m| {
                    m != busbar_kernel::config::KEYS_MODULE
                        && m != LEGACY_TOKENS_MODULE
                        && m != busbar_kernel::config::operator_provider()
                })
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

    let Value::Map(gm) = gm else {
        root.insert_key(field::GROUP_MAP, gm);
        todos.push(
            "group_map: could not migrate to auth.role_bindings because `group_map:` itself is \
             not a mapping (malformed 1.4.x config); group_map was left at the top level \
             UNCHANGED - fix `group_map:` by hand, then re-run the migrator so it can nest these \
             bindings under auth.role_bindings"
                .into(),
        );
        return;
    };
    if gm.values().any(|binding| {
        binding.as_mapping().is_none_or(|fields| {
            fields.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    Some(
                        field::ALLOWED_POOLS
                            | field::BUDGET_GROUP
                            | field::GROUP
                            | field::ADMIN_SCOPE
                            | field::RPM_LIMIT
                            | field::TPM_LIMIT
                            | field::MAX_BUDGET_CENTS
                            | field::BUDGET_PERIOD
                    )
                )
            })
        })
    }) {
        root.insert_key(field::GROUP_MAP, Value::Map(gm));
        todos.push("group_map: a role is not a mapping or contains unrecognized fields; the group_map was left unchanged for manual migration".into());
        return;
    }
    let mut bindings = Pairs::new();
    let mut generated_groups: Pairs = Pairs::new();
    {
        for (role, b) in gm {
            let role_name = role.as_str().unwrap_or("?").to_string();
            let mut b = as_map(b);
            let mut binding = Pairs::new();
            if let Some(pools) = take(&mut b, field::ALLOWED_POOLS) {
                if pools.as_sequence().is_some_and(|s| s.is_empty()) {
                    warnings.push(
                        busbar_kernel::diagnostics::coded::migrate_empty_allowed_pools_flipped(
                            &module, &role_name,
                        )
                        .into(),
                    );
                }
                binding.insert_key(field::ALLOWED_POOLS, pools);
            }
            if let Some(g) =
                take(&mut b, field::BUDGET_GROUP).or_else(|| take(&mut b, field::GROUP))
            {
                binding.insert_key(field::GROUP, g);
            }
            if let Some(scope) = take(&mut b, field::ADMIN_SCOPE) {
                binding.insert_key(field::ADMIN_SCOPE, scope);
            }

            let rpm = take(&mut b, field::RPM_LIMIT);
            let tpm = take(&mut b, field::TPM_LIMIT);
            let budget = take(&mut b, field::MAX_BUDGET_CENTS);
            let period = take(&mut b, field::BUDGET_PERIOD)
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_else(|| {
                    busbar_kernel::config::groups::LimitWindow::Total
                        .as_str()
                        .into()
                });
            if rpm.is_some() || tpm.is_some() || budget.is_some() {
                let gname = format!("migrated-{role_name}");
                let mut limits: Vec<Value> = Vec::new();
                if let Some(r) = rpm {
                    let mut l = Pairs::new();
                    l.insert_key(field::REQUESTS, r);
                    l.insert_key(
                        field::PER,
                        busbar_kernel::config::groups::LimitWindow::Minute
                            .as_str()
                            .into(),
                    );
                    limits.push(Value::Map(l));
                }
                if let Some(t) = tpm {
                    let mut l = Pairs::new();
                    l.insert_key(field::TOKENS, t);
                    l.insert_key(
                        field::PER,
                        busbar_kernel::config::groups::LimitWindow::Minute
                            .as_str()
                            .into(),
                    );
                    limits.push(Value::Map(l));
                }
                if let Some(bu) = budget {
                    let mut l = Pairs::new();
                    let (window, divisor) = window_noun(&period, &format!("groups.{gname}"), todos);
                    l.insert_key(field::BUDGET, rescale_amount(bu, divisor));
                    l.insert_key(field::PER, window.into());
                    limits.push(Value::Map(l));
                }
                let mut entry = Pairs::new();
                entry.insert_key(field::LIMITS, Value::Array(limits));
                generated_groups.insert_key(gname.as_str(), Value::Map(entry));
                if !binding.contains_key(field::GROUP) {
                    binding.insert_key(field::GROUP, gname.as_str().into());
                }
                todos.push(format!(
                    "groups.{gname}: generated from the old group_map role '{role_name}' inline \
                     caps; review the limits and consider merging it into your real group tree"
                ));
                changes.push(format!(
                    "auth.group_map.{role_name} caps -> generated groups.{gname}"
                ));
            }
            bindings.insert_key(role, Value::Map(binding));
        }
    }
    let mut nested = Pairs::new();
    nested.insert_key(module.as_str(), Value::Map(bindings));
    auth.insert_key(field::ROLE_BINDINGS, Value::Map(nested));
    changes.push(format!(
        "auth.group_map -> auth.role_bindings.{module} (nested by module)"
    ));
    if !generated_groups.is_empty() {
        let groups = root.entry_or_insert_with(field::GROUPS, || Value::Map(Pairs::new()));
        if let Value::Map(groups) = groups {
            for (k, v) in generated_groups {
                groups.insert_key(k, v);
            }
        }
    }
}

fn migrate_providers(root: &mut Pairs, changes: &mut Vec<String>) {
    let Some(Value::Map(providers)) = root.get_key_mut(Kind::Transport.root()) else {
        return;
    };
    for (name, p) in providers.iter_mut() {
        let Value::Map(p) = p else { continue };
        if let Some(var) = take(p, field::API_KEY_ENV) {
            let mut secret = Pairs::new();
            secret.insert_key(field::ENV, var);
            p.insert_key(field::API_KEY, Value::Map(secret));
            changes.push(format!(
                "providers.{}.api_key_env -> api_key: {{ env: ... }}",
                name.as_str().unwrap_or("?")
            ));
        }
    }
}

fn at_to_phase(at: &Value) -> Option<Value> {
    let s = at.as_str()?;
    let renamed = crate::config::retired::RENAMED_HOOK_STAGES
        .iter()
        .find(|(o, _)| *o == s)
        .map(|(_, n)| *n)
        .unwrap_or(s);
    Some(Value::Array(vec![Value::from(renamed)]))
}

fn hook_entry_to_def(name: &str, entry: &Value, todos: &mut Vec<String>) -> Value {
    let m = entry.as_mapping().cloned().unwrap_or_default();
    let mut def = Pairs::new();
    let mut settings = as_map(m.get_key(field::SETTINGS).cloned().unwrap_or(Value::Null));
    let url_transport = super::migration_table::text("hook_1x_url_transport");
    if let Some(url) = m
        .get_key(url_transport)
        .filter(|_| !url_transport.is_empty())
        .and_then(|v| v.as_str())
    {
        def.insert_key(field::MODULE, url_transport.into());
        settings.insert_key(field::URL, url.into());
    } else if let Some(path) = m.get_key(field::SOCKET).and_then(|v| v.as_str()) {
        def.insert_key(field::MODULE, field::SOCKET.into());
        settings.insert_key(field::PATH, path.into());
    } else if let Some(module) = m.get_key(field::MODULE).and_then(|v| v.as_str()) {
        def.insert_key(field::MODULE, module.into());
    } else if let Some(plugin) = m.get_key(field::PLUGIN).and_then(|v| v.as_str()) {
        def.insert_key(field::MODULE, plugin.into());
    } else {
        todos.push(format!(
            "hook '{name}': no module/socket/{url_transport}/plugin transport found; set `module:` \
             to a `kind: hook` plugin"
        ));
        def.insert_key(field::MODULE, url_transport.into());
    }
    if !settings.is_empty() {
        def.insert_key(field::SETTINGS, Value::Map(settings));
    }
    for k in [
        field::KIND,
        field::TIMEOUT_MS,
        field::ON_ERROR,
        field::ON_EMPTY,
        field::PROMPT,
        field::USER,
        field::PRIORITY,
        field::GROUPS,
    ] {
        if let Some(v) = m.get_key(k) {
            def.insert_key(k, v.clone());
        }
    }
    let phase = m.get_key(field::PHASE);
    if let Some(phase) = phase.filter(|p| !p.as_sequence().is_some_and(Vec::is_empty)) {
        def.insert_key(field::PHASE, phase.clone());
    } else if let Some(phase) = m.get_key(field::AT).and_then(at_to_phase) {
        def.insert_key(field::PHASE, phase);
    } else if let Some(phase) = phase {
        def.insert_key(field::PHASE, phase.clone());
    } else if m.get_key(field::KIND).and_then(|v| v.as_str()) == Some(LEGACY_TAP_HOOK_KIND) {
        def.insert_key(
            field::PHASE,
            Value::Array(vec![Value::from(
                busbar_kernel::config::HookStage::Request.as_str(),
            )]),
        );
    }
    if m.get_key(field::DEFAULT).and_then(|v| v.as_bool()) == Some(true) {
        todos.push(format!(
            "hook '{name}': the retired `default: true` flag is gone; name the base ordering \
             strategy in each pool's `hooks:` list explicitly"
        ));
    }
    if m.contains_key(field::SIGNALS) {
        todos.push(format!(
            "hook '{name}': the `signals:` declaration did not carry over automatically; re-add it \
             under the named `hooks:` entry if the hook still needs it"
        ));
    }
    Value::Map(def)
}

fn uniq_def_name(defs: &Pairs, base: &str) -> String {
    if !defs.contains_key(base) {
        return base.to_string();
    }
    let mut n = 2usize;
    loop {
        let candidate = format!("{base}-{n}");
        if !defs.contains_key(candidate.as_str()) {
            return candidate;
        }
        n += 1;
    }
}

/// 1.5.3 NAMED-HOOKS migration: converge the OLD hook surfaces onto the new shape — the top-level
/// `hooks:` NAMED-DEFINITION map plus the reserved `pools.hooks:` all-pools attach and per-pool
/// bare-name references. Handles three legacy sources, idempotently:
///   * a 1.x `hooks:` REGISTRY (socket: / URL transport entries) → named definitions (same names).
///   * `global_hooks:` (bare registry names OR 1.5.0/1.5.2 inline instances) → the reserved
///     `pools.hooks:` all-pools list (inline instances lifted to a named def first, with a todo).
///   * inline pool-hook instances (`pools.X.hooks: [{ module: … }]`) → a named def + a bare-name
///     reference in that pool (with a todo).
///
/// A config already in the new shape (a `hooks:` map of `module:` defs) passes through untouched.
fn migrate_hooks_block(root: &mut Pairs, changes: &mut Vec<String>, todos: &mut Vec<String>) {
    let needs_all_pools = root.contains_key(field::GLOBAL_HOOKS)
        || root
            .get_key(Kind::Hook.root())
            .and_then(Value::as_mapping)
            .is_some_and(|hooks| {
                hooks
                    .values()
                    .any(|hook| hook.get(field::GLOBAL).and_then(Value::as_bool) == Some(true))
            });
    if needs_all_pools
        && root.get_key(field::POOLS).is_some_and(|pools| {
            !pools.is_mapping()
                || pools
                    .get(field::HOOKS)
                    .is_some_and(|hooks| !hooks.is_sequence())
        })
    {
        todos.push("pools or pools.hooks: has an incompatible shape; global hook definitions and attachments were left unchanged because their all-pools references cannot be merged".into());
        return;
    }

    let hooks_src = match take_mapping(root, Kind::Hook.root(), "", todos) {
        Taken::Got(m) => Some(m),
        Taken::Absent | Taken::Malformed => None,
    };
    let mut defs = Pairs::new();
    let mut all_pools: Vec<Value> = Vec::new();

    if let Some(src) = hooks_src {
        if is_new_hook_defs(&src) {
            defs = src;
        } else {
            for (k, entry) in &src {
                let Some(name) = k.as_str() else { continue };
                defs.insert_key(k.clone(), hook_entry_to_def(name, entry, todos));
                if entry
                    .as_mapping()
                    .and_then(|m| m.get_key(field::GLOBAL))
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

    let global_hooks_src = match take_sequence(root, field::GLOBAL_HOOKS, "", todos) {
        Taken::Got(s) => s,

        Taken::Absent | Taken::Malformed => Vec::new(),
    };
    for entry in global_hooks_src {
        match entry {
            Value::Text(name) => {
                if !all_pools.iter().any(|v| v.as_str() == Some(name.as_str())) {
                    all_pools.push(Value::from(name.as_str()));
                }
                changes.push(format!(
                    "global_hooks '{name}' -> pools.hooks all-pools attach (1.5.3)"
                ));
            }
            Value::Map(m) => {
                let base = m
                    .get_key(field::MODULE)
                    .and_then(|v| v.as_str())
                    .unwrap_or(UNNAMED_HOOK_STEM)
                    .to_string();
                let nm = uniq_def_name(&defs, &base);
                let def = hook_entry_to_def(&nm, &Value::Map(m), todos);
                defs.insert_key(nm.as_str(), def);
                all_pools.push(Value::from(nm.as_str()));
                todos.push(format!(
                    "global_hooks inline instance lifted to a named hook '{nm}' + a pools.hooks \
                     all-pools reference; review the auto-generated name"
                ));
            }
            other => all_pools.push(other),
        }
    }

    if let Some(Value::Map(pools)) = root.get_key_mut(field::POOLS) {
        let pool_names: Vec<Value> = pools.keys().cloned().collect();
        for pk in pool_names {
            if pk.as_str() == Some(field::HOOKS) {
                continue;
            }
            let Some(Value::Map(p)) = pools.get_key_mut(&pk) else {
                continue;
            };
            let pool_ctx = format!("pools.{}", pk.as_str().unwrap_or("?"));
            let existing = match take_sequence(p, field::HOOKS, &pool_ctx, todos) {
                Taken::Got(s) => s,

                Taken::Absent | Taken::Malformed => continue,
            };
            let mut new_list: Vec<Value> = Vec::new();
            for entry in existing {
                match entry {
                    Value::Map(m) => {
                        let base = m
                            .get_key(field::MODULE)
                            .and_then(|v| v.as_str())
                            .unwrap_or(UNNAMED_HOOK_STEM)
                            .to_string();
                        let nm = uniq_def_name(&defs, &base);
                        let def = hook_entry_to_def(&nm, &Value::Map(m), todos);
                        defs.insert_key(nm.as_str(), def);
                        new_list.push(Value::from(nm.as_str()));
                        todos.push(format!(
                            "pools.{}.hooks inline instance lifted to a named hook '{nm}' + a \
                             bare-name reference",
                            pk.as_str().unwrap_or("?")
                        ));
                    }

                    other => new_list.push(other),
                }
            }
            if !new_list.is_empty() {
                p.insert_key(field::HOOKS, Value::Array(new_list));
            }
        }
    }

    if !defs.is_empty() {
        if root.contains_key(Kind::Hook.root()) {
            todos.push(format!(
                "hooks: {} hook definition(s) lifted from `global_hooks:`/inline pool hooks could \
                 NOT be written, because the top-level `hooks:` key is present in a shape this \
                 migrator cannot merge into and was left as you wrote it. Fix `hooks:` (a mapping \
                 of NAME -> {{ module: … }}) and re-run `--migrate-config`.",
                defs.len()
            ));
        } else {
            root.insert_key(Kind::Hook.root(), Value::Map(defs));
        }
    }
    if !all_pools.is_empty() {
        let pools = root.entry_or_insert_with(field::POOLS, || Value::Map(Pairs::new()));
        if let Value::Map(pm) = pools {
            let mut merged = match take_sequence(pm, field::HOOKS, field::POOLS, todos) {
                Taken::Got(s) => s,
                Taken::Absent => Vec::new(),

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
            pm.insert_key(field::HOOKS, Value::Array(merged));
        }
    }
}

/// The top-level `pools:` key is the model plane's alone (a released 1.5.5 key).
fn check_top_level_pool_plane(root: &Pairs, todos: &mut Vec<String>) {
    let pools_key = busbar_contract::section::RESERVED_POOLS_KEY;
    let model = |member: &str| -> bool {
        matches!(root.get_key(field::MODELS), Some(Value::Map(m)) if m.contains_key(member))
    };
    let Some(Value::Map(pools)) = root.get_key(pools_key) else {
        return;
    };
    for (name, def) in pools {
        let Some(n) = name.as_str() else { continue };
        if busbar_contract::section::RESERVED_SECTION_KEYS.contains(&n) {
            continue;
        }
        let bare: Option<Vec<&str>> = def
            .get(field::MEMBERS)
            .and_then(Value::as_sequence)
            .and_then(|m| m.iter().map(Value::as_str).collect());
        if bare.is_some_and(|m| !m.is_empty() && !m.iter().any(|x| model(x))) {
            todos.push(format!(
                "`{pools_key}.{n}` names no `models:` entry: the top-level `{pools_key}:` is the \
                 model plane's alone. Move it under the section of the plane its members are \
                 registered on (`<section>.{pools_key}.{n}`), with the same `members:` and \
                 `repeatable:`."
            ));
        }
    }
}

fn migrate_pools(root: &mut Pairs, changes: &mut Vec<String>, todos: &mut Vec<String>) {
    let Some(Value::Map(pools)) = root.get_key_mut(field::POOLS) else {
        return;
    };
    for (pname, p) in pools.iter_mut() {
        let pname = pname.as_str().unwrap_or("?").to_string();
        let Value::Map(p) = p else { continue };

        let policy = p
            .get_key(field::POLICY)
            .and_then(|v| v.as_str())
            .map(str::to_string);
        if let Some(policy) = policy {
            let pool_ctx = format!("pools.{pname}");
            match take_sequence(p, field::HOOKS, &pool_ctx, todos) {
                Taken::Got(mut list) => {
                    take(p, field::POLICY);
                    list.insert(0, policy.as_str().into());
                    p.insert_key(field::HOOKS, Value::Array(list));
                    changes.push(format!("pools.{pname}.policy -> hooks: [{policy}, ...]"));
                }
                Taken::Absent => {
                    take(p, field::POLICY);
                    p.insert_key(field::HOOKS, Value::Array(vec![policy.as_str().into()]));
                    changes.push(format!("pools.{pname}.policy -> hooks: [{policy}]"));
                }
                Taken::Malformed => todos.push(format!(
                    "pools.{pname}.policy: could not be folded into `hooks:` (see the `hooks:` todo \
                     above); BOTH keys were left EXACTLY as written. The retired `policy:` key is \
                     rejected by 1.5.3, so fix `hooks:` and re-run `--migrate-config`."
                )),
            }
        }
        if let Some(Value::Array(members)) = p.get_key_mut(field::MEMBERS) {
            for mem in members.iter_mut() {
                let Value::Map(mem) = mem else { continue };
                if let Some(target) = take(mem, field::TARGET) {
                    mem.insert_key(field::MODEL, target);
                    changes.push(format!("pools.{pname}.members[].target -> model"));
                }
                if take(mem, field::COST_PER_MTOK).is_some() {
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
        if let Some(Value::Map(breaker)) = p.get_key_mut(field::BREAKER) {
            if let Some(Value::Map(trip)) = breaker.get_key_mut(field::TRIP) {
                if let Some(v) = take(trip, field::WINDOW_S) {
                    trip.insert_key(field::WINDOW_SECS, v);
                    changes.push(format!(
                        "pools.{pname}.breaker.trip.window_s -> window_secs"
                    ));
                }
                if let Some(v) = take(trip, field::N) {
                    trip.insert_key(field::CONSECUTIVE_N, v);
                    changes.push(format!("pools.{pname}.breaker.trip.n -> consecutive_n"));
                }
            }
        }
        if let Some(Value::Map(failover)) = p.get_key_mut(field::FAILOVER) {
            if let Some(v) = take(failover, field::DEADLINE_SECS) {
                failover.insert_key(field::TIMEOUT_SECS, v);
                changes.push(format!(
                    "pools.{pname}.failover.deadline_secs -> timeout_secs"
                ));
            }
            if let Some(v) = take(failover, field::CAP) {
                failover.insert_key(field::MAX_HOPS, v);
                changes.push(format!("pools.{pname}.failover.cap -> max_hops"));
            }
        }
        migrate_on_exhausted(&pname, p, changes, todos);
    }
}

fn migrate_on_exhausted(
    pname: &str,
    p: &mut Pairs,
    changes: &mut Vec<String>,
    todos: &mut Vec<String>,
) {
    let Some(oe) = p.get_key(field::ON_EXHAUSTED).cloned() else {
        return;
    };

    let Some(action) = oe
        .as_mapping()
        .and_then(|m| m.get_key(field::ACTION))
        .and_then(|v| v.as_str())
    else {
        return;
    };
    let action = action.trim().to_string();
    let new_val: Value = if let Some(pool) = action.strip_prefix(LEGACY_FALLBACK_ACTION_PREFIX) {
        let pool = pool.trim();
        if pool.is_empty() {
            todos.push(format!(
                "pools.{pname}.on_exhausted: the 1.4.x `fallback_pool:` action named NO pool; set \
                 `on_exhausted: {{ fallback_pool: <pool> }}` to a real pool (left as `reject`)"
            ));
            Value::from(EXHAUSTED_REJECT)
        } else {
            let mut fb = Pairs::new();
            fb.insert_key(field::FALLBACK_POOL, pool.into());
            Value::Map(fb)
        }
    } else {
        match action.as_str() {
            word if LEGACY_REJECT_ACTIONS.contains(&word) => Value::from(EXHAUSTED_REJECT),
            word if LEGACY_LEAST_BAD_ACTIONS.contains(&word) => Value::from(EXHAUSTED_LEAST_BAD),
            word if LEGACY_TARGETLESS_FALLBACK_ACTIONS.contains(&word) => {
                todos.push(format!(
                    "pools.{pname}.on_exhausted: the 1.4.x `{action}` action needs a target pool; \
                     set `on_exhausted: {{ fallback_pool: <pool> }}` (left as `reject`)"
                ));
                Value::from(EXHAUSTED_REJECT)
            }
            other => {
                todos.push(format!(
                    "pools.{pname}.on_exhausted: unrecognized 1.4.x action `{other}`; the 1.5.0 \
                     options are `reject` | `least_bad` | {{ fallback_pool: <pool> }} (left as \
                     `reject`)"
                ));
                Value::from(EXHAUSTED_REJECT)
            }
        }
    };
    p.insert_key(field::ON_EXHAUSTED, new_val);
    changes.push(format!(
        "pools.{pname}.on_exhausted: {{ action: {action} }} -> 1.5.0 bare keyword / {{ fallback_pool }}"
    ));
}

fn migrate_observability(root: &mut Pairs, changes: &mut Vec<String>) {
    let Some(Value::Map(obs)) = root.get_key_mut(field::OBSERVABILITY) else {
        return;
    };
    let (old, new) = (
        super::migration_table::text("observability_trace_key_1_4"),
        super::migration_table::text("observability_trace_key"),
    );
    if old.is_empty() || new.is_empty() {
        return;
    }
    if let Some(v) = take(obs, old) {
        obs.insert_key(new, v);
        changes.push(format!("observability.{old} -> {new}"));
    }
}

fn migrate_observability_export(root: &mut Pairs, changes: &mut Vec<String>) {
    fn export_mut(root: &mut Pairs) -> &mut Pairs {
        let entry = root.entry_or_insert_with(Kind::Export.root(), || Value::Map(Pairs::new()));
        if !matches!(entry, Value::Map(_)) {
            *entry = Value::Map(Pairs::new());
        }
        match entry {
            Value::Map(m) => m,
            _ => unreachable!("just normalized to a mapping"),
        }
    }

    let mut log_settings = Pairs::new();
    if let Some(Value::Map(obs)) = root.get_key_mut(field::OBSERVABILITY) {
        for (old, leaf) in super::migration_table::pairs("observability_log_keys") {
            if let Some(v) = take(obs, old) {
                log_settings.insert_key(leaf, v);
            }
        }

        if obs.is_empty() {
            swap_remove_key(root, field::OBSERVABILITY);
        }
    }
    if log_settings.contains_key(field::URL) {
        let mut body = Pairs::new();
        body.insert_key(field::SETTINGS, Value::Map(log_settings));
        export_mut(root).insert_key(
            super::migration_table::text("observability_log_type_key"),
            Value::Map(body),
        );
        changes.push(super::migration_table::text("observability_log_change").into());
    }

    let metrics_type_key = super::migration_table::text("metrics_type_key");
    let removed_metrics = swap_remove_key(root, field::METRICS);
    if let Some(Value::Map(mut metrics)) = removed_metrics {
        let mut settings = Pairs::new();
        if let Some(v) = take(&mut metrics, field::BUFFER_SECONDS) {
            settings.insert_key(field::BUFFER_SECONDS, v);
        }
        if let Some(v) = take(&mut metrics, field::KEY_GAUGE_LIMIT) {
            settings.insert_key(field::KEY_GAUGE_LIMIT, v);
        }

        for (k, v) in metrics {
            settings.insert_key(k, v);
        }
        let mut body = Pairs::new();
        body.insert_key(field::SETTINGS, Value::Map(settings));
        export_mut(root).insert_key(metrics_type_key, Value::Map(body));
        changes.push(format!(
            "metrics: block -> export.{metrics_type_key}.settings (built-in exporter)"
        ));
    } else if let Some(other) = removed_metrics {
        changes.push(format!(
            "metrics: block removed (RETIRED in 1.5.3; it was not a mapping — the value `{}` \
             carried no settings foldable into export.{metrics_type_key})",
            one_line(&other)
        ));
    }
}

fn migrate_response_headers(root: &mut Pairs, changes: &mut Vec<String>, todos: &mut Vec<String>) {
    if !matches!(
        root.get_key(field::OBSERVABILITY),
        Some(Value::Map(m)) if m.contains_key(field::EMIT_SERVER_TIMING)
    ) {
        return;
    }

    let mut advanced = match take_mapping(root, field::ADVANCED, "", todos) {
        Taken::Got(m) => m,
        Taken::Absent => Pairs::new(),
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
    let Some(Value::Map(obs)) = root.get_key_mut(field::OBSERVABILITY) else {
        unreachable!("shape checked above");
    };
    let Some(v) = take(obs, field::EMIT_SERVER_TIMING) else {
        unreachable!("presence checked above");
    };
    let mut response_headers = as_map(
        swap_remove_key(&mut advanced, field::RESPONSE_HEADERS).unwrap_or(Value::Map(Pairs::new())),
    );
    response_headers.insert_key(field::SERVER_TIMING, v);
    advanced.insert_key(field::RESPONSE_HEADERS, Value::Map(response_headers));
    root.insert_key(field::ADVANCED, Value::Map(advanced));
    changes
        .push("observability.emit_server_timing -> advanced.response_headers.server_timing".into());
}

fn migrate_hook_stages(root: &mut Pairs, changes: &mut Vec<String>) {
    fn rewrite_list(list: &mut [Value], location: &str, changes: &mut Vec<String>) {
        for entry in list {
            let Value::Map(m) = entry else { continue };
            let Some(old) = m.get_key(field::AT).and_then(|v| v.as_str()) else {
                continue;
            };
            if let Some((_, new)) = crate::config::retired::RENAMED_HOOK_STAGES
                .iter()
                .find(|(o, _)| *o == old)
            {
                changes.push(format!("{location}: hook stage `at: {old}` -> `at: {new}`"));
                m.insert_key(field::AT, Value::from(*new));
            }
        }
    }
    if let Some(Value::Array(globals)) = root.get_key_mut(field::GLOBAL_HOOKS) {
        rewrite_list(globals, field::GLOBAL_HOOKS, changes);
    }
    if let Some(Value::Map(pools)) = root.get_key_mut(field::POOLS) {
        for (pname, p) in pools.iter_mut() {
            let Value::Map(p) = p else { continue };
            let Some(Value::Array(hooks)) = p.get_key_mut(field::HOOKS) else {
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
///   * `at: <stage>` → `phase: [<stage>]` (stage-renamed via [`crate::config::retired::RENAMED_HOOK_STAGES`],
///     matching the overlay boot-migration), unless a non-empty `phase:` is already present, in which
///     case `at:` is dropped — the list is authoritative under the old `fires_at_stage` precedence.
///
/// IDEMPOTENT: an entry already spelled `module:`/`phase:` has nothing to rewrite. Complements
/// [`hook_entry_to_def`] (which performs the same conversion when LIFTING a legacy registry/inline
/// hook); this pass catches a `hooks:` map that was ALREADY the named-def shape yet still carried a
/// retired key, which `migrate_hooks_block` passes through untouched.
fn migrate_hook_def_keys(root: &mut Pairs, changes: &mut Vec<String>) {
    let Some(Value::Map(hooks)) = root.get_key_mut(Kind::Hook.root()) else {
        return;
    };
    for (name, entry) in hooks.iter_mut() {
        let Value::Map(def) = entry else { continue };
        let hook_name = name.as_str().unwrap_or("?").to_string();

        if let Some(plugin) = take(def, field::PLUGIN) {
            if !def.contains_key(field::MODULE) {
                def.insert_key(field::MODULE, plugin);
                changes.push(format!("hooks.{hook_name}: `plugin:` -> `module:` (1.6.0)"));
            } else {
                changes.push(format!(
                    "hooks.{hook_name}: retired `plugin:` dropped (`module:` already set, 1.6.0)"
                ));
            }
        }

        if let Some(at) = take(def, field::AT) {
            let phase_present = def
                .get_key(field::PHASE)
                .and_then(|v| v.as_sequence())
                .is_some_and(|s| !s.is_empty());
            if phase_present {
                changes.push(format!(
                    "hooks.{hook_name}: retired `at:` dropped (`phase:` already set, 1.6.0)"
                ));
            } else if let Some(phase) = at_to_phase(&at) {
                def.insert_key(field::PHASE, phase);
                changes.push(format!(
                    "hooks.{hook_name}: single-stage `at: {}` -> `phase:` list (1.6.0)",
                    at.as_str().unwrap_or("?")
                ));
            }
        }
    }
}

fn migrate_admin_require_mtls(root: &mut Pairs, changes: &mut Vec<String>) {
    let Some(old) = take(root, field::ADMIN_INSECURE) else {
        return;
    };

    let insecure = old.as_bool().unwrap_or(false);
    root.insert_key(field::ADMIN_REQUIRE_MTLS, Value::from(!insecure));
    changes.push(format!(
        "admin_insecure: {insecure} -> admin_require_mtls: {} (INVERTED in 1.5.3 so the safe \
         posture is the default)",
        !insecure
    ));
}

fn migrate_pools_upstream_credentials(
    root: &mut Pairs,
    changes: &mut Vec<String>,
    todos: &mut Vec<String>,
) {
    if root
        .get_key(field::POOLS)
        .is_some_and(|pools| !pools.is_mapping())
    {
        if root
            .get_key(field::AUTH)
            .and_then(|auth| auth.get(field::UPSTREAM_CREDENTIALS))
            .is_some()
        {
            todos.push("auth.upstream_credentials: could not move into non-mapping pools; both values were left unchanged for manual migration".into());
        }
        return;
    }
    let Some(Value::Map(auth)) = root.get_key_mut(field::AUTH) else {
        return;
    };
    let Some(mode) = take(auth, field::UPSTREAM_CREDENTIALS) else {
        return;
    };
    let pools = root.entry_or_insert_with(field::POOLS, || Value::Map(Pairs::new()));
    if let Value::Map(pm) = pools {
        if pm.contains_key(field::UPSTREAM_CREDENTIALS) {
            changes.push(
                "auth.upstream_credentials dropped: pools.upstream_credentials is already set (the \
                 1.5.3 home) and wins"
                    .into(),
            );
        } else {
            pm.insert_key(field::UPSTREAM_CREDENTIALS, mode);
            changes.push(
                "auth.upstream_credentials -> pools.upstream_credentials (the all-pools SCALAR \
                 default; override it per pool with `pools.<p>.upstream_credentials`)"
                    .into(),
            );
        }
    }
}

fn migrate_store_module(root: &mut Pairs, changes: &mut Vec<String>, todos: &mut Vec<String>) {
    let mut store = match take_mapping(root, Kind::Store.root(), "", todos) {
        Taken::Got(m) => m,
        Taken::Absent | Taken::Malformed => return,
    };
    if let Some((old, alias)) =
        crate::config::migration_table::rewrite_retired(Kind::Store.root(), &mut store, true)
    {
        changes.push(format!(
            "store.module: {old} -> {alias} (the first-party store plugin for this backend was \
             RENAMED in 1.5.3: artifact `{}-<ver>-<target>.tar.gz`, manifest name `{}`. Install the \
             renamed tarball — the old one no longer answers to any name in this config. Your \
             `settings.url` is UNCHANGED: `{}://` is the driver's own URL scheme, not a busbar \
             name.)",
            legacy_store_text(&format!("asset.{alias}")),
            legacy_store_text(&format!("manifest.{alias}")),
            legacy_store_text("retired_url_scheme"),
        ));
    }

    root.insert_key(Kind::Store.root(), Value::Map(store));
}

fn split_suffix(site: &str) -> &str {
    match site {
        field::ADMIN_AUTH => ADMIN_PROVIDER_SUFFIX,
        other => other,
    }
}

fn migrate_identity_providers(
    root: &mut Pairs,
    changes: &mut Vec<String>,
    todos: &mut Vec<String>,
) {
    let removed_auth = swap_remove_key(root, field::AUTH);
    let Some(Value::Map(mut auth)) = removed_auth else {
        if let Some(other) = removed_auth {
            let shape = one_line(&other);
            root.insert_key(field::AUTH, other);
            todos.push(format!(
                "auth: is not a mapping (`{shape}`) — it was left EXACTLY as written and NOTHING \
                 was lifted out of it. 1.5.3 expects `auth: {{ chain: [...], admin_auth: [...] }}` \
                 with the providers defined under the top-level `identity-providers:` map; fix the \
                 block by hand, then re-run the migration."
            ));
        }
        return;
    };

    let removed_defs = swap_remove_key(root, Kind::Auth.root());
    let mut defs = match removed_defs {
        None => Pairs::new(),
        Some(Value::Map(m)) => m,

        Some(other) => {
            let shape = one_line(&other);
            root.insert_key(field::AUTH, Value::Map(auth));
            root.insert_key(Kind::Auth.root(), other);
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
            let module = v.as_mapping()?.get_key(field::MODULE)?.as_str()?;
            Some((module.to_string(), name))
        })
        .collect();

    let lift = |module: &str,
                body: &Pairs,
                site: &str,
                defs: &mut Pairs,
                by_module: &mut Vec<(String, String)>,
                changes: &mut Vec<String>,
                todos: &mut Vec<String>|
     -> String {
        let want = body.get_key(field::SETTINGS);
        let settings_of = |defs: &Pairs, name: &str| -> Option<Value> {
            defs.get_key(name)
                .and_then(|d| d.as_mapping())
                .and_then(|d| d.get_key(field::SETTINGS))
                .cloned()
        };
        let compatible = |name: &str| {
            let existing = defs.get_key(name).and_then(Value::as_mapping);
            [field::MAX_ADMIN_SCOPE, field::TOKEN, field::SETTINGS]
                .iter()
                .all(
                    |key| match (existing.and_then(|d| d.get_key(*key)), body.get_key(*key)) {
                        (Some(old), Some(new)) => yaml::same_tree(old, new),
                        _ => true,
                    },
                )
        };

        let candidates: Vec<String> = by_module
            .iter()
            .filter(|(m, _)| m == module)
            .map(|(_, n)| n.clone())
            .collect();

        let may_split = site != field::METHODS;

        let reuse = if may_split {
            candidates
                .iter()
                .find(|n| {
                    compatible(n)
                        && (want.is_none() || same_settings(settings_of(defs, n).as_ref(), want))
                })
                .or_else(|| {
                    candidates
                        .iter()
                        .find(|n| compatible(n) && settings_of(defs, n).is_none())
                })
                .cloned()
        } else {
            candidates.first().cloned()
        };
        if let Some(name) = reuse {
            if let Some(Value::Map(existing)) = defs.get_key_mut(name.as_str()) {
                for key in [field::MAX_ADMIN_SCOPE, field::TOKEN, field::SETTINGS] {
                    if !existing.contains_key(key) {
                        if let Some(v) = body.get_key(key) {
                            existing.insert_key(key, v.clone());
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

        let split = !candidates.is_empty();
        let base = if split {
            format!("{module}-{}", split_suffix(site))
        } else {
            module.to_string()
        };
        let name = super::migrate_export::uniq_export_name(defs, &base);
        let mut def = Pairs::new();
        def.insert_key(field::MODULE, Value::from(module));
        for key in [field::MAX_ADMIN_SCOPE, field::TOKEN, field::SETTINGS] {
            if let Some(v) = body.get_key(key) {
                def.insert_key(key, v.clone());
            }
        }
        defs.insert_key(name.as_str(), Value::Map(def));
        by_module.push((module.to_string(), name.clone()));
        if split {
            let settings_conflict = candidates.iter().all(|name| {
                matches!((settings_of(defs, name).as_ref(), want),
                    (Some(old), Some(new)) if !yaml::same_tree(old, new))
            });
            let field = if settings_conflict {
                "`settings:`"
            } else {
                "typed fields"
            };
            let values = if settings_conflict {
                field::SETTINGS
            } else {
                "fields"
            };
            changes.push(format!(
                "auth.{site} entry `{module}: {{ … }}` -> a SECOND identity-providers.{name} \
                 definition (its {field} differ from the existing `{module}` definition, so the \
                 two were NOT deduped)"
            ));
            todos.push(format!(
                "identity-providers.{name}: `{module}` was configured on more than one auth plane \
                 with DIFFERENT {field}, so the migrator kept BOTH — `{name}` carries the \
                 `auth.{site}` {values} and is referenced from there; the other definition keeps \
                 the {values} of the site that declared it first. Nothing was lost; rename them to \
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

    for plane in [field::CHAIN, field::ADMIN_AUTH] {
        let Some(Value::Array(seq)) = auth.get_key(plane).cloned() else {
            continue;
        };
        let mut names: Vec<Value> = Vec::new();
        for entry in seq {
            match entry {
                Value::Text(s) => names.push(Value::from(s)),
                Value::Map(m) => {
                    let Some((module, body)) = m
                        .first()
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
        auth.insert_key(plane, Value::Array(names));
    }

    if let Some(Value::Map(methods)) = take(&mut auth, field::METHODS) {
        for (k, v) in methods {
            let Some(module) = k.as_str().map(str::to_string) else {
                continue;
            };
            let mut body = as_map(v);
            let browser_login = take(&mut body, field::BROWSER_LOGIN);

            let mut settings = Pairs::new();
            settings.insert_key(field::SETTINGS, Value::Map(body));
            let name = lift(
                &module,
                &settings,
                field::METHODS,
                &mut defs,
                &mut by_module,
                changes,
                todos,
            );
            if let Some(Value::Map(def)) = defs.get_key_mut(name.as_str()) {
                if let Some(bl) = browser_login {
                    def.insert_key(field::BROWSER_LOGIN, bl);
                }

                if let Some(Value::Map(from)) = settings.get_key(field::SETTINGS).cloned() {
                    let mut merged = match def.get_key(field::SETTINGS).cloned() {
                        Some(Value::Map(m)) => m,
                        _ => Pairs::new(),
                    };
                    for (sk, sv) in from {
                        merged.insert_key(sk, sv);
                    }
                    if !merged.is_empty() {
                        def.insert_key(field::SETTINGS, Value::Map(merged));
                    }
                }
            }
            changes.push(format!(
                "auth.methods.{module} -> identity-providers.{name} (browser_login + settings are \
                 PER-PROVIDER in 1.5.3; the parallel methods map is gone)"
            ));
        }
    }

    root.insert_key(field::AUTH, Value::Map(auth));
    if !defs.is_empty() {
        root.insert_key(Kind::Auth.root(), Value::Map(defs));
    }
}

/// `a == b` over two optional settings trees, as 1.5.5 compared them: mapping key order aside.
fn same_settings(a: Option<&Value>, b: Option<&Value>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => yaml::same_tree(a, b),
        (a, b) => a.is_none() && b.is_none(),
    }
}

#[cfg(test)]
mod hook_migration_tests {
    use super::*;
    use busbar_kernel::config::{HookDefCfg, HookStage};

    #[test]
    fn legacy_hook_conversion_preserves_the_selected_stages() {
        for (input, expected) in [
            (
                "{kind: tap, module: observer, at: request, phase: [response]}",
                vec![HookStage::Response],
            ),
            (
                "{kind: tap, module: observer, at: response, phase: []}",
                vec![HookStage::Response],
            ),
            (
                "{kind: tap, module: observer, at: response}",
                vec![HookStage::Response],
            ),
            ("{kind: tap, module: observer}", vec![HookStage::Request]),
        ] {
            let entry: Value = yaml::from_str(input).unwrap();
            let mut todos = Vec::new();
            let value = hook_entry_to_def("observer", &entry, &mut todos);
            assert!(todos.is_empty(), "{todos:?}");
            let definition: HookDefCfg = yaml::from_value(value).unwrap();
            assert_eq!(definition.phase, expected, "{input}");
        }
    }

    #[test]
    fn named_hook_migration_is_idempotent_and_keeps_a_single_stage() {
        let mut root: Mapping = yaml::mapping_from_str(
            "hooks: {observer: {kind: tap, plugin: observer, at: response}}",
        )
        .unwrap();
        let mut changes = Vec::new();
        migrate_hook_def_keys(&mut root, &mut changes);
        assert_eq!(changes.len(), 2);
        let converted = root.clone();
        changes.clear();
        migrate_hook_def_keys(&mut root, &mut changes);
        assert!(changes.is_empty());
        assert_eq!(root, converted);
        let definition: HookDefCfg =
            yaml::from_value(Value::from(root.clone()).at("hooks").at("observer").clone()).unwrap();
        assert_eq!(definition.module, "observer");
        assert_eq!(definition.phase, vec![HookStage::Response]);
    }
}

#[cfg(test)]
mod identity_provider_migration_tests {
    use super::*;

    #[test]
    fn current_named_provider_and_bindings_require_no_decision() {
        let mut root: Mapping = yaml::mapping_from_str(
            "identity-providers: {rig: {module: oidc, settings: {issuer: https://issuer.example}, max_admin_scope: full}}
auth: {chain: [keys], admin_auth: [rig], role_bindings: {rig: {reader: {admin_scope: read-only}, writer: {verbs: [get_keys, post_keys]}}}}",
        ).unwrap();
        let original = root.clone();
        let (mut changes, mut todos) = (Vec::new(), Vec::new());
        migrate_identity_providers(&mut root, &mut changes, &mut todos);
        assert_eq!(root, original);
        assert!(changes.is_empty(), "{changes:?}");
        assert!(todos.is_empty(), "{todos:?}");
    }

    #[test]
    fn unambiguous_inline_provider_lift_preserves_exact_bindings_without_debt() {
        let mut root: Mapping = yaml::mapping_from_str(
            "auth: {chain: [keys], admin_auth: [{oidc: {settings: {issuer: https://issuer.example}, max_admin_scope: full}}], role_bindings: {oidc: {reader: {admin_scope: read-only}, writer: {verbs: [get_keys, post_keys]}}}}",
        ).unwrap();
        let bindings = root.get_key("auth").unwrap().at("role_bindings").clone();
        let (mut changes, mut todos) = (Vec::new(), Vec::new());
        migrate_identity_providers(&mut root, &mut changes, &mut todos);
        assert!(todos.is_empty(), "{todos:?}");
        assert!(!changes.is_empty());
        let expected: Mapping = yaml::mapping_from_str(
            "identity-providers: {oidc: {module: oidc, settings: {issuer: https://issuer.example}, max_admin_scope: full}}
auth: {chain: [keys], admin_auth: [oidc], role_bindings: {oidc: {reader: {admin_scope: read-only}, writer: {verbs: [get_keys, post_keys]}}}}",
        ).unwrap();
        assert_eq!(root, expected);
        assert_eq!(root.get_key("auth").unwrap().at("role_bindings"), &bindings);
    }

    #[test]
    fn conflicting_inline_providers_preserve_both_definitions_and_require_a_decision() {
        let mut root: Mapping = yaml::mapping_from_str(
            "auth: {chain: [{oidc: {settings: {issuer: https://data.example}}}], admin_auth: [{oidc: {settings: {issuer: https://admin.example}}}], role_bindings: {oidc: {reader: {admin_scope: read-only}}}}",
        ).unwrap();
        let bindings = root.get_key("auth").unwrap().at("role_bindings").clone();
        let (mut changes, mut todos) = (Vec::new(), Vec::new());
        migrate_identity_providers(&mut root, &mut changes, &mut todos);
        assert_eq!(todos.len(), 1, "{todos:?}");
        assert!(todos[0].contains("DIFFERENT `settings:`"), "{todos:?}");
        let chain = root
            .get_key("auth")
            .unwrap()
            .at("chain")
            .at(0usize)
            .as_str()
            .unwrap();
        let admin = root
            .get_key("auth")
            .unwrap()
            .at("admin_auth")
            .at(0usize)
            .as_str()
            .unwrap();
        assert_ne!(chain, admin);
        assert_eq!(
            root.get_key("identity-providers")
                .unwrap()
                .at(chain)
                .at("settings")
                .at("issuer")
                .as_str(),
            Some("https://data.example")
        );
        assert_eq!(
            root.get_key("identity-providers")
                .unwrap()
                .at(admin)
                .at("settings")
                .at("issuer")
                .as_str(),
            Some("https://admin.example")
        );
        assert_eq!(root.get_key("auth").unwrap().at("role_bindings"), &bindings);
    }
}

#[cfg(test)]
mod decision_path_tests {
    use super::*;

    #[test]
    fn decision_paths_name_each_decision_once_without_its_reason() {
        let output = MigrateOutput {
            yaml: String::new(),
            changes: Vec::new(),
            todos: vec![
                "export.hook.settings: current settings were refused (Bearer secret-ish)".into(),
                "export.trace.settings: current settings were refused".into(),
                "export.hook.settings: a second reason".into(),
                "a decision without a path prefix".into(),
            ],
            warnings: Vec::new(),
            notices: Vec::new(),
        };
        assert_eq!(
            output.decision_paths(),
            vec![
                "export.hook.settings",
                "export.trace.settings",
                UNNAMED_DECISION
            ],
        );
        assert!(output
            .decision_paths()
            .iter()
            .all(|path| !path.contains("Bearer") && !path.contains("prefix")));
    }
}

#[cfg(test)]
mod missing_signing_key_hint_tests {
    use super::*;

    #[test]
    fn the_hint_says_file_and_env_need_an_admitted_secret_plugin() {
        assert_eq!(
            MISSING_SIGNING_KEY,
            "auth.signing_key: required now that the chain uses `keys` (busbar no longer \
             auto-generates one); run `busbar --generate-signing-key` and set \
             auth.signing_key to a secret reference for it. {file: /path} and {env: VAR} \
             are not built in: each needs an installed, admitted secret plugin that \
             declares it (busbar-secret-file for file, busbar-secret-env for env), \
             otherwise boot refuses; the key must be shared across a fleet"
        );
    }
}
