// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use busbar_kernel::diagnostics::{
    diag_debug, diag_error, diag_warn, ADMIN_STORE_OPERATION_FAILED, ADMIN_STORE_TASK_JOIN_FAILED,
    GROUP_DELETE_KEY_READ_FAILED, PLUGINS_DIR_FINGERPRINT_FAILED,
    PLUGIN_CATALOG_BLOCKING_TASK_FAILED, PLUGIN_CATALOG_SCAN_GATE_TIMEOUT,
    USAGE_BLOCKING_TASK_JOIN_FAILED,
};
use busbar_kernel::state::App;

use crate::v1::contract::{
    AdminAuthView, AdminError, AuthView, BuildInfo, ClassUsage, ConfigValidateView,
    EffectiveConfigView, GroupView, HookHealthView, HookTransportView, HookView, InfoView,
    KeyUsageView, ModelUsageView, ModelView, NamedDefView, Page, PluginView, PoolDetailView,
    PoolMemberStatusView, PoolMemberView, PoolView, ProviderView, TopologyInfo, UsageBreakdown,
    UsageView, UsageWindow,
};
use busbar_kernel::config::named_map::NamedMapSection;
use busbar_kernel::config::{
    DeployCfg, HookCfg, HookKind, HookStage, PromptAccess, ProviderDef, UserAccess,
};

pub(crate) fn settings_keys(settings: &serde_json::Map<String, serde_json::Value>) -> Vec<String> {
    let mut keys: Vec<String> = settings.keys().cloned().collect();
    keys.sort();
    keys
}

pub(crate) fn redact_settings_bags(v: &mut serde_json::Value) {
    redact_settings_bags_with(v, &busbar_kernel::config::settings_public::public);
}

pub(crate) fn redact_settings_bags_with(
    v: &mut serde_json::Value,
    public: &dyn Fn(&str) -> std::collections::BTreeSet<String>,
) {
    match v {
        serde_json::Value::Object(map) => {
            if let Some(bag) = map.remove("settings") {
                let module = map
                    .get("module")
                    .and_then(serde_json::Value::as_str)
                    .map(public)
                    .unwrap_or_default();
                let (keys, shown) = match bag {
                    serde_json::Value::Object(o) => (
                        settings_keys(&o),
                        busbar_contract::settings_public::public_view(&o, &module),
                    ),
                    _ => (Vec::new(), serde_json::Map::new()),
                };
                map.insert(
                    "settings_keys".to_string(),
                    serde_json::Value::Array(
                        keys.into_iter().map(serde_json::Value::String).collect(),
                    ),
                );
                if !shown.is_empty() {
                    map.insert(
                        "settings_public".to_string(),
                        serde_json::Value::Object(shown),
                    );
                }
            }
            for (key, child) in map.iter_mut() {
                if key != "settings_public" {
                    redact_settings_bags_with(child, public);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                redact_settings_bags_with(item, public);
            }
        }
        _ => {}
    }
}

use super::named_def_views::{export_def_view, identity_provider_view, unparseable_def_view};

pub fn derive_spend_micros_row(
    cost: &busbar_kernel::cost::CostModel,
    model: &str,
    b: &UsageBreakdown,
) -> Result<i64, busbar_kernel::cost::MoneyError> {
    metered_row(cost, model, b, &std::collections::BTreeMap::new())
        .spend_micros_at_card(cost.card())
}

pub fn derive_spend_micros_row_classes(
    cost: &busbar_kernel::cost::CostModel,
    model: &str,
    b: &UsageBreakdown,
    classes: &std::collections::BTreeMap<String, u64>,
) -> Result<i64, busbar_kernel::cost::MoneyError> {
    metered_row(cost, model, b, classes).spend_micros_at_card(cost.card())
}

fn metered_row<'a>(
    cost: &'a busbar_kernel::cost::CostModel,
    model: &'a str,
    b: &UsageBreakdown,
    classes: &'a std::collections::BTreeMap<String, u64>,
) -> busbar_kernel::cost::MeteredRow<'a> {
    busbar_kernel::cost::MeteredRow::new(
        cost.resolve_model_alias(model),
        row_counts(b)
            .map(|(class, quantity)| (class.to_string(), quantity))
            .collect(),
        b.requests,
        classes,
    )
}

pub(crate) fn row_carries_classes(provider: &str) -> bool {
    matches!(
        busbar_kernel::plane_driver::registry::plane_decl_for(provider),
        Some(decl) if !decl.fallback
    )
}

pub fn row_lane<'a>(model: &'a str, provider: &str) -> std::borrow::Cow<'a, str> {
    busbar_kernel::governance::metering_lane(model, provider)
}

pub fn fold_adjustments(
    rows: &mut [busbar_kernel::governance::MeteringRow],
    adjustments: &[busbar_kernel::governance::UsageAdjustment],
) -> Result<(), String> {
    fn column<'r>(row: &'r mut busbar_kernel::governance::MeteringRow, class: &str) -> &'r mut u64 {
        match class {
            busbar_contract::records::UNIT_INPUT => &mut row.tokens_input,
            busbar_contract::records::UNIT_OUTPUT => &mut row.tokens_output,
            busbar_contract::records::UNIT_CACHE_READ => &mut row.tokens_cache_read,
            busbar_contract::records::UNIT_CACHE_WRITE => &mut row.tokens_cache_write,
            other => row.usage_units.entry(other.to_string()).or_insert(0),
        }
    }
    for adj in adjustments {
        let slot: Vec<usize> = (0..rows.len())
            .filter(|&i| {
                let r = &rows[i];
                let same_entry = match (
                    adj.entry_id,
                    busbar_kernel::cost::EntryId::parse_metering_version(&r.pricing_version),
                ) {
                    (Some(expected), Some(Some(actual))) => expected == actual,
                    (None, None) => true,
                    _ => false,
                };
                r.key_id == adj.key_id
                    && r.priced_from_ms == adj.era
                    && same_entry
                    && row_lane(&r.model, &r.provider) == adj.lane.as_str()
            })
            .collect();
        let Some(&first) = slot.first() else {
            return Err(format!(
                "an adjustment of key {} lane {:?} era {} has no metering row",
                adj.key_id, adj.lane, adj.era
            ));
        };
        for (class, d) in &adj.delta {
            let magnitude = u64::try_from(d.unsigned_abs())
                .map_err(|_| format!("an adjustment of {class} leaves the range"))?;
            if *d >= 0 {
                let c = column(&mut rows[first], class);
                *c = c
                    .checked_add(magnitude)
                    .ok_or_else(|| format!("an adjustment of {class} leaves the range"))?;
                continue;
            }
            let mut owed = magnitude;
            for &i in &slot {
                let c = column(&mut rows[i], class);
                let take = owed.min(*c);
                *c -= take;
                owed -= take;
            }
            if owed != 0 {
                return Err(format!(
                    "an adjustment of {class} on key {} takes the count below zero",
                    adj.key_id
                ));
            }
        }
        for &i in &slot {
            rows[i].usage_units.retain(|_, n| *n != 0);
        }
    }
    Ok(())
}

pub(crate) fn usage_refusal(
    operation: &'static str,
    e: &busbar_kernel::cost::MoneyError,
) -> AdminError {
    use busbar_kernel::cost::MoneyError;
    diag_error!(ADMIN_STORE_OPERATION_FAILED, operation, error = %e, "admin store operation failed");
    match e {
        MoneyError::ClassUnpriced { lane, class, .. } => AdminError::UnpricedClass {
            lane: lane.clone(),
            class: Some(class.clone()),
        },
        MoneyError::LaneUnpriced { lane, .. } => AdminError::UnpricedClass {
            lane: lane.clone(),
            class: None,
        },
        MoneyError::NoCardInForce { .. } | MoneyError::Overflow => AdminError::Internal,
    }
}

fn dated_rate_history() -> Option<Arc<busbar_kernel::cost::History>> {
    busbar_kernel::rate_apply::dated_history()
}

pub fn row_priced_at_ms(bucket_start_secs: u64, priced_from_ms: u64) -> u64 {
    bucket_start_secs.saturating_mul(1_000).max(priced_from_ms)
}

fn row_card<'a>(
    view: &'a busbar_kernel::cost::HistoryView<'_>,
    row: &busbar_contract::records::MeteringRow,
    wall_at: u64,
) -> Result<
    (
        busbar_kernel::cost::EntryKey,
        &'a busbar_kernel::cost::RateCard,
    ),
    busbar_kernel::cost::MoneyError,
> {
    use busbar_kernel::cost::{EntryId, MoneyError, RawRateEra};
    let era = match EntryId::parse_metering_version(&row.pricing_version) {
        Some(Some(id)) => RawRateEra::entry(row.priced_from_ms, id),
        Some(None) => return Err(MoneyError::NoCardInForce { at: wall_at }),
        None => RawRateEra::legacy(row.priced_from_ms),
    };
    view.card_for_raw_era(era, wall_at)
        .ok_or(MoneyError::NoCardInForce { at: wall_at })
}

fn row_counts(b: &UsageBreakdown) -> impl Iterator<Item = (&'static str, u64)> + '_ {
    [
        (busbar_contract::records::UNIT_INPUT, b.tokens_input),
        (busbar_contract::records::UNIT_OUTPUT, b.tokens_output),
        (
            busbar_contract::records::UNIT_CACHE_READ,
            b.tokens_cache_read,
        ),
        (
            busbar_contract::records::UNIT_CACHE_WRITE,
            b.tokens_cache_creation,
        ),
    ]
    .into_iter()
    .filter(|(_, quantity)| *quantity != 0)
}

pub fn derive_spend_micros_row_at_card(
    view: &busbar_kernel::cost::HistoryView<'_>,
    arrived_ms: u64,
    _card: &busbar_kernel::cost::RateCard,
    cost: &busbar_kernel::cost::CostModel,
    model: &str,
    b: &UsageBreakdown,
) -> Result<i64, busbar_kernel::cost::MoneyError> {
    metered_row(cost, model, b, &std::collections::BTreeMap::new())
        .spend_micros_in_view(arrived_ms, view)
}

pub fn derive_spend_micros_row_classes_at_card(
    view: &busbar_kernel::cost::HistoryView<'_>,
    arrived_ms: u64,
    _card: &busbar_kernel::cost::RateCard,
    cost: &busbar_kernel::cost::CostModel,
    model: &str,
    b: &UsageBreakdown,
    classes: &std::collections::BTreeMap<String, u64>,
) -> Result<i64, busbar_kernel::cost::MoneyError> {
    metered_row(cost, model, b, classes).spend_micros_in_view(arrived_ms, view)
}

pub fn derive_spend_micros_row_classes_at_entry(
    seq: busbar_kernel::cost::EntryKey,
    card: &busbar_kernel::cost::RateCard,
    cost: &busbar_kernel::cost::CostModel,
    model: &str,
    b: &UsageBreakdown,
    classes: &std::collections::BTreeMap<String, u64>,
) -> Result<i64, busbar_kernel::cost::MoneyError> {
    metered_row(cost, model, b, classes).spend_micros_at_card_seq(seq, card)
}

#[cfg(any(test, feature = "test-support"))]
pub mod read_path_money {
    pub use super::{
        derive_spend_micros_row, derive_spend_micros_row_at_card, derive_spend_micros_row_classes,
        derive_spend_micros_row_classes_at_card, derive_spend_micros_row_classes_at_entry,
        row_lane, row_priced_at_ms,
    };

    pub use crate::v1::contract::UsageBreakdown;
}

static PROCESS_START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

static PROCESS_START_EPOCH: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

pub fn mark_start() {
    let _ = PROCESS_START.set(std::time::Instant::now());
    let _ = PROCESS_START_EPOCH.set(busbar_kernel::store::now());
}

struct CatalogCacheEntry {
    key: u64,
    rows: Vec<PluginView>,

    misses: u64,

    inserted_at: u64,
}

const CATALOG_CACHE_TTL_SECS: u64 = 120;

static CATALOG_CACHE: OnceLock<Mutex<HashMap<PathBuf, CatalogCacheEntry>>> = OnceLock::new();

fn prune_catalog_cache(cache: &mut HashMap<PathBuf, CatalogCacheEntry>, now: u64) {
    cache.retain(|_, entry| {
        entry.inserted_at <= now && now.saturating_sub(entry.inserted_at) < CATALOG_CACHE_TTL_SECS
    });
}

fn catalog_cache() -> &'static Mutex<HashMap<PathBuf, CatalogCacheEntry>> {
    CATALOG_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

static CATALOG_SCAN_GATE: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

const CATALOG_SCAN_GATE_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

fn plugins_dir_fingerprint(dir: &Path) -> std::io::Result<u64> {
    let mut entries: Vec<(std::ffi::OsString, u64, u128)> = Vec::new();
    match std::fs::read_dir(dir) {
        Ok(rd) => {
            for entry in rd {
                let entry = entry?;
                let meta = entry.metadata()?;
                let mtime = meta
                    .modified()?
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0);
                entries.push((entry.file_name(), meta.len(), mtime));
            }
        }

        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    entries.sort();
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    entries.hash(&mut hasher);
    Ok(hasher.finish())
}

#[cfg(test)]
macro_rules! catalog_scan_test_hook {
    ($dir:expr) => {
        catalog_scan_test_hooks::maybe_delay_or_panic($dir)
    };
}
#[cfg(not(test))]
macro_rules! catalog_scan_test_hook {
    ($dir:expr) => {};
}

#[cfg(test)]
mod catalog_scan_test_hooks {
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::time::Duration;

    enum Armed {
        Delay(Duration),
        Panic,
    }
    static SLOT: Mutex<Option<(PathBuf, Armed)>> = Mutex::new(None);

    pub(super) fn maybe_delay_or_panic(dir: &std::path::Path) {
        let armed = SLOT.lock().unwrap();
        let Some((armed_dir, kind)) = armed.as_ref() else {
            return;
        };
        if armed_dir != dir {
            return;
        }
        match kind {
            Armed::Delay(d) => std::thread::sleep(*d),
            Armed::Panic => {
                drop(armed);
                panic!(
                    "catalog_scan_test_hooks: injected panic for {} (spawn_blocking join-error \
                     fallback proof)",
                    dir.display()
                );
            }
        }
    }

    #[must_use]
    pub(super) struct HookGuard;
    impl Drop for HookGuard {
        fn drop(&mut self) {
            *SLOT.lock().unwrap() = None;
        }
    }

    pub(super) fn set_delay(dir: std::path::PathBuf, d: Duration) -> HookGuard {
        *SLOT.lock().unwrap() = Some((dir, Armed::Delay(d)));
        HookGuard
    }

    pub(super) fn set_panic(dir: std::path::PathBuf) -> HookGuard {
        *SLOT.lock().unwrap() = Some((dir, Armed::Panic));
        HookGuard
    }
}

pub fn auth_modules_compiled_in() -> Vec<&'static str> {
    let mut modules = vec![busbar_kernel::config::KEYS_MODULE];
    modules.extend(busbar_kernel::preflight::inbound_auth_names(
        busbar_kernel::preflight::linked_auth_rows(),
    ));
    modules
}

pub(crate) fn hook_plugins_compiled_in() -> Vec<&'static str> {
    busbar_kernel::preflight::root_rows().hook_names.to_vec()
}

const MAX_PLUGIN_FILENAME_LEN: usize = 256;

fn validate_plugin_filename(app: &App, file: &str) -> Result<String, AdminError> {
    validate_plugin_filename_with(file, |file| {
        app.plugin_admission
            .is_some_and(|admission| admission.is_tarball(file))
    })
}

fn validate_plugin_filename_with(
    file: &str,
    is_tarball: impl FnOnce(&str) -> bool,
) -> Result<String, AdminError> {
    if file.is_empty() || file.len() > MAX_PLUGIN_FILENAME_LEN {
        return Err(AdminError::Validation(format!(
            "plugin filename must be 1..={MAX_PLUGIN_FILENAME_LEN} chars"
        )));
    }

    if file.contains('/') || file.contains('\\') || file.contains("..") {
        return Err(AdminError::Validation(
            "plugin filename must be a bare filename (no path separators or `..`)".into(),
        ));
    }

    let path = std::path::Path::new(file);
    let mut comps = path.components();
    match (comps.next(), comps.next()) {
        (Some(std::path::Component::Normal(c)), None) if c == std::ffi::OsStr::new(file) => {}
        _ => {
            return Err(AdminError::Validation(
                "plugin filename must be a single, normal path component".into(),
            ));
        }
    }
    if !is_tarball(file) {
        return Err(AdminError::Validation(
            "plugin filename must be a `.tar.gz` (or `.tgz`) signed plugin tarball".into(),
        ));
    }
    Ok(file.to_string())
}

async fn probe_transport(
    cfg: &HookCfg,
    env: &busbar_kernel::hooks::HookEnv,
) -> (Option<bool>, Option<String>) {
    match env.registry.resolve(&cfg.plugin) {
        Some(p) if p.kind == "hook" => (Some(true), None),
        Some(p) => (
            Some(false),
            Some(format!(
                "plugin '{}' resolves to kind '{}', not 'hook'",
                cfg.plugin, p.kind
            )),
        ),
        None => (
            Some(false),
            Some(match env.registry.unresolved_reason(&cfg.plugin) {
                Some(sk) => format!(
                    "plugin '{}' present but not loaded: {}",
                    cfg.plugin, sk.reason
                ),
                None => format!("plugin '{}' is not installed", cfg.plugin),
            }),
        ),
    }
}

pub(crate) const MAX_SETTINGS_BYTES: usize = 64 * 1024;
pub(crate) const MAX_SETTINGS_KEYS: usize = 256;

pub(crate) const MAX_HOOK_NAME_LEN: usize = 256;

pub(crate) use busbar_kernel::governance::group_provision::build_with_group;

#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use busbar_kernel::governance::group_provision::MAX_GROUP_NAME_LEN;

pub(crate) fn validate_hook_settings_size(
    settings: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), AdminError> {
    if settings.len() > MAX_SETTINGS_KEYS {
        return Err(AdminError::Validation(format!(
            "settings has too many keys ({}, max {MAX_SETTINGS_KEYS})",
            settings.len()
        )));
    }
    if let Ok(bytes) = serde_json::to_vec(settings) {
        if bytes.len() > MAX_SETTINGS_BYTES {
            return Err(AdminError::Validation(format!(
                "settings too large ({} bytes, max {MAX_SETTINGS_BYTES})",
                bytes.len()
            )));
        }
    }
    Ok(())
}

fn lane_model(
    view: &dyn busbar_kernel::plane_driver::route_tables::EngineTablesView,
    idx: usize,
) -> String {
    view.lane_view(idx)
        .map(|l| l.model.to_string())
        .unwrap_or_default()
}

pub fn build_with_hook(current: &App, name: &str, cfg: HookCfg) -> Result<App, AdminError> {
    if name.trim().is_empty() {
        return Err(AdminError::Validation("hook name must not be empty".into()));
    }

    if name.len() > MAX_HOOK_NAME_LEN {
        return Err(AdminError::Validation(format!(
            "hook name is {} chars; must be <= {MAX_HOOK_NAME_LEN}",
            name.len()
        )));
    }

    if busbar_kernel::config::is_reserved_hook_name(name) {
        return Err(AdminError::Validation(format!(
            "hook name `{name}` is reserved (a built-in ranking strategy, auth module, or on_error \
             terminal); pick another name"
        )));
    }

    validate_hook_settings_size(&cfg.settings)?;
    busbar_kernel::config_validate::validate_hook_timeout(name, cfg.timeout_ms)
        .map_err(AdminError::Validation)?;

    if cfg.plugin.trim().is_empty() {
        return Err(AdminError::Validation(
            "a hook must name a `kind: hook` plugin via `module:`".into(),
        ));
    }

    if cfg.kind == HookKind::Tap && cfg.prompt == PromptAccess::Rw {
        return Err(AdminError::Validation(
            "`prompt: rw` is invalid on a `kind: tap` hook (a tap cannot rewrite)".into(),
        ));
    }

    if let Some(existing) = current.hook_registry.get(name) {
        if existing.kind != cfg.kind || existing.prompt != cfg.prompt || existing.user != cfg.user {
            return Err(AdminError::Conflict(format!(
                "hook `{name}` already exists with different kind/prompt/user grants; grants are \
                 immutable — delete and re-register to change them"
            )));
        }
    }

    let mut next = current.clone();
    next.config_version = current.config_version.wrapping_add(1);
    let is_global = cfg.global;
    next.hook_registry.insert(name.to_string(), cfg);
    if is_global {
        if !next.global_hooks.iter().any(|n| n == name) {
            next.global_hooks.push(name.to_string());
        }
    } else {
        next.global_hooks.retain(|n| n != name);
    }
    stage_hook_routes(&mut next)?;

    if let Err(e) = next.hook_env.preopen_gate_hooks(&next.hook_registry) {
        return Err(AdminError::Validation(e));
    }

    rebuild_hook_derived(&mut next);
    next.root_rules
        .check_built(&next)
        .map_err(AdminError::Validation)?;
    Ok(next)
}

fn stage_hook_routes(next: &mut App) -> Result<(), AdminError> {
    let mut env = next.hook_env.clone();
    let declarations = env
        .route_decls(&next.hook_registry)
        .map_err(AdminError::Validation)?;
    let routes = next
        .plugin_routes
        .with_hook_routes(declarations)
        .map_err(AdminError::Validation)?;
    next.hook_env = env;
    next.plugin_routes = std::sync::Arc::new(routes);
    Ok(())
}

pub fn build_without_hook(current: &App, name: &str) -> Result<App, AdminError> {
    if !current.hook_registry.contains_key(name) {
        return Err(AdminError::not_found(format!("hook `{name}`")));
    }
    let mut next = current.clone();
    next.config_version = current.config_version.wrapping_add(1);
    next.hook_registry.remove(name);
    next.global_hooks.retain(|n| n != name);
    stage_hook_routes(&mut next)?;
    rebuild_hook_derived(&mut next);
    next.root_rules
        .check_built(&next)
        .map_err(AdminError::Validation)?;
    Ok(next)
}

pub(crate) fn count_keys_bound_to(app: &App, group: &str) -> Result<usize, AdminError> {
    let Some(gov) = &app.governance else {
        return Ok(0);
    };

    Ok(gov
        .all_keys()
        .map_err(|e| {
            diag_error!(GROUP_DELETE_KEY_READ_FAILED, group = %group, error = %e, "group delete: cannot read keys to check bindings");
            AdminError::Internal
        })?
        .into_iter()
        .filter(|k| k.group.as_deref() == Some(group))
        .count())
}

pub(crate) fn build_without_group(
    current: &App,
    name: &str,
    bound_keys: usize,
) -> Result<App, AdminError> {
    if !current.groups_registry.contains_key(name) {
        return Err(AdminError::not_found(format!("group `{name}`")));
    }

    if bound_keys > 0 {
        return Err(AdminError::Conflict(format!(
            "cannot delete group `{name}`: {bound_keys} key(s) are still bound to it; rebind those \
             keys to another group (PATCH /api/v1/admin/keys/{{id}} with `group`) or delete them \
             first"
        )));
    }
    let mut groups = current.groups_registry.clone();
    groups.remove(name);

    let mut errors = Vec::new();
    busbar_kernel::config::groups::validate_groups(
        &groups,
        &|p| busbar_kernel::governance::group_provision::pool_known(current, p),
        &mut errors,
    );
    if !errors.is_empty() {
        return Err(AdminError::Conflict(format!(
            "cannot delete group `{name}`: {} (re-parent or remove the referencing group first)",
            errors.join("; ")
        )));
    }
    let mut next = current.clone();
    next.config_version = current.config_version.wrapping_add(1);
    next.cost = std::sync::Arc::new(next.cost.with_groups(&groups));
    next.groups_registry = groups;
    Ok(next)
}

fn validate_hook_registry(
    registry: &std::collections::HashMap<String, HookCfg>,
    global_hooks: &[String],
) -> Result<(), AdminError> {
    for (name, cfg) in registry {
        if cfg.plugin.trim().is_empty() {
            return Err(AdminError::Validation(format!(
                "hook `{name}` must name a `kind: hook` plugin via `module:`"
            )));
        }
        if cfg.kind == HookKind::Tap && cfg.prompt == PromptAccess::Rw {
            return Err(AdminError::Validation(format!(
                "hook `{name}` sets `prompt: rw` on a `kind: tap` (a tap cannot rewrite)"
            )));
        }
    }
    let defaults: Vec<&str> = registry
        .iter()
        .filter(|(_, h)| h.default)
        .map(|(n, _)| n.as_str())
        .collect();
    if defaults.len() > 1 {
        return Err(AdminError::Validation(format!(
            "snapshot has more than one `default: true` hook: {}",
            defaults.join(", ")
        )));
    }
    for g in global_hooks {
        if !registry.contains_key(g) {
            return Err(AdminError::Validation(format!(
                "snapshot wires unknown global hook `{g}`"
            )));
        }
    }
    Ok(())
}

pub(crate) fn build_with_registry(
    current: &App,
    registry: std::collections::HashMap<String, HookCfg>,
    global_hooks: Vec<String>,
) -> Result<App, AdminError> {
    validate_hook_registry(&registry, &global_hooks)?;
    let mut next = current.clone();
    next.config_version = current.config_version.wrapping_add(1);
    next.hook_registry = registry;
    next.global_hooks = global_hooks;
    stage_hook_routes(&mut next)?;

    if let Err(e) = next.hook_env.preopen_gate_hooks(&next.hook_registry) {
        return Err(AdminError::Validation(e));
    }
    rebuild_hook_derived(&mut next);
    next.root_rules
        .check_built(&next)
        .map_err(AdminError::Validation)?;
    Ok(next)
}

const MAX_INSPECT_SCHEMA_JSON_BYTES: usize = 256 * 1024;

const MAX_INSPECT_SCHEMA_JSON_DEPTH: u32 = 64;

fn schema_json_within_bounds(text: &str) -> Result<(), String> {
    if text.len() > MAX_INSPECT_SCHEMA_JSON_BYTES {
        return Err(format!(
            "manifest settings_schema is {} bytes, exceeding the {}-byte cap",
            text.len(),
            MAX_INSPECT_SCHEMA_JSON_BYTES
        ));
    }
    let mut depth: u32 = 0;
    let mut in_string = false;
    let mut escape = false;
    for b in text.bytes() {
        if in_string {
            if escape {
                escape = false;
            } else if b == b'\\' {
                escape = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > MAX_INSPECT_SCHEMA_JSON_DEPTH {
                    return Err(format!(
                        "manifest settings_schema nests deeper than the {MAX_INSPECT_SCHEMA_JSON_DEPTH}-level cap"
                    ));
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    Ok(())
}

fn manifest_schema_url_and_error(
    name: &str,
    settings_schema: Option<&str>,
) -> (Option<String>, Option<String>) {
    let Some(s) = settings_schema else {
        return (None, None);
    };
    let url = Some(format!(
        "{}/plugins/{name}/schema",
        crate::v1::contract::ADMIN_PREFIX
    ));
    match serde_json::from_str::<serde_json::Value>(s) {
        Ok(_) => (url, None),
        Err(e) => (
            url,
            Some(format!("manifest settings_schema is not valid JSON: {e}")),
        ),
    }
}

fn check_inspect_tarball_size(size: usize, cap: u64) -> Result<(), AdminError> {
    if size as u64 > cap {
        return Err(AdminError::Validation(format!(
            "decoded tarball is {} bytes, exceeding the {cap}-byte cap",
            size
        )));
    }
    Ok(())
}

fn inspect_plugin_view(
    manifest: busbar_kernel::admission::Stated,
    judged: busbar_kernel::admission::Judged,
    restart_default: impl FnOnce(&str) -> bool,
) -> serde_json::Value {
    use busbar_kernel::admission::Judged;
    let trust = match judged {
        Judged::Trusted { .. } => "trusted",
        Judged::Allowed => "unverified",
        Judged::Rejected { .. } => "rejected",
    };

    let (schema, schema_error) = match manifest.settings_schema.as_deref() {
        None => (None, None),
        Some(s) => match schema_json_within_bounds(s) {
            Err(reason) => (None, Some(reason)),
            Ok(()) => match serde_json::from_str::<serde_json::Value>(s) {
                Ok(v) => (Some(v), None),
                Err(e) => (
                    None,
                    Some(format!("manifest settings_schema is not valid JSON: {e}")),
                ),
            },
        },
    };

    serde_json::json!({
        "name": manifest.name,
        "version": manifest.version,
        "kind": manifest.kind,
        "schema": schema,
        "schema_error": schema_error,
        "trust": trust,
        "source": "manifest",
        "restart_required_default": restart_default(&manifest.kind),
    })
}

fn plugin_inventory_view(row: busbar_kernel::admission::Inventoried) -> PluginView {
    let trust = if row.status == "ready" {
        if row.signature == "first-party" || row.signature.starts_with("publisher:") {
            Some("trusted")
        } else {
            Some("unverified")
        }
    } else if row.stated.is_some() {
        Some("rejected")
    } else {
        None
    };
    let name = row
        .stated
        .as_ref()
        .map(|m| m.name.clone())
        .unwrap_or_else(|| row.file.clone());

    let r#type = match row.stated.as_ref().map(|m| m.kind.as_str()) {
        Some("secret") => "secret",
        Some("auth") => "auth",
        Some("hook") => "hook",
        Some("export") => "export",
        Some("transport") => "transport",
        Some("plane") => "plane",
        _ => "store",
    };

    let (schema_url, schema_error) = match row.stated.as_ref() {
        Some(m) => manifest_schema_url_and_error(&name, m.settings_schema.as_deref()),
        None => (None, None),
    };
    PluginView {
        name,
        r#type,
        loader: "dynamic-library",
        active: None,
        target: Some(row.file.clone()),
        file: Some(row.file.clone()),
        has_schema: schema_url.is_some(),
        version: row.stated.as_ref().map(|m| m.version.clone()),
        publisher: row.stated.as_ref().map(|m| m.publisher.clone()),
        interface_version: row.stated.as_ref().map(|m| m.abi_version),
        trust,
        valid: Some(row.status == "ready"),
        error: (row.status != "ready").then(|| row.status.clone()),
        schema_url,
        schema_error,
    }
}

enum PluginQuery {
    Auth,
    Hooks,
    Store,
    Secret,
}

fn plugin_query(ptype: &str) -> Result<PluginQuery, AdminError> {
    match ptype {
        "auth" => Ok(PluginQuery::Auth),
        "hooks" => Ok(PluginQuery::Hooks),
        "store" | "db" => Ok(PluginQuery::Store),
        "secret" => Ok(PluginQuery::Secret),
        other => Err(AdminError::Validation(format!(
            "unknown plugin type `{other}`: expected `auth`, `hooks`, `secret`, or `store`"
        ))),
    }
}

fn catalog_rows_of_kind(
    rows: Vec<PluginView>,
    kind: &'static str,
) -> impl Iterator<Item = PluginView> {
    rows.into_iter().filter(move |row| row.r#type == kind)
}

pub(crate) struct AdminService {
    app: Arc<App>,

    rate_history: Option<Arc<busbar_kernel::cost::History>>,
}

#[path = "service_operations.rs"]
mod operations;

pub(crate) fn project_hook_view(name: &str, cfg: &HookCfg, global_hooks: &[String]) -> HookView {
    {
        let (transport_kind, target) = if cfg.plugin.trim().is_empty() {
            ("none", None)
        } else {
            ("plugin", Some(cfg.plugin.clone()))
        };
        HookView {
            name: name.to_string(),
            kind: match cfg.kind {
                HookKind::Tap => "tap",
                HookKind::Gate => "gate",
            },
            transport: HookTransportView {
                kind: transport_kind,
                target,
            },
            prompt: match cfg.prompt {
                PromptAccess::No => "no",
                PromptAccess::Ro => "ro",
                PromptAccess::Rw => "rw",
            },
            user: match cfg.user {
                UserAccess::No => "no",
                UserAccess::Ro => "ro",
            },
            priority: cfg.priority,

            at: cfg.at.map(HookStage::as_str),
            phase: cfg.phase.iter().copied().map(HookStage::as_str).collect(),
            fires_at: cfg
                .resolved_stages()
                .into_iter()
                .map(HookStage::as_str)
                .collect(),
            on_error: cfg.on_error.clone(),
            timeout_ms: cfg.timeout_ms,
            settings_keys: settings_keys(&cfg.settings),
            global: cfg.global || global_hooks.iter().any(|n| n == name),
            groups: cfg.groups.clone(),
        }
    }
}

fn rebuild_hook_derived(next: &mut busbar_kernel::state::App) {
    next.any_content_hook = busbar_kernel::hooks::any_content_hook(&next.hook_registry);

    next.requested_signals = busbar_kernel::hooks::requested_signals(&next.hook_registry);

    next.rewrite_hooks = busbar_kernel::hooks::resolve_rewrite_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.hook_env,
        next.config_version,
    );
    next.tap_hooks = busbar_kernel::hooks::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.hook_env,
        next.config_version,
        busbar_kernel::config::HookStage::Request,
    );
    next.tap_hooks_candidate = busbar_kernel::hooks::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.hook_env,
        next.config_version,
        busbar_kernel::config::HookStage::Candidate,
    );
    next.tap_hooks_routing = busbar_kernel::hooks::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.hook_env,
        next.config_version,
        busbar_kernel::config::HookStage::Routing,
    );
    next.tap_hooks_response = busbar_kernel::hooks::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.hook_env,
        next.config_version,
        busbar_kernel::config::HookStage::Response,
    );
    next.global_gates = busbar_kernel::hooks::resolve_gate_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.hook_env,
        next.config_version,
    );
    reresolve_plane_gates(next);
}

fn reresolve_plane_gates(next: &mut busbar_kernel::state::App) {
    for decl in busbar_kernel::plane_driver::registry::plane_decls() {
        if let Some(reresolve) = decl.reresolve_gates {
            reresolve(decl, next);
        }
    }
}

fn plane_named_def_list(
    section: NamedMapSection,
    app: &busbar_kernel::state::App,
) -> Vec<NamedDefView> {
    busbar_kernel::plane_driver::registry::plane_decl_for_config_section(section.key())
        .and_then(|d| d.named_def_list.map(|f| (d, f)))
        .map_or_else(Vec::new, |(d, f)| {
            f(
                d,
                app as &dyn busbar_kernel::plane_driver::slots::PlaneSlots,
            )
        })
}

fn plane_named_def_get(
    section: NamedMapSection,
    app: &busbar_kernel::state::App,
    name: &str,
) -> Option<NamedDefView> {
    busbar_kernel::plane_driver::registry::plane_decl_for_config_section(section.key())
        .and_then(|d| d.named_def_get.map(|f| (d, f)))
        .and_then(|(d, f)| {
            f(
                d,
                app as &dyn busbar_kernel::plane_driver::slots::PlaneSlots,
                name,
            )
        })
}

#[cfg(test)]
#[path = "tests/service_tests.rs"]
pub(crate) mod tests;
