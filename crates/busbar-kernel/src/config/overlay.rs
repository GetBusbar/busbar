// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

pub use super::overlay_store::OverlayStore;
use super::{
    ConfigMgmtCfg, DeployCfg, GroupCfg, HookCfg, OverlayCfg, RateEntryCfg, RootCfg, StoreCfg,
    TlsCfg,
};
use crate::diagnostics::{diag_error, CONFIG_OVERLAY_PATCH_UNPARSABLE};
use busbar_contract::plugin::Kind;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

pub const NO_WRITABLE_OVERLAY_MSG: &str = "config mutation refused: this busbar has no writable Store-backed config overlay; edit config.yaml and reload a locked deployment";

pub const DEFAULT_OVERLAY_FILENAME: &str = "busbar-overlay.json";
#[derive(Debug, Clone)]
pub struct OverlayResolution {
    pub locked: bool,
    pub enabled: bool,
}
#[cfg(test)]
pub fn resolve_backend(
    cfg: &ConfigMgmtCfg,
    config_path: &Path,
    probe_fs: bool,
) -> Result<OverlayResolution, String> {
    resolve_backend_with_env(cfg, config_path, None, probe_fs)
}
pub fn resolve_backend_with_env(
    cfg: &ConfigMgmtCfg,
    _config_path: &Path,
    env_override: Option<&Path>,
    _probe_fs: bool,
) -> Result<OverlayResolution, String> {
    if cfg.locked {
        return Ok(OverlayResolution {
            locked: true,
            enabled: false,
        });
    }
    match &cfg.overlay {
        Some(OverlayCfg::Disabled(_)) => return Err("mutable config requires its configured Store-backed overlay; set config.locked: true to disable runtime mutations".into()),
        Some(OverlayCfg::Backend(backend)) if backend.file.is_none() => return Err("config.overlay names no backend".into()),
        _ => {}
    }
    if env_override.is_some() || matches!(&cfg.overlay, Some(OverlayCfg::Backend(_))) {
        tracing::warn!("legacy config overlay file selector is deprecated and does not select a file; runtime config persists exclusively in the configured Store");
    }
    Ok(OverlayResolution {
        locked: false,
        enabled: true,
    })
}
pub const OVERLAY_VERSION: u32 = 1;
fn default_overlay_version() -> u32 {
    1
}
fn backend(value: Option<&OverlayStore>) -> Result<&OverlayStore, String> {
    value.ok_or_else(|| NO_WRITABLE_OVERLAY_MSG.to_string())
}
pub fn persist(
    store: Option<&OverlayStore>,
    hooks: &HashMap<String, HookCfg>,
    global_hooks: &[String],
    deleted_add: Option<&str>,
    deleted_remove: Option<&str>,
    base_hook_names: &HashSet<String>,
) -> Result<(), String> {
    backend(store)?.update(|doc| {
        if let Some(name) = deleted_add {
            if !doc.deleted.iter().any(|n| n == name) {
                doc.deleted.push(name.into());
            }
        }
        if let Some(name) = deleted_remove {
            doc.deleted.retain(|n| n != name);
        }
        doc.hooks = hooks.clone();
        doc.global_hooks = global_hooks.to_vec();
        doc.deleted
            .retain(|name| !hooks.contains_key(name) && base_hook_names.contains(name));
    })
}
pub fn persist_groups(
    store: Option<&OverlayStore>,
    groups: &BTreeMap<String, GroupCfg>,
    deleted_add: Option<&str>,
    deleted_remove: Option<&str>,
    base_group_names: &HashSet<String>,
) -> Result<(), String> {
    backend(store)?.update(|doc| {
        if let Some(name) = deleted_add {
            if !doc.deleted_groups.iter().any(|n| n == name) {
                doc.deleted_groups.push(name.into());
            }
        }
        if let Some(name) = deleted_remove {
            doc.deleted_groups.retain(|n| n != name);
        }
        doc.groups = groups.clone();
        doc.deleted_groups
            .retain(|name| !groups.contains_key(name) && base_group_names.contains(name));
    })
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsCfg>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_listen: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_tls: Option<TlsCfg>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_require_mtls: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_card: Option<BTreeMap<String, RateEntryCfg>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_request_fee: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store: Option<StoreCfg>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<crate::config::patch::SecurityPatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<crate::config::patch::LimitsPatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advanced: Option<crate::config::patch::AdvancedPatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<crate::config::patch::HealthPatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routing: Option<crate::config::patch::RoutingPatch>,
}

impl RootSettings {
    pub fn is_empty(&self) -> bool {
        let RootSettings {
            listen,
            tls,
            admin_listen,
            admin_tls,
            admin_require_mtls,
            rate_card,
            per_request_fee,
            store,
            security,
            limits,
            advanced,
            health,
            routing,
        } = self;
        listen.is_none()
            && tls.is_none()
            && admin_listen.is_none()
            && admin_tls.is_none()
            && admin_require_mtls.is_none()
            && rate_card.is_none()
            && per_request_fee.is_none()
            && store.is_none()
            && security.is_none()
            && limits.is_none()
            && advanced.is_none()
            && health.is_none()
            && routing.is_none()
    }

    pub fn apply_to_deploy(&self, deploy: &mut DeployCfg) {
        let RootSettings {
            listen,
            tls,
            admin_listen,
            admin_tls,
            admin_require_mtls,
            rate_card,
            per_request_fee,
            store,
            security,
            limits,
            advanced,
            health,
            routing,
        } = self;
        if let Some(v) = listen {
            deploy.listen = v.clone();
        }
        if tls.is_some() {
            deploy.tls = tls.clone();
        }
        if let Some(v) = admin_listen {
            deploy.admin_listen = v.clone();
        }
        if admin_tls.is_some() {
            deploy.admin_tls = admin_tls.clone();
        }
        if let Some(v) = admin_require_mtls {
            deploy.admin_require_mtls = *v;
        }
        if rate_card.is_some() {
            deploy.rate_card = rate_card.clone();
        }
        if let Some(v) = per_request_fee {
            deploy.per_request_fee = *v;
        }
        if store.is_some() {
            deploy.store = store.clone();
        }

        if let Some(v) = security {
            v.apply(deploy.security.get_or_insert_with(Default::default));
        }
        if let Some(v) = limits {
            v.apply(&mut deploy.limits);
        }
        if let Some(v) = advanced {
            v.apply(&mut deploy.advanced);
        }

        if let Some(v) = health {
            v.apply(&mut deploy.health);
        }
        if let Some(v) = routing {
            v.apply(&mut deploy.routing);
        }
    }
}
pub fn persist_root(store: Option<&OverlayStore>, settings: &RootSettings) -> Result<(), String> {
    backend(store)?.update(|doc| {
        doc.root = if settings.is_empty() {
            None
        } else {
            Some(settings.clone())
        }
    })
}
pub fn try_persist_plugin_versions(
    store: Option<&OverlayStore>,
    pins: &BTreeMap<String, String>,
) -> Result<(), String> {
    backend(store)?.update(|doc| doc.plugin_versions = pins.clone())
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlaySection {
    Hooks,
    Groups,
    /// The single-value config sections (`RootSettings`) — the 1.5.0 full-config coverage slice.
    Root,
    /// The per-plugin ROLLBACK version pins (1.5.0). Clearing it drops every explicit rollback pin,
    /// restoring the base-config `plugins.min_versions` floors — the plugins then upgrade back to their
    /// current artifacts on the next (re)load.
    PluginVersions,
    /// ONE named-DEFINITION map (`identity-providers:` / `export:`, and whatever
    /// [`NamedMapSection`](crate::config::named_map::NamedMapSection) gains next). Clearing it
    /// discards every API-applied definition in THAT map and reverts it to `config.yaml` truth,
    /// leaving the other maps alone — the same granularity the CRUD that writes them is served at.
    ///
    /// This variant did not exist until 1.5.4, and its absence was a shipped functional gap: the
    /// `named_maps` overlay section was durable and API-writable with no way to revert it, so
    /// `DELETE /api/v1/admin/overlay/identity-providers` answered `400 unknown overlay section`
    /// while the docs listed the section set as COMPLETE.
    NamedMap(crate::config::named_map::NamedMapSection),
}

impl OverlaySection {
    pub fn all() -> Vec<OverlaySection> {
        let mut out = vec![
            OverlaySection::Groups,
            OverlaySection::Hooks,
            OverlaySection::Root,
            OverlaySection::PluginVersions,
        ];
        out.extend(
            crate::config::named_map::NamedMapSection::sections()
                .into_iter()
                .map(OverlaySection::NamedMap),
        );
        out
    }

    pub fn parse(s: &str) -> Option<Self> {
        OverlaySection::all().into_iter().find(|v| v.as_str() == s)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            OverlaySection::Hooks => Kind::Hook.root(),
            OverlaySection::Groups => "groups",
            OverlaySection::Root => "root",
            OverlaySection::PluginVersions => "plugin_versions",
            OverlaySection::NamedMap(s) => s.key(),
        }
    }

    pub fn valid_names() -> String {
        OverlaySection::all()
            .iter()
            .map(|s| format!("`{}`", s.as_str()))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

pub fn clear_section(store: Option<&OverlayStore>, section: OverlaySection) -> Result<(), String> {
    backend(store)?.update(|doc| doc.clear_section(section))
}
/// The persisted overlay document: the API-applied hook registry + global-hook wiring, plus TOMBSTONES
/// (`deleted`) — hooks removed via the API that must be subtracted from base config at boot. Tombstones
/// are what let the additive `base + overlay` model express a DELETION (an additive merge alone cannot
/// remove a base-defined hook).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlayDoc {
    /// Overlay schema version (see `OVERLAY_VERSION`). Absent in a pre-versioning overlay -> `1`.
    #[serde(default = "default_overlay_version")]
    pub version: u32,
    #[serde(default)]
    pub hooks: HashMap<String, HookCfg>,
    #[serde(default)]
    pub global_hooks: Vec<String>,
    #[serde(default)]
    pub deleted: Vec<String>,
    /// API-applied `groups:` entries (the second section on the spine). An overlay group with a base
    /// group's name WINS at merge (last-applied definition), matching hook semantics.
    #[serde(default)]
    pub groups: BTreeMap<String, GroupCfg>,
    /// Group tombstones — groups deleted via the API, subtracted from base config at boot.
    #[serde(default)]
    pub deleted_groups: Vec<String>,
    /// The `root` section (1.5.0 full-config coverage): API-set single-value config overrides
    /// (`listen`/`tls`/`rate_card`/`store`/`security`/`limits`/…). `None` = no root override (base
    /// `config.yaml` stands). Applied at the `DeployCfg` level BEFORE `resolve` — see
    /// `RootSettings::apply_to_deploy`. No tombstones: a single-value field is present-or-absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<RootSettings>,
    /// The `plugin_versions` section (1.5.0 rollback-friendly versioning): per-plugin VERSION PINS an
    /// operator set via an EXPLICIT, authenticated, audited rollback (`POST
    /// /api/v1/admin/plugins/rollback`). Maps a plugin's manifest `name` -> the version the operator
    /// deliberately pinned it to. This is DISTINCT from `plugins.min_versions` (the base-config
    /// anti-downgrade FLOOR): a pin LOWERS the effective floor for THAT plugin to the pinned version so
    /// the prior artifact re-loads, and it does so ONLY because a human took an explicit, audited
    /// action — an automatic/silent replay of an old artifact never consults this map and still faces
    /// the full floor. See `PluginsCfg::to_policy_with_pins`. Empty (`{}`, the default) = no pins, the
    /// base floors stand unchanged. No tombstones: a pin is present-or-absent.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub plugin_versions: BTreeMap<String, String>,
    /// The `named_maps` section (1.5.3 universal named-DEFINITION pattern): API-applied entries of
    /// EVERY named map the generic admin CRUD serves, keyed `section key → entry name → the raw
    /// definition document` (`identity-providers`/`export` today; `tools`/`agents` in 1.6.0).
    ///
    /// The definition is stored RAW (`serde_json::Value`) ON PURPOSE. It is re-parsed into its typed,
    /// `deny_unknown_fields` config struct on every apply
    /// ([`crate::config::named_map::NamedMapSection::insert`]), which means (a) a new section needs no
    /// new overlay field and no `Serialize` derive on a config struct that is otherwise
    /// deserialize-only, and (b) the bytes a restart replays are byte-identical to the definition the
    /// operator PUT — the overlay cannot silently normalize a definition into a different one.
    ///
    /// NO TOMBSTONES, deliberately: the API refuses to write over a BASE-config-defined entry at all
    /// (409 `conflict`, edit config.yaml), so overlay names and base names are disjoint and a
    /// deletion is expressible as a plain removal from this map.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub named_maps: BTreeMap<String, BTreeMap<String, serde_json::Value>>,
}

impl Default for OverlayDoc {
    fn default() -> Self {
        Self {
            version: default_overlay_version(),
            hooks: HashMap::new(),
            global_hooks: Vec::new(),
            deleted: Vec::new(),
            groups: BTreeMap::new(),
            deleted_groups: Vec::new(),
            root: None,
            plugin_versions: BTreeMap::new(),
            named_maps: BTreeMap::new(),
        }
    }
}

impl OverlayDoc {
    pub fn clear_section(&mut self, section: OverlaySection) {
        let OverlayDoc {
            hooks,
            global_hooks,
            deleted,
            groups,
            deleted_groups,
            root,
            plugin_versions,
            named_maps,

            version: _,
        } = self;
        match section {
            OverlaySection::Hooks => {
                hooks.clear();
                global_hooks.clear();
                deleted.clear();
            }
            OverlaySection::Groups => {
                groups.clear();
                deleted_groups.clear();
            }
            OverlaySection::Root => {
                *root = None;
            }
            OverlaySection::PluginVersions => {
                plugin_versions.clear();
            }

            OverlaySection::NamedMap(s) => {
                named_maps.remove(s.key());
            }
        }
    }

    pub fn section_is_empty(&self, section: OverlaySection) -> bool {
        match section {
            OverlaySection::Hooks => {
                self.hooks.is_empty() && self.global_hooks.is_empty() && self.deleted.is_empty()
            }
            OverlaySection::Groups => self.groups.is_empty() && self.deleted_groups.is_empty(),
            OverlaySection::Root => self.root.as_ref().is_none_or(RootSettings::is_empty),
            OverlaySection::PluginVersions => self.plugin_versions.is_empty(),

            OverlaySection::NamedMap(s) => self
                .named_maps
                .get(s.key())
                .is_none_or(std::collections::BTreeMap::is_empty),
        }
    }
}

pub fn read(store: &OverlayStore) -> Option<OverlayDoc> {
    store.read_required().ok().flatten()
}
pub enum OverlayReadState {
    Absent,
    Loaded(Box<OverlayDoc>),
    Unreadable,
    VersionTooNew(u32),
}
pub fn read_state(store: &OverlayStore) -> OverlayReadState {
    match store.read_bytes() {
        Ok(bytes) => classify_bytes(bytes),
        Err(error) => {
            tracing::error!(%error, "config overlay Store read failed");
            OverlayReadState::Unreadable
        }
    }
}
pub(super) fn classify_bytes(bytes: Option<Vec<u8>>) -> OverlayReadState {
    let Some(bytes) = bytes else {
        return OverlayReadState::Absent;
    };
    let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return OverlayReadState::Unreadable;
    };
    if let Some(version) = value.get("version").and_then(serde_json::Value::as_u64) {
        if version > u64::from(OVERLAY_VERSION) {
            return OverlayReadState::VersionTooNew(u32::try_from(version).unwrap_or(u32::MAX));
        }
    }
    migrate_legacy_hook_keys(&mut value);
    match serde_json::from_value(value) {
        Ok(doc) => OverlayReadState::Loaded(Box::new(doc)),
        Err(_) => OverlayReadState::Unreadable,
    }
}
/// Rewrite the RETIRED hook-key spellings in a raw overlay document IN PLACE so a pre-1.6.0 overlay
/// still loads after the 1.6.0 clean slate removed the `plugin` alias and the single-stage `at:` key
/// from [`HookCfg`]:
///   * a hook entry's `plugin:` → `module:` (the one wire spelling), unless `module:` is already set;
///   * a hook entry's `at: <stage>` → `phase: [<stage>]` (stage-renamed via the shared
///     [`crate::config::RENAMED_HOOK_STAGES`] table, matching `--migrate-config`), unless a non-empty
///     `phase:` is already present, in which case `at:` is simply dropped (the list wins, exactly as
///     the old `fires_at_stage` precedence resolved it).
///
/// A no-op on an overlay already in the 1.6.0 spelling, so it is safe to run on every read. Only the
/// `hooks` section carries [`HookCfg`] entries; every other section is left untouched.
fn migrate_legacy_hook_keys(value: &mut serde_json::Value) {
    let Some(hooks) = value
        .get_mut(Kind::Hook.root())
        .and_then(serde_json::Value::as_object_mut)
    else {
        return;
    };
    for entry in hooks.values_mut() {
        let Some(obj) = entry.as_object_mut() else {
            continue;
        };

        if let Some(plugin) = obj.remove("plugin") {
            obj.entry("module".to_string()).or_insert(plugin);
        }

        if let Some(at) = obj.remove("at") {
            let phase_present = obj
                .get("phase")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|a| !a.is_empty());
            if !phase_present {
                if let Some(stage) = at.as_str() {
                    let renamed = crate::config::RENAMED_HOOK_STAGES
                        .iter()
                        .find(|(old, _)| *old == stage)
                        .map(|(_, new)| *new)
                        .unwrap_or(stage);
                    obj.insert(
                        "phase".to_string(),
                        serde_json::Value::Array(vec![serde_json::Value::String(
                            renamed.to_string(),
                        )]),
                    );
                }
            }
        }
    }
}

pub fn write(store: &OverlayStore, doc: &OverlayDoc) -> Result<(), String> {
    store.update(|current| *current = doc.clone())
}

#[cfg(test)]
pub fn from_state(hooks: &HashMap<String, HookCfg>, global_hooks: &[String]) -> OverlayDoc {
    OverlayDoc {
        hooks: hooks.clone(),
        global_hooks: global_hooks.to_vec(),
        deleted: Vec::new(),
        ..Default::default()
    }
}

pub fn apply_root_to_deploy(deploy: &mut DeployCfg, doc: &OverlayDoc) {
    if let Some(root) = &doc.root {
        root.apply_to_deploy(deploy);
    }
    apply_pre_resolve_sections(deploy, doc);
}

pub fn apply_plugin_versions_to_deploy(deploy: &mut DeployCfg, doc: &OverlayDoc) {
    for (name, pinned) in &doc.plugin_versions {
        deploy
            .plugins
            .min_versions
            .insert(name.clone(), pinned.clone());

        deploy
            .plugins
            .first_party_floors
            .insert(name.clone(), pinned.clone());
    }
}

pub fn apply_named_maps_to_deploy(deploy: &mut DeployCfg, doc: &OverlayDoc) {
    use crate::config::named_map::NamedMapSection;
    for section in NamedMapSection::sections() {
        let Some(entries) = doc.named_maps.get(section.key()) else {
            continue;
        };
        for (name, def) in entries {
            if let Err(e) = section.insert(deploy, name, def) {
                diag_error!(
                    CONFIG_OVERLAY_PATCH_UNPARSABLE,
                    section = section.key(), entry = %name, error = %e,
                    "config overlay holds a `{}` definition this binary cannot parse; it is NOT \
                     applied (edit or remove it, then reload)",
                    section.key()
                );
            }
        }
    }
}

/// One overlay named-map definition this binary cannot parse: the parse ERROR plus the RAW stored
/// document, so the admin read can project the operator's own `module`/`settings` keys back at them
/// instead of showing an anonymous hole.
#[derive(Debug, Clone)]
pub struct UnparseableNamedDef {
    pub error: String,
    pub raw: serde_json::Value,
}

pub fn unparseable_named_map_entries(
    store: Option<&OverlayStore>,
    section: crate::config::named_map::NamedMapSection,
) -> Result<BTreeMap<String, UnparseableNamedDef>, String> {
    let mut out = BTreeMap::new();
    let Some(doc) = store
        .map(OverlayStore::read_required)
        .transpose()?
        .flatten()
    else {
        return Ok(out);
    };
    let Some(entries) = doc.named_maps.get(section.key()) else {
        return Ok(out);
    };
    for (name, def) in entries {
        if let Err(error) = section.validate_def(name, def) {
            out.insert(
                name.clone(),
                UnparseableNamedDef {
                    error,
                    raw: def.clone(),
                },
            );
        }
    }
    Ok(out)
}
pub fn apply_pre_resolve_sections(deploy: &mut DeployCfg, doc: &OverlayDoc) {
    apply_plugin_versions_to_deploy(deploy, doc);
    apply_named_maps_to_deploy(deploy, doc);
}
pub fn persist_named_map(
    store: Option<&OverlayStore>,
    section: crate::config::named_map::NamedMapSection,
    name: &str,
    def: Option<&serde_json::Value>,
) -> Result<(), String> {
    backend(store)?.update(|doc| match def {
        Some(value) => {
            doc.named_maps
                .entry(section.key().into())
                .or_default()
                .insert(name.into(), value.clone());
        }
        None => {
            if let Some(entries) = doc.named_maps.get_mut(section.key()) {
                entries.remove(name);
                if entries.is_empty() {
                    doc.named_maps.remove(section.key());
                }
            }
        }
    })
}

pub fn merge_into(cfg: &mut RootCfg, doc: OverlayDoc) {
    for (name, hook) in doc.hooks {
        cfg.hooks.insert(name, hook);
    }
    for g in doc.global_hooks {
        if !cfg.global_hooks.contains(&g) {
            cfg.global_hooks.push(g);
        }
    }

    for (name, group) in doc.groups {
        cfg.groups.insert(name, group);
    }

    for name in &doc.deleted {
        cfg.hooks.remove(name);
        cfg.global_hooks.retain(|g| g != name);
    }
    for name in &doc.deleted_groups {
        cfg.groups.remove(name);
    }
}

#[cfg(test)]
#[path = "tests/config_consolidation_tests.rs"]
mod config_consolidation_tests;

#[cfg(test)]
#[path = "tests/version_gate_tests.rs"]
mod version_gate_tests;

#[cfg(test)]
#[path = "tests/overlay_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/overlay_read_only_tests.rs"]
mod overlay_read_only_tests;
