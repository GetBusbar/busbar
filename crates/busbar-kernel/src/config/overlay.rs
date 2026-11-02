// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Store-owned runtime configuration overlay. Operator config files remain read-only inputs.
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
/// Legacy selector only. No file is created, read, probed or removed.
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
    /// Whether NO root override is set (every field `None`) — drives the section-empty predicate and
    /// the idempotent-reset short-circuit. Checked field-by-field (not via `PartialEq`) so the nested
    /// config structs need no `PartialEq` derive.
    ///
    /// DRIFT GUARD, same idiom as `config::patch::tests::every_patch_mirrors_every_field_of_its_section`:
    /// an EXHAUSTIVE destructure with NO `..`, so a field added to `RootSettings` fails to compile
    /// until it is considered here. This predicate decides whether `persist_root` stores the section
    /// at all, so a field missing from it would make a `PUT /config/settings` naming ONLY that field
    /// compute "empty", store `None`, and return 200 — a SILENT DISCARD reported as a success.
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

    /// Splice the present overrides onto a base `DeployCfg`, IN PLACE. Applied BEFORE `resolve` so the
    /// limits projection + the exposed-admin-mTLS boot-guard re-derive over the merged shape exactly
    /// as for a hand-written config. Only `Some` fields overwrite; a `None` field leaves base config
    /// untouched. `admin_require_mtls`/`per_request_fee` are non-optional on `DeployCfg`, so an unset
    /// overlay override simply preserves the base value.
    ///
    /// DRIFT GUARD: EXHAUSTIVE destructure with NO `..` (same idiom as `is_empty`), so a field added
    /// to `RootSettings` cannot be stored-but-never-applied by omission — the compiler forces it to
    /// be spliced onto `DeployCfg` here (or bound `_` with a stated reason).
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
        // PER-FIELD from here down. Assigning the whole section instead meant a partial `PUT`
        // deserialized into a full struct of compiled defaults, so every field the operator did not
        // name silently reverted — `config.yaml` values included.
        if let Some(v) = security {
            v.apply(deploy.security.get_or_insert_with(Default::default));
        }
        if let Some(v) = limits {
            v.apply(&mut deploy.limits);
        }
        if let Some(v) = advanced {
            v.apply(&mut deploy.advanced);
        }
        // 1.5.3: the retired `metrics:` AND `observability:` overlay sections are gone — Prometheus
        // metrics and OTLP traces are now named `export:` instances (`module: prometheus` /
        // `module: otlp`), edited in config.yaml + applied via plugin reload (consistent with every
        // other exporter), never through the single-value settings overlay.
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
    /// EVERY section, in wire order. The route's error message, the OpenAPI enum and the docs audit
    /// all read THIS, so the valid set is stated ONCE: a new section cannot be live in the parser and
    /// missing from what the API tells an operator, or from what the reference documents.
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

    /// Parse a URL path segment into a section, or `None` for an unknown name (the caller 400s). The
    /// ONE place the valid section names live, so the route + the doc + the tests share one source.
    pub fn parse(s: &str) -> Option<Self> {
        OverlaySection::all().into_iter().find(|v| v.as_str() == s)
    }

    /// The section's wire/label name (the path segment). For a named map this is the section KEY,
    /// which is deliberately the same string as the config key and the CRUD path segment
    /// (`export:` ⇄ `/export` ⇄ `/overlay/export`).
    pub fn as_str(self) -> &'static str {
        match self {
            OverlaySection::Hooks => Kind::Hook.root(),
            OverlaySection::Groups => "groups",
            OverlaySection::Root => "root",
            OverlaySection::PluginVersions => "plugin_versions",
            OverlaySection::NamedMap(s) => s.key(),
        }
    }

    /// The valid section names as a comma-separated, backticked list for an error message. Derived
    /// from [`OverlaySection::all`] rather than written out, because the hand-written version of this
    /// string is exactly what told operators `export` was not a section while it was becoming one.
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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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

impl OverlayDoc {
    /// Wipe ONE section's entries + tombstones in place (the pure core of a per-section reset). The
    /// remaining section is untouched, so merging this doc onto a freshly-resolved base config reverts
    /// exactly the cleared section to `config.yaml` truth while the other section's overlay stays live.
    ///
    /// DRIFT GUARD, the idiom `RootSettings::is_empty` and `config::patch` already use: an EXHAUSTIVE
    /// destructure with NO `..`, so a new field on `OverlayDoc` fails to compile until somebody has
    /// said WHICH SECTION OWNS IT. A durable, API-writable overlay field that belongs to no section
    /// is a slice of config an operator can change and cannot revert, which is exactly what
    /// `named_maps` was: it shipped durable and API-writable while `OverlaySection` had four variants
    /// and none of them was it.
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
            // NOT a section: the overlay's own schema version describes the FILE, not any slice of
            // config. It is rewritten by every persist and must survive every reset.
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
            // Only THIS map. `named_maps` is keyed by section, so a reset of `export` leaves
            // `identity-providers` (and every future map) exactly as it was — the same isolation the
            // hooks/groups sections have from each other.
            OverlaySection::NamedMap(s) => {
                named_maps.remove(s.key());
            }
        }
    }

    /// Whether a section carries NO overlay state (no API-applied entries AND no tombstones) — so a
    /// reset of it is a clean no-op (the effective config already equals base for that section). Drives
    /// the idempotent-success short-circuit: resetting an untouched section changes nothing and must
    /// not bump the config version or re-run the boot pipeline.
    pub fn section_is_empty(&self, section: OverlaySection) -> bool {
        match section {
            OverlaySection::Hooks => {
                self.hooks.is_empty() && self.global_hooks.is_empty() && self.deleted.is_empty()
            }
            OverlaySection::Groups => self.groups.is_empty() && self.deleted_groups.is_empty(),
            OverlaySection::Root => self.root.as_ref().is_none_or(RootSettings::is_empty),
            OverlaySection::PluginVersions => self.plugin_versions.is_empty(),
            // `persist_named_map` removes a map's key entirely once its last entry goes, so an
            // ABSENT key and a present-but-empty one both mean "no overlay state here".
            OverlaySection::NamedMap(s) => self
                .named_maps
                .get(s.key())
                .is_none_or(std::collections::BTreeMap::is_empty),
        }
    }
}

/// Convenience projection for diagnostics. Boot/reload use OverlayStore::read_required.
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
        // `plugin:` → `module:` (a persisted overlay that already carries `module:` wins).
        if let Some(plugin) = obj.remove("plugin") {
            obj.entry("module".to_string()).or_insert(plugin);
        }
        // `at: <stage>` → `phase: [<stage>]`, unless a non-empty `phase:` is already authoritative.
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
/// Replace the complete document through the same atomic Store generation protocol.
pub fn write(store: &OverlayStore, doc: &OverlayDoc) -> Result<(), String> {
    store.update(|current| *current = doc.clone())
}
/// Build an overlay from a hook state (registry + global-hook names), no tombstones — a test helper
/// (the live apply path builds the doc inline in `persist` so it can carry tombstones).
#[cfg(test)]
pub fn from_state(hooks: &HashMap<String, HookCfg>, global_hooks: &[String]) -> OverlayDoc {
    OverlayDoc {
        hooks: hooks.clone(),
        global_hooks: global_hooks.to_vec(),
        deleted: Vec::new(),
        ..Default::default()
    }
}

/// Apply the overlay's `root` section (the single-value config overrides) to a base `DeployCfg`
/// BEFORE `resolve` — the pre-resolve half of the boot-merge. The hooks + groups sections merge
/// POST-resolve (`merge_into`, the runtime registry is synthesized in `resolve`); the root section is
/// DeployCfg-level input, so the limits projection + the exposed-admin-mTLS boot-guard re-run over
/// the merged shape. A no-op when the overlay carries no root override. Kept a free fn (not folded
/// into `merge_into`) precisely because it operates on a DIFFERENT input (DeployCfg, not RootCfg) at
/// a DIFFERENT pipeline stage.
pub fn apply_root_to_deploy(deploy: &mut DeployCfg, doc: &OverlayDoc) {
    if let Some(root) = &doc.root {
        root.apply_to_deploy(deploy);
    }
    apply_pre_resolve_sections(deploy, doc);
}

/// Apply the overlay's `plugin_versions` pins onto `deploy.plugins.min_versions` (1.5.0
/// rollback-friendly versioning). Each pin OVERRIDES the base-config floor for THAT plugin name to the
/// operator's explicitly-pinned version — so on the next (re)load the pinned (older) third-party
/// artifact clears its (now-lowered) floor and re-loads, and no floor is silently RAISED. A pin only
/// ever exists because a human took an explicit, authenticated, audited rollback action; the automatic
/// boot/reload path merely honors the persisted decision. A pin for a plugin the base config never
/// floored simply adds a (low) floor entry — harmless, since a floor at/below the artifact's version
/// is a no-op.
///
/// The FIRST-PARTY floor override is now PER-PLUGIN, not a single global floor. Each pin adds
/// BOTH a `min_versions` entry (the third-party floor path) AND a `first_party_floors[name]` entry (the
/// first-party floor path in the loader's trust evaluation). The evaluation applies the per-name
/// first-party floor ONLY to a plugin whose manifest is actually first-party, so pinning a third-party
/// name is a harmless no-op on the first-party path (its `min_versions` entry does the work). The
/// earlier single global `first_party_floor` set to the LOWEST pin across all pins lowered the floor for
/// EVERY first-party plugin — so a rollback of plugin A could silently admit an unpinned old first-party
/// plugin B. Scoping the override to the pinned name closes that.
pub fn apply_plugin_versions_to_deploy(deploy: &mut DeployCfg, doc: &OverlayDoc) {
    for (name, pinned) in &doc.plugin_versions {
        deploy
            .plugins
            .min_versions
            .insert(name.clone(), pinned.clone());
        // Scope the first-party floor override to THIS name alone. Harmless for a third-party
        // pin: `evaluate` only consults `first_party_floors` for a verified first-party manifest.
        deploy
            .plugins
            .first_party_floors
            .insert(name.clone(), pinned.clone());
    }
}

/// Apply the overlay's `named_maps` sections onto a base `DeployCfg`, PRE-resolve — the durable half
/// of the generic named-map admin CRUD. Runs at the same seam as the `root` / `plugin_versions`
/// overrides (and for the same reason): `resolve` LOWERS these definition maps into the auth chains
/// and the typed export projection, so an overlay entry that arrived after resolve would never reach
/// the runtime at all.
///
/// A definition that no longer parses (a downgrade whose typed struct lost a field, a hand-edited
/// overlay) is dropped with a LOUD error rather than aborting the whole boot: an unparseable exporter
/// must not brick startup, and an unparseable identity provider that something still references fails
/// LOUDLY anyway at `resolve` (the dangling-reference error), which is the actionable diagnostic.
pub fn apply_named_maps_to_deploy(deploy: &mut DeployCfg, doc: &OverlayDoc) {
    use crate::config::named_map::NamedMapSection;
    for section in NamedMapSection::sections() {
        let Some(entries) = doc.named_maps.get(section.key()) else {
            continue;
        };
        for (name, def) in entries {
            // WHOLE-ENTRY REPLACE, as 1.5.5 applied it (v1.5.5 crates/busbar/src/config/overlay.rs
            // :887-904, parity, Q128 arch u29): the stored definition IS the entry, so a field the
            // overlay entry does not name never leaks in from a same-named base entry, and an
            // explicit `null` inside it reaches the typed parse exactly as the operator PUT it.
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

/// Every definition STORED in the overlay at `path` under `section` that this binary CANNOT parse —
/// `name -> {error, raw}`, empty when everything parses (and when there is no overlay at all).
///
/// [`apply_named_maps_to_deploy`] drops such an entry with a `tracing::error!` and then
/// omits it forever: the definition sits in the operator's overlay, is never applied, and NOTHING
/// outside a boot log line says so — the admin read simply showed the name as absent, which is
/// indistinguishable from "I never wrote it". This is the read-side signal that closes that: the
/// admin named-map surface calls it and flags each such entry explicitly (`unparseable`), so an
/// operator inspecting STATE discovers the drop. The entry is only ever REPORTED — never deleted,
/// never rewritten; the operator's data stays exactly as they left it.
///
/// Derived at read time from the overlay file rather than remembered from the last apply, so it
/// needs no diagnostics channel threaded through the seven rebuild sites and can never go stale
/// against the overlay it describes.
///
/// SCOPE, stated precisely now that an overlay entry is a PATCH: this validates the stored patch in
/// ISOLATION, without the base entry it would be merged onto, so a partial patch fails here even
/// though it applies perfectly well. That does not produce a false report, because both callers ask
/// this only about names that are NOT live, and a patch that merged successfully IS live. What a
/// partial patch can produce is a less precise ERROR STRING for a name that genuinely failed for
/// some other reason. The flag itself is correct either way.
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
/// Merge an overlay into the RESOLVED config (the boot-merge, run AFTER `config::resolve` - the
/// runtime hook registry is synthesized there from the inline refs, so the overlay layers on top
/// of it). Overlay hooks are inserted into the registry (an overlay hook with a base hook's name
/// WINS - the last-applied definition, which matches the live-apply semantics), overlay global
/// names are unioned into `global_hooks`, and finally TOMBSTONES (`deleted`) are subtracted - so a
/// hook the API deleted stays gone across a restart even if it was defined in base `config.yaml`.
/// Tombstones are applied LAST so a delete always wins over a stale add.
pub fn merge_into(cfg: &mut RootCfg, doc: OverlayDoc) {
    for (name, hook) in doc.hooks {
        cfg.hooks.insert(name, hook);
    }
    for g in doc.global_hooks {
        if !cfg.global_hooks.contains(&g) {
            cfg.global_hooks.push(g);
        }
    }
    // Groups section: same semantics as hooks — an overlay group with a base group's name wins, then
    // group tombstones are subtracted LAST so an API deletion survives a restart even if base defined
    // the group. The parent-chain validity (parents exist, acyclic, depth) is re-checked by
    // `validate_groups` after the merge, exactly as for a hand-written config.
    for (name, group) in doc.groups {
        cfg.groups.insert(name, group);
    }
    // Tombstones LAST: an API deletion removes the hook/group from the effective config even if base
    // defined it.
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

/// A read-only config mount must not stop busbar from serving: the degrade-and-warn posture, and the
/// line between it and the config errors that DO still refuse to boot.
#[cfg(test)]
#[path = "tests/overlay_read_only_tests.rs"]
mod overlay_read_only_tests;
