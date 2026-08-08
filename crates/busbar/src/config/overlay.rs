// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The busbar-owned config OVERLAY — the persistence substrate that lets an API-applied hook survive
//! a restart. Effective config = base (`config.yaml`, hand-written, NEVER touched) + overlay
//! (busbar-owned). Today the overlay carries the runtime hook registry; it grows as more of the config
//! plane becomes API-mutable.
//!
//! This module is the PURE substrate (read/write/merge) — unit-tested in isolation. The wiring (write
//! on apply, read + merge at boot, gated by the overlay path) is layered on top. `write` is atomic
//! (temp + rename) so a crash mid-write never leaves a torn overlay; `read` is fail-soft (a missing or
//! corrupt overlay yields `None` and boot proceeds on base config alone — a bad overlay never bricks
//! startup).

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{
    ConfigMgmtCfg, DeployCfg, GroupCfg, HookCfg, OverlayCfg, RateEntryCfg, RootCfg, StoreCfg,
    TlsCfg,
};

/// The single, actionable message a config mutation gets when there is no writable overlay backend to
/// record it. With the 1.5.3 boot invariant (`locked` XOR a writable overlay), a MUTABLE busbar always
/// has a writable overlay, so this is only reachable on a LOCKED (immutable/GitOps) deployment — where
/// refusing runtime config mutation is exactly the point. Used both as the `persist_*` `None`-path
/// error (the structural backstop that makes silent non-durable mutation impossible) and by the admin
/// handlers' early locked-config refusals.
pub(crate) const NO_WRITABLE_OVERLAY_MSG: &str =
    "config mutation refused: this busbar has no writable config overlay. This is expected when \
     `config.locked: true` (an immutable/GitOps deployment) — edit config.yaml and POST /config/reload \
     to change it. If the config is meant to be mutable, give it a writable `config.overlay` backend \
     and reload.";

/// The default overlay filename, written next to `config.yaml` when `config.overlay` names no explicit
/// path. One source of truth for the code + tests (the doc-comment prose in `config/mod.rs` mirrors it).
pub(crate) const DEFAULT_OVERLAY_FILENAME: &str = "busbar-overlay.json";
/// Filename prefix for the boot-time writability probe (a leading-dot temp file, pid-suffixed).
const PROBE_FILE_PREFIX: &str = ".busbar-overlay-probe-";

/// The resolved config-management posture for a boot/reload: whether config is locked, and the
/// writable overlay backend path (if any). Computed by [`resolve_backend`].
#[derive(Debug, Clone)]
pub(crate) struct OverlayResolution {
    /// `true` ⇒ `config.locked: true`: admin-API config mutations are refused at runtime.
    pub(crate) locked: bool,
    /// The writable file-backend path when the config is MUTABLE; `None` when locked. The boot
    /// invariant guarantees `locked == path.is_none()` for a config that BOOTED.
    pub(crate) path: Option<PathBuf>,
}

/// Resolve the config-management posture + overlay backend from the `config:` block (1.5.3), enforcing
/// the BOOT INVARIANT: `locked` XOR a writable overlay. Returns `Err` (a boot refusal) when the config
/// is mutable but has no writable backend — the state that used to be silently reachable and let a
/// mutation apply in RAM only.
///
/// Precedence for a mutable config's backend path: an explicit `config.overlay` wins; else the
/// deprecated `BUSBAR_CONFIG_OVERLAY` env var (`env_override`, with a deprecation warn); else the
/// default `busbar-overlay.json` next to the resolved config.yaml. `probe_fs` gates the filesystem
/// writability check — `true` at boot/reload (so a read-only config dir refuses to boot), `false` for
/// `--validate` (which must have zero side effects and may run away from the target filesystem).
pub(crate) fn resolve_backend(
    cfg: &ConfigMgmtCfg,
    config_path: &Path,
    env_override: Option<&Path>,
    probe_fs: bool,
) -> Result<OverlayResolution, String> {
    if env_override.is_some() {
        tracing::warn!(
            "BUSBAR_CONFIG_OVERLAY is DEPRECATED and will be removed in a future release; set \
             `config.overlay.file` in config.yaml instead. It is honored for now only when \
             `config.overlay` is not set."
        );
    }
    if cfg.locked {
        // Immutable/GitOps: the overlay is irrelevant and ignored; runtime mutations are refused.
        return Ok(OverlayResolution {
            locked: true,
            path: None,
        });
    }
    let config_dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    // MUTABLE: resolve the backend path (config wins > deprecated env > default next to config.yaml).
    let path: Option<PathBuf> = match &cfg.overlay {
        Some(OverlayCfg::Disabled(false)) => None, // `overlay: false` — explicitly no backend.
        Some(OverlayCfg::Disabled(true)) => {
            return Err(
                "config.overlay: `true` names no backend — use `{ file: <path> }`, or \
                        `false` together with `config.locked: true` to run immutable."
                    .to_string(),
            );
        }
        Some(OverlayCfg::Backend(b)) => b.file.as_ref().map(|f| resolve_rel(f, config_dir)),
        None => Some(
            env_override
                .map(Path::to_path_buf)
                .unwrap_or_else(|| config_dir.join(DEFAULT_OVERLAY_FILENAME)),
        ),
    };
    let Some(p) = path else {
        return Err("config is mutable (config.locked: false) but has no writable overlay backend — \
                    `config.overlay` is disabled, so an admin-API config change could not be stored \
                    and would silently revert on restart. Give it a backend (`config.overlay.file: \
                    <path>`), or set `config.locked: true` for an immutable deployment."
            .to_string());
    };
    if probe_fs && !is_backend_writable(&p) {
        return Err(format!(
            "config is mutable (config.locked: false) but the overlay backend '{}' is not writable \
             (is the config directory read-only?). A mutable config MUST be able to persist admin-API \
             changes. Point `config.overlay.file` at a writable path, or set `config.locked: true` for \
             an immutable/GitOps deployment (which never persists runtime mutations anyway).",
            p.display()
        ));
    }
    Ok(OverlayResolution {
        locked: false,
        path: Some(p),
    })
}

/// Resolve a possibly-relative overlay path against the config.yaml directory.
fn resolve_rel(file: &str, config_dir: &Path) -> PathBuf {
    let p = Path::new(file);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        config_dir.join(p)
    }
}

/// Probe whether the overlay backend path is writable WITHOUT a durable side effect: an existing file
/// must open for write; a not-yet-created file needs a writable parent dir (create + immediately
/// remove a probe file). This never routes through `crate::durable` because it writes nothing that
/// must survive — it is a boot-time capability check, not a config write.
fn is_backend_writable(p: &Path) -> bool {
    if p.exists() {
        return std::fs::OpenOptions::new().write(true).open(p).is_ok();
    }
    // A not-yet-created overlay is writable iff its PARENT directory is writable. Treat an EMPTY parent
    // (`p` is a bare filename with no directory component — e.g. `BUSBAR_CONFIG=config.yaml` run from
    // inside the config dir resolves the default overlay to a bare `busbar-overlay.json`) as the CURRENT
    // directory. Crucially, do NOT fall back to `OpenOptions::open(p)` WITHOUT `.create(true)`: that
    // errors `NotFound` for a not-yet-existing file regardless of whether the directory is writable, so
    // it would wrongly report a perfectly writable cwd as non-writable and REFUSE a valid durable-by-
    // default boot. Probe with the same create-then-remove dance as a normal directory-qualified path.
    let dir = p
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    // pid + a process-global monotonic nonce so concurrent probes (parallel test threads sharing a
    // cwd, or repeated boot-time calls) never collide on the same probe filename.
    static PROBE_NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nonce = PROBE_NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let probe = dir.join(format!("{PROBE_FILE_PREFIX}{}-{nonce}", std::process::id()));
    match std::fs::File::create(&probe) {
        Ok(file) => {
            // Close the handle BEFORE unlinking. On Windows (no `FILE_SHARE_DELETE`) and some network
            // filesystems an open file cannot be removed; holding it across `remove_file` would leak the
            // probe on every boot.
            drop(file);
            if let Err(e) = std::fs::remove_file(&probe) {
                // The probe name is pid-scoped, so a leaked probe is never reclaimed by a later boot.
                // Surface it (WARN) rather than swallowing the error silently.
                tracing::warn!(
                    probe = %probe.display(), error = %e,
                    "could not remove the overlay writability probe file after creating it; it may be \
                     left behind in the config directory"
                );
            }
            true
        }
        Err(_) => false,
    }
}

/// Current overlay schema version. Stamped on every write; a missing field (a pre-versioning overlay)
/// reads as `1`, the additive baseline (hooks + the newly-added groups section, both backward
/// compatible). Bump only on a BREAKING overlay-format change, and add a migration at `read` time.
pub(crate) const OVERLAY_VERSION: u32 = 1;
fn default_overlay_version() -> u32 {
    1
}

/// Persist the current hook state to the overlay at `path`, IF persistence is enabled (`Some`), and
/// update the TOMBSTONE set for this change: `deleted_add` (a just-deleted hook) is tombstoned so the
/// additive boot-merge REMOVES it even if it was defined in base `config.yaml`; `deleted_remove` (a
/// just-registered hook) clears any prior tombstone (a re-add). Read-modify-write so tombstones
/// accumulate across applies. The path is resolved from the `config.overlay` backend (1.5.3) and
/// carried on `App`. FAIL-CLOSED: returns `Err` on an unreadable overlay (refuse-to-clobber) or a
/// write failure, so its caller — `AppHandle::commit_and_swap` — does NOT swap a mutation it could not
/// durably record (a live-applied-but-unpersisted config that a restart would silently revert). A
/// `None` path is NO LONGER a silent success: with the boot invariant it means the config is LOCKED,
/// so the mutation is refused ([`NO_WRITABLE_OVERLAY_MSG`]).
pub(crate) fn persist(
    path: Option<&Path>,
    hooks: &HashMap<String, HookCfg>,
    global_hooks: &[String],
    deleted_add: Option<&str>,
    deleted_remove: Option<&str>,
    base_hook_names: &std::collections::HashSet<String>,
) -> Result<(), String> {
    let Some(p) = path else {
        // 1.5.3: NEVER a silent `Ok`. With the boot invariant (`locked` XOR a writable overlay), a
        // mutable busbar always has a backend here, so `None` means the config is locked — refuse.
        return Err(NO_WRITABLE_OVERLAY_MSG.to_string());
    };
    // Read-modify-WRITE the WHOLE overlay so a hook write preserves the groups section verbatim
    // (and vice-versa in `persist_groups`). `load_for_rmw` refuses on an unreadable overlay —
    // starting empty then overwriting would PERMANENTLY drop accumulated tombstones from BOTH
    // sections and silently resurrect an API-deleted hook/group on restart. That REFUSE is now an
    // `Err` (fail-closed): the caller must NOT swap a mutation it could not durably record.
    let Some(mut doc) = load_for_rmw(p) else {
        return Err(format!(
            "could not read the overlay at '{}' to persist hooks (refusing to overwrite a corrupt \
             overlay, which would drop deletion tombstones)",
            p.display()
        ));
    };
    if let Some(name) = deleted_add {
        if !doc.deleted.iter().any(|n| n == name) {
            doc.deleted.push(name.to_string());
        }
    }
    if let Some(name) = deleted_remove {
        doc.deleted.retain(|n| n != name);
    }
    doc.hooks = hooks.clone();
    doc.global_hooks = global_hooks.to_vec();
    // INVARIANT: a hook present in the registry being persisted can never ALSO be tombstoned —
    // the boot-merge would insert it then subtract it, silently dropping a live hook. The
    // explicit `deleted_remove` above covers the register-a-name case; this reconciliation also
    // covers the WHOLESALE-registry writes (config ROLLBACK, which passes both args `None`):
    // rollback restores a registry that may contain a name still tombstoned from an earlier
    // API delete, and without this the rollback would not survive a restart.
    //
    // ALSO prune any tombstone whose name is not (or no longer) in BASE `config.yaml`
    // (`base_hook_names`): such a tombstone can never be reconciled by the "name comes back" rule
    // above, since nothing at boot ever re-inserts a non-base name into `hooks` on its own — it is
    // permanently inert dead weight that would otherwise grow the overlay file forever. A tombstone
    // for a name still present in base config is kept: it is still actively shadowing that entry.
    doc.deleted
        .retain(|name| !hooks.contains_key(name) && base_hook_names.contains(name));
    doc.version = OVERLAY_VERSION;
    write(p, &doc).map_err(|e| format!("overlay write to '{}' failed: {e}", p.display()))
}

/// Load the existing overlay for a read-modify-WRITE, or `None` to signal REFUSE-to-overwrite.
/// `Absent` -> a fresh default doc (safe to start clean); `Loaded` -> the existing doc (all sections
/// carried forward so a write to one section never clobbers another); `Unreadable` -> `None`, and the
/// caller aborts the write, because overwriting a corrupt overlay would drop the deletion tombstones
/// of EVERY section. `version` is stamped by the caller just before `write`.
fn load_for_rmw(p: &Path) -> Option<OverlayDoc> {
    match read_state(p) {
        OverlayReadState::Absent => Some(OverlayDoc::default()),
        OverlayReadState::Loaded(doc) => Some(*doc),
        OverlayReadState::Unreadable => {
            tracing::error!(
                path = %p.display(),
                "config overlay exists but is unreadable/corrupt; REFUSING to overwrite it (would \
                 drop hook AND group deletion tombstones and could resurrect a deleted item). This \
                 apply is NOT persisted — fix or remove the overlay file to restore durability."
            );
            None
        }
        OverlayReadState::VersionTooNew(v) => {
            tracing::error!(
                path = %p.display(), overlay_version = v, understood = OVERLAY_VERSION,
                "config overlay was written by a NEWER busbar; REFUSING to overwrite it — this \
                 binary cannot represent everything it holds, so a write would silently discard \
                 whatever it does not understand. This apply is NOT persisted."
            );
            None
        }
    }
}

/// Persist the current GROUPS state to the overlay, mirroring `persist` for the `groups:` section:
/// the API-mutable group registry + its tombstones (`deleted_groups`), read-modify-written so the
/// HOOKS section and its tombstones are preserved untouched. FAIL-CLOSED (matches `persist`): returns
/// `Err` on an unreadable overlay or a write failure so `commit_and_swap` does not swap an
/// unpersistable mutation. `None` path is NOT a silent success (matches `persist`): with the boot
/// invariant it means the config is LOCKED, so the mutation is refused ([`NO_WRITABLE_OVERLAY_MSG`]).
/// `deleted_add`/`deleted_remove` tombstone/untombstone a group name; a wholesale write (both `None`,
/// e.g. rollback) reconciles away any tombstone for a name the restored registry contains.
pub(crate) fn persist_groups(
    path: Option<&Path>,
    groups: &BTreeMap<String, GroupCfg>,
    deleted_add: Option<&str>,
    deleted_remove: Option<&str>,
    base_group_names: &std::collections::HashSet<String>,
) -> Result<(), String> {
    let Some(p) = path else {
        // 1.5.3: never a silent `Ok` (see `persist`). `None` here ⇒ a locked config — refuse.
        return Err(NO_WRITABLE_OVERLAY_MSG.to_string());
    };
    let Some(mut doc) = load_for_rmw(p) else {
        return Err(format!(
            "could not read the overlay at '{}' to persist groups (refusing to overwrite a corrupt \
             overlay)",
            p.display()
        ));
    };
    if let Some(name) = deleted_add {
        if !doc.deleted_groups.iter().any(|n| n == name) {
            doc.deleted_groups.push(name.to_string());
        }
    }
    if let Some(name) = deleted_remove {
        doc.deleted_groups.retain(|n| n != name);
    }
    doc.groups = groups.clone();
    // Prune on "name comes back" (as above) AND on "name is absent from base config.yaml" (a
    // tombstone that can never be reconciled the first way, since nothing at boot re-adds a
    // non-base name — see `persist`'s matching comment).
    doc.deleted_groups
        .retain(|name| !groups.contains_key(name) && base_group_names.contains(name));
    doc.version = OVERLAY_VERSION;
    write(p, &doc).map_err(|e| format!("overlay write to '{}' failed: {e}", p.display()))
}

/// The `root` overlay section (1.5.0 full-config coverage): the API-settable SINGLE-VALUE config
/// sections that are NOT name-keyed maps (so they carry no tombstones — a field is either PRESENT in
/// the overlay, and WINS over base `config.yaml`, or ABSENT, and base stands). It mirrors the
/// uncovered `DeployCfg` surface: the process-level binds (`listen`/`tls`/`admin_listen`/`admin_tls`/
/// `admin_require_mtls`), the cost inputs (`rate_card`/`per_request_fee`), the durable `store`, the
/// `security` SSRF controls, and the operational-limit blocks (`limits`/`advanced`/`health`/
/// `routing`). Every field is `Option`: a `PUT /config/settings` overwrites only
/// the fields it names (a partial edit), and the merge (`apply_to_deploy`) splices exactly those onto
/// the resolved base `DeployCfg` BEFORE `resolve` — so the limits projection + admin-mTLS boot-guard
/// re-run over the merged shape exactly as for a hand-written config. `deny_unknown_fields` so a
/// typo'd key is a loud reject, never a silent no-op.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RootSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) listen: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) tls: Option<TlsCfg>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) admin_listen: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) admin_tls: Option<TlsCfg>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) admin_require_mtls: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) rate_card: Option<BTreeMap<String, RateEntryCfg>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) per_request_fee: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) store: Option<StoreCfg>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) security: Option<crate::config::patch::SecurityPatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) limits: Option<crate::config::patch::LimitsPatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) advanced: Option<crate::config::patch::AdvancedPatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) health: Option<crate::config::patch::HealthPatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) routing: Option<crate::config::patch::RoutingPatch>,
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
    pub(crate) fn is_empty(&self) -> bool {
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
    pub(crate) fn apply_to_deploy(&self, deploy: &mut DeployCfg) {
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

/// Persist the `root` overlay section (1.5.0 full-config coverage), IF persistence is enabled. Same
/// read-modify-WRITE durability contract as `persist`/`persist_groups`: the hooks + groups sections
/// (and their tombstones) are carried forward verbatim, and an unreadable overlay is REFUSED (never
/// clobbered). `None` path is a no-op. `settings` is the full desired root state (the merge of the
/// prior overlay root + this request's fields is computed by the caller, so a `PUT /config/settings`
/// passes the already-merged desired state here — this fn just stores it).
pub(crate) fn persist_root(path: Option<&Path>, settings: &RootSettings) -> Result<(), String> {
    let Some(p) = path else {
        // 1.5.3: this is the exact silent-`Ok` that let handlers report durable storage that never
        // happened. It is now a hard error. The boot invariant guarantees a MUTABLE config has a
        // writable backend here, so `None` means the config is LOCKED — refuse the mutation instead
        // of lying about persisting it.
        return Err(NO_WRITABLE_OVERLAY_MSG.to_string());
    };
    let Some(mut doc) = load_for_rmw(p) else {
        return Err(format!(
            "could not read the overlay at '{}' to persist root settings (refusing to overwrite a \
             corrupt overlay)",
            p.display()
        ));
    };
    doc.root = if settings.is_empty() {
        None
    } else {
        Some(settings.clone())
    };
    doc.version = OVERLAY_VERSION;
    write(p, &doc).map_err(|e| format!("overlay write to '{}' failed: {e}", p.display()))
}

/// Persist the `plugin_versions` overlay section — the durable half of an explicit plugin ROLLBACK
/// (1.5.0). Same read-modify-WRITE durability contract as `persist_root`: the hooks/groups/root
/// sections (and their tombstones) are carried forward verbatim, and an unreadable overlay is REFUSED
/// (never clobbered). `pins` is the FULL desired pin map (the caller computed the merge of the prior
/// pins + this rollback), so an empty map clears the section (every pin lifted).
///
/// Persist the plugin version-pin section (read-modify-WRITE; siblings preserved). Returns whether the
/// write landed: the rollback path (both the forward persist and the compensating revert after a failed
/// rebuild) must FAIL CLOSED on a persist error — a silently-swallowed failure would leave disk out of
/// sync with the running engine (a stale pin a restart would honor, contradicting the live policy), so
/// every caller propagates the error rather than warning-and-continuing. A `None` path is likewise NOT
/// a silent success (matching the sibling `persist_*`): it means the config is LOCKED, so the pin is
/// refused ([`NO_WRITABLE_OVERLAY_MSG`]).
pub(crate) fn try_persist_plugin_versions(
    path: Option<&Path>,
    pins: &BTreeMap<String, String>,
) -> Result<(), String> {
    let Some(p) = path else {
        // 1.5.3: NEVER a silent `Ok` — this matches the fail-closed contract stated in this function's
        // own doc comment and the sibling `persist_*` functions. With the boot invariant (`locked` XOR a
        // writable overlay), a mutable busbar always has a backend here, so `None` means the config is
        // LOCKED. The `plugins/rollback` caller already refuses a locked config up front; this is the
        // structural backstop so a future caller cannot silently drop an operator's rollback/pin.
        return Err(NO_WRITABLE_OVERLAY_MSG.to_string());
    };
    let Some(mut doc) = load_for_rmw(p) else {
        return Err(format!(
            "could not read the overlay at '{}' to update plugin_versions",
            p.display()
        ));
    };
    doc.plugin_versions = pins.clone();
    doc.version = OVERLAY_VERSION;
    write(p, &doc).map_err(|e| format!("overlay write to '{}' failed: {e}", p.display()))
}

/// One MUTABLE overlay SECTION — the unit a per-section reset (`DELETE /api/v1/admin/overlay/{section}`)
/// discards. Each section is an independent `base + overlay` layer with its own entries + tombstones;
/// clearing one reverts exactly that slice of the effective config to base `config.yaml` while the
/// other section's overlay mutations survive untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OverlaySection {
    Hooks,
    Groups,
    /// The single-value config sections (`RootSettings`) — the 1.5.0 full-config coverage slice.
    Root,
    /// The per-plugin ROLLBACK version pins (1.5.0). Clearing it drops every explicit rollback pin,
    /// restoring the base-config `plugins.min_versions` floors — the plugins then upgrade back to their
    /// current artifacts on the next (re)load.
    PluginVersions,
}

impl OverlaySection {
    /// Parse a URL path segment into a section, or `None` for an unknown name (the caller 400s). The
    /// ONE place the valid section names live, so the route + the doc + the tests share one source.
    pub(crate) fn parse(s: &str) -> Option<Self> {
        match s {
            "hooks" => Some(OverlaySection::Hooks),
            "groups" => Some(OverlaySection::Groups),
            "root" => Some(OverlaySection::Root),
            "plugin_versions" => Some(OverlaySection::PluginVersions),
            _ => None,
        }
    }

    /// The section's wire/label name (the path segment).
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            OverlaySection::Hooks => "hooks",
            OverlaySection::Groups => "groups",
            OverlaySection::Root => "root",
            OverlaySection::PluginVersions => "plugin_versions",
        }
    }
}

/// Clear ONE section's entries + tombstones from the persisted overlay, IF persistence is enabled —
/// the durable half of a per-section reset (`DELETE /api/v1/admin/overlay/{section}`). Read-modify-write
/// so the OTHER section (its API-applied entries and tombstones) is carried forward verbatim: a
/// `groups` reset must not resurrect an API-deleted hook, and vice-versa. FAIL-CLOSED (matches
/// `persist`/`persist_groups`): returns `Err` on an unreadable overlay (REFUSED — clearing it would
/// silently drop the other section's tombstones) or a write failure, so `commit_and_swap` does not
/// swap a reset it could not durably record. `None` path is NO LONGER a silent success: with the boot
/// invariant it means the config is LOCKED, so the reset is refused ([`NO_WRITABLE_OVERLAY_MSG`]).
pub(crate) fn clear_section(path: Option<&Path>, section: OverlaySection) -> Result<(), String> {
    let Some(p) = path else {
        // 1.5.3: NEVER a silent `Ok` (matches `persist`/`persist_groups`/`persist_root`). With the boot
        // invariant (`locked` XOR a writable overlay), a mutable busbar always has a backend here, so
        // `None` means the config is LOCKED — refuse the reset instead of reporting a success that never
        // touched disk. (The `DELETE /overlay/{section}` caller already short-circuits a locked config
        // to an idempotent no-op before reaching here; this is the structural backstop so a future
        // caller cannot reintroduce the lying `Ok`.)
        return Err(NO_WRITABLE_OVERLAY_MSG.to_string());
    };
    let Some(mut doc) = load_for_rmw(p) else {
        return Err(format!(
            "could not read the overlay at '{}' to reset the '{}' section (refusing to overwrite a \
             corrupt overlay)",
            p.display(),
            section.as_str()
        ));
    };
    doc.clear_section(section);
    doc.version = OVERLAY_VERSION;
    write(p, &doc).map_err(|e| format!("overlay write to '{}' failed: {e}", p.display()))
}

/// The persisted overlay document: the API-applied hook registry + global-hook wiring, plus TOMBSTONES
/// (`deleted`) — hooks removed via the API that must be subtracted from base config at boot. Tombstones
/// are what let the additive `base + overlay` model express a DELETION (an additive merge alone cannot
/// remove a base-defined hook).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct OverlayDoc {
    /// Overlay schema version (see `OVERLAY_VERSION`). Absent in a pre-versioning overlay -> `1`.
    #[serde(default = "default_overlay_version")]
    pub(crate) version: u32,
    #[serde(default)]
    pub(crate) hooks: HashMap<String, HookCfg>,
    #[serde(default)]
    pub(crate) global_hooks: Vec<String>,
    #[serde(default)]
    pub(crate) deleted: Vec<String>,
    /// API-applied `groups:` entries (the second section on the spine). An overlay group with a base
    /// group's name WINS at merge (last-applied definition), matching hook semantics.
    #[serde(default)]
    pub(crate) groups: BTreeMap<String, GroupCfg>,
    /// Group tombstones — groups deleted via the API, subtracted from base config at boot.
    #[serde(default)]
    pub(crate) deleted_groups: Vec<String>,
    /// The `root` section (1.5.0 full-config coverage): API-set single-value config overrides
    /// (`listen`/`tls`/`rate_card`/`store`/`security`/`limits`/…). `None` = no root override (base
    /// `config.yaml` stands). Applied at the `DeployCfg` level BEFORE `resolve` — see
    /// `RootSettings::apply_to_deploy`. No tombstones: a single-value field is present-or-absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) root: Option<RootSettings>,
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
    pub(crate) plugin_versions: BTreeMap<String, String>,
    /// The `named_maps` section (1.5.3 universal named-DEFINITION pattern): API-applied entries of
    /// EVERY named map the generic admin CRUD serves, keyed `section key → entry name → the raw
    /// definition document` (`identity-providers`/`export` today; `tools`/`agents` in 1.5.4/1.5.5).
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
    pub(crate) named_maps: BTreeMap<String, BTreeMap<String, serde_json::Value>>,
}

impl OverlayDoc {
    /// Wipe ONE section's entries + tombstones in place (the pure core of a per-section reset). The
    /// remaining section is untouched, so merging this doc onto a freshly-resolved base config reverts
    /// exactly the cleared section to `config.yaml` truth while the other section's overlay stays live.
    pub(crate) fn clear_section(&mut self, section: OverlaySection) {
        match section {
            OverlaySection::Hooks => {
                self.hooks.clear();
                self.global_hooks.clear();
                self.deleted.clear();
            }
            OverlaySection::Groups => {
                self.groups.clear();
                self.deleted_groups.clear();
            }
            OverlaySection::Root => {
                self.root = None;
            }
            OverlaySection::PluginVersions => {
                self.plugin_versions.clear();
            }
        }
    }

    /// Whether a section carries NO overlay state (no API-applied entries AND no tombstones) — so a
    /// reset of it is a clean no-op (the effective config already equals base for that section). Drives
    /// the idempotent-success short-circuit: resetting an untouched section changes nothing and must
    /// not bump the config version or re-run the boot pipeline.
    pub(crate) fn section_is_empty(&self, section: OverlaySection) -> bool {
        match section {
            OverlaySection::Hooks => {
                self.hooks.is_empty() && self.global_hooks.is_empty() && self.deleted.is_empty()
            }
            OverlaySection::Groups => self.groups.is_empty() && self.deleted_groups.is_empty(),
            OverlaySection::Root => self.root.as_ref().is_none_or(RootSettings::is_empty),
            OverlaySection::PluginVersions => self.plugin_versions.is_empty(),
        }
    }
}

/// Read the overlay at `path`, or `None` if it is absent, unreadable, or malformed. Fail-soft: a
/// corrupt overlay must NEVER brick boot — busbar starts on base config alone and the operator can
/// re-apply. Unlike the old silent-soft read, a present-but-corrupt overlay is now logged LOUD at
/// boot: silently starting on base config alone drops every API-applied hook AND group with no signal,
/// which is exactly the failure that hides overlay corruption.
pub(crate) fn read(path: &Path) -> Option<OverlayDoc> {
    match read_state(path) {
        OverlayReadState::Absent => None,
        OverlayReadState::Loaded(doc) => Some(*doc),
        OverlayReadState::Unreadable => {
            // ADMISSION-CONTROL SIGNAL: a torn overlay drops every API-registered hook,
            // which includes SECURITY GATES — so admission control silently reverts to base config. Warn
            // LOUD and name gates explicitly, aligning with the fail-closed hook discipline: an operator
            // who registered a gate via the API must not silently lose it to a corrupt overlay without a
            // diagnostic. (We still fail-soft on boot — a corrupt overlay must never brick startup — but
            // never silently.)
            tracing::warn!(
                path = %path.display(),
                "config overlay is present but unreadable/corrupt; starting on base config.yaml ALONE \
                 — API-applied hooks (INCLUDING security GATES that enforce admission control), groups, \
                 and plugin version pins are NOT restored. Any gate registered only via the admin API \
                 is now ABSENT until re-applied. Fix or remove the overlay file to restore durability."
            );
            None
        }
        OverlayReadState::VersionTooNew(v) => {
            // NOT the corrupt path: this overlay is intact and meaningful. Ignoring it would run
            // without hooks and groups the operator believes are persisted — security gates
            // included — so the boot caller refuses to start rather than silently disarming them.
            tracing::error!(
                path = %path.display(), overlay_version = v, understood = OVERLAY_VERSION,
                "config overlay was written by a NEWER busbar than this one"
            );
            None
        }
    }
}

/// Classified overlay read for the read-modify-WRITE path (`persist`), which — unlike the fail-soft
/// boot `read` — MUST tell "absent" (safe to start fresh) apart from "present but unreadable/corrupt"
/// (must NOT overwrite, or accumulated tombstones are lost).
pub(crate) enum OverlayReadState {
    Absent,
    // Boxed: `OverlayDoc` grew a large `root` section (1.5.0 full-config coverage), so an inline
    // variant would make the whole enum ~1 KiB regardless of the `Absent`/`Unreadable` common case
    // (clippy `large_enum_variant`). The box keeps the enum pointer-sized.
    Loaded(Box<OverlayDoc>),
    Unreadable,
    /// Written by a NEWER busbar than this one. Distinct from `Unreadable` on purpose: a corrupt
    /// overlay has lost its bytes and there is nothing to honour, but this one is intact and
    /// meaningful — silently ignoring it would run without hooks and groups the operator believes
    /// are persisted, security gates included.
    VersionTooNew(u32),
}

pub(crate) fn read_state(path: &Path) -> OverlayReadState {
    match std::fs::read(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => OverlayReadState::Absent,
        Err(_) => OverlayReadState::Unreadable,
        Ok(bytes) => match serde_json::from_slice::<Box<OverlayDoc>>(&bytes) {
            // A newer overlay may have added a section this binary drops, or changed how an existing
            // one is represented — neither is visible as a parse error, so the version is the only
            // signal. 1.5.0 is the first release that can refuse one; a binary without this check
            // never can, whatever number is stamped.
            Ok(doc) if doc.version > OVERLAY_VERSION => {
                OverlayReadState::VersionTooNew(doc.version)
            }
            Ok(doc) => OverlayReadState::Loaded(doc),
            Err(_) => OverlayReadState::Unreadable,
        },
    }
}

/// Atomically + durably write the overlay via the crate's ONE durable-write choke point
/// ([`crate::durable::write_with`]): serialize to a sibling temp, fsync its CONTENTS, rename over
/// `path`, then fsync the parent DIRECTORY — so a reader (or a crash) never observes a half-written
/// file AND a power loss cannot surface a torn/zero-length overlay after the rename. This is the
/// former reference implementation of the dance; it is now SUBSUMED (behavior identical: same temp-in-
/// same-dir, same fsync order, same empty-parent→"." resolution, same tmp cleanup on error) so a
/// future facet fix lands once, in the primitive, for every durable write.
///
/// `mode: Some(0o600)` — the overlay can carry operator-supplied credential material verbatim (e.g. a
/// postgres `store.settings.url` of the form `postgres://user:pass@host:5432/busbar`), the same class
/// of secret the signing key gets 0600 treatment for; the temp (and therefore the published overlay)
/// is created 0600 AT OPEN, so it is never briefly world-readable between write and a later chmod (no
/// TOCTOU window). `exclusive` is left at its default (`false`), unlike the signing key: the signing
/// key's `exclusive: true` guards a first-boot, predictable-path secret MINTING moment (anti-pre-plant
/// so a decoy left at that exact path is never adopted). The overlay is instead written repeatedly
/// during normal operation, and `write_with` already gives every call a per-call-unique
/// `.<name>.<pid>-<seq>.tmp` temp name, so there is no fixed, guessable temp name for a pre-planted
/// decoy to occupy in the first place — the anti-pre-plant posture would add no protection here.
pub(crate) fn write(path: &Path, doc: &OverlayDoc) -> std::io::Result<()> {
    let json = serde_json::to_vec_pretty(doc).map_err(std::io::Error::other)?;
    crate::durable::write_with(
        path,
        &json,
        crate::durable::DurableOpts {
            mode: Some(0o600),
            ..Default::default()
        },
    )
}

/// Build an overlay from a hook state (registry + global-hook names), no tombstones — a test helper
/// (the live apply path builds the doc inline in `persist` so it can carry tombstones).
#[cfg(test)]
pub(crate) fn from_state(hooks: &HashMap<String, HookCfg>, global_hooks: &[String]) -> OverlayDoc {
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
pub(crate) fn apply_root_to_deploy(deploy: &mut DeployCfg, doc: &OverlayDoc) {
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
/// first-party floor path in `busbar_plugin_sign::evaluate`). `evaluate` applies the per-name
/// first-party floor ONLY to a plugin whose manifest is actually first-party, so pinning a third-party
/// name is a harmless no-op on the first-party path (its `min_versions` entry does the work). The
/// earlier single global `first_party_floor` set to the LOWEST pin across all pins lowered the floor for
/// EVERY first-party plugin — so a rollback of plugin A could silently admit an unpinned old first-party
/// plugin B. Scoping the override to the pinned name closes that.
pub(crate) fn apply_plugin_versions_to_deploy(deploy: &mut DeployCfg, doc: &OverlayDoc) {
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
pub(crate) fn apply_named_maps_to_deploy(deploy: &mut DeployCfg, doc: &OverlayDoc) {
    use crate::config::named_map::NamedMapSection;
    for section in NamedMapSection::ALL {
        let Some(entries) = doc.named_maps.get(section.key()) else {
            continue;
        };
        for (name, patch) in entries {
            // PER-ENTRY MERGE, not replace. The stored entry is a PATCH over whatever base config
            // says for this name, so recording one field never restates the rest of the entry, and
            // a field the operator later changes in `config.yaml` keeps taking effect unless the
            // patch names it. For a name base config does not define, the target is `null` and the
            // merge degrades to exactly the replace this used to do, which is what makes the change
            // safe over every overlay already on disk.
            let mut merged = section
                .entry_as_document(deploy, name)
                .unwrap_or(serde_json::Value::Null);
            crate::config::patch::merge_entry(&mut merged, patch);
            // The MERGED document faces the one typed `deny_unknown_fields` parse, so the grammar
            // did not move: a patch is judged by the same structs `config.yaml` is, and a patch that
            // would produce an invalid entry is dropped WHOLE rather than half-applied.
            if let Err(e) = section.insert(deploy, name, &merged) {
                tracing::error!(
                    section = section.key(), entry = %name, error = %e,
                    "config overlay holds a `{}` patch that does not produce a definition this \
                     binary can parse; it is NOT applied (edit or remove it, then reload)",
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
pub(crate) struct UnparseableNamedDef {
    pub(crate) error: String,
    pub(crate) raw: serde_json::Value,
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
pub(crate) fn unparseable_named_map_entries(
    path: Option<&Path>,
    section: crate::config::named_map::NamedMapSection,
) -> BTreeMap<String, UnparseableNamedDef> {
    let mut out = BTreeMap::new();
    let Some(doc) = path.and_then(read) else {
        return out;
    };
    let Some(entries) = doc.named_maps.get(section.key()) else {
        return out;
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
    out
}

/// Apply EVERY pre-resolve overlay section that is not the `root` block — the `plugin_versions` pins
/// and the `named_maps` definitions. One function so a caller that must NOT take the overlay's `root`
/// (because it is applying a caller-supplied root, e.g. `PUT /config/settings`) still cannot forget a
/// sibling pre-resolve section; adding the next one is an edit HERE, not at six rebuild sites.
pub(crate) fn apply_pre_resolve_sections(deploy: &mut DeployCfg, doc: &OverlayDoc) {
    apply_plugin_versions_to_deploy(deploy, doc);
    apply_named_maps_to_deploy(deploy, doc);
}

/// Persist ONE named-map entry to the overlay: `Some(def)` upserts it, `None` removes it. Same
/// read-modify-WRITE durability contract as `persist`/`persist_groups`/`persist_root` — every sibling
/// section (and its tombstones) is carried forward verbatim, an unreadable overlay is REFUSED rather
/// than clobbered, and a `None` path is the LOCKED config (refuse, never a silent `Ok`).
pub(crate) fn persist_named_map(
    path: Option<&Path>,
    section: crate::config::named_map::NamedMapSection,
    name: &str,
    def: Option<&serde_json::Value>,
) -> Result<(), String> {
    let Some(p) = path else {
        return Err(NO_WRITABLE_OVERLAY_MSG.to_string());
    };
    let Some(mut doc) = load_for_rmw(p) else {
        return Err(format!(
            "could not read the overlay at '{}' to persist the `{}` section (refusing to overwrite \
             a corrupt overlay)",
            p.display(),
            section.key()
        ));
    };
    match def {
        Some(v) => {
            doc.named_maps
                .entry(section.key().to_string())
                .or_default()
                .insert(name.to_string(), v.clone());
        }
        None => {
            if let Some(entries) = doc.named_maps.get_mut(section.key()) {
                entries.remove(name);
                if entries.is_empty() {
                    doc.named_maps.remove(section.key());
                }
            }
        }
    }
    doc.version = OVERLAY_VERSION;
    write(p, &doc).map_err(|e| format!("overlay write to '{}' failed: {e}", p.display()))
}

/// Merge an overlay into the RESOLVED config (the boot-merge, run AFTER `config::resolve` - the
/// runtime hook registry is synthesized there from the inline refs, so the overlay layers on top
/// of it). Overlay hooks are inserted into the registry (an overlay hook with a base hook's name
/// WINS - the last-applied definition, which matches the live-apply semantics), overlay global
/// names are unioned into `global_hooks`, and finally TOMBSTONES (`deleted`) are subtracted - so a
/// hook the API deleted stays gone across a restart even if it was defined in base `config.yaml`.
/// Tombstones are applied LAST so a delete always wins over a stale add.
pub(crate) fn merge_into(cfg: &mut RootCfg, doc: OverlayDoc) {
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
mod config_consolidation_tests {
    use super::*;
    use crate::config::{ConfigMgmtCfg, OverlayBackend, OverlayCfg};

    fn writable_dir(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("busbar-cfgcons-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// (a) DURABLE-BY-DEFAULT: with NOTHING specified (default `ConfigMgmtCfg`) and NO
    /// `BUSBAR_CONFIG_OVERLAY` env var, a mutable config resolves to a writable overlay next to
    /// config.yaml, and an admin mutation persisted there SURVIVES a simulated restart (a fresh read).
    ///
    /// Pre-1.5.3 an unset `BUSBAR_CONFIG_OVERLAY` meant RAM-only — there was no
    /// default backend, so this durable round-trip had nowhere to land and `read` would find nothing.
    #[test]
    fn a_mutable_default_persists_across_a_simulated_restart_with_no_env_var() {
        let dir = writable_dir("durable-default");
        let config_path = dir.join("config.yaml");
        let res = resolve_backend(&ConfigMgmtCfg::default(), &config_path, None, true)
            .expect("a mutable default config must resolve a writable overlay");
        assert!(!res.locked, "default config is mutable");
        let path = res
            .path
            .expect("durable-by-default: a writable overlay next to config.yaml");
        assert_eq!(path, dir.join(DEFAULT_OVERLAY_FILENAME));

        let settings = RootSettings {
            per_request_fee: Some(7),
            ..Default::default()
        };
        persist_root(Some(&path), &settings).expect("persist must land durably");
        // Simulate a restart: read the overlay fresh from disk.
        let doc = read(&path).expect("overlay reads back after a 'restart'");
        assert_eq!(
            doc.root.and_then(|r| r.per_request_fee),
            Some(7),
            "the mutation must survive the simulated restart"
        );
    }

    /// (b) LOCKED ⇒ no overlay backend, so a persist against it is REFUSED (never a silent success).
    ///
    /// Pre-1.5.3 there was no `locked` concept and `persist_root(None, ..)` returned
    /// a silent `Ok`, so neither of these assertions could hold.
    #[test]
    fn b_locked_config_has_no_overlay_and_refuses_a_mutation() {
        let res = resolve_backend(
            &ConfigMgmtCfg {
                locked: true,
                overlay: None,
            },
            std::path::Path::new("/etc/busbar/config.yaml"),
            None,
            true,
        )
        .expect("a locked config resolves (overlay ignored)");
        assert!(res.locked);
        assert!(res.path.is_none(), "locked ⇒ no overlay backend");
        // A persist against the locked (None) backend must ERROR, not silently succeed.
        assert!(persist_root(res.path.as_deref(), &RootSettings::default()).is_err());
    }

    /// (c) BOOT INVARIANT: a MUTABLE config with the overlay explicitly DISABLED refuses (no writable
    /// backend). Also the read-only-config-dir edge case (unix): the default path is unwritable, so a
    /// mutable config refuses with an actionable message.
    ///
    /// Pre-1.5.3 nothing enforced "mutable XOR writable overlay" — a mutable config
    /// with no backend booted fine and mutated in RAM only.
    #[test]
    fn c_mutable_without_a_writable_backend_refuses() {
        let dir = writable_dir("disabled");
        let config_path = dir.join("config.yaml");
        let err = resolve_backend(
            &ConfigMgmtCfg {
                locked: false,
                overlay: Some(OverlayCfg::Disabled(false)),
            },
            &config_path,
            None,
            true,
        )
        .expect_err("mutable + overlay disabled must refuse");
        assert!(
            err.contains("config.locked") || err.contains("no writable overlay"),
            "the refusal must be actionable: {err}"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let ro = writable_dir("readonly");
            let ro_config = ro.join("config.yaml");
            std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o555)).unwrap();
            let err = resolve_backend(&ConfigMgmtCfg::default(), &ro_config, None, true)
                .expect_err("a read-only config dir must refuse a mutable config");
            assert!(
                err.contains("not writable") && err.contains("config.locked"),
                "the read-only refusal must name the fix (writable path or config.locked): {err}"
            );
            // restore so cleanup can proceed
            let _ = std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o755));
        }
    }

    /// (d) Overlay backend PRECEDENCE for the env→config migration: an explicit `config.overlay` WINS;
    /// else the deprecated `BUSBAR_CONFIG_OVERLAY` env override is honored; else the default next to
    /// config.yaml. Both the new config key AND the deprecated env fallback work.
    ///
    /// Pre-1.5.3 the ONLY source was the env var; `config.overlay` did not exist, so
    /// the "config wins" and "default next to config" cases had no code path.
    #[test]
    fn d_overlay_precedence_config_over_env_over_default() {
        let dir = writable_dir("precedence");
        let config_path = dir.join("config.yaml");
        let env = dir.join("env-overlay.json");

        // config.overlay.file wins over the env override.
        let cfg_file = ConfigMgmtCfg {
            locked: false,
            overlay: Some(OverlayCfg::Backend(OverlayBackend {
                file: Some("chosen.json".into()),
            })),
        };
        let r = resolve_backend(&cfg_file, &config_path, Some(&env), true).unwrap();
        assert_eq!(
            r.path.unwrap(),
            dir.join("chosen.json"),
            "config.overlay wins"
        );

        // No config.overlay → the deprecated env override is used (back-compat).
        let r2 =
            resolve_backend(&ConfigMgmtCfg::default(), &config_path, Some(&env), true).unwrap();
        assert_eq!(
            r2.path.unwrap(),
            env,
            "env fallback is honored when config is silent"
        );

        // Neither → default next to config.yaml.
        let r3 = resolve_backend(&ConfigMgmtCfg::default(), &config_path, None, true).unwrap();
        assert_eq!(
            r3.path.unwrap(),
            dir.join(DEFAULT_OVERLAY_FILENAME),
            "default next to config"
        );
    }

    /// (e) A BARE-FILENAME overlay (no directory component) in a writable cwd must be reported WRITABLE
    /// — so a `BUSBAR_CONFIG=config.yaml` deployment run from inside its config dir (overlay resolves to
    /// a bare `busbar-overlay.json`) BOOTS instead of being refused.
    ///
    /// The pre-fix `is_backend_writable` no-parent branch probed the not-yet-existing
    /// bare path via `OpenOptions::open` WITHOUT `.create(true)` → `NotFound` → `false` → boot refused,
    /// even though the cwd is perfectly writable.
    #[test]
    fn e_bare_filename_overlay_in_writable_cwd_is_writable() {
        // A bare filename → `parent()` is `Some("")` (empty), NOT `None`: the exact branch under test.
        let bare = std::path::PathBuf::from(format!(
            "busbar-cfgcons-bare-does-not-exist-{}.json",
            std::process::id()
        ));
        assert!(
            !bare.exists(),
            "test precondition: the bare target must not already exist"
        );
        assert!(
            is_backend_writable(&bare),
            "a bare-filename overlay in a writable cwd must probe the cwd and report writable"
        );
        // The probe is cleaned up and the bare target itself is never created (only a probe file was).
        assert!(
            !bare.exists(),
            "the writability probe must not create the overlay target file"
        );
    }

    /// (f) The `None` (LOCKED) overlay path is REFUSED by EVERY persist/reset entry point — not just
    /// `persist_root`. Guards against reverting any one of them to the pre-1.5.3 silent `Ok(())`.
    ///
    /// `clear_section(None, ..)` and `try_persist_plugin_versions(None, ..)` returned
    /// a silent `Ok(())` until this fix; reverting either to `return Ok(())` fails this test.
    #[test]
    fn f_every_persist_entry_point_refuses_a_none_locked_overlay() {
        let empty_names: std::collections::HashSet<String> = std::collections::HashSet::new();
        assert!(
            persist(
                None,
                &HashMap::<String, HookCfg>::new(),
                &[],
                None,
                None,
                &empty_names,
            )
            .is_err(),
            "persist(None) must refuse (hooks)"
        );
        assert!(
            persist_groups(
                None,
                &BTreeMap::<String, GroupCfg>::new(),
                None,
                None,
                &empty_names,
            )
            .is_err(),
            "persist_groups(None) must refuse (groups)"
        );
        assert!(
            persist_root(None, &RootSettings::default()).is_err(),
            "persist_root(None) must refuse (settings)"
        );
        assert!(
            clear_section(None, OverlaySection::Hooks).is_err(),
            "clear_section(None) must refuse (per-section reset)"
        );
        assert!(
            try_persist_plugin_versions(None, &BTreeMap::<String, String>::new()).is_err(),
            "try_persist_plugin_versions(None) must refuse (rollback pin)"
        );
    }
}

#[cfg(test)]
mod version_gate_tests {
    use super::*;

    /// An overlay from a NEWER busbar is refused, both for reading and for writing. It is intact and
    /// meaningful — unlike a corrupt one — so ignoring it would run with the operator's
    /// API-registered hooks and groups silently absent, security gates included. 1.5.0 is the first
    /// release that can refuse one at all: a binary without this check never will, whatever version
    /// a future overlay stamps.
    #[test]
    fn an_overlay_from_a_newer_busbar_is_refused_not_ignored() {
        let dir = std::env::temp_dir().join(format!("busbar-overlay-vgate-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("overlay.json");
        std::fs::write(
            &path,
            serde_json::json!({
                "version": OVERLAY_VERSION + 1,
                "hooks": { "gate": { "kind": "gate", "plugin": "x" } }
            })
            .to_string(),
        )
        .unwrap();

        assert!(
            matches!(read_state(&path), OverlayReadState::VersionTooNew(v) if v == OVERLAY_VERSION + 1),
            "a newer overlay is classified distinctly from corrupt"
        );
        assert!(
            read(&path).is_none(),
            "and is not merged onto the resolved config"
        );
        assert!(
            load_for_rmw(&path).is_none(),
            "and is never overwritten — a write would discard what this binary cannot represent"
        );

        // The current version still loads, so the gate is a ceiling and not a wall.
        std::fs::write(
            &path,
            serde_json::json!({ "version": OVERLAY_VERSION, "hooks": {} }).to_string(),
        )
        .unwrap();
        assert!(read(&path).is_some(), "the understood version still loads");

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gate() -> HookCfg {
        serde_json::from_value(serde_json::json!({
            "kind": "gate", "plugin": "test-hook", "prompt": "rw", "global": true
        }))
        .unwrap()
    }

    /// write → read round-trips the overlay through the filesystem (atomic write, fail-soft read).
    #[test]
    fn write_read_round_trip() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("busbar-overlay-test-{}.json", std::process::id()));
        let doc = from_state(
            &HashMap::from([("compress".to_string(), gate())]),
            &["compress".to_string()],
        );
        write(&path, &doc).expect("atomic write");
        let read_back = read(&path).expect("read back");
        assert!(read_back.hooks.contains_key("compress"));
        assert_eq!(read_back.global_hooks, vec!["compress".to_string()]);
        // No durable temp for THIS target (`.<file-name>.<pid>-<seq>.tmp`, the primitive's unique
        // naming) must linger after a successful write — the rename consumed it, and the RAII guard
        // leaves nothing to accumulate. (Scan by our unique file-name prefix; the temp_dir is shared.)
        let file_name = path.file_name().unwrap().to_string_lossy().into_owned();
        let no_durable_temp = || {
            let prefix = format!(".{file_name}.");
            !std::fs::read_dir(&dir).unwrap().any(|e| {
                let n = e.unwrap().file_name();
                let n = n.to_string_lossy();
                n.starts_with(&prefix) && n.ends_with(".tmp")
            })
        };
        assert!(no_durable_temp(), "no durable temp should remain");
        // A pre-existing stale temp from a prior crashed run (a foreign name under the primitive's
        // per-call-unique naming) must NOT wedge the next write — it is simply ignored.
        std::fs::write(path.with_extension("overlay.tmp"), b"stale").unwrap();
        write(&path, &doc).expect("write despite a pre-existing stale temp");
        assert!(no_durable_temp(), "no durable temp should remain");
        let _ = std::fs::remove_file(path.with_extension("overlay.tmp"));
        let _ = std::fs::remove_file(&path);
    }

    /// The overlay can carry operator-supplied credential material verbatim (e.g. a postgres
    /// `store.settings.url` of `postgres://user:pass@host:5432/busbar`), so `write` must publish it
    /// 0600 (owner read/write only) rather than at OS/umask-default permissions (typically 0644,
    /// world-readable) — the same posture the signing key gets, and for the same reason.
    #[test]
    #[cfg(unix)]
    fn write_is_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "busbar-overlay-perm-test-{}.json",
            std::process::id()
        ));
        let doc = from_state(
            &HashMap::from([("compress".to_string(), gate())]),
            &["compress".to_string()],
        );
        write(&path, &doc).expect("atomic write");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "overlay file must be 0600 (credential-bearing), got {mode:#o}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// A missing or corrupt overlay is fail-soft (None), never a panic.
    #[test]
    fn read_absent_or_corrupt_is_none() {
        assert!(read(Path::new("/nonexistent/busbar-overlay-xyz.json")).is_none());
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "busbar-overlay-corrupt-{}.json",
            std::process::id()
        ));
        std::fs::write(&path, b"{ this is not json").unwrap();
        assert!(
            read(&path).is_none(),
            "a corrupt overlay must not brick boot"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// A minimal RESOLVED config to merge overlays into (providers/models empty; registry empty).
    fn minimal_cfg() -> RootCfg {
        let deploy: super::super::DeployCfg =
            serde_json::from_value(serde_json::json!({"providers": {}, "models": {}})).unwrap();
        super::super::resolve(&deploy, &HashMap::new()).expect("minimal config resolves")
    }

    /// merge_into adds overlay hooks to the resolved registry + unions global names; an overlay
    /// hook with a base hook's name wins.
    #[test]
    fn merge_into_deploy() {
        let mut cfg = minimal_cfg();
        cfg.hooks.insert("base_hook".to_string(), gate());
        let doc = from_state(
            &HashMap::from([
                ("base_hook".to_string(), gate()), // same name as a base hook → overlay wins
                ("api_hook".to_string(), gate()),
            ]),
            &["api_hook".to_string(), "base_hook".to_string()],
        );
        cfg.global_hooks.push("base_hook".to_string());
        merge_into(&mut cfg, doc);
        assert!(cfg.hooks.contains_key("api_hook"));
        assert!(cfg.hooks.contains_key("base_hook"));
        // global_hooks unioned, no duplicate of base_hook.
        assert_eq!(
            cfg.global_hooks
                .iter()
                .filter(|g| *g == "base_hook")
                .count(),
            1,
            "global union does not duplicate"
        );
        assert!(cfg.global_hooks.iter().any(|g| g == "api_hook"));
    }

    /// TOMBSTONE: a hook the API deleted (recorded in `deleted`) is removed from the effective config at
    /// boot even if it was defined in base config.yaml — so an API deletion survives a restart.
    #[test]
    fn merge_into_applies_tombstones() {
        let mut cfg = minimal_cfg();
        cfg.hooks.insert("base_hook".to_string(), gate());
        cfg.global_hooks.push("base_hook".to_string());
        let doc = OverlayDoc {
            hooks: HashMap::new(),
            global_hooks: Vec::new(),
            deleted: vec!["base_hook".to_string()],
            ..Default::default()
        };
        merge_into(&mut cfg, doc);
        assert!(
            !cfg.hooks.contains_key("base_hook"),
            "a tombstoned base hook is removed from the effective config"
        );
        assert!(!cfg.global_hooks.iter().any(|g| g == "base_hook"));
    }

    /// REGRESSION: `persist` must NOT overwrite a present-but-unreadable/corrupt overlay — that would
    /// drop accumulated deletion tombstones and silently resurrect a deleted hook on restart.
    #[test]
    fn persist_refuses_to_overwrite_unreadable_overlay() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "busbar-overlay-corrupt-persist-{}.json",
            std::process::id()
        ));
        let corrupt = b"{ this is not valid json and may hide tombstones";
        std::fs::write(&path, corrupt).unwrap();
        let err = persist(
            Some(&path),
            &HashMap::from([("newhook".to_string(), gate())]),
            &["newhook".to_string()],
            Some("deleteme"),
            None,
            &std::collections::HashSet::new(),
        );
        assert!(
            err.is_err(),
            "persisting onto a corrupt overlay must FAIL CLOSED (refuse), not silently proceed"
        );
        let raw = std::fs::read(&path).expect("file still present");
        assert_eq!(
            raw, corrupt,
            "persist must preserve an unreadable overlay verbatim"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// A WHOLESALE registry write (config rollback passes both tombstone
    /// args `None`) must reconcile away any tombstone for a name that the restored registry
    /// contains — otherwise the boot-merge inserts the hook then subtracts it, and the rollback
    /// silently vanishes on the next restart. `persist` retains only tombstones whose name is
    /// ABSENT from the persisted registry.
    #[test]
    fn persist_reconciles_tombstone_against_present_hook() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("busbar-overlay-recon-{}.json", std::process::id()));
        // Seed a prior overlay that tombstoned "x" (an earlier API delete).
        write(
            &path,
            &OverlayDoc {
                hooks: HashMap::new(),
                global_hooks: Vec::new(),
                deleted: vec!["x".to_string()],
                ..Default::default()
            },
        )
        .unwrap();
        // Rollback restores a registry that CONTAINS "x", persisting with both tombstone args None.
        persist(
            Some(&path),
            &HashMap::from([("x".to_string(), gate())]),
            &["x".to_string()],
            None,
            None,
            &std::collections::HashSet::new(),
        )
        .expect("persist");
        let doc = read(&path).expect("read back");
        assert!(
            !doc.deleted.iter().any(|n| n == "x"),
            "a restored hook must not remain tombstoned, or it vanishes on restart"
        );
        // And it survives the boot merge (inserted, not subtracted).
        let mut cfg = minimal_cfg();
        merge_into(&mut cfg, doc);
        assert!(
            cfg.hooks.contains_key("x"),
            "rollback is durable across restart"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// REGRESSION: a tombstone for a name that is ABSENT from base `config.yaml` (never defined there,
    /// or since removed from it) can never be reconciled by the "name comes back" rule — nothing will
    /// ever re-add it as a HOOK, since the boot-merge only inserts base-config names. Such a tombstone
    /// is permanently inert dead weight and must be pruned at persist time. A tombstone whose name IS
    /// still in base config is kept (it is still actively shadowing that base entry).
    #[test]
    fn persist_prunes_tombstone_for_a_name_absent_from_base_config() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("busbar-ovl-prune-hook-{}.json", std::process::id()));
        write(
            &path,
            &OverlayDoc {
                hooks: HashMap::new(),
                global_hooks: Vec::new(),
                deleted: vec!["ghost".to_string(), "shadowed_base".to_string()],
                ..Default::default()
            },
        )
        .unwrap();
        let base_hook_names: std::collections::HashSet<String> =
            ["shadowed_base".to_string()].into_iter().collect();
        persist(
            Some(&path),
            &HashMap::from([("newhook".to_string(), gate())]),
            &["newhook".to_string()],
            None,
            None,
            &base_hook_names,
        )
        .expect("persist");
        let doc = read(&path).expect("read back");
        assert!(
            !doc.deleted.iter().any(|n| n == "ghost"),
            "a tombstone for a name absent from base config.yaml is permanently inert and must be \
             pruned: {:?}",
            doc.deleted
        );
        assert!(
            doc.deleted.iter().any(|n| n == "shadowed_base"),
            "a tombstone for a name STILL in base config must be kept (it still shadows it): {:?}",
            doc.deleted
        );
        let _ = std::fs::remove_file(&path);
    }

    fn group_with_budget() -> GroupCfg {
        serde_json::from_value(serde_json::json!({
            "limits": [ { "budget": 1000, "per": "month" } ]
        }))
        .unwrap()
    }

    /// merge_into inserts overlay groups (an overlay group with a base group's name wins) and applies
    /// group tombstones LAST — an API-deleted group stays gone even if base config.yaml defined it.
    #[test]
    fn merge_into_groups_and_group_tombstones() {
        let mut cfg = minimal_cfg();
        cfg.groups.insert("team".to_string(), group_with_budget());
        cfg.groups.insert("doomed".to_string(), group_with_budget());
        let doc = OverlayDoc {
            groups: BTreeMap::from([("user:alice".to_string(), group_with_budget())]),
            deleted_groups: vec!["doomed".to_string()],
            ..Default::default()
        };
        merge_into(&mut cfg, doc);
        assert!(cfg.groups.contains_key("user:alice"), "overlay group added");
        assert!(cfg.groups.contains_key("team"), "base group untouched");
        assert!(
            !cfg.groups.contains_key("doomed"),
            "tombstoned group removed even though base defined it"
        );
    }

    /// REGRESSION: a HOOK write must PRESERVE the groups section + its tombstones — the read-modify-write
    /// loads the whole doc and mutates only the hook section. Guards against "persist rebuilds the doc
    /// inline and silently drops groups".
    #[test]
    fn persist_hook_preserves_groups_section() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("busbar-ovl-preserve-{}.json", std::process::id()));
        write(
            &path,
            &OverlayDoc {
                groups: BTreeMap::from([("user:bob".to_string(), group_with_budget())]),
                deleted_groups: vec!["oldteam".to_string()],
                ..Default::default()
            },
        )
        .unwrap();
        persist(
            Some(&path),
            &HashMap::from([("h".to_string(), gate())]),
            &["h".to_string()],
            None,
            None,
            &std::collections::HashSet::new(),
        )
        .expect("persist");
        let doc = read(&path).expect("read back");
        assert!(doc.hooks.contains_key("h"), "hook written");
        assert!(
            doc.groups.contains_key("user:bob"),
            "groups section preserved across a hook write"
        );
        assert!(
            doc.deleted_groups.iter().any(|n| n == "oldteam"),
            "group tombstones preserved across a hook write"
        );
        assert_eq!(
            doc.version, OVERLAY_VERSION,
            "schema version stamped on write"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// Symmetric: a GROUP write preserves the hooks section, and reconciles away a group tombstone for a
    /// name the written registry contains (wholesale-rollback safety, mirroring the hook path's c1r5 fix).
    #[test]
    fn persist_groups_preserves_hooks_and_reconciles_tombstone() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("busbar-ovl-gpreserve-{}.json", std::process::id()));
        write(
            &path,
            &OverlayDoc {
                hooks: HashMap::from([("keepme".to_string(), gate())]),
                deleted_groups: vec!["x".to_string()],
                ..Default::default()
            },
        )
        .unwrap();
        // Persist a group registry that CONTAINS "x" (a rollback), both tombstone args None.
        persist_groups(
            Some(&path),
            &BTreeMap::from([("x".to_string(), group_with_budget())]),
            None,
            None,
            &std::collections::HashSet::new(),
        )
        .expect("persist groups");
        let doc = read(&path).expect("read back");
        assert!(
            doc.hooks.contains_key("keepme"),
            "hooks section preserved across a group write"
        );
        assert!(doc.groups.contains_key("x"), "group written");
        assert!(
            !doc.deleted_groups.iter().any(|n| n == "x"),
            "tombstone reconciled away for a restored group, else it vanishes on restart"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// REGRESSION (groups half of the hook test above): a group tombstone for a name absent from base
    /// `config.yaml` can never come back via the "name comes back" reconciliation (nothing re-adds a
    /// non-base name at boot), so it is permanently inert and must be pruned at persist time. A
    /// tombstone for a name still in base config is kept.
    #[test]
    fn persist_groups_prunes_tombstone_for_a_name_absent_from_base_config() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "busbar-ovl-prune-group-{}.json",
            std::process::id()
        ));
        write(
            &path,
            &OverlayDoc {
                deleted_groups: vec!["ghost_group".to_string(), "shadowed_base_group".to_string()],
                ..Default::default()
            },
        )
        .unwrap();
        let base_group_names: std::collections::HashSet<String> =
            ["shadowed_base_group".to_string()].into_iter().collect();
        persist_groups(
            Some(&path),
            &BTreeMap::from([("newgroup".to_string(), group_with_budget())]),
            None,
            None,
            &base_group_names,
        )
        .expect("persist groups");
        let doc = read(&path).expect("read back");
        assert!(
            !doc.deleted_groups.iter().any(|n| n == "ghost_group"),
            "a group tombstone for a name absent from base config.yaml is permanently inert and \
             must be pruned: {:?}",
            doc.deleted_groups
        );
        assert!(
            doc.deleted_groups
                .iter()
                .any(|n| n == "shadowed_base_group"),
            "a group tombstone for a name STILL in base config must be kept: {:?}",
            doc.deleted_groups
        );
        let _ = std::fs::remove_file(&path);
    }

    /// `OverlaySection::parse` is the ONE valid-name gate: `groups`/`hooks` round-trip, everything
    /// else is `None` (the reset endpoint 400s on it).
    #[test]
    fn overlay_section_parse_round_trips_and_rejects() {
        assert_eq!(
            OverlaySection::parse("groups"),
            Some(OverlaySection::Groups)
        );
        assert_eq!(OverlaySection::parse("hooks"), Some(OverlaySection::Hooks));
        assert_eq!(OverlaySection::parse("root"), Some(OverlaySection::Root));
        assert_eq!(OverlaySection::Groups.as_str(), "groups");
        assert_eq!(OverlaySection::Hooks.as_str(), "hooks");
        assert_eq!(OverlaySection::Root.as_str(), "root");
        for bad in ["", "Groups", "hook", "auth", "plugins", "groups/", "Root"] {
            assert!(
                OverlaySection::parse(bad).is_none(),
                "`{bad}` is not a section"
            );
        }
    }

    /// `clear_section(Groups)` wipes the groups entries + tombstones and leaves the hooks section
    /// (and its tombstones) untouched — the per-section reset invariant.
    #[test]
    fn clear_section_wipes_one_section_only() {
        let mut doc = OverlayDoc {
            hooks: HashMap::from([("h".to_string(), gate())]),
            global_hooks: vec!["h".to_string()],
            deleted: vec!["gonehook".to_string()],
            groups: BTreeMap::from([("user:alice".to_string(), group_with_budget())]),
            deleted_groups: vec!["gonegroup".to_string()],
            ..Default::default()
        };
        doc.clear_section(OverlaySection::Groups);
        assert!(doc.groups.is_empty(), "groups entries cleared");
        assert!(doc.deleted_groups.is_empty(), "group tombstones cleared");
        assert!(doc.hooks.contains_key("h"), "hooks section preserved");
        assert_eq!(
            doc.global_hooks,
            vec!["h".to_string()],
            "global wiring preserved"
        );
        assert_eq!(
            doc.deleted,
            vec!["gonehook".to_string()],
            "hook tombstones preserved"
        );
        // And the symmetric case.
        doc.clear_section(OverlaySection::Hooks);
        assert!(doc.hooks.is_empty() && doc.global_hooks.is_empty() && doc.deleted.is_empty());
    }

    /// `section_is_empty` is true only when a section carries neither entries nor tombstones — the
    /// idempotent-no-op predicate the reset handler short-circuits on.
    #[test]
    fn section_is_empty_tracks_entries_and_tombstones() {
        let empty = OverlayDoc::default();
        assert!(empty.section_is_empty(OverlaySection::Groups));
        assert!(empty.section_is_empty(OverlaySection::Hooks));
        // A lone tombstone (no live entry) still counts as non-empty (a base deletion to revert).
        let tombstoned = OverlayDoc {
            deleted_groups: vec!["x".to_string()],
            deleted: vec!["y".to_string()],
            ..Default::default()
        };
        assert!(!tombstoned.section_is_empty(OverlaySection::Groups));
        assert!(!tombstoned.section_is_empty(OverlaySection::Hooks));
    }

    /// The DURABLE half of a reset: `clear_section` on disk wipes one section + preserves the other,
    /// exactly like the read-modify-write persist paths. Guards "reset drops the sibling section".
    #[test]
    fn clear_section_persist_preserves_sibling() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("busbar-ovl-clearsect-{}.json", std::process::id()));
        write(
            &path,
            &OverlayDoc {
                hooks: HashMap::from([("keepme".to_string(), gate())]),
                deleted: vec!["keephook_tomb".to_string()],
                groups: BTreeMap::from([("user:zap".to_string(), group_with_budget())]),
                deleted_groups: vec!["zap_tomb".to_string()],
                ..Default::default()
            },
        )
        .unwrap();
        clear_section(Some(&path), OverlaySection::Groups).expect("clear groups section");
        let doc = read(&path).expect("read back");
        assert!(
            doc.groups.is_empty() && doc.deleted_groups.is_empty(),
            "groups reset on disk"
        );
        assert!(
            doc.hooks.contains_key("keepme"),
            "hooks entries survive the groups reset"
        );
        assert_eq!(
            doc.deleted,
            vec!["keephook_tomb".to_string()],
            "hook tombstones survive"
        );
        assert_eq!(doc.version, OVERLAY_VERSION, "schema version stamped");
        let _ = std::fs::remove_file(&path);
    }

    /// A section reset must REFUSE to overwrite a present-but-corrupt overlay (clearing it would drop
    /// the sibling section's tombstones), mirroring the persist paths' fail-closed posture.
    #[test]
    fn clear_section_refuses_to_overwrite_corrupt_overlay() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "busbar-ovl-clearcorrupt-{}.json",
            std::process::id()
        ));
        let corrupt = b"{ not valid json hiding tombstones";
        std::fs::write(&path, corrupt).unwrap();
        assert!(
            clear_section(Some(&path), OverlaySection::Groups).is_err(),
            "clearing a section on a corrupt overlay must FAIL CLOSED (refuse), not clobber it"
        );
        let raw = std::fs::read(&path).expect("still present");
        assert_eq!(
            raw, corrupt,
            "a corrupt overlay is preserved verbatim, never clobbered"
        );
        let _ = std::fs::remove_file(&path);
    }

    // ── ROOT section (1.5.0 full-config coverage) ─────────────────────────────────────────────

    /// A minimal base `DeployCfg` (all uncovered sections at their defaults) to apply root overrides
    /// onto. Uses the real YAML parse path so the defaults match production exactly.
    fn minimal_deploy() -> DeployCfg {
        serde_yaml::from_str("providers: {}\nmodels: {}\n").expect("minimal deploy parses")
    }

    /// A `RootSettings` naming a couple of overrides, parsed from JSON exactly as the API body would.
    fn sample_root() -> RootSettings {
        serde_json::from_value(serde_json::json!({
            "listen": "0.0.0.0:9000",
            "per_request_fee": 7,
            "rate_card": { "m0": { "input_utok": 1.5, "output_utok": 2.0 } },
            "limits": { "max_inbound_concurrent": 512 }
        }))
        .expect("root settings parse")
    }

    /// `apply_to_deploy` overwrites ONLY the named fields; unset fields keep base values.
    #[test]
    fn root_apply_overwrites_only_named_fields() {
        let mut deploy = minimal_deploy();
        let base_admin_listen = deploy.admin_listen.clone();
        // NON-DEFAULT base values, or this test cannot see the defect it guards: with an
        // all-defaults base a whole-section clobber is indistinguishable from a per-field merge,
        // which is why it passed for as long as the bug existed.
        deploy.limits.upstream_request_timeout_secs = 30;
        deploy.limits.request_body_max_bytes = 1_048_576;
        sample_root().apply_to_deploy(&mut deploy);
        assert_eq!(
            deploy.limits.upstream_request_timeout_secs, 30,
            "a limits field the overlay never names keeps the operator's value"
        );
        assert_eq!(
            deploy.limits.request_body_max_bytes, 1_048_576,
            "including a deliberately tightened body cap"
        );
        assert_eq!(deploy.listen, "0.0.0.0:9000", "listen overridden");
        assert_eq!(deploy.per_request_fee, 7, "fee overridden");
        assert_eq!(
            deploy.limits.max_inbound_concurrent, 512,
            "a limits field overridden"
        );
        assert!(
            deploy
                .rate_card
                .as_ref()
                .is_some_and(|rc| rc.contains_key("m0")),
            "rate_card overridden"
        );
        assert_eq!(
            deploy.admin_listen, base_admin_listen,
            "an unset field keeps its base value"
        );
    }

    /// `is_empty` / `section_is_empty(Root)` track whether any override is set.
    #[test]
    fn root_is_empty_tracks_overrides() {
        assert!(RootSettings::default().is_empty());
        assert!(OverlayDoc::default().section_is_empty(OverlaySection::Root));
        let doc = OverlayDoc {
            root: Some(sample_root()),
            ..Default::default()
        };
        assert!(!doc.section_is_empty(OverlaySection::Root));
        // A root override does not make hooks/groups non-empty (independent sections).
        assert!(doc.section_is_empty(OverlaySection::Hooks));
        assert!(doc.section_is_empty(OverlaySection::Groups));
    }

    /// `persist_root` round-trips the root section AND preserves the hooks + groups sections; storing
    /// an empty `RootSettings` clears the section back to `None`.
    #[test]
    fn persist_root_round_trips_and_preserves_siblings() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("busbar-ovl-root-{}.json", std::process::id()));
        write(
            &path,
            &OverlayDoc {
                hooks: HashMap::from([("keepme".to_string(), gate())]),
                groups: BTreeMap::from([("user:z".to_string(), group_with_budget())]),
                deleted_groups: vec!["oldteam".to_string()],
                ..Default::default()
            },
        )
        .unwrap();
        persist_root(Some(&path), &sample_root()).expect("persist root");
        let doc = read(&path).expect("read back");
        assert!(
            doc.root
                .as_ref()
                .is_some_and(|r| r.per_request_fee == Some(7)),
            "root section written"
        );
        assert!(doc.hooks.contains_key("keepme"), "hooks preserved");
        assert!(doc.groups.contains_key("user:z"), "groups preserved");
        assert_eq!(
            doc.deleted_groups,
            vec!["oldteam".to_string()],
            "group tombstones preserved"
        );
        // Storing an empty root clears the section.
        persist_root(Some(&path), &RootSettings::default()).expect("persist empty root");
        let doc = read(&path).expect("read back after clear");
        assert!(doc.root.is_none(), "empty root clears the section");
        assert!(doc.hooks.contains_key("keepme"), "hooks still preserved");
        let _ = std::fs::remove_file(&path);
    }

    /// `clear_section(Root)` wipes only the root override; the hooks/groups sections survive. And the
    /// on-disk `clear_section` refuses a corrupt overlay (fail-closed, like the sibling sections).
    #[test]
    fn clear_root_section_only() {
        let mut doc = OverlayDoc {
            hooks: HashMap::from([("h".to_string(), gate())]),
            root: Some(sample_root()),
            ..Default::default()
        };
        doc.clear_section(OverlaySection::Root);
        assert!(doc.root.is_none(), "root cleared");
        assert!(doc.hooks.contains_key("h"), "hooks preserved");
    }

    /// `apply_root_to_deploy` is a no-op when the overlay has no root override, and applies it when
    /// present — the pre-resolve boot-merge half.
    #[test]
    fn apply_root_to_deploy_noop_and_active() {
        let mut deploy = minimal_deploy();
        apply_root_to_deploy(&mut deploy, &OverlayDoc::default());
        assert_eq!(
            deploy.per_request_fee, 0,
            "no root override → base unchanged"
        );
        let doc = OverlayDoc {
            root: Some(sample_root()),
            ..Default::default()
        };
        apply_root_to_deploy(&mut deploy, &doc);
        assert_eq!(deploy.per_request_fee, 7, "root override applied");
    }

    /// An unknown key in a root-settings body is a loud reject (`deny_unknown_fields`), never a silent
    /// no-op — the same fail-closed posture as the DeployCfg surface.
    #[test]
    fn root_settings_rejects_unknown_field() {
        let r: Result<RootSettings, _> =
            serde_json::from_value(serde_json::json!({ "lissten": "0.0.0.0:9000" }));
        assert!(r.is_err(), "a typo'd root field is rejected");
    }

    /// PLUGIN VERSION PINS (1.5.0 rollback-friendly versioning): a `plugin_versions` pin lowers BOTH
    /// the per-name `min_versions` floor (third-party path) AND a PER-NAME `first_party_floors` entry
    /// (first-party path) when applied to a base `DeployCfg`. Each pin scopes its first-party
    /// override to its own name — there is no single global floor lowered for every first-party plugin.
    #[test]
    fn plugin_versions_pins_lower_the_floors() {
        let mut deploy = minimal_deploy();
        // Base has a higher floor and no first-party floor override (the automatic default).
        deploy
            .plugins
            .min_versions
            .insert("acme-store-x".to_string(), "2.0.0".to_string());
        assert!(deploy.plugins.first_party_floors.is_empty());

        let doc = OverlayDoc {
            plugin_versions: BTreeMap::from([
                ("acme-store-x".to_string(), "1.4.0".to_string()),
                (
                    "busbar-store-valkey-plugin".to_string(),
                    "1.5.0".to_string(),
                ),
            ]),
            ..Default::default()
        };
        apply_plugin_versions_to_deploy(&mut deploy, &doc);

        assert_eq!(
            deploy
                .plugins
                .min_versions
                .get("acme-store-x")
                .map(String::as_str),
            Some("1.4.0"),
            "the third-party floor is LOWERED to the pinned version"
        );
        // PER-NAME first-party floor overrides: each pinned name gets exactly its pinned version;
        // there is no global floor, so an unpinned first-party plugin is unaffected.
        assert_eq!(
            deploy
                .plugins
                .first_party_floors
                .get("acme-store-x")
                .map(String::as_str),
            Some("1.4.0"),
        );
        assert_eq!(
            deploy
                .plugins
                .first_party_floors
                .get("busbar-store-valkey-plugin")
                .map(String::as_str),
            Some("1.5.0"),
        );
    }

    /// No pins ⇒ no per-name floor overrides (the automatic posture is untouched): `apply_root_to_deploy`
    /// (which also applies pins) leaves `first_party_floors` EMPTY when the overlay carries no pins, so
    /// every first-party plugin keeps the binary's own version as its floor.
    #[test]
    fn no_pins_leaves_first_party_floor_none() {
        let mut deploy = minimal_deploy();
        apply_root_to_deploy(&mut deploy, &OverlayDoc::default());
        assert!(
            deploy.plugins.first_party_floors.is_empty(),
            "with no pins the automatic first-party floor stands"
        );
    }

    /// `try_persist_plugin_versions` round-trips the pin map AND preserves the hooks/groups/root
    /// sections; storing an empty map clears the section (every pin lifted → the base floors return).
    #[test]
    fn persist_plugin_versions_round_trips_and_preserves_siblings() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("busbar-ovl-pins-{}.json", std::process::id()));
        write(
            &path,
            &OverlayDoc {
                hooks: HashMap::from([("keepme".to_string(), gate())]),
                root: Some(sample_root()),
                ..Default::default()
            },
        )
        .unwrap();
        let pins = BTreeMap::from([("acme-store-x".to_string(), "1.4.0".to_string())]);
        try_persist_plugin_versions(Some(&path), &pins).unwrap();
        let doc = read(&path).expect("read back");
        assert_eq!(
            doc.plugin_versions.get("acme-store-x").map(String::as_str),
            Some("1.4.0"),
            "pin persisted"
        );
        assert!(doc.hooks.contains_key("keepme"), "hooks preserved");
        assert!(doc.root.is_some(), "root preserved");
        assert!(
            !doc.section_is_empty(OverlaySection::PluginVersions),
            "the pin section is non-empty"
        );

        // Clearing the pins restores the base floors and preserves siblings.
        try_persist_plugin_versions(Some(&path), &BTreeMap::new()).unwrap();
        let doc = read(&path).expect("read back after clear");
        assert!(doc.plugin_versions.is_empty(), "pins cleared");
        assert!(doc.hooks.contains_key("keepme"), "hooks still preserved");
        assert!(
            doc.section_is_empty(OverlaySection::PluginVersions),
            "the pin section is empty after clear"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// `clear_section(PluginVersions)` wipes only the pins; the other sections survive — the durable
    /// half of `DELETE /api/v1/admin/overlay/plugin_versions` (lift every rollback pin).
    #[test]
    fn clear_plugin_versions_section_only() {
        let mut doc = OverlayDoc {
            hooks: HashMap::from([("h".to_string(), gate())]),
            plugin_versions: BTreeMap::from([("p".to_string(), "1.0.0".to_string())]),
            ..Default::default()
        };
        doc.clear_section(OverlaySection::PluginVersions);
        assert!(doc.plugin_versions.is_empty(), "pins cleared");
        assert!(doc.hooks.contains_key("h"), "hooks preserved");
    }

    /// The `plugin_versions` path segment parses to the section and round-trips its label.
    #[test]
    fn plugin_versions_section_parses() {
        assert_eq!(
            OverlaySection::parse("plugin_versions"),
            Some(OverlaySection::PluginVersions)
        );
        assert_eq!(OverlaySection::PluginVersions.as_str(), "plugin_versions");
    }
}
