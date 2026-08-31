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

use crate::diagnostics::{
    diag_error, diag_warn, CONFIG_OVERLAY_CORRUPT_BASE_ONLY, CONFIG_OVERLAY_CORRUPT_REFUSE_WRITE,
    CONFIG_OVERLAY_NOT_WRITABLE, CONFIG_OVERLAY_PATCH_UNPARSABLE, CONFIG_OVERLAY_PROBE_LEAK,
    CONFIG_OVERLAY_VERSION_TOO_NEW, CONFIG_OVERLAY_VERSION_TOO_NEW_RMW,
};

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
    /// The writable file-backend path when the config is MUTABLE and its backend is writable; `None`
    /// when locked, and `None` when the config is mutable but its backend turned out to be UNWRITABLE
    /// (see `read_only_backend`). The boot invariant is therefore
    /// `(locked || read_only_backend) == path.is_none()` for a config that BOOTED.
    pub(crate) path: Option<PathBuf>,
    /// `true` ⇒ the config did NOT declare `config.locked: true`, but the resolved overlay backend is
    /// not writable on this filesystem — the classic case being a config directory mounted read-only
    /// (`docker run -v ./config.yaml:/etc/busbar/config.yaml:ro`). Busbar boots and serves, but with
    /// NO durable config overlay: every admin-API config mutation is refused up front with
    /// [`NO_WRITABLE_OVERLAY_MSG`] rather than applying in RAM and silently reverting on restart. The
    /// operator is told loudly at boot. Never `true` when `locked` is `true`.
    pub(crate) read_only_backend: bool,
}

/// Resolve the config-management posture + overlay backend from the `config:` block (1.5.3), enforcing
/// the BOOT INVARIANT: no snapshot ever carries a backend path it cannot durably write. What the
/// invariant actually protects against is a mutation that applies in RAM only and silently reverts on
/// restart; it is satisfied by handing back `path: None` (which makes every admin-API config mutation
/// refuse up front with [`NO_WRITABLE_OVERLAY_MSG`]), and does NOT require refusing to boot.
///
/// So the two "mutable but no usable backend" states are treated differently, on purpose:
///
/// * `config.overlay: false` on a mutable config is a SELF-CONTRADICTORY config the operator wrote by
///   hand ("mutable, and also no place to store mutations"). It stays a boot `Err`, because the only
///   way to reach it is to have typed it, and the fix is to edit the file.
/// * An overlay backend that is not WRITABLE is a property of the ENVIRONMENT, not of the config: a
///   read-only config mount is a legitimate and common hardening choice, and the documented Docker
///   quickstart uses exactly that (`-v "$PWD/config.yaml:/etc/busbar/config.yaml:ro"`). Refusing to
///   boot for it means a hardened deployment cannot serve traffic at all, which is a far worse
///   outcome than serving with the admin-API config mutations disabled. This degrades: it warns
///   loudly, sets `read_only_backend`, and returns `path: None`.
///
/// Precedence for a mutable config's backend path: an explicit `config.overlay` wins; else the default
/// `busbar-overlay.json` next to the resolved config.yaml. (The `BUSBAR_CONFIG_OVERLAY` env var was
/// deprecated in 1.5.3 and removed in 1.6.0.) `probe_fs` gates the filesystem writability check —
/// `true` at boot/reload (so a read-only config dir refuses to boot), `false` for `--validate` (which
/// must have zero side effects and may run away from the target filesystem).
pub(crate) fn resolve_backend(
    cfg: &ConfigMgmtCfg,
    config_path: &Path,
    probe_fs: bool,
) -> Result<OverlayResolution, String> {
    if cfg.locked {
        // Immutable/GitOps: the overlay is irrelevant and ignored; runtime mutations are refused.
        return Ok(OverlayResolution {
            locked: true,
            path: None,
            read_only_backend: false,
        });
    }
    let config_dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    // MUTABLE: resolve the backend path (config wins > default next to config.yaml).
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
        None => Some(config_dir.join(DEFAULT_OVERLAY_FILENAME)),
    };
    let Some(p) = path else {
        return Err("config is mutable (config.locked: false) but has no writable overlay backend — \
                    `config.overlay` is disabled, so an admin-API config change could not be stored \
                    and would silently revert on restart. Give it a backend (`config.overlay.file: \
                    <path>`), or set `config.locked: true` for an immutable deployment."
            .to_string());
    };
    if probe_fs && !is_backend_writable(&p) {
        // DEGRADE, do not refuse to boot. A read-only config directory is a hardening choice, not a
        // config error, and a gateway that will not start is strictly worse than a gateway that
        // serves traffic with admin-API config mutations turned off. `path: None` is what makes the
        // "off" real: every mutation entry point refuses against a `None` backend, so nothing can
        // apply in RAM and silently revert. Logged at WARN here (and again at boot in `main`) because
        // an operator who DID intend to drive this busbar by admin API must not discover it at the
        // first mutation.
        diag_warn!(
            CONFIG_OVERLAY_NOT_WRITABLE,
            overlay = %p.display(),
            "the config overlay backend is NOT WRITABLE (is the config directory mounted read-only?) \
             — busbar is starting WITHOUT a durable config overlay: it serves traffic normally, but \
             every admin-API config mutation will be REFUSED, because a change that cannot be \
             persisted would silently revert on restart. If that is what you want, set \
             `config.locked: true` to say so explicitly and silence this warning. If you want a \
             mutable config, point `config.overlay.file` at a writable path (e.g. mount a writable \
             volume and set `config.overlay.file: /var/lib/busbar/busbar-overlay.json`)."
        );
        return Ok(OverlayResolution {
            locked: false,
            path: None,
            read_only_backend: true,
        });
    }
    Ok(OverlayResolution {
        locked: false,
        path: Some(p),
        read_only_backend: false,
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
                diag_warn!(
                    CONFIG_OVERLAY_PROBE_LEAK,
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
            diag_error!(
                CONFIG_OVERLAY_CORRUPT_REFUSE_WRITE,
                path = %p.display(),
                "config overlay exists but is unreadable/corrupt; REFUSING to overwrite it (would \
                 drop hook AND group deletion tombstones and could resurrect a deleted item). This \
                 apply is NOT persisted — fix or remove the overlay file to restore durability."
            );
            None
        }
        OverlayReadState::VersionTooNew(v) => {
            diag_error!(
                CONFIG_OVERLAY_VERSION_TOO_NEW_RMW,
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
    pub(crate) fn all() -> Vec<OverlaySection> {
        let mut out = vec![
            OverlaySection::Groups,
            OverlaySection::Hooks,
            OverlaySection::Root,
            OverlaySection::PluginVersions,
        ];
        out.extend(
            crate::config::named_map::NamedMapSection::ALL
                .iter()
                .map(|s| OverlaySection::NamedMap(*s)),
        );
        out
    }

    /// Parse a URL path segment into a section, or `None` for an unknown name (the caller 400s). The
    /// ONE place the valid section names live, so the route + the doc + the tests share one source.
    pub(crate) fn parse(s: &str) -> Option<Self> {
        OverlaySection::all().into_iter().find(|v| v.as_str() == s)
    }

    /// The section's wire/label name (the path segment). For a named map this is the section KEY,
    /// which is deliberately the same string as the config key and the CRUD path segment
    /// (`export:` ⇄ `/export` ⇄ `/overlay/export`).
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            OverlaySection::Hooks => "hooks",
            OverlaySection::Groups => "groups",
            OverlaySection::Root => "root",
            OverlaySection::PluginVersions => "plugin_versions",
            OverlaySection::NamedMap(s) => s.key(),
        }
    }

    /// The valid section names as a comma-separated, backticked list for an error message. Derived
    /// from [`OverlaySection::all`] rather than written out, because the hand-written version of this
    /// string is exactly what told operators `export` was not a section while it was becoming one.
    pub(crate) fn valid_names() -> String {
        OverlaySection::all()
            .iter()
            .map(|s| format!("`{}`", s.as_str()))
            .collect::<Vec<_>>()
            .join(", ")
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
pub struct OverlayDoc {
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
    pub(crate) named_maps: BTreeMap<String, BTreeMap<String, serde_json::Value>>,
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
    pub(crate) fn clear_section(&mut self, section: OverlaySection) {
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
    pub(crate) fn section_is_empty(&self, section: OverlaySection) -> bool {
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
            diag_warn!(
                CONFIG_OVERLAY_CORRUPT_BASE_ONLY,
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
            diag_error!(
                CONFIG_OVERLAY_VERSION_TOO_NEW,
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
        // Parse to a generic `Value` FIRST so a pre-1.6.0 overlay whose hook entries still use the
        // retired `plugin:`/`at:` spellings can be rewritten to `module:`/`phase:` BEFORE the typed,
        // `deny_unknown_fields` `HookCfg` deserialize would reject them. This is the boot-time
        // half of the 1.6.0 clean-slate migration (the config-file half is `--migrate-config`); it is
        // what keeps removing the `plugin` alias + the `at` key from bricking a durable overlay. The
        // next `persist` rewrites the file in the new spelling, so the migration runs at most once.
        Ok(bytes) => match serde_json::from_slice::<serde_json::Value>(&bytes) {
            Ok(mut value) => {
                migrate_legacy_hook_keys(&mut value);
                match serde_json::from_value::<Box<OverlayDoc>>(value) {
                    // A newer overlay may have added a section this binary drops, or changed how an
                    // existing one is represented — neither is visible as a parse error, so the
                    // version is the only signal. 1.5.0 is the first release that can refuse one; a
                    // binary without this check never can, whatever number is stamped.
                    Ok(doc) if doc.version > OVERLAY_VERSION => {
                        OverlayReadState::VersionTooNew(doc.version)
                    }
                    Ok(doc) => OverlayReadState::Loaded(doc),
                    Err(_) => OverlayReadState::Unreadable,
                }
            }
            Err(_) => OverlayReadState::Unreadable,
        },
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
        .get_mut("hooks")
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
                diag_error!(
                    CONFIG_OVERLAY_PATCH_UNPARSABLE,
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
