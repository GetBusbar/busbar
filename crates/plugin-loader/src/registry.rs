// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Plugin **discovery, three-phase load validation, and the name/alias registry** - the single
//! pipeline behind boot, `--validate`, and `--list-plugins`, so the pre-flight gate can never
//! drift from real boot behavior.
//!
//! Phases (in order, fail-closed):
//!
//! 1. **STRUCTURAL** (trust-independent): the tarball unpacks, the manifest parses, every required
//!    field is present and well-formed, `sha256(lib) == manifest.sha256`, and the `abi_version` is
//!    supported for the `kind`. A failure here is INVALID - at boot/`--validate` it is a HARD
//!    error naming the file and the reason (never a partial boot).
//! 2. **TRUST**: the signature verifies against the embedded busbar release key (first-party) or an
//!    allowlisted publisher - else the plugin loads only under the matching explicit opt-in flag
//!    (`allow_unsigned` / `allow_third_party`), otherwise it is logged and SKIPPED (never
//!    `dlopen`ed). Anti-downgrade floors are hard rejects inside this phase.
//! 3. **CONFLICT** (over the loadable set): no two plugins share a `name`, no two share an `alias`,
//!    and no alias collides with another plugin's `name`. Any collision is a HARD error naming
//!    both plugins - "you can't use valkey and a third-party valkey".
//!
//! Only after all three phases does a plugin enter the [`PluginRegistry`], addressable by BOTH its
//! canonical name and its alias. Identity comes exclusively from the signed manifest - the tarball
//! filename is irrelevant.

use crate::tarball;
use busbar_plugin_sign::{
    evaluate, validate_structure, Manifest, TrustPolicy, Verdict, HOST_IDENTITY,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// The OLDEST store payload schema this binary still speaks: v2, the 1.5.x credentials-generalized
/// wire. v1 is genuinely unspeakable (its AWS-specific credential variants no longer exist), so the
/// floor cannot go lower; see [`supported_abi`] for why it must not go higher.
pub const STORE_ABI_FLOOR: u32 = 2;

/// The per-kind PAYLOAD schema versions this binary supports — a CONTIGUOUS `[floor, max]` inclusive
/// range of manifest `abi_version` values the engine can speak for `kind` (empty = unknown/unsupported
/// kind, rejected at scan). This is the PAYLOAD axis (the manifest `abi_version`), NOT the transport
/// axis: every kind exports the SAME six kind-neutral C symbols at `busbar_abi() == TRANSPORT_VERSION`;
/// `kind` only selects which payload schema (and engine seam) the cdylib speaks. The range is its
/// endpoints; contiguity is the contract (every value between is speakable), so an additive schema
/// bump stays in range and an old plugin of the same kind keeps loading.
pub fn supported_abi(kind: &str) -> &'static [u32] {
    match kind {
        // A `kind: store` plugin speaks payload schema v2 (the 1.5.x wire every published first-party
        // store — sqlite/postgres/mysql/valkey — was built against) up to the current `ABI_VERSION`.
        // THE FLOOR MUST STAY 2: every request variant the 1.5.x engine sent still exists unchanged,
        // and the only additions since are the eight neutral plane-record verbs, which `DynStore`
        // already treats as inert when the plugin answers `STATUS_UNSUPPORTED` (exactly what the
        // 1.5.x SDK returns for a variant it cannot decode). v3 and v4 changed the source contract a
        // plugin is COMPILED against, not a byte on the wire, so a v2 artifact keeps behaving exactly
        // as it did under 1.5.5. Raising this floor refuses every published store plugin at load.
        "store" => &[STORE_ABI_FLOOR, busbar_plugin::cold::ABI_VERSION],
        // A `kind: secret` plugin resolves a secret reference's settings to bytes.
        "secret" => &[
            busbar_plugin::cold::SECRET_ABI_VERSION,
            busbar_plugin::cold::SECRET_ABI_VERSION,
        ],
        // A `kind: auth` plugin is a first-class identity provider (the engine's auth chain consumes
        // `Box<dyn AuthModule>` via `open_auth`). Payload schema v1 (verify-only) OR v2 (adds the
        // browser-login primitives). The FLOOR MUST STAY 1: the v2 wire additions are
        // externally-tagged additive variants, so a v1 plugin that only speaks `Authenticate`/
        // `Identity` still loads and works. `[1, AUTH_ABI_VERSION]` = `[1, 2]`.
        "auth" => &[1, busbar_plugin::cold::AUTH_ABI_VERSION],
        // A `kind: hook` plugin is an in-process routing policy (the engine's routing/hook chains
        // consume `Arc<dyn RoutingPolicy>` via `open_hook`). The 1.5.0 replacement for the retired
        // out-of-process socket/webhook hook transport. Payload schema v1.
        "hook" => &[
            busbar_plugin::cold::hook::HOOK_ABI_VERSION,
            busbar_plugin::cold::hook::HOOK_ABI_VERSION,
        ],
        // A `kind: export` plugin is a telemetry sink the engine's observability seam feeds
        // (`open_export`). Payload schema v1 (`streams`/`deliver`).
        "export" => &[
            busbar_plugin::cold::export::EXPORT_ABI_VERSION,
            busbar_plugin::cold::export::EXPORT_ABI_VERSION,
        ],
        _ => &[],
    }
}

/// A plugin that passed phases 1 + 2 and MAY load: its signed manifest, the trust verdict, and the
/// exact verified library bytes (what the loader will map - never re-read from disk).
pub struct LoadablePlugin {
    /// The tarball filename (diagnostics only - identity is the manifest).
    pub file: String,
    pub manifest: Manifest,
    pub verdict: Verdict,
    pub lib_bytes: Vec<u8>,
}

/// A plugin that failed phase 2 (untrusted, no matching opt-in; or an anti-downgrade reject) and is
/// SKIPPED: recorded for logging/`--list-plugins`, never a load candidate, never `dlopen`ed.
pub struct SkippedPlugin {
    pub file: String,
    pub manifest: Manifest,
    pub reason: String,
    /// STRUCTURED rejection category from the trust evaluator — the authority for any label/column.
    /// Never derive a trust label by substring-matching `reason` (it embeds plugin-controlled bytes).
    pub kind: busbar_plugin_sign::RejectKind,
}

/// The registry of validated, loadable plugins, addressable by canonical name OR alias. Built only
/// after all three phases pass; this is the ONLY resolution surface (`governance.store:` etc.), so
/// nothing outside the validated set can ever be selected.
pub struct PluginRegistry {
    loadable: Vec<LoadablePlugin>,
    skipped: Vec<SkippedPlugin>,
    /// name -> index into `loadable`; alias -> index (aliases equal to the own name are fine).
    by_name: HashMap<String, usize>,
    by_alias: HashMap<String, usize>,
}

impl std::fmt::Debug for PluginRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginRegistry")
            .field(
                "loadable",
                &self
                    .loadable
                    .iter()
                    .map(|p| p.manifest.name.as_str())
                    .collect::<Vec<_>>(),
            )
            .field(
                "skipped",
                &self
                    .skipped
                    .iter()
                    .map(|p| p.manifest.name.as_str())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl PluginRegistry {
    /// An empty registry (plugins disabled / empty dir).
    pub fn empty() -> Self {
        PluginRegistry {
            loadable: Vec::new(),
            skipped: Vec::new(),
            by_name: HashMap::new(),
            by_alias: HashMap::new(),
        }
    }

    /// Resolve `name_or_alias` (canonical name first, then alias) to a loadable plugin.
    pub fn resolve(&self, name_or_alias: &str) -> Option<&LoadablePlugin> {
        self.by_name
            .get(name_or_alias)
            .or_else(|| self.by_alias.get(name_or_alias))
            .map(|&i| &self.loadable[i])
    }

    /// Why a reference cannot be resolved: if a SKIPPED plugin matches it, name the skip reason -
    /// "the plugin you asked for is here, but trust refused it" is the actionable message.
    pub fn unresolved_reason(&self, name_or_alias: &str) -> Option<&SkippedPlugin> {
        self.skipped
            .iter()
            .find(|s| s.manifest.name == name_or_alias || s.manifest.alias == name_or_alias)
    }

    /// Every loadable plugin (for logging / catalog).
    pub fn loadable(&self) -> &[LoadablePlugin] {
        &self.loadable
    }

    /// Every skipped plugin (for logging / catalog).
    pub fn skipped(&self) -> &[SkippedPlugin] {
        &self.skipped
    }

    /// Open a STORE plugin resolved by name or alias: verifies the resolved plugin's `kind` is
    /// `store`, then loads the VERIFIED bytes over the store C ABI (memfd on Linux, private temp
    /// staging elsewhere) and `open`s it with `cfg_json`. The one engine-facing load entrypoint.
    pub fn open_store(
        &self,
        name_or_alias: &str,
        cfg_json: &str,
    ) -> Result<Box<dyn busbar_api::Store>, String> {
        let Some(p) = self.resolve(name_or_alias) else {
            return Err(match self.unresolved_reason(name_or_alias) {
                Some(s) => format!(
                    "plugin '{name_or_alias}' is present ({}) but was not loaded: {}",
                    s.file, s.reason
                ),
                None => format!(
                    "no plugin named or aliased '{name_or_alias}' is available (loadable plugins: \
                     [{}])",
                    self.loadable
                        .iter()
                        .map(|p| p.manifest.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
        };
        if p.manifest.kind != "store" {
            return Err(format!(
                "plugin '{}' has kind '{}', not 'store' - it cannot back the governance store",
                p.manifest.name, p.manifest.kind
            ));
        }
        // Hand the manifest's payload schema to the loader: a store built against an older schema
        // is spoken to in the shape it can decode (the usage-ledger ops changed shape in 1.6.0).
        crate::load_store_from_bytes_at_abi(
            &p.lib_bytes,
            cfg_json,
            &p.manifest.name,
            &p.manifest.kind,
            p.manifest.abi_version,
        )
    }

    /// Open an AUTH plugin resolved by name or alias: verifies the resolved plugin's `kind` is `auth`,
    /// then loads the VERIFIED bytes over the kind-neutral C ABI and `open`s it with `cfg_json`,
    /// returning `Box<dyn AuthModule>` — the seam the engine's auth chain consumes. Same trust and
    /// load pipeline as store/secret; only the kind (and the consuming seam) differs. FAIL-CLOSED.
    pub fn open_auth(
        &self,
        name_or_alias: &str,
        cfg_json: &str,
    ) -> Result<Box<dyn busbar_api::AuthModule>, String> {
        let Some(p) = self.resolve(name_or_alias) else {
            return Err(match self.unresolved_reason(name_or_alias) {
                Some(s) => format!(
                    "plugin '{name_or_alias}' is present ({}) but was not loaded: {}",
                    s.file, s.reason
                ),
                None => format!(
                    "no plugin named or aliased '{name_or_alias}' is available (loadable plugins: \
                     [{}])",
                    self.loadable
                        .iter()
                        .map(|p| p.manifest.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
        };
        if p.manifest.kind != "auth" {
            return Err(format!(
                "plugin '{}' has kind '{}', not 'auth' - it cannot serve as an auth module",
                p.manifest.name, p.manifest.kind
            ));
        }
        crate::auth::load_auth_from_bytes(
            &p.lib_bytes,
            cfg_json,
            &p.manifest.name,
            &p.manifest.kind,
        )
    }

    /// Open an AUTH plugin as the unified [`busbar_api::AuthPlugin`] handle (verify + LOGIN) —
    /// identical trust/load pipeline as [`Self::open_auth`], but the returned box KEEPS the
    /// `LoginModule` capability the hosted browser-login flow (`auth.methods`, 1.5.2) drives. Also
    /// returns the resolved plugin's manifest `abi_version` so the caller can gate v2-only login
    /// methods (a `browser_login` method needs an ABI v2 login-capable plugin). FAIL-CLOSED.
    pub fn open_login(
        &self,
        name_or_alias: &str,
        cfg_json: &str,
    ) -> Result<(Box<dyn busbar_api::AuthPlugin>, u32), String> {
        let Some(p) = self.resolve(name_or_alias) else {
            return Err(match self.unresolved_reason(name_or_alias) {
                Some(s) => format!(
                    "plugin '{name_or_alias}' is present ({}) but was not loaded: {}",
                    s.file, s.reason
                ),
                None => format!(
                    "no plugin named or aliased '{name_or_alias}' is available (loadable plugins: \
                     [{}])",
                    self.loadable
                        .iter()
                        .map(|p| p.manifest.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
        };
        if p.manifest.kind != "auth" {
            return Err(format!(
                "plugin '{}' has kind '{}', not 'auth' - it cannot serve as a login module",
                p.manifest.name, p.manifest.kind
            ));
        }
        let abi_version = p.manifest.abi_version;
        let module = crate::auth::load_login_from_bytes(
            &p.lib_bytes,
            cfg_json,
            &p.manifest.name,
            &p.manifest.kind,
        )?;
        Ok((module, abi_version))
    }

    /// Open a HOOK plugin resolved by name or alias: verifies the resolved plugin's `kind` is `hook`,
    /// then loads the VERIFIED bytes over the kind-neutral C ABI and `open`s it with `cfg_json`,
    /// returning `Arc<dyn RoutingPolicy>` — the seam the engine's routing/hook chains consume. Same
    /// trust and load pipeline as store/secret/auth; only the kind (and consuming seam) differs.
    /// `name` is the hook's registry name (metrics id); `projectors` are the engine's fail-closed
    /// projection/parse closures. FAIL-CLOSED on any resolution/kind/load failure.
    pub fn open_hook(
        &self,
        name_or_alias: &str,
        cfg_json: &str,
        name: &str,
        projectors: std::sync::Arc<crate::hook::HookProjectors>,
    ) -> Result<std::sync::Arc<dyn busbar_api::RoutingPolicy>, String> {
        let Some(p) = self.resolve(name_or_alias) else {
            return Err(match self.unresolved_reason(name_or_alias) {
                Some(s) => format!(
                    "plugin '{name_or_alias}' is present ({}) but was not loaded: {}",
                    s.file, s.reason
                ),
                None => format!(
                    "no plugin named or aliased '{name_or_alias}' is available (loadable plugins: \
                     [{}])",
                    self.loadable
                        .iter()
                        .map(|p| p.manifest.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
        };
        if p.manifest.kind != "hook" {
            return Err(format!(
                "plugin '{}' has kind '{}', not 'hook' - it cannot serve as a routing hook",
                p.manifest.name, p.manifest.kind
            ));
        }
        crate::hook::load_hook_from_bytes(
            &p.lib_bytes,
            cfg_json,
            &p.manifest.name,
            &p.manifest.kind,
            name,
            projectors,
        )
    }

    /// Open a SECRET plugin resolved by name or alias: verifies the resolved plugin's `kind` is
    /// `secret`, then loads the VERIFIED bytes over the secret C ABI and `open`s it with
    /// `cfg_json`. Same trust and load pipeline as a store plugin - only the kind (and the seam
    /// consuming it) differs. FAIL-CLOSED: any resolution/kind/load failure is an error the caller
    /// surfaces as an unresolvable secret.
    pub fn open_secret(
        &self,
        name_or_alias: &str,
        cfg_json: &str,
    ) -> Result<Box<dyn busbar_api::SecretModule>, String> {
        let Some(p) = self.resolve(name_or_alias) else {
            return Err(match self.unresolved_reason(name_or_alias) {
                Some(s) => format!(
                    "plugin '{name_or_alias}' is present ({}) but was not loaded: {}",
                    s.file, s.reason
                ),
                None => format!(
                    "no plugin named or aliased '{name_or_alias}' is available (loadable plugins: \
                     [{}])",
                    self.loadable
                        .iter()
                        .map(|p| p.manifest.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
        };
        if p.manifest.kind != "secret" {
            return Err(format!(
                "plugin '{}' has kind '{}', not 'secret' - it cannot resolve config secrets",
                p.manifest.name, p.manifest.kind
            ));
        }
        crate::load_secret_from_bytes(&p.lib_bytes, cfg_json, &p.manifest.name, &p.manifest.kind)
    }

    /// Open an EXPORT sink resolved by name or alias: verifies the resolved plugin's `kind` is
    /// `export`, then loads the VERIFIED bytes over the kind-neutral C ABI and `open`s it with
    /// `cfg_json`, returning a [`crate::export::DynExport`] whose declared streams were queried once at
    /// load. Same trust and load pipeline as store/secret/auth/hook; only the kind (and the consuming
    /// seam) differs. FAIL-CLOSED on any resolution/kind/load failure.
    pub fn open_export(
        &self,
        name_or_alias: &str,
        cfg_json: &str,
    ) -> Result<crate::export::DynExport, String> {
        let Some(p) = self.resolve(name_or_alias) else {
            return Err(match self.unresolved_reason(name_or_alias) {
                Some(s) => format!(
                    "plugin '{name_or_alias}' is present ({}) but was not loaded: {}",
                    s.file, s.reason
                ),
                None => format!(
                    "no plugin named or aliased '{name_or_alias}' is available (loadable plugins: \
                     [{}])",
                    self.loadable
                        .iter()
                        .map(|p| p.manifest.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
        };
        if p.manifest.kind != "export" {
            return Err(format!(
                "plugin '{}' has kind '{}', not 'export' - it cannot serve as a telemetry sink",
                p.manifest.name, p.manifest.kind
            ));
        }
        crate::export::load_export_from_bytes(
            &p.lib_bytes,
            cfg_json,
            &p.manifest.name,
            &p.manifest.kind,
        )
    }
}

/// Discover plugin tarballs (`*.tar.gz` / `*.tgz`) in `dir`, sorted by filename. A missing
/// directory is an empty list (drop-is-inert: no dir, no plugins), an unreadable one an error.
#[cold] // boot/admin-only — keeps hot text dense (never inlined into a warm path)
#[inline(never)]
pub fn discover(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(format!("cannot read plugins dir {}: {e}", dir.display())),
    };
    // FAIL CLOSED on a DirEntry iteration error: a per-entry `io::Error` (corrupted inode, bad NFS
    // mount, concurrent unlink-during-readdir) must NOT be silently dropped — swallowing it could make
    // a configured/named plugin tarball vanish from the scan while boot still SUCCEEDS with a smaller
    // loadable set. Propagate it so the whole scan fails rather than serving with a plugin missing.
    for entry in entries {
        let entry =
            entry.map_err(|e| format!("error reading plugins dir {}: {e}", dir.display()))?;
        let path = entry.path();
        let Some(file) = path.file_name().and_then(|f| f.to_str()) else {
            continue;
        };
        if path.is_file() && tarball::is_plugin_tarball(file) {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

/// One file's outcome through phases 1 + 2 (phase 3 needs the whole set).
enum FileOutcome {
    Loadable(LoadablePlugin),
    Skipped(SkippedPlugin),
    Invalid { file: String, reason: String },
}

/// Run phases 1 (structural) + 2 (trust) over one tarball.
fn examine(path: &Path, policy: &TrustPolicy) -> FileOutcome {
    let file = path
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("plugin")
        .to_string();
    // Check the file's size BEFORE reading it into memory: `tarball::unpack` bounds the two
    // DECOMPRESSED members it extracts, but that check only runs after the WHOLE compressed file
    // has already been read into a `Vec<u8>`. A huge file planted in the plugins directory (by
    // accident or otherwise) would otherwise be read in full - unbounded - on every boot-time scan,
    // before any validation gets a chance to reject it.
    match std::fs::metadata(path) {
        Ok(meta) if meta.len() > tarball::MAX_TARBALL_FILE_BYTES => {
            return FileOutcome::Invalid {
                file,
                reason: format!(
                    "tarball is {} bytes, exceeding the {}-byte cap",
                    meta.len(),
                    tarball::MAX_TARBALL_FILE_BYTES
                ),
            };
        }
        Ok(_) => {}
        Err(e) => {
            return FileOutcome::Invalid {
                file,
                reason: format!("cannot stat: {e}"),
            };
        }
    }
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            return FileOutcome::Invalid {
                file,
                reason: format!("cannot read: {e}"),
            }
        }
    };
    // Phase 1a: unpack in memory (bounded).
    let unpacked = match tarball::unpack(&bytes) {
        Ok(u) => u,
        Err(reason) => return FileOutcome::Invalid { file, reason },
    };
    // Phase 1b: structural completeness + well-formedness + integrity + abi.
    if let Err(reason) = validate_structure(
        &unpacked.manifest,
        &unpacked.lib_bytes,
        &supported_abi,
        HOST_IDENTITY,
    ) {
        return FileOutcome::Invalid { file, reason };
    }
    // Phase 2: trust. A rejection here is a SKIP (logged, never dlopen'ed) - unless the plugin is
    // actually referenced, in which case resolution fails loudly with this reason attached.
    match evaluate(&unpacked.lib_bytes, &unpacked.manifest, policy) {
        Ok(verdict) => FileOutcome::Loadable(LoadablePlugin {
            file,
            manifest: unpacked.manifest,
            verdict,
            lib_bytes: unpacked.lib_bytes,
        }),
        Err(rejected) => FileOutcome::Skipped(SkippedPlugin {
            file,
            manifest: unpacked.manifest,
            reason: rejected.reason,
            kind: rejected.kind,
        }),
    }
}

/// Phase 3: cross-plugin conflict detection over the LOADABLE set. Any name/alias collision is a
/// hard error naming BOTH plugins and the colliding identifier.
fn conflicts(loadable: &[LoadablePlugin]) -> Vec<String> {
    let mut errors = Vec::new();
    let mut name_owner: HashMap<&str, &LoadablePlugin> = HashMap::new();
    for p in loadable {
        if let Some(prev) = name_owner.get(p.manifest.name.as_str()) {
            errors.push(format!(
                "plugin name conflict: '{}' is claimed by both {} and {} - remove one \
                 (\"you can't use valkey and a third-party valkey\")",
                p.manifest.name, prev.file, p.file
            ));
        } else {
            name_owner.insert(&p.manifest.name, p);
        }
    }
    let mut alias_owner: HashMap<&str, &LoadablePlugin> = HashMap::new();
    for p in loadable {
        if let Some(prev) = alias_owner.get(p.manifest.alias.as_str()) {
            errors.push(format!(
                "plugin alias conflict: '{}' is claimed by both {} ({}) and {} ({}) - remove one",
                p.manifest.alias, prev.file, prev.manifest.name, p.file, p.manifest.name
            ));
        } else {
            alias_owner.insert(&p.manifest.alias, p);
        }
        // An alias colliding with ANOTHER plugin's canonical name is equally ambiguous.
        if let Some(other) = name_owner.get(p.manifest.alias.as_str()) {
            if other.manifest.name != p.manifest.name {
                errors.push(format!(
                    "plugin alias/name conflict: alias '{}' of {} ({}) collides with the canonical \
                     name of {} ({}) - remove one",
                    p.manifest.alias, p.file, p.manifest.name, other.file, other.manifest.name
                ));
            }
        }
    }
    errors
}

/// The full boot/validate pipeline: discover -> phase 1 -> phase 2 -> phase 3 -> registry.
/// FAIL-CLOSED: any unreadable/invalid tarball (phase 1) or any conflict (phase 3) returns
/// `Err(errors)` with every problem named - the caller (boot / `--validate`) aborts; there is no
/// partial result. Untrusted plugins (phase 2) are SKIPPED into the registry's skip list (the
/// caller logs them); they only become fatal if actually referenced.
pub fn scan_and_validate(dir: &Path, policy: &TrustPolicy) -> Result<PluginRegistry, Vec<String>> {
    let files = discover(dir).map_err(|e| vec![e])?;
    let mut errors = Vec::new();
    let mut loadable = Vec::new();
    let mut skipped = Vec::new();
    for path in &files {
        match examine(path, policy) {
            FileOutcome::Loadable(p) => loadable.push(p),
            FileOutcome::Skipped(s) => skipped.push(s),
            FileOutcome::Invalid { file, reason } => errors.push(format!(
                "invalid plugin '{}': {reason}",
                dir.join(file).display()
            )),
        }
    }
    errors.extend(conflicts(&loadable));
    if !errors.is_empty() {
        return Err(errors);
    }
    let mut by_name = HashMap::new();
    let mut by_alias = HashMap::new();
    for (i, p) in loadable.iter().enumerate() {
        by_name.insert(p.manifest.name.clone(), i);
        by_alias.insert(p.manifest.alias.clone(), i);
    }
    Ok(PluginRegistry {
        loadable,
        skipped,
        by_name,
        by_alias,
    })
}

/// One row of the MANIFEST-ONLY inventory behind `busbar --list-plugins` and the admin catalog:
/// every tarball in the directory with its identity (when decodable) and its trust/status verdict.
/// NEVER `dlopen`s anything - untrusted code cannot run from listing the directory.
pub struct InventoryEntry {
    pub file: String,
    /// `None` when the tarball/manifest is invalid (see `status`).
    pub manifest: Option<Manifest>,
    /// The signature column: `first-party` / `publisher:<name>` / `unsigned (allowed)` /
    /// `third-party (allowed)` / `unsigned` / `unknown-publisher` / `tampered` / `INVALID`.
    pub signature: String,
    /// The status column: `ready` / `SKIPPED: <reason>` / `REJECTED: <reason>` / `INVALID: <reason>`.
    pub status: String,
}

/// Build the manifest-only inventory of `dir` under `policy`. Never errors, never loads: every
/// tarball yields a row, including invalid ones (with the exact reason). Conflicts across loadable
/// plugins are appended to the affected rows' status.
pub fn inventory(dir: &Path, policy: &TrustPolicy) -> Vec<InventoryEntry> {
    let files = match discover(dir) {
        Ok(f) => f,
        Err(e) => {
            return vec![InventoryEntry {
                file: dir.display().to_string(),
                manifest: None,
                signature: "-".into(),
                status: format!("INVALID: {e}"),
            }]
        }
    };
    let mut loadable = Vec::new();
    let mut rows = Vec::new();
    for path in &files {
        match examine(path, policy) {
            FileOutcome::Loadable(p) => {
                let signature = match &p.verdict {
                    Verdict::Trusted {
                        first_party: true, ..
                    } => "first-party".to_string(),
                    Verdict::Trusted { publisher, .. } => format!("publisher:{publisher}"),
                    Verdict::Allowed {
                        allow: busbar_plugin_sign::AllowReason::Unsigned,
                        ..
                    } => "unsigned (allowed)".to_string(),
                    Verdict::Allowed { .. } => "third-party (allowed)".to_string(),
                };
                rows.push(InventoryEntry {
                    file: p.file.clone(),
                    manifest: Some(p.manifest.clone()),
                    signature,
                    status: "ready".to_string(),
                });
                loadable.push(p);
            }
            FileOutcome::Skipped(s) => {
                // Derive the signature label from the STRUCTURED verdict (`s.kind`), NEVER by
                // substring-matching `s.reason` — the reason embeds plugin-author-controlled bytes
                // (`manifest.publisher`), so a crafted publisher like "anti-downgrade-bypass" could
                // otherwise mislabel an unknown-publisher reject as "trusted (below floor)".
                use busbar_plugin_sign::RejectKind;
                let signature = match s.kind {
                    RejectKind::AntiDowngrade => "trusted (below floor)",
                    // A floored artifact that could NOT prove trust: labeled as the UNTRUSTED artifact
                    // it is, never mislabeled "trusted (below floor)".
                    RejectKind::UntrustedFloored => "untrusted (below floor)",
                    RejectKind::UnknownPublisher => "unknown-publisher",
                    RejectKind::Tampered => "tampered",
                    RejectKind::Unsigned => "unsigned",
                }
                .to_string();
                let status = match s.kind {
                    // Only a TRUSTED-but-below-floor artifact is a hard REJECTED row; every untrusted
                    // reject (including a floored untrusted one) is a SKIP.
                    RejectKind::AntiDowngrade => format!("REJECTED: {}", s.reason),
                    _ => format!("SKIPPED: {}", s.reason),
                };
                rows.push(InventoryEntry {
                    file: s.file,
                    manifest: Some(s.manifest),
                    signature,
                    status,
                });
            }
            FileOutcome::Invalid { file, reason } => rows.push(InventoryEntry {
                file,
                manifest: None,
                signature: "INVALID".to_string(),
                status: format!("INVALID: {reason}"),
            }),
        }
    }
    // Surface phase-3 conflicts on the affected loadable rows.
    for conflict in conflicts(&loadable) {
        for row in rows.iter_mut() {
            if let Some(m) = &row.manifest {
                if conflict.contains(&format!("'{}'", m.name))
                    || conflict.contains(&format!("'{}'", m.alias))
                {
                    row.status = format!("CONFLICT: {conflict}");
                }
            }
        }
    }
    rows
}

#[cfg(test)]
#[path = "tests/registry_tests.rs"]
mod tests;
