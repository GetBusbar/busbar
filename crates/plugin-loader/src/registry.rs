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
//!    (`allow_untrusted`), otherwise it is logged and SKIPPED (never
//!    `dlopen`ed). Anti-downgrade floors are hard rejects inside this phase.
//! 3. **CONFLICT** (over the loadable set): no two plugins share a `name`, no two share an `alias`,
//!    and no alias collides with another plugin's `name`. Any collision is a HARD error naming
//!    both claimants and the conflicting identity.
//!
//! Only after all three phases does a plugin enter the [`PluginRegistry`], addressable by BOTH its
//! canonical name and its alias. Identity comes exclusively from the signed manifest - the tarball
//! filename is irrelevant.

use crate::sign::{
    evaluate_with_verification, validate_structure, Manifest, TrustPolicy, Verdict, HOST_IDENTITY,
};
use crate::tarball;
use busbar_contract::plugin_settings::sugar_words::kind;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub use busbar_artifact_verifier::supported_abi;

/// ONE ROW of the registry: a plugin it resolves by name or alias. A row passed phases 1 + 2: its signed
/// manifest, the trust verdict, and the exact verified library bytes (what the loader will map,
/// never re-read from disk).
#[derive(Clone)]
pub struct LoadablePlugin {
    /// The tarball filename (diagnostics only - identity is the manifest).
    pub file: String,
    pub manifest: Manifest,
    pub verdict: Verdict,
    /// The verified library bytes, shared (never copied) with every boot row it becomes
    /// ([`Self::candidate`]).
    pub lib_bytes: std::sync::Arc<Vec<u8>>,
    /// Digest of the exact capped archive whose verified image `lib_bytes` retains. Never
    /// recomputed from the path, which may have been replaced after discovery.
    pub archive_sha256: Option<String>,
    /// Authenticated keys-document version from this exact image's successful first-party seal.
    /// Never recovered by parsing an unverified signature, and absent for unverified rows.
    pub verification: crate::sign::Verification,
    /// Whether what this plugin holds is lost on restart. A dropped-in row never states it: the plugins
    /// directory is where a durable store comes from.
    pub ephemeral: bool,
    /// Validated Statement schema, or the legacy manifest fallback. Never changes signed bytes.
    pub(crate) settings_schema: Option<String>,
    /// Parsed at admission; admin discovery never calls the door to read declarations.
    configuration_statement: Option<Box<busbar_contract::rendering::Read>>,
}

impl LoadablePlugin {
    pub fn configuration_statement(&self) -> Option<&busbar_contract::rendering::Read> {
        self.configuration_statement.as_deref()
    }

    /// Whether this row is the module `name`: its manifest's name, or the name its Statement
    /// states. Process start registers a plane under its Statement's name (`decision`), while its
    /// signed manifest carries its repo's (`busbar-plane-decisions`).
    #[must_use]
    pub fn is_module(&self, name: &str) -> bool {
        self.manifest.name == name
            || self
                .configuration_statement()
                .is_some_and(|stated| stated.name == name)
    }

    #[must_use]
    pub fn release_keys_version(&self) -> Option<u64> {
        self.verification.keys_version
    }

    pub fn key(&self) -> &str {
        &self.manifest.name
    }

    /// The version this plugin states in its manifest's Statement.
    pub fn plugin_version(&self) -> Result<String, String> {
        stated_version(&self.manifest)
    }

    pub fn candidate(&self) -> Result<Option<crate::boot::Candidate>, String> {
        let named = |e: String| format!("plugin '{}': {e}", self.manifest.name);
        let Some(stated) = self.manifest.stated_rendering().map_err(named)? else {
            return Ok(None);
        };
        let origin = crate::boot::Origin::Dropped {
            file: self.file.clone(),
            bytes: std::sync::Arc::clone(&self.lib_bytes),
        };
        crate::boot::Candidate::from_manifest(stated, &self.manifest, origin)
            .map(Some)
            .map_err(named)
    }

    /// The Statement bytes this plugin's manifest carries, when it carries one.
    pub fn statement(&self) -> Option<Vec<u8>> {
        self.manifest.stated_rendering().ok().flatten()
    }

    /// What this plugin declares it needs: its manifest's declares section.
    pub fn declarations(&self) -> Result<crate::sign::Declares, String> {
        Ok(self.manifest.declares.clone())
    }

    /// Whether this plugin is the release's own: its archive verified under the first-party trust root.
    pub fn first_party(&self) -> bool {
        matches!(
            self.verdict,
            Verdict::Trusted {
                first_party: true,
                ..
            }
        )
    }
}

pub const JSON_SECRET_REFUSED: &str = "it speaks the 1.5.5 JSON secret contract, which this host does not load — rebuild the plugin against the 1.6.0 SDK";

/// A plugin that failed phase 2 (untrusted, no matching opt-in; or an anti-downgrade reject) and is
/// SKIPPED: recorded for logging/`--list-plugins`, never a load candidate, never `dlopen`ed.
#[derive(Clone)]
pub struct SkippedPlugin {
    pub file: String,
    pub manifest: Manifest,
    pub reason: String,
    /// STRUCTURED rejection category from the trust evaluator — the authority for any label/column.
    /// Never derive a trust label by substring-matching `reason` (it embeds plugin-controlled bytes).
    pub kind: crate::sign::RejectKind,
    /// Trusted first-party root identifiers, carried separately from plugin-controlled text.
    pub trusted_keys: Vec<String>,
}

/// The longest file name a skip line echoes, in characters, after escaping.
const SKIP_LINE_FILE_CHARS: usize = 96;

impl SkippedPlugin {
    /// The operator's line for a skipped file whose kind can declare config grammar (`kind:
    /// secret | plane | auth`): which file, and why it was not admitted. `None` for other kinds.
    ///
    /// The reason is a fixed class keyed by [`Self::kind`], never the plugin-controlled reason
    /// text or the manifest's name; the file name is escaped and capped.
    #[must_use]
    pub fn skip_line(&self) -> Option<String> {
        use crate::sign::RejectKind;
        let kind = [kind::SECRET, kind::PLANE, kind::AUTH]
            .into_iter()
            .find(|k| *k == self.manifest.kind)?;
        let why = match self.kind {
            RejectKind::VerificationUnavailable => "verification unavailable",
            RejectKind::Unsigned => "unsigned",
            RejectKind::Tampered => "tampered",
            RejectKind::UnknownPublisher => "unknown publisher",
            RejectKind::PublisherScope => "publisher not authorized for this plugin",
            RejectKind::RetiredKey => "retired key",
            RejectKind::Revoked => "revoked",
            RejectKind::Superseded => "superseded",
            RejectKind::AntiDowngrade => "below its version floor (anti-downgrade)",
            RejectKind::UntrustedFloored => "untrusted below floor",
            RejectKind::ExternalCrypto => "not busbar's own release, on a FIPS crypto backend",
        };
        let escaped = self.file.escape_debug().to_string();
        let mut file: String = escaped.chars().take(SKIP_LINE_FILE_CHARS).collect();
        if file.len() < escaped.len() {
            file.push('\u{2026}');
        }
        Some(format!("\"{file}\" (kind {kind}) was not admitted: {why}"))
    }
}

/// The registry of validated, loadable plugins, addressable by canonical name OR alias. Built only
/// after all three phases pass; this is the ONLY resolution surface (`governance.store:` etc.), so
/// nothing outside the validated set can ever be selected.
#[derive(Clone)]
pub struct PluginRegistry {
    /// Every row, in the plugins directory's order.
    rows: Vec<LoadablePlugin>,
    skipped: Vec<SkippedPlugin>,
    /// name -> index into `rows`; alias or former name -> index (aliases equal to the own name are
    /// fine).
    by_name: HashMap<String, usize>,
    by_alias: HashMap<String, usize>,
}

impl std::fmt::Debug for PluginRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names = |rows: &[LoadablePlugin]| -> Vec<String> {
            rows.iter().map(|p| p.manifest.name.clone()).collect()
        };
        f.debug_struct("PluginRegistry")
            .field("loadable", &names(self.loadable()))
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
    pub fn empty() -> Self {
        Self::of(Vec::new(), Vec::new())
    }

    fn of(rows: Vec<LoadablePlugin>, skipped: Vec<SkippedPlugin>) -> Self {
        let mut registry = PluginRegistry {
            rows: Vec::new(),
            skipped,
            by_name: HashMap::new(),
            by_alias: HashMap::new(),
        };
        for row in rows {
            registry.admit(row);
        }
        registry
    }

    fn admit(&mut self, row: LoadablePlugin) {
        let i = self.rows.len();
        self.by_name.entry(row.manifest.name.clone()).or_insert(i);
        for word in row.manifest.config_names() {
            self.by_alias.entry(word.to_string()).or_insert(i);
        }
        self.rows.push(row);
    }

    pub fn resolve(&self, name_or_alias: &str) -> Option<&LoadablePlugin> {
        self.by_name
            .get(name_or_alias)
            .or_else(|| self.by_alias.get(name_or_alias))
            .map(|&i| &self.rows[i])
    }

    pub fn answers(&self, name_or_alias: &str, kind: &str) -> bool {
        self.resolve(name_or_alias)
            .is_some_and(|p| p.manifest.kind == kind)
    }

    pub fn unresolved_reason(&self, name_or_alias: &str) -> Option<&SkippedPlugin> {
        self.skipped
            .iter()
            .find(|s| s.manifest.answers_to(name_or_alias))
    }

    /// Every admitted row.
    pub fn loadable(&self) -> &[LoadablePlugin] {
        &self.rows
    }

    pub fn skipped(&self) -> &[SkippedPlugin] {
        &self.skipped
    }

    /// The image the dropped-in row of `kind` that is the module `name`
    /// ([`LoadablePlugin::is_module`]) is bound from: its archive's SHA-256. `None`: this registry
    /// admits no such dropped-in row.
    #[must_use]
    pub fn dropped_image(&self, kind: &str, name: &str) -> Option<String> {
        self.loadable()
            .iter()
            .find(|row| row.manifest.kind == kind && row.is_module(name))
            .map(|row| row.archive_sha256.clone().unwrap_or_default())
    }

    pub(crate) fn resolve_kind(
        &self,
        name_or_alias: &str,
        kind: &str,
        role: &str,
    ) -> Result<&LoadablePlugin, String> {
        let Some(p) = self.resolve(name_or_alias) else {
            return Err(match self.unresolved_reason(name_or_alias) {
                Some(s) => format!(
                    "plugin '{name_or_alias}' is present ({}) but was not loaded: {}",
                    s.file, s.reason
                ),
                None => format!(
                    "no plugin named or aliased '{name_or_alias}' is available (loadable plugins: \
                     [{}])",
                    self.loadable()
                        .iter()
                        .map(|p| p.manifest.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
        };
        if p.manifest.kind != kind {
            return Err(format!(
                "plugin '{}' has kind '{}', not '{kind}' - it cannot {role}",
                p.key(),
                p.manifest.kind
            ));
        }
        Ok(p)
    }

    #[must_use]
    pub fn kind_refusal(&self, kind: &str, purpose: &str, name_or_alias: &str) -> String {
        match self.resolve_kind(name_or_alias, kind, purpose) {
            Err(e) => e,
            Ok(p) => format!(
                "plugin '{}': it speaks the 1.5.5 JSON {kind} contract, which this host does not \
                 load — rebuild the plugin against the 1.6.0 SDK",
                p.manifest.name
            ),
        }
    }

    #[must_use]
    pub fn secret_refusal(&self, name_or_alias: &str) -> String {
        self.kind_refusal(kind::SECRET, "resolve config secrets", name_or_alias)
    }
}

pub fn unversioned(name: &str) -> String {
    format!(
        "plugin '{name}' states no version in its Statement: the one-version rule cannot compare it"
    )
}

pub fn stated_version(manifest: &Manifest) -> Result<String, String> {
    match manifest.stated() {
        Ok(Some(read)) if !read.version.is_empty() => Ok(read.version),
        _ => Err(unversioned(&manifest.name)),
    }
}

fn archive_filename(path: &Path) -> Option<Result<&str, String>> {
    let name = path.file_name()?;
    let bytes = name.as_encoded_bytes();
    if !bytes.ends_with(b".tar.gz") && !bytes.ends_with(b".tgz") {
        return None;
    }
    Some(
        name.to_str()
            .ok_or_else(|| format!("plugin archive filename is not UTF-8: {}", path.display())),
    )
}

#[cold]
#[inline(never)]
pub fn discover(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(format!("cannot read plugins dir {}: {e}", dir.display())),
    };

    for entry in entries {
        let entry =
            entry.map_err(|e| format!("error reading plugins dir {}: {e}", dir.display()))?;
        let path = entry.path();

        let Some(name) = archive_filename(&path) else {
            continue;
        };
        let metadata = path
            .metadata()
            .map_err(|e| format!("cannot inspect plugin archive {}: {e}", path.display()))?;
        if !metadata.is_file() {
            continue;
        }
        name?;
        out.push(path);
    }
    out.sort();
    Ok(out)
}

fn read_file_capped(path: &Path, cap: u64) -> Result<Vec<u8>, String> {
    use std::io::Read as _;
    let f = std::fs::File::open(path).map_err(|e| format!("cannot read: {e}"))?;
    let mut buf = Vec::new();
    f.take(cap + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("cannot read: {e}"))?;
    if buf.len() as u64 > cap {
        return Err(format!(
            "tarball exceeds the {cap}-byte cap (a file swapped in after the size check cannot \
             bypass the bound)"
        ));
    }
    Ok(buf)
}

enum FileOutcome {
    Loadable(LoadablePlugin),
    Skipped(SkippedPlugin),
    Invalid {
        file: String,
        reason: String,
    },

    Outdated {
        file: String,
        reason: String,
        manifest: Manifest,
    },
}

fn examine(path: &Path, policy: &TrustPolicy) -> FileOutcome {
    let file = path
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("plugin")
        .to_string();

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

    let bytes = match read_file_capped(path, tarball::MAX_TARBALL_FILE_BYTES) {
        Ok(b) => b,
        Err(reason) => return FileOutcome::Invalid { file, reason },
    };

    let unpacked = match tarball::unpack(&bytes) {
        Ok(u) => u,
        Err(reason) => return FileOutcome::Invalid { file, reason },
    };

    if let Err(reason) = validate_structure(
        &unpacked.manifest,
        &unpacked.lib_bytes,
        &supported_abi,
        HOST_IDENTITY,
    ) {
        let speaks = supported_abi(&unpacked.manifest.kind);
        if matches!(crate::sign::native_stamp(&unpacked.lib_bytes), Ok(None))
            && speaks.is_some_and(|v| v != unpacked.manifest.abi_version)
        {
            return FileOutcome::Outdated {
                file,
                reason,
                manifest: unpacked.manifest,
            };
        }
        return FileOutcome::Invalid { file, reason };
    }

    match evaluate_with_verification(&unpacked.lib_bytes, &unpacked.manifest, policy) {
        Ok((verdict, verification)) => {
            let settings_schema = match unpacked.manifest.settings_schema_text() {
                Ok(schema) => schema,
                Err(reason) => return FileOutcome::Invalid { file, reason },
            };
            let configuration_statement = match unpacked.manifest.stated() {
                Ok(statement) => statement.map(Box::new),
                Err(reason) => return FileOutcome::Invalid { file, reason },
            };
            let plugin = LoadablePlugin {
                file,
                manifest: unpacked.manifest,
                verdict,
                lib_bytes: std::sync::Arc::new(unpacked.lib_bytes),
                archive_sha256: Some(crate::sign::sha256_hex(&bytes)),
                verification,
                ephemeral: false,
                settings_schema,
                configuration_statement,
            };

            FileOutcome::Loadable(plugin)
        }
        Err(rejected) => FileOutcome::Skipped(SkippedPlugin {
            file,
            manifest: unpacked.manifest,
            reason: rejected.reason,
            kind: rejected.kind,
            trusted_keys: rejected.trusted_keys,
        }),
    }
}

pub struct Conflict {
    pub message: String,

    pub files: Vec<String>,
}

fn conflicts(loadable: &[LoadablePlugin]) -> Vec<Conflict> {
    let mut errors = Vec::new();
    let mut name_owner: HashMap<&str, &LoadablePlugin> = HashMap::new();
    for p in loadable {
        if let Some(prev) = name_owner.get(p.manifest.name.as_str()) {
            errors.push(Conflict {
                message: format!(
                    "plugin name conflict: '{}' is claimed by both {} and {} - remove one",
                    p.manifest.name, prev.file, p.file
                ),
                files: vec![prev.file.clone(), p.file.clone()],
            });
        } else {
            name_owner.insert(&p.manifest.name, p);
        }
    }
    let mut alias_owner: HashMap<&str, &LoadablePlugin> = HashMap::new();
    for p in loadable {
        if let Some(prev) = alias_owner.get(p.manifest.alias.as_str()) {
            errors.push(Conflict {
                message: format!(
                    "plugin alias conflict: '{}' is claimed by both {} ({}) and {} ({}) - remove one",
                    p.manifest.alias, prev.file, prev.manifest.name, p.file, p.manifest.name
                ),
                files: vec![prev.file.clone(), p.file.clone()],
            });
        } else {
            alias_owner.insert(&p.manifest.alias, p);
        }

        if let Some(other) = name_owner.get(p.manifest.alias.as_str()) {
            if other.manifest.name != p.manifest.name {
                errors.push(Conflict {
                    message: format!(
                        "plugin alias/name conflict: alias '{}' of {} ({}) collides with the \
                         canonical name of {} ({}) - remove one",
                        p.manifest.alias, p.file, p.manifest.name, other.file, other.manifest.name
                    ),
                    files: vec![p.file.clone(), other.file.clone()],
                });
            }
        }
    }

    for (i, p) in loadable.iter().enumerate() {
        for word in &p.manifest.former_names {
            for (j, q) in loadable.iter().enumerate() {
                let shared_earlier = j > i && q.manifest.former_names.contains(word);
                if j == i
                    || q.manifest.name == p.manifest.name
                    || shared_earlier
                    || !q.manifest.answers_to(word)
                {
                    continue;
                }
                errors.push(Conflict {
                    message: format!(
                        "plugin former-name conflict: former name '{word}' of {} ({}) is also \
                         claimed by {} ({}) - remove one",
                        p.file, p.manifest.name, q.file, q.manifest.name
                    ),
                    files: vec![p.file.clone(), q.file.clone()],
                });
            }
        }
    }
    errors
}

fn superseder<'a>(
    old: &Manifest,
    file: &str,
    stated: bool,
    outcomes: &'a [FileOutcome],
) -> Option<&'a LoadablePlugin> {
    outcomes.iter().find_map(|o| match o {
        FileOutcome::Loadable(q)
            if q.file != file
                && matches!(crate::sign::native_stamp(&q.lib_bytes), Ok(None))
                && q.manifest.kind == old.kind
                && (!stated || q.manifest.statement.is_some())
                && (q.manifest.name == old.name || q.manifest.former_names.contains(&old.name))
                && crate::sign::version_at_least(&q.manifest.version, &old.version) =>
        {
            Some(q)
        }
        _ => None,
    })
}

fn supersede(outcomes: Vec<FileOutcome>) -> Vec<FileOutcome> {
    let reasons: Vec<Option<String>> = outcomes
        .iter()
        .map(|o| {
            let (file, old, stated) = match o {
                FileOutcome::Outdated { file, manifest, .. } => (file, manifest, false),
                FileOutcome::Loadable(p)
                    if p.manifest.statement.is_none()
                        && matches!(crate::sign::native_stamp(&p.lib_bytes), Ok(None)) =>
                {
                    (&p.file, &p.manifest, true)
                }
                _ => return None,
            };
            superseder(old, file, stated, &outcomes).map(|q| {
                format!(
                    "superseded by {} {} ({}): this is an older build of the same plugin, made for \
                     an earlier busbar, so it is not loaded; remove it from the plugins directory",
                    q.manifest.name, q.manifest.version, q.file
                )
            })
        })
        .collect();
    outcomes
        .into_iter()
        .zip(reasons)
        .map(|(o, why)| match (o, why) {
            (FileOutcome::Outdated { file, manifest, .. }, Some(reason)) => {
                FileOutcome::Skipped(SkippedPlugin {
                    file,
                    manifest,
                    reason,
                    kind: crate::sign::RejectKind::Superseded,
                    trusted_keys: Vec::new(),
                })
            }
            (FileOutcome::Loadable(p), Some(reason)) => FileOutcome::Skipped(SkippedPlugin {
                file: p.file,
                manifest: p.manifest,
                reason,
                kind: crate::sign::RejectKind::Superseded,
                trusted_keys: Vec::new(),
            }),
            (o, _) => o,
        })
        .collect()
}

pub fn scan_and_validate(dir: &Path, policy: &TrustPolicy) -> Result<PluginRegistry, Vec<String>> {
    let files = discover(dir).map_err(|e| vec![e])?;
    let mut errors = Vec::new();
    let mut loadable = Vec::new();
    let mut skipped = Vec::new();
    let examined: Vec<FileOutcome> = files.iter().map(|path| examine(path, policy)).collect();
    for outcome in supersede(examined) {
        match outcome {
            FileOutcome::Loadable(p) => loadable.push(p),
            FileOutcome::Skipped(s) => skipped.push(s),
            FileOutcome::Invalid { file, reason } | FileOutcome::Outdated { file, reason, .. } => {
                errors.push(format!(
                    "invalid plugin '{}': {reason}",
                    dir.join(file).display()
                ));
            }
        }
    }
    errors.extend(conflicts(&loadable).into_iter().map(|c| c.message));
    if !errors.is_empty() {
        return Err(errors);
    }
    Ok(PluginRegistry::of(loadable, skipped))
}

pub struct InventoryEntry {
    pub file: String,

    pub manifest: Option<Manifest>,

    pub signature: String,

    pub status: String,
}

pub fn inventory(dir: &Path, policy: &TrustPolicy) -> Vec<InventoryEntry> {
    let files = match discover(dir) {
        Ok(f) => f,
        Err(e) => {
            return vec![InventoryEntry {
                file: dir.display().to_string(),
                manifest: None,
                signature: "-".into(),
                status: format!("INVALID: {e}"),
            }];
        }
    };
    let mut loadable = Vec::new();
    let mut rows = Vec::new();
    let examined: Vec<FileOutcome> = files.iter().map(|path| examine(path, policy)).collect();
    for outcome in supersede(examined) {
        match outcome {
            FileOutcome::Loadable(p) => {
                let signature = match &p.verdict {
                    Verdict::Trusted {
                        first_party: true, ..
                    } => "first-party".to_string(),
                    Verdict::Trusted { publisher, .. } => format!("publisher:{publisher}"),
                    Verdict::Allowed { .. } => "unverified (allow_untrusted)".to_string(),
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
                use crate::sign::RejectKind;
                let signature = match s.kind {
                    RejectKind::AntiDowngrade => "trusted (below floor)",

                    RejectKind::UntrustedFloored => "untrusted (below floor)",
                    RejectKind::UnknownPublisher => "unknown-publisher",
                    RejectKind::PublisherScope => "publisher-scope",
                    RejectKind::Tampered => "tampered",
                    RejectKind::VerificationUnavailable => "verification unavailable",
                    RejectKind::Unsigned => "unsigned",
                    RejectKind::ExternalCrypto => "not first-party (FIPS backend)",
                    RejectKind::Superseded => "superseded",
                    RejectKind::RetiredKey => "retired-key",
                    RejectKind::Revoked => "revoked",
                }
                .to_string();
                let status = match s.kind {
                    RejectKind::AntiDowngrade
                    | RejectKind::Revoked
                    | RejectKind::ExternalCrypto => {
                        format!("REJECTED: {}", s.reason)
                    }
                    _ => format!("SKIPPED: {}", s.reason),
                };
                rows.push(InventoryEntry {
                    file: s.file,
                    manifest: Some(s.manifest),
                    signature,
                    status,
                });
            }
            FileOutcome::Invalid { file, reason } | FileOutcome::Outdated { file, reason, .. } => {
                rows.push(InventoryEntry {
                    file,
                    manifest: None,
                    signature: "INVALID".to_string(),
                    status: format!("INVALID: {reason}"),
                })
            }
        }
    }

    for conflict in conflicts(&loadable) {
        for row in rows.iter_mut() {
            if conflict.files.contains(&row.file) {
                row.status = match row.status.strip_prefix("CONFLICT: ") {
                    Some(earlier) => format!("CONFLICT: {earlier}; {}", conflict.message),
                    None => format!("CONFLICT: {}", conflict.message),
                };
            }
        }
    }
    rows
}

#[cfg(test)]
#[path = "tests/registry_tests.rs"]
mod tests;
