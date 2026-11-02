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

use crate::sign::{
    evaluate_with_evidence, validate_structure, Manifest, TrustPolicy, Verdict, HOST_IDENTITY,
};
use crate::tarball;
use busbar_contract::abi::mechanism::kind;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub fn supported_abi(kind: &str) -> &'static [u32] {
    match kind {
        kind::STORE => &[busbar_contract::abi::store::ABI_VERSION],
        kind::SECRET => &[busbar_contract::abi::secret::ABI_VERSION],
        kind::AUTH => &[busbar_contract::abi::auth::ABI_VERSION],
        kind::HOOK => &[busbar_contract::abi::hook::ABI_VERSION],
        kind::EXPORT => &[busbar_contract::abi::export::ABI_VERSION],
        kind::PLANE => &[busbar_contract::abi::plane::ABI_VERSION],
        kind::TRANSPORT => &[busbar_contract::abi::transport::ABI_VERSION],
        _ => &[],
    }
}

/// ONE ROW of the registry: a plugin it resolves by name or alias, loaded through the one loading
/// path (`load_linked` / `load_dropped`). A DROPPED-IN row passed phases 1 + 2 — its signed
/// manifest, the trust verdict, and the exact verified library bytes (what the loader will map,
/// never re-read from disk). A LINKED row ([`LinkedPlugin`], [`PluginRegistry::link`]) states the
/// same manifest and carries its door instead of bytes. Both are registered by the one [`PluginRegistry`] admission and loaded
/// by the one load; nothing downstream reads which door a row came in by.
#[derive(Clone)]
pub struct LoadablePlugin {
    /// The tarball filename (diagnostics only - identity is the manifest). A linked row's is
    /// [`LINKED_FILE`].
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
    /// Never recovered by parsing an unverified signature, and absent for linked/unverified rows.
    accepted_release_keys_version: Option<u64>,
    /// Whether what this plugin holds is lost on restart — a store's own statement ([`LinkedPlugin`]).
    /// A dropped-in row never states it: the plugins directory is where a durable store comes from.
    pub ephemeral: bool,
    /// A linked row's door; `None` for a dropped-in row, whose image is `lib_bytes`.
    entry: Option<LinkedEntry>,
    /// [`LinkedPlugin::keyed_by_alias`]: this row's surfaces print its alias ([`Self::key`]).
    keyed_by_alias: bool,
}

impl LoadablePlugin {
    #[must_use]
    pub fn release_keys_version(&self) -> Option<u64> {
        self.accepted_release_keys_version
    }

    pub fn key(&self) -> &str {
        match self.keyed_by_alias {
            true => &self.manifest.alias,
            false => &self.manifest.name,
        }
    }

    pub fn plugin_version(&self) -> Result<String, String> {
        if self.entry.is_none() {
            return stated_version(&self.manifest);
        }
        self.statement()
            .and_then(|s| busbar_contract::abi::mechanism::rendering::read(&s).ok())
            .map(|r| r.version)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| unversioned(&self.manifest.name))
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

    pub fn statement(&self) -> Option<Vec<u8>> {
        match self.door() {
            Some(door) => crate::dispatch::LinkedRow::of_raw(door)
                .ok()
                .map(|row| row.statement),
            None => self.manifest.stated_rendering().ok().flatten(),
        }
    }

    pub fn declarations(&self) -> Result<crate::sign::Declares, String> {
        use busbar_contract::abi::mechanism::{extensions, rendering};

        let Some(door) = self.door() else {
            return Ok(self.manifest.declares.clone());
        };
        let row = crate::dispatch::LinkedRow::of_raw(door).map_err(|e| e.to_string())?;
        let stated = rendering::read(&row.statement)
            .map_err(|e| format!("expected {} at statement byte {}", e.what, e.at))?;
        match extensions::get(&stated.extensions.bytes, extensions::EXT_DECLARES) {
            Some(bytes) => crate::sign::Declares::from_declares_json(bytes),
            None => Ok(self.manifest.declares.clone()),
        }
    }

    pub fn in_process(&self) -> bool {
        matches!(self.entry, Some(LinkedEntry::Store { .. }))
    }

    pub fn door(&self) -> Option<busbar_contract::abi::sdk::door::RawDoorFn> {
        match self.entry {
            Some(LinkedEntry::Door(door)) => Some(door),
            Some(LinkedEntry::Store { door }) => Some(crate::dispatch::load::raw(door)),
            _ => None,
        }
    }

    pub fn linked(&self) -> bool {
        self.entry.is_some()
    }

    pub fn first_party(&self) -> bool {
        self.entry.is_some()
            || matches!(
                self.verdict,
                Verdict::Trusted {
                    first_party: true,
                    ..
                }
            )
    }

    pub fn migrate(
        &self,
        settings: &serde_json::Value,
        from: &str,
    ) -> Result<Option<busbar_contract::abi::sdk::migrate::Migrated>, String> {
        use crate::dispatch::migrate::{migrate_door, migrate_library};
        match &self.entry {
            Some(LinkedEntry::Store { door }) => {
                migrate_door(crate::dispatch::load::raw(*door), settings, from)
            }
            Some(LinkedEntry::Door(door)) => migrate_door(*door, settings, from),
            None => migrate_library(&self.lib_bytes, &self.file, settings, from),
        }
    }
}

pub const JSON_SECRET_REFUSED: &str = "it speaks the 1.5.5 JSON secret contract, which this host does not load — rebuild the plugin against the 1.6.0 SDK";

pub const LINKED_FILE: &str = "(linked)";

const LINKED_KINDS: &[&str] = &[
    kind::STORE,
    kind::SECRET,
    kind::AUTH,
    kind::HOOK,
    kind::EXPORT,
];

pub struct LinkedPlugin {
    pub manifest: Manifest,
    pub entry: LinkedEntry,

    pub ephemeral: bool,

    keyed_by_alias: bool,
}

/// A linked plugin's door.
#[derive(Clone, Copy)]
pub enum LinkedEntry {
    /// The build's in-process STORE: its store v3 door, which boot opens it through
    /// ([`PluginRegistry::store_door`]); the row is handed no configuration across a boundary
    /// ([`LoadablePlugin::in_process`]).
    Store {
        /// The row's store v3 door.
        door: busbar_contract::abi::mechanism::door::DoorFn,
    },
    /// A compiled-in plugin on its kind's memory ABI: the logic crate's `plugin_door!` door function,
    /// the same door a dropped-in build exports as `busbar_plugin_door` (THE DESIGN: compiled-in =
    /// dropped-in). Loaded through [`crate::dispatch::load_linked`].
    Door(busbar_contract::abi::sdk::door::RawDoorFn),
}

impl LinkedPlugin {
    #[must_use]
    pub fn with_former_names<S: AsRef<str>>(mut self, former: impl IntoIterator<Item = S>) -> Self {
        for word in former {
            let word = word.as_ref();
            if !self.manifest.answers_to(word) {
                self.manifest.former_names.push(word.to_string());
            }
        }
        self
    }

    pub fn door(manifest: Manifest, door: busbar_contract::abi::mechanism::door::DoorFn) -> Self {
        LinkedPlugin {
            manifest,
            entry: LinkedEntry::Door(crate::dispatch::load::raw(door)),
            ephemeral: false,
            keyed_by_alias: false,
        }
    }

    pub fn of_macro(manifest: Manifest, door: busbar_contract::abi::sdk::door::MacroDoor) -> Self {
        Self::door(manifest, door.door_fn())
    }

    pub fn of_loaded(manifest: Manifest, door: crate::dispatch::LoadedDoor) -> Self {
        LinkedPlugin {
            manifest,
            entry: LinkedEntry::Door(door.door),
            ephemeral: false,
            keyed_by_alias: false,
        }
    }

    pub fn store_named(
        name: &str,
        alias: &str,
        door: busbar_contract::abi::mechanism::door::DoorFn,
        ephemeral: bool,
    ) -> Self {
        let abi = busbar_contract::abi::store::ABI_VERSION;
        let entry = LinkedEntry::Store { door };
        Self::built_in(name, &[alias], kind::STORE, abi, entry, ephemeral)
    }

    pub fn auth_door_named(
        name: &str,
        alias: &str,
        door: busbar_contract::abi::mechanism::door::DoorFn,
    ) -> Self {
        Self::auth_entry(name, alias, crate::dispatch::load::raw(door))
    }

    fn auth_entry(
        name: &str,
        alias: &str,
        door: busbar_contract::abi::sdk::door::RawDoorFn,
    ) -> Self {
        let abi = supported_abi(kind::AUTH)
            .first()
            .copied()
            .unwrap_or_default();
        Self::built_in(
            name,
            &[alias],
            kind::AUTH,
            abi,
            LinkedEntry::Door(door),
            false,
        )
    }

    pub fn door_of_kind(
        kind: &str,
        name: &str,
        door: busbar_contract::abi::mechanism::door::DoorFn,
    ) -> Self {
        let abi = supported_abi(kind).first().copied().unwrap_or_default();
        let entry = LinkedEntry::Door(crate::dispatch::load::raw(door));
        Self::built_in(name, &[], kind, abi, entry, false)
    }

    pub fn built_in(
        name: &str,
        aliases: &[&str],
        kind: &str,
        abi_version: u32,
        entry: LinkedEntry,
        ephemeral: bool,
    ) -> Self {
        let alias = aliases.first().copied().unwrap_or(name);
        let row = LinkedPlugin {
            manifest: Manifest {
                name: name.into(),
                alias: alias.into(),
                kind: kind.into(),
                version: env!("CARGO_PKG_VERSION").into(),
                publisher: crate::sign::FIRST_PARTY_PUBLISHER.into(),
                abi_version,
                sha256: String::new(),
                signature: String::new(),
                description: String::new(),
                homepage: String::new(),
                license: String::new(),
                needs: Default::default(),
                settings_schema: None,
                schema_derived: false,
                host: None,
                declares: Default::default(),
                statement: None,
                former_names: Vec::new(),
            },
            entry,
            ephemeral,
            keyed_by_alias: alias != name,
        };
        row.with_former_names(aliases.iter().skip(1))
    }
}

#[cfg(test)]
impl LinkedPlugin {
    pub(crate) fn store(
        name: &str,
        door: busbar_contract::abi::mechanism::door::DoorFn,
        ephemeral: bool,
    ) -> Self {
        Self::store_named(name, name, door, ephemeral)
    }

    pub(crate) fn auth_door(
        name: &str,
        door: busbar_contract::abi::mechanism::door::DoorFn,
    ) -> Self {
        Self::auth_door_named(name, name, door)
    }

    pub(crate) fn door_raw(
        manifest: Manifest,
        door: busbar_contract::abi::sdk::door::RawDoorFn,
    ) -> Self {
        LinkedPlugin {
            manifest,
            entry: LinkedEntry::Door(door),
            ephemeral: false,
            keyed_by_alias: false,
        }
    }

    pub(crate) fn auth_door_raw(
        name: &str,
        door: busbar_contract::abi::sdk::door::RawDoorFn,
    ) -> Self {
        Self::auth_entry(name, name, door)
    }

    pub(crate) fn auth_door_named_raw(
        name: &str,
        alias: &str,
        door: busbar_contract::abi::sdk::door::RawDoorFn,
    ) -> Self {
        Self::auth_entry(name, alias, door)
    }

    pub(crate) fn door_of_kind_raw(
        kind: &str,
        name: &str,
        door: busbar_contract::abi::sdk::door::RawDoorFn,
    ) -> Self {
        let abi = supported_abi(kind).first().copied().unwrap_or_default();
        Self::built_in(name, &[], kind, abi, LinkedEntry::Door(door), false)
    }
}

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

/// The registry of validated, loadable plugins, addressable by canonical name OR alias. Built only
/// after all three phases pass; this is the ONLY resolution surface (`governance.store:` etc.), so
/// nothing outside the validated set can ever be selected.
#[derive(Clone)]
pub struct PluginRegistry {
    /// Every row, in registration order: the linked rows, then the plugins directory's.
    rows: Vec<LoadablePlugin>,
    /// How many of `rows` are linked (they lead).
    linked: usize,
    skipped: Vec<SkippedPlugin>,
    /// The dropped-in copies of plugins this build links at the same version ([`one_version`]):
    /// validated, admitted once — the linked row serves — so never a row.
    copies: Vec<LinkedCopy>,
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
            .field("linked", &names(self.linked()))
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
        Self::of(Vec::new(), 0, Vec::new())
    }

    fn of(rows: Vec<LoadablePlugin>, linked: usize, skipped: Vec<SkippedPlugin>) -> Self {
        let mut registry = PluginRegistry {
            rows: Vec::new(),
            linked,
            skipped,
            copies: Vec::new(),
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

    pub fn link(self, linked: Vec<LinkedPlugin>) -> Result<Self, String> {
        let mut rows = Vec::with_capacity(linked.len() + self.rows.len());
        for LinkedPlugin {
            manifest,
            entry,
            ephemeral,
            keyed_by_alias,
        } in linked
        {
            crate::sign::validate_identity(&manifest, crate::sign::HOST_IDENTITY)
                .and_then(|()| crate::sign::validate_abi(&manifest, &supported_abi))
                .and_then(|()| match LINKED_KINDS.contains(&manifest.kind.as_str()) {
                    true => Ok(()),
                    false => Err(format!(
                        "kind '{}' is not linked through this door",
                        manifest.kind
                    )),
                })
                .map_err(|e| format!("linked plugin '{}': {e}", manifest.name))?;
            rows.push(LoadablePlugin {
                file: LINKED_FILE.to_string(),
                verdict: Verdict::Trusted {
                    publisher: manifest.publisher.clone(),
                    first_party: false,
                },
                manifest,
                lib_bytes: std::sync::Arc::default(),
                archive_sha256: None,
                accepted_release_keys_version: None,
                ephemeral,
                entry: Some(entry),
                keyed_by_alias,
            });
        }
        let new = rows.len();
        let n = new + self.linked;
        rows.extend(self.rows);
        let copies = cross_claim(&rows, new)?;
        let mut kept = Vec::with_capacity(rows.len());
        let mut found = self.copies;
        for (i, row) in rows.into_iter().enumerate() {
            match copies.iter().find(|(j, _)| *j == i) {
                Some((_, version)) => found.push(LinkedCopy {
                    name: row.manifest.name,
                    version: version.clone(),
                    file: row.file,
                }),
                None => kept.push(row),
            }
        }
        let mut registry = Self::of(kept, n, self.skipped);
        registry.copies = found;
        Ok(registry)
    }

    pub fn linked_copies(&self) -> &[LinkedCopy] {
        &self.copies
    }

    pub fn linked_copy(
        &self,
        manifest: &Manifest,
        file: &str,
    ) -> Result<Option<LinkedCopy>, String> {
        let Some(linked) = self
            .linked()
            .iter()
            .find(|p| p.manifest.name == manifest.name)
        else {
            return Ok(None);
        };
        let version = one_version(linked, file, &stated_version(manifest)?)?;
        Ok(Some(LinkedCopy {
            name: manifest.name.clone(),
            version,
            file: file.to_string(),
        }))
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

    pub fn loadable(&self) -> &[LoadablePlugin] {
        &self.rows[self.linked..]
    }

    pub fn linked(&self) -> &[LoadablePlugin] {
        &self.rows[..self.linked]
    }

    pub fn skipped(&self) -> &[SkippedPlugin] {
        &self.skipped
    }

    pub fn dropped_hooks(&self) -> impl Iterator<Item = &LoadablePlugin> {
        self.loadable()
            .iter()
            .filter(|p| p.manifest.kind == kind::HOOK && !p.linked())
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

    fn resolve_store(&self, name_or_alias: &str) -> Result<&LoadablePlugin, String> {
        self.resolve_kind(name_or_alias, "store", "back the governance store")
    }

    pub fn store_door(
        &self,
        name_or_alias: &str,
    ) -> Result<busbar_contract::store_calls::StoreDoor, String> {
        use busbar_contract::store_calls::StoreDoor;
        let p = self.resolve_store(name_or_alias)?;
        let no_door = || {
            format!(
                "plugin '{}' states no store door: rebuild the plugin against the 1.6.0 SDK",
                p.key()
            )
        };
        if let Some(entry) = p.entry {
            return match entry {
                LinkedEntry::Store { door } => Ok(StoreDoor::Linked(door)),
                LinkedEntry::Door(_) => Err(no_door()),
            };
        }
        let named = |e: String| format!("plugin '{}': {e}", p.key());
        match p.manifest.stated_rendering().map_err(named)? {
            Some(stated) => Ok(StoreDoor::Dropped {
                file: p.file.clone(),
                bytes: std::sync::Arc::clone(&p.lib_bytes),
                stated,
            }),
            None => Err(no_door()),
        }
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

    pub fn open_transport_entries(
        &self,
        bind: &crate::dispatch::Bind,
        uses: &crate::boot::Uses,
        logs: &crate::dispatch::PluginLogConfig,
    ) -> Result<TransportEntries, String> {
        use crate::dispatch::load::{load_staged, Staging};
        let mut entries = TransportEntries::default();
        for p in self
            .loadable()
            .iter()
            .filter(|p| p.manifest.kind == kind::TRANSPORT)
        {
            let name = &p.manifest.name;
            let Some(stated) = p.manifest.stated_rendering()? else {
                return Err(format!(
                    "transport plugin '{name}' states no Statement in its signed manifest, so it \
                     exports no memory-ABI door (`busbar_plugin_door`) this host admits: a \
                     transport loads only through its door"
                ));
            };
            let selected = crate::boot::Candidate::from_manifest(
                stated.clone(),
                &p.manifest,
                crate::boot::Origin::Dropped {
                    file: p.file.clone(),
                    bytes: std::sync::Arc::clone(&p.lib_bytes),
                },
            )
            .map_err(|e| format!("transport plugin '{name}': {e}"))?
            .serves(uses);
            if !selected {
                continue;
            }
            let (lib, staged) = crate::stage::load_library_from_bytes(&p.lib_bytes, name)?;
            let sink = logs
                .sink(
                    name,
                    busbar_contract::abi::mechanism::KindCode::Transport,
                    bind.sink.clone(),
                )
                .map_err(|e| format!("transport plugin '{name}': {e}"))?;
            match load_staged::<crate::dispatch::kinds::transport::Transport>(
                lib,
                staged,
                Some(stated.as_slice()),
                crate::dispatch::Bind {
                    instance: std::sync::Arc::from(name.as_str()),
                    sink: std::sync::Arc::new(sink),
                    ..bind.clone()
                },
            )
            .map_err(|e| format!("transport plugin '{name}' refused at its door: {e}"))?
            {
                Staging::Door(plugin) => entries.doors.push(plugin),
                Staging::NotADoor => {
                    return Err(format!(
                        "transport plugin '{name}' exports no memory-ABI door \
                         (`busbar_plugin_door`): a transport loads only through its door"
                    ))
                }
            }
        }
        Ok(entries)
    }

    pub fn open_planes(
        &self,
        linked: &[busbar_contract::abi::mechanism::door::DoorFn],
    ) -> Result<crate::boot::PlaneSet, String> {
        let mut set = crate::boot::PlaneSet::default();
        for door in linked {
            set.doors.push(crate::boot::Candidate::linked(*door)?);
        }
        let planes = self.loadable().iter();
        for p in planes.filter(|p| p.manifest.kind == kind::PLANE) {
            let Some(c) = p.candidate()? else {
                return Err(format!(
                    "plugin '{}': states no Statement: a plane loads only through its memory-ABI \
                     door (`busbar_plugin_door`)",
                    p.manifest.name
                ));
            };
            set.doors.push(c);
        }
        Ok(set)
    }
}

fn cross_claim(rows: &[LoadablePlugin], new: usize) -> Result<Vec<(usize, String)>, String> {
    let mut copies = Vec::new();
    for (i, a) in rows.iter().enumerate().take(new) {
        for (j, b) in rows.iter().enumerate().skip(i + 1) {
            if a.manifest.name == b.manifest.name {
                if b.linked() {
                    return Err(format!(
                        "plugin claim conflict: '{}' is declared by two linked rows ({} and {}); \
                         a canonical name must resolve to one linked plugin",
                        a.manifest.name, a.manifest.kind, b.manifest.kind
                    ));
                }
                if !copies.iter().any(|(k, _)| *k == j) {
                    copies.push((j, one_version(a, &b.file, &b.plugin_version()?)?));
                }
                continue;
            }
            if let Some(word) = a.manifest.identities().find(|w| b.manifest.answers_to(w)) {
                return Err(format!(
                    "plugin claim conflict: '{word}' is claimed by both {} ({}) and {} ({}) - \
                     a name, alias or former name must resolve to one plugin; remove one",
                    a.file,
                    a.key(),
                    b.file,
                    b.key()
                ));
            }
        }
    }
    Ok(copies)
}

/// A dropped-in tarball that is a COPY of a plugin this build links, at the same version: one
/// plugin, arriving by both doors, admitted once (the linked row serves it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedCopy {
    /// The plugin's canonical name.
    pub name: String,
    /// The one version both doors carry ([`LoadablePlugin::plugin_version`]).
    pub version: String,
    /// The tarball's file name.
    pub file: String,
}

impl LinkedCopy {
    pub fn line(&self) -> String {
        both_doors(&self.name, &self.version, &self.file)
    }
}

pub fn both_doors(name: &str, version: &str, file: &str) -> String {
    format!("plugin '{name}' v{version} is linked and also dropped in ({file}); the linked build serves it")
}

pub fn one_version(linked: &LoadablePlugin, file: &str, dropped: &str) -> Result<String, String> {
    two_versions(
        &linked.manifest.name,
        &linked.plugin_version()?,
        file,
        dropped,
    )
}

pub fn unversioned(name: &str) -> String {
    format!("plugin '{name}' states no version in its Statement: the one-version rule cannot compare it")
}

pub fn two_versions(name: &str, linked: &str, file: &str, dropped: &str) -> Result<String, String> {
    match linked == dropped {
        true => Ok(linked.to_string()),
        false => Err(format!(
            "plugin '{name}' arrives by both doors at two versions: linked v{linked}, dropped in \
             v{dropped} ({file}) - one version per plugin: remove one"
        )),
    }
}

pub fn stated_version(manifest: &Manifest) -> Result<String, String> {
    match manifest.stated() {
        Ok(Some(read)) if !read.version.is_empty() => Ok(read.version),
        _ => Err(unversioned(&manifest.name)),
    }
}

/// The transports a plugins directory contributes ([`PluginRegistry::open_transport_entries`]).
#[derive(Default)]
pub struct TransportEntries {
    /// Memory-ABI transport doors, bound.
    pub doors: Vec<crate::dispatch::Plugin<crate::dispatch::kinds::transport::Transport>>,
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

        let archive = path.file_name().is_some_and(|name| {
            let bytes = name.as_encoded_bytes();
            bytes.ends_with(b".tar.gz") || bytes.ends_with(b".tgz")
        });
        if !archive {
            continue;
        }
        let metadata = path
            .metadata()
            .map_err(|e| format!("cannot inspect plugin archive {}: {e}", path.display()))?;
        if !metadata.is_file() {
            continue;
        }
        if path.file_name().and_then(|f| f.to_str()).is_none() {
            return Err(format!(
                "plugin archive filename is not UTF-8: {}",
                path.display()
            ));
        }
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
        if !speaks.is_empty() && !speaks.contains(&unpacked.manifest.abi_version) {
            return FileOutcome::Outdated {
                file,
                reason,
                manifest: unpacked.manifest,
            };
        }
        return FileOutcome::Invalid { file, reason };
    }

    match evaluate_with_evidence(&unpacked.lib_bytes, &unpacked.manifest, policy) {
        Ok((verdict, accepted_release_keys_version)) => {
            let plugin = LoadablePlugin {
                file,
                manifest: unpacked.manifest,
                verdict,
                lib_bytes: std::sync::Arc::new(unpacked.lib_bytes),
                archive_sha256: Some(crate::sign::sha256_hex(&bytes)),
                accepted_release_keys_version,
                ephemeral: false,
                entry: None,
                keyed_by_alias: false,
            };

            match plugin.first_party() {
                true => FileOutcome::Loadable(plugin),
                false => match crate::sign::egress_grant(&plugin.manifest) {
                    Ok(()) => FileOutcome::Loadable(plugin),
                    Err(reason) => FileOutcome::Skipped(SkippedPlugin {
                        file: plugin.file,
                        manifest: plugin.manifest,
                        reason,
                        kind: crate::sign::RejectKind::EgressGrant,
                        trusted_keys: Vec::new(),
                    }),
                },
            }
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
                    "plugin name conflict: '{}' is claimed by both {} and {} - remove one \
                     (\"you can't use valkey and a third-party valkey\")", // noun-neutrality: frozen-literal pinned-by=crates/plugin-loader/tests/fixtures/conflict_messages.txt 1.5.5 operator boot and --validate refusal text, asserted byte for byte by registry_tests.rs
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
                FileOutcome::Loadable(p) if p.manifest.statement.is_none() => {
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
    Ok(PluginRegistry::of(loadable, 0, skipped))
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
            }]
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
                    Verdict::Allowed {
                        allow: crate::sign::AllowReason::Unsigned,
                        ..
                    } => "unsigned (allowed)".to_string(),
                    Verdict::Allowed {
                        allow: crate::sign::AllowReason::RetiredKey,
                        ..
                    } => "retired-key (allowed)".to_string(),
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
                use crate::sign::RejectKind;
                let signature = match s.kind {
                    RejectKind::AntiDowngrade => "trusted (below floor)",

                    RejectKind::UntrustedFloored => "untrusted (below floor)",
                    RejectKind::UnknownPublisher => "unknown-publisher",
                    RejectKind::Tampered => "tampered",
                    RejectKind::Unsigned => "unsigned",
                    RejectKind::EgressGrant => "third-party (egress grant)",
                    RejectKind::Superseded => "superseded",
                    RejectKind::RetiredKey => "retired-key",
                    RejectKind::Revoked => "revoked",
                }
                .to_string();
                let status = match s.kind {
                    RejectKind::AntiDowngrade | RejectKind::EgressGrant | RejectKind::Revoked => {
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
                row.status = format!("CONFLICT: {}", conflict.message);
            }
        }
    }
    rows
}

#[cfg(test)]
#[path = "tests/registry_tests.rs"]
mod tests;
