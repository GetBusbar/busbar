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

use crate::sign::{evaluate, validate_structure, Manifest, TrustPolicy, Verdict, HOST_IDENTITY};
use crate::tarball;
use busbar_contract::abi::cold::ColdEntry;
use busbar_contract::abi::mechanism::kind;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// The ONE version of each kind this binary accepts — the manifest `abi_version` a plugin of `kind`
/// must state (empty = unknown kind, refused at scan): exactly `abi::<kind>::ABI_VERSION`, the
/// shipped numbers (store 3, secret 2, auth 3, hook 2, export 3, plane 1, transport 1;
/// `BUSBAR-1.6.0.md` §11.2, A.9).
///
/// NO LEGACY LOADING (THE DESIGN §11.8): no ranges, no floors. A published 1.5.5 JSON-contract
/// plugin states its kind's 1.5.5 version and is refused at boot naming the rebuild against the
/// 1.6.0 SDK; a plugin built for a newer version than the host is refused too.
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
pub struct LoadablePlugin {
    /// The tarball filename (diagnostics only - identity is the manifest). A linked row's is
    /// [`LINKED_FILE`].
    pub file: String,
    pub manifest: Manifest,
    pub verdict: Verdict,
    pub lib_bytes: Vec<u8>,
    /// Whether what this plugin holds is lost on restart — a store's own statement ([`LinkedPlugin`]).
    /// A dropped-in row never states it: the plugins directory is where a durable store comes from.
    pub ephemeral: bool,
    /// A linked row's door; `None` for a dropped-in row, whose image is `lib_bytes`.
    entry: Option<LinkedEntry>,
}

impl LoadablePlugin {
    /// Whether this row is the build's in-process STORE ([`LinkedEntry::Store`]) — such a row is
    /// handed no configuration, so there is none to resolve for it.
    pub fn in_process(&self) -> bool {
        matches!(self.entry, Some(LinkedEntry::Store { .. }))
    }

    /// M6-COLD-DELETE residue: whether this row is a LINKED JSON-lane export sink
    /// (`BUSBAR_COLD_ENTRY`), the request-log file and webhook sinks until their door re-pins.
    pub fn image_is_cold_linked(&self) -> bool {
        matches!(self.entry, Some(LinkedEntry::Boundary(_)))
    }

    /// A compiled-in memory-ABI row's door; `None` for any other row.
    pub fn door(&self) -> Option<busbar_contract::abi::mechanism::door::DoorFn> {
        match self.entry {
            Some(LinkedEntry::Door(door)) | Some(LinkedEntry::Store { door }) => Some(door),
            _ => None,
        }
    }

    /// Whether this row came in through the LINKED door (it has no tarball).
    pub fn linked(&self) -> bool {
        self.entry.is_some()
    }

    /// What a JSON-lane load runs over (M6-COLD-DELETE residue: the hosted login and the two
    /// request-log sinks): the linked boundary, or the verified bytes.
    pub fn image(&self) -> crate::Image<'_> {
        match self.entry {
            Some(LinkedEntry::Boundary(entry)) => crate::Image::Linked(entry),
            _ => crate::Image::Bytes(&self.lib_bytes),
        }
    }

    /// FIRST-PARTY: admitted through the LINKED door, or dropped in and signed by the busbar
    /// release key under the trust policy — the plugins the host grants what they declare (K9a).
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
}

/// The refusal of a `kind: secret` plugin that states no door.
pub const JSON_SECRET_REFUSED: &str = "it speaks the 1.5.5 JSON secret contract, which this host does not load — rebuild the plugin against the 1.6.0 SDK";

/// The `file` a linked row reports: it has no tarball.
pub const LINKED_FILE: &str = "(linked)";

/// The kinds the LINKED door serves through the registry: every kind whose compiled-in row is a
/// memory-ABI door registered here. A plane is linked through its own door axis (`crate::boot`).
const LINKED_KINDS: &[&str] = &[
    kind::STORE,
    kind::SECRET,
    kind::AUTH,
    kind::HOOK,
    kind::EXPORT,
];

/// A plugin LINKED into this build (DECISIONS #2 rule (1)): the manifest its signed tarball would
/// carry — every statement about the plugin, none about an artifact (`sha256` and `signature`
/// describe a file it does not have) — and its door.
pub struct LinkedPlugin {
    pub manifest: Manifest,
    pub entry: LinkedEntry,
    /// [`LoadablePlugin::ephemeral`]: the plugin states that what it holds is lost on restart.
    pub ephemeral: bool,
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
    Door(busbar_contract::abi::mechanism::door::DoorFn),
    /// M6-COLD-DELETE residue: a linked JSON-lane export sink's SDK boundary (`BUSBAR_COLD_ENTRY`),
    /// the request-log file and webhook sinks until their door re-pins land.
    Boundary(&'static ColdEntry),
}

impl LinkedPlugin {
    /// This row, answering also to `former` — the names its earlier releases' manifests carried
    /// ([`Manifest::former_names`]), so a configuration naming one resolves to the linked row exactly
    /// as it does to the same plugin dropped in (compiled in = dropped in). Names already on the row
    /// are not repeated.
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

    /// M6-COLD-DELETE residue: a linked JSON-lane export sink, `manifest` and its boundary.
    pub fn boundary(manifest: Manifest, entry: &'static ColdEntry) -> Self {
        LinkedPlugin {
            manifest,
            entry: LinkedEntry::Boundary(entry),
            ephemeral: false,
        }
    }

    /// A linked MEMORY-ABI plugin: `manifest` and its door (THE DESIGN: compiled-in = dropped-in,
    /// the same door the dropped-in build exports).
    pub fn door(manifest: Manifest, door: busbar_contract::abi::mechanism::door::DoorFn) -> Self {
        LinkedPlugin {
            manifest,
            entry: LinkedEntry::Door(door),
            ephemeral: false,
        }
    }

    /// The build's in-process STORE named `name` (its own alias), at the store kind's one version:
    /// its store v3 `door`, and whether what it holds is lost on restart.
    pub fn store(
        name: &str,
        door: busbar_contract::abi::mechanism::door::DoorFn,
        ephemeral: bool,
    ) -> Self {
        let abi = busbar_contract::abi::store::ABI_VERSION;
        Self::built_in(
            name,
            kind::STORE,
            abi,
            LinkedEntry::Store { door },
            ephemeral,
        )
    }

    /// A linked AUTH plugin named `name` (its own alias) on the auth kind's MEMORY ABI: the logic
    /// crate's `plugin_door!` door, the same door its dropped-in build exports.
    pub fn auth_door(name: &str, door: busbar_contract::abi::mechanism::door::DoorFn) -> Self {
        Self::door_of_kind(kind::AUTH, name, door)
    }

    /// A linked memory-ABI plugin of `kind` named `name` (its own alias), at the kind's one version.
    pub fn door_of_kind(
        kind: &str,
        name: &str,
        door: busbar_contract::abi::mechanism::door::DoorFn,
    ) -> Self {
        let abi = supported_abi(kind).first().copied().unwrap_or_default();
        Self::built_in(name, kind, abi, LinkedEntry::Door(door), false)
    }

    /// The row a built-in states: the manifest a first-party tarball of `kind` would carry.
    fn built_in(
        name: &str,
        kind: &str,
        abi_version: u32,
        entry: LinkedEntry,
        ephemeral: bool,
    ) -> Self {
        LinkedPlugin {
            manifest: Manifest {
                name: name.into(),
                alias: name.into(),
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
        }
    }
}

/// A plugin that failed phase 2 (untrusted, no matching opt-in; or an anti-downgrade reject) and is
/// SKIPPED: recorded for logging/`--list-plugins`, never a load candidate, never `dlopen`ed.
pub struct SkippedPlugin {
    pub file: String,
    pub manifest: Manifest,
    pub reason: String,
    /// STRUCTURED rejection category from the trust evaluator — the authority for any label/column.
    /// Never derive a trust label by substring-matching `reason` (it embeds plugin-controlled bytes).
    pub kind: crate::sign::RejectKind,
}

/// The registry of validated, loadable plugins, addressable by canonical name OR alias. Built only
/// after all three phases pass; this is the ONLY resolution surface (`governance.store:` etc.), so
/// nothing outside the validated set can ever be selected.
pub struct PluginRegistry {
    /// Every row, in registration order: the linked rows, then the plugins directory's.
    rows: Vec<LoadablePlugin>,
    /// How many of `rows` are linked (they lead).
    linked: usize,
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
    /// An empty registry (plugins disabled / empty dir).
    pub fn empty() -> Self {
        Self::of(Vec::new(), 0, Vec::new())
    }

    /// A registry over `rows` (the first `linked` of them linked) and the skip list, each row
    /// registered through [`Self::admit`] in order.
    fn of(rows: Vec<LoadablePlugin>, linked: usize, skipped: Vec<SkippedPlugin>) -> Self {
        let mut registry = PluginRegistry {
            rows: Vec::new(),
            linked,
            skipped,
            by_name: HashMap::new(),
            by_alias: HashMap::new(),
        };
        for row in rows {
            registry.admit(row);
        }
        registry
    }

    /// THE REGISTRATION of one row on the axis — the ONE function both doors call (DECISIONS #2
    /// rule (1)): the row becomes resolvable by its name, by its alias and by each of its former
    /// names ([`Manifest::former_names`]). The FIRST row to register a name or alias holds it, so a
    /// linked row (registered first) is not displaced by a dropped-in one spelling the same name or
    /// alias, and no word is ever ambiguous otherwise: phase 3 refused a shared word among the
    /// dropped-in rows, and [`Self::link`] refuses a former name two plugins claim, or a word two
    /// linked plugins claim ([`cross_claim`]), before any of it got here.
    fn admit(&mut self, row: LoadablePlugin) {
        let i = self.rows.len();
        self.by_name.entry(row.manifest.name.clone()).or_insert(i);
        for word in row.manifest.config_names() {
            self.by_alias.entry(word.to_string()).or_insert(i);
        }
        self.rows.push(row);
    }

    /// THE LINKED DOOR: register `linked` ahead of every row already here, each through the SAME
    /// admission a dropped-in row takes — its manifest through the structural gate a signed one
    /// passes (every check but the artifact's integrity, which it has no artifact for), then the one
    /// registration (`admit`). FAIL-CLOSED: a linked plugin that would not pass is a refusal naming
    /// it, as an invalid tarball is.
    pub fn link(self, linked: Vec<LinkedPlugin>) -> Result<Self, String> {
        let mut rows = Vec::with_capacity(linked.len() + self.rows.len());
        for LinkedPlugin {
            manifest,
            entry,
            ephemeral,
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
                lib_bytes: Vec::new(),
                ephemeral,
                entry: Some(entry),
            });
        }
        let new = rows.len();
        let n = new + self.linked;
        rows.extend(self.rows);
        if let Some(refusal) = cross_claim(&rows, new) {
            return Err(refusal);
        }
        Ok(Self::of(rows, n, self.skipped))
    }

    /// Resolve `name_or_alias` (canonical name first, then alias or former name) to a loadable
    /// plugin.
    pub fn resolve(&self, name_or_alias: &str) -> Option<&LoadablePlugin> {
        self.by_name
            .get(name_or_alias)
            .or_else(|| self.by_alias.get(name_or_alias))
            .map(|&i| &self.rows[i])
    }

    /// Whether `name_or_alias` resolves to a loadable row of `kind`.
    pub fn answers(&self, name_or_alias: &str, kind: &str) -> bool {
        self.resolve(name_or_alias)
            .is_some_and(|p| p.manifest.kind == kind)
    }

    /// Why a reference cannot be resolved: if a SKIPPED plugin matches it, name the skip reason -
    /// "the plugin you asked for is here, but trust refused it" is the actionable message.
    pub fn unresolved_reason(&self, name_or_alias: &str) -> Option<&SkippedPlugin> {
        self.skipped
            .iter()
            .find(|s| s.manifest.answers_to(name_or_alias))
    }

    /// Every plugin the plugins DIRECTORY admitted (for logging / catalog / its own conflict and
    /// anti-downgrade bookkeeping, which are facts about that directory's tarballs).
    pub fn loadable(&self) -> &[LoadablePlugin] {
        &self.rows[self.linked..]
    }

    /// Every plugin this build linked, in registration order.
    pub fn linked(&self) -> &[LoadablePlugin] {
        &self.rows[..self.linked]
    }

    /// Every skipped plugin (for logging / catalog).
    pub fn skipped(&self) -> &[SkippedPlugin] {
        &self.skipped
    }

    /// Every DROPPED-IN `kind: hook` row, in scan order: the rows the hook axis reads its
    /// dropped-in candidates from ([`crate::hook_door::HookRows::new`]). The manifest's kind word is
    /// read here, where every other kind's is ([`Self::open_planes`], [`Self::open_transport_entries`]).
    pub fn dropped_hooks(&self) -> impl Iterator<Item = &LoadablePlugin> {
        self.loadable()
            .iter()
            .filter(|p| p.manifest.kind == kind::HOOK && !p.linked())
    }

    /// Resolve `name_or_alias` to a row of `kind`, or say why not — the one explanation every
    /// `open_*` below gives: a skipped match names the skip, a miss names the loadable set, a row of
    /// another kind says it cannot `role`.
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
                p.manifest.name, p.manifest.kind
            ));
        }
        Ok(p)
    }

    /// The STORE `name_or_alias` resolves to, refused unless its manifest says `store`. The one
    /// place the loader spells the store kind's root key; [`Self::store_door`] resolves through it.
    fn resolve_store(&self, name_or_alias: &str) -> Result<&LoadablePlugin, String> {
        self.resolve_kind(name_or_alias, "store", "back the governance store")
    }

    /// THE DOOR a STORE resolved by name or alias opens through (the store axis,
    /// `busbar_contract::store_calls::StoreAxis`): a linked row's store v3 door, or a dropped-in
    /// plugin's verified bytes with the Statement its signed manifest states. A store that states no
    /// door (a 1.5.5 JSON-contract plugin) is refused, naming the rebuild.
    ///
    /// # Errors
    /// The name resolves to no store, or the store states no door.
    pub fn store_door(
        &self,
        name_or_alias: &str,
    ) -> Result<busbar_contract::store_calls::StoreDoor, String> {
        use busbar_contract::store_calls::StoreDoor;
        let p = self.resolve_store(name_or_alias)?;
        let no_door = || {
            format!(
                "plugin '{}' states no store door: rebuild the plugin against the 1.6.0 SDK",
                p.manifest.name
            )
        };
        if let Some(entry) = p.entry {
            return match entry {
                LinkedEntry::Store { door } => Ok(StoreDoor::Linked(door)),
                LinkedEntry::Door(_) | LinkedEntry::Boundary(_) => Err(no_door()),
            };
        }
        let named = |e: String| format!("plugin '{}': {e}", p.manifest.name);
        match p.manifest.stated_rendering().map_err(named)? {
            Some(stated) => Ok(StoreDoor::Dropped {
                file: p.file.clone(),
                bytes: std::sync::Arc::new(p.lib_bytes.clone()),
                stated,
            }),
            None => Err(no_door()),
        }
    }

    /// M6-COLD-DELETE: whether the `kind: auth` row `name_or_alias` resolves to opens on the COLD
    /// auth lane — a linked `BUSBAR_COLD_ENTRY`, or a dropped-in library with no door and no
    /// Statement (`crate::auth_axis::AuthRows` opens such a row through its `ColdAuth`) — rather
    /// than on the auth kind's memory ABI. A cold row's `verify` is a synchronous call that may
    /// block: its caller keeps it off an async worker.
    ///
    /// # Errors
    /// No row resolves to `name_or_alias`, or it is not `kind: auth`, in [`Self::open_auth`]'s words.
    /// A name only a door's Statement alias answers resolves to no row here: the auth axis answers it.
    pub fn auth_row_is_cold(&self, name_or_alias: &str) -> Result<bool, String> {
        let p = self.resolve_kind(name_or_alias, "auth", "serve as an auth module")?;
        Ok(p.door().is_none()
            && (p.image_is_cold_linked() || matches!(p.manifest.stated_rendering(), Ok(None))))
    }

    /// Open an AUTH plugin resolved by name or alias: verifies the resolved plugin's `kind` is `auth`,
    /// then loads it over the kind-neutral C ABI and `open`s it with `cfg_json`, returning
    /// `Box<dyn AuthModule>` — the seam the engine's auth chain consumes. Same trust and load
    /// pipeline as store/secret; only the kind (and the consuming seam) differs. FAIL-CLOSED.
    pub fn open_auth(
        &self,
        name_or_alias: &str,
        cfg_json: &str,
    ) -> Result<Box<dyn busbar_contract::auth::AuthModule>, String> {
        let p = self.resolve_kind(name_or_alias, "auth", "serve as an auth module")?;
        if p.door().is_some() {
            return Err(format!(
                "auth plugin '{name_or_alias}' is on the memory ABI: it opens through the auth \
                 axis, not the cold lane"
            ));
        }
        crate::auth::load_auth_image(p.image(), cfg_json, &p.manifest.name, &p.manifest.kind)
    }

    /// M6-COLD-DELETE RESIDUE (deleted when the hosted login moves onto the auth door): open an AUTH
    /// plugin as the unified [`busbar_contract::auth::AuthPlugin`] handle, KEEPING the `LoginModule`
    /// capability the hosted browser-login flow (`auth.methods`, 1.5.2) drives. Also
    /// returns the resolved plugin's manifest `abi_version` so the caller can gate v2-only login
    /// methods (a `browser_login` method needs an ABI v2 login-capable plugin). FAIL-CLOSED.
    pub fn open_login(
        &self,
        name_or_alias: &str,
        cfg_json: &str,
    ) -> Result<(Box<dyn busbar_contract::auth::AuthPlugin>, u32), String> {
        let p = self.resolve_kind(name_or_alias, "auth", "serve as a login module")?;
        let abi_version = p.manifest.abi_version;
        let module =
            crate::auth::load_login_image(p.image(), cfg_json, &p.manifest.name, &p.manifest.kind)?;
        Ok((module, abi_version))
    }

    /// Why no secret plugin answers `name_or_alias` on the secret axis: no `kind: secret` row
    /// resolves to it (in [`Self::resolve_kind`]'s words), or the row states no door — a 1.5.5
    /// JSON-contract secret plugin, refused naming the rebuild (THE DESIGN §11.8).
    #[must_use]
    pub fn secret_refusal(&self, name_or_alias: &str) -> String {
        match self.resolve_kind(name_or_alias, kind::SECRET, "resolve config secrets") {
            Err(e) => e,
            Ok(p) => format!("plugin '{}': {JSON_SECRET_REFUSED}", p.manifest.name),
        }
    }

    /// Open a PLANE resolved by name or alias: verifies the resolved plugin's `kind` is `plane`, then
    /// loads the VERIFIED bytes over the HOT-tier ABI (`busbar_contract::abi::hot`) and reads its
    /// [`PlaneDecl`](busbar_contract::abi::hot::PlaneDecl), returning a [`crate::DynPlane`] — the boundary-safe
    /// handle the composition root drives exactly as it drives a compiled-in plane. Same trust and
    /// load pipeline as store/secret/auth/hook/export; only the kind (and the driving seam) differs.
    /// FAIL-CLOSED on any resolution/kind/load failure. The 1.6.0 S4 both-ways entrypoint for planes.
    pub fn open_plane(&self, name_or_alias: &str) -> Result<crate::DynPlane, String> {
        let p = self.resolve_kind(name_or_alias, "plane", "serve as a protocol plane")?;
        crate::plane::load_plane_from_bytes(&p.lib_bytes, &p.manifest.name, &p.manifest.kind)
    }

    /// Open a TRANSPORT resolved by name or alias: verifies the resolved plugin's `kind` is
    /// `transport`, then loads the VERIFIED bytes over the HOT-tier ABI and admits its
    /// [`TransportDecl`](busbar_contract::abi::hot::TransportDecl) through the SAME admission a linked
    /// transport takes ([`crate::link_transport`]), returning the [`crate::DynTransport`] row the
    /// composition root folds. FAIL-CLOSED on any resolution/kind/load failure.
    pub fn open_transport(&self, name_or_alias: &str) -> Result<crate::DynTransport, String> {
        let p = self.resolve_kind(name_or_alias, "transport", "carry bytes as a transport")?;
        crate::transport::load_transport_from_bytes(
            &p.lib_bytes,
            &p.manifest.name,
            &p.manifest.kind,
        )
    }

    /// Open EVERY loadable transport, in scan order, each through the lane its image speaks: a
    /// library with the memory-ABI door ([`busbar_contract::abi::mechanism::DOOR_SYMBOL`]) is
    /// admitted through the one dispatcher's door validation and bound with `bind`, labelled with
    /// its own plugin name (each opened door is its own instance to the host services); any other
    /// through the HOT decl ([`Self::open_transport`]'s lane). Each image is staged and opened once.
    /// The first that will not load fails the whole set, naming it.
    ///
    /// # Errors
    ///
    /// The plugin that would not load, and why.
    pub fn open_transport_entries(
        &self,
        bind: &crate::dispatch::Bind,
    ) -> Result<TransportEntries, String> {
        use crate::dispatch::load::{load_staged, Staging};
        let mut entries = TransportEntries::default();
        for p in self
            .loadable()
            .iter()
            .filter(|p| p.manifest.kind == kind::TRANSPORT)
        {
            let name = &p.manifest.name;
            let stated = p.manifest.stated_rendering()?;
            let (lib, staged) = crate::stage::load_library_from_bytes(&p.lib_bytes, name)?;
            match load_staged::<crate::dispatch::kinds::transport::Transport>(
                lib,
                staged,
                stated.as_deref(),
                crate::dispatch::Bind {
                    instance: std::sync::Arc::from(name.as_str()),
                    ..bind.clone()
                },
            )
            .map_err(|e| format!("transport plugin '{name}' refused at its door: {e}"))?
            {
                Staging::Door(plugin) => entries.doors.push(plugin),
                Staging::NotADoor(lib, staged) => {
                    entries.hot.push(crate::transport::wire_up_transport(
                        lib,
                        name.clone(),
                        &p.manifest.kind,
                        Some(staged),
                    )?)
                }
            }
        }
        Ok(entries)
    }

    /// THE PLANES, discovered for the one load: every compiled-in plane door in `linked`, then every
    /// loadable dropped-in plane whose signed manifest states a Statement, as a
    /// [`crate::boot::Candidate`] ([`crate::boot::load_planes`] binds them through
    /// `load_linked`/`load_dropped` on the process's dispatcher). A dropped-in plane with no
    /// Statement (a HOT-lane `PlaneDecl` cdylib) is opened here over the HOT-tier ABI
    /// ([`Self::open_plane`]).
    ///
    /// M6-HOT-PLANE: the HOT-lane branch is transitional. Each linked HOT-lane plane leaves it in its
    /// own fold's series (one per plane, `1.6.0-TODO.md`), which ship the plane's door export and its
    /// linked door row; the last fold deletes this branch and the HOT declaration read.
    ///
    /// # Errors
    ///
    /// The first plane that will not state itself or load, named: a trusted plane that cannot be
    /// admitted is not skipped.
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
            let named = |e: String| format!("plugin '{}': {e}", p.manifest.name);
            match p.manifest.stated_rendering().map_err(named)? {
                Some(stated) => set.doors.push(
                    crate::boot::Candidate::from_manifest(
                        stated,
                        &p.manifest,
                        crate::boot::Origin::Dropped {
                            file: p.file.clone(),
                            bytes: std::sync::Arc::new(p.lib_bytes.clone()),
                        },
                    )
                    .map_err(named)?,
                ),
                None => set.hot.push(self.open_plane(&p.manifest.name)?),
            }
        }
        Ok(set)
    }
}

/// THE ONE-OWNER RULE across the doors (ARCHITECT, legacy names): a name, alias or former name
/// config may reference resolves to exactly one plugin. `rows` is the registry about to be built,
/// its first `new` rows the ones being linked; each is checked against every row after it (the
/// other linked rows and every row already admitted: earlier linked rows and the plugins
/// directory's). Two DIFFERENT plugins (different canonical names) claiming one word refuse the
/// boot, naming both and the word, when the word is a FORMER NAME of either (a legacy name never
/// resolves ambiguously) or when both rows are linked. Two DROPPED-IN rows were already held to this
/// by phase 3 ([`conflicts`]).
///
/// The one exception is the design's own: a LINKED row answers its name and alias ahead of a
/// dropped-in row spelling the same word ([`PluginRegistry::admit`]; K9e-2 "a dropped-in row never
/// takes a module from the sink this build links"), so a name/alias a linked row and a dropped-in
/// row share is not refused. The same plugin linked and dropped in (one canonical name) is never a
/// conflict.
fn cross_claim(rows: &[LoadablePlugin], new: usize) -> Option<String> {
    for (i, a) in rows.iter().enumerate().take(new) {
        for b in &rows[i + 1..] {
            if a.manifest.name == b.manifest.name {
                continue;
            }
            let legacy = |w: &str| {
                a.manifest.former_names.iter().any(|f| f == w)
                    || b.manifest.former_names.iter().any(|f| f == w)
            };
            let contested = a
                .manifest
                .identities()
                .find(|w| b.manifest.answers_to(w) && (b.linked() || legacy(w)));
            if let Some(word) = contested {
                return Some(format!(
                    "plugin claim conflict: '{word}' is claimed by both {} ({}) and {} ({}) - \
                     a name, alias or former name must resolve to one plugin; remove one",
                    a.file, a.manifest.name, b.file, b.manifest.name
                ));
            }
        }
    }
    None
}

/// The transports a plugins directory contributes, by the lane each image speaks
/// ([`PluginRegistry::open_transport_entries`]).
#[derive(Default)]
pub struct TransportEntries {
    /// HOT-decl wires.
    pub hot: Vec<crate::DynTransport>,
    /// Memory-ABI transport doors, bound.
    pub doors: Vec<crate::dispatch::Plugin<crate::dispatch::kinds::transport::Transport>>,
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

/// Read a file fully, but bounded at `cap` bytes STREAMED — never trusting `metadata().len()` for the
/// bound. The size pre-check in [`examine`] rejects a declared-oversize file cheaply, but `fs::read`
/// afterwards reads the file as it is at read time; a file swapped larger between the stat and the
/// read would slip past that pre-check unbounded (a boot-time TOCTOU). Bounding the STREAM with
/// `take(cap + 1)` makes the cap real: at most `cap + 1` bytes ever enter memory, and one byte over is
/// a hard reject. Pure enough to unit-test without touching the rest of the scan pipeline.
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
    // Read with the cap enforced on the STREAM, not on `metadata().len()`. The size check above is a
    // cheap early reject, but on its own it is a TOCTOU: `fs::read` sizes and then reads the file as it
    // is NOW, so a file swapped for a larger one AFTER the stat is read in full — the cap the stat
    // enforced is bypassable, an unbounded read on every boot-time scan. `read_file_capped` bounds the
    // read with `take(cap + 1)`, so the cap holds regardless of any swap between check and use.
    let bytes = match read_file_capped(path, tarball::MAX_TARBALL_FILE_BYTES) {
        Ok(b) => b,
        Err(reason) => return FileOutcome::Invalid { file, reason },
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
            ephemeral: false,
            entry: None,
        }),
        Err(rejected) => FileOutcome::Skipped(SkippedPlugin {
            file,
            manifest: unpacked.manifest,
            reason: rejected.reason,
            kind: rejected.kind,
        }),
    }
}

/// ONE phase-3 conflict: the operator-facing message, and — STRUCTURED, beside it — the tarballs it
/// is about.
///
/// The files are carried rather than left to be recovered from the message, because every identifier
/// the message names (`name`, `alias`) is bytes a plugin AUTHOR chose. Asking "is this row one of the
/// ones this conflict is about?" by looking for the row's quoted name inside the prose answers yes for
/// any row whose name happens to appear in a message about two OTHER plugins — a plugin named
/// `remove one`, or one whose name is a substring the message spells for a different reason. The
/// files are the loader's own facts, so the join is exact.
pub struct Conflict {
    /// The operator-facing text, unchanged from what the loader has always printed.
    pub message: String,
    /// The tarball filenames this conflict is about (the `file` an [`InventoryEntry`] carries).
    pub files: Vec<String>,
}

/// Phase 3: cross-plugin conflict detection over the LOADABLE set. Any name/alias/former-name
/// collision is a hard error naming BOTH plugins and the colliding identifier.
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
        // An alias colliding with ANOTHER plugin's canonical name is equally ambiguous.
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
    // A FORMER NAME is a reference the registry resolves like the alias, so it collides like one:
    // with another plugin's name, alias or former name. A former name two plugins share is reported
    // once, at the later of the two.
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
    errors.extend(conflicts(&loadable).into_iter().map(|c| c.message));
    if !errors.is_empty() {
        return Err(errors);
    }
    Ok(PluginRegistry::of(loadable, 0, skipped))
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
                        allow: crate::sign::AllowReason::Unsigned,
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
                use crate::sign::RejectKind;
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
    // Surface phase-3 conflicts on the affected loadable rows. The join is on the tarball the
    // conflict NAMES, never on finding the row's identifier somewhere inside the message — the
    // identifiers in that prose are plugin-author bytes, and a row that merely shares them with a
    // conflict about two other plugins is not a row in conflict.
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
