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
use busbar_plugin::cold::ColdEntry;
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
        // `Identity` still loads and works; v3 wraps the same answers in the observability
        // envelope (#85), which the decoder reads beside the bare shape. `[1, AUTH_ABI_VERSION]` =
        // `[1, 3]`.
        "auth" => &[1, busbar_plugin::cold::AUTH_ABI_VERSION],
        // A `kind: hook` plugin is an in-process routing policy (the engine's routing/hook chains
        // consume `Arc<dyn RoutingPolicy>` via `open_hook`). The 1.5.0 replacement for the retired
        // out-of-process socket/webhook hook transport. Payload schema v1 (bare replies) up to v2
        // (the same replies inside the observability envelope, #85): the decoder accepts either
        // shape, so THE FLOOR STAYS 1 and every published hook keeps loading.
        "hook" => &[1, busbar_plugin::cold::hook::HOOK_ABI_VERSION],
        // A `kind: export` plugin is a telemetry sink the engine's observability seam feeds
        // (`open_export`). Payload schema v2 (`streams`/`deliver`): 1.5.3 expanded the stream
        // vocabulary and REMOVED `audit` — an auditor is a projection made of other streams, not a
        // data type of its own — so a v1 sink that declared `audit` no longer has a stream to
        // declare, and v1 is not accepted here.
        // v3 (DECISIONS #85) wraps the response in the observability envelope; v2 answers bare. BOTH
        // load — the decoder accepts either shape and they are disjoint — so the FLOOR stays at the
        // 1.5.3 vocabulary version and the envelope landing refuses no published sink.
        "export" => &[2, busbar_plugin::cold::export::EXPORT_ABI_VERSION],
        // A `kind: plane` plugin is a protocol plane delivered as a `cdylib` and driven over the
        // HOT-tier `#[repr(C)]` `PlaneDecl` vtable (`busbar_plugin::hot`) — NOT the six-symbol JSON
        // `call` wire the five cold kinds share. Its per-kind PAYLOAD axis is the AIRLOCK MINOR
        // (`busbar_plugin::ABI_MINOR`): a plane cdylib stamps that minor into its `PlaneDecl`'s frozen
        // `AbiPreamble`, and `open_plane` fail-closes on a MAJOR mismatch while accepting an older
        // minor (append-only). The manifest `abi_version` a plane declares is that same minor, floored
        // at 1 (the first minor a plane ABI could target) so an older-minor plane still validates and
        // its real forward-compat gate is the airlock `check_preamble` at load. `[1, ABI_MINOR]`.
        "plane" => &[1, busbar_plugin::ABI_MINOR],
        // No arm for `transport`, deliberately: the contract names seven kinds, and a transport is
        // in-tree only (compiled into the binary, never dynamically loaded). A dropped-in
        // `kind: transport` tarball is refused, and [`kind_refusal_note`] says why.
        _ => &[],
    }
}

/// The explanation a refusal appends for a kind this binary will not load, so an operator who drops
/// in a `kind: transport` tarball is told the kind is compiled-in only rather than merely that it is
/// not in a list. Empty for every other kind.
#[must_use]
pub fn kind_refusal_note(kind: &str) -> &'static str {
    match kind {
        "transport" => {
            " — transports are in-tree only: a transport is compiled into the busbar binary and is \
             never loaded from the plugins folder"
        }
        _ => "",
    }
}

/// ONE ROW of the cold-kind axis: a plugin the registry resolves by name or alias and loads over its
/// [`crate::Image`]. A DROPPED-IN row passed phases 1 + 2 — its signed manifest, the trust verdict,
/// and the exact verified library bytes (what the loader will map, never re-read from disk). A
/// LINKED row ([`LinkedPlugin`], [`PluginRegistry::link`]) states the same manifest and carries its
/// boundary instead of bytes. Both are registered by the one [`PluginRegistry`] admission and loaded
/// by the one load; nothing downstream reads which door a row came in by.
pub struct LoadablePlugin {
    /// The tarball filename (diagnostics only - identity is the manifest). A linked row's is
    /// [`LINKED_FILE`].
    pub file: String,
    pub manifest: Manifest,
    pub verdict: Verdict,
    pub lib_bytes: Vec<u8>,
    /// A linked row's boundary; `None` for a dropped-in row, whose boundary is `lib_bytes`.
    entry: Option<&'static ColdEntry>,
}

impl LoadablePlugin {
    /// What the one load runs over: the linked boundary, or the verified bytes.
    pub fn image(&self) -> crate::Image<'_> {
        match self.entry {
            Some(entry) => crate::Image::Linked(entry),
            None => crate::Image::Bytes(&self.lib_bytes),
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

/// The `file` a linked row reports: it has no tarball.
pub const LINKED_FILE: &str = "(linked)";

/// The kinds the LINKED door serves: the cold kinds whose load is the one [`crate::Image`] load —
/// an export sink's included (item 141). A plane is linked through [`crate::link_plane`] (its
/// HOT-lane airlock).
const LINKED_KINDS: &[&str] = &[
    busbar_plugin::cold::kind::STORE,
    busbar_plugin::cold::kind::SECRET,
    busbar_plugin::cold::kind::AUTH,
    busbar_plugin::cold::kind::HOOK,
    busbar_plugin::cold::kind::EXPORT,
];

/// A cold-lane plugin LINKED into this build (DECISIONS #2 rule (1)): the manifest its signed
/// tarball would carry — every statement about the plugin, none about an artifact (`sha256` and
/// `signature` describe a file it does not have) — and its boundary, the SDK's `BUSBAR_COLD_ENTRY`.
pub struct LinkedPlugin {
    pub manifest: Manifest,
    pub entry: &'static ColdEntry,
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
    /// name -> index into `rows`; alias -> index (aliases equal to the own name are fine).
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
    /// rule (1)): the row becomes resolvable by its name and by its alias. The FIRST row to register
    /// a name or alias holds it, so a linked row (registered first) is not displaced by a dropped-in
    /// one spelling the same name, and two dropped-in rows never share one: phase 3 refused that set
    /// before any of it got here.
    fn admit(&mut self, row: LoadablePlugin) {
        let i = self.rows.len();
        self.by_name.entry(row.manifest.name.clone()).or_insert(i);
        self.by_alias.entry(row.manifest.alias.clone()).or_insert(i);
        self.rows.push(row);
    }

    /// THE LINKED DOOR: register `linked` ahead of every row already here, each through the SAME
    /// admission a dropped-in row takes — its manifest through the structural gate a signed one
    /// passes (every check but the artifact's integrity, which it has no artifact for), then the one
    /// registration (`admit`). FAIL-CLOSED: a linked plugin that would not pass is a refusal naming
    /// it, as an invalid tarball is.
    pub fn link(self, linked: Vec<LinkedPlugin>) -> Result<Self, String> {
        let mut rows = Vec::with_capacity(linked.len() + self.rows.len());
        for LinkedPlugin { manifest, entry } in linked {
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
                entry: Some(entry),
            });
        }
        let n = rows.len() + self.linked;
        rows.extend(self.rows);
        Ok(Self::of(rows, n, self.skipped))
    }

    /// Resolve `name_or_alias` (canonical name first, then alias) to a loadable plugin.
    pub fn resolve(&self, name_or_alias: &str) -> Option<&LoadablePlugin> {
        self.by_name
            .get(name_or_alias)
            .or_else(|| self.by_alias.get(name_or_alias))
            .map(|&i| &self.rows[i])
    }

    /// Why a reference cannot be resolved: if a SKIPPED plugin matches it, name the skip reason -
    /// "the plugin you asked for is here, but trust refused it" is the actionable message.
    pub fn unresolved_reason(&self, name_or_alias: &str) -> Option<&SkippedPlugin> {
        self.skipped
            .iter()
            .find(|s| s.manifest.name == name_or_alias || s.manifest.alias == name_or_alias)
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

    /// Resolve `name_or_alias` to a row of `kind`, or say why not — the one explanation every
    /// `open_*` below gives: a skipped match names the skip, a miss names the loadable set, a row of
    /// another kind says it cannot `role`.
    fn resolve_kind(
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

    /// Open a STORE plugin resolved by name or alias: verifies the resolved plugin's `kind` is
    /// `store`, then loads it over the store C ABI (its verified bytes staged — memfd on Linux,
    /// private temp elsewhere — or its linked boundary) and `open`s it with `cfg_json`. The one
    /// engine-facing load entrypoint.
    pub fn open_store(
        &self,
        name_or_alias: &str,
        cfg_json: &str,
    ) -> Result<Box<dyn busbar_api::Store>, String> {
        let p = self.resolve_kind(name_or_alias, "store", "back the governance store")?;
        // Hand the manifest's payload schema to the loader: a store built against an older schema
        // is spoken to in the shape it can decode (the usage-ledger ops changed shape in 1.6.0).
        crate::load_store_image(
            p.image(),
            cfg_json,
            &p.manifest.name,
            &p.manifest.kind,
            p.manifest.abi_version,
        )
    }

    /// Open an AUTH plugin resolved by name or alias: verifies the resolved plugin's `kind` is `auth`,
    /// then loads it over the kind-neutral C ABI and `open`s it with `cfg_json`, returning
    /// `Box<dyn AuthModule>` — the seam the engine's auth chain consumes. Same trust and load
    /// pipeline as store/secret; only the kind (and the consuming seam) differs. FAIL-CLOSED.
    pub fn open_auth(
        &self,
        name_or_alias: &str,
        cfg_json: &str,
    ) -> Result<Box<dyn busbar_api::AuthModule>, String> {
        let p = self.resolve_kind(name_or_alias, "auth", "serve as an auth module")?;
        crate::auth::load_auth_image(p.image(), cfg_json, &p.manifest.name, &p.manifest.kind)
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
        let p = self.resolve_kind(name_or_alias, "auth", "serve as a login module")?;
        let abi_version = p.manifest.abi_version;
        let module =
            crate::auth::load_login_image(p.image(), cfg_json, &p.manifest.name, &p.manifest.kind)?;
        Ok((module, abi_version))
    }

    /// Open a HOOK plugin resolved by name or alias: verifies the resolved plugin's `kind` is `hook`,
    /// then loads it over the kind-neutral C ABI and `open`s it with `cfg_json`, returning
    /// `Arc<dyn RoutingPolicy>` — the seam the engine's routing/hook chains consume. Same trust and
    /// load pipeline as store/secret/auth; only the kind (and consuming seam) differs. `name` is the
    /// hook's registry name (metrics id); `projectors` are the engine's fail-closed projection/parse
    /// closures. FAIL-CLOSED on any resolution/kind/load failure.
    pub fn open_hook(
        &self,
        name_or_alias: &str,
        cfg_json: &str,
        name: &str,
        projectors: std::sync::Arc<crate::hook::HookProjectors>,
    ) -> Result<std::sync::Arc<dyn busbar_api::RoutingPolicy>, String> {
        let p = self.resolve_kind(name_or_alias, "hook", "serve as a routing hook")?;
        crate::hook::load_hook_image(
            p.image(),
            cfg_json,
            &p.manifest.name,
            &p.manifest.kind,
            name,
            projectors,
        )
    }

    /// Open a SECRET plugin resolved by name or alias: verifies the resolved plugin's `kind` is
    /// `secret`, then loads it over the secret C ABI and `open`s it with `cfg_json`. Same trust and
    /// load pipeline as a store plugin - only the kind (and the seam consuming it) differs.
    /// FAIL-CLOSED: any resolution/kind/load failure is an error the caller surfaces as an
    /// unresolvable secret.
    pub fn open_secret(
        &self,
        name_or_alias: &str,
        cfg_json: &str,
    ) -> Result<Box<dyn busbar_api::SecretModule>, String> {
        let p = self.resolve_kind(name_or_alias, "secret", "resolve config secrets")?;
        crate::load_secret_image(p.image(), cfg_json, &p.manifest.name, &p.manifest.kind)
    }

    /// Open an EXPORT sink resolved by name or alias: verifies the resolved plugin's `kind` is
    /// `export`, then loads it over the kind-neutral C ABI (its verified bytes, or its linked
    /// boundary) and `open`s it with
    /// `cfg_json`, returning a [`crate::export::DynExport`] whose declared streams were queried once at
    /// load. Same trust and load pipeline as store/secret/auth/hook; only the kind (and the consuming
    /// seam) differs. FAIL-CLOSED on any resolution/kind/load failure.
    pub fn open_export(
        &self,
        name_or_alias: &str,
        cfg_json: &str,
    ) -> Result<crate::export::DynExport, String> {
        let p = self.resolve_kind(name_or_alias, "export", "serve as a telemetry sink")?;
        let (name, declares) = (&p.manifest.name, &p.manifest.declares);
        crate::observe::grant_series(name, p.first_party(), &declares.metrics)?;
        crate::export::load_export_image(p.image(), cfg_json, name, &p.manifest.kind)?
            .with_destinations(&declares.destinations, cfg_json)
    }

    /// Open a PLANE resolved by name or alias: verifies the resolved plugin's `kind` is `plane`, then
    /// loads the VERIFIED bytes over the HOT-tier ABI (`busbar_plugin::hot`) and reads its
    /// [`PlaneDecl`](busbar_plugin::hot::PlaneDecl), returning a [`crate::DynPlane`] — the boundary-safe
    /// handle the composition root drives exactly as it drives a compiled-in plane. Same trust and
    /// load pipeline as store/secret/auth/hook/export; only the kind (and the driving seam) differs.
    /// FAIL-CLOSED on any resolution/kind/load failure. The 1.6.0 S4 both-ways entrypoint for planes.
    pub fn open_plane(&self, name_or_alias: &str) -> Result<crate::DynPlane, String> {
        let p = self.resolve_kind(name_or_alias, "plane", "serve as a protocol plane")?;
        crate::plane::load_plane_from_bytes(&p.lib_bytes, &p.manifest.name, &p.manifest.kind)
    }

    /// Open EVERY loadable plane, in scan (filename) order, through [`Self::open_plane`] — the planes
    /// a dropped-in plugins directory contributes to the plane axis. The first that will not load
    /// fails the whole set, naming it: a trusted plane that cannot be admitted is not skipped.
    pub fn open_planes(&self) -> Result<Vec<crate::DynPlane>, String> {
        self.loadable()
            .iter()
            .filter(|p| p.manifest.kind == busbar_plugin::cold::kind::PLANE)
            .map(|p| self.open_plane(&p.manifest.name))
            .collect()
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

/// Phase 3: cross-plugin conflict detection over the LOADABLE set. Any name/alias collision is a
/// hard error naming BOTH plugins and the colliding identifier.
fn conflicts(loadable: &[LoadablePlugin]) -> Vec<Conflict> {
    let mut errors = Vec::new();
    let mut name_owner: HashMap<&str, &LoadablePlugin> = HashMap::new();
    for p in loadable {
        if let Some(prev) = name_owner.get(p.manifest.name.as_str()) {
            errors.push(Conflict {
                message: format!(
                    "plugin name conflict: '{}' is claimed by both {} and {} - remove one \
                     (\"you can't use valkey and a third-party valkey\")",
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

#[cfg(test)]
#[path = "tests/kind_refusal_tests.rs"]
mod kind_refusal_tests;
