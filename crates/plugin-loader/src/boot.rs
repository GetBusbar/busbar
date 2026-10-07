// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE BOOT STAGES the loader owns (`BUSBAR-1.6.0.md` THE DESIGN, §3 Boot): what the configuration
//! USES (read from stage 0's plan), DISCOVER (stage 1: each plugin's facts, read from the linked
//! row or the signed manifest, nothing loaded), SELECT (stage 2: the plugins the configuration uses,
//! BUSBAR-1.6.0.md §2 "A plugin loads if and only if config uses it", §4 "Selection follows the classes") and the
//! ONE LOAD (every selected instance bound through the one dispatcher, each to its own log sink).
//!
//! [`Uses::of`], [`Candidate`] and [`select`] are pure: no file is read, nothing is opened, no
//! library is loaded, so `--validate` (stages 0-2) and `--list-plugins` run them without dialing
//! or opening anything. [`load`] is the only function here that opens a plugin.

use std::collections::BTreeSet;
use std::sync::Arc;

use busbar_contract::abi::host::conn::connector::DIRECTION_INBOUND;
use busbar_contract::abi::mechanism::door::{
    DoorFn, REWRITE_ALIAS, REWRITE_SUGAR, SECTION_DECLARING,
};
use busbar_contract::abi::mechanism::rendering::{read, Read, ReadNeed};
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::plugin::Kind;

use crate::dispatch::kinds::{
    auth::Auth, export::Export, hook::Hook, plane::Plane, secret::Secret, store::Store,
    transport::Transport,
};
use crate::dispatch::{
    load_dropped_bytes, load_linked, Adopter, Bind, EnvelopeSink, LinkedRow, Plugin,
    PluginLogConfig,
};

/// The kind a [`KindCode`] names, in the contract's kind vocabulary (whose [`Kind::root_key`] is
/// the ONE spelling of each kind's root key).
#[must_use]
pub const fn kind_of(code: KindCode) -> Kind {
    match code {
        KindCode::Store => Kind::Store,
        KindCode::Secret => Kind::Secret,
        KindCode::Auth => Kind::Auth,
        KindCode::Hook => Kind::Hook,
        KindCode::Export => Kind::Export,
        KindCode::Plane => Kind::Plane,
        KindCode::Transport => Kind::Transport,
    }
}

// ── USES: what the configuration names, read from the plan's document ──────────────────────────

/// WHAT THE CONFIGURATION USES, by the three classes of root key (BUSBAR-1.6.0.md §4): the root keys it
/// carries (a plane is used iff its verb is one), every `module:` an entry under a non-plane kind's
/// root key names, the reference keys it spells (`{k: X}`, a plugin's sugar), and the URL schemes its
/// URLs use (a transport is used iff it claims one).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Uses {
    /// The document's root keys.
    pub roots: BTreeSet<String>,
    /// `(kind, instance, module)`: each entry under a non-plane kind's root key, by its key.
    pub modules: Vec<(KindCode, String, String)>,
    /// Every key of a one-key mapping anywhere in the document: a reference's sugar word.
    pub refs: BTreeSet<String>,
    /// Every URL scheme a string value anywhere under `providers:` or a non-plane kind's root key
    /// uses (`scheme://…`).
    pub schemes: BTreeSet<String>,
}

/// The non-plane kinds whose root key holds a `module:`-naming definition.
const DEFINED: [KindCode; 5] = [
    KindCode::Store,
    KindCode::Secret,
    KindCode::Auth,
    KindCode::Hook,
    KindCode::Export,
];

impl Uses {
    /// What `doc` (the plan's document, secret references still raw) uses.
    #[must_use]
    pub fn of(doc: &serde_json::Value) -> Self {
        let mut uses = Uses::default();
        let Some(root) = doc.as_object() else {
            return uses;
        };
        uses.roots = root.keys().cloned().collect();
        refs(doc, &mut uses.refs);
        for code in DEFINED {
            let Some(key) = kind_of(code).root_key() else {
                continue;
            };
            let Some(v) = root.get(key) else {
                continue;
            };
            schemes(v, &mut uses.schemes);
            match (code, v.as_object()) {
                // One instance, `{module, settings}`.
                (KindCode::Store, Some(entry)) => {
                    if let Some(m) = entry.get("module").and_then(|m| m.as_str()) {
                        uses.modules.push((code, key.to_string(), m.to_string()));
                    }
                }
                // Module-level settings, keyed by module.
                (KindCode::Secret, Some(map)) => {
                    for m in map.keys() {
                        uses.modules.push((code, m.clone(), m.clone()));
                    }
                }
                // Named definitions, each naming its module.
                (_, Some(map)) => {
                    for (name, entry) in map {
                        if let Some(m) = entry.get("module").and_then(|m| m.as_str()) {
                            uses.modules.push((code, name.clone(), m.to_string()));
                        }
                    }
                }
                _ => {}
            }
        }
        if let Some(v) = kind_of(KindCode::Transport)
            .root_key()
            .and_then(|k| root.get(k))
        {
            schemes(v, &mut uses.schemes);
        }
        uses
    }
}

fn refs(v: &serde_json::Value, out: &mut BTreeSet<String>) {
    match v {
        serde_json::Value::Object(map) => {
            if map.len() == 1 {
                out.extend(map.keys().cloned());
            }
            map.values().for_each(|v| refs(v, out));
        }
        serde_json::Value::Array(items) => items.iter().for_each(|v| refs(v, out)),
        _ => {}
    }
}

fn schemes(v: &serde_json::Value, out: &mut BTreeSet<String>) {
    match v {
        serde_json::Value::String(s) => {
            if let Some((scheme, _)) = s.split_once("://") {
                let ok = scheme.starts_with(|c: char| c.is_ascii_alphabetic())
                    && scheme
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "+.-".contains(c));
                if ok {
                    out.insert(scheme.to_ascii_lowercase());
                }
            }
        }
        serde_json::Value::Object(map) => map.values().for_each(|v| schemes(v, out)),
        serde_json::Value::Array(items) => items.iter().for_each(|v| schemes(v, out)),
        _ => {}
    }
}

// ── DISCOVER: each plugin's facts, from its linked row or its signed manifest ───────────────────

/// Where a candidate's plugin comes from, for [`load`].
#[derive(Debug, Clone)]
pub enum Origin {
    /// A compiled-in row.
    Linked(LinkedRow),
    /// A dropped-in plugin: its tarball's file name and its verified library bytes.
    Dropped {
        /// The tarball's file name.
        file: String,
        /// The library bytes its signed manifest's `sha256` names.
        bytes: Arc<Vec<u8>>,
    },
}

/// The `from` word of every rewrite of `class` (`REWRITE_*`) a Statement rendering states: an
/// alias config may give the plugin ([`REWRITE_ALIAS`]), a reference key that names it
/// ([`REWRITE_SUGAR`]).
pub(crate) fn rewrites(r: &Read, class: u32) -> impl Iterator<Item = String> + '_ {
    r.rewrites
        .iter()
        .filter(move |(c, _, _)| *c == class)
        .map(|(_, from, _)| from.clone())
}

/// ONE DISCOVERED PLUGIN: the facts [`select`] reads, off its Statement rendering (a linked row's or
/// a signed manifest's) — never off an opened plugin.
#[derive(Debug, Clone)]
pub struct Candidate {
    /// Its kind.
    pub kind: KindCode,
    /// Its name.
    pub name: String,
    /// Its version, as its Statement states it (the one-version rule's, [`one_owner`]).
    pub version: String,
    /// The other names config may give it: its Statement's alias rewrites and, for a dropped
    /// plugin, its manifest's alias and former names.
    pub aliases: Vec<String>,
    /// The reference keys that name it (its sugar rewrites).
    pub sugar: Vec<String>,
    /// Its declaring sections (a plane's verbs).
    pub verbs: Vec<String>,
    /// The URL schemes it claims (its Statement's claims; a transport's).
    pub schemes: Vec<String>,
    /// Its connection needs, in its Statement's order (a need's index is its place here).
    pub needs: Vec<ReadNeed>,
    /// Its Statement rendering: what [`load`] admits it against.
    pub stated: Vec<u8>,
    /// Where it comes from.
    pub origin: Origin,
}

impl Candidate {
    /// The candidate a Statement rendering states. `alias` is a dropped plugin's manifest alias. The
    /// URL schemes a transport claims are the rendering's own `claims`: read off the signed
    /// manifest, never off an opened plugin.
    ///
    /// # Errors
    ///
    /// A rendering that does not read back, or that names no kind.
    pub fn from_rendering(
        stated: Vec<u8>,
        alias: Option<&str>,
        origin: Origin,
    ) -> Result<Self, String> {
        let r: Read = read(&stated).map_err(|e| {
            format!(
                "the Statement rendering does not read back: byte {} is not {}",
                e.at, e.what
            )
        })?;
        let kind = KindCode::from_raw(r.kind)
            .ok_or_else(|| format!("the Statement names kind {}", r.kind))?;
        let words = |class| rewrites(&r, class);
        let mut aliases: Vec<String> = words(REWRITE_ALIAS).collect();
        if let Some(a) = alias.filter(|a| *a != r.name && !aliases.iter().any(|x| x == a)) {
            aliases.push(a.to_string());
        }
        Ok(Self {
            kind,
            aliases,
            sugar: words(REWRITE_SUGAR).collect(),
            verbs: r
                .sections
                .iter()
                .filter(|(_, flags)| flags & SECTION_DECLARING != 0)
                .map(|(name, _)| name.clone())
                .collect(),
            schemes: r.claims,
            needs: r.needs,
            name: r.name,
            version: r.version,
            stated,
            origin,
        })
    }

    /// The candidate a DROPPED-IN plugin's signed manifest states: its Statement rendering, its
    /// manifest alias and each of its former names ([`crate::sign::Manifest::former_names`]), so
    /// config reaches it by every name the registry resolves it by.
    ///
    /// # Errors
    ///
    /// As [`Candidate::from_rendering`].
    pub fn from_manifest(
        stated: Vec<u8>,
        manifest: &crate::sign::Manifest,
        origin: Origin,
    ) -> Result<Self, String> {
        Self::from_rendering(stated, Some(&manifest.alias), origin)
            .map(|c| c.answering(&manifest.former_names))
    }

    /// This candidate, answering also to each of `names` it does not already answer to (a plugin's
    /// former names: what config written for its earlier releases calls it).
    #[must_use]
    pub fn answering<S: AsRef<str>>(mut self, names: impl IntoIterator<Item = S>) -> Self {
        for word in names {
            let word = word.as_ref();
            if !self.answers(word) {
                self.aliases.push(word.to_string());
            }
        }
        self
    }

    /// Every word config may name this candidate by: its name, then its aliases.
    fn words(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.name.as_str()).chain(self.aliases.iter().map(String::as_str))
    }

    /// A compiled-in row's candidate: its row's rendering.
    ///
    /// # Errors
    ///
    /// As [`Candidate::from_rendering`].
    pub fn linked(door: DoorFn) -> Result<Self, String> {
        let row = LinkedRow::of(door).map_err(|e| e.to_string())?;
        Self::from_rendering(row.statement.clone(), None, Origin::Linked(row))
    }

    /// Whether config names this plugin by `word` (its name or an alias).
    fn answers(&self, word: &str) -> bool {
        self.name == word || self.aliases.iter().any(|a| a == word)
    }
}

/// THE ONE-OWNER RULE over an axis's candidates, linked and dropped in alike (Q-P4-12 (ARCHITECT, BUSBAR-1.6.0.md:106 "it refuses at boot when two plugins claim the same thing")): two DIFFERENT
/// plugins (different names) that answer one word (a name, an alias, a former name) are refused,
/// naming both and the word. No ambiguity is resolved by picking a winner, and neither door outranks
/// the other (compiled in = dropped in). Two candidates of the SAME plugin (a linked row and its
/// dropped-in copy) are not a claim conflict: they are one plugin, held to the ONE-VERSION RULE
/// (ARCHITECT C', [`crate::registry::one_version`]) — at one version the linked row serves (it is
/// read first; [`both_doors`] names the pair for the log), at two the boot is refused.
///
/// # Errors
///
/// The first contested word, with the two plugins that claim it; or one plugin linked and dropped
/// in at two versions.
pub fn one_owner(candidates: &[Candidate]) -> Result<(), String> {
    for (i, a) in candidates.iter().enumerate() {
        for b in &candidates[i + 1..] {
            if a.name == b.name {
                if let Some((linked, file, dropped)) = doors(a, b) {
                    crate::registry::two_versions(
                        &a.name,
                        &linked.version,
                        file,
                        &dropped.version,
                    )?;
                }
                continue;
            }
            if let Some(word) = a.words().find(|w| b.answers(w)) {
                return Err(format!(
                    "plugin claim conflict: '{word}' is claimed by both '{}' and '{}' - a name, \
                     alias or former name must resolve to one plugin; remove one",
                    a.name, b.name
                ));
            }
        }
    }
    Ok(())
}

/// The pair `a`, `b` as (the linked one, the dropped-in one's file, the dropped-in one), when one
/// came in by each door.
fn doors<'c>(
    a: &'c Candidate,
    b: &'c Candidate,
) -> Option<(&'c Candidate, &'c str, &'c Candidate)> {
    match (&a.origin, &b.origin) {
        (Origin::Linked(_), Origin::Dropped { file, .. }) => Some((a, file, b)),
        (Origin::Dropped { file, .. }, Origin::Linked(_)) => Some((b, file, a)),
        _ => None,
    }
}

/// THE ONE INFO LINE per plugin among `candidates` that is linked AND dropped in at one version
/// ([`crate::registry::LinkedCopy::line`]'s words): what the axis that admits them logs, once.
#[must_use]
pub fn both_doors(candidates: &[Candidate]) -> Vec<String> {
    let mut lines = Vec::new();
    for (i, a) in candidates.iter().enumerate() {
        for b in &candidates[i + 1..] {
            if let Some((linked, file, dropped)) = doors(a, b) {
                if a.name == b.name && linked.version == dropped.version {
                    lines.push(crate::registry::both_doors(&a.name, &linked.version, file));
                }
            }
        }
    }
    lines
}

// ── SELECT: the plugins the configuration uses ──────────────────────────────────────────────────

/// One selected instance: which candidate, under which instance name (the config key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selected {
    /// The index into the candidates.
    pub candidate: usize,
    /// The instance name: the entry's key, the kind's root key for the one store, the verb for a
    /// plane, the plugin's name for secret sugar and a transport.
    pub instance: String,
}

/// STAGE 2, SELECT (BUSBAR-1.6.0.md §4 "Selection follows the classes"; pure): a plane is selected iff
/// one of its verbs is a root key; a store, secret, auth, hook or export plugin once per entry whose
/// `module` names it (its name or an alias) and once if a reference uses its sugar; a transport iff
/// a configured URL uses a scheme it claims. Candidates are read in order and the first that answers
/// an entry takes it; two DIFFERENT plugins never both answer one word, which the one-owner rule
/// ([`one_owner`], Q-P4-12 (ARCHITECT, BUSBAR-1.6.0.md:106 "it refuses at boot when two plugins claim the same thing")) refuses before selection. An entry no candidate answers selects nothing here:
/// the kind's own validation refuses it, naming the missing module.
#[must_use]
pub fn select(uses: &Uses, candidates: &[Candidate]) -> Vec<Selected> {
    let mut out = Vec::new();
    let mut taken: BTreeSet<(u32, String)> = BTreeSet::new();
    let mut take = |out: &mut Vec<Selected>, i: usize, kind: KindCode, instance: String| {
        if taken.insert((kind as u32, instance.clone())) {
            out.push(Selected {
                candidate: i,
                instance,
            });
        }
    };
    for (i, c) in candidates.iter().enumerate() {
        match c.kind {
            KindCode::Plane => {
                if let Some(verb) = c.verbs.iter().find(|v| uses.roots.contains(*v)) {
                    take(&mut out, i, c.kind, verb.clone());
                }
            }
            KindCode::Transport => {
                if c.schemes.iter().any(|s| uses.schemes.contains(s)) {
                    take(&mut out, i, c.kind, c.name.clone());
                }
            }
            kind => {
                for (k, instance, module) in &uses.modules {
                    if *k == kind && c.answers(module) {
                        take(&mut out, i, kind, instance.clone());
                    }
                }
                if c.sugar.iter().any(|s| uses.refs.contains(s)) {
                    take(&mut out, i, kind, c.name.clone());
                }
            }
        }
    }
    out
}

// ── THE REGISTRY: the linked rows, then the plugins directory's, through one admission ─────────────

/// What [`registry`] reads to build THE plugin registry: the rows this build LINKS (registered
/// ahead of the directory's, through the same admission) and, unless only those are wanted, the
/// directory [`Scan`].
pub struct Build<'a> {
    /// The build's linked rows.
    pub linked: Vec<crate::LinkedPlugin>,
    /// The directory scan, or `None` for the linked rows alone (no policy, no floor, no file read).
    pub scan: Option<Scan<'a>>,
}

/// The plugins directory's half of a [`Build`].
pub struct Scan<'a> {
    /// The resolved `plugins.trust` policy. Its first-party floor is the build's to arm: it is an
    /// observed fact (the persisted high-water marks), never a configuration value.
    pub policy: crate::sign::TrustPolicy,
    /// The fleet data dir the first-party floor persists under (`None` = memory-only: no probe, no
    /// files).
    pub data_dir: Option<&'a std::path::Path>,
    /// The plugins directory, or `None` when the plugin subsystem is off: then nothing in any
    /// directory is read (drop-is-inert) and the registry is the linked rows.
    pub dir: Option<&'a std::path::Path>,
}

/// What [`registry`] tells its caller as it goes, in order, so the caller's log lines keep their
/// order: the floor could not be read; the subsystem is off; the directory was scanned (every
/// loadable and skipped row, before the floor rises); the risen floor could not be persisted.
#[derive(Debug)]
pub enum Note<'r> {
    /// The persisted first-party floor could not be used (booting with no floor).
    FloorUnreadable(&'r str),
    /// The plugin subsystem is off: the registry is the linked rows.
    Off,
    /// The directory's rows, admitted, with the linked rows ahead of them.
    Scanned(&'r crate::PluginRegistry),
    /// The first-party floor rose but could not be persisted (it still floors this process).
    FloorUnwritable(&'r std::io::Error),
}

/// THE REGISTRY BUILD (BUSBAR-1.6.0.md §3 stage 1; ARCHITECT ruling Q8: the composition root builds the
/// registry and the kernel receives it): the linked rows alone, or — given a [`Scan`] — the
/// first-party floor armed from the persisted marks, the directory's three-phase scan
/// (structural -> trust -> conflict; ANY invalid tarball or conflict refuses, every problem named;
/// an untrusted plugin is skipped, never opened) with the linked rows registered ahead of it, and
/// the floor raised to what the scan proved loadable (only a verified first-party verdict counts;
/// the mark only rises; a failure to persist is a [`Note`], not a refusal). Nothing is opened.
///
/// # Errors
///
/// An invalid tarball, manifest or conflict (`plugin validation failed:` and every problem), or
/// a linked row the admission refuses.
pub fn registry(
    b: Build<'_>,
    note: &mut dyn FnMut(Note<'_>),
) -> Result<crate::PluginRegistry, String> {
    let Some(mut scan) = b.scan else {
        return crate::PluginRegistry::empty().link(b.linked);
    };
    let (mut high_water, unreadable) = crate::HighWaterMarks::load(scan.data_dir);
    if let Some(n) = unreadable {
        note(Note::FloorUnreadable(&n));
    }
    scan.policy.first_party_high_water = high_water.marks();
    let Some(dir) = scan.dir else {
        note(Note::Off);
        return crate::PluginRegistry::empty().link(b.linked);
    };
    let registry = crate::scan_and_validate(dir, &scan.policy)
        .map_err(|errs| format!("plugin validation failed:\n  - {}", errs.join("\n  - ")))?
        .link(b.linked)?;
    note(Note::Scanned(&registry));
    if high_water.record_registry(&registry) {
        if let Err(e) = high_water.persist() {
            note(Note::FloorUnwritable(&e));
        }
    }
    Ok(registry)
}

// ── THE PLANES ───────────────────────────────────────────────────────────────────────────────────

/// The plane axis, discovered ([`crate::PluginRegistry::open_planes`]): the planes that state
/// themselves through a door, not yet bound, and the HOT-lane planes (M6-HOT-PLANE) already opened.
#[derive(Default)]
pub struct PlaneSet {
    /// Each plane with a door: linked rows first, then the dropped-in ones in scan order.
    pub doors: Vec<Candidate>,
    /// Each HOT-lane plane (no Statement), opened.
    pub hot: Vec<crate::DynPlane>,
}

/// THE PLANES' ONE LOAD: every door plane of a [`PlaneSet`] selected under its own name and bound
/// through [`load`] — a linked row by `load_linked`, a dropped one by `load_dropped` over its
/// verified bytes, each against its stated Statement and tail, on `dispatcher`, to its own log
/// sink.
///
/// # Errors
///
/// The first plane that will not bind, named.
pub fn load_planes(
    doors: &[Candidate],
    logs: &PluginLogConfig,
    metrics: Arc<dyn EnvelopeSink>,
    dispatcher: Adopter,
    max_inflight_cap: u32,
    conns: Option<Arc<dyn busbar_contract::conn::DeclaredConns>>,
) -> Result<Vec<(String, Plugin<Plane>)>, String> {
    let selected: Vec<Selected> = doors
        .iter()
        .enumerate()
        .map(|(candidate, c)| Selected {
            candidate,
            instance: c.name.clone(),
        })
        .collect();
    let loaded = load(&LoadRequest {
        candidates: doors,
        selected: &selected,
        logs,
        metrics,
        dispatcher,
        max_inflight_cap,
        conns,
        opening: None,
    })?;
    loaded
        .bound
        .into_iter()
        .map(|(instance, bound)| match bound {
            Bound::Plane(p) => Ok((instance, p)),
            _ => Err(format!("{instance}: a plane door states another kind")),
        })
        .collect()
}

// ── INBOUND: every selected instance's listener needs and their binds ─────────────────────────────

/// A listener's connection cap when its settings block names none (new in 1.6.0).
pub const DEFAULT_MAX_CONNS: u64 = 1024;

/// Whose listener a bind is.
#[derive(Debug, Clone, PartialEq)]
pub enum BindOwner {
    /// The host's own: the root data door (`listen`) or the admin surface (`admin_listen`).
    Root,
    /// A selected instance's `DIRECTION_INBOUND` need.
    Need {
        /// The instance (the selection's instance name).
        instance: String,
        /// Its kind.
        kind: KindCode,
        /// The need, by its index in the instance's Statement needs.
        need: u32,
    },
}

/// ONE LISTENER'S BIND (boot stages 3f and 6), from the one list every listener comes from: the
/// root's own (its `listen` and `admin_listen`, which the root synthesises) and each selected
/// instance's `DIRECTION_INBOUND` need, read from the settings block its `target_from` names,
/// `{listen, tls: {cert, key, client_ca?}, max_conns?}` — the 1.5.5 root `listen` / `tls` shape.
/// The TLS block stays raw: its `cert` and `key` are secret references the root resolves through
/// the secret kind at stage 3f.
#[derive(Debug, Clone, PartialEq)]
pub struct InboundBind {
    /// Whose listener it is.
    pub owner: BindOwner,
    /// The transport claim the need names; empty for the root's own.
    pub transport: String,
    /// Where its block is, as the operator spells it: `<section>.<instance>.<path>` for a need,
    /// the root setting (`listen`, `admin_listen`) for the root's own.
    pub at: String,
    /// The address to bind.
    pub listen: std::net::SocketAddr,
    /// The raw `tls` block; `None` = the listener is in the clear.
    pub tls: Option<serde_json::Value>,
    /// The most connections held at once.
    pub max_conns: u64,
}

impl InboundBind {
    /// The setting that states the address, as the operator spells it.
    #[must_use]
    pub fn listen_setting(&self) -> String {
        match self.owner {
            BindOwner::Root => self.at.clone(),
            BindOwner::Need { .. } => format!("{}.listen", self.at),
        }
    }
}

/// Where a selected instance's settings live in `doc`, and how the operator spells that place: a
/// plane's is its verb's section; the store's, `store.settings`; a secret module's, its entry under
/// `secrets`; a named auth, hook or export entry's, its `settings`. A transport has none.
fn instance_settings<'d>(
    doc: &'d serde_json::Value,
    kind: KindCode,
    instance: &str,
) -> Option<(&'d serde_json::Value, String)> {
    let at = |v: Option<&'d serde_json::Value>, spelled: String| v.map(|v| (v, spelled));
    match kind {
        KindCode::Transport => None,
        KindCode::Plane => at(doc.get(instance), instance.to_string()),
        KindCode::Secret => {
            let key = kind_of(kind).root_key()?;
            at(doc.get(key)?.get(instance), format!("{key}.{instance}"))
        }
        KindCode::Store => {
            let key = kind_of(kind).root_key()?;
            at(doc.get(key)?.get("settings"), format!("{key}.settings"))
        }
        KindCode::Auth | KindCode::Hook | KindCode::Export => {
            let key = kind_of(kind).root_key()?;
            at(
                doc.get(key)?.get(instance)?.get("settings"),
                format!("{key}.{instance}.settings"),
            )
        }
    }
}

/// Whether two binds would take one address: the same port on the same IP, or on any IP when
/// either is unspecified. Port `0` asks the OS for a free one and never collides.
fn collide(a: std::net::SocketAddr, b: std::net::SocketAddr) -> bool {
    a.port() != 0
        && a.port() == b.port()
        && (a.ip() == b.ip() || a.ip().is_unspecified() || b.ip().is_unspecified())
}

/// STAGE 3f's input, pure: THE ONE LIST OF LISTENERS — `root`, the host's own binds, then every
/// `DIRECTION_INBOUND` need of every selected instance, with its bind read from the settings block
/// the need's `target_from` names. Two listeners on one address are refused here, before anything
/// binds.
///
/// # Errors
///
/// The first refusal, naming the setting: an inbound need that names no settings block, a block
/// missing or without `listen`, an address that is not `ip:port`, a `max_conns` that is not a
/// positive whole number, or an address taken twice.
pub fn inbound(
    doc: &serde_json::Value,
    candidates: &[Candidate],
    selected: &[Selected],
    root: Vec<InboundBind>,
) -> Result<Vec<InboundBind>, String> {
    let mut out = root;
    for s in selected {
        let Some(c) = candidates.get(s.candidate) else {
            continue;
        };
        for (i, n) in c.needs.iter().enumerate() {
            if n.direction != DIRECTION_INBOUND {
                continue;
            }
            let who = format!("{} ({})", s.instance, c.name);
            if n.target_from.is_empty() {
                return Err(format!(
                    "{who}: inbound need {i} over `{}` names no settings block to listen from",
                    n.transport
                ));
            }
            let (settings, base) = instance_settings(doc, c.kind, &s.instance)
                .ok_or_else(|| format!("{who}: `{}` is not set", n.target_from))?;
            let at = format!("{base}.{}", n.target_from);
            let block = n
                .target_from
                .split('.')
                .try_fold(settings, |v, k| v.get(k))
                .ok_or_else(|| format!("{at}: not set; an inbound listener needs `listen`"))?;
            let listen = block
                .get("listen")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| format!("{at}.listen: not set"))?;
            let listen: std::net::SocketAddr = listen
                .parse()
                .map_err(|_| format!("{at}.listen: `{listen}` is not an ip:port address"))?;
            let max_conns = match block.get("max_conns") {
                None => DEFAULT_MAX_CONNS,
                Some(v) => v
                    .as_u64()
                    .filter(|n| *n > 0)
                    .ok_or_else(|| format!("{at}.max_conns: not a positive whole number"))?,
            };
            if let Some(o) = out.iter().find(|o| collide(o.listen, listen)) {
                return Err(format!(
                    "{at}.listen: {listen} is already taken by `{}`",
                    o.listen_setting()
                ));
            }
            out.push(InboundBind {
                owner: BindOwner::Need {
                    instance: s.instance.clone(),
                    kind: c.kind,
                    need: u32::try_from(i).unwrap_or(u32::MAX),
                },
                transport: n.transport.clone(),
                at,
                listen,
                tls: block.get("tls").filter(|v| !v.is_null()).cloned(),
                max_conns,
            });
        }
    }
    Ok(out)
}

// ── THE ONE LOAD ─────────────────────────────────────────────────────────────────────────────────

/// One bound instance, of its kind.
#[derive(Debug)]
#[allow(missing_docs)]
pub enum Bound {
    Store(Plugin<Store>),
    Secret(Plugin<Secret>),
    Auth(Plugin<Auth>),
    Hook(Plugin<Hook>),
    Export(Plugin<Export>),
    Plane(Plugin<Plane>),
    Transport(Plugin<Transport>),
}

/// THE ONE LOAD's request: the discovered candidates, the selection over them, and what every bind
/// takes — the plugin log configuration (each instance gets its own sink, BUSBAR-1.6.0.md §11.2 Plugin
/// logging), where the #85 metrics go, the dispatcher that adopts every instance, and the host's
/// clamp on a Statement's `max_inflight`.
pub struct LoadRequest<'a> {
    /// The discovered plugins.
    pub candidates: &'a [Candidate],
    /// The instances selected over them.
    pub selected: &'a [Selected],
    /// `plugins.logs`, resolved once per configuration.
    pub logs: &'a PluginLogConfig,
    /// Where every instance's #85 metrics and dropped records go.
    pub metrics: Arc<dyn EnvelopeSink>,
    /// The dispatcher that adopts every instance.
    pub dispatcher: Adopter,
    /// The host's clamp on `max_inflight`.
    pub max_inflight_cap: u32,
    /// The host's one connection table ([`Bind::conns`]).
    pub conns: Option<Arc<dyn busbar_contract::conn::DeclaredConns>>,
    /// What OPENS each auth instance the load binds, and awaits its `ready`; `None` = bind only.
    pub opening: Option<Opening<'a>>,
}

/// THE AUTH OPEN AND READY at the one load (ARCHITECT 2026-10-02, discovery at boot): every bound
/// auth instance is opened with its settings block from `doc`, then its `ready` is awaited on
/// `dispatcher` (the one that adopts it) before the load answers, so before any listener binds. An
/// instance that will not open or will not be ready refuses the boot with the plugin's own text,
/// as 1.5.5 refused a boot whose discovery failed.
#[derive(Clone, Copy)]
pub struct Opening<'a> {
    /// The plan's document, where each instance's settings block lives.
    pub doc: &'a serde_json::Value,
    /// The dispatcher every instance is adopted by ([`LoadRequest::dispatcher`] is its adopter).
    pub dispatcher: &'a crate::dispatch::Dispatcher,
    /// The secret kind's resolver: each settings key the Statement names in `secret_refs` is
    /// resolved through it, in that order, into `OpenIn::secrets`, and stripped from the settings
    /// `open` is handed (ARCHITECT 2026-10-02).
    pub secrets: &'a dyn busbar_contract::secret::SecretResolve,
}

/// What [`load`] bound: `(instance, bound)`, in selection order.
#[derive(Debug, Default)]
pub struct Loaded {
    /// The bound instances.
    pub bound: Vec<(String, Bound)>,
}

/// THE ONE LOAD: every selected instance, bound through the one loader path — a compiled-in row's
/// door ([`load_linked`]) or a dropped plugin's verified bytes ([`load_dropped_bytes`]), each
/// admitted against its stated Statement — to its own log sink.
///
/// # Errors
///
/// The first instance that will not bind, named: `<instance>: <why>`.
pub fn load(req: &LoadRequest<'_>) -> Result<Loaded, String> {
    let mut loaded = Loaded::default();
    for s in req.selected {
        let c = req
            .candidates
            .get(s.candidate)
            .ok_or_else(|| format!("{}: no such candidate", s.instance))?;
        let sink = req
            .logs
            .sink(&s.instance, c.kind, req.metrics.clone())
            .map_err(|e| format!("{}: {e}", s.instance))?;
        let bind = Bind {
            instance: Arc::from(s.instance.as_str()),
            max_inflight_cap: req.max_inflight_cap,
            sink: Arc::new(sink),
            dispatcher: req.dispatcher.clone(),
            conns: req.conns.clone(),
        };
        let bound = bind_one(c, bind).map_err(|e| format!("{}: {e}", s.instance))?;
        if let (Some(opening), Bound::Auth(plugin)) = (req.opening, &bound) {
            open_ready(plugin, opening, c, &s.instance)
                .map_err(|e| format!("{}: {e}", s.instance))?;
        }
        loaded.bound.push((s.instance.clone(), bound));
    }
    Ok(loaded)
}

/// Open `plugin` (the instance `instance` of candidate `c`) with its settings block in
/// `opening.doc` and its declared secrets resolved ([`resolve_secrets`]), then await its `ready` on
/// `opening.dispatcher`.
fn open_ready<K: crate::dispatch::Kind>(
    plugin: &Plugin<K>,
    opening: Opening<'_>,
    c: &Candidate,
    instance: &str,
) -> Result<(), String> {
    use busbar_contract::abi::mechanism::call::{Blob, Outcome, BLOB_JSON};
    use busbar_contract::abi::mechanism::lifecycle::{slot, OpenIn, OpenOut};
    use busbar_contract::abi::sdk::door::{blank_in, blank_out};

    let keys = read(&c.stated).map(|r| r.secret_refs).map_err(|e| {
        format!(
            "the Statement rendering does not read back at byte {}",
            e.at
        )
    })?;
    let mut block = instance_settings(opening.doc, K::CODE, instance)
        .map(|(v, _)| v.clone())
        .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));
    let mut held = Secrets(resolve_secrets(&mut block, &keys, opening.secrets)?);
    let blobs = held.blobs();
    let settings = serde_json::to_vec(&block).unwrap_or_default();
    let mut i: OpenIn = blank_in();
    i.settings = Blob {
        ptr: settings.as_ptr(),
        len: settings.len(),
        fmt: BLOB_JSON,
        flags: 0,
    };
    i.secrets = blobs.as_ptr();
    i.secrets_len = blobs.len();
    i.generation = 1;
    let mut f = crate::dispatch::Frame::new(i, blank_out::<OpenOut>());
    let opened = plugin.call(slot::OPEN, &mut f);
    drop(blobs);
    held.wipe();
    if opened.outcome != Outcome::Ready {
        return Err(opened.open_failure(plugin.name()));
    }
    plugin.ready(opening.dispatcher, crate::dispatch::ready::READY_DEADLINE)
}

/// THE DECLARED SECRETS (the Statement's `secret_refs`, ARCHITECT 2026-10-02): each key — a path
/// into the settings block, `.`-separated — is read as a secret reference, resolved through the
/// secret kind's resolver, and REMOVED from the block, so the secret reaches `open` only as its
/// `OpenIn::secrets` entry, in the Statement's order. A key the block does not set is an empty
/// entry (its place is kept); a reference that does not parse or resolve refuses, naming the key
/// and never a byte of the secret.
///
/// # Errors
/// The key whose reference is malformed or does not resolve.
pub fn resolve_secrets(
    block: &mut serde_json::Value,
    keys: &[String],
    resolver: &dyn busbar_contract::secret::SecretResolve,
) -> Result<Vec<Vec<u8>>, String> {
    keys.iter()
        .map(|key| {
            let Some(found) = take_path(block, key) else {
                return Ok(Vec::new());
            };
            let r: busbar_contract::secret_ref::SecretRef = serde_json::from_value(found)
                .map_err(|e| format!("settings.{key}: not a secret reference: {e}"))?;
            resolver
                .resolve(&r)
                .map_err(|e| format!("settings.{key}: the secret did not resolve: {e}"))
        })
        .collect()
}

/// Remove and answer the value at the `.`-separated `path` of `v`, if set.
fn take_path(v: &mut serde_json::Value, path: &str) -> Option<serde_json::Value> {
    let (parent, last) = match path.rsplit_once('.') {
        Some((head, last)) => (
            head.split('.').try_fold(&mut *v, |v, k| v.get_mut(k))?,
            last,
        ),
        None => (v, path),
    };
    parent.as_object_mut()?.remove(last)
}

/// Resolved secret bytes, held for one `open` and overwritten with zeroes when it returns.
struct Secrets(Vec<Vec<u8>>);

impl Secrets {
    /// One `BLOB_SECRET` blob per secret, in order, over the bytes held here.
    fn blobs(&self) -> Vec<busbar_contract::abi::mechanism::call::Blob> {
        use busbar_contract::abi::mechanism::call::{Blob, BLOB_OCTETS, BLOB_SECRET};
        self.0
            .iter()
            .map(|b| Blob {
                ptr: b.as_ptr(),
                len: b.len(),
                fmt: BLOB_OCTETS,
                flags: BLOB_SECRET,
            })
            .collect()
    }

    /// Overwrite every secret byte with zero.
    fn wipe(&mut self) {
        for b in &mut self.0 {
            for byte in b.iter_mut() {
                // SAFETY: `byte` is a live, exclusively borrowed `u8`; the volatile write keeps the
                // compiler from dropping the zeroing of memory about to be freed.
                unsafe { std::ptr::write_volatile(byte, 0) };
            }
        }
    }
}

impl Drop for Secrets {
    fn drop(&mut self) {
        self.wipe();
    }
}

fn bind_one(c: &Candidate, bind: Bind) -> Result<Bound, String> {
    fn one<K: crate::dispatch::Kind>(c: &Candidate, bind: Bind) -> Result<Plugin<K>, String> {
        match &c.origin {
            Origin::Linked(row) => load_linked::<K>(row, bind),
            Origin::Dropped { file, bytes } => {
                load_dropped_bytes::<K>(bytes, file, &c.stated, bind)
            }
        }
        .map_err(|e| e.to_string())
    }
    Ok(match c.kind {
        KindCode::Store => Bound::Store(one(c, bind)?),
        KindCode::Secret => Bound::Secret(one(c, bind)?),
        KindCode::Auth => Bound::Auth(one(c, bind)?),
        KindCode::Hook => Bound::Hook(one(c, bind)?),
        KindCode::Export => Bound::Export(one(c, bind)?),
        KindCode::Plane => Bound::Plane(one(c, bind)?),
        KindCode::Transport => Bound::Transport(one(c, bind)?),
    })
}

#[cfg(test)]
#[path = "tests/boot_tests.rs"]
mod tests;
