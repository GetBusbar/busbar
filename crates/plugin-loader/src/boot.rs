// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::BTreeSet;
use std::sync::Arc;

use busbar_contract::abi::host::conn::connector::DIRECTION_INBOUND;
use busbar_contract::abi::mechanism::door::{
    DoorFn, REWRITE_ALIAS, REWRITE_SUGAR, SECTION_CONSUMED, SECTION_DECLARING, SECTION_SELECTS,
};
use busbar_contract::abi::mechanism::rendering::{read, Read, ReadNeed};
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::plugin::Kind;

use crate::dispatch::kinds::{
    auth::Auth, export::Export, hook::Hook, plane::Plane, secret::Secret, store::Store,
    transport::Transport,
};
use crate::dispatch::{
    load_dropped_bytes, load_linked, Adopter, Bind, ConnTable, EnvelopeSink, LinkedRow, Plugin,
    PluginLogConfig,
};

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

const DEFINED: [KindCode; 5] = [
    KindCode::Store,
    KindCode::Secret,
    KindCode::Auth,
    KindCode::Hook,
    KindCode::Export,
];

impl Uses {
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
                (KindCode::Store, Some(entry)) => {
                    if let Some(m) = entry.get("module").and_then(|m| m.as_str()) {
                        uses.modules.push((code, key.to_string(), m.to_string()));
                    }
                }

                (KindCode::Secret, Some(map)) => {
                    for m in map.keys() {
                        uses.modules.push((code, m.clone(), m.clone()));
                    }
                }

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

impl Uses {
    #[must_use]
    pub fn reaching<'u>(mut self, urls: impl IntoIterator<Item = &'u str>) -> Self {
        for url in urls {
            schemes(
                &serde_json::Value::String(url.to_string()),
                &mut self.schemes,
            );
        }
        self
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
    /// The other sections whose presence uses it (Law 7), in Statement order: a section it owns
    /// (neither declaring nor consumed), and a section it only consumes that its Statement marks
    /// `SECTION_SELECTS`. Config carrying one selects a plane as its verb does.
    pub selecting: Vec<String>,
    /// The URL schemes it claims (its Statement's claims; a transport's).
    pub schemes: Vec<String>,
    /// Its connection needs, in its Statement's order (a need's index is its place here).
    pub needs: Vec<ReadNeed>,
    /// Its Statement rendering: what [`load`] admits it against.
    pub stated: Vec<u8>,
    /// Where it comes from.
    pub origin: Origin,
    /// Whether its source reads the local disk (`declares.disk`, a `kind: secret` source only; THE
    /// DESIGN §11.11 R4): its `resolve` runs on the host's disk lane at config time, never on a
    /// request path.
    pub disk: bool,
    /// Whether its `decide` may answer an order (`declares.hook.orders`, a `kind: hook` plugin;
    /// `true` unless declared `false`): a hook that declared it never orders is refused when it
    /// does ([`crate::hook_door::HookInstance::open_declaring`]).
    pub orders: bool,
}

impl Candidate {
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
            selecting: r
                .sections
                .iter()
                .filter(|(_, flags)| {
                    flags & SECTION_DECLARING == 0
                        && (flags & SECTION_CONSUMED == 0 || flags & SECTION_SELECTS != 0)
                })
                .map(|(name, _)| name.clone())
                .collect(),
            schemes: r.claims,
            needs: r.needs,
            name: r.name,
            version: r.version,
            stated,
            origin,
            disk: false,
            orders: true,
        })
    }

    pub fn from_manifest(
        stated: Vec<u8>,
        manifest: &crate::sign::Manifest,
        origin: Origin,
    ) -> Result<Self, String> {
        Self::from_rendering(stated, Some(&manifest.alias), origin)
            .map(|c| c.answering(&manifest.former_names))
            .map(|c| c.reading_disk(manifest.declares.disk))
            .map(|c| c.ordering(manifest.declares.hook_orders()))
    }

    #[must_use]
    pub fn ordering(mut self, orders: bool) -> Self {
        self.orders = orders;
        self
    }

    #[must_use]
    pub fn reading_disk(mut self, disk: bool) -> Self {
        self.disk = disk;
        self
    }

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

    fn words(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.name.as_str()).chain(self.aliases.iter().map(String::as_str))
    }

    pub fn linked(door: DoorFn) -> Result<Self, String> {
        let row = LinkedRow::of(door).map_err(|e| e.to_string())?;
        Self::from_rendering(row.statement.clone(), None, Origin::Linked(row))
    }

    pub(crate) fn answers(&self, word: &str) -> bool {
        self.name == word || self.aliases.iter().any(|a| a == word)
    }

    #[must_use]
    pub(crate) fn answering_former(self, former_of: impl Fn(&str) -> Vec<String>) -> Self {
        let words: Vec<String> = self.words().flat_map(former_of).collect();
        self.answering(words)
    }

    #[must_use]
    pub fn serves(&self, uses: &Uses) -> bool {
        uses.schemes
            .iter()
            .any(|s| self.schemes.contains(s) || self.answers(s))
    }

    #[must_use]
    pub fn sectioned(&self, uses: &Uses) -> bool {
        plane_use(uses, self).is_some()
    }
}

pub fn sugars_of(candidates: &[Candidate]) -> Result<busbar_contract::secret_ref::Sugars, String> {
    let mut sugars = busbar_contract::secret_ref::Sugars::default();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for c in candidates {
        if !seen.insert(c.name.as_str()) {
            continue;
        }
        let r: Read = read(&c.stated).map_err(|e| {
            format!(
                "plugin '{}': its Statement rendering does not read back at byte {}",
                c.name, e.at
            )
        })?;
        sugars.declare(&c.name, &r.rewrites)?;
    }
    Ok(sugars)
}

pub fn one_owner(candidates: &[Candidate]) -> Result<(), String> {
    for (i, a) in candidates.iter().enumerate() {
        for b in &candidates[i + 1..] {
            if a.name == b.name {
                if let Some((linked, file, dropped)) = doors(a, b) {
                    if linked.version.is_empty() || dropped.version.is_empty() {
                        return Err(crate::registry::unversioned(&a.name));
                    }
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

/// One selected instance: which candidate, under which instance name (the config key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selected {
    /// The index into the candidates.
    pub candidate: usize,
    /// The instance name: the entry's key, the kind's root key for the one store, the verb for a
    /// plane, the plugin's name for secret sugar and a transport.
    pub instance: String,
}

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
                if let Some(at) = plane_use(uses, c) {
                    let verb = c.verbs.first().map_or(at, String::as_str);
                    take(&mut out, i, c.kind, verb.to_string());
                }
            }
            KindCode::Transport => {
                if c.serves(uses) {
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

#[must_use]
pub fn plane_use<'c>(uses: &Uses, plane: &'c Candidate) -> Option<&'c str> {
    if plane.kind != KindCode::Plane {
        return None;
    }
    plane
        .verbs
        .iter()
        .chain(&plane.selecting)
        .find(|v| uses.roots.contains(*v))
        .map(String::as_str)
}

pub struct Build<'a> {
    pub linked: Vec<crate::LinkedPlugin>,

    pub scan: Option<Scan<'a>>,
}

pub struct Scan<'a> {
    pub policy: crate::sign::TrustPolicy,

    pub data_dir: Option<&'a std::path::Path>,

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

/// The plane axis, discovered ([`crate::PluginRegistry::open_planes`]): the planes that state
/// themselves through a door, not yet bound.
#[derive(Default)]
pub struct PlaneSet {
    /// Each plane with a door: linked rows first, then the dropped-in ones in scan order.
    pub doors: Vec<Candidate>,
}

#[must_use]
pub fn used_planes(uses: &Uses, doors: &[Candidate]) -> Vec<Candidate> {
    doors
        .iter()
        .filter(|c| c.sectioned(uses))
        .cloned()
        .collect()
}

pub fn load_planes(
    doors: &[Candidate],
    logs: &PluginLogConfig,
    metrics: Arc<dyn EnvelopeSink>,
    dispatcher: Adopter,
    max_inflight_cap: u32,
    conns: ConnTable,
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
    #[must_use]
    pub fn listen_setting(&self) -> String {
        match self.owner {
            BindOwner::Root => self.at.clone(),
            BindOwner::Need { .. } => format!("{}.listen", self.at),
        }
    }
}

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

fn collide(a: std::net::SocketAddr, b: std::net::SocketAddr) -> bool {
    a.port() != 0
        && a.port() == b.port()
        && (a.ip() == b.ip() || a.ip().is_unspecified() || b.ip().is_unspecified())
}

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

pub struct LoadRequest<'a> {
    pub candidates: &'a [Candidate],

    pub selected: &'a [Selected],

    pub logs: &'a PluginLogConfig,

    pub metrics: Arc<dyn EnvelopeSink>,

    pub dispatcher: Adopter,

    pub max_inflight_cap: u32,

    pub conns: ConnTable,

    pub opening: Option<Opening<'a>>,
}

/// THE AUTH OPEN AND READY at the one load: every bound
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
    /// `open` is handed.
    pub secrets: &'a dyn busbar_contract::secret::SecretResolve,
    /// The config-time proof the boot that loads holds (THE DESIGN §11.11 R4): every declared
    /// secret resolves through it, so a source that reads the disk answers on the host's lane.
    pub scope: &'a busbar_contract::config_time::ConfigScope,
}

/// What [`load`] bound: `(instance, bound)`, in selection order.
#[derive(Debug, Default)]
pub struct Loaded {
    /// The bound instances.
    pub bound: Vec<(String, Bound)>,
}

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
    if let Some(at) = busbar_contract::secret_fields::undeclared_reference(&block, &keys) {
        let field = instance_settings(opening.doc, K::CODE, instance).map_or_else(
            || format!("settings.{at}"),
            |(_, base)| format!("{base}.{at}"),
        );
        return Err(busbar_contract::secret_fields::undeclared_refusal(
            &field, &c.name,
        ));
    }
    let mut held = Secrets(resolve_secrets(
        &mut block,
        &keys,
        opening.secrets,
        opening.scope,
    )?);
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
    drop(held);
    if opened.outcome != Outcome::Ready {
        return Err(opened.open_failure(plugin.name()));
    }
    plugin.ready(opening.dispatcher, crate::dispatch::ready::READY_DEADLINE)
}

pub fn resolve_secrets(
    block: &mut serde_json::Value,
    keys: &[String],
    resolver: &dyn busbar_contract::secret::SecretResolve,
    scope: &busbar_contract::config_time::ConfigScope,
) -> Result<Vec<busbar_contract::redacted::Secret<Vec<u8>>>, String> {
    busbar_contract::secret_fields::lend(
        block,
        keys,
        false,
        |path, found| resolve_one(found, path, resolver, scope),
        |at, found| resolve_one(Some(found), at, resolver, scope),
    )
}

fn resolve_one(
    found: Option<serde_json::Value>,
    path: &str,
    resolver: &dyn busbar_contract::secret::SecretResolve,
    scope: &busbar_contract::config_time::ConfigScope,
) -> Result<busbar_contract::redacted::Secret<Vec<u8>>, String> {
    let Some(found) = found else {
        return Ok(busbar_contract::redacted::Secret::default());
    };
    let r: busbar_contract::secret_ref::SecretRef =
        serde_json::from_value(found).map_err(not_a_reference(format!("settings.{path}")))?;
    resolver
        .resolve_at_config(&r, scope)
        .map_err(|e| format!("settings.{path}: the secret did not resolve: {e}"))
}

pub(crate) fn not_a_reference(at: String) -> impl FnOnce(serde_json::Error) -> String {
    move |e: serde_json::Error| {
        let class = match e.classify() {
            serde_json::error::Category::Io => "the value could not be read",
            serde_json::error::Category::Syntax | serde_json::error::Category::Eof => {
                "it is not well-formed"
            }
            serde_json::error::Category::Data => "a field is missing or has the wrong type",
        };
        format!("{at}: not a secret reference: {class} (the decoder's text is withheld)")
    }
}

struct Secrets(Vec<busbar_contract::redacted::Secret<Vec<u8>>>);

impl Secrets {
    fn blobs(&mut self) -> Vec<busbar_contract::abi::mechanism::call::Blob> {
        use busbar_contract::abi::mechanism::call::{Blob, BLOB_OCTETS, BLOB_SECRET};
        self.0
            .iter_mut()
            .map(|b| {
                let (ptr, len) = b.lend_mut();
                Blob {
                    ptr: ptr.cast_const(),
                    len,
                    fmt: BLOB_OCTETS,
                    flags: BLOB_SECRET,
                }
            })
            .collect()
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

/// The settings one plugin's schema declares public, and every word a `module:` may name it by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicSettings {
    /// The plugin's Statement name.
    pub name: String,
    /// Its Statement name, its aliases and the caller's `words`, sorted.
    pub words: Vec<String>,
    /// The settings its schema declares `x-busbar-public`; every other setting is sensitive
    /// (`busbar_contract::settings_public`).
    pub public: BTreeSet<String>,
}

pub fn public_settings(stated: &[u8], words: &[&str]) -> Result<Option<PublicSettings>, String> {
    use busbar_contract::abi::mechanism::door::REWRITE_ALIAS;
    let r: Read = read(stated)
        .map_err(|e| format!("a Statement rendering does not read back at byte {}", e.at))?;
    let public = crate::settings_schema::public_settings_of_schema(&r.settings_schema.bytes)
        .map_err(|e| format!("plugin '{}': {e}", r.name))?;
    if public.is_empty() {
        return Ok(None);
    }
    let mut answers: Vec<String> = std::iter::once(r.name.clone())
        .chain(
            r.rewrites
                .iter()
                .filter(|(class, _, _)| *class == REWRITE_ALIAS)
                .map(|(_, from, _)| from.clone()),
        )
        .chain(words.iter().map(|w| (*w).to_string()))
        .collect();
    answers.sort();
    answers.dedup();
    Ok(Some(PublicSettings {
        name: r.name,
        words: answers,
        public,
    }))
}

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/boot_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/public_settings_tests.rs"]
mod public_settings_tests;
