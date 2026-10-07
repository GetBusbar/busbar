// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DEAL (`BUSBAR-1.6.0.md` THE DESIGN §3, stage 3g "deal config sections; plugins validate";
//! §4 Config): the operator's document split into one SECTION per plugin, the reserved core-owned
//! sub-keys read off a declared-verb section and stripped before it crosses, and the POSITION MAP
//! the sections carry, so a plugin's refusal names the operator's file position.
//!
//! The position map is the operator's own text, kept beside the document value. A position is
//! asked for by path and answered by the YAML library 1.5.5 parsed with, at the node the path names
//! — so a refusal reads `<path>: <reason> at line L column C`, 1.5.5's bytes for a refusal raised at
//! that node. A stage-0 rewrite edits the value ([`Document::value_mut`]) and leaves the text, so the
//! line and column a refusal names are the ones the operator wrote.

use busbar_contract::plugin::Kind;
use serde::de::{self, DeserializeSeed, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

/// THE RESERVED CORE-OWNED SUB-KEYS a declared-verb section may carry beyond the two every section
/// reserves (`busbar_contract::section::RESERVED_SECTION_KEYS`) and its card and fees
/// (`crate::config::prepass`): §4 "Reserved core-owned sub-keys" and the OWNER-CONFIRMED (b) list
/// (`breaker`, `on_exhausted`, the `gates` binding, `affinity`, `tier`, `repeatable`), and POOLS-VERBS's
/// `work` and `pools` (#47: tool and agent pools sit under their plane's verb as a reserved `pools`
/// sub-key; Q-STEP9-a, ARCHITECT 2026-10-07).
pub const RESERVED_SUB_KEYS: [&str; 8] = [
    "breaker",
    "on_exhausted",
    "gates",
    "affinity",
    "tier",
    "repeatable",
    "work",
    busbar_contract::section::RESERVED_POOLS_KEY,
];

/// Whether `key` is read by the kernel and stripped before a section crosses.
#[must_use]
pub fn is_reserved(key: &str) -> bool {
    RESERVED_SUB_KEYS.contains(&key)
        || busbar_contract::section::RESERVED_SECTION_KEYS.contains(&key)
        || crate::config::prepass::PLANE_CARD_KEYS.contains(&key)
}

/// The shape a reserved knob's value has, as the kernel reads it.
#[derive(Debug, Clone, Copy)]
enum Shape {
    /// A list (`hooks`, `gates`, `repeatable`).
    List,
    /// A scalar (`upstream_credentials`: `own`|`passthrough`; `tier`).
    Scalar,
    /// A map of these keys (`on_exhausted` may also be a word, `reject`; a word is never a map).
    Fields(&'static [&'static str]),
    /// A map whose every value is a map (`pools`: name → pool; `rate_card`: lane → entry).
    MapOfMaps,
}

/// Each reserved knob's shape, read off the kernel type that reads it: `hooks`/`gates`/`repeatable`
/// a list of names; `upstream_credentials` the `own`|`passthrough` scalar; `tier` a scalar;
/// `breaker` `config::pools::BreakerCfg`; `on_exhausted` `config::pools::OnExhaustedCfg` (a word, or
/// `{fallback_pool}`/`{queue}`); `affinity` `config::pools::AffinityCfg`; `work`
/// `host_work::WorkBounds::of_section`; `fees` `config::PlaneFeesCfg`; `pools` and `rate_card` maps
/// of maps (a pool; a `RateEntryCfg`). The field lists are pinned against those types' own
/// `expected one of` lists in the deal's tests.
fn shape(key: &str) -> Option<Shape> {
    use busbar_contract::section::{
        RESERVED_POOLS_KEY, RESERVED_SECTION_KEYS, RESERVED_WORK_KEY, UPSTREAM_CREDENTIALS_KEY,
        WORK_MAX_LIVE_KEY, WORK_RETAIN_S_KEY,
    };
    let [card, fees] = crate::config::prepass::PLANE_CARD_KEYS;
    Some(match key {
        UPSTREAM_CREDENTIALS_KEY | "tier" => Shape::Scalar,
        // The section's other word is its `hooks:` attach list.
        k if RESERVED_SECTION_KEYS.contains(&k) => Shape::List,
        "gates" | "repeatable" => Shape::List,
        "breaker" => Shape::Fields(&["base_cooldown_secs", "max_cooldown_secs", "trip"]),
        "on_exhausted" => Shape::Fields(&["fallback_pool", "queue"]),
        "affinity" => Shape::Fields(&["mode", "header_name"]),
        RESERVED_WORK_KEY => Shape::Fields(&[WORK_MAX_LIVE_KEY, WORK_RETAIN_S_KEY]),
        k if k == fees => Shape::Fields(&["per_request", "per_session"]),
        k if k == card || k == RESERVED_POOLS_KEY => Shape::MapOfMaps,
        _ => return None,
    })
}

/// THE GENERIC CHECK (spec :567, "a plane entry named after any reserved key is refused at
/// validation with a clear message"): whether `value`, written at a declared-verb section's own
/// level under the reserved key `key`, is plainly NOT that knob — an entry by that name. Only a
/// clear mismatch counts, as `busbar_contract::section::split_section` judges `hooks`: a map where
/// the knob is a list or a scalar; a map holding a key the knob does not read; a `pools`/`rate_card`
/// map holding a value that is a list or a scalar. A knob that is the right kind of value but
/// malformed is left to the knob's own reader, whose refusal says what is wrong with it.
#[must_use]
pub fn names_an_entry(key: &str, value: &serde_yaml::Value) -> bool {
    use serde_yaml::Value as Y;
    let Some(map) = value.as_mapping() else {
        return false;
    };
    match shape(key) {
        None => false,
        Some(Shape::List | Shape::Scalar) => true,
        Some(Shape::Fields(keys)) => map
            .keys()
            .any(|k| k.as_str().is_none_or(|k| !keys.contains(&k))),
        Some(Shape::MapOfMaps) => map.values().any(|v| !matches!(v, Y::Mapping(_) | Y::Null)),
    }
}

/// A declared-verb section read off the operator's document, each depth-1 entry named after a
/// reserved key judged AS IT IS READ ([`names_an_entry`]), so the refusal carries that entry's own
/// path and position: `<section>.<key>: <sentence> at line L column C`, the form
/// [`Document::refusal`] prints. `noun` is what one registration of the section is called; the
/// sentence is `busbar_contract::section::reserved_name_refusal`'s.
///
/// # Errors
///
/// The deserializer's own, or the reserved-name refusal.
pub fn read_section<'de, D: Deserializer<'de>>(
    de: D,
    section: &str,
    noun: &str,
) -> Result<serde_yaml::Value, D::Error> {
    Read::Section { section, noun }.deserialize(de)
}

/// How [`read_section`] reads a node: the section itself, entry by entry; or one depth-1 entry,
/// named after a reserved key, judged once read.
#[derive(Clone, Copy)]
enum Read<'a> {
    Section {
        section: &'a str,
        noun: &'a str,
    },
    Entry {
        section: &'a str,
        noun: &'a str,
        name: &'a str,
    },
}

impl Read<'_> {
    /// The node read: an entry that is plainly not its knob is refused here, inside its own node,
    /// so the library marks the refusal with the entry's path and position.
    fn done<E: de::Error>(self, value: serde_yaml::Value) -> Result<serde_yaml::Value, E> {
        match self {
            Read::Entry {
                section,
                noun,
                name,
            } if names_an_entry(name, &value) => Err(E::custom(
                busbar_contract::section::reserved_name_refusal(section, noun, name),
            )),
            _ => Ok(value),
        }
    }
}

impl<'de> DeserializeSeed<'de> for Read<'_> {
    type Value = serde_yaml::Value;
    fn deserialize<D: Deserializer<'de>>(self, de: D) -> Result<Self::Value, D::Error> {
        de.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Read<'_> {
    type Value = serde_yaml::Value;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("any YAML value")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        use serde::Deserialize as _;
        let Read::Section { section, noun } = self else {
            let read = serde_yaml::Value::deserialize(de::value::MapAccessDeserializer::new(map))?;
            return self.done(read);
        };
        // The library's own map read (duplicate keys refused in its words), each reserved-named
        // entry read through its judge.
        let mut out = serde_yaml::Mapping::new();
        while let Some(key) = map.next_key::<serde_yaml::Value>()? {
            if out.contains_key(&key) {
                return Err(de::Error::custom(duplicate_entry(&key)));
            }
            let value = match key.as_str().filter(|k| is_reserved(k)) {
                Some(name) => map.next_value_seed(Read::Entry {
                    section,
                    noun,
                    name,
                })?,
                None => map.next_value()?,
            };
            out.insert(key, value);
        }
        Ok(serde_yaml::Value::Mapping(out))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<Self::Value, A::Error> {
        use serde::Deserialize as _;
        let read = serde_yaml::Value::deserialize(de::value::SeqAccessDeserializer::new(seq))?;
        self.done(read)
    }

    fn visit_enum<A: de::EnumAccess<'de>>(self, data: A) -> Result<Self::Value, A::Error> {
        use serde::Deserialize as _;
        let read = serde_yaml::Value::deserialize(de::value::EnumAccessDeserializer::new(data))?;
        self.done(read)
    }

    fn visit_some<D: Deserializer<'de>>(self, de: D) -> Result<Self::Value, D::Error> {
        use serde::Deserialize as _;
        let read = serde_yaml::Value::deserialize(de)?;
        self.done(read)
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
        self.done(serde_yaml::Value::Bool(v))
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
        self.done(serde_yaml::Value::Number(v.into()))
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
        self.done(serde_yaml::Value::Number(v.into()))
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> {
        self.done(serde_yaml::Value::Number(v.into()))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        self.done(serde_yaml::Value::String(v.to_owned()))
    }
    fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
        self.done(serde_yaml::Value::String(v))
    }
    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        self.done(serde_yaml::Value::Null)
    }
    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        self.done(serde_yaml::Value::Null)
    }
}

/// The YAML library's own sentence for a key written twice in one map (its `Mapping` read's).
fn duplicate_entry(key: &serde_yaml::Value) -> String {
    use serde_yaml::Value as Y;
    match key {
        Y::Null => "duplicate entry with null key".to_owned(),
        Y::Bool(b) => format!("duplicate entry with key `{b}`"),
        Y::Number(n) => format!("duplicate entry with key {n}"),
        Y::String(s) => format!("duplicate entry with key {s:?}"),
        Y::Sequence(_) | Y::Mapping(_) | Y::Tagged(_) => "duplicate entry in YAML map".to_owned(),
    }
}

/// The operator's document: its value and the text its positions are read off.
#[derive(Debug, Clone)]
pub struct Document {
    text: String,
    value: Value,
}

/// Who a section is dealt to.
#[derive(Debug, Clone, Copy)]
pub enum Seat<'a> {
    /// A plugin of the kind whose verbs each plugin declares, by the verbs it states.
    Verbs(&'a [String]),
    /// A plugin instance of a kind with a root key, by the name config gives it.
    Instance(Kind, &'a str),
}

impl<'a> Seat<'a> {
    /// The seat of a plugin of `kind`: by the verbs it states when its kind's verbs are declared
    /// (`Kind::verb`), else by the name config gives the instance.
    #[must_use]
    pub fn of(kind: Kind, verbs: &'a [String], instance: &'a str) -> Self {
        match kind.verb() {
            busbar_contract::plugin::Verb::Declared => Seat::Verbs(verbs),
            busbar_contract::plugin::Verb::Root(_) => Seat::Instance(kind, instance),
        }
    }
}

/// One plugin's section.
#[derive(Debug, Clone, PartialEq)]
pub struct Section {
    /// Where it sits in the operator's file: one path per root key it was dealt from.
    pub at: Vec<Vec<String>>,
    /// The blob that crosses: `{verb: section}` for every stated verb the document writes, reserved
    /// sub-keys stripped; an instance's own `settings`.
    // settings-leak-lint: allow — NON-PROJECTION engine type. `Section` derives no `Serialize`: it
    // is the stage-3g deal, whose `settings` crosses only OUTBOUND to the dealt plugin's lifecycle
    // `validate` (`root::boot::validate_dealt`); no admin read serves it.
    pub settings: Value,
    /// The reserved sub-keys read off, each at its path, for the kernel.
    pub reserved: Vec<(Vec<String>, Value)>,
}

/// A line and column in the operator's file, 1-based as 1.5.5 printed them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Position {
    pub line: usize,
    pub column: usize,
}

impl Document {
    /// The document `text` states.
    ///
    /// # Errors
    ///
    /// The text is not one YAML document.
    pub fn parse(text: String) -> Result<Self, serde_yaml::Error> {
        let value = serde_yaml::from_str(&text)?;
        Ok(Self { text, value })
    }

    /// The document's value.
    #[must_use]
    pub fn value(&self) -> &Value {
        &self.value
    }

    /// The value, for a stage-0 rewrite; positions stay the operator's.
    pub fn value_mut(&mut self) -> &mut Value {
        &mut self.value
    }

    /// The section dealt to `seat`, or `None` when the document writes none for it.
    #[must_use]
    pub fn deal(&self, seat: Seat<'_>) -> Option<Section> {
        match seat {
            Seat::Verbs(verbs) => {
                let mut section = Section {
                    at: Vec::new(),
                    settings: Value::Object(Map::new()),
                    reserved: Vec::new(),
                };
                for verb in verbs {
                    let Some(v) = self.value.get(verb).filter(|v| !v.is_null()) else {
                        continue;
                    };
                    let stripped = strip(verb, v.clone(), &mut section.reserved);
                    section.settings[verb.as_str()] = stripped;
                    section.at.push(vec![verb.clone()]);
                }
                (!section.at.is_empty()).then_some(section)
            }
            Seat::Instance(kind, instance) => {
                let key = kind.root_key()?;
                let entry = match kind {
                    Kind::Transport | Kind::Plane => return None,
                    Kind::Store => vec![key],
                    _ => vec![key, instance],
                };
                let at = self.walk(&entry)?;
                let (path, settings) = match at.get("settings") {
                    Some(s) => ([&entry[..], &["settings"][..]].concat(), s.clone()),
                    None => (entry, Value::Object(Map::new())),
                };
                Some(Section {
                    at: vec![path.into_iter().map(str::to_owned).collect()],
                    settings,
                    reserved: Vec::new(),
                })
            }
        }
    }

    fn walk(&self, path: &[&str]) -> Option<&Value> {
        path.iter()
            .try_fold(&self.value, |v, k| v.get(*k))
            .filter(|v| !v.is_null())
    }

    /// Where `path` sits in the operator's file, or `None` when the text holds no such node.
    #[must_use]
    pub fn position(&self, path: &[String]) -> Option<Position> {
        self.probe(path, "")
            .ok()
            .and_then(|e| e.location())
            .map(|l| Position {
                line: l.line(),
                column: l.column(),
            })
    }

    /// THE REFUSAL TEXT for `reason` at `path`: `<path>: <reason> at line L column C`, 1.5.5's bytes
    /// for a refusal raised at that node; `<path>: <reason>` when the text holds no such node.
    #[must_use]
    pub fn refusal(&self, path: &[String], reason: &str) -> String {
        match self.probe(path, reason) {
            Ok(e) => e.to_string(),
            Err(()) => format!("{}: {reason}", path.join(".")),
        }
    }

    /// [`Self::refusal`] at the first place `section` was dealt from.
    #[must_use]
    pub fn refuse(&self, section: &Section, reason: &str) -> String {
        section
            .at
            .first()
            .map_or_else(|| reason.to_owned(), |p| self.refusal(p, reason))
    }

    /// The library's own error raised at the node `path` names, carrying its path and mark.
    fn probe(&self, path: &[String], reason: &str) -> Result<serde_yaml::Error, ()> {
        let found = std::cell::Cell::new(false);
        let seed = Probe {
            path,
            reason,
            found: &found,
        };
        match seed.deserialize(serde_yaml::Deserializer::from_str(&self.text)) {
            Err(e) if found.get() => Ok(e),
            _ => Err(()),
        }
    }
}

/// THE STRIP (Q-STEP9-a, ARCHITECT 2026-10-07): `section`, the value the document writes under
/// `verb`, with the reserved sub-keys taken off at EXACT depths and nowhere else — the section's own
/// level, each registration's level, each pool (`pools.<p>`) and each pool member
/// (`pools.<p>.members[i]`, when the members are maps) — each recorded in `reserved` at its path
/// (`[verb, ...]`). No recursion: a word spelled like a reserved key deeper than those is the
/// plane's own and crosses.
///
/// Under a declared verb, `pools` is itself reserved, so the whole subtree leaves the blob and is
/// recorded at `[verb, "pools"]`; the reserved keys of each of its pools and members are recorded at
/// their own paths as well. Under the root `pools:` section (the verb that IS
/// `busbar_contract::section::RESERVED_POOLS_KEY`) every depth-1 key is a POOL, as in 1.5.5: only
/// the two section words (`RESERVED_SECTION_KEYS`, 1.5.5's frozen pair) are taken at that level, so
/// a pool named `tier`, `work`, `breaker`, `rate_card`, … is a pool and crosses.
///
/// The one strip every crossing of a section goes through (the deal; a door plane's `open` and
/// `refresh`).
pub fn strip(verb: &str, mut section: Value, reserved: &mut Vec<(Vec<String>, Value)>) -> Value {
    use busbar_contract::section::{RESERVED_POOLS_KEY, RESERVED_SECTION_KEYS};
    let at = [verb.to_owned()];
    let Some(map) = section.as_object_mut() else {
        return section;
    };
    if verb == RESERVED_POOLS_KEY {
        take(map, &at, |k| RESERVED_SECTION_KEYS.contains(&k), reserved);
        for (name, pool) in map.iter_mut() {
            strip_pool(
                pool,
                &[&at[..], std::slice::from_ref(name)].concat(),
                reserved,
            );
        }
        return section;
    }
    take(map, &at, is_reserved, reserved);
    // The `pools` subtree has left whole; the kernel also has its pools' and members' reserved keys
    // by path.
    let pools_at = [verb.to_owned(), RESERVED_POOLS_KEY.to_owned()];
    let lifted = reserved.iter().rev().find(|(p, _)| p[..] == pools_at[..]);
    if let Some(Value::Object(mut pools)) = lifted.map(|(_, v)| v.clone()) {
        for (name, pool) in &mut pools {
            strip_pool(
                pool,
                &[&pools_at[..], std::slice::from_ref(name)].concat(),
                reserved,
            );
        }
    }
    for (name, entry) in map.iter_mut() {
        if let Some(inner) = entry.as_object_mut() {
            take(
                inner,
                &[&at[..], std::slice::from_ref(name)].concat(),
                is_reserved,
                reserved,
            );
        }
    }
    section
}

/// THE CROSSING (P1b; spec Part 1 §4 :561-570): `section`, the value the document writes under
/// `verb`, as a plugin is handed it at `open` and `refresh`: through [`strip`], the one strip, its
/// reserved core-owned sub-keys taken off; beside it, the kernel's POOL AFFINITY projection read off
/// what the strip took ([`pool_affinity`]).
#[must_use]
pub fn crossing(verb: &str, section: Value) -> (Value, Map<String, Value>) {
    let mut reserved = Vec::new();
    let stripped = strip(verb, section, &mut reserved);
    let affinity = pool_affinity(verb, &reserved);
    (stripped, affinity)
}

/// THE POOL AFFINITY PROJECTION (ARCHITECT P1b 2026-10-07): `affinity` is a reserved core-owned
/// sub-key, so the kernel reads each pool's (`config::pools::AffinityCfg`) off what [`strip`] took
/// under `verb` — the pools of the root `pools:` section, or the pools under a declared verb's
/// reserved `pools` — and hands the plane, beside its settings, the resolved directive of each pool
/// whose affinity names a header: `{"<pool>": {"header_name": "<header>"}}`
/// (`busbar_contract::abi::plane::POOL_AFFINITY_HEADER_NAME`). A pool whose affinity names none is
/// absent (the plane's default header). No plane is named: any section's pools are read the same.
#[must_use]
pub fn pool_affinity(verb: &str, reserved: &[(Vec<String>, Value)]) -> Map<String, Value> {
    use busbar_contract::abi::plane::POOL_AFFINITY_HEADER_NAME;
    use busbar_contract::section::RESERVED_POOLS_KEY;
    const AFFINITY: &str = "affinity";
    let pools_at: &[&str] = if verb == RESERVED_POOLS_KEY {
        &[RESERVED_POOLS_KEY]
    } else {
        &[verb, RESERVED_POOLS_KEY]
    };
    let mut out = Map::new();
    for (path, value) in reserved {
        let [head @ .., pool, key] = path.as_slice() else {
            continue;
        };
        if key != AFFINITY
            || head.len() != pools_at.len()
            || head.iter().zip(pools_at).any(|(a, b)| a != b)
        {
            continue;
        }
        let header = serde_json::from_value::<crate::config::pools::AffinityCfg>(value.clone())
            .ok()
            .and_then(|a| a.header_name);
        if let Some(header) = header {
            out.insert(
                pool.clone(),
                serde_json::json!({ POOL_AFFINITY_HEADER_NAME: header }),
            );
        }
    }
    out
}

/// One pool at `at`: its reserved keys, then each member's (a member written as a map).
fn strip_pool(pool: &mut Value, at: &[String], reserved: &mut Vec<(Vec<String>, Value)>) {
    let Some(map) = pool.as_object_mut() else {
        return;
    };
    take(map, at, is_reserved, reserved);
    let members_key = busbar_contract::section::POOL_MEMBERS_KEY;
    if let Some(Value::Array(members)) = map.get_mut(members_key) {
        for (i, member) in members.iter_mut().enumerate() {
            if let Some(m) = member.as_object_mut() {
                let path = [at, &[members_key.to_owned(), i.to_string()][..]].concat();
                take(m, &path, is_reserved, reserved);
            }
        }
    }
}

/// The keys of `map` that `reserved_here` names, taken off and recorded at `at.<key>`.
fn take(
    map: &mut Map<String, Value>,
    at: &[String],
    reserved_here: impl Fn(&str) -> bool,
    reserved: &mut Vec<(Vec<String>, Value)>,
) {
    let keys: Vec<String> = map
        .keys()
        .filter(|k| reserved_here(k.as_str()))
        .cloned()
        .collect();
    for k in keys {
        if let Some(v) = map.remove(&k) {
            reserved.push(([at, std::slice::from_ref(&k)].concat(), v));
        }
    }
}

/// Walks the operator's text to the node a path names and raises `reason` there, so the library
/// marks the error with that node's path and position.
struct Probe<'p> {
    path: &'p [String],
    reason: &'p str,
    found: &'p std::cell::Cell<bool>,
}

impl Probe<'_> {
    fn here<E: de::Error>(self) -> Result<(), E> {
        self.found.set(self.path.is_empty());
        Err(E::custom(self.reason))
    }
}

impl<'de> DeserializeSeed<'de> for Probe<'_> {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(self, de: D) -> Result<(), D::Error> {
        de.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Probe<'_> {
    type Value = ();

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("any node")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let Some((head, rest)) = self.path.split_first() else {
            return self.here();
        };
        while let Some(key) = map.next_key::<String>()? {
            if key == *head {
                return map.next_value_seed(Probe { path: rest, ..self });
            }
            map.next_value::<IgnoredAny>()?;
        }
        Err(de::Error::custom(self.reason))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        let reason = self.reason;
        let Some((head, rest)) = self.path.split_first() else {
            return self.here();
        };
        let index: usize = head.parse().map_err(|_| de::Error::custom(reason))?;
        for _ in 0..index {
            if seq.next_element::<IgnoredAny>()?.is_none() {
                return Err(de::Error::custom(reason));
            }
        }
        seq.next_element_seed(Probe { path: rest, ..self })?;
        Err(de::Error::custom(reason))
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
        self.here()
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
        self.here()
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> Result<(), E> {
        self.here()
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<(), E> {
        self.here()
    }
    fn visit_str<E: de::Error>(self, _: &str) -> Result<(), E> {
        self.here()
    }
    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        self.here()
    }
    fn visit_none<E: de::Error>(self) -> Result<(), E> {
        self.here()
    }
}

#[cfg(test)]
#[path = "tests/deal.rs"]
mod tests;
