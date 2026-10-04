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
/// `work`.
pub const RESERVED_SUB_KEYS: [&str; 7] = [
    "breaker",
    "on_exhausted",
    "gates",
    "affinity",
    "tier",
    "repeatable",
    "work",
];

/// Whether `key` is read by the kernel and stripped before a section crosses.
#[must_use]
pub fn is_reserved(key: &str) -> bool {
    RESERVED_SUB_KEYS.contains(&key)
        || busbar_contract::section::RESERVED_SECTION_KEYS.contains(&key)
        || crate::config::prepass::PLANE_CARD_KEYS.contains(&key)
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
                    let path = vec![verb.clone()];
                    let stripped = strip(v.clone(), &path, &mut section.reserved);
                    section.settings[verb.as_str()] = stripped;
                    section.at.push(path);
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

/// `value` with the reserved sub-keys taken off its own level and off each of its registrations,
/// each recorded at its path.
fn strip(mut value: Value, at: &[String], reserved: &mut Vec<(Vec<String>, Value)>) -> Value {
    let mut take = |map: &mut Map<String, Value>, at: &[String]| {
        let keys: Vec<String> = map.keys().filter(|k| is_reserved(k)).cloned().collect();
        for k in keys {
            if let Some(v) = map.remove(&k) {
                reserved.push(([at, std::slice::from_ref(&k)].concat(), v));
            }
        }
    };
    if let Some(map) = value.as_object_mut() {
        take(map, at);
        for (name, entry) in map.iter_mut() {
            if let Some(inner) = entry.as_object_mut() {
                take(inner, &[at, std::slice::from_ref(name)].concat());
            }
        }
    }
    value
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
