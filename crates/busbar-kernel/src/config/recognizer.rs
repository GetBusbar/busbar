// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The native section recognizer's kernel hook (WP1-GAP-plane-sections r3, section 2.2).
//!
//! A top-level key is a core section ([`core_keys`], taken from `DeployCfg`'s own typed parse,
//! never literals), or the section of an admitted plane instance, or refused. The instance names
//! arrive as the grammar's [`ItemKind::Section`] items, which the root fills from the loader's
//! `plane_sections`. Reading them runs no plugin code. Nothing here consults the legacy plane
//! declaration registry.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;
use std::sync::{Mutex, OnceLock, PoisonError};

use super::grammar::{Grammar, ItemKind};
use super::DeployCfg;

/// Instance names live as long as the process: they are admitted identities, a small set that a
/// reload repeats, so each distinct name is interned once.
fn intern(name: &str) -> &'static str {
    static NAMES: Mutex<BTreeSet<&'static str>> = Mutex::new(BTreeSet::new());
    let mut names = NAMES.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(found) = names.get(name) {
        return found;
    }
    let leaked: &'static str = Box::leak(name.to_owned().into_boxed_str());
    names.insert(leaked);
    leaked
}

/// The admitted plane instance names one read recognizes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SectionNames(BTreeSet<&'static str>);

impl SectionNames {
    pub(crate) fn of(grammar: &Grammar) -> Self {
        Self(
            grammar
                .items
                .iter()
                .filter(|item| item.kind == ItemKind::Section)
                .map(|item| intern(&item.name))
                .collect(),
        )
    }

    /// The interned key when `key` is an admitted instance name that no core section uses.
    pub(crate) fn recognize(&self, key: &str) -> Option<&'static str> {
        if is_core_key(key) {
            return None;
        }
        self.0.get(key).copied()
    }

    /// Rule 3's sentence, appended to the unknown-field refusal.
    pub(crate) fn refusal(&self, key: &str) -> String {
        let names = if self.0.is_empty() {
            "(none)".to_owned()
        } else {
            self.0.iter().copied().collect::<Vec<_>>().join(", ")
        };
        format!(
            "`{key}` is not a core section and no admitted plane answers to it; plane sections \
             are: {names}"
        )
    }
}

thread_local! {
    static CURRENT: RefCell<Option<Rc<SectionNames>>> = const { RefCell::new(None) };
}

/// Run one synchronous document read with `names` as its recognizer.
pub(crate) fn scoped<T>(names: SectionNames, body: impl FnOnce() -> T) -> T {
    struct Reset(Option<Rc<SectionNames>>);
    impl Drop for Reset {
        fn drop(&mut self) {
            CURRENT.with(|current| current.replace(self.0.take()));
        }
    }
    let _reset = Reset(CURRENT.with(|current| current.replace(Some(Rc::new(names)))));
    body()
}

pub(crate) fn current() -> Rc<SectionNames> {
    CURRENT.with(|current| current.borrow().clone().unwrap_or_default())
}

/// Captures the field list serde's derived reader names when it refuses an unknown key.
#[derive(Debug)]
struct Probe(Option<&'static [&'static str]>);

impl std::fmt::Display for Probe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("core key probe")
    }
}

impl std::error::Error for Probe {}

impl serde::de::Error for Probe {
    fn custom<T: std::fmt::Display>(_: T) -> Self {
        Self(None)
    }

    fn unknown_field(_: &str, expected: &'static [&'static str]) -> Self {
        Self(Some(expected))
    }
}

/// Every top-level key of the authored `DeployCfg`, from its own typed definition.
pub fn core_keys() -> &'static BTreeSet<&'static str> {
    static KEYS: OnceLock<BTreeSet<&'static str>> = OnceLock::new();
    KEYS.get_or_init(|| {
        let probe = serde::de::value::MapDeserializer::<_, Probe>::new(std::iter::once((
            "\u{1}busbar-core-key-probe",
            (),
        )));
        match DeployCfg::deserialize(probe) {
            Err(Probe(Some(fields))) => fields.iter().copied().collect(),
            _ => BTreeSet::new(),
        }
    })
}

/// Whether `key` is a core section's key: what the loader's `plane_sections` takes as
/// `is_core_key`.
#[must_use]
pub fn is_core_key(key: &str) -> bool {
    core_keys().contains(key)
}

/// The audiences of the recognized plane sections that serve HTTP routes: each section's
/// `canonical_uri`, in instance-name order. `serves_http` is the root reader's judgement of the
/// instance's admitted routes (the loader's route records); a section that states no
/// `canonical_uri` has no audience to protect.
#[must_use]
pub fn plane_audiences(
    sections: &std::collections::BTreeMap<&'static str, busbar_contract::yaml::Value>,
    serves_http: impl Fn(&str) -> bool,
) -> Vec<String> {
    use busbar_contract::yaml::ValueExt as _;
    sections
        .iter()
        .filter(|(instance, _)| serves_http(instance))
        .filter_map(|(_, section)| section.get("canonical_uri")?.as_str().map(str::to_owned))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oauth_as_protected_resources_match_the_http_instances_routes() {
        let sections = std::collections::BTreeMap::from([
            (
                "decisions",
                busbar_contract::yaml::from_str("canonical_uri: https://dec.example\n").unwrap(),
            ),
            (
                "mcp",
                busbar_contract::yaml::from_str("canonical_uri: https://tools.example\n").unwrap(),
            ),
            (
                "quiet",
                busbar_contract::yaml::from_str("greeting: hi\n").unwrap(),
            ),
        ]);
        assert_eq!(
            plane_audiences(&sections, |instance| instance == "mcp"),
            vec!["https://tools.example".to_owned()]
        );
        assert!(plane_audiences(&sections, |_| false).is_empty());
        assert!(plane_audiences(&sections, |instance| instance == "quiet").is_empty());
    }

    #[test]
    fn the_grammar_carries_which_instances_serve_http() {
        let grammar = Grammar::empty().with_http_instances(["mcp".to_owned()]);
        assert!(grammar.serves_http("mcp"));
        assert!(!grammar.serves_http("decisions"));
    }

    #[test]
    fn core_keys_come_from_the_typed_parse() {
        for key in [
            "listen",
            "providers",
            "models",
            "pools",
            "hooks",
            "oauth_as",
            "rate_card",
        ] {
            assert!(is_core_key(key), "{key}");
        }
        assert!(!is_core_key("mcp"));
        assert!(!is_core_key("tools"));
    }
}
