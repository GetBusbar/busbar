// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
//! Read the original document, recognizing plane sections by admitted instance name.
//!
//! Core configuration fields are parsed directly by their current schema. A key that no core field
//! owns but an admitted plane instance is named by is that plane's section: its core-owned
//! `rate_card` and `fees` are lifted into core pricing keyed by instance name, and the remainder is
//! carried raw. Any other key is refused (WP1-GAP-plane-sections r3). Reading the original event
//! stream preserves source locations and duplicate-field errors.

use std::fmt;

use serde::de::value::MapAccessDeserializer;
use serde::de::{DeserializeSeed, Deserializer, Error as _, IntoDeserializer, MapAccess, Visitor};
use serde::Deserialize;

use super::grammar::Grammar;
use super::DeployCfg;

use super::recognizer::SectionNames;

/// Everything the pre-pass pulled out of one document: the `#[serde(skip)]` carriers of
/// [`DeployCfg`], each at its `Default` (an omitted section) until its key is read.
#[derive(Default)]
pub(crate) struct Lifted {
    listen_explicit: bool,
    plane_rate_cards: super::PlaneRateCards,
    plane_fees: super::PlaneFeesMap,
    /// Each recognized plane section, by instance name, minus the core words lifted off it.
    instance_sections: std::collections::BTreeMap<&'static str, busbar_contract::yaml::Value>,
    /// The plane sections the document wrote, in document order: what the read used (§3.8).
    sections: Vec<&'static str>,
}

impl Lifted {
    fn install(self, deploy: &mut DeployCfg) {
        deploy.listen_explicit = self.listen_explicit;
        deploy.plane_rate_cards = self.plane_rate_cards;
        deploy.plane_fees = self.plane_fees;
        deploy.instance_sections = self.instance_sections;
    }
}

struct LiftedSeed<'a> {
    key: &'static str,
    lifted: &'a mut Lifted,
}

impl<'de> DeserializeSeed<'de> for LiftedSeed<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, de: D) -> Result<Self::Value, D::Error> {
        let (key, lifted) = (self.key, self.lifted);
        // The instance name labels the section; the legacy plane registry is not consulted.
        let section = plane_remainder_in(key, key, "entry", de, lifted)?;
        lifted.instance_sections.insert(key, section);
        Ok(())
    }
}

pub(crate) const PLANE_CARD_KEYS: [&str; 2] = ["rate_card", "fees"];

fn plane_remainder_in<'de, D: Deserializer<'de>>(
    section_key: &'static str,
    plane: &str,
    noun: &str,
    de: D,
    lifted: &mut Lifted,
) -> Result<busbar_contract::yaml::Value, D::Error> {
    let [card_key, fees_key] = PLANE_CARD_KEYS;
    let mut section = crate::config_validate::deal::read_section(de, section_key, noun)?;
    let mut map = busbar_contract::yaml::ValueExt::as_mapping_mut(&mut section);
    let mut take = |key: &str| {
        map.as_mut()
            .and_then(|m| busbar_contract::yaml::MappingExt::remove_key(&mut **m, key))
    };
    let fail = |key: &str, e: busbar_contract::yaml::Error| {
        D::Error::custom(format!("{section_key}.{key}: {e}"))
    };
    if let Some(card) = take(card_key) {
        let card = busbar_contract::yaml::from_value(card).map_err(|e| fail(card_key, e))?;
        lifted.plane_rate_cards.insert(plane.to_string(), card);
    }
    if let Some(fees) = take(fees_key) {
        let f: super::PlaneFeesCfg =
            busbar_contract::yaml::from_value(fees).map_err(|e| fail(fees_key, e))?;
        let (per_request, per_session) = (f.per_request.into(), f.per_session.into());
        let fees = busbar_kernel_ledger::cost::PlaneFees {
            per_request,
            per_session,
        };
        lifted.plane_fees.insert(plane.to_string(), fees);
    }
    Ok(section)
}

enum KeyOutcome<V, S> {
    Forward(V),
    Lift(S),
}

struct KeySeed<'a, S> {
    inner: S,
    names: &'a SectionNames,
    listen_explicit: &'a mut bool,
    lifted: &'a mut Option<&'static str>,
}

impl<'de, S: DeserializeSeed<'de>> DeserializeSeed<'de> for KeySeed<'_, S> {
    type Value = KeyOutcome<S::Value, S>;

    fn deserialize<D: Deserializer<'de>>(self, de: D) -> Result<Self::Value, D::Error> {
        de.deserialize_str(self)
    }
}

impl<'de, S: DeserializeSeed<'de>> Visitor<'de> for KeySeed<'_, S> {
    type Value = KeyOutcome<S::Value, S>;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("field identifier")
    }

    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
        if v == "upstreams" {
            return Err(E::custom("unknown field `upstreams`: move each entry's dial settings into the registration that uses it, under that plane's declared registration path"));
        }
        if let Some(key) = self.names.recognize(v) {
            *self.lifted = Some(key);
            return Ok(KeyOutcome::Lift(self.inner));
        }
        if v == "listen" {
            *self.listen_explicit = true;
        }
        let names = self.names;
        self.inner
            .deserialize(v.into_deserializer())
            .map(KeyOutcome::Forward)
            .map_err(|error: E| {
                // Rule 3: only a key core's own parse refuses reaches here.
                if super::recognizer::is_core_key(v) {
                    error
                } else {
                    E::custom(format!("{error}. {}", names.refusal(v)))
                }
            })
    }

    fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
        match std::str::from_utf8(v) {
            Ok(s) => self.visit_str(s),
            Err(_) => Err(E::invalid_value(serde::de::Unexpected::Bytes(v), &self)),
        }
    }
}

struct LiftingMap<'a, M> {
    inner: M,
    names: &'a SectionNames,
    lifted: &'a mut Lifted,
    seen_lifted: Vec<&'static str>,
}

impl<'de, M: MapAccess<'de>> MapAccess<'de> for LiftingMap<'_, M> {
    type Error = M::Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Self::Error> {
        let mut seed = seed;
        loop {
            let mut lifted = None;
            let outcome = self.inner.next_key_seed(KeySeed {
                inner: seed,
                names: self.names,
                listen_explicit: &mut self.lifted.listen_explicit,
                lifted: &mut lifted,
            })?;
            match outcome {
                None => return Ok(None),
                Some(KeyOutcome::Forward(v)) => return Ok(Some(v)),
                Some(KeyOutcome::Lift(returned)) => {
                    let key = lifted.expect("a lifted key always names itself");
                    if self.seen_lifted.contains(&key) {
                        return Err(Self::Error::duplicate_field(key));
                    }
                    self.seen_lifted.push(key);
                    self.lifted.sections.push(key);
                    self.inner.next_value_seed(LiftedSeed {
                        key,
                        lifted: &mut *self.lifted,
                    })?;
                    seed = returned;
                }
            }
        }
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(
        &mut self,
        seed: V,
    ) -> Result<V::Value, Self::Error> {
        self.inner.next_value_seed(seed)
    }

    fn size_hint(&self) -> Option<usize> {
        self.inner.size_hint()
    }
}

struct SplitDocument(DeployCfg, Vec<&'static str>);

/// The document body as its fields declare it, read under whatever source context encloses it.
struct Body(DeployCfg);

impl<'de> Deserialize<'de> for Body {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        DeployCfg::deserialize(de).map(Body)
    }
}

/// A `DeployCfg` decoded through serde with no grammar given: canonical references only, and its
/// grammar stays [`GrammarField::Unbound`](super::grammar::GrammarField), which refuses wherever
/// a grammar is needed. Every configuration reader reads through [`deploy_from_deserializer`] instead, under the
/// grammar of its own read; nothing reads the live secret axis to parse a document.
impl<'de> Deserialize<'de> for DeployCfg {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let none = busbar_contract::secret_ref::Sugars::default();
        busbar_contract::secret_ref::context::deserialize::<Body, _>(de, &none).map(|body| body.0)
    }
}

impl<'de> Deserialize<'de> for SplitDocument {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        de.deserialize_map(DocumentVisitor)
    }
}

struct DocumentVisitor;

impl<'de> Visitor<'de> for DocumentVisitor {
    type Value = SplitDocument;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a busbar configuration document")
    }

    fn visit_map<M: MapAccess<'de>>(self, map: M) -> Result<Self::Value, M::Error> {
        let names = super::recognizer::current();
        let (Body(mut deploy), mut lifted) = read_document::<_, Body>(map, &names)?;
        let sections = std::mem::take(&mut lifted.sections);
        lifted.install(&mut deploy);
        Ok(SplitDocument(deploy, sections))
    }
}

fn read_document<'de, M: MapAccess<'de>, T: Deserialize<'de>>(
    map: M,
    names: &SectionNames,
) -> Result<(T, Lifted), M::Error> {
    let mut lifted = Lifted::default();
    let deploy = T::deserialize(MapAccessDeserializer::new(LiftingMap {
        inner: map,
        names,
        lifted: &mut lifted,
        seen_lifted: Vec::new(),
    }))?;
    Ok((deploy, lifted))
}

/// Read a deployment document under `grammar`: the grammar of this read (§3.4).
pub fn deploy_from_yaml_str(
    text: &str,
    grammar: &Grammar,
) -> Result<DeployCfg, busbar_contract::yaml::Error> {
    let mut deploy =
        busbar_contract::yaml::with_deserializer(text, |d| deploy_from_deserializer(d, grammar))?;
    deploy.authored_routing = super::authored_routing::capture(text, &deploy.pools);
    Ok(deploy)
}

/// THE ONE DOCUMENT READER: the deployment document under `grammar`, which the result carries, so
/// every later check of it reads the same shorthand. A shorthand no module of `grammar` declares
/// is refused (an empty grammar accepts canonical references only).
pub fn deploy_from_deserializer<'de, D: Deserializer<'de>>(
    de: D,
    grammar: &Grammar,
) -> Result<DeployCfg, D::Error> {
    // Bind the opaque named secret definitions before any typed SecretRef is parsed. The
    // untyped reader rejects duplicate keys, including duplicate instance definitions.
    let bound;
    let words = busbar_contract::secret_ref::context::UsedWords::default();
    let (SplitDocument(mut deploy, sections), grammar) = if !grammar.secret_binding_required() {
        (
            super::recognizer::scoped(SectionNames::of(grammar), || {
                busbar_contract::secret_ref::context::deserialize_recording::<SplitDocument, _>(
                    de,
                    &grammar.sugars,
                    &words,
                )
            })?,
            grammar,
        )
    } else {
        use busbar_contract::yaml::ValueExt as _;
        let document = busbar_contract::yaml::untyped(de)?;
        let secrets = match document.get("secrets") {
            Some(value) => busbar_contract::yaml::from_value::<
                std::collections::BTreeMap<String, super::SecretModuleCfg>,
            >(value.clone())
            .map_err(D::Error::custom)?,
            None => std::collections::BTreeMap::new(),
        };
        bound = grammar
            .bind_secret_instances(&secrets)
            .map_err(D::Error::custom)?;
        let parsed = super::recognizer::scoped(SectionNames::of(&bound), || {
            busbar_contract::secret_ref::context::deserialize_recording::<SplitDocument, _>(
                busbar_contract::yaml::deserializer(document),
                &bound.sugars,
                &words,
            )
        })
        .map_err(D::Error::custom)?;
        (parsed, &bound)
    };
    // What this read used of its grammar, recorded by the parse itself (§3.8): the grammar pin
    // compares exactly these items.
    let mut used = super::grammar::Used::default();
    used.absorb(words);
    used.sections = sections.into_iter().map(str::to_owned).collect();
    if !used.sections.is_empty() {
        // A plane section's `${VAR}` fills read through the fill role (`filled::plane_bound`).
        used.roles
            .insert(busbar_contract::abi::mechanism::door::SUGAR_ROLE_FILL.to_owned());
    }
    deploy.grammar = super::grammar::GrammarField::bound_used(grammar.clone(), used);
    Ok(deploy)
}

pub fn deploy_from_yaml_value(
    value: busbar_contract::yaml::Value,
    grammar: &Grammar,
) -> Result<DeployCfg, busbar_contract::yaml::Error> {
    deploy_from_deserializer(busbar_contract::yaml::deserializer(value), grammar)
}

#[cfg(test)]
#[path = "tests/recognizer_tests.rs"]
mod recognizer_tests;

#[cfg(test)]
#[path = "tests/plane_remainder_tests.rs"]
mod plane_remainder_tests;

#[cfg(test)]
#[path = "tests/document_metadata_tests.rs"]
mod document_metadata_tests;

#[cfg(test)]
#[path = "tests/prepass_tests.rs"]
mod source_declarations_tests;
