// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
//! The 1.6.0-only config PRE-PASS: lift the 1.6.0-additive keys out of the document BEFORE the
//! frozen 1.5.5-shaped structs ever see them.
//!
//! The config grammar is frozen: every `deny_unknown_fields` struct must produce the SAME
//! `expected one of` key list the published 1.5.5 binary produces, byte for byte. A 1.6.0-additive
//! key declared as a plain field on one of those structs breaks that, because serde builds the
//! list from the struct's own field set — the key would be named in a refusal a 1.5.5 operator
//! never saw.
//!
//! So the additive keys are NOT fields of the frozen structs. They are `#[serde(skip)]` carriers,
//! filled in by this module: the document's map is walked once, the additive keys are pulled out
//! and deserialized into their own types, and the REMAINDER — structurally unchanged — is what the
//! frozen structs parse. The refusal a 1.5.5-shaped document gets is therefore the 1.5.5 refusal,
//! including its key list.
//!
//! The lift happens INSIDE the live deserializer rather than on a rebuilt document, which is what
//! keeps the refusal byte-identical rather than merely equivalent: a document rebuilt from a
//! `serde_yaml::Value` has lost every source position, so the `at line N column M` suffix (and the
//! `section:` path prefix) would be dropped from every parse error in the file. Walking the real
//! event stream keeps both.
//!
//! Two levels are lifted today:
//!   * the TOP-LEVEL sections — the kernel's own 1.6.0 additions ([`LIFTED_TOP_LEVEL_KEYS`]) and
//!     every section a REGISTERED plane declares (#49: the kernel spells no plane section, it reads
//!     them off the plane registry), and
//!   * the token-mint policy block nested under `auth:`, by that field's own reader
//!     ([`auth_section`]).
//!
//! A plane that is not registered declares nothing, so its section is not lifted: it reaches the
//! frozen struct and is refused with serde's own unknown-field message — exactly what 1.5.5 said
//! for any key it did not know (Option A, S11b (c) / Q67).
//!
//! The mirror image holds for a section a registered plane REQUIRES
//! (`PlaneDeclaration::required_config_sections`, Law 7): the pass watches for it, and a document
//! that does not carry it is refused with serde's own missing-field message for it — 1.5.5's bytes
//! for `providers`/`models` in a build that links a plane requiring them. A section no registered
//! plane requires may be omitted (the frozen struct defaults it).
//!
//! The remaining fleet-scalar keys named in the design (a data directory, peers, a keyset
//! reference, a WAL capacity, and the per-bucket tier/currency pair) are NOT part of the parse
//! surface yet — no frozen struct declares them — so there is nothing for this module to lift for
//! them. They join [`LIFTED_TOP_LEVEL_KEYS`] (or the per-bucket list) on the commit that first
//! parses them, and the frozen key lists stay unmoved because they never became fields.

use std::fmt;

use serde::de::value::MapAccessDeserializer;
use serde::de::{DeserializeSeed, Deserializer, Error as _, IntoDeserializer, MapAccess, Visitor};
use serde::Deserialize;

use super::{AuthDeployCfg, DeployCfg};

use crate::config::plane_sections::{DeclaredSections, EndpointSection};
use crate::plane_driver::registry::{PlaneDeclaration, CORE_OWNED_CONCRETE_SECTIONS};

pub(crate) const LIFTED_TOP_LEVEL_KEYS: &[&str] = &["oauth_as", "credentials"];

pub(crate) const LIFTED_AUTH_KEYS: &[&str] = &["policy"];

/// Where one lifted key's value lands: one [`Lifted`] carrier each.
#[derive(Clone, Copy)]
enum Dest {
    Endpoint,
    OauthAs,
    /// A declaring section its plane owns the grammar of: parsed by that plane into the map carrier.
    Declared(PlaneMetadata),
    /// A declaring section no carrier holds: carried RAW, for its plane to read over the ABI.
    Raw(PlaneMetadata),
    AuthPolicy,
    Credentials,
}

#[derive(Clone, Copy)]
struct PlaneMetadata {
    key: &'static str,
    noun: &'static str,
}

impl Dest {
    fn for_declared(decl: &PlaneDeclaration, key: &'static str) -> Dest {
        let metadata = crate::plane_driver::registry::plane_decl_for_config_section(key)
            .map(|d| PlaneMetadata {
                key: d.key,
                noun: d.subject_noun,
            })
            .unwrap_or(PlaneMetadata { key, noun: "entry" });
        let carried = if key == decl.config_section {
            DeclaredSections::holds(decl).then_some(Dest::Declared(metadata))
        } else {
            (decl.config_section == EndpointSection::OWNER).then_some(Dest::Endpoint)
        };
        carried.unwrap_or(Dest::Raw(metadata))
    }
}

fn lift_table() -> Vec<(&'static str, Dest)> {
    let mut table: Vec<(&'static str, Dest)> = vec![
        (LIFTED_TOP_LEVEL_KEYS[0], Dest::OauthAs),
        (LIFTED_TOP_LEVEL_KEYS[1], Dest::Credentials),
    ];
    for decl in crate::plane_driver::registry::plane_decls() {
        let decl: &PlaneDeclaration = &decl.declaration;
        for &key in std::iter::once(&decl.config_section).chain(decl.owned_config_sections) {
            if !CORE_OWNED_CONCRETE_SECTIONS.contains(&key) && !table.iter().any(|(k, _)| *k == key)
            {
                table.push((key, Dest::for_declared(decl, key)));
            }
        }
    }
    table
}

const AUTH_LIFTS: &[(&str, Dest)] = &[(LIFTED_AUTH_KEYS[0], Dest::AuthPolicy)];

/// Everything the pre-pass pulled out of one document: the `#[serde(skip)]` carriers of
/// [`DeployCfg`], each at its `Default` (an omitted section) until its key is read.
#[derive(Default)]
pub(crate) struct Lifted {
    endpoint: EndpointSection,
    oauth_as: Option<serde_yaml::Value>,
    declared: DeclaredSections,
    auth_policy: Option<crate::config::AuthPolicyCfg>,
    credentials: crate::config::CredentialsCfg,
    plane_rate_cards: super::PlaneRateCards,
    plane_fees: super::PlaneFeesMap,
    plane_raw: std::collections::BTreeMap<&'static str, serde_yaml::Value>,
    declared_raw: std::collections::BTreeMap<&'static str, serde_yaml::Value>,
    /// The top-level keys the key reader watches for: the nested key, then every section a
    /// registered plane requires. A key is struck as the document is seen to carry it, so what is
    /// left once the document is read is what it omitted.
    watch: Vec<&'static str>,
}

impl Lifted {
    fn install(self, deploy: &mut DeployCfg) {
        deploy.plane_rate_cards = self.plane_rate_cards;
        deploy.plane_fees = self.plane_fees;
        deploy.plane_raw = self.plane_raw;
        deploy.declared_raw = self.declared_raw;
        deploy.declared = self.declared;
        deploy.endpoint = self.endpoint;
        deploy.oauth_as = self.oauth_as;
        deploy.credentials = self.credentials;
    }
}

struct LiftedSeed<'a> {
    key: &'static str,
    dest: Dest,
    lifted: &'a mut Lifted,
}

impl<'de> DeserializeSeed<'de> for LiftedSeed<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, de: D) -> Result<Self::Value, D::Error> {
        let (key, lifted) = (self.key, self.lifted);
        match self.dest {
            Dest::Endpoint => {
                let section = serde_yaml::Value::deserialize(de)?;
                if !section.is_null() {
                    lifted.declared_raw.insert(key, section.clone());
                }
                lifted.endpoint =
                    EndpointSection::deserialize(section).map_err(D::Error::custom)?;
            }
            Dest::OauthAs => lifted.oauth_as = Option::deserialize(de)?,
            Dest::Declared(metadata) => {
                let section = plane_remainder_in(key, metadata.key, metadata.noun, de, lifted)?;
                lifted.declared_raw.insert(key, section.clone());
                let parsed = DeclaredSections::parse(key, section).map_err(D::Error::custom)?;
                lifted.declared.0.extend(parsed.0);
            }
            Dest::Raw(metadata) => {
                let section = plane_remainder_in(key, metadata.key, metadata.noun, de, lifted)?;
                lifted.plane_raw.insert(key, section);
            }
            Dest::AuthPolicy => lifted.auth_policy = Some(Deserialize::deserialize(de)?),

            Dest::Credentials => lifted.credentials = Option::deserialize(de)?.unwrap_or_default(),
        }
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
) -> Result<serde_yaml::Value, D::Error> {
    let [card_key, fees_key] = PLANE_CARD_KEYS;
    let mut section = crate::config_validate::deal::read_section(de, section_key, noun)?;
    let mut map = section.as_mapping_mut();
    let mut take = |key: &str| map.as_mut().and_then(|m| m.remove(key));
    let fail =
        |key: &str, e: serde_yaml::Error| D::Error::custom(format!("{section_key}.{key}: {e}"));
    if let Some(card) = take(card_key) {
        let card = serde_yaml::from_value(card).map_err(|e| fail(card_key, e))?;
        lifted.plane_rate_cards.insert(plane.to_string(), card);
    }
    if let Some(fees) = take(fees_key) {
        let f: super::PlaneFeesCfg = serde_yaml::from_value(fees).map_err(|e| fail(fees_key, e))?;
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
    lift: &'a [(&'static str, Dest)],
    watch: &'a mut Vec<&'static str>,

    lifted: &'a mut Option<(&'static str, Dest)>,
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
        if let Some(entry) = self.lift.iter().find(|(k, _)| *k == v) {
            *self.lifted = Some(*entry);
            return Ok(KeyOutcome::Lift(self.inner));
        }
        self.watch.retain(|k| *k != v);
        self.inner
            .deserialize(v.into_deserializer())
            .map(KeyOutcome::Forward)
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
    lift: &'a [(&'static str, Dest)],
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
                lift: self.lift,
                watch: &mut self.lifted.watch,
                lifted: &mut lifted,
            })?;
            match outcome {
                None => return Ok(None),
                Some(KeyOutcome::Forward(v)) => return Ok(Some(v)),
                Some(KeyOutcome::Lift(returned)) => {
                    let (key, dest) = lifted.expect("a lifted key always names itself");
                    if self.seen_lifted.contains(&key) {
                        return Err(Self::Error::duplicate_field(key));
                    }
                    self.seen_lifted.push(key);
                    self.inner.next_value_seed(LiftedSeed {
                        key,
                        dest,
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

pub(crate) fn auth_section<'de, D: Deserializer<'de>>(
    de: D,
) -> Result<Option<AuthDeployCfg>, D::Error> {
    de.deserialize_any(AuthVisitor)
}

struct AuthVisitor;

impl<'de> Visitor<'de> for AuthVisitor {
    type Value = Option<AuthDeployCfg>;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a configuration section")
    }

    fn visit_map<M: MapAccess<'de>>(self, map: M) -> Result<Self::Value, M::Error> {
        let mut lifted = Lifted::default();
        let mut auth = AuthDeployCfg::deserialize(MapAccessDeserializer::new(LiftingMap {
            inner: map,
            lift: AUTH_LIFTS,
            lifted: &mut lifted,
            seen_lifted: Vec::new(),
        }))?;
        if let Some(policy) = lifted.auth_policy {
            auth.policy = policy;
        }
        Ok(Some(auth))
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_some<D: Deserializer<'de>>(self, de: D) -> Result<Self::Value, D::Error> {
        de.deserialize_any(self)
    }
}

struct SplitDocument(DeployCfg);

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
        let watch = crate::plane_driver::registry::plane_decls()
            .iter()
            .flat_map(|d| d.required_config_sections.iter().copied())
            .collect();
        let table = lift_table();
        let (mut deploy, lifted) = read_document::<_, DeployCfg>(map, watch, &table)?;
        lifted.install(&mut deploy);
        Ok(SplitDocument(deploy))
    }
}

fn read_document<'de, M: MapAccess<'de>, T: Deserialize<'de>>(
    map: M,
    watch: Vec<&'static str>,
    table: &[(&'static str, Dest)],
) -> Result<(T, Lifted), M::Error> {
    let mut lifted = Lifted {
        watch,
        ..Lifted::default()
    };
    let deploy = T::deserialize(MapAccessDeserializer::new(LiftingMap {
        inner: map,
        lift: table,
        lifted: &mut lifted,
        seen_lifted: Vec::new(),
    }))?;
    if let Some(s) = lifted.watch.iter().find(|k| **k != "auth") {
        return Err(M::Error::missing_field(s));
    }
    Ok((deploy, lifted))
}

pub fn deploy_from_yaml_str(text: &str) -> Result<DeployCfg, serde_yaml::Error> {
    deploy_from_deserializer(serde_yaml::Deserializer::from_str(text))
}

pub fn deploy_from_deserializer<'de, D: Deserializer<'de>>(de: D) -> Result<DeployCfg, D::Error> {
    SplitDocument::deserialize(de).map(|d| d.0)
}

pub fn deploy_from_yaml_value(value: serde_yaml::Value) -> Result<DeployCfg, serde_yaml::Error> {
    deploy_from_deserializer(value)
}

#[cfg(test)]
#[path = "tests/plane_remainder_tests.rs"]
mod plane_remainder_tests;

#[cfg(test)]
#[path = "tests/document_metadata_tests.rs"]
mod document_metadata_tests;
