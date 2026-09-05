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
//!   * the TOP-LEVEL plane sections, and
//!   * the token-mint policy block nested under `auth:`.
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

use super::DeployCfg;
use crate::plane::config::{AgentsSection, McpEndpointSection, StreamsSection, ToolsSection}; // plane-purity: frozen-wire the carrier TYPE names recorded verbatim in config-schema.snapshot.json

/// The TOP-LEVEL keys that exist only in 1.6.0 and must never reach the frozen top-level struct.
///
/// This list is the authoritative enumeration of the 1.6.0-additive top-level grammar: every entry
/// is a key the published 1.5.5 binary refuses as unknown, and none of them may appear in the
/// frozen struct's field set. Adding a 1.6.0 top-level key means adding it HERE and giving the
/// carrier field a serde-skipped declaration — never a plain field.
///
/// In order: busbar's OWN endpoint as an OAuth 2.1 resource server; busbar AS an OAuth 2.1
/// authorization server; the MCP upstream registry; the A2A agent registry; the live-voice
/// session section.
pub(crate) const LIFTED_TOP_LEVEL_KEYS: &[&str] =
    &["mcp", "oauth_as", "tools", "agents", "streams"]; // plane-purity: frozen-wire the frozen top-level wire KEYS this pass lifts

/// The keys lifted out of the `auth:` block. `policy:` is a 1.6.0 addition (token-mint caps); the
/// five keys around it are 1.5.5's and stay in the frozen struct.
pub(crate) const LIFTED_AUTH_KEYS: &[&str] = &["policy"];

/// The top-level key whose VALUE carries a nested lift of its own.
const NESTED_TOP_LEVEL_KEY: &str = "auth";

/// [`NESTED_TOP_LEVEL_KEY`] as the one-element slice the key reader matches forwarded keys against.
const NESTED_WATCH: &[&str] = &[NESTED_TOP_LEVEL_KEY];

/// Everything the pre-pass pulled out of one document.
#[derive(Default)]
pub(crate) struct Lifted {
    mcp: Option<McpEndpointSection>, // plane-purity: frozen-wire the frozen carrier field + its snapshot TYPE
    oauth_as: Option<Option<crate::oauth_as::config::OauthAsCfg>>,
    tools: Option<ToolsSection>,
    agents: Option<AgentsSection>,
    streams: Option<StreamsSection>,
    auth_policy: Option<crate::config::AuthPolicyCfg>,
}

impl Lifted {
    /// Install what was lifted onto the freshly parsed frozen struct. Absent keys leave the
    /// carrier at its `Default`, which is exactly what an omitted section means.
    fn install(self, deploy: &mut DeployCfg) {
        // plane-purity: frozen-wire reads the frozen carrier slot
        if let Some(v) = self.mcp {
            // plane-purity: frozen-wire writes the frozen carrier field
            deploy.mcp = v;
        }
        if let Some(v) = self.oauth_as {
            deploy.oauth_as = v;
        }
        if let Some(v) = self.tools {
            deploy.tools = v;
        }
        if let Some(v) = self.agents {
            deploy.agents = v;
        }
        if let Some(v) = self.streams {
            deploy.streams = v;
        }
        if let Some(v) = self.auth_policy {
            // A policy block without an `auth:` block cannot happen: `policy:` is lifted from
            // INSIDE `auth:`, so reaching here means `auth:` parsed.
            if let Some(auth) = deploy.auth.as_mut() {
                auth.policy = v;
            }
        }
    }
}

/// One lifted key's parsed value. Deserializing straight into the destination type (rather than
/// into a generic value that is re-parsed afterwards) is what keeps a malformed 1.6.0 section's
/// error message positioned and path-prefixed exactly like every other section's.
enum LiftedValue {
    Mcp(McpEndpointSection), // plane-purity: frozen-wire the frozen carrier TYPE for one lifted key
    OauthAs(Option<crate::oauth_as::config::OauthAsCfg>),
    Tools(ToolsSection),
    Agents(AgentsSection),
    Streams(StreamsSection),
    AuthPolicy(crate::config::AuthPolicyCfg),
}

impl LiftedValue {
    fn store(self, into: &mut Lifted) {
        match self {
            LiftedValue::Mcp(v) => into.mcp = Some(v), // plane-purity: frozen-wire banks the frozen carrier value
            LiftedValue::OauthAs(v) => into.oauth_as = Some(v),
            LiftedValue::Tools(v) => into.tools = Some(v),
            LiftedValue::Agents(v) => into.agents = Some(v),
            LiftedValue::Streams(v) => into.streams = Some(v),
            LiftedValue::AuthPolicy(v) => into.auth_policy = Some(v),
        }
    }
}

/// Deserialize the value of one lifted key into its own type, chosen by the key.
struct LiftedSeed(&'static str);

impl<'de> DeserializeSeed<'de> for LiftedSeed {
    type Value = LiftedValue;

    fn deserialize<D: Deserializer<'de>>(self, de: D) -> Result<Self::Value, D::Error> {
        Ok(match self.0 {
            // plane-purity: frozen-wire routes the frozen wire KEY to its frozen carrier TYPE
            "mcp" => LiftedValue::Mcp(McpEndpointSection::deserialize(de)?),
            "oauth_as" => LiftedValue::OauthAs(Option::deserialize(de)?),
            "tools" => LiftedValue::Tools(ToolsSection::deserialize(de)?),
            "agents" => LiftedValue::Agents(AgentsSection::deserialize(de)?),
            "streams" => LiftedValue::Streams(StreamsSection::deserialize(de)?),
            "policy" => LiftedValue::AuthPolicy(crate::config::AuthPolicyCfg::deserialize(de)?),
            other => {
                // Unreachable while the two key lists and this match agree; a hard error rather
                // than a silent drop so they cannot drift apart unnoticed.
                return Err(D::Error::custom(format!(
                    "internal: no lift destination for the key `{other}`"
                )));
            }
        })
    }
}

/// What reading one map key produced: a key for the frozen struct, or a key this pass lifts (in
/// which case the untouched seed comes back, so the caller can read the next key with it).
enum KeyOutcome<V, S> {
    Forward(V),
    Lift(S),
}

/// Reads one map key: lifted keys are reported without ever reaching `inner`, so the frozen
/// struct's field matcher — and therefore its `expected one of` list — never sees them.
struct KeySeed<'a, S> {
    inner: S,
    lift: &'static [&'static str],
    watch: &'static [&'static str],
    /// Set to the matched entry of `lift` when the key is lifted.
    lifted: &'a mut Option<&'static str>,
    /// Set to the matched entry of `watch` when a FORWARDED key is one whose value needs a
    /// nested pass of its own.
    watched: &'a mut Option<&'static str>,
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
        // The same wording serde's derived key matcher uses, so a non-string key produces the
        // message it always did.
        f.write_str("field identifier")
    }

    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
        if let Some(k) = self.lift.iter().find(|k| **k == v) {
            *self.lifted = Some(k);
            return Ok(KeyOutcome::Lift(self.inner));
        }
        *self.watched = self.watch.iter().find(|k| **k == v).copied();
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

/// A `MapAccess` that hides the lifted keys from whoever it is handed to, banking their values in
/// [`Lifted`] on the way past.
struct LiftingMap<'a, M> {
    inner: M,
    lift: &'static [&'static str],
    /// A forwarded key whose VALUE gets its own nested lift (`auth:`), and the keys to lift there.
    nested: Option<(&'static str, &'static [&'static str])>,
    /// Set when the key just forwarded is the `nested` one, so the value read can be wrapped.
    pending_nested: bool,
    lifted: &'a mut Lifted,
}

impl<'de, M: MapAccess<'de>> MapAccess<'de> for LiftingMap<'_, M> {
    type Error = M::Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Self::Error> {
        let watch: &'static [&'static str] = match self.nested {
            Some(_) => NESTED_WATCH,
            None => &[],
        };
        let mut seed = seed;
        loop {
            let mut lifted = None;
            let mut watched = None;
            let outcome = self.inner.next_key_seed(KeySeed {
                inner: seed,
                lift: self.lift,
                watch,
                lifted: &mut lifted,
                watched: &mut watched,
            })?;
            match outcome {
                None => return Ok(None),
                Some(KeyOutcome::Forward(v)) => {
                    self.pending_nested = watched.is_some();
                    return Ok(Some(v));
                }
                Some(KeyOutcome::Lift(returned)) => {
                    let key = lifted.expect("a lifted key always names itself");
                    self.inner
                        .next_value_seed(LiftedSeed(key))?
                        .store(self.lifted);
                    seed = returned;
                }
            }
        }
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(
        &mut self,
        seed: V,
    ) -> Result<V::Value, Self::Error> {
        match (self.pending_nested, self.nested) {
            (true, Some((_, keys))) => self.inner.next_value_seed(NestedSeed {
                inner: seed,
                lift: keys,
                lifted: self.lifted,
            }),
            _ => self.inner.next_value_seed(seed),
        }
    }

    fn size_hint(&self) -> Option<usize> {
        self.inner.size_hint()
    }
}

/// Runs a nested lift over the value of one forwarded key (`auth:`), then hands the remainder to
/// the frozen struct that key belongs to.
struct NestedSeed<'a, S> {
    inner: S,
    lift: &'static [&'static str],
    lifted: &'a mut Lifted,
}

impl<'de, S: DeserializeSeed<'de>> DeserializeSeed<'de> for NestedSeed<'_, S> {
    type Value = S::Value;

    fn deserialize<D: Deserializer<'de>>(self, de: D) -> Result<Self::Value, D::Error> {
        de.deserialize_any(self)
    }
}

impl<'de, S: DeserializeSeed<'de>> Visitor<'de> for NestedSeed<'_, S> {
    type Value = S::Value;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a configuration section")
    }

    fn visit_map<M: MapAccess<'de>>(self, map: M) -> Result<Self::Value, M::Error> {
        self.inner.deserialize(OptionalMap(LiftingMap {
            inner: map,
            lift: self.lift,
            nested: None,
            pending_nested: false,
            lifted: self.lifted,
        }))
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        self.inner
            .deserialize(serde::de::value::UnitDeserializer::new())
    }

    fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        self.visit_unit()
    }

    fn visit_some<D: Deserializer<'de>>(self, de: D) -> Result<Self::Value, D::Error> {
        de.deserialize_any(self)
    }
}

/// [`MapAccessDeserializer`] forwards `deserialize_option` to `deserialize_any`, which hands a map
/// to an `Option` visitor and errors. The lifted-from sections are declared `Option<…>`, so the
/// map has to answer "some" for itself first.
struct OptionalMap<M>(M);

impl<'de, M: MapAccess<'de>> Deserializer<'de> for OptionalMap<M> {
    type Error = M::Error;

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        visitor.visit_some(self)
    }

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        MapAccessDeserializer::new(self.0).deserialize_any(visitor)
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        MapAccessDeserializer::new(self.0).deserialize_enum(name, variants, visitor)
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf unit unit_struct newtype_struct seq tuple tuple_struct
        map struct identifier ignored_any
    }
}

/// The whole document: the frozen struct plus whatever the pre-pass lifted off it.
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
        let mut lifted = Lifted::default();
        let mut deploy = DeployCfg::deserialize(MapAccessDeserializer::new(LiftingMap {
            inner: map,
            lift: LIFTED_TOP_LEVEL_KEYS,
            nested: Some((NESTED_TOP_LEVEL_KEY, LIFTED_AUTH_KEYS)),
            pending_nested: false,
            lifted: &mut lifted,
        }))?;
        lifted.install(&mut deploy);
        Ok(SplitDocument(deploy))
    }
}

/// Parse a configuration document: the 1.6.0-additive keys are lifted off it first, and the
/// remainder is parsed by the frozen 1.5.5-shaped structs.
///
/// THE entry point for turning config text into a [`DeployCfg`]. A bare
/// `serde_yaml::from_str::<DeployCfg>` skips the lift and leaves every plane section at its
/// default, so it is only ever right for a document that has none.
pub fn deploy_from_yaml_str(text: &str) -> Result<DeployCfg, serde_yaml::Error> {
    deploy_from_deserializer(serde_yaml::Deserializer::from_str(text))
}

/// The format-agnostic form of [`deploy_from_yaml_str`] — the lift is a property of the DOCUMENT,
/// not of YAML, so the JSON-shaped paths (an admin config document) get it too.
pub fn deploy_from_deserializer<'de, D: Deserializer<'de>>(de: D) -> Result<DeployCfg, D::Error> {
    SplitDocument::deserialize(de).map(|d| d.0)
}

/// The [`serde_yaml::Value`] twin of [`deploy_from_yaml_str`], for the paths that have already
/// built a document in memory (the admin overlay merge). Source positions are gone by then, so no
/// error can carry one — the text entry point above is the one boot uses.
pub fn deploy_from_yaml_value(value: serde_yaml::Value) -> Result<DeployCfg, serde_yaml::Error> {
    deploy_from_deserializer(value)
}
