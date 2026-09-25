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
//!   * the token-mint policy block nested under `auth:`.
//!
//! A plane that is not registered declares nothing, so its section is not lifted: it reaches the
//! frozen struct and is refused with serde's own unknown-field message — exactly what 1.5.5 said
//! for any key it did not know (Option A, S11b (c) / Q67).
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
// Every carrier is lifted through the config seam's plane-NEUTRAL spellings, so this generic lift
// machinery names no concrete plane (DECISIONS #1).
use crate::plane::config::{
    AgentsSection, DecisionsSection, EndpointSection, StreamsSection, ToolsSection,
};
use crate::plane::registry::{PlaneDeclaration, CORE_OWNED_CONCRETE_SECTIONS};

/// HOW `cargo xtask gate config-schema` ties a carrier to its key. The gate reads this from source:
/// a carrier is matched by its field's own name unless it says otherwise.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Declared {
    /// The carrier's field name IS its key (a kernel `LIFTED_*KEYS` key or a plane's declaring
    /// section).
    ByField,
    /// The one section a plane declares BESIDE its declaring section
    /// (`PlaneDeclaration::owned_config_sections`): its endpoint door, read off the declarations.
    Door,
}

/// One lifted key's parse-and-bank step: deserialize the key's value into `Target`, then bank it
/// into the [`Lifted`] buffer. Adding a carrier is implementing this trait for the new carrier type
/// and adding one [`Dest`] arm (and one field to [`Lifted`]) — never widening a value enum.
trait LiftableSection: for<'de> Deserialize<'de> {
    /// How the config-schema gate ties this carrier to its key.
    const KEY: Declared = Declared::ByField;

    /// Bank the parsed value into the buffer that [`Lifted::install`] later applies to the frozen
    /// struct.
    fn bank(self, into: &mut Lifted);
}

impl LiftableSection for EndpointSection {
    const KEY: Declared = Declared::Door;
    fn bank(self, into: &mut Lifted) {
        into.endpoint = Some(self);
    }
}

impl LiftableSection for Option<crate::oauth_as::config::OauthAsCfg> {
    fn bank(self, into: &mut Lifted) {
        into.oauth_as = Some(self);
    }
}

impl LiftableSection for ToolsSection {
    fn bank(self, into: &mut Lifted) {
        into.tools = Some(self);
    }
}

impl LiftableSection for AgentsSection {
    fn bank(self, into: &mut Lifted) {
        into.agents = Some(self);
    }
}

impl LiftableSection for StreamsSection {
    fn bank(self, into: &mut Lifted) {
        into.streams = Some(self);
    }
}

impl LiftableSection for DecisionsSection {
    fn bank(self, into: &mut Lifted) {
        into.decisions = Some(self);
    }
}

impl LiftableSection for crate::config::AuthPolicyCfg {
    fn bank(self, into: &mut Lifted) {
        into.auth_policy = Some(self);
    }
}

/// The KERNEL-OWNED top-level keys that exist only in 1.6.0 and must never reach the frozen
/// top-level struct: busbar AS an OAuth 2.1 authorization server. Every entry is a key the
/// published 1.5.5 binary refuses as unknown, and none may appear in the frozen struct's field set.
///
/// A PLANE's top-level sections are not here: they are read off the registered planes'
/// declarations ([`lift_table`]), so a build without a plane never lifts its section.
pub(crate) const LIFTED_TOP_LEVEL_KEYS: &[&str] = &["oauth_as"];

/// The keys lifted out of the `auth:` block. `policy:` is a 1.6.0 addition (token-mint caps); the
/// five keys around it are 1.5.5's and stay in the frozen struct.
pub(crate) const LIFTED_AUTH_KEYS: &[&str] = &["policy"];

/// The top-level key whose VALUE carries a nested lift of its own.
const NESTED_TOP_LEVEL_KEY: &str = "auth";

/// [`NESTED_TOP_LEVEL_KEY`] as the one-element slice the key reader matches forwarded keys against.
const NESTED_WATCH: &[&str] = &[NESTED_TOP_LEVEL_KEY];

/// Where one lifted key's value lands.
#[derive(Clone, Copy)]
enum Dest {
    Endpoint,
    OauthAs,
    Tools,
    Agents,
    Streams,
    Decisions,
    /// A declaring section no named carrier holds: carried RAW, for its plane to read over the ABI.
    Raw,
    AuthPolicy,
}

impl Dest {
    /// The carrier `key` lands in when `decl` declares it, or `None` (no carrier: left unlifted). A
    /// section declared BESIDE the declaring one is the endpoint door of the plane that owns it; a
    /// declaring section lands in the carrier for that section — the named ones by their section,
    /// the generic singular one by [`DecisionsSection::section`], and any other in the generic RAW
    /// carrier ([`DeployCfg::plane_raw`]) — so every registered plane's declaring section is lifted,
    /// whichever door the plane came in by.
    fn for_declared(decl: &PlaneDeclaration, key: &'static str) -> Option<Dest> {
        if key != decl.config_section {
            // The carrier that states itself the door takes it, for the plane that owns that door.
            let door = (EndpointSection::KEY == Declared::Door).then_some(Dest::Endpoint);
            return door.filter(|_| decl.config_section == EndpointSection::OWNER);
        }
        [
            (ToolsSection::SECTION, Dest::Tools),
            (AgentsSection::SECTION, Dest::Agents),
            (StreamsSection::SECTION, Dest::Streams),
        ]
        .into_iter()
        .find(|(s, _)| *s == key)
        .map(|(_, d)| d)
        .or((DecisionsSection::section() == Some(key)).then_some(Dest::Decisions))
        .or(Some(Dest::Raw))
    }
}

/// THE TOP-LEVEL LIFT TABLE for one document: the kernel's own keys, then every section a
/// REGISTERED plane declares (its declaring section and the sections it owns beside it), minus the
/// sections core still owns concretely (a frozen field, never lifted). First declaration wins.
fn lift_table() -> Vec<(&'static str, Dest)> {
    let mut table: Vec<(&'static str, Dest)> = vec![(LIFTED_TOP_LEVEL_KEYS[0], Dest::OauthAs)];
    for decl in crate::plane::registry::plane_decls() {
        let decl: &PlaneDeclaration = &decl.declaration;
        for &key in std::iter::once(&decl.config_section).chain(decl.owned_config_sections) {
            let fresh = !CORE_OWNED_CONCRETE_SECTIONS.contains(&key)
                && !table.iter().any(|(k, _)| *k == key);
            table.extend(
                Dest::for_declared(decl, key)
                    .filter(|_| fresh)
                    .map(|d| (key, d)),
            );
        }
    }
    table
}

/// The `auth:` block's lift table.
const AUTH_LIFTS: &[(&str, Dest)] = &[(LIFTED_AUTH_KEYS[0], Dest::AuthPolicy)];

/// Everything the pre-pass pulled out of one document.
#[derive(Default)]
pub(crate) struct Lifted {
    endpoint: Option<EndpointSection>,
    oauth_as: Option<Option<crate::oauth_as::config::OauthAsCfg>>,
    tools: Option<ToolsSection>,
    agents: Option<AgentsSection>,
    streams: Option<StreamsSection>,
    decisions: Option<DecisionsSection>,
    auth_policy: Option<crate::config::AuthPolicyCfg>,
    plane_rate_cards: super::PlaneRateCards,
    plane_fees: super::PlaneFeesMap,
    plane_raw: std::collections::BTreeMap<&'static str, serde_yaml::Value>,
}

impl Lifted {
    /// Install what was lifted onto the freshly parsed frozen struct. Absent keys leave the
    /// carrier at its `Default`, which is exactly what an omitted section means.
    fn install(self, deploy: &mut DeployCfg) {
        deploy.plane_rate_cards = self.plane_rate_cards;
        deploy.plane_fees = self.plane_fees;
        deploy.plane_raw = self.plane_raw;
        if let Some(v) = self.endpoint {
            deploy.endpoint = v;
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
        if let Some(v) = self.decisions {
            deploy.decisions = v;
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

/// Deserialize the value of one lifted key straight into its destination type (rather than into a
/// generic value that is re-parsed afterwards) — this is what keeps a malformed 1.6.0 section's
/// error message positioned and path-prefixed exactly like every other section's — then bank it.
///
/// The routing is by [`Dest`], resolved once per key from the lift table; every arm is otherwise
/// identical (`Type::deserialize(de)?.bank(self.lifted)`).
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
            Dest::Endpoint => EndpointSection::deserialize(de)?.bank(lifted),
            Dest::OauthAs => {
                Option::<crate::oauth_as::config::OauthAsCfg>::deserialize(de)?.bank(lifted)
            }
            Dest::Tools => lift_plane::<ToolsSection, D>(key, de, lifted)?,
            Dest::Agents => lift_plane::<AgentsSection, D>(key, de, lifted)?,
            Dest::Streams => lift_plane::<StreamsSection, D>(key, de, lifted)?,
            Dest::Decisions => lift_plane::<DecisionsSection, D>(key, de, lifted)?,
            Dest::Raw => {
                let section = plane_remainder::<D>(key, de, lifted)?;
                lifted.plane_raw.insert(key, section);
            }
            Dest::AuthPolicy => crate::config::AuthPolicyCfg::deserialize(de)?.bank(lifted),
        }
        Ok(())
    }
}

/// **THE CORE-OWNED SUB-KEYS OF A PLANE'S SECTION** (#43, #47): its `rate_card`, and its `fees`.
/// Authored beside the plane's own settings for ergonomics, and LIFTED OFF the section here, before
/// its remainder is handed to the plane — a plane plugin never sees its card or its fees, exactly
/// as it never sees a secret (#40). Each lands under the plane's registry key — the card on
/// [`DeployCfg::plane_rate_cards`], the fees (`{ per_request, per_session }`, #44) on
/// [`DeployCfg::plane_fees`] — and prices that plane's rows alone (#42 "scoped per plane"). The
/// fallback (`pools:`) plane's card and fee are still the flat top-level `rate_card:` and
/// `per_request_fee:`, loaded byte-identically.
const PLANE_CARD_KEYS: [&str; 2] = ["rate_card", "fees"];

/// Lift a plane section: strip its core-owned sub-keys (see [`plane_remainder`]), then parse the
/// REMAINDER through the section's own carrier exactly as before — the plane's parse error reaches
/// the operator through the same `custom` channel it always did.
fn lift_plane<'de, S: LiftableSection, D: Deserializer<'de>>(
    section_key: &'static str,
    de: D,
    lifted: &mut Lifted,
) -> Result<(), D::Error> {
    let section = plane_remainder::<D>(section_key, de, lifted)?;
    S::deserialize(section)
        .map_err(D::Error::custom)?
        .bank(lifted);
    Ok(())
}

/// A plane section with its core-owned sub-keys (see [`PLANE_CARD_KEYS`]) lifted off it and banked
/// under the plane's registry key: the REMAINDER, which is the plane's own.
fn plane_remainder<'de, D: Deserializer<'de>>(
    section_key: &'static str,
    de: D,
    lifted: &mut Lifted,
) -> Result<serde_yaml::Value, D::Error> {
    let [card_key, fees_key] = PLANE_CARD_KEYS;
    let mut section = serde_yaml::Value::deserialize(de)?;
    let plane = crate::plane::registry::plane_decl_for_config_section(section_key)
        .map_or(section_key, |d| d.key);
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
    lift: &'a [(&'static str, Dest)],
    watch: &'static [&'static str],
    /// Set to the matched entry of `lift` when the key is lifted.
    lifted: &'a mut Option<(&'static str, Dest)>,
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
        if let Some(entry) = self.lift.iter().find(|(k, _)| *k == v) {
            *self.lifted = Some(*entry);
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
    lift: &'a [(&'static str, Dest)],
    /// A forwarded key whose VALUE gets its own nested lift (`auth:`), and the keys to lift there.
    nested: Option<(&'static str, &'a [(&'static str, Dest)])>,
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
                    let (key, dest) = lifted.expect("a lifted key always names itself");
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
    lift: &'a [(&'static str, Dest)],
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
        let table = lift_table();
        let mut deploy = DeployCfg::deserialize(MapAccessDeserializer::new(LiftingMap {
            inner: map,
            lift: &table,
            nested: Some((NESTED_TOP_LEVEL_KEY, AUTH_LIFTS)),
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
/// not of YAML, so the JSON-shaped paths (a config document built by the management surface) get
/// it too.
pub fn deploy_from_deserializer<'de, D: Deserializer<'de>>(de: D) -> Result<DeployCfg, D::Error> {
    SplitDocument::deserialize(de).map(|d| d.0)
}

/// The [`serde_yaml::Value`] twin of [`deploy_from_yaml_str`], for the paths that have already
/// built a document in memory (the management-surface overlay merge). Source positions are gone by then, so no
/// error can carry one — the text entry point above is the one boot uses.
pub fn deploy_from_yaml_value(value: serde_yaml::Value) -> Result<DeployCfg, serde_yaml::Error> {
    deploy_from_deserializer(value)
}
