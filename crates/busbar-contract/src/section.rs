// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SECTION-MAP SPLIT a plane's top-level config section is read by: a pure, stateless helper.
//!
//! Every plane's named-definition section has one shape: a map whose keys are registrations, except
//! for the two words reserved at the section level on EVERY plane ([`RESERVED_SECTION_KEYS`]),
//! which are lifted out first as the all-plane `hooks:` attach (a LIST, so ADDITIVE) and the
//! all-plane `upstream_credentials:` default (a SCALAR, so OVERRIDE).
//!
//! [`split_section`] owns the ORDER and every SENTENCE, and a plane supplies the only three things
//! that differ: the WORDS for its section (the section key and the noun an operator reads back, both
//! off the plane's own declaration), the TYPE one registration parses into, and its own VALUE RULES.
//!
//! No statics, no I/O and no registry: words and a deserializer in, a split section out. A plane
//! reads its section through this without naming the kernel or another plane.

use serde::Deserialize as _;

/// THE TWO WORDS RESERVED AT EVERY PLANE SECTION'S TOP LEVEL: the all-plane `hooks:` attach list and
/// the `upstream_credentials:` default. Every other key is a registration.
///
/// The one declaration of the pair, so a word cannot come to be reserved on one plane and free on
/// another.
pub const RESERVED_SECTION_KEYS: &[&str] = &["hooks", "upstream_credentials"];

/// THE RESERVED `pools` SUB-KEY of a plane's section (#47, POOLS-VERBS): its named pools, each a list
/// of the section's own entries under `members`. Core-owned: the kernel reads it, the plane never.
pub const RESERVED_POOLS_KEY: &str = "pools";

/// THE RESERVED `work` SUB-KEY of a plane's section (POOLS-VERBS, lifted as `pools` is): the bounds
/// of the plane instance's durable work handles, `{max_live, retain_s}`. Core-owned: the kernel reads
/// it and the plane never sees it.
pub const RESERVED_WORK_KEY: &str = "work";

/// The most live work handles one instance holds, inside [`RESERVED_WORK_KEY`].
pub const WORK_MAX_LIVE_KEY: &str = "max_live";

/// How long a settled work handle is retained, in seconds, inside [`RESERVED_WORK_KEY`].
pub const WORK_RETAIN_S_KEY: &str = "retain_s";

/// THE RESERVED `models` MAP of a model-serving plane's section (the uniform model-serving map,
/// owner config-model ruling 2026-09-19): where present, its keys are the section's entries.
pub const RESERVED_MODELS_KEY: &str = "models";

/// THE PROVIDER an entry of a [`RESERVED_MODELS_KEY`] map names (#49's uniform schema
/// `{ provider, protocol?/dialect?, ... }`): a `providers:` entry, the connection it is reached over.
pub const MODEL_PROVIDER_KEY: &str = "provider";

/// THE WIRE-PROTOCOL OVERRIDE of a [`RESERVED_MODELS_KEY`] entry, in the order read (#51: the
/// model's override if present, else its provider's default protocol).
pub const MODEL_PROTOCOL_KEYS: &[&str] = &["protocol", "dialect"];

/// A pool's member list, inside its [`RESERVED_POOLS_KEY`] entry.
pub const POOL_MEMBERS_KEY: &str = "members";

/// One plane's top-level section, split into its two reserved knobs and its registrations.
///
/// Insertion-ordered, because catalogue construction and every operator-facing listing read it and a
/// hash-ordered listing is a listing that changes between runs for no reason.
#[derive(Debug)]
pub struct Section<T> {
    /// The reserved `<section>.hooks:` all-plane attach list. LIST ⇒ ADDITIVE.
    pub hooks: Vec<String>,
    /// The reserved `<section>.upstream_credentials:` all-plane default. SCALAR ⇒ OVERRIDE.
    pub upstream_credentials: Option<crate::config::UpstreamCreds>,
    /// The registrations — every key that is not one of [`RESERVED_SECTION_KEYS`].
    pub entries: indexmap::IndexMap<String, T>,
}

/// THE SECTION-MAP SPLIT: read one plane's top-level section into its two reserved knobs and its
/// registrations, in the one order every plane is read in.
///
/// `section` / `noun` supply the WORDS for the operator sentences (a plane passes its own
/// declaration's section key and subject noun); `validate` is the plane's VALUE RULES, run on each
/// entry as it is parsed, so the config document and the admin write path refuse the same
/// definitions. A plane
/// with no value rules passes `|_, _| Ok(())`.
///
/// The REFUSAL ORDER is the load-bearing part. A reserved key holding a MAPPING is somebody trying to
/// define a registration by that name, and it is refused BEFORE the typed lifts so the operator reads
/// "that name is reserved" rather than "expected a sequence".
///
/// # Errors
///
/// The deserializer's error carrying the refusal sentence: a reserved word used as a registration
/// name, a malformed reserved knob, a registration that does not parse, or one `validate` refuses.
pub fn split_section<'de, D, T>(
    deserializer: D,
    section: &'static str,
    noun: &'static str,
    validate: impl Fn(&str, &T) -> Result<(), String>,
) -> Result<Section<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    use serde::de::Error as _;

    let mut raw: indexmap::IndexMap<String, serde_yaml::Value> =
        indexmap::IndexMap::deserialize(deserializer)?;

    // BEFORE the typed lifts, for the reason in the doc above.
    for reserved in RESERVED_SECTION_KEYS {
        if raw
            .get(*reserved)
            .is_some_and(|v| matches!(v, serde_yaml::Value::Mapping(_)))
        {
            return Err(D::Error::custom(reserved_name_refusal(
                section, noun, reserved,
            )));
        }
    }

    let hooks: Vec<String> = match raw.shift_remove("hooks") {
        None => Vec::new(),
        Some(v) => Vec::<String>::deserialize(v).map_err(|e| {
            D::Error::custom(format!(
                "the reserved `{section}.hooks:` all-{section} attach must be a list of hook \
                 names: {e}"
            ))
        })?,
    };
    // The sentence is 1.5.5's, to the byte, with the section word substituted in.
    let upstream_credentials = match raw.shift_remove("upstream_credentials") {
        None => None,
        Some(v) => Some(crate::config::UpstreamCreds::deserialize(v).map_err(|e| {
            D::Error::custom(format!(
                "the reserved `{section}.upstream_credentials:` all-{section} default must be \
                 `own` or `passthrough`: {e}"
            ))
        })?),
    };

    let mut entries = indexmap::IndexMap::new();
    for (name, value) in raw {
        // The well-typed spellings are gone; this catches the map-valued "I meant a registration"
        // one with a precise message instead of a type error.
        if RESERVED_SECTION_KEYS.contains(&name.as_str()) {
            return Err(D::Error::custom(reserved_name_refusal(
                section, noun, &name,
            )));
        }
        let def: T = T::deserialize(value).map_err(D::Error::custom)?;
        validate(&name, &def).map_err(D::Error::custom)?;
        entries.insert(name, def);
    }

    Ok(Section {
        hooks,
        upstream_credentials,
        entries,
    })
}

/// THE SENTENCE an operator reads when they name a registration with a reserved section word,
/// written once for every plane and for both spellings that reach it.
///
/// It is 1.5.5's sentence, to the byte, with the section and noun substituted in: a clause 1.5.5 did
/// not carry changes the line a matcher matches, so it stays out.
fn reserved_name_refusal(section: &str, noun: &str, name: &str) -> String {
    format!(
        "a {noun} may not be named `{name}`: that key is RESERVED at the \
         `{section}:` section level (the all-{section} `hooks:` attach list and \
         `upstream_credentials:` default). Rename the {noun}."
    )
}
