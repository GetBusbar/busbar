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
pub const RESERVED_SECTION_KEYS: &[&str] = &["hooks", UPSTREAM_CREDENTIALS_KEY];

/// The reserved `upstream_credentials:` word: how a member is credentialed (`own` or
/// `passthrough`), the section's default and a registration's override.
pub const UPSTREAM_CREDENTIALS_KEY: &str = "upstream_credentials";

/// A registration's RFC 8693 `token_exchange:` block (ARCHITECT round 5 Q-L3B-EXCHANGE (B)): busbar's
/// own subject token is exchanged, per call, for a token down-scoped to the caller's grant and
/// audience-bound to the registration's [`AUDIENCE_KEY`]. Its keys are [`TOKEN_URL_KEY`],
/// [`SUBJECT_TOKEN_KEY`] (a secret reference) and [`SUBJECT_TOKEN_TYPE_KEY`].
pub const TOKEN_EXCHANGE_KEY: &str = "token_exchange";

/// Inside [`TOKEN_EXCHANGE_KEY`]: the authorization server's token endpoint.
pub const TOKEN_URL_KEY: &str = "token_url";

/// Inside [`TOKEN_EXCHANGE_KEY`]: busbar's own subject token, a secret reference.
pub const SUBJECT_TOKEN_KEY: &str = "subject_token";

/// Inside [`TOKEN_EXCHANGE_KEY`]: RFC 8693 section 2.1 `subject_token_type`; absent =
/// [`DEFAULT_SUBJECT_TOKEN_TYPE`].
pub const SUBJECT_TOKEN_TYPE_KEY: &str = "subject_token_type";

/// The `subject_token_type` a [`TOKEN_EXCHANGE_KEY`] block that states none exchanges: an access
/// token, which is what busbar's own ambient credential is.
pub const DEFAULT_SUBJECT_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

/// A registration's `aud:`: the RFC 8707 resource indicator its outbound token is audience-bound to.
pub const AUDIENCE_KEY: &str = "aud";

/// THE RESERVED `pools` SUB-KEY of a plane's section (#47, POOLS-VERBS): its named pools, each a list
/// of the section's own entries under `members`, and the operations it may repeat under
/// [`POOL_REPEATABLE_KEY`]. Core-owned: the kernel walks it; a plane reads it only to name the pool
/// a unit routes over and whether its operation is performed at most once (ARCHITECT round 4
/// Q-L3B-SURFACES (h)).
pub const RESERVED_POOLS_KEY: &str = "pools";

/// The operations a pool may perform twice, inside its [`RESERVED_POOLS_KEY`] entry: an operation
/// not named is never repeated on another member once one answered.
pub const POOL_REPEATABLE_KEY: &str = "repeatable";

/// A pool whose members are each admitted on their OWN grant by the plane (a pool of named
/// definitions, whose members are registrations), inside its [`RESERVED_POOLS_KEY`] entry: `true` =
/// the pool's name is no grant of its own, and naming a pool never widens what a caller reaches.
pub const POOL_MEMBER_GRANTED_KEY: &str = "member_granted";

/// THE RESERVED `work` SUB-KEY of a plane's section (POOLS-VERBS, lifted as `pools` is): the bounds
/// of the plane instance's durable work handles, `{max_live, retain_s}`. Core-owned: the kernel reads
/// it and the plane never sees it.
pub const RESERVED_WORK_KEY: &str = "work";

/// The most live work handles one instance holds, inside [`RESERVED_WORK_KEY`].
pub const WORK_MAX_LIVE_KEY: &str = "max_live";

/// How long a settled work handle is retained, in seconds, inside [`RESERVED_WORK_KEY`].
pub const WORK_RETAIN_S_KEY: &str = "retain_s";

/// THE RESERVED PER-ENTRY `timeout:` of any plane's section (ARCHITECT timeout ruling; R2-G: "PoolSpec
/// carries ... per-member tier and timeout"): an entry's wall-clock bound on ONE attempt to reach it,
/// `<n><s|m|h|d>`. Core-owned: the kernel judges it ([`entry_timeout_ms`]) and holds every attempt
/// its walk makes to that entry's member to it (`Member::attempt_timeout_ms`), for every plane alike;
/// a plane names none of it. An entry that writes none is bounded by its walk's own budget.
pub const ENTRY_TIMEOUT_KEY: &str = "timeout";

/// [`ENTRY_TIMEOUT_KEY`] as written, in milliseconds: THE ONE READING of the value, the kernel's
/// judgement and every reader's. `0` is refused rather than read as "no deadline": a zero budget
/// would refuse every call before it was sent, and there is deliberately no spelling for
/// "unlimited" (an attempt that cannot time out holds a concurrency slot for as long as the far end
/// chooses).
///
/// # Errors
///
/// The sentence after the entry's path: the value does not parse, or it is zero.
pub fn entry_timeout_ms(written: &str) -> Result<u64, String> {
    let secs = crate::duration::parse_duration_secs(written)
        .map_err(|e| format!("`{ENTRY_TIMEOUT_KEY}:` {e}"))?;
    if secs == 0 {
        return Err(format!(
            "`{ENTRY_TIMEOUT_KEY}: {written}` is zero, which would refuse every call to this entry \
             before it was sent. There is no spelling for an unlimited deadline: an attempt that \
             cannot time out holds a concurrency slot for as long as the far end chooses."
        ));
    }
    Ok(secs.saturating_mul(1000))
}

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

/// A member written as an object inside a pool's [`POOL_MEMBERS_KEY`] list: the entry it names.
pub const POOL_MEMBER_NAME_KEY: &str = "name";

/// A member's TIER inside a pool's [`POOL_MEMBERS_KEY`] list (`{name, tier}`), the core-owned
/// per-member `tier` (`BUSBAR-1.6.0.md` l.4196 (b), l.4202; R2-G l.4285): an unsigned integer,
/// the walk taking the lowest tier that can take the request. Core-owned: the kernel reads it and a
/// plane is handed the member's bare name.
pub const POOL_MEMBER_TIER_KEY: &str = "tier";

/// THE MEMBER-TARGET PATH of a need's `target_from` (ARCHITECT Q-L3B-ROUTES: a door plane's member
/// routes come from its own section): `settings.*.<key>`, where `*` stands for EACH registration of
/// the section, names every member's own target — its registration's `<key>` — rather than one
/// target for the instance: that member's URL. Such a need is not pinned at `open`: the composition
/// root seals one route per registration, at its URL's origin, and the plane spells the path of
/// every request it sends that member.
pub const MEMBER_TARGET_PREFIX: &str = "settings.*.";

/// The registration key a member-target path names ([`MEMBER_TARGET_PREFIX`]); `None` for any
/// other path (a single target, or none).
#[must_use]
pub fn member_target(target_from: &str) -> Option<&str> {
    target_from
        .strip_prefix(MEMBER_TARGET_PREFIX)
        .filter(|key| !key.is_empty() && !key.contains('.'))
}

/// THE MEMBER-PROGRAM PATH of a need's `target_from` (ARCHITECT round 5 Q-L3B-STDIO-UPSTREAM (A)):
/// `settings.*`, where `*` stands for EACH registration of the section, names every member's own
/// PROGRAM — the registration's `command`, `args` and `env` ([`crate::conn::Program::of_member`];
/// its other keys are not the program's). A registration that names no `command` is not a member of
/// such a need. The host keeps ONE long-lived program connection per (instance, need, member); an
/// open names the member it reaches.
pub const MEMBER_PROGRAM: &str = "settings.*";

/// Whether `target_from` is the member-program path ([`MEMBER_PROGRAM`]).
#[must_use]
pub fn member_program(target_from: &str) -> bool {
    target_from == MEMBER_PROGRAM
}

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
