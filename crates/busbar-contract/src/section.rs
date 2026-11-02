// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SECTION-MAP SPLIT a plane's top-level config section is read by: a pure, stateless helper.

use serde::Deserialize as _;

/// THE TWO WORDS RESERVED AT EVERY PLANE SECTION'S TOP LEVEL: the all-plane `hooks:` attach list and
pub const RESERVED_SECTION_KEYS: &[&str] = &["hooks", UPSTREAM_CREDENTIALS_KEY];

/// The reserved `upstream_credentials:` word: how a member is credentialed (`own` or
pub const UPSTREAM_CREDENTIALS_KEY: &str = "upstream_credentials";

/// A registration's RFC 8693 `token_exchange:` block: busbar's
pub const TOKEN_EXCHANGE_KEY: &str = "token_exchange";

/// Inside [`TOKEN_EXCHANGE_KEY`]: the authorization server's token endpoint.
pub const TOKEN_URL_KEY: &str = "token_url";

/// Inside [`TOKEN_EXCHANGE_KEY`]: busbar's own subject token, a secret reference.
pub const SUBJECT_TOKEN_KEY: &str = "subject_token";

/// Inside [`TOKEN_EXCHANGE_KEY`]: RFC 8693 section 2.1 `subject_token_type`; absent =
pub const SUBJECT_TOKEN_TYPE_KEY: &str = "subject_token_type";

/// The `subject_token_type` a [`TOKEN_EXCHANGE_KEY`] block that states none exchanges: an access
pub const DEFAULT_SUBJECT_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

/// A registration's LEASED OUTBOUND CREDENTIAL block: busbar's own credential for the member,
pub const UPSTREAM_CREDENTIAL_KEY: &str = "upstream_credential";

/// Inside [`UPSTREAM_CREDENTIAL_KEY`]: the credential, a secret reference.
pub const CREDENTIAL_SECRET_KEY: &str = "secret";

/// Inside [`UPSTREAM_CREDENTIAL_KEY`]: where the credential is presented: [`PLACEMENT_BEARER`]
pub const CREDENTIAL_PLACEMENT_KEY: &str = "placement";

/// The [`CREDENTIAL_PLACEMENT_KEY`] word that presents `authorization: Bearer <credential>`.
pub const PLACEMENT_BEARER: &str = "bearer";

/// The [`CREDENTIAL_PLACEMENT_KEY`] object's key naming the header the credential is carried in.
pub const PLACEMENT_HEADER_KEY: &str = "header";

/// Inside [`UPSTREAM_CREDENTIAL_KEY`]: the lease, in milliseconds (greater than zero).
pub const CREDENTIAL_LEASE_TTL_KEY: &str = "lease_ttl_ms";

/// A registration's `aud:`: the RFC 8707 resource indicator its outbound token is audience-bound to.
pub const AUDIENCE_KEY: &str = "aud";

/// THE RESERVED `pools` SUB-KEY of a plane's section (#47, POOLS-VERBS): its named pools, each a list
pub const RESERVED_POOLS_KEY: &str = "pools";

/// The operations a pool may perform twice, inside its [`RESERVED_POOLS_KEY`] entry: an operation
pub const POOL_REPEATABLE_KEY: &str = "repeatable";

/// A pool whose members are each admitted on their OWN grant by the plane (a pool of named
pub const POOL_MEMBER_GRANTED_KEY: &str = "member_granted";

/// THE RESERVED `work` SUB-KEY of a plane's section (POOLS-VERBS, lifted as `pools` is): the bounds
pub const RESERVED_WORK_KEY: &str = "work";

/// The most live work handles one instance holds, inside [`RESERVED_WORK_KEY`].
pub const WORK_MAX_LIVE_KEY: &str = "max_live";

/// How long a settled work handle is retained, in seconds, inside [`RESERVED_WORK_KEY`].
pub const WORK_RETAIN_S_KEY: &str = "retain_s";

/// THE RESERVED PER-ENTRY `timeout:` of any plane's section: an entry's wall-clock bound on ONE attempt to reach it,
pub const ENTRY_TIMEOUT_KEY: &str = "timeout";

/// THE CORE'S DEFAULT [`ENTRY_TIMEOUT_KEY`] OF A TOOL CALL, in milliseconds: the attempt bound of a
pub const DEFAULT_ENTRY_TIMEOUT_MS: u64 = 30_000;

/// THE DECLARING SECTION OF THE PLANE THAT RELAYS TOOL CALLS (`tools:`, one registration per tool
pub const TOOL_CALL_SECTION_KEY: &str = "tools";

/// The core's default attempt bound, in milliseconds, of an entry that writes no
#[must_use]
pub fn default_entry_timeout_ms(declared: &str) -> Option<u64> {
    (declared == TOOL_CALL_SECTION_KEY).then_some(DEFAULT_ENTRY_TIMEOUT_MS)
}

/// [`ENTRY_TIMEOUT_KEY`] as written, in milliseconds: THE ONE READING of the value, the kernel's
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
pub const RESERVED_MODELS_KEY: &str = "models";

/// THE PROVIDER an entry of a [`RESERVED_MODELS_KEY`] map names (#49's uniform schema
pub const MODEL_PROVIDER_KEY: &str = "provider";

/// THE WIRE-PROTOCOL OVERRIDE of a [`RESERVED_MODELS_KEY`] entry, in the order read (#51: the
pub const MODEL_PROTOCOL_KEYS: &[&str] = &["protocol", "dialect"];

/// A pool's member list, inside its [`RESERVED_POOLS_KEY`] entry.
pub const POOL_MEMBERS_KEY: &str = "members";

/// A member written as an object inside a pool's [`POOL_MEMBERS_KEY`] list: the entry it names.
pub const POOL_MEMBER_NAME_KEY: &str = "name";

/// A member's TIER inside a pool's [`POOL_MEMBERS_KEY`] list (`{name, tier}`), the core-owned
pub const POOL_MEMBER_TIER_KEY: &str = "tier";

/// THE MEMBER-TARGET PATH of a need's `target_from` (a door plane's member
pub const MEMBER_TARGET_PREFIX: &str = "settings.*.";

/// The registration key a member-target path names ([`MEMBER_TARGET_PREFIX`]); `None` for any
#[must_use]
pub fn member_target(target_from: &str) -> Option<&str> {
    target_from
        .strip_prefix(MEMBER_TARGET_PREFIX)
        .filter(|key| !key.is_empty() && !key.contains('.'))
}

/// THE MEMBER-PROGRAM PATH of a need's `target_from`: `settings.*`, where `*` stands for EACH registration of the section, names
pub const MEMBER_PROGRAM: &str = "settings.*";

/// Whether `target_from` is the member-program path ([`MEMBER_PROGRAM`]).
#[must_use]
pub fn member_program(target_from: &str) -> bool {
    target_from == MEMBER_PROGRAM
}

/// THE OWNED-SECTION PATH of a need's `trust_from`: `owned.<section>.<key>[...]` names a value in one of the plane's OTHER OWNED
pub const OWNED_PATH_PREFIX: &str = "owned.";

/// The path inside the owned sections an owned-section path names ([`OWNED_PATH_PREFIX`]):
#[must_use]
pub fn owned_path(path: &str) -> Option<&str> {
    path.strip_prefix(OWNED_PATH_PREFIX)
        .filter(|rest| !rest.is_empty() && rest.split('.').all(|segment| !segment.is_empty()))
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

/// THE SENTENCE an operator reads when they name a registration with a reserved word, written once
#[must_use]
pub fn reserved_name_refusal(section: &str, noun: &str, name: &str) -> String {
    if RESERVED_SECTION_KEYS.contains(&name) {
        format!(
            "a {noun} may not be named `{name}`: that key is RESERVED at the \
             `{section}:` section level (the all-{section} `hooks:` attach list and \
             `upstream_credentials:` default). Rename the {noun}."
        )
    } else {
        format!(
            "a {noun} may not be named `{name}`: that key is RESERVED at the \
             `{section}:` section level (the core-owned `{name}:` setting). Rename the {noun}."
        )
    }
}
