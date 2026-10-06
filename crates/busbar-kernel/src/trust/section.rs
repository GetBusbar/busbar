// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TRUST KEYS A PLANE DECLARES, parsed by the kernel.
//!
//! The trust lifecycle (the pin, the re-verification cadence, demotion) is the kernel's. A plane
//! whose registrations carry a trust root declares WHICH of its per-registration keys hold it
//! ([`busbar_contract::plane::PlaneDeclaration::trust_keys`], the tail's `trust_keys`); the kernel
//! reads those keys here, applies their value rules, and keeps the result per counterparty. The
//! plane's own validator never reads them.
//!
//! The result, one [`TrustEntry`] per registration ([`parse_section`]), is what the `trust.*` host
//! services answer from: a registration's name is the counterparty a `trust.sight` names, its
//! [`TrustEntry::pin`] is the declared root the reported catalogue is judged against, and its
//! [`TrustEntry::policy`] is the cadence `trust.due` marks re-verification by.
//!
//! No instance knowledge: the key names, the mechanism tokens, which mechanism is a root and every
//! default come off the declaration. The sentences are the ones the planes spoke before the keys
//! moved here, with the key and token words substituted in.

use std::collections::BTreeMap;

use busbar_contract::plane::{TrustKeyDecl, TrustRole};

use super::reverify::Policy;

/// A registration's declared pin, as the kernel read it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeclaredPin {
    /// The mechanism token, exactly as written.
    pub mechanism: String,
    /// Whether that mechanism is an authenticity root.
    pub root: bool,
    /// Whether that mechanism's material is the far end's key (a pin of its certificate's
    /// SubjectPublicKeyInfo), which the host seals into the registration's trust anchors.
    pub peer_key: bool,
    /// The operator's out-of-band material, verbatim; `None` when absent or blank.
    pub key: Option<String>,
    /// The approved fingerprint, where the declaration allows one and the operator wrote it.
    pub fingerprint: Option<String>,
}

/// One registration's trust facts: its declared pin (if its plane declares one) and its cadence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustEntry {
    /// The declared pin, or `None` when the plane declares no pin key or the registration wrote none.
    pub pin: Option<DeclaredPin>,
    /// The re-verification cadence, each half from its key, its declared default, or zero.
    pub policy: Policy,
    /// The CONFIGURED ITEM APPROVALS (`abi::plane::TRUST_ITEM_APPROVALS`): each item the
    /// registration approves, at the digest it approves it at. An item written with a blank or
    /// absent digest is allowed but approved at none, and is absent here.
    pub approved: BTreeMap<String, String>,
}

/// Parse and judge one registration's trust keys, in declaration order.
///
/// `at` is the site wording (`` `<section>.<name>` ``); `entry` is the registration as written. A
/// key the declaration names and the registration omits takes its default. An `entry` that is not
/// a mapping carries no trust keys.
///
/// # Errors
///
/// The sentence an operator reads for the first key that breaks its rule, its shape included.
pub fn parse_entry(
    at: &str,
    entry: &serde_yaml::Value,
    keys: &[TrustKeyDecl],
) -> Result<TrustEntry, String> {
    read_entry(at, entry, keys, true)
}

/// Judge one registration's trust-key VALUES, before its plane has parsed it: a root pin with no
/// material, the no-root pin with material, a duration that does not parse. A key whose SHAPE is
/// wrong (a pin that is not an object, an unknown mechanism, a field of the wrong type) is left for
/// the plane's own parse of its section to refuse in its own words, so this pass never preempts it.
///
/// # Errors
///
/// The sentence an operator reads for the first key whose value breaks its rule.
pub fn judge_entry(
    at: &str,
    entry: &serde_yaml::Value,
    keys: &[TrustKeyDecl],
) -> Result<(), String> {
    read_entry(at, entry, keys, false).map(|_| ())
}

/// Both readings: `strict` refuses a malformed shape; otherwise a malformed key reads as absent.
fn read_entry(
    at: &str,
    entry: &serde_yaml::Value,
    keys: &[TrustKeyDecl],
    strict: bool,
) -> Result<TrustEntry, String> {
    let mut out = TrustEntry {
        pin: None,
        policy: Policy {
            ttl_ms: 0,
            recovery_backoff_ms: 0,
        },
        approved: BTreeMap::new(),
    };
    let map = entry.as_mapping();
    for decl in keys {
        // An explicit null is the same as an absent key, as the plane's own optional fields read it.
        let value = map.and_then(|m| m.get(decl.key)).filter(|v| !v.is_null());
        match decl.role {
            TrustRole::Pin => {
                out.pin = match value {
                    Some(v) => pin(at, decl, v, strict)?,
                    None => None,
                };
            }
            TrustRole::ReverifyTtl => out.policy.ttl_ms = duration_ms(at, decl, value, strict)?,
            TrustRole::RecoveryBackoff => {
                out.policy.recovery_backoff_ms = duration_ms(at, decl, value, strict)?;
            }
            // Read by [`private_reach`] where the host seals the registration's anchors; judged
            // here so a malformed value refuses the load in the trust keys' own words.
            TrustRole::PrivateReach => {
                if value.is_some_and(|v| v.as_bool().is_none()) {
                    let k = decl.key;
                    shape::<()>(strict, format!("{at}: `{k}:` must be true or false"))?;
                }
            }
            TrustRole::ItemApprovals => out.approved = item_approvals(decl, value),
        }
    }
    Ok(out)
}

/// The registration's PRIVATE REACH (`abi::plane::TRUST_PRIVATE_REACH`): `true` only where the plane
/// declares the key and the registration writes `true` under it; a malformed value reads as `false`
/// (the load's [`parse_entry`] refuses it first).
#[must_use]
pub fn private_reach(entry: &serde_yaml::Value, keys: &[TrustKeyDecl]) -> bool {
    keys.iter()
        .filter(|k| k.role == TrustRole::PrivateReach)
        .filter_map(|k| entry.as_mapping()?.get(k.key)?.as_bool())
        .any(|b| b)
}

/// The configured item approvals under an item-approvals key: every item whose object carries a
/// non-blank digest (trimmed) under the declared field. The map's SHAPE is the plane's grammar to
/// refuse in its own words; anything that is not an item object reads as no approval here.
fn item_approvals(
    decl: &TrustKeyDecl,
    value: Option<&serde_yaml::Value>,
) -> BTreeMap<String, String> {
    let field = decl.default.unwrap_or_default();
    value
        .and_then(serde_yaml::Value::as_mapping)
        .into_iter()
        .flat_map(|m| m.iter())
        .filter_map(|(item, object)| {
            let digest = object.as_mapping()?.get(field)?.as_str()?.trim();
            if digest.is_empty() {
                return None;
            }
            Some((item.as_str()?.to_string(), digest.to_string()))
        })
        .collect()
}

/// A malformed shape: refused when `strict`, otherwise read as absent.
fn shape<T>(strict: bool, refusal: String) -> Result<Option<T>, String> {
    if strict {
        Err(refusal)
    } else {
        Ok(None)
    }
}

/// Parse every registration of one plane section, in section order, skipping the reserved section
/// words. The map is keyed by registration name: the counterparty the `trust.*` services name.
///
/// # Errors
///
/// The first registration's refusal, worded by [`parse_entry`].
pub fn parse_section(
    section: &str,
    value: &serde_yaml::Value,
    keys: &[TrustKeyDecl],
) -> Result<indexmap::IndexMap<String, TrustEntry>, String> {
    let mut book = indexmap::IndexMap::new();
    for (name, entry) in registrations(value) {
        let parsed = parse_entry(&format!("`{section}.{name}`"), entry, keys)?;
        book.insert(name.to_string(), parsed);
    }
    Ok(book)
}

/// The registrations of a plane section, in order: every string key that is not a reserved section
/// word or the core-owned `work:` bounds.
pub(crate) fn registrations(
    value: &serde_yaml::Value,
) -> impl Iterator<Item = (&str, &serde_yaml::Value)> {
    value
        .as_mapping()
        .into_iter()
        .flat_map(|m| m.iter())
        .filter_map(|(k, v)| k.as_str().map(|k| (k, v)))
        .filter(|(k, _)| {
            !busbar_contract::section::RESERVED_SECTION_KEYS.contains(k)
                && *k != busbar_contract::section::RESERVED_WORK_KEY
        })
}

/// A pin object: its shape, then the rule that makes the object form worth having — a root needs
/// material and the no-root spelling carries none.
fn pin(
    at: &str,
    decl: &TrustKeyDecl,
    value: &serde_yaml::Value,
    strict: bool,
) -> Result<Option<DeclaredPin>, String> {
    let k = decl.key;
    let Some(map) = value.as_mapping() else {
        return shape(
            strict,
            format!("{at}: `{k}:` must be a pin object naming its `mechanism:`"),
        );
    };
    let mut mechanism = None;
    let mut key = None;
    let mut fingerprint = None;
    for (field, v) in map {
        if v.is_null() {
            continue;
        }
        let field = field.as_str().unwrap_or_default();
        let slot = match field {
            "mechanism" => &mut mechanism,
            "key" => &mut key,
            "fingerprint" if decl.fingerprint => &mut fingerprint,
            _ => {
                return shape(
                    strict,
                    format!("{at}: `{k}.{field}:` is not a field of `{k}:`"),
                )
            }
        };
        let Some(text) = v.as_str() else {
            return shape(strict, format!("{at}: `{k}.{field}:` must be a string"));
        };
        *slot = Some(text.to_string());
    }
    let Some(mechanism) = mechanism else {
        return shape(
            strict,
            format!(
                "{at}: `{k}.mechanism:` is required: name the authenticity root this registration \
                 has"
            ),
        );
    };
    let Some(declared) = decl.mechanisms.iter().find(|m| m.token == mechanism) else {
        let known: Vec<String> = decl
            .mechanisms
            .iter()
            .map(|m| format!("`{}`", m.token))
            .collect();
        return shape(
            strict,
            format!(
                "{at}: `{k}.mechanism: {mechanism}` is not one of {}",
                known.join(", ")
            ),
        );
    };
    let has_key = key.as_deref().is_some_and(|m| !m.trim().is_empty());
    if declared.root && !has_key {
        return Err(format!(
            "{at}: `{k}.mechanism: {mechanism}` needs `{k}.key:` — the out-of-band material this \
             registration is verified against. A pin with nothing to verify with is not a pin."
        ));
    }
    if !declared.root && has_key {
        return Err(format!(
            "{at}: `{k}.mechanism: {mechanism}` must not carry `{k}.key:`. `{mechanism}` means \
             there is no authenticity root; key material that is never verified against reads to \
             an operator as protection that does not exist. Name the real mechanism, or drop the \
             key."
        ));
    }
    Ok(Some(DeclaredPin {
        mechanism,
        root: declared.root,
        peer_key: declared.peer_key,
        key: key.filter(|m| !m.trim().is_empty()),
        fingerprint,
    }))
}

/// A `<n><s|m|h|d>` duration key, in milliseconds: as written, else its declared default, else zero.
fn duration_ms(
    at: &str,
    decl: &TrustKeyDecl,
    value: Option<&serde_yaml::Value>,
    strict: bool,
) -> Result<u64, String> {
    let k = decl.key;
    let text = match value {
        Some(v) => match v.as_str() {
            Some(text) => text,
            None => {
                return shape(
                    strict,
                    format!("{at}: `{k}:` must be a duration such as `5s`"),
                )
                .map(|none: Option<u64>| none.unwrap_or(0))
            }
        },
        None => match decl.default {
            Some(d) => d,
            None => return Ok(0),
        },
    };
    busbar_contract::duration::parse_duration_secs(text)
        .map(|secs| secs.saturating_mul(1_000))
        .map_err(|e| format!("{at}: `{k}:` {e}"))
}

#[cfg(test)]
#[path = "tests/section_tests.rs"]
mod section_tests;
