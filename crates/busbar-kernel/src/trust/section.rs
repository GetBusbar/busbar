// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::BTreeMap;

use busbar_contract::plane::{TrustKeyDecl, TrustRole};

use super::reverify::Policy;

/// A registration's declared pin, as the kernel read it. Kept with every operator decision
/// ([`super::book::RulingRow::declared`]), so a decision replays only over the declaration it was
/// made under.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
    /// The fingerprint the operator declared, where the declaration allows one and the operator
    /// wrote it. Intent, never an approval: the counterparty stays pending, and nothing drifts,
    /// until the operator approves it.
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

impl TrustEntry {
    #[must_use]
    pub fn rootless(&self) -> bool {
        self.pin
            .as_ref()
            .is_some_and(|p| !p.root && p.fingerprint.is_none())
    }
}

pub fn parse_entry(
    at: &str,
    entry: &serde_yaml::Value,
    keys: &[TrustKeyDecl],
) -> Result<TrustEntry, String> {
    read_entry(at, entry, keys, true)
}

pub fn judge_entry(
    at: &str,
    entry: &serde_yaml::Value,
    keys: &[TrustKeyDecl],
) -> Result<(), String> {
    read_entry(at, entry, keys, false).map(|_| ())
}

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

            TrustRole::PrivateReach => {
                if value.is_some_and(|v| v.as_bool().is_none()) {
                    let k = decl.key;
                    shape::<()>(strict, format!("{at}: `{k}:` must be true or false"))?;
                }
            }
            TrustRole::ItemApprovals => out.approved = item_approvals(decl, value),
        }
    }

    if out.rootless() {
        out.approved.clear();
    }
    Ok(out)
}

#[must_use]
pub fn private_reach(entry: &serde_yaml::Value, keys: &[TrustKeyDecl]) -> bool {
    keys.iter()
        .filter(|k| k.role == TrustRole::PrivateReach)
        .filter_map(|k| entry.as_mapping()?.get(k.key)?.as_bool())
        .any(|b| b)
}

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

fn shape<T>(strict: bool, refusal: String) -> Result<Option<T>, String> {
    if strict {
        Err(refusal)
    } else {
        Ok(None)
    }
}

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
                && *k != busbar_contract::section::RESERVED_POOLS_KEY
        })
}

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
