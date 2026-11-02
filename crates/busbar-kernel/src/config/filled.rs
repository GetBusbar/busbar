// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::hash_map::RandomState;
use std::collections::HashMap;
use std::hash::BuildHasher;
use std::sync::{LazyLock, RwLock};

/// One step of a document path: a mapping key, or a sequence index.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Seg {
    Key(String),
    Index(usize),
}

/// What filled one scalar position.
#[derive(Clone, Debug)]
struct Fill {
    /// The variables, in source order (one, when `whole`).
    vars: Vec<String>,
    /// `${VAR}` was the whole scalar.
    whole: bool,
    /// The scalar as written, each `${VAR}` in place (config text: no secret byte).
    written: String,
    /// The keyed digest of the scalar's value as JSON renders it.
    digest: u64,
}

struct Ledger {
    keys: RandomState,
    at: HashMap<Vec<Seg>, Vec<Fill>>,
}

static LEDGER: LazyLock<RwLock<Ledger>> = LazyLock::new(|| {
    RwLock::new(Ledger {
        keys: RandomState::new(),
        at: HashMap::new(),
    })
});

const MAX_DEPTH: usize = 128;

fn scalar_text(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        serde_json::Value::Null => Some(String::new()),
        _ => None,
    }
}

fn key_of(k: &serde_yaml::Value) -> Option<String> {
    match k {
        serde_yaml::Value::String(s) => Some(s.clone()),
        serde_yaml::Value::Number(n) => Some(n.to_string()),
        serde_yaml::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn placeholders_in(s: &str, placeholder_of: &dyn Fn(usize) -> String, count: usize) -> Vec<usize> {
    let mut found: Vec<(usize, usize)> = (0..count)
        .filter_map(|i| s.find(&placeholder_of(i)).map(|at| (at, i)))
        .collect();
    found.sort_unstable();
    found.into_iter().map(|(_, i)| i).collect()
}

pub(super) fn record(
    real: &serde_yaml::Value,
    shape: &serde_yaml::Value,
    vars: &[&str],
    placeholder_of: &dyn Fn(usize) -> String,
) {
    let mut found: Vec<(Vec<Seg>, Fill)> = Vec::new();
    let mut path = Vec::new();
    let mut ledger = LEDGER
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let keys = ledger.keys.clone();
    walk_record(real, shape, &mut path, 0, &mut |path, real, s| {
        let hits = placeholders_in(s, placeholder_of, vars.len());
        if hits.is_empty() {
            return;
        }
        let whole = hits.len() == 1 && s == placeholder_of(hits[0]);
        let written = hits.iter().fold(s.to_string(), |text, &i| {
            text.replace(&placeholder_of(i), &format!("${{{}}}", vars[i]))
        });
        let Some(text) = serde_json::to_value(real)
            .ok()
            .as_ref()
            .and_then(scalar_text)
        else {
            return;
        };
        found.push((
            path.to_vec(),
            Fill {
                vars: hits.iter().map(|&i| vars[i].to_string()).collect(),
                whole,
                written,
                digest: keys.hash_one(text.as_str()),
            },
        ));
    });
    for (path, fill) in found {
        let fills = ledger.at.entry(path).or_default();
        if !fills
            .iter()
            .any(|f| f.digest == fill.digest && f.vars == fill.vars)
        {
            fills.push(fill);
        }
    }
}

fn walk_record(
    real: &serde_yaml::Value,
    shape: &serde_yaml::Value,
    path: &mut Vec<Seg>,
    depth: usize,
    on_scalar: &mut dyn FnMut(&[Seg], &serde_yaml::Value, &str),
) {
    use serde_yaml::Value;
    if depth > MAX_DEPTH {
        return;
    }
    match (real, shape) {
        (Value::Mapping(r), Value::Mapping(s)) => {
            for (k, sv) in s {
                let (Some(rv), Some(name)) = (r.get(k), key_of(k)) else {
                    continue;
                };
                path.push(Seg::Key(name));
                walk_record(rv, sv, path, depth + 1, on_scalar);
                path.pop();
            }
        }
        (Value::Sequence(r), Value::Sequence(s)) => {
            for (i, (rv, sv)) in r.iter().zip(s).enumerate() {
                path.push(Seg::Index(i));
                walk_record(rv, sv, path, depth + 1, on_scalar);
                path.pop();
            }
        }
        (Value::Tagged(r), Value::Tagged(s)) => {
            walk_record(&r.value, &s.value, path, depth + 1, on_scalar);
        }
        (r, Value::String(s)) => on_scalar(path, r, s),
        _ => {}
    }
}

const CREDENTIAL_KEYS: &[&str] = &[
    "api_key",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "client_secret",
    "subject_token",
    "secret",
    "password",
    "passphrase",
    "private_key",
    "authorization",
    "bearer",
];

const CREDENTIAL_MAPS: &[&str] = &[busbar_contract::conn::PROGRAM_KEYS[2]];

const CREDENTIAL_BLOCK: &str = "upstream_credentials";

fn is_credential(path: &[Seg]) -> bool {
    fn key(s: &Seg) -> Option<&str> {
        match s {
            Seg::Key(k) => Some(k.as_str()),
            Seg::Index(_) => None,
        }
    }
    if path
        .iter()
        .filter_map(key)
        .any(|k| k.eq_ignore_ascii_case(CREDENTIAL_BLOCK))
    {
        return true;
    }
    let leaf = path.last().and_then(key);
    if leaf.is_some_and(|k| CREDENTIAL_KEYS.iter().any(|c| k.eq_ignore_ascii_case(c))) {
        return true;
    }
    path.len() >= 2
        && leaf.is_some()
        && key(&path[path.len() - 2])
            .is_some_and(|m| CREDENTIAL_MAPS.iter().any(|c| m.eq_ignore_ascii_case(c)))
}

fn reference_to(fill: &Fill) -> serde_json::Value {
    let reference = if fill.whole {
        busbar_contract::secret_ref::SecretRef::env(&fill.vars[0])
    } else {
        busbar_contract::secret_ref::SecretRef::template(&fill.written)
    };
    if let Some(var) = reference.env_var() {
        let mut m = serde_json::Map::new();
        m.insert(
            busbar_contract::secret_ref::SECRET_MODULE_ENV.to_string(),
            serde_json::Value::String(var.to_string()),
        );
        return serde_json::Value::Object(m);
    }
    serde_json::to_value(&reference).unwrap_or(serde_json::Value::Null)
}

#[must_use]
pub fn plane_bound(prefix: &[&str], value: serde_json::Value) -> serde_json::Value {
    let ledger = LEDGER
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if ledger.at.is_empty() {
        return value;
    }
    let mut path: Vec<Seg> = prefix.iter().map(|k| Seg::Key((*k).to_string())).collect();
    let mut value = value;
    project(&ledger, &mut path, &mut value, 0);
    value
}

pub fn plane_bound_bytes(prefix: &[&str], value: &serde_yaml::Value) -> Result<Vec<u8>, String> {
    if value.is_null() {
        return Ok(Vec::new());
    }
    let json = serde_json::to_value(value)
        .map_err(|e| format!("the section is not representable as JSON: {e}"))?;
    serde_json::to_vec(&plane_bound(prefix, json))
        .map_err(|e| format!("the section is not representable as JSON: {e}"))
}

fn project(ledger: &Ledger, path: &mut Vec<Seg>, v: &mut serde_json::Value, depth: usize) {
    if depth > MAX_DEPTH {
        return;
    }
    match v {
        serde_json::Value::Object(m) => {
            for (k, inner) in m.iter_mut() {
                path.push(Seg::Key(k.clone()));
                project(ledger, path, inner, depth + 1);
                path.pop();
            }
        }
        serde_json::Value::Array(a) => {
            for (i, inner) in a.iter_mut().enumerate() {
                path.push(Seg::Index(i));
                project(ledger, path, inner, depth + 1);
                path.pop();
            }
        }
        scalar => {
            if !is_credential(path) {
                return;
            }
            let Some(fills) = ledger.at.get(path.as_slice()) else {
                return;
            };
            let Some(text) = scalar_text(scalar) else {
                return;
            };
            let digest = ledger.keys.hash_one(text.as_str());
            if let Some(fill) = fills.iter().find(|f| f.digest == digest) {
                *scalar = reference_to(fill);
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/filled_tests.rs"]
mod tests;
