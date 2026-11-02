// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! DECLARED SECRET FIELDS: the settings paths a plugin's Statement names in `secret_refs`, as every

use serde_json::Value;
use zeroize::Zeroize;

pub use crate::abi::sdk::cred::SECRET_MARKER;

/// The segment that matches any object key or any array index.
pub const WILDCARD: &str = "*";

/// The single key that says "this object is the plugin's own data, not a reference":
pub const LITERAL_KEY: &str = "literal";

/// Whether the declared `path` has a `*` segment.
#[must_use]
pub fn is_wildcard(path: &str) -> bool {
    path.split('.').any(|s| s == WILDCARD)
}

/// Whether `v` is a secret reference by shape: an object that reads as a
#[must_use]
pub fn is_reference(v: &Value) -> bool {
    v.is_object() && serde_json::from_value::<crate::secret_ref::SecretRef>(v.clone()).is_ok()
}

/// Whether the declared `path` names the position `at` (its segments, an array index in decimal).
#[must_use]
pub fn covers(path: &str, at: &[String]) -> bool {
    let segs: Vec<&str> = path.split('.').collect();
    segs.len() == at.len()
        && segs
            .iter()
            .zip(at)
            .all(|(s, a)| *s == WILDCARD || *s == a.as_str())
}

/// The first position (`.`-joined) in `settings` that holds a secret reference no path in
#[must_use]
pub fn undeclared_reference(settings: &Value, declared: &[String]) -> Option<String> {
    fn walk(v: &Value, at: &mut Vec<String>, declared: &[String]) -> Option<String> {
        if is_reference(v) {
            return (!declared.iter().any(|p| covers(p, at))).then(|| at.join("."));
        }
        match v {
            Value::Object(m) if m.len() == 1 && m.contains_key(LITERAL_KEY) => None,
            Value::Object(m) => m.iter().find_map(|(k, item)| {
                at.push(k.clone());
                let found = walk(item, at, declared);
                at.pop();
                found
            }),
            Value::Array(a) => a.iter().enumerate().find_map(|(i, item)| {
                at.push(i.to_string());
                let found = walk(item, at, declared);
                at.pop();
                found
            }),
            _ => None,
        }
    }
    walk(settings, &mut Vec::new(), declared)
}

/// The refusal for a secret reference at `field` (the operator's path to it) in the settings of
#[must_use]
pub fn undeclared_refusal(field: &str, plugin: &str) -> String {
    format!(
        "{field}: this setting holds a secret reference ({{env:}}, {{file:}} or {{module:}}), but \
         the plugin '{plugin}' did not declare it as a secret, so busbar will not resolve a secret \
         into it; write the value itself here instead (or, if the object is the plugin's own data, \
         wrap it as {{ literal: … }})"
    )
}

/// The first position (`.`-joined) a declared path names, EXACT or WILDCARD, whose value in `tree` is
#[must_use]
pub fn declared_literal(tree: &Value, declared: &[String]) -> Option<String> {
    declared.iter().find_map(|path| {
        let segs: Vec<&str> = path.split('.').collect();
        let mut found = Vec::new();
        named(tree, &segs, &mut Vec::new(), &mut found);
        found
            .into_iter()
            .find(|at| at_mut_ref(tree, at).is_some_and(|v| !v.is_null() && !is_reference(v)))
            .map(|at| at.join("."))
    })
}

/// The refusal for a literal at `field` (the operator's path to it), a position `plugin` declares
#[must_use]
pub fn declared_literal_refusal(field: &str, plugin: &str) -> String {
    format!(
        "{field}: the plugin '{plugin}' declares this setting secret; {}",
        crate::secret_ref::INLINE_LITERAL_REFUSAL
    )
}

/// The first path the reference-capable list `reference` names that the secret list `secret` also
#[must_use]
pub fn contradiction(secret: &[String], reference: &[String]) -> Option<String> {
    reference.iter().find(|p| secret.contains(p)).cloned()
}

/// The refusal for a Statement of `plugin` naming `path` both secret and reference-capable.
#[must_use]
pub fn contradiction_refusal(path: &str, plugin: &str) -> String {
    format!(
        "the plugin '{plugin}' declares the settings path '{path}' both secret and \
         reference-capable (not secret); a field is one or the other, so its Statement is refused"
    )
}

/// Every position (its segments) under `tree` that a `reference` path names, that holds a secret
#[must_use]
pub fn reference_positions(
    tree: &Value,
    secret: &[String],
    reference: &[String],
) -> Vec<Vec<String>> {
    let mut out: Vec<Vec<String>> = Vec::new();
    for path in reference {
        for at in declared_references(tree, path) {
            if !secret.iter().any(|s| covers(s, &at)) && !out.contains(&at) {
                out.push(at);
            }
        }
    }
    out
}

/// RESOLVE the REFERENCE-CAPABLE positions of `tree` in place (lead ruling item 7a): each secret
pub fn resolve_references(
    tree: &mut Value,
    secret: &[String],
    reference: &[String],
    mut resolve: impl FnMut(&str, &crate::secret_ref::SecretRef) -> Result<String, String>,
) -> Result<(), String> {
    for at in reference_positions(tree, secret, reference) {
        let field = at.join(".");
        let Some(slot) = at_mut(tree, &at) else {
            continue;
        };
        let Ok(r) = serde_json::from_value::<crate::secret_ref::SecretRef>(slot.clone()) else {
            continue;
        };
        *slot = Value::String(resolve(&field, &r)?);
    }
    Ok(())
}

/// RESOLVE a plugin's settings `tree` as the kernel does before they cross the ABI: a reference
pub fn resolve_declared(
    tree: &mut Value,
    declared: &[String],
    plugin: &str,
    resolve: impl FnMut(&str, &crate::secret_ref::SecretRef) -> Result<String, String>,
) -> Result<(), String> {
    resolve_declared_fields(tree, declared, &[], plugin, resolve)
}

/// [`resolve_declared`] with the plugin's REFERENCE-CAPABLE, NOT-SECRET paths `reference` beside
pub fn resolve_declared_fields(
    tree: &mut Value,
    declared: &[String],
    reference: &[String],
    plugin: &str,
    mut resolve: impl FnMut(&str, &crate::secret_ref::SecretRef) -> Result<String, String>,
) -> Result<(), String> {
    if let Some(path) = contradiction(declared, reference) {
        return Err(contradiction_refusal(&path, plugin));
    }
    if let Some(at) = undeclared_reference(tree, &[declared, reference].concat()) {
        return Err(undeclared_refusal(&format!("settings.{at}"), plugin));
    }
    if let Some(at) = declared_literal(tree, declared) {
        return Err(declared_literal_refusal(&format!("settings.{at}"), plugin));
    }
    for path in declared {
        for at in declared_references(tree, path) {
            let field = at.join(".");
            let Some(slot) = at_mut(tree, &at) else {
                continue;
            };
            let Ok(r) = serde_json::from_value::<crate::secret_ref::SecretRef>(slot.clone()) else {
                continue;
            };
            *slot = Value::String(resolve(&field, &r)?);
        }
    }
    resolve_references(tree, declared, reference, &mut resolve)
}

/// LEND the declared secrets out of `block` (see the module docs). `keep_exact`: an exact path's
pub fn lend<T: Zeroize, E>(
    block: &mut Value,
    paths: &[String],
    keep_exact: bool,
    mut exact: impl FnMut(&str, Option<Value>) -> Result<T, E>,
    mut wild: impl FnMut(&str, Value) -> Result<T, E>,
) -> Result<Vec<T>, E> {
    let mut out: Vec<T> = Vec::new();
    let mut run = || -> Result<(), E> {
        for path in paths.iter().filter(|p| !is_wildcard(p)) {
            let taken = if keep_exact {
                at_mut(
                    block,
                    &path.split('.').map(str::to_owned).collect::<Vec<_>>(),
                )
                .cloned()
            } else {
                take_path(block, path)
            };
            out.push(exact(path, taken)?);
        }
        for path in paths.iter().filter(|p| is_wildcard(p)) {
            let segs: Vec<&str> = path.split('.').collect();
            let mut found = Vec::new();
            matches(block, &segs, &mut Vec::new(), &mut found);
            for at in found {
                let Some(slot) = at_mut(block, &at) else {
                    continue;
                };
                let marker = serde_json::json!({ SECRET_MARKER: out.len() });
                let value = std::mem::replace(slot, marker);
                out.push(wild(&at.join("."), value)?);
            }
        }
        Ok(())
    };
    match run() {
        Ok(()) => Ok(out),
        Err(e) => {
            out.iter_mut().for_each(Zeroize::zeroize);
            Err(e)
        }
    }
}

/// Every position (its segments) under `v` that the declared `path` names and that holds a secret
#[must_use]
pub fn declared_references(v: &Value, path: &str) -> Vec<Vec<String>> {
    let segs: Vec<&str> = path.split('.').collect();
    let mut found = Vec::new();
    matches(v, &segs, &mut Vec::new(), &mut found);
    found.retain(|at| at_mut_ref(v, at).is_some_and(is_reference));
    found
}

/// The value at the position `at` of `v`, to change it.
pub fn value_at_mut<'v>(v: &'v mut Value, at: &[String]) -> Option<&'v mut Value> {
    at_mut(v, at)
}

fn at_mut_ref<'v>(v: &'v Value, at: &[String]) -> Option<&'v Value> {
    at.iter().try_fold(v, |v, k| match v {
        Value::Object(m) => m.get(k),
        Value::Array(a) => k.parse::<usize>().ok().and_then(|i| a.get(i)),
        _ => None,
    })
}

/// Remove and answer the value at the exact `.`-separated `path` of `v`, if set. An array
fn take_path(v: &mut Value, path: &str) -> Option<Value> {
    let (parent, last) = match path.rsplit_once('.') {
        Some((head, last)) => (
            at_mut(v, &head.split('.').map(str::to_owned).collect::<Vec<_>>())?,
            last,
        ),
        None => (v, path),
    };
    match parent {
        Value::Object(m) => m.remove(last),
        Value::Array(a) => a.get_mut(last.parse::<usize>().ok()?).map(Value::take),
        _ => None,
    }
}

/// Every position under `v` that `segs` names and that holds a string or a reference, in
fn matches(v: &Value, segs: &[&str], at: &mut Vec<String>, out: &mut Vec<Vec<String>>) {
    let mut found = Vec::new();
    named(v, segs, at, &mut found);
    out.extend(found.into_iter().filter(|p| {
        at_mut_ref(v, &p[at.len()..]).is_some_and(|x| x.is_string() || is_reference(x))
    }));
}

/// Every position under `v` that `segs` names, whatever it holds, in document order.
fn named(v: &Value, segs: &[&str], at: &mut Vec<String>, out: &mut Vec<Vec<String>>) {
    let Some((head, rest)) = segs.split_first() else {
        out.push(at.clone());
        return;
    };
    let mut step = |k: String, item: &Value| {
        at.push(k);
        named(item, rest, at, out);
        at.pop();
    };
    match v {
        Value::Object(m) => {
            for (k, item) in m {
                if *head == WILDCARD || *head == k.as_str() {
                    step(k.clone(), item);
                }
            }
        }
        Value::Array(a) => {
            for (i, item) in a.iter().enumerate() {
                let k = i.to_string();
                if *head == WILDCARD || *head == k.as_str() {
                    step(k, item);
                }
            }
        }
        _ => {}
    }
}

/// The value at the position `at` (as [`matches`] answers it).
fn at_mut<'v>(v: &'v mut Value, at: &[String]) -> Option<&'v mut Value> {
    at.iter().try_fold(v, |v, k| match v {
        Value::Object(m) => m.get_mut(k),
        Value::Array(a) => k.parse::<usize>().ok().and_then(|i| a.get_mut(i)),
        _ => None,
    })
}

#[cfg(test)]
#[path = "tests/secret_fields_tests.rs"]
mod tests;
