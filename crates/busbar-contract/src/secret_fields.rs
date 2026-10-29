// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! DECLARED SECRET FIELDS: the settings paths a plugin's Statement names in `secret_refs`, as every
//! host reads them.
//!
//! A path is `.`-separated. A segment `*` matches any object key or any array index, so
//! `servers.*.env.*` names every environment value of every server. A path with no `*` is EXACT.
//!
//! * **Lending** ([`lend`]). Each exact path's value is taken out of the settings and lent, one
//!   entry per path in the Statement's order (an unset one lends empty bytes), as hosts always
//!   have. Then each wildcard path's matches, in document order, are lent after them: every string
//!   or secret reference it matches is lent and replaced in the settings by the marker
//!   `{"$secret": <index into the lent secrets>}`, which the SDK's
//!   [`crate::abi::sdk::cred::settings_lent`] reads back.
//! * **Policing** ([`undeclared_reference`]). A secret reference (`{env:}`, `{file:}`,
//!   `{module:, settings:}`) at a position no declared path names is refused: the plugin did not
//!   declare the field secret, so the kernel will not resolve a secret into it (OWNER RULING,
//!   CHIP-REVIEW-v4 change 2).

use serde_json::Value;
use zeroize::Zeroize;

pub use crate::abi::sdk::cred::SECRET_MARKER;

/// The segment that matches any object key or any array index.
pub const WILDCARD: &str = "*";

/// The single key that says "this object is the plugin's own data, not a reference":
/// `{ literal: … }` (the kernel unwraps it; nothing under it is a reference).
pub const LITERAL_KEY: &str = "literal";

/// Whether the declared `path` has a `*` segment.
#[must_use]
pub fn is_wildcard(path: &str) -> bool {
    path.split('.').any(|s| s == WILDCARD)
}

/// Whether `v` is a secret reference by shape: an object that reads as a
/// [`crate::secret_ref::SecretRef`].
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
/// `declared` names, or `None`. A `{ literal: … }` object is the plugin's own data and is not
/// looked into.
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
/// `plugin`, which did not declare that field secret.
#[must_use]
pub fn undeclared_refusal(field: &str, plugin: &str) -> String {
    format!(
        "{field}: this setting holds a secret reference ({{env:}}, {{file:}} or {{module:}}), but \
         the plugin '{plugin}' did not declare it as a secret, so busbar will not resolve a secret \
         into it; write the value itself here instead (or, if the object is the plugin's own data, \
         wrap it as {{ literal: … }})"
    )
}

/// RESOLVE a plugin's settings `tree` as the kernel does before they cross the ABI: a reference
/// at a position `declared` does not name is refused ([`undeclared_refusal`], naming `plugin`), and
/// each reference at a declared position, exact or wildcard, is replaced in place by the string
/// `resolve(field, reference)` answers. Everything else is left as written.
///
/// # Errors
/// The refusal, or the first error `resolve` answers.
pub fn resolve_declared(
    tree: &mut Value,
    declared: &[String],
    plugin: &str,
    mut resolve: impl FnMut(&str, &crate::secret_ref::SecretRef) -> Result<String, String>,
) -> Result<(), String> {
    if let Some(at) = undeclared_reference(tree, declared) {
        return Err(undeclared_refusal(&format!("settings.{at}"), plugin));
    }
    for path in declared {
        for at in declared_references(tree, path) {
            let field = at.join(".");
            let Some(slot) = at_mut(tree, &at) else {
                continue;
            };
            let Ok(reference) =
                serde_json::from_value::<crate::secret_ref::SecretRef>(slot.clone())
            else {
                continue;
            };
            *slot = Value::String(resolve(&field, &reference)?);
        }
    }
    Ok(())
}

/// LEND the declared secrets out of `block` (see the module docs). `keep_exact`: an exact path's
/// value stays in the settings (the secret kind's host leaves it), otherwise it is taken out. `exact(path, taken)` turns an
/// exact path's taken-out value (`None` = unset) into its bytes; `wild(at, value)` turns one
/// wildcard match (a string or a reference) at `at` into its bytes. The bytes are the caller's
/// holder `T`: plain `Vec<u8>`, or a host-held `Secret` the resolver wrote into, which moves here
/// and is never copied. On an error every byte lent so far is wiped.
///
/// # Errors
/// The first error a callback answers.
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
/// reference, in document order.
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

/// Remove and answer the value at the exact `.`-separated `path` of `v`, if set.
fn take_path(v: &mut Value, path: &str) -> Option<Value> {
    let (parent, last) = match path.rsplit_once('.') {
        Some((head, last)) => (
            head.split('.').try_fold(&mut *v, |v, k| v.get_mut(k))?,
            last,
        ),
        None => (v, path),
    };
    parent.as_object_mut()?.remove(last)
}

/// Every position under `v` that `segs` names and that holds a string or a reference, in
/// document order.
fn matches(v: &Value, segs: &[&str], at: &mut Vec<String>, out: &mut Vec<Vec<String>>) {
    let Some((head, rest)) = segs.split_first() else {
        if v.is_string() || is_reference(v) {
            out.push(at.clone());
        }
        return;
    };
    let mut step = |k: String, item: &Value| {
        at.push(k);
        matches(item, rest, at, out);
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
