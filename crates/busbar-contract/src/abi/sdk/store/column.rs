// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A RECORD'S FIELDS AS A BACKEND STORES THEM: what the store plugins wrote alike, stated once.

use std::collections::BTreeMap;

use crate::records::{RecordStoreError, RecordStoreResult, ScopeRef};

/// A key's `allowed_scopes` as two columns: `(pool names, every other kind)`.
pub type ScopeColumns = (Option<String>, Option<String>);

/// `scopes` as [`ScopeColumns`]. `None` (the grant omitted: every scope) is two NULLs; `Some` always
#[must_use]
pub fn scope_columns(scopes: Option<&[ScopeRef]>) -> ScopeColumns {
    let Some(list) = scopes else {
        return (None, None);
    };
    let mut pools: Vec<&str> = Vec::new();
    let mut by_kind: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for s in list {
        if s.kind == "pool" {
            pools.push(&s.value);
        } else {
            by_kind.entry(&s.kind).or_default().push(&s.value);
        }
    }
    let pools = serde_json::to_string(&pools).unwrap_or_else(|_| "[]".to_string());
    let by_kind = (!by_kind.is_empty())
        .then(|| serde_json::to_string(&by_kind).unwrap_or_else(|_| "{}".to_string()));
    (Some(pools), by_kind)
}

/// The inverse of [`scope_columns`]: pools first, then every other kind in kind order. Both columns
#[must_use]
pub fn scopes_from_columns(
    pools: Option<String>,
    by_kind: Option<String>,
) -> Option<Vec<ScopeRef>> {
    if pools.is_none() && by_kind.is_none() {
        return None;
    }
    let mut out: Vec<ScopeRef> = pools
        .map(|p| serde_json::from_str::<Vec<String>>(p.trim()).unwrap_or_default())
        .unwrap_or_default()
        .into_iter()
        .map(ScopeRef::pool)
        .collect();
    let by_kind: BTreeMap<String, Vec<String>> = by_kind
        .map(|o| serde_json::from_str(o.trim()).unwrap_or_default())
        .unwrap_or_default();
    for (kind, values) in by_kind {
        out.extend(values.into_iter().map(|value| ScopeRef {
            kind: kind.clone(),
            value,
        }));
    }
    Some(out)
}

/// `v` as a signed 64-bit column holds it.
pub fn storable_i64(method: &str, field: &str, v: u64) -> RecordStoreResult<i64> {
    i64::try_from(v).map_err(|_| {
        RecordStoreError(format!(
            "{method}: {field} {v} exceeds the storable range (i64::MAX); refusing to store a row \
             that would not read back as itself"
        ))
    })
}

/// A counter into a signed 64-bit column: above `i64::MAX` pins to `i64::MAX`, never wraps.
#[must_use]
pub fn clamp(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// A signed 64-bit column read back as a counter: a negative (a corrupt or hand-edited row) reads
#[must_use]
pub fn read_u64(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

/// The smallest key above every key that starts with `prefix`: the last byte that is not `0xff`
#[must_use]
pub fn prefix_end(prefix: &[u8]) -> Option<Vec<u8>> {
    let i = prefix.iter().rposition(|&b| b != u8::MAX)?;
    let mut end = prefix[..=i].to_vec();
    end[i] += 1;
    Some(end)
}

#[cfg(test)]
#[path = "../tests/store_column_tests.rs"]
mod tests;
