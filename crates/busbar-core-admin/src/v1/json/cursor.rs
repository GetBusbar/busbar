// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The one pagination parameter (ADMIN-API-1.6 section 7.1).
//!
//! A cursor is `k1.<op>.<filter-digest>.<last-sort-key>`: opaque to clients, resuming STRICTLY AFTER
//! the last key served, so a row deleted or added between pages can neither be skipped nor repeated.
//! It is bound to the operation and to the filters that produced it; used anywhere else it is 400
//! `cursor_mismatch`. The legacy `o:` offset cursor is gone: it is `malformed_cursor`.

use std::collections::HashMap;

use axum::response::Response;

use crate::v1::contract::taxonomy::Cond;
use crate::v1::contract::{AdminError, Page, LIST_LIMIT_MAX};

use super::err_json_cond;

const VERSION: &str = "k1";

/// A parsed page request: resume strictly after `after`, return at most `limit` rows.
pub(crate) struct Window {
    pub(crate) after: Option<String>,
    pub(crate) limit: usize,
}

/// FNV-1a over the filter text: binds a cursor to its filters. Not a security digest.
fn fnv(text: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in text.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// The digest of the named filter parameters present in `q`, in name order.
pub(crate) fn filter_digest(q: &HashMap<String, String>, names: &[&str]) -> String {
    let mut sorted: Vec<&str> = names.to_vec();
    sorted.sort_unstable();
    let mut text = String::new();
    for name in sorted {
        if let Some(value) = q.get(name) {
            text.push_str(name);
            text.push('=');
            text.push_str(value);
            text.push('\n');
        }
    }
    format!("{:016x}", fnv(&text))
}

/// The digest of every query pair that is not paging (`limit`, `cursor`), repeats included.
pub(crate) fn filter_digest_of_pairs(pairs: &[(String, String)]) -> String {
    let mut kept: Vec<String> = pairs
        .iter()
        .filter(|(name, _)| name != "limit" && name != "cursor")
        .map(|(name, value)| format!("{name}={value}\n"))
        .collect();
    kept.sort_unstable();
    format!("{:016x}", fnv(&kept.concat()))
}

/// The zero-padded sort key of a number, so keys compare as strings in numeric order.
pub(crate) fn numeric_key(n: u64) -> String {
    format!("{n:020}")
}

pub(crate) fn encode(op: &str, filter: &str, last_key: &str) -> String {
    format!("{VERSION}.{op}.{filter}.{}", hex::encode(last_key))
}

fn decode(raw: &str) -> Option<(&str, &str, String)> {
    let mut parts = raw.splitn(4, '.');
    if parts.next()? != VERSION {
        return None;
    }
    let op = parts.next().filter(|s| !s.is_empty())?;
    let filter = parts.next().filter(|s| !s.is_empty())?;
    let key = String::from_utf8(hex::decode(parts.next()?).ok()?).ok()?;
    Some((op, filter, key))
}

fn mismatch() -> Response {
    busbar_kernel::admin::gate::admin_error_envelope_with(
        400,
        "invalid_request",
        Some("cursor_mismatch"),
        "this `cursor` was issued for another operation or another set of filters",
        &serde_json::json!({}),
    )
}

/// `410 cursor_expired`: the cursor is below what is still held; `oldest_available` is a cursor
/// that starts at the oldest retained row.
pub(crate) fn expired(oldest_available: String) -> Response {
    busbar_kernel::admin::gate::admin_error_envelope_with(
        410,
        "invalid_request",
        Some("cursor_expired"),
        "this `cursor` is older than the rows still held; restart from `oldest_available`",
        &serde_json::json!({ "oldest_available": oldest_available }),
    )
}

/// Parses `cursor` and `limit` for operation `op` under the filter digest `filter`.
pub(crate) fn window(
    q: &HashMap<String, String>,
    op: &str,
    filter: &str,
    default_limit: usize,
) -> Result<Window, Box<Response>> {
    let limit = q
        .get("limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(default_limit)
        .clamp(1, LIST_LIMIT_MAX);
    let after = match q.get("cursor") {
        None => None,
        Some(raw) => match decode(raw) {
            None => {
                return Err(Box::new(err_json_cond(
                    &AdminError::Validation("invalid pagination cursor".into()),
                    Cond::MalformedCursor,
                )))
            }
            Some((cursor_op, cursor_filter, key)) => {
                if cursor_op != op || cursor_filter != filter {
                    return Err(Box::new(mismatch()));
                }
                Some(key)
            }
        },
    };
    Ok(Window { after, limit })
}

/// One keyset page of `items`, served in ascending `key` order (descending when `descending`). Rows at or before the cursor are dropped, so a row deleted
/// between pages cannot make the next page skip or repeat another. `next_cursor` is null at the end.
pub(crate) fn keyset<T>(
    mut items: Vec<T>,
    w: &Window,
    op: &str,
    filter: &str,
    key: impl Fn(&T) -> String,
    descending: bool,
) -> Page<T> {
    items.sort_by_cached_key(|item| key(item));
    if descending {
        items.reverse();
    }
    let mut rest: Vec<T> = items
        .into_iter()
        .filter(|item| match &w.after {
            None => true,
            Some(after) if descending => key(item).as_str() < after.as_str(),
            Some(after) => key(item).as_str() > after.as_str(),
        })
        .collect();
    let more = rest.len() > w.limit;
    rest.truncate(w.limit);
    let next_cursor = if more {
        rest.last().map(|item| encode(op, filter, &key(item)))
    } else {
        None
    };
    Page {
        items: rest,
        next_cursor,
    }
}

/// A service list (`Page::single`) cut to its keyset page for `w`.
pub(crate) fn paged<T>(
    listed: Result<Page<T>, AdminError>,
    w: &Window,
    op: &str,
    key: impl Fn(&T) -> String,
) -> Result<Page<T>, AdminError> {
    listed.map(|page| keyset(page.items, w, op, "", key, false))
}

#[cfg(test)]
#[path = "tests/cursor_tests.rs"]
mod tests;
