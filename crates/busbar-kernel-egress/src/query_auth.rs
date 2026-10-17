// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE QUERY-PARAMETER AUTH FIELDS ON THE REQUEST TARGET (the auth ABI's
//! [`FIELD_QUERY`](busbar_contract::abi::auth::FIELD_QUERY)): how the host's framer appends them, and
//! how every target the host shows (a log line, an error, a metric label) keeps their values out.
//! Pure; host-side only (a plugin never builds a target), so it lives with the egress seam, not in
//! the contract.

/// Percent-encode `s` outside RFC 3986's unreserved set (`A-Z a-z 0-9 - . _ ~`).
fn encode(s: &str, out: &mut String) {
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push(char::from(b"0123456789ABCDEF"[usize::from(b >> 4)]));
            out.push(char::from(b"0123456789ABCDEF"[usize::from(b & 0xF)]));
        }
    }
}

/// `target` (an origin-form path with an optional query, or an absolute URL) with `params`
/// appended as `name=value` pairs, in order, after any query it already has; a fragment stays last.
/// No params: `target` unchanged.
#[must_use]
pub fn append_query(target: &str, params: &[(&str, &str)]) -> String {
    if params.is_empty() {
        return target.to_string();
    }
    let (head, fragment) = match target.find('#') {
        Some(i) => target.split_at(i),
        None => (target, ""),
    };
    let mut out = String::with_capacity(target.len() + 16 * params.len());
    out.push_str(head);
    let mut sep = if !head.contains('?') {
        '?'
    } else if head.ends_with('?') || head.ends_with('&') {
        '\0'
    } else {
        '&'
    };
    for (name, value) in params {
        if sep != '\0' {
            out.push(sep);
        }
        encode(name, &mut out);
        out.push('=');
        encode(value, &mut out);
        sep = '&';
    }
    out.push_str(fragment);
    out
}

/// The value the host shows in place of a redacted query parameter's.
pub const REDACTED_VALUE: &str = "<redacted>";

/// `target` with the value of every query parameter named in `names` (compared after
/// percent-decoding nothing: the names the plugin wrote, encoded as [`append_query`] encodes them)
/// replaced by [`REDACTED_VALUE`]. Everything else is kept byte for byte.
#[must_use]
pub fn redact_query(target: &str, names: &[&str]) -> String {
    let (head, fragment) = match target.find('#') {
        Some(i) => target.split_at(i),
        None => (target, ""),
    };
    let Some(q) = head.find('?') else {
        return target.to_string();
    };
    let (path, query) = head.split_at(q + 1);
    let encoded: Vec<String> = names
        .iter()
        .map(|n| {
            let mut e = String::new();
            encode(n, &mut e);
            e
        })
        .collect();
    let pairs: Vec<String> = query
        .split('&')
        .map(|pair| {
            let name = pair.split_once('=').map_or(pair, |(n, _)| n);
            if encoded.iter().any(|e| e == name) {
                format!("{name}={REDACTED_VALUE}")
            } else {
                pair.to_string()
            }
        })
        .collect();
    format!("{path}{}{fragment}", pairs.join("&"))
}

#[cfg(test)]
#[path = "tests/query_auth_tests.rs"]
mod tests;
