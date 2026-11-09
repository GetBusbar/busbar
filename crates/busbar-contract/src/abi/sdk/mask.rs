// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A URL AS A LOG LINE MAY NAME IT: [`mask_url`], the one masker the export sinks (and any plugin

/// What a masked part reads as.
const MASK: &str = "***";

/// A query or fragment key holding any of these (in any case) names a secret.
const SECRET_WORDS: &[&str] = &[
    "token",
    "key",
    "secret",
    "pass",
    "pwd",
    "auth",
    "sig",
    "credential",
    "session",
    "code",
];

/// `url` with its userinfo and every secret-looking query or fragment value masked (the module
#[must_use]
pub fn mask_url(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    match rest.rfind('@') {
        Some(at) => format!(
            "{scheme}://{MASK}@{}",
            mask_pairs(&rest[at + 1..], rest[..at].contains(['?', '#']))
        ),
        None => format!("{scheme}://{}", mask_pairs(rest, false)),
    }
}

/// `s` with the secret-looking pair values masked: from its first `?` or `#`, or from its start
fn mask_pairs(s: &str, open: bool) -> String {
    let start = if open {
        0
    } else {
        match s.find(['?', '#']) {
            Some(i) => i,
            None => return s.to_string(),
        }
    };
    let mut out = String::with_capacity(s.len());
    out.push_str(&s[..start]);
    let mut pair = String::new();
    // A raw `;` or `?` is legal inside a value (RFC 3986 3.4): a keyless segment they split off
    // right after a masked value is that value's tail, and is dropped with it.
    let mut masked = false;
    let mut after = None;
    for ch in s[start..].chars() {
        if matches!(ch, '?' | '#' | '&' | ';') {
            masked = push_pair(&mut out, &pair, masked && matches!(after, Some('?' | ';')));
            pair.clear();
            out.push(ch);
            after = Some(ch);
        } else {
            pair.push(ch);
        }
    }
    push_pair(&mut out, &pair, masked && matches!(after, Some('?' | ';')));
    out
}

/// `pair` onto `out`, its value masked when its key looks like a secret; whether the value that
/// ends here is masked (`continued`: `pair` is the keyless tail of a masked value, so it is dropped).
fn push_pair(out: &mut String, pair: &str, continued: bool) -> bool {
    match pair.split_once('=') {
        Some((key, value)) if !value.is_empty() && secret_looking(key) => {
            out.push_str(key);
            out.push('=');
            out.push_str(MASK);
            true
        }
        None if continued => true,
        _ => {
            out.push_str(pair);
            false
        }
    }
}

/// Whether `key` names a secret.
fn secret_looking(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    SECRET_WORDS.iter().any(|w| key.contains(w))
}

#[cfg(test)]
#[path = "tests/mask_tests.rs"]
mod tests;
