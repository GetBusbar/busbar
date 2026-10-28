// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A URL AS A LOG LINE MAY NAME IT: [`mask_url`], the one masker the export sinks (and any plugin
//! that names a configured URL in a line, a refusal or a `Debug`) write a URL through.
//!
//! Read as text, not parsed, so a string no URL parser accepts is masked the same way:
//!
//! * the userinfo — everything between `://` and the LAST `@` — becomes `***`. A credential may hold
//!   an unescaped `/`, `?` or `#`, so no delimiter bounds it; an `@` later in the path or query is
//!   over-cut, which is accepted: a shortened line is better than a leaked secret;
//! * in the query and fragment, the value of every pair whose key looks like a secret (`token`,
//!   `key`, `secret`, `pass`, `pwd`, `auth`, `sig`, `credential`, `session`, `code`, in any case,
//!   anywhere in the key) becomes `***`.
//!
//! Everything else is written as given. A string with no `://` is returned unchanged.

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
/// docs).
#[must_use]
pub fn mask_url(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    match rest.rfind('@') {
        // When the cut reached into what may have been a query or fragment, everything after the
        // `@` is read as pairs.
        Some(at) => format!(
            "{scheme}://{MASK}@{}",
            mask_pairs(&rest[at + 1..], rest[..at].contains(['?', '#']))
        ),
        None => format!("{scheme}://{}", mask_pairs(rest, false)),
    }
}

/// `s` with the secret-looking pair values masked: from its first `?` or `#`, or from its start
/// when `open`.
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
    for ch in s[start..].chars() {
        if matches!(ch, '?' | '#' | '&' | ';') {
            push_pair(&mut out, &pair);
            pair.clear();
            out.push(ch);
        } else {
            pair.push(ch);
        }
    }
    push_pair(&mut out, &pair);
    out
}

/// `pair` onto `out`, its value masked when its key looks like a secret.
fn push_pair(out: &mut String, pair: &str) {
    match pair.split_once('=') {
        Some((key, value)) if !value.is_empty() && secret_looking(key) => {
            out.push_str(key);
            out.push('=');
            out.push_str(MASK);
        }
        _ => out.push_str(pair),
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
