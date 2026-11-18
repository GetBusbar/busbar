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
///
/// Appended to `out`, the caller's buffer.
pub fn mask_url(url: &str, out: &mut String) {
    let Some((scheme, rest)) = url.split_once("://") else {
        out.push_str(url);
        return;
    };
    out.push_str(scheme);
    out.push_str("://");
    match rest.rfind('@') {
        Some(at) => {
            out.push_str(MASK);
            out.push('@');
            mask_pairs(out, &rest[at + 1..], rest[..at].contains(['?', '#']));
        }
        None => mask_pairs(out, rest, false),
    }
}

/// `s` onto `out`, its secret-looking pair values masked: from its first `?` or `#`, or from its
/// start when `open`. Each pair is read in place, never copied out of `s`.
fn mask_pairs(out: &mut String, s: &str, open: bool) {
    let start = if open {
        0
    } else {
        match s.find(['?', '#']) {
            Some(i) => i,
            None => {
                out.push_str(s);
                return;
            }
        }
    };
    out.push_str(&s[..start]);
    // A raw `;` or `?` is legal inside a value (RFC 3986 3.4): a keyless segment they split off
    // right after a masked value is that value's tail, and is dropped with it.
    let mut masked = false;
    let mut after = None;
    let mut pair_at = start;
    for (i, ch) in s[start..].char_indices() {
        if matches!(ch, '?' | '#' | '&' | ';') {
            let at = start + i;
            masked = push_pair(
                out,
                &s[pair_at..at],
                masked && matches!(after, Some('?' | ';')),
            );
            out.push(ch);
            after = Some(ch);
            pair_at = at + ch.len_utf8();
        }
    }
    push_pair(
        out,
        &s[pair_at..],
        masked && matches!(after, Some('?' | ';')),
    );
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

/// Whether `key` names a secret: holds a [`SECRET_WORDS`] word in any ASCII case, compared in
/// place.
fn secret_looking(key: &str) -> bool {
    let key = key.as_bytes();
    SECRET_WORDS.iter().any(|word| {
        key.windows(word.len())
            .any(|at| at.eq_ignore_ascii_case(word.as_bytes()))
    })
}

#[cfg(test)]
#[path = "tests/mask_tests.rs"]
mod tests;
