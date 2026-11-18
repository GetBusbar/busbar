// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A CONFIGURED URL'S CREDENTIAL, KEPT TO ITS ONE USE: the pieces the export and hook sinks that

use crate::secure::{SecureString, SecureVec};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

/// What a cut part reads as.
const CUT: &str = "***";

/// `%XX` (two hex digits, either case) decoded to its octet; any other byte, a `%` not followed by
/// two hex digits included, passes as itself. Each octet is handed to `push` in order: the decoder
/// keeps no buffer of its own.
pub fn percent_decode(s: &[u8], mut push: impl FnMut(u8)) {
    let hex = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    let mut i = 0;
    while let Some(&c) = s.get(i) {
        if c == b'%' {
            if let (Some(hi), Some(lo)) = (
                s.get(i + 1).copied().and_then(hex),
                s.get(i + 2).copied().and_then(hex),
            ) {
                push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        push(c);
        i += 1;
    }
}

/// `s` percent-decoded in custody: one wiping buffer with room for all of `s` (decoding only
/// shrinks), so it never grows.
fn decoded_in_custody(s: &[u8]) -> SecureVec {
    let mut out = SecureVec::with_capacity(s.len()).unwrap_or_default();
    percent_decode(s, |b| out.extend_from_slice(&[b]));
    #[cfg(test)]
    tests::watch_scratch(&out);
    out
}

/// How a userinfo's decoded halves are taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Userinfo {
    /// As octets (RFC 7617: the user-pass is an octet sequence), whatever they spell
    /// (export-otlp).
    Octets,
    /// As text, as reqwest 0.12 took them for 1.5.5 (export-webhook, hook-webrequest): a username
    /// that does not decode to UTF-8 sends no field at all, a password that does not is left out.
    Utf8,
}

/// THE USERINFO AS A BASIC CREDENTIAL: `Basic ` and the padded standard base64 (RFC 4648 section 4)
/// of `username:password`, each half percent-decoded, appended to `out` (the caller's buffer, in its
/// custody). `false`, and nothing written, when the userinfo states no credential `read` accepts.
#[must_use]
pub fn basic_authorization(
    username: &str,
    password: Option<&str>,
    read: Userinfo,
    out: &mut String,
) -> bool {
    let username = decoded_in_custody(username.as_bytes());
    if username.contains(&b':') {
        return false;
    }
    let password = password.map(|p| decoded_in_custody(p.as_bytes()));
    let password = match read {
        Userinfo::Octets => password,
        Userinfo::Utf8 => {
            if std::str::from_utf8(&username).is_err() {
                return false;
            }
            password.filter(|p| std::str::from_utf8(p).is_ok())
        }
    };
    if username.is_empty() && password.is_none() {
        return false;
    }

    // One exact allocation, made in custody: the wiping buffer never grows (LINT-RULES LR-117).
    let pass = password.as_ref().map_or(&[][..], |p| &p[..]);
    let mut user_pass =
        SecureVec::with_capacity(username.len() + 1 + pass.len()).unwrap_or_default();
    user_pass.extend_from_slice(&username);
    user_pass.extend_from_slice(b":");
    user_pass.extend_from_slice(pass);
    #[cfg(test)]
    tests::watch_scratch(&user_pass);
    out.push_str("Basic ");
    STANDARD.encode_string(&*user_pass, out);
    true
}

/// `url` with its credential-bearing prefix through the LAST `@` replaced by `with` (`with`
/// carries its own `@` if one is wanted), appended to `out`; a `url` with no `@` is appended whole.
pub fn cut_userinfo(url: &str, with: &str, out: &mut String) {
    let Some(at) = url.rfind('@') else {
        out.push_str(url);
        return;
    };

    if let Some((scheme, _)) = url[..at].split_once("://") {
        if scheme
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphabetic)
            && scheme
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.'))
        {
            out.push_str(scheme);
            out.push_str("://");
        }
    }
    out.push_str(with);
    out.push_str(&url[at + 1..]);
}

/// Returns a refusal for an ambiguous credential-bearing URL, without exposing its credential.
#[must_use]
pub fn ambiguous_url(url: &str, from_path: &str) -> Option<String> {
    if !from_path.contains('@') {
        return None;
    }
    Some(super::cold::wire::ambiguous_url(url))
}

/// Strings that wipe their whole allocations when the list drops; its own block holds only
/// pointers and lengths.
struct Wiped(Vec<String>);

impl Drop for Wiped {
    fn drop(&mut self) {
        for part in &mut self.0 {
            crate::secure::wipe_string(part);
        }
    }
}

/// Item `k` of the replacement order: the parts (`n` of them, held first), each followed, when
/// `quoted`, by its escaped form without the quotes (held after the parts, quotes included).
fn scrub_item(held: &[String], n: usize, quoted: bool, k: usize) -> &str {
    if !quoted {
        return &held[k];
    }
    if k.is_multiple_of(2) {
        &held[k / 2]
    } else {
        let escaped = &held[n + k / 2];
        &escaped[1..escaped.len() - 1]
    }
}

/// `text` (a host's failure words, say, which may quote a URL or a setting) with each of `parts`
#[must_use]
pub fn scrub(text: &str, parts: Vec<String>, quoted: bool) -> String {
    // Each part wipes itself when `held` drops.
    let mut held = Wiped(parts);
    let n = held.0.len();
    #[cfg(test)]
    for part in &held.0 {
        tests::watch_scratch(part.as_bytes());
    }
    if quoted {
        // Exact room, so the list never reallocates; each escaped form is built in custody and
        // moved in whole (LINT-RULES LR-117).
        held.0.reserve_exact(n);
        for at in 0..n {
            let escaped = SecureString::from_args(format_args!("{:?}", held.0[at].as_str()));
            #[cfg(test)]
            tests::watch_scratch(escaped.as_bytes());
            held.0.push(escaped.into_string());
        }
    }
    let count = if quoted { 2 * n } else { n };
    let mut out = SecureString::from(text);
    #[cfg(test)]
    tests::watch_scratch(out.as_bytes());
    // Longest first; equal lengths keep their order, so the replacements run as they always did.
    // Empty parts cut nothing, and a part equal to the one cut just before it is cut once.
    let mut below = usize::MAX;
    loop {
        let mut len = 0;
        for k in 0..count {
            let l = scrub_item(&held.0, n, quoted, k).len();
            if l < below && l > len {
                len = l;
            }
        }
        if len == 0 {
            break;
        }
        let mut last: Option<&str> = None;
        for k in 0..count {
            let p = scrub_item(&held.0, n, quoted, k);
            if p.len() != len || last == Some(p) {
                continue;
            }
            last = Some(p);
            if out.contains(p) {
                let mut cut = SecureString::with_capacity(out.len());
                let mut from = 0;
                for (at, _) in out.match_indices(p) {
                    cut.push_str(&out[from..at]);
                    cut.push_str(CUT);
                    from = at + p.len();
                }
                cut.push_str(&out[from..]);
                out = cut;
                #[cfg(test)]
                tests::watch_scratch(out.as_bytes());
            }
        }
        below = len;
    }
    out.into_string()
}

#[cfg(test)]
#[path = "tests/url_tests.rs"]
mod tests;
