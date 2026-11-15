// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A CONFIGURED URL'S CREDENTIAL, KEPT TO ITS ONE USE: the pieces the export and hook sinks that

use crate::secure::{SecureString, SecureVec};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

/// What a cut part reads as.
const CUT: &str = "***";

/// `%XX` (two hex digits, either case) decoded to its octet; any other byte, a `%` not followed by
#[must_use]
pub fn percent_decode(s: &[u8]) -> Vec<u8> {
    let hex = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while let Some(&c) = s.get(i) {
        if c == b'%' {
            if let (Some(hi), Some(lo)) = (
                s.get(i + 1).copied().and_then(hex),
                s.get(i + 2).copied().and_then(hex),
            ) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
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
#[must_use]
pub fn basic_authorization(
    username: &str,
    password: Option<&str>,
    read: Userinfo,
) -> Option<String> {
    let username = SecureVec::from(percent_decode(username.as_bytes()));
    if username.contains(&b':') {
        return None;
    }
    let password = password.map(|p| SecureVec::from(percent_decode(p.as_bytes())));
    let password = match read {
        Userinfo::Octets => password,
        Userinfo::Utf8 => {
            std::str::from_utf8(&username).ok()?;
            password.filter(|p| std::str::from_utf8(p).is_ok())
        }
    };
    if username.is_empty() && password.is_none() {
        return None;
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
    let encoded = SecureString::from(STANDARD.encode(&*user_pass));
    #[cfg(test)]
    tests::watch_scratch(encoded.as_bytes());
    Some(format!("Basic {}", encoded.as_str()))
}

/// `url` with its credential-bearing prefix through the LAST `@` replaced by `with` (`with`
#[must_use]
pub fn cut_userinfo(url: &str, with: &str) -> String {
    let Some(at) = url.rfind('@') else {
        return url.to_string();
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
            return format!("{scheme}://{with}{}", &url[at + 1..]);
        }
    }
    format!("{with}{}", &url[at + 1..])
}

/// Returns a refusal for an ambiguous credential-bearing URL, without exposing its credential.
#[must_use]
pub fn ambiguous_url(url: &str, from_path: &str) -> Option<String> {
    if !from_path.contains('@') {
        return None;
    }
    Some(super::cold::wire::ambiguous_url(url))
}

/// `parts` followed by each of them percent-decoded (lossily read as text), in the same order: the
#[must_use]
pub fn and_decoded(mut parts: Vec<String>) -> Vec<String> {
    let given = parts.len();
    parts.reserve(given);
    for at in 0..given {
        let decoded = SecureVec::from(percent_decode(parts[at].as_bytes()));
        let text = String::from_utf8_lossy(&decoded).into_owned();
        parts.push(text);
    }
    parts
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
