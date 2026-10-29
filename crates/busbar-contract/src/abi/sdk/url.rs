// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A CONFIGURED URL'S CREDENTIAL, KEPT TO ITS ONE USE: the pieces the export and hook sinks that
//! POST to an operator's URL each wrote (export-otlp, export-webhook, hook-webrequest).
//!
//! * [`percent_decode`]: a URL component's `%XX` escapes as octets;
//! * [`basic_authorization`]: the `Authorization: Basic …` value the URL's userinfo becomes;
//! * [`ambiguous_url`]: the refusal of a url whose credential a parser reads as host and path;
//! * [`cut_userinfo`]: everything between `://` and the last `@` replaced;
//! * [`scrub`] (over [`and_decoded`] parts): a text with every credential-bearing part of a URL, or
//!   every credential string of a setting, cut out.
//!
//! The URL itself is parsed by the plugin's own WHATWG reader (the `url` crate the dialling client
//! follows): these take the parts it read (username, password, the text from the path on, the
//! parts to scrub), so each plugin's answers are the ones its parser gives, unchanged.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

/// What a cut part reads as.
const CUT: &str = "***";

/// `%XX` (two hex digits, either case) decoded to its octet; any other byte, a `%` not followed by
/// two hex digits included (`%+4` too), kept as written: the `percent-encoding` crate's
/// `percent_decode`, the decoder `url` and the 1.5.5 clients used.
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
/// of the percent-decoded `{username}:{password}` (`{username}:` with no password), read as
/// `read` says; `None` when the username is empty and there is no password. `username` and
/// `password` are the parsed URL's, as written (still percent-encoded).
#[must_use]
pub fn basic_authorization(
    username: &str,
    password: Option<&str>,
    read: Userinfo,
) -> Option<String> {
    let mut user_pass = percent_decode(username.as_bytes());
    let password = password.map(|p| percent_decode(p.as_bytes()));
    let password = match read {
        Userinfo::Octets => password,
        Userinfo::Utf8 => {
            std::str::from_utf8(&user_pass).ok()?;
            password.filter(|p| std::str::from_utf8(p).is_ok())
        }
    };
    if user_pass.is_empty() && password.is_none() {
        return None;
    }
    user_pass.push(b':');
    user_pass.extend(password.unwrap_or_default());
    Some(format!("Basic {}", STANDARD.encode(&user_pass)))
}

/// `url` with everything between `://` and the LAST `@` after it replaced by `with` (`with` names
/// its own `@`, when one is wanted). A password may hold an unescaped `/`, `?` or `#`, so no
/// delimiter bounds the userinfo here; an `@` in the path or query is over-cut, which is accepted:
/// a shortened line is better than a leaked secret. A string with no `@` after `://` is returned
/// unchanged.
#[must_use]
pub fn cut_userinfo(url: &str, with: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    match rest.rfind('@') {
        Some(at) => format!("{scheme}://{with}{}", &rest[at + 1..]),
        None => url.to_string(),
    }
}

/// THE AMBIGUOUS-URL REFUSAL (owner ruling 2026-10-24): `Some(the refusal)` when the parsed `url`
/// carries an `@` after its host (`from_path`, the parsed URL from its path on, holds one):
/// `https://tok/en@host/…` or `https://u:123/x@host/…`, a credential holding an unescaped `/`, `?`
/// or `#`, which a parser reads as host `tok` (or `u`, port `123`) and a path, so the credential
/// would be dialled as a host and written into lines. The refusal shows `url` with its userinfo
/// cut ([`cut_userinfo`]), never the credential. `None` when `from_path` holds no `@`; a url that
/// does not parse is not ambiguous, and its caller does not ask.
#[must_use]
pub fn ambiguous_url(url: &str, from_path: &str) -> Option<String> {
    if !from_path.contains('@') {
        return None;
    }
    Some(format!(
        "settings: url `{}` is ambiguous: it has an `@` after its host, so what comes before that \
         `@` would be read as the host and path, not as a credential. Percent-encode a `/`, `?` or \
         `#` inside the credential (`%2F`, `%3F`, `%23`), or write an `@` meant for the path as \
         `%40`",
        cut_userinfo(url, "***@")
    ))
}

/// `parts` followed by each of them percent-decoded (lossily read as text), in the same order: the
/// credential-bearing parts of a URL (the URL as written and as echoed, its path, query, username
/// and password, as the caller's parser reads them) as [`scrub`] cuts them.
#[must_use]
pub fn and_decoded(mut parts: Vec<String>) -> Vec<String> {
    let decoded: Vec<String> = parts
        .iter()
        .map(|p| String::from_utf8_lossy(&percent_decode(p.as_bytes())).into_owned())
        .collect();
    parts.extend(decoded);
    parts
}

/// `text` (a host's failure words, say, which may quote a URL or a setting) with each of `parts`
/// replaced by `***`, and, when `quoted`, each also as `{:?}` escapes it inside a quoted string (so
/// a serde refusal's quotation of it is cut too). Empty parts are dropped, and the longest is cut
/// first, so no part is left half-cut.
#[must_use]
pub fn scrub(text: &str, mut parts: Vec<String>, quoted: bool) -> String {
    if quoted {
        parts = parts
            .into_iter()
            .flat_map(|s| {
                let escaped = format!("{s:?}");
                let escaped = escaped[1..escaped.len() - 1].to_string();
                [s, escaped]
            })
            .collect();
    }
    parts.retain(|p| !p.is_empty());
    parts.sort_by_key(|p| std::cmp::Reverse(p.len()));
    parts.dedup();
    let mut out = text.to_string();
    for p in &parts {
        if out.contains(p.as_str()) {
            out = out.replace(p.as_str(), CUT);
        }
    }
    out
}

#[cfg(test)]
#[path = "tests/url_tests.rs"]
mod tests;
