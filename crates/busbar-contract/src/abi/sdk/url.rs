// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A CONFIGURED URL'S CREDENTIAL, KEPT TO ITS ONE USE: the pieces the export and hook sinks that

use crate::secure::{SecureString, SecureVec};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use zeroize::Zeroize;

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
    // busbar:expect(bp::fresh_buffer, reason = "config: a configured URL, read once as its instance opens")
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

    // One exact allocation (`concat`): the wiping buffer never grows (LINT-RULES LR-117).
    let user_pass = SecureVec::from(
        [
            &username[..],
            b":",
            password.as_ref().map_or(&[][..], |p| &p[..]),
        ]
        .concat(),
    );
    #[cfg(test)]
    tests::watch_scratch(&user_pass);
    let encoded = SecureString::from(STANDARD.encode(&*user_pass));
    #[cfg(test)]
    tests::watch_scratch(encoded.as_bytes());
    #[expect(
        clippy::disallowed_methods,
        reason = "config: a configured URL, read once as its instance opens"
    )]
    let authorization = format!("Basic {}", encoded.as_str());
    Some(authorization)
}

/// `url` with its credential-bearing prefix through the LAST `@` replaced by `with` (`with`
#[must_use]
pub fn cut_userinfo(url: &str, with: &str) -> String {
    let Some(at) = url.rfind('@') else {
        #[expect(
            clippy::disallowed_methods,
            reason = "config: a configured URL, read once as its instance opens"
        )]
        let whole = url.to_string();
        return whole;
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
            #[expect(
                clippy::disallowed_methods,
                reason = "config: a configured URL, read once as its instance opens"
            )]
            return format!("{scheme}://{with}{}", &url[at + 1..]);
        }
    }
    #[expect(
        clippy::disallowed_methods,
        reason = "config: a configured URL, read once as its instance opens"
    )]
    let cut = format!("{with}{}", &url[at + 1..]);
    cut
}

/// Returns a refusal for an ambiguous credential-bearing URL, without exposing its credential.
#[must_use]
pub fn ambiguous_url(url: &str, from_path: &str) -> Option<String> {
    if !from_path.contains('@') {
        return None;
    }
    #[expect(
        clippy::disallowed_methods,
        reason = "config: a configured URL, read once as its instance opens"
    )]
    let refusal = format!(
        "settings: url `{}` is ambiguous: it has an `@` after its host, so what comes before that \
         `@` would be read as the host and path, not as a credential. Percent-encode a `/`, `?` or \
         `#` inside the credential (`%2F`, `%3F`, `%23`), or write an `@` meant for the path as \
         `%40`",
        cut_userinfo(url, "***@")
    );
    Some(refusal)
}

/// `parts` followed by each of them percent-decoded (lossily read as text), in the same order: the
#[must_use]
pub fn and_decoded(mut parts: Vec<String>) -> Vec<String> {
    #[expect(
        clippy::disallowed_methods,
        reason = "config: a configured URL, read once as its instance opens"
    )]
    let decoded: Vec<String> = parts
        .iter()
        .map(|p| {
            let decoded = SecureVec::from(percent_decode(p.as_bytes()));
            String::from_utf8_lossy(&decoded).into_owned()
        })
        .collect();
    parts.extend(decoded);
    parts
}

/// `text` (a host's failure words, say, which may quote a URL or a setting) with each of `parts`
#[must_use]
pub fn scrub(text: &str, parts: Vec<String>, quoted: bool) -> String {
    // Each part wipes itself; the list's own block holds only pointers and lengths.
    let mut held = Vec::with_capacity(parts.len());
    for part in parts {
        held.push(SecureString::from(part));
    }
    let mut parts = held;
    #[cfg(test)]
    for part in &parts {
        tests::watch_scratch(part.as_bytes());
    }
    if quoted {
        // Exact capacity, so it never reallocates; the strings' own blocks never move, and each
        // escaped form is built in custody (LINT-RULES LR-117).
        let mut expanded = Vec::with_capacity(parts.len() * 2);
        for part in parts.iter_mut() {
            let escaped = SecureString::from_args(format_args!("{:?}", part.as_str()));
            #[cfg(test)]
            tests::watch_scratch(escaped.as_bytes());
            expanded.push(std::mem::take(part));
            let inner = SecureString::from(&escaped[1..escaped.len() - 1]);
            expanded.push(inner);
        }
        parts = expanded;
    }
    #[expect(
        clippy::disallowed_methods,
        reason = "error: a failure text, scrubbed once on its way to a diagnostic"
    )]
    parts.retain(|p| !p.is_empty());
    // Stable: equal-length parts keep their order, so the replacements run as they always did.
    #[expect(
        clippy::disallowed_methods,
        reason = "error: a failure text, scrubbed once on its way to a diagnostic"
    )]
    parts.sort_by_key(|p| std::cmp::Reverse(p.len()));
    parts.dedup_by(|removed, kept| {
        if removed == kept {
            removed.zeroize();
            true
        } else {
            false
        }
    });
    let mut out = SecureString::from(text);
    #[cfg(test)]
    tests::watch_scratch(out.as_bytes());
    for p in &parts {
        if out.contains(p.as_str()) {
            #[expect(
                clippy::disallowed_methods,
                reason = "error: a failure text, scrubbed once on its way to a diagnostic"
            )]
            let cut = out.replace(p.as_str(), CUT);
            out = SecureString::from(cut);
            #[cfg(test)]
            tests::watch_scratch(out.as_bytes());
        }
    }
    out.into_string()
}

#[cfg(test)]
#[path = "tests/url_tests.rs"]
mod tests;
