// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Protocol capture without handing secret-bearing text to an allocating URL parser.

use super::{
    decode, decode_form, hex, secure_requested, AuthFloor, Bytes, Cred, CredUrl, PasswordAt,
};
use zeroize::Zeroizing;

fn captured(public: String, found: Option<(Bytes, PasswordAt)>, echoes: Vec<Cred>) -> CredUrl {
    let floor = AuthFloor::of(&public);
    let secure = secure_requested(&public);
    let (password, at) = match found {
        Some((b, at)) => {
            let c = Cred::from_bytes(b).with_floor(floor);
            (Some(if secure { c.require_secure() } else { c }), Some(at))
        }
        None => (None, None),
    };
    #[cfg(test)]
    for c in password.iter().chain(echoes.iter()) {
        watch(c.wire());
    }
    CredUrl {
        public,
        password,
        at,
        floor,
        echoes,
        parsing_error: None,
    }
}

fn strict(s: &str) -> Result<Bytes, &'static str> {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if b.get(i + 1).and_then(|&c| hex(c)).is_none()
                || b.get(i + 2).and_then(|&c| hex(c)).is_none()
            {
                return Err("invalid percent encoding");
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    let out = decode(s);
    #[cfg(test)]
    watch(&out);
    core::str::from_utf8(&out).map_err(|_| "invalid percent encoding")?;
    Ok(out)
}

fn remember(echoes: &mut Vec<Cred>, raw: &str, decoded: &Bytes) {
    echoes.push(Cred::from_bytes(Zeroizing::new(raw.as_bytes().to_vec())));
    echoes.push(Cred::from_bytes(decoded.clone()));
}

fn visit_postgres_keyword<'a>(
    text: &'a str,
    mut visit: impl FnMut(&'a str, Bytes, &'a str) -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    let mut i = 0;
    let next = |i: usize| text[i..].chars().next();
    loop {
        while next(i).is_some_and(char::is_whitespace) {
            i += next(i).expect("character").len_utf8();
        }
        if i == text.len() {
            return Ok(());
        }
        let start = i;
        while next(i).is_some_and(|c| c != '=' && !c.is_whitespace()) {
            i += next(i).expect("character").len_utf8();
        }
        let key = &text[start..i];
        while next(i).is_some_and(char::is_whitespace) {
            i += next(i).expect("character").len_utf8();
        }
        if next(i) != Some('=') {
            return Err("unexpected EOF: a connection parameter without `=` (expected key=value)");
        }
        i += 1;
        while next(i).is_some_and(char::is_whitespace) {
            i += next(i).expect("character").len_utf8();
        }
        let mut value = Zeroizing::new(String::with_capacity(text.len() - i));
        if next(i) == Some('\'') {
            i += 1;
            loop {
                let Some(c) = next(i) else {
                    return Err("unterminated quoted connection parameter value");
                };
                i += c.len_utf8();
                if c == '\'' {
                    break;
                }
                if c == '\\' {
                    let Some(c) = next(i) else {
                        return Err("unterminated quoted connection parameter value");
                    };
                    i += c.len_utf8();
                    value.push(c);
                } else {
                    value.push(c);
                }
            }
        } else {
            while let Some(c) = next(i).filter(|c| !c.is_whitespace()) {
                i += c.len_utf8();
                if c == '\\' {
                    if let Some(c) = next(i) {
                        i += c.len_utf8();
                        value.push(c);
                    }
                } else {
                    value.push(c);
                }
            }
        }
        let bytes = Zeroizing::new(value.as_bytes().to_vec());
        #[cfg(test)]
        {
            watch(value.as_bytes());
            watch(&bytes);
        }
        visit(key, bytes, &text[start..i])?;
    }
}

fn postgres_policy(mut url: CredUrl, require_auth: Option<Bytes>) -> CredUrl {
    let floor = url.floor.postgres(
        require_auth
            .as_ref()
            .and_then(|v| core::str::from_utf8(v).ok()),
    );
    url.floor = floor;
    url.password = url.password.map(|c| c.with_floor(floor));
    url
}

pub(super) fn postgres(text: &str) -> Result<CredUrl, &'static str> {
    let mut echoes = Vec::new();
    let mut found = None;
    let mut require_auth = None;
    let prefix = text
        .strip_prefix("postgres://")
        .map(|r| ("postgres://", r))
        .or_else(|| {
            text.strip_prefix("postgresql://")
                .map(|r| ("postgresql://", r))
        });
    let Some((head, rest)) = prefix else {
        let mut kept = Vec::new();
        visit_postgres_keyword(text, |key, value, raw| {
            if key == "password" {
                let raw_value = raw.split_once('=').expect("visited keyword").1.trim_start();
                let raw_value = raw_value
                    .strip_prefix('\'')
                    .and_then(|v| v.strip_suffix('\''))
                    .unwrap_or(raw_value);
                remember(&mut echoes, raw_value, &value);
                found = Some((value, PasswordAt::Keyword));
            } else {
                if key == "require_auth" {
                    require_auth = Some(value.clone());
                }
                let value = core::str::from_utf8(&value).expect("keyword characters are UTF-8");

                kept.push(format!(
                    "{key}='{}'",
                    value.replace('\\', "\\\\").replace('\'', "\\'")
                ));
            }
            Ok(())
        })?;
        return Ok(postgres_policy(
            captured(kept.join(" "), found, echoes),
            require_auth,
        ));
    };
    let (main, query) = rest
        .split_once('?')
        .map_or((rest, None), |(m, q)| (m, Some(q)));
    let authority_end = main.find('/').unwrap_or(main.len());
    let authority = &main[..authority_end];
    if !authority.contains('@') && !authority.starts_with('[') {
        if let Some((_, port)) = authority.rsplit_once(':') {
            if rest[authority.len()..].contains('@') && port.parse::<u16>().is_err() {
                return Err(
                    if query
                        .is_some_and(|q| q.split('&').any(|p| !p.is_empty() && !p.contains('=')))
                    {
                        "invalid query parameter (expected key=value)"
                    } else {
                        "invalid value for option `port`"
                    },
                );
            }
        }
    }
    let mut public = String::with_capacity(text.len());
    public.push_str(head);
    if let Some((userinfo, host)) = authority.rsplit_once('@') {
        if let Some((user, pass)) = userinfo.split_once(':') {
            let b = strict(pass)?;
            remember(&mut echoes, pass, &b);
            found = Some((b, PasswordAt::Userinfo));
            public.push_str(user);
        } else {
            public.push_str(userinfo);
        }
        public.push('@');
        public.push_str(host);
    } else {
        public.push_str(authority);
    }
    public.push_str(&main[authority_end..]);
    if let Some(query) = query {
        let mut kept = Vec::new();
        for pair in query.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                let key = strict(key)?;
                if &key[..] == b"require_auth" {
                    require_auth = Some(strict(value)?);
                }
                if &key[..] == b"password" {
                    let b = strict(value)?;
                    remember(&mut echoes, value, &b);
                    found = Some((b, PasswordAt::Query("password")));
                    continue;
                }
                if &key[..] == b"sslmode" {
                    let value = strict(value)?;
                    let value = core::str::from_utf8(&value).expect("strict UTF-8");

                    if matches!(
                        value,
                        "disable" | "allow" | "prefer" | "require" | "verify-ca" | "verify-full"
                    ) {
                        kept.push(format!("sslmode={value}"));
                        continue;
                    }
                }
            }
            kept.push(pair.to_owned());
        }
        if !kept.is_empty() {
            public.push('?');
            public.push_str(&kept.join("&"));
        }
    }
    Ok(postgres_policy(
        captured(public, found, echoes),
        require_auth,
    ))
}

/// WHATWG preprocessing: strip leading/trailing C0/space, ignore tab/newline/CR anywhere.

fn normalized(text: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(text.len()));
    for c in text.trim_matches(|c: char| c <= '\u{20}').chars() {
        if !matches!(c, '\t' | '\n' | '\r') {
            out.push(c);
        }
    }
    #[cfg(test)]
    watch(out.as_bytes());
    out
}

fn lossy(bytes: &[u8]) -> Bytes {
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len().saturating_mul(3)));
    let mut rest = bytes;
    while !rest.is_empty() {
        match core::str::from_utf8(rest) {
            Ok(_) => {
                out.extend_from_slice(rest);
                break;
            }
            Err(e) => {
                out.extend_from_slice(&rest[..e.valid_up_to()]);
                out.extend_from_slice("\u{fffd}".as_bytes());
                rest = &rest
                    [e.valid_up_to() + e.error_len().unwrap_or(rest.len() - e.valid_up_to())..];
            }
        }
    }
    #[cfg(test)]
    watch(&out);
    out
}

pub(super) fn valkey(text: &str) -> CredUrl {
    let text = normalized(text);
    let mut echoes = Vec::new();
    let mut found = None;
    let mut error = None;
    let Some(colon) = text.find(':') else {
        let mut out = captured(String::new(), None, echoes);

        out.parsing_error = if text.is_empty() {
            None
        } else {
            Some("Redis URL did not parse")
        };
        return out;
    };
    let scheme = &text[..colon];
    let unix = ["unix", "redis+unix", "valkey+unix"]
        .iter()
        .any(|s| scheme.eq_ignore_ascii_case(s));
    let supported = unix
        || ["redis", "rediss", "valkey", "valkeys"]
            .iter()
            .any(|s| scheme.eq_ignore_ascii_case(s));
    if !supported {
        error = Some("Redis URL did not parse");
    }
    let rest = &text[colon + 1..];
    if !supported || (!rest.starts_with("//") && (!unix || !rest.starts_with('/'))) {
        let mut out = captured(format!("{scheme}:"), None, echoes);
        out.parsing_error = error;
        return out;
    }
    let mut ambiguous = false;
    let mut public = String::with_capacity(text.len());
    public.push_str(scheme);
    public.push(':');
    let after = if let Some(authority_rest) = rest.strip_prefix("//") {
        public.push_str("//");
        let end = authority_rest
            .find(['/', '?', '#'])
            .unwrap_or(authority_rest.len());
        let authority = &authority_rest[..end];
        if !authority.contains('@') && !authority.starts_with('[') {
            if let Some((_, port)) = authority.rsplit_once(':') {
                if let Some(at) = authority_rest[end..].rfind('@') {
                    ambiguous = true;
                    let start = authority.find(':').expect("authority colon") + 1;
                    let raw = &authority_rest[start..end + at];
                    let b = decode(raw);
                    remember(&mut echoes, raw, &b);
                    if !port.is_empty() && port.parse::<u16>().is_err() {
                        let mut out = captured(String::new(), None, echoes);
                        out.parsing_error = Some("Redis URL did not parse");
                        return out;
                    }
                }
            }
        }
        if let Some((userinfo, host)) = authority.rsplit_once('@') {
            if let Some((user, pass)) = userinfo.split_once(':') {
                let b = decode(pass);
                remember(&mut echoes, pass, &b);
                echoes.push(Cred::from_bytes(lossy(&b)));
                echoes.push(Cred::from_bytes(lossy(&decode_form(pass))));
                if !unix && !pass.is_empty() {
                    if core::str::from_utf8(&b).is_err() {
                        error = Some("Password is not valid UTF-8 string");
                    }
                    found = Some((b, PasswordAt::Userinfo));
                }
                public.push_str(user);
            } else {
                public.push_str(userinfo);
            }
            public.push('@');
            public.push_str(host);
        } else {
            public.push_str(authority);
        }
        &authority_rest[end..]
    } else {
        rest
    };
    let (before_fragment, fragment) = after
        .split_once('#')
        .map_or((after, None), |(a, f)| (a, Some(f)));
    let (path, query) = before_fragment
        .split_once('?')
        .map_or((before_fragment, None), |(a, q)| (a, Some(q)));
    if ambiguous {
        for (i, segment) in path.split('/').enumerate() {
            if i != 0 {
                public.push('/');
            }
            public.push_str(if segment.contains('@') {
                "redacted@"
            } else {
                segment
            });
        }
    } else {
        public.push_str(path);
    }
    if let Some(query) = query {
        public.push('?');
        for (i, pair) in query.split('&').enumerate() {
            if i != 0 {
                public.push('&');
            }
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let key_decoded = decode_form(key);
            if matches!(&key_decoded[..], b"pass" | b"password") {
                let b = decode_form(value);
                remember(&mut echoes, value, &b);

                let value = lossy(&b);
                echoes.push(Cred::from_bytes(decode(
                    pair.split_once('=').map_or("", |(_, v)| v),
                )));
                if unix && &key_decoded[..] == b"pass" {
                    found = Some((value, PasswordAt::Query("pass")));
                } else {
                    echoes.push(Cred::from_bytes(value));
                }
                public.push_str(key);
                public.push('=');
            } else if ambiguous {
                let known = if unix {
                    &["db", "user", "protocol"][..]
                } else {
                    &["protocol"][..]
                };
                let key_text = core::str::from_utf8(&key_decoded).unwrap_or("");
                if known.contains(&key_text) {
                    public.push_str(key);
                    if pair.contains('=') {
                        public.push('=');
                        public.push_str(if value.contains('@') {
                            "<redacted>"
                        } else {
                            value
                        });
                    }
                } else {
                    public.push_str("redacted@");
                }
            } else {
                public.push_str(pair);
            }
        }
    }
    if let Some(f) = fragment {
        public.push('#');
        public.push_str(if ambiguous && f.contains('@') {
            "redacted@"
        } else {
            f
        });
    }
    let mut out = captured(public, found, echoes);
    out.parsing_error = error;
    if scheme.eq_ignore_ascii_case("valkeys") {
        out.password = out.password.map(Cred::require_secure);
    }
    out
}

/// Compare one sealed spelling to a message suffix. Percent triplets ignore only hex case;

fn echo_len_mode(message: &[u8], secret: &[u8], encoded: bool) -> Option<usize> {
    if secret.is_empty() {
        return None;
    }
    let mut i = 0;
    for &b in secret {
        if encoded
            && message.get(i) == Some(&b'%')
            && message
                .get(i + 1)
                .and_then(|&c| hex(c))
                .zip(message.get(i + 2).and_then(|&c| hex(c)))
                .is_some_and(|(h, l)| (h << 4 | l) == b)
        {
            i += 3;
        } else if message.get(i) == Some(&b) || (b == b' ' && message.get(i) == Some(&b'+')) {
            i += 1;
        } else {
            return None;
        }
    }
    Some(i)
}

pub(super) fn redact(url: &CredUrl, text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < text.len() {
        let n = url
            .password
            .iter()
            .chain(url.echoes.iter())
            .flat_map(|c| {
                [
                    echo_len_mode(&text.as_bytes()[i..], c.wire(), false),
                    echo_len_mode(&text.as_bytes()[i..], c.wire(), true),
                ]
            })
            .flatten()
            .filter(|&n| text.is_char_boundary(i + n))
            .max();
        if let Some(n) = n {
            out.push_str("<redacted>");
            i += n;
        } else {
            let c = text[i..].chars().next().expect("within text");
            out.push(c);
            i += c.len_utf8();
        }
    }
    out
}

#[cfg(test)]
fn watch(bytes: &[u8]) {
    // SAFETY: these are initialized base prefixes of owned buffers, retained on this thread
    // until deallocation or probe completion. The observer reads only at current deallocation.
    unsafe { crate::alloc_counter::watch_initialized_payload(bytes) }
}

#[cfg(test)]
#[path = "../tests/native_cred_tests.rs"]
mod tests;
