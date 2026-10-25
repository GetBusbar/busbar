// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A URL or connection-string setting, split at parse into public text and a sealed password.

use zeroize::Zeroizing;

use super::Cred;

/// A URL (`scheme://user:pass@host/...?password=...`, or `?pass=`) or key/value connection string
/// (`host=h password='p'`) with its password taken out and sealed. [`CredUrl::public`] is the text
/// with no password in it (a userinfo keeps its user and its `@`, so `:pw@` reads as an empty
/// user, as a URL reader read it); the password is a [`Cred`].
#[allow(missing_debug_implementations)]
#[derive(Clone, PartialEq, Eq)]
pub struct CredUrl {
    public: String,
    password: Option<Cred>,
    at: Option<PasswordAt>,
}

/// Where in the text the password was written (public: a plugin keeps its own URL rules).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordAt {
    /// `user:password@` in a URL's authority.
    Userinfo,
    /// The same, with a `/`, `?` or `#` written unencoded inside it: a WHATWG URL reader ends the
    /// authority there.
    UserinfoUnencoded,
    /// A URL query parameter of this name (`password` or `pass`).
    Query(&'static str),
    /// `password=` in a key=value connection string.
    Keyword,
}

impl CredUrl {
    /// The text with the password removed: safe to parse, log and print.
    pub fn public(&self) -> &str {
        &self.public
    }

    /// The password the text carried, sealed.
    pub fn password(&self) -> Option<&Cred> {
        self.password.as_ref()
    }

    /// Where the password was written.
    pub fn password_at(&self) -> Option<PasswordAt> {
        self.at
    }

    /// Split `text` (a URL or connection string the plugin already holds).
    ///
    /// # Errors
    /// The text carries two passwords, or is a malformed key=value connection string.
    pub fn parse(text: &str) -> Result<Self, &'static str> {
        Self::split(text)
    }

    /// Take a URL setting out of a parsed settings document: split it, and wipe the string where
    /// it was. `None`: `v` is not a string (left as it was).
    pub fn take(v: &mut serde_json::Value) -> Option<Result<Self, &'static str>> {
        let serde_json::Value::String(s) = v else {
            return None;
        };
        let text = Zeroizing::new(core::mem::take(s));
        *v = serde_json::Value::Null;
        Some(Self::split(&text))
    }

    pub(crate) fn split(text: &str) -> Result<Self, &'static str> {
        let (public, found) = if let Some(i) = text.find("://") {
            split_url(text, i)?
        } else if looks_keyword(text) {
            let (p, pw) = split_keyword(text)?;
            (p, pw.map(|b| (b, PasswordAt::Keyword)))
        } else {
            (text.to_owned(), None)
        };
        let (password, at) = match found {
            Some((b, at)) => (Some(Cred::from_bytes(b)), Some(at)),
            None => (None, None),
        };
        Ok(Self {
            public,
            password,
            at,
        })
    }
}

type Bytes = Zeroizing<Vec<u8>>;
type Found = (Bytes, PasswordAt);

const TWO: &str = "a URL with one password (userinfo or `password=`, not both)";

fn split_url(text: &str, scheme_end: usize) -> Result<(String, Option<Found>), &'static str> {
    let head = &text[..scheme_end + 3];
    let rest = &text[scheme_end + 3..];
    let pre_query = rest.find('?').unwrap_or(rest.len());
    let strict = rest[..pre_query].rfind('@');
    let at = strict.or_else(|| {
        rest.rfind('@')
            .filter(|&a| !rest[..a].contains('/') && rest[..a].contains(':'))
    });
    let userinfo_at = match at {
        Some(a) if strict.is_some() && !rest[..a].contains(['/', '#']) => PasswordAt::Userinfo,
        _ => PasswordAt::UserinfoUnencoded,
    };
    let mut public = String::with_capacity(text.len());
    public.push_str(head);
    let mut password = None;
    let after = match at {
        Some(a) => {
            let userinfo = &rest[..a];
            match userinfo.split_once(':') {
                Some((user, pass)) => {
                    password = Some((decode(pass), userinfo_at));
                    public.push_str(user);
                    public.push('@');
                }
                None => {
                    public.push_str(userinfo);
                    public.push('@');
                }
            }
            &rest[a + 1..]
        }
        None => rest,
    };
    match after.split_once('?') {
        None => public.push_str(after),
        Some((path, query)) => {
            public.push_str(path);
            let (fragment_free, fragment) = match query.split_once('#') {
                Some((q, f)) => (q, Some(f)),
                None => (query, None),
            };
            let mut kept = Vec::new();
            for pair in fragment_free.split('&') {
                let named = pair
                    .strip_prefix("password=")
                    .map(|v| ("password", v))
                    .or_else(|| pair.strip_prefix("pass=").map(|v| ("pass", v)));
                if let Some((name, v)) = named {
                    if password.is_some() {
                        return Err(TWO);
                    }
                    password = Some((decode_form(v), PasswordAt::Query(name)));
                } else {
                    kept.push(pair);
                }
            }
            if !kept.is_empty() {
                public.push('?');
                public.push_str(&kept.join("&"));
            }
            if let Some(f) = fragment {
                public.push('#');
                public.push_str(f);
            }
        }
    }
    Ok((public, password))
}

fn looks_keyword(text: &str) -> bool {
    let t = text.trim_start();
    let key = t
        .bytes()
        .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
        .count();
    key > 0 && t[key..].trim_start().starts_with('=')
}

const KEYWORD: &str = "a connection string of key=value pairs";

fn split_keyword(text: &str) -> Result<(String, Option<Bytes>), &'static str> {
    let b = text.as_bytes();
    let mut i = 0;
    let mut kept: Vec<&str> = Vec::new();
    let mut password = None;
    while i < b.len() {
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= b.len() {
            break;
        }
        let start = i;
        while i < b.len() && b[i] != b'=' && !b[i].is_ascii_whitespace() {
            i += 1;
        }
        let key = &text[start..i];
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= b.len() || b[i] != b'=' {
            return Err(KEYWORD);
        }
        i += 1;
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        let mut value = Zeroizing::new(Vec::new());
        if i < b.len() && b[i] == b'\'' {
            i += 1;
            loop {
                match b.get(i) {
                    None => return Err(KEYWORD),
                    Some(b'\'') => {
                        i += 1;
                        break;
                    }
                    Some(b'\\') if i + 1 < b.len() => {
                        value.push(b[i + 1]);
                        i += 2;
                    }
                    Some(&c) => {
                        value.push(c);
                        i += 1;
                    }
                }
            }
        } else {
            while i < b.len() && !b[i].is_ascii_whitespace() {
                if b[i] == b'\\' && i + 1 < b.len() {
                    value.push(b[i + 1]);
                    i += 2;
                } else {
                    value.push(b[i]);
                    i += 1;
                }
            }
        }
        if key == "password" {
            if password.is_some() {
                return Err(TWO);
            }
            password = Some(value);
        } else {
            kept.push(&text[start..i]);
        }
    }
    Ok((kept.join(" "), password))
}

fn hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn decode_form(s: &str) -> Bytes {
    let spaced = Zeroizing::new(s.replace('+', " "));
    decode(&spaced)
}

fn decode(s: &str) -> Bytes {
    let b = s.as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(b.len()));
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}
