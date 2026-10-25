// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A URL or connection-string setting, split at parse into public text and a sealed password.

use zeroize::Zeroizing;

use super::Cred;

/// A URL (`scheme://user:pass@host/...?password=...`, or `?pass=`) or key/value connection string
/// (`host=h password='p'`) with its password taken out and sealed. [`CredUrl::public`] is the text
/// with no password in it; the password is a [`Cred`].
#[allow(missing_debug_implementations)]
#[derive(Clone)]
pub struct CredUrl {
    public: String,
    password: Option<Cred>,
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

    pub(crate) fn split(text: &str) -> Result<Self, &'static str> {
        let (public, password) = if let Some(i) = text.find("://") {
            split_url(text, i)?
        } else if looks_keyword(text) {
            split_keyword(text)?
        } else {
            (text.to_owned(), None)
        };
        Ok(Self {
            public,
            password: password.map(Cred::from_bytes),
        })
    }
}

type Bytes = Zeroizing<Vec<u8>>;

const TWO: &str = "a URL with one password (userinfo or `password=`, not both)";

fn split_url(text: &str, scheme_end: usize) -> Result<(String, Option<Bytes>), &'static str> {
    let head = &text[..scheme_end + 3];
    let rest = &text[scheme_end + 3..];
    let pre_query = rest.find('?').unwrap_or(rest.len());
    let at = rest[..pre_query].rfind('@').or_else(|| {
        rest.rfind('@')
            .filter(|&a| !rest[..a].contains('/') && rest[..a].contains(':'))
    });
    let mut public = String::with_capacity(text.len());
    public.push_str(head);
    let mut password = None;
    let after = match at {
        Some(a) => {
            let userinfo = &rest[..a];
            match userinfo.split_once(':') {
                Some((user, pass)) => {
                    password = Some(decode(pass));
                    if !user.is_empty() {
                        public.push_str(user);
                        public.push('@');
                    }
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
                if let Some(v) = pair
                    .strip_prefix("password=")
                    .or_else(|| pair.strip_prefix("pass="))
                {
                    if password.is_some() {
                        return Err(TWO);
                    }
                    password = Some(decode_form(v));
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
    t.split_whitespace().next().is_some_and(|w| {
        w.split_once('=').is_some_and(|(k, _)| {
            !k.is_empty() && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
    })
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
