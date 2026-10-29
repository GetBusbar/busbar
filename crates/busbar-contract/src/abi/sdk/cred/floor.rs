// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUTH FLOOR (coordinator rulings S4 and S5): which auth methods weaker than the best a
//! protocol offers the operator's connection string allows. It is read from the operator's text
//! when a [`super::CredUrl`] is split, carried by the [`super::Cred`] it seals and checked by the
//! chip's recipes, so a plugin cannot widen it: no method relaxes it.
//!
//! * Postgres: libpq 16's `require_auth`. With none written, busbar allows only SCRAM-SHA-256 (and
//!   a server that asks for no password); `require_auth=password`, `md5` or a list naming them
//!   allows the weaker method. A list of `!`-negated methods allows every method it does not name.
//! * MySQL: `enable_cleartext_plugin=true` allows `mysql_clear_password`; `secure_auth=false`
//!   allows `mysql_old_password` (both the 1.5.5 driver's switches, off by default).
//!   `caching_sha2_password` full authentication sends the password RSA-encrypted only to a server
//!   key the operator pinned (`server_public_key_sha256=<hex SHA-256 of the key's DER>`), or in
//!   clear on a unix socket (`socket=`) or a connection the host connector reports secured.

/// A Postgres auth method, as libpq's `require_auth` names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PgAuth {
    /// `password`: AuthenticationCleartextPassword.
    Password,
    /// `md5`: AuthenticationMD5Password.
    Md5,
    /// `scram-sha-256`: SASL SCRAM-SHA-256.
    ScramSha256,
    /// `gss`: GSSAPI.
    Gss,
    /// `sspi`: SSPI.
    Sspi,
    /// `none`: the server asks for no authentication.
    None,
}

impl PgAuth {
    const ALL: [Self; 6] = [
        Self::Password,
        Self::Md5,
        Self::ScramSha256,
        Self::Gss,
        Self::Sspi,
        Self::None,
    ];

    /// The name `require_auth` uses.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Md5 => "md5",
            Self::ScramSha256 => "scram-sha-256",
            Self::Gss => "gss",
            Self::Sspi => "sspi",
            Self::None => "none",
        }
    }

    const fn bit(self) -> u8 {
        1 << self as u8
    }

    fn named(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|m| m.name() == name)
    }
}

/// The Postgres methods a connection string's `require_auth` allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequireAuth(u8);

impl RequireAuth {
    /// No `require_auth` written: busbar 1.6.0 allows SCRAM-SHA-256 and a server that asks for no
    /// password, never a weaker password method.
    pub const DEFAULT: Self = Self(PgAuth::ScramSha256.bit() | PgAuth::None.bit());

    /// Parse a `require_auth` value as libpq 16 does: a comma-separated list of method names, or a
    /// list of `!`-negated ones (every method but those).
    ///
    /// # Errors
    /// An unknown method, an empty list, a method named twice, or negated and plain names mixed.
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        const MIXED: &str = "require_auth mixes negated (`!`) and plain methods";
        let mut negated = None;
        let mut bits = 0_u8;
        for item in value.split(',') {
            let (neg, name) = match item.strip_prefix('!') {
                Some(n) => (true, n),
                None => (false, item),
            };
            if *negated.get_or_insert(neg) != neg {
                return Err(MIXED);
            }
            let m = PgAuth::named(name).ok_or(
                "require_auth names an unknown method (password, md5, scram-sha-256, gss, sspi \
                 or none)",
            )?;
            if bits & m.bit() != 0 {
                return Err("require_auth names a method twice");
            }
            bits |= m.bit();
        }
        let all = PgAuth::ALL.iter().fold(0, |a, m| a | m.bit());
        Ok(Self(if negated == Some(true) {
            all & !bits
        } else {
            bits
        }))
    }

    /// Whether `method` is allowed.
    #[must_use]
    pub const fn allows(self, method: PgAuth) -> bool {
        self.0 & method.bit() != 0
    }
}

/// What the operator's connection string allows below a protocol's best auth method. See the
/// module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthFloor {
    pg: RequireAuth,
    mysql_clear: bool,
    mysql_old: bool,
    local: bool,
    rsa_pin: Option<[u8; 32]>,
}

impl Default for AuthFloor {
    fn default() -> Self {
        Self::STRICT
    }
}

impl AuthFloor {
    /// Nothing weaker allowed: a credential configured outside a connection string.
    pub const STRICT: Self = Self {
        pg: RequireAuth::DEFAULT,
        mysql_clear: false,
        mysql_old: false,
        local: false,
        rsa_pin: None,
    };

    /// The floor the operator's connection string `public` (its password already taken out) sets.
    /// A value that does not parse allows nothing weaker: the plugin refuses it at its own parse.
    #[must_use]
    pub fn of(public: &str) -> Self {
        let mut f = Self::STRICT;
        if public.to_ascii_lowercase().starts_with("unix:") {
            f.local = true;
        }
        let (authority, params) = params(public);
        if authority
            .rsplit('@')
            .next()
            .is_some_and(|h| h.starts_with('/') || h.to_ascii_lowercase().starts_with("%2f"))
        {
            f.local = true;
        }
        for (k, v) in params {
            match k.as_str() {
                "require_auth" => f.pg = RequireAuth::parse(&v).unwrap_or(RequireAuth::DEFAULT),
                "enable_cleartext_plugin" => f.mysql_clear = v == "true",
                "secure_auth" => f.mysql_old = v == "false",
                "server_public_key_sha256" => f.rsa_pin = pin(&v),
                "socket" => f.local = !v.is_empty(),
                "host" if v.starts_with('/') => f.local = true,
                _ => {}
            }
        }
        f
    }

    /// The Postgres methods allowed.
    #[must_use]
    pub const fn pg(&self) -> RequireAuth {
        self.pg
    }

    /// Whether `mysql_clear_password` is allowed (`enable_cleartext_plugin=true`).
    #[must_use]
    pub const fn mysql_clear(&self) -> bool {
        self.mysql_clear
    }

    /// Whether `mysql_old_password` is allowed (`secure_auth=false`).
    #[must_use]
    pub const fn mysql_old(&self) -> bool {
        self.mysql_old
    }

    /// Whether the connection string names a unix socket.
    #[must_use]
    pub const fn local(&self) -> bool {
        self.local
    }

    /// The pinned SHA-256 of the MySQL server's RSA public key (its DER), when one is written.
    #[must_use]
    pub const fn rsa_pin(&self) -> Option<[u8; 32]> {
        self.rsa_pin
    }
}

/// A `server_public_key_sha256` value: 64 hex digits, either case.
fn pin(v: &str) -> Option<[u8; 32]> {
    let mut out = [0_u8; 32];
    hex::decode_to_slice(v, &mut out).ok().map(|()| out)
}

fn unquote(v: &str) -> &str {
    v.trim_matches(['\'', '"'])
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let hex = |c: u8| char::from(c).to_digit(16);
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push((h << 4 | l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A key=value string with the whitespace around each `=` taken out (`k = v` is `k=v`).
fn tight(public: &str) -> String {
    let mut out = String::with_capacity(public.len());
    let mut chars = public.chars().peekable();
    while let Some(c) = chars.next() {
        if c.is_whitespace() {
            let mut rest = chars.clone();
            while rest.peek().is_some_and(|n| n.is_whitespace()) {
                rest.next();
            }
            if out.ends_with('=') || rest.peek() == Some(&'=') {
                chars = rest;
                continue;
            }
        }
        out.push(c);
    }
    out
}

/// A URL's authority and its decoded query pairs, or a key=value string's pairs.
fn params(public: &str) -> (&str, Vec<(String, String)>) {
    match public.find("://") {
        Some(i) => {
            let rest = &public[i + 3..];
            let rest = rest.split_once('#').map_or(rest, |(r, _)| r);
            let (head, query) = rest.split_once('?').unwrap_or((rest, ""));
            let authority = head.split('/').next().unwrap_or_default();
            let pairs = query
                .split('&')
                .filter_map(|p| p.split_once('='))
                .map(|(k, v)| (percent_decode(k), percent_decode(&v.replace('+', " "))))
                .collect();
            (authority, pairs)
        }
        None => (
            "",
            tight(public)
                .split_whitespace()
                .filter_map(|p| p.split_once('='))
                .map(|(k, v)| (k.to_owned(), unquote(v).to_owned()))
                .collect(),
        ),
    }
}
