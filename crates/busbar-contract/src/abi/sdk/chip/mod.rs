// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CHIP'S RECIPES (the chip design, its section on recipe classes): every auth step a plugin needs, performed by the
//! credential, answering a [`Seal`] or a yes/no. A raw stream's recipe builds the WHOLE auth message
//! from public inputs, so the plugin cannot choose where credential-derived bytes sit on the wire.
//!
//! Until row 4 the recipes run in the plugin's own image; from row 4 the same calls cross the ABI
//! to the secret plugin and nothing a plugin wrote against this module changes.

pub mod aws4;
pub(crate) mod digests;
mod jws;
pub(crate) mod rsa;
mod scheme;

use base64::Engine as _;
use zeroize::Zeroizing;

use crate::abi::sdk::cred::{Cred, Held, PgAuth, Seal};
use crate::abi::sdk::hmac::hmac_sha256;

/// Why a recipe refused: a sentence with no material in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refused(pub &'static str);

impl core::fmt::Display for Refused {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for Refused {}

/// RULING S4: a Postgres server asked for the password in clear.
pub const PG_CLEARTEXT_REFUSED: Refused = Refused(
    "the server asked for the password in clear (AuthenticationCleartextPassword), which the \
     operator's connection string does not allow: busbar sends only SCRAM-SHA-256 unless \
     `require_auth` allows the weaker method (add `require_auth=password`, or use SCRAM on the \
     server)",
);

/// RULING S4: a Postgres server asked for MD5.
pub const PG_MD5_REFUSED: Refused = Refused(
    "the server asked for MD5 password authentication, which the operator's connection string \
     does not allow: busbar sends only SCRAM-SHA-256 unless `require_auth` allows the weaker \
     method (add `require_auth=md5`, or set the role's password with SCRAM on the server)",
);

/// The operator's `require_auth` leaves SCRAM-SHA-256 out (libpq's rule).
pub const PG_SCRAM_REFUSED: Refused = Refused(
    "the server asked for SCRAM-SHA-256, which the operator's `require_auth` does not name",
);

/// RULING S4: a MySQL server asked for `mysql_clear_password`.
pub const MYSQL_CLEAR_REFUSED: Refused = Refused(
    "the server asked for mysql_clear_password (the password in clear), which the operator's URL \
     does not allow: add `enable_cleartext_plugin=true` to allow it",
);

/// RULING S4: a MySQL server asked for `mysql_old_password`.
pub const MYSQL_OLD_REFUSED: Refused = Refused(
    "the server asked for mysql_old_password (the pre-4.1 scramble), which the operator's URL \
     does not allow: add `secure_auth=false` to allow it",
);

/// RULING S5: the server's RSA key is not the one the operator pinned.
pub const MYSQL_RSA_PIN_MISMATCH: Refused = Refused(
    "the MySQL server's RSA public key does not match the operator's `server_public_key_sha256` \
     pin, so the password was not sent: check the pin against the server's key",
);

type Bytes = Zeroizing<Vec<u8>>;

fn b64(bytes: &[u8]) -> Bytes {
    Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .encode(bytes)
            .into_bytes(),
    )
}

/// What a SCRAM exchange left to check: the server's signature, held until the server-final
/// message arrives. Use it once.
#[allow(missing_debug_implementations)]
pub struct ScramLink(Held<Zeroizing<[u8; 32]>>);

impl ScramLink {
    /// Whether `server_final` (`v=<base64>`) proves the server knew the password.
    pub fn verify(self, server_final: &str) -> bool {
        let Some(v) = server_final.split(',').find_map(|a| a.strip_prefix("v=")) else {
            return false;
        };
        let Ok(got) = base64::engine::general_purpose::STANDARD.decode(v) else {
            return false;
        };
        crate::constant_time_eq(&got[..], &self.0.wire()[..])
    }
}

/// Which MySQL auth plugin a handshake response answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MysqlAuth {
    /// `mysql_native_password`: SHA-1 scramble.
    Native,
    /// `caching_sha2_password`: SHA-256 scramble.
    CachingSha2,
    /// `mysql_old_password` (pre-4.1; a plugin allows it only when the operator turned
    /// `secure_auth` off).
    Old,
    /// `mysql_clear_password`: the password itself (a plugin allows it only when the operator
    /// enabled the cleartext plugin).
    Clear,
}

impl MysqlAuth {
    fn name(self) -> &'static [u8] {
        match self {
            Self::Native => b"mysql_native_password",
            Self::CachingSha2 => b"caching_sha2_password",
            Self::Old => b"mysql_old_password",
            Self::Clear => b"mysql_clear_password",
        }
    }
}

/// The public inputs of a MySQL `HandshakeResponse41`.
#[derive(Debug, Clone, Copy)]
pub struct MysqlHandshake<'a> {
    /// The packet's sequence id.
    pub seq: u8,
    /// The client capability flags as the client will send them.
    pub capabilities: u32,
    /// Max packet size.
    pub max_packet: u32,
    /// Collation id.
    pub collation: u8,
    /// The user name.
    pub user: &'a [u8],
    /// The database, when `CLIENT_CONNECT_WITH_DB`.
    pub database: Option<&'a [u8]>,
    /// The auth plugin answered.
    pub auth: MysqlAuth,
    /// The server's 20-byte nonce.
    pub nonce: &'a [u8],
    /// Connection attributes, when `CLIENT_CONNECT_ATTRS`.
    pub attrs: &'a [(&'a [u8], &'a [u8])],
}

const CLIENT_CONNECT_WITH_DB: u32 = 0x0000_0008;
const CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;
const CLIENT_CONNECT_ATTRS: u32 = 0x0010_0000;
const CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA: u32 = 0x0020_0000;

fn lenenc(out: &mut Vec<u8>, n: u64) {
    match n {
        0..=250 => out.push(n as u8),
        251..=0xffff => {
            out.push(0xfc);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x1_0000..=0xff_ffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u32).to_le_bytes()[..3]);
        }
        _ => {
            out.push(0xfe);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}

fn lenenc_len(n: u64) -> u64 {
    match n {
        0..=250 => 1,
        251..=0xffff => 3,
        0x1_0000..=0xff_ffff => 4,
        _ => 9,
    }
}

fn mysql_packet(seq: u8, payload: &[u8]) -> Result<Bytes, Refused> {
    if payload.len() >= 0xff_ffff {
        return Err(Refused("the auth packet does not fit one MySQL packet"));
    }
    let mut out = Zeroizing::new(Vec::with_capacity(payload.len() + 4));
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes()[..3]);
    out.push(seq);
    out.extend_from_slice(payload);
    Ok(out)
}

fn ber_len(out: &mut Vec<u8>, n: usize) {
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let bytes = (n as u64).to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (8 - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
}

fn ber_tlv(out: &mut Vec<u8>, tag: u8, value: &[u8]) {
    out.push(tag);
    ber_len(out, value.len());
    out.extend_from_slice(value);
}

fn ber_int(out: &mut Vec<u8>, v: i64) {
    let bytes = v.to_be_bytes();
    let mut start = 0;
    while start < 7 {
        let (b, next) = (bytes[start], bytes[start + 1]);
        if (b == 0 && next & 0x80 == 0) || (b == 0xff && next & 0x80 != 0) {
            start += 1;
        } else {
            break;
        }
    }
    ber_tlv(out, 0x02, &bytes[start..]);
}

fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32) -> Zeroizing<[u8; 32]> {
    let mut first = Zeroizing::new(salt.to_vec());
    first.extend_from_slice(&1_u32.to_be_bytes());
    let mut u = hmac_sha256(password, &first);
    let mut acc = Zeroizing::new(*u);
    for _ in 1..iterations {
        u = hmac_sha256(password, &u[..]);
        for (a, b) in acc.iter_mut().zip(u.iter()) {
            *a ^= b;
        }
    }
    acc
}

impl Cred {
    /// The credential as a field value, unchanged (an API key header).
    pub fn field(&self) -> Seal {
        self.seal(Zeroizing::new(self.wire().to_vec()))
    }

    /// `Bearer <credential>`.
    pub fn bearer(&self) -> Seal {
        let mut v = Zeroizing::new(b"Bearer ".to_vec());
        v.extend_from_slice(self.wire());
        self.seal(v)
    }

    /// `Basic base64(user:credential)` (RFC 7617; the user's octets as they are).
    pub fn basic(&self, user: impl AsRef<[u8]>) -> Seal {
        let user = user.as_ref();
        let mut pair = Zeroizing::new(Vec::with_capacity(user.len() + 1 + self.len()));
        pair.extend_from_slice(user);
        pair.push(b':');
        pair.extend_from_slice(self.wire());
        let mut v = Zeroizing::new(b"Basic ".to_vec());
        v.extend_from_slice(&b64(&pair));
        self.seal(v)
    }

    /// HMAC-SHA256 of `data` keyed by the credential, as lowercase hex.
    pub fn hmac_sha256_hex(&self, data: &[u8]) -> Seal {
        let mac = hmac_sha256(self.wire(), data);
        self.seal(Zeroizing::new(hex::encode(&mac[..]).into_bytes()))
    }

    /// Whether `signature` is HMAC-SHA256 of `data` under the credential (constant time).
    pub fn verify_hmac_sha256(&self, data: &[u8], signature: &[u8]) -> bool {
        let mac = hmac_sha256(self.wire(), data);
        crate::constant_time_eq(&mac[..], signature)
    }

    /// Whether `presented` equals the credential, compared over SHA-256 digests so neither content
    /// nor length leaks through timing.
    pub fn verify_eq(&self, presented: &[u8]) -> bool {
        let a = digests::sha256(&[self.wire()]);
        let b = digests::sha256(&[presented]);
        crate::constant_time_eq(&a[..], &b[..])
    }

    /// `text` with every occurrence of the credential replaced by `[redacted]`: for a destination
    /// that echoes what it was sent (a server error quoting a password). Text without it comes
    /// back unchanged.
    pub fn redact_echo(&self, text: &str) -> String {
        let needle = self.wire();
        if needle.is_empty() || needle.len() > text.len() {
            return text.to_owned();
        }
        let hay = text.as_bytes();
        let mut out = Vec::with_capacity(hay.len());
        let mut i = 0;
        while i < hay.len() {
            if hay[i..].starts_with(needle) {
                out.extend_from_slice(b"[redacted]");
                i += needle.len();
            } else {
                out.push(hay[i]);
                i += 1;
            }
        }
        String::from_utf8(out).unwrap_or_else(|_| "[redacted]".to_owned())
    }

    fn pg_allows(&self, method: PgAuth, refused: Refused) -> Result<(), Refused> {
        if self.floor().pg().allows(method) {
            Ok(())
        } else {
            Err(refused)
        }
    }

    /// Postgres `PasswordMessage` carrying the password in clear (AuthenticationCleartextPassword).
    ///
    /// # Errors
    /// [`PG_CLEARTEXT_REFUSED`]: the operator's `require_auth` does not allow `password` (ruling
    /// S4; none written allows only SCRAM-SHA-256).
    pub fn pg_password_message(&self) -> Result<Seal, Refused> {
        self.pg_allows(PgAuth::Password, PG_CLEARTEXT_REFUSED)?;
        Ok(pg_message(self, self.wire()))
    }

    /// Postgres `PasswordMessage` for AuthenticationMD5Password:
    /// `"md5" + hex(md5(hex(md5(password + user)) + salt))`.
    ///
    /// # Errors
    /// [`PG_MD5_REFUSED`]: the operator's `require_auth` does not allow `md5` (ruling S4).
    pub fn pg_md5_message(&self, user: &str, salt: [u8; 4]) -> Result<Seal, Refused> {
        self.pg_allows(PgAuth::Md5, PG_MD5_REFUSED)?;
        let inner = digests::md5(&[self.wire(), user.as_bytes()]);
        let inner_hex = Zeroizing::new(hex::encode(&inner[..]).into_bytes());
        let outer = digests::md5(&[&inner_hex, &salt]);
        let mut body = Zeroizing::new(b"md5".to_vec());
        body.extend_from_slice(hex::encode(&outer[..]).as_bytes());
        Ok(pg_message(self, &body))
    }

    /// Postgres `SASLResponse` carrying the SCRAM-SHA-256 client-final message (RFC 5802, 7677),
    /// and the link that checks the server-final message. `client_first_bare` is what the client
    /// sent (`n=,r=<nonce>`); `server_first` is the server's reply; `channel_binding` is the GS2
    /// header plus any binding data (`b"n,,"` without binding).
    ///
    /// # Errors
    /// The server's message is malformed, does not extend the client nonce, or names an iteration
    /// count outside 4096..=1000000; or the operator's `require_auth` leaves SCRAM-SHA-256 out.
    pub fn pg_scram_sha256(
        &self,
        client_first_bare: &str,
        server_first: &str,
        channel_binding: &[u8],
    ) -> Result<(Seal, ScramLink), Refused> {
        self.pg_allows(PgAuth::ScramSha256, PG_SCRAM_REFUSED)?;
        let (client_final, link) =
            self.scram_sha256(client_first_bare, server_first, channel_binding)?;
        Ok((pg_message_raw(self, &client_final), link))
    }

    fn scram_sha256(
        &self,
        client_first_bare: &str,
        server_first: &str,
        channel_binding: &[u8],
    ) -> Result<(Bytes, ScramLink), Refused> {
        const BAD: Refused = Refused("the SCRAM server-first message is malformed");
        let attr = |msg: &'_ str, k: &str| -> Option<String> {
            msg.split(',')
                .find_map(|a| a.strip_prefix(k).map(str::to_owned))
        };
        let cnonce = attr(client_first_bare, "r=")
            .ok_or(Refused("the SCRAM client-first message has no nonce"))?;
        let nonce = attr(server_first, "r=").ok_or(BAD)?;
        if !nonce.starts_with(&cnonce) || nonce.len() <= cnonce.len() {
            return Err(Refused(
                "the SCRAM server nonce does not extend the client nonce",
            ));
        }
        let salt = base64::engine::general_purpose::STANDARD
            .decode(attr(server_first, "s=").ok_or(BAD)?)
            .map_err(|_| BAD)?;
        let iterations: u32 = attr(server_first, "i=")
            .ok_or(BAD)?
            .parse()
            .map_err(|_| BAD)?;
        if !(4096..=1_000_000).contains(&iterations) {
            return Err(Refused(
                "the SCRAM iteration count is outside 4096..=1000000",
            ));
        }
        let salted = pbkdf2_sha256(self.wire(), &salt, iterations);
        let client_key = hmac_sha256(&salted[..], b"Client Key");
        let stored_key = digests::sha256(&[&client_key[..]]);
        let server_key = hmac_sha256(&salted[..], b"Server Key");
        let without_proof = format!(
            "c={},r={nonce}",
            base64::engine::general_purpose::STANDARD.encode(channel_binding)
        );
        let auth_message = format!("{client_first_bare},{server_first},{without_proof}");
        let client_sig = hmac_sha256(&stored_key[..], auth_message.as_bytes());
        let mut proof = Zeroizing::new([0_u8; 32]);
        for ((p, k), s) in proof
            .iter_mut()
            .zip(client_key.iter())
            .zip(client_sig.iter())
        {
            *p = k ^ s;
        }
        let server_sig = hmac_sha256(&server_key[..], auth_message.as_bytes());
        let mut out = Zeroizing::new(without_proof.into_bytes());
        out.extend_from_slice(b",p=");
        out.extend_from_slice(&b64(&proof[..]));
        Ok((out, ScramLink(Held::new(server_sig))))
    }

    /// The RESP `AUTH [user] <password>` command, whole.
    pub fn resp_auth(&self, user: Option<&str>) -> Seal {
        let mut args: Vec<&[u8]> = vec![b"AUTH"];
        if let Some(u) = user {
            args.push(u.as_bytes());
        }
        args.push(self.wire());
        let mut out = Zeroizing::new(Vec::new());
        out.extend_from_slice(format!("*{}\r\n", args.len()).as_bytes());
        for a in args {
            out.extend_from_slice(format!("${}\r\n", a.len()).as_bytes());
            out.extend_from_slice(a);
            out.extend_from_slice(b"\r\n");
        }
        self.seal(out)
    }

    /// An LDAP simple `BindRequest` (RFC 4511 4.2) for `dn`, message id `id`, whole.
    pub fn ldap_simple_bind(&self, id: i32, dn: &str) -> Seal {
        let mut op = Zeroizing::new(Vec::new());
        ber_int(&mut op, 3);
        ber_tlv(&mut op, 0x04, dn.as_bytes());
        ber_tlv(&mut op, 0x80, self.wire());
        let mut content = Zeroizing::new(Vec::new());
        ber_int(&mut content, i64::from(id));
        ber_tlv(&mut content, 0x60, &op);
        let mut out = Zeroizing::new(Vec::new());
        ber_tlv(&mut out, 0x30, &content);
        self.seal(out)
    }

    /// RULING S4: `mysql_old_password` and `mysql_clear_password` only as the operator allowed.
    fn mysql_allows(&self, auth: MysqlAuth) -> Result<(), Refused> {
        let floor = self.floor();
        match auth {
            MysqlAuth::Old if !floor.mysql_old() => Err(MYSQL_OLD_REFUSED),
            MysqlAuth::Clear if !floor.mysql_clear() => Err(MYSQL_CLEAR_REFUSED),
            _ => Ok(()),
        }
    }

    /// A seal of the password in clear (or encrypted to a key nobody pinned): it goes out in the
    /// open only when `open` (the operator's socket, pin or switch), else only secured (ruling S5).
    fn mysql_seal(&self, bytes: Bytes, open: bool) -> Seal {
        let seal = self.seal(bytes);
        if open {
            seal
        } else {
            seal.require_secure()
        }
    }

    fn mysql_scramble(&self, auth: MysqlAuth, nonce: &[u8]) -> Bytes {
        let pw = self.wire();
        if pw.is_empty() {
            return Zeroizing::new(Vec::new());
        }
        match auth {
            MysqlAuth::Native => {
                let h1 = digests::sha1(&[pw]);
                let h2 = digests::sha1(&[&h1[..]]);
                let h3 = digests::sha1(&[nonce, &h2[..]]);
                Zeroizing::new(h1.iter().zip(h3.iter()).map(|(a, b)| a ^ b).collect())
            }
            MysqlAuth::CachingSha2 => {
                let h1 = digests::sha256(&[pw]);
                let h2 = digests::sha256(&[&h1[..]]);
                let h3 = digests::sha256(&[&h2[..], nonce]);
                Zeroizing::new(h1.iter().zip(h3.iter()).map(|(a, b)| a ^ b).collect())
            }
            MysqlAuth::Old => {
                let mut out = scramble_323(&nonce[..nonce.len().min(8)], pw);
                out.push(0);
                out
            }
            MysqlAuth::Clear => {
                let mut out = Zeroizing::new(pw.to_vec());
                out.push(0);
                out
            }
        }
    }

    /// A MySQL `HandshakeResponse41` packet, whole, header included.
    ///
    /// # Errors
    /// The packet would not fit one MySQL packet; or it answers `mysql_old_password` or
    /// `mysql_clear_password` and the operator did not allow it ([`MYSQL_OLD_REFUSED`],
    /// [`MYSQL_CLEAR_REFUSED`]).
    pub fn mysql_handshake_response(&self, h: &MysqlHandshake<'_>) -> Result<Seal, Refused> {
        self.mysql_allows(h.auth)?;
        let mut caps = h.capabilities | CLIENT_PLUGIN_AUTH;
        if h.database.is_some() {
            caps |= CLIENT_CONNECT_WITH_DB;
        } else {
            caps &= !CLIENT_CONNECT_WITH_DB;
        }
        if h.attrs.is_empty() {
            caps &= !CLIENT_CONNECT_ATTRS;
        } else {
            caps |= CLIENT_CONNECT_ATTRS;
        }
        let scramble = self.mysql_scramble(h.auth, h.nonce);
        let mut p = Zeroizing::new(Vec::new());
        p.extend_from_slice(&caps.to_le_bytes());
        p.extend_from_slice(&h.max_packet.to_le_bytes());
        p.push(h.collation);
        p.extend_from_slice(&[0; 23]);
        p.extend_from_slice(h.user);
        p.push(0);
        if caps & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA != 0 {
            lenenc(&mut p, scramble.len() as u64);
            p.extend_from_slice(&scramble);
        } else if caps & CLIENT_SECURE_CONNECTION != 0 {
            p.push(scramble.len() as u8);
            p.extend_from_slice(&scramble);
        } else {
            p.extend_from_slice(&scramble);
            p.push(0);
        }
        if let Some(db) = h.database {
            p.extend_from_slice(db);
            p.push(0);
        }
        p.extend_from_slice(h.auth.name());
        p.push(0);
        if !h.attrs.is_empty() {
            let total: u64 = h
                .attrs
                .iter()
                .map(|(k, v)| {
                    lenenc_len(k.len() as u64)
                        + k.len() as u64
                        + lenenc_len(v.len() as u64)
                        + v.len() as u64
                })
                .sum();
            lenenc(&mut p, total);
            for (k, v) in h.attrs {
                lenenc(&mut p, k.len() as u64);
                p.extend_from_slice(k);
                lenenc(&mut p, v.len() as u64);
                p.extend_from_slice(v);
            }
        }
        mysql_packet(h.seq, &p).map(|b| self.seal(b))
    }

    /// A MySQL auth-switch response packet for `auth` over the switch request's `nonce`, whole.
    ///
    /// # Errors
    /// `mysql_old_password` or `mysql_clear_password` the operator did not allow
    /// ([`MYSQL_OLD_REFUSED`], [`MYSQL_CLEAR_REFUSED`]); else never in practice (the scramble is at
    /// most 32 bytes).
    pub fn mysql_auth_switch_response(
        &self,
        seq: u8,
        auth: MysqlAuth,
        nonce: &[u8],
    ) -> Result<Seal, Refused> {
        self.mysql_allows(auth)?;
        let scramble = self.mysql_scramble(auth, nonce);
        mysql_packet(seq, &scramble).map(|b| self.seal(b))
    }

    /// A MySQL packet carrying the password in clear, NUL-terminated: `caching_sha2_password` full
    /// authentication over a secured or unix-socket link, or `mysql_clear_password`, whole.
    ///
    /// RULING S5: it goes out in the open only over the unix socket the operator's URL names, or
    /// when the operator enabled the cleartext plugin; otherwise the seal goes out only where the
    /// host connector reports the connection secured ([`Seal::secure_required`]).
    ///
    /// # Errors
    /// The password does not fit one MySQL packet.
    pub fn mysql_clear_packet(&self, seq: u8) -> Result<Seal, Refused> {
        let mut p = Zeroizing::new(self.wire().to_vec());
        p.push(0);
        let floor = self.floor();
        mysql_packet(seq, &p).map(|b| self.mysql_seal(b, floor.local() || floor.mysql_clear()))
    }
}

impl Cred {
    /// A MySQL packet for `caching_sha2_password` full authentication on a link with no TLS: the
    /// password (NUL-terminated) XORed with the `nonce`, RSA-OAEP-encrypted to the server's PEM
    /// public key, whole.
    ///
    /// RULING S5: the key comes from the server on a link with no TLS, so it is trusted only when
    /// the operator pinned it (`server_public_key_sha256`). With no pin the seal goes out in the
    /// open only over the operator's unix socket, else only where the host connector reports the
    /// connection secured ([`Seal::secure_required`]).
    ///
    /// # Errors
    /// An empty nonce, a key that does not parse, a key that is not the pinned one
    /// ([`MYSQL_RSA_PIN_MISMATCH`]), a password too long for the key, or no randomness for the
    /// OAEP seed.
    pub fn mysql_rsa_packet(
        &self,
        seq: u8,
        nonce: &[u8],
        server_key_pem: &[u8],
    ) -> Result<Seal, Refused> {
        if nonce.is_empty() {
            return Err(Refused("the server sent no nonce"));
        }
        let floor = self.floor();
        let pinned = match floor.rsa_pin() {
            Some(pin) => {
                let key = rsa::key_sha256(server_key_pem)?;
                if !crate::constant_time_eq(&key[..], &pin[..]) {
                    return Err(MYSQL_RSA_PIN_MISMATCH);
                }
                true
            }
            None => false,
        };
        let mut seed = Zeroizing::new([0_u8; 20]);
        getrandom::fill(&mut seed[..]).map_err(|_| Refused("no randomness for the OAEP seed"))?;
        let mut plain = Zeroizing::new(self.wire().to_vec());
        plain.push(0);
        for (i, b) in plain.iter_mut().enumerate() {
            *b ^= nonce[i % nonce.len()];
        }
        let ct = rsa::oaep_sha1(&plain, server_key_pem, &seed)?;
        mysql_packet(seq, &ct).map(|b| self.mysql_seal(b, pinned || floor.local()))
    }
}

fn hash_323(bytes: &[u8]) -> [u32; 2] {
    let (mut nr, mut add, mut nr2) = (1_345_345_333_u32, 7_u32, 0x1234_5671_u32);
    for &x in bytes.iter().filter(|b| **b != b' ' && **b != b'\t') {
        let tmp = u32::from(x);
        nr ^= (nr & 63)
            .wrapping_add(add)
            .wrapping_mul(tmp)
            .wrapping_add(nr << 8);
        nr2 = nr2.wrapping_add((nr2 << 8) ^ nr);
        add = add.wrapping_add(tmp);
    }
    [nr & 0x7fff_ffff, nr2 & 0x7fff_ffff]
}

/// The pre-4.1 `mysql_old_password` scramble (8 bytes), as the 1.5.5 driver computed it.
fn scramble_323(nonce: &[u8], password: &[u8]) -> Bytes {
    const MAX: u32 = 0x3FFF_FFFF;
    let (hp, hm) = (hash_323(password), hash_323(nonce));
    let (mut s1, mut s2) = ((hp[0] ^ hm[0]) % MAX, (hp[1] ^ hm[1]) % MAX);
    let mut rnd = || {
        s1 = (s1 * 3 + s2) % MAX;
        s2 = (s1 + s2 + 33) % MAX;
        f64::from(s1) / f64::from(MAX)
    };
    let mut out = Zeroizing::new(vec![0_u8; 8]);
    for x in out.iter_mut() {
        *x = ((rnd() * 31.0).floor() + 64.0) as u8;
    }
    let extra = (rnd() * 31.0).floor() as u8;
    for x in out.iter_mut() {
        *x ^= extra;
    }
    out
}

fn pg_message(c: &Cred, body: &[u8]) -> Seal {
    let mut b = Zeroizing::new(body.to_vec());
    b.push(0);
    pg_message_raw(c, &b)
}

fn pg_message_raw(c: &Cred, body: &[u8]) -> Seal {
    let mut out = Zeroizing::new(Vec::with_capacity(body.len() + 5));
    out.push(b'p');
    out.extend_from_slice(&((body.len() + 4) as i32).to_be_bytes());
    out.extend_from_slice(body);
    c.seal(out)
}

#[cfg(test)]
#[path = "../tests/chip_tests.rs"]
mod tests;
