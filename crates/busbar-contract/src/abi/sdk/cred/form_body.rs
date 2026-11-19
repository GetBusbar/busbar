// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! An `application/x-www-form-urlencoded` body whose credential values are the chip's: the

use crate::secure::{SecureString, SecureVec};

use super::{Cred, SealedWrite};

/// One form value.
#[expect(
    missing_debug_implementations,
    reason = "holds secret bytes: no Debug, so none can print"
)]
#[derive(Clone, PartialEq, Eq)]
pub enum FormValue {
    /// Public text.
    Public(String),
    /// A credential, written as its bytes form-encoded.
    Sealed(Cred),
    /// An RS256 JWS (RFC 7515) over `signing_input` (`header.claims`, base64url) under the PKCS #8
    /// RSA key `key`: `signing_input.signature`.
    JwsRs256 {
        /// The private key (PKCS #8 DER).
        key: Cred,
        /// `base64url(header).base64url(claims)`.
        signing_input: String,
    },
}

/// A form body: pairs in order, encoded as `serde_urlencoded` writes them (space as `+`, every
/// byte but ASCII alphanumerics and `*-._` as upper-case `%XX`).
#[derive(Clone, Default)]
pub struct FormBody {
    /// The pairs; a name is held in custody and wiped when the form drops.
    pairs: Vec<(SecureString, FormValue)>,
    /// The encoded body's length, kept up to date as each pair is appended (an RS256 signature
    /// counted at its key's modulus length), so encoding sizes its one buffer without a sweep.
    len: usize,
    /// Whether `len` overflowed on the way.
    too_large: bool,
    /// The union of the credential values' connection-security requirements.
    secure: bool,
}

/// Equal when the pairs are equal: the kept aggregates follow from them.
impl PartialEq for FormBody {
    fn eq(&self, other: &Self) -> bool {
        self.pairs == other.pairs
    }
}

impl Eq for FormBody {}

impl core::fmt::Debug for FormBody {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_list()
            .entries(self.pairs.iter().map(|(n, _)| n.as_str()))
            .finish()
    }
}

impl Drop for FormBody {
    fn drop(&mut self) {
        // A name is a `SecureString`: it wipes itself as it drops, right after this.
        for (_, value) in &mut self.pairs {
            if let FormValue::Public(v) = value {
                crate::secure::wipe_string(v);
            }
            if let FormValue::JwsRs256 { signing_input, .. } = value {
                crate::secure::wipe_string(signing_input);
            }
        }
    }
}

impl zeroize::ZeroizeOnDrop for FormBody {}

const fn kept(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'*' | b'-' | b'.' | b'_')
}

fn encoded_len(bytes: &[u8]) -> Option<usize> {
    bytes.iter().try_fold(0usize, |len, &b| {
        len.checked_add(if kept(b) || b == b' ' { 1 } else { 3 })
    })
}

fn encode(out: &mut SecureVec, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &b in bytes {
        if kept(b) {
            out.extend_from_slice(&[b]);
        } else if b == b' ' {
            out.extend_from_slice(b"+");
        } else {
            out.extend_from_slice(&[b'%', HEX[usize::from(b >> 4)], HEX[usize::from(b & 15)]]);
        }
    }
}

impl FormBody {
    /// An empty form.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append `name=value` (public).
    #[must_use]
    pub fn public(self, name: &str, value: &str) -> Self {
        self.push(name, FormValue::Public(value.to_owned()))
    }

    /// Append `name=<the credential>`.
    #[must_use]
    pub fn sealed(self, name: &str, value: &Cred) -> Self {
        self.push(name, FormValue::Sealed(value.clone()))
    }

    /// Append `name=<value>`.
    #[must_use]
    pub fn value(self, name: &str, value: FormValue) -> Self {
        self.push(name, value)
    }

    /// Append the pair, keeping the encoded length and the security requirement up to date.
    fn push(mut self, name: &str, value: FormValue) -> Self {
        let value_len = match &value {
            FormValue::Public(v) => encoded_len(v.as_bytes()),
            FormValue::Sealed(c) => {
                self.secure |= c.secure_required();
                encoded_len(c.wire())
            }
            FormValue::JwsRs256 { key, signing_input } => {
                // The signature's seal carries the key's requirement. It is counted at the key's
                // signature length (base64url: every byte is kept as it is); a key that is not one
                // adds nothing here and is refused as the body is encoded.
                self.secure |= key.secure_required();
                encoded_len(signing_input.as_bytes())
                    .and_then(|n| n.checked_add(1))
                    .and_then(|n| n.checked_add(key.jws_rs256_len().unwrap_or(0)))
            }
        };
        let separators = usize::from(!self.pairs.is_empty()) + 1;
        let pair_len = encoded_len(name.as_bytes())
            .and_then(|n| n.checked_add(separators))
            .zip(value_len)
            .and_then(|(name_len, value_len)| name_len.checked_add(value_len));
        match pair_len.and_then(|n| self.len.checked_add(n)) {
            Some(len) => self.len = len,
            None => self.too_large = true,
        }
        self.pairs.push((SecureString::from(name), value));
        self
    }

    /// The names, in order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.pairs.iter().map(|(n, _)| n.as_str())
    }

    /// The encoded body, ready to write.
    pub fn encoded(&self) -> Result<SealedWrite, crate::abi::sdk::chip::Refused> {
        use crate::abi::sdk::chip::Refused;

        let too_large = || Refused("the encoded form body is too large");
        if self.too_large {
            return Err(too_large());
        }
        // Sized by the lengths kept as each pair was appended: the buffer never grows.
        let mut out = SecureVec::with_capacity(self.len).map_err(|_| too_large())?;
        for (i, (name, value)) in self.pairs.iter().enumerate() {
            if i > 0 {
                out.extend_from_slice(b"&");
            }
            encode(&mut out, name.as_bytes());
            out.extend_from_slice(b"=");
            match value {
                FormValue::Public(v) => encode(&mut out, v.as_bytes()),
                FormValue::Sealed(c) => encode(&mut out, c.wire()),
                FormValue::JwsRs256 { key, signing_input } => {
                    let sig = key.jws_rs256(signing_input.as_bytes())?;
                    encode(&mut out, signing_input.as_bytes());
                    encode(&mut out, b".");
                    encode(&mut out, sig.wire());
                }
            }
        }
        Ok(SealedWrite::from_bytes(out, self.secure))
    }
}

