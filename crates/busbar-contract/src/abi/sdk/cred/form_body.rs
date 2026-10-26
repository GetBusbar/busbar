// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! An `application/x-www-form-urlencoded` body whose credential values are the chip's: the
//! plugin names the pairs, the SDK encodes them, the sealed values only where they go out.

use zeroize::Zeroizing;

use super::{Cred, SealedWrite};

/// One form value.
#[allow(missing_debug_implementations)]
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
#[derive(Clone, PartialEq, Eq, Default)]
pub struct FormBody {
    pairs: Vec<(String, FormValue)>,
}

impl core::fmt::Debug for FormBody {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_list()
            .entries(self.pairs.iter().map(|(n, _)| n))
            .finish()
    }
}

// The public values travel with the credential (an authorization code, a PKCE verifier): wiped
// on drop with it.
impl Drop for FormBody {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for (name, value) in &mut self.pairs {
            name.zeroize();
            if let FormValue::Public(v) = value {
                v.zeroize();
            }
            if let FormValue::JwsRs256 { signing_input, .. } = value {
                signing_input.zeroize();
            }
        }
    }
}

impl zeroize::ZeroizeOnDrop for FormBody {}

const fn kept(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'*' | b'-' | b'.' | b'_')
}

fn encode(out: &mut Vec<u8>, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &b in bytes {
        if kept(b) {
            out.push(b);
        } else if b == b' ' {
            out.push(b'+');
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
    pub fn public(mut self, name: &str, value: &str) -> Self {
        self.pairs
            .push((name.to_owned(), FormValue::Public(value.to_owned())));
        self
    }

    /// Append `name=<the credential>`.
    #[must_use]
    pub fn sealed(mut self, name: &str, value: &Cred) -> Self {
        self.pairs
            .push((name.to_owned(), FormValue::Sealed(value.clone())));
        self
    }

    /// Append `name=<value>`.
    #[must_use]
    pub fn value(mut self, name: &str, value: FormValue) -> Self {
        self.pairs.push((name.to_owned(), value));
        self
    }

    /// The names, in order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.pairs.iter().map(|(n, _)| n.as_str())
    }

    /// The encoded body, ready to write.
    ///
    /// # Errors
    /// A signature could not be made.
    pub fn encoded(&self) -> Result<SealedWrite, crate::abi::sdk::chip::Refused> {
        let mut out = Zeroizing::new(Vec::new());
        let mut secure = false;
        for (i, (name, value)) in self.pairs.iter().enumerate() {
            if i > 0 {
                out.push(b'&');
            }
            encode(&mut out, name.as_bytes());
            out.push(b'=');
            match value {
                FormValue::Public(v) => encode(&mut out, v.as_bytes()),
                FormValue::Sealed(c) => {
                    secure |= c.secure_required();
                    encode(&mut out, c.wire());
                }
                FormValue::JwsRs256 { key, signing_input } => {
                    let sig = key.jws_rs256(signing_input.as_bytes())?;
                    secure |= sig.secure_required();
                    encode(&mut out, signing_input.as_bytes());
                    encode(&mut out, b".");
                    encode(&mut out, sig.wire());
                }
            }
        }
        Ok(SealedWrite::from_bytes(out, secure))
    }
}
