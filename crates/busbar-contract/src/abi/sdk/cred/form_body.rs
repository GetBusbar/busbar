// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! An `application/x-www-form-urlencoded` body whose credential values are the chip's: the

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

impl Drop for FormBody {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for (name, value) in &mut self.pairs {
            #[cfg(test)]
            wipe_tests::watch(name.as_bytes());
            name.zeroize();
            if let FormValue::Public(v) = value {
                #[cfg(test)]
                wipe_tests::watch(v.as_bytes());
                v.zeroize();
            }
            if let FormValue::JwsRs256 { signing_input, .. } = value {
                #[cfg(test)]
                wipe_tests::watch(signing_input.as_bytes());
                signing_input.zeroize();
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
        #[cfg(test)]
        wipe_tests::watch(out);
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

    pub fn encoded(&self) -> Result<SealedWrite, crate::abi::sdk::chip::Refused> {
        use crate::abi::sdk::chip::Refused;

        let too_large = || Refused("the encoded form body is too large");
        let mut signatures = Vec::new();
        signatures
            .try_reserve_exact(
                self.pairs
                    .iter()
                    .filter(|(_, value)| matches!(value, FormValue::JwsRs256 { .. }))
                    .count(),
            )
            .map_err(|_| too_large())?;
        let mut len = 0usize;
        let mut secure = false;
        for (i, (name, value)) in self.pairs.iter().enumerate() {
            let mut add = |n: usize| -> Result<(), Refused> {
                len = len.checked_add(n).ok_or_else(too_large)?;
                Ok(())
            };
            add(usize::from(i > 0))?;
            add(encoded_len(name.as_bytes()).ok_or_else(too_large)?)?;
            add(1)?;
            match value {
                FormValue::Public(v) => {
                    add(encoded_len(v.as_bytes()).ok_or_else(too_large)?)?;
                }
                FormValue::Sealed(c) => {
                    secure |= c.secure_required();
                    add(encoded_len(c.wire()).ok_or_else(too_large)?)?;
                }
                FormValue::JwsRs256 { key, signing_input } => {
                    let sig = key.jws_rs256(signing_input.as_bytes())?;
                    secure |= sig.secure_required();
                    add(encoded_len(signing_input.as_bytes()).ok_or_else(too_large)?)?;
                    add(1)?;
                    add(encoded_len(sig.wire()).ok_or_else(too_large)?)?;
                    signatures.push(sig);
                }
            }
        }
        let mut out = Zeroizing::new(Vec::new());
        out.try_reserve_exact(len).map_err(|_| too_large())?;
        let mut signatures = signatures.iter();
        for (i, (name, value)) in self.pairs.iter().enumerate() {
            if i > 0 {
                out.push(b'&');
            }
            encode(&mut out, name.as_bytes());
            out.push(b'=');
            match value {
                FormValue::Public(v) => encode(&mut out, v.as_bytes()),
                FormValue::Sealed(c) => encode(&mut out, c.wire()),
                FormValue::JwsRs256 { signing_input, .. } => {
                    encode(&mut out, signing_input.as_bytes());
                    encode(&mut out, b".");
                    encode(
                        &mut out,
                        signatures.next().expect("prepared signature").wire(),
                    );
                }
            }
        }
        #[cfg(test)]
        wipe_tests::watch(&out);
        Ok(SealedWrite::from_bytes(out, secure))
    }
}

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "../tests/form_body_wipe_tests.rs"]
mod wipe_tests;
