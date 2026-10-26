// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RS256 (RSASSA-PKCS1-v1_5 over SHA-256) under a PKCS #8 RSA private key the credential holds
//! a JWT-bearer assertion's signature (RFC 7515, 7523).

use base64::Engine as _;
use zeroize::Zeroizing;

use super::Refused;
use crate::abi::sdk::cred::{Cred, Seal};

impl Cred {
    /// Whether the credential is a PKCS #8 RSA private key ring accepts; `Err` is ring's words
    /// (no key material in them).
    ///
    /// # Errors
    /// It is not.
    pub fn rsa_pkcs8_check(&self) -> Result<(), String> {
        ring::signature::RsaKeyPair::from_pkcs8(self.wire())
            .map(drop)
            .map_err(|e| e.to_string())
    }

    /// The RS256 signature of `signing_input`, base64url without padding.
    ///
    /// # Errors
    /// The key is not a PKCS #8 RSA key, or signing failed.
    pub fn jws_rs256(&self, signing_input: &[u8]) -> Result<Seal, Refused> {
        let key = ring::signature::RsaKeyPair::from_pkcs8(self.wire())
            .map_err(|_| Refused("the key is not a PKCS #8 RSA key"))?;
        let mut sig = Zeroizing::new(vec![0_u8; key.public().modulus_len()]);
        key.sign(
            &ring::signature::RSA_PKCS1_SHA256,
            &ring::rand::SystemRandom::new(),
            signing_input,
            &mut sig,
        )
        .map_err(|_| Refused("RS256 signing failed"))?;
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&*sig);
        Ok(self.seal(Zeroizing::new(encoded.into_bytes())))
    }
}
