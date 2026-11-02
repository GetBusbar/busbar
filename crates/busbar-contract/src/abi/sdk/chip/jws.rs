// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RS256 (RSASSA-PKCS1-v1_5 over SHA-256) under a PKCS #8 RSA private key the credential holds

use base64::Engine as _;
use zeroize::Zeroizing;

use super::Refused;
use crate::abi::sdk::cred::{Cred, Seal};

mod rsa;

impl Cred {
    /// Whether the credential is a supported PKCS #8 RSA private key.

    pub fn rsa_pkcs8_check(&self) -> Result<(), String> {
        rsa::Key::from_pkcs8(self.wire())
            .map(drop)
            .map_err(|_| "the key is not a supported PKCS #8 RSA key".to_owned())
    }

    /// The RS256 signature of `signing_input`, base64url without padding.

    pub fn jws_rs256(&self, signing_input: &[u8]) -> Result<Seal, Refused> {
        let mut key = rsa::Key::from_pkcs8(self.wire())
            .map_err(|_| Refused("the key is not a PKCS #8 RSA key"))?;
        let sig = key
            .sign(signing_input)
            .map_err(|_| Refused("RS256 signing failed"))?;
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&*sig);
        Ok(self.seal(Zeroizing::new(encoded.into_bytes())))
    }
}
