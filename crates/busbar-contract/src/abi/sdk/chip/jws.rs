// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RS256 (RSASSA-PKCS1-v1_5 over SHA-256) under a PKCS #8 RSA private key the credential holds

use base64::Engine as _;

use super::Refused;
use crate::abi::sdk::cred::{Cred, Seal};
use crate::crypto;

/// The largest modulus the JWS signer accepts, in bytes (4096 bits).
const MAX_MODULUS_BYTES: usize = 512;

/// The `AlgorithmIdentifier` contents of rsaEncryption with its NULL parameters.
const RSA_ENCRYPTION_WITH_NULL: &[u8] = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";

/// One DER item of `b`: its tag, contents and the bytes after it. Definite, minimally encoded
/// lengths only (at most four length octets), as DER requires.
fn der_item(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = b.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let (octets, rest) = rest.split_at(n);
        if octets.first() == Some(&0) {
            return None;
        }
        let len = octets
            .iter()
            .fold(0_usize, |a, &x| (a << 8) | usize::from(x));
        if len < 0x80 {
            return None;
        }
        (len, rest)
    };
    (rest.len() >= len).then(|| {
        let (contents, after) = rest.split_at(len);
        (tag, contents, after)
    })
}

/// Whether `der` is exactly one PKCS #8 v1 `PrivateKeyInfo` (RFC 5208) over rsaEncryption:
/// version 0, the rsaEncryption algorithm, the private key, optional `[0]` attributes and nothing
/// else. The provider's parser also reads RFC 5958 v2 `OneAsymmetricKey`, which this signer
/// does not take.
fn pkcs8_v1_rsa(der: &[u8]) -> bool {
    let Some((0x30, info, [])) = der_item(der) else {
        return false;
    };
    let Some((0x02, [0], rest)) = der_item(info) else {
        return false;
    };
    let Some((0x30, algorithm, rest)) = der_item(rest) else {
        return false;
    };
    if algorithm != RSA_ENCRYPTION_WITH_NULL {
        return false;
    }
    let Some((0x04, _, rest)) = der_item(rest) else {
        return false;
    };
    rest.is_empty() || matches!(der_item(rest), Some((0xa0, _, [])))
}

fn signing_key(der: &[u8]) -> Result<crypto::rsa::SigningKey, ()> {
    if !pkcs8_v1_rsa(der) {
        return Err(());
    }
    let key = crypto::rsa::SigningKey::from_pkcs8(der).map_err(|_| ())?;
    if key.modulus_len() > MAX_MODULUS_BYTES {
        return Err(());
    }
    Ok(key)
}

impl Cred {
    /// Whether the credential is a supported PKCS #8 RSA private key.
    pub fn rsa_pkcs8_check(&self) -> Result<(), String> {
        signing_key(self.wire())
            .map(drop)
            .map_err(|()| crate::abi::sdk::cold::cred::not_a_pkcs8_rsa_key())
    }

    /// The length of [`Cred::jws_rs256`]'s answer under this key, found without signing: the
    /// modulus length in base64url without padding. `None` when the key is not one.
    pub(crate) fn jws_rs256_len(&self) -> Option<usize> {
        let key = signing_key(self.wire()).ok()?;
        base64::encoded_len(key.modulus_len(), false)
    }

    /// The RS256 signature of `signing_input`, base64url without padding.
    pub fn jws_rs256(&self, signing_input: &[u8]) -> Result<Seal, Refused> {
        let key =
            signing_key(self.wire()).map_err(|_| Refused("the key is not a PKCS #8 RSA key"))?;
        let sig = key
            .sign_pkcs1_sha256(signing_input)
            .map(crate::secure::SecureVec::from)
            .map_err(|_| Refused("RS256 signing failed"))?;
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&*sig);
        Ok(self.seal(crate::secure::SecureVec::from(encoded.into_bytes())))
    }
}
