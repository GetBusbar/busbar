// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! oauth-as's crypto through busbar's facade (CRYPTO-SEAM §2.8, decision 228). oauth-as is built with
//! `default-features = false` (no crypto crate of its own) and every server gets [`FacadeCrypto`], so
//! its SHA-256, HMAC, randomness, comparisons and JWS verification run on the linked crypto backend.

use busbar_contract::crypto;
use oauth_as::crypto::{CryptoError, CryptoProvider};
use oauth_as::jwt::{JwsAlg, JwsVerifier};

use crate::signer::{Es256Verifier, Ps256Verifier};

/// The one `oauth_as::crypto::CryptoProvider` busbar installs.
#[derive(Clone, Copy, Debug, Default)]
pub struct FacadeCrypto;

static ES256: Es256Verifier = Es256Verifier;
static PS256: Ps256Verifier = Ps256Verifier;

impl CryptoProvider for FacadeCrypto {
    fn validate(&self) -> Result<(), CryptoError> {
        crypto::self_test().map_err(|e| match e {
            crypto::Error::Unsupported(u) => CryptoError::UnsupportedAlgorithm(u.alg),
            _ => CryptoError::MissingProvider,
        })
    }

    fn sha256(&self, input: &[u8]) -> [u8; 32] {
        crypto::sha256(input)
    }

    /// oauth-as 1.1.0 declares this infallible. The keys it reaches are `client_secret_jwt` secrets,
    /// which oauth-as refuses below 22 characters at registration and on deserialize, so no backend
    /// (FIPS refuses below 14 bytes) refuses one. A refusal is never answered with a filler MAC (a
    /// constant tag would let a forged assertion verify); it stops the request instead.
    fn hmac_sha256(&self, key: &[u8], message: &[u8]) -> [u8; 32] {
        match crypto::hmac_sha256(key, message) {
            Ok(tag) => tag,
            Err(e) => panic!(
                "crypto backend {} refused HMAC-SHA256: {e}",
                crypto::BACKEND
            ),
        }
    }

    fn fill_random(&self, output: &mut [u8]) -> Result<(), CryptoError> {
        crypto::fill(output).map_err(|_| CryptoError::EntropyUnavailable)
    }

    fn ct_eq(&self, a: &[u8], b: &[u8]) -> bool {
        crypto::ct_eq(a, b)
    }

    /// ES256 and PS256 only (FAPI 2.0 forbids RS256; no EdDSA client keys): every other algorithm
    /// has no verifier, so oauth-as refuses it and leaves it out of discovery.
    fn verifier(&self, alg: JwsAlg) -> Option<&dyn JwsVerifier> {
        match alg {
            JwsAlg::Es256 => Some(&ES256),
            JwsAlg::Ps256 => Some(&PS256),
            _ => None,
        }
    }
}

#[cfg(test)]
#[path = "tests/crypto_provider_tests.rs"]
mod tests;
