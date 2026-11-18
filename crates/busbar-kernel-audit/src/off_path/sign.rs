// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Loading the audit signing key (once, when the node is configured) and signing a ledger checkpoint
//! body for its owned row (once per checkpoint flush); never per request.

use busbar_contract::crypto::ed25519::SigningKey;

use crate::sign::{
    checkpoint_preimage, from_hex_secret, key_id_of, AuditKeySet, AuditSigningKey, KeyError,
};

impl AuditSigningKey {
    /// Build one from a 32-byte ed25519 seed.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        // PANIC: any 32-byte seed is a valid RFC 8032 seed; only a backend refusing Ed25519 outright
        // can fail here, and a node without its audit signature cannot run.
        let inner = SigningKey::from_seed(seed)
            .unwrap_or_else(|e| panic!("crypto backend refused an Ed25519 seed: {e}"));
        let key_id = std::sync::Arc::from(key_id_of(&inner.verifying_key()));
        AuditSigningKey::from_parts(inner, key_id)
    }

    /// A 32-BYTE KEY DERIVED FROM THE KEYSET SEED: HKDF-SHA256 with the seed as input keying
    /// material, under `salt` and `info` (RFC 5869). Runs once per boot for each key a node
    /// derives (`records.user`'s `K_user`, ADMIN-API-1.6 §3.5); the caller holds the result as a
    /// secret and never serves it.
    #[must_use]
    pub fn derived_key(&self, salt: &[u8], info: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        // PANIC: HKDF-SHA256 with a 32-byte key and a 32-byte output is inside every backend's
        // bounds; only a backend refusing HKDF outright can fail here.
        busbar_contract::crypto::hkdf_sha256(salt, self.seed_bytes(), info, &mut out)
            .unwrap_or_else(|e| panic!("crypto backend refused HKDF-SHA256: {e}"));
        out
    }

    /// Build one from 64 lowercase hex characters. The decoded seed is held where it is wiped when
    /// dropped.
    pub fn from_hex_seed(text: &str) -> Result<Self, KeyError> {
        let seed = from_hex_secret::<32>(text.trim())?;
        Ok(AuditSigningKey::from_seed(&seed))
    }

    /// Sign one ledger checkpoint's body: 64 raw ed25519 signature bytes over its preimage, owned for
    /// the checkpoint row. Runs once per checkpoint the unit flusher writes, never per request.
    #[must_use]
    pub fn sign_checkpoint_body(&self, body: &[u8]) -> Vec<u8> {
        self.sign_checkpoint_raw(body).to_vec()
    }
}

impl AuditKeySet {
    /// Check one unit checkpoint's signature against EVERY key in the set. A unit checkpoint record
    /// does not say which key signed it, so each key the node has held is tried. Its one caller
    /// reads those records back (`busbar-kernel` `off_path/governance/unit_checkpoint_store.rs`:
    /// restore, replay and the flusher's own re-read), never per request; a record that names its
    /// key (the response intent) is verified by that key alone
    /// ([`crate::sign::AuditVerifyingKey::verify_checkpoint_body`]).
    pub fn verify_checkpoint_body(&self, body: &[u8], signature: &[u8]) -> Result<(), KeyError> {
        if signature.len() != 64 {
            return Err(KeyError::MalformedSignature);
        }
        let preimage = checkpoint_preimage(body);
        if self
            .keys()
            .iter()
            .any(|k| k.verify_raw(&preimage, signature).is_ok())
        {
            Ok(())
        } else {
            Err(KeyError::BadSignature)
        }
    }
}
