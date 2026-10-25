// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A RECOVERABLE CREDENTIAL AT REST (CHIP-DESIGN v4.1 change 1): the store holds only ciphertext.
//!
//! A recoverable credential (a signed-request secret its verifier re-derives from) cannot be a
//! one-way digest, so before 1.6.0 it crossed the store ABI (`put_credential`,
//! `put_key_with_credential`, `list_credentials`) and sat in every store as `v1:plain:<secret>`.
//! Now governance seals it before the store sees it, as
//! `v1:aead:<kid>:<nonce>:<ciphertext>` (base64url, no padding): AES-256-GCM under a key-encryption
//! key HKDF-SHA256-derived from the node's token-signing key (label [`LABEL`]), with the row's
//! identity (`id`, `key_id`, `kind`, `public_id`) as associated data, so a sealed secret moved to
//! another row does not open. Minting one already needs the signing key, so no new refusal exists.
//!
//! A row written before 1.6.0 (`v1:plain:`) still authenticates; the first read of one per process
//! WARNs, naming no secret. A sealed row whose `kid` is not this node's signing key, or that does
//! not open, answers as an unknown credential and WARNs once, naming the `kid`.

use std::sync::atomic::{AtomicBool, Ordering};

use base64::Engine as _;
use busbar_contract::records::CredentialMeta;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::hkdf;
use zeroize::Zeroizing;

/// The HKDF label the key-encryption key is expanded under.
pub const LABEL: &[u8] = b"busbar credential-at-rest v1";

const PLAIN: &str = "v1:plain:";
const AEAD: &str = "v1:aead:";

static LEGACY_WARNED: AtomicBool = AtomicBool::new(false);
static FOREIGN_WARNED: AtomicBool = AtomicBool::new(false);

/// The key recoverable credentials are sealed under at rest. No `Clone`, no accessor.
pub struct CredentialKek {
    kid: String,
    key: LessSafeKey,
}

impl std::fmt::Debug for CredentialKek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialKek")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// The row identity a sealed secret is bound to.
fn aad(meta: &CredentialMeta) -> Vec<u8> {
    let mut a = Vec::new();
    for part in [&meta.id, &meta.key_id, &meta.kind, &meta.public_id] {
        a.extend_from_slice(&(part.len() as u64).to_be_bytes());
        a.extend_from_slice(part.as_bytes());
    }
    a
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
}

impl CredentialKek {
    /// Derive the key from the signing key `material`, whose id is `kid`.
    #[must_use]
    pub fn derive(kid: &str, material: &[u8]) -> Self {
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(material);
        let mut raw = Zeroizing::new([0_u8; 32]);
        prk.expand(&[LABEL], Len(raw.len()))
            .and_then(|okm| okm.fill(&mut raw[..]))
            .expect("32 bytes is within HKDF-SHA256's output bound");
        let key = UnboundKey::new(&AES_256_GCM, &raw[..]).expect("an AES-256 key is 32 bytes");
        Self {
            kid: kid.to_string(),
            key: LessSafeKey::new(key),
        }
    }

    /// Seal `plain` for the row `meta`: the envelope the store keeps.
    ///
    /// # Errors
    /// The CSPRNG is unavailable.
    pub fn seal(&self, meta: &CredentialMeta, plain: &[u8]) -> Result<String, String> {
        let mut nonce = [0_u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|e| format!("CSPRNG unavailable: {e}"))?;
        let mut buf = Zeroizing::new(plain.to_vec());
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad(meta)),
                &mut *buf,
            )
            .map_err(|_| "the credential could not be sealed".to_string())?;
        Ok(format!(
            "{AEAD}{}:{}:{}",
            self.kid,
            b64().encode(nonce),
            b64().encode(&buf[..])
        ))
    }

    /// Open a sealed envelope for the row `meta`. `None`: not this key's, or it does not open.
    fn open_sealed(&self, meta: &CredentialMeta, rest: &str) -> Option<Zeroizing<String>> {
        let mut parts = rest.splitn(3, ':');
        let (kid, nonce, ct) = (parts.next()?, parts.next()?, parts.next()?);
        if kid != self.kid {
            return None;
        }
        let nonce: [u8; NONCE_LEN] = b64().decode(nonce).ok()?.try_into().ok()?;
        let mut buf = Zeroizing::new(b64().decode(ct).ok()?);
        let plain = self
            .key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad(meta)),
                &mut buf[..],
            )
            .ok()?;
        let text = std::str::from_utf8(plain).ok()?.to_string();
        Some(Zeroizing::new(text))
    }
}

/// The secret a stored envelope holds for the row `meta`, under `kek` (the node's, if it signs).
/// `None`: an envelope this node cannot open (sealed under another signing key, tampered, or of
/// an unknown scheme); the caller answers it as an unknown credential.
pub fn open(
    kek: Option<&CredentialKek>,
    meta: &CredentialMeta,
    envelope: &str,
) -> Option<Zeroizing<String>> {
    if let Some(plain) = envelope.strip_prefix(PLAIN) {
        if !LEGACY_WARNED.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                kind = %meta.kind,
                "a recoverable credential is stored in the clear (written before 1.6.0); it still \
                 authenticates, and a credential minted now is stored sealed"
            );
        }
        return Some(Zeroizing::new(plain.to_string()));
    }
    let rest = envelope.strip_prefix(AEAD)?;
    let opened = kek.and_then(|k| k.open_sealed(meta, rest));
    if opened.is_none() && !FOREIGN_WARNED.swap(true, Ordering::Relaxed) {
        let kid = rest.split(':').next().unwrap_or_default();
        tracing::warn!(
            kind = %meta.kind,
            sealed_under = %kid,
            node_kid = %kek.map(|k| k.kid.as_str()).unwrap_or("none"),
            "a recoverable credential does not open under this node's signing key, so it does not \
             authenticate: it was sealed under another signing key, or its row was altered"
        );
    }
    opened
}

/// Whether `envelope` is in the clear (a pre-1.6.0 row).
#[must_use]
pub fn is_plain(envelope: &str) -> bool {
    envelope.starts_with(PLAIN)
}

#[cfg(test)]
#[path = "tests/at_rest_tests.rs"]
mod tests;
