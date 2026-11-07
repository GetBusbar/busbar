// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use base64::Engine as _;
use busbar_contract::records::CredentialMeta;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::hkdf;
use zeroize::Zeroizing;

pub const LABEL: &[u8] = b"busbar credential-at-rest v1";

pub const KID_LABEL: &[u8] = b"busbar credential-at-rest kid v1";

pub const NO_KEY_REFUSAL: &str = "a recoverable credential cannot be minted: no at-rest key is \
     configured, so it could not be stored sealed. Set credentials.at_rest.key to a secret \
     reference that resolves to 32 random bytes (for example `openssl rand -hex 32` written to a \
     file, then `credentials: { at_rest: { key: { file: /run/secrets/busbar-at-rest.key } } }`), \
     give every node that shares this store the same key, and reload";

pub const REWRAP_CLAIM_KIND: &str = "busbar.credential-at-rest.rewrap";

pub const REWRAP_CLAIM_SECS: u64 = 300;

const PLAIN: &str = "v1:plain:";
const AEAD: &str = "v1:aead:";

const REFUSED_KIDS_CAP: usize = 64;

static LEGACY_WARNED: AtomicBool = AtomicBool::new(false);
static REFUSED_KIDS: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

struct CredentialKek {
    kid: String,
    key: LessSafeKey,
}

struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

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
    fn derive(material: &[u8]) -> Self {
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(material);
        let expand = |label: &[u8]| {
            let mut out = Zeroizing::new([0_u8; 32]);
            prk.expand(&[label], Len(out.len()))
                .and_then(|okm| okm.fill(&mut out[..]))
                .expect("32 bytes is within HKDF-SHA256's output bound");
            out
        };
        let raw = expand(LABEL);
        let kid_input = expand(KID_LABEL);
        let digest = ring::digest::digest(&ring::digest::SHA256, &kid_input[..]);
        let key = UnboundKey::new(&AES_256_GCM, &raw[..]).expect("an AES-256 key is 32 bytes");
        Self {
            kid: hex::encode(&digest.as_ref()[..8]),
            key: LessSafeKey::new(key),
        }
    }

    fn seal(&self, meta: &CredentialMeta, plain: &[u8]) -> Result<String, String> {
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

pub struct AtRestKeys {
    key: CredentialKek,
    previous: Option<CredentialKek>,
}

impl std::fmt::Debug for AtRestKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AtRestKeys")
            .field("kid", &self.key.kid)
            .field("previous", &self.previous.as_ref().map(|p| p.kid.as_str()))
            .finish_non_exhaustive()
    }
}

impl AtRestKeys {
    #[must_use]
    pub fn new(key: &[u8], previous: Option<&[u8]>) -> Self {
        Self {
            key: CredentialKek::derive(key),
            previous: previous.map(CredentialKek::derive),
        }
    }

    #[must_use]
    pub fn kid(&self) -> &str {
        &self.key.kid
    }

    #[must_use]
    pub fn previous_kid(&self) -> Option<&str> {
        self.previous.as_ref().map(|p| p.kid.as_str())
    }

    pub fn seal(&self, meta: &CredentialMeta, plain: &[u8]) -> Result<String, String> {
        self.key.seal(meta, plain)
    }

    fn open_sealed(&self, meta: &CredentialMeta, rest: &str) -> Option<(Zeroizing<String>, bool)> {
        if let Some(plain) = self.key.open_sealed(meta, rest) {
            return Some((plain, true));
        }
        self.previous
            .as_ref()
            .and_then(|p| p.open_sealed(meta, rest))
            .map(|plain| (plain, false))
    }
}

pub fn parse_key(path: &str, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    let text = std::str::from_utf8(bytes).ok().map(str::trim);
    if let Some(hex) = text.filter(|t| t.len() == 64) {
        if let Ok(raw) = hex::decode(hex) {
            return Ok(Zeroizing::new(raw));
        }
    }
    if bytes.len() == 32 {
        return Ok(Zeroizing::new(bytes.to_vec()));
    }
    Err(format!(
        "{path} must resolve to a 32-byte key (32 raw bytes, or 64 hex characters: `openssl rand \
         -hex 32`)"
    ))
}

#[must_use]
pub fn sealed_kid(envelope: &str) -> Option<&str> {
    envelope.strip_prefix(AEAD)?.split(':').next()
}

#[must_use]
pub fn is_plain(envelope: &str) -> bool {
    envelope.starts_with(PLAIN)
}

pub fn open(
    keys: Option<&AtRestKeys>,
    meta: &CredentialMeta,
    envelope: &str,
) -> Option<Zeroizing<String>> {
    if let Some(plain) = envelope.strip_prefix(PLAIN) {
        if !LEGACY_WARNED.swap(true, Ordering::Relaxed) {
            crate::diagnostics::diag_warn!(
                crate::diagnostics::CREDENTIAL_AT_REST_LEGACY_PLAIN,
                kind = %meta.kind,
                "a recoverable credential is stored in the clear (written before 1.6.0); it still \
                 authenticates, and it is re-sealed under credentials.at_rest.key at the next boot \
                 or reload that has one configured"
            );
        }
        return Some(Zeroizing::new(plain.to_string()));
    }
    let rest = envelope.strip_prefix(AEAD)?;
    let opened = keys.and_then(|k| k.open_sealed(meta, rest)).map(|(p, _)| p);
    if opened.is_none() {
        refused(keys, meta, rest.split(':').next().unwrap_or_default());
    }
    opened
}

#[must_use]
pub fn stale(
    keys: &AtRestKeys,
    meta: &CredentialMeta,
    envelope: &str,
) -> Option<Zeroizing<String>> {
    if let Some(plain) = envelope.strip_prefix(PLAIN) {
        return Some(Zeroizing::new(plain.to_string()));
    }
    let rest = envelope.strip_prefix(AEAD)?;
    match keys.open_sealed(meta, rest)? {
        (_, true) => None,
        (plain, false) => Some(plain),
    }
}

fn refused(keys: Option<&AtRestKeys>, meta: &CredentialMeta, kid: &str) {
    let kid: String = kid.chars().take(32).collect();
    {
        let mut seen = REFUSED_KIDS.lock().unwrap_or_else(|e| e.into_inner());
        if seen.contains(&kid) || seen.len() >= REFUSED_KIDS_CAP {
            return;
        }
        seen.insert(kid.clone());
    }
    let node = keys.map_or_else(
        || "none (credentials.at_rest is not configured)".to_string(),
        |k| match k.previous_kid() {
            Some(p) => format!("{} (previous {p})", k.kid()),
            None => k.kid().to_string(),
        },
    );
    crate::diagnostics::diag_warn!(
        crate::diagnostics::CREDENTIAL_AT_REST_UNOPENABLE,
        kind = %meta.kind,
        sealed_under = %kid,
        node_kids = %node,
        "a recoverable credential sealed under at-rest key {kid} opens under neither \
         credentials.at_rest.key nor credentials.at_rest.previous on this node, so it does not \
         authenticate. Configure the key with kid {kid} as credentials.at_rest.previous (or as \
         key) and reload; a row whose key is lost cannot be recovered and must be re-minted"
    );
    crate::audit_ring::AUDIT.record_by(
        "credential.at_rest.open",
        &format!("kid:{kid}"),
        crate::audit_ring::OUTCOME_REJECTED,
        "busbar",
    );
}

/// What one re-wrap pass did ([`crate::governance::GovState::rewrap_credentials`]).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Rewrap {
    /// Rows this node re-sealed under `key` and wrote back.
    pub resealed: usize,
    /// Rows that still need it: claimed by another node, changed under this pass, or refused by
    /// the store. A later boot or reload takes them up; until then they open under `previous`.
    pub pending: usize,
}

#[cfg(test)]
#[path = "tests/at_rest_tests.rs"]
mod tests;
