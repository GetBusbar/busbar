// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use base64::Engine as _;
use busbar_contract::crypto::{self, Aes256Gcm};
use busbar_contract::records::CredentialMeta;
use busbar_contract::secure::{SecureArray, SecureString, SecureVec};

pub const LABEL: &[u8] = b"busbar credential-at-rest v1";

pub(crate) const KID_LABEL: &[u8] = b"busbar credential-at-rest kid v1";

pub const NO_KEY_REFUSAL: &str = "a recoverable credential cannot be minted: no at-rest key is \
     configured, so it could not be stored sealed. The at-rest key is derived from \
     `auth.signing_key`: set `auth.signing_key` (the same secret every node that shares this \
     same key, and reload";

const PLAIN: &str = "v1:plain:";
const AEAD: &str = "v1:aead:";

const REFUSED_KIDS_CAP: usize = 64;

static LEGACY_WARNED: AtomicBool = AtomicBool::new(false);
static REFUSED_KIDS: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

struct CredentialKek {
    kid: String,
    key: Aes256Gcm,
}

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

thread_local! {
    /// The thread's reused AAD buffer: a row's associated data is rebuilt into it per seal/open.
    static AAD: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Runs `f` over the row's associated data, built into the thread's reused buffer.
fn with_aad<R>(meta: &CredentialMeta, f: impl FnOnce(&[u8]) -> R) -> R {
    AAD.with_borrow_mut(|a| {
        a.clear();
        for part in [&meta.id, &meta.key_id, &meta.kind, &meta.public_id] {
            a.extend_from_slice(&(part.len() as u64).to_be_bytes());
            a.extend_from_slice(part.as_bytes());
        }
        f(a.as_slice())
    })
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
}

impl CredentialKek {
    fn derive(material: &[u8]) -> Self {
        let expand = |label: &[u8]| {
            let mut out = SecureArray::<32>::zeroed();
            crypto::hkdf_sha256(&[], material, label, &mut out[..])
                .expect("32 bytes is within HKDF-SHA256's output bound");
            out
        };
        let raw = expand(LABEL);
        let kid_input = expand(KID_LABEL);
        let digest = crypto::sha256(&kid_input[..]);
        // PANIC: `raw` is a fixed 32-byte derived key, so AES-256 cannot reject its length.
        let key = Aes256Gcm::new(&raw).expect("an AES-256 key is 32 bytes");
        Self {
            kid: hex::encode(&digest[..8]),
            key,
        }
    }

    fn seal(&self, meta: &CredentialMeta, plain: &[u8]) -> Result<String, String> {
        // One block at its final size (the secret, then the tag): it never regrows.
        let mut buf = SecureVec::from(Vec::with_capacity(plain.len() + TAG_LEN));
        buf.extend_from_slice(plain);
        let sealed = with_aad(meta, |aad| self.key.seal_random_nonce(aad, &mut buf[..]));
        let (nonce, tag) =
            sealed.map_err(crate::cold::governance::runtime::at_rest_seal_refusal)?;
        // The stored ciphertext is the encrypted bytes followed by the tag, as it always was.
        buf.extend_from_slice(&tag);
        Ok(crate::cold::governance::runtime::at_rest_envelope(
            AEAD,
            &self.kid,
            &nonce,
            &buf[..],
        ))
    }

    fn open_sealed(&self, meta: &CredentialMeta, rest: &str) -> Option<SecureString> {
        let mut parts = rest.splitn(3, ':');
        let (kid, nonce, ct) = (parts.next()?, parts.next()?, parts.next()?);
        if kid != self.kid {
            return None;
        }
        let nonce: [u8; NONCE_LEN] = b64().decode(nonce).ok()?.try_into().ok()?;
        let mut buf = SecureVec::from(b64().decode(ct).ok()?);
        let split = buf.len().checked_sub(TAG_LEN)?;
        let tag: [u8; TAG_LEN] = buf[split..].try_into().ok()?;
        with_aad(meta, |aad| {
            self.key.open_in_place(&nonce, aad, &mut buf[..split], &tag)
        })
        .ok()?;
        // The plaintext is the decoded buffer's prefix: keep that buffer as the secret's own storage
        // rather than copying it out. The cut-off tag is wiped by the truncate.
        buf.truncate(split);
        match String::from_utf8(buf.into_vec()) {
            Ok(text) => Some(SecureString::from(text)),
            Err(e) => {
                drop(SecureVec::from(e.into_bytes()));
                None
            }
        }
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

    /// The at-rest keys of a node whose token-signing secret is `secret` (`auth.signing_key`):
    /// HKDF-SHA256 under [`LABEL`], so one configured secret covers both uses, and rotating the
    /// signing key retires the credentials sealed under it.
    #[must_use]
    pub fn from_signing_secret(secret: &[u8; 32]) -> Self {
        Self::new(secret, None)
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

    fn open_sealed(&self, meta: &CredentialMeta, rest: &str) -> Option<(SecureString, bool)> {
        if let Some(plain) = self.key.open_sealed(meta, rest) {
            return Some((plain, true));
        }
        self.previous
            .as_ref()
            .and_then(|p| p.open_sealed(meta, rest))
            .map(|plain| (plain, false))
    }
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
) -> Option<SecureString> {
    if let Some(plain) = envelope.strip_prefix(PLAIN) {
        if !LEGACY_WARNED.swap(true, Ordering::Relaxed) {
            crate::diagnostics::diag_warn!(
                crate::diagnostics::CREDENTIAL_AT_REST_LEGACY_PLAIN,
                kind = %meta.kind,
                "a recoverable credential is stored in the clear (written before 1.6.0); it still \
                 authenticates, and it is re-sealed under the key derived from auth.signing_key at the next boot \
                 or reload with a signing key configured"
            );
        }
        return Some(SecureString::from(plain));
    }
    let rest = envelope.strip_prefix(AEAD)?;
    let opened = keys.and_then(|k| k.open_sealed(meta, rest)).map(|(p, _)| p);
    if opened.is_none() {
        refused(keys, meta, rest.split(':').next().unwrap_or_default());
    }
    opened
}

#[must_use]
pub fn stale(keys: &AtRestKeys, meta: &CredentialMeta, envelope: &str) -> Option<SecureString> {
    if let Some(plain) = envelope.strip_prefix(PLAIN) {
        return Some(SecureString::from(plain));
    }
    let rest = envelope.strip_prefix(AEAD)?;
    match keys.open_sealed(meta, rest)? {
        (_, true) => None,
        (plain, false) => Some(plain),
    }
}

/// The node's at-rest kids, as the unopenable-row warning names them.
struct NodeKids<'a>(Option<&'a AtRestKeys>);

impl std::fmt::Display for NodeKids<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            None => f.write_str("none (auth.signing_key is not configured)"),
            Some(k) => match k.previous_kid() {
                Some(p) => write!(f, "{} (previous {p})", k.kid()),
                None => f.write_str(k.kid()),
            },
        }
    }
}

fn refused(keys: Option<&AtRestKeys>, meta: &CredentialMeta, kid: &str) {
    // At most 32 characters of the kid, borrowed.
    let kid = &kid[..kid.char_indices().nth(32).map_or(kid.len(), |(i, _)| i)];
    {
        let mut seen = REFUSED_KIDS.lock().unwrap_or_else(|e| e.into_inner());
        if seen.contains(kid) || seen.len() >= REFUSED_KIDS_CAP {
            return;
        }
        crate::cold::governance::runtime::at_rest_refused_kid(&mut seen, kid);
    }
    let node = NodeKids(keys);
    crate::diagnostics::diag_warn!(
        crate::diagnostics::CREDENTIAL_AT_REST_UNOPENABLE,
        kind = %meta.kind,
        sealed_under = %kid,
        node_kids = %node,
        "a recoverable credential sealed under at-rest key {kid} does not open under the key \
         derived from auth.signing_key on this node, so it does not authenticate. It was sealed \
         under a different auth.signing_key (rotating the signing key invalidates the \
         credentials sealed under it); every node that shares the store must use the same \
         auth.signing_key, and a row whose key is lost cannot be recovered and must be re-minted"
    );
    let resource = crate::cold::governance::runtime::at_rest_kid_resource(kid);
    crate::audit_ring::AUDIT.record_by(
        "credential.at_rest.open",
        &resource,
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

#[cfg(test)]
#[path = "at_rest/caller_tests.rs"]
mod caller_tests;
