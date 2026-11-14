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

thread_local! {
    /// The thread's reused AAD buffer: a row's associated data is rebuilt into it per seal/open.
    static AAD: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Runs `f` over the row's associated data, built into the thread's reused buffer.
fn with_aad<R>(meta: &CredentialMeta, f: impl FnOnce(Aad<&[u8]>) -> R) -> R {
    AAD.with_borrow_mut(|a| {
        a.clear();
        for part in [&meta.id, &meta.key_id, &meta.kind, &meta.public_id] {
            a.extend_from_slice(&(part.len() as u64).to_be_bytes());
            a.extend_from_slice(part.as_bytes());
        }
        f(Aad::from(a.as_slice()))
    })
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
        #[expect(
            clippy::disallowed_methods,
            reason = "config: a nonce is drawn only when a credential is sealed at mint or re-wrap"
        )]
        getrandom::fill(&mut nonce).map_err(|e| format!("CSPRNG unavailable: {e}"))?;
        #[expect(
            clippy::disallowed_methods,
            reason = "config: sealing copies the secret once, at mint or re-wrap"
        )]
        let mut buf = Zeroizing::new(plain.to_vec());
        let sealed = with_aad(meta, |aad| {
            self.key
                .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), aad, &mut *buf)
        });
        #[expect(
            clippy::disallowed_methods,
            reason = "error: a seal failure renders its message once"
        )]
        sealed.map_err(|_| "the credential could not be sealed".to_string())?;
        #[expect(
            clippy::disallowed_methods,
            reason = "config: the sealed envelope is the stored row, written at mint or re-wrap"
        )]
        let envelope = format!(
            "{AEAD}{}:{}:{}",
            self.kid,
            b64().encode(nonce),
            b64().encode(&buf[..])
        );
        Ok(envelope)
    }

    fn open_sealed(&self, meta: &CredentialMeta, rest: &str) -> Option<Zeroizing<String>> {
        let mut parts = rest.splitn(3, ':');
        let (kid, nonce, ct) = (parts.next()?, parts.next()?, parts.next()?);
        if kid != self.kid {
            return None;
        }
        let nonce: [u8; NONCE_LEN] = b64().decode(nonce).ok()?.try_into().ok()?;
        let mut buf = Zeroizing::new(b64().decode(ct).ok()?);
        let len = with_aad(meta, |aad| {
            self.key
                .open_in_place(Nonce::assume_unique_for_key(nonce), aad, &mut buf[..])
                .map(|plain| plain.len())
        })
        .ok()?;
        // The plaintext is the decoded buffer's prefix: keep that buffer as the secret's own storage
        // rather than copying it out. The cut-off tag stays in spare capacity, which zeroizing clears.
        let mut bytes = std::mem::take(&mut *buf);
        bytes.truncate(len);
        match String::from_utf8(bytes) {
            Ok(text) => Some(Zeroizing::new(text)),
            Err(e) => {
                drop(Zeroizing::new(e.into_bytes()));
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
        #[expect(
            clippy::disallowed_methods,
            reason = "config: the at-rest key is read once per boot or reload"
        )]
        let raw = bytes.to_vec();
        return Ok(Zeroizing::new(raw));
    }
    #[expect(
        clippy::disallowed_methods,
        reason = "error: a malformed at-rest key renders its message once"
    )]
    let refusal = format!(
        "{path} must resolve to a 32-byte key (32 raw bytes, or 64 hex characters: `openssl rand \
         -hex 32`)"
    );
    Err(refusal)
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
        #[expect(
            clippy::disallowed_methods,
            reason = "config: a clear row exists only until a configured at-rest key re-seals it"
        )]
        let plain = plain.to_string();
        return Some(Zeroizing::new(plain));
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
        #[expect(
            clippy::disallowed_methods,
            reason = "boot: a stale row is read only by the boot or reload re-wrap"
        )]
        let plain = plain.to_string();
        return Some(Zeroizing::new(plain));
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
            None => f.write_str("none (credentials.at_rest is not configured)"),
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
        #[expect(
            clippy::disallowed_methods,
            reason = "error: a refused kid is remembered once, at most REFUSED_KIDS_CAP times"
        )]
        seen.insert(kid.to_string());
    }
    let node = NodeKids(keys);
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
    #[expect(
        clippy::disallowed_methods,
        reason = "error: a refused kid is audited once, at most REFUSED_KIDS_CAP times"
    )]
    let resource = format!("kid:{kid}");
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
