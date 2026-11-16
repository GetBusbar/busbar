// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use busbar_contract::crypto::ed25519::{SigningKey, VerifyingKey};
use busbar_contract::crypto::{self, RngError};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};

pub const TOKEN_PREFIX: &str = "bbk_";

pub(crate) const TICKET_AUDIENCE: &str = "busbar:ticket";

const ED25519_KEY_INFO_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

pub const DEFAULT_KID: &str = "k1";

/// The signed token PAYLOAD: subject + expiry + signing-key id. Serialized compactly (short field
/// names) since it rides in an Authorization header on every request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenClaims {
    /// Subject: the key's stable `vk_...` id. Policy is resolved by this at verify time.
    pub sub: String,
    /// Expiry, Unix seconds. A token past this is rejected (stateless).
    pub exp: u64,
    /// Signing-key id (selects the verifying key; single-key `k1` for 1.5.0).
    pub kid: String,
    /// The BINDING GENERATION this token was minted against (wire name `g`), mirrored in the
    /// binding row's `generation_hash` marker (`binding:<id>:<generation>`). `POST /keys/{id}/rotate`
    /// stamps a FRESH generation into the durable binding, so every token carrying the previous one
    /// stops verifying immediately and fleet-wide — the subject id (and with it the ledger bucket,
    /// budgets and usage history) stays stable. `None` = a token minted before generations existed;
    /// it verifies only against a binding that likewise carries none (see
    /// `GovState::binding_generation_matches`), never against a rotated one.
    #[serde(default, rename = "g", skip_serializing_if = "Option::is_none")]
    pub generation: Option<String>,
    /// The AUDIENCE this token is bound to (wire name `a`), 1.6.0: a substrate-owned, plane-neutral
    /// scoping claim. `None` = a plain data-plane busbar key (every token minted before 1.6.0, and
    /// every `/auth/token` key after it). `Some(uri)` = a token bound to whatever operator-configured
    /// audience URI the minting caller passed to [`SigningKey::mint_for_audience`] — the substrate
    /// names no specific plane here; it is whichever ingress that caller scoped the token to.
    /// Enforcement lives in the VERIFIER ([`TokenVerifier::verify`]), never in a handler, so a
    /// route added later cannot forget it: the data plane verifies with expected-audience `None`
    /// and REJECTS any token carrying an audience; an audience-checked ingress verifies with
    /// `Some(uri)` and rejects a token whose audience is absent or different. Same additive
    /// fleet-compat shape as `generation`/`g`: old tokens carry no `a` and keep verifying on the
    /// data plane.
    #[serde(default, rename = "a", skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    /// The OAuth CLIENT id this token was minted through (wire name `cid`), for per-client
    /// attribution. HOW MUCH THAT ATTRIBUTION IS WORTH DEPENDS ON THE CLIENT CLASS, and an audit
    /// reader has to be told which: a CONFIDENTIAL client authenticated to the authorization
    /// server, so its `cid` is cryptographically attributable; a PUBLIC (PKCE-only) client did
    /// not, so its `cid` is self-asserted and names only who the client SAID it was. Carried,
    /// never an admission input on the data plane — which is exactly why the weaker of the two
    /// classes is tolerable here and would not be in an authorization decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cid: Option<String>,
    /// The TICKET id (wire name `t`), 1.6.0: present only on a host-minted ticket, naming the record
    /// stored beside it and the single-use claim its admission spends. `None` on every key.
    #[serde(default, rename = "t", skip_serializing_if = "Option::is_none")]
    pub ticket: Option<String>,
}

/// A verify failure. Every arm rejects fail-closed; the distinctions exist for the AUDIT log /
/// tests, never to leak to the caller (the auth path collapses all of them to one opaque 401).
#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// Not a busbar token shape (missing prefix / not two base64url segments).
    Malformed,
    /// The `kid` names no known signing key (e.g. a token minted under a rotated-away key).
    UnknownKid,
    /// The ed25519 signature did not verify under the selected key (tampered, or wrong key).
    BadSignature,
    /// The token is past its `exp`.
    Expired,
    /// The token's audience claim does not match the boundary it was presented on: an
    /// audience-bound token on the plain data plane, a plain token on an audience-checked
    /// ingress, or a different audience URI. The 1.6.0 audience boundary; fail-closed.
    AudienceMismatch,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            VerifyError::Malformed => "malformed token",
            VerifyError::UnknownKid => "unknown signing-key id",
            VerifyError::BadSignature => "bad signature",
            VerifyError::Expired => "token expired",
            VerifyError::AudienceMismatch => "audience mismatch",
        };
        f.write_str(s)
    }
}

/// Bound on cached domain subkeys per signer. Domains come only from admitted plane decls, so a
/// real deployment holds a handful; a domain past the bound is derived per call, never cached.
const MAX_SIGNING_DOMAINS: usize = 8;

pub struct TokenSigner {
    key: SigningKey,
    kid: String,
    /// Domain subkeys derived from `key`, each once. The cache lives and dies with this signer, so
    /// a rotation (a new `TokenSigner`, even under the same kid) starts empty and derives afresh.
    subkeys: RwLock<Vec<(Box<str>, Arc<SigningKey>)>>,
}

impl std::fmt::Debug for TokenSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenSigner")
            .field("kid", &self.kid)
            .field("key", &"<redacted ed25519 signing key>")
            .finish()
    }
}

/// The Ed25519 key of a 32-byte seed. PANIC: every 32-byte seed is a valid RFC 8032 seed, so this
/// fails only if the crypto backend refuses Ed25519 outright, and a node without its token key
/// cannot run.
fn signing_key(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_seed(seed)
        .unwrap_or_else(|e| panic!("crypto backend refused an Ed25519 seed: {e}"))
}

impl TokenSigner {
    pub fn from_secret_bytes(bytes: &[u8; 32], kid: impl Into<String>) -> Self {
        Self {
            key: signing_key(bytes),
            kid: kid.into(),
            subkeys: RwLock::default(),
        }
    }

    pub fn generate(kid: impl Into<String>) -> Result<Self, RngError> {
        let mut bytes = [0u8; 32];
        crypto::fill(&mut bytes)?;
        Ok(Self {
            key: signing_key(&bytes),
            kid: kid.into(),
            subkeys: RwLock::default(),
        })
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        *self.key.seed()
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    pub fn derived_subkey_seed(&self, domain: &str) -> [u8; 32] {
        subkey_seed(self.key.seed(), domain)
    }

    pub fn sign_with_subkey(&self, domain: &str, input: &[u8]) -> [u8; 64] {
        let key = self.subkey(domain);
        key.sign(input)
    }

    pub fn subkey_key_info_base64(&self, domain: &str) -> String {
        let key = signing_key(&self.derived_subkey_seed(domain));
        // The SubjectPublicKeyInfo DER is a fixed 44 bytes: built on the stack.
        let mut der = [0u8; ED25519_KEY_INFO_PREFIX.len() + 32];
        der[..ED25519_KEY_INFO_PREFIX.len()].copy_from_slice(&ED25519_KEY_INFO_PREFIX);
        der[ED25519_KEY_INFO_PREFIX.len()..].copy_from_slice(&key.verifying_key().to_bytes());
        base64::engine::general_purpose::STANDARD.encode(der)
    }

    /// The domain subkey, derived at most once per (signer, domain).
    fn subkey(&self, domain: &str) -> Arc<SigningKey> {
        let cached = |set: &[(Box<str>, Arc<SigningKey>)]| {
            set.iter()
                .find(|(d, _)| &**d == domain)
                .map(|(_, k)| Arc::clone(k))
        };
        if let Some(k) = cached(&self.subkeys.read().unwrap_or_else(|e| e.into_inner())) {
            return k;
        }
        let mut set = self.subkeys.write().unwrap_or_else(|e| e.into_inner());
        if let Some(k) = cached(&set) {
            return k;
        }
        #[cfg(test)]
        SUBKEY_DERIVATIONS.with(|c| c.set(c.get() + 1));
        // The seed is wiped when it drops, right after the key is built from it.
        let seed = busbar_contract::secure::SecureArray::from(self.derived_subkey_seed(domain));
        let key = Arc::new(signing_key(&seed));
        drop(seed);
        if set.len() < MAX_SIGNING_DOMAINS {
            set.push((domain.into(), Arc::clone(&key)));
        }
        key
    }

    pub fn mint(&self, sub: &str, exp: u64, generation: Option<&str>) -> String {
        self.sign_token(
            TOKEN_PREFIX,
            &MintClaims {
                sub,
                exp,
                kid: &self.kid,
                generation,
                aud: None,
                cid: None,
                ticket: None,
            },
        )
    }

    pub fn mint_for_audience(
        &self,
        sub: &str,
        exp: u64,
        generation: Option<&str>,
        aud: &str,
        cid: Option<&str>,
    ) -> String {
        self.sign_token(
            TOKEN_PREFIX,
            &MintClaims {
                sub,
                exp,
                kid: &self.kid,
                generation,
                aud: Some(Audience::Uri(aud)),
                cid,
                ticket: None,
            },
        )
    }

    pub fn mint_ticket_body(
        &self,
        sub: &str,
        exp: u64,
        generation: Option<&str>,
        ticket: &str,
        consumer: &str,
    ) -> String {
        self.sign_token(
            "",
            &MintClaims {
                sub,
                exp,
                kid: &self.kid,
                generation,
                aud: Some(Audience::Ticket(consumer)),
                cid: None,
                ticket: Some(ticket),
            },
        )
    }

    /// `prefix` + base64url(payload) + `.` + base64url(signature), written into the one token
    /// String with no intermediate encodings.
    fn sign_token(&self, prefix: &str, claims: &MintClaims<'_>) -> String {
        crate::cold::governance::state::signing_token(&self.key, prefix, claims)
    }
}

/// The claims a mint signs, borrowed from the caller: the same fields, wire names and order as
/// [`TokenClaims`], so the signed payload is byte-for-byte what serializing `TokenClaims` writes.
#[derive(Serialize)]
struct MintClaims<'a> {
    sub: &'a str,
    exp: u64,
    kid: &'a str,
    #[serde(rename = "g", skip_serializing_if = "Option::is_none")]
    generation: Option<&'a str>,
    #[serde(rename = "a", skip_serializing_if = "Option::is_none")]
    aud: Option<Audience<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cid: Option<&'a str>,
    #[serde(rename = "t", skip_serializing_if = "Option::is_none")]
    ticket: Option<&'a str>,
}

/// An audience claim: an operator-configured URI, or a ticket audience
/// (`busbar:ticket:<consumer>`), written in place without composing a String.
#[derive(Clone, Copy)]
enum Audience<'a> {
    Uri(&'a str),
    Ticket(&'a str),
}

impl Audience<'_> {
    fn matches(self, aud: &str) -> bool {
        match self {
            Audience::Uri(expected) => expected == aud,
            Audience::Ticket(consumer) => {
                aud.strip_prefix(TICKET_AUDIENCE)
                    .and_then(|rest| rest.strip_prefix(':'))
                    == Some(consumer)
            }
        }
    }
}

impl Serialize for Audience<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Audience::Uri(uri) => serializer.serialize_str(uri),
            Audience::Ticket(consumer) => {
                serializer.collect_str(&format_args!("{TICKET_AUDIENCE}:{consumer}"))
            }
        }
    }
}

/// The STATELESS verifier: a keyset (kid -> verifying key) so verify selects by the token's `kid`
/// and a future rotation/keyset drops in without a shape change. 1.5.0 populates it single-key.
#[derive(Clone)]
pub struct TokenVerifier {
    keys: foldhash::HashMap<String, VerifyingKey>,
}

impl TokenVerifier {
    pub fn single(kid: impl Into<String>, key: VerifyingKey) -> Self {
        let mut keys = foldhash::HashMap::default();
        keys.insert(kid.into(), key);
        Self { keys }
    }

    pub fn verify(
        &self,
        token: &str,
        now: u64,
        expected_aud: Option<&str>,
    ) -> Result<TokenClaims, VerifyError> {
        let body = token
            .strip_prefix(TOKEN_PREFIX)
            .ok_or(VerifyError::Malformed)?;
        self.verify_body(body, now, expected_aud)
    }

    pub(crate) fn verify_body(
        &self,
        body: &str,
        now: u64,
        expected_aud: Option<&str>,
    ) -> Result<TokenClaims, VerifyError> {
        self.verify_body_at(body, Some(now), expected_aud.map(Audience::Uri))
    }

    pub(crate) fn verify_ticket_body(
        &self,
        body: &str,
        consumer: &str,
    ) -> Result<TokenClaims, VerifyError> {
        self.verify_body_at(body, None, Some(Audience::Ticket(consumer)))
    }

    fn verify_body_at(
        &self,
        body: &str,
        expiry_clock: Option<u64>,
        expected_aud: Option<Audience<'_>>,
    ) -> Result<TokenClaims, VerifyError> {
        let (payload_b64, sig_b64) = body.split_once('.').ok_or(VerifyError::Malformed)?;
        let payload = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|_| VerifyError::Malformed)?;
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|_| VerifyError::Malformed)?;
        let sig_arr: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| VerifyError::Malformed)?;

        let claims: TokenClaims =
            busbar_contract::json::parse(&payload).map_err(|_| VerifyError::Malformed)?;
        let key = self.keys.get(&claims.kid).ok_or(VerifyError::UnknownKid)?;

        key.verify_strict(&payload, &sig_arr)
            .map_err(|_| VerifyError::BadSignature)?;

        if expiry_clock.is_some_and(|now| claims.exp <= now) {
            return Err(VerifyError::Expired);
        }

        match (expected_aud, claims.aud.as_deref()) {
            (None, None) => {}

            (Some(expected), Some(aud)) if expected.matches(aud) => {}

            _ => return Err(VerifyError::AudienceMismatch),
        }
        Ok(claims)
    }
}

#[cfg(test)]
thread_local! {
    /// Domain subkey derivations on this thread (sha256 of the root secret plus a scalar mult).
    pub(crate) static SUBKEY_DERIVATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// sha256("busbar/subkey/v1" || secret || domain), hashed as a stream so no heap copy of the root
/// secret is left behind (the old `concat` was never wiped). Same bytes as before.
fn subkey_seed(secret: &[u8; 32], domain: &str) -> [u8; 32] {
    // SHA-256 over the three parts in order: the digest of their concatenation, without one.
    let mut digest = crate::hashing::Sha256::new();
    digest.update(b"busbar/subkey/v1");
    digest.update(secret);
    digest.update(domain.as_bytes());
    digest.finalize()
}

#[cfg(test)]
#[path = "tests/signing_tests.rs"]
mod tests;
