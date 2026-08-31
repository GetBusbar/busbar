// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The busbar-SIGNED virtual-key TOKEN (1.5.0). A minted key is a compact token
//! `<b64url(payload)>.<b64url(sig)>` where the payload is the JSON `{ sub, exp, kid }`:
//!
//! - `sub` - the STABLE subject id (the key's `vk_...` id). Policy (group, allowed_pools, labels)
//!   is resolved from the store/config BY `sub` at verify time - mutable without reissuing the key.
//! - `exp` - the Unix-seconds expiry. Keys now EXPIRE (the one new user-facing thing vs 1.4.x).
//! - `kid` - the signing-key id, so a future keyset can select the verifying key. 1.5.0 is
//!   single-key; the verify path is written so a keyset slots in (verify tries the key whose id
//!   matches `kid`).
//!
//! VERIFY is STATELESS except a denylist read: signature valid + not expired + `sub` not revoked =
//! identified. A tampered or expired token is rejected; a token signed by key A verifies under key
//! A and fails after a rotation to key B (the `kid` no longer matches, and even a replayed `kid`
//! fails the signature check under the new key).
//!
//! The token is NOT a JWT (no alg-confusion surface, no header): a single fixed algorithm
//! (ed25519), two base64url segments, busbar on both ends. Small and unambiguous.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The token prefix, so a busbar key is visually distinct from an opaque bearer and a quick
/// structural pre-check can reject an obviously-non-busbar credential before any crypto.
pub const TOKEN_PREFIX: &str = "bbk_";

/// The DER prefix of an Ed25519 SubjectPublicKeyInfo, RFC 8410 section 4: `SEQUENCE { SEQUENCE {
/// OID 1.3.101.112 }, BIT STRING }`. Fixed-length and fully determined; prefixed to the 32 raw key
/// bytes to render busbar's PUBLIC card-issuer key in the ONE spelling the verifier accepts.
#[cfg_attr(not(feature = "relay"), allow(dead_code))]
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// The signing-key id carried in every token's `kid`. Single-key for 1.5.0; a keyset later maps
/// several ids to several verifying keys. Stable so a token minted before a restart still names a
/// key the (persisted) signing key answers to.
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
    /// The AUDIENCE this token is bound to (wire name `a`), 1.6.0: the MCP plane boundary.
    /// `None` = a plain data-plane busbar key (every token
    /// minted before 1.6.0, and every `/auth/token` key after it). `Some(uri)` = an MCP
    /// authorization-server access token bound to the operator-configured canonical MCP URI.
    /// Enforcement lives in the VERIFIER ([`TokenVerifier::verify`]), never in a handler, so a
    /// route added later cannot forget it: the data plane verifies with expected-audience `None`
    /// and REJECTS any token carrying an audience; the MCP ingress verifies with `Some(uri)` and
    /// rejects a token whose audience is absent or different. Same additive fleet-compat shape as
    /// `generation`/`g`: old tokens carry no `a` and keep verifying on the data plane.
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
    /// The token's audience claim does not match the plane it was presented on: an
    /// audience-bound (MCP) token on the plain data plane, a plain token on an audience-checked
    /// (MCP) ingress, or a different audience URI. The 1.6.0 plane boundary; fail-closed.
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

/// The busbar signing key + its id: mints tokens and verifies its own. Holds the ed25519 secret;
/// its `Debug` never prints key bytes.
pub struct TokenSigner {
    key: SigningKey,
    kid: String,
}

impl std::fmt::Debug for TokenSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenSigner")
            .field("kid", &self.kid)
            .field("key", &"<redacted ed25519 signing key>")
            .finish()
    }
}

impl TokenSigner {
    /// Build a signer from raw ed25519 secret-key bytes (32 bytes) and a kid.
    pub fn from_secret_bytes(bytes: &[u8; 32], kid: impl Into<String>) -> Self {
        Self {
            key: SigningKey::from_bytes(bytes),
            kid: kid.into(),
        }
    }

    /// Generate a fresh random signing key (first-boot, dev zero-config path) from 32 bytes of the
    /// OS CSPRNG. An ed25519 secret key IS 32 uniformly-random bytes, so drawing them directly from
    /// `getrandom` (the same fail-closed entropy source key secrets use) is exactly the standard
    /// generation - no `rand` dependency needed. Fails closed: a `getrandom` failure aborts
    /// first-boot key generation (never a request path) rather than mint a guessable key.
    pub fn generate(kid: impl Into<String>) -> Result<Self, getrandom::Error> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes)?;
        Ok(Self {
            key: SigningKey::from_bytes(&bytes),
            kid: kid.into(),
        })
    }

    /// This signer's kid (the `kid` it stamps into every token).
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The raw 32-byte ed25519 secret (for PERSISTING the generated key 0600). Secret-equivalent:
    /// callers must write it 0600 and never log it.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.key.to_bytes()
    }

    /// The verifying (public) key, for a stateless verifier that holds only public material.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// A DOMAIN-SEPARATED SUBKEY SEED derived from this signer's secret.
    ///
    /// busbar holds one long-lived ed25519 secret and other planes need a signing key of their own
    /// (the A2A plane signs the agent cards it serves, so an external caller has something to pin
    /// busbar by). Handing them THIS key would put the credential-minting secret on a path that
    /// signs documents somebody else largely authored. Handing them a second CONFIGURED key would
    /// be a second secret an operator can fail to generate, hold or rotate — and a zero-config
    /// first boot would then serve unsigned cards.
    ///
    /// A one-way derivation is the answer to both: the subkey is not this key, and compromise of a
    /// subkey does not walk back to this one, while a deployment still holds exactly one secret and
    /// a rotation of it rotates every subkey with it. `domain` MUST be a versioned constant — see
    /// [`crate::a2a::sign::CARD_SIGNING_DOMAIN`] — so that changing a derivation is a new key
    /// rather than a silently different one under the same name.
    ///
    /// The secret NEVER leaves this method: callers get 32 derived bytes, not
    /// [`Self::secret_bytes`].
    // A2A-only: the sole caller is the A2A agent-card signing path (`crate::a2a::sign`), so with
    // `plane-a2a` off (and MCP on) it has no caller.
    #[cfg_attr(not(feature = "relay"), allow(dead_code))]
    pub fn derived_subkey_seed(&self, domain: &str) -> [u8; 32] {
        subkey_seed(&self.key.to_bytes(), domain)
    }

    /// SIGN `input` with this signer's DOMAIN-DERIVED card subkey — the host-owned card-signing
    /// primitive behind the plane host `card_sign` seam. Deterministic Ed25519 over the plane-framed
    /// signing input; the subkey is expanded from [`Self::derived_subkey_seed`] and the secret NEVER
    /// leaves this method — the plane receives only the 64 signature bytes.
    #[cfg_attr(not(feature = "relay"), allow(dead_code))]
    pub fn sign_with_card_subkey(&self, domain: &str, input: &[u8]) -> [u8; 64] {
        let key = SigningKey::from_bytes(&self.derived_subkey_seed(domain));
        key.sign(input).to_bytes()
    }

    /// BUSBAR'S PUBLISHED CARD-ISSUER KEY for `domain`, as base64 SubjectPublicKeyInfo — the string a
    /// counterparty pins busbar by. The PUBLIC half of the same domain-derived card subkey
    /// [`Self::sign_with_card_subkey`] signs with, rendered through the ONE Ed25519 SPKI spelling the
    /// verifier accepts, so a value emitted here and a value that verifier reads back cannot drift.
    #[cfg_attr(not(feature = "relay"), allow(dead_code))]
    pub fn card_subkey_spki_base64(&self, domain: &str) -> String {
        let key = SigningKey::from_bytes(&self.derived_subkey_seed(domain));
        let mut der = Vec::with_capacity(ED25519_SPKI_PREFIX.len() + 32);
        der.extend_from_slice(&ED25519_SPKI_PREFIX);
        der.extend_from_slice(key.verifying_key().as_bytes());
        base64::engine::general_purpose::STANDARD.encode(der)
    }

    /// Mint a signed token for `sub` expiring at `exp` (Unix seconds), stamped with the binding
    /// GENERATION it is issued against (see [`TokenClaims::generation`]). Returns the full token
    /// string, shown to the caller ONCE.
    pub fn mint(&self, sub: &str, exp: u64, generation: Option<&str>) -> String {
        self.sign_claims(TokenClaims {
            sub: sub.to_string(),
            exp,
            kid: self.kid.clone(),
            generation: generation.map(str::to_string),
            aud: None,
            cid: None,
        })
    }

    /// Mint an AUDIENCE-BOUND token (1.6.0, the MCP authorization-server mint): identical to
    /// [`Self::mint`] plus the `aud` plane-boundary claim and the optional `cid` client
    /// attribution. Such a token verifies ONLY where the verifier expects exactly this audience
    /// (the MCP ingress); the plain data-plane verify rejects it (see [`TokenClaims::aud`]).
    ///
    /// `cfg(test)` until the authorization-server mint path (OAuth Unit D) lands and becomes its
    /// production caller - per the house rule against shipping dead code behind a live-looking
    /// surface. The boundary tests below exercise it against the real verifier today. Gated on
    /// `test-support` too so the crates whose test binaries link this one (core, and the mcp/a2a
    /// plane tests dual-compiled into core) can name it — the same cross-crate test-only seam the
    /// metrics initializer uses.
    #[cfg(any(test, feature = "test-support"))]
    pub fn mint_for_audience(
        &self,
        sub: &str,
        exp: u64,
        generation: Option<&str>,
        aud: &str,
        cid: Option<&str>,
    ) -> String {
        self.sign_claims(TokenClaims {
            sub: sub.to_string(),
            exp,
            kid: self.kid.clone(),
            generation: generation.map(str::to_string),
            aud: Some(aud.to_string()),
            cid: cid.map(str::to_string),
        })
    }

    /// Serialize + sign a claims payload into the two-segment token form. The ONE signing site,
    /// so every mint variant produces the identical wire shape.
    fn sign_claims(&self, claims: TokenClaims) -> String {
        let payload = serde_json::to_vec(&claims).expect("TokenClaims serializes");
        let sig: Signature = self.key.sign(&payload);
        format!(
            "{TOKEN_PREFIX}{}.{}",
            URL_SAFE_NO_PAD.encode(&payload),
            URL_SAFE_NO_PAD.encode(sig.to_bytes())
        )
    }
}

/// The STATELESS verifier: a keyset (kid -> verifying key) so verify selects by the token's `kid`
/// and a future rotation/keyset drops in without a shape change. 1.5.0 populates it single-key.
#[derive(Clone)]
pub struct TokenVerifier {
    keys: std::collections::HashMap<String, VerifyingKey>,
}

impl TokenVerifier {
    /// A single-key verifier (the 1.5.0 case): kid -> key.
    pub fn single(kid: impl Into<String>, key: VerifyingKey) -> Self {
        let mut keys = std::collections::HashMap::new();
        keys.insert(kid.into(), key);
        Self { keys }
    }

    /// PARSE + verify + expiry + AUDIENCE, returning the claims. Does NOT consult the denylist -
    /// the caller pairs this with a `sub`-denylist read (kept separate so the crypto is pure and
    /// testable and the revocation read is the only state touched). `now` is Unix seconds.
    ///
    /// `expected_aud` is the PLANE the token is being presented on (1.6.0): `None` = the plain
    /// data plane, which rejects a token
    /// carrying ANY audience; `Some(uri)` = an audience-checked ingress (the MCP endpoint), which
    /// rejects a token whose audience is absent or different. Enforced HERE in the verifier, not
    /// per handler, so a route added later cannot forget the boundary.
    ///
    /// Order: structural parse -> kid lookup -> signature -> expiry -> audience. Signature is
    /// checked BEFORE expiry so an attacker cannot learn a real `sub`'s existence by probing
    /// expiries on a forged token (both a bad signature and an expiry reject opaquely upstream
    /// anyway, but checking the signature first means the claims are only trusted once
    /// authenticated).
    pub fn verify(
        &self,
        token: &str,
        now: u64,
        expected_aud: Option<&str>,
    ) -> Result<TokenClaims, VerifyError> {
        let body = token
            .strip_prefix(TOKEN_PREFIX)
            .ok_or(VerifyError::Malformed)?;
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
        let signature = Signature::from_bytes(&sig_arr);

        // Decode the claims to read the `kid` BEFORE trusting anything: the kid selects which
        // verifying key to check the signature against. A claims blob that does not even parse is
        // malformed; a well-formed one whose kid is unknown is UnknownKid (a rotated-away token).
        let claims: TokenClaims =
            serde_json::from_slice(&payload).map_err(|_| VerifyError::Malformed)?;
        let key = self.keys.get(&claims.kid).ok_or(VerifyError::UnknownKid)?;

        // Authenticate the payload bytes. Only AFTER this succeeds are the claims trusted.
        key.verify(&payload, &signature)
            .map_err(|_| VerifyError::BadSignature)?;

        if claims.exp <= now {
            return Err(VerifyError::Expired);
        }

        // THE PLANE BOUNDARY (fail-closed, both directions): a token is admissible exactly on the
        // plane whose audience it carries. No arm falls through.
        match (expected_aud, claims.aud.as_deref()) {
            // Plain data-plane token on the plain data plane.
            (None, None) => {}
            // Audience-bound token on the ingress expecting exactly that audience.
            (Some(expected), Some(aud)) if expected == aud => {}
            // Everything else: an MCP token on the data plane, a plain token on an
            // audience-checked ingress, or a different audience URI.
            _ => return Err(VerifyError::AudienceMismatch),
        }
        Ok(claims)
    }
}

/// The domain-separated derivation itself, as a free function so it can be asserted on directly.
///
/// `SHA-256(context ‖ secret ‖ domain)`. The secret is a FIXED 32 bytes and sits in the middle, so
/// the boundary between it and the domain string is unambiguous without a length prefix — two
/// different domains cannot produce one pre-image by moving the boundary.
///
/// This is generic busbar KEY HYGIENE, not the property of any one plane. It lives here, beside the
/// root secret it derives from, because the planes that ask for a subkey are its CALLERS: a
/// derivation that lived on one of them would make every other plane's subkey a dependency on that
/// plane, for a function whose body mentions none of them. The context string is versioned, so
/// changing this derivation is a new key rather than a silently different one under the same name —
/// which is also why the bytes it emits are pinned by known-answer vectors in the tests below.
// Its one production caller today is [`SigningKey::derived_subkey_seed`], reached only from the A2A
// card-signing path; so with `plane-a2a` off (and MCP on) it has no non-test caller. Kept generic
// (not plane-gated) because it is key hygiene any future plane may derive through.
#[cfg_attr(not(feature = "relay"), allow(dead_code))]
fn subkey_seed(secret: &[u8; 32], domain: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"busbar/subkey/v1");
    h.update(secret);
    h.update(domain.as_bytes());
    h.finalize().into()
}

#[cfg(test)]
#[path = "tests/signing_tests.rs"]
mod tests;
