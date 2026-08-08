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

/// The token prefix, so a busbar key is visually distinct from an opaque bearer and a quick
/// structural pre-check can reject an obviously-non-busbar credential before any crypto.
pub(crate) const TOKEN_PREFIX: &str = "bbk_";

/// The signing-key id carried in every token's `kid`. Single-key for 1.5.0; a keyset later maps
/// several ids to several verifying keys. Stable so a token minted before a restart still names a
/// key the (persisted) signing key answers to.
pub(crate) const DEFAULT_KID: &str = "k1";

/// The signed token PAYLOAD: subject + expiry + signing-key id. Serialized compactly (short field
/// names) since it rides in an Authorization header on every request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TokenClaims {
    /// Subject: the key's stable `vk_...` id. Policy is resolved by this at verify time.
    pub(crate) sub: String,
    /// Expiry, Unix seconds. A token past this is rejected (stateless).
    pub(crate) exp: u64,
    /// Signing-key id (selects the verifying key; single-key `k1` for 1.5.0).
    pub(crate) kid: String,
    /// The BINDING GENERATION this token was minted against (wire name `g`), mirrored in the
    /// binding row's `generation_hash` marker (`binding:<id>:<generation>`). `POST /keys/{id}/rotate`
    /// stamps a FRESH generation into the durable binding, so every token carrying the previous one
    /// stops verifying immediately and fleet-wide — the subject id (and with it the ledger bucket,
    /// budgets and usage history) stays stable. `None` = a token minted before generations existed;
    /// it verifies only against a binding that likewise carries none (see
    /// `GovState::binding_generation_matches`), never against a rotated one.
    #[serde(default, rename = "g", skip_serializing_if = "Option::is_none")]
    pub(crate) generation: Option<String>,
    /// The AUDIENCE this token is bound to (wire name `a`), 1.5.4 P1: the MCP plane boundary
    /// (`mcp-oauth-1.5.4-DESIGN.md` par. 4). `None` = a plain data-plane busbar key (every token
    /// minted before 1.5.4, and every `/auth/token` key after it). `Some(uri)` = an MCP
    /// authorization-server access token bound to the operator-configured canonical MCP URI.
    /// Enforcement lives in the VERIFIER ([`TokenVerifier::verify`]), never in a handler, so a
    /// route added later cannot forget it: the data plane verifies with expected-audience `None`
    /// and REJECTS any token carrying an audience; the MCP ingress verifies with `Some(uri)` and
    /// rejects a token whose audience is absent or different. Same additive fleet-compat shape as
    /// `generation`/`g`: old tokens carry no `a` and keep verifying on the data plane.
    #[serde(default, rename = "a", skip_serializing_if = "Option::is_none")]
    pub(crate) aud: Option<String>,
    /// The OAuth CLIENT id this token was minted through (wire name `cid`), for per-client
    /// attribution (`mcp-oauth-1.5.4-DESIGN.md` par. 8.9). Attribution strength is stated by
    /// client class there: cryptographically attributable for confidential clients, self-asserted
    /// for public (PKCE-only) clients. Carried, never an admission input on the data plane.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) cid: Option<String>,
}

/// A verify failure. Every arm rejects fail-closed; the distinctions exist for the AUDIT log /
/// tests, never to leak to the caller (the auth path collapses all of them to one opaque 401).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum VerifyError {
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
    /// (MCP) ingress, or a different audience URI. The 1.5.4 plane boundary; fail-closed.
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
pub(crate) struct TokenSigner {
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
    pub(crate) fn from_secret_bytes(bytes: &[u8; 32], kid: impl Into<String>) -> Self {
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
    pub(crate) fn generate(kid: impl Into<String>) -> Result<Self, getrandom::Error> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes)?;
        Ok(Self {
            key: SigningKey::from_bytes(&bytes),
            kid: kid.into(),
        })
    }

    /// This signer's kid (the `kid` it stamps into every token).
    pub(crate) fn kid(&self) -> &str {
        &self.kid
    }

    /// The raw 32-byte ed25519 secret (for PERSISTING the generated key 0600). Secret-equivalent:
    /// callers must write it 0600 and never log it.
    pub(crate) fn secret_bytes(&self) -> [u8; 32] {
        self.key.to_bytes()
    }

    /// The verifying (public) key, for a stateless verifier that holds only public material.
    pub(crate) fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// Mint a signed token for `sub` expiring at `exp` (Unix seconds), stamped with the binding
    /// GENERATION it is issued against (see [`TokenClaims::generation`]). Returns the full token
    /// string, shown to the caller ONCE.
    pub(crate) fn mint(&self, sub: &str, exp: u64, generation: Option<&str>) -> String {
        self.sign_claims(TokenClaims {
            sub: sub.to_string(),
            exp,
            kid: self.kid.clone(),
            generation: generation.map(str::to_string),
            aud: None,
            cid: None,
        })
    }

    /// Mint an AUDIENCE-BOUND token (1.5.4, the MCP authorization-server mint): identical to
    /// [`Self::mint`] plus the `aud` plane-boundary claim and the optional `cid` client
    /// attribution. Such a token verifies ONLY where the verifier expects exactly this audience
    /// (the MCP ingress); the plain data-plane verify rejects it (see [`TokenClaims::aud`]).
    ///
    /// `cfg(test)` until the authorization-server mint path (OAuth Unit D) lands and becomes its
    /// production caller - per the house rule against shipping dead code behind a live-looking
    /// surface. The boundary tests below exercise it against the real verifier today.
    #[cfg(test)]
    pub(crate) fn mint_for_audience(
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
pub(crate) struct TokenVerifier {
    keys: std::collections::HashMap<String, VerifyingKey>,
}

impl TokenVerifier {
    /// A single-key verifier (the 1.5.0 case): kid -> key.
    pub(crate) fn single(kid: impl Into<String>, key: VerifyingKey) -> Self {
        let mut keys = std::collections::HashMap::new();
        keys.insert(kid.into(), key);
        Self { keys }
    }

    /// PARSE + verify + expiry + AUDIENCE, returning the claims. Does NOT consult the denylist -
    /// the caller pairs this with a `sub`-denylist read (kept separate so the crypto is pure and
    /// testable and the revocation read is the only state touched). `now` is Unix seconds.
    ///
    /// `expected_aud` is the PLANE the token is being presented on (1.5.4 P1,
    /// `mcp-oauth-1.5.4-DESIGN.md` par. 4): `None` = the plain data plane, which rejects a token
    /// carrying ANY audience; `Some(uri)` = an audience-checked ingress (the MCP endpoint), which
    /// rejects a token whose audience is absent or different. Enforced HERE in the verifier, not
    /// per handler, so a route added later cannot forget the boundary.
    ///
    /// Order: structural parse -> kid lookup -> signature -> expiry -> audience. Signature is
    /// checked BEFORE expiry so an attacker cannot learn a real `sub`'s existence by probing
    /// expiries on a forged token (both a bad signature and an expiry reject opaquely upstream
    /// anyway, but checking the signature first means the claims are only trusted once
    /// authenticated).
    pub(crate) fn verify(
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

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> TokenSigner {
        TokenSigner::from_secret_bytes(&[7u8; 32], DEFAULT_KID)
    }

    fn verifier(s: &TokenSigner) -> TokenVerifier {
        TokenVerifier::single(s.kid(), s.verifying_key())
    }

    /// Mint -> verify round-trips the subject + expiry, and the token carries the prefix + kid.
    #[test]
    fn mint_then_verify_roundtrips() {
        let s = signer();
        let v = verifier(&s);
        let tok = s.mint("vk_abc", 2000, None);
        assert!(tok.starts_with(TOKEN_PREFIX));
        let claims = v.verify(&tok, 1000, None).expect("valid");
        assert_eq!(claims.sub, "vk_abc");
        assert_eq!(claims.exp, 2000);
        assert_eq!(claims.kid, DEFAULT_KID);
    }

    /// THE PLANE BOUNDARY (1.5.4 P1, `mcp-oauth-1.5.4-DESIGN.md` par. 4): an AUDIENCE-BOUND token
    /// (the shape the MCP authorization server mints, wire claim `a`) must be REJECTED by the
    /// plain data-plane verify. Before the boundary existed, serde ignored the unknown claim and
    /// the token verified everywhere a busbar key does (`/stats`, `/v1/models`, every
    /// `RouteAuth::Key` route): an MCP-scoped token was silently a full data-plane key.
    #[test]
    fn audience_bound_token_is_rejected_on_the_plain_verify_path() {
        let s = signer();
        let v = verifier(&s);
        // Hand-craft the payload (TokenClaims + the audience claim) and sign it with the real
        // signer key, exactly as an AS mint will.
        let payload = serde_json::to_vec(&serde_json::json!({
            "sub": "vk_mcp",
            "exp": 2000u64,
            "kid": DEFAULT_KID,
            "a": "https://busbar.example.com/mcp"
        }))
        .unwrap();
        let sig: Signature = s.key.sign(&payload);
        let token = format!(
            "{TOKEN_PREFIX}{}.{}",
            URL_SAFE_NO_PAD.encode(&payload),
            URL_SAFE_NO_PAD.encode(sig.to_bytes())
        );
        assert!(
            v.verify(&token, 1000, None).is_err(),
            "an audience-bound token must NOT verify on the plain (no-expected-audience) path"
        );
    }

    /// The full audience matrix, fail-closed on every mismatch arm (1.5.4 P1). The two accept
    /// arms are exact: plain token on the plain plane, and matching audience on the
    /// audience-checked plane. Everything else is `AudienceMismatch`.
    #[test]
    fn audience_matrix_is_fail_closed() {
        let s = signer();
        let v = verifier(&s);
        let mcp = "https://busbar.example.com/mcp";
        let plain = s.mint("vk_abc", 2000, None);
        let bound = s.mint_for_audience("vk_abc", 2000, None, mcp, Some("client-1"));

        // Accept arms.
        assert!(v.verify(&plain, 1000, None).is_ok(), "plain on plain");
        let claims = v
            .verify(&bound, 1000, Some(mcp))
            .expect("matching audience on the audience-checked plane");
        assert_eq!(claims.aud.as_deref(), Some(mcp));
        assert_eq!(claims.cid.as_deref(), Some("client-1"));

        // Reject arms.
        assert_eq!(
            v.verify(&bound, 1000, None),
            Err(VerifyError::AudienceMismatch),
            "audience-bound token on the plain data plane"
        );
        assert_eq!(
            v.verify(&plain, 1000, Some(mcp)),
            Err(VerifyError::AudienceMismatch),
            "plain token on an audience-checked ingress"
        );
        assert_eq!(
            v.verify(&bound, 1000, Some("https://other.example.com/mcp")),
            Err(VerifyError::AudienceMismatch),
            "different audience URI"
        );
    }

    /// FLEET COMPAT: a token minted before the `aud` claim existed (no `a` on the wire) keeps
    /// verifying on the data plane, exactly like the `generation`/`g` rollout. No flag day.
    #[test]
    fn legacy_token_without_audience_still_verifies_on_the_data_plane() {
        let s = signer();
        let v = verifier(&s);
        // The pre-1.5.4 payload shape, hand-crafted: {sub, exp, kid} only.
        let payload = serde_json::to_vec(&serde_json::json!({
            "sub": "vk_old",
            "exp": 2000u64,
            "kid": DEFAULT_KID
        }))
        .unwrap();
        let sig: Signature = s.key.sign(&payload);
        let token = format!(
            "{TOKEN_PREFIX}{}.{}",
            URL_SAFE_NO_PAD.encode(&payload),
            URL_SAFE_NO_PAD.encode(sig.to_bytes())
        );
        let claims = v.verify(&token, 1000, None).expect("legacy token verifies");
        assert_eq!(claims.aud, None);
        assert_eq!(claims.cid, None);
    }

    /// An EXPIRED token (now >= exp) is rejected.
    #[test]
    fn expired_token_rejected() {
        let s = signer();
        let v = verifier(&s);
        let tok = s.mint("vk_abc", 1000, None);
        assert_eq!(v.verify(&tok, 1000, None), Err(VerifyError::Expired));
        assert_eq!(v.verify(&tok, 1001, None), Err(VerifyError::Expired));
        assert!(v.verify(&tok, 999, None).is_ok());
    }

    /// A TAMPERED payload (any byte flip) fails the signature check.
    #[test]
    fn tampered_token_rejected() {
        let s = signer();
        let v = verifier(&s);
        let tok = s.mint("vk_abc", 2000, None);
        // Flip a char in the payload segment.
        let body = tok.strip_prefix(TOKEN_PREFIX).unwrap();
        let (payload, sig) = body.split_once('.').unwrap();
        let mut p = payload.to_string();
        let last = p.pop().unwrap();
        p.push(if last == 'A' { 'B' } else { 'A' });
        let tampered = format!("{TOKEN_PREFIX}{p}.{sig}");
        assert!(matches!(
            v.verify(&tampered, 1000, None),
            Err(VerifyError::BadSignature) | Err(VerifyError::Malformed)
        ));
    }

    /// ROTATION: a token signed by key A fails under a verifier holding only key B (same kid: the
    /// signature check fails; different kid: UnknownKid). Both reject.
    #[test]
    fn token_fails_after_rotation() {
        let key_a = TokenSigner::from_secret_bytes(&[1u8; 32], DEFAULT_KID);
        let tok = key_a.mint("vk_abc", 2000, None);

        // Same kid, different key material -> BadSignature.
        let key_b_same_kid = TokenSigner::from_secret_bytes(&[2u8; 32], DEFAULT_KID);
        let v_b = verifier(&key_b_same_kid);
        assert_eq!(v_b.verify(&tok, 1000, None), Err(VerifyError::BadSignature));

        // Different kid entirely -> UnknownKid (the kid the token names is gone from the keyset).
        let key_c = TokenSigner::from_secret_bytes(&[3u8; 32], "k2");
        let v_c = verifier(&key_c);
        assert_eq!(v_c.verify(&tok, 1000, None), Err(VerifyError::UnknownKid));
    }

    /// Malformed inputs (no prefix, no dot, bad base64, wrong sig length) all reject as Malformed.
    #[test]
    fn malformed_tokens_rejected() {
        let s = signer();
        let v = verifier(&s);
        for bad in [
            "not-a-token",
            "bbk_onlyonesegment",
            "bbk_%%%.%%%",
            "bbk_YWJj.YWJj", // decodes but sig is not 64 bytes
        ] {
            assert!(
                matches!(
                    v.verify(bad, 1000, None),
                    Err(VerifyError::Malformed) | Err(VerifyError::BadSignature)
                ),
                "must reject: {bad}"
            );
        }
    }

    /// A generated key round-trips through its raw secret bytes (the persistence path).
    #[test]
    fn generated_key_persists_and_reloads() {
        let s = TokenSigner::generate(DEFAULT_KID).unwrap();
        let bytes = s.secret_bytes();
        let reloaded = TokenSigner::from_secret_bytes(&bytes, DEFAULT_KID);
        let tok = s.mint("vk_x", 2000, None);
        // The reloaded key is the SAME key: it mints/verifies interchangeably.
        let v = TokenVerifier::single(DEFAULT_KID, reloaded.verifying_key());
        assert!(v.verify(&tok, 1000, None).is_ok());
    }

    /// The signer's Debug never leaks key bytes.
    #[test]
    fn signer_debug_redacts_key() {
        let s = signer();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains(&hex::encode([7u8; 32])));
    }
}
