// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! BUSBAR SIGNS THE CARDS IT SERVES, so an external caller has something to pin busbar BY.
//!
//! The receiving side rewrites a fronted agent's card through busbar and, in doing so, destroys the
//! vendor's signature: the document is no longer the one the vendor signed, so their JWS cannot
//! verify over it and [`super::serve::rewrite_card`] drops it rather than publish one that fails.
//! Until this module existed nothing replaced it, and "busbar's card IS the thing external callers
//! pin against" was a property the build did not have — busbar demanded a signed, out-of-band-rooted
//! card from every agent it delegates to, and offered an unsigned one to everybody who calls it.
//! This is the other half of its own trust model.
//!
//! ## THE KEY IS DERIVED FROM THE TOKEN SIGNING KEY. IT IS NOT THE TOKEN SIGNING KEY
//!
//! busbar already holds exactly one long-lived ed25519 secret: the one
//! [`crate::governance::signing::TokenSigner`] mints virtual-key tokens with. Reusing it verbatim
//! here was the obvious move and it is the wrong one, for a reason that is specific rather than
//! hygienic:
//!
//! **the document busbar signs is largely authored by somebody else.** A served card is a VENDOR's
//! card with busbar's endpoints substituted in; every other member — names, descriptions, skills,
//! whatever unmodelled extensions the vendor ships — travels through verbatim. Signing it with the
//! credential-minting key would make the card-signing path a signing oracle over upstream-chosen
//! bytes, holding the key that mints working busbar credentials. Nothing about JWS makes that
//! exploitable today (the token payload is a bare JSON object and a JWS signing input never is
//! one), but "the two message formats happen not to overlap" is an argument that has to be
//! re-checked every time either format moves, and nobody will re-check it.
//!
//! So the card key is a **domain-separated subkey**:
//! `SHA-256("busbar/subkey/v1" ‖ token_secret ‖ "a2a/agent-card-signing/v1")`. The blast radius is
//! then stated in both directions, which is the point of choosing rather than defaulting:
//!
//! - **Card key compromised ⇒ tokens are unaffected.** The derivation is a one-way hash, so an
//!   attacker holding the card key cannot walk back to the token secret. They can impersonate
//!   busbar's *card* to a caller who pinned it, and they cannot mint a virtual key.
//! - **Token secret compromised ⇒ the card key falls too.** The token secret is the root of both.
//!   That is accepted rather than hidden: an attacker holding it can already mint any credential in
//!   the deployment, so a forged agent card is not the interesting thing they would do with it.
//! - **Operationally there is one secret to hold, generate and rotate.** A second configured key is
//!   a second key an operator can fail to rotate, and a first-boot zero-config deployment that
//!   generates one key still serves signed cards. Rotating the token key rotates the card key with
//!   it, which is visible to callers as a `kid` change — the same rotation signal busbar's own
//!   `approve-pin` path is built to absorb.
//!
//! ## THE WIRE FORMAT IS THE ONE BUSBAR ALREADY VERIFIES
//!
//! Not a second format that happens to look similar. The signature this module produces is checked
//! by [`super::jws::verify_card`] — the same detached-payload construction, over
//! [`super::card::signing_payload`], which is [`super::canonical::canonicalize`] with `signatures`
//! removed. There is exactly one canonicalizer on this plane and both halves call it, because two
//! halves with two canonicalizers disagree about what was signed the first time a card contains a
//! number, a supplementary-plane character, or a member busbar does not model.

use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::canonical::canonicalize;
use super::card::{signing_payload, CardError};
use super::jws::{B64URL, ED25519_SPKI_PREFIX};

/// The domain string the card-signing subkey is derived under. Versioned, so a future change to the
/// derivation is a NEW key rather than a silently different one under the same name.
pub(crate) const CARD_SIGNING_DOMAIN: &str = "a2a/agent-card-signing/v1";

/// The `kid` busbar stamps into every card signature, derived from the token signer's own kid.
///
/// Prefixed rather than reused bare, because a `kid` that read `k1` on both a token and a card
/// would tell an operator that one key signs both — which is exactly the thing the derivation
/// exists to make untrue.
pub(crate) fn card_kid(token_kid: &str) -> String {
    format!("busbar-a2a-card-{token_kid}")
}

/// Why a card could not be signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SignError {
    /// The document cannot be canonicalized, so there is no payload to sign.
    Card(CardError),
}

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignError::Card(e) => write!(f, "cannot sign the agent card: {e}"),
        }
    }
}

impl From<CardError> for SignError {
    fn from(e: CardError) -> Self {
        SignError::Card(e)
    }
}

/// BUSBAR'S AGENT-CARD ISSUER KEY: the domain-separated subkey, plus the `kid` it publishes under.
///
/// Its `Debug` never prints key bytes, for the same reason
/// [`crate::governance::signing::TokenSigner`]'s does not.
pub(crate) struct CardSigner {
    key: SigningKey,
    kid: String,
}

impl std::fmt::Debug for CardSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CardSigner")
            .field("kid", &self.kid)
            .field("key", &"<redacted ed25519 signing key>")
            .finish()
    }
}

impl CardSigner {
    /// Derive the card-signing key from busbar's token signing key.
    ///
    /// The ONLY constructor that production uses, and it takes the signer rather than raw bytes so
    /// there is no call site at which the token secret itself could be handed in as a card key by
    /// mistake.
    pub(crate) fn derived_from(signer: &crate::governance::signing::TokenSigner) -> Self {
        Self {
            key: SigningKey::from_bytes(&signer.derived_subkey_seed(CARD_SIGNING_DOMAIN)),
            kid: card_kid(signer.kid()),
        }
    }

    /// The `kid` this signer stamps, and the one a caller reads off the served card.
    pub(crate) fn kid(&self) -> &str {
        &self.kid
    }

    /// BUSBAR'S PUBLISHED ISSUER KEY, in the exact form the verifier accepts.
    ///
    /// Base64 of an Ed25519 SubjectPublicKeyInfo — the string an operator hands their counterparty
    /// out of band, and the string that counterparty pastes into their own `pin.key:`. Rendered
    /// through the same SPKI prefix [`super::jws::IssuerKey::from_spki_base64`] requires, so a value
    /// this method emits and a value that method accepts cannot drift into two spellings.
    pub(crate) fn issuer_spki_base64(&self) -> String {
        let mut der = Vec::with_capacity(ED25519_SPKI_PREFIX.len() + 32);
        der.extend_from_slice(&ED25519_SPKI_PREFIX);
        der.extend_from_slice(self.key.verifying_key().as_bytes());
        base64::engine::general_purpose::STANDARD.encode(der)
    }

    /// SIGN a card, returning it with busbar's signature attached under `signatures`.
    ///
    /// Any signature already on the document is REPLACED, not appended to. A served card carries
    /// busbar's signature and no other: the vendor's cannot verify over a rewritten document, and a
    /// second signature from an unnamed party is the countersigning shape
    /// [`super::jws::verify_card`] is written to give no weight to. Attaching after the payload is
    /// computed is not merely convenient — [`signing_payload`] REMOVES `signatures`, so what is
    /// signed is the card without it and inserting afterwards cannot change what was signed.
    pub(crate) fn sign_card(&self, card: &Value) -> Result<Value, SignError> {
        let payload_b64 = B64URL.encode(signing_payload(card)?.as_bytes());

        // THE PROTECTED HEADER, through the SAME canonicalizer the payload uses. A second
        // serializer here would be a second set of bytes this plane calls canonical.
        let protected = canonicalize(&json!({ "alg": "EdDSA", "kid": self.kid }))
            .map_err(|e| SignError::Card(CardError::Canonical(e)))?;
        let protected_b64 = B64URL.encode(protected.as_bytes());

        // RFC 7515's signing input, spelled exactly as the verifier spells it.
        let signing_input = format!("{protected_b64}.{payload_b64}");
        let signature = self.key.sign(signing_input.as_bytes());

        let mut out: Map<String, Value> = card
            .as_object()
            .ok_or(SignError::Card(CardError::NotAnObject))?
            .clone();
        out.insert(
            "signatures".to_string(),
            json!([{
                "protected": protected_b64,
                "signature": B64URL.encode(signature.to_bytes()),
            }]),
        );
        Ok(Value::Object(out))
    }
}

/// The domain-separated derivation itself, as a free function so it can be asserted on directly.
///
/// `SHA-256(context ‖ secret ‖ domain)`. The secret is a FIXED 32 bytes and sits in the middle, so
/// the boundary between it and the domain string is unambiguous without a length prefix — two
/// different domains cannot produce one pre-image by moving the boundary.
pub(crate) fn subkey_seed(secret: &[u8; 32], domain: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"busbar/subkey/v1");
    h.update(secret);
    h.update(domain.as_bytes());
    h.finalize().into()
}

#[cfg(test)]
#[path = "tests/sign_tests.rs"]
mod sign_tests;
