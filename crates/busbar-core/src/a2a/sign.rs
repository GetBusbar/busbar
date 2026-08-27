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
//! [`busbar_substrate::governance::signing::TokenSigner`] mints virtual-key tokens with. Reusing it verbatim
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
use serde_json::{json, Map, Value};

use super::canonical::canonicalize;
use super::card::{signing_payload, CardError};
use super::jws::B64URL;

/// The domain string the card-signing subkey is derived under. Versioned, so a future change to the
/// derivation is a NEW key rather than a silently different one under the same name.
pub(crate) const CARD_SIGNING_DOMAIN: &str = "a2a/agent-card-signing/v1";

/// The `kid` PREFIX busbar stamps into every card signature, prepended to the token signer's own kid.
///
/// Prefixed rather than reused bare, because a `kid` that read `k1` on both a token and a card
/// would tell an operator that one key signs both — which is exactly the thing the derivation
/// exists to make untrue. Declared on this plane's `PlaneDecl` (`card_kid_prefix`) so the host builds
/// the published issuer `kid` (`GovState::a2a_card_issuer`) from it without naming this plane.
pub(crate) const CARD_KID_PREFIX: &str = "busbar-a2a-card-";

/// Why a card could not be signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SignError {
    /// The document cannot be canonicalized, so there is no payload to sign.
    Card(CardError),
    /// The host card-signing capability yielded no signature — the deployment holds no card-signing
    /// key. `card_signer` screens this out before a `CardSigner` is built, so it is an
    /// invariant-violation guard rather than a path a served card reaches.
    HostUnavailable,
}

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignError::Card(e) => write!(f, "cannot sign the agent card: {e}"),
            SignError::HostUnavailable => {
                write!(
                    f,
                    "cannot sign the agent card: the host holds no card-signing key"
                )
            }
        }
    }
}

impl From<CardError> for SignError {
    fn from(e: CardError) -> Self {
        SignError::Card(e)
    }
}

/// BUSBAR'S AGENT-CARD SIGNER for one served card: the PUBLIC issuer key (`kid` + SPKI) this
/// deployment publishes, plus the live [`App`](crate::state::App) that is the seam to the host's
/// `card_sign` capability.
///
/// The plane holds NO card-signing key. The subkey is derived and held host-side
/// ([`crate::governance::state::GovState::card_sign`], reached through
/// [`crate::plane_host::card_sign_over`]); this type carries only PUBLIC material and a `&App`, and
/// `sign_card` hands the framed signing input to the host and receives the 64 signature bytes back.
/// That is the shape the R7 relocation needs: the extracted A2A crate names no signing-secret type.
pub(crate) struct CardSigner<'a> {
    /// The live app snapshot — the seam through which [`Self::sign_card`] reaches the host card signer.
    app: &'a crate::state::App,
    /// The PUBLIC card-issuer key (`kid` + SPKI base64), computed host-side.
    issuer: crate::plane::registry::CardIssuer,
}

impl std::fmt::Debug for CardSigner<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CardSigner")
            .field("kid", &self.issuer.kid)
            .finish_non_exhaustive()
    }
}

/// THE A2A PLANE'S CARD SIGNER for this deployment: the PUBLIC issuer key bound to the live app, so
/// `sign_card` can reach the host card-signing capability. The issuer is read off the plane's OWN
/// runtime slot ([`super::runtime`]'s [`crate::a2a::plane::A2aPlane::card_issuer`]), where the plane's
/// `start` hook stashed the host-computed [`crate::plane::registry::BootCtx::card_issuer`] — so this
/// plane names no `GovState`. `None` when no signing key is configured (the governance-off path) or
/// before the start hook has run, matching the old typed accessor's own absence — the caller then
/// serves an unsigned card.
pub(crate) fn card_signer(app: &crate::state::App) -> Option<CardSigner<'_>> {
    let issuer = super::runtime(app)?.card_issuer()?.clone();
    Some(CardSigner { app, issuer })
}

impl CardSigner<'_> {
    /// The `kid` this signer stamps, and the one a caller reads off the served card. The published
    /// value lives on the [`CardIssuer`](crate::plane::registry::CardIssuer) this wraps; this is the
    /// plane-side accessor the card-signing test suite reads it back through.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn kid(&self) -> &str {
        &self.issuer.kid
    }

    /// BUSBAR'S PUBLISHED ISSUER KEY, in the exact form the verifier accepts.
    ///
    /// Base64 of an Ed25519 SubjectPublicKeyInfo — the string an operator hands their counterparty
    /// out of band, and the string that counterparty pastes into their own `pin.key:`. Computed
    /// host-side under the same SPKI prefix [`super::jws::IssuerKey::from_spki_base64`] requires, so a
    /// value this method emits and a value that method accepts cannot drift into two spellings.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn issuer_spki_base64(&self) -> String {
        self.issuer.issuer_spki_base64.clone()
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
        let protected = canonicalize(&json!({ "alg": "EdDSA", "kid": self.issuer.kid }))
            .map_err(|e| SignError::Card(CardError::Canonical(e)))?;
        let protected_b64 = B64URL.encode(protected.as_bytes());

        // RFC 7515's signing input, spelled exactly as the verifier spells it.
        let signing_input = format!("{protected_b64}.{payload_b64}");
        // THE HOST DOES THE CRYPTO. The plane frames the signing input and hands the bytes to the
        // host `card_sign` seam; the domain-derived card subkey is expanded and used entirely
        // host-side (`GovState::card_sign`) and only the 64 signature bytes come back — so no signing
        // material is ever held on this plane. `None` only if the deployment holds no card-signing
        // key, which `card_signer` already screened out before constructing a `CardSigner`.
        let signature = crate::plane_host::card_sign_over(self.app, signing_input.as_bytes())
            .ok_or(SignError::HostUnavailable)?;

        let mut out: Map<String, Value> = card
            .as_object()
            .ok_or(SignError::Card(CardError::NotAnObject))?
            .clone();
        out.insert(
            "signatures".to_string(),
            json!([{
                "protected": protected_b64,
                "signature": B64URL.encode(signature),
            }]),
        );
        Ok(Value::Object(out))
    }
}

#[cfg(test)]
#[path = "tests/sign_tests.rs"]
mod sign_tests;
