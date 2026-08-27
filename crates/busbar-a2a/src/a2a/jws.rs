// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! AGENT CARD SIGNATURE VERIFICATION against the OPERATOR-SUPPLIED, OUT-OF-BAND issuer key.
//!
//! This is the module that makes the trust root real. Without it the pin is a fingerprint compare,
//! which detects that a card CHANGED and says nothing about who wrote it; a rewritten card served
//! from a hijacked CDN would simply look like a new card awaiting approval. With it, a card that
//! was not signed by the key the operator supplied out of band is never honored at all.
//!
//! ## The algorithm is decided by the KEY, never by the header
//!
//! This is the single most important line in the file. A JWS header is written by whoever wrote the
//! signature, which on this plane is the party being authenticated. Reading `alg` from it and
//! dispatching on the result is how `alg: none` works, and how algorithm confusion works: declare
//! `HS256` and hand back an HMAC computed with the operator's PUBLIC key as the shared secret, which
//! is a value the attacker also has. So the pinned key selects the verifier, the header is only
//! CHECKED for agreement, and a disagreement is a refusal rather than a fallback.
//!
//! ## What is supported, stated rather than implied
//!
//! `EdDSA` over Ed25519, and nothing else. Every other algorithm is refused BY NAME, including the
//! ones a wider build might one day support: a verifier that silently ignored a signature it could
//! not check would report "unsigned" for a card that is signed, and an operator would then pin it at
//! a weaker mechanism believing that was the best the vendor offered. Adding an algorithm means
//! adding a dependency and a pinned key type, which is a deliberate act and not a fallback.
//!
//! ## The payload is DETACHED
//!
//! A card's signature covers the card, and the card is not inside the signature object. The signing
//! input is the JWS spec's `BASE64URL(protected) || "." || BASE64URL(payload)`, where the payload is
//! the canonical card with `signatures` removed ([`super::card::signing_payload`]). The protected
//! header is used EXACTLY AS RECEIVED, never re-encoded: re-serializing it would change the bytes
//! that were actually signed, and a verifier that did so would reject every genuine signature whose
//! producer spelled the header differently than we would have.

use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;

use super::card::{signing_payload, CardError};

/// Base64url WITHOUT padding, which is the only encoding JWS permits for these fields. Strict, so a
/// padded or otherwise non-canonical spelling is refused rather than quietly accepted: two encodings
/// of one signature would be two signatures over one card as far as any audit row is concerned.
pub(crate) const B64URL: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// The DER prefix of an Ed25519 SubjectPublicKeyInfo, RFC 8410 section 4: `SEQUENCE { SEQUENCE {
/// OID 1.3.101.112 }, BIT STRING }`. It is fixed-length and fully determined, so a key that does not
/// carry it byte for byte is not an Ed25519 SPKI and is refused rather than salvaged.
pub(crate) const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// A hostile card can carry as many signatures as it likes, and each one costs a verification. The
/// cap is small because a legitimate card needs one, or a handful across a key rotation.
const MAX_SIGNATURES: usize = 8;

/// Why a card was not accepted as signed by the pinned issuer. Every arm is a REFUSAL: there is no
/// arm that means "could not check, proceeding".
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum JwsError {
    /// The operator-supplied key is not an Ed25519 SubjectPublicKeyInfo.
    MalformedIssuerKey,
    /// The card carries no `signatures` member, or an empty one. Distinct from
    /// [`JwsError::NoSignatureVerified`] on purpose: "this vendor does not sign" is an operator
    /// decision about which mechanism to pin, while "signed, but not by the pinned key" is an alarm.
    Unsigned,
    /// More signatures than any legitimate card needs.
    TooManySignatures(usize),
    /// A `protected` header that is not base64url, not JSON, or not an object.
    MalformedProtectedHeader,
    /// The header's `alg` is not the one the pinned key implies. Carries what was asked for, so an
    /// audit row can say whether it saw `none`, a symmetric algorithm, or simply an algorithm this
    /// build does not implement.
    UnsupportedAlgorithm(String),
    /// RFC 7515 section 4.1.11: a verifier that does not understand a member listed in `crit` MUST
    /// reject the signature. Ignoring it is how an extension that CHANGES the meaning of the
    /// signature gets silently dropped.
    UnknownCriticalHeader(String),
    /// The signature is not base64url, or not 64 bytes.
    MalformedSignature,
    /// The card is signed, well-formed, and NOT by the pinned issuer key. This is the look-alike and
    /// the hijacked-CDN case, and it is the one that must never degrade to anything softer.
    NoSignatureVerified,
    /// The card could not be canonicalized, so there is no payload to verify against.
    Card(CardError),
}

impl std::fmt::Display for JwsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwsError::MalformedIssuerKey => write!(
                f,
                "the pinned issuer key is not an Ed25519 SubjectPublicKeyInfo"
            ),
            JwsError::Unsigned => write!(f, "the agent card carries no signature"),
            JwsError::TooManySignatures(n) => write!(
                f,
                "the agent card carries {n} signatures, more than any legitimate card needs"
            ),
            JwsError::MalformedProtectedHeader => {
                write!(
                    f,
                    "a signature's protected header is not a base64url JSON object"
                )
            }
            JwsError::UnsupportedAlgorithm(alg) => write!(
                f,
                "signature algorithm `{alg}` is refused: the pinned key selects the algorithm, and \
                 a header that disagrees with it is not honored"
            ),
            JwsError::UnknownCriticalHeader(name) => write!(
                f,
                "a signature marks `{name}` critical and this verifier does not implement it"
            ),
            JwsError::MalformedSignature => {
                write!(f, "a signature is not 64 bytes of base64url")
            }
            JwsError::NoSignatureVerified => write!(
                f,
                "the agent card is signed, but not by the pinned issuer key"
            ),
            JwsError::Card(e) => write!(f, "{e}"),
        }
    }
}

impl From<CardError> for JwsError {
    fn from(e: CardError) -> Self {
        JwsError::Card(e)
    }
}

/// The operator's out-of-band issuer key, parsed once at the boundary.
///
/// A parsed type rather than a string, so a caller cannot reach verification holding something that
/// was never checked. There is no way to build one from a key that failed to parse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IssuerKey(VerifyingKey);

impl IssuerKey {
    /// Parse a base64 Ed25519 SubjectPublicKeyInfo, which is the form the operator pastes.
    ///
    /// ONE accepted form, deliberately. A raw 32-byte fallback would be unambiguous by length and
    /// would still be wrong to offer: it lets an operator paste the wrong half of a key pair, or a
    /// key of a different algorithm that happens to be 32 bytes, and have it silently become the
    /// trust root. The SPKI wrapper names the algorithm, so requiring it means the key itself says
    /// what it is.
    pub(crate) fn from_spki_base64(s: &str) -> Result<Self, JwsError> {
        let der = base64::engine::general_purpose::STANDARD
            .decode(s.trim())
            .map_err(|_| JwsError::MalformedIssuerKey)?;
        if der.len() != ED25519_SPKI_PREFIX.len() + 32 || der[..12] != ED25519_SPKI_PREFIX {
            return Err(JwsError::MalformedIssuerKey);
        }
        let mut raw = [0u8; 32];
        raw.copy_from_slice(&der[12..]);
        VerifyingKey::from_bytes(&raw)
            .map(IssuerKey)
            .map_err(|_| JwsError::MalformedIssuerKey)
    }
}

/// What a successful verification establishes. Returned rather than a bare `bool` so a caller cannot
/// record "verified" without recording WHICH signature verified, which is what an operator needs
/// when a vendor rotates a key and two signatures are briefly present.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Verified {
    /// The index of the signature that verified, in the order the card listed them.
    pub(crate) index: usize,
    /// The `kid` the verifying signature declared, if it declared one. Operator-facing only; it is
    /// NOT how the key was selected, because a `kid` is attacker-written.
    pub(crate) kid: Option<String>,
}

/// VERIFY the card against the operator-supplied issuer key.
///
/// Succeeds when at least one signature verifies against THAT key. Signatures by other issuers are
/// not evidence of anything on this plane: the operator pinned one identity, and a card countersigned
/// by a party the operator never named is exactly what an attacker who can add a signature would
/// produce.
pub(crate) fn verify_card(card: &Value, issuer: &IssuerKey) -> Result<Verified, JwsError> {
    let payload = signing_payload(card)?;
    let signing_payload_b64 = B64URL.encode(payload.as_bytes());

    let signatures = card
        .get("signatures")
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
        .ok_or(JwsError::Unsigned)?;
    if signatures.len() > MAX_SIGNATURES {
        return Err(JwsError::TooManySignatures(signatures.len()));
    }

    // A malformed signature is a hard refusal rather than a skip. Skipping would let an attacker
    // append a well-formed forgery after a pile of garbage and have the pile cost nothing, and more
    // importantly it would mean a card whose ONLY signature is malformed reports as merely
    // unverified, which is the softer of the two alarms and the wrong one.
    let mut verified: Option<Verified> = None;
    for (index, sig) in signatures.iter().enumerate() {
        let protected_b64 = sig
            .get("protected")
            .and_then(Value::as_str)
            .ok_or(JwsError::MalformedProtectedHeader)?;
        let header = decode_protected_header(protected_b64)?;
        check_algorithm(&header)?;
        check_critical_headers(&header)?;

        let signature = decode_signature(sig)?;
        let signing_input = format!("{protected_b64}.{signing_payload_b64}");
        if issuer
            .0
            .verify(signing_input.as_bytes(), &signature)
            .is_ok()
            && verified.is_none()
        {
            verified = Some(Verified {
                index,
                kid: header
                    .get("kid")
                    .and_then(Value::as_str)
                    .map(str::to_string),
            });
        }
    }
    verified.ok_or(JwsError::NoSignatureVerified)
}

fn decode_protected_header(
    protected_b64: &str,
) -> Result<serde_json::Map<String, Value>, JwsError> {
    let raw = B64URL
        .decode(protected_b64)
        .map_err(|_| JwsError::MalformedProtectedHeader)?;
    let parsed: Value =
        serde_json::from_slice(&raw).map_err(|_| JwsError::MalformedProtectedHeader)?;
    match parsed {
        Value::Object(map) => Ok(map),
        _ => Err(JwsError::MalformedProtectedHeader),
    }
}

/// The header must AGREE with the pinned key's algorithm. It does not get to choose it.
///
/// A missing `alg` is refused rather than defaulted, because a default is a choice made on the
/// attacker's behalf.
fn check_algorithm(header: &serde_json::Map<String, Value>) -> Result<(), JwsError> {
    match header.get("alg").and_then(Value::as_str) {
        Some("EdDSA") => Ok(()),
        Some(other) => Err(JwsError::UnsupportedAlgorithm(other.to_string())),
        None => Err(JwsError::UnsupportedAlgorithm(String::new())),
    }
}

/// RFC 7515 section 4.1.11. `crit` lists header members the producer says MUST be understood. This
/// verifier implements none of them, so any `crit` entry is a refusal.
///
/// `b64` is the reason this matters rather than being pedantry: RFC 7797's `b64: false` changes the
/// signing input itself, so a verifier that ignored it would compute a different input, fail, and
/// report a genuine card as forged. A `crit` this verifier cannot honor is a refusal in EITHER
/// direction, and naming the member is what lets an operator tell the two apart.
fn check_critical_headers(header: &serde_json::Map<String, Value>) -> Result<(), JwsError> {
    let Some(crit) = header.get("crit") else {
        return Ok(());
    };
    let names = crit.as_array().ok_or(JwsError::MalformedProtectedHeader)?;
    match names.first() {
        Some(Value::String(name)) => Err(JwsError::UnknownCriticalHeader(name.clone())),
        // A `crit` present but empty, or holding a non-string, is malformed per the same section.
        _ => Err(JwsError::MalformedProtectedHeader),
    }
}

fn decode_signature(sig: &Value) -> Result<Signature, JwsError> {
    let raw = B64URL
        .decode(
            sig.get("signature")
                .and_then(Value::as_str)
                .ok_or(JwsError::MalformedSignature)?,
        )
        .map_err(|_| JwsError::MalformedSignature)?;
    let bytes: [u8; 64] = raw.try_into().map_err(|_| JwsError::MalformedSignature)?;
    Ok(Signature::from_bytes(&bytes))
}

#[cfg(all(test, not(busbar_a2a_native)))]
#[path = "tests/jws_tests.rs"]
mod jws_tests;
