// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE A2A PLANE'S IDENTITY PIN, and the one plane-specific rule the plane-neutral machine must not
//! learn.
//!
//! [`CardPin`] is this plane's [`busbar_kernel::trust::PinnedArtifact`]. Everything else about approval,
//! drift, quarantine, suspension and the dispatch gate is [`busbar_kernel::trust`], unchanged and
//! un-forked. A2A supplies an artifact; it does not supply a second state machine.
//!
//! ## Why the pin is a sum type rather than a string
//!
//! An A2A card's signature is OPTIONAL, so the authenticity root is not one mechanism, it is
//! whichever mechanism this particular upstream can actually offer. Naming it precisely per
//! registration is the design decision:
//!
//! - a SIGNED card is rooted in the operator-supplied, out-of-band issuer key, and the card itself
//!   is identified by its canonical fingerprint. Two values, and drift in either half is drift: a
//!   card re-signed by a different issuer is the look-alike attack, and a card re-issued under the
//!   right key is the rug-pull. A single-value pin could not tell an operator which one happened.
//! - an UNSIGNED card can still be bound at the transport layer, which is a real network-layer root
//!   and still not trust-on-first-use.
//! - and where an operator has neither, [`CardPin::Unpinned`] says so LOUDLY rather than by
//!   omission, because the failure this whole model exists to prevent is a pin that was never really
//!   there reading as one that was.
//!
//! ## The rule that stays on this side of the boundary
//!
//! An `Unpinned` registration is capped: it can be captured and inspected, and it can never be
//! approved. That is an A2A ruling about what A2A's artifact MEANS, so it lives here, in
//! [`approve_registration`], and not in the machine. Teaching the machine that some artifacts are
//! second-class would be teaching it one plane's vocabulary, and the sibling plane would inherit a
//! rule it never asked for.

// PARTLY UNMOUNTED. The artifact and its refusals are driven by the re-verification sweep, and
// `approve_registration` — the A2A cap on approving an unrooted registration — is now driven by
// `super::verbs::approve`. What remains without a caller is the mechanism-specific
// construction `pin_a_signed_card` performs for a mechanism the sweep does not reach.
#![cfg_attr(not(test), allow(dead_code))]

use super::card::{self, CardError};
use super::config::PinMechanism;
use busbar_contract::abi::host::service as svc;
use busbar_kernel::trust::signed;
use busbar_kernel::trust::{Approval, PinnedArtifact, Sighting, TrustError};

/// The identity an A2A registration is pinned to. The mechanism is part of the value, not a
/// separate field, so a registration cannot claim `jws_issuer_key` while carrying a transport pin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CardPin {
    /// A SIGNED card: the operator-supplied out-of-band JWS verification key, plus the canonical
    /// fingerprint of the card it signed.
    JwsIssuerKey {
        issuer_key: String,
        card_fingerprint: String,
    },
    /// An UNSIGNED card bound at the transport layer by the certificate's subject-public-key-info
    /// hash, plus the canonical fingerprint of the card that endpoint served.
    CertKeyPin {
        key_pin: String,
        card_fingerprint: String,
    },
    /// An UNSIGNED card behind mutual TLS, pinned on the peer certificate's SPKI hash.
    MutualTls {
        key_pin: String,
        card_fingerprint: String,
    },
    /// NO authenticity root at all. Legal to register, deliberately impossible to approve, and named
    /// out loud so an operator reading a registration list can see which entries have no root rather
    /// than having to notice an absent field.
    Unpinned,
}

impl CardPin {
    /// The canonical fingerprint this pin is bound to, where it has one.
    pub(crate) fn card_fingerprint(&self) -> Option<&str> {
        match self {
            CardPin::JwsIssuerKey {
                card_fingerprint, ..
            }
            | CardPin::CertKeyPin {
                card_fingerprint, ..
            }
            | CardPin::MutualTls {
                card_fingerprint, ..
            } => Some(card_fingerprint),
            CardPin::Unpinned => None,
        }
    }

    /// Whether this pin is an authenticity root at all. The single question
    /// [`approve_registration`] asks.
    pub(crate) fn is_a_root(&self) -> bool {
        !matches!(self, CardPin::Unpinned)
    }
}

impl PinnedArtifact for CardPin {
    fn mechanism(&self) -> &'static str {
        match self {
            CardPin::JwsIssuerKey { .. } => "jws_issuer_key",
            CardPin::CertKeyPin { .. } => PinMechanism::CertKeyPin.token(),
            CardPin::MutualTls { .. } => PinMechanism::MutualTls.token(),
            CardPin::Unpinned => "unpinned",
        }
    }

    /// A rendering for operator views and audit rows. It names the mechanism and EVERY part the
    /// equality compares, because an audit row saying "the pin changed" that cannot show WHICH half
    /// changed does not tell an operator whether they are looking at a routine key rotation or an
    /// impostor.
    fn digest(&self) -> String {
        match self {
            CardPin::JwsIssuerKey {
                issuer_key,
                card_fingerprint,
            } => format!("jws_issuer_key:{issuer_key}+{card_fingerprint}"),
            CardPin::CertKeyPin {
                key_pin,
                card_fingerprint,
            } => format!(
                "{}:{key_pin}+{card_fingerprint}",
                PinMechanism::CertKeyPin.token()
            ),
            CardPin::MutualTls {
                key_pin,
                card_fingerprint,
            } => format!(
                "{}:{key_pin}+{card_fingerprint}",
                PinMechanism::MutualTls.token()
            ),
            CardPin::Unpinned => "unpinned".to_string(),
        }
    }
}

/// READING AN OPERATOR'S `agents.<name>.pin:` INTO THIS PLANE'S ARTIFACT — the whole of what A2A
/// writes for it. The sequence, and the refusal of a present-but-blank key, are
/// [`busbar_kernel::trust::declared`]'s.
///
/// `None` means "the operator supplied a root but not yet a fingerprint", which is the normal state
/// of a fresh registration: the fingerprint is captured at `connect` and approved by a human. It is
/// deliberately NOT an error, and it is deliberately not filled in with anything the upstream said.
impl busbar_kernel::trust::declared::Declares for CardPin {
    type Mechanism = super::config::PinMechanism;

    fn is_a_root(mechanism: Self::Mechanism) -> bool {
        mechanism.is_a_root()
    }

    fn artifact(
        reading: busbar_kernel::trust::declared::Reading<'_, Self::Mechanism>,
    ) -> Option<Self> {
        use busbar_kernel::trust::declared::Reading;
        match reading {
            // NAMED OUT LOUD, which is this plane's ruling and not core's: an operator reading a
            // registration list must SEE which entries have no root rather than inferring it from
            // an absent field. It is still impossible to approve — [`approve_registration`] is what
            // caps it, and [`CardPin::is_a_root`] is the question it asks.
            Reading::NoRoot { .. } => Some(CardPin::Unpinned),
            Reading::Rooted {
                mechanism,
                key,
                fingerprint,
            } => {
                // NO FINGERPRINT IS NOT AN ERROR AND IS NOT A PIN. Every rooted mechanism on this
                // plane binds the canonical fingerprint of the card the root signed or served, so a
                // declaration without one has named a root and approved no document. Fabricating
                // the missing half would pin the registration to whatever arrives first.
                let card_fingerprint = fingerprint?.to_string();
                let key = key.to_string();
                match mechanism {
                    PinMechanism::JwsIssuerKey => Some(CardPin::JwsIssuerKey {
                        issuer_key: key,
                        card_fingerprint,
                    }),
                    PinMechanism::CertKeyPin => Some(CardPin::CertKeyPin {
                        key_pin: key,
                        card_fingerprint,
                    }),
                    PinMechanism::MutualTls => Some(CardPin::MutualTls {
                        key_pin: key,
                        card_fingerprint,
                    }),
                    // UNREACHABLE BY CONSTRUCTION — `is_a_root` routed this mechanism to `NoRoot`
                    // above. It is spelled out rather than `_`-ed so a mechanism added to the
                    // grammar later is a compile error here until it has been given an artifact,
                    // which is the whole reason `Reading` carries the plane's own enum.
                    PinMechanism::Unpinned => None,
                }
            }
        }
    }
}

/// Why an A2A approval was refused. The plane-neutral refusals pass through unchanged; this adds
/// exactly the one A2A rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApproveError {
    /// The pin on offer is [`CardPin::Unpinned`], so approving would lock the registration to no
    /// identity at all and every later observation would "match". A capped registration is
    /// inspectable and never delegable.
    Unpinned,
    /// A refusal that belongs to the plane-neutral machine.
    Trust(TrustError),
}

impl std::fmt::Display for ApproveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApproveError::Unpinned => write!(
                f,
                "cannot approve: this registration has no authenticity root (unpinned). Supply an \
                 issuer key out of band, or pin the endpoint at the transport layer."
            ),
            ApproveError::Trust(e) => write!(f, "{e}"),
        }
    }
}

/// APPROVE on the A2A plane: the plane-neutral approval, with the unpinned cap applied FIRST.
///
/// The check is on the pin that would actually be locked (the operator's out-of-band override where
/// they supplied one, otherwise whatever the endpoint presented), and not merely on what the
/// endpoint offered. Checking the offered value would let an operator override an unpinned
/// observation with an unpinned override and still land approved.
pub fn approve_registration(
    approval: &mut Approval<CardPin>,
    sighting: &Sighting<CardPin>,
    pin_override: Option<CardPin>,
) -> Result<(), ApproveError> {
    let candidate = pin_override
        .clone()
        .or_else(|| observed_pin(sighting))
        .ok_or(ApproveError::Trust(TrustError::NoPinToLock))?;
    if !candidate.is_a_root() {
        return Err(ApproveError::Unpinned);
    }
    approval
        .approve(sighting, pin_override)
        .map_err(ApproveError::Trust)
}

fn observed_pin(sighting: &Sighting<CardPin>) -> Option<CardPin> {
    match sighting {
        Sighting::Seen(o) => o.pin.clone(),
        _ => None,
    }
}

/// Why a card was not accepted as signed by the pinned issuer. Every arm is a REFUSAL: there is no
/// arm that means "could not check, proceeding".
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JwsError {
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

/// THE SANCTIONED WAY TO PRODUCE A SIGNED PIN: verify first, then pin what verified.
///
/// The ordering is the whole point. A fingerprint taken before verification is a fingerprint of
/// whatever arrived, and pinning it would record "the operator approved this card" about a document
/// nobody authenticated. So the signature is checked against the operator's out-of-band key FIRST,
/// and the fingerprint is only computed on the document that passed.
///
/// The verdict is the kernel's ([`busbar_kernel::trust::signed`], the verifier behind
/// `trust.verify`): the card's detached payload is [`card::signing_payload`], its `signatures` go
/// as written, and the `SIGNED_*` refusal is read back as this plane's [`JwsError`] words.
///
/// `issuer_key_info` travels into the pin verbatim, as the operator wrote it, because that string is
/// what an operator compares against the value their vendor published out of band. Re-rendering it
/// from the parsed key would produce a value that is correct and that they cannot check by eye.
pub(crate) fn pin_a_signed_card(
    card: &serde_json::Value,
    issuer_key_info: &str,
) -> Result<CardPin, JwsError> {
    let refused = |r| jws_refusal(r, card);
    let root = signed::root_key(issuer_key_info).map_err(refused)?;
    let payload = card::signing_payload(card)?;
    let signatures = card.get("signatures").unwrap_or(&serde_json::Value::Null);
    signed::verify(payload.as_bytes(), signatures, &root).map_err(refused)?;
    Ok(CardPin::JwsIssuerKey {
        issuer_key: issuer_key_info.trim().to_string(),
        card_fingerprint: card::fingerprint(card)?,
    })
}

/// The kernel's `SIGNED_*` verdict, in this plane's words: one arm per verdict, the name it carries
/// where it carries one, and the card's own signature count for [`JwsError::TooManySignatures`].
fn jws_refusal((verdict, name): signed::Refused, card: &serde_json::Value) -> JwsError {
    match verdict {
        svc::SIGNED_MALFORMED_ROOT => JwsError::MalformedIssuerKey,
        svc::SIGNED_TOO_MANY => JwsError::TooManySignatures(
            card.get("signatures")
                .and_then(serde_json::Value::as_array)
                .map_or(0, Vec::len),
        ),
        svc::SIGNED_MALFORMED_HEADER => JwsError::MalformedProtectedHeader,
        svc::SIGNED_ALGORITHM => JwsError::UnsupportedAlgorithm(name),
        svc::SIGNED_CRITICAL => JwsError::UnknownCriticalHeader(name),
        svc::SIGNED_MALFORMED_SIGNATURE => JwsError::MalformedSignature,
        svc::SIGNED_NOT_BY_ROOT => JwsError::NoSignatureVerified,
        // SIGNED_NONE: no `signatures` member, or an empty one.
        _ => JwsError::Unsigned,
    }
}

#[cfg(all(test, feature = "test-support"))]
#[path = "tests/pin_tests.rs"]
mod pin_tests;

#[cfg(all(test, feature = "test-support"))]
#[path = "tests/pin_jws_tests.rs"]
mod pin_jws_tests;

#[cfg(all(test, feature = "test-support"))]
#[path = "tests/reuse_tests.rs"]
mod reuse_tests;
