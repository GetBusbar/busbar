// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE A2A PLANE'S IDENTITY PIN, and the one plane-specific rule the plane-neutral machine must not
//! learn.
//!
//! [`CardPin`] is this plane's [`crate::trust::PinnedArtifact`]. Everything else about approval,
//! drift, quarantine, suspension and the dispatch gate is [`crate::trust`], unchanged and
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

use crate::trust::{Approval, PinnedArtifact, Sighting, TrustError};

/// The identity an A2A registration is pinned to. The mechanism is part of the value, not a
/// separate field, so a registration cannot claim `jws_issuer_key` while carrying a transport pin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CardPin {
    /// A SIGNED card: the operator-supplied out-of-band JWS verification key, plus the canonical
    /// fingerprint of the card it signed.
    JwsIssuerKey {
        issuer_key: String,
        card_fingerprint: String,
    },
    /// An UNSIGNED card bound at the transport layer by the certificate's subject-public-key-info
    /// hash, plus the canonical fingerprint of the card that endpoint served.
    CertSpki {
        spki: String,
        card_fingerprint: String,
    },
    /// An UNSIGNED card behind mutual TLS, pinned on the peer certificate's SPKI hash.
    Mtls {
        spki: String,
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
            | CardPin::CertSpki {
                card_fingerprint, ..
            }
            | CardPin::Mtls {
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
            CardPin::CertSpki { .. } => "cert_spki",
            CardPin::Mtls { .. } => "mtls",
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
            CardPin::CertSpki {
                spki,
                card_fingerprint,
            } => format!("cert_spki:{spki}+{card_fingerprint}"),
            CardPin::Mtls {
                spki,
                card_fingerprint,
            } => format!("mtls:{spki}+{card_fingerprint}"),
            CardPin::Unpinned => "unpinned".to_string(),
        }
    }
}

/// Why an A2A approval was refused. The plane-neutral refusals pass through unchanged; this adds
/// exactly the one A2A rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ApproveError {
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
pub(crate) fn approve_registration(
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

#[cfg(test)]
#[path = "tests/pin_tests.rs"]
mod pin_tests;

#[cfg(test)]
#[path = "tests/reuse_tests.rs"]
mod reuse_tests;
