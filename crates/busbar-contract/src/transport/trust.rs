// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! HOST-OWNED TRUST, as seam currency between the unit that decides it and the transport that
//! applies it.
//!
//! Two byte-producing capabilities used to live only inside a fat plane crate, with no twin on the
//! spine a neutral onboarding plane could reach. This module is that twin: the plain, dependency-free
//! shapes a composition root fills in and hands ACROSS a seam, so the transport that consumes them
//! never has to name the unit that produced them and the unit never has to name the transport that
//! will apply them. Both sides name only this crate — which is exactly why the three transport-facing
//! units (egress, trust, transport-key) are told to name it directly.
//!
//! ## The unset value is today's behaviour, exactly
//!
//! Every field here defaults to "the host decided nothing extra". A default [`EgressTrust`] asks a
//! transport for precisely the posture it already had — platform trust anchors, the stack's own
//! certificate check, and no client certificate — so a seam handed a default value is byte-for-byte
//! the seam that was handed nothing. The capability is therefore ADDITIVE: it changes no existing
//! caller until a caller fills a field in.

/// A parsed client identity: a certificate chain and the private key that proves it, both in DER.
///
/// The chain is leaf-first, the way a TLS stack presents it. The private key is the DER a stack
/// parses; the host owns the parse and never lets the plane hold it, so what crosses this seam is the
/// material a composition root already resolved, not a handle into a registry the transport cannot
/// reach.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ClientIdentity {
    /// The certificate chain to present, leaf first, each entry one DER certificate.
    pub cert_chain: Vec<Vec<u8>>,
    /// The private key, in DER, that proves the leaf.
    pub private_key: Vec<u8>,
}

impl core::fmt::Debug for ClientIdentity {
    /// Hand-rolled to REDACT the private key. The DER private key is secret material a derived
    /// `Debug` would spill byte-for-byte into any log line or panic that formats this type; the
    /// certificate chain is public and prints as itself, and the key prints as `<redacted>`.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClientIdentity")
            .field("cert_chain", &self.cert_chain)
            .field("private_key", &"<redacted>")
            .finish()
    }
}

/// The trust a composition root decided for one OUTBOUND connection, as the seam carries it.
///
/// Three optional decisions, each independent and each byte-inert when unset:
///
/// * `extra_anchors` — additional trust anchors (DER certificates) to trust ALONGSIDE the platform
///   roots. Empty means the platform roots alone, which is today's posture.
/// * `pinned_public_keys` — per-destination public-key pins, each the SHA-256 of the peer's whole
///   public-key info. When present, the ordinary chain check still runs AND the peer's key must
///   hash to one of these. Empty means no pinning, which is today's posture.
/// * `client_identity` — the certificate the connection should present for a mutual handshake. `None`
///   means present none, which is today's posture.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct EgressTrust {
    /// Extra trust anchors (DER certificates) trusted alongside the platform roots. Empty = none.
    pub extra_anchors: Vec<Vec<u8>>,
    /// Per-destination public-key pins, each the SHA-256 of the peer certificate's whole public-key
    /// info. Empty = no pinning.
    pub pinned_public_keys: Vec<[u8; 32]>,
    /// The client identity to present for a mutual handshake. `None` = present none.
    pub client_identity: Option<ClientIdentity>,
}

impl core::fmt::Debug for EgressTrust {
    /// Hand-rolled so the `client_identity`'s private key is redacted through [`ClientIdentity`]'s
    /// own `Debug`. The anchors and pins are public bytes and print as themselves; the shape is
    /// exactly what the derive produced, minus the key material.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EgressTrust")
            .field("extra_anchors", &self.extra_anchors)
            .field("pinned_public_keys", &self.pinned_public_keys)
            .field("client_identity", &self.client_identity)
            .finish()
    }
}

impl EgressTrust {
    /// Whether the host decided nothing extra — no added anchors, no pins, no client identity.
    ///
    /// A seam that sees this returns to the exact platform-roots / no-client-auth posture it had
    /// before this type existed, and MUST take that path rather than a reconstructed-equal one, so
    /// the unset case is provably unchanged.
    #[must_use]
    pub fn is_unset(&self) -> bool {
        self.extra_anchors.is_empty()
            && self.pinned_public_keys.is_empty()
            && self.client_identity.is_none()
    }
}

/// THE ONE SPELLING OF A KEY PIN: the SHA-256 of a certificate's whole SubjectPublicKeyInfo (its
/// DER, tag and length included), in standard base64 with padding. What an operator writes as a
/// registration's peer-key pin, what the connector compares the far end's key against and what it
/// reports as observed are this one rendering, so a pin and an observation compare as strings.
#[must_use]
pub fn key_pin(subject_public_key_info: &[u8]) -> String {
    use sha2::Digest as _;
    crate::media::base64_encode(&sha2::Sha256::digest(subject_public_key_info))
}

/// THE TRUST ANCHORS OF ONE DESTINATION a need reaches (the transport pin, ARCHITECT 2026-10-03): the
/// connector enforces them itself, on every connection to it.
///
/// * `key_pin` — the far end's key, in the [`key_pin`] spelling: a secured connection whose leaf
///   certificate's key is another is refused before a request byte is written (the ordinary chain
///   and name check still runs first), and a connection that is not secured is refused outright.
/// * `client_identity` — busbar's client certificate for that destination, presented when the far
///   end asks for one.
///
/// What the connection observed (the far end's key, whether the identity was presented) is the
/// connection's facts either way ([`crate::transport::ConnFacts`]). The default anchors nothing.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Anchors {
    /// The far end's key pin; `None` = no pin.
    pub key_pin: Option<String>,
    /// The client identity to present; `None` = present none.
    pub client_identity: Option<ClientIdentity>,
    /// The REGISTRATION's private reach for its need (`abi::plane::TRUST_PRIVATE_REACH`): carried
    /// with the member's anchors, and sealed for that registration alone
    /// (`conn::PollConns::seal_reach`), never per destination. It anchors no connection security.
    pub private_reach: bool,
}

impl Anchors {
    /// Whether these anchor no connection security (the private reach is sealed on its own).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        !self.secures()
    }

    /// Whether these hold the connection's security to anything (a key pin or a client identity).
    #[must_use]
    pub fn secures(&self) -> bool {
        self.key_pin.is_some() || self.client_identity.is_some()
    }
}

impl core::fmt::Debug for Anchors {
    /// The identity's private key is redacted through [`ClientIdentity`]'s own `Debug`.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Anchors")
            .field("key_pin", &self.key_pin)
            .field("client_identity", &self.client_identity)
            .field("private_reach", &self.private_reach)
            .finish()
    }
}

#[cfg(test)]
#[path = "tests/redaction_tests.rs"]
mod redaction_tests;
