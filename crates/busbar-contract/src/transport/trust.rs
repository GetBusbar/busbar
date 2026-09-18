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
/// * `pinned_spki` — per-destination SubjectPublicKeyInfo pins, each the SHA-256 of the peer's whole
///   SPKI. When present, the ordinary chain check still runs AND the peer's key must hash to one of
///   these. Empty means no pinning, which is today's posture.
/// * `client_identity` — the certificate the connection should present for a mutual handshake. `None`
///   means present none, which is today's posture.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct EgressTrust {
    /// Extra trust anchors (DER certificates) trusted alongside the platform roots. Empty = none.
    pub extra_anchors: Vec<Vec<u8>>,
    /// Per-destination SPKI pins, each the SHA-256 of the peer certificate's whole SPKI. Empty = no
    /// pinning.
    pub pinned_spki: Vec<[u8; 32]>,
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
            .field("pinned_spki", &self.pinned_spki)
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
            && self.pinned_spki.is_empty()
            && self.client_identity.is_none()
    }
}

/// The host's decision seam for an INBOUND document's authenticity — the "decided fact" a plane
/// CONSUMES rather than a mechanism it owns.
///
/// A composition root that owns the verifying mechanism implements this; a plane that used to carry
/// the pin/verify machinery itself instead asks the host across this seam and records the decision.
/// The trait is deliberately small and names no protocol: a document is bytes, an issuer key is the
/// operator-supplied string that roots it, and a fingerprint is the canonical identity the decision
/// is pinned to.
///
/// Unused until a plane opts in — declaring the seam does not wire any caller onto it.
pub trait InboundTrust: Send + Sync {
    /// Verify a fetched `document` against the operator-supplied `issuer_key`, returning the
    /// document's canonical fingerprint when at least one signature verifies against that key, or an
    /// operator-facing reason when none does.
    ///
    /// # Errors
    /// Returns the refusal reason when the document is unsigned, malformed, or signed by no key the
    /// operator named.
    fn verify_signed(&self, document: &[u8], issuer_key: &str) -> Result<String, String>;

    /// The canonical fingerprint of a `document`, independent of any signature — the identity a
    /// transport-layer (unsigned) pin binds to.
    ///
    /// # Errors
    /// Returns the reason when the document cannot be canonicalised.
    fn fingerprint(&self, document: &[u8]) -> Result<String, String>;
}

#[cfg(test)]
mod redaction_tests {
    use super::{ClientIdentity, EgressTrust};

    /// A byte value that appears NOWHERE in the redacted `Debug` shells (`ClientIdentity { … }`,
    /// `EgressTrust { … }`, `[]`, `<redacted>`), so its decimal spelling in the output can only mean
    /// the key material leaked. `0xEF` = 239.
    const KEY_BYTE: u8 = 0xEF;

    #[test]
    fn client_identity_debug_redacts_private_key() {
        let id = ClientIdentity {
            cert_chain: Vec::new(),
            private_key: vec![KEY_BYTE; 8],
        };
        let shown = format!("{id:?}");
        assert!(
            shown.contains("<redacted>"),
            "private key must be redacted, got: {shown}"
        );
        assert!(
            !shown.contains(&KEY_BYTE.to_string()),
            "Debug output leaked private key bytes: {shown}"
        );
    }

    #[test]
    fn egress_trust_debug_redacts_client_private_key() {
        let trust = EgressTrust {
            extra_anchors: Vec::new(),
            pinned_spki: Vec::new(),
            client_identity: Some(ClientIdentity {
                cert_chain: Vec::new(),
                private_key: vec![KEY_BYTE; 8],
            }),
        };
        let shown = format!("{trust:?}");
        assert!(
            shown.contains("<redacted>"),
            "nested client identity's private key must be redacted, got: {shown}"
        );
        assert!(
            !shown.contains(&KEY_BYTE.to_string()),
            "Debug output leaked nested private key bytes: {shown}"
        );
    }
}
