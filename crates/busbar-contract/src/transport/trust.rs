// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! HOST-OWNED TRUST, as seam currency between the unit that decides it and the transport that

/// A parsed client identity: a certificate chain and the private key that proves it, both in DER.
///
/// The chain is leaf-first, the way a TLS stack presents it. The private key is the DER a stack
/// parses; the host owns the parse and never lets the plane hold it, so what crosses this seam is the
/// material a composition root already resolved, not a handle into a registry the transport cannot
/// reach.
///
/// The key is a [`Secret`](crate::Secret): it zeroizes on drop, compares in constant time, and a
/// TLS stack reads it through the sealed `expose` at the one site that hands it to the handshake.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ClientIdentity {
    /// The certificate chain to present, leaf first, each entry one DER certificate.
    pub cert_chain: Vec<Vec<u8>>,
    /// The private key, in DER, that proves the leaf.
    pub private_key: crate::Secret<Vec<u8>>,
}

impl core::fmt::Debug for ClientIdentity {
    /// Hand-rolled so the text stays exactly what 1.5.5 printed (log text is customer-visible): the
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
    #[must_use]
    pub fn is_unset(&self) -> bool {
        self.extra_anchors.is_empty()
            && self.pinned_public_keys.is_empty()
            && self.client_identity.is_none()
    }
}

/// THE TAG of a key pin's canonical spelling: `sha256/<standard base64>`, the spelling an operator
pub const KEY_PIN_TAG: &str = crate::abi::sdk::digest::SHA256_TAG;

/// THE ONE SPELLING OF A KEY PIN: the SHA-256 of a certificate's whole SubjectPublicKeyInfo (its
#[must_use]
pub fn key_pin(subject_public_key_info: &[u8]) -> String {
    crate::abi::sdk::digest::sha256_tagged(subject_public_key_info)
}

/// A written key pin that names no SHA-256 digest: why, never the value itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BadKeyPin(pub &'static str);

impl std::fmt::Display for BadKeyPin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the key pin is not `sha256/<base64>` of a 32-byte SHA-256 SubjectPublicKeyInfo digest \
             (nor its plain base64 alias): {}",
            self.0
        )
    }
}

impl std::error::Error for BadKeyPin {}

/// THE ONE READER OF A WRITTEN KEY PIN, to its canonical spelling ([`key_pin`]), surrounding
pub fn canonical_key_pin(written: &str) -> Result<String, BadKeyPin> {
    use base64::Engine as _;
    let decode = |encoded: &str| -> Option<[u8; 32]> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .ok()?;
        bytes.try_into().ok()
    };
    let written = written.trim();
    let digest = written
        .strip_prefix(KEY_PIN_TAG)
        .and_then(decode)
        .or_else(|| decode(written))
        .ok_or(BadKeyPin(
            "it is neither `sha256/` and the standard, padded base64 of 32 bytes, nor that base64 \
             alone",
        ))?;
    Ok(crate::abi::sdk::digest::tagged(&digest))
}

/// THE TRUST ANCHORS OF ONE DESTINATION a need reaches: the
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

#[cfg(test)]
#[path = "tests/key_pin_tests.rs"]
mod key_pin_tests;
