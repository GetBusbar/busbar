// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ENGINE'S TLS POSTURE VOCABULARY: what busbar trusts, and who busbar is.
//!
//! [`ClientIdentity`] replaces `reqwest::Identity` at every seam the migration crosses, and its
//! `from_pem` is written for VERDICT PARITY with `reqwest::Identity::from_pem` (the rustls arm):
//! the same `rustls-pki-types` PEM walk, the same accepted section kinds (certificates plus a
//! PKCS#8 / PKCS#1 / SEC1 private key, any order), the same rejections (an unparseable buffer, a
//! section kind that has no place in an identity, no certificate, no key) — and, deliberately,
//! the same tolerance: a buffer carrying MORE than one private key loads with the LAST one,
//! because that is what reqwest ships and a config that loaded yesterday must load tomorrow
//! (risk R4: a stricter parser here would be a boot refusal on upgrade). The parity corpus test
//! drives both parsers over every fixture and adversarial buffer and asserts the verdicts agree.
//! The walk itself runs in the connector's TLS wrap (`crate::secure`): TLS stays in the connector,
//! and this crate keeps the parsed DER.
//!
//! [`Trust`] names the trust source: the compiled-in webpki (Mozilla) roots always, optionally
//! JOINED by operator-registered extra roots (DER) — the same "extras join the default store"
//! semantics as reqwest's `add_root_certificate`. An extra root the store refuses fails the
//! CLIENT BUILD loudly; nothing is skipped silently.

use std::sync::Arc;

use crate::secure::KeyDer;

/// What the engine trusts on a posture.
pub enum Trust {
    /// The compiled-in webpki (Mozilla) roots — the pooled posture's trust story, byte-identical
    /// to reqwest's `rustls-tls`.
    Webpki,
    /// The webpki roots PLUS these extra roots (DER; parsed from PEM at registration, so a
    /// garbage root fails at parse time exactly as `reqwest::Certificate::from_pem` did).
    WebpkiPlus(Vec<Vec<u8>>),
}

/// Busbar's own end of a mutual handshake: a certificate chain and its private key, parsed once
/// and shared by refcount (registries clone one identity per hop, and `Arc` is cheaper and more
/// honest than a key copy per hop).
#[derive(Clone)]
pub struct ClientIdentity {
    chain: Vec<Vec<u8>>,
    key: Arc<KeyDer>,
}

impl ClientIdentity {
    /// One PEM buffer holding the certificate chain and the private key, any order —
    /// `reqwest::Identity::from_pem` verdict parity (see the module header for exactly what that
    /// means, including the more-than-one-key tolerance). The error names what was missing or
    /// refused, so a boot refusal is actionable.
    pub fn from_pem(pem: &[u8]) -> Result<Self, String> {
        let layer = crate::secure::layer().ok_or_else(|| crate::secure::NO_LAYER.to_string())?;
        let (chain, key) = layer.identity_from_pem(pem)?;
        Ok(Self::from_parts(chain, key))
    }

    /// An identity from its already-parsed parts: the chain (leaf first, DER) and its key.
    pub fn from_parts(chain: Vec<Vec<u8>>, key: KeyDer) -> Self {
        ClientIdentity {
            chain,
            key: Arc::new(key),
        }
    }

    /// The chain, leaf first, for the client build.
    pub(super) fn chain(&self) -> &[Vec<u8>] {
        &self.chain
    }

    /// The key, for the client build (which copies it per CLIENT BUILD, never per request).
    pub(super) fn key(&self) -> &KeyDer {
        &self.key
    }

    /// The leaf certificate, DER — what an mTLS peer records busbar as.
    pub fn leaf_der(&self) -> &[u8] {
        &self.chain[0]
    }

    /// Overwrite the private key IF this handle is the last one holding it.
    ///
    /// `Arc::get_mut` is the whole guard, and it is not an optimisation: identities are cloned per
    /// hop and per client build (`plane_host::identity::resolve` hands out a clone every time), so a
    /// wipe that did not ask whether anyone else still held the key would blank a key another hop is
    /// about to hand to the TLS stack, and the handshake it was parsed for would fail. `get_mut` answers
    /// `Some` only when this is the last strong reference and there are no weak ones — exactly the
    /// moment the key's allocation is about to go back to the allocator.
    ///
    /// Only the key is wiped. The chain is the certificate busbar PRESENTS; it is public by
    /// construction and the peer already has it.
    ///
    /// Its own function rather than a body inlined into `drop` so the wipe is OBSERVABLE: a test can
    /// call exactly what `Drop` calls and then read the key back, which is the only sound way to
    /// check it — inspecting a value after its own `Drop` has run is a read of freed memory.
    pub(super) fn wipe(&mut self) {
        if let Some(key) = Arc::get_mut(&mut self.key) {
            key.zeroize();
        }
    }
}

/// A superseded identity's private key must not be handed back to the allocator intact.
///
/// The key's DER is an ordinary `Vec<u8>`, and its drop glue is an ordinary deallocation: the key DER sits in freed heap afterwards, readable by a
/// heap dump, a core file, or an out-of-bounds read elsewhere in the process. That drop is reached
/// on a live path — `plane_host::identity::register` retains at most `MAX_RETAINED_IDENTITIES`
/// identities and evicts the oldest FIFO, and the evicted `ClientIdentity` drops right there — so an
/// operator who rotates the mTLS client certificate 257 times has 257 client keys lying in the
/// process's freed heap, which is exactly the retention the FIFO cap was added to stop.
impl Drop for ClientIdentity {
    fn drop(&mut self) {
        self.wipe();
    }
}
