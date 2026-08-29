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
//!
//! [`Trust`] names the trust source: the compiled-in webpki (Mozilla) roots always, optionally
//! JOINED by operator-registered extra roots (DER) — the same "extras join the default store"
//! semantics as reqwest's `add_root_certificate`. An extra root the store refuses fails the
//! CLIENT BUILD loudly; nothing is skipped silently.

use std::sync::Arc;

use rustls_pki_types::{CertificateDer, PrivateKeyDer};

/// What the engine trusts on a posture.
pub enum Trust {
    /// The compiled-in webpki (Mozilla) roots — the LLM-lane trust story, byte-identical to
    /// reqwest's `rustls-tls`.
    Webpki,
    /// The webpki roots PLUS these extra roots (DER; parsed from PEM at registration, so a
    /// garbage root fails at parse time exactly as `reqwest::Certificate::from_pem` did).
    WebpkiPlus(Vec<CertificateDer<'static>>),
}

/// Busbar's own end of a mutual handshake: a certificate chain and its private key, parsed once
/// and shared by refcount (registries clone one identity per hop; `PrivateKeyDer` is not `Clone`,
/// and `Arc` is cheaper and more honest than `clone_key` per hop).
#[derive(Clone)]
pub struct ClientIdentity {
    chain: Vec<CertificateDer<'static>>,
    key: Arc<PrivateKeyDer<'static>>,
}

impl ClientIdentity {
    /// One PEM buffer holding the certificate chain and the private key, any order —
    /// `reqwest::Identity::from_pem` verdict parity (see the module header for exactly what that
    /// means, including the more-than-one-key tolerance). The error names what was missing or
    /// refused, so a boot refusal is actionable.
    pub fn from_pem(pem: &[u8]) -> Result<Self, String> {
        use rustls_pki_types::pem::{self, SectionKind};
        let mut cursor = std::io::Cursor::new(pem);
        let mut chain: Vec<CertificateDer<'static>> = Vec::new();
        let mut keys: Vec<PrivateKeyDer<'static>> = Vec::new();
        while let Some((kind, data)) = pem::from_buf(&mut cursor)
            .map_err(|e| format!("client identity PEM does not parse: {e:?}"))?
        {
            match kind {
                SectionKind::Certificate => chain.push(data.into()),
                SectionKind::PrivateKey => keys.push(PrivateKeyDer::Pkcs8(data.into())),
                SectionKind::RsaPrivateKey => keys.push(PrivateKeyDer::Pkcs1(data.into())),
                SectionKind::EcPrivateKey => keys.push(PrivateKeyDer::Sec1(data.into())),
                other => {
                    return Err(format!(
                        "client identity PEM carries a section that has no place in an \
                         identity ({other:?}): expected certificates and a private key \
                         (PKCS#8, PKCS#1 or SEC1)"
                    ))
                }
            }
        }
        if chain.is_empty() {
            return Err("client identity PEM holds no certificate".to_string());
        }
        let Some(key) = keys.pop() else {
            return Err(
                "client identity PEM holds no private key (PKCS#8, PKCS#1 or SEC1)".to_string(),
            );
        };
        Ok(ClientIdentity {
            chain,
            key: Arc::new(key),
        })
    }

    /// The chain, cloned for `with_client_auth_cert` (rustls takes ownership per config).
    pub(super) fn chain(&self) -> Vec<CertificateDer<'static>> {
        self.chain.clone()
    }

    /// The key, structurally cloned for `with_client_auth_cert`. Parsed once at registration;
    /// this copy is per CLIENT BUILD, never per request.
    pub(super) fn key(&self) -> PrivateKeyDer<'static> {
        self.key.clone_key()
    }

    /// The leaf certificate, DER — what an mTLS peer records busbar as.
    pub fn leaf_der(&self) -> &[u8] {
        self.chain[0].as_ref()
    }
}
