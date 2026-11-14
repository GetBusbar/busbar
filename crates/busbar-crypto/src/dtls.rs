// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! DTLS (WebRTC) through the linked backend: dimpl's crypto provider and the per-session
//! self-signed certificate. Like TLS, the provider is never installed as a process default; every
//! association is built with [`dtls_provider`].

use busbar_crypto_backend as b;

use crate::{map, Error};

/// The dimpl crypto provider to build a DTLS association with. A backend may refuse DTLS
/// (`supports(alg::DTLS_SRTP)` says so).
pub fn dtls_provider() -> Result<dimpl::crypto::CryptoProvider, Error> {
    b::dtls_provider().map_err(map)
}

/// A per-session self-signed ECDSA P-256 certificate whose private key stays in the backend:
/// [`DtlsCert::handle`] is what dimpl carries in its place (`DtlsCertificate::private_key`), and
/// only [`dtls_provider`] resolves it. Dropping the certificate forgets the key.
#[derive(Debug)]
pub struct DtlsCert(b::DtlsCert);

impl DtlsCert {
    /// The certificate, DER (public).
    #[must_use]
    pub fn der(&self) -> &[u8] {
        self.0.der()
    }

    /// The opaque handle naming the backend-held private key (not key material).
    #[must_use]
    pub fn handle(&self) -> &[u8] {
        self.0.handle()
    }
}

/// Mint a fresh per-session self-signed certificate.
pub fn dtls_self_signed() -> Result<DtlsCert, Error> {
    b::dtls_self_signed().map(DtlsCert).map_err(map)
}
