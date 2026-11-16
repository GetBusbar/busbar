// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! An operator PEM CA at a D_TRUST_PATH node, read through rustls-pki-types' PEM reader (no PEM parser of our
//! own) into a [`TrustAnchor`]: one or more certificates and the SHA-256 of their DER, in order.

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;

use super::TrustAnchor;

/// The certificates of `text`; None = not PEM, a malformed section, or no CERTIFICATE section at all.
pub(super) fn trust_anchor(text: &str) -> Option<TrustAnchor> {
    let mut der = Vec::new();
    for cert in CertificateDer::pem_slice_iter(text.as_bytes()) {
        der.push(cert.ok()?.as_ref().to_vec());
    }
    if der.is_empty() {
        return None;
    }
    let mut parts: Vec<&[u8]> = Vec::with_capacity(der.len());
    for d in &der {
        parts.push(d.as_slice());
    }
    let sha256 = busbar_contract::crypto::sha256_parts(&parts);
    Some(TrustAnchor { der, sha256 })
}
