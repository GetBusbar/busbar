// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Plain words for the dialled TLS refusals whose rustls Display alone does not say what to change.
//!
//! Plane-neutral (the connector serves MCP, A2A and hooks alike), so the words name no config key;
//! each plane's docs carry its own recipe. Built only on the failure path.

use std::fmt::Write as _;

use busbar_contract::crypto;

/// The text a refusal `e` of a DIALLED handshake is reported with: rustls's own words, plus one
/// sentence for an unknown issuer or a CA certificate served as the leaf, and exactly rustls's
/// words for every other kind. Never prefixed: it is the connection's cause text.
#[must_use]
pub fn handshake_refusal(e: &rustls::Error) -> String {
    use rustls::{CertificateError, Error};
    let mut words = String::new();
    let _ = write!(words, "{e}");
    let more = match e {
        Error::InvalidCertificate(CertificateError::UnknownIssuer) => {
            ": the server's certificate does not chain to a root busbar trusts for this \
             destination (the bundled public roots plus any CA configured for it); a \
             cert_spki/mtls pin is checked in addition to the chain, not instead of it"
        }
        _ if crypto::tls::ca_used_as_end_entity(e) => {
            ": the server presents a CA certificate (CA:TRUE) as its own; it needs a leaf \
             certificate with CA:FALSE"
        }
        _ => "",
    };
    words.push_str(more);
    words
}
