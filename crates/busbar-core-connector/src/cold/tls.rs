// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The TLS seam's cold text (`crate::tls`): the refusal values, failure records and handshake
//! refusal words it builds only when a dial is refused or a handshake fails, called out of line.

use std::fmt::Write as _;

use busbar_contract::crypto;

use crate::tls::store::{dialled, Anchor, Entry, TrustStore};

/// The text a refusal `e` of a DIALLED handshake is reported with: rustls's own words, plus one
/// sentence for an unknown issuer or a CA certificate served as the leaf, and exactly rustls's
/// words for every other kind. Never prefixed: it is the connection's cause text.
#[cold]
pub(crate) fn handshake_refusal(e: &rustls::Error) -> String {
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

impl TrustStore {
    /// The entries matching `host`, as written (for a refusal's or a failure's record).
    #[must_use]
    #[cold]
    pub fn matched(&self, host: &str) -> Vec<String> {
        let Some(d) = dialled(host) else {
            return Vec::new();
        };
        self.entries
            .iter()
            .filter(|e| !e.plaintext && e.matcher.matches(&d))
            .map(|e| e.shown.clone())
            .collect()
    }

    /// The fingerprints of the operator anchors in force for `host` (never the base set's).
    #[must_use]
    #[cold]
    pub fn fingerprints_for(&self, host: &str) -> Vec<String> {
        let withdrawn = self.withdrawn.read().expect("withdrawn");
        let Some(d) = dialled(host) else {
            return Vec::new();
        };
        let matched: Vec<&Entry> = self
            .entries
            .iter()
            .filter(|e| !e.plaintext && e.matcher.matches(&d))
            .collect();
        let own = matched.iter().flat_map(|e| e.anchors.iter());
        let replaces = matched.iter().any(|e| !e.anchors.is_empty())
            && !matched.iter().any(|e| e.include_roots);
        let global: Box<dyn Iterator<Item = &Anchor>> = if replaces {
            Box::new(std::iter::empty())
        } else {
            Box::new(self.global.iter())
        };
        own.chain(global)
            .filter(|a| !withdrawn.contains(&a.sha256))
            .map(Anchor::fingerprint)
            .collect()
    }
}
