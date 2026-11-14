// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A dialled handshake refusal keeps rustls's own words and adds a sentence only for the two kinds
//! whose Display alone does not say what to change (design mcp-issuer §3.1).

use std::sync::Arc;
use std::time::Duration;

use crate::tls::explain::handshake_refusal;

fn invalid(e: rustls::CertificateError) -> rustls::Error {
    rustls::Error::InvalidCertificate(e)
}

#[test]
fn an_unknown_issuer_keeps_the_stacks_words_and_says_the_pin_is_checked_on_top_of_the_chain() {
    let e = invalid(rustls::CertificateError::UnknownIssuer);
    let text = handshake_refusal(&e);
    assert!(text.starts_with(&e.to_string()), "{text}");
    assert!(text.contains("does not chain"), "{text}");
    assert!(text.contains("in addition to the chain"), "{text}");
    assert!(!text.starts_with("tls: "), "no prefix: {text}");
}

#[test]
fn a_ca_certificate_served_as_the_leaf_keeps_the_stacks_words_and_asks_for_ca_false() {
    let e = invalid(rustls::CertificateError::Other(rustls::OtherError(
        Arc::new(webpki::Error::CaUsedAsEndEntity),
    )));
    let text = handshake_refusal(&e);
    assert!(text.starts_with(&e.to_string()), "{text}");
    assert!(text.contains("CA:FALSE"), "{text}");
    assert!(!text.starts_with("tls: "), "no prefix: {text}");
}

#[test]
fn every_other_refusal_is_the_stacks_words_exactly() {
    let at = |s| rustls_pki_types::UnixTime::since_unix_epoch(Duration::from_secs(s));
    let wrong_name = invalid(rustls::CertificateError::NotValidForNameContext {
        expected: rustls_pki_types::ServerName::try_from("a.example")
            .unwrap()
            .to_owned(),
        presented: vec!["b.example".to_owned()],
    });
    let expired = invalid(rustls::CertificateError::ExpiredContext {
        time: at(2_000),
        not_after: at(1_000),
    });
    let other = invalid(rustls::CertificateError::Other(rustls::OtherError(
        Arc::new(webpki::Error::UnknownIssuer),
    )));
    for e in [wrong_name, expired, other] {
        assert_eq!(handshake_refusal(&e), e.to_string());
    }
}
