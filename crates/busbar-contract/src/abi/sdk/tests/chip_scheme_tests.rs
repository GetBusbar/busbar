// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use zeroize::Zeroizing;

use crate::abi::sdk::cred::Cred;

fn cred(s: &str) -> Cred {
    Cred::captured(Zeroizing::new(s.as_bytes().to_vec()))
}

#[test]
fn a_credential_follows_its_scheme_after_one_space() {
    assert_eq!(cred("s3cret").scheme("Bearer").wire(), b"Bearer s3cret");
    assert_eq!(
        cred("dXNlcjpwdw==").scheme("Basic").wire(),
        b"Basic dXNlcjpwdw=="
    );
    assert_eq!(cred("a b").scheme("Custom").wire(), b"Custom a b");
}

#[test]
fn an_empty_credential_is_the_bare_scheme() {
    assert_eq!(Cred::empty().scheme("Basic").wire(), b"Basic");
    assert_eq!(cred("").scheme("Negotiate").wire(), b"Negotiate");
}

#[test]
fn the_scheme_is_written_as_given() {
    assert_eq!(cred("t").scheme("bEaReR").wire(), b"bEaReR t");
    assert_eq!(cred("t").scheme(b"X-Tok".as_slice()).wire(), b"X-Tok t");
}

#[test]
fn bearer_is_the_bearer_scheme_for_a_credential() {
    let c = cred("open sesame");
    assert_eq!(c.scheme("Bearer").wire(), c.bearer().wire());
}

/// A `scheme` seal placed through `request_sealed` frames the very head the plain request with the
/// same `authorization` value framed: the field order, the separator, every byte.
#[test]
fn a_sealed_authorization_frames_the_head_the_plain_one_framed() {
    use crate::abi::sdk::exchange::{Exchange, Request};
    use crate::abi::sdk::test_support::chip::framed_head;
    let base = |fields: Vec<(Vec<u8>, Vec<u8>)>| Request {
        method: b"POST".to_vec(),
        target: b"/hook?x=1".to_vec(),
        fields,
        body: b"{}".to_vec(),
        timeout_ms: 10_000,
    };
    let ct = (b"content-type".to_vec(), b"application/json".to_vec());
    for (scheme, secret, plain) in [
        ("Bearer", "s3cret", &b"Bearer s3cret"[..]),
        ("Basic", "", &b"Basic"[..]),
    ] {
        let old = Exchange::request(base(vec![
            ct.clone(),
            (b"authorization".to_vec(), plain.to_vec()),
        ]))
        .expect("frames");
        let new = Exchange::request_sealed(
            base(vec![ct.clone()]),
            vec![(1, b"authorization".to_vec(), cred(secret).scheme(scheme))],
        )
        .expect("frames");
        assert_eq!(framed_head(&new), framed_head(&old));
        assert_eq!(new.framed_fields()[1].1, b"<sealed>");
    }
}

#[test]
fn a_scheme_seal_carries_the_credentials_secure_requirement() {
    assert!(!cred("t").scheme("Bearer").secure_required());
    assert!(cred("t")
        .secure_for("https://hooks.example/")
        .scheme("Bearer")
        .secure_required());
    assert!(Cred::empty()
        .secure_for("https://hooks.example/")
        .scheme("Basic")
        .secure_required());
}
