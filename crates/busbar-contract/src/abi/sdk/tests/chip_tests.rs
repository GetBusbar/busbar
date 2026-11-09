// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use super::digests::{md5, sha1};
use crate::abi::sdk::cred::Cred;
use zeroize::Zeroizing;
fn cred(s: &str) -> Cred {
    Cred::captured(Zeroizing::new(s.as_bytes().to_vec()))
}

#[test]
fn sha1_matches_fips_180_vectors() {
    assert_eq!(
        hex::encode(&sha1(&[b"abc"])[..]),
        "a9993e364706816aba3e25717850c26c9cd0d89d"
    );
    assert_eq!(
        hex::encode(&sha1(&[b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"])[..]),
        "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
    );
    assert_eq!(
        hex::encode(&sha1(&[b"ab", b"c"])[..]),
        "a9993e364706816aba3e25717850c26c9cd0d89d"
    );
}

#[test]
fn md5_matches_rfc_1321_vectors() {
    assert_eq!(
        hex::encode(&md5(&[b""])[..]),
        "d41d8cd98f00b204e9800998ecf8427e"
    );
    assert_eq!(
        hex::encode(&md5(&[b"abc"])[..]),
        "900150983cd24fb0d6963f7d28e17f72"
    );
    assert_eq!(
        hex::encode(
            &md5(&[
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            ])[..]
        ),
        "57edf4a22be3c955ac49da2e2107b67a"
    );
}

#[test]
fn http_field_values() {
    let c = cred("open sesame");
    assert_eq!(
        c.basic("Aladdin").wire(),
        b"Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
    );
    assert_eq!(c.bearer().wire(), b"Bearer open sesame");
    assert_eq!(c.field().wire(), b"open sesame");
}

#[test]
fn verify_eq() {
    let c = cred("s3cr3t-pw");
    assert!(c.verify_eq(b"s3cr3t-pw"));
    assert!(!c.verify_eq(b"s3cr3t-pX"));
}

#[test]
fn redact_echo_replaces_every_occurrence() {
    let c = cred("hunter2");
    assert_eq!(
        c.redact_echo("Access denied using hunter2 (hunter2)"),
        "Access denied using [redacted] ([redacted])"
    );
    assert_eq!(c.redact_echo("nothing here"), "nothing here");
}
