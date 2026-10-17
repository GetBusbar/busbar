// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The login kit's id-token nonce binding, case by case (v1.5.5 `auth/token.rs:529-540`).

use super::{b64url_decode, check_hop_nonce, SecurityCheckFailed};

/// Unpadded base64url of `b`.
fn b64(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut s = String::new();
    for chunk in b.chunks(3) {
        let n = chunk.iter().fold(0u32, |a, &x| (a << 8) | u32::from(x)) << (8 * (3 - chunk.len()));
        for i in 0..=chunk.len() {
            s.push(char::from(A[((n >> (18 - 6 * i)) & 63) as usize]));
        }
    }
    s
}

/// A token-endpoint body carrying an id_token whose payload is `claims`.
fn body_with(claims: &str) -> Vec<u8> {
    let jwt = format!(
        "{}.{}.sig",
        b64(br#"{"alg":"RS256"}"#),
        b64(claims.as_bytes())
    );
    format!(r#"{{"access_token":"a","id_token":"{jwt}"}}"#).into_bytes()
}

#[test]
fn no_id_token_passes_whatever_is_expected() {
    for body in [
        br#"{"access_token":"a"}"#.as_slice(),
        b"not json",
        br#"{"id_token":7}"#,
        b"",
    ] {
        assert_eq!(check_hop_nonce(body, Some("n-1")), Ok(()));
        assert_eq!(check_hop_nonce(body, None), Ok(()));
    }
}

#[test]
fn the_minted_nonce_passes() {
    assert_eq!(
        check_hop_nonce(&body_with(r#"{"sub":"u","nonce":"n-1"}"#), Some("n-1")),
        Ok(())
    );
}

#[test]
fn another_nonce_fails() {
    assert_eq!(
        check_hop_nonce(&body_with(r#"{"nonce":"n-2"}"#), Some("n-1")),
        Err(SecurityCheckFailed)
    );
}

#[test]
fn an_id_token_without_a_nonce_claim_fails() {
    assert_eq!(
        check_hop_nonce(&body_with(r#"{"sub":"u"}"#), Some("n-1")),
        Err(SecurityCheckFailed)
    );
    assert_eq!(
        check_hop_nonce(&body_with(r#"{"nonce":5}"#), Some("5")),
        Err(SecurityCheckFailed)
    );
}

#[test]
fn an_id_token_with_nothing_expected_fails_closed() {
    assert_eq!(
        check_hop_nonce(&body_with(r#"{"nonce":"n-1"}"#), None),
        Err(SecurityCheckFailed)
    );
}

#[test]
fn an_unreadable_payload_fails() {
    for jwt in ["only-one-segment", "a.!!!.c", "a.e30=.c", "a.A.c"] {
        let body = format!(r#"{{"id_token":"{jwt}"}}"#).into_bytes();
        assert_eq!(
            check_hop_nonce(&body, Some("n")),
            Err(SecurityCheckFailed),
            "{jwt}"
        );
    }
}

#[test]
fn base64url_is_strict_and_unpadded() {
    assert_eq!(b64url_decode("e30").as_deref(), Some(b"{}".as_slice()));
    assert_eq!(
        b64url_decode(&b64(b"\xfb\xff")).as_deref(),
        Some(b"\xfb\xff".as_slice())
    );
    assert_eq!(b64url_decode("e30="), None, "padding is refused");
    assert_eq!(
        b64url_decode("e3+/"),
        None,
        "the standard alphabet is refused"
    );
    assert_eq!(
        b64url_decode("e31"),
        None,
        "non-zero trailing bits are refused"
    );
    assert_eq!(b64url_decode("A"), None, "a length of 1 mod 4 is refused");
}
