// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn signer() -> TokenSigner {
    TokenSigner::from_secret_bytes(&[7u8; 32], DEFAULT_KID)
}

fn verifier(s: &TokenSigner) -> TokenVerifier {
    TokenVerifier::single(s.kid(), s.verifying_key())
}

#[test]
fn mint_then_verify_roundtrips() {
    let s = signer();
    let v = verifier(&s);
    let tok = s.mint("vk_abc", 2000, None);
    assert!(tok.starts_with(TOKEN_PREFIX));
    let claims = v.verify(&tok, 1000, None).expect("valid");
    assert_eq!(claims.sub, "vk_abc");
    assert_eq!(claims.exp, 2000);
    assert_eq!(claims.kid, DEFAULT_KID);
}

#[test]
fn audience_bound_token_is_rejected_on_the_plain_verify_path() {
    let s = signer();
    let v = verifier(&s);

    let payload = serde_json::to_vec(&serde_json::json!({
        "sub": "vk_audience",
        "exp": 2000u64,
        "kid": DEFAULT_KID,
        "a": "https://busbar.example.com/ingress"
    }))
    .unwrap();
    let sig: Signature = s.key.sign(&payload);
    let token = format!(
        "{TOKEN_PREFIX}{}.{}",
        URL_SAFE_NO_PAD.encode(&payload),
        URL_SAFE_NO_PAD.encode(sig.to_bytes())
    );
    assert!(
        v.verify(&token, 1000, None).is_err(),
        "an audience-bound token must NOT verify on the plain (no-expected-audience) path"
    );
}

#[test]
fn audience_matrix_is_fail_closed() {
    let s = signer();
    let v = verifier(&s);
    let aud = "https://busbar.example.com/ingress";
    let plain = s.mint("vk_abc", 2000, None);
    let bound = s.mint_for_audience("vk_abc", 2000, None, aud, Some("client-1"));

    assert!(v.verify(&plain, 1000, None).is_ok(), "plain on plain");
    let claims = v
        .verify(&bound, 1000, Some(aud))
        .expect("matching audience on the audience-checked plane");
    assert_eq!(claims.aud.as_deref(), Some(aud));
    assert_eq!(claims.cid.as_deref(), Some("client-1"));

    assert_eq!(
        v.verify(&bound, 1000, None),
        Err(VerifyError::AudienceMismatch),
        "audience-bound token on the plain data plane"
    );
    assert_eq!(
        v.verify(&plain, 1000, Some(aud)),
        Err(VerifyError::AudienceMismatch),
        "plain token on an audience-checked ingress"
    );
    assert_eq!(
        v.verify(&bound, 1000, Some("https://other.example.com/ingress")),
        Err(VerifyError::AudienceMismatch),
        "different audience URI"
    );
}

#[test]
fn legacy_token_without_audience_still_verifies_on_the_data_plane() {
    let s = signer();
    let v = verifier(&s);

    let payload = serde_json::to_vec(&serde_json::json!({
        "sub": "vk_old",
        "exp": 2000u64,
        "kid": DEFAULT_KID
    }))
    .unwrap();
    let sig: Signature = s.key.sign(&payload);
    let token = format!(
        "{TOKEN_PREFIX}{}.{}",
        URL_SAFE_NO_PAD.encode(&payload),
        URL_SAFE_NO_PAD.encode(sig.to_bytes())
    );
    let claims = v.verify(&token, 1000, None).expect("legacy token verifies");
    assert_eq!(claims.aud, None);
    assert_eq!(claims.cid, None);
}

#[test]
fn expired_token_rejected() {
    let s = signer();
    let v = verifier(&s);
    let tok = s.mint("vk_abc", 1000, None);
    assert_eq!(v.verify(&tok, 1000, None), Err(VerifyError::Expired));
    assert_eq!(v.verify(&tok, 1001, None), Err(VerifyError::Expired));
    assert!(v.verify(&tok, 999, None).is_ok());
}

#[test]
fn tampered_token_rejected() {
    let s = signer();
    let v = verifier(&s);
    let tok = s.mint("vk_abc", 2000, None);

    let body = tok.strip_prefix(TOKEN_PREFIX).unwrap();
    let (payload, sig) = body.split_once('.').unwrap();
    let mut p = payload.to_string();
    let last = p.pop().unwrap();
    p.push(if last == 'A' { 'B' } else { 'A' });
    let tampered = format!("{TOKEN_PREFIX}{p}.{sig}");
    assert!(matches!(
        v.verify(&tampered, 1000, None),
        Err(VerifyError::BadSignature) | Err(VerifyError::Malformed)
    ));
}

#[test]
fn token_fails_after_rotation() {
    let key_a = TokenSigner::from_secret_bytes(&[1u8; 32], DEFAULT_KID);
    let tok = key_a.mint("vk_abc", 2000, None);

    let key_b_same_kid = TokenSigner::from_secret_bytes(&[2u8; 32], DEFAULT_KID);
    let v_b = verifier(&key_b_same_kid);
    assert_eq!(v_b.verify(&tok, 1000, None), Err(VerifyError::BadSignature));

    let key_c = TokenSigner::from_secret_bytes(&[3u8; 32], "k2");
    let v_c = verifier(&key_c);
    assert_eq!(v_c.verify(&tok, 1000, None), Err(VerifyError::UnknownKid));
}

#[test]
fn malformed_tokens_rejected() {
    let s = signer();
    let v = verifier(&s);
    for bad in [
        "not-a-token",
        "bbk_onlyonesegment",
        "bbk_%%%.%%%",
        "bbk_YWJj.YWJj",
    ] {
        assert!(
            matches!(
                v.verify(bad, 1000, None),
                Err(VerifyError::Malformed) | Err(VerifyError::BadSignature)
            ),
            "must reject: {bad}"
        );
    }
}

#[test]
fn generated_key_persists_and_reloads() {
    let s = TokenSigner::generate(DEFAULT_KID).unwrap();
    let bytes = s.secret_bytes();
    let reloaded = TokenSigner::from_secret_bytes(&bytes, DEFAULT_KID);
    let tok = s.mint("vk_x", 2000, None);

    let v = TokenVerifier::single(DEFAULT_KID, reloaded.verifying_key());
    assert!(v.verify(&tok, 1000, None).is_ok());
}

#[test]
fn signer_debug_redacts_key() {
    let s = signer();
    let dbg = format!("{s:?}");
    assert!(dbg.contains("redacted"));
    assert!(!dbg.contains(&hex::encode([7u8; 32])));
}

#[test]
fn subkey_seed_derives_the_exact_pinned_bytes() {
    for (secret, domain, expected) in [
        (
            [0u8; 32],
            "",
            "0b1c0a2d5c88dd84043ada4280656292b0b97260f89b9c099deebdae4dc24a6b",
        ),
        (
            [0u8; 32],
            "example-plane/artifact-signing/v1",
            "3cf3dfab725d686c8ac91dd7361d5ff5183344693a20487d1ebe653b6ae7a72d",
        ),
        (
            [7u8; 32],
            "example-plane/artifact-signing/v1",
            "9d170779b08994af289bd84634a3151cf69a1e39b370900ed165c612522c7894",
        ),
        (
            [7u8; 32],
            "some/other/purpose/v1",
            "c7e527e9bd89ac13380f2853fbebf85eed87f4bba9f8d76302d91268abd68fec",
        ),
        (
            [0xffu8; 32],
            "",
            "77bf96146778130445d006dea40df5f2e76e92ed2f78df2b7d7ea167f7be51b1",
        ),
    ] {
        assert_eq!(
            hex::encode(subkey_seed(&secret, domain)),
            expected,
            "the derived subkey seed CHANGED for domain {domain:?} — every deployment's subkeys \
             just rotated silently"
        );
    }

    let mut counting = [0u8; 32];
    for (i, b) in counting.iter_mut().enumerate() {
        *b = i as u8;
    }
    assert_eq!(
        hex::encode(subkey_seed(&counting, "dømain/✓/v1")),
        "a8d12c9765387d05e5147563df692d7b66b582e26d8879be61a74db65cad6bd2"
    );
}

#[test]
fn derived_subkey_seed_is_the_free_function_over_the_root_secret() {
    let s = signer();
    assert_eq!(
        hex::encode(s.derived_subkey_seed("example-plane/artifact-signing/v1")),
        "9d170779b08994af289bd84634a3151cf69a1e39b370900ed165c612522c7894",
        "a plane subkey derived off this signer must be byte-identical across the move"
    );
    assert_eq!(
        s.derived_subkey_seed("example-plane/artifact-signing/v1"),
        subkey_seed(&s.secret_bytes(), "example-plane/artifact-signing/v1"),
        "the method must be exactly the free function over the root secret, with no second path"
    );
}
