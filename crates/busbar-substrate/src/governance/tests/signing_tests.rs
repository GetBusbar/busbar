// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/governance/signing.rs`.

use super::*;

fn signer() -> TokenSigner {
    TokenSigner::from_secret_bytes(&[7u8; 32], DEFAULT_KID)
}

fn verifier(s: &TokenSigner) -> TokenVerifier {
    TokenVerifier::single(s.kid(), s.verifying_key())
}

/// Mint -> verify round-trips the subject + expiry, and the token carries the prefix + kid.
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

/// THE PLANE BOUNDARY (1.6.0): an AUDIENCE-BOUND token
/// (the shape the MCP authorization server mints, wire claim `a`) must be REJECTED by the
/// plain data-plane verify. Before the boundary existed, serde ignored the unknown claim and
/// the token verified everywhere a busbar key does (`/stats`, `/v1/models`, every
/// `RouteAuth::Key` route): an MCP-scoped token was silently a full data-plane key.
#[test]
fn audience_bound_token_is_rejected_on_the_plain_verify_path() {
    let s = signer();
    let v = verifier(&s);
    // Hand-craft the payload (TokenClaims + the audience claim) and sign it with the real
    // signer key, exactly as an AS mint will.
    let payload = serde_json::to_vec(&serde_json::json!({
        "sub": "vk_mcp",
        "exp": 2000u64,
        "kid": DEFAULT_KID,
        "a": "https://busbar.example.com/mcp"
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

/// The full audience matrix, fail-closed on every mismatch arm (1.6.0 P1). The two accept
/// arms are exact: plain token on the plain plane, and matching audience on the
/// audience-checked plane. Everything else is `AudienceMismatch`.
#[test]
fn audience_matrix_is_fail_closed() {
    let s = signer();
    let v = verifier(&s);
    let mcp = "https://busbar.example.com/mcp";
    let plain = s.mint("vk_abc", 2000, None);
    let bound = s.mint_for_audience("vk_abc", 2000, None, mcp, Some("client-1"));

    // Accept arms.
    assert!(v.verify(&plain, 1000, None).is_ok(), "plain on plain");
    let claims = v
        .verify(&bound, 1000, Some(mcp))
        .expect("matching audience on the audience-checked plane");
    assert_eq!(claims.aud.as_deref(), Some(mcp));
    assert_eq!(claims.cid.as_deref(), Some("client-1"));

    // Reject arms.
    assert_eq!(
        v.verify(&bound, 1000, None),
        Err(VerifyError::AudienceMismatch),
        "audience-bound token on the plain data plane"
    );
    assert_eq!(
        v.verify(&plain, 1000, Some(mcp)),
        Err(VerifyError::AudienceMismatch),
        "plain token on an audience-checked ingress"
    );
    assert_eq!(
        v.verify(&bound, 1000, Some("https://other.example.com/mcp")),
        Err(VerifyError::AudienceMismatch),
        "different audience URI"
    );
}

/// FLEET COMPAT: a token minted before the `aud` claim existed (no `a` on the wire) keeps
/// verifying on the data plane, exactly like the `generation`/`g` rollout. No flag day.
#[test]
fn legacy_token_without_audience_still_verifies_on_the_data_plane() {
    let s = signer();
    let v = verifier(&s);
    // The pre-1.6.0 payload shape, hand-crafted: {sub, exp, kid} only.
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

/// An EXPIRED token (now >= exp) is rejected.
#[test]
fn expired_token_rejected() {
    let s = signer();
    let v = verifier(&s);
    let tok = s.mint("vk_abc", 1000, None);
    assert_eq!(v.verify(&tok, 1000, None), Err(VerifyError::Expired));
    assert_eq!(v.verify(&tok, 1001, None), Err(VerifyError::Expired));
    assert!(v.verify(&tok, 999, None).is_ok());
}

/// A TAMPERED payload (any byte flip) fails the signature check.
#[test]
fn tampered_token_rejected() {
    let s = signer();
    let v = verifier(&s);
    let tok = s.mint("vk_abc", 2000, None);
    // Flip a char in the payload segment.
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

/// ROTATION: a token signed by key A fails under a verifier holding only key B (same kid: the
/// signature check fails; different kid: UnknownKid). Both reject.
#[test]
fn token_fails_after_rotation() {
    let key_a = TokenSigner::from_secret_bytes(&[1u8; 32], DEFAULT_KID);
    let tok = key_a.mint("vk_abc", 2000, None);

    // Same kid, different key material -> BadSignature.
    let key_b_same_kid = TokenSigner::from_secret_bytes(&[2u8; 32], DEFAULT_KID);
    let v_b = verifier(&key_b_same_kid);
    assert_eq!(v_b.verify(&tok, 1000, None), Err(VerifyError::BadSignature));

    // Different kid entirely -> UnknownKid (the kid the token names is gone from the keyset).
    let key_c = TokenSigner::from_secret_bytes(&[3u8; 32], "k2");
    let v_c = verifier(&key_c);
    assert_eq!(v_c.verify(&tok, 1000, None), Err(VerifyError::UnknownKid));
}

/// Malformed inputs (no prefix, no dot, bad base64, wrong sig length) all reject as Malformed.
#[test]
fn malformed_tokens_rejected() {
    let s = signer();
    let v = verifier(&s);
    for bad in [
        "not-a-token",
        "bbk_onlyonesegment",
        "bbk_%%%.%%%",
        "bbk_YWJj.YWJj", // decodes but sig is not 64 bytes
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

/// A generated key round-trips through its raw secret bytes (the persistence path).
#[test]
fn generated_key_persists_and_reloads() {
    let s = TokenSigner::generate(DEFAULT_KID).unwrap();
    let bytes = s.secret_bytes();
    let reloaded = TokenSigner::from_secret_bytes(&bytes, DEFAULT_KID);
    let tok = s.mint("vk_x", 2000, None);
    // The reloaded key is the SAME key: it mints/verifies interchangeably.
    let v = TokenVerifier::single(DEFAULT_KID, reloaded.verifying_key());
    assert!(v.verify(&tok, 1000, None).is_ok());
}

/// The signer's Debug never leaks key bytes.
#[test]
fn signer_debug_redacts_key() {
    let s = signer();
    let dbg = format!("{s:?}");
    assert!(dbg.contains("redacted"));
    assert!(!dbg.contains(&hex::encode([7u8; 32])));
}

// ── THE SUBKEY DERIVATION: KNOWN-ANSWER VECTORS ──────────────────────────────────────────────────

/// THE BYTES ARE FROZEN. `subkey_seed` derives KEY MATERIAL, so a change to it is not a refactor
/// with a test to update — it silently rotates every subkey in every existing deployment, and the
/// symptom is signatures that stop verifying against what external callers already pinned. No
/// property test can catch that (a different-but-still-deterministic, still-domain-separated
/// derivation passes every property the neighbouring tests assert), so the bytes themselves are
/// pinned here.
///
/// These vectors were captured from the implementation as it stood BEFORE the function moved out of
/// the A2A plane into governance, and independently reproduced as
/// `SHA-256("busbar/subkey/v1" ‖ secret ‖ domain)` outside this codebase — so they pin the
/// construction, not merely whatever the current code happens to emit.
///
/// If one of these fails, do NOT re-baseline it. The context string is versioned precisely so that
/// an intended change to the derivation is spelled as a new version, leaving these vectors intact.
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
            "a2a/agent-card-signing/v1",
            "0bf68ad180162cd1cef2d93c0714a0bbc8584f6039fb39a4690589d11e82ecb5",
        ),
        (
            [7u8; 32],
            "a2a/agent-card-signing/v1",
            "9e3cc179e80446fc289701e3f0996a2305eedf7747bc082053f417f22bfbc14b",
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

    // A non-ASCII domain, pinned so the UTF-8 encoding of the domain string is part of the frozen
    // construction rather than an implementation detail free to change under it.
    let mut counting = [0u8; 32];
    for (i, b) in counting.iter_mut().enumerate() {
        *b = i as u8;
    }
    assert_eq!(
        hex::encode(subkey_seed(&counting, "dømain/✓/v1")),
        "a8d12c9765387d05e5147563df692d7b66b582e26d8879be61a74db65cad6bd2"
    );
}

/// The method on the signer is the free function over the signer's own secret — the seam the A2A
/// plane's `CardSigner` actually calls. Pinned end-to-end so the move cannot have changed what a
/// caller holding a TokenSigner gets, only where the code lives.
#[test]
fn derived_subkey_seed_is_the_free_function_over_the_root_secret() {
    let s = signer(); // secret [7u8; 32]
    assert_eq!(
        hex::encode(s.derived_subkey_seed("a2a/agent-card-signing/v1")),
        "9e3cc179e80446fc289701e3f0996a2305eedf7747bc082053f417f22bfbc14b",
        "the A2A card key derived off this signer must be byte-identical across the move"
    );
    assert_eq!(
        s.derived_subkey_seed("a2a/agent-card-signing/v1"),
        subkey_seed(&s.secret_bytes(), "a2a/agent-card-signing/v1"),
        "the method must be exactly the free function over the root secret, with no second path"
    );
}
