// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn the_opaque_caller_uses_only_the_verified_credential_for_every_carrier() {
    for (carrier, verified) in [
        ("bearer", Some("bearer-verified")),
        ("query", Some("query-verified")),
        ("custom", Some("custom-verified")),
        ("transformed", Some("normalized-verified")),
        ("absent", None),
    ] {
        let secret = verified.map(|value| busbar_contract::redacted::Secret::new(value.to_owned()));
        let opaque =
            verified_caller_credential(Some(secret.as_ref()), Some("unverified-wire-value"));
        assert_eq!(
            opaque
                .as_ref()
                .map(|caller| caller.lend().expose(&crate::seal::lend()).clone()),
            verified.map(|value| value.as_bytes().to_vec()),
            "{carrier}"
        );
        if let Some(verified) = verified {
            assert!(!format!("{opaque:?}").contains(verified));
        }
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer unverified-wire-value"),
        );
        headers.insert(
            "x-custom",
            HeaderValue::from_static("unverified-wire-value"),
        );
        headers.insert("x-safe", HeaderValue::from_static("kept"));
        let consumed = ConsumedCredentials::carrying(&[
            HeaderName::from_static("authorization"),
            HeaderName::from_static("x-custom"),
        ]);
        consumed.strip(&mut headers);
        assert!(!headers.contains_key("authorization"));
        assert!(!headers.contains_key("x-custom"));
        assert_eq!(headers.get("x-safe").unwrap(), "kept");
    }
    assert_eq!(
        verified_caller_credential(None, Some("normal-client-token"))
            .unwrap()
            .lend()
            .expose(&crate::seal::lend())
            .as_slice(),
        b"normal-client-token"
    );
    assert!(verified_caller_credential(None, None).is_none());
    assert!(verified_caller_credential(Some(None), Some("must-not-fall-back")).is_none());
}

#[test]
fn inbound_candidate_metadata_preserves_bearer_and_only_enables_dpop_with_the_as() {
    let carriers = [HeaderName::from_static("authorization")];
    for (has_as, scheme, expected) in [
        (false, "Bearer", Some("candidate")),
        (false, "DPoP", None),
        (true, "DPoP", Some("candidate")),
    ] {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_str(&format!("{scheme} candidate")).unwrap(),
        );
        headers.insert("x-safe", HeaderValue::from_static("unchanged"));
        let candidate = candidate_from_metadata(has_as, &carriers, &headers);
        assert_eq!(
            candidate
                .as_ref()
                .map(|value| value.expose(&crate::seal::lend()).as_str()),
            expected
        );
        assert_eq!(
            headers.get("authorization").unwrap().to_str().unwrap(),
            format!("{scheme} candidate")
        );
        assert_eq!(headers.get("x-safe").unwrap(), "unchanged");
    }
    let store = crate::real_store::store();
    let gov = crate::governance::GovState::new_with_signer(
        store,
        None,
        Some(crate::governance::signing::TokenSigner::from_secret_bytes(
            &[7; 32],
            crate::governance::signing::DEFAULT_KID,
        )),
    )
    .unwrap();
    let now = crate::store::now();
    let (key, token) = gov
        .mint_signed(crate::governance::NewKeySpec::default(), now + 3600, now)
        .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!("DPoP {}", token.expose(&crate::seal::lend()))).unwrap(),
    );
    let candidate = candidate_from_metadata(true, &carriers, &headers).unwrap();
    let verdict = keys_arm_verdict(
        Some(&gov),
        Some(candidate.expose(&crate::seal::lend())),
        now,
        None,
    );
    assert!(
        matches!(verdict, ChainVerdict::Identified { resolved: Some(resolved), .. } if resolved.id == key.id),
        "candidate preflight checks the real key without claiming a DPoP proof"
    );
    assert!(candidate_from_metadata(false, &carriers, &headers).is_none());
}
