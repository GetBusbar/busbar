// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn exchange_ok_body_includes_base_url_equal_to_public_url() {
    let issued = IssuedKey {
        secret: busbar_contract::redacted::Secret::new("sk-busbar-abc".to_string()),
        key_id: "kid-1".into(),
        group: "eng".into(),
        exp: 1234567890,
    };
    let public_url = "https://busbar.example.com";
    let body = exchange_ok_body(&issued, public_url);
    assert_eq!(body["base_url"], public_url);
    assert_eq!(body["api_key"], "sk-busbar-abc");
    assert_eq!(body["key_id"], "kid-1");
    assert_eq!(body["group"], "eng");
    assert_eq!(body["exp"], 1234567890u64);

    assert!(!body["base_url"].as_str().unwrap().ends_with("/v1"));
}

#[tokio::test]
async fn mode_refused_exchange_leaves_its_verified_identitys_replay_claim_unclaimed() {
    use busbar_contract::auth_calls::{Replay, VerifiedIdentity};
    use std::sync::Arc;
    // Internal post-verification continuation: identity/replay/configuration are DATA;
    // the attached Store is the required actual product, not a verifier or Store replacement.
    let actual = crate::real_store::store();
    let gov = Arc::new(
        crate::governance::GovState::new_with_signer(
            actual.clone(),
            None,
            Some(crate::governance::signing::TokenSigner::from_secret_bytes(
                &[7u8; 32],
                crate::governance::signing::DEFAULT_KID,
            )),
        )
        .expect("actual governance constructs"),
    );
    assert!(gov.attach_store_calls(actual));
    let mut principal = crate::auth::Principal::from_id("sam");
    principal.roles = vec!["eng".to_string()];
    let verdict = crate::auth::ChainVerdict::Identified {
        module: "mode-replay-idp".to_string(),
        principal,
        resolved: None,
    };
    let bindings = std::collections::BTreeMap::from([(
        "mode-replay-idp".to_string(),
        std::collections::BTreeMap::from([(
            "eng".to_string(),
            crate::config::RoleBindingCfg {
                group: Some("team".to_string()),
                ..Default::default()
            },
        )]),
    )]);
    let policy = crate::governance::mint_policy::MintPolicy {
        block_binding_modes: Some(vec![crate::governance::SELF_KEY_BINDING_MODE_APP.into()]),
        ..Default::default()
    };
    let replay = Replay {
        key: "self-mode-refused".to_string(),
        ttl_secs: 300,
    };
    let identity = VerifiedIdentity {
        subject: "sam".to_string(),
        groups: vec!["eng".to_string()],
        replay: Some(Box::new(replay.clone())),
        ..Default::default()
    };
    let now = busbar_kernel::store::now();
    for _ in 0..2 {
        let claim = crate::auth::PendingClaim::for_identity(
            "mode-replay-idp",
            &identity,
            Some(gov.clone()),
            now,
        );
        let error = match admit_exchange_mint(&verdict, &bindings, &policy, 3600, Some(&gov), claim)
            .await
        {
            Ok(_) => {
                panic!("the mode policy must refuse before claiming the verified replay identity")
            }
            Err(error) => error,
        };
        let response = refusal(error);
        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }
    assert!(gov.all_keys().unwrap().is_empty());
    assert!(
        crate::auth::replay_claimed(Some(&gov), "mode-replay-idp", &replay, now).await,
        "the refused exchanges leave the verified replay claim available"
    );
    assert!(
        !crate::auth::replay_claimed(Some(&gov), "mode-replay-idp", &replay, now).await,
        "the attached actual Store really enforces replay claims"
    );
    // Actual App Arc non-swap/no-group publication is checked separately for this same mode
    // policy by the real root self_mint_mode_policy_gates_exchange_login_and_refresh_before_mutation.
}

#[tokio::test]
async fn dpop_refusal_keeps_the_exchange_unauthenticated_words() {
    // DPoP's Refused decision reaches this same production unauthorized formatter. The
    // constraint decision is separately pinned in auth::dpop unit tests.
    let response = refusal(ExchangeError::Unauthorized);
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    let body = std::str::from_utf8(&bytes).unwrap();
    assert_eq!((status, body), (401, r#"{"error":"not authenticated"}"#));
}

#[tokio::test]
async fn exchange_verifier_outcome_projection_preserves_failed_and_faulted_503() {
    use busbar_contract::auth_calls::{Verified, VerifiedIdentity};
    for faulted in [false, true] {
        let verified = if faulted {
            Verified::Identity(VerifiedIdentity {
                subject: "faulted".into(),
                ..Default::default()
            })
        } else {
            Verified::Failed
        };
        let judged = crate::auth::data_verdict_of("door", verified.into(), faulted).map(|judged| {
            crate::auth::chain_position_verdict("door", judged.verdict)
                .unwrap_or(crate::auth::ChainVerdict::Denied)
        });
        let response =
            exchange_verdict_result(judged).expect_err("no verdict refuses the exchange");
        assert_eq!(
            (
                response.status().as_u16(),
                response
                    .headers()
                    .get("retry-after")
                    .map(|value| value.to_str().unwrap())
            ),
            (503, Some("1")),
            "failed/faulted exchange:503 +Retry-After (SIGN-auth-kind 2026-10-30)"
        );
    }
}
