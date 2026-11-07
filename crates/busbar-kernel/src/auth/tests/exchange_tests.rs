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

    let actual = crate::real_store::core().await;
    let gov = Arc::new(
        crate::governance::GovState::new_with_core(
            actual.clone(),
            None,
            Some(crate::governance::signing::TokenSigner::from_secret_bytes(
                &[7u8; 32],
                crate::governance::signing::DEFAULT_KID,
            )),
        )
        .await
        .expect("actual governance constructs"),
    );
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
    assert!(gov.all_keys_async().await.unwrap().is_empty());
    assert!(
        crate::auth::replay_claimed(Some(&gov), "mode-replay-idp", &replay, now).await,
        "the refused exchanges leave the verified replay claim available"
    );
    assert!(
        !crate::auth::replay_claimed(Some(&gov), "mode-replay-idp", &replay, now).await,
        "the attached actual Store really enforces replay claims"
    );
}

#[tokio::test]
async fn dpop_refusal_keeps_the_exchange_unauthenticated_words() {
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

struct ReplayBackend {
    inner: std::sync::Arc<dyn busbar_contract::persistence::PersistenceBackend>,
    lose: std::sync::atomic::AtomicBool,
    delivery_clock: std::sync::atomic::AtomicU64,
    original: std::sync::Mutex<Option<[u8; 32]>>,
}
impl busbar_contract::persistence::PersistenceBackend for ReplayBackend {
    fn info(&self) -> busbar_contract::persistence::BackendInfo {
        self.inner.info()
    }
    fn read(
        &self,
        request: std::sync::Arc<busbar_contract::persistence::Read>,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::ReadResult> {
        self.inner.read(request)
    }
    fn scan(
        &self,
        request: std::sync::Arc<busbar_contract::persistence::Scan>,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::Page> {
        self.inner.scan(request)
    }
    fn clock(
        &self,
        dataset: busbar_contract::persistence::DatasetId,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::ClockObservation>
    {
        Box::pin(async move {
            let mut clock = self.inner.clock(dataset).await?;
            let advanced = self
                .delivery_clock
                .load(std::sync::atomic::Ordering::SeqCst);
            if advanced != 0 {
                clock.unix_seconds = advanced;
            }
            Ok(clock)
        })
    }
    fn commit(
        &self,
        candidate: busbar_contract::persistence::PreparedCandidate,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::Decision> {
        Box::pin(async move {
            let replay = candidate.candidate().mutations.iter().any(|mutation| {
                let busbar_contract::persistence::Mutation::Put { address, .. } = mutation else {
                    return false;
                };
                crate::persistence::keys::components(&address.key, b'C').is_ok_and(|parts| {
                    parts.len() == 4
                        && parts[1] == b"busbar.auth-replay"
                        && parts[2] == b"auth-replay"
                })
            });
            let fingerprint = candidate.fingerprint();
            if replay {
                let mut original = self.original.lock().unwrap();
                if let Some(original) = *original {
                    assert_eq!(
                        fingerprint, original,
                        "an uncertain replay keeps the exact original candidate and expiry"
                    );
                } else {
                    *original = Some(fingerprint);
                }
            }
            let result = self.inner.commit(candidate).await?;
            if replay
                && self.lose.swap(false, std::sync::atomic::Ordering::SeqCst)
                && matches!(result, busbar_contract::persistence::Decision::Applied(_))
            {
                return Err(busbar_contract::persistence::Failure::Unknown);
            }
            Ok(result)
        })
    }
}

#[tokio::test]
async fn concurrent_auth_replay_admission_delivers_one_win_including_retained_unknown() {
    use std::sync::Arc;
    for (lose, expires_before_delivery) in [(false, false), (true, false), (true, true)] {
        let backend = Arc::new(ReplayBackend {
            inner: crate::real_store::native_backend().await,
            lose: std::sync::atomic::AtomicBool::new(false),
            delivery_clock: std::sync::atomic::AtomicU64::new(0),
            original: std::sync::Mutex::new(None),
        });
        let core = crate::real_store::core_over(backend.clone()).await;
        let gov = Arc::new(
            crate::governance::GovState::new_with_core(core, None, None)
                .await
                .unwrap(),
        );
        let replay = busbar_contract::auth_calls::Replay {
            key: "one-verified-request".into(),
            ttl_secs: 300,
        };
        let now = crate::store::now();
        for ttl_secs in [u64::MAX, u64::MAX - now] {
            let unbounded = busbar_contract::auth_calls::Replay {
                key: "unbounded-window".into(),
                ttl_secs,
            };
            assert!(
                !crate::auth::replay_claimed(Some(&gov), "provider", &unbounded, now).await,
                "overflow and an unbounded native deadline must not create replay records"
            );
        }
        if lose {
            backend
                .lose
                .store(true, std::sync::atomic::Ordering::SeqCst);
            assert!(
                !crate::auth::replay_claimed(Some(&gov), "provider", &replay, now).await,
                "an uncertain consume grants no auth admission"
            );
        }
        if expires_before_delivery {
            backend.delivery_clock.store(
                now + replay.ttl_secs + 1,
                std::sync::atomic::Ordering::SeqCst,
            );
        }
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let mut contenders = Vec::new();
        for _ in 0..2 {
            let (gov, replay, barrier) = (gov.clone(), replay.clone(), barrier.clone());
            contenders.push(tokio::spawn(async move {
                barrier.wait().await;
                crate::auth::replay_claimed(Some(&gov), "provider", &replay, now).await
            }));
        }
        barrier.wait().await;
        let mut admitted = 0;
        for contender in contenders {
            admitted += usize::from(contender.await.unwrap());
        }
        assert_eq!(
            admitted,
            usize::from(!expires_before_delivery),
            "only one eligible fresh auth invocation receives the claim's win"
        );
        assert!(
            !crate::auth::replay_claimed(Some(&gov), "provider", &replay, now).await,
            "later invocations cannot share the original Applied result"
        );
    }
}
