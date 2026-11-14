// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use super::super::self_keys::{
    admit_self_mint, mint_provisioned_self_key, resolve_exchange, ExchangeError,
};
use super::super::{ChainVerdict, Principal};
use crate::config::{RoleBindingCfg, RoleBindings};
use crate::governance::{GovState, SelfMintOp, SelfMintRefusal};
use busbar_contract::persistence::{
    BackendInfo, Call, ClockObservation, DatasetId, Decision, Failure, Page, PersistenceBackend,
    PreparedCandidate, Read, ReadResult, Scan,
};

const SEED: [u8; 32] = [7u8; 32];

async fn gov() -> Arc<GovState> {
    Arc::new(
        GovState::new_with_core(
            crate::real_store::core().await,
            None,
            Some(crate::governance::signing::TokenSigner::from_secret_bytes(
                &SEED,
                crate::governance::signing::DEFAULT_KID,
            )),
        )
        .await
        .expect("gov constructs"),
    )
}

fn principal(id: &str, roles: &[&str]) -> Principal {
    Principal {
        id: id.to_string(),
        name: Some("Sam".into()),
        roles: roles.iter().map(|r| r.to_string()).collect(),
        ttl_secs: None,
    }
}

fn bindings(module: &str, role: &str, group: Option<&str>) -> RoleBindings {
    let mut inner = BTreeMap::new();
    inner.insert(
        role.to_string(),
        RoleBindingCfg {
            allowed_pools: None,
            group: group.map(str::to_string),
            admin_scope: None,
            verbs: None,
            plane_grants: Default::default(),
        },
    );
    let mut outer: RoleBindings = BTreeMap::new();
    outer.insert(module.to_string(), inner);
    outer
}

fn identified(module: &str, p: Principal) -> ChainVerdict {
    ChainVerdict::Identified {
        module: module.to_string(),
        principal: p,
        resolved: None,
    }
}

async fn self_rows(gov: &GovState, sub: &str) -> Vec<crate::governance::VirtualKey> {
    let group = format!("user:{sub}");
    gov.all_keys_async()
        .await
        .unwrap()
        .into_iter()
        .filter(|k| k.enabled && k.deleted_at.is_none() && k.group.as_deref() == Some(&group))
        .collect()
}

/// Every undeleted row owned as the subject's self key, in any group.
async fn all_self_rows(gov: &GovState, sub: &str) -> Vec<VirtualKey> {
    let derived = GovState::derived_self_ids(&SEED, sub, 64);
    gov.all_keys_async()
        .await
        .unwrap()
        .into_iter()
        .filter(|k| GovState::owned_by(k, sub, &SEED, &derived))
        .collect()
}

#[tokio::test]
async fn first_call_provisions_second_call_reuses_one_row() {
    let gov = gov().await;
    let (b1, t1) = gov
        .issue_self("sam", "corp", None, 5000, 1000)
        .await
        .unwrap();
    let (b2, t2) = gov
        .issue_self("sam", "corp", None, 6000, 2000)
        .await
        .unwrap();

    assert_eq!(
        b1.id, b2.id,
        "deterministic id: re-login reuses the same subject"
    );
    assert_eq!(
        self_rows(&gov, "sam").await.len(),
        1,
        "exactly one binding row after two logins"
    );

    assert!(gov.verify_token(&t1, 1000, None).is_some());
    assert!(gov.verify_token(&t2, 2000, None).is_some());
}

#[tokio::test]
async fn cap_not_tripped_n_logins_one_row() {
    let gov = gov().await;
    for i in 0..25u64 {
        gov.issue_self("sam", "corp", None, 100_000, 1000 + i)
            .await
            .unwrap();
    }
    assert_eq!(
        self_rows(&gov, "sam").await.len(),
        1,
        "N logins must never sprawl past the one idempotent binding row"
    );
}

#[tokio::test]
async fn refresh_invalidates_old_token() {
    let gov = gov().await;
    let (_b, old) = gov
        .issue_self("sam", "corp", None, 100_000, 1000)
        .await
        .unwrap();
    assert!(
        gov.verify_token(&old, 1000, None).is_some(),
        "old token valid before refresh"
    );

    let (_b2, fresh) = gov
        .refresh_self("sam", "corp", None, 100_000, 2000)
        .await
        .unwrap();

    assert!(
        gov.verify_token(&old, 2000, None).is_none(),
        "refresh must invalidate the prior token"
    );

    assert!(
        gov.verify_token(&fresh, 2000, None).is_some(),
        "fresh token valid"
    );
    assert_eq!(
        self_rows(&gov, "sam").await.len(),
        1,
        "still one live self key after refresh"
    );
}

#[test]
fn hmac_sig_token_rejected_bad_signature() {
    let signer = crate::governance::signing::TokenSigner::from_secret_bytes(
        &SEED,
        crate::governance::signing::DEFAULT_KID,
    );
    let verifier =
        crate::governance::signing::TokenVerifier::single(signer.kid(), signer.verifying_key());

    let tok = signer.mint("vk_deadbeef", 5000, Some("0"));
    let body = tok.strip_prefix("bbk_").unwrap();
    let (payload_b64, _sig_b64) = body.split_once('.').unwrap();

    let forged_sig = busbar_contract::crypto::hmac_sha512(&SEED, b"user:vk_deadbeef#0")
        .expect("a 32-byte HMAC key");
    use base64::Engine;
    let forged = format!(
        "bbk_{}.{}",
        payload_b64,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(forged_sig)
    );
    let err = verifier.verify(&forged, 1000, None).unwrap_err();
    assert_eq!(
        err,
        crate::governance::signing::VerifyError::BadSignature,
        "an HMAC in the signature slot is a forgery, rejected BadSignature"
    );
}

#[tokio::test]
async fn issued_token_verifies_through_the_unchanged_path() {
    let gov = gov().await;
    let (binding, token) = gov
        .issue_self("sam", "corp", None, 5000, 1000)
        .await
        .unwrap();
    let resolved = gov
        .verify_token(&token, 1000, None)
        .expect("standard token verifies");
    assert_eq!(resolved.id, binding.id);
    assert_eq!(resolved.group.as_deref(), Some("user:sam"));
}

#[tokio::test]
async fn re_login_updates_allowed_pools_when_they_change() {
    use busbar_contract::records::ScopeRef;
    let gov = gov().await;
    let (b1, _t1) = gov
        .issue_self("sam", "corp", Some(vec!["poolA".into()]), 5000, 1000)
        .await
        .unwrap();
    assert_eq!(b1.allowed_scopes, Some(vec![ScopeRef::pool("poolA")]));

    let (b2, _t2) = gov
        .issue_self("sam", "corp", Some(vec!["poolB".into()]), 6000, 2000)
        .await
        .unwrap();
    assert_eq!(
        b2.id, b1.id,
        "still exactly ONE binding (same deterministic id)"
    );
    assert_eq!(
        b2.allowed_scopes,
        Some(vec![ScopeRef::pool("poolB")]),
        "a changed allowed_pools must take effect on re-login, not keep the stale set"
    );
}

#[tokio::test]
async fn concurrent_issue_self_yields_one_binding() {
    let gov = gov().await;
    let mut handles = vec![];
    for i in 0..8u64 {
        let g = gov.clone();
        handles.push(tokio::spawn(async move {
            g.issue_self("sam", "corp", Some(vec!["p".into()]), 5000, 1000 + i)
                .await
                .unwrap();
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    assert_eq!(
        self_rows(&gov, "sam").await.len(),
        1,
        "concurrent self-logins for one sub must leave exactly one binding"
    );
}

struct RefreshOverlapStore {
    inner: Arc<dyn PersistenceBackend>,
    next_put: std::sync::Mutex<
        Option<(
            tokio::sync::oneshot::Sender<()>,
            tokio::sync::oneshot::Receiver<()>,
        )>,
    >,
}
impl PersistenceBackend for RefreshOverlapStore {
    fn info(&self) -> BackendInfo {
        self.inner.info()
    }
    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        self.inner.read(request)
    }
    fn scan(&self, request: Arc<Scan>) -> Call<'_, Page> {
        self.inner.scan(request)
    }
    fn clock(&self, dataset: DatasetId) -> Call<'_, ClockObservation> {
        self.inner.clock(dataset)
    }
    fn commit(
        &self,
        candidate: PreparedCandidate,
        key: busbar_contract::persistence::CommitKey,
    ) -> Call<'_, Decision> {
        Box::pin(async move {
            let key_write = candidate
                .candidate()
                .mutations
                .iter()
                .any(|mutation| match mutation {
                    busbar_contract::persistence::Mutation::Put { address, .. } => {
                        address.namespace == crate::governance::persistence::identity::NAMESPACE.0
                            && address.key.first() == Some(&b'K')
                    }
                    _ => false,
                });
            let pause = if key_write {
                self.next_put.lock().unwrap().take()
            } else {
                None
            };
            if let Some((entered, release)) = pause {
                let _ = entered.send(());
                tokio::time::timeout(Duration::from_secs(10), release)
                    .await
                    .map_err(|_| Failure::Refused)?
                    .map_err(|_| Failure::Refused)?;
            }
            self.inner.commit(candidate, key).await
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_login_or_refresh_overlapping_refresh_uses_the_surviving_binding() {
    fn issued(
        answer: Result<super::super::self_keys::IssuedKey, ExchangeError>,
    ) -> busbar_contract::redacted::Secret<String> {
        answer
            .expect("the admitted identity must receive an actual Store key")
            .secret
    }

    for contender_refresh in [false, true] {
        let store = Arc::new(RefreshOverlapStore {
            inner: crate::real_store::native_backend().await,
            next_put: std::sync::Mutex::new(None),
        });
        let core = crate::real_store::core_over(store.clone()).await;
        let gov = Arc::new(
            GovState::new_with_core(
                core.clone(),
                None,
                Some(crate::governance::signing::TokenSigner::from_secret_bytes(
                    &SEED,
                    crate::governance::signing::DEFAULT_KID,
                )),
            )
            .await
            .unwrap(),
        );

        let mint_now = busbar_kernel::store::now();
        let original = issued(
            mint_provisioned_self_key(
                gov.clone(),
                crate::governance::SelfMintOp::Issue,
                crate::governance::UnattributedBinding::Adopt,
                &principal("sam", &["eng"]),
                "corp",
                None,
                mint_now.saturating_add(3600),
                mint_now,
            )
            .await,
        );
        let now = busbar_kernel::store::now();
        let original_id = gov
            .verify_token(original.expose(&crate::seal::lend()), now, None)
            .expect("the initial token verifies")
            .id
            .clone();

        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        *store.next_put.lock().unwrap() = Some((entered_tx, release_rx));
        let first_gov = gov.clone();
        let first = tokio::spawn(async move {
            mint_provisioned_self_key(
                first_gov,
                crate::governance::SelfMintOp::Refresh,
                crate::governance::UnattributedBinding::Adopt,
                &principal("sam", &["eng"]),
                "corp",
                None,
                mint_now.saturating_add(3600),
                mint_now,
            )
            .await
        });
        if !matches!(
            tokio::time::timeout(Duration::from_secs(5), entered_rx).await,
            Ok(Ok(()))
        ) {
            let _ = release_tx.send(());
            let _ = tokio::time::timeout(Duration::from_secs(10), first).await;
            panic!("refresh did not reach the real store write");
        }

        let waiting = gov.observe_identity_mutation_wait();
        let next_gov = gov.clone();
        let contender = tokio::spawn(async move {
            mint_provisioned_self_key(
                next_gov,
                if contender_refresh {
                    crate::governance::SelfMintOp::Refresh
                } else {
                    crate::governance::SelfMintOp::Issue
                },
                crate::governance::UnattributedBinding::Adopt,
                &principal("sam", &["eng"]),
                "corp",
                None,
                mint_now.saturating_add(3600),
                mint_now,
            )
            .await
        });
        let contended = tokio::time::timeout(Duration::from_secs(5), async {
            while !waiting.load(std::sync::atomic::Ordering::Acquire) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .is_ok();

        let other_gov = gov.clone();
        let mut other = tokio::spawn(async move {
            mint_provisioned_self_key(
                other_gov,
                crate::governance::SelfMintOp::Issue,
                crate::governance::UnattributedBinding::Adopt,
                &principal("other", &["eng"]),
                "corp",
                None,
                mint_now.saturating_add(3600),
                mint_now,
            )
            .await
        });
        let other_progress = tokio::time::timeout(Duration::from_secs(2), &mut other).await;
        let other_completed_while_parked = other_progress.is_ok();
        let completed_while_parked = contender.is_finished();

        let _ = release_tx.send(());
        let first = tokio::time::timeout(Duration::from_secs(10), first)
            .await
            .expect("the released first actual mint completes");
        let contender = tokio::time::timeout(Duration::from_secs(10), contender)
            .await
            .expect("the released contender actual mint completes");
        let other = match other_progress {
            Ok(answer) => answer,
            Err(_) => tokio::time::timeout(Duration::from_secs(10), other)
                .await
                .expect("the other actual mint completes after release"),
        };
        assert!(
            contended,
            "the overlapping caller must reach the subject's contended wait while refresh is parked"
        );
        assert!(
            other_completed_while_parked,
            "another subject progresses while this refresh is parked"
        );
        let other = issued(other.unwrap());
        let first = issued(first.unwrap());
        let contender = issued(contender.unwrap());
        assert!(
            !completed_while_parked,
            "the same subject must wait for its refresh transfer"
        );

        let now = busbar_kernel::store::now();
        assert!(gov
            .verify_token(original.expose(&crate::seal::lend()), now, None)
            .is_none());
        let surviving = gov
            .verify_token(contender.expose(&crate::seal::lend()), now, None)
            .expect("the overlapping caller receives the surviving token");
        assert_ne!(surviving.id, original_id);
        let first_live = gov.verify_token(first.expose(&crate::seal::lend()), now, None);
        if contender_refresh {
            assert!(
                first_live.is_none(),
                "the second refresh invalidates the first refresh's token"
            );
        } else {
            assert_eq!(
                first_live.expect("a login reuses the refreshed binding").id,
                surviving.id
            );
        }
        assert!(gov
            .verify_token(other.expose(&crate::seal::lend()), now, None)
            .is_some());
        let live = self_rows(&gov, "sam").await;
        assert_eq!(live.len(), 1, "overlap leaves one live self binding");
        assert_eq!(live[0].id, surviving.id);
        let old = core
            .identity()
            .get_key(&original_id)
            .await
            .unwrap()
            .unwrap();
        assert!(
            !old.enabled && old.deleted_at.is_some(),
            "the original binding stays tombstoned"
        );
    }
}

const SELF_TTL: u64 = crate::governance::mint_policy::DEFAULT_KEY_TTL_SECS;

#[test]
fn the_block_ttl_ceiling_clamps_the_self_serve_key() {
    let rb = bindings("test-idp-double", "eng", Some("team"));
    let v = identified("test-idp-double", principal("sam", &["eng"]));
    let policy = crate::governance::mint_policy::MintPolicy {
        block_max_ttl_secs: Some(3_600),
        ..Default::default()
    };
    let mint = admit_self_mint(&v, &rb, &policy, SELF_TTL).expect("admitted, clamped");
    assert_eq!(mint.ttl, Duration::from_secs(3_600));
    assert_eq!(mint.principal.id, "sam");
    assert_eq!(mint.team, "team");
}

#[test]
fn a_role_ttl_ceiling_clamps_the_self_serve_key() {
    let rb = bindings("test-idp-double", "eng", Some("team"));
    let v = identified("test-idp-double", principal("sam", &["eng"]));
    let mut policy = crate::governance::mint_policy::MintPolicy {
        block_max_ttl_secs: Some(86_400),
        ..Default::default()
    };
    policy.ceilings.insert(
        "eng".to_string(),
        crate::governance::mint_policy::RoleCeiling {
            max_ttl_secs: Some(600),
            ..Default::default()
        },
    );
    let mint = admit_self_mint(&v, &rb, &policy, SELF_TTL).expect("admitted, clamped");
    assert_eq!(mint.ttl, Duration::from_secs(600));
}

#[test]
fn a_role_pool_ceiling_refuses_a_self_serve_key_over_it() {
    let rb = bindings("test-idp-double", "eng", Some("team"));
    let v = identified("test-idp-double", principal("sam", &["eng"]));
    let mut policy = crate::governance::mint_policy::MintPolicy::default();
    policy.ceilings.insert(
        "eng".to_string(),
        crate::governance::mint_policy::RoleCeiling {
            allowed_pools: Some(vec!["pool-a".to_string()]),
            ..Default::default()
        },
    );
    assert!(matches!(
        admit_self_mint(&v, &rb, &policy, SELF_TTL),
        Err(ExchangeError::OverCeiling(_))
    ));
}

#[test]
fn no_policy_mints_at_the_self_serve_default_and_self_mint_off_still_refuses() {
    let rb = bindings("test-idp-double", "eng", Some("team"));
    let v = identified("test-idp-double", principal("sam", &["eng"]));
    let open = crate::governance::mint_policy::MintPolicy::default();
    let mint = admit_self_mint(&v, &rb, &open, SELF_TTL).expect("no ceiling");
    assert_eq!(mint.ttl, Duration::from_secs(SELF_TTL));
    assert_eq!(mint.granted_scopes, None);
    let off = crate::governance::mint_policy::MintPolicy {
        self_mint: Some(false),
        block_max_ttl_secs: Some(3_600),
        ..Default::default()
    };
    assert!(matches!(
        admit_self_mint(&v, &rb, &off, SELF_TTL),
        Err(ExchangeError::SelfMintDisabled)
    ));
}

#[test]
fn self_mint_checks_its_recorded_mode_against_block_and_role_lists() {
    use crate::governance::mint_policy::{MintPolicy, RoleCeiling};
    use crate::governance::SELF_KEY_BINDING_MODE;

    let rb = bindings("test-idp-double", "eng", Some("team"));
    let verdict = identified("test-idp-double", principal("sam", &["eng"]));
    let user = SELF_KEY_BINDING_MODE;
    let time = crate::governance::SELF_KEY_BINDING_MODE_APP;
    for (block, role, allowed) in [
        (None, None, true),
        (Some(vec![user]), None, true),
        (None, Some(vec![user]), true),
        (Some(vec![user, time]), Some(vec![user]), true),
        (Some(vec![time]), None, false),
        (Some(vec![]), None, false),
        (None, Some(vec![time]), false),
        (None, Some(vec![]), false),
        (Some(vec![user, time]), Some(vec![time]), false),
        (Some(vec![time]), Some(vec![user]), false),
        (Some(vec![]), Some(vec![user]), false),
    ] {
        let mut policy = MintPolicy {
            block_binding_modes: block.map(|modes| modes.into_iter().map(str::to_string).collect()),
            ..Default::default()
        };
        if let Some(modes) = role {
            policy.ceilings.insert(
                "eng".into(),
                RoleCeiling {
                    binding_modes: Some(modes.into_iter().map(str::to_string).collect()),
                    ..Default::default()
                },
            );
        }
        match admit_self_mint(&verdict, &rb, &policy, SELF_TTL) {
            Ok(mint) => {
                assert!(allowed, "{policy:?}");
                assert_eq!(mint.principal.id, "sam");
                assert_eq!(mint.team, "team");
                assert_eq!(mint.granted_scopes, None);
                assert_eq!(mint.ttl, Duration::from_secs(SELF_TTL));
            }
            Err(ExchangeError::OverCeiling(message)) => {
                assert!(!allowed, "{policy:?}: {message}");
                assert!(message.contains(SELF_KEY_BINDING_MODE), "{message}");
            }
            Err(other) => panic!("unexpected admission error: {other:?}"),
        }
    }
}

#[test]
fn self_mint_unions_held_role_modes_then_narrows_by_the_block() {
    use crate::governance::mint_policy::{MintPolicy, RoleCeiling};
    use crate::governance::{SELF_KEY_BINDING_MODE, SELF_KEY_BINDING_MODE_APP};

    let rb = bindings("test-idp-double", "eng", Some("team"));
    let verdict = identified("test-idp-double", principal("sam", &["eng", "ops"]));
    for second_role_modes in [Some(vec![SELF_KEY_BINDING_MODE.to_string()]), None] {
        let mut policy = MintPolicy::default();
        for (role, modes) in [
            ("eng", Some(vec![SELF_KEY_BINDING_MODE_APP.to_string()])),
            ("ops", second_role_modes),
        ] {
            policy.ceilings.insert(
                role.into(),
                RoleCeiling {
                    binding_modes: modes,
                    ..Default::default()
                },
            );
        }
        assert!(admit_self_mint(&verdict, &rb, &policy, SELF_TTL).is_ok());
        policy.block_binding_modes = Some(vec![SELF_KEY_BINDING_MODE_APP.to_string()]);
        assert!(matches!(
            admit_self_mint(&verdict, &rb, &policy, SELF_TTL),
            Err(ExchangeError::OverCeiling(_))
        ));
    }
}

#[test]
fn self_mint_mode_refusal_preserves_identity_and_disabled_policy_errors() {
    use crate::governance::mint_policy::MintPolicy;

    let rb = bindings("test-idp-double", "eng", Some("team"));
    let mut policy = MintPolicy {
        block_binding_modes: Some(Vec::new()),
        ..Default::default()
    };
    for verdict in [ChainVerdict::Open, ChainVerdict::Denied] {
        assert!(matches!(
            admit_self_mint(&verdict, &rb, &policy, SELF_TTL),
            Err(ExchangeError::Unauthorized)
        ));
    }
    let verdict = identified("test-idp-double", principal("sam", &["eng"]));
    policy.self_mint = Some(false);
    assert!(matches!(
        admit_self_mint(&verdict, &rb, &policy, SELF_TTL),
        Err(ExchangeError::SelfMintDisabled)
    ));
}

#[test]
fn identity_from_principal_not_body() {
    let rb = bindings("test-idp-double", "eng", Some("team"));
    let v = identified("test-idp-double", principal("sam", &["eng"]));
    let (p, team, _pools) = resolve_exchange(&v, &rb, None).expect("bound principal admitted");
    assert_eq!(
        p.id, "sam",
        "self-scope comes from the verified principal, never a body"
    );
    assert_eq!(
        team, "team",
        "the bound team is threaded out for provisioning"
    );
}

#[test]
fn rejects_static_key_400() {
    let rb = bindings("test-idp-double", "eng", Some("team"));

    let key = Arc::new(crate::governance::VirtualKey {
        id: "vk_static".into(),
        generation_hash: "binding:vk_static:0".into(),
        name: "k".into(),
        allowed_scopes: None,
        enabled: true,
        created_at: 0,
        group: None,
        labels: BTreeMap::new(),
        expires_at: None,
        deleted_at: None,
        revision: 0,
        ..Default::default()
    });
    let v = ChainVerdict::Identified {
        module: "test-idp-double".into(),
        principal: principal("sam", &["eng"]),
        resolved: Some(key),
    };
    assert_eq!(
        resolve_exchange(&v, &rb, None).unwrap_err(),
        ExchangeError::StaticKeyPresented
    );
}

#[test]
fn open_and_denied_are_unauthorized() {
    let rb = bindings("test-idp-double", "eng", Some("team"));
    assert_eq!(
        resolve_exchange(&ChainVerdict::Open, &rb, None).unwrap_err(),
        ExchangeError::Unauthorized
    );
    assert_eq!(
        resolve_exchange(&ChainVerdict::Denied, &rb, None).unwrap_err(),
        ExchangeError::Unauthorized
    );
}

#[test]
fn unbound_role_is_403() {
    let rb = bindings("test-idp-double", "eng", Some("team"));
    let v = identified("test-idp-double", principal("sam", &["other"]));
    assert_eq!(
        resolve_exchange(&v, &rb, None).unwrap_err(),
        ExchangeError::Unbound
    );
}

#[test]
fn bound_role_without_group_is_403() {
    let rb = bindings("test-idp-double", "eng", None);
    let v = identified("test-idp-double", principal("sam", &["eng"]));
    assert_eq!(
        resolve_exchange(&v, &rb, None).unwrap_err(),
        ExchangeError::Unbound
    );
}

#[test]
fn later_role_group_used_when_earlier_role_bound_but_groupless() {
    let mut inner = BTreeMap::new();
    inner.insert(
        "A".to_string(),
        RoleBindingCfg {
            allowed_pools: Some(vec!["pool-a".to_string()]),
            group: None,
            admin_scope: None,
            verbs: None,
            plane_grants: Default::default(),
        },
    );
    inner.insert(
        "B".to_string(),
        RoleBindingCfg {
            allowed_pools: Some(vec!["pool-b".to_string()]),
            group: Some("x".to_string()),
            admin_scope: None,
            verbs: None,
            plane_grants: Default::default(),
        },
    );
    let mut rb: RoleBindings = BTreeMap::new();
    rb.insert("test-idp-double".to_string(), inner);

    let v = identified("test-idp-double", principal("sam", &["A", "B"]));
    let (_p, team, pools) = resolve_exchange(&v, &rb, None)
        .expect("a later granting role's group must admit the principal, not Unbound");
    assert_eq!(team, "x", "resolves to role B's group, not Unbound");
    let pools = pools.expect("neither granting binding omits allowed_pools");
    assert_eq!(
        pools.len(),
        2,
        "pools must be the union across ALL granting bindings: {pools:?}"
    );
    assert!(
        pools.contains(&busbar_contract::records::ScopeRef::pool("pool-a")),
        "role A's pool must be in the union: {pools:?}"
    );
    assert!(
        pools.contains(&busbar_contract::records::ScopeRef::pool("pool-b")),
        "role B's pool must be in the union: {pools:?}"
    );
}

#[test]
fn omitted_pools_on_any_granting_binding_widens_union_to_all_pools() {
    let mut inner = BTreeMap::new();
    inner.insert(
        "A".to_string(),
        RoleBindingCfg {
            allowed_pools: None,
            group: None,
            admin_scope: None,
            verbs: None,
            plane_grants: Default::default(),
        },
    );
    inner.insert(
        "B".to_string(),
        RoleBindingCfg {
            allowed_pools: Some(vec!["pool-b".to_string()]),
            group: Some("x".to_string()),
            admin_scope: None,
            verbs: None,
            plane_grants: Default::default(),
        },
    );
    let mut rb: RoleBindings = BTreeMap::new();
    rb.insert("test-idp-double".to_string(), inner);

    let v = identified("test-idp-double", principal("sam", &["A", "B"]));
    let (_p, team, pools) = resolve_exchange(&v, &rb, None).expect("both roles grant");
    assert_eq!(team, "x");
    assert_eq!(
        pools, None,
        "an omitted allowed_pools on ANY granting binding widens the union to ALL pools"
    );
}

#[test]
fn sub_sanitization_refused() {
    let rb = bindings("test-idp-double", "eng", Some("team"));

    for bad in ["a/b", "vk_evil", "group:x", "user:x", "", "a\tb", "a\nb"] {
        let v = identified("test-idp-double", principal(bad, &["eng"]));
        assert_eq!(
            resolve_exchange(&v, &rb, None).unwrap_err(),
            ExchangeError::BadSubject,
            "unsafe subject {bad:?} must be refused"
        );
    }

    for ok in ["sam", "test-idp-double:alice", "test-external-idp:torvalds"] {
        let v = identified("test-idp-double", principal(ok, &["eng"]));
        assert!(
            resolve_exchange(&v, &rb, None).is_ok(),
            "legitimate subject {ok:?} must be admitted"
        );
    }
}

#[tokio::test]
async fn resolve_then_issue_via_real_seam() {
    let gov = gov().await;

    let mint_now = busbar_kernel::store::now();
    let rb = bindings("test-idp-double", "eng", Some("team"));
    let v = identified("test-idp-double", principal("sam", &["eng"]));
    let (p, team, pools) = resolve_exchange(&v, &rb, None).unwrap();
    assert_eq!(team, "team");
    let issued = mint_provisioned_self_key(
        gov.clone(),
        crate::governance::SelfMintOp::Issue,
        crate::governance::UnattributedBinding::Adopt,
        p,
        "corp",
        pools,
        mint_now.saturating_add(3600),
        mint_now,
    )
    .await
    .unwrap();
    assert!(issued
        .secret
        .expose(&crate::seal::lend())
        .starts_with("bbk_"));
    assert_eq!(issued.group, "user:sam");

    let now = busbar_kernel::store::now();
    assert!(gov
        .verify_token(issued.secret.expose(&crate::seal::lend()), now, None)
        .is_some());
}

#[tokio::test]
async fn module_namespaced_sub_is_admitted_and_grouped_under_user() {
    let gov = gov().await;

    let mint_now = busbar_kernel::store::now();
    let rb = bindings("test-idp-double", "eng", Some("team"));
    let v = identified(
        "test-idp-double",
        principal("test-idp-double:alice", &["eng"]),
    );
    let (p, team, pools) = resolve_exchange(&v, &rb, None)
        .expect("a module-namespaced subject is legitimate + verified");
    assert_eq!(team, "team");
    let issued = mint_provisioned_self_key(
        gov.clone(),
        crate::governance::SelfMintOp::Issue,
        crate::governance::UnattributedBinding::Adopt,
        p,
        "corp",
        pools,
        mint_now.saturating_add(3600),
        mint_now,
    )
    .await
    .unwrap();
    assert_eq!(
        issued.group, "user:test-idp-double:alice",
        "the whole sub lives inside the user: namespace"
    );
    assert!(gov
        .verify_token(
            issued.secret.expose(&crate::seal::lend()),
            busbar_kernel::store::now(),
            None
        )
        .is_some());
}

async fn row(gov: &GovState, id: &str) -> crate::governance::VirtualKey {
    gov.core_store()
        .unwrap()
        .identity()
        .get_key(id)
        .await
        .unwrap()
        .expect("the row exists")
}

/// Every non-tombstoned self-serve row of `sub`, enabled or not, in whatever group an admin put it.
async fn subject_rows(gov: &GovState, sub: &str) -> Vec<crate::governance::VirtualKey> {
    gov.all_keys_async()
        .await
        .unwrap()
        .into_iter()
        .filter(|k| k.deleted_at.is_none() && k.idp_subject.as_deref() == Some(sub))
        .collect()
}

async fn login(
    gov: &Arc<GovState>,
    who: &Principal,
    provider: &str,
    op: SelfMintOp,
) -> Result<super::super::self_keys::IssuedKey, ExchangeError> {
    let now = busbar_kernel::store::now();
    mint_provisioned_self_key(gov.clone(), op, who, provider, None, now + 3600, now).await
}

fn live(gov: &GovState, token: &super::super::self_keys::IssuedKey) -> bool {
    gov.verify_token(
        token.secret.expose(&crate::seal::lend()),
        busbar_kernel::store::now(),
        None,
    )
    .is_some()
}

#[tokio::test]
async fn an_admin_disable_is_not_undone_by_the_next_login() {
    let gov = gov().await;
    let alice = principal("oidc:alice", &["eng"]);

    let t0 = login(&gov, &alice, "corp", SelfMintOp::Issue)
        .await
        .expect("first login issues");
    assert!(live(&gov, &t0));

    gov.update_key_outcome_async(&t0.key_id, Some(false), None)
        .await
        .unwrap()
        .expect("the key exists");
    let before = subject_rows(&gov, "oidc:alice").await;

    assert_eq!(
        login(&gov, &alice, "corp", SelfMintOp::Issue)
            .await
            .map(|k| k.key_id),
        Err(ExchangeError::Held(SelfMintRefusal::Disabled)),
        "a login while the key is disabled is refused, not re-enabled"
    );
    assert_eq!(
        login(&gov, &alice, "corp", SelfMintOp::Refresh)
            .await
            .map(|k| k.key_id),
        Err(ExchangeError::Held(SelfMintRefusal::Disabled)),
        "a refresh while the key is disabled is refused too"
    );
    assert!(
        !row(&gov, &t0.key_id).await.enabled,
        "the admin's disable still stands"
    );
    assert!(
        !live(&gov, &t0),
        "the pre-disable token must NOT come back to life"
    );
    assert_eq!(
        subject_rows(&gov, "oidc:alice").await,
        before,
        "no fresh key was minted beside the disabled one"
    );
}

// T1 (owner sign-off: inverts the 1.5.5-parity pin `a_login_after_an_admin_disable_mints_as_1_5_5_minted`).
// Default configuration, no `hold_self_mint_state`: a login after an admin disable is refused and the
// disable stands. Red on b345530502: the probe reuses the disabled derived row (self_serve.rs:137-140)
// and `write_self_binding` writes it back `enabled: true` (:229), so both doors return Ok.
#[tokio::test]
async fn a_disable_at_a_skipped_epoch_mints_no_sibling() {
    let gov = gov().await;
    let alice = principal("oidc:alice", &["eng"]);
    login(&gov, &alice, "corp", SelfMintOp::Issue)
        .await
        .unwrap();
    let mut current = None;
    for _ in 0..3 {
        current = Some(
            login(&gov, &alice, "corp", SelfMintOp::Refresh)
                .await
                .unwrap(),
        );
    }
    let current = current.unwrap();
    gov.update_key_outcome_async(&current.key_id, Some(false), None)
        .await
        .unwrap()
        .expect("the live key exists");

    assert_eq!(
        login(&gov, &alice, "corp", SelfMintOp::Issue)
            .await
            .map(|k| k.key_id),
        Err(ExchangeError::Held(SelfMintRefusal::Disabled)),
        "a disable at an epoch the probe skips is not routed around"
    );
    let rows = subject_rows(&gov, "oidc:alice").await;
    assert_eq!(
        rows.iter().map(|k| k.id.as_str()).collect::<Vec<_>>(),
        vec![current.key_id.as_str()],
        "still exactly the one disabled key: {rows:?}"
    );
}

// T2 (owner sign-off: inverts the 1.5.5-parity pin
// `a_second_provider_asserting_the_same_subject_is_handed_its_key_as_1_5_5_did`). OIDC Core 1.0 §2:
// `sub` is unique only within its issuer. Red on b345530502: `self_mint_refusal` returns None while
// the toggle is off (self_serve.rs:90-92), so partner is handed corp's key id.
#[tokio::test]
async fn a_revoked_self_key_is_refused_403_not_500() {
    for refreshes in [0usize, 3] {
        let gov = gov().await;
        let alice = principal("oidc:alice", &["eng"]);
        let mut current = login(&gov, &alice, "corp", SelfMintOp::Issue)
            .await
            .unwrap();
        for _ in 0..refreshes {
            current = login(&gov, &alice, "corp", SelfMintOp::Refresh)
                .await
                .unwrap();
        }
        gov.revoke_async(&current.key_id, "operator revoked")
            .await
            .unwrap();
        for op in [SelfMintOp::Issue, SelfMintOp::Refresh] {
            assert_eq!(
                login(&gov, &alice, "corp", op).await.map(|k| k.key_id),
                Err(ExchangeError::Held(SelfMintRefusal::Revoked)),
                "after {refreshes} refreshes, {op:?} on a revoked key is a coded 403, never a 500 \
                 or a fresh sibling key"
            );
        }
        let rows = subject_rows(&gov, "oidc:alice").await;
        assert_eq!(
            rows.iter().map(|k| k.id.as_str()).collect::<Vec<_>>(),
            vec![current.key_id.as_str()],
            "no sibling key was minted beside the revoked one: {rows:?}"
        );
    }
}

#[tokio::test]
async fn a_revoked_self_key_is_never_re_enabled_and_delete_resets() {
    let gov = gov().await;
    let alice = principal("oidc:alice", &["eng"]);
    let t0 = login(&gov, &alice, "corp", SelfMintOp::Issue)
        .await
        .unwrap();
    gov.revoke_async(&t0.key_id, "operator revoked")
        .await
        .unwrap();

    assert!(
        matches!(
            gov.update_key_outcome_async(&t0.key_id, Some(true), None)
                .await,
            Err(crate::governance::KeyMutationError::Revoked { ref key_id }) if *key_id == t0.key_id
        ),
        "an admin PATCH {{enabled:true}} on a revoked key is refused"
    );
    assert!(
        !row(&gov, &t0.key_id).await.enabled,
        "the revoked key stays disabled"
    );
    for op in [SelfMintOp::Issue, SelfMintOp::Refresh, SelfMintOp::Issue] {
        assert_eq!(
            login(&gov, &alice, "corp", op).await.map(|k| k.key_id),
            Err(ExchangeError::Held(SelfMintRefusal::Revoked)),
            "{op:?}: revoked is terminal"
        );
    }
    assert!(!live(&gov, &t0), "the revoked token never verifies again");

    // The admin's DELETE is the reset: tombstone, then the next login mints a NEW key.
    gov.delete_key(&t0.key_id).await.unwrap();
    let fresh = login(&gov, &alice, "corp", SelfMintOp::Issue)
        .await
        .expect("a login after the admin's delete mints a fresh key");
    assert_ne!(fresh.key_id, t0.key_id, "a new id, never the revoked one");
    assert!(live(&gov, &fresh));
    assert!(
        !live(&gov, &t0),
        "the revoked-then-deleted key's token never verifies again"
    );
    assert!(
        gov.update_key_outcome_async(&t0.key_id, Some(true), None)
            .await
            .unwrap()
            .is_none(),
        "the tombstone cannot be re-enabled either"
    );
    assert!(!live(&gov, &t0));
}

#[tokio::test]
async fn an_admin_re_enable_lets_the_next_login_reshow_the_same_key() {
    let gov = gov().await;
    let alice = principal("oidc:alice", &["eng"]);
    let t0 = login(&gov, &alice, "corp", SelfMintOp::Issue)
        .await
        .unwrap();
    gov.update_key_outcome_async(&t0.key_id, Some(false), None)
        .await
        .unwrap()
        .unwrap();
    gov.update_key_outcome_async(&t0.key_id, Some(true), None)
        .await
        .unwrap()
        .expect("an admin re-enables a disabled (not revoked) key");
    let again = login(&gov, &alice, "corp", SelfMintOp::Issue)
        .await
        .expect("the admin cleared the hold");
    assert_eq!(again.key_id, t0.key_id, "the same key is re-shown");
    assert!(live(&gov, &t0), "the admin chose to revive its tokens");
}

#[tokio::test]
async fn an_admin_regroup_is_kept_across_login_and_refresh() {
    let gov = gov().await;
    let alice = principal("oidc:alice", &["eng"]);
    let t0 = login(&gov, &alice, "corp", SelfMintOp::Issue)
        .await
        .unwrap();
    gov.update_key_outcome_async(&t0.key_id, None, Some(Some("quarantine".into())))
        .await
        .unwrap()
        .unwrap();

    let again = login(&gov, &alice, "corp", SelfMintOp::Issue)
        .await
        .expect("a regrouped key still logs in");
    assert_eq!(again.key_id, t0.key_id, "the same key, not a second one");
    assert_eq!(again.group, "quarantine");
    assert_eq!(
        row(&gov, &t0.key_id).await.group.as_deref(),
        Some("quarantine"),
        "the login did not move the key back to user:<sub>"
    );

    let refreshed = login(&gov, &alice, "corp", SelfMintOp::Refresh)
        .await
        .expect("a regrouped key refreshes");
    assert_ne!(refreshed.key_id, t0.key_id);
    assert_eq!(
        row(&gov, &refreshed.key_id).await.group.as_deref(),
        Some("quarantine"),
        "the refresh carries the admin's group"
    );
    let rows = subject_rows(&gov, "oidc:alice").await;
    assert_eq!(
        rows.iter()
            .filter(|k| k.enabled)
            .map(|k| k.id.as_str())
            .collect::<Vec<_>>(),
        vec![refreshed.key_id.as_str()],
        "one live key for the subject: {rows:?}"
    );
}

#[tokio::test]
async fn a_disable_racing_a_login_is_a_403_not_a_500() {
    let gov = gov().await;
    let alice = principal("oidc:alice", &["eng"]);
    let t0 = login(&gov, &alice, "corp", SelfMintOp::Issue)
        .await
        .unwrap();

    let waiting = gov.observe_identity_mutation_wait();
    let claim = gov.identity_key_guard(&t0.key_id).await;
    let racer = {
        let gov = gov.clone();
        let alice = alice.clone();
        tokio::spawn(async move { login(&gov, &alice, "corp", SelfMintOp::Issue).await })
    };
    while !waiting.load(std::sync::atomic::Ordering::Acquire) {
        tokio::task::yield_now().await;
    }
    gov.update_key_outcome_claimed_async(&t0.key_id, Some(false), None, &claim)
        .await
        .unwrap()
        .unwrap();
    drop(claim);
    assert_eq!(
        racer.await.unwrap().map(|k| k.key_id),
        Err(ExchangeError::Held(SelfMintRefusal::Disabled)),
        "a disable landing while the login waits is the same coded 403"
    );
}

#[tokio::test]
async fn a_held_refusal_is_audited() {
    crate::audit::auditlog::ensure_global_audit_stream_registered().await;
    let gov = gov().await;
    let sub = format!("oidc:audited-{}", busbar_kernel::door::op_id().counter());
    let who = principal(&sub, &["eng"]);
    let t0 = login(&gov, &who, "corp", SelfMintOp::Issue).await.unwrap();
    gov.update_key_outcome_async(&t0.key_id, Some(false), None)
        .await
        .unwrap()
        .unwrap();
    assert!(login(&gov, &who, "corp", SelfMintOp::Issue).await.is_err());
    crate::audit::auditlog::flush_pending()
        .await
        .expect("the refusal's audit record is confirmed");
    let resource = format!("key:{}#disabled", t0.key_id);
    let sealed = crate::audit::auditlog::AUDIT_LOG.list_filtered(
        0,
        usize::MAX,
        Some("self_serve.mint"),
        Some(&resource),
    );
    assert_eq!(
        sealed.len(),
        1,
        "one admin-log record per refusal: {sealed:?}"
    );
    assert_eq!(sealed[0].outcome, "rejected");
    assert_eq!(sealed[0].principal, sub, "attributed to the subject");
}

#[tokio::test]
async fn a_self_serve_key_carries_empty_labels_as_1_5_5_wrote_it() {
    let gov = gov().await;

    let mint_now = busbar_kernel::store::now();
    let alice = principal("oidc:alice", &["eng"]);
    let ttl = Duration::from_secs(3600);

    let issued = mint_provisioned_self_key(
        gov.clone(),
        crate::governance::SelfMintOp::Issue,
        crate::governance::UnattributedBinding::Adopt,
        &alice,
        "corp",
        None,
        mint_now.saturating_add(ttl.as_secs()),
        mint_now,
    )
    .await
    .expect("issues");
    let first = row(&gov, &issued.key_id).await;
    assert!(first.labels.is_empty(), "issue: {:?}", first.labels);
    assert_eq!(first.idp_provider.as_deref(), Some("corp"));

    let again = mint_provisioned_self_key(
        gov.clone(),
        crate::governance::SelfMintOp::Issue,
        crate::governance::UnattributedBinding::Adopt,
        &alice,
        "corp",
        None,
        mint_now.saturating_add(ttl.as_secs()),
        mint_now,
    )
    .await
    .expect("re-issues");
    assert!(row(&gov, &again.key_id).await.labels.is_empty(), "re-issue");

    let rotated = mint_provisioned_self_key(
        gov.clone(),
        crate::governance::SelfMintOp::Refresh,
        crate::governance::UnattributedBinding::Adopt,
        &alice,
        "corp",
        None,
        mint_now.saturating_add(ttl.as_secs()),
        mint_now,
    )
    .await
    .expect("refreshes");
    let rotated_row = row(&gov, &rotated.key_id).await;
    assert!(
        rotated_row.labels.is_empty(),
        "refresh: {:?}",
        rotated_row.labels
    );
    assert_eq!(rotated_row.idp_provider.as_deref(), Some("corp"));
}

#[tokio::test]
async fn a_second_provider_asserting_the_same_subject_is_refused() {
    let gov = gov().await;

    let mint_now = busbar_kernel::store::now();

    let alice = principal("oidc:alice", &["eng"]);
    let ttl = Duration::from_secs(3600);

    let issued = mint_provisioned_self_key(
        gov.clone(),
        crate::governance::SelfMintOp::Issue,
        crate::governance::UnattributedBinding::Adopt,
        &alice,
        "corp",
        None,
        mint_now.saturating_add(ttl.as_secs()),
        mint_now,
    )
    .await
    .expect("corp issues");
    let before = row(&gov, &issued.key_id).await;
    assert_eq!(
        before.idp_provider.as_deref(),
        Some("corp"),
        "the binding records its minting provider"
    );

    assert_eq!(
        mint_provisioned_self_key(
            gov.clone(),
            crate::governance::SelfMintOp::Issue,
            crate::governance::UnattributedBinding::Adopt,
            &alice,
            "partner",
            None,
            mint_now.saturating_add(ttl.as_secs()),
            mint_now
        )
        .await
        .unwrap_err(),
        ExchangeError::Held(SelfMintRefusal::OtherProvider),
        "another provider asserting the subject is refused"
    );
    assert_eq!(
        mint_provisioned_self_key(
            gov.clone(),
            crate::governance::SelfMintOp::Refresh,
            crate::governance::UnattributedBinding::Adopt,
            &alice,
            "partner",
            None,
            mint_now.saturating_add(ttl.as_secs()),
            mint_now
        )
        .await
        .unwrap_err(),
        ExchangeError::Held(SelfMintRefusal::OtherProvider),
        "and cannot refresh corp's key away"
    );

    let after = row(&gov, &issued.key_id).await;
    assert!(after.enabled && after.deleted_at.is_none());
    assert_eq!(
        after.generation_hash, before.generation_hash,
        "corp's key is untouched"
    );
    let now = busbar_kernel::store::now();
    assert!(gov
        .verify_token(issued.secret.expose(&crate::seal::lend()), now, None)
        .is_some());
    let again = mint_provisioned_self_key(
        gov.clone(),
        crate::governance::SelfMintOp::Issue,
        crate::governance::UnattributedBinding::Adopt,
        &alice,
        "corp",
        None,
        mint_now.saturating_add(ttl.as_secs()),
        mint_now,
    )
    .await
    .expect("corp still logs in");
    assert_eq!(again.key_id, issued.key_id);
}

#[tokio::test]
async fn a_legacy_self_serve_binding_adopts_the_first_provider_that_logs_in() {
    let gov = gov().await;

    let mint_now = busbar_kernel::store::now();

    let alice = principal("oidc:alice", &["eng"]);
    let ttl = Duration::from_secs(3600);

    let issued = mint_provisioned_self_key(
        gov.clone(),
        crate::governance::SelfMintOp::Issue,
        crate::governance::UnattributedBinding::Adopt,
        &alice,
        "corp",
        None,
        mint_now.saturating_add(ttl.as_secs()),
        mint_now,
    )
    .await
    .expect("issues");
    let mut legacy = row(&gov, &issued.key_id).await;
    legacy.idp_provider = None;
    gov.core_store()
        .unwrap()
        .identity()
        .put_key(&legacy)
        .await
        .unwrap();
    gov.refresh_async().await.unwrap();

    let adopted = mint_provisioned_self_key(
        gov.clone(),
        crate::governance::SelfMintOp::Issue,
        crate::governance::UnattributedBinding::Adopt,
        &alice,
        "partner",
        None,
        mint_now.saturating_add(ttl.as_secs()),
        mint_now,
    )
    .await
    .expect("the first provider to log in adopts the legacy binding");
    assert_eq!(adopted.key_id, issued.key_id, "the same key, not a new one");
    let adopted_row = row(&gov, &issued.key_id).await;
    assert_eq!(
        adopted_row.idp_provider.as_deref(),
        Some("partner"),
        "the adoption is recorded on the row"
    );
    assert!(
        adopted_row.labels.is_empty(),
        "the adoption writes no label (1.5.5's empty labels stand)"
    );
    assert_eq!(
        mint_provisioned_self_key(
            gov.clone(),
            crate::governance::SelfMintOp::Issue,
            crate::governance::UnattributedBinding::Adopt,
            &alice,
            "corp",
            None,
            mint_now.saturating_add(ttl.as_secs()),
            mint_now
        )
        .await
        .unwrap_err(),
        ExchangeError::Held(SelfMintRefusal::OtherProvider),
        "after the adoption, any other provider is refused"
    );
}

#[tokio::test]
async fn issued_key_debug_never_leaks_the_live_token() {
    let rb = bindings("test-idp-double", "eng", Some("team"));
    let v = identified("test-idp-double", principal("sam", &["eng"]));
    let (p, _team, _pools) = resolve_exchange(&v, &rb, None).unwrap();
    let now = busbar_kernel::store::now();
    let issued = mint_provisioned_self_key(
        gov().await,
        crate::governance::SelfMintOp::Issue,
        crate::governance::UnattributedBinding::Adopt,
        p,
        "corp",
        None,
        now.saturating_add(60),
        now,
    )
    .await
    .expect("the actual Store mints the credential whose Debug is inspected");
    let token = issued.secret.expose(&crate::seal::lend()).clone();
    let dbg = format!("{issued:?}");
    assert!(
        !dbg.contains(&token),
        "the live token must NOT appear in a derived Debug of IssuedKey: {dbg}"
    );
    assert!(
        dbg.contains("[REDACTED]"),
        "the secret field must render redacted: {dbg}"
    );

    assert!(
        dbg.contains(&issued.key_id),
        "key_id (safe id) still shows: {dbg}"
    );
}

// ---- selfmint: a self-serve login must not undo an admin decision or cross IdPs ----
// Every case below runs on the default configuration (no `hold_self_mint_state`).

use super::super::self_keys::{self_mint_modules_of, self_mint_refused_resource, IssuedKey};
use crate::governance::SelfMintOp::{Issue, Refresh};
use crate::governance::UnattributedBinding::{Adopt, Refuse};

async fn mint(
    gov: &Arc<GovState>,
    op: crate::governance::SelfMintOp,
    unattributed: UnattributedBinding,
    sub: &str,
    provider: &str,
) -> Result<IssuedKey, ExchangeError> {
    let now = busbar_kernel::store::now();
    mint_provisioned_self_key(
        gov.clone(),
        op,
        unattributed,
        &principal(sub, &["eng"]),
        provider,
        None,
        now.saturating_add(3600),
        now,
    )
    .await
}

/// Audit records `self_mint.refused` for this subject, provider and reason.
async fn refusals(sub: &str, provider: &str, reason: SelfMintRefusal) -> usize {
    crate::audit::auditlog::flush_pending()
        .await
        .expect("the refusal audit is confirmed");
    crate::audit::auditlog::AUDIT_LOG
        .list_filtered(
            0,
            usize::MAX,
            Some("self_mint.refused"),
            Some(&self_mint_refused_resource(sub, provider, reason)),
        )
        .len()
}

/// A row in the real 1.5.5 shape: derived id, `binding_marker(id, epoch)`, group `user:<sub>`, and no
/// `idp_provider` / `idp_subject` / `binding_mode`.
fn legacy_row(sub: &str, epoch: u64) -> VirtualKey {
    let id = GovState::derive_self_subject(&SEED, sub, epoch);
    VirtualKey {
        generation_hash: crate::governance::binding_marker(&id, &epoch.to_string()),
        name: format!("self-serve key ({sub})"),
        enabled: true,
        group: Some(format!("user:{sub}")),
        id,
        ..Default::default()
    }
}

async fn seed(gov: &GovState, key: &VirtualKey) {
    gov.core_store()
        .unwrap()
        .identity()
        .put_key(key)
        .await
        .unwrap();
    gov.refresh_async().await.unwrap();
}

async fn tombstone(gov: &GovState, key: &VirtualKey) {
    seed(gov, key).await;
    gov.core_store()
        .unwrap()
        .identity()
        .delete_key(&key.id)
        .await
        .unwrap();
    gov.refresh_async().await.unwrap();
}

async fn live_self_rows(gov: &GovState, sub: &str) -> Vec<VirtualKey> {
    all_self_rows(gov, sub)
        .await
        .into_iter()
        .filter(|k| k.enabled)
        .collect()
}

async fn regroup(gov: &GovState, id: &str, group: &str) {
    gov.update_key_outcome_async(id, None, Some(Some(group.to_string())))
        .await
        .unwrap()
        .expect("the key exists");
}

// T5 kernel half / T1 audit. Red on b345530502: the probe reuses the disabled row and Ok is returned.
#[tokio::test]
async fn a_disable_refusal_is_audited_with_subject_provider_and_reason() {
    crate::audit::auditlog::ensure_global_audit_stream_registered().await;
    let gov = gov().await;
    let sub = "oidc:audit-disabled";
    let first = mint(&gov, Issue, Adopt, sub, "corp").await.unwrap();
    gov.update_key_outcome_async(&first.key_id, Some(false), None)
        .await
        .unwrap();
    assert_eq!(
        mint(&gov, Issue, Adopt, sub, "corp").await.unwrap_err(),
        ExchangeError::SelfMintRefused(SelfMintRefusal::Disabled)
    );
    assert_eq!(
        refusals(sub, "corp", SelfMintRefusal::Disabled).await,
        1,
        "one audit record per refused login"
    );
}

// T6 kernel half. Red on b345530502: partner is handed corp's key.
#[tokio::test]
async fn an_other_provider_refusal_is_audited() {
    crate::audit::auditlog::ensure_global_audit_stream_registered().await;
    let gov = gov().await;
    let sub = "oidc:audit-other";
    mint(&gov, Issue, Adopt, sub, "corp").await.unwrap();
    assert_eq!(
        mint(&gov, Issue, Adopt, sub, "other").await.unwrap_err(),
        ExchangeError::SelfMintRefused(SelfMintRefusal::OtherProvider)
    );
    assert_eq!(
        refusals(sub, "other", SelfMintRefusal::OtherProvider).await,
        1
    );
}

// T7 kernel twin. Red on b345530502: the regrouped row is not the cached/current binding (both are
// group-only, self_serve.rs:11-34), so the login falls into `write_self_binding`, which reuses epoch 0
// and writes `group: user:<sub>` back: the body group is `user:<sub>`.
#[tokio::test]
async fn a_login_after_an_admin_regroup_keeps_the_key_in_the_admins_group() {
    let gov = gov().await;
    let sub = "oidc:regroup-t7";
    let first = mint(&gov, Issue, Adopt, sub, "corp").await.unwrap();
    regroup(&gov, &first.key_id, "contractors").await;

    let again = mint(&gov, Issue, Adopt, sub, "corp")
        .await
        .expect("a login after a regroup issues");
    assert_eq!(again.key_id, first.key_id, "the same key, not a second one");
    assert_eq!(again.group, "contractors", "in the admin's group");
    let live = live_self_rows(&gov, sub).await;
    assert_eq!(live.len(), 1, "one live key: {live:?}");
    assert_eq!(live[0].group.as_deref(), Some("contractors"));

    let rotated = mint(&gov, Refresh, Adopt, sub, "corp")
        .await
        .expect("refresh rotates");
    assert_ne!(rotated.key_id, first.key_id);
    assert_eq!(
        rotated.group, "contractors",
        "the rotation stays in the group"
    );
    assert!(row(&gov, &first.key_id).await.deleted_at.is_some());
    let live = live_self_rows(&gov, sub).await;
    assert_eq!(live.len(), 1, "one live key after refresh: {live:?}");
    assert_eq!(live[0].id, rotated.key_id);
}

// T10 kernel twin (C1). Red on b345530502: the probe reuses the revoked row at epoch 0 and
// `compare_self_key` refuses "self binding is revoked" (identity.rs:677-682): a MintFailed store
// error, never a Revoked refusal, and no audit record.
#[tokio::test]
async fn a_login_after_an_admin_revoke_is_refused_as_revoked_even_on_a_stale_node() {
    crate::audit::auditlog::ensure_global_audit_stream_registered().await;
    let gov = gov().await;
    let sub = "oidc:revoke-t10";
    let first = mint(&gov, Issue, Adopt, sub, "corp").await.unwrap();
    gov.revoke_async(&first.key_id, "admin revoke")
        .await
        .unwrap();
    for op in [Issue, Refresh] {
        assert_eq!(
            mint(&gov, op, Adopt, sub, "corp").await.unwrap_err(),
            ExchangeError::SelfMintRefused(SelfMintRefusal::Revoked),
            "{op:?}: revoked, not disabled"
        );
    }
    assert_eq!(refusals(sub, "corp", SelfMintRefusal::Revoked).await, 2);

    gov.forget_denylisted_in_memory(&first.key_id);
    assert_eq!(
        mint(&gov, Issue, Adopt, sub, "corp").await.unwrap_err(),
        ExchangeError::SelfMintRefused(SelfMintRefusal::Revoked),
        "the store read keeps a node with a stale denylist truthful"
    );
    assert_eq!(all_self_rows(&gov, sub).await.len(), 1);
}

// T10 legacy (E2), epoch 0. Red on b345530502: see the case above (probe reuse at epoch 0, generic
// "self binding is revoked" store error, no audit).
#[tokio::test]
async fn a_revoked_1_5_5_row_is_refused_as_revoked() {
    crate::audit::auditlog::ensure_global_audit_stream_registered().await;
    let gov = gov().await;
    let sub = "oidc:revoke-legacy-0";
    let legacy = legacy_row(sub, 0);
    seed(&gov, &legacy).await;
    gov.revoke_async(&legacy.id, "admin revoke").await.unwrap();
    for op in [Issue, Refresh] {
        assert_eq!(
            mint(&gov, op, Adopt, sub, "corp").await.unwrap_err(),
            ExchangeError::SelfMintRefused(SelfMintRefusal::Revoked),
            "{op:?}"
        );
    }
    assert_eq!(refusals(sub, "corp", SelfMintRefusal::Revoked).await, 2);
    let rows = all_self_rows(&gov, sub).await;
    assert_eq!(rows.len(), 1, "only the revoked row: {rows:?}");
    assert_eq!(rows[0].id, legacy.id);
}

// T10 legacy (E2), epoch 5 behind tombstones 0..=4, moved to `contractors`. Red on b345530502: the
// moved row is not in `self_keys`, the probe walks 0, 1, 2, 4 (tombstones) and mints at epoch 8.
#[tokio::test]
async fn a_revoked_and_moved_1_5_5_row_is_matched_by_the_window_and_refused() {
    let gov = gov().await;
    let sub = "oidc:revoke-legacy-5";
    for epoch in 0..5 {
        tombstone(&gov, &legacy_row(sub, epoch)).await;
    }
    let mut legacy = legacy_row(sub, 5);
    legacy.group = Some("contractors".into());
    seed(&gov, &legacy).await;
    gov.revoke_async(&legacy.id, "admin revoke").await.unwrap();
    for op in [Issue, Refresh] {
        assert_eq!(
            mint(&gov, op, Adopt, sub, "corp").await.unwrap_err(),
            ExchangeError::SelfMintRefused(SelfMintRefusal::Revoked),
            "{op:?}"
        );
    }
    let rows = all_self_rows(&gov, sub).await;
    assert_eq!(rows.len(), 1, "no fresh key past the revoked one: {rows:?}");
}

// T11 kernel (C3). Red on b345530502: `cached_self_binding(alice)` finds bob's row in `user:alice`
// (group-only lookup, self_serve.rs:23-34) and alice's login is handed bob's key.
#[tokio::test]
async fn another_subjects_key_in_my_self_group_is_refused_and_left_alone() {
    crate::audit::auditlog::ensure_global_audit_stream_registered().await;
    let gov = gov().await;
    let alice = "oidc:t11-alice";
    let bob = "oidc:t11-bob";
    let bobs = mint(&gov, Issue, Adopt, bob, "corp").await.unwrap();
    regroup(&gov, &bobs.key_id, &format!("user:{alice}")).await;
    let before = row(&gov, &bobs.key_id).await;

    assert_eq!(
        mint(&gov, Issue, Adopt, alice, "corp").await.unwrap_err(),
        ExchangeError::SelfMintRefused(SelfMintRefusal::ForeignKeyInGroup)
    );
    assert_eq!(
        refusals(alice, "corp", SelfMintRefusal::ForeignKeyInGroup).await,
        1
    );
    assert_eq!(
        row(&gov, &bobs.key_id).await,
        before,
        "bob's row is untouched"
    );

    let again = mint(&gov, Issue, Adopt, bob, "corp")
        .await
        .expect("bob still logs in");
    assert_eq!(again.key_id, bobs.key_id);
    assert_eq!(
        again.group,
        format!("user:{alice}"),
        "the admin's regroup stands"
    );
}

// T11 further cases (D1): an admin-minted time-bound key, a plain admin key, and a legacy-shaped
// key with a random id, each live in `user:<alice>`. Red on b345530502: alice's login takes it over.
#[tokio::test]
async fn an_admin_or_unverifiable_key_in_my_self_group_is_refused() {
    let gov = gov().await;
    let now = busbar_kernel::store::now();
    for (n, mode) in [Some("time-bound"), None].into_iter().enumerate() {
        let alice = format!("oidc:t11-admin-{n}");
        let (key, _) = gov
            .mint_signed_async(
                crate::governance::NewKeySpec {
                    group: Some(format!("user:{alice}")),
                    binding_mode: mode.map(str::to_string),
                    ..Default::default()
                },
                now + 3600,
                now,
            )
            .await
            .unwrap();
        let before = row(&gov, &key.id).await;
        assert_eq!(
            mint(&gov, Issue, Adopt, &alice, "corp").await.unwrap_err(),
            ExchangeError::SelfMintRefused(SelfMintRefusal::ForeignKeyInGroup),
            "{mode:?}"
        );
        assert_eq!(row(&gov, &key.id).await, before, "{mode:?}: untouched");
    }
    let alice = "oidc:t11-legacy-foreign";
    let foreign = VirtualKey {
        id: "vk_00112233445566778899aabbccddeeff".into(),
        generation_hash: crate::governance::binding_marker(
            "vk_00112233445566778899aabbccddeeff",
            "random-generation",
        ),
        enabled: true,
        group: Some(format!("user:{alice}")),
        ..Default::default()
    };
    seed(&gov, &foreign).await;
    let before = row(&gov, &foreign.id).await;
    assert_eq!(
        mint(&gov, Issue, Adopt, alice, "corp").await.unwrap_err(),
        ExchangeError::SelfMintRefused(SelfMintRefusal::ForeignKeyInGroup)
    );
    assert_eq!(row(&gov, &foreign.id).await, before);
}

// T11 bob-side legacy (E1). Red on b345530502: bob's login does not see his moved 1.5.5 row (it is in
// `user:<alice>` with no `idp_subject`) and mints a second key.
#[tokio::test]
async fn a_moved_1_5_5_row_stays_its_owners_binding() {
    let gov = gov().await;
    let alice = "oidc:e1-alice";
    let bob = "oidc:e1-bob";
    let mut legacy = legacy_row(bob, 0);
    legacy.group = Some(format!("user:{alice}"));
    seed(&gov, &legacy).await;

    assert_eq!(
        mint(&gov, Issue, Adopt, alice, "corp").await.unwrap_err(),
        ExchangeError::SelfMintRefused(SelfMintRefusal::ForeignKeyInGroup)
    );
    let issued = mint(&gov, Issue, Adopt, bob, "corp").await.unwrap();
    assert_eq!(issued.key_id, legacy.id, "bob's own row is his binding");
    let rotated = mint(&gov, Refresh, Adopt, bob, "corp").await.unwrap();
    assert_eq!(rotated.group, format!("user:{alice}"));
    let live = live_self_rows(&gov, bob).await;
    assert_eq!(live.len(), 1, "bob holds one live self key: {live:?}");
    assert_eq!(live[0].id, rotated.key_id);
}

// T14 / T8 (D1, D2). Red on b345530502: adoption stamps only `idp_provider` (self_serve.rs:317-321);
// with more than one mint-capable module nothing refuses the unattributed row.
#[tokio::test]
async fn a_1_5_5_row_is_adopted_only_by_the_one_mint_capable_module() {
    let gov = gov().await;
    let sub = "oidc:t14-adopt";
    let legacy = legacy_row(sub, 0);
    seed(&gov, &legacy).await;
    let issued = mint(&gov, Issue, Adopt, sub, "corp").await.unwrap();
    assert_eq!(issued.key_id, legacy.id);
    let adopted = row(&gov, &legacy.id).await;
    assert_eq!(adopted.idp_provider.as_deref(), Some("corp"));
    assert_eq!(adopted.idp_subject.as_deref(), Some(sub));
    assert_eq!(adopted.binding_mode.as_deref(), Some("user-bound"));
    assert_eq!(
        adopted.group, legacy.group,
        "adoption never writes the group"
    );

    let sub = "oidc:t14-refuse";
    let legacy = legacy_row(sub, 0);
    seed(&gov, &legacy).await;
    let before = row(&gov, &legacy.id).await;
    for op in [Issue, Refresh] {
        assert_eq!(
            mint(&gov, op, Refuse, sub, "second").await.unwrap_err(),
            ExchangeError::SelfMintRefused(SelfMintRefusal::Unattributed),
            "{op:?}"
        );
    }
    assert_eq!(row(&gov, &legacy.id).await, before, "the row is unchanged");
}

// T14 moved-disabled. Red on b345530502: the moved row is not in `self_keys`, the probe reuses epoch
// 0 and `write_self_binding` aborts with "self binding changed; retry the request": no Disabled
// refusal, no audit.
#[tokio::test]
async fn a_disabled_1_5_5_row_moved_to_another_group_is_refused_as_disabled() {
    crate::audit::auditlog::ensure_global_audit_stream_registered().await;
    let gov = gov().await;
    let sub = "oidc:t14-moved-disabled";
    let mut legacy = legacy_row(sub, 0);
    legacy.enabled = false;
    legacy.group = Some("contractors".into());
    seed(&gov, &legacy).await;
    for op in [Issue, Refresh] {
        assert_eq!(
            mint(&gov, op, Adopt, sub, "corp").await.unwrap_err(),
            ExchangeError::SelfMintRefused(SelfMintRefusal::Disabled),
            "{op:?}"
        );
    }
    assert_eq!(refusals(sub, "corp", SelfMintRefusal::Disabled).await, 2);
    assert_eq!(all_self_rows(&gov, sub).await.len(), 1, "no new self row");
}

// T14 moved-live. Red on b345530502: neither door sees the moved row; the probe reuses epoch 0 and
// both fail with "self binding changed; retry the request".
#[tokio::test]
async fn a_live_1_5_5_row_moved_to_another_group_is_bound_and_rotated_there() {
    let gov = gov().await;
    let sub = "oidc:t14-moved-live";
    let mut legacy = legacy_row(sub, 0);
    legacy.group = Some("contractors".into());
    seed(&gov, &legacy).await;
    let issued = mint(&gov, Issue, Adopt, sub, "corp").await.unwrap();
    assert_eq!(issued.key_id, legacy.id);
    assert_eq!(issued.group, "contractors");
    let rotated = mint(&gov, Refresh, Adopt, sub, "corp").await.unwrap();
    assert_eq!(rotated.group, "contractors");
    assert!(row(&gov, &legacy.id).await.deleted_at.is_some());
    let live = live_self_rows(&gov, sub).await;
    assert_eq!(live.len(), 1, "{live:?}");
    assert_eq!(live[0].id, rotated.key_id);
}

// T14 rotated by the admin (random generation), live in `user:<sub>`: owned through the window. A
// guard: green before and after.
#[tokio::test]
async fn an_admin_rotated_1_5_5_row_is_still_the_binding() {
    let gov = gov().await;
    let sub = "oidc:t14-rotated";
    let mut legacy = legacy_row(sub, 0);
    legacy.generation_hash = crate::governance::binding_marker(&legacy.id, "c0ffee-random");
    seed(&gov, &legacy).await;
    let issued = mint(&gov, Issue, Adopt, sub, "corp").await.unwrap();
    assert_eq!(issued.key_id, legacy.id);
    assert_eq!(live_self_rows(&gov, sub).await.len(), 1);
}

// T14 unverifiable legacy row in `user:<sub>`. Red on b345530502: it is taken over.
#[tokio::test]
async fn a_legacy_shaped_random_id_in_my_self_group_is_refused_and_audited() {
    crate::audit::auditlog::ensure_global_audit_stream_registered().await;
    let gov = gov().await;
    let sub = "oidc:t14-random";
    let foreign = VirtualKey {
        id: "vk_ffeeddccbbaa99887766554433221100".into(),
        generation_hash: crate::governance::binding_marker(
            "vk_ffeeddccbbaa99887766554433221100",
            "0",
        ),
        enabled: true,
        group: Some(format!("user:{sub}")),
        ..Default::default()
    };
    seed(&gov, &foreign).await;
    let before = row(&gov, &foreign.id).await;
    assert_eq!(
        mint(&gov, Issue, Adopt, sub, "corp").await.unwrap_err(),
        ExchangeError::SelfMintRefused(SelfMintRefusal::ForeignKeyInGroup)
    );
    assert_eq!(
        refusals(sub, "corp", SelfMintRefusal::ForeignKeyInGroup).await,
        1
    );
    assert_eq!(row(&gov, &foreign.id).await, before);
}

// T12 (C5). Only a door with a group-granting role binding counts; `keys` never does.
#[test]
fn only_modules_that_can_reach_a_self_mint_count_toward_adoption() {
    let mut rb = bindings("corp", "eng", Some("team"));
    rb.extend(bindings("admin-oidc", "admins", None));
    assert_eq!(
        self_mint_modules_of(["corp", "admin-oidc", "keys"], &rb),
        std::collections::BTreeSet::from(["corp".to_string()]),
        "an admin-only module (no group binding) is not a second IdP"
    );
    rb.extend(bindings("admin-oidc", "admins", Some("ops")));
    assert_eq!(
        self_mint_modules_of(["corp", "admin-oidc"], &rb).len(),
        2,
        "an admin module that grants a group can mint, so adoption refuses"
    );
    rb.extend(bindings("keys", "eng", Some("team")));
    assert!(!self_mint_modules_of(["keys"], &rb).contains("keys"));
}
