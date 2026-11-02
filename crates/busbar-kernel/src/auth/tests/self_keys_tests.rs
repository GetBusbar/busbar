// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use super::super::self_keys::{
    admit_self_mint, issue_key, mint_provisioned_self_key, resolve_exchange,
    DeterministicEd25519Keys, ExchangeError,
};
use super::super::{ChainVerdict, Principal};
use crate::config::groups::GroupCfg;
use crate::config::{RoleBindingCfg, RoleBindings};
use crate::governance::{GovState, RecordStore as _};

const SEED: [u8; 32] = [7u8; 32];

fn gov() -> Arc<GovState> {
    Arc::new(
        GovState::new_with_signer(
            crate::real_store::store(),
            None,
            Some(crate::governance::signing::TokenSigner::from_secret_bytes(
                &SEED,
                crate::governance::signing::DEFAULT_KID,
            )),
        )
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

fn self_rows(gov: &GovState, sub: &str) -> Vec<crate::governance::VirtualKey> {
    let group = format!("user:{sub}");
    gov.all_keys()
        .unwrap()
        .into_iter()
        .filter(|k| k.enabled && k.deleted_at.is_none() && k.group.as_deref() == Some(&group))
        .collect()
}

#[test]
fn first_call_provisions_second_call_reuses_one_row() {
    let gov = gov();
    let (b1, t1) = gov.issue_self("sam", "corp", None, 5000, 1000).unwrap();
    let (b2, t2) = gov.issue_self("sam", "corp", None, 6000, 2000).unwrap();

    assert_eq!(
        b1.id, b2.id,
        "deterministic id: re-login reuses the same subject"
    );
    assert_eq!(
        self_rows(&gov, "sam").len(),
        1,
        "exactly one binding row after two logins"
    );

    assert!(gov.verify_token(&t1, 1000, None).is_some());
    assert!(gov.verify_token(&t2, 2000, None).is_some());
}

#[test]
fn cap_not_tripped_n_logins_one_row() {
    let gov = gov();
    for i in 0..25u64 {
        gov.issue_self("sam", "corp", None, 100_000, 1000 + i)
            .unwrap();
    }
    assert_eq!(
        self_rows(&gov, "sam").len(),
        1,
        "N logins must never sprawl past the one idempotent binding row"
    );
}

#[test]
fn refresh_invalidates_old_token() {
    let gov = gov();
    let (_b, old) = gov.issue_self("sam", "corp", None, 100_000, 1000).unwrap();
    assert!(
        gov.verify_token(&old, 1000, None).is_some(),
        "old token valid before refresh"
    );

    let (_b2, fresh) = gov
        .refresh_self("sam", "corp", None, 100_000, 2000)
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
        self_rows(&gov, "sam").len(),
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

    let forged_sig = ring::hmac::sign(
        &ring::hmac::Key::new(ring::hmac::HMAC_SHA512, &SEED),
        b"user:vk_deadbeef#0",
    );
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

#[test]
fn issued_token_verifies_through_the_unchanged_path() {
    let gov = gov();
    let (binding, token) = gov.issue_self("sam", "corp", None, 5000, 1000).unwrap();
    let resolved = gov
        .verify_token(&token, 1000, None)
        .expect("standard token verifies");
    assert_eq!(resolved.id, binding.id);
    assert_eq!(resolved.group.as_deref(), Some("user:sam"));
}

#[test]
fn re_login_updates_allowed_pools_when_they_change() {
    use busbar_contract::records::ScopeRef;
    let gov = gov();
    let (b1, _t1) = gov
        .issue_self("sam", "corp", Some(vec!["poolA".into()]), 5000, 1000)
        .unwrap();
    assert_eq!(b1.allowed_scopes, Some(vec![ScopeRef::pool("poolA")]));

    let (b2, _t2) = gov
        .issue_self("sam", "corp", Some(vec!["poolB".into()]), 6000, 2000)
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

#[test]
fn concurrent_issue_self_yields_one_binding() {
    let gov = gov();
    let mut handles = vec![];
    for i in 0..8u64 {
        let g = gov.clone();
        handles.push(std::thread::spawn(move || {
            g.issue_self("sam", "corp", Some(vec!["p".into()]), 5000, 1000 + i)
                .unwrap();
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(
        self_rows(&gov, "sam").len(),
        1,
        "concurrent self-logins for one sub must leave exactly one binding"
    );
}

struct RefreshOverlapStore {
    inner: std::sync::Arc<busbar_plugin_loader::store_v3::LoadedStore>,
    next_put: std::sync::Mutex<
        Option<(
            tokio::sync::oneshot::Sender<()>,
            std::sync::mpsc::Receiver<()>,
        )>,
    >,
}

impl crate::governance::RecordStore for RefreshOverlapStore {
    fn put_key(
        &self,
        key: &crate::governance::VirtualKey,
    ) -> crate::governance::RecordStoreResult<()> {
        let pause = self.next_put.lock().unwrap().take();
        if let Some((entered, release)) = pause {
            let _ = entered.send(());
            release.recv_timeout(Duration::from_secs(10)).map_err(|_| {
                crate::governance::RecordStoreError("test write was not released".into())
            })?;
        }
        self.inner.put_key(key)
    }

    fn get_key(
        &self,
        id: &str,
    ) -> crate::governance::RecordStoreResult<Option<crate::governance::VirtualKey>> {
        self.inner.get_key(id)
    }

    fn list_keys(
        &self,
    ) -> crate::governance::RecordStoreResult<Vec<crate::governance::VirtualKey>> {
        self.inner.list_keys()
    }

    fn delete_key(&self, id: &str) -> crate::governance::RecordStoreResult<()> {
        self.inner.delete_key(id)
    }

    fn get_usage(
        &self,
        id: &str,
        window: u64,
    ) -> crate::governance::RecordStoreResult<crate::governance::UsageLedger> {
        self.inner.get_usage(id, window)
    }

    fn put_usage(
        &self,
        id: &str,
        window: u64,
        ledger: &crate::governance::UsageLedger,
    ) -> crate::governance::RecordStoreResult<()> {
        self.inner.put_usage(id, window, ledger)
    }

    fn add_metering(
        &self,
        delta: &crate::governance::MeteringDelta,
    ) -> crate::governance::RecordStoreResult<()> {
        self.inner.add_metering(delta)
    }

    fn list_metering(
        &self,
        bucket: u64,
    ) -> crate::governance::RecordStoreResult<Vec<crate::governance::MeteringRow>> {
        self.inner.list_metering(bucket)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_login_or_refresh_overlapping_refresh_uses_the_surviving_binding() {
    use crate::auth::login::{issue_self_key, SelfKeyIssue};

    fn issued(answer: SelfKeyIssue) -> busbar_contract::redacted::Secret<String> {
        match answer {
            SelfKeyIssue::Issued { secret, .. } => secret,
            other => panic!("the admitted identity must receive a key: {other:?}"),
        }
    }

    for contender_refresh in [false, true] {
        let store = Arc::new(RefreshOverlapStore {
            inner: crate::real_store::store(),
            next_put: std::sync::Mutex::new(None),
        });
        let gov = Arc::new(
            GovState::new_with_signer(
                store.clone(),
                None,
                Some(crate::governance::signing::TokenSigner::from_secret_bytes(
                    &SEED,
                    crate::governance::signing::DEFAULT_KID,
                )),
            )
            .unwrap(),
        );
        let groups = serde_yaml::from_str(
            "team: {}\nuser:sam: {parent: team}\nuser:other: {parent: team}\n",
        )
        .unwrap();
        let app = crate::test_support::TestApp::new()
            .governance(gov.clone())
            .groups_tree(groups)
            .role_bindings(bindings("corp", "eng", Some("team")))
            .build();
        let handle = Arc::new(crate::state::AppHandle::new(app));
        let app = handle.snapshot();
        let original =
            issued(issue_self_key(&app, &handle, "corp", principal("sam", &["eng"]), false).await);
        let now = busbar_kernel::store::now();
        let original_id = gov
            .verify_token(original.expose(&crate::seal::lend()), now, None)
            .expect("the initial token verifies")
            .id
            .clone();

        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        *store.next_put.lock().unwrap() = Some((entered_tx, release_rx));
        let first_handle = handle.clone();
        let first = tokio::spawn(async move {
            let app = first_handle.snapshot();
            issue_self_key(
                &app,
                &first_handle,
                "corp",
                principal("sam", &["eng"]),
                true,
            )
            .await
        });
        if !matches!(
            tokio::time::timeout(Duration::from_secs(5), entered_rx).await,
            Ok(Ok(()))
        ) {
            let _ = release_tx.send(());
            let _ = first.await;
            panic!("refresh did not reach the real store write");
        }

        let waiting = gov.observe_self_mint_wait("sam");
        let next_handle = handle.clone();
        let contender = tokio::spawn(async move {
            let app = next_handle.snapshot();
            issue_self_key(
                &app,
                &next_handle,
                "corp",
                principal("sam", &["eng"]),
                contender_refresh,
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

        let other_handle = handle.clone();
        let mut other = tokio::spawn(async move {
            let app = other_handle.snapshot();
            issue_self_key(
                &app,
                &other_handle,
                "corp",
                principal("other", &["eng"]),
                false,
            )
            .await
        });
        let other_progress = tokio::time::timeout(Duration::from_secs(2), &mut other).await;
        let other_completed_while_parked = other_progress.is_ok();
        let completed_while_parked = contender.is_finished();

        let _ = release_tx.send(());
        let first = first.await;
        let contender = contender.await;
        let other = match other_progress {
            Ok(answer) => answer,
            Err(_) => other.await,
        };
        assert!(contended, "the overlapping caller must reach the subject's contended wait while refresh is parked");
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
        let live = self_rows(&gov, "sam");
        assert_eq!(live.len(), 1, "overlap leaves one live self binding");
        assert_eq!(live[0].id, surviving.id);
        let old = store.get_key(&original_id).unwrap().unwrap();
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
    let gov = gov();
    // Internal post-provisioning mint continuation over the actual Store. Actual group
    // transaction/provisioning is outside this continuation; no no-op provisioner stands in here.
    let mint_now = busbar_kernel::store::now();
    let rb = bindings("test-idp-double", "eng", Some("team"));
    let v = identified("test-idp-double", principal("sam", &["eng"]));
    let (p, team, pools) = resolve_exchange(&v, &rb, None).unwrap();
    assert_eq!(team, "team");
    let issued = mint_provisioned_self_key(
        gov.clone(),
        crate::governance::SelfMintOp::Issue,
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
    let gov = gov();
    // Internal post-provisioning mint continuation over the actual Store. Actual group
    // transaction/provisioning is outside this continuation; no no-op provisioner stands in here.
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

fn row(gov: &GovState, id: &str) -> crate::governance::VirtualKey {
    gov.store().get_key(id).unwrap().expect("the row exists")
}

#[tokio::test]
async fn an_admin_disable_of_a_self_serve_key_holds_across_the_next_login() {
    let gov = gov();
    // Internal post-provisioning mint continuation over the actual Store. Actual group
    // transaction/provisioning is outside this continuation; no no-op provisioner stands in here.
    let mint_now = busbar_kernel::store::now();

    gov.hold_self_mint_state();
    let alice = principal("oidc:alice", &["eng"]);
    let ttl = Duration::from_secs(3600);

    let t0 = mint_provisioned_self_key(
        gov.clone(),
        crate::governance::SelfMintOp::Issue,
        &alice,
        "corp",
        None,
        mint_now.saturating_add(ttl.as_secs()),
        mint_now,
    )
    .await
    .expect("first login issues");
    let now = busbar_kernel::store::now();
    assert!(gov
        .verify_token(t0.secret.expose(&crate::seal::lend()), now, None)
        .is_some());

    gov.update_key(&t0.key_id, Some(false), None)
        .unwrap()
        .expect("the key exists");

    assert_eq!(
        mint_provisioned_self_key(
            gov.clone(),
            crate::governance::SelfMintOp::Issue,
            &alice,
            "corp",
            None,
            mint_now.saturating_add(ttl.as_secs()),
            mint_now
        )
        .await
        .unwrap_err(),
        ExchangeError::Unbound,
        "a login while the key is disabled is refused, not re-enabled"
    );
    assert_eq!(
        mint_provisioned_self_key(
            gov.clone(),
            crate::governance::SelfMintOp::Refresh,
            &alice,
            "corp",
            None,
            mint_now.saturating_add(ttl.as_secs()),
            mint_now
        )
        .await
        .unwrap_err(),
        ExchangeError::Unbound,
        "a refresh while the key is disabled is refused too"
    );
    assert!(
        !row(&gov, &t0.key_id).enabled,
        "the admin's disable still stands"
    );
    assert!(
        gov.verify_token(t0.secret.expose(&crate::seal::lend()), now, None)
            .is_none(),
        "the pre-disable token must NOT come back to life"
    );
    assert!(
        self_rows(&gov, "oidc:alice").is_empty(),
        "no fresh key was minted beside the disabled one"
    );
}

#[tokio::test]
async fn a_login_after_an_admin_disable_mints_as_1_5_5_minted() {
    let gov = gov();
    // Internal post-provisioning mint continuation over the actual Store. Actual group
    // transaction/provisioning is outside this continuation; no no-op provisioner stands in here.
    let mint_now = busbar_kernel::store::now();
    let alice = principal("oidc:alice", &["eng"]);
    let ttl = Duration::from_secs(3600);

    let t0 = mint_provisioned_self_key(
        gov.clone(),
        crate::governance::SelfMintOp::Issue,
        &alice,
        "corp",
        None,
        mint_now.saturating_add(ttl.as_secs()),
        mint_now,
    )
    .await
    .expect("first login issues");
    gov.update_key(&t0.key_id, Some(false), None)
        .unwrap()
        .expect("the key exists");

    let again = mint_provisioned_self_key(
        gov.clone(),
        crate::governance::SelfMintOp::Issue,
        &alice,
        "corp",
        None,
        mint_now.saturating_add(ttl.as_secs()),
        mint_now,
    )
    .await
    .expect("1.5.5 minted a key on the next login");
    assert_eq!(again.key_id, t0.key_id, "1.5.5 wrote the derived row back");
    assert!(row(&gov, &t0.key_id).enabled, "and wrote it enabled");
    mint_provisioned_self_key(
        gov.clone(),
        crate::governance::SelfMintOp::Refresh,
        &alice,
        "corp",
        None,
        mint_now.saturating_add(ttl.as_secs()),
        mint_now,
    )
    .await
    .expect("1.5.5 minted on a refresh too");
}

#[tokio::test]
async fn a_second_provider_asserting_the_same_subject_is_handed_its_key_as_1_5_5_did() {
    let gov = gov();
    // Internal post-provisioning mint continuation over the actual Store. Actual group
    // transaction/provisioning is outside this continuation; no no-op provisioner stands in here.
    let mint_now = busbar_kernel::store::now();
    let alice = principal("oidc:alice", &["eng"]);
    let ttl = Duration::from_secs(3600);

    let corp = mint_provisioned_self_key(
        gov.clone(),
        crate::governance::SelfMintOp::Issue,
        &alice,
        "corp",
        None,
        mint_now.saturating_add(ttl.as_secs()),
        mint_now,
    )
    .await
    .expect("corp issues");
    let partner = mint_provisioned_self_key(
        gov.clone(),
        crate::governance::SelfMintOp::Issue,
        &alice,
        "partner",
        None,
        mint_now.saturating_add(ttl.as_secs()),
        mint_now,
    )
    .await
    .expect("1.5.5 minted for the second provider");
    assert_eq!(
        partner.key_id, corp.key_id,
        "the subject's one key, as in 1.5.5"
    );
}

#[tokio::test]
async fn a_self_serve_key_carries_empty_labels_as_1_5_5_wrote_it() {
    let gov = gov();
    // Internal post-provisioning mint continuation over the actual Store. Actual group
    // transaction/provisioning is outside this continuation; no no-op provisioner stands in here.
    let mint_now = busbar_kernel::store::now();
    let alice = principal("oidc:alice", &["eng"]);
    let ttl = Duration::from_secs(3600);

    let issued = mint_provisioned_self_key(
        gov.clone(),
        crate::governance::SelfMintOp::Issue,
        &alice,
        "corp",
        None,
        mint_now.saturating_add(ttl.as_secs()),
        mint_now,
    )
    .await
    .expect("issues");
    let first = row(&gov, &issued.key_id);
    assert!(first.labels.is_empty(), "issue: {:?}", first.labels);
    assert_eq!(first.idp_provider.as_deref(), Some("corp"));

    let again = mint_provisioned_self_key(
        gov.clone(),
        crate::governance::SelfMintOp::Issue,
        &alice,
        "corp",
        None,
        mint_now.saturating_add(ttl.as_secs()),
        mint_now,
    )
    .await
    .expect("re-issues");
    assert!(row(&gov, &again.key_id).labels.is_empty(), "re-issue");

    let rotated = mint_provisioned_self_key(
        gov.clone(),
        crate::governance::SelfMintOp::Refresh,
        &alice,
        "corp",
        None,
        mint_now.saturating_add(ttl.as_secs()),
        mint_now,
    )
    .await
    .expect("refreshes");
    let rotated_row = row(&gov, &rotated.key_id);
    assert!(
        rotated_row.labels.is_empty(),
        "refresh: {:?}",
        rotated_row.labels
    );
    assert_eq!(rotated_row.idp_provider.as_deref(), Some("corp"));
}

#[tokio::test]
async fn a_second_provider_asserting_the_same_subject_is_refused() {
    let gov = gov();
    // Internal post-provisioning mint continuation over the actual Store. Actual group
    // transaction/provisioning is outside this continuation; no no-op provisioner stands in here.
    let mint_now = busbar_kernel::store::now();

    gov.hold_self_mint_state();
    let alice = principal("oidc:alice", &["eng"]);
    let ttl = Duration::from_secs(3600);

    let issued = mint_provisioned_self_key(
        gov.clone(),
        crate::governance::SelfMintOp::Issue,
        &alice,
        "corp",
        None,
        mint_now.saturating_add(ttl.as_secs()),
        mint_now,
    )
    .await
    .expect("corp issues");
    let before = row(&gov, &issued.key_id);
    assert_eq!(
        before.idp_provider.as_deref(),
        Some("corp"),
        "the binding records its minting provider"
    );

    assert_eq!(
        mint_provisioned_self_key(
            gov.clone(),
            crate::governance::SelfMintOp::Issue,
            &alice,
            "partner",
            None,
            mint_now.saturating_add(ttl.as_secs()),
            mint_now
        )
        .await
        .unwrap_err(),
        ExchangeError::Unbound,
        "another provider asserting the subject is refused"
    );
    assert_eq!(
        mint_provisioned_self_key(
            gov.clone(),
            crate::governance::SelfMintOp::Refresh,
            &alice,
            "partner",
            None,
            mint_now.saturating_add(ttl.as_secs()),
            mint_now
        )
        .await
        .unwrap_err(),
        ExchangeError::Unbound,
        "and cannot refresh corp's key away"
    );

    let after = row(&gov, &issued.key_id);
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
    let gov = gov();
    // Internal post-provisioning mint continuation over the actual Store. Actual group
    // transaction/provisioning is outside this continuation; no no-op provisioner stands in here.
    let mint_now = busbar_kernel::store::now();

    gov.hold_self_mint_state();
    let alice = principal("oidc:alice", &["eng"]);
    let ttl = Duration::from_secs(3600);

    let issued = mint_provisioned_self_key(
        gov.clone(),
        crate::governance::SelfMintOp::Issue,
        &alice,
        "corp",
        None,
        mint_now.saturating_add(ttl.as_secs()),
        mint_now,
    )
    .await
    .expect("issues");
    let mut legacy = row(&gov, &issued.key_id);
    legacy.idp_provider = None;
    gov.store().put_key(&legacy).unwrap();
    gov.refresh().unwrap();

    let adopted = mint_provisioned_self_key(
        gov.clone(),
        crate::governance::SelfMintOp::Issue,
        &alice,
        "partner",
        None,
        mint_now.saturating_add(ttl.as_secs()),
        mint_now,
    )
    .await
    .expect("the first provider to log in adopts the legacy binding");
    assert_eq!(adopted.key_id, issued.key_id, "the same key, not a new one");
    let adopted_row = row(&gov, &issued.key_id);
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
            &alice,
            "corp",
            None,
            mint_now.saturating_add(ttl.as_secs()),
            mint_now
        )
        .await
        .unwrap_err(),
        ExchangeError::Unbound,
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
        gov(),
        crate::governance::SelfMintOp::Issue,
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

struct ModeReplayIdentity;

struct ModeReplayAnswer(Option<busbar_contract::auth_calls::VerifyAnswer>);

impl std::future::Future for ModeReplayAnswer {
    type Output = busbar_contract::auth_calls::VerifyAnswer;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::task::Poll::Ready(self.0.take().expect("the verify answers once"))
    }
}

impl busbar_contract::auth_calls::Verifying for ModeReplayAnswer {
    fn settled(&mut self) -> Option<busbar_contract::auth_calls::VerifyAnswer> {
        self.0.take()
    }
}

impl busbar_contract::auth_calls::AuthCalls for ModeReplayIdentity {
    fn name(&self) -> &str {
        "mode-replay-idp"
    }

    fn facts(&self) -> u32 {
        0
    }

    fn verify_now(
        &self,
        _: &busbar_contract::auth_calls::VerifyRequest,
    ) -> Option<busbar_contract::auth_calls::VerifyAnswer> {
        use busbar_contract::auth_calls::{Replay, Verified, VerifiedIdentity};
        Some(
            Verified::Identity(VerifiedIdentity {
                subject: "sam".into(),
                groups: vec!["eng".into()],
                replay: Some(Box::new(Replay {
                    key: "self-mode-refused".into(),
                    ttl_secs: 300,
                })),
                ..Default::default()
            })
            .into(),
        )
    }

    fn verify(
        &self,
        request: busbar_contract::auth_calls::VerifyRequest,
    ) -> Box<dyn busbar_contract::auth_calls::Verifying> {
        Box::new(ModeReplayAnswer(self.verify_now(&request)))
    }

    fn refresh(&self) -> Result<u64, String> {
        Ok(0)
    }
}

#[tokio::test]
async fn mode_refused_exchange_leaves_its_verified_identitys_replay_claim_unclaimed() {
    use busbar_contract::store_calls::StoreDoor;

    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let opened = crate::test_support::store_axis_stand_in()
        .open(
            StoreDoor::Linked(crate::test_support::store_double::door),
            crate::test_support::store_double::NAME,
            b"{}",
        )
        .unwrap();
    let gov = Arc::new(
        GovState::new_with_signer(
            opened.records,
            None,
            Some(crate::governance::signing::TokenSigner::from_secret_bytes(
                &SEED,
                crate::governance::signing::DEFAULT_KID,
            )),
        )
        .unwrap(),
    );
    assert!(gov.attach_store_calls(opened.calls.unwrap()));
    let auth = Arc::new(super::super::AuthMiddleware::from_doors_for_test(vec![(
        "mode-replay-idp".into(),
        Arc::new(ModeReplayIdentity),
    )]));
    let app = crate::test_support::TestApp::new()
        .auth(auth)
        .governance(gov.clone())
        .group("team", GroupCfg::default())
        .role_bindings(bindings("mode-replay-idp", "eng", Some("team")))
        .mint_policy(crate::governance::mint_policy::MintPolicy {
            block_binding_modes: Some(vec![crate::governance::SELF_KEY_BINDING_MODE_APP.into()]),
            ..Default::default()
        })
        .build();
    let handle = Arc::new(crate::state::AppHandle::new(app));
    let before = handle.load();
    for _ in 0..2 {
        let response = crate::auth::exchange::exchange(
            axum::extract::State(handle.clone()),
            axum::http::Request::builder()
                .method("POST")
                .uri("/auth/token")
                .header("authorization", "Bearer verified-message")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }
    assert!(Arc::ptr_eq(&before, &handle.load()));
    assert!(gov.all_keys().unwrap().is_empty());
    let claim = busbar_contract::auth_calls::Replay {
        key: "self-mode-refused".into(),
        ttl_secs: 300,
    };
    let now = crate::store::now();
    assert!(
        super::super::replay_claimed(Some(&gov), "mode-replay-idp", &claim, now).await,
        "the refused exchanges leave the verified replay claim available"
    );
    assert!(
        !super::super::replay_claimed(Some(&gov), "mode-replay-idp", &claim, now).await,
        "the attached store really enforces replay claims"
    );
}
