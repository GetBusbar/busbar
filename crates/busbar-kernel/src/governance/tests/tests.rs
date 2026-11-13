static ISSUED_SHAPE: std::sync::LazyLock<busbar_contract::auth_calls::IssuedShape> =
    std::sync::LazyLock::new(|| busbar_contract::auth_calls::IssuedShape {
        id_prefix: "AKIA".to_string(),
        id_len: 20,
        id_alphabet: "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".to_string(),
        secret_len: 40,
        secret_alphabet: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            .to_string(),
    });

#[tokio::test]
async fn synthesize_principal_key_union_semantics() {
    use crate::config::RoleBindingCfg;
    let mut table = std::collections::BTreeMap::new();
    table.insert(
        "a".to_string(),
        RoleBindingCfg {
            allowed_pools: Some(vec!["p1".to_string()]),
            group: Some("finance".to_string()),
            ..Default::default()
        },
    );
    table.insert(
        "b".to_string(),
        RoleBindingCfg {
            allowed_pools: Some(vec!["p2".to_string()]),
            ..Default::default()
        },
    );

    table.insert(
        "admin-only".to_string(),
        RoleBindingCfg {
            allowed_pools: Some(vec![]),
            admin_scope: Some("full".to_string()),
            ..Default::default()
        },
    );

    table.insert("all-pools".to_string(), RoleBindingCfg::default());

    let mut p = crate::auth::Principal::from_id("test:u");
    p.roles = vec!["a".to_string(), "b".to_string()];
    let k = synthesize_principal_key(&p, Some(&table)).expect("bound roles synthesize");
    assert_eq!(k.id, "test:u", "keyed by the principal id");
    let mut pools: Vec<String> = k
        .allowed_scopes
        .clone()
        .expect("an explicit union list")
        .into_iter()
        .map(|s| s.value)
        .collect();
    pools.sort();
    assert_eq!(
        pools,
        vec!["p1".to_string(), "p2".to_string()],
        "pools union"
    );

    assert_eq!(
        k.group.as_deref(),
        Some("finance"),
        "the bound group becomes the key's group"
    );
    assert!(k.enabled);

    p.roles = vec!["a".to_string(), "all-pools".to_string()];
    let k = synthesize_principal_key(&p, Some(&table)).expect("granting");
    assert!(
        k.allowed_scopes.is_none(),
        "omitted allowed_pools grants every pool (None encoding)"
    );

    p.roles = vec!["admin-only".to_string(), "unbound".to_string()];
    assert!(
        synthesize_principal_key(&p, Some(&table)).is_none(),
        "an all-[] pool grant = no synthetic key (fail closed)"
    );
    p.roles = vec![];
    assert!(synthesize_principal_key(&p, Some(&table)).is_none());

    p.roles = vec!["a".to_string()];
    assert!(synthesize_principal_key(&p, None).is_none());
}

#[tokio::test]
async fn group_prefixed_principal_id_cannot_alias_a_budget_group_bucket() {
    use crate::config::RoleBindingCfg;
    let mut table = std::collections::BTreeMap::new();

    table.insert("eng".to_string(), RoleBindingCfg::default());

    let mut ok = crate::auth::Principal::from_id("sso:alice");
    ok.roles = vec!["eng".to_string()];
    let k = synthesize_principal_key(&ok, Some(&table)).expect("benign id synthesizes");
    assert_eq!(k.id, "sso:alice", "the key id IS the ledger bucket id");

    let mut evil = crate::auth::Principal::from_id("group:acme");
    evil.roles = vec!["eng".to_string()];
    assert!(
        synthesize_principal_key(&evil, Some(&table)).is_none(),
        "a group:-prefixed principal id must be refused, never keyed into the ledger"
    );

    let mut bare = crate::auth::Principal::from_id("group:");
    bare.roles = vec!["eng".to_string()];
    assert!(synthesize_principal_key(&bare, Some(&table)).is_none());
}

#[tokio::test]
async fn vk_prefixed_principal_id_cannot_alias_a_virtual_key_bucket() {
    use crate::config::RoleBindingCfg;
    let mut table = std::collections::BTreeMap::new();
    table.insert("eng".to_string(), RoleBindingCfg::default());

    let mut evil = crate::auth::Principal::from_id("vk_deadbeefdeadbeef");
    evil.roles = vec!["eng".to_string()];
    assert!(
        synthesize_principal_key(&evil, Some(&table)).is_none(),
        "a vk_-prefixed principal id must be refused, never keyed into a virtual key's bucket"
    );

    let mut bare = crate::auth::Principal::from_id("vk_");
    bare.roles = vec!["eng".to_string()];
    assert!(synthesize_principal_key(&bare, Some(&table)).is_none());
}
use super::native_ledger_fixture::*;
use super::*;

#[path = "ordinary_flush_unknown_cases.rs"]
mod ordinary_flush_unknown_cases;

fn sample_key(id: &str, hash: &str) -> VirtualKey {
    VirtualKey {
        id: id.to_string(),
        generation_hash: hash.to_string(),
        name: "test-key".to_string(),
        allowed_scopes: Some(vec![ScopeRef::pool("prod"), ScopeRef::pool("cheap")]),
        enabled: true,
        created_at: 1_700_000_000,
        group: None,
        labels: std::collections::BTreeMap::new(),
        expires_at: None,
        deleted_at: None,
        revision: 1,
        ..Default::default()
    }
}

fn flat_cost(fee: i64) -> crate::cost::CostModel {
    crate::cost::CostModel::flat(fee)
}

fn one_entry_card(
    model: &str,
    input_utok: f64,
) -> std::collections::BTreeMap<String, crate::config::RateEntryCfg> {
    std::collections::BTreeMap::from([(
        model.to_string(),
        crate::config::RateEntryCfg {
            input_utok,
            output_utok: 0.0,
            cache_read_utok: 0.0,
            cache_write_utok: 0.0,
            ..Default::default()
        },
    )])
}

fn budget_group_cfg(cap: i64, period: &str, parent: Option<&str>) -> crate::config::GroupCfg {
    use crate::config::groups::{LimitCfg, LimitMetric, LimitWindow};
    let per = match period {
        "day" => LimitWindow::Day,
        "month" => LimitWindow::Month,
        "minute" => LimitWindow::Minute,
        "hour" => LimitWindow::Hour,
        _ => LimitWindow::Total,
    };
    crate::config::GroupCfg {
        parent: parent.map(String::from),
        enabled: true,
        limits: vec![LimitCfg {
            metric: LimitMetric::Budget,
            amount: u64::try_from(cap).unwrap_or(0),
            per: Some(per),
            scope: None,
            on_exhaust: None,
            downgrade_to: None,
            admission: None,
            on_exhaustion: None,
        }],
        ..Default::default()
    }
}

fn card_cost(model: &str, input_utok: f64) -> crate::cost::CostModel {
    crate::cost::CostModel::resolve_parts(
        Some(&one_entry_card(model, input_utok)),
        0,
        &std::collections::BTreeMap::new(),
    )
}

fn group_cost(fee: i64, groups: &[(&str, i64, &str, Option<&str>)]) -> crate::cost::CostModel {
    let groups_cfg: std::collections::BTreeMap<String, crate::config::GroupCfg> = groups
        .iter()
        .map(|(name, cap, period, parent)| {
            (name.to_string(), budget_group_cfg(*cap, period, *parent))
        })
        .collect();
    crate::cost::CostModel::resolve_parts(None, fee, &groups_cfg)
}

fn card_and_group_cost(
    model: &str,
    input_utok: f64,
    groups: &[(&str, i64, &str, Option<&str>)],
) -> crate::cost::CostModel {
    let groups_cfg: std::collections::BTreeMap<String, crate::config::GroupCfg> = groups
        .iter()
        .map(|(name, cap, period, parent)| {
            (name.to_string(), budget_group_cfg(*cap, period, *parent))
        })
        .collect();
    crate::cost::CostModel::resolve_parts(Some(&one_entry_card(model, input_utok)), 0, &groups_cfg)
}

fn tt(n: u64) -> std::collections::BTreeMap<String, u64> {
    let mut m = std::collections::BTreeMap::new();
    if n != 0 {
        m.insert(busbar_contract::records::UNIT_INPUT.to_string(), n);
    }
    m
}

async fn ledger_tokens(
    store: &crate::persistence::facade::CoreStore,
    bucket: &str,
    window: u64,
) -> u64 {
    store
        .ledger()
        .get_usage(bucket, window)
        .await
        .unwrap()
        .total_whole_tokens_for_test()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_concurrent_govstate_admission_respects_cap() {
    let store = crate::real_store::core().await;
    let gov = Arc::new(
        GovState::new_with_core(store.clone().core(), None, None)
            .await
            .unwrap(),
    );
    let cost = Arc::new(group_cost(1, &[("team", 5, "total", None)]));
    let (key, _s) = {
        gov.set_signing_key(Some(self_serve_signer()));
        gov.mint_signed_async(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: None,
                group: Some("team".to_string()),
                labels: std::collections::BTreeMap::new(),
                ..Default::default()
            },
            4_000_000_000,
            1_700_000_000,
        )
        .await
    }
    .unwrap();
    let at = 1_700_000_000u64;
    let mut handles = Vec::new();
    for _ in 0..20 {
        let gov = gov.clone();
        let cost = cost.clone();
        let key = key.clone();
        handles.push(tokio::spawn(async move {
            gov.try_admit(&cost, &key, "", at).is_ok()
        }));
    }
    let mut admitted = 0u32;
    for h in handles {
        if h.await.unwrap() {
            admitted += 1;
        }
    }
    assert_eq!(
        admitted, 5,
        "exactly 5 of 20 concurrent GovState admissions fit under a 5c group cap at 1c/request"
    );

    gov.flush_budgets().await;
    assert_eq!(
        store.ledger().get_usage(&key.id, 0).await.unwrap().requests,
        5,
        "exactly 5 requests ledgered on the key bucket - no overshoot"
    );
    assert_eq!(
        store
            .ledger()
            .get_usage("group:team@total", 0)
            .await
            .unwrap()
            .requests,
        5,
        "and 5 on the group's total-window bucket (the capped one)"
    );
    assert_eq!(
        gov.usage_for_async(&cost, &key.id, at)
            .await
            .unwrap()
            .unwrap()
            .spend_cents,
        5,
        "derived spend = 5 requests x 1c fee"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_charge_refund_readmit_cycle() {
    let store = crate::real_store::core().await;
    let gov = Arc::new(
        GovState::new_with_core(store.clone().core(), None, None)
            .await
            .unwrap(),
    );
    let cost = group_cost(1, &[("solo", 1, "total", None)]);
    let (key, _s) = {
        gov.set_signing_key(Some(self_serve_signer()));
        gov.mint_signed_async(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: None,
                group: Some("solo".to_string()),
                labels: std::collections::BTreeMap::new(),
                ..Default::default()
            },
            4_000_000_000,
            1_700_000_000,
        )
        .await
    }
    .unwrap();
    let at = 1_700_000_000u64;

    let first = (gov.try_admit(&cost, &key, "", at))
        .expect("1st (1c) admitted, spends the whole 1c group cap");

    match gov.try_admit(&cost, &key, "", at).unwrap_err() {
        LimitBlocked::Limit {
            group,
            metric: "budget",
            ..
        } => assert_eq!(group, "solo"),
        other => panic!("expected the group budget to block, got {other:?}"),
    }

    gov.refund_charge(first.charge());
    assert_eq!(
        gov.usage_for_async(&cost, &key.id, at)
            .await
            .unwrap()
            .unwrap()
            .spend_cents,
        0,
        "refund must reverse the derived charge back to 0 spend"
    );

    assert!(
        gov.try_admit(&cost, &key, "", at).is_ok(),
        "post-refund request re-admitted: the refunded fee freed the budget"
    );
}

#[tokio::test]
async fn test_try_admit_rejects_at_group_cap() {
    let store = crate::real_store::core().await;
    let gov = GovState::new_with_core(store.core(), None, None)
        .await
        .unwrap();
    let cost = group_cost(1, &[("g", 2, "total", None)]);
    let (key, _s) = {
        gov.set_signing_key(Some(self_serve_signer()));
        gov.mint_signed_async(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: None,
                group: Some("g".to_string()),
                labels: std::collections::BTreeMap::new(),
                ..Default::default()
            },
            4_000_000_000,
            1_700_000_000,
        )
        .await
    }
    .unwrap();
    let at = 1_700_000_000u64;
    assert!(
        gov.try_admit(&cost, &key, "", at).is_ok(),
        "1st (1c) admitted"
    );
    assert!(
        gov.try_admit(&cost, &key, "", at).is_ok(),
        "2nd (2c) admitted"
    );
    assert_eq!(
        gov.try_admit(&cost, &key, "", at).unwrap_err(),
        LimitBlocked::Limit {
            group: "g".to_string(),
            metric: "budget",
            window: Some("total"),
            pool: None,
            downgrade_to: None,
            retry_after: None,
        },
        "3rd (would be 3c > 2c cap) rejected atomically, naming the exact bucket"
    );
}

#[tokio::test]
async fn test_metering_accumulates_split_per_key_model_and_bucket() {
    let s = crate::real_store::core().await;
    let day = metering_bucket(1_700_000_123);
    assert_eq!(day % METERING_BUCKET_SECS, 0);
    let d = |model: &str, input: u64, output: u64| MeteringDelta {
        scale: 0,
        usage_units: Default::default(),
        key_id: "vk_a".into(),
        bucket: day,
        model: model.into(),
        provider: "acme".into(),
        tokens_input: i128::from(input),
        tokens_output: i128::from(output),
        tokens_cache_read: 7,
        tokens_cache_write: 3,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: String::new(),
        pricing_version: String::new(),
        priced_from_ms: 0,
    };

    s.ledger().add_metering(&d("gpt-x", 100, 20)).await.unwrap();
    s.ledger().add_metering(&d("gpt-x", 50, 10)).await.unwrap();
    s.ledger().add_metering(&d("gpt-y", 1, 2)).await.unwrap();

    s.ledger()
        .add_metering(&MeteringDelta {
            scale: 0,
            bucket: day + METERING_BUCKET_SECS,
            ..d("gpt-x", 999, 999)
        })
        .await
        .unwrap();

    let mut rows = s.ledger().list_metering(day).await.unwrap();
    rows.sort_by(|a, b| a.model.cmp(&b.model));
    assert_eq!(rows.len(), 2, "two models in this bucket: {rows:?}");
    let x = &rows[0];
    assert_eq!((x.model.as_str(), x.provider.as_str()), ("gpt-x", "acme"));
    assert_eq!(
        (
            stored_whole_for_test(x.tokens_input, x.scale),
            stored_whole_for_test(x.tokens_output, x.scale),
            x.requests
        ),
        (150, 30, 2),
        "raw split accumulates + one request per response"
    );
    assert_eq!(
        (
            stored_whole_for_test(x.tokens_cache_read, x.scale),
            stored_whole_for_test(x.tokens_cache_write, x.scale)
        ),
        (14, 6),
        "cache reads/writes carry separately (they price differently)"
    );
    assert_eq!(rows[1].model, "gpt-y");
    assert_eq!(rows[1].requests, 1);
}

#[tokio::test]
async fn test_record_metering_from_ir_usage_and_flat() {
    let store = crate::real_store::core().await;
    let gov = GovState::new_with_core(store.core(), None, None)
        .await
        .unwrap();
    let now = 1_700_000_500;
    let usage = busbar_contract::billing::TokenUsage {
        input: 11,
        output: 22,
        cache_read: Some(5),
        cache_creation: None,
        ..Default::default()
    };
    gov.record_metering("vk_m", "model-z", "acme", Some(&usage), now);
    gov.record_metering("vk_m", "model-z", "acme", None, now);
    gov.flush_metering().await;
    let rows = gov.metering_for_async(metering_bucket(now)).await.unwrap();
    assert_eq!(rows.len(), 1);
    let r = &rows[0];
    assert_eq!(
        (r.key_id.as_str(), r.model.as_str(), r.provider.as_str()),
        ("vk_m", "model-z", "acme")
    );
    assert_eq!(
        (
            stored_whole_for_test(r.tokens_input, r.scale),
            stored_whole_for_test(r.tokens_output, r.scale),
            stored_whole_for_test(r.tokens_cache_read, r.scale),
            stored_whole_for_test(r.tokens_cache_write, r.scale),
            r.requests
        ),
        (11, 22, 5, 0, 2),
        "split preserved; the flat-fee response still counted its request; requests==N survives coalescing"
    );
}

#[tokio::test]
async fn test_virtualkey_debug_redacts_key_hash() {
    let mut k = sample_key("vk_dbg", "SECRET-key-hash-value-zzz");
    let dbg = format!("{k:?}");
    assert!(
        !dbg.contains("SECRET-key-hash-value-zzz"),
        "VirtualKey Debug leaked generation_hash: {dbg}"
    );
    assert!(
        dbg.contains("<redacted; present>"),
        "VirtualKey Debug should mark generation_hash present-but-redacted: {dbg}"
    );

    assert!(dbg.contains("vk_dbg"), "id must still appear: {dbg}");
    assert!(dbg.contains("test-key"), "name must still appear: {dbg}");

    let ctx = GovCtx {
        key: Some(std::sync::Arc::new(k.clone())),
    };
    let ctx_dbg = format!("{ctx:?}");
    assert!(
        !ctx_dbg.contains("SECRET-key-hash-value-zzz"),
        "GovCtx Debug leaked the embedded generation_hash: {ctx_dbg}"
    );

    k.generation_hash = String::new();
    let dbg_empty = format!("{k:?}");
    assert!(
        dbg_empty.contains("<absent>"),
        "empty generation_hash should read as absent: {dbg_empty}"
    );
}

#[tokio::test]
async fn test_create_key_with_aws_issues_and_resolves_credential() {
    let store = crate::real_store::core().await;
    let gov = GovState::new_with_core(store, None, None).await.unwrap();
    let (key, _bearer, akid, secret) = {
        gov.set_signing_key(Some(self_serve_signer()));
        gov.set_at_rest_keys(Some(crate::governance::at_rest::AtRestKeys::new(
            &[3u8; 32], None,
        )));
        gov.mint_signed_with_credential_async(
            NewKeySpec {
                name: "vendor-a-key".to_string(),
                allowed_pools: Some(vec!["prod".to_string()]),
                group: None,
                labels: std::collections::BTreeMap::new(),
                ..Default::default()
            },
            4_000_000_000,
            1_700_000_000,
            &signed_kind(),
            &ISSUED_SHAPE,
        )
        .await
        .map(|(key, bearer, public_id, secret)| {
            (
                key,
                bearer,
                public_id,
                secret.expose(&crate::seal::lend()).clone(),
            )
        })
    }
    .unwrap();

    assert!(akid.starts_with("AKIA"), "akid shape: {akid}");
    assert_eq!(akid.len(), 20);
    assert_eq!(secret.len(), 40);

    let (resolved_key, cred) = gov
        .lookup_credential(&crate::governance::tests::signed_kind(), &akid)
        .expect("akid resolves");
    assert_eq!(resolved_key.id, key.id);
    let (opened, live) = gov.credential_secret(&signed_kind(), &akid, 1_700_000_000);
    assert_eq!(opened.expose(&crate::seal::lend()), &secret);
    assert!(live);
    assert!(
        !cred.secret.contains(&secret),
        "the durable credential is encrypted"
    );
    assert!(resolved_key.enabled);

    assert!(gov
        .lookup_credential(&signed_kind(), "AKIAdoesnotexist0000")
        .is_none());
}

#[tokio::test]
async fn test_credential_generators_contract() {
    let (_, shape) = (signed_kind(), ISSUED_SHAPE.clone());
    let (akid, sak) = issue_credential(&shape).expect("OS entropy available");
    assert_eq!(akid.len(), 20);
    assert!(akid.starts_with("AKIA"), "akid prefix: {akid}");
    assert!(
        akid.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()),
        "akid is uppercase-alphanumeric: {akid}"
    );
    assert_eq!(sak.len(), 40);
    assert!(
        sak.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/'),
        "the secret is over the stated alphabet: {sak}"
    );

    assert_ne!(
        issue_credential(&shape).unwrap().0,
        akid,
        "akids must not repeat"
    );
}

#[tokio::test]
async fn test_aws_credential_persists_across_reload() {
    let store = crate::real_store::core().await;
    let akid = {
        let gov = GovState::new_with_core(store.clone(), None, None)
            .await
            .unwrap();
        let (_k, _b, akid, _s) = {
            gov.set_signing_key(Some(self_serve_signer()));
            gov.set_at_rest_keys(Some(crate::governance::at_rest::AtRestKeys::new(
                &[3u8; 32], None,
            )));
            gov.mint_signed_with_credential_async(
                NewKeySpec {
                    name: "k".to_string(),
                    allowed_pools: None,
                    group: None,
                    labels: std::collections::BTreeMap::new(),
                    ..Default::default()
                },
                4_000_000_000,
                0,
                &signed_kind(),
                &ISSUED_SHAPE,
            )
            .await
            .map(|(key, bearer, public_id, secret)| {
                (
                    key,
                    bearer,
                    public_id,
                    secret.expose(&crate::seal::lend()).clone(),
                )
            })
        }
        .unwrap();
        akid
    };
    let gov2 = GovState::new_with_core(store, None, None).await.unwrap();
    assert!(
        gov2.lookup_credential(&signed_kind(), &akid).is_some(),
        "credential must survive a reload"
    );
}

#[tokio::test]
async fn test_delete_key_removes_aws_credential() {
    let store = crate::real_store::core().await;
    let gov = GovState::new_with_core(store, None, None).await.unwrap();
    let (key, _b, akid, _s) = {
        gov.set_signing_key(Some(self_serve_signer()));
        gov.set_at_rest_keys(Some(crate::governance::at_rest::AtRestKeys::new(
            &[3u8; 32], None,
        )));
        gov.mint_signed_with_credential_async(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: None,
                group: None,
                labels: std::collections::BTreeMap::new(),
                ..Default::default()
            },
            4_000_000_000,
            0,
            &signed_kind(),
            &ISSUED_SHAPE,
        )
        .await
        .map(|(key, bearer, public_id, secret)| {
            (
                key,
                bearer,
                public_id,
                secret.expose(&crate::seal::lend()).clone(),
            )
        })
    }
    .unwrap();
    assert!(gov.lookup_credential(&signed_kind(), &akid).is_some());
    gov.delete_key(&key.id).await.unwrap();
    assert!(
        gov.lookup_credential(&signed_kind(), &akid).is_none(),
        "a revoked key's AWS credential must be gone"
    );

    assert!(gov
        .core_store()
        .unwrap()
        .identity()
        .list_credentials(&key.id)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn test_refresh_updates_both_indices_atomically() {
    let store = crate::real_store::core().await;
    let signer = crate::governance::signing::TokenSigner::from_secret_bytes(
        &[7u8; 32],
        crate::governance::signing::DEFAULT_KID,
    );
    let gov = GovState::new_with_core(store, None, Some(signer))
        .await
        .unwrap();
    gov.set_at_rest_keys(Some(crate::governance::at_rest::AtRestKeys::new(
        &[3u8; 32], None,
    )));
    let (key, _token, akid, _secret) = gov
        .mint_signed_with_credential_async(
            NewKeySpec {
                name: "dual-index-key".to_string(),
                allowed_pools: None,
                group: None,
                labels: std::collections::BTreeMap::new(),
                ..Default::default()
            },
            2_000_000_000,
            1_700_000_000,
            &signed_kind(),
            &ISSUED_SHAPE,
        )
        .await
        .unwrap();

    assert_eq!(
        gov.lookup_by_sub(&key.id).map(|k| k.id.clone()),
        Some(key.id.clone()),
        "subject id must resolve via by_id before delete"
    );
    assert_eq!(
        gov.lookup_credential(&signed_kind(), &akid)
            .map(|(k, _)| k.id.clone()),
        Some(key.id.clone()),
        "akid must resolve via by_access_key_id before delete"
    );

    gov.delete_key(&key.id).await.unwrap();

    assert!(
        gov.lookup_by_sub(&key.id).is_none(),
        "subject id must be gone from by_id after delete"
    );
    assert!(
        gov.lookup_credential(&signed_kind(), &akid).is_none(),
        "akid must be gone from by_credential after delete"
    );
}

#[tokio::test]
async fn test_aws_credential_debug_redacts_secret() {
    let cred = CredentialSecret {
        meta: CredentialMeta {
            id: "cred_x".to_string(),
            key_id: "vk_x".to_string(),
            kind: signed_kind(),
            slot: 0,
            public_id: "AKIAPUBLIC1234567890".to_string(),
            secret_form: SecretForm::Recoverable,
            created_at: 0,
            updated_at: 0,
            expires_at: None,
            revoked_at: None,
            revoke_reason: None,
            revision: 0,
        },
        secret: "v1:plain:SUPER-SECRET-SIGNING-KEY-zzz".to_string().into(),
    };
    let dbg = format!("{cred:?}");
    assert!(
        !dbg.contains("SUPER-SECRET-SIGNING-KEY-zzz"),
        "CredentialSecret Debug leaked the secret: {dbg}"
    );
    assert!(dbg.contains("<redacted; present>"));
    assert!(dbg.contains("AKIAPUBLIC1234567890"), "akid is not secret");
}

#[tokio::test]
async fn test_generated_aws_credentials_are_distinct() {
    let store = crate::real_store::core().await;
    let gov = GovState::new_with_core(store, None, None).await.unwrap();
    let mk = async |gov: &GovState, n: &str| {
        {
            gov.set_signing_key(Some(self_serve_signer()));
            gov.set_at_rest_keys(Some(crate::governance::at_rest::AtRestKeys::new(
                &[3u8; 32], None,
            )));
            gov.mint_signed_with_credential_async(
                NewKeySpec {
                    name: n.to_string(),
                    allowed_pools: None,
                    group: None,
                    labels: std::collections::BTreeMap::new(),
                    ..Default::default()
                },
                4_000_000_000,
                0,
                &signed_kind(),
                &ISSUED_SHAPE,
            )
            .await
            .map(|(key, bearer, public_id, secret)| {
                (
                    key,
                    bearer,
                    public_id,
                    secret.expose(&crate::seal::lend()).clone(),
                )
            })
        }
        .unwrap()
    };
    let (_k1, _b1, akid1, s1) = mk(&gov, "a").await;
    let (_k2, _b2, akid2, s2) = mk(&gov, "b").await;
    assert_ne!(akid1, akid2);
    assert_ne!(s1, s2);
}

#[tokio::test]
async fn test_govstate_lookup_pool_allowed_refresh() {
    let store = crate::real_store::core().await;
    let mut k = sample_key("k1", "binding:k1:gen1");
    k.allowed_scopes = Some(vec![ScopeRef::pool("prod")]);
    store.identity().put_key(&k).await.unwrap();

    let gov = GovState::new_with_core(store, None, None).await.unwrap();

    assert_eq!(gov.lookup_by_sub("k1").unwrap().id, "k1");
    assert!(gov.lookup_by_sub("no-such-id").is_none());

    let resolved = gov.lookup_by_sub("k1").unwrap();
    assert!(pool_allowed(&resolved, "prod"));
    assert!(!pool_allowed(&resolved, "other"));

    let mut k2 = sample_key("k2", "binding:k2:gen1");
    k2.allowed_scopes = None;
    gov.core_store()
        .unwrap()
        .identity()
        .put_key(&k2)
        .await
        .unwrap();
    assert!(gov.lookup_by_sub("k2").is_none(), "not cached pre-refresh");
    gov.refresh_async().await.unwrap();
    let r2 = gov.lookup_by_sub("k2").unwrap();
    assert!(pool_allowed(&r2, "anything"), "None allowed_pools = all");

    let mut k3 = sample_key("k3", "h3");
    k3.allowed_scopes = Some(vec![]);
    assert!(
        !pool_allowed(&k3, "prod"),
        "explicit [] = NO pools, never all"
    );
}

#[tokio::test]
async fn test_civil_from_days_and_days_from_civil_known_dates() {
    let cases: &[(i64, (i64, i64, i64))] = &[
        (0, (1970, 1, 1)),
        (-1, (1969, 12, 31)),
        (-365, (1969, 1, 1)),
        (11_016, (2000, 2, 29)),
        (11_017, (2000, 3, 1)),
        (-25_508, (1900, 3, 1)),
        (-25_509, (1900, 2, 28)),
        (19_691, (2023, 11, 30)),
        (19_692, (2023, 12, 1)),
        (19_782, (2024, 2, 29)),
        (19_783, (2024, 3, 1)),
        (157_113, (2400, 2, 29)),
        (-1_000_000, (-768, 2, 4)),
    ];
    for &(z, ymd) in cases {
        assert_eq!(
            {
                let (y, m, d) = busbar_contract::civil::civil_from_days(z);
                (y, i64::from(m), i64::from(d))
            },
            ymd,
            "civil_from_days({z})"
        );
        assert_eq!(
            days_from_civil(ymd.0, ymd.1, ymd.2),
            z,
            "days_from_civil{ymd:?}"
        );
    }
}

#[tokio::test]
async fn test_budget_window_periods() {
    assert_eq!(budget_window(WINDOW_TOTAL, 1_700_000_000), 0);
    assert_eq!(budget_window("unknown", 1_700_000_000), 0);
    assert_eq!(budget_window(WINDOW_DAY, 1_700_000_000), 1_699_920_000);

    assert_eq!(budget_window(WINDOW_MONTH, 1_700_000_000), 1_698_796_800);

    assert_eq!(budget_window(WINDOW_HOUR, 1_700_000_000), 1_699_999_200);

    assert_eq!(
        window_end(WINDOW_MINUTE, 1_700_000_010),
        Some(1_700_000_040)
    );

    assert_eq!(
        window_end(WINDOW_HOUR, 1_700_000_000),
        Some(1_699_999_200 + 3600)
    );
    assert_eq!(
        window_end(WINDOW_DAY, 1_700_000_000),
        Some(1_699_920_000 + SECS_PER_DAY)
    );

    assert_eq!(window_end(WINDOW_MONTH, 1_700_000_000), Some(1_701_388_800));
    assert_eq!(window_end(WINDOW_TOTAL, 1_700_000_000), None);
}

#[tokio::test]
async fn test_derived_spend_enforces_cap_from_request_ledger() {
    let store = crate::real_store::core().await;
    let mut k = sample_key("k1", "h1");
    k.group = Some("team".to_string());
    store.identity().put_key(&k).await.unwrap();
    let gov = GovState::new_with_core(store.core(), None, None)
        .await
        .unwrap();
    let cost = group_cost(30, &[("team", 100, "total", None)]);

    for i in 0..3 {
        assert!(
            gov.try_admit(&cost, &k, "", 1_700_000_000).is_ok(),
            "admission {i} fits (derived spend stays under 100c)"
        );
    }
    assert_eq!(
        gov.usage_for_async(&cost, "k1", 1_700_000_000)
            .await
            .unwrap()
            .unwrap()
            .spend_cents,
        90,
        "derived spend = 3 requests x 30c"
    );
    match gov.try_admit(&cost, &k, "", 1_700_000_000).unwrap_err() {
        LimitBlocked::Limit {
            group,
            metric: "budget",
            ..
        } => assert_eq!(group, "team"),
        other => panic!("expected the group budget to block, got {other:?}"),
    }

    let mut unlimited = k.clone();
    unlimited.id = "k_free".to_string();
    unlimited.group = None;
    assert!(
        gov.try_admit(&cost, &unlimited, "", 1_700_000_000).is_ok(),
        "a key with no group is authed + unlimited"
    );
}

#[tokio::test]
async fn test_two_node_flush_is_additive_no_lost_update() {
    let store = crate::real_store::core().await;
    let k = sample_key("k_fleet", "h_fleet");
    store.identity().put_key(&k).await.unwrap();

    let node_a = GovState::new_with_core(store.clone().core(), None, None)
        .await
        .unwrap();
    let node_b = GovState::new_with_core(store.clone().core(), None, None)
        .await
        .unwrap();
    let cost = flat_cost(10);

    for _ in 0..3 {
        assert!(node_a.try_admit(&cost, &k, "", 1_700_000_000).is_ok());
    }
    node_a.record_usage(&cost, &k, "", "gpt-5", &tt(100), 1_700_000_000);
    for _ in 0..2 {
        assert!(node_b.try_admit(&cost, &k, "", 1_700_000_000).is_ok());
    }
    node_b.record_usage(&cost, &k, "", "gpt-5", &tt(40), 1_700_000_000);
    node_b.record_usage(&cost, &k, "", "haiku", &tt(7), 1_700_000_000);
    node_a.flush_budgets().await;
    node_b.flush_budgets().await;

    let u = store.ledger().get_usage("k_fleet", 0).await.unwrap();
    assert_eq!(
        u.requests, 5,
        "the durable record is the FLEET SUM (3 + 2), not last-writer-wins"
    );
    assert_eq!(
        u.tokens_for_whole_test("gpt-5").unwrap(),
        140,
        "per-model token deltas SUM across nodes (100 + 40)"
    );
    assert_eq!(
        u.tokens_for_whole_test("haiku").unwrap(),
        7,
        "a model only one node used still lands"
    );

    node_a.flush_budgets().await;
    node_b.flush_budgets().await;
    let u = store.ledger().get_usage("k_fleet", 0).await.unwrap();
    assert_eq!(u.requests, 5, "an idle re-flush adds nothing");
    assert_eq!(u.tokens_for_whole_test("gpt-5").unwrap(), 140);

    assert!(node_a.try_admit(&cost, &k, "", 1_700_000_000).is_ok());
    node_a.flush_budgets().await;
    assert_eq!(
        store
            .ledger()
            .get_usage("k_fleet", 0)
            .await
            .unwrap()
            .requests,
        6
    );
}

#[tokio::test]
async fn test_additive_flush_carries_refund_deltas() {
    let store = crate::real_store::core().await;
    let k = sample_key("k_refund", "h_refund");
    store.identity().put_key(&k).await.unwrap();
    let gov = GovState::new_with_core(store.clone().core(), None, None)
        .await
        .unwrap();
    let cost = flat_cost(10);

    assert!(gov.try_admit(&cost, &k, "", 1_700_000_000).is_ok());
    let second = gov.try_admit(&cost, &k, "", 1_700_000_000).expect("admits");
    gov.flush_budgets().await;
    let u = store.ledger().get_usage("k_refund", 0).await.unwrap();
    assert_eq!(u.requests, 2);
    assert_eq!(u.billable_requests, 2);

    gov.refund_charge(second.charge());
    gov.flush_budgets().await;
    let u = store.ledger().get_usage("k_refund", 0).await.unwrap();
    assert_eq!(
        u.requests, 2,
        "the ADMISSION count is never refunded (the requests-limit truth)"
    );
    assert_eq!(
        u.billable_requests, 1,
        "the refund's negative BILLABLE delta lands durably"
    );
    assert_eq!(
        gov.usage_for_async(&cost, "k_refund", 1_700_000_000)
            .await
            .unwrap()
            .unwrap()
            .spend_cents,
        10,
        "derived spend follows the refunded BILLABLE count (1 x 10c fee)"
    );
}

#[tokio::test]
async fn test_metering_accumulator_is_bounded_and_lossless_under_sustained_store_outage() {
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));

    let store = Arc::new(FlakyStore::new().await);
    store.meter_down.store(true, Ordering::SeqCst);
    let gov = GovState::new_with_core(store.core(), None, None)
        .await
        .unwrap();
    let now = 1_700_000_000;
    let per = busbar_contract::billing::TokenUsage {
        input: 3,
        output: 5,
        cache_read: Some(1),
        cache_creation: Some(2),
        ..Default::default()
    };

    let n = MAX_PENDING_METERING + 5_000;
    for i in 0..n {
        gov.record_metering(&format!("k{i}"), "m", "p", Some(&per), now);
    }

    let (len_rec, sum_rec) = gov.pending_metering_totals();
    let n64 = n as u64;
    assert!(
        len_rec <= MAX_PENDING_METERING + GOV_SHARDS,
        "the accrual path holds the map at the cap (+ at most one per-bucket sentinel per shard), not one cell per key: {len_rec}"
    );
    assert_eq!(
        sum_rec.requests, n64,
        "every accrued request is still counted"
    );
    assert_eq!(
        sum_rec.tokens_input.whole_for_test(),
        n64 * 3,
        "no input tokens lost to the cap"
    );
    assert_eq!(
        sum_rec.tokens_output.whole_for_test(),
        n64 * 5,
        "no output tokens lost to the cap"
    );
    assert_eq!(
        sum_rec.tokens_cache_read.whole_for_test(),
        n64,
        "no cache-read tokens lost to the cap"
    );
    assert_eq!(
        sum_rec.tokens_cache_write.whole_for_test(),
        n64 * 2,
        "no cache-write tokens lost to the cap"
    );

    let flushed = gov.flush_metering().await;
    assert_eq!(
        flushed, 0,
        "the store is down, so nothing persisted this tick"
    );
    let (len_flush, sum_flush) = gov.pending_metering_totals();
    assert!(
        len_flush <= MAX_PENDING_METERING + GOV_SHARDS,
        "the failed-flush re-queue stays bounded rather than growing unbounded: {len_flush}"
    );
    assert_eq!(
        sum_flush.requests, n64,
        "retry preserves every request across the failed flush (nothing dropped, nothing doubled)"
    );
    assert_eq!(
        sum_flush.tokens_input.whole_for_test(),
        n64 * 3,
        "no billable input tokens lost across the failed flush"
    );

    let rendered = crate::snapshot::snapshot().expect("the actual recorder is installed");
    let coalesced = rendered
        .iter()
        .flat_map(|family| &family.samples)
        .find(|sample| {
            sample.name == "busbar_metering_pending_coalesced_total" && sample.labels.is_empty()
        })
        .and_then(|sample| sample.value.parse::<u64>().ok())
        .unwrap_or(0);
    assert!(
        coalesced > 0,
        "coalesced cells are exported on busbar_metering_pending_coalesced_total so the degradation \
         is observable; got:\n{rendered:?}"
    );
}

#[tokio::test]
async fn test_sharded_metering_accrual_is_exactly_once_under_concurrency() {
    let store = crate::real_store::core().await;
    let gov = Arc::new(
        GovState::new_with_core(store.clone().core(), None, None)
            .await
            .unwrap(),
    );

    let now = busbar_kernel::store::now();
    let threads = 16u64;
    let per_thread = 5_000u64;
    let key_space = 64u64;

    let mut handles = Vec::new();
    for t in 0..threads {
        let gov = gov.clone();
        handles.push(std::thread::spawn(move || {
            let usage = busbar_contract::billing::TokenUsage {
                input: 2,
                output: 3,
                ..Default::default()
            };
            for i in 0..per_thread {
                let k = format!("k{}", (t * 7 + i) % key_space);
                gov.record_metering(&k, "m", "p", Some(&usage), now);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    let total = threads * per_thread;
    let (_, sum) = gov.pending_metering_totals();
    assert_eq!(
        sum.requests, total,
        "every one of the {total} concurrent accruals is counted exactly once"
    );
    assert_eq!(
        sum.tokens_input.whole_for_test(),
        total * 2,
        "input tokens summed exactly once"
    );
    assert_eq!(
        sum.tokens_output.whole_for_test(),
        total * 3,
        "output tokens summed exactly once"
    );

    let flushed = gov.flush_metering().await;
    assert!(flushed > 0, "the flush wrote the drained cells");
    let rows = gov.metering_for_async(metering_bucket(now)).await.unwrap();
    let store_reqs: u64 = rows.iter().map(|r| r.requests).sum();
    assert_eq!(
        store_reqs, total,
        "flush drained every shard exactly once — the store total equals the sum of accruals"
    );
    let (len_after, sum_after) = gov.pending_metering_totals();
    assert_eq!(len_after, 0, "drain emptied every shard");
    assert_eq!(sum_after.requests, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sharded_metering_no_loss_with_a_concurrent_flusher() {
    let store = crate::real_store::core().await;
    let gov = Arc::new(
        GovState::new_with_core(store.clone().core(), None, None)
            .await
            .unwrap(),
    );

    let now = busbar_kernel::store::now();
    let threads = 8u64;
    let per_thread = 10_000u64;

    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (started, ready) = tokio::sync::oneshot::channel();
    let flusher = {
        let gov = gov.clone();
        let stop = stop.clone();
        tokio::spawn(async move {
            started.send(()).unwrap();
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                gov.flush_metering().await;
                tokio::task::yield_now().await;
            }
        })
    };

    ready.await.unwrap();
    let mut handles = Vec::new();
    for t in 0..threads {
        let gov = gov.clone();
        handles.push(std::thread::spawn(move || {
            let usage = busbar_contract::billing::TokenUsage {
                input: 1,
                ..Default::default()
            };
            for i in 0..per_thread {
                let k = format!("k{}", (t * 13 + i) % 200);
                gov.record_metering(&k, "m", "p", Some(&usage), now);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    flusher.await.unwrap();
    gov.flush_metering().await;

    let total = threads * per_thread;
    let rows = gov.metering_for_async(metering_bucket(now)).await.unwrap();
    let store_reqs: u64 = rows.iter().map(|r| r.requests).sum();
    let (_, pending) = gov.pending_metering_totals();
    assert_eq!(
        store_reqs + pending.requests,
        total,
        "no accrual was lost or double-counted across a flush running concurrently with accrual \
         (store {store_reqs} + pending {} == {total})",
        pending.requests
    );
    assert_eq!(
        store_reqs, total,
        "the final drain flushed everything, so the store alone holds the full sum"
    );
}

#[tokio::test]
async fn test_failed_flush_retries_the_unacked_delta() {
    let store = Arc::new(FlakyStore::new().await);
    store.set_down(true);
    let k = sample_key("k_flaky", "h_flaky");
    store.inner.identity().put_key(&k).await.unwrap();
    let gov = GovState::new_with_core(store.clone().core(), None, None)
        .await
        .unwrap();
    let cost = flat_cost(10);

    assert!(gov.try_admit(&cost, &k, "", 1_700_000_000).is_ok());
    gov.flush_budgets().await;
    assert_eq!(
        store
            .inner
            .ledger()
            .get_usage("k_flaky", 0)
            .await
            .unwrap()
            .requests,
        0
    );

    store.set_down(false);
    gov.flush_budgets().await;
    assert_eq!(
        store
            .inner
            .ledger()
            .get_usage("k_flaky", 0)
            .await
            .unwrap()
            .requests,
        1
    );
    gov.flush_budgets().await;
    assert_eq!(
        store
            .inner
            .ledger()
            .get_usage("k_flaky", 0)
            .await
            .unwrap()
            .requests,
        1
    );
}

#[tokio::test]
async fn test_record_usage_derives_spend_and_reprices_on_read() {
    let store = crate::real_store::core().await;
    let gov = GovState::new_with_core(store.clone().core(), None, None)
        .await
        .unwrap();
    let k = {
        let k = sample_key("k1", "h1");
        store.identity().put_key(&k).await.unwrap();
        k
    };
    let cost = card_cost("gpt-5", 500.0);
    gov.record_usage(&cost, &k, "", "gpt-5", &tt(2000), 1_700_000_000);
    gov.flush_budgets().await;
    let ledger = store.ledger().get_usage("k1", 0).await.unwrap();
    assert_eq!(ledger.tokens_for_whole_test("gpt-5").unwrap(), 2000);
    let u = gov
        .usage_for_async(&cost, "k1", 1_700_000_000)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(u.spend_cents, 100, "2000 x 500 micro = 100 cents derived");
    assert_eq!(u.tokens.whole_for_test(), 2000);

    let corrected = card_cost("gpt-5", 250.0);
    let u = gov
        .usage_for_async(&corrected, "k1", 1_700_000_000)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        u.spend_cents, 50,
        "historical derived spend halves on the next read under the corrected rate"
    );
    assert_eq!(
        u.tokens.whole_for_test(),
        2000,
        "tokens never changed - they are the truth"
    );
}

#[tokio::test]
async fn test_sub_cent_precision_via_ledger_no_carry() {
    let store = crate::real_store::core().await;
    let gov = GovState::new_with_core(store.clone().core(), None, None)
        .await
        .unwrap();
    let k = {
        let k = sample_key("k1", "h1");
        store.identity().put_key(&k).await.unwrap();
        k
    };
    let cost = card_cost("m", 10.0);

    gov.record_usage(&cost, &k, "", "m", &tt(500), 1_700_000_000);
    let u1 = gov
        .usage_for_async(&cost, "k1", 1_700_000_000)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(u1.spend_cents, 0, "0.5 cents derives to 0 whole cents");
    assert_eq!(
        u1.tokens.whole_for_test(),
        500,
        "but every token is recorded - nothing truncated"
    );

    gov.record_usage(&cost, &k, "", "m", &tt(500), 1_700_000_000);
    let u2 = gov
        .usage_for_async(&cost, "k1", 1_700_000_000)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        u2.spend_cents, 1,
        "two 0.5-cent requests derive a whole cent from the raw ledger - no carry needed"
    );
    assert_eq!(u2.tokens.whole_for_test(), 1000);
}

#[tokio::test]
async fn test_ledger_windows_are_isolated_across_days() {
    let store = crate::real_store::core().await;
    let gov = GovState::new_with_core(store.clone().core(), None, None)
        .await
        .unwrap();
    let k = {
        let mut k = sample_key("k1", "h1");
        k.group = Some("g".to_string());
        store.identity().put_key(&k).await.unwrap();
        k
    };
    let cost = card_and_group_cost("m", 10.0, &[("g", 1_000_000, "day", None)]);
    let day1 = 1_700_000_000;
    let day2 = day1 + 86_400;
    let w1 = budget_window(WINDOW_DAY, day1);
    let w2 = budget_window(WINDOW_DAY, day2);
    assert_ne!(w1, w2);

    gov.record_usage(&cost, &k, "", "m", &tt(500), day1);
    gov.flush_budgets().await;
    gov.record_usage(&cost, &k, "", "m", &tt(500), day2);
    gov.flush_budgets().await;
    assert_eq!(
        ledger_tokens(&store, "group:g@day", w1).await,
        500,
        "day-1 tokens stay in day 1"
    );
    assert_eq!(
        ledger_tokens(&store, "group:g@day", w2).await,
        500,
        "day-2 window holds only its own tokens (no cross-window leak)"
    );

    assert_eq!(ledger_tokens(&store, "k1", 0).await, 1000);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_record_usage_write_behind_under_runtime() {
    let store = crate::real_store::core().await;
    let gov = GovState::new_with_core(store.clone().core(), None, None)
        .await
        .unwrap();
    let k = {
        let k = sample_key("k1", "h1");
        store.identity().put_key(&k).await.unwrap();
        k
    };
    let cost = card_cost("gpt-5", 500.0);
    gov.record_usage(&cost, &k, "", "gpt-5", &tt(2000), 1_700_000_000);
    assert_eq!(
        store.ledger().get_usage("k1", 0).await.unwrap(),
        UsageLedger::default(),
        "write-behind: the durable ledger is untouched until a flush"
    );
    assert_eq!(gov.flush_budgets().await, 1, "one dirty cell flushed");
    let u = store.ledger().get_usage("k1", 0).await.unwrap();
    assert_eq!(
        u.tokens_for_whole_test("gpt-5").unwrap(),
        2000,
        "the per-model tier split lands durably"
    );
    assert_eq!(
        gov.usage_for_async(&cost, "k1", 1_700_000_000)
            .await
            .unwrap()
            .unwrap()
            .spend_cents,
        100,
        "2000 tokens at 500 micro/token derive exactly 100c"
    );
}

#[tokio::test]
async fn test_rate_headroom_reports_fraction_remaining() {
    use crate::config::groups::{LimitCfg, LimitMetric, LimitWindow};
    let store = crate::real_store::core().await;
    let gov = GovState::new_with_core(store.core(), None, None)
        .await
        .unwrap();
    let now = 1_700_000_040;

    let unl = sample_key("ku", "hu");
    let no_groups = crate::cost::CostModel::flat(0);
    assert_eq!(gov.rate_headroom(&no_groups, &unl, None, now), None);

    let zero_cfg: std::collections::BTreeMap<String, crate::config::GroupCfg> =
        std::collections::BTreeMap::from([(
            "z".to_string(),
            crate::config::GroupCfg {
                parent: None,
                enabled: true,
                limits: vec![LimitCfg {
                    metric: LimitMetric::Requests,
                    amount: 0,
                    per: Some(LimitWindow::Minute),
                    scope: None,
                    on_exhaust: None,
                    downgrade_to: None,
                    admission: None,
                    on_exhaustion: None,
                }],
                ..Default::default()
            },
        )]);
    let zero = crate::cost::CostModel::resolve_parts(None, 0, &zero_cfg);
    let mut kz = sample_key("kz", "hz");
    kz.group = Some("z".to_string());
    assert_eq!(
        gov.rate_headroom(&zero, &kz, None, now),
        Some(0.0),
        "requests=0 is fully closed -> 0.0 headroom, not a divide-by-zero panic"
    );

    let cfg: std::collections::BTreeMap<String, crate::config::GroupCfg> =
        std::collections::BTreeMap::from([(
            "g".to_string(),
            crate::config::GroupCfg {
                parent: None,
                enabled: true,
                limits: vec![
                    LimitCfg {
                        metric: LimitMetric::Requests,
                        amount: 4,
                        per: Some(LimitWindow::Minute),
                        scope: None,
                        on_exhaust: None,
                        downgrade_to: None,
                        admission: None,
                        on_exhaustion: None,
                    },
                    LimitCfg {
                        metric: LimitMetric::Tokens,
                        amount: 100_000,
                        per: Some(LimitWindow::Minute),
                        scope: None,
                        on_exhaust: None,
                        downgrade_to: None,
                        admission: None,
                        on_exhaustion: None,
                    },
                ],
                ..Default::default()
            },
        )]);
    let cost = crate::cost::CostModel::resolve_parts(None, 0, &cfg);
    let mut k = sample_key("k1", "h1");
    k.group = Some("g".to_string());
    assert_eq!(gov.rate_headroom(&cost, &k, None, now), Some(1.0));
    assert_eq!(
        gov.rate_headroom(&cost, &k, None, now),
        Some(1.0),
        "rate_headroom is read-only; repeated reads must not drain the window"
    );

    assert!(gov.try_admit(&cost, &k, "", now).is_ok());
    let h = gov.rate_headroom(&cost, &k, None, now).unwrap();
    assert!((h - 0.75).abs() < 1e-9, "expected 0.75 headroom, got {h}");

    for _ in 0..3 {
        assert!(gov.try_admit(&cost, &k, "", now).is_ok());
    }
    let hb = gov.rate_headroom(&cost, &k, None, now).unwrap();
    assert!(
        hb.abs() < 1e-9,
        "requests at cap must yield 0.0 headroom, got {hb}"
    );
}

#[tokio::test]
async fn test_budget_sweep_is_window_agnostic_across_cotenants() {
    let store = crate::real_store::core().await;
    let gov = GovState::new_with_core(store.core(), None, None)
        .await
        .unwrap();
    let now = 1_700_000_040u64;

    let survivor = sample_key("survivor", "hs");

    let seeded = |window_start: u64, requests: u64, dirty: bool| BudgetCell {
        flushing_windows: Default::default(),
        correction: None,
        group_owners: Default::default(),
        flushing: 0,
        window_start,
        requests,
        billable_requests: requests,
        flushed_requests: 0,
        flushed_billable_requests: 0,
        models: Vec::new(),
        fee_eras: Default::default(),
        flushed_fee_eras: Default::default(),
        rolled: Vec::new(),
        rolled_eras: Vec::new(),
        dirty,
        last_touch: now,
    };

    {
        let mut map = gov.budget.write("survivor");

        map.insert("total-cotenant".to_string(), seeded(0, 4999, true));

        map.insert(
            "monthly-cotenant".to_string(),
            seeded(budget_window(WINDOW_MONTH, now), 1234, true),
        );

        map.insert(
            "stale-cotenant".to_string(),
            seeded(now - 32 * SECS_PER_DAY, 1, false),
        );
    }

    gov.budget.sweep_ticker_for("survivor").store(
        crate::config::DEFAULT_RATE_SWEEP_INTERVAL - 1,
        Ordering::Relaxed,
    );
    assert!(
        gov.try_admit(&flat_cost(1), &survivor, "", now).is_ok(),
        "key admits"
    );

    let map = gov.budget.read("survivor");
    let total = map
        .get("total-cotenant")
        .expect("total-window cell must survive the sweep (window 0 never ages out)");
    assert_eq!(
        (total.requests, total.dirty),
        (4999, true),
        "total-window accrual + dirty flag intact"
    );
    let monthly = map
        .get("monthly-cotenant")
        .expect("current month cell must survive the sweep");
    assert_eq!(monthly.requests, 1234, "month accrual intact");
    assert!(
        !map.contains_key("stale-cotenant"),
        "genuinely stale (>31 d) bounded-window cell is still evicted"
    );
    assert!(
        map.contains_key("survivor"),
        "the charging key's own cell exists"
    );
}

#[tokio::test]
async fn test_budget_sweep_staleness_boundary_is_exact() {
    let store = crate::real_store::core().await;
    let gov = GovState::new_with_core(store.core(), None, None)
        .await
        .unwrap();
    let now = 1_700_000_040u64;
    let max_window = 31 * SECS_PER_DAY;
    let survivor = sample_key("survivor2", "hs2");

    let seeded = |window_start: u64, last_touch: u64| BudgetCell {
        flushing_windows: Default::default(),
        correction: None,
        group_owners: Default::default(),
        flushing: 0,
        window_start,
        requests: 1,
        billable_requests: 1,
        flushed_requests: 0,
        flushed_billable_requests: 0,
        models: Vec::new(),
        fee_eras: Default::default(),
        flushed_fee_eras: Default::default(),
        rolled: Vec::new(),
        rolled_eras: Vec::new(),
        dirty: false,
        last_touch,
    };

    {
        let mut map = gov.budget.write("survivor2");

        map.insert(
            "bounded-at-boundary".to_string(),
            seeded(now - max_window, now),
        );
        map.insert(
            "bounded-just-under".to_string(),
            seeded(now - max_window + 1, now),
        );

        map.insert(
            "alltime-at-boundary".to_string(),
            seeded(0, now - max_window),
        );
        map.insert(
            "alltime-just-under".to_string(),
            seeded(0, now - max_window + 1),
        );
    }

    gov.budget.sweep_ticker_for("survivor2").store(
        crate::config::DEFAULT_RATE_SWEEP_INTERVAL - 1,
        Ordering::Relaxed,
    );
    assert!(
        gov.try_admit(&flat_cost(1), &survivor, "", now).is_ok(),
        "key admits"
    );

    let map = gov.budget.read("survivor2");
    assert!(
        !map.contains_key("bounded-at-boundary"),
        "a bounded-window cell aged EXACTLY max_window must be evicted (> not >=)"
    );
    assert!(
        map.contains_key("bounded-just-under"),
        "a bounded-window cell one second younger than the boundary must survive"
    );
    assert!(
        !map.contains_key("alltime-at-boundary"),
        "an all-time cell last-touched EXACTLY max_window ago must be evicted (> not >=)"
    );
    assert!(
        map.contains_key("alltime-just-under"),
        "an all-time cell touched one second more recently than the boundary must survive"
    );
}

#[tokio::test]
async fn test_budget_sweep_cadence_post_increment_no_off_by_one() {
    const N: u32 = crate::config::DEFAULT_RATE_SWEEP_INTERVAL;
    let store = crate::real_store::core().await;
    let gov = GovState::new_with_core(store.core(), None, None)
        .await
        .unwrap();
    let k = sample_key("k1", "h1");
    let now = 1_700_000_040u64;
    let stale = || BudgetCell {
        flushing_windows: Default::default(),
        correction: None,
        group_owners: Default::default(),
        flushing: 0,
        window_start: now - 40 * SECS_PER_DAY,
        requests: 1,
        billable_requests: 1,
        flushed_requests: 0,
        flushed_billable_requests: 0,
        models: Vec::new(),
        fee_eras: Default::default(),
        flushed_fee_eras: Default::default(),
        rolled: Vec::new(),
        rolled_eras: Vec::new(),
        dirty: false,
        last_touch: now,
    };

    {
        let mut map = gov.budget.write("k1");
        map.insert("stale".to_string(), stale());
    }

    assert_eq!(gov.budget.sweep_ticker_for("k1").load(Ordering::Relaxed), 0);
    assert!(gov.try_admit(&flat_cost(0), &k, "", now).is_ok());
    assert!(
        gov.budget.read("k1").contains_key("stale"),
        "first admission must NOT sweep (post-increment value 1 is not a multiple of N)"
    );

    gov.budget
        .sweep_ticker_for("k1")
        .store(N - 1, Ordering::Relaxed);
    assert!(gov.try_admit(&flat_cost(0), &k, "", now).is_ok());
    assert!(
        !gov.budget.read("k1").contains_key("stale"),
        "admission N must run the sweep and evict the stale entry"
    );

    {
        let mut map = gov.budget.write("k1");
        map.insert("stale2".to_string(), stale());
    }
    gov.budget
        .sweep_ticker_for("k1")
        .store(u32::MAX, Ordering::Relaxed);
    assert!(gov.try_admit(&flat_cost(0), &k, "", now).is_ok());
    assert_eq!(
        gov.budget.sweep_ticker_for("k1").load(Ordering::Relaxed),
        0,
        "ticker wrapped to 0"
    );
    assert!(
        !gov.budget.read("k1").contains_key("stale2"),
        "wrap boundary must still sweep (post-increment 0 is a multiple of N) - no skipped cycle"
    );
}

#[tokio::test]
async fn test_admission_charge_write_behind_under_runtime() {
    let store = crate::real_store::core().await;
    let mut k = sample_key("k1", "h1");
    k.group = Some("team".to_string());
    let gov = GovState::new_with_core(store.clone().core(), None, None)
        .await
        .unwrap();
    let cost = group_cost(30, &[("team", 1000, "total", None)]);

    assert!(gov.try_admit(&cost, &k, "", 1_700_000_000).is_ok());
    assert_eq!(
        store.ledger().get_usage("k1", 0).await.unwrap().requests,
        0,
        "write-behind: durable ledger untouched until a flush"
    );
    assert_eq!(gov.flush_budgets().await, 2, "key + group cells flushed");
    assert_eq!(
        store.ledger().get_usage("k1", 0).await.unwrap().requests,
        1,
        "the request-count delta lands durably after the flush"
    );
    assert_eq!(
        store
            .ledger()
            .get_usage("group:team@total", 0)
            .await
            .unwrap()
            .requests,
        1,
        "the group's window bucket flushed too"
    );

    assert!(gov.try_admit(&cost, &k, "", 1_700_000_000).is_ok());
}

#[tokio::test]
async fn test_negative_fee_and_rate_clamp_to_zero() {
    let store = crate::real_store::core().await;
    let mut k = sample_key("k1", "h1");
    k.group = Some("team".to_string());
    store.identity().put_key(&k).await.unwrap();
    let gov = GovState::new_with_core(store.clone().core(), None, None)
        .await
        .unwrap();

    let cost = {
        let groups: std::collections::BTreeMap<String, crate::config::GroupCfg> =
            std::collections::BTreeMap::from([(
                "team".to_string(),
                budget_group_cfg(100, "total", None),
            )]);
        crate::cost::CostModel::resolve_parts(None, -50, &groups)
    };

    for _ in 0..5 {
        assert!(gov.try_admit(&cost, &k, "", 1_700_000_000).is_ok());
    }
    let u = gov
        .usage_for_async(&cost, "k1", 1_700_000_000)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(u.spend_cents, 0, "negative fee clamps to 0 derived spend");
    assert_eq!(u.requests, 5, "requests are still counted");

    let neg_rate = card_cost("m", -100.0);
    gov.record_usage(&neg_rate, &k, "", "m", &tt(5000), 1_700_000_000);
    let refused = gov.usage_for_async(&neg_rate, "k1", 1_700_000_000).await;
    assert!(
        refused
            .as_ref()
            .is_err_and(|e| e.to_string().contains("names no price for class")),
        "a negative token rate is an unpriced class, and the read refuses: {refused:?}"
    );
    let tokens: u64 = gov
        .bucket_model_tokens_async("k1", crate::governance::WINDOW_TOTAL, 1_700_000_000)
        .await
        .unwrap()
        .iter()
        .flat_map(|(_, units)| units.values())
        .map(|n| n.whole_for_test())
        .sum();
    assert_eq!(tokens, 5000, "tokens are still counted");
}

#[tokio::test]
async fn test_create_key_minted_id_is_free_so_mint_succeeds() {
    let store = crate::real_store::core().await;
    let gov = GovState::new_with_core(store.clone(), None, None)
        .await
        .unwrap();
    let spec = NewKeySpec {
        name: "first".to_string(),
        allowed_pools: None,
        group: None,
        labels: std::collections::BTreeMap::new(),
        ..Default::default()
    };
    let (key, _secret) = {
        gov.set_signing_key(Some(self_serve_signer()));
        gov.mint_signed_async(spec, 4_000_000_000, 1_700_000_000)
            .await
    }
    .unwrap();
    assert!(key.id.starts_with("vk_"));

    assert_eq!(gov.lookup_by_sub(&key.id).unwrap().id, key.id);
}

#[tokio::test]
async fn test_update_key_toggles_enabled_and_rebinds_group_in_place() {
    let store = crate::real_store::core().await;
    let gov = GovState::new_with_core(store.clone(), None, None)
        .await
        .unwrap();
    let (key, _secret) = {
        gov.set_signing_key(Some(self_serve_signer()));
        gov.mint_signed_async(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: None,
                group: Some("growth".to_string()),
                labels: std::collections::BTreeMap::new(),
                ..Default::default()
            },
            4_000_000_000,
            1_700_000_000,
        )
        .await
    }
    .unwrap();
    assert!(key.enabled, "new key starts enabled");
    let hash = key.generation_hash.clone();

    let updated = gov
        .update_key_outcome_async(&key.id, Some(false), None)
        .await
        .unwrap()
        .expect("key exists");
    assert!(!updated.enabled, "key is now disabled");
    assert_eq!(
        updated.group.as_deref(),
        Some("growth"),
        "untouched binding preserved"
    );
    assert_eq!(updated.generation_hash, hash, "secret hash is not rotated");

    let looked = gov.lookup_by_sub(&key.id).unwrap();
    assert!(!looked.enabled, "lookup reflects the disabled key");

    let re = gov
        .update_key_outcome_async(&key.id, Some(true), Some(Some("acme".to_string())))
        .await
        .unwrap()
        .expect("key exists");
    assert!(re.enabled);
    assert_eq!(re.group.as_deref(), Some("acme"));

    let unbound = gov
        .update_key_outcome_async(&key.id, None, Some(None))
        .await
        .unwrap()
        .expect("key exists");
    assert_eq!(unbound.group, None, "inner None unbinds to no group");

    assert_eq!(
        store
            .identity()
            .get_key(&key.id)
            .await
            .unwrap()
            .unwrap()
            .group,
        None
    );

    assert!(gov
        .update_key_outcome_async("vk_does_not_exist", Some(false), None)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn test_compare_key_guards_silent_overwrite() {
    let store = crate::real_store::core().await;
    let incumbent = sample_key("vk_freshid", "HASH_A");
    store
        .identity()
        .compare_key(None, &incumbent)
        .await
        .expect("a free id must be allowed");
    store
        .identity()
        .compare_key(Some(&incumbent), &incumbent)
        .await
        .expect("an exact incumbent can be reasserted");
    let collision = sample_key("vk_freshid", "HASH_B_DIFFERENT");
    store
        .identity()
        .compare_key(None, &collision)
        .await
        .expect_err("a colliding id must never silently overwrite its incumbent");
    let still = store
        .identity()
        .get_key("vk_freshid")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        still.generation_hash, "HASH_A",
        "incumbent must not be clobbered"
    );
}

#[tokio::test]
async fn test_poisoned_budget_lock_recovers_not_panics() {
    let store = crate::real_store::core().await;
    let gov = Arc::new(
        GovState::new_with_core(store.core(), None, None)
            .await
            .unwrap(),
    );
    let cost = group_cost(1, &[("g", 2, "total", None)]);
    let mut k = sample_key("k1", "h1");
    k.group = Some("g".to_string());
    let now = 1_700_000_040;

    let g = gov.clone();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = g.budget.shard_lock_for("group:g@total").write().unwrap();
        panic!("intentional poison");
    }));
    assert!(
        gov.budget.shard_lock_for("group:g@total").is_poisoned(),
        "the group bucket's shard lock must be poisoned for the test"
    );

    assert!(
        gov.try_admit(&cost, &k, "", now).is_ok(),
        "1st admits after poison"
    );
    assert!(
        gov.try_admit(&cost, &k, "", now).is_ok(),
        "2nd admits after poison"
    );
    assert!(
        gov.try_admit(&cost, &k, "", now).is_err(),
        "2c cap still enforced on a recovered (poisoned) lock"
    );
}

#[tokio::test]
async fn test_poisoned_by_hash_lock_recovers_not_panics() {
    let store = crate::real_store::core().await;
    let k = sample_key("k1", "binding:k1:gen1");
    store.identity().put_key(&k).await.unwrap();
    let gov = Arc::new(GovState::new_with_core(store, None, None).await.unwrap());

    let g = gov.clone();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = g.caches.write().unwrap();
        panic!("intentional poison");
    }));
    assert!(gov.caches.is_poisoned(), "cache lock must be poisoned");

    assert_eq!(gov.lookup_by_sub("k1").unwrap().id, "k1");
    gov.refresh_async()
        .await
        .expect("refresh recovers the poisoned cache lock");
    assert_eq!(gov.lookup_by_sub("k1").unwrap().id, "k1");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_write_behind_flush_serializes_and_counts_exactly_once() {
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let store = Arc::new(FlakyStore::new().await);
    *store.before_add.lock().unwrap() = Some(Box::new(move || {
        Box::pin(async move {
            entered_tx.send(()).unwrap();
            release_rx.await.unwrap();
        })
    }));
    let gov = Arc::new(
        GovState::new_with_core(store.core(), None, None)
            .await
            .unwrap(),
    );
    let cost = flat_cost(1);
    let at = 1_700_000_000u64;
    let key = sample_key("k1", "h1");

    for _ in 0..3 {
        assert!(gov.try_admit(&cost, &key, "", at).is_ok());
    }
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);
    let flusher = crate::governance::spawn_budget_flusher(gov.clone(), shutdown_rx, None);

    entered_rx.await.unwrap();

    assert!(gov.try_admit(&cost, &key, "", at).is_ok());
    assert!(gov.try_admit(&cost, &key, "", at).is_ok());

    tokio::task::yield_now().await;

    release_tx.send(()).unwrap();

    shutdown_tx.send(()).unwrap();
    flusher.await.unwrap();

    let durable = store
        .inner
        .ledger()
        .get_usage("k1", 0)
        .await
        .unwrap()
        .requests;
    assert_eq!(
        durable, 5,
        "additive flushes must sum to exactly the accrued requests - no loss, no double count"
    );
}

#[tokio::test]
async fn a_self_serve_mint_for_another_subject_is_not_held_behind_one_parked_in_the_store() {
    let (store, faults) = native_identity_fixture().await;
    let gov = Arc::new(
        GovState::new_with_core(store.clone(), None, Some(self_serve_signer()))
            .await
            .unwrap(),
    );
    let now = 1_700_000_000;
    let (entered, release) = park_identity(&faults.park_commit);
    let alice_gov = gov.clone();
    let alice = tokio::spawn(async move {
        alice_gov
            .issue_self("oidc:alice", "corp", None, now + 3600, now)
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), entered)
        .await
        .unwrap()
        .unwrap();
    let bob = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        gov.issue_self("oidc:bob", "corp", None, now + 3600, now),
    )
    .await;
    release.send(()).unwrap();
    alice.await.unwrap().unwrap();
    bob.expect("bob must not wait for alice's parked native commit")
        .unwrap();
    assert!(self_binding_for(&gov, "oidc:alice").await.is_some());
    assert!(self_binding_for(&gov, "oidc:bob").await.is_some());
}

#[tokio::test]
async fn a_revoke_is_not_held_behind_a_reload_parked_in_the_store_and_the_reload_does_not_revert_it(
) {
    let (store, faults) = native_identity_fixture().await;
    let gov = Arc::new(
        GovState::new_with_core(store.clone(), None, Some(self_serve_signer()))
            .await
            .unwrap(),
    );
    let now = 1_700_000_000;
    let (key, token) = gov
        .issue_self("reload-race", "corp", None, now + 3600, now)
        .await
        .unwrap();
    let (entered, release) = park_identity(&faults.park_scan);
    let reload_gov = gov.clone();
    let reload = tokio::spawn(async move { reload_gov.refresh_async().await });
    tokio::time::timeout(std::time::Duration::from_secs(5), entered)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        gov.revoke_async(&key.id, "test"),
    )
    .await
    .expect("mutation cannot wait on parked reload")
    .unwrap();
    release.send(()).unwrap();
    reload.await.unwrap().unwrap();
    assert!(gov.verify_token(&token, now, None).is_none());
    assert!(gov.is_revoked(&key.id));
    assert!(!gov.lookup_by_sub(&key.id).unwrap().enabled);
}

#[tokio::test]
async fn a_reload_is_not_held_behind_a_revoke_parked_in_the_store() {
    let (store, faults) = native_identity_fixture().await;
    let gov = Arc::new(
        GovState::new_with_core(store.clone(), None, Some(self_serve_signer()))
            .await
            .unwrap(),
    );
    let now = 1_700_000_000;
    let (key, token) = gov
        .issue_self("revoke-race", "corp", None, now + 3600, now)
        .await
        .unwrap();
    let (entered, release) = park_identity(&faults.park_commit);
    let revoke_gov = gov.clone();
    let id = key.id.clone();
    let revoke = tokio::spawn(async move { revoke_gov.revoke_async(&id, "test").await });
    tokio::time::timeout(std::time::Duration::from_secs(5), entered)
        .await
        .unwrap()
        .unwrap();
    let reloaded =
        tokio::time::timeout(std::time::Duration::from_secs(5), gov.refresh_async()).await;
    release.send(()).unwrap();
    revoke.await.unwrap().unwrap();
    reloaded
        .expect("reload cannot wait on parked revoke")
        .unwrap();
    assert!(gov.is_revoked(&key.id));
    assert!(!gov.lookup_by_sub(&key.id).unwrap().enabled);
    assert!(gov.verify_token(&token, now, None).is_none());
}

#[tokio::test]
async fn test_chain_enforcement_rejects_naming_the_blocking_group() {
    let store = crate::real_store::core().await;
    let gov = GovState::new_with_core(store.clone().core(), None, None)
        .await
        .unwrap();
    let cost = group_cost(
        10,
        &[
            ("growth", 1_000_000, "month", None),
            ("bob", 25, "month", Some("growth")),
        ],
    );
    let mut k = sample_key("vk_bob", "h_bob");
    k.group = Some("bob".to_string());
    store.identity().put_key(&k).await.unwrap();
    let at = 1_700_000_000u64;

    let zero = group_cost(10, &[("broke", 0, "month", None)]);
    let mut kb = sample_key("vk_broke", "h_broke");
    kb.group = Some("broke".to_string());
    store.identity().put_key(&kb).await.unwrap();
    assert_eq!(
        gov.try_admit(&zero, &kb, "", at).unwrap_err(),
        LimitBlocked::Limit {
            group: "broke".to_string(),
            metric: "budget",
            window: Some("month"),
            pool: None,
            downgrade_to: None,
            retry_after: crate::governance::window_end("month", at)
                .map(|end| end.saturating_sub(at).max(1)),
        },
        "a zero-cap group blocks and the exact bucket is NAMED"
    );

    assert_eq!(
        gov.usage_for_async(&zero, "vk_broke", at)
            .await
            .unwrap()
            .unwrap()
            .requests,
        0
    );

    assert!(gov.try_admit(&cost, &k, "", at).is_ok());
    assert!(gov.try_admit(&cost, &k, "", at).is_ok());

    match gov.try_admit(&cost, &k, "", at).unwrap_err() {
        LimitBlocked::Limit {
            group,
            metric: "budget",
            window: Some("month"),
            ..
        } => assert_eq!(group, "bob"),
        other => panic!("expected bob's month budget to block, got {other:?}"),
    }
    gov.flush_budgets().await;
    assert_eq!(
        store
            .ledger()
            .get_usage("vk_bob", 0)
            .await
            .unwrap()
            .requests,
        2,
        "key attribution bucket charged (and only for the ADMITTED requests)"
    );
    let month_window = budget_window(WINDOW_MONTH, at);
    assert_eq!(
        store
            .ledger()
            .get_usage("group:bob@month", month_window)
            .await
            .unwrap()
            .requests,
        2,
        "group bucket charged in ITS OWN (month) window"
    );
    assert_eq!(
        store
            .ledger()
            .get_usage("group:growth@month", month_window)
            .await
            .unwrap()
            .requests,
        2,
        "the whole ancestor chain is charged atomically"
    );
}

#[tokio::test]
async fn test_group_token_spend_blocks_chain_admission() {
    let store = crate::real_store::core().await;
    let gov = GovState::new_with_core(store.clone().core(), None, None)
        .await
        .unwrap();

    let cost = card_and_group_cost("gpt-5", 100.0, &[("team", 100, "total", None)]);

    let mut k = sample_key("vk_t", "h_t");
    k.group = Some("team".to_string());
    store.identity().put_key(&k).await.unwrap();
    let at = 1_700_000_000u64;

    assert!(gov.try_admit(&cost, &k, "", at).is_ok());

    gov.record_usage(&cost, &k, "", "gpt-5", &tt(10_000), at);
    match gov.try_admit(&cost, &k, "", at).unwrap_err() {
        LimitBlocked::Limit {
            group,
            metric: "budget",
            window: Some("total"),
            pool: None,
            downgrade_to: None,
            retry_after: None,
        } => assert_eq!(group, "team"),
        other => panic!("expected team's budget to block, got {other:?}"),
    }
}

#[tokio::test]
async fn test_boundary_straddle_charge_never_rewinds_the_live_cell() {
    let store = crate::real_store::core().await;
    let gov = GovState::new_with_core(store.core(), None, None)
        .await
        .unwrap();

    let cost = card_and_group_cost("m", 100.0, &[("g", 150, "day", None)]);
    let mut k = sample_key("vk_straddle", "h_s");
    k.group = Some("g".to_string());
    let w0_late = 3 * crate::governance::SECS_PER_DAY - 5;
    let w1_early = 3 * crate::governance::SECS_PER_DAY + 5;
    let bucket = "group:g@day";

    gov.try_admit(&cost, &k, "", w1_early)
        .expect("fresh window admits");
    gov.record_usage(&cost, &k, "", "m", &tt(10_000), w1_early);
    let before = gov
        .derived_bucket_usage_async(&cost, bucket, WINDOW_DAY, true, w1_early)
        .await
        .unwrap();
    assert_eq!(
        (before.tokens.whole_for_test(), before.requests),
        (10_000, 1)
    );

    gov.try_admit(&cost, &k, "", w0_late)
        .expect("under-cap straddler admits");
    let after = gov
        .derived_bucket_usage_async(&cost, bucket, WINDOW_DAY, true, w1_early)
        .await
        .unwrap();
    assert_eq!(
        (after.tokens.whole_for_test(), after.requests),
        (10_000, 2),
        "the live window's ledger survives a straddling charge (no rewind); the straddler's \
         request lands in the live cell"
    );

    gov.record_usage(&cost, &k, "", "m", &tt(10_000), w1_early);
    match gov.try_admit(&cost, &k, "", w0_late).unwrap_err() {
        LimitBlocked::Limit {
            group,
            metric: "budget",
            ..
        } => assert_eq!(group, "g"),
        other => panic!(
            "a straddler must be checked against the live cell's derived spend, not a phantom \
             fresh window; got {other:?}"
        ),
    }
}

#[tokio::test]
async fn test_new_window_admission_rolls_the_stale_cell_fresh() {
    let store = crate::real_store::core().await;
    let gov = GovState::new_with_core(store.core(), None, None)
        .await
        .unwrap();
    let cost = card_and_group_cost("m", 100.0, &[("g", 150, "day", None)]);
    let mut k = sample_key("vk_roll", "h_r");
    k.group = Some("g".to_string());
    let bucket = "group:g@day";
    let day0 = 3 * crate::governance::SECS_PER_DAY + 100;
    let day5 = 8 * crate::governance::SECS_PER_DAY + 100;

    gov.try_admit(&cost, &k, "", day0).expect("day0 admits");
    gov.record_usage(&cost, &k, "", "m", &tt(20_000), day0);
    match gov.try_admit(&cost, &k, "", day0).unwrap_err() {
        LimitBlocked::Limit {
            group,
            metric: "budget",
            ..
        } => assert_eq!(group, "g"),
        other => panic!("day0 must be at-cap and block; got {other:?}"),
    }

    gov.try_admit(&cost, &k, "", day5)
        .expect("a genuinely new window must not be blocked by a stale window's exhausted cap");
    let after = gov
        .derived_bucket_usage_async(&cost, bucket, WINDOW_DAY, true, day5)
        .await
        .unwrap();
    assert_eq!(
        (after.tokens.whole_for_test(), after.requests),
        (0, 1),
        "the rolled cell must carry ONLY the new window's charge, not day 0's leftover spend"
    );
}

#[tokio::test]
async fn test_missing_group_fails_closed() {
    let store = crate::real_store::core().await;
    let gov = GovState::new_with_core(store.clone().core(), None, None)
        .await
        .unwrap();
    let cost = flat_cost(1);
    let mut k = sample_key("vk_g", "h_g");
    k.group = Some("ghost".to_string());
    store.identity().put_key(&k).await.unwrap();
    let at = 1_700_000_000u64;

    assert_eq!(
        gov.try_admit(&cost, &k, "", at).unwrap_err(),
        LimitBlocked::MissingGroup("ghost".to_string()),
        "an unresolvable chain is never admitted (fail closed), naming the missing group"
    );

    gov.record_usage(&cost, &k, "", "m", &tt(7), at);
    gov.flush_budgets().await;
    assert_eq!(
        ledger_tokens(&store, "vk_g", 0).await,
        7,
        "tokens are never lost"
    );
}

#[tokio::test]
async fn test_hydrate_budgets_restores_group_buckets() {
    let store: Arc<crate::persistence::facade::CoreStore> = crate::real_store::core().await;
    let card = || card_and_group_cost("m", 100.0, &[("team", 25, "total", None)]);
    let mut k = sample_key("vk_h", "h_h");
    k.group = Some("team".to_string());
    store.identity().put_key(&k).await.unwrap();
    let at = 1_700_000_000u64;

    {
        let gov = GovState::new_with_core(store.clone().core(), None, None)
            .await
            .unwrap();

        gov.record_usage(&card(), &k, "", "m", &tt(2_500), at);
        gov.flush_budgets().await;
    }

    let gov2 = GovState::new_with_core(store.clone().core(), None, None)
        .await
        .unwrap();
    gov2.hydrate_budgets_async(&card(), at)
        .await
        .expect("hydrate");
    match gov2.try_admit(&card(), &k, "", at).unwrap_err() {
        LimitBlocked::Limit {
            group,
            metric: "budget",
            ..
        } => assert_eq!(
            group, "team",
            "post-restart enforcement resumes from the PERSISTED group ledger (25c >= 25c cap)"
        ),
        other => panic!("expected the hydrated group budget to block, got {other:?}"),
    }
}

#[tokio::test]
#[allow(clippy::field_reassign_with_default)]
async fn test_hydrate_budgets_propagates_store_error() {
    let store = Arc::new(FlakyStore::new().await);
    let k = sample_key("vk_m9", "m9_h");
    store.identity().put_key(&k).await.unwrap();
    store
        .ledger()
        .put_usage(
            "vk_m9",
            budget_window(WINDOW_TOTAL, 0),
            &UsageLedger {
                requests: 1,
                billable_requests: 1,
                models: vec![],
            },
        )
        .await
        .ok();
    let gov = GovState::new_with_core(store.clone().core(), None, None)
        .await
        .unwrap();
    store.usage_read_down.store(true, Ordering::SeqCst);
    let err = gov
        .hydrate_budgets_async(&crate::cost::CostModel::flat(1), 0)
        .await
        .expect_err(
            "a store get_usage error must PROPAGATE (fail boot), not reset budgets to zero",
        );
    assert!(
        err.to_string().contains("Unavailable"),
        "the store error must surface verbatim; got: {err}"
    );
}

#[tokio::test]
async fn hydrate_budgets_never_writes_a_read_only_store_boots_like_a_writable_one() {
    let card = || card_and_group_cost("m", 100.0, &[("team", 25, "total", None)]);
    let mem = Arc::new(FlakyStore::new().await);
    let mut k = sample_key("vk_ro", "ro_h");
    k.group = Some("team".to_string());
    let writable = mem.clone();
    writable.identity().put_key(&k).await.unwrap();
    let at = 1_700_000_000u64;
    {
        let gov = GovState::new_with_core(writable.core(), None, None)
            .await
            .unwrap();
        gov.record_usage(&card(), &k, "", "m", &tt(2_500), at);
        gov.flush_budgets().await;
    }

    mem.readonly.store(true, Ordering::SeqCst);
    let ro = mem;
    let gov2 = GovState::new_with_core(ro.core(), None, None)
        .await
        .unwrap();
    gov2.hydrate_budgets_async(&card(), at)
        .await
        .expect("hydrate_budgets must succeed against a read-only store: it never writes");
    match gov2.try_admit(&card(), &k, "", at).unwrap_err() {
        LimitBlocked::Limit {
            group,
            metric: "budget",
            ..
        } => assert_eq!(
            group, "team",
            "post-restart enforcement resumes from the persisted ledger on a read-only store, \
             exactly as it does on a writable one"
        ),
        other => panic!("expected the hydrated group budget to block, got {other:?}"),
    }
}

#[tokio::test]
async fn test_hydrate_budgets_trusts_billable_requests_even_when_it_looks_like_a_refunded_window() {
    let store: Arc<crate::persistence::facade::CoreStore> = crate::real_store::core().await;
    let k = sample_key("vk_refunded", "refunded_h");
    store.identity().put_key(&k).await.unwrap();

    store
        .ledger()
        .put_usage(
            "vk_refunded",
            budget_window(WINDOW_TOTAL, 0),
            &UsageLedger {
                requests: 7,
                billable_requests: 0,
                models: vec![],
            },
        )
        .await
        .unwrap();
    let gov = GovState::new_with_core(store.core(), None, None)
        .await
        .unwrap();
    gov.hydrate_budgets_async(&flat_cost(1), 0)
        .await
        .expect("hydrate");
    {
        let cell = gov.budget.read("vk_refunded");
        let cell = cell.get("vk_refunded").expect("hydrated cell exists");
        assert_eq!(
            cell.requests, 7,
            "requests is always trusted verbatim from the ledger"
        );
        assert_eq!(
            cell.billable_requests, 0,
            "billable_requests must be trusted verbatim too - re-deriving it from requests here is \
             exactly the bug this test guards against (it would silently re-bill a refunded window \
             on every restart)"
        );
    }
    let store2: Arc<crate::persistence::facade::CoreStore> = crate::real_store::core().await;
    let k2 = sample_key("vk_split", "split_h");
    store2.identity().put_key(&k2).await.unwrap();
    store2
        .ledger()
        .put_usage(
            "vk_split",
            budget_window(WINDOW_TOTAL, 0),
            &UsageLedger {
                requests: 7,
                billable_requests: 3,
                models: vec![],
            },
        )
        .await
        .unwrap();
    let gov2 = GovState::new_with_core(store2.core(), None, None)
        .await
        .unwrap();
    gov2.hydrate_budgets_async(&flat_cost(1), 0)
        .await
        .expect("hydrate");
    let cell2_billable = gov2
        .budget
        .read("vk_split")
        .get("vk_split")
        .expect("hydrated cell exists")
        .billable_requests;
    assert_eq!(
        cell2_billable, 3,
        "a normal partially-billable row must keep its own billable_requests, verbatim"
    );
}

#[tokio::test]
async fn test_budget_state_projects_the_whole_chain() {
    let store = crate::real_store::core().await;
    let gov = GovState::new_with_core(store.clone().core(), None, None)
        .await
        .unwrap();
    let cost = group_cost(
        10,
        &[
            ("acme", 1_000, "month", None),
            ("growth", 500, "month", Some("acme")),
        ],
    );
    let mut k = sample_key("vk_s", "h_s");
    k.group = Some("growth".to_string());
    store.identity().put_key(&k).await.unwrap();
    let at = 1_700_000_000u64;

    assert!(gov.try_admit(&cost, &k, "", at).is_ok());
    let state = gov.budget_state(&cost, &k, at);
    assert_eq!(state.len(), 3, "key + growth@month + acme@month");
    assert_eq!(state[0].bucket_id, "vk_s");
    assert_eq!(state[0].budget_group, None);
    assert_eq!(
        state[0].spend_micros_at_current_rate,
        10 * 10_000,
        "key bucket: 1 request x 10c fee = 100_000 micros"
    );
    assert_eq!(
        state[0].remaining_micros, None,
        "keys carry no cap: remaining is None"
    );
    assert_eq!(state[0].budget_period, "total");
    assert_eq!(state[1].bucket_id, "group:growth@month");
    assert_eq!(state[1].budget_group.as_deref(), Some("growth"));
    assert_eq!(
        state[1].spend_micros_at_current_rate,
        10 * 10_000,
        "the fee counts into the group bucket's own derived spend too"
    );
    assert_eq!(
        state[1].remaining_micros,
        Some(500 * 10_000 - 10 * 10_000),
        "remaining under growth's 500c cap after one 10c fee"
    );
    assert_eq!(state[1].budget_period, "month");
    assert_eq!(state[2].bucket_id, "group:acme@month");
}

mod signed_token {
    use super::{signed_kind, ISSUED_SHAPE};
    use crate::governance::signing::{TokenSigner, DEFAULT_KID};
    use crate::governance::{GovState, NewKeySpec, ScopeRef};
    use std::sync::Arc;

    async fn gov() -> Arc<GovState> {
        let store = crate::real_store::core().await;
        let signer = TokenSigner::from_secret_bytes(&[9u8; 32], DEFAULT_KID);
        let g = GovState::new_with_core(store, Some("admintok".into()), Some(signer))
            .await
            .expect("gov");

        g.set_at_rest_keys(Some(crate::governance::at_rest::AtRestKeys::new(
            &[3u8; 32], None,
        )));
        Arc::new(g)
    }

    fn spec(name: &str, group: Option<&str>, pools: Option<Vec<&str>>) -> NewKeySpec {
        NewKeySpec {
            name: name.into(),
            allowed_pools: pools.map(|p| p.into_iter().map(str::to_string).collect()),
            group: group.map(str::to_string),
            labels: std::collections::BTreeMap::new(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn production_audience_mint_preserves_binding_and_refuses_wrong_unscoped_expired_and_revoked_use(
    ) {
        let g = gov().await;
        let audience = "https://gateway.example/v1/realtime";
        let (binding, token) = g
            .mint_signed_for_audience_async(
                spec("scoped", None, Some(vec!["fast"])),
                2_000,
                1_000,
                audience,
            )
            .await
            .expect("production scoped mint");
        let token = token.expose(&crate::seal::lend());
        let actual = g
            .verify_token(token, 1_001, Some(audience))
            .expect("correct audience");
        assert_eq!(actual.id, binding.id);
        assert_eq!(actual.generation_hash, binding.generation_hash);
        assert_eq!(actual.allowed_scopes, binding.allowed_scopes);
        assert!(g.verify_token(token, 1_001, None).is_none());
        assert!(g
            .verify_token(token, 1_001, Some("https://other.example/v1/realtime"))
            .is_none());
        assert!(g.verify_token(token, 2_000, Some(audience)).is_none());
        g.revoke_async(&binding.id, "test revocation")
            .await
            .expect("revoke real binding");
        assert!(g.verify_token(token, 1_001, Some(audience)).is_none());

        let (_, plain) = g
            .mint_signed_async(spec("plain", None, None), 2_000, 1_000)
            .await
            .expect("ordinary mint");
        let plain = plain.expose(&crate::seal::lend());
        assert!(g.verify_token(plain, 1_001, None).is_some());
        assert!(g.verify_token(plain, 1_001, Some(audience)).is_none());
        assert!(g
            .mint_signed_for_audience_async(spec("empty", None, None), 2_000, 1_000, " ")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn audience_bound_token_is_confined_to_its_plane_through_govstate() {
        use crate::governance::signing::TokenVerifier;

        let g = gov().await;
        let plane_x = "https://busbar.example.com/plane-x";
        let (binding, plain) = g
            .mint_signed_async(spec("agent", None, Some(vec!["fast"])), 2_000, 1_000)
            .await
            .expect("mint");

        let signer = TokenSigner::from_secret_bytes(&[9u8; 32], DEFAULT_KID);
        let verifier = TokenVerifier::single(signer.kid(), signer.verifying_key());
        let generation = verifier
            .verify(plain.expose(&crate::seal::lend()), 1_000, None)
            .expect("plain claims")
            .generation;
        let bound =
            signer.mint_for_audience(&binding.id, 2_000, generation.as_deref(), plane_x, None);

        assert!(g
            .verify_token(plain.expose(&crate::seal::lend()), 1_000, None)
            .is_some());
        assert!(
            g.verify_token(&bound, 1_000, None).is_none(),
            "an audience-bound token must be rejected on the data plane even with a valid binding"
        );

        assert!(g.verify_token(&bound, 1_000, Some(plane_x)).is_some());
        assert!(
            g.verify_token(plain.expose(&crate::seal::lend()), 1_000, Some(plane_x))
                .is_none(),
            "a plain data-plane key must be rejected on an audience-checked ingress"
        );
    }

    #[tokio::test]
    async fn mint_then_verify_resolves_the_binding() {
        let g = gov().await;
        let (binding, token) = g
            .mint_signed_async(
                spec("bob", Some("growth"), Some(vec!["fast"])),
                2_000,
                1_000,
            )
            .await
            .expect("mint");
        assert!(
            token.expose(&crate::seal::lend()).starts_with("bbk_"),
            "token carries the prefix"
        );
        assert!(binding.id.starts_with("vk_"));
        assert_eq!(binding.group.as_deref(), Some("growth"));
        assert_eq!(binding.allowed_scopes, Some(vec![ScopeRef::pool("fast")]));

        let resolved = g
            .verify_token(token.expose(&crate::seal::lend()), 1_500, None)
            .expect("verify");
        assert_eq!(resolved.id, binding.id);
        assert_eq!(resolved.group.as_deref(), Some("growth"));
    }

    #[tokio::test]
    async fn no_group_key_is_authed_unlimited() {
        let g = gov().await;
        let (_b, token) = g
            .mint_signed_async(spec("free", None, None), 2_000, 1_000)
            .await
            .expect("mint");
        let resolved = g
            .verify_token(token.expose(&crate::seal::lend()), 1_500, None)
            .expect("verify");
        assert_eq!(resolved.group, None);

        assert!(resolved.allowed_scopes.is_none());
    }

    #[tokio::test]
    async fn expired_token_is_rejected() {
        let g = gov().await;
        let (_b, token) = g
            .mint_signed_async(spec("bob", None, None), 1_000, 500)
            .await
            .expect("mint");
        assert!(
            g.verify_token(token.expose(&crate::seal::lend()), 999, None)
                .is_some(),
            "valid before exp"
        );
        assert!(
            g.verify_token(token.expose(&crate::seal::lend()), 1_000, None)
                .is_none(),
            "rejected at exp"
        );
        assert!(
            g.verify_token(token.expose(&crate::seal::lend()), 5_000, None)
                .is_none(),
            "rejected past exp"
        );
    }

    #[tokio::test]
    async fn tampered_token_is_rejected() {
        let g = gov().await;
        let (_b, token) = g
            .mint_signed_async(spec("bob", None, None), 2_000, 1_000)
            .await
            .expect("mint");
        let mut chars: Vec<char> = token.expose(&crate::seal::lend()).chars().collect();

        let mid = chars.len() / 2;
        chars[mid] = if chars[mid] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();
        assert!(g.verify_token(&tampered, 1_500, None).is_none());
    }

    #[tokio::test]
    async fn revoke_denylists_and_keeps_binding() {
        let g = gov().await;
        let (binding, token) = g
            .mint_signed_async(spec("bob", None, None), 2_000, 1_000)
            .await
            .expect("mint");
        assert!(g
            .verify_token(token.expose(&crate::seal::lend()), 1_500, None)
            .is_some());
        g.revoke_async(&binding.id, "test").await.expect("revoke");
        g.revoke_async(&binding.id, "again")
            .await
            .expect("idempotent");
        assert!(g.is_revoked(&binding.id));
        assert!(
            g.verify_token(token.expose(&crate::seal::lend()), 1_500, None)
                .is_none(),
            "a revoked subject's token is rejected"
        );

        assert!(g
            .all_keys_async()
            .await
            .unwrap()
            .iter()
            .any(|k| k.id == binding.id));
    }

    #[tokio::test]
    async fn revocation_survives_restart() {
        let store = crate::real_store::core().await;
        let signer = TokenSigner::from_secret_bytes(&[9u8; 32], DEFAULT_KID);
        let g = Arc::new(
            GovState::new_with_core(store.clone(), Some("t".into()), Some(signer))
                .await
                .unwrap(),
        );
        let (binding, token) = g
            .mint_signed_async(spec("bob", None, None), 5_000, 1_000)
            .await
            .expect("mint");
        g.revoke_async(&binding.id, "test").await.expect("revoke");

        let signer2 = TokenSigner::from_secret_bytes(&[9u8; 32], DEFAULT_KID);
        let g2 = Arc::new(
            GovState::new_with_core(store, Some("t".into()), Some(signer2))
                .await
                .unwrap(),
        );
        assert!(g2.is_revoked(&binding.id), "denylist re-hydrated at boot");
        assert!(
            g2.verify_token(token.expose(&crate::seal::lend()), 1_500, None)
                .is_none(),
            "the revoked token is still rejected after restart"
        );
    }

    #[tokio::test]
    async fn token_verifies_across_shared_key_and_fails_after_rotation() {
        let store_a = crate::real_store::core().await;
        let key_a = TokenSigner::from_secret_bytes(&[1u8; 32], DEFAULT_KID);
        let node_a = Arc::new(
            GovState::new_with_core(store_a.clone(), Some("t".into()), Some(key_a))
                .await
                .unwrap(),
        );
        let (binding, token) = node_a
            .mint_signed_async(spec("bob", None, None), 5_000, 1_000)
            .await
            .expect("mint");

        let store_b = crate::real_store::core().await;
        {
            store_b.identity().put_key(&binding).await.unwrap();
        }
        let key_b_same = TokenSigner::from_secret_bytes(&[1u8; 32], DEFAULT_KID);
        let node_b = Arc::new(
            GovState::new_with_core(store_b.clone(), Some("t".into()), Some(key_b_same))
                .await
                .unwrap(),
        );
        assert!(
            node_b
                .verify_token(token.expose(&crate::seal::lend()), 1_500, None)
                .is_some(),
            "a token signed by the shared key verifies on another node"
        );

        let key_b_rotated = TokenSigner::from_secret_bytes(&[2u8; 32], DEFAULT_KID);
        let node_b2 = Arc::new(
            GovState::new_with_core(store_b, Some("t".into()), Some(key_b_rotated))
                .await
                .unwrap(),
        );
        assert!(
            node_b2
                .verify_token(token.expose(&crate::seal::lend()), 1_500, None)
                .is_none(),
            "after rotation, a token signed by the old key is rejected (revoke-all)"
        );
    }

    #[tokio::test]
    async fn mint_with_aws_issues_token_and_credential() {
        let g = gov().await;
        let (binding, token, akid, secret) = g
            .mint_signed_with_credential_async(
                spec("bob", None, None),
                2_000,
                1_000,
                &signed_kind(),
                &ISSUED_SHAPE,
            )
            .await
            .expect("mint+aws");
        assert!(token.expose(&crate::seal::lend()).starts_with("bbk_"));
        assert!(akid.starts_with("AKIA"));
        assert!(!secret.expose(&crate::seal::lend()).is_empty());

        let (resolved_key, _cred) = g
            .lookup_credential(&crate::governance::tests::signed_kind(), &akid)
            .expect("akid resolves");
        assert_eq!(resolved_key.id, binding.id);
    }

    #[tokio::test]
    async fn mint_with_aws_secrets_never_print() {
        let g = gov().await;
        let minted = g
            .mint_signed_with_credential_async(
                spec("bob", None, None),
                2_000,
                1_000,
                &signed_kind(),
                &ISSUED_SHAPE,
            )
            .await
            .expect("mint+aws");
        let token = minted.1.expose(&crate::seal::lend()).clone();
        let aws_secret = minted.3.expose(&crate::seal::lend()).clone();
        assert!(!token.is_empty() && !aws_secret.is_empty());
        let printed = [
            format!("{:?}", minted.1),
            format!("{}", minted.1),
            format!("{:?}", minted.3),
            format!("{}", minted.3),
            format!("{minted:?}"),
        ];
        for out in &printed {
            assert!(!out.contains(&token), "token leaked through a print");
            assert!(
                !out.contains(&aws_secret),
                "AWS secret leaked through a print"
            );
        }
        assert!(printed[4].contains("[REDACTED]"));
        let (_, cred) = g
            .lookup_credential(&crate::governance::tests::signed_kind(), &minted.2)
            .expect("akid resolves");

        assert!(cred.secret.starts_with("v1:aead:"), "stored in the clear");
        assert!(!cred.secret.contains(&aws_secret));
        let (read, live) =
            g.credential_secret(&crate::governance::tests::signed_kind(), &minted.2, 1_500);
        assert!(live);
        assert_eq!(read.expose(&crate::seal::lend()), &aws_secret);
    }

    #[tokio::test]
    async fn mint_without_signer_fails_closed() {
        let store = crate::real_store::core().await;
        let g = Arc::new(
            GovState::new_with_core(store, Some("t".into()), None)
                .await
                .unwrap(),
        );
        assert!(!g.signing_enabled());
        let err = g
            .mint_signed_async(spec("bob", None, None), 2_000, 1_000)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no signing key"), "got {err}");
    }

    #[tokio::test]
    async fn local_revoke_rejects_the_very_next_auth_attempt() {
        let g = gov().await;
        let base = busbar_kernel::store::now();
        let (binding, token) = g
            .mint_signed_async(spec("bob", None, None), base + 10_000, base)
            .await
            .expect("mint");
        assert!(
            g.verify_token(token.expose(&crate::seal::lend()), base + 1, None)
                .is_some(),
            "admitted before the revoke"
        );

        g.revoke_async(&binding.id, "compromised")
            .await
            .expect("revoke");

        assert!(
            g.verify_token(token.expose(&crate::seal::lend()), base + 1, None)
                .is_none(),
            "the very next signed-token check after a local revoke must reject — no window"
        );
        assert!(
            g.is_revoked_at(&binding.id, base + 1),
            "the predicate the legacy-hash and signed-request admit paths consult must agree immediately"
        );
    }

    #[tokio::test]
    async fn peer_revoke_written_to_the_store_is_honoured_within_the_window() {
        use crate::governance::REVOCATION_SYNC_TTL_SECS;
        let store = crate::real_store::core().await;
        let signer = TokenSigner::from_secret_bytes(&[9u8; 32], DEFAULT_KID);
        let g = Arc::new(
            GovState::new_with_core(store.clone(), Some("t".into()), Some(signer))
                .await
                .unwrap(),
        );
        let base = busbar_kernel::store::now();
        let (binding, token) = g
            .mint_signed_async(spec("bob", None, None), base + 10_000, base)
            .await
            .expect("mint");
        assert!(
            g.verify_token(token.expose(&crate::seal::lend()), base, None)
                .is_some(),
            "admitted at mint"
        );

        store
            .identity()
            .add_denylist(&binding.id, "revoked by a peer node")
            .await
            .expect("peer revoke persists");

        assert!(
            g.verify_token(token.expose(&crate::seal::lend()), base, None)
                .is_some(),
            "inside the staleness window the cached set still governs (documented)"
        );

        let past = base + REVOCATION_SYNC_TTL_SECS + 2;
        g.is_revoked_at(&binding.id, past);
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while g.denylist.synced_at() < past {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("peer revocation refresh completes");
        assert!(
            g.verify_token(token.expose(&crate::seal::lend()), past, None)
                .is_none(),
            "a peer's revoke must be honoured within REVOCATION_SYNC_TTL_SECS ({REVOCATION_SYNC_TTL_SECS}s)"
        );
        assert!(
            g.is_revoked_at(&binding.id, past),
            "the signed-request/legacy-hash admit predicate re-syncs on the same window"
        );
    }

    #[tokio::test]
    async fn rotate_invalidates_the_outstanding_signed_token() {
        let g = gov().await;
        let (binding, old_token) = g
            .mint_signed_async(spec("bob", Some("growth"), None), 9_000, 1_000)
            .await
            .expect("mint");
        assert!(
            g.verify_token(old_token.expose(&crate::seal::lend()), 1_500, None)
                .is_some(),
            "valid at mint"
        );

        let rotated = g
            .rotate_key_outcome_async(&binding.id, 9_000)
            .await
            .expect("rotate")
            .expect("known id");
        let crate::governance::RotatedCredential { key, token, .. } = rotated;

        assert_eq!(
            key.id, binding.id,
            "the subject id is stable across rotation"
        );
        assert_eq!(
            key.group.as_deref(),
            Some("growth"),
            "policy carries over untouched"
        );
        assert!(
            g.verify_token(old_token.expose(&crate::seal::lend()), 1_500, None)
                .is_none(),
            "the PRE-ROTATION token must be rejected immediately after rotate"
        );
        assert!(
            g.verify_token(token.expose(&crate::seal::lend()), 1_500, None)
                .is_some(),
            "the re-minted token authenticates"
        );
    }
}

#[tokio::test]
async fn delete_key_drops_its_budget_cell() {
    let store = crate::real_store::core().await;
    let gov = GovState::new_with_core(store.core(), None, None)
        .await
        .unwrap();
    let cost = flat_cost(7);
    let key = sample_key("vk_doomed", "hs-doomed");
    gov.core_store()
        .unwrap()
        .identity()
        .put_key(&key)
        .await
        .expect("put");
    gov.refresh_async().await.expect("refresh");

    gov.record_usage(&cost, &key, "prod", "m", &tt(10), 1_700_000_000);
    assert!(
        gov.budget.read(&key.id).contains_key(&key.id),
        "precondition: use accrues an attribution cell"
    );

    gov.delete_key(&key.id).await.expect("delete");
    assert!(
        !gov.budget.read(&key.id).contains_key(&key.id),
        "the deleted key's budget cell is reclaimed, not retained for the process lifetime"
    );
}

#[tokio::test]
async fn test_budget_sweep_evicts_idle_attribution_cells_but_never_group_caps() {
    let store = crate::real_store::core().await;
    let gov = GovState::new_with_core(store.core(), None, None)
        .await
        .unwrap();
    let now = 1_700_000_040u64;
    let idle_for = 40 * SECS_PER_DAY;

    let survivor = sample_key("survivor", "hs");

    let all_time = |requests: u64, dirty: bool, last_touch: u64| BudgetCell {
        flushing_windows: Default::default(),
        correction: None,
        group_owners: Default::default(),
        flushing: 0,
        window_start: 0,
        requests,
        billable_requests: requests,
        flushed_requests: requests,
        flushed_billable_requests: requests,
        models: Vec::new(),
        fee_eras: Default::default(),
        flushed_fee_eras: Default::default(),
        rolled: Vec::new(),
        rolled_eras: Vec::new(),
        dirty,
        last_touch,
    };

    {
        let mut map = gov.budget.write("survivor");

        map.insert(
            "vk_deleted".to_string(),
            all_time(17, false, now - idle_for),
        );
        map.insert(
            "user:alice@example.com".to_string(),
            all_time(3, false, now - idle_for),
        );

        map.insert(
            "group:acme@total".to_string(),
            all_time(4999, false, now - idle_for),
        );

        map.insert(
            "vk_unflushed".to_string(),
            all_time(9, true, now - idle_for),
        );
    }

    gov.budget.sweep_ticker_for("survivor").store(
        crate::config::DEFAULT_RATE_SWEEP_INTERVAL - 1,
        Ordering::Relaxed,
    );
    let cost = crate::cost::CostModel::resolve_parts(
        None,
        1,
        &std::collections::BTreeMap::from([(
            "acme".to_string(),
            budget_group_cfg(5000, "total", None),
        )]),
    );
    assert!(gov.try_admit(&cost, &survivor, "", now).is_ok());

    let map = gov.budget.read("survivor");
    assert!(
        !map.contains_key("vk_deleted"),
        "an idle, fully-flushed key attribution cell must not be retained forever"
    );
    assert!(
        !map.contains_key("user:alice@example.com"),
        "a synthesized principal's cell has no other removal path and must age out"
    );
    assert_eq!(
        map.get("group:acme@total").map(|c| c.requests),
        Some(4999),
        "an enforced group cap must never be reset by the sweep"
    );
    assert_eq!(
        map.get("vk_unflushed").map(|c| c.requests),
        Some(9),
        "an unflushed cell must be retained until its delta lands"
    );
    assert!(
        map.contains_key("survivor"),
        "the cell just charged is not idle"
    );
}

#[tokio::test]
async fn test_hydrated_cells_survive_the_first_sweep() {
    let store = crate::real_store::core().await;
    let restored = sample_key("restored", "hr");
    store.identity().put_key(&restored).await.unwrap();
    store
        .ledger()
        .add_usage(
            "restored",
            0,
            &busbar_contract::records::UsageDelta {
                requests: 42,
                billable_requests: 42,
                models: Vec::new(),
            },
        )
        .await
        .unwrap();

    let gov = GovState::new_with_core(store.core(), None, None)
        .await
        .unwrap();
    let now = 1_700_000_040u64;
    gov.hydrate_budgets_async(&flat_cost(1), now).await.unwrap();
    assert_eq!(
        gov.budget
            .read("restored")
            .get("restored")
            .map(|c| c.requests),
        Some(42),
        "hydrate seeds the cell"
    );

    let driver = sample_key("restored", "hr");
    gov.budget.sweep_ticker_for("restored").store(
        crate::config::DEFAULT_RATE_SWEEP_INTERVAL - 1,
        Ordering::Relaxed,
    );
    assert!(gov.try_admit(&flat_cost(1), &driver, "", now).is_ok());

    assert_eq!(
        gov.budget
            .read("restored")
            .get("restored")
            .map(|c| c.requests),
        Some(43),
        "a hydrated cell must not be swept away before it is first used"
    );
}

mod metering_fanout {
    use super::*;
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn metering_write_fanout_is_bounded_at_one() {
        let store = std::sync::Arc::new(FlakyStore::new().await);
        let gov = std::sync::Arc::new(
            GovState::new_with_core(store.clone().core(), None, None)
                .await
                .unwrap(),
        );
        let now = 1_700_100_000u64;
        let n = 8usize;
        let mut handles = Vec::new();
        for i in 0..n {
            let gov = gov.clone();
            handles.push(tokio::spawn(async move {
                let usage = busbar_contract::billing::TokenUsage {
                    input: 1,
                    output: 1,
                    ..Default::default()
                };
                gov.record_metering(&format!("vk_{i}"), "m", "p", Some(&usage), now);
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        let flushed = gov.flush_metering().await;
        assert_eq!(
            flushed, n,
            "every distinct key's delta was written on the one flush"
        );
        assert!(
            store.meter_high_water.load(Ordering::SeqCst) <= 1,
            "add_metering must never see more than one call in flight (observed {})",
            store.meter_high_water.load(Ordering::SeqCst)
        );
        assert_eq!(
            store.meter_calls.load(Ordering::SeqCst),
            n,
            "one add_metering call per distinct key, all eventually accounted"
        );
    }

    #[tokio::test]
    async fn a_store_error_requeues_without_double_counting() {
        let store = std::sync::Arc::new(FlakyStore::new().await);
        store.meter_fail_n.store(1, Ordering::SeqCst);
        let gov = GovState::new_with_core(store.clone().core(), None, None)
            .await
            .unwrap();
        let now = 1_700_200_000u64;
        let usage = busbar_contract::billing::TokenUsage {
            input: 10,
            output: 5,
            ..Default::default()
        };
        gov.record_metering("vk_err", "m", "p", Some(&usage), now);

        let n1 = gov.flush_metering().await;
        assert_eq!(n1, 0, "the failed flush wrote nothing");
        let rows = gov.metering_for_async(metering_bucket(now)).await.unwrap();
        assert!(rows.is_empty(), "a failed flush must not partially land");

        let n2 = gov.flush_metering().await;
        assert_eq!(n2, 1, "the requeued entry flushes on the next tick");
        let rows = gov.metering_for_async(metering_bucket(now)).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            (
                stored_whole_for_test(rows[0].tokens_input, rows[0].scale),
                rows[0].requests
            ),
            (10, 1),
            "the full delta landed exactly once, not zero and not twice"
        );

        let n3 = gov.flush_metering().await;
        assert_eq!(
            n3, 0,
            "a third flush writes nothing — the entry is gone, not duplicated"
        );
    }

    #[tokio::test]
    async fn flush_metering_skips_a_genuinely_all_zero_entry() {
        let store = crate::real_store::core().await;
        let gov = GovState::new_with_core(store.core(), None, None)
            .await
            .unwrap();
        let now = 1_700_300_000u64;
        let key = (
            "vk_zero".to_string(),
            metering_bucket(now),
            "m".to_string(),
            "p".to_string(),
            0u64,
            String::new(),
            String::new(),
        );

        gov.pending_metering.accrue(key, MeterCounts::default());

        let flushed = gov.flush_metering().await;
        assert_eq!(flushed, 0, "an all-zero entry must not count as flushed");
        let rows = gov.metering_for_async(metering_bucket(now)).await.unwrap();
        assert!(
            rows.is_empty(),
            "an all-zero entry must never become a store row"
        );
    }

    #[tokio::test]
    async fn a_failed_flush_keeps_each_pinned_groups_units_through_retry() {
        let store = Arc::new(FlakyStore::new().await);
        store.meter_fail_n.store(1, Ordering::SeqCst);
        let gov = GovState::new_with_core(store.core(), None, None)
            .await
            .unwrap();
        let cost = plane_fee_cost(1_000);
        let mut key = sample_key("same-key", "h");
        let units = [("search_units".to_owned(), 3)].into();
        key.group = Some("first".into());
        gov.record_usage_served(&cost, &key, "", "m", Some("p"), &units, AT);
        assert_eq!(
            gov.flush_metering().await,
            0,
            "first write fails without committing"
        );
        key.group = Some("second".into());
        gov.record_usage_served(&cost, &key, "", "m", Some("p"), &units, AT);
        assert_eq!(gov.flush_metering().await, 2);
        let counts: std::collections::BTreeMap<_, _> = gov
            .metering_for_async(metering_bucket(AT))
            .await
            .unwrap()
            .into_iter()
            .map(|row| {
                (
                    row.key_group_at_use,
                    Count::from_stored(row.usage_units["search_units"], row.scale)
                        .unwrap()
                        .whole_for_test(),
                )
            })
            .collect();
        assert_eq!(counts, [("first".into(), 3), ("second".into(), 3)].into());
        assert_eq!(
            gov.flush_metering().await,
            0,
            "retry commits each count once"
        );
    }
}

fn self_serve_signer() -> crate::governance::signing::TokenSigner {
    crate::governance::signing::TokenSigner::from_secret_bytes(
        &[3u8; 32],
        crate::governance::signing::DEFAULT_KID,
    )
}

async fn self_binding_for(gov: &GovState, user_sub: &str) -> Option<VirtualKey> {
    let group = format!("{SELF_KEY_GROUP_PREFIX}{user_sub}");
    gov.all_keys_async()
        .await
        .unwrap()
        .into_iter()
        .find(|k| k.enabled && k.deleted_at.is_none() && k.group.as_deref() == Some(group.as_str()))
}

#[tokio::test]
async fn refresh_self_failed_atomic_commit_keeps_the_old_binding() {
    let (store, faults) = native_identity_fixture().await;
    let gov = GovState::new_with_core(store.clone(), None, Some(self_serve_signer()))
        .await
        .unwrap();
    let now = 1_700_000_000;
    let sub = "oidc:alice";
    let (old, old_token) = gov
        .issue_self(sub, "corp", None, now + 3600, now)
        .await
        .unwrap();
    faults.fail_writes.store(true, Ordering::SeqCst);
    gov.refresh_self(sub, "corp", None, now + 3600, now)
        .await
        .expect_err("native replacement and tombstone must commit atomically");
    let rows = store.identity().list_keys().await.unwrap();
    assert_eq!(rows.len(), 1, "no stranded replacement is written");
    assert_eq!(rows[0], old);
    assert_eq!(self_binding_for(&gov, sub).await.unwrap().id, old.id);
    assert!(gov.verify_token(&old_token, now, None).is_some());
}

#[tokio::test]
async fn self_serve_key_records_idp_subject_and_user_bound_mode() {
    let store = crate::real_store::core().await;
    let gov = GovState::new_with_core(store, None, Some(self_serve_signer()))
        .await
        .unwrap();
    let sub = "oidc:carol";
    let now = 1_700_000_000u64;

    let (binding, token) = gov
        .issue_self(sub, "corp", None, now + 3600, now)
        .await
        .unwrap();
    assert_eq!(
        binding.idp_subject.as_deref(),
        Some(sub),
        "the personal key records the IdP subject for attribution"
    );
    assert_eq!(binding.binding_mode.as_deref(), Some("user-bound"));
    assert_eq!(
        binding.minted_by, None,
        "a self-minted personal token has no separate minter provenance"
    );

    assert!(gov.verify_token(&token, now, None).is_some());

    let (rotated, _t) = gov
        .refresh_self(sub, "corp", None, now + 3600, now)
        .await
        .unwrap();
    assert_eq!(rotated.idp_subject.as_deref(), Some(sub));
    assert_eq!(rotated.binding_mode.as_deref(), Some("user-bound"));
}

#[tokio::test]
async fn refresh_self_tombstones_the_old_binding_on_success() {
    let store = crate::real_store::core().await;
    let gov = GovState::new_with_core(store, None, Some(self_serve_signer()))
        .await
        .unwrap();
    let sub = "oidc:bob";
    let now = 1_700_000_000u64;

    let (_first_binding, first_token) = gov
        .issue_self(sub, "corp", None, now + 3600, now)
        .await
        .unwrap();
    let (second_binding, second_token) = gov
        .refresh_self(sub, "corp", None, now + 3600, now)
        .await
        .unwrap();

    assert!(
        gov.verify_token(&first_token, now, None).is_none(),
        "the prior token must stop verifying after a successful refresh"
    );
    assert!(gov.verify_token(&second_token, now, None).is_some());
    let surviving = self_binding_for(&gov, sub)
        .await
        .expect("the new binding exists");
    assert_eq!(surviving.id, second_binding.id);
}

#[tokio::test]
async fn self_refresh_publishes_atomic_binding_transfer_without_postcommit_scan() {
    let (store, faults) = native_identity_fixture().await;
    let gov = GovState::new_with_core(store.clone(), None, Some(self_serve_signer()))
        .await
        .unwrap();
    let now = 1_700_000_000;
    let sub = "oidc:alice";
    let (old, old_token) = gov
        .issue_self(sub, "corp", None, now + 3600, now)
        .await
        .unwrap();
    faults.fail_scans_after_commit.store(true, Ordering::SeqCst);
    let (new, token) = gov
        .refresh_self(sub, "corp", None, now + 3600, now)
        .await
        .unwrap();
    assert_ne!(old.id, new.id);
    assert!(gov.verify_token(&old_token, now, None).is_none());
    assert!(gov.verify_token(&token, now, None).is_some());
    assert!(store
        .identity()
        .get_key(&old.id)
        .await
        .unwrap()
        .unwrap()
        .deleted_at
        .is_some());
    faults.fail_scans.store(false, Ordering::SeqCst);
    let live: Vec<_> = store
        .identity()
        .list_keys()
        .await
        .unwrap()
        .into_iter()
        .filter(|k| k.enabled && k.deleted_at.is_none())
        .collect();
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].id, new.id);
}

#[tokio::test]
async fn default_self_refresh_publishes_when_the_derived_id_is_reused() {
    let (store, faults) = native_identity_fixture().await;
    let gov = GovState::new_with_core(store.clone(), None, Some(self_serve_signer()))
        .await
        .unwrap();
    let now = 1_700_000_000;
    let sub = "oidc:alice";
    let (old, old_token) = gov
        .issue_self(sub, "corp", None, now + 3600, now)
        .await
        .unwrap();
    let (epoch_one, _) = gov
        .refresh_self(sub, "corp", None, now + 3600, now)
        .await
        .unwrap();
    let mut rotated = gov
        .rotate_key_outcome_async(&epoch_one.id, now + 3600)
        .await
        .unwrap()
        .unwrap()
        .key;
    rotated.generation_hash = binding_marker(&rotated.id, "admin-rotation");
    store.identity().put_key(&rotated).await.unwrap();
    gov.refresh_async().await.unwrap();
    let prior = self_serve_signer().mint(&rotated.id, now + 3600, Some("admin-rotation"));
    assert!(gov.verify_token(&prior, now, None).is_some());
    faults.fail_scans_after_commit.store(true, Ordering::SeqCst);
    let (binding, token) = gov
        .refresh_self(sub, "corp", None, now + 3600, now)
        .await
        .unwrap();
    assert_eq!(
        binding.id, epoch_one.id,
        "retain the default same-id policy"
    );
    assert!(gov.verify_token(&token, now, None).is_some());
    assert!(gov.verify_token(&prior, now, None).is_none());
    assert_ne!(old.id, binding.id);
    assert!(gov.verify_token(&old_token, now, None).is_none());
}

#[tokio::test]
async fn key_mutation_waits_for_the_same_key_claim_but_allows_another_key() {
    let store = crate::real_store::core().await;
    let gov = Arc::new(
        GovState::new_with_core(store, None, Some(self_serve_signer()))
            .await
            .unwrap(),
    );
    let now = 1_700_000_000;
    let (first, _) = gov
        .issue_self("claim-a", "corp", None, now + 3600, now)
        .await
        .unwrap();
    let (second, _) = gov
        .issue_self("claim-b", "corp", None, now + 3600, now)
        .await
        .unwrap();
    let held = gov.identity_key_guard(&first.id).await;
    let waiting = gov.observe_identity_mutation_wait();
    let first_gov = gov.clone();
    let id = first.id.clone();
    let blocked = tokio::spawn(async move {
        first_gov
            .update_key_outcome_async(&id, None, Some(Some("outer".into())))
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !waiting.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(!blocked.is_finished());
    gov.update_key_outcome_async(&second.id, Some(false), None)
        .await
        .unwrap();
    drop(held);
    let changed = blocked.await.unwrap().unwrap().unwrap();
    assert!(changed.enabled);
    assert_eq!(changed.group.as_deref(), Some("outer"));
    assert!(!gov.lookup_by_sub(&second.id).unwrap().enabled);
}

#[tokio::test]
async fn self_subject_and_admin_key_mutations_complete_without_a_claim_cycle() {
    let (store, faults) = native_identity_fixture().await;
    let gov = Arc::new(
        GovState::new_with_core(store.clone(), None, Some(self_serve_signer()))
            .await
            .unwrap(),
    );
    let now = 1_700_000_000;
    let (key, _) = gov
        .issue_self("claim-cycle", "corp", None, now + 3600, now)
        .await
        .unwrap();
    let (entered, release) = park_identity(&faults.park_commit);
    let admin_gov = gov.clone();
    let id = key.id.clone();
    let admin = tokio::spawn(async move {
        admin_gov
            .update_key_outcome_async(&id, None, Some(Some("outer".into())))
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), entered)
        .await
        .unwrap()
        .unwrap();
    let login_gov = gov.clone();
    let login = tokio::spawn(async move {
        login_gov
            .issue_self(
                "claim-cycle",
                "corp",
                Some(vec!["narrow".into()]),
                now + 3600,
                now,
            )
            .await
    });
    tokio::task::yield_now().await;
    release.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        admin.await.unwrap().unwrap();
        login.await.unwrap()
    })
    .await
    .expect("native claims must not form a cycle")
    .unwrap();
    assert_eq!(store.identity().list_keys().await.unwrap().len(), 1);
}

#[tokio::test]
async fn self_scope_update_preserves_a_newer_durable_generation() {
    let store = crate::real_store::core().await;
    let first = GovState::new_with_core(store.clone(), None, Some(self_serve_signer()))
        .await
        .unwrap();
    let now = 1_700_000_000;
    let (old, old_token) = first
        .issue_self("stale", "corp", None, now + 3600, now)
        .await
        .unwrap();
    let second = GovState::new_with_core(store.clone(), None, Some(self_serve_signer()))
        .await
        .unwrap();
    let rotated = second
        .rotate_key_outcome_async(&old.id, now + 3600)
        .await
        .unwrap()
        .unwrap();
    let (updated, _) = first
        .issue_self(
            "stale",
            "corp",
            Some(vec!["narrow".into()]),
            now + 3600,
            now,
        )
        .await
        .unwrap();
    assert_eq!(updated.generation_hash, rotated.key.generation_hash);
    assert_eq!(
        store
            .identity()
            .get_key(&old.id)
            .await
            .unwrap()
            .unwrap()
            .generation_hash,
        rotated.key.generation_hash
    );
    assert!(first.verify_token(&old_token, now, None).is_none());
    let (_, current_token) = first
        .issue_self(
            "stale",
            "corp",
            Some(vec!["narrow".into()]),
            now + 3600,
            now,
        )
        .await
        .unwrap();
    assert!(first.verify_token(&current_token, now, None).is_some());
    second
        .update_key_outcome_async(&old.id, Some(false), None)
        .await
        .unwrap();
    assert!(first
        .issue_self("stale", "corp", None, now + 3600, now)
        .await
        .is_err());
    assert!(
        !store
            .identity()
            .get_key(&old.id)
            .await
            .unwrap()
            .unwrap()
            .enabled
    );
}

#[tokio::test]
async fn durable_disable_is_published_without_postcommit_scan() {
    let (store, faults) = native_identity_fixture().await;
    let gov = GovState::new_with_core(store.clone(), None, Some(self_serve_signer()))
        .await
        .unwrap();
    let now = 1_700_000_000;
    let sub = "oidc:alice";
    let (old, old_token) = gov
        .issue_self(sub, "corp", None, now + 3600, now)
        .await
        .unwrap();
    faults.fail_scans_after_commit.store(true, Ordering::SeqCst);
    gov.update_key_outcome_async(&old.id, Some(false), None)
        .await
        .unwrap();
    assert!(
        !store
            .identity()
            .get_key(&old.id)
            .await
            .unwrap()
            .unwrap()
            .enabled
    );
    assert!(gov.verify_token(&old_token, now, None).is_none());
}

#[tokio::test]
async fn deletion_eviction_cannot_be_reversed_by_an_older_reload() {
    let (store, faults) = native_identity_fixture().await;
    let gov = Arc::new(
        GovState::new_with_core(store.clone(), None, Some(self_serve_signer()))
            .await
            .unwrap(),
    );
    let now = 1_700_000_000;
    let (key, token) = gov
        .issue_self("reload-race", "corp", None, now + 3600, now)
        .await
        .unwrap();
    let (entered, release) = park_identity(&faults.park_scan);
    let reload_gov = gov.clone();
    let reload = tokio::spawn(async move { reload_gov.refresh_async().await });
    tokio::time::timeout(std::time::Duration::from_secs(5), entered)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        gov.delete_key_outcome_async(&key.id),
    )
    .await
    .expect("mutation cannot wait on parked reload")
    .unwrap();
    release.send(()).unwrap();
    reload.await.unwrap().unwrap();
    assert!(gov.verify_token(&token, now, None).is_none());
    assert!(gov.lookup_by_sub(&key.id).is_none());
    assert!(store
        .identity()
        .get_key(&key.id)
        .await
        .unwrap()
        .unwrap()
        .deleted_at
        .is_some());
}

#[tokio::test]
async fn partial_revoke_immediately_retires_the_durable_credential() {
    let (store, faults) = native_identity_fixture().await;
    let gov = GovState::new_with_core(store.clone(), None, Some(self_serve_signer()))
        .await
        .unwrap();
    gov.set_at_rest_keys(Some(crate::governance::at_rest::AtRestKeys::new(
        &[3; 32], None,
    )));
    let (key, _, public_id, _) = gov
        .mint_signed_with_credential_async(
            NewKeySpec::default(),
            4_000_000_000,
            1,
            &signed_kind(),
            &ISSUED_SHAPE,
        )
        .await
        .unwrap();
    assert!(gov.lookup_credential(&signed_kind(), &public_id).is_some());
    // Denylist and credential retirement apply, then the key patch is refused.
    faults.refuse_after.store(3, Ordering::SeqCst);
    assert!(gov.revoke_async(&key.id, "test").await.is_err());
    assert!(store
        .identity()
        .list_credentials(&key.id)
        .await
        .unwrap()
        .iter()
        .all(|c| c.revoked_at.is_some()));
    assert!(gov.lookup_credential(&signed_kind(), &public_id).is_none());
    assert!(gov.is_revoked(&key.id));
    gov.revoke_async(&key.id, "retry").await.unwrap();
    assert!(gov.lookup_credential(&signed_kind(), &public_id).is_none());
    assert!(
        !store
            .identity()
            .get_key(&key.id)
            .await
            .unwrap()
            .unwrap()
            .enabled
    );
}

#[tokio::test]
async fn refresh_self_evicts_old_binding_without_postcommit_scan() {
    let (store, faults) = native_identity_fixture().await;
    let gov = GovState::new_with_core(store.clone(), None, Some(self_serve_signer()))
        .await
        .unwrap();
    let now = 1_700_000_000;
    let sub = "oidc:alice";
    let (old, old_token) = gov
        .issue_self(sub, "corp", None, now + 3600, now)
        .await
        .unwrap();
    faults.fail_scans_after_commit.store(true, Ordering::SeqCst);
    let (new, token) = gov
        .refresh_self(sub, "corp", None, now + 3600, now)
        .await
        .unwrap();
    assert_ne!(old.id, new.id);
    assert!(gov.verify_token(&old_token, now, None).is_none());
    assert!(gov.verify_token(&token, now, None).is_some());
    assert!(store
        .identity()
        .get_key(&old.id)
        .await
        .unwrap()
        .unwrap()
        .deleted_at
        .is_some());
    faults.fail_scans.store(false, Ordering::SeqCst);
    let live: Vec<_> = store
        .identity()
        .list_keys()
        .await
        .unwrap()
        .into_iter()
        .filter(|k| k.enabled && k.deleted_at.is_none())
        .collect();
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].id, new.id);
}

#[tokio::test]
async fn mint_self_offloaded_issues_and_refreshes_through_native_async_identity() {
    let store = crate::real_store::core().await;
    let gov = Arc::new(
        GovState::new_with_core(store, None, Some(self_serve_signer()))
            .await
            .unwrap(),
    );
    let sub = "oidc:offloaded";
    let now = 1_700_000_000u64;

    let (issued, issued_token) = crate::governance::mint_self_offloaded(
        gov.clone(),
        crate::governance::SelfMintOp::Issue,
        sub.to_string(),
        "corp".to_string(),
        None,
        now + 3600,
        now,
    )
    .await
    .expect("issue via the async wrapper succeeds");
    assert!(gov.verify_token(&issued_token, now, None).is_some());
    assert_eq!(
        issued.group.as_deref(),
        Some(format!("user:{sub}").as_str())
    );

    let (refreshed, refreshed_token) = crate::governance::mint_self_offloaded(
        gov.clone(),
        crate::governance::SelfMintOp::Refresh,
        sub.to_string(),
        "corp".to_string(),
        None,
        now + 7200,
        now,
    )
    .await
    .expect("refresh via the async wrapper succeeds");
    assert_ne!(
        issued.id, refreshed.id,
        "refresh rotates to a new binding id"
    );
    assert!(
        gov.verify_token(&issued_token, now, None).is_none(),
        "the native refresh still tombstones the prior token"
    );
    assert!(gov.verify_token(&refreshed_token, now, None).is_some());
}

#[tokio::test]
async fn mint_self_async_preserves_a_native_commit_failure() {
    let (store, faults) = native_identity_fixture().await;
    let gov = Arc::new(
        GovState::new_with_core(store.clone(), None, Some(self_serve_signer()))
            .await
            .unwrap(),
    );
    faults.fail_writes.store(true, Ordering::SeqCst);
    let result = crate::governance::mint_self_offloaded(
        gov.clone(),
        crate::governance::SelfMintOp::Issue,
        "refused".into(),
        "corp".into(),
        None,
        2000,
        1000,
    )
    .await;
    assert!(matches!(result, Err(SelfMintError::Store(_))));
    assert!(store.identity().list_keys().await.unwrap().is_empty());
    assert!(gov.all_keys_async().await.unwrap().is_empty());
}

// Fault injection decorates the real primitive backend, never domain methods.
type IdentityPark = (
    tokio::sync::oneshot::Sender<()>,
    tokio::sync::oneshot::Receiver<()>,
);
#[derive(Default)]
struct NativeIdentityFaults {
    park_commit: std::sync::Mutex<Option<IdentityPark>>,
    park_scan: std::sync::Mutex<Option<IdentityPark>>,
    refuse_after: std::sync::atomic::AtomicUsize,
    fail_writes: std::sync::atomic::AtomicBool,
    fail_scans: std::sync::atomic::AtomicBool,
    fail_scans_after_commit: std::sync::atomic::AtomicBool,
}
struct NativeIdentityBackend {
    inner: Arc<dyn busbar_contract::persistence::PersistenceBackend>,
    faults: Arc<NativeIdentityFaults>,
}
impl busbar_contract::persistence::PersistenceBackend for NativeIdentityBackend {
    fn info(&self) -> busbar_contract::persistence::BackendInfo {
        self.inner.info()
    }
    fn read(
        &self,
        request: Arc<busbar_contract::persistence::Read>,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::ReadResult> {
        self.inner.read(request)
    }
    fn scan(
        &self,
        request: Arc<busbar_contract::persistence::Scan>,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::Page> {
        Box::pin(async move {
            if self.faults.fail_scans.load(Ordering::SeqCst) {
                return Err(busbar_contract::persistence::Failure::Refused);
            }
            let response = self.inner.scan(request).await;
            let park = self.faults.park_scan.lock().unwrap().take();
            if let Some((entered, release)) = park {
                let _ = entered.send(());
                let _ = release.await;
            }
            response
        })
    }
    fn clock(
        &self,
        dataset: busbar_contract::persistence::DatasetId,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::ClockObservation>
    {
        self.inner.clock(dataset)
    }
    // `fetch_update` is deprecated in favour of `try_update` (Rust 1.95+); this crate's
    // MSRV floor is below 1.95, so keep the older name.
    #[allow(deprecated)]
    fn commit(
        &self,
        candidate: busbar_contract::persistence::PreparedCandidate,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::Decision> {
        Box::pin(async move {
            if self.faults.fail_writes.load(Ordering::SeqCst) {
                return Err(busbar_contract::persistence::Failure::Refused);
            }
            if self
                .faults
                .refuse_after
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                    left.checked_sub(1)
                })
                .is_ok_and(|left| left == 1)
            {
                return Err(busbar_contract::persistence::Failure::Refused);
            }
            let park = self.faults.park_commit.lock().unwrap().take();
            if let Some((entered, release)) = park {
                let _ = entered.send(());
                let _ = release.await;
            }
            let result = self.inner.commit(candidate).await;
            if matches!(
                result,
                Ok(busbar_contract::persistence::Decision::Applied(_))
            ) && self
                .faults
                .fail_scans_after_commit
                .swap(false, Ordering::SeqCst)
            {
                self.faults.fail_scans.store(true, Ordering::SeqCst);
            }
            result
        })
    }
}
fn park_identity(
    slot: &std::sync::Mutex<Option<IdentityPark>>,
) -> (
    tokio::sync::oneshot::Receiver<()>,
    tokio::sync::oneshot::Sender<()>,
) {
    let (entered_tx, entered) = tokio::sync::oneshot::channel();
    let (release, release_rx) = tokio::sync::oneshot::channel();
    *slot.lock().unwrap() = Some((entered_tx, release_rx));
    (entered, release)
}
async fn native_identity_fixture() -> (
    Arc<crate::persistence::facade::CoreStore>,
    Arc<NativeIdentityFaults>,
) {
    let faults = Arc::new(NativeIdentityFaults::default());
    let core = crate::real_store::core_over(Arc::new(NativeIdentityBackend {
        inner: crate::real_store::native_backend().await,
        faults: faults.clone(),
    }))
    .await;
    (core, faults)
}

#[tokio::test]
async fn signed_mints_publish_exact_applied_rows_without_postcommit_refresh() {
    for issued in [false, true] {
        let (store, faults) = native_identity_fixture().await;
        let gov = GovState::new_with_core(store.clone(), None, Some(self_serve_signer()))
            .await
            .unwrap();
        gov.set_at_rest_keys(Some(crate::governance::at_rest::AtRestKeys::new(
            &[3; 32], None,
        )));
        faults.fail_scans_after_commit.store(true, Ordering::SeqCst);
        let spec = NewKeySpec {
            name: "applied-mint".into(),
            ..Default::default()
        };
        let (key, token, credential) = if issued {
            let (key, token, public_id, _) = gov
                .mint_signed_with_credential_async(spec, 2000, 1000, &signed_kind(), &ISSUED_SHAPE)
                .await
                .unwrap();
            (key, token, Some(public_id))
        } else {
            let (key, token) = gov.mint_signed_async(spec, 2000, 1000).await.unwrap();
            (key, token, None)
        };
        assert_eq!(gov.lookup_by_sub(&key.id).unwrap().id, key.id);
        assert!(gov
            .verify_token(token.expose(&crate::seal::lend()), 1500, None)
            .is_some());
        assert_eq!(
            store.identity().get_key(&key.id).await.unwrap().unwrap(),
            key
        );
        if let Some(public_id) = credential {
            assert!(gov.lookup_credential(&signed_kind(), &public_id).is_some());
        }
        faults.fail_scans.store(false, Ordering::SeqCst);
        assert_eq!(store.identity().list_keys().await.unwrap().len(), 1);
        assert_eq!(
            store
                .identity()
                .list_credentials_since(0)
                .await
                .unwrap()
                .len(),
            usize::from(issued)
        );
        gov.delete_key_outcome_async(&key.id).await.unwrap();
        assert!(gov.lookup_by_sub(&key.id).is_none());
    }
}

#[tokio::test]
async fn signed_mints_do_not_claim_applied_when_the_write_fails() {
    for issued in [false, true] {
        let (store, faults) = native_identity_fixture().await;
        let gov = GovState::new_with_core(store.clone(), None, Some(self_serve_signer()))
            .await
            .unwrap();
        gov.set_at_rest_keys(Some(crate::governance::at_rest::AtRestKeys::new(
            &[3; 32], None,
        )));
        faults.fail_writes.store(true, Ordering::SeqCst);
        let spec = NewKeySpec {
            name: "refused-mint".into(),
            ..Default::default()
        };
        let error = if issued {
            gov.mint_signed_with_credential_async(spec, 2000, 1000, &signed_kind(), &ISSUED_SHAPE)
                .await
                .unwrap_err()
                .to_string()
        } else {
            gov.mint_signed_async(spec, 2000, 1000)
                .await
                .unwrap_err()
                .to_string()
        };
        assert!(!error.contains("MINT APPLIED"));
        assert!(store.identity().list_keys().await.unwrap().is_empty());
        assert!(store
            .identity()
            .list_credentials_since(0)
            .await
            .unwrap()
            .is_empty());
    }
}

#[tokio::test]
async fn delete_applied_commit_retires_old_credential_without_postcommit_refresh() {
    let (store, faults) = native_identity_fixture().await;
    let gov = GovState::new_with_core(store.clone(), None, Some(self_serve_signer()))
        .await
        .unwrap();
    let (key, token) = gov
        .mint_signed_async(
            NewKeySpec {
                name: "retire".into(),
                ..Default::default()
            },
            2000,
            1000,
        )
        .await
        .unwrap();
    assert!(gov
        .verify_token(token.expose(&crate::seal::lend()), 1500, None)
        .is_some());
    faults.fail_scans_after_commit.store(true, Ordering::SeqCst);
    gov.delete_key_outcome_async(&key.id).await.unwrap();
    assert!(gov
        .verify_token(token.expose(&crate::seal::lend()), 1500, None)
        .is_none());
    let durable = store.identity().get_key(&key.id).await.unwrap().unwrap();
    assert!(durable.deleted_at.is_some());
}

#[tokio::test]
async fn rotate_applied_commit_retires_old_credential_without_postcommit_refresh() {
    let (store, faults) = native_identity_fixture().await;
    let gov = GovState::new_with_core(store.clone(), None, Some(self_serve_signer()))
        .await
        .unwrap();
    let (key, token) = gov
        .mint_signed_async(
            NewKeySpec {
                name: "retire".into(),
                ..Default::default()
            },
            2000,
            1000,
        )
        .await
        .unwrap();
    assert!(gov
        .verify_token(token.expose(&crate::seal::lend()), 1500, None)
        .is_some());
    faults.fail_scans_after_commit.store(true, Ordering::SeqCst);
    gov.rotate_key_outcome_async(&key.id, 3000)
        .await
        .unwrap()
        .unwrap();
    assert!(gov
        .verify_token(token.expose(&crate::seal::lend()), 1500, None)
        .is_none());
    let durable = store.identity().get_key(&key.id).await.unwrap().unwrap();
    assert_ne!(durable.generation_hash, key.generation_hash);
}

#[tokio::test]
async fn test_budget_sweep_only_exempts_group_cells_that_still_enforce_a_cap() {
    let store = crate::real_store::core().await;
    let gov = GovState::new_with_core(store.core(), None, None)
        .await
        .unwrap();
    let now = 1_700_000_040u64;
    let max_window = 31 * SECS_PER_DAY;
    let survivor = sample_key("survivor3", "hs3");

    let groups: std::collections::BTreeMap<String, crate::config::GroupCfg> =
        std::collections::BTreeMap::from([
            ("capped".to_string(), budget_group_cfg(5000, "total", None)),
            ("uncapped".to_string(), crate::config::GroupCfg::default()),
        ]);
    let cost = crate::cost::CostModel::resolve_parts(None, 1, &groups);

    let idle = || BudgetCell {
        flushing_windows: Default::default(),
        correction: None,
        group_owners: Default::default(),
        flushing: 0,
        window_start: 0,
        requests: 7,
        billable_requests: 7,
        flushed_requests: 7,
        flushed_billable_requests: 7,
        models: Vec::new(),
        fee_eras: Default::default(),
        flushed_fee_eras: Default::default(),
        rolled: Vec::new(),
        rolled_eras: Vec::new(),
        dirty: false,
        last_touch: now - max_window - 1,
    };
    {
        let mut map = gov.budget.write("survivor3");
        map.insert("group:capped@total".to_string(), idle());
        map.insert("group:gone@total".to_string(), idle());
        map.insert("group:uncapped@total".to_string(), idle());

        map.insert("group:gone@month".to_string(), {
            let mut c = idle();
            c.window_start = 0;
            c.dirty = true;
            c
        });
    }

    gov.budget.sweep_ticker_for("survivor3").store(
        crate::config::DEFAULT_RATE_SWEEP_INTERVAL - 1,
        Ordering::Relaxed,
    );
    assert!(
        gov.try_admit(&cost, &survivor, "", now).is_ok(),
        "key admits"
    );

    let map = gov.budget.read("survivor3");
    assert!(
        map.contains_key("group:capped@total"),
        "a cell that STILL backs an enforced cap must never be aged out — its spend must not reset"
    );
    assert!(
        !map.contains_key("group:gone@total"),
        "a DELETED group's cell enforces nothing; pinning it forever is a pure leak"
    );
    assert!(
        !map.contains_key("group:uncapped@total"),
        "an auto-provisioned group with NO cap enforces nothing either — same leak, one per subject"
    );
    assert!(
        map.contains_key("group:gone@month"),
        "a still-DIRTY cell is protected by the dirty check regardless of its group"
    );
}

#[tokio::test]
async fn test_reclaim_group_cells_drops_every_window_and_scope_of_that_group() {
    let store = crate::real_store::core().await;
    let gov = GovState::new_with_core(store.core(), None, None)
        .await
        .unwrap();
    let now = 1_700_000_040u64;
    let cell = BudgetCell {
        flushing_windows: Default::default(),
        correction: None,
        group_owners: Default::default(),
        flushing: 0,
        window_start: 0,
        requests: 1,
        billable_requests: 1,
        flushed_requests: 1,
        flushed_billable_requests: 1,
        models: Vec::new(),
        fee_eras: Default::default(),
        flushed_fee_eras: Default::default(),
        rolled: Vec::new(),
        rolled_eras: Vec::new(),
        dirty: false,
        last_touch: now,
    };

    for id in [
        "group:doomed@total",
        "group:doomed@month",
        "group:doomed@day#pool:frontier",
    ] {
        let mut owned = cell.clone();
        owned.group_owners.insert("doomed".to_string());
        gov.budget.write(id).insert(id.to_string(), owned);
    }

    for id in ["group:keeper@total", "group:doomed-2@total"] {
        gov.budget.write(id).insert(id.to_string(), cell.clone());
    }

    assert_eq!(
        gov.reclaim_group_cells("doomed"),
        3,
        "every window/scope cell of the deleted group is reclaimed"
    );
    for id in [
        "group:doomed@total",
        "group:doomed@month",
        "group:doomed@day#pool:frontier",
    ] {
        assert!(!gov.budget.read(id).contains_key(id), "{id} must be gone");
    }
    for id in ["group:keeper@total", "group:doomed-2@total"] {
        assert!(
            gov.budget.read(id).contains_key(id),
            "{id} must be untouched — a name-prefix neighbour is not the same group"
        );
    }
    assert_eq!(
        gov.reclaim_group_cells("doomed"),
        0,
        "idempotent: a second reclamation of the same group drops nothing"
    );
}

#[tokio::test]
async fn test_reclaim_group_cells_drops_the_per_group_concurrent_gauge() {
    use crate::config::groups::{LimitCfg, LimitMetric};
    let store = crate::real_store::core().await;
    let gov = GovState::new_with_core(store.core(), None, None)
        .await
        .unwrap();
    let now = 1_700_000_040u64;

    let concurrent_group = || crate::config::GroupCfg {
        enabled: true,
        limits: vec![LimitCfg {
            metric: LimitMetric::Concurrent,
            amount: 4,
            per: None,
            scope: None,
            on_exhaust: None,
            downgrade_to: None,
            admission: None,
            on_exhaustion: None,
        }],
        ..Default::default()
    };

    const N: usize = 50;
    let groups: std::collections::BTreeMap<String, crate::config::GroupCfg> = (0..N)
        .map(|i| (format!("churny-{i}"), concurrent_group()))
        .collect();
    let cost = crate::cost::CostModel::resolve_parts(None, 0, &groups);

    for i in 0..N {
        let mut key = sample_key(&format!("k-{i}"), &format!("h-{i}"));
        key.group = Some(format!("churny-{i}"));
        let grant = gov
            .try_admit(&cost, &key, "", now)
            .expect("a capped group with an unused gauge admits");
        assert_eq!(grant.held(), 1, "one concurrent hold was taken");
        drop(grant);
    }

    assert_eq!(
        gov.concurrent
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .len(),
        N,
        "every admitted capped group materialised exactly one gauge entry"
    );

    for i in 0..N {
        gov.reclaim_group_cells(&format!("churny-{i}"));
    }
    assert!(
        gov.concurrent
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .is_empty(),
        "a deleted group's concurrent gauge must be reclaimed — the map is bounded, not monotonic"
    );

    let mut revived = sample_key("k-revived", "h-revived");
    revived.group = Some("churny-0".to_string());
    let grant = gov
        .try_admit(&cost, &revived, "", now)
        .expect("a re-created capped group admits cleanly");
    assert_eq!(
        gov.concurrent_in_flight("churny-0"),
        1,
        "fresh gauge at one"
    );
    drop(grant);
}

#[tokio::test]
async fn test_sweep_exemption_survives_a_group_name_containing_the_id_delimiters() {
    let store = crate::real_store::core().await;
    let gov = GovState::new_with_core(store.core(), None, None)
        .await
        .unwrap();
    let now = 1_700_000_040u64;
    let max_window = 31 * SECS_PER_DAY;
    let survivor = sample_key("survivor-delim", "hs-delim");

    let groups: std::collections::BTreeMap<String, crate::config::GroupCfg> =
        std::collections::BTreeMap::from([
            (
                "user:alice@corp.com".to_string(),
                budget_group_cfg(50000, "total", None),
            ),
            (
                "team#eng".to_string(),
                budget_group_cfg(50000, "total", None),
            ),
            ("user:alice".to_string(), crate::config::GroupCfg::default()),
        ]);
    let cost = crate::cost::CostModel::resolve_parts(None, 1, &groups);

    let idle = || BudgetCell {
        flushing_windows: Default::default(),
        correction: None,
        group_owners: Default::default(),
        flushing: 0,
        window_start: 0,
        requests: 7,
        billable_requests: 7,
        flushed_requests: 7,
        flushed_billable_requests: 7,
        models: Vec::new(),
        fee_eras: Default::default(),
        flushed_fee_eras: Default::default(),
        rolled: Vec::new(),
        rolled_eras: Vec::new(),
        dirty: false,
        last_touch: now - max_window - 1,
    };
    {
        let mut map = gov.budget.write("survivor-delim");
        map.insert("group:user:alice@corp.com@total".to_string(), idle());
        map.insert("group:team#eng@total".to_string(), idle());
    }

    gov.budget.sweep_ticker_for("survivor-delim").store(
        crate::config::DEFAULT_RATE_SWEEP_INTERVAL - 1,
        Ordering::Relaxed,
    );
    assert!(
        gov.try_admit(&cost, &survivor, "", now).is_ok(),
        "key admits"
    );

    let map = gov.budget.read("survivor-delim");
    assert!(
        map.contains_key("group:user:alice@corp.com@total"),
        "an EMAIL-named group's all-time budget cell still backs an enforced cap; sweeping it \
         resets lifetime spend to 0 on the next read (hydrate is boot-only) and an EXHAUSTED cap \
         starts admitting again"
    );
    assert!(
        map.contains_key("group:team#eng@total"),
        "a group name containing the SCOPE delimiter `#` is capped just the same"
    );
}

#[tokio::test]
async fn test_reclaim_group_cells_never_takes_a_longer_name_that_shares_the_at_prefix() {
    let store = crate::real_store::core().await;
    let gov = GovState::new_with_core(store.core(), None, None)
        .await
        .unwrap();
    let now = 1_700_000_040u64;
    let cell = BudgetCell {
        flushing_windows: Default::default(),
        correction: None,
        group_owners: Default::default(),
        flushing: 0,
        window_start: 0,
        requests: 1,
        billable_requests: 1,
        flushed_requests: 1,
        flushed_billable_requests: 1,
        models: Vec::new(),
        fee_eras: Default::default(),
        flushed_fee_eras: Default::default(),
        rolled: Vec::new(),
        rolled_eras: Vec::new(),
        dirty: false,
        last_touch: now,
    };
    for (id, owner) in [
        ("group:user:alice@total", "user:alice"),
        ("group:user:alice@day#pool:frontier", "user:alice"),
        ("group:user:alice@corp.com@total", "user:alice@corp.com"),
        (
            "group:user:alice@corp.com@day#pool:frontier",
            "user:alice@corp.com",
        ),
    ] {
        let mut owned = cell.clone();
        owned.group_owners.insert(owner.to_string());
        gov.budget.write(id).insert(id.to_string(), owned);
    }

    assert_eq!(
        gov.reclaim_group_cells("user:alice"),
        2,
        "ONLY the deleted group's own cells: `user:alice@corp.com` is a different group"
    );
    for id in [
        "group:user:alice@corp.com@total",
        "group:user:alice@corp.com@day#pool:frontier",
    ] {
        assert!(
            gov.budget.read(id).contains_key(id),
            "{id} belongs to a live, capped group and must survive the deletion of `user:alice`"
        );
    }

    assert_eq!(
        gov.reclaim_group_cells("user:alice@corp.com"),
        2,
        "the longer name reclaims its own two cells"
    );
}

#[tokio::test]
async fn an_admin_deletion_of_a_self_serve_key_survives_the_next_login() {
    let store = crate::real_store::core().await;
    let gov = GovState::new_with_core(store, None, Some(self_serve_signer()))
        .await
        .unwrap();
    let sub = "oidc:carol";
    let now = 1_700_000_000u64;

    let (first, first_token) = gov
        .issue_self(sub, "corp", None, now + 3600, now)
        .await
        .unwrap();
    assert!(gov.verify_token(&first_token, now, None).is_some());

    gov.delete_key(&first.id).await.unwrap();
    assert!(
        gov.verify_token(&first_token, now, None).is_none(),
        "precondition: the deleted key's token must stop verifying"
    );

    let (second, second_token) = gov
        .issue_self(sub, "corp", None, now + 3600, now)
        .await
        .expect("a login after an admin deletion must still succeed, with a NEW binding");

    assert_ne!(
        second.id, first.id,
        "the new binding must not reuse the deleted id — that id is never reissued"
    );
    let tombstone = gov
        .core_store()
        .unwrap()
        .identity()
        .get_key(&first.id)
        .await
        .unwrap()
        .expect("the tombstoned row is kept for attribution");
    assert!(
        tombstone.deleted_at.is_some(),
        "the admin's deletion must still stand after the login: {tombstone:?}"
    );
    assert!(
        gov.verify_token(&first_token, now, None).is_none(),
        "the pre-deletion token must NOT come back to life"
    );
    assert!(
        gov.verify_token(&second_token, now, None).is_some(),
        "the freshly issued token must work"
    );
}

#[tokio::test]
async fn an_admin_rotation_of_a_self_serve_key_survives_the_next_refresh() {
    let gov = GovState::new_with_core(
        crate::real_store::core().await,
        None,
        Some(self_serve_signer()),
    )
    .await
    .unwrap();

    gov.hold_self_mint_state();
    let sub = "oidc:alice";
    let now = 1_700_000_000u64;

    gov.issue_self(sub, "corp", None, now + 3600, now)
        .await
        .unwrap();
    let (x, t1) = gov
        .refresh_self(sub, "corp", None, now + 3600, now)
        .await
        .unwrap();
    assert!(gov.verify_token(&t1, now, None).is_some());

    gov.rotate_key_outcome_async(&x.id, now + 3600)
        .await
        .unwrap()
        .expect("the live key rotates");
    assert!(
        gov.verify_token(&t1, now, None).is_none(),
        "precondition: the rotation kills the pre-rotate token"
    );

    let (y, t2) = gov
        .refresh_self(sub, "corp", None, now + 3600, now)
        .await
        .expect("a refresh after an admin rotation still mints");
    assert!(
        gov.verify_token(&t1, now, None).is_none(),
        "the pre-rotate token must NOT come back to life on the next refresh"
    );
    assert_ne!(
        y.id, x.id,
        "the refresh must mint a new id, never write over the rotated row"
    );
    assert!(gov.verify_token(&t2, now, None).is_some());
}

#[tokio::test]
async fn a_failed_atomic_refresh_can_still_be_retried() {
    let (store, faults) = native_identity_fixture().await;
    let gov = GovState::new_with_core(store.clone(), None, Some(self_serve_signer()))
        .await
        .unwrap();
    let now = 1_700_000_000;
    let sub = "oidc:alice";
    let (old, old_token) = gov
        .issue_self(sub, "corp", None, now + 3600, now)
        .await
        .unwrap();
    faults.fail_writes.store(true, Ordering::SeqCst);
    gov.refresh_self(sub, "corp", None, now + 3600, now)
        .await
        .unwrap_err();
    faults.fail_writes.store(false, Ordering::SeqCst);
    let (retried, token) = gov
        .refresh_self(sub, "corp", None, now + 3600, now)
        .await
        .unwrap();
    assert_ne!(retried.id, old.id);
    assert!(gov.verify_token(&token, now, None).is_some());
    assert!(gov.verify_token(&old_token, now, None).is_none());
    let live: Vec<_> = store
        .identity()
        .list_keys()
        .await
        .unwrap()
        .into_iter()
        .filter(|k| k.enabled && k.deleted_at.is_none())
        .collect();
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].id, retried.id);
}

#[tokio::test]
async fn a_long_refresh_history_does_not_lock_a_subject_out_after_a_deletion() {
    let store = crate::real_store::core().await;
    let gov = GovState::new_with_core(store, None, Some(self_serve_signer()))
        .await
        .unwrap();
    let sub = "oidc:erin";
    let now = 1_700_000_000u64;

    gov.issue_self(sub, "corp", None, now + 3600, now)
        .await
        .unwrap();
    for _ in 0..70 {
        gov.refresh_self(sub, "corp", None, now + 3600, now)
            .await
            .expect("each refresh rotates and tombstones its predecessor");
    }
    let live = self_binding_for(&gov, sub)
        .await
        .expect("one live binding after the refresh run");

    gov.delete_key(&live.id).await.unwrap();

    let (issued, issued_token) = gov
        .issue_self(sub, "corp", None, now + 3600, now)
        .await
        .expect("a login after a long refresh history plus a deletion must still mint");
    assert!(
        gov.verify_token(&issued_token, now, None).is_some(),
        "the freshly issued token must verify"
    );
    assert_ne!(
        issued.id, live.id,
        "the new binding must not reuse the deleted id"
    );

    let (_refreshed, refreshed_token) = gov
        .refresh_self(sub, "corp", None, now + 3600, now)
        .await
        .expect("refresh must work too, not just issue");
    assert!(gov.verify_token(&refreshed_token, now, None).is_some());

    let tombstone = gov
        .core_store()
        .unwrap()
        .identity()
        .get_key(&live.id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        tombstone.deleted_at.is_some(),
        "the admin's deletion must still stand: {tombstone:?}"
    );
}

#[tokio::test]
async fn an_admin_rotate_then_a_pools_change_does_not_fork_the_binding() {
    let store = crate::real_store::core().await;
    let gov = GovState::new_with_core(store, None, Some(self_serve_signer()))
        .await
        .unwrap();
    let sub = "oidc:zed";
    let now = 1_700_000_000u64;

    gov.issue_self(sub, "corp", None, now + 3600, now)
        .await
        .unwrap();
    for _ in 0..3 {
        gov.refresh_self(sub, "corp", None, now + 3600, now)
            .await
            .unwrap();
    }
    let live = self_binding_for(&gov, sub).await.expect("one live binding");

    gov.rotate_key_outcome_async(&live.id, now + 3600)
        .await
        .unwrap()
        .unwrap();

    let (issued, token) = gov
        .issue_self(
            sub,
            "corp",
            Some(vec!["poolA".to_string()]),
            now + 3600,
            now,
        )
        .await
        .unwrap();

    assert_eq!(
        issued.id, live.id,
        "a pools change must update the existing binding, never mint a parallel one"
    );
    assert!(
        gov.verify_token(&token, now, None).is_some(),
        "the token issued over the updated binding must verify"
    );

    let group = format!("{SELF_KEY_GROUP_PREFIX}{sub}");
    let enabled: Vec<VirtualKey> = gov
        .all_keys_async()
        .await
        .unwrap()
        .into_iter()
        .filter(|k| {
            k.enabled && k.deleted_at.is_none() && k.group.as_deref() == Some(group.as_str())
        })
        .collect();
    assert_eq!(
        enabled.len(),
        1,
        "at most one enabled binding per subject: {enabled:?}"
    );

    assert_eq!(
        enabled[0].allowed_scopes,
        Some(vec![busbar_contract::records::ScopeRef::pool(
            "poolA".to_string()
        )]),
        "the changed pools must be persisted on the surviving binding"
    );
}

#[tokio::test]
async fn flush_metering_failure_warns_once_per_tick_not_per_key() {
    use tracing_subscriber::layer::SubscriberExt as _;
    #[derive(Clone, Default)]
    struct MeteringWarnings(Arc<std::sync::Mutex<Vec<String>>>);
    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for MeteringWarnings {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if *event.metadata().level() != tracing::Level::WARN {
                return;
            }
            struct Fields(String);
            impl tracing::field::Visit for Fields {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    use std::fmt::Write as _;
                    write!(&mut self.0, "{}={value:?} ", field.name()).unwrap();
                }
            }
            let mut fields = Fields(String::new());
            event.record(&mut fields);
            self.0.lock().unwrap().push(fields.0);
        }
    }

    let store = Arc::new(FlakyStore::new().await);
    store.meter_down.store(true, Ordering::SeqCst);
    let gov = GovState::new_with_core(store.core(), None, None)
        .await
        .unwrap();
    let now = 1_700_000_500;

    for k in ["vk_a", "vk_b", "vk_c", "vk_d", "vk_e"] {
        gov.record_metering(k, "model-x", "prov", None, now);
    }

    let cap = MeteringWarnings::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    let flushed = {
        use tracing::instrument::WithSubscriber;
        gov.flush_metering().with_subscriber(subscriber).await
    };

    let messages = cap.0.lock().unwrap().clone();
    assert_eq!(flushed, 0, "every key failed to persist");
    assert_eq!(
        messages
            .iter()
            .filter(|message| message.contains("metering flush:"))
            .count(),
        1,
        "exactly ONE aggregate warn per tick, not one per failed key: {:?}",
        messages
    );

    assert!(
        messages.iter().any(|message| message.contains("failed=5")),
        "the aggregate warn reports the failed-key count: {:?}",
        messages
    );

    assert_eq!(
        gov.flush_metering().await,
        0,
        "the deltas are retained and retried, still failing while the store is down"
    );
}

#[tokio::test]
async fn proof_manual_revoke_kills_a_minted_key() {
    let store = crate::real_store::core().await;
    let gov = GovState::new_with_core(store, None, Some(self_serve_signer()))
        .await
        .unwrap();
    let sub = "oidc:dave";
    let now = 1_700_000_000u64;

    let (binding, token) = gov
        .issue_self(sub, "corp", None, now + 3600, now)
        .await
        .unwrap();
    assert!(
        gov.verify_token(&token, now, None).is_some(),
        "precondition: the freshly minted token MUST verify before revoke, or the \
         post-revoke assertion proves nothing"
    );
    assert!(!gov.is_revoked(&binding.id));

    gov.revoke_async(&binding.id, "offboarded").await.unwrap();

    assert!(
        gov.verify_token(&token, now, None).is_none(),
        "after a manual revoke the token MUST be dead on the issuing node"
    );
    assert!(gov.is_revoked(&binding.id));
}

#[tokio::test]
async fn proof_manual_revoke_is_authoritative_across_the_fleet() {
    let store = crate::real_store::core().await;
    let node_a = GovState::new_with_core(store.clone(), None, Some(self_serve_signer()))
        .await
        .unwrap();
    let sub = "oidc:erin";
    let now = 1_700_000_000u64;

    let (binding, token) = node_a
        .issue_self(sub, "corp", None, now + 3600, now)
        .await
        .unwrap();
    let node_b = GovState::new_with_core(store.clone(), None, Some(self_serve_signer()))
        .await
        .unwrap();
    assert!(
        node_b.verify_token(&token, now, None).is_some(),
        "a second fleet node over the shared store must accept the token BEFORE the revoke"
    );

    node_a
        .revoke_async(&binding.id, "offboarded")
        .await
        .unwrap();

    let node_c = GovState::new_with_core(store, None, Some(self_serve_signer()))
        .await
        .unwrap();
    assert!(
        node_c.verify_token(&token, now, None).is_none(),
        "the revoke MUST be authoritative on every fleet node reading the shared store"
    );
    assert!(node_c.is_revoked(&binding.id));
}

#[tokio::test]
async fn proof_one_session_mints_a_personal_key_plus_n_independent_app_tokens() {
    let store = crate::real_store::core().await;
    let gov = GovState::new_with_core(store, None, Some(self_serve_signer()))
        .await
        .unwrap();
    let admin = "oidc:matthew";
    let now = 1_700_000_000u64;

    let (personal, personal_tok) = gov
        .issue_self(admin, "corp", None, now + 3600, now)
        .await
        .unwrap();
    assert_eq!(personal.binding_mode.as_deref(), Some("user-bound"));
    assert_eq!(personal.idp_subject.as_deref(), Some(admin));
    assert_eq!(personal.minted_by, None);
    assert!(gov.verify_token(&personal_tok, now, None).is_some());

    let apps = [
        ("billing", "pool-billing"),
        ("search", "pool-search"),
        ("etl", "pool-etl"),
    ];
    let mut minted = Vec::new();
    for (label, pool) in apps {
        let mut labels = std::collections::BTreeMap::new();
        labels.insert("app".to_string(), label.to_string());
        let spec = NewKeySpec {
            name: format!("app-token-{label}"),
            allowed_pools: Some(vec![pool.to_string()]),
            group: None,
            labels,
            minted_by: Some(admin.to_string()),
            binding_mode: Some("time-bound".to_string()),
            plane_scopes: None,
        };
        let (key, token) = gov
            .mint_signed_async(spec, now + 30 * 86_400, now)
            .await
            .unwrap();
        minted.push((label, pool, key, token));
    }

    let ids: std::collections::HashSet<String> =
        minted.iter().map(|(_, _, k, _)| k.id.clone()).collect();
    assert_eq!(
        ids.len(),
        apps.len(),
        "N app tokens minted in one session are N DISTINCT keys"
    );
    assert!(
        !ids.contains(&personal.id),
        "no app token collides with the personal key"
    );
    for (label, pool, key, token) in &minted {
        assert_eq!(key.minted_by.as_deref(), Some(admin), "provenance recorded");
        assert_eq!(key.binding_mode.as_deref(), Some("time-bound"));
        assert_eq!(key.labels.get("app").map(String::as_str), Some(*label));
        let scopes = key.allowed_scopes.as_ref().expect("scoped");
        assert!(
            scopes.iter().all(|s| s.value == *pool) && scopes.len() == 1,
            "each app token is scoped to EXACTLY its own pool: {scopes:?}"
        );
        assert!(
            gov.verify_token(token.expose(&crate::seal::lend()), now, None)
                .is_some(),
            "each app token verifies"
        );
    }

    let (_, _, victim_key, victim_tok) = &minted[1];
    gov.revoke_async(&victim_key.id, "compromised app token")
        .await
        .unwrap();
    assert!(
        gov.verify_token(victim_tok.expose(&crate::seal::lend()), now, None)
            .is_none(),
        "the revoked app token is dead"
    );
    assert!(
        gov.verify_token(&personal_tok, now, None).is_some(),
        "the personal token is untouched by an app-token revoke"
    );
    for (i, (_, _, _, token)) in minted.iter().enumerate() {
        if i == 1 {
            continue;
        }
        assert!(
            gov.verify_token(token.expose(&crate::seal::lend()), now, None)
                .is_some(),
            "a sibling app token is untouched by revoking a different one"
        );
    }
}

#[tokio::test]
async fn proof_time_bound_expiry_is_enforced_locally() {
    let store = crate::real_store::core().await;

    let gov = GovState::new_with_core(store, None, Some(self_serve_signer()))
        .await
        .unwrap();
    let now = 1_700_000_000u64;
    let exp = now + 30 * 86_400;

    let spec = NewKeySpec {
        name: "expiry-probe".to_string(),
        allowed_pools: None,
        group: None,
        labels: Default::default(),
        ..Default::default()
    };
    let (_binding, token) = gov.mint_signed_async(spec, exp, now).await.unwrap();

    assert!(
        gov.verify_token(token.expose(&crate::seal::lend()), now, None)
            .is_some(),
        "precondition: the token MUST verify at mint time, or the post-expiry None proves nothing"
    );
    assert!(
        gov.verify_token(token.expose(&crate::seal::lend()), exp - 1, None)
            .is_some(),
        "precondition: the token MUST still verify one second before its expiry"
    );

    assert!(
        gov.verify_token(token.expose(&crate::seal::lend()), exp + 1, None)
            .is_none(),
        "past exp the token MUST NOT verify — time-bound expiry is enforced locally"
    );

    assert!(
        gov.verify_token(token.expose(&crate::seal::lend()), exp, None)
            .is_none(),
        "exp is exclusive: at exactly exp the token is already expired"
    );
}

#[tokio::test]
async fn proof_minted_key_verifies_locally_and_never_calls_the_idp() {
    let now = 1_700_000_000u64;
    let exp = now + 30 * 86_400;
    let spec = |name: &str| NewKeySpec {
        name: name.to_string(),
        allowed_pools: None,
        group: None,
        labels: Default::default(),
        ..Default::default()
    };

    let new_gov = async || {
        GovState::new_with_core(
            crate::real_store::core().await,
            None,
            Some(self_serve_signer()),
        )
        .await
        .unwrap()
    };

    let gov = new_gov().await;
    let (_b, token) = gov
        .mint_signed_async(spec("baseline"), exp, now)
        .await
        .unwrap();
    assert!(
        gov.verify_token(token.expose(&crate::seal::lend()), now, None)
            .is_some(),
        "precondition: a freshly minted key MUST verify locally with no IdP configured"
    );

    {
        let gov = new_gov().await;
        let (_b, token) = gov.mint_signed_async(spec("sig"), exp, now).await.unwrap();
        assert!(gov
            .verify_token(token.expose(&crate::seal::lend()), now, None)
            .is_some());

        let mut chars: Vec<char> = token.expose(&crate::seal::lend()).chars().collect();
        chars[10] = if chars[10] == 'x' { 'y' } else { 'x' };
        let tampered: String = chars.into_iter().collect();
        assert_ne!(
            &tampered,
            token.expose(&crate::seal::lend()),
            "the tamper actually changed the token"
        );
        assert!(
            gov.verify_token(&tampered, now, None).is_none(),
            "signature gate: a tampered token fails the local ed25519 verify"
        );
    }

    assert!(
        gov.verify_token(token.expose(&crate::seal::lend()), exp + 1, None)
            .is_none(),
        "expire gate: past exp the token is dead (local time check, no network)"
    );

    {
        let gov = new_gov().await;
        let (b, token) = gov
            .mint_signed_async(spec("revoke"), exp, now)
            .await
            .unwrap();
        assert!(gov
            .verify_token(token.expose(&crate::seal::lend()), now, None)
            .is_some());
        gov.revoke_async(&b.id, "offboarded").await.unwrap();
        assert!(
            gov.verify_token(token.expose(&crate::seal::lend()), now, None)
                .is_none(),
            "revoke gate: a denylisted subject fails the local denylist read"
        );
    }

    {
        let gov = new_gov().await;
        let (b, token) = gov
            .mint_signed_async(spec("rotate"), exp, now)
            .await
            .unwrap();
        assert!(gov
            .verify_token(token.expose(&crate::seal::lend()), now, None)
            .is_some());
        gov.rotate_key_outcome_async(&b.id, exp)
            .await
            .unwrap()
            .expect("rotate mints a new credential over the live binding");
        assert!(
            gov.verify_token(token.expose(&crate::seal::lend()), now, None)
                .is_none(),
            "rotate gate: the pre-rotation token fails the local generation match"
        );
    }

    {
        let gov = new_gov().await;
        let (b, token) = gov
            .mint_signed_async(spec("disable"), exp, now)
            .await
            .unwrap();
        assert!(gov
            .verify_token(token.expose(&crate::seal::lend()), now, None)
            .is_some());
        gov.update_key_outcome_async(&b.id, Some(false), None)
            .await
            .unwrap()
            .expect("disable updates the binding in place");
        assert!(
            gov.verify_token(token.expose(&crate::seal::lend()), now, None)
                .is_none(),
            "disable gate: an `enabled=false` binding fails the local admit check"
        );
    }

    {
        let gov = new_gov().await;
        let (_b, token) = gov.mint_signed_async(spec("aud"), exp, now).await.unwrap();
        assert!(
            gov.verify_token(token.expose(&crate::seal::lend()), now, None)
                .is_some(),
            "the plain token verifies on the plain data plane (expected_aud = None)"
        );
        assert!(
            gov.verify_token(
                token.expose(&crate::seal::lend()),
                now,
                Some("plane-x://example/canonical")
            )
            .is_none(),
            "audience gate: a plain token is refused where a specific audience is required (local)"
        );
    }
}

#[tokio::test]
async fn proof_minted_admission_is_store_state_config_signing_is_not() {
    use crate::governance::signing::{TokenVerifier, DEFAULT_KID};
    let now = 1_700_000_000u64;
    let exp = now + 30 * 86_400;

    let store_s = crate::real_store::core().await;
    let gov_s = GovState::new_with_core(store_s, None, Some(self_serve_signer()))
        .await
        .unwrap();
    let (binding, token) = gov_s
        .mint_signed_async(
            NewKeySpec {
                name: "config-vs-store".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            exp,
            now,
        )
        .await
        .unwrap();
    assert!(
        gov_s
            .verify_token(token.expose(&crate::seal::lend()), now, None)
            .is_some(),
        "precondition: the token verifies on the node that minted it (config + store agree)"
    );

    drop(gov_s);

    let fresh_store = crate::real_store::core().await;
    let gov_fresh = GovState::new_with_core(fresh_store, None, Some(self_serve_signer()))
        .await
        .unwrap();

    let verifier = TokenVerifier::single(DEFAULT_KID, self_serve_signer().verifying_key());
    let claims = verifier
        .verify(token.expose(&crate::seal::lend()), now, None)
        .expect("the signature is still authentic under the shared signing key");
    assert_eq!(
        claims.sub, binding.id,
        "the authentic claims still name the minted subject"
    );

    assert!(
        gov_fresh.lookup_by_sub(&binding.id).is_none(),
        "the fresh store records NO binding for the minted subject"
    );
    assert!(
        gov_fresh
            .verify_token(token.expose(&crate::seal::lend()), now, None)
            .is_none(),
        "admission is store state: a genuinely-signed token is refused when the store has no binding"
    );
}

#[tokio::test]
async fn the_metering_accrual_reads_the_millisecond_clock_not_the_lifted_second() {
    const T0: u64 = 1_700_000_000_000;
    let cards = [T0, T0 + 500];

    let dater = |at_ms: u64| {
        cards
            .iter()
            .copied()
            .filter(|s| *s <= at_ms)
            .max()
            .unwrap_or(0)
    };
    let clock = || T0 + 700;

    let gov = GovState::new_with_core(crate::real_store::core().await.core(), None, None)
        .await
        .unwrap();
    let add = MeterCounts {
        requests: 1,
        ..MeterCounts::default()
    };
    gov.record_metered_request_dated("vk_dated", "", "m", "p", add, T0 / 1_000, &clock, &dater);

    let drained = gov.pending_metering.drain();
    assert_eq!(drained.len(), 1, "one response, one cell");
    assert_eq!(
        drained[0].0 .4,
        T0 + 500,
        "a response served after the second card published in the same second must date at that \
         card (#79), not at the first card the lifted second resolves to"
    );
}

fn plane_fee_cost(cap: i64) -> crate::cost::CostModel {
    use busbar_kernel_ledger::cost::PlaneFees;
    let fees = crate::config::PlaneFeesMap::from([
        (
            "tp".to_string(),
            PlaneFees {
                per_request: 3,
                per_session: 0,
            },
        ),
        (
            "sp".to_string(),
            PlaneFees {
                per_request: 0,
                per_session: 40,
            },
        ),
    ]);
    group_cost(5, &[("team", cap, "total", None)]).with_plane_fees(&fees)
}

fn plane_pool(plane: &str, pool: &str) -> String {
    format!("{plane}{PLANE_LANE_SEP}{pool}")
}

async fn team_gov() -> (
    Arc<crate::persistence::facade::CoreStore>,
    GovState,
    VirtualKey,
) {
    let store = crate::real_store::core().await;
    let mut k = sample_key("k1", "h1");
    k.group = Some("team".to_string());
    store.identity().put_key(&k).await.unwrap();
    let gov = GovState::new_with_core(store.clone().core(), None, None)
        .await
        .unwrap();
    (store, gov, k)
}

const AT: u64 = 1_700_000_000;

async fn spend(gov: &GovState, cost: &crate::cost::CostModel) -> i64 {
    gov.usage_for_async(cost, "k1", AT)
        .await
        .unwrap()
        .unwrap()
        .spend_cents
}

#[tokio::test]
async fn a_planes_request_fee_charges_its_requests_and_the_pools_fee_charges_the_pools_plane() {
    use busbar_kernel_ledger::cost::{plane_fee_lane, PER_REQUEST};
    let (store, gov, k) = team_gov().await;
    let cost = plane_fee_cost(1_000);
    for _ in 0..2 {
        assert!(gov.try_admit(&cost, &k, "", AT).is_ok(), "a pools request");
    }
    for _ in 0..3 {
        let pool = plane_pool("tp", "srv_read");
        assert!(
            gov.try_admit(&cost, &k, &pool, AT).is_ok(),
            "a `tp` request"
        );
    }

    assert_eq!(spend(&gov, &cost).await, 19);
    assert_eq!(
        gov.priced_bucket_async(&cost, "k1", WINDOW_TOTAL, AT)
            .await
            .unwrap()
            .billable_requests,
        5
    );
    let u = gov.usage_for_async(&cost, "k1", AT).await.unwrap().unwrap();
    assert_eq!(
        u.requests, 5,
        "every admission still counts toward a requests cap"
    );
    assert_eq!(u.tokens.whole_for_test(), 0, "a fee unit is not a token");

    gov.flush_budgets().await;
    let ledger = store.ledger().get_usage("k1", 0).await.unwrap();
    assert_eq!(
        ledger.billable_requests, 2,
        "the flat fee base is the pools plane's"
    );
    let lane = plane_fee_lane("tp");
    let row = ledger
        .models
        .iter()
        .find(|m| m.model == lane)
        .expect("fee lane");
    assert_eq!(
        Count::from_stored(row.usage_units[PER_REQUEST], row.scale).unwrap(),
        whole_count(3)
    );
    let restarted = GovState::new_with_core(store.core(), None, None)
        .await
        .unwrap();
    restarted.hydrate_budgets_async(&cost, AT).await.unwrap();
    assert_eq!(spend(&restarted, &cost).await, 19);
    assert_eq!(
        restarted
            .priced_bucket_async(&cost, "k1", WINDOW_TOTAL, AT)
            .await
            .unwrap()
            .billable_requests,
        5
    );
}

#[tokio::test]
async fn a_planes_session_fee_charges_one_per_session() {
    use busbar_kernel_ledger::cost::{plane_fee_lane, PER_SESSION};
    let (_store, gov, k) = team_gov().await;
    let cost = plane_fee_cost(1_000);
    let one = std::collections::BTreeMap::from([(PER_SESSION.to_string(), 1)]);
    for _ in 0..2 {
        gov.record_usage(&cost, &k, "", &plane_fee_lane("sp"), &one, AT);
    }
    assert_eq!(spend(&gov, &cost).await, 80, "2 sessions × 40");
    assert_eq!(
        gov.priced_bucket_async(&cost, "k1", WINDOW_TOTAL, AT)
            .await
            .unwrap()
            .billable_requests,
        0
    );
}

#[tokio::test]
async fn a_planes_refund_returns_its_own_fee_unit_never_the_flat_base() {
    let (store, gov, k) = team_gov().await;
    let cost = plane_fee_cost(1_000);
    let tp = plane_pool("tp", "srv_read");
    let mut charged = Vec::new();
    for _ in 0..2 {
        let pools = gov.try_admit(&cost, &k, "", AT).expect("a pools request");
        let tp = gov.try_admit(&cost, &k, &tp, AT).expect("a `tp` request");
        charged.push((pools, tp));
    }
    assert_eq!(spend(&gov, &cost).await, 16, "2 × 5 + 2 × 3");
    gov.refund_charge(charged[0].1.charge());
    assert_eq!(
        spend(&gov, &cost).await,
        13,
        "one `tp` fee back, the pools fees kept"
    );
    gov.flush_budgets().await;
    let ledger = store.ledger().get_usage("k1", 0).await.unwrap();
    assert_eq!(
        ledger.billable_requests, 2,
        "the flat fee base is untouched"
    );
    let lane = busbar_kernel_ledger::cost::plane_fee_lane("tp");
    let row = ledger
        .models
        .iter()
        .find(|m| m.model == lane)
        .expect("fee lane");
    assert_eq!(
        Count::from_stored(
            row.usage_units[busbar_kernel_ledger::cost::PER_REQUEST],
            row.scale
        )
        .unwrap(),
        Count::ONE
    );
    assert_eq!(
        gov.usage_for_async(&cost, "k1", AT)
            .await
            .unwrap()
            .unwrap()
            .requests,
        4,
        "a refund never gives back a request slot"
    );

    gov.refund_charge(charged[0].0.charge());
    assert_eq!(spend(&gov, &cost).await, 8);
    assert_eq!(
        gov.priced_bucket_async(&cost, "k1", WINDOW_TOTAL, AT)
            .await
            .unwrap()
            .billable_requests,
        2
    );
}

#[tokio::test]
async fn the_fee_refund_primitive_returns_one_session_fee_unit() {
    use busbar_kernel_ledger::cost::{plane_fee_lane, PER_SESSION};
    let (_store, gov, k) = team_gov().await;
    let cost = plane_fee_cost(1_000);
    let one = std::collections::BTreeMap::from([(PER_SESSION.to_string(), 1)]);
    for _ in 0..2 {
        gov.record_usage(&cost, &k, "", &plane_fee_lane("sp"), &one, AT);
    }
    gov.refund_fee_unit(&cost, &k, &plane_pool("sp", ""), AT, PER_SESSION);
    assert_eq!(spend(&gov, &cost).await, 40, "one session fee back");
    gov.refund_fee_unit(&cost, &k, &plane_pool("sp", ""), AT, PER_SESSION);
    gov.refund_fee_unit(&cost, &k, &plane_pool("sp", ""), AT, PER_SESSION);
    assert_eq!(spend(&gov, &cost).await, 0, "floored at zero");
}

#[tokio::test]
async fn the_metering_row_carries_every_class_the_budget_book_holds() {
    use busbar_kernel_ledger::cost::{plane_fee_lane, PER_SESSION};
    let (store, gov, k) = team_gov().await;
    let cost = plane_fee_cost(1_000);
    let map = |pairs: &[(&str, u64)]| -> std::collections::BTreeMap<String, u64> {
        pairs.iter().map(|(c, n)| (c.to_string(), *n)).collect()
    };
    gov.record_usage(
        &cost,
        &k,
        "",
        &plane_fee_lane("sp"),
        &map(&[(PER_SESSION, 1)]),
        AT,
    );
    gov.record_usage(
        &cost,
        &k,
        "",
        &plane_fee_lane("sp"),
        &map(&[(PER_SESSION, 1)]),
        AT,
    );
    let tool = format!("tp{PLANE_LANE_SEP}srv.read");
    gov.record_usage(&cost, &k, "srv.read", &tool, &map(&[("tool_calls", 3)]), AT);
    gov.record_usage(
        &cost,
        &k,
        "",
        "m",
        &map(&[("input", 7), ("search_units", 4)]),
        AT,
    );
    gov.flush_metering().await;
    let rows = store
        .ledger()
        .list_metering(metering_bucket(AT))
        .await
        .unwrap();
    let row = |model: &str, provider: &str| {
        rows.iter()
            .find(|r| r.key_id == k.id && r.model == model && r.provider == provider)
            .map(|r| {
                (
                    r.requests,
                    Count::from_stored(r.tokens_input, r.scale)
                        .unwrap()
                        .whole_for_test(),
                    r.usage_units
                        .iter()
                        .map(|(k, n)| {
                            (
                                k.clone(),
                                Count::from_stored(*n, r.scale).unwrap().whole_for_test(),
                            )
                        })
                        .collect(),
                )
            })
    };
    assert_eq!(
        row("", "sp"),
        Some((0, 0, map(&[(PER_SESSION, 2)]))),
        "2 sessions"
    );
    assert_eq!(
        row("srv.read", "tp"),
        Some((0, 0, map(&[("tool_calls", 3)])))
    );
    assert_eq!(
        row("m", ""),
        Some((0, 0, map(&[("search_units", 4)]))),
        "the open class, and not the input tier the token columns carry"
    );
    assert_eq!(rows.len(), 3, "nothing else was written");
}

#[tokio::test]
async fn a_served_units_open_class_lands_on_its_providers_row() {
    let (store, gov, k) = team_gov().await;
    let cost = plane_fee_cost(1_000);
    let units: std::collections::BTreeMap<String, u64> = [
        ("input".to_string(), 18),
        ("output".to_string(), 7),
        ("unitemized_tokens".to_string(), 3),
    ]
    .into_iter()
    .collect();
    gov.record_usage_served(&cost, &k, "", "m", Some("p"), &units, AT);
    gov.record_lane_metering_for_key(&k, "m", Some("p"), &units, AT);
    gov.flush_metering().await;
    let rows = store
        .ledger()
        .list_metering(metering_bucket(AT))
        .await
        .unwrap();
    let mine: Vec<_> = rows.iter().filter(|r| r.key_id == k.id).collect();
    assert_eq!(
        mine.iter()
            .map(|r| (r.model.as_str(), r.provider.as_str()))
            .collect::<Vec<_>>(),
        [("m", "p")],
        "one row, attributed to the serving provider: {mine:?}"
    );
    let row = mine[0];
    assert_eq!(row.requests, 1);
    assert_eq!(
        row.usage_units
            .get("unitemized_tokens")
            .map(|n| Count::from_stored(*n, row.scale).unwrap()),
        Some(whole_count(3)),
        "the open class rides its provider's row"
    );
}

#[tokio::test]
async fn a_plane_without_fees_bills_no_fee() {
    let (_store, gov, k) = team_gov().await;
    let cost = plane_fee_cost(1_000);
    for _ in 0..4 {
        let pool = plane_pool("np", "agent");
        assert!(gov.try_admit(&cost, &k, &pool, AT).is_ok());
    }

    assert_eq!(spend(&gov, &cost).await, 0);
    assert_eq!(
        gov.usage_for_async(&cost, "k1", AT)
            .await
            .unwrap()
            .unwrap()
            .requests,
        4
    );
    assert_eq!(
        gov.priced_bucket_async(&cost, "k1", WINDOW_TOTAL, AT)
            .await
            .unwrap()
            .billable_requests,
        4
    );
}

#[tokio::test]
async fn budget_caps_include_each_planes_fees() {
    let (_store, gov, k) = team_gov().await;
    let cost = plane_fee_cost(10);
    let tp = plane_pool("tp", "srv_read");
    assert!(gov.try_admit(&cost, &k, "", AT).is_ok(), "pools: 5");
    assert!(gov.try_admit(&cost, &k, &tp, AT).is_ok(), "`tp`: 5 + 3 = 8");
    let blocked = |r: Result<AdmitGrant, LimitBlocked>| {
        matches!(
            r,
            Err(LimitBlocked::Limit {
                metric: "budget",
                ..
            })
        )
    };
    assert!(blocked(gov.try_admit(&cost, &k, &tp, AT)), "8 + 3 > 10");
    assert!(blocked(gov.try_admit(&cost, &k, "", AT)), "8 + 5 > 10");
    let free = plane_pool("np", "agent");
    assert!(gov.try_admit(&cost, &k, &free, AT).is_ok(), "8 + 0 fits");

    let one = std::collections::BTreeMap::from([(
        busbar_kernel_ledger::cost::PER_SESSION.to_string(),
        1,
    )]);
    let lane = busbar_kernel_ledger::cost::plane_fee_lane("sp");
    gov.record_usage(&cost, &k, "", &lane, &one, AT);
    assert_eq!(spend(&gov, &cost).await, 48);
    assert!(
        blocked(gov.try_admit(&cost, &k, &free, AT)),
        "48 is past 10"
    );
}

fn bound_table(binding: crate::config::RoleBindingCfg) -> crate::config::RoleBindings {
    let mut roles = std::collections::BTreeMap::new();
    roles.insert("eng".to_string(), binding);
    let mut rb = crate::config::RoleBindings::new();
    rb.insert("idp".to_string(), roles);
    rb
}

fn bound_principal() -> crate::auth::Principal {
    crate::auth::Principal {
        id: "alice@example.com".to_string(),
        name: Some("Alice".to_string()),
        roles: vec!["eng".to_string()],
        ttl_secs: None,
    }
}

#[tokio::test]
async fn a_bound_key_records_its_admission_and_a_registry_key_does_not() {
    let rb = bound_table(crate::config::RoleBindingCfg::default());
    let key =
        synthesize_bound_key("idp", &bound_principal(), &rb).expect("a bound role synthesizes");
    assert!(key.generation_hash.starts_with(PRINCIPAL_MARKER_PREFIX));
    let (module, p) = bound_admission(&key).expect("the admission reads back");
    assert_eq!(module, "idp");
    assert_eq!(p.id, "alice@example.com");
    assert_eq!(p.roles, vec!["eng".to_string()]);

    let registry = VirtualKey {
        id: "vk_0123456789abcdef".to_string(),
        generation_hash: binding_marker("vk_0123456789abcdef", "g1"),
        ..Default::default()
    };
    assert!(bound_admission(&registry).is_none());

    let mut forged = (*key).clone();
    forged.id = "someone-else".to_string();
    assert!(bound_admission(&forged).is_none());
}

#[tokio::test]
async fn a_role_bound_standing_follows_the_live_bindings_and_lapses_when_the_binding_goes() {
    use crate::trust::validate::{GovResolve, Lapsed, Refusal, Snapshot, Standing};
    let mut rb = bound_table(crate::config::RoleBindingCfg::default());
    let key = synthesize_bound_key("idp", &bound_principal(), &rb).expect("bound");
    let standing = Standing::opened(
        Some(&key),
        Snapshot::Watching,
        std::time::Duration::from_secs(300),
    );
    let ask = |rb: &crate::config::RoleBindings| {
        let live = LiveResolve {
            governance: None,
            role_bindings: rb,
        };
        standing.still_permitted(Some(&live as &dyn GovResolve), 1, 1_700_000_000)
    };

    let now = ask(&rb)
        .expect("a bound principal stands")
        .expect("governed");
    assert_eq!(now.id, "alice@example.com");
    assert_eq!(now.allowed_scopes, None);
    assert_eq!(now.group, None);

    rb = bound_table(crate::config::RoleBindingCfg {
        allowed_pools: Some(vec!["p2".to_string()]),
        group: Some("finance".to_string()),
        ..Default::default()
    });
    let now = ask(&rb).expect("still bound").expect("governed");
    assert_eq!(
        now.allowed_scopes,
        Some(vec![busbar_contract::records::ScopeRef::pool("p2")])
    );
    assert_eq!(now.group.as_deref(), Some("finance"));

    let lapsed = Err(Lapsed::Identity(Refusal::IdentityNotLive {
        principal: "alice@example.com".to_string(),
    }));
    rb = bound_table(crate::config::RoleBindingCfg {
        allowed_pools: Some(vec![]),
        ..Default::default()
    });
    assert_eq!(ask(&rb), lapsed);

    rb = crate::config::RoleBindings::new();
    assert_eq!(ask(&rb), lapsed);
}

#[tokio::test]
async fn a_registry_key_standing_is_unchanged_by_the_bindings_resolver() {
    use crate::trust::validate::{GovResolve, Lapsed, Refusal, Snapshot, Standing};
    let gov = GovState::new_with_core(crate::real_store::core().await, None, None)
        .await
        .expect("registry");
    let (key, _secret) = {
        gov.set_signing_key(Some(self_serve_signer()));
        gov.mint_signed_async(
            NewKeySpec {
                name: "streamer".to_string(),
                ..Default::default()
            },
            4_000_000_000,
            1_700_000_000,
        )
        .await
    }
    .expect("mint");
    let rb = bound_table(crate::config::RoleBindingCfg::default());
    let standing = Standing::opened(
        Some(&key),
        Snapshot::Watching,
        std::time::Duration::from_secs(300),
    );
    let ask = || {
        let live = LiveResolve {
            governance: Some(&gov),
            role_bindings: &rb,
        };
        standing.still_permitted(Some(&live as &dyn GovResolve), 1, 1_700_000_000)
    };
    let now = ask()
        .expect("a live registry key stands")
        .expect("governed");
    assert_eq!(now.id, key.id);
    assert_eq!(
        now.generation_hash, key.generation_hash,
        "the registry row, not a synthesis"
    );

    gov.update_key_outcome_async(&key.id, Some(false), None)
        .await
        .expect("the admin PATCH")
        .expect("the key exists");
    assert_eq!(
        ask(),
        Err(Lapsed::Identity(Refusal::IdentityNotLive {
            principal: key.id.clone()
        }))
    );
}

fn signed_kind() -> String {
    crate::tests::frozen_str("signed_credential_kind")
}

#[tokio::test]
async fn the_credential_read_answers_a_secret_for_any_id_and_live_only_for_a_live_credential() {
    let store = crate::real_store::core().await;
    let gov = GovState::new_with_core(store, None, None).await.unwrap();
    let now = busbar_kernel::store::now();
    let (key, _bearer, akid, secret) = {
        gov.set_signing_key(Some(self_serve_signer()));
        gov.set_at_rest_keys(Some(crate::governance::at_rest::AtRestKeys::new(
            &[3u8; 32], None,
        )));
        gov.mint_signed_with_credential_async(
            NewKeySpec {
                name: "read".to_string(),
                ..Default::default()
            },
            4_000_000_000,
            now,
            &signed_kind(),
            &ISSUED_SHAPE,
        )
        .await
        .map(|(key, bearer, public_id, secret)| {
            (
                key,
                bearer,
                public_id,
                secret.expose(&crate::seal::lend()).clone(),
            )
        })
    }
    .unwrap();
    let (got, live) = gov.credential_secret(&signed_kind(), &akid, now);
    assert_eq!(
        (got.expose(&crate::seal::lend()).as_str(), live),
        (secret.as_str(), true)
    );
    let (got, live) = gov.credential_secret(&signed_kind(), "AKIAdoesnotexist0000", now);
    assert_eq!(
        (got.expose(&crate::seal::lend()).as_str(), live),
        ("", false),
        "an unknown pair answers an empty secret, not live: the verifier swaps in its own dummy"
    );
    gov.revoke_async(&key.id, "test").await.unwrap();
    assert!(
        !gov.credential_secret(&signed_kind(), &akid, now).1,
        "a revoked key is not live"
    );
}

#[tokio::test]
async fn the_credential_read_does_the_same_work_for_a_known_and_an_unknown_id() {
    let store = crate::real_store::core().await;
    let gov = GovState::new_with_core(store, None, None).await.unwrap();
    let now = busbar_kernel::store::now();
    let (_key, _bearer, akid, _secret) = {
        gov.set_signing_key(Some(self_serve_signer()));
        gov.set_at_rest_keys(Some(crate::governance::at_rest::AtRestKeys::new(
            &[3u8; 32], None,
        )));
        gov.mint_signed_with_credential_async(
            NewKeySpec {
                name: "work".to_string(),
                ..Default::default()
            },
            4_000_000_000,
            now,
            &signed_kind(),
            &ISSUED_SHAPE,
        )
        .await
        .map(|(key, bearer, public_id, secret)| {
            (
                key,
                bearer,
                public_id,
                secret.expose(&crate::seal::lend()).clone(),
            )
        })
    }
    .unwrap();
    let kind = signed_kind();

    let window = REVOCATION_SYNC_TTL_SECS;
    let mut at = gov.denylist.synced_at();
    for (round, id) in [
        akid.as_str(),
        "AKIAdoesnotexist0000",
        akid.as_str(),
        "AKIAdoesnotexist0000",
    ]
    .into_iter()
    .enumerate()
    {
        at += window;
        gov.credential_secret(&kind, id, at);
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while gov.denylist.synced_at() < at {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("credential read schedules the revocation refresh");
        assert_eq!(
            gov.denylist.synced_at(),
            at,
            "read {round} of {id:?} did not take the revocation check: the known and the unknown \
             id's reads must run the same steps"
        );
    }
}

#[tokio::test]
async fn a_virtual_keys_generation_is_compared_in_constant_time() {
    let src = include_str!("../mod.rs");
    let body = src
        .split("pub fn generation_matches(")
        .nth(1)
        .and_then(|rest| rest.split("\n}\n").next())
        .expect("generation_matches is in governance/mod.rs");
    assert!(
        body.contains("constant_time_eq"),
        "the generation compare goes through the timing-safe primitive: {body}"
    );
    assert!(
        !body.contains("=="),
        "no plain equality on key material: {body}"
    );

    let marker = super::binding_marker("vk_1", "g7");
    assert!(super::generation_matches(&marker, Some("g7")));
    assert!(!super::generation_matches(&marker, Some("g8")));
    assert!(!super::generation_matches(&marker, Some("g")));
    assert!(!super::generation_matches(&marker, None));
    let legacy = "not-a-binding-marker";
    assert!(super::generation_matches(legacy, None));
    assert!(!super::generation_matches(legacy, Some("g7")));
}

#[tokio::test]
async fn a_usage_window_past_the_horizon_is_purged_from_the_durable_store() {
    let records = crate::real_store::core().await;
    let gov = GovState::new_with_core(records.clone().core(), None, None)
        .await
        .expect("gov");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs();
    let live = crate::governance::budget_window(crate::governance::WINDOW_DAY, now);
    let old = crate::governance::budget_window(
        crate::governance::WINDOW_DAY,
        now - 40 * crate::governance::SECS_PER_DAY,
    );
    let one = UsageLedger {
        requests: 1,
        ..UsageLedger::default()
    };
    for w in [old, 0, live] {
        records
            .ledger()
            .put_usage("vk_horizon", w, &one)
            .await
            .expect("put");
    }
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);
    let flusher = crate::governance::spawn_budget_flusher(Arc::new(gov), shutdown_rx, None);
    shutdown_tx.send(()).expect("the flusher listens");
    flusher.await.expect("the flusher ends");
    let requests = async |w| {
        records
            .ledger()
            .get_usage("vk_horizon", w)
            .await
            .expect("get")
            .requests
    };
    assert_eq!(
        requests(old).await,
        0,
        "a window 40 days old is still in the durable store"
    );
    assert_eq!(requests(0).await, 1, "the all-time window is never purged");
    assert_eq!(requests(live).await, 1, "the live window is kept");
}

#[tokio::test]
async fn metering_open_units_keep_the_pinned_keys_historical_group() {
    let (store, gov, mut key) = team_gov().await;
    let cost = plane_fee_cost(1_000);
    let units = [("search_units".to_owned(), 3)].into();
    for group in [Some("team"), Some("later"), None, Some("team")] {
        key.group = group.map(str::to_owned);
        gov.record_usage_served(&cost, &key, "", "m", Some("p"), &units, AT);
    }
    gov.flush_metering().await;
    let counts: std::collections::BTreeMap<_, _> = store
        .ledger()
        .list_metering(metering_bucket(AT))
        .await
        .unwrap()
        .into_iter()
        .map(|row| {
            assert_eq!(
                (
                    row.key_id.as_str(),
                    row.model.as_str(),
                    row.provider.as_str()
                ),
                (key.id.as_str(), "m", "p")
            );
            assert!(
                row.pricing_version.is_empty(),
                "no named price version was supplied"
            );
            (
                row.key_group_at_use,
                Count::from_stored(row.usage_units["search_units"], row.scale)
                    .unwrap()
                    .whole_for_test(),
            )
        })
        .collect();
    assert_eq!(
        counts,
        [("team".into(), 6), ("later".into(), 3), (String::new(), 3)].into()
    );
}

#[tokio::test]
async fn credential_applied_commit_publishes_without_postcommit_refresh() {
    for operation in ["key.patch", "key.rotate", "key.delete"] {
        let (store, faults) = native_identity_fixture().await;
        let gov = GovState::new_with_core(store.clone(), None, Some(self_serve_signer()))
            .await
            .unwrap();
        let (key, token) = gov
            .mint_signed_async(
                NewKeySpec {
                    name: "typed-outcome".into(),
                    ..Default::default()
                },
                2000,
                1000,
            )
            .await
            .unwrap();
        faults.fail_scans_after_commit.store(true, Ordering::SeqCst);
        match operation {
            "key.patch" => {
                gov.update_key_outcome_async(&key.id, Some(false), None)
                    .await
                    .unwrap();
            }
            "key.rotate" => {
                gov.rotate_key_outcome_async(&key.id, 3000).await.unwrap();
            }
            _ => gov.delete_key_outcome_async(&key.id).await.unwrap(),
        }
        assert!(gov
            .verify_token(token.expose(&crate::seal::lend()), 1500, None)
            .is_none());
        let durable = store.identity().get_key(&key.id).await.unwrap().unwrap();
        match operation {
            "key.patch" => assert!(!durable.enabled),
            "key.rotate" => assert_ne!(durable.generation_hash, key.generation_hash),
            _ => assert!(durable.deleted_at.is_some()),
        }
    }
}

#[tokio::test]
async fn credential_precommit_write_failure_is_not_typed_applied() {
    let (store, faults) = native_identity_fixture().await;
    let gov = GovState::new_with_core(store.clone(), None, Some(self_serve_signer()))
        .await
        .unwrap();
    let (key, token) = gov
        .mint_signed_async(
            NewKeySpec {
                name: "precommit".into(),
                ..Default::default()
            },
            2000,
            1000,
        )
        .await
        .unwrap();
    faults.fail_writes.store(true, Ordering::SeqCst);
    assert!(matches!(
        gov.update_key_outcome_async(&key.id, Some(false), None)
            .await,
        Err(KeyMutationError::Store(_))
    ));
    assert!(matches!(
        gov.rotate_key_outcome_async(&key.id, 3000).await,
        Err(KeyMutationError::Store(_))
    ));
    assert!(gov
        .verify_token(token.expose(&crate::seal::lend()), 1500, None)
        .is_some());
    assert_eq!(
        store.identity().get_key(&key.id).await.unwrap().unwrap(),
        key
    );
}
