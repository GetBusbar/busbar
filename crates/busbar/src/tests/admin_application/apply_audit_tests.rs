// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SECRET-SHORTHAND-BOOT MR-A: a refused config apply is audited (F2), and a transaction that ends
//! without publishing leaves the live dropped-in secret set as it found it (F1).

use std::collections::HashSet;
use std::sync::Arc;

use busbar_core_admin::v1::contract::AdminError;
use busbar_kernel::audit_ring;
use busbar_kernel::config::transaction::config_transaction;

/// RA6 (F2): `POST config/apply` whose body the parse refuses is a refused apply like any other:
/// the audit records it as rejected.
#[tokio::test]
async fn admin_apply_parse_refusal_is_audited() {
    const CHILD: &str = "BUSBAR_SSB_APPLY_AUDIT_CHILD";
    const WITNESS: &str = "actual root case admin_apply_parse_refusal_is_audited completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) =
        crate::distribution::rig::actual_store("admin_apply_parse_refusal_is_audited-store");
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the test signing input");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let plugin_document = crate::root::test_plugins::config_document(
        &crate::root::test_plugins::trusted_config(&directory),
    );
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "plugins": plugin_document,
        "advanced": {  },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let crate::root::min3_boot::fixture::Fixture {
        backend: anchor,
        rules,
    } = crate::root::min3_boot::fixture::open(&config, &plugin_config, rules.clone())
        .await
        .expect("the actual Store opens the configuration authority");
    let anchor = crate::root::real_store::core_over(anchor).await;
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
        .expect("the actual Store supports conditional configuration records");
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay),
        HashSet::new(),
        HashSet::new(),
        (None, None),
        None,
        &rules,
        Some(anchor),
        true,
    )
    .await
    .expect("the real root composes the configured Store and admin application");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .await
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().await.expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let router =
        busbar_kernel::build_router(crate::root::real_store::hydrated(Arc::new(app)).await);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    let refused = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/admin/config/apply"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "config": {
                    "not_a_config_key": true,
                    "providers": {},
                    "store": {"module": module, "settings": settings},
                    "plugins": plugin_document,
                    "models": {}
                },
                "providers": {}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    let status = refused.status().as_u16();
    let body = refused.text().await.unwrap();
    assert_eq!(status, 400, "the parse refuses the body: {body}");

    let rows = busbar_kernel::audit::auditlog::AUDIT_LOG.list_filtered(
        0,
        audit_ring::MAX_AUDIT_ENTRIES,
        Some("config.apply"),
        None,
    );
    assert!(
        rows.iter()
            .any(|e| e.resource == "config:body" && e.outcome == audit_ring::OUTCOME_REJECTED),
        "a parse-refused apply is audited as rejected: {rows:?}"
    );
    handle.abort();
    println!("{WITNESS}");
}

/// A dropped-in secret candidate the live axis answers to by `name` (no image behind it).
fn dropped_secret(name: &str) -> busbar_plugin_loader::boot::Candidate {
    busbar_plugin_loader::boot::Candidate {
        kind: busbar_contract::abi::mechanism::KindCode::Secret,
        name: name.into(),
        version: "1.0.0".into(),
        aliases: Vec::new(),
        sugar: Vec::new(),
        verbs: Vec::new(),
        selecting: Vec::new(),
        schemes: Vec::new(),
        needs: Vec::new(),
        stated: Vec::new(),
        origin: busbar_plugin_loader::boot::Origin::Dropped {
            file: format!("{name}.tar.gz"),
            bytes: Arc::new(Vec::new()),
        },
        disk: false,
        orders: true,
    }
}

/// RA5 (F1): a build's admission puts its dropped-in secret set on the live axis before the
/// generation is published. A transaction whose commit is then refused must put the set it found
/// back: an unpublished generation's secret modules never answer for the serving one.
#[tokio::test]
async fn refused_commit_after_build_restores_the_secret_axis() {
    use busbar_contract::secret::SecretAxis as _;
    const CHILD: &str = "BUSBAR_SSB_SECRET_RESTORE_CHILD";
    const WITNESS: &str =
        "actual root case refused_commit_after_build_restores_the_secret_axis completed";
    isolated!(CHILD, WITNESS);
    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "refused_commit_after_build_restores_the_secret_axis-store",
    );
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        serde_json::json!({
            "providers": {},
            "models": {},
            "auth": { "chain": [], "admin_auth": [] },
            "store": { "module": module, "settings": settings },
            "advanced": {  },
        }),
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = crate::root::real_store::build_app(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .await
    .expect("the actual product builds");
    limits.stage_boot();
    let boot_calls = app
        .governance
        .as_ref()
        .expect("actual governance")
        .core_store_handle()
        .expect("actual boot Store calls");
    crate::root::kernel::ROOT_CARD
        .keep_in_store(boot_calls, 101)
        .expect("actual rate history binds once");
    crate::root::kernel::ROOT_CARD
        .boot_in_store(None)
        .await
        .expect("the actual rate history boots before rates are committed");
    limits
        .keep()
        .await
        .expect("the booted actual rates and limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(Arc::new(app)));

    let rows = crate::root::linked::secret_rows();
    let serving = dropped_secret("ssb-serving-vault");
    let unpublished = dropped_secret("ssb-unpublished-vault");
    rows.set_dropped([serving.clone()]);
    let before = handle.load().config_version;
    let refused = config_transaction::<_, (), AdminError>(&handle, |txn| {
        // What a reload's build admission does before its generation is published.
        rows.set_dropped([unpublished.clone()]);
        let mut next = (**txn.app()).clone();
        next.config_version = before.wrapping_add(1);
        Ok(txn.commit(Arc::new(next), || Err("disk said no".to_string()), ()))
    })
    .await;
    assert!(refused.is_err(), "the refused commit fails the transaction");
    assert_eq!(
        handle.load().config_version,
        before,
        "nothing was published"
    );
    assert!(
        !rows.answers("ssb-unpublished-vault"),
        "the unpublished generation's secret module stayed on the live axis"
    );
    assert!(
        rows.answers("ssb-serving-vault"),
        "the serving generation's secret module was not put back"
    );
    rows.set_dropped(std::iter::empty());
    println!("{WITNESS}");
}
