// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel as kernel;
use kernel::trust::book::RulingRow;
use std::sync::Arc;

use crate::root::test_plugins as plugins;

#[tokio::test]
async fn boot_hydration_makes_the_trust_record_durable_on_the_configured_store() {
    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_TEST_SQLITE_CDYLIB")
            .expect("BUSBAR_TEST_SQLITE_CDYLIB names the actual built SQLite store"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch(&format!(
        "boot-trust-persistence-{}",
        kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    assert_eq!(
        module, "busbar-store-sqlite",
        "this restart oracle requires the actual durable SQLite product"
    );
    let database = directory.join("trust.sqlite3");
    let settings = serde_json::json!({"db_path": database});
    let deploy = kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let config = kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules =
        Arc::new(crate::root::door_steps::Rules::default()) as Arc<dyn kernel::appbuild::RootRules>;
    let (app, rotate, limits) = crate::root::real_store::build_app(
        config,
        plugin_config.clone(),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .await
    .expect("the actual product builds the host deployment");
    if !crate::root::kernel::ROOT_CARD.keeps_store() {
        limits.stage_boot();
        crate::root::kernel::ROOT_CARD
            .keep_in_store(
                app.governance
                    .as_ref()
                    .expect("the actual deployment configured governance")
                    .core_store_handle()
                    .expect("the configured Store exposes canonical persistence"),
                144,
            )
            .expect("the canonical rate history binds");
        crate::root::kernel::ROOT_CARD
            .boot_in_store(None)
            .await
            .expect("the configured Store boots its initial rate history");
    }
    limits.keep().await.expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let app = Arc::new(app);
    kernel::boot::hydrate_all(&app)
        .await
        .expect("boot hydrates");

    let decision = RulingRow {
        instance: "inst".to_string(),
        counterparty: "upstream".to_string(),
        item: None,
        approved: Some("sha256:pinned".to_string()),
        declared: None,
        demoted: false,
    };
    app.demotion_record
        .keep_decision(&decision, 1)
        .await
        .expect("the store keeps the decision");
    app.demotion_record
        .record("inst\u{1f}upstream", "quarantined", 1)
        .await
        .expect("the native trust owner keeps the demotion data");

    drop(app);
    assert!(
        database.is_file(),
        "the actual Store created the configured database"
    );
    let (restarted_app, rotate, limits) = crate::root::real_store::build_app(
        kernel::config::resolve(&deploy, &Default::default())
            .expect("the same deployment resolves after restart"),
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .await
    .expect("the actual product reopens its durable Store");
    limits
        .keep()
        .await
        .expect("the restarted product limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let restarted_app = Arc::new(restarted_app);
    kernel::audit::auditlog::register_test_audit_stream(&restarted_app).await;
    kernel::boot::hydrate_all(&restarted_app)
        .await
        .expect("restart hydrates from the actual Store");
    let restarted = &restarted_app.demotion_record;
    assert_eq!(
        restarted.decisions().await.expect("the store reads"),
        vec![decision],
        "an operator's trust decision outlives the process"
    );
    let demoted = restarted.read().await.expect("the store reads");
    assert_eq!(demoted.len(), 1, "a demotion outlives the process");
    assert_eq!(demoted[0].upstream, "inst\u{1f}upstream");
}
