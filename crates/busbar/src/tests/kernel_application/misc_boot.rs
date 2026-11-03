// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel as kernel;
use kernel::trust::book::RulingRow;
use std::sync::Arc;

use crate::root::test_plugins as plugins;

#[test]
fn boot_hydration_makes_the_trust_record_durable_on_the_configured_store() {
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
    let (app, rotate, limits) = kernel::build_app_from_config(
        config,
        plugin_config.clone(),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the actual product builds the host deployment");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);
    kernel::boot::hydrate_all(&app).expect("boot hydrates");

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
        .expect("the store keeps the decision");
    let demotion = busbar_contract::records::PlaneRecord {
        kind: kernel::store::plane_view::KIND_DEMOTION.into(),
        id: "inst\u{1f}upstream".into(),
        parent: None,
        seq: 0,
        ts: 1,
        disposition: busbar_contract::records::PlaneDisposition::Active,
        body: serde_json::to_vec(&serde_json::json!({
            "server": "inst\u{1f}upstream", "reason": "quarantined", "recorded_at": 1,
        }))
        .expect("the persisted demotion data is JSON"),
    };
    kernel::store::plane_view::PlaneStoreView::narrow(
        app.governance
            .as_ref()
            .expect("the actual Store owns governance")
            .store(),
    )
    .upsert_plane_record(demotion.view())
    .expect("the actual Store keeps the demotion data");

    drop(app);
    assert!(
        database.is_file(),
        "the actual Store created the configured database"
    );
    let (restarted_app, rotate, limits) = kernel::build_app_from_config(
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
    .expect("the actual product reopens its durable Store");
    limits.keep().expect("the restarted product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let restarted_app = Arc::new(restarted_app);
    kernel::boot::hydrate_all(&restarted_app).expect("restart hydrates from the actual Store");
    let restarted = &restarted_app.demotion_record;
    assert_eq!(
        restarted.decisions().expect("the store reads"),
        vec![decision],
        "an operator's trust decision outlives the process"
    );
    let demoted = restarted.read().expect("the store reads");
    assert_eq!(demoted.len(), 1, "a demotion outlives the process");
    assert_eq!(demoted[0].upstream, "inst\u{1f}upstream");
}
