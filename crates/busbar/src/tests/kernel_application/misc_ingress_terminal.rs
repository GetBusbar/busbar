// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;
use std::time::Instant;

use axum::{http::StatusCode, response::IntoResponse};
use busbar_contract::records::{PlaneRequestCtx, ScopeRef, VirtualKey};
use busbar_kernel as kernel;
use kernel::ingress::{
    destination_guard, finish_admitted, finish_rejected, governance_guard, pool_label,
};
use kernel::state::App;

#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

fn deployment(pool: &str) -> Arc<App> {
    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built store"),
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
        "ingress-terminal-{}",
        kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let credential = directory.join("provider.key");
    std::fs::write(&credential, "unused-terminal-provider-key")
        .expect("write the normal provider credential data");
    let deploy = kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {"local": {"protocol": "anthropic", "base_url": "http://127.0.0.1:1", "api_key": {"file": credential}}},
        "models": {"m": {"provider": "local"}},
        "pools": {pool: {"members": ["m"]}},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let providers = std::collections::HashMap::from([(
        "local".to_owned(),
        serde_json::from_value::<kernel::config::ProviderDef>(serde_json::json!({
            "protocol": "anthropic", "base_url": "http://127.0.0.1:1"
        }))
        .expect("the actual provider catalog entry parses"),
    )]);
    let config =
        kernel::config::resolve(&deploy, &providers).expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules =
        Arc::new(crate::root::door_steps::Rules::default()) as Arc<dyn kernel::appbuild::RootRules>;
    let (app, rotate, limits) = kernel::build_app_from_config(
        config,
        plugin_config,
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
    let retention = std::time::Duration::from_secs(3600);
    kernel::snapshot::configure(Some(retention));
    kernel::snapshot::init_with(retention);
    Arc::new(app)
}

fn caller(pools: &[&str]) -> PlaneRequestCtx {
    PlaneRequestCtx {
        key: Some(Arc::new(VirtualKey {
            id: "ingress-terminal-key".to_string(),
            enabled: true,
            allowed_scopes: Some(pools.iter().map(|p| ScopeRef::pool(*p)).collect()),
            ..Default::default()
        })),
    }
}

fn request_terminals(proto: &str, pool: Option<&str>) -> u64 {
    let snapshot = kernel::snapshot::snapshot().expect("the real metrics recorder is installed");
    snapshot
        .iter()
        .flat_map(|family| family.samples.iter())
        .filter(|sample| sample.name == kernel::snapshot::REQUESTS_TOTAL)
        .filter(|sample| {
            sample
                .labels
                .iter()
                .any(|(name, value)| name == "ingress_protocol" && value == proto)
        })
        .filter(|sample| {
            pool.is_none_or(|pool| {
                sample
                    .labels
                    .iter()
                    .any(|(name, value)| name == "pool" && value == pool)
            })
        })
        .map(|sample| {
            sample
                .value
                .parse::<f64>()
                .expect("the request terminal counter is numeric")
        })
        .sum::<f64>()
        .round() as u64
}

fn terminals(proto: &str) -> u64 {
    request_terminals(proto, None)
}

#[test]
fn a_destination_refusal_ends_the_unit_exactly_once() {
    let pool = "ingress-terminal-acl-pool";
    let app = deployment(pool);
    let proto = "ingress-terminal-acl-proto";
    let before = terminals(proto);
    let Err(refused) = governance_guard(
        &app,
        &caller(&["some-other-pool"]),
        proto,
        pool,
        Instant::now(),
        0,
    ) else {
        panic!("a key without a grant on the pool is turned away");
    };
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        terminals(proto) - before,
        1,
        "one refused unit, one terminal: never none, never two"
    );
}

#[test]
fn an_admitted_unit_ends_once_at_its_finish_and_never_at_the_door() {
    let pool = "ingress-terminal-admitted-pool";
    let app = deployment(pool);
    let proto = "ingress-terminal-admitted-proto";
    let gov = caller(&[pool]);
    let before = terminals(proto);
    let (grant, downgraded) = governance_guard(&app, &gov, proto, pool, Instant::now(), 0)
        .expect("the key holds a grant on the pool");
    assert_eq!(
        terminals(proto),
        before,
        "the door admitted the unit, so it must not have ended it"
    );
    let _ = finish_admitted(
        &app,
        &gov,
        proto,
        downgraded.as_deref().unwrap_or(pool),
        Instant::now(),
        0,
        StatusCode::BAD_GATEWAY.into_response(),
        grant.as_ref().map(kernel::governance::AdmitGrant::charge),
    );
    assert_eq!(
        terminals(proto) - before,
        1,
        "one admitted unit, one terminal"
    );
}

#[test]
fn each_finish_door_is_one_terminal() {
    let pool = "ingress-terminal-doors-pool";
    let app = deployment(pool);
    let proto = "ingress-terminal-doors-proto";
    let gov = caller(&[pool]);
    let before = terminals(proto);
    let _ = finish_rejected(
        &app,
        &gov,
        proto,
        pool,
        Instant::now(),
        0,
        StatusCode::BAD_REQUEST.into_response(),
    );
    assert_eq!(terminals(proto) - before, 1, "the not-charged door");
    let _ = finish_admitted(
        &app,
        &gov,
        proto,
        pool,
        Instant::now(),
        0,
        StatusCode::OK.into_response(),
        None,
    );
    assert_eq!(terminals(proto) - before, 2, "the charged door");
}

#[test]
fn the_refused_terminal_labels_a_configured_pool_with_its_name() {
    let pool = "ingress-terminal-label-pool";
    let app = deployment(pool);
    assert_eq!(
        pool_label(&app, pool),
        pool,
        "the fixture's pool is configured, so the live label is its name"
    );

    let proto = "ingress-terminal-label-proto";
    let labelled = |label: &str| request_terminals(proto, Some(label));
    let before = labelled(pool);
    let Err(refused) = destination_guard(
        &app,
        &caller(&["some-other-pool"]),
        proto,
        pool,
        Instant::now(),
        0,
    ) else {
        panic!("the key may not reach the pool it named");
    };
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        labelled(pool) - before,
        1,
        "the refusal's terminal is labelled with the configured pool's name"
    );

    let unknown = "ingress-terminal-no-such-pool";
    assert_eq!(
        pool_label(&app, unknown),
        kernel::telemetry::POOL_LABEL_UNRESOLVED
    );
    let unresolved_proto = "ingress-terminal-label-unresolved-proto";
    let unresolved = || {
        request_terminals(
            unresolved_proto,
            Some(kernel::telemetry::POOL_LABEL_UNRESOLVED),
        )
    };
    let before = unresolved();
    let Err(refused) = destination_guard(
        &app,
        &caller(&["some-other-pool"]),
        unresolved_proto,
        unknown,
        Instant::now(),
        0,
    ) else {
        panic!("the key may not reach a name it holds no grant on");
    };
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        unresolved() - before,
        1,
        "an unconfigured name is never widened into a label of its own"
    );
}
