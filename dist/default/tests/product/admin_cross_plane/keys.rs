// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel::governance::{GovState, NewKeySpec};
use busbar_kernel::plane_driver::serve::ServeTables;

const PROTO_ANTHROPIC: &str = "anthropic";

use std::sync::Arc;

/// The governance posture a keys error case is exercised against.
#[derive(Clone, Copy, PartialEq, Eq)]
enum KeysFixture {
    /// Governance on, signing key present — the normal server.
    Signing,
    /// Governance on, NO signing key — mint and signing-key rotate have nothing to sign with.
    NoSigner,
    /// Governance off entirely — the whole keys resource is unavailable.
    Off,
}

struct KeysErrCase {
    name: &'static str,
    fixture: KeysFixture,
    method: &'static str,

    path: &'static str,
    headers: &'static [(&'static str, &'static str)],
    body: Option<&'static str>,
}

const KEYS_ERROR_GOLDEN: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../crates/busbar-core-admin/src/tests/keys_error_wire.json"
);

const fn c(
    name: &'static str,
    fixture: KeysFixture,
    method: &'static str,
    path: &'static str,
    headers: &'static [(&'static str, &'static str)],
    body: Option<&'static str>,
) -> KeysErrCase {
    KeysErrCase {
        name,
        fixture,
        method,
        path,
        headers,
        body,
    }
}

fn gov_with_signer(
    store: Arc<dyn busbar_kernel::governance::RecordStore>,
    admin_token: Option<String>,
) -> Arc<GovState> {
    Arc::new(
        GovState::new_with_signer(
            store,
            admin_token,
            Some(
                busbar_kernel::governance::signing::TokenSigner::from_secret_bytes(
                    &[9u8; 32],
                    busbar_kernel::governance::signing::DEFAULT_KID,
                ),
            ),
        )
        .unwrap(),
    )
}

async fn spin_up(
    router: axum::Router,
) -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<()>,
    reqwest::Client,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (addr, handle, reqwest::Client::new())
}

async fn drive_unpriced_usage_reads() -> Vec<(String, u16, serde_json::Value)> {
    crate::distribution::admin_cross_plane::ensure_seam();
    let store = crate::root::real_store::store();
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let card: std::collections::BTreeMap<String, busbar_kernel::config::RateEntryCfg> =
        std::collections::BTreeMap::from([(
            "m".to_string(),
            busbar_kernel::config::RateEntryCfg {
                input_utok: 500.0,
                output_utok: -1.0,
                ..Default::default()
            },
        )]);
    let groups = std::collections::BTreeMap::from([(
        "team".to_string(),
        busbar_kernel::config::GroupCfg {
            enabled: true,
            limits: vec![busbar_kernel::config::groups::LimitCfg {
                metric: busbar_kernel::config::groups::LimitMetric::Budget,
                amount: 1_000_000,
                per: Some(busbar_kernel::config::groups::LimitWindow::Total),
                scope: None,
                on_exhaust: None,
                downgrade_to: None,
                admission: None,
                on_exhaustion: None,
            }],
            ..Default::default()
        },
    )]);
    let cost = busbar_kernel::cost::CostModel::resolve_parts(Some(&card), 0, &groups);
    let now = busbar_kernel::store::now();
    let (minted, _secret) = gov
        .mint_signed(
            NewKeySpec {
                name: "k".to_string(),
                ..Default::default()
            },
            now + 3600,
            now,
        )
        .unwrap();

    let app = {
        crate::distribution::admin_cross_plane::ensure_seam();
        let directory = super::plugins::scratch(&format!(
            "admin-root-{}",
            busbar_kernel::door::op_id().counter()
        ));
        let library_path = crate::root::test_plugins::application_store_library();
        let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
            .expect("the actual Store statement reads")
            .expect("the actual Store states itself");
        let facts = busbar_contract::abi::mechanism::rendering::read(&statement)
            .expect("the actual Store statement parses");
        let mut manifest =
            super::plugins::manifest("store", &facts.name, super::plugins::FIXTURE_PUBLISHER);
        manifest.version = facts.version;
        manifest.statement = Some(hex::encode(statement));
        let archive = super::plugins::signed(
            &crate::dist_root_install::release_key(),
            manifest,
            &std::fs::read(library_path).expect("the actual Store artifact reads"),
        );
        std::fs::write(directory.join("store.tar.gz"), archive)
            .expect("stage the actual Store product");
        std::fs::write(directory.join("admin.token"), "admintok")
            .expect("write the operator credential");
        let settings = crate::root::test_plugins::application_store_settings(&directory);
        let mut document = serde_json::json!({});
        document["providers"] = serde_json::json!({});
        document["models"] = serde_json::json!({});
        document["store"] = serde_json::json!({"module": facts.name, "settings": settings});
        document["plugins"] =
            super::plugins::config_document(&super::plugins::trusted_config(&directory));
        document["auth"] = serde_json::json!({"chain": [], "admin_auth": ["admin-tokens"]});
        document["identity-providers"] = serde_json::json!({"admin-tokens": {
            "module": "admin-tokens", "token": {"file": directory.join("admin.token")}
        }});
        document["advanced"] = serde_json::json!({"allow_destinations": ["127.0.0.1"]});
        let deploy = busbar_kernel::config::deploy_from_deserializer(document)
            .expect("the actual admin deployment parses");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the actual admin deployment resolves");
        let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
            as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
        let (mut app, rotate, limits) = busbar_kernel::build_app_from_config(
            cfg,
            super::plugins::trusted_config(&directory),
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
        )
        .expect("the product root builds the actual admin application");
        limits.stage_boot();
        let _book = crate::root::boot::book(&app, "configured-store")
            .expect("the actual configured Store binds boot rate history before activation");
        limits.keep().expect("the product limits commit");
        if let Some(rotate) = rotate {
            rotate();
        }
        app.overlay_path = Some(
            busbar_kernel::config::overlay::OverlayStore::new(
                app.governance
                    .as_ref()
                    .expect("the actual root opened governance")
                    .store_calls()
                    .expect("the actual Store exposes its calls"),
            )
            .expect("the actual Store opens its overlay"),
        );
        // Model the historical unpriced card through the actual Store-backed rate holder;
        // the normal boot configuration remains valid and receives its ordinary validation.
        let historical = busbar_kernel::config::card::CardFields {
            rate_card: Some(card.clone()),
            ..Default::default()
        };
        let rates = historical.rates();
        busbar_kernel::rate_apply::with_origin("historical unpriced usage fixture", || {
            busbar_kernel::rate_apply::prepare(&historical, &rates.raw())
        })
        .expect("the actual Store prepares the historical unpriced card")
        .confirm_activation()
        .expect("the actual Store confirms the historical card's activation")
        .commit();
        let now = busbar_kernel::store::now();
        let mut in_team = minted.clone();
        in_team.group = Some("team".to_string());
        let units = std::collections::BTreeMap::from([
            (busbar_contract::records::UNIT_INPUT.to_string(), 700u64),
            (busbar_contract::records::UNIT_OUTPUT.to_string(), 200u64),
        ]);
        gov.record_usage(&cost, &in_team, "", "m", &units, now);
        let usage = busbar_contract::billing::TokenUsage {
            input: 700,
            output: 200,
            ..Default::default()
        };
        gov.record_metering(&minted.id, "m", "vendor", Some(&usage), now);
        gov.flush_metering();
        app.governance = Some(gov);
        app.cost = std::sync::Arc::new(cost);

        std::sync::Arc::new(app)
    };
    let router = crate::distribution::admin_cross_plane::build_router(app);
    let (addr, handle, client) = spin_up(router).await;
    let mut out = Vec::new();
    for path in [
        format!("/api/v1/admin/keys/{}/usage", minted.id),
        "/api/v1/admin/groups/team/usage".to_string(),
        "/api/v1/admin/usage".to_string(),
    ] {
        let resp = client
            .get(format!("http://{addr}{path}"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
        out.push((path, status, body));
    }
    handle.abort();
    out
}

async fn assert_unpriced_usage_read_is_named(prefix: &str) {
    let reads = drive_unpriced_usage_reads().await;
    let (path, status, body) = reads
        .iter()
        .find(|(p, _, _)| p.starts_with(prefix))
        .expect("the driver reads every usage path");
    assert_eq!(
        *status, 409,
        "{path}: an unpriced class under a present rate card is a NAMED 409 (Q25b), not a bare \
         500: {body}"
    );
    assert_eq!(body["error"]["code"], "unpriced_class", "{path}: {body}");
    let message = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("`m`") && message.contains("`output`"),
        "{path}: the refusal names the lane and the class: {body}"
    );
}

#[tokio::test]
async fn config_apply_accepts_a_plane_section_and_moves_that_planes_own_fee() {
    use http_body_util::BodyExt;
    crate::distribution::admin_cross_plane::ensure_seam();
    let store = crate::root::real_store::store();
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let overlay =
        busbar_kernel::config::overlay::OverlayStore::new(crate::root::real_store::store())
            .expect("the actual Store opens the overlay");
    let app = {
        crate::distribution::admin_cross_plane::ensure_seam();
        let directory = super::plugins::scratch(&format!(
            "admin-root-{}",
            busbar_kernel::door::op_id().counter()
        ));
        let library_path = crate::root::test_plugins::application_store_library();
        let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
            .expect("the actual Store statement reads")
            .expect("the actual Store states itself");
        let facts = busbar_contract::abi::mechanism::rendering::read(&statement)
            .expect("the actual Store statement parses");
        let mut manifest =
            super::plugins::manifest("store", &facts.name, super::plugins::FIXTURE_PUBLISHER);
        manifest.version = facts.version;
        manifest.statement = Some(hex::encode(statement));
        let archive = super::plugins::signed(
            &crate::dist_root_install::release_key(),
            manifest,
            &std::fs::read(library_path).expect("the actual Store artifact reads"),
        );
        std::fs::write(directory.join("store.tar.gz"), archive)
            .expect("stage the actual Store product");
        std::fs::write(directory.join("admin.token"), "admintok")
            .expect("write the operator credential");
        let settings = crate::root::test_plugins::application_store_settings(&directory);
        let mut document = serde_json::json!({});
        document["providers"] = serde_json::json!({});
        document["models"] = serde_json::json!({});
        document["store"] = serde_json::json!({"module": facts.name, "settings": settings});
        document["plugins"] =
            super::plugins::config_document(&super::plugins::trusted_config(&directory));
        document["auth"] = serde_json::json!({"chain": [], "admin_auth": ["admin-tokens"]});
        document["identity-providers"] = serde_json::json!({"admin-tokens": {
            "module": "admin-tokens", "token": {"file": directory.join("admin.token")}
        }});
        document["advanced"] = serde_json::json!({"allow_destinations": ["127.0.0.1"]});
        let deploy = busbar_kernel::config::deploy_from_deserializer(document)
            .expect("the actual admin deployment parses");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the actual admin deployment resolves");
        let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
            as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
        let (mut app, rotate, limits) = busbar_kernel::build_app_from_config(
            cfg,
            super::plugins::trusted_config(&directory),
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
        )
        .expect("the product root builds the actual admin application");
        limits.stage_boot();
        let _book = crate::root::boot::book(&app, "configured-store")
            .expect("the actual configured Store binds boot rate history before activation");
        limits.keep().expect("the product limits commit");
        if let Some(rotate) = rotate {
            rotate();
        }
        app.overlay_path = Some(
            busbar_kernel::config::overlay::OverlayStore::new(
                app.governance
                    .as_ref()
                    .expect("the actual root opened governance")
                    .store_calls()
                    .expect("the actual Store exposes its calls"),
            )
            .expect("the actual Store opens its overlay"),
        );
        app.governance = Some(gov);
        app.overlay_path = Some(overlay.clone());

        std::sync::Arc::new(app)
    };

    let section = "tools";
    let plane = busbar_kernel::plane_driver::registry::plane_decl_for_config_section(section)
        .expect("a plane is registered to own the `tools:` section");
    let fee_lane = busbar_kernel_ledger::cost::plane_fee_lane(plane.key);
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(app));
    let fee =
        |h: &busbar_kernel::state::AppHandle| h.load().cost.card().plane_lane(&fee_lane).0.fee();
    assert_eq!(fee(&handle), 0, "the test App configures no plane fee");

    let apply = |config: serde_json::Value| {
        let handle = handle.clone();
        async move {
            let body = axum::body::Bytes::from(
                serde_json::json!({ "config": config, "providers": {} }).to_string(),
            );
            let resp = busbar_core_admin::test_support::apply_config(
                axum::extract::State(handle),
                axum::Extension(busbar_kernel::auth::AuthPrincipal(None)),
                axum::http::HeaderMap::new(),
                body,
            )
            .await;
            let status = resp.status().as_u16();
            let bytes = resp.into_body().collect().await.unwrap().to_bytes();
            (status, String::from_utf8_lossy(&bytes).into_owned())
        }
    };
    let base = || {
        serde_json::json!({
            "providers": {},
            "models": {},
            "store": {"module": "memory"}
        })
    };

    let mut with_plane = base();
    with_plane[section] = serde_json::json!({ "fees": { "per_request": 7 } });
    let (status, body) = apply(with_plane).await;
    assert_eq!(
        status, 200,
        "a document carrying a plane section (as boot accepts it) must apply: {body}"
    );
    assert_eq!(
        fee(&handle),
        7,
        "the applied App prices the plane's requests at the plane's own applied fee (#47)"
    );

    let mut unknown = base();
    unknown["no_plane_declares_this"] = serde_json::json!({});
    let (status, body) = apply(unknown).await;
    assert_eq!(
        status, 400,
        "a key no registered plane declares is still refused, as boot refuses it: {body}"
    );
    assert!(
        body.contains("unknown field"),
        "named as boot names it: {body}"
    );
    assert_eq!(fee(&handle), 7, "a refused apply changes nothing");
}

#[tokio::test]
async fn test_admin_v1_openapi_is_identity_json_for_every_client() {
    crate::distribution::admin_cross_plane::ensure_seam();
    let store = crate::root::real_store::store();
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = {
        crate::distribution::admin_cross_plane::ensure_seam();
        let directory = super::plugins::scratch(&format!(
            "admin-root-{}",
            busbar_kernel::door::op_id().counter()
        ));
        let library_path = crate::root::test_plugins::application_store_library();
        let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
            .expect("the actual Store statement reads")
            .expect("the actual Store states itself");
        let facts = busbar_contract::abi::mechanism::rendering::read(&statement)
            .expect("the actual Store statement parses");
        let mut manifest =
            super::plugins::manifest("store", &facts.name, super::plugins::FIXTURE_PUBLISHER);
        manifest.version = facts.version;
        manifest.statement = Some(hex::encode(statement));
        let archive = super::plugins::signed(
            &crate::dist_root_install::release_key(),
            manifest,
            &std::fs::read(library_path).expect("the actual Store artifact reads"),
        );
        std::fs::write(directory.join("store.tar.gz"), archive)
            .expect("stage the actual Store product");
        std::fs::write(directory.join("admin.token"), "admintok")
            .expect("write the operator credential");
        let settings = crate::root::test_plugins::application_store_settings(&directory);
        let mut document = serde_json::json!({});
        document["providers"] = serde_json::json!({});
        document["models"] = serde_json::json!({});
        document["store"] = serde_json::json!({"module": facts.name, "settings": settings});
        document["plugins"] =
            super::plugins::config_document(&super::plugins::trusted_config(&directory));
        document["auth"] = serde_json::json!({"chain": [], "admin_auth": ["admin-tokens"]});
        document["identity-providers"] = serde_json::json!({"admin-tokens": {
            "module": "admin-tokens", "token": {"file": directory.join("admin.token")}
        }});
        document["advanced"] = serde_json::json!({"allow_destinations": ["127.0.0.1"]});
        let deploy = busbar_kernel::config::deploy_from_deserializer(document)
            .expect("the actual admin deployment parses");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the actual admin deployment resolves");
        let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
            as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
        let (mut app, rotate, limits) = busbar_kernel::build_app_from_config(
            cfg,
            super::plugins::trusted_config(&directory),
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
        )
        .expect("the product root builds the actual admin application");
        limits.stage_boot();
        let _book = crate::root::boot::book(&app, "configured-store")
            .expect("the actual configured Store binds boot rate history before activation");
        limits.keep().expect("the product limits commit");
        if let Some(rotate) = rotate {
            rotate();
        }
        app.overlay_path = Some(
            busbar_kernel::config::overlay::OverlayStore::new(
                app.governance
                    .as_ref()
                    .expect("the actual root opened governance")
                    .store_calls()
                    .expect("the actual Store exposes its calls"),
            )
            .expect("the actual Store opens its overlay"),
        );
        app.governance = Some(gov);

        std::sync::Arc::new(app)
    };
    let router = crate::distribution::admin_cross_plane::build_router(app);
    let (addr, handle, client) = spin_up(router).await;
    let url = format!("http://{addr}/api/v1/admin/openapi.json");

    let mut bodies = Vec::new();
    for accept in [
        None,
        Some("gzip"),
        Some("gzip;q=0"),
        Some("br, gzip, deflate"),
    ] {
        let mut req = client.get(&url).header("x-admin-token", "admintok");
        if let Some(a) = accept {
            req = req.header("accept-encoding", a);
        }
        let resp = req.send().await.unwrap();
        assert_eq!(resp.status().as_u16(), 200, "{accept:?}");
        assert!(
            resp.headers().get("content-encoding").is_none(),
            "{accept:?}: the document is identity-encoded, as 1.5.5 served it"
        );
        assert!(
            resp.headers().get("vary").is_none(),
            "{accept:?}: no Vary, as 1.5.5 served it"
        );
        let body = resp.text().await.unwrap();
        assert!(body.starts_with('{'), "{accept:?}: the JSON document");
        bodies.push(body);
    }
    assert!(
        bodies.windows(2).all(|w| w[0] == w[1]),
        "every client reads the same document"
    );
    handle.abort();
}

fn admin_test_tarball(name: &str, alias: &str) -> Vec<u8> {
    admin_test_tarball_versioned(name, alias, "1.0.0")
}

fn admin_test_tarball_versioned(name: &str, alias: &str, version: &str) -> Vec<u8> {
    let lib = format!("junk library bytes for {name} {version} (never dlopened)").into_bytes();
    let lib = lib.as_slice();
    let m = busbar_plugin_loader::sign::Manifest {
        name: name.into(),
        alias: alias.into(),
        kind: "store".into(),
        version: version.into(),
        publisher: "acme".into(),
        abi_version: *busbar_plugin_loader::supported_abi("store")
            .iter()
            .max()
            .expect("store abi"),
        sha256: busbar_plugin_loader::sign::sha256_hex(lib),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: Default::default(),
        settings_schema: None,
        schema_derived: false,
        host: None,
        declares: Default::default(),
        statement: None,
        former_names: Vec::new(),
    };
    busbar_plugin_loader::tarball::package(&m, "lib.so", lib).unwrap()
}

fn budget_limit(cents: u64) -> busbar_kernel::config::groups::LimitCfg {
    busbar_kernel::config::groups::LimitCfg {
        metric: busbar_kernel::config::groups::LimitMetric::Budget,
        amount: cents,
        per: Some(busbar_kernel::config::groups::LimitWindow::Month),
        scope: None,
        on_exhaust: None,
        downgrade_to: None,
        admission: None,
        on_exhaustion: None,
    }
}

/// The three anti-sprawl refusals, driven end-to-end. Split out of the `#[tokio::test]` so the
/// class-level drift test can run it too.
///
/// 1. **`PATCH /keys/{id}` rebind into an at-cap group**. Only its pure
///    predicate (`check_key_cap`) was tested; the HANDLER arm that turns it into a 409 had no test
///    at all, so `contract::taxonomy` never declared `Conflict/AtKeyCap` for that operation and
///    `openapi.json` documented a `409` that named only `GovernanceOff`. The under-claim guard could
///    not catch it either: it compared `ErrKind` alone, and `Conflict` WAS declared.
/// 2. **RE-ENABLE past the cap** — the same ratchet, reached through the other field. `check_key_cap` counts LIVE keys, so `disable → mint → re-enable` walks a bucket past
///    its ceiling with every single request passing the guard. Now gated by the same 409.
///
/// (1.5.2 scope collapse removed the former case 3 — the delegated-mint-must-bind 400 — since the
/// narrower `mint` scope that could reach it no longer exists; only a `full` operator mints, and the
/// operator may legitimately mint an unbound key.)
///
/// It also asserts the audit consequence: every one of these refusals writes a `rejected` row —
/// a refused mint is an attempt to issue a credential, and it must leave a trace.
async fn drive_key_cap_and_delegation_errors() {
    crate::distribution::admin_cross_plane::ensure_seam();
    let store = crate::root::real_store::store();
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let groups = std::collections::BTreeMap::from([
        (
            "capped".to_string(),
            busbar_kernel::config::GroupCfg {
                limits: vec![budget_limit(1_000_000)],
                ..Default::default()
            },
        ),
        (
            "roomy".to_string(),
            busbar_kernel::config::GroupCfg {
                limits: vec![budget_limit(1_000_000)],
                ..Default::default()
            },
        ),
    ]);
    let mut app = {
        crate::distribution::admin_cross_plane::ensure_seam();
        let directory = super::plugins::scratch(&format!(
            "admin-root-{}",
            busbar_kernel::door::op_id().counter()
        ));
        let library_path = crate::root::test_plugins::application_store_library();
        let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
            .expect("the actual Store statement reads")
            .expect("the actual Store states itself");
        let facts = busbar_contract::abi::mechanism::rendering::read(&statement)
            .expect("the actual Store statement parses");
        let mut manifest =
            super::plugins::manifest("store", &facts.name, super::plugins::FIXTURE_PUBLISHER);
        manifest.version = facts.version;
        manifest.statement = Some(hex::encode(statement));
        let archive = super::plugins::signed(
            &crate::dist_root_install::release_key(),
            manifest,
            &std::fs::read(library_path).expect("the actual Store artifact reads"),
        );
        std::fs::write(directory.join("store.tar.gz"), archive)
            .expect("stage the actual Store product");
        std::fs::write(directory.join("admin.token"), "admintok")
            .expect("write the operator credential");
        let settings = crate::root::test_plugins::application_store_settings(&directory);
        let mut document = serde_json::json!({"groups": groups});
        document["providers"] = serde_json::json!({});
        document["models"] = serde_json::json!({});
        document["store"] = serde_json::json!({"module": facts.name, "settings": settings});
        document["plugins"] =
            super::plugins::config_document(&super::plugins::trusted_config(&directory));
        document["auth"] = serde_json::json!({"chain": [], "admin_auth": ["admin-tokens"]});
        document["identity-providers"] = serde_json::json!({"admin-tokens": {
            "module": "admin-tokens", "token": {"file": directory.join("admin.token")}
        }});
        document["advanced"] = serde_json::json!({"allow_destinations": ["127.0.0.1"]});
        let deploy = busbar_kernel::config::deploy_from_deserializer(document)
            .expect("the actual admin deployment parses");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the actual admin deployment resolves");
        let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
            as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
        let (mut app, rotate, limits) = busbar_kernel::build_app_from_config(
            cfg,
            super::plugins::trusted_config(&directory),
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
        )
        .expect("the product root builds the actual admin application");
        limits.stage_boot();
        let _book = crate::root::boot::book(&app, "configured-store")
            .expect("the actual configured Store binds boot rate history before activation");
        limits.keep().expect("the product limits commit");
        if let Some(rotate) = rotate {
            rotate();
        }
        app.overlay_path = Some(
            busbar_kernel::config::overlay::OverlayStore::new(
                app.governance
                    .as_ref()
                    .expect("the actual root opened governance")
                    .store_calls()
                    .expect("the actual Store exposes its calls"),
            )
            .expect("the actual Store opens its overlay"),
        );
        app.governance = Some(gov);

        std::sync::Arc::new(app)
    };
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.max_keys_per_principal = 2;
    }
    busbar_kernel::audit::auditlog::register_test_audit_stream(&app);
    let router = crate::distribution::admin_cross_plane::build_router(app);
    let (addr, server, client) = spin_up(router).await;
    let keys_url = format!("http://{addr}/api/v1/admin/keys");

    let mint = |name: &'static str, group: &'static str| {
        let (c, u) = (client.clone(), keys_url.clone());
        async move {
            let r = c
                .post(&u)
                .header("x-admin-token", "admintok")
                .json(&serde_json::json!({"name": name, "group": group}))
                .send()
                .await
                .unwrap();
            assert_eq!(r.status().as_u16(), 201, "mint {name}/{group}");
            let b: serde_json::Value = r.json().await.unwrap();
            b["id"].as_str().unwrap().to_string()
        }
    };
    let patch = |id: String, body: serde_json::Value| {
        let (c, u) = (client.clone(), keys_url.clone());
        async move {
            c.patch(format!("{u}/{id}"))
                .header("x-admin-token", "admintok")
                .json(&body)
                .send()
                .await
                .unwrap()
        }
    };

    let cap_a = mint("a", "capped").await;
    let _cap_b = mint("b", "capped").await;
    let roamer = mint("roamer", "roomy").await;

    let r = patch(roamer.clone(), serde_json::json!({"group": "capped"})).await;
    assert_eq!(r.status().as_u16(), 409, "rebind into an at-cap group");
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["error"]["code"], "conflict");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("max_keys_per_principal"),
        "the rebind 409 names the cap: {body}"
    );

    assert_eq!(
        patch(cap_a.clone(), serde_json::json!({"enabled": false}))
            .await
            .status()
            .as_u16(),
        200,
        "disabling is always allowed — it can only free a slot"
    );
    let _cap_c = mint("c", "capped").await;

    let r = patch(cap_a.clone(), serde_json::json!({"enabled": true})).await;
    assert_eq!(
        r.status().as_u16(),
        409,
        "re-enabling past the cap is the same admission as a rebind past the cap"
    );
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["error"]["code"], "conflict");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("max_keys_per_principal"),
        "the re-enable 409 names the cap: {body}"
    );

    assert_eq!(
        patch(cap_a.clone(), serde_json::json!({"enabled": false}))
            .await
            .status()
            .as_u16(),
        200,
        "a no-op disable of a key in an at-cap bucket is not an admission"
    );

    let r = client
        .post(&keys_url)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"name": "unbound-by-operator"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        201,
        "the operator owns the tree and may still mint an unbound key"
    );

    let audit_rows = |resource: String| {
        let (c, a) = (client.clone(), addr);
        async move {
            let r = c
                .get(format!("http://{a}/api/v1/admin/audit"))
                .query(&[("action", "key.patch"), ("resource", resource.as_str())])
                .header("x-admin-token", "admintok")
                .send()
                .await
                .unwrap();
            assert_eq!(
                r.status().as_u16(),
                200,
                "the key's audit rows are readable"
            );
            let b: serde_json::Value = r.json().await.unwrap();
            b["items"]
                .as_array()
                .expect("the audit response has items")
                .clone()
        }
    };

    for id in [&roamer, &cap_a] {
        let resource = format!("key:{id}");
        let rows = audit_rows(resource.clone()).await;
        assert!(
            rows.iter().any(|e| e["outcome"] == "rejected"
                && e["action"] == "key.patch"
                && e["resource"] == resource),
            "the refused patch of {resource} left no rejected audit row: {rows:?}"
        );
    }

    server.abort();
}

#[tokio::test]
async fn key_cap_and_delegation_refusals_are_reachable_declared_and_audited() {
    drive_key_cap_and_delegation_errors().await;
}

#[tokio::test]
async fn test_admin_v1_overlay_reset_unknown_section_keeps_1_5_5_sentence_shape() {
    crate::distribution::admin_cross_plane::ensure_seam();
    let store = crate::root::real_store::store();
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = {
        crate::distribution::admin_cross_plane::ensure_seam();
        let directory = super::plugins::scratch(&format!(
            "admin-root-{}",
            busbar_kernel::door::op_id().counter()
        ));
        let library_path = crate::root::test_plugins::application_store_library();
        let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
            .expect("the actual Store statement reads")
            .expect("the actual Store states itself");
        let facts = busbar_contract::abi::mechanism::rendering::read(&statement)
            .expect("the actual Store statement parses");
        let mut manifest =
            super::plugins::manifest("store", &facts.name, super::plugins::FIXTURE_PUBLISHER);
        manifest.version = facts.version;
        manifest.statement = Some(hex::encode(statement));
        let archive = super::plugins::signed(
            &crate::dist_root_install::release_key(),
            manifest,
            &std::fs::read(library_path).expect("the actual Store artifact reads"),
        );
        std::fs::write(directory.join("store.tar.gz"), archive)
            .expect("stage the actual Store product");
        std::fs::write(directory.join("admin.token"), "admintok")
            .expect("write the operator credential");
        let settings = crate::root::test_plugins::application_store_settings(&directory);
        let mut document = serde_json::json!({});
        document["providers"] = serde_json::json!({});
        document["models"] = serde_json::json!({});
        // These positive named-map surfaces are served only for configured planes.
        // Use the same actual plane definitions as the file-backed fixture below.
        document["tools"] = serde_json::json!({"base-tools": {
            "url": "https://tools.internal/fs",
            "pin": {"mechanism": "cert_spki", "key": "sha256/BASE="}
        }});
        document["agents"] = serde_json::json!({"base-agent": {
            "url": "https://agents.example/planner",
            "pin": {"mechanism": "unpinned"}
        }});
        document["store"] = serde_json::json!({"module": facts.name, "settings": settings});
        document["plugins"] =
            super::plugins::config_document(&super::plugins::trusted_config(&directory));
        document["auth"] = serde_json::json!({"chain": [], "admin_auth": ["admin-tokens"]});
        document["identity-providers"] = serde_json::json!({"admin-tokens": {
            "module": "admin-tokens", "token": {"file": directory.join("admin.token")}
        }});
        document["advanced"] = serde_json::json!({"allow_destinations": ["127.0.0.1"]});
        let deploy = busbar_kernel::config::deploy_from_deserializer(document)
            .expect("the actual admin deployment parses");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the actual admin deployment resolves");
        assert!(
            cfg.plane_sections.contains("tools") && cfg.plane_sections.contains("agents"),
            "the actual parser configures both positive named-map planes"
        );
        let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
            as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
        let (mut app, rotate, limits) = busbar_kernel::build_app_from_config(
            cfg,
            super::plugins::trusted_config(&directory),
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
        )
        .expect("the product root builds the actual admin application");
        limits.stage_boot();
        let _book = crate::root::boot::book(&app, "configured-store")
            .expect("the actual configured Store binds boot rate history before activation");
        limits.keep().expect("the product limits commit");
        if let Some(rotate) = rotate {
            rotate();
        }
        app.overlay_path = Some(
            busbar_kernel::config::overlay::OverlayStore::new(
                app.governance
                    .as_ref()
                    .expect("the actual root opened governance")
                    .store_calls()
                    .expect("the actual Store exposes its calls"),
            )
            .expect("the actual Store opens its overlay"),
        );
        app.governance = Some(gov);

        std::sync::Arc::new(app)
    };
    let router = crate::distribution::admin_cross_plane::build_router(app);
    let (addr, handle, _) = spin_up(router).await;

    let r = reqwest::Client::new()
        .delete(format!("http://{addr}/api/v1/admin/overlay/limits"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 400);
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["error"]["code"], "invalid_request");

    assert_eq!(
        body["error"]["message"],
        "unknown overlay section `limits`: expected `groups`, `hooks`, `root`, \
         `plugin_versions`, `identity-providers`, `export`, `tools`, or `agents`",
        "1.5.5's sentence shape (serial comma, `or` before the last name) with the longer list"
    );

    handle.abort();
}

#[tokio::test]
async fn test_admin_v1_overlay_reset_named_map_section_reverts_to_base() {
    linked_export_axis();
    let (dir, overlay, addr, handle) = named_map_app("resetnamedmap", false).await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| {
        r.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };

    let r = admin(client.put(format!("http://{addr}/api/v1/admin/export/runtime-sink")))
        .body(
            serde_json::json!({
                "module": "request-log-file",
                "settings": {"path": dir.join("req.jsonl").to_string_lossy()}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200, "{:?}", r.text().await);
    assert!(
        busbar_kernel::config::overlay::read(&overlay.clone())
            .expect("overlay written")
            .named_maps
            .get("export")
            .is_some_and(|e| e.contains_key("runtime-sink")),
        "the definition is in the overlay before the reset"
    );

    let reset = admin(client.delete(format!("http://{addr}/api/v1/admin/overlay/export")))
        .send()
        .await
        .unwrap();
    assert_eq!(reset.status().as_u16(), 200, "{:?}", reset.text().await);
    let body: serde_json::Value = reset.json().await.unwrap();
    assert_eq!(body["reset"], "export");
    assert_eq!(body["changed"], true, "the reset discarded a mutation");

    let gone = admin(client.get(format!("http://{addr}/api/v1/admin/export/runtime-sink")))
        .send()
        .await
        .unwrap();
    assert_eq!(
        gone.status().as_u16(),
        404,
        "the API-applied definition reverted to base"
    );
    let base = admin(client.get(format!("http://{addr}/api/v1/admin/export/base-metrics")))
        .send()
        .await
        .unwrap();
    assert_eq!(
        base.status().as_u16(),
        200,
        "a base config.yaml definition is NOT what a reset removes"
    );

    assert!(
        busbar_kernel::config::overlay::read(&overlay.clone())
            .is_none_or(|d| !d.named_maps.contains_key("export")),
        "the overlay `export` section is cleared in the configured Store"
    );

    let idp = admin(client.get(format!(
        "http://{addr}/api/v1/admin/identity-providers/base-idp"
    )))
    .send()
    .await
    .unwrap();
    assert_eq!(idp.status().as_u16(), 200, "sibling sections survive");

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_admin_v1_overlay_reset_named_map_refuses_a_dangling_reference() {
    let (dir, _overlay, addr, handle) = named_map_app("resetdangling", true).await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| {
        r.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };

    let r = admin(client.put(format!(
        "http://{addr}/api/v1/admin/identity-providers/corp-ad"
    )))
    .body(
        serde_json::json!({
            "module": "admin-tokens",
            "token": {"file": dir.join("corp.token").to_string_lossy()}
        })
        .to_string(),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(r.status().as_u16(), 200, "{:?}", r.text().await);

    let reset = admin(client.delete(format!(
        "http://{addr}/api/v1/admin/overlay/identity-providers"
    )))
    .send()
    .await
    .unwrap();
    assert_eq!(
        reset.status().as_u16(),
        409,
        "a reset that would dangle a reference is refused"
    );
    let body: serde_json::Value = reset.json().await.unwrap();
    assert_eq!(body["error"]["code"], "conflict");
    let msg = body["error"]["message"].as_str().unwrap();
    assert!(
        msg.contains("corp-ad") && msg.contains("auth.admin_auth"),
        "the refusal names the entry AND the referent so an operator knows what to fix: {body}"
    );

    let after = admin(client.get(format!(
        "http://{addr}/api/v1/admin/identity-providers/corp-ad"
    )))
    .send()
    .await
    .unwrap();
    assert_eq!(
        after.status().as_u16(),
        200,
        "the refused reset changed nothing"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

async fn serve_keys_fixture(
    fixture: KeysFixture,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>, String) {
    let store: Arc<dyn busbar_kernel::governance::RecordStore> = crate::root::real_store::store();
    let app = match fixture {
        KeysFixture::Signing => {
            let gov = gov_with_signer(store, Some("admintok".to_string()));
            {
                crate::distribution::admin_cross_plane::ensure_seam();
                let directory = super::plugins::scratch(&format!(
                    "admin-root-{}",
                    busbar_kernel::door::op_id().counter()
                ));
                let library_path = crate::root::test_plugins::application_store_library();
                let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
                    .expect("the actual Store statement reads")
                    .expect("the actual Store states itself");
                let facts = busbar_contract::abi::mechanism::rendering::read(&statement)
                    .expect("the actual Store statement parses");
                let mut manifest = super::plugins::manifest(
                    "store",
                    &facts.name,
                    super::plugins::FIXTURE_PUBLISHER,
                );
                manifest.version = facts.version;
                manifest.statement = Some(hex::encode(statement));
                let archive = super::plugins::signed(
                    &crate::dist_root_install::release_key(),
                    manifest,
                    &std::fs::read(library_path).expect("the actual Store artifact reads"),
                );
                std::fs::write(directory.join("store.tar.gz"), archive)
                    .expect("stage the actual Store product");
                std::fs::write(directory.join("admin.token"), "admintok")
                    .expect("write the operator credential");
                let settings = crate::root::test_plugins::application_store_settings(&directory);
                let mut document = serde_json::json!({});
                document["providers"] = serde_json::json!({});
                document["models"] = serde_json::json!({});
                document["store"] = serde_json::json!({"module": facts.name, "settings": settings});
                document["plugins"] =
                    super::plugins::config_document(&super::plugins::trusted_config(&directory));
                document["auth"] = serde_json::json!({"chain": [], "admin_auth": ["admin-tokens"]});
                document["identity-providers"] = serde_json::json!({"admin-tokens": {
                    "module": "admin-tokens", "token": {"file": directory.join("admin.token")}
                }});
                document["advanced"] = serde_json::json!({"allow_destinations": ["127.0.0.1"]});
                let deploy = busbar_kernel::config::deploy_from_deserializer(document)
                    .expect("the actual admin deployment parses");
                let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
                    .expect("the actual admin deployment resolves");
                let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
                    as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
                let (mut app, rotate, limits) = busbar_kernel::build_app_from_config(
                    cfg,
                    super::plugins::trusted_config(&directory),
                    None,
                    Default::default(),
                    Default::default(),
                    (None, None),
                    None,
                    &rules,
                )
                .expect("the product root builds the actual admin application");
                limits.stage_boot();
                let _book = crate::root::boot::book(&app, "configured-store").expect(
                    "the actual configured Store binds boot rate history before activation",
                );
                limits.keep().expect("the product limits commit");
                if let Some(rotate) = rotate {
                    rotate();
                }
                app.overlay_path = Some(
                    busbar_kernel::config::overlay::OverlayStore::new(
                        app.governance
                            .as_ref()
                            .expect("the actual root opened governance")
                            .store_calls()
                            .expect("the actual Store exposes its calls"),
                    )
                    .expect("the actual Store opens its overlay"),
                );
                app.governance = Some(gov);

                std::sync::Arc::new(app)
            }
        }
        KeysFixture::NoSigner => {
            let gov = Arc::new(
                GovState::new_with_signer(store, Some("admintok".to_string()), None).unwrap(),
            );
            {
                crate::distribution::admin_cross_plane::ensure_seam();
                let directory = super::plugins::scratch(&format!(
                    "admin-root-{}",
                    busbar_kernel::door::op_id().counter()
                ));
                let library_path = crate::root::test_plugins::application_store_library();
                let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
                    .expect("the actual Store statement reads")
                    .expect("the actual Store states itself");
                let facts = busbar_contract::abi::mechanism::rendering::read(&statement)
                    .expect("the actual Store statement parses");
                let mut manifest = super::plugins::manifest(
                    "store",
                    &facts.name,
                    super::plugins::FIXTURE_PUBLISHER,
                );
                manifest.version = facts.version;
                manifest.statement = Some(hex::encode(statement));
                let archive = super::plugins::signed(
                    &crate::dist_root_install::release_key(),
                    manifest,
                    &std::fs::read(library_path).expect("the actual Store artifact reads"),
                );
                std::fs::write(directory.join("store.tar.gz"), archive)
                    .expect("stage the actual Store product");
                std::fs::write(directory.join("admin.token"), "admintok")
                    .expect("write the operator credential");
                let settings = crate::root::test_plugins::application_store_settings(&directory);
                let mut document = serde_json::json!({});
                document["providers"] = serde_json::json!({});
                document["models"] = serde_json::json!({});
                document["store"] = serde_json::json!({"module": facts.name, "settings": settings});
                document["plugins"] =
                    super::plugins::config_document(&super::plugins::trusted_config(&directory));
                document["auth"] = serde_json::json!({"chain": [], "admin_auth": ["admin-tokens"]});
                document["identity-providers"] = serde_json::json!({"admin-tokens": {
                    "module": "admin-tokens", "token": {"file": directory.join("admin.token")}
                }});
                document["advanced"] = serde_json::json!({"allow_destinations": ["127.0.0.1"]});
                let deploy = busbar_kernel::config::deploy_from_deserializer(document)
                    .expect("the actual admin deployment parses");
                let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
                    .expect("the actual admin deployment resolves");
                let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
                    as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
                let (mut app, rotate, limits) = busbar_kernel::build_app_from_config(
                    cfg,
                    super::plugins::trusted_config(&directory),
                    None,
                    Default::default(),
                    Default::default(),
                    (None, None),
                    None,
                    &rules,
                )
                .expect("the product root builds the actual admin application");
                limits.stage_boot();
                let _book = crate::root::boot::book(&app, "configured-store").expect(
                    "the actual configured Store binds boot rate history before activation",
                );
                limits.keep().expect("the product limits commit");
                if let Some(rotate) = rotate {
                    rotate();
                }
                app.overlay_path = Some(
                    busbar_kernel::config::overlay::OverlayStore::new(
                        app.governance
                            .as_ref()
                            .expect("the actual root opened governance")
                            .store_calls()
                            .expect("the actual Store exposes its calls"),
                    )
                    .expect("the actual Store opens its overlay"),
                );
                app.governance = Some(gov);

                std::sync::Arc::new(app)
            }
        }

        KeysFixture::Off => {
            crate::distribution::admin_cross_plane::ensure_seam();
            let directory = super::plugins::scratch(&format!(
                "admin-root-{}",
                busbar_kernel::door::op_id().counter()
            ));
            let library_path = crate::root::test_plugins::application_store_library();
            let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
                .expect("the actual Store statement reads")
                .expect("the actual Store states itself");
            let facts = busbar_contract::abi::mechanism::rendering::read(&statement)
                .expect("the actual Store statement parses");
            let mut manifest =
                super::plugins::manifest("store", &facts.name, super::plugins::FIXTURE_PUBLISHER);
            manifest.version = facts.version;
            manifest.statement = Some(hex::encode(statement));
            let archive = super::plugins::signed(
                &crate::dist_root_install::release_key(),
                manifest,
                &std::fs::read(library_path).expect("the actual Store artifact reads"),
            );
            std::fs::write(directory.join("store.tar.gz"), archive)
                .expect("stage the actual Store product");
            std::fs::write(directory.join("admin.token"), "admintok")
                .expect("write the operator credential");
            let settings = crate::root::test_plugins::application_store_settings(&directory);
            let mut document = serde_json::json!({});
            document["providers"] = serde_json::json!({});
            document["models"] = serde_json::json!({});
            document["store"] = serde_json::json!({"module": facts.name, "settings": settings});
            document["plugins"] =
                super::plugins::config_document(&super::plugins::trusted_config(&directory));
            document["auth"] = serde_json::json!({"chain": [], "admin_auth": []});
            document["identity-providers"] = serde_json::json!({"admin-tokens": {
                "module": "admin-tokens", "token": {"file": directory.join("admin.token")}
            }});
            document["advanced"] = serde_json::json!({"allow_destinations": ["127.0.0.1"]});
            let deploy = busbar_kernel::config::deploy_from_deserializer(document)
                .expect("the actual admin deployment parses");
            let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
                .expect("the actual admin deployment resolves");
            let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
                as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
            let (mut app, rotate, limits) = busbar_kernel::build_app_from_config(
                cfg,
                super::plugins::trusted_config(&directory),
                None,
                Default::default(),
                Default::default(),
                (None, None),
                None,
                &rules,
            )
            .expect("the product root builds the actual admin application");
            limits.stage_boot();
            let _book = crate::root::boot::book(&app, "configured-store")
                .expect("the actual configured Store binds boot rate history before activation");
            limits.keep().expect("the product limits commit");
            if let Some(rotate) = rotate {
                rotate();
            }
            app.overlay_path = Some(
                busbar_kernel::config::overlay::OverlayStore::new(
                    app.governance
                        .as_ref()
                        .expect("the actual root opened governance")
                        .store_calls()
                        .expect("the actual Store exposes its calls"),
                )
                .expect("the actual Store opens its overlay"),
            );
            app.governance = None;

            std::sync::Arc::new(app)
        }
    };
    let router = crate::distribution::admin_cross_plane::build_router(app.clone());
    let (addr, handle, _) = spin_up(router).await;

    let live = if fixture == KeysFixture::Signing {
        let (key, _) = app
            .governance
            .as_ref()
            .unwrap()
            .mint_signed(
                NewKeySpec {
                    name: "live".into(),
                    allowed_pools: None,
                    group: None,
                    labels: Default::default(),
                    ..Default::default()
                },
                busbar_kernel::store::now() + 3600,
                busbar_kernel::store::now(),
            )
            .unwrap();
        key.id
    } else {
        String::new()
    };
    (addr, handle, live)
}

#[tokio::test]
async fn keys_error_surface_is_byte_stable() {
    drive_keys_error_surface().await;
}

async fn drive_keys_error_surface() {
    crate::distribution::admin_cross_plane::ensure_seam();

    const OVERLONG: &str = "vk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const MISSING: &str = "vk_0000000000000000";

    const STALE_ETAG: &str = "\"00000000000000ff\"";
    let cases: &[KeysErrCase] = &[
        c(
            "list_bad_cursor",
            KeysFixture::Signing,
            "GET",
            "/keys?cursor=%21%21",
            &[],
            None,
        ),
        c(
            "list_bad_enabled",
            KeysFixture::Signing,
            "GET",
            "/keys?enabled=maybe",
            &[],
            None,
        ),
        c(
            "list_bad_limit",
            KeysFixture::Signing,
            "GET",
            "/keys?limit=lots",
            &[],
            None,
        ),
        c(
            "mint_bad_json",
            KeysFixture::Signing,
            "POST",
            "/keys",
            &[],
            Some("{"),
        ),
        c(
            "mint_reserved_label",
            KeysFixture::Signing,
            "POST",
            "/keys",
            &[],
            Some(r#"{"name":"k","labels":{"key":"v"}}"#),
        ),
        c(
            "mint_both_expiry_fields",
            KeysFixture::Signing,
            "POST",
            "/keys",
            &[],
            Some(r#"{"name":"k","expires_in":"1h","expires_at":9999999999}"#),
        ),
        c(
            "mint_bad_duration",
            KeysFixture::Signing,
            "POST",
            "/keys",
            &[],
            Some(r#"{"name":"k","expires_in":"1x"}"#),
        ),
        c(
            "mint_expires_in_the_past",
            KeysFixture::Signing,
            "POST",
            "/keys",
            &[],
            Some(r#"{"name":"k","expires_at":1}"#),
        ),
        c(
            "mint_parent_without_group",
            KeysFixture::Signing,
            "POST",
            "/keys",
            &[],
            Some(r#"{"name":"k","parent":"team"}"#),
        ),
        c(
            "mint_unknown_group_no_parent",
            KeysFixture::Signing,
            "POST",
            "/keys",
            &[],
            Some(r#"{"name":"k","group":"nope"}"#),
        ),
        c(
            "mint_unknown_parent",
            KeysFixture::Signing,
            "POST",
            "/keys",
            &[],
            Some(r#"{"name":"k","group":"leaf","parent":"nope"}"#),
        ),
        c(
            "mint_no_signing_key",
            KeysFixture::NoSigner,
            "POST",
            "/keys",
            &[],
            Some(r#"{"name":"k"}"#),
        ),
        c(
            "mint_governance_off",
            KeysFixture::Off,
            "POST",
            "/keys",
            &[],
            Some(r#"{"name":"k"}"#),
        ),
        c(
            "read_overlong_id",
            KeysFixture::Signing,
            "GET",
            "/keys/{overlong}",
            &[],
            None,
        ),
        c(
            "read_unknown",
            KeysFixture::Signing,
            "GET",
            "/keys/{missing}",
            &[],
            None,
        ),
        c(
            "read_governance_off",
            KeysFixture::Off,
            "GET",
            "/keys/{missing}",
            &[],
            None,
        ),
        c(
            "patch_overlong_id",
            KeysFixture::Signing,
            "PATCH",
            "/keys/{overlong}",
            &[],
            Some("{}"),
        ),
        c(
            "patch_malformed_if_match",
            KeysFixture::Signing,
            "PATCH",
            "/keys/{missing}",
            &[("if-match", "not-an-etag")],
            Some("{}"),
        ),
        c(
            "patch_bad_json",
            KeysFixture::Signing,
            "PATCH",
            "/keys/{missing}",
            &[],
            Some("{"),
        ),
        c(
            "patch_rebind_target_missing",
            KeysFixture::Signing,
            "PATCH",
            "/keys/{missing}",
            &[],
            Some(r#"{"group":"nope"}"#),
        ),
        c(
            "patch_unknown",
            KeysFixture::Signing,
            "PATCH",
            "/keys/{missing}",
            &[],
            Some("{}"),
        ),
        c(
            "patch_stale_etag",
            KeysFixture::Signing,
            "PATCH",
            "/keys/{live}",
            &[("if-match", STALE_ETAG)],
            Some("{}"),
        ),
        c(
            "patch_governance_off",
            KeysFixture::Off,
            "PATCH",
            "/keys/{missing}",
            &[],
            Some("{}"),
        ),
        c(
            "delete_overlong_id",
            KeysFixture::Signing,
            "DELETE",
            "/keys/{overlong}",
            &[],
            None,
        ),
        c(
            "delete_malformed_if_match",
            KeysFixture::Signing,
            "DELETE",
            "/keys/{missing}",
            &[("if-match", "not-an-etag")],
            None,
        ),
        c(
            "delete_unknown",
            KeysFixture::Signing,
            "DELETE",
            "/keys/{missing}",
            &[],
            None,
        ),
        c(
            "delete_stale_etag",
            KeysFixture::Signing,
            "DELETE",
            "/keys/{live}",
            &[("if-match", STALE_ETAG)],
            None,
        ),
        c(
            "delete_governance_off",
            KeysFixture::Off,
            "DELETE",
            "/keys/{missing}",
            &[],
            None,
        ),
        c(
            "usage_overlong_id",
            KeysFixture::Signing,
            "GET",
            "/keys/{overlong}/usage",
            &[],
            None,
        ),
        c(
            "usage_unknown",
            KeysFixture::Signing,
            "GET",
            "/keys/{missing}/usage",
            &[],
            None,
        ),
        c(
            "usage_governance_off",
            KeysFixture::Off,
            "GET",
            "/keys/{missing}/usage",
            &[],
            None,
        ),
        c(
            "rotate_overlong_id",
            KeysFixture::Signing,
            "POST",
            "/keys/{overlong}/rotate",
            &[],
            None,
        ),
        c(
            "rotate_unknown",
            KeysFixture::Signing,
            "POST",
            "/keys/{missing}/rotate",
            &[],
            None,
        ),
        c(
            "rotate_governance_off",
            KeysFixture::Off,
            "POST",
            "/keys/{missing}/rotate",
            &[],
            None,
        ),
        c(
            "revoke_overlong_id",
            KeysFixture::Signing,
            "POST",
            "/keys/{overlong}/revoke",
            &[],
            None,
        ),
        c(
            "revoke_unknown",
            KeysFixture::Signing,
            "POST",
            "/keys/{missing}/revoke",
            &[],
            None,
        ),
        c(
            "revoke_governance_off",
            KeysFixture::Off,
            "POST",
            "/keys/{missing}/revoke",
            &[],
            None,
        ),
        c(
            "signing_rotate_no_key",
            KeysFixture::NoSigner,
            "POST",
            "/signing-key/rotate",
            &[],
            None,
        ),
        c(
            "signing_rotate_governance_off",
            KeysFixture::Off,
            "POST",
            "/signing-key/rotate",
            &[],
            None,
        ),
    ];

    let client = reqwest::Client::new();
    let mut observed = serde_json::Map::new();
    for fixture in [
        KeysFixture::Signing,
        KeysFixture::NoSigner,
        KeysFixture::Off,
    ] {
        let (addr, server, live) = serve_keys_fixture(fixture).await;
        for case in cases.iter().filter(|c| c.fixture == fixture) {
            let path = case
                .path
                .replace("{overlong}", OVERLONG)
                .replace("{missing}", MISSING)
                .replace("{live}", &live);
            let mut req = client
                .request(
                    reqwest::Method::from_bytes(case.method.as_bytes()).unwrap(),
                    format!("http://{addr}/api/v1/admin{path}"),
                )
                .header("x-admin-token", "admintok");
            for (k, v) in case.headers {
                req = req.header(*k, *v);
            }
            if let Some(body) = case.body {
                req = req
                    .header("content-type", "application/json")
                    .body(body.to_string());
            }
            let resp = req.send().await.unwrap();
            let status = resp.status().as_u16();
            let content_type = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            let body = resp.text().await.unwrap();
            assert!(
                (400..600).contains(&status),
                "{} expected an error response, got {status}: {body}",
                case.name
            );
            observed.insert(
                case.name.to_string(),
                serde_json::json!({"status": status, "content_type": content_type, "body": body}),
            );
        }
        server.abort();
    }

    let fresh = format!(
        "{}\n",
        serde_json::to_string_pretty(&serde_json::Value::Object(observed))
            .expect("serialize keys error wire")
    );
    if std::env::var("UPDATE_KEYS_ERROR_GOLDEN").is_ok_and(|v| v == "1") {
        std::fs::write(KEYS_ERROR_GOLDEN, &fresh)
            .unwrap_or_else(|e| panic!("write {KEYS_ERROR_GOLDEN}: {e}"));
        return;
    }
    let committed = std::fs::read_to_string(KEYS_ERROR_GOLDEN)
        .unwrap_or_else(|e| panic!("read {KEYS_ERROR_GOLDEN}: {e}"));
    assert_eq!(
        committed, fresh,
        "the keys error WIRE changed — status/content-type/body bytes on a FROZEN surface. If this \
         is deliberate, regenerate with `UPDATE_KEYS_ERROR_GOLDEN=1`."
    );
}

#[tokio::test]
async fn admin_error_surface_witnesses_every_declared_response() {
    if std::env::var_os("BUSBAR_ADMIN_ERROR_UNSUPERVISED_PROCESS").is_none() {
        let current = std::thread::current();
        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args(["--exact", current.name().expect("test name"), "--nocapture"])
            .env("BUSBAR_ADMIN_ERROR_UNSUPERVISED_PROCESS", "1")
            .env_remove("INVOCATION_ID")
            .env_remove("KUBERNETES_SERVICE_HOST")
            .output()
            .expect("run the restart assertions in an unsupervised process");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success()
                && stdout.contains("test result: ok. 1 passed; 0 failed; 0 ignored;"),
            "unsupervised restart assertions failed: {}\n{stdout}\n{stderr}",
            output.status
        );
        return;
    }
    drive_admin_error_surface().await;
}

async fn admin_error_fixture() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let store = crate::root::real_store::store();
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = {
        crate::distribution::admin_cross_plane::ensure_seam();
        let directory = super::plugins::scratch(&format!(
            "admin-root-{}",
            busbar_kernel::door::op_id().counter()
        ));
        let library_path = crate::root::test_plugins::application_store_library();
        let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
            .expect("the actual Store statement reads")
            .expect("the actual Store states itself");
        let facts = busbar_contract::abi::mechanism::rendering::read(&statement)
            .expect("the actual Store statement parses");
        let mut manifest =
            super::plugins::manifest("store", &facts.name, super::plugins::FIXTURE_PUBLISHER);
        manifest.version = facts.version;
        manifest.statement = Some(hex::encode(statement));
        let archive = super::plugins::signed(
            &crate::dist_root_install::release_key(),
            manifest,
            &std::fs::read(library_path).expect("the actual Store artifact reads"),
        );
        std::fs::write(directory.join("store.tar.gz"), archive)
            .expect("stage the actual Store product");
        std::fs::write(directory.join("admin.token"), "admintok")
            .expect("write the operator credential");
        let ranking_library = std::path::PathBuf::from(
            std::env::var_os("BUSBAR_TEST_RANKING_CDYLIB")
                .expect("the admin hook witnesses require the actual Ranking product"),
        );
        let ranking_statement =
            busbar_plugin_loader::dispatch::rendering_of_library(&ranking_library)
                .expect("the actual Ranking statement reads")
                .expect("the actual Ranking product states its door");
        let ranking_facts = busbar_contract::abi::mechanism::rendering::read(&ranking_statement)
            .expect("the actual Ranking statement parses");
        let mut ranking_manifest = super::plugins::manifest(
            "hook",
            &ranking_facts.name,
            super::plugins::FIXTURE_PUBLISHER,
        );
        ranking_manifest.alias = "hooks-ranking".into();
        ranking_manifest.version = ranking_facts.version;
        ranking_manifest.statement = Some(hex::encode(ranking_statement));
        let ranking_archive = super::plugins::signed(
            &crate::dist_root_install::release_key(),
            ranking_manifest,
            &std::fs::read(ranking_library).expect("the actual Ranking library reads"),
        );
        std::fs::write(directory.join("ranking.tar.gz"), ranking_archive)
            .expect("stage the actual signed Ranking product");
        let oidc_path = super::plugins::token_verifier_cdylib_path()
            .expect("the lockout witness requires the actual OIDC product");
        let oidc_statement = busbar_plugin_loader::dispatch::rendering_of_library(&oidc_path)
            .expect("the actual OIDC statement reads")
            .expect("the actual OIDC product states its door");
        let oidc_module = busbar_contract::abi::mechanism::rendering::read(&oidc_statement)
            .expect("the actual OIDC statement parses")
            .name;
        crate::test_common::credentials::install_auth_plugin(
            &directory,
            &oidc_module,
            "test-scope-module",
            true,
        );
        let settings = crate::root::test_plugins::application_store_settings(&directory);
        let mut document = serde_json::json!({"groups": {"team": {"enabled": true, "limits": []}}, "hooks": {"basehook": {"kind":"gate","module":"hooks-ranking","settings":{"policy":"cheapest"},"timeout_ms":25,"on_error":"reject"}}});
        document["providers"] = serde_json::json!({});
        document["models"] = serde_json::json!({});
        document["store"] = serde_json::json!({"module": facts.name, "settings": settings});
        document["plugins"] =
            super::plugins::config_document(&super::plugins::trusted_config(&directory));
        document["auth"] =
            serde_json::json!({"chain": [], "admin_auth": ["test-scope-module", "admin-tokens"]});
        document["identity-providers"] = serde_json::json!({"admin-tokens": {
            "module": "admin-tokens", "token": {"file": directory.join("admin.token")}
        }});
        document["identity-providers"]["test-scope-module"] = serde_json::json!({
            "module": oidc_module,
            "settings": crate::test_common::credentials::settings("admin-lockout-witness"),
            "max_admin_scope": "full",
        });
        document["advanced"] = serde_json::json!({"allow_destinations": ["127.0.0.1"]});
        let deploy = busbar_kernel::config::deploy_from_deserializer(document)
            .expect("the actual admin deployment parses");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the actual admin deployment resolves");
        let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
            as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
        let (mut app, rotate, limits) = busbar_kernel::build_app_from_config(
            cfg,
            super::plugins::trusted_config(&directory),
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
        )
        .expect("the product root builds the actual admin application");
        limits.stage_boot();
        let _book = crate::root::boot::book(&app, "configured-store")
            .expect("the actual configured Store binds boot rate history before activation");
        limits.keep().expect("the product limits commit");
        if let Some(rotate) = rotate {
            rotate();
        }
        app.overlay_path = Some(
            busbar_kernel::config::overlay::OverlayStore::new(
                app.governance.as_ref().unwrap().store_calls().unwrap(),
            )
            .unwrap(),
        );
        app.governance = Some(gov);
        app.base_group_names.insert("team".into());
        app.base_hook_names.insert("basehook".into());
        std::sync::Arc::new(app)
    };
    let router = crate::distribution::admin_cross_plane::build_router(app);
    let (addr, server, client) = spin_up(router).await;
    for (rel, body) in [
        (
            "/groups",
            r#"{"name":"og","config":{"parent":"team","limits":[]}}"#,
        ),
        (
            "/hooks",
            r#"{"name":"oh","config":{"kind":"gate","module":"hooks-ranking","settings":{"policy":"cheapest"}}}"#,
        ),
    ] {
        let created = client
            .post(format!("http://{addr}/api/v1/admin{rel}"))
            .header("x-admin-token", "admintok")
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(created.status().as_u16(), 201, "fixture: POST {rel}");
    }
    (addr, server)
}

async fn drive_admin_error_surface() {
    crate::distribution::admin_cross_plane::ensure_seam();

    const STALE: &str = "\"999999\"";
    const BAD_ETAG: &str = "not-an-etag";
    let group_body = r#"{"config":{"limits":[]}}"#;

    type ErrCase = (
        &'static str,
        &'static str,
        &'static str,
        Option<&'static str>,
        Option<&'static str>,
        u16,
        &'static str,
    );
    let cases: &[ErrCase] = &[
        (
            "groups_post_invalid_tree",
            "POST",
            "/groups",
            None,
            Some(r#"{"name":"x","config":{"parent":"ghost","limits":[]}}"#),
            400,
            "invalid_request",
        ),
        (
            "groups_post_base_defined",
            "POST",
            "/groups",
            None,
            Some(r#"{"name":"team","config":{"limits":[]}}"#),
            409,
            "conflict",
        ),
        (
            "groups_post_stale",
            "POST",
            "/groups",
            Some(STALE),
            Some(r#"{"name":"z","config":{"limits":[]}}"#),
            409,
            "version_conflict",
        ),
        (
            "groups_post_bad_if_match",
            "POST",
            "/groups",
            Some(BAD_ETAG),
            Some(r#"{"name":"z","config":{"limits":[]}}"#),
            400,
            "invalid_request",
        ),
        (
            "groups_put_bad_if_match",
            "PUT",
            "/groups/og",
            Some(BAD_ETAG),
            Some(group_body),
            400,
            "invalid_request",
        ),
        (
            "groups_put_unknown",
            "PUT",
            "/groups/ghost",
            None,
            Some(group_body),
            404,
            "not_found",
        ),
        (
            "groups_put_base_defined",
            "PUT",
            "/groups/team",
            None,
            Some(group_body),
            409,
            "conflict",
        ),
        (
            "groups_put_stale",
            "PUT",
            "/groups/og",
            Some(STALE),
            Some(group_body),
            409,
            "version_conflict",
        ),
        (
            "groups_patch_bad_if_match",
            "PATCH",
            "/groups/og",
            Some(BAD_ETAG),
            Some("{}"),
            400,
            "invalid_request",
        ),
        (
            "groups_patch_unknown",
            "PATCH",
            "/groups/ghost",
            None,
            Some("{}"),
            404,
            "not_found",
        ),
        (
            "groups_patch_base_defined",
            "PATCH",
            "/groups/team",
            None,
            Some("{}"),
            409,
            "conflict",
        ),
        (
            "groups_patch_stale",
            "PATCH",
            "/groups/og",
            Some(STALE),
            Some("{}"),
            409,
            "version_conflict",
        ),
        (
            "groups_patch_invalid_tree",
            "PATCH",
            "/groups/og",
            None,
            Some(r#"{"parent":"ghost"}"#),
            400,
            "invalid_request",
        ),
        (
            "groups_delete_bad_if_match",
            "DELETE",
            "/groups/og",
            Some(BAD_ETAG),
            None,
            400,
            "invalid_request",
        ),
        (
            "groups_delete_unknown",
            "DELETE",
            "/groups/ghost",
            None,
            None,
            404,
            "not_found",
        ),
        (
            "groups_delete_base_defined",
            "DELETE",
            "/groups/team",
            None,
            None,
            409,
            "conflict",
        ),
        (
            "groups_delete_stale",
            "DELETE",
            "/groups/og",
            Some(STALE),
            None,
            409,
            "version_conflict",
        ),
        (
            "hooks_post_stale",
            "POST",
            "/hooks",
            Some(STALE),
            Some(
                r#"{"name":"h2","config":{"kind":"gate","module":"hooks-ranking","settings":{"policy":"cheapest"}}}"#,
            ),
            409,
            "version_conflict",
        ),
        (
            "hooks_put_bad_if_match",
            "PUT",
            "/hooks/oh",
            Some(BAD_ETAG),
            Some(
                r#"{"config":{"kind":"gate","module":"hooks-ranking","settings":{"policy":"cheapest"}}}"#,
            ),
            400,
            "invalid_request",
        ),
        (
            "hooks_delete_bad_if_match",
            "DELETE",
            "/hooks/oh",
            Some(BAD_ETAG),
            None,
            400,
            "invalid_request",
        ),
        (
            "hooks_delete_stale",
            "DELETE",
            "/hooks/oh",
            Some(STALE),
            None,
            409,
            "version_conflict",
        ),
        (
            "hook_settings_bad_if_match",
            "PATCH",
            "/hooks/oh/settings",
            Some(BAD_ETAG),
            Some(r#"{"settings":{}}"#),
            400,
            "invalid_request",
        ),
        (
            "hook_settings_base_defined",
            "PATCH",
            "/hooks/basehook/settings",
            None,
            Some(r#"{"settings":{}}"#),
            409,
            "conflict",
        ),
        (
            "hook_settings_stale",
            "PATCH",
            "/hooks/oh/settings",
            Some(STALE),
            Some(r#"{"settings":{}}"#),
            409,
            "version_conflict",
        ),
        (
            "pools_bad_detail",
            "GET",
            "/pools?detail=maybe",
            None,
            None,
            400,
            "invalid_request",
        ),
        (
            "usage_bad_window",
            "GET",
            "/usage?window=soon",
            None,
            None,
            400,
            "invalid_request",
        ),
        (
            "audit_bad_cursor",
            "GET",
            "/audit?cursor=%21%21",
            None,
            None,
            400,
            "invalid_request",
        ),
        (
            "versions_bad_cursor",
            "GET",
            "/config/versions?cursor=%21%21",
            None,
            None,
            400,
            "invalid_request",
        ),
        (
            "diff_missing_params",
            "GET",
            "/config/diff",
            None,
            None,
            400,
            "invalid_request",
        ),
        (
            "diff_unknown_version",
            "GET",
            "/config/diff?from=900&to=901",
            None,
            None,
            404,
            "not_found",
        ),
        (
            "config_rollback_bad_body",
            "POST",
            "/config/rollback",
            None,
            Some("{"),
            400,
            "invalid_request",
        ),
        (
            "config_rollback_bad_if_match",
            "POST",
            "/config/rollback",
            Some(BAD_ETAG),
            Some(r#"{"version":1}"#),
            400,
            "invalid_request",
        ),
        (
            "config_apply_bad_body",
            "POST",
            "/config/apply",
            None,
            Some("{"),
            400,
            "invalid_request",
        ),
        (
            "config_settings_bad_if_match",
            "PUT",
            "/config/settings",
            Some(BAD_ETAG),
            Some("{}"),
            400,
            "invalid_request",
        ),
        (
            "admin_auth_bad_if_match",
            "PUT",
            "/admin-auth",
            Some(BAD_ETAG),
            Some(r#"{"admin_auth":[]}"#),
            400,
            "invalid_request",
        ),
        (
            "plugin_rollback_bad_body",
            "POST",
            "/plugins/rollback",
            None,
            Some("{"),
            400,
            "invalid_request",
        ),
        (
            "plugin_rollback_bad_if_match",
            "POST",
            "/plugins/rollback",
            Some(BAD_ETAG),
            Some(r#"{"file":"p.tar.gz"}"#),
            400,
            "invalid_request",
        ),
        (
            "plugin_rollback_stale",
            "POST",
            "/plugins/rollback",
            Some(STALE),
            Some(r#"{"file":"p.tar.gz"}"#),
            409,
            "version_conflict",
        ),
        (
            "pool_unknown",
            "GET",
            "/pools/ghost",
            None,
            None,
            404,
            "not_found",
        ),
        (
            "hook_unknown",
            "GET",
            "/hooks/ghost",
            None,
            None,
            404,
            "not_found",
        ),
        (
            "hook_health_unknown",
            "GET",
            "/hooks/ghost/health",
            None,
            None,
            404,
            "not_found",
        ),
        (
            "hook_schema_unknown",
            "GET",
            "/hooks/ghost/schema",
            None,
            None,
            404,
            "not_found",
        ),
        (
            "hook_status_unknown",
            "GET",
            "/hooks/ghost/status",
            None,
            None,
            404,
            "not_found",
        ),
        (
            "plugins_schema_unknown",
            "GET",
            "/plugins/ghost/schema",
            None,
            None,
            404,
            "not_found",
        ),
        (
            "group_unknown",
            "GET",
            "/groups/ghost",
            None,
            None,
            404,
            "not_found",
        ),
        (
            "group_usage_unknown",
            "GET",
            "/groups/ghost/usage",
            None,
            None,
            404,
            "not_found",
        ),
        (
            "version_non_numeric",
            "GET",
            "/config/versions/abc",
            None,
            None,
            400,
            "invalid_request",
        ),
        (
            "version_unknown",
            "GET",
            "/config/versions/999",
            None,
            None,
            404,
            "not_found",
        ),
        (
            "plugins_missing_type",
            "GET",
            "/plugins",
            None,
            None,
            400,
            "invalid_request",
        ),
        (
            "restart_malformed_body",
            "POST",
            "/restart",
            None,
            Some(r#"{"confrim": true}"#),
            400,
            "invalid_request",
        ),
        (
            "restart_no_supervisor",
            "POST",
            "/restart",
            None,
            None,
            409,
            "conflict",
        ),
        (
            "restart_not_restartable",
            "POST",
            "/restart",
            None,
            Some(r#"{"confirm": true}"#),
            409,
            "conflict",
        ),
        (
            "hooks_post_bad_body",
            "POST",
            "/hooks",
            None,
            Some("{"),
            400,
            "invalid_request",
        ),
        (
            "hooks_post_bad_if_match",
            "POST",
            "/hooks",
            Some(BAD_ETAG),
            Some(
                r#"{"name":"h3","config":{"kind":"gate","module":"hooks-ranking","settings":{"policy":"cheapest"}}}"#,
            ),
            400,
            "invalid_request",
        ),
        (
            "hooks_post_base_defined",
            "POST",
            "/hooks",
            None,
            Some(
                r#"{"name":"basehook","config":{"kind":"gate","module":"hooks-ranking","settings":{"policy":"cheapest"}}}"#,
            ),
            409,
            "conflict",
        ),
        (
            "hooks_post_grant_change",
            "POST",
            "/hooks",
            None,
            Some(
                r#"{"name":"oh","config":{"kind":"tap","module":"hooks-ranking","settings":{"policy":"cheapest"}}}"#,
            ),
            409,
            "conflict",
        ),
        (
            "hooks_put_unknown",
            "PUT",
            "/hooks/ghost",
            None,
            Some(
                r#"{"config":{"kind":"gate","module":"hooks-ranking","settings":{"policy":"cheapest"}}}"#,
            ),
            404,
            "not_found",
        ),
        (
            "hooks_put_base_defined",
            "PUT",
            "/hooks/basehook",
            None,
            Some(
                r#"{"config":{"kind":"gate","module":"hooks-ranking","settings":{"policy":"cheapest"}}}"#,
            ),
            409,
            "conflict",
        ),
        (
            "hooks_put_stale",
            "PUT",
            "/hooks/oh",
            Some(STALE),
            Some(
                r#"{"config":{"kind":"gate","module":"hooks-ranking","settings":{"policy":"cheapest"}}}"#,
            ),
            409,
            "version_conflict",
        ),
        (
            "hooks_delete_unknown",
            "DELETE",
            "/hooks/ghost",
            None,
            None,
            404,
            "not_found",
        ),
        (
            "hooks_delete_base_defined",
            "DELETE",
            "/hooks/basehook",
            None,
            None,
            409,
            "conflict",
        ),
        (
            "hook_settings_unknown",
            "PATCH",
            "/hooks/ghost/settings",
            None,
            Some(r#"{"settings":{}}"#),
            404,
            "not_found",
        ),
        (
            "overlay_unknown_section",
            "DELETE",
            "/overlay/nosuch",
            None,
            None,
            400,
            "invalid_request",
        ),
        (
            "overlay_stale",
            "DELETE",
            "/overlay/groups",
            Some(STALE),
            None,
            409,
            "version_conflict",
        ),
        (
            "cache_flush_bad_body",
            "POST",
            "/auth/cache/flush",
            None,
            Some("["),
            400,
            "invalid_request",
        ),
        (
            "config_validate_bad_body",
            "POST",
            "/config/validate",
            None,
            Some("{"),
            400,
            "invalid_request",
        ),
        (
            "config_reload_ephemeral",
            "POST",
            "/config/reload",
            None,
            None,
            400,
            "invalid_request",
        ),
        (
            "config_apply_stale",
            "POST",
            "/config/apply",
            Some(STALE),
            Some(
                r#"{"config":{"listen":"127.0.0.1:0","store":{"module":"memory"},"providers":{},"models":{},"pools":{}}}"#,
            ),
            409,
            "version_conflict",
        ),
        (
            "config_rollback_unknown",
            "POST",
            "/config/rollback",
            None,
            Some(r#"{"version":999}"#),
            404,
            "not_found",
        ),
        (
            "config_rollback_stale",
            "POST",
            "/config/rollback",
            Some(STALE),
            Some(r#"{"version":1}"#),
            409,
            "version_conflict",
        ),
        (
            "config_settings_stale",
            "PUT",
            "/config/settings",
            Some(STALE),
            Some("{}"),
            409,
            "version_conflict",
        ),
        (
            "admin_auth_unknown_module",
            "PUT",
            "/admin-auth",
            None,
            Some(r#"{"admin_auth":["definitely-not-a-module"]}"#),
            400,
            "invalid_request",
        ),
        (
            "admin_auth_stale",
            "PUT",
            "/admin-auth",
            Some(STALE),
            Some(r#"{"admin_auth":["admin-tokens"]}"#),
            409,
            "version_conflict",
        ),
        (
            "admin_auth_lockout",
            "PUT",
            "/admin-auth",
            None,
            Some(r#"{"admin_auth":["test-scope-module"]}"#),
            409,
            "conflict",
        ),
    ];

    let client = reqwest::Client::new();
    for batch in cases.chunks(6) {
        let (addr, server) = admin_error_fixture().await;
        for (label, method, rel, if_match, body, want_status, want_code) in batch {
            let mut req = client
                .request(
                    reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                    format!("http://{addr}/api/v1/admin{rel}"),
                )
                .header("x-admin-token", "admintok");
            if let Some(tag) = if_match {
                req = req.header("if-match", *tag);
            }
            if let Some(b) = body {
                req = req.header("content-type", "application/json").body(*b);
            }

            let resp = req.send().await.unwrap();
            let status = resp.status().as_u16();
            let parsed: serde_json::Value = resp.json().await.unwrap();
            assert_eq!(
                status, *want_status,
                "{label}: expected {want_status}, got {status} ({parsed})"
            );
            assert_eq!(parsed["error"]["code"], *want_code, "{label}");
        }
        server.abort();
    }
}

#[tokio::test]
async fn plugin_rollback_reports_missing_and_untrusted_targets() {
    drive_plugin_rollback_errors().await;
}

#[tokio::test]
async fn plugin_reload_reports_an_unrebuildable_disk_config() {
    drive_plugin_reload_errors().await;
}

async fn drive_plugin_reload_errors() {
    crate::distribution::admin_cross_plane::ensure_seam();

    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "busbar-admin-reload-witness-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let config = dir.join("config.yaml");
    let providers = dir.join("providers.yaml");
    std::fs::write(&config, "this: [is not: valid: yaml\n").unwrap();
    std::fs::write(&providers, "providers: {}\n").unwrap();
    let store = crate::root::real_store::store();
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = {
        crate::distribution::admin_cross_plane::ensure_seam();
        let directory = super::plugins::scratch(&format!(
            "admin-root-{}",
            busbar_kernel::door::op_id().counter()
        ));
        let library_path = crate::root::test_plugins::application_store_library();
        let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
            .expect("the actual Store statement reads")
            .expect("the actual Store states itself");
        let facts = busbar_contract::abi::mechanism::rendering::read(&statement)
            .expect("the actual Store statement parses");
        let mut manifest =
            super::plugins::manifest("store", &facts.name, super::plugins::FIXTURE_PUBLISHER);
        manifest.version = facts.version;
        manifest.statement = Some(hex::encode(statement));
        let archive = super::plugins::signed(
            &crate::dist_root_install::release_key(),
            manifest,
            &std::fs::read(library_path).expect("the actual Store artifact reads"),
        );
        std::fs::write(directory.join("store.tar.gz"), archive)
            .expect("stage the actual Store product");
        std::fs::write(directory.join("admin.token"), "admintok")
            .expect("write the operator credential");
        let settings = crate::root::test_plugins::application_store_settings(&directory);
        let mut document = serde_json::json!({});
        document["providers"] = serde_json::json!({});
        document["models"] = serde_json::json!({});
        document["store"] = serde_json::json!({"module": facts.name, "settings": settings});
        document["plugins"] =
            super::plugins::config_document(&super::plugins::trusted_config(&directory));
        document["auth"] = serde_json::json!({"chain": [], "admin_auth": ["admin-tokens"]});
        document["identity-providers"] = serde_json::json!({"admin-tokens": {
            "module": "admin-tokens", "token": {"file": directory.join("admin.token")}
        }});
        document["advanced"] = serde_json::json!({"allow_destinations": ["127.0.0.1"]});
        let deploy = busbar_kernel::config::deploy_from_deserializer(document)
            .expect("the actual admin deployment parses");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the actual admin deployment resolves");
        let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
            as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
        let (mut app, rotate, limits) = busbar_kernel::build_app_from_config(
            cfg,
            super::plugins::trusted_config(&directory),
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
        )
        .expect("the product root builds the actual admin application");
        limits.stage_boot();
        let _book = crate::root::boot::book(&app, "configured-store")
            .expect("the actual configured Store binds boot rate history before activation");
        limits.keep().expect("the product limits commit");
        if let Some(rotate) = rotate {
            rotate();
        }
        app.overlay_path = Some(
            busbar_kernel::config::overlay::OverlayStore::new(
                app.governance
                    .as_ref()
                    .expect("the actual root opened governance")
                    .store_calls()
                    .expect("the actual Store exposes its calls"),
            )
            .expect("the actual Store opens its overlay"),
        );
        app.governance = Some(gov);
        app.plugins_dir = dir.clone();
        app.config_path = Some(config);
        app.providers_path = Some(providers);

        std::sync::Arc::new(app)
    };
    let router = crate::distribution::admin_cross_plane::build_router(app);
    let (addr, server, client) = spin_up(router).await;

    let r = client
        .post(format!("http://{addr}/api/v1/admin/plugins/reload"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    let status = r.status().as_u16();
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(status, 400, "an unrebuildable disk config: {body}");
    assert_eq!(body["error"]["code"], "invalid_request");

    server.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

async fn drive_plugin_rollback_errors() {
    crate::distribution::admin_cross_plane::ensure_seam();

    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "busbar-admin-rollback-witness-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let overlay =
        busbar_kernel::config::overlay::OverlayStore::new(crate::root::real_store::store())
            .expect("the actual Store opens the overlay");

    let tarball = admin_test_tarball("rollme", "rollme");
    let file = "rollme-1.0.0.tar.gz";
    std::fs::write(dir.join(file), &tarball).unwrap();
    let store = crate::root::real_store::store();
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = {
        crate::distribution::admin_cross_plane::ensure_seam();
        let directory = super::plugins::scratch(&format!(
            "admin-root-{}",
            busbar_kernel::door::op_id().counter()
        ));
        let library_path = crate::root::test_plugins::application_store_library();
        let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
            .expect("the actual Store statement reads")
            .expect("the actual Store states itself");
        let facts = busbar_contract::abi::mechanism::rendering::read(&statement)
            .expect("the actual Store statement parses");
        let mut manifest =
            super::plugins::manifest("store", &facts.name, super::plugins::FIXTURE_PUBLISHER);
        manifest.version = facts.version;
        manifest.statement = Some(hex::encode(statement));
        let archive = super::plugins::signed(
            &crate::dist_root_install::release_key(),
            manifest,
            &std::fs::read(library_path).expect("the actual Store artifact reads"),
        );
        std::fs::write(directory.join("store.tar.gz"), archive)
            .expect("stage the actual Store product");
        std::fs::write(directory.join("admin.token"), "admintok")
            .expect("write the operator credential");
        let settings = crate::root::test_plugins::application_store_settings(&directory);
        let mut document = serde_json::json!({});
        document["providers"] = serde_json::json!({});
        document["models"] = serde_json::json!({});
        document["store"] = serde_json::json!({"module": facts.name, "settings": settings});
        document["plugins"] =
            super::plugins::config_document(&super::plugins::trusted_config(&directory));
        document["auth"] = serde_json::json!({"chain": [], "admin_auth": ["admin-tokens"]});
        document["identity-providers"] = serde_json::json!({"admin-tokens": {
            "module": "admin-tokens", "token": {"file": directory.join("admin.token")}
        }});
        document["advanced"] = serde_json::json!({"allow_destinations": ["127.0.0.1"]});
        let deploy = busbar_kernel::config::deploy_from_deserializer(document)
            .expect("the actual admin deployment parses");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the actual admin deployment resolves");
        let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
            as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
        let (mut app, rotate, limits) = busbar_kernel::build_app_from_config(
            cfg,
            super::plugins::trusted_config(&directory),
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
        )
        .expect("the product root builds the actual admin application");
        limits.stage_boot();
        let _book = crate::root::boot::book(&app, "configured-store")
            .expect("the actual configured Store binds boot rate history before activation");
        limits.keep().expect("the product limits commit");
        if let Some(rotate) = rotate {
            rotate();
        }
        app.overlay_path = Some(
            busbar_kernel::config::overlay::OverlayStore::new(
                app.governance
                    .as_ref()
                    .expect("the actual root opened governance")
                    .store_calls()
                    .expect("the actual Store exposes its calls"),
            )
            .expect("the actual Store opens its overlay"),
        );
        app.governance = Some(gov);
        app.overlay_path = Some(overlay.clone());
        app.plugins_dir = dir.clone();
        app.plugins_cfg = busbar_kernel::config::PluginsCfg::default();

        std::sync::Arc::new(app)
    };
    let router = crate::distribution::admin_cross_plane::build_router(app);
    let (addr, server, client) = spin_up(router).await;
    let rollback = |body: String| {
        client
            .post(format!("http://{addr}/api/v1/admin/plugins/rollback"))
            .header("x-admin-token", "admintok")
            .header("content-type", "application/json")
            .body(body)
            .send()
    };

    let r = rollback(r#"{"file":"nosuch-9.9.9.tar.gz"}"#.to_string())
        .await
        .unwrap();
    let status = r.status().as_u16();
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(
        status, 404,
        "a target that is not in the plugins dir: {body}"
    );
    assert_eq!(body["error"]["code"], "not_found");

    let r = rollback(format!(r#"{{"file":"{file}"}}"#)).await.unwrap();
    let status = r.status().as_u16();
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(
        status, 409,
        "an untrusted target is a terminal conflict, not a validation error: {body}"
    );
    assert_eq!(body["error"]["code"], "conflict");

    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&tarball);
    for (label, rel, method, body, want_status, want_code) in [
        (
            "install_bad_body",
            "/plugins",
            "POST",
            Some("{".to_string()),
            400,
            "invalid_request",
        ),
        (
            "install_bad_filename",
            "/plugins",
            "POST",
            Some(format!(
                r#"{{"file":"not-an-archive","tarball_b64":"{b64}"}}"#
            )),
            400,
            "invalid_request",
        ),
        (
            "install_untrusted",
            "/plugins",
            "POST",
            Some(format!(
                r#"{{"file":"fresh-1.0.0.tar.gz","tarball_b64":"{b64}"}}"#
            )),
            409,
            "conflict",
        ),
        (
            "remove_bad_filename",
            "/plugins/not-an-archive",
            "DELETE",
            None,
            400,
            "invalid_request",
        ),
        (
            "remove_unknown",
            "/plugins/ghost-1.0.0.tar.gz",
            "DELETE",
            None,
            404,
            "not_found",
        ),
    ] {
        let mut req = client
            .request(
                reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                format!("http://{addr}/api/v1/admin{rel}"),
            )
            .header("x-admin-token", "admintok");
        if let Some(b) = body {
            req = req.header("content-type", "application/json").body(b);
        }
        let r = req.send().await.unwrap();
        let status = r.status().as_u16();
        let parsed: serde_json::Value = r.json().await.unwrap();
        assert_eq!(status, want_status, "{label}: {parsed}");
        assert_eq!(parsed["error"]["code"], want_code, "{label}");
    }
    server.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

async fn drive_plugin_inspect_errors() {
    crate::distribution::admin_cross_plane::ensure_seam();
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "busbar-admin-inspect-witness-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let overlay =
        busbar_kernel::config::overlay::OverlayStore::new(crate::root::real_store::store())
            .expect("the actual Store opens the overlay");
    let store = crate::root::real_store::store();
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = {
        crate::distribution::admin_cross_plane::ensure_seam();
        let directory = super::plugins::scratch(&format!(
            "admin-root-{}",
            busbar_kernel::door::op_id().counter()
        ));
        let library_path = crate::root::test_plugins::application_store_library();
        let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
            .expect("the actual Store statement reads")
            .expect("the actual Store states itself");
        let facts = busbar_contract::abi::mechanism::rendering::read(&statement)
            .expect("the actual Store statement parses");
        let mut manifest =
            super::plugins::manifest("store", &facts.name, super::plugins::FIXTURE_PUBLISHER);
        manifest.version = facts.version;
        manifest.statement = Some(hex::encode(statement));
        let archive = super::plugins::signed(
            &crate::dist_root_install::release_key(),
            manifest,
            &std::fs::read(library_path).expect("the actual Store artifact reads"),
        );
        std::fs::write(directory.join("store.tar.gz"), archive)
            .expect("stage the actual Store product");
        std::fs::write(directory.join("admin.token"), "admintok")
            .expect("write the operator credential");
        let settings = crate::root::test_plugins::application_store_settings(&directory);
        let mut document = serde_json::json!({});
        document["providers"] = serde_json::json!({});
        document["models"] = serde_json::json!({});
        document["store"] = serde_json::json!({"module": facts.name, "settings": settings});
        document["plugins"] =
            super::plugins::config_document(&super::plugins::trusted_config(&directory));
        document["auth"] = serde_json::json!({"chain": [], "admin_auth": ["admin-tokens"]});
        document["identity-providers"] = serde_json::json!({"admin-tokens": {
            "module": "admin-tokens", "token": {"file": directory.join("admin.token")}
        }});
        document["advanced"] = serde_json::json!({"allow_destinations": ["127.0.0.1"]});
        let deploy = busbar_kernel::config::deploy_from_deserializer(document)
            .expect("the actual admin deployment parses");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the actual admin deployment resolves");
        let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
            as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
        let (mut app, rotate, limits) = busbar_kernel::build_app_from_config(
            cfg,
            super::plugins::trusted_config(&directory),
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
        )
        .expect("the product root builds the actual admin application");
        limits.stage_boot();
        let _book = crate::root::boot::book(&app, "configured-store")
            .expect("the actual configured Store binds boot rate history before activation");
        limits.keep().expect("the product limits commit");
        if let Some(rotate) = rotate {
            rotate();
        }
        app.overlay_path = Some(
            busbar_kernel::config::overlay::OverlayStore::new(
                app.governance
                    .as_ref()
                    .expect("the actual root opened governance")
                    .store_calls()
                    .expect("the actual Store exposes its calls"),
            )
            .expect("the actual Store opens its overlay"),
        );
        app.governance = Some(gov);
        app.overlay_path = Some(overlay.clone());
        app.plugins_dir = dir.clone();
        app.plugins_cfg = busbar_kernel::config::PluginsCfg::default();

        std::sync::Arc::new(app)
    };
    let router = crate::distribution::admin_cross_plane::build_router(app);
    let (addr, server, client) = spin_up(router).await;

    let r = client
        .post(format!("http://{addr}/api/v1/admin/plugins/inspect"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(r#"{"file":"witness-1.0.0.tar.gz","tarball_b64":"not-base64!!"}"#.to_string())
        .send()
        .await
        .unwrap();
    let status = r.status().as_u16();
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(status, 400, "invalid base64 tarball_b64: {body}");
    assert_eq!(body["error"]["code"], "invalid_request");

    server.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn every_admin_error_surface_answers_its_declared_status() {
    if std::env::var_os("BUSBAR_ADMIN_ERROR_UNSUPERVISED_PROCESS").is_none() {
        let current = std::thread::current();
        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args(["--exact", current.name().expect("test name"), "--nocapture"])
            .env("BUSBAR_ADMIN_ERROR_UNSUPERVISED_PROCESS", "1")
            .env_remove("INVOCATION_ID")
            .env_remove("KUBERNETES_SERVICE_HOST")
            .output()
            .expect("run the restart assertions in an unsupervised process");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success()
                && stdout.contains("test result: ok. 1 passed; 0 failed; 0 ignored;"),
            "unsupervised restart assertions failed: {}\n{stdout}\n{stderr}",
            output.status
        );
        return;
    }
    drive_admin_error_surface().await;
    drive_keys_error_surface().await;
    drive_plugin_rollback_errors().await;
    drive_plugin_reload_errors().await;
    drive_plugin_inspect_errors().await;
    drive_key_cap_and_delegation_errors().await;
    drive_named_map_errors().await;
    drive_door_verb_errors().await;
    drive_agent_door_verb_errors().await;
    drive_unpriced_usage_reads().await;
    crate::distribution::admin_cross_plane::ensure_seam();
}

fn documented_operations() -> Vec<(String, busbar_core_admin::v1::contract::taxonomy::MethodTag)> {
    use busbar_core_admin::v1::contract::taxonomy::MethodTag;
    let doc: serde_json::Value =
        serde_json::from_str(&busbar_core_admin::test_support::openapi_json())
            .expect("the committed openapi.json parses");
    let paths = doc["paths"]
        .as_object()
        .expect("openapi.json has a paths object");
    let mut ops = Vec::new();
    for (abs, item) in paths {
        let rel = abs
            .strip_prefix(busbar_core_admin::v1::contract::ADMIN_PREFIX)
            .unwrap_or(abs);
        for key in item.as_object().into_iter().flatten().map(|(k, _)| k) {
            if let Some(m) = MethodTag::from_op_key(key) {
                ops.push((rel.to_string(), m));
            }
        }
    }
    assert!(
        ops.len() >= 40,
        "only {} operations read out of the committed openapi.json — the projection is broken",
        ops.len()
    );
    ops
}

#[test]
fn rate_limit_doc_table_matches_classifier() {
    use busbar_core_admin::v1::contract::taxonomy::MethodTag;

    crate::distribution::admin_cross_plane::ensure_seam();

    let loop_verbs: std::collections::BTreeSet<&'static str> =
        crate::distribution::admin_cross_plane::verb::NEW_VERBS
            .iter()
            .chain(crate::distribution::admin_cross_plane::verb::LEDGER_VERBS)
            .chain(crate::distribution::admin_cross_plane::verb::AUDIT_VERBS)
            .filter_map(|v| crate::distribution::admin_cross_plane::verb::verb_name(*v))
            .collect();
    let answered_by_loop = |rel: &str, method: MethodTag| {
        let method = match method {
            MethodTag::Get => "GET",
            MethodTag::Post => "POST",
            MethodTag::Put => "PUT",
            MethodTag::Patch => "PATCH",
            MethodTag::Delete => "DELETE",
        };
        crate::distribution::admin_cross_plane::admin_codec::verbs::resolve(
            method,
            &format!("{}{rel}", busbar_core_admin::v1::contract::ADMIN_PREFIX),
        )
        .is_some_and(|row| loop_verbs.contains(row.verb))
    };

    let doc = include_str!("../../../../../docs/admin-api.md");
    let row = doc
        .lines()
        .find(|l| l.trim_start().starts_with("| config | 10/min |"))
        .expect("docs/admin-api.md has a `config` row in the mutation rate-limit table");
    let doc_config: std::collections::BTreeSet<(String, MethodTag)> = row
        .split('`')
        .skip(1)
        .step_by(2)
        .map(|token| {
            let mut parts = token.splitn(2, ' ');
            let method = parts.next().unwrap();
            let path = parts.next().unwrap_or_else(|| {
                panic!("doc token {token:?} is not \"METHOD /path\"");
            });
            let m = MethodTag::from_op_key(&method.to_lowercase())
                .unwrap_or_else(|| panic!("unrecognized HTTP method {method:?} in doc row"));
            (path.to_string(), m)
        })
        .collect();
    assert!(
        doc_config.len() >= 6,
        "only parsed {} endpoints out of the doc's config row — the parser is broken: {row:?}",
        doc_config.len()
    );

    let code_config: std::collections::BTreeSet<(String, MethodTag)> = documented_operations()
        .into_iter()
        .filter(|(rel, method)| {
            matches!(
                method,
                MethodTag::Post | MethodTag::Put | MethodTag::Patch | MethodTag::Delete
            ) && !answered_by_loop(rel, *method)
                && busbar_kernel::ratelimit::classify_mutation(rel)
                    == busbar_kernel::ratelimit::MutationClass::Config
        })
        .collect();

    let missing_from_doc: Vec<_> = code_config.difference(&doc_config).collect();
    let missing_from_code: Vec<_> = doc_config.difference(&code_config).collect();
    assert!(
        missing_from_doc.is_empty() && missing_from_code.is_empty(),
        "docs/admin-api.md's config-class row has drifted from ratelimit::classify_mutation.\n\
         In classifier's CONFIG class but not in the doc: {missing_from_doc:?}\n\
         In the doc but not classified CONFIG: {missing_from_code:?}"
    );
}

#[test]
fn overlay_reset_doc_row_matches_the_section_set() {
    use busbar_kernel::config::overlay::OverlaySection;

    crate::distribution::admin_cross_plane::ensure_seam();

    let doc = include_str!("../../../../../docs/admin-api.md");
    let row = doc
        .lines()
        .find(|l| {
            l.trim_start()
                .starts_with("| `DELETE /overlay/{section}` |")
        })
        .expect("docs/admin-api.md has a `DELETE /overlay/{section}` row");

    let (_, after) = row
        .split_once("(`section` ∈ ")
        .expect("the row states the section set as \"(`section` ∈ …)\"");
    let enumerated = after
        .split_once(')')
        .expect("the section set is parenthesised")
        .0;
    let doc_sections: std::collections::BTreeSet<&str> =
        enumerated.split('`').skip(1).step_by(2).collect();
    assert!(
        doc_sections.len() >= 4,
        "only parsed {} section names out of the doc row; the parser is broken and this test must \
         not report a pass on an empty set: {enumerated:?}",
        doc_sections.len()
    );

    let all = OverlaySection::all();
    let code_sections: std::collections::BTreeSet<&str> = all.iter().map(|s| s.as_str()).collect();
    assert_eq!(
        code_sections.len(),
        all.len(),
        "OverlaySection::all() yields a duplicate wire name"
    );
    let missing_from_doc: Vec<_> = code_sections.difference(&doc_sections).collect();
    let missing_from_code: Vec<_> = doc_sections.difference(&code_sections).collect();
    assert!(
        missing_from_doc.is_empty() && missing_from_code.is_empty(),
        "docs/admin-api.md's `DELETE /overlay/{{section}}` row has drifted from \
         OverlaySection::all().\nLive in the code but absent from the doc (an operator is told the \
         section does not exist): {missing_from_doc:?}\nClaimed by the doc but rejected by \
         `OverlaySection::parse` (an operator is told to call something that 400s): \
         {missing_from_code:?}"
    );

    for name in &doc_sections {
        assert!(
            OverlaySection::parse(name).is_some(),
            "the doc lists section `{name}` but `OverlaySection::parse` rejects it"
        );
    }
}

fn linked_export_axis() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        static SINKS: [crate::distribution::admin_cross_plane::root_install::ExportDoor; 1] = [(
            busbar_export_prometheus::NAME,
            busbar_export_prometheus::ALIAS,
            busbar_export_prometheus::door::door,
        )];
        crate::distribution::admin_cross_plane::ensure_seam();
        crate::distribution::admin_cross_plane::root_install::link_exports(&SINKS);
    });
}

fn write_named_map_fixture(
    tag: &str,
    reference_corp_ad: bool,
    base_export: bool,
) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    linked_export_axis();
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "busbar-namedmap-{}-{}-{}",
        tag,
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let providers_path = dir.join("providers.yaml");
    let config_path = dir.join("config.yaml");
    std::fs::write(
        &providers_path,
        format!(
            "test-provider:
  protocol: {PROTO_ANTHROPIC}
  base_url: http://127.0.0.1:1/
"
        ),
    )
    .unwrap();
    std::fs::write(
        &config_path,
        ("listen: 127.0.0.1:0
store: {module: memory}
providers:
  test-provider:
    api_key: none
models:
  m0:
    provider: test-provider
    max_concurrent: 4
pools:
  p:
    members:
      - model: m0
identity-providers:
  base-idp:
    module: keys
  admin-tokens:
    module: admin-tokens
    token: { file: ADMIN_TOKEN_FILE }
tools:
  base-tools:
    url: https://tools.internal/fs
    pin: { mechanism: cert_spki, key: \"sha256/BASE=\" }
agents:
  base-agent:
    url: https://agents.example/planner
    pin:
      mechanism: unpinned
"
        .to_string()
            + if base_export {
                "export:\n  base-metrics:\n    module: prometheus\n    settings: { buffer_seconds: 60 }\n"
            } else {
                ""
            })
        .replace(
            "ADMIN_TOKEN_FILE",
            &dir.join("admin.token").to_string_lossy(),
        ) + if reference_corp_ad {
            "auth:\n  admin_auth: [admin-tokens, corp-ad]\n"
        } else {
            ""
        },
    )
    .unwrap();

    std::fs::write(dir.join("admin.token"), "admintok").unwrap();
    if reference_corp_ad {
        std::fs::write(dir.join("corp.token"), "corp-secret").unwrap();
    }
    (dir, config_path, providers_path)
}

async fn named_map_app(
    tag: &str,
    reference_corp_ad: bool,
) -> (
    std::path::PathBuf,
    Arc<busbar_kernel::config::overlay::OverlayStore>,
    std::net::SocketAddr,
    tokio::task::JoinHandle<()>,
) {
    named_map_app_opts(tag, reference_corp_ad, true, ServeTables::default()).await
}

async fn named_map_app_serving(
    tag: &str,
    tables: ServeTables,
) -> (
    std::path::PathBuf,
    Arc<busbar_kernel::config::overlay::OverlayStore>,
    std::net::SocketAddr,
    tokio::task::JoinHandle<()>,
) {
    named_map_app_opts(tag, false, true, tables).await
}

async fn named_map_app_opts(
    tag: &str,
    reference_corp_ad: bool,
    base_export: bool,
    tables: ServeTables,
) -> (
    std::path::PathBuf,
    Arc<busbar_kernel::config::overlay::OverlayStore>,
    std::net::SocketAddr,
    tokio::task::JoinHandle<()>,
) {
    linked_export_axis();
    let (dir, config_path, providers_path) =
        write_named_map_fixture(tag, reference_corp_ad, base_export);
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual Store statement reads")
        .expect("the actual Store states itself");
    let facts = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual Store statement parses");
    let mut manifest =
        super::plugins::manifest("store", &facts.name, super::plugins::FIXTURE_PUBLISHER);
    manifest.version = facts.version;
    manifest.statement = Some(hex::encode(statement));
    let archive = super::plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &std::fs::read(library_path).expect("the actual Store artifact reads"),
    );
    let plugin_dir = dir.join("plugins");
    std::fs::create_dir_all(&plugin_dir).expect("the product plugin directory");
    std::fs::write(plugin_dir.join("store.tar.gz"), archive)
        .expect("stage the actual Store product");
    let settings = crate::root::test_plugins::application_store_settings(&dir);
    let mut disk: serde_yaml::Value =
        serde_yaml::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
    disk["store"] =
        serde_yaml::to_value(serde_json::json!({"module": facts.name, "settings": settings}))
            .unwrap();
    disk["plugins"] = serde_yaml::to_value(super::plugins::config_document(
        &super::plugins::trusted_config(&plugin_dir),
    ))
    .expect("the disk baseline retains the actual signed Store configuration");
    std::fs::write(&config_path, serde_yaml::to_string(&disk).unwrap())
        .expect("write the actual Store selection");
    // The reset witness intentionally leaves corp-ad referenced only in the disk baseline;
    // the initial live generation has the operator entry until the test creates corp-ad.
    let mut live = disk;
    live["auth"] = serde_yaml::from_str("chain: []\nadmin_auth: [admin-tokens]\n").unwrap();
    let deploy =
        busbar_kernel::config::deploy_from_deserializer(live).expect("the admin deployment parses");
    let defs = busbar_kernel::config::providers::catalog_from_str(
        &std::fs::read_to_string(&providers_path).unwrap(),
    )
    .expect("the provider catalog parses");
    let cfg = busbar_kernel::config::resolve(&deploy, &defs)
        .expect("the actual admin deployment resolves");
    let store = crate::root::real_store::store();
    let overlay = busbar_kernel::config::overlay::OverlayStore::new(store.clone())
        .expect("the configured Store opens its overlay");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (mut app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        cfg,
        super::plugins::trusted_config(&plugin_dir),
        Some(overlay.clone()),
        Default::default(),
        Default::default(),
        (Some(config_path), Some(providers_path)),
        None,
        &rules,
        Some(busbar_contract::store_calls::OpenedStore {
            records: store.clone(),
            calls: Some(store),
        }),
        false,
    )
    .expect("the actual product builds the named-map application");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, "configured-store")
        .expect("the actual configured Store binds boot rate history before activation");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    app.serve_tables = tables;
    let app = Arc::new(app);
    busbar_kernel::audit::auditlog::register_test_audit_stream(&app);
    let router = crate::distribution::admin_cross_plane::build_router(app);
    let (addr, handle, _) = spin_up(router).await;
    (dir, overlay, addr, handle)
}

#[tokio::test]
async fn test_admin_v1_named_maps_list_get_and_put_round_trip() {
    linked_export_axis();
    let (dir, overlay, addr, handle) = named_map_app("roundtrip", false).await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| {
        r.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };

    let cases: [(&str, &str, serde_json::Value); 2] = [
        (
            "identity-providers",
            "base-idp",
            serde_json::json!({"module": "keys", "max_admin_scope": "read-only"}),
        ),
        (
            "export",
            "base-metrics",
            serde_json::json!({
                "module": "request-log-file",
                "settings": {"path": dir.join("req.jsonl").to_string_lossy()}
            }),
        ),
    ];
    for (section, base, def) in &cases {
        let r = admin(client.get(format!("http://{addr}/api/v1/admin/{section}")))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 200, "GET /{section}");
        let etag = r
            .headers()
            .get("etag")
            .expect("the list read emits the config-plane ETag")
            .to_str()
            .unwrap()
            .to_string();
        let body: serde_json::Value = r.json().await.unwrap();
        let names: Vec<&str> = body["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(base), "GET /{section} lists {base}: {body}");

        let one: serde_json::Value =
            admin(client.get(format!("http://{addr}/api/v1/admin/{section}/{base}")))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
        assert_eq!(one["name"], *base);
        assert!(one["module"].is_string(), "the definition names its module");
        if *section == "identity-providers" {
            assert_eq!(
                one["token_configured"], false,
                "an identity provider projects WHETHER a credential is configured, never the \
                 reference itself"
            );
        } else {
            assert!(
                one.get("max_admin_scope").is_none() && one.get("token_configured").is_none(),
                "an exporter carries no ceiling and no credential, so those fields are omitted \
                 entirely: {one}"
            );
        }

        let name = format!("new-{section}");
        let put = admin(client.put(format!("http://{addr}/api/v1/admin/{section}/{name}")))
            .header("if-match", etag)
            .body(def.to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(
            put.status().as_u16(),
            200,
            "PUT /{section}/{name}: {:?}",
            put.text().await
        );

        let after: serde_json::Value =
            admin(client.get(format!("http://{addr}/api/v1/admin/{section}/{name}")))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
        assert_eq!(
            after["name"], name,
            "the PUT definition reads back: {after}"
        );
        assert_eq!(after["module"], def["module"]);

        let doc = busbar_kernel::config::overlay::read(&overlay.clone()).expect("overlay written");
        assert_eq!(
            doc.named_maps[*section][&name], *def,
            "the overlay stores the definition VERBATIM"
        );
    }
    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_admin_v1_named_map_put_honors_expected_version() {
    linked_export_axis();
    let (dir, _overlay, addr, handle) = named_map_app("ifmatch", false).await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| {
        r.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };
    for (section, def) in [
        ("identity-providers", serde_json::json!({"module": "keys"})),
        (
            "export",
            serde_json::json!({"module": "prometheus", "settings": {"buffer_seconds": 30}}),
        ),
    ] {
        let r = admin(client.put(format!("http://{addr}/api/v1/admin/{section}/stale")))
            .header("if-match", "\"9999\"")
            .body(def.to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 409, "a stale guard rejects");
        let body: serde_json::Value = r.json().await.unwrap();
        assert_eq!(
            body["error"]["code"], "version_conflict",
            "RETRYABLE, distinct from a terminal conflict: {body}"
        );

        let after = admin(client.get(format!("http://{addr}/api/v1/admin/{section}/stale")))
            .send()
            .await
            .unwrap();
        assert_eq!(
            after.status().as_u16(),
            404,
            "the rejected PUT stored nothing"
        );
    }
    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_admin_v1_identity_provider_refuses_raising_max_admin_scope() {
    let (dir, addr, handle) = {
        let (dir, _overlay, addr, handle) = named_map_app("ceiling", false).await;
        (dir, addr, handle)
    };
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| {
        r.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };

    let provider = "ceiling-audit-witness";

    let r = admin(client.put(format!(
        "http://{addr}/api/v1/admin/identity-providers/{provider}"
    )))
    .body(r#"{"module":"keys","max_admin_scope":"full"}"#)
    .send()
    .await
    .unwrap();
    assert_eq!(r.status().as_u16(), 409, "raising the ceiling is refused");
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["error"]["code"], "conflict");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("max_admin_scope"),
        "the refusal names the ceiling: {body}"
    );

    let after = admin(client.get(format!(
        "http://{addr}/api/v1/admin/identity-providers/{provider}"
    )))
    .send()
    .await
    .unwrap();
    assert_eq!(
        after.status().as_u16(),
        404,
        "the refused PUT stored nothing"
    );

    let r = admin(client.put(format!(
        "http://{addr}/api/v1/admin/identity-providers/{provider}"
    )))
    .body(r#"{"module":"keys","max_admin_scope":"none"}"#)
    .send()
    .await
    .unwrap();
    assert_eq!(
        r.status().as_u16(),
        400,
        "`none` is not a ceiling the engine accepts, so the API must refuse it"
    );
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["error"]["code"], "invalid_request");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("expected read-only or full"),
        "the refusal names the accepted values: {body}"
    );
    let after = admin(client.get(format!(
        "http://{addr}/api/v1/admin/identity-providers/{provider}"
    )))
    .send()
    .await
    .unwrap();
    assert_eq!(
        after.status().as_u16(),
        404,
        "the refused PUT stored nothing"
    );

    let r = admin(client.put(format!(
        "http://{addr}/api/v1/admin/identity-providers/{provider}"
    )))
    .body(r#"{"module":"keys","max_admin_scope":"read-only"}"#)
    .send()
    .await
    .unwrap();
    assert_eq!(
        r.status().as_u16(),
        200,
        "`read-only` can never be a raise: {:?}",
        r.text().await
    );

    let r = admin(client.put(format!(
        "http://{addr}/api/v1/admin/identity-providers/{provider}"
    )))
    .body(r#"{"module":"keys","max_admin_scope":"full"}"#)
    .send()
    .await
    .unwrap();
    assert_eq!(r.status().as_u16(), 409, "a raise in place is refused too");
    let still: serde_json::Value = admin(client.get(format!(
        "http://{addr}/api/v1/admin/identity-providers/{provider}"
    )))
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    assert_eq!(
        still["max_admin_scope"], "read-only",
        "the live ceiling is untouched by the refused raise: {still}"
    );

    let audit: serde_json::Value = admin(client.get(format!(
        "http://{addr}/api/v1/admin/audit?resource=identity-provider:{provider}"
    )))
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    let items = audit["items"].as_array().unwrap();
    assert!(
        items.iter().any(|i| i["outcome"] == "rejected"
            && i["action"] == "identity-provider.replace"
            && i["resource"] == format!("identity-provider:{provider}")),
        "a refused ceiling raise is audited: {audit}"
    );
    assert!(
        items.iter().any(|i| i["outcome"] == "applied"
            && i["action"] == "identity-provider.replace"
            && i["resource"] == format!("identity-provider:{provider}")),
        "the accepted change is audited: {audit}"
    );
    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_admin_v1_export_put_that_adds_a_route_reports_restart_required() {
    linked_export_axis();
    use busbar_contract::export_calls::ExportAxis as _;
    const REQLOG_RESTART_NOTE: &str = "stored, but the export instance(s) export.reqlog require a \
RESTART to apply membership, module or streams/fields projection changes to push delivery; this \
process keeps its boot-opened sinks and their projections until then. Settings refreshes for \
existing instances of the same module still apply live";
    assert!(crate::root::exports::EXPORTS.linked("request-log-file"));
    assert!(
        crate::root::exports::EXPORTS
            .routes("request-log-file")
            .is_empty(),
        "the actual file sink declares no route; its restart requirement is push membership"
    );

    let (dir, _overlay, addr, handle) =
        named_map_app_opts("bootfrozen", false, false, ServeTables::default()).await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| {
        r.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };

    let r = admin(client.put(format!("http://{addr}/api/v1/admin/export/reqlog")))
        .body(
            serde_json::json!({
                "module": "request-log-file",
                "settings": {"path": dir.join("req.jsonl").to_string_lossy()}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200, "{:?}", r.text().await);
    let put_body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(put_body["note"], REQLOG_RESTART_NOTE);
    assert_eq!(
        put_body["reload_to_apply"],
        serde_json::json!(["export.reqlog"])
    );
    assert!(
        put_body["note"]
            .as_str()
            .is_some_and(|note| note.contains("RESTART")
                && note.contains("membership")
                && note.contains("push delivery")),
        "the route-free sink names its boot-bound push membership: {put_body}"
    );
    let body: serde_json::Value =
        admin(client.get(format!("http://{addr}/api/v1/admin/export/reqlog")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    assert_eq!(
        body["reload_to_apply"],
        serde_json::json!(["export.reqlog"])
    );
    assert_eq!(
        body["note"], REQLOG_RESTART_NOTE,
        "GET retains the pending push-delivery membership independently of routes"
    );

    let r = admin(client.put(format!("http://{addr}/api/v1/admin/export/prom")))
        .body(
            serde_json::json!({
                "module": "prometheus", "settings": {"buffer_seconds": 30}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200, "the definition is still stored");
    let body: serde_json::Value = r.json().await.unwrap();
    let empty = Vec::new();
    assert_eq!(
        body["reload_to_apply"],
        serde_json::json!(["/metrics", "export.prom"])
    );
    let flagged: Vec<&str> = body["reload_to_apply"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .filter_map(|v| v.as_str())
        .filter(|name| name.starts_with('/'))
        .collect();
    assert_eq!(
        flagged,
        vec!["/metrics"],
        "the ADDED route the router cannot serve is named: {body}"
    );
    assert!(
        body["note"].as_str().unwrap_or("").contains("RESTART"),
        "the note tells the operator what to do about it: {body}"
    );

    assert_eq!(body["name"], "prom");
    assert_eq!(body["module"], "prometheus");

    assert_eq!(
        client
            .get(format!("http://{addr}/metrics"))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        404,
        "`/metrics` is not mounted, exactly as the response just said"
    );

    // This instance is still newly added, so a settings-only edit cannot clear its pending
    // membership. The existing-instance live-settings control is retained in the actual kernel's
    // `export_restart_metadata_compares_boot_membership_module_and_effective_projection` test.
    let r = admin(client.patch(format!("http://{addr}/api/v1/admin/export/reqlog/settings")))
        .body(
            serde_json::json!({"settings": {"path": dir.join("req2.jsonl").to_string_lossy()}})
                .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200, "{:?}", r.text().await);
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(
        body["reload_to_apply"],
        serde_json::json!(["export.reqlog"])
    );
    assert_eq!(
        body["note"], REQLOG_RESTART_NOTE,
        "settings cannot open a newly added sink; no unrelated pending route is re-flagged"
    );

    let r = admin(client.delete(format!("http://{addr}/api/v1/admin/export/prom")))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 204, "a removal applies live");

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_admin_v1_identity_provider_validates_an_unreferenced_definition() {
    let (dir, addr, handle) = {
        let (dir, _overlay, addr, handle) = named_map_app("unreferenced", false).await;
        (dir, addr, handle)
    };
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| {
        r.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };

    let r = admin(client.put(format!(
        "http://{addr}/api/v1/admin/identity-providers/stray"
    )))
    .body(r#"{"module":"keys","token":{"env":"BUSBAR_STRAY_TOKEN"}}"#)
    .send()
    .await
    .unwrap();
    assert_eq!(
        r.status().as_u16(),
        400,
        "a `token:` on a non-`admin-tokens` module is a misplaced secret, referenced or not"
    );
    let body: serde_json::Value = r.json().await.unwrap();
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("meaningless on `module: keys`"),
        "the refusal states the placement rule: {body}"
    );
    let after = admin(client.get(format!(
        "http://{addr}/api/v1/admin/identity-providers/stray"
    )))
    .send()
    .await
    .unwrap();
    assert_eq!(
        after.status().as_u16(),
        404,
        "the refused PUT stored no credential"
    );

    let r = admin(client.put(format!(
        "http://{addr}/api/v1/admin/identity-providers/stray"
    )))
    .body(r#"{"module":"keys","max_admin_scope":"none"}"#)
    .send()
    .await
    .unwrap();
    assert_eq!(
        r.status().as_u16(),
        400,
        "an unreferenced provider's ceiling is checked where it is written"
    );

    let r = admin(client.put(format!(
        "http://{addr}/api/v1/admin/identity-providers/stray"
    )))
    .body(r#"{"module":"keys","max_admin_scope":"read-only"}"#)
    .send()
    .await
    .unwrap();
    assert_eq!(r.status().as_u16(), 200, "{:?}", r.text().await);
    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_admin_v1_identity_provider_rejects_an_unknown_module() {
    let (dir, addr, handle) = {
        let (dir, _overlay, addr, handle) = named_map_app("unknown-module", false).await;
        (dir, addr, handle)
    };
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| {
        r.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };
    let r = admin(client.put(format!(
        "http://{addr}/api/v1/admin/identity-providers/typo"
    )))
    .body(r#"{"module":"not-a-real-idp"}"#)
    .send()
    .await
    .unwrap();
    assert_eq!(
        r.status().as_u16(),
        400,
        "a `module:` naming nothing that exists must be refused where it is written"
    );
    let body: serde_json::Value = r.json().await.unwrap();
    let msg = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains("not-a-real-idp"),
        "the refusal names the unknown module: {body}"
    );
    assert!(
        msg.contains("keys") && msg.contains("admin-tokens"),
        "the refusal lists the valid modules, the way every other section's module refusal names \
         its whole valid set: {body}"
    );
    let after = admin(client.get(format!(
        "http://{addr}/api/v1/admin/identity-providers/typo"
    )))
    .send()
    .await
    .unwrap();
    assert_eq!(
        after.status().as_u16(),
        404,
        "the refused PUT stored nothing"
    );

    let r = admin(client.put(format!(
        "http://{addr}/api/v1/admin/identity-providers/typo"
    )))
    .body(r#"{"module":"keys"}"#)
    .send()
    .await
    .unwrap();
    assert_eq!(r.status().as_u16(), 200, "{:?}", r.text().await);
    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_admin_v1_identity_provider_delete_rejects_a_dangling_reference() {
    linked_export_axis();
    let (dir, _overlay, addr, handle) = named_map_app("dangling", true).await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| {
        r.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };

    let r = admin(client.put(format!(
        "http://{addr}/api/v1/admin/identity-providers/corp-ad"
    )))
    .body(
        serde_json::json!({
            "module": "admin-tokens",
            "token": {"file": dir.join("corp.token").to_string_lossy()}
        })
        .to_string(),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(r.status().as_u16(), 200, "{:?}", r.text().await);

    let r = admin(client.delete(format!(
        "http://{addr}/api/v1/admin/identity-providers/corp-ad"
    )))
    .send()
    .await
    .unwrap();
    assert_eq!(r.status().as_u16(), 409, "a dangling delete is refused");
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["error"]["code"], "conflict");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("auth.admin_auth"),
        "the refusal NAMES the referent so an operator knows what to fix: {body}"
    );

    let after = admin(client.get(format!(
        "http://{addr}/api/v1/admin/identity-providers/corp-ad"
    )))
    .send()
    .await
    .unwrap();
    assert_eq!(
        after.status().as_u16(),
        200,
        "the refused delete changed nothing"
    );

    let r = admin(client.put(format!("http://{addr}/api/v1/admin/export/spare")))
        .body(
            serde_json::json!({
                "module": "request-log-file",
                "settings": {"path": dir.join("spare.jsonl").to_string_lossy()}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200, "{:?}", r.text().await);
    let r = admin(client.delete(format!("http://{addr}/api/v1/admin/export/spare")))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        204,
        "an unreferenced definition deletes"
    );
    let after = admin(client.get(format!("http://{addr}/api/v1/admin/export/spare")))
        .send()
        .await
        .unwrap();
    assert_eq!(after.status().as_u16(), 404, "and is gone");
    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

fn try_publish_door(
    section: &str,
    settings: &str,
) -> Result<(ServeTables, Arc<busbar_kernel::plane_driver::PlaneDriver>), String> {
    use busbar_contract::plane_calls::PlaneCalls;
    use busbar_plugin_loader::dispatch::kinds::plane::{open_door, Plane};
    use busbar_plugin_loader::dispatch::{
        load_linked, Bind, DispatchConfig, Dispatcher, LinkedRow, NoSink,
    };
    crate::distribution::admin_cross_plane::ensure_seam();
    let owner = busbar_kernel::plane_driver::registry::plane_decl_for_config_section(section)
        .unwrap_or_else(|| panic!("a test-linked plane owns `{section}:`"));
    // These are serving instances, so their advertised conditional-record protocol needs
    // the actual Store-backed host services used by the composition root.
    let store = crate::root::real_store::store();
    let gov = gov_with_signer(store.clone(), None);
    assert!(gov.attach_store_calls(store.clone()));
    let services = crate::root::serve::LateServices::new();
    let kernel = Arc::new(
        busbar_kernel::host_services::KernelServices::new()
            .with_signer(gov.clone())
            .with_pool(Arc::new(busbar_kernel::host_services::BlockingPool::new(
                tokio::runtime::Handle::current(),
                busbar_kernel::host_records::QUEUE_CAP,
            )))
            .with_records(Arc::new(busbar_kernel::host_records::StoreRows(store))),
    );
    services
        .install_kernel(kernel.clone(), kernel.clone())
        .unwrap();
    let dispatcher = Arc::new(Dispatcher::with_services(
        DispatchConfig::default(),
        services.served(),
    ));
    let _ = dispatcher.lend_seal(busbar_kernel::seal::lend());
    let conns = crate::root::connector::installed()
        .expect("the actual root installs its declared connection table")
        .clone();
    let (instance, plane) = crate::distribution::admin_cross_plane::test_seams::linked_doors()
        .iter()
        .find_map(|(label, door)| {
            let row = LinkedRow::of(*door).ok()?;
            let instance = format!("{label}-published");
            let plane = load_linked::<Plane>(
                &row,
                Bind {
                    instance: Arc::from(instance.as_str()),
                    max_inflight_cap: 64,
                    sink: Arc::new(NoSink),
                    dispatcher: dispatcher.adopter(),
                    conns: busbar_plugin_loader::dispatch::ConnTable::Host(conns.clone()),
                },
            )
            .ok()?;
            (plane.served().section == owner.config_section).then_some((instance, plane))
        })
        .expect("the owning plane's door is test-linked");
    let snapshot = open_door(&plane, settings.as_bytes(), b"", None)?;
    let routes = snapshot
        .admin_routes
        .iter()
        .map(|r| busbar_kernel::plane_driver::serve::ServeRoute {
            verb: r.verb.clone(),
            target: r.target.clone(),
            flags: r.flags,
            audit_verb: r.audit_verb.clone(),
        })
        .collect();
    let audit_kind = plane.served().audit_kind.to_string();
    let op_classes = plane
        .served()
        .op_classes
        .iter()
        .map(|class| busbar_contract::ids::OpClassId::new(class))
        .collect();
    let calls = Arc::new(
        busbar_plugin_loader::dispatch::plane_calls::PlaneInstance::new(plane, dispatcher, 0),
    );
    let refusal_statuses = calls.refusal_statuses();
    let calls: Arc<dyn PlaneCalls> = calls;
    let node = Arc::new(crate::root::plane_node::Node::new());
    let money = Arc::new(busbar_kernel::plane_driver::PlaneMoney::new(
        gov,
        Arc::new(crate::root::plane_node::NodeEndPost::new(node)),
    ));
    let settings = serde_yaml::from_str(settings)
        .expect("the exact opened section also supplies the normal host admission");
    // The real trust verbs read admitted counterparties. Keep normal driver custody until the
    // generation's requests finish, rather than opening a raw unadmitted plugin and dropping it.
    let admission = Arc::new(busbar_kernel::plane_driver::PlaneDriver::new(
        calls.clone(),
        busbar_kernel::plane_driver::DriverConfig {
            caps: busbar_kernel::plane_driver::BufferCaps::default(),
            op_classes,
            status_of: busbar_kernel::plane_driver::refusal_status,
            refusal_statuses,
            caller_refs: money.caller_refs(),
        },
        money,
        kernel,
        (section, &settings),
    )?);
    let tables = ServeTables::default();
    tables
        .publish(
            busbar_kernel::plane_driver::serve::ServeTable {
                instance,
                audit_kind,
                calls,
                caps: busbar_kernel::plane_driver::BufferCaps::default(),
                routes,
                records: None,
            },
            &[],
        )
        .expect("its admin routes publish");
    Ok((tables, admission))
}

fn publish_door(
    section: &str,
    settings: &str,
) -> (ServeTables, Arc<busbar_kernel::plane_driver::PlaneDriver>) {
    try_publish_door(section, settings).expect("the door opens")
}

fn assert_passthrough_is_refused_before_publication() {
    // This original registration formerly reached connect's 400 guard. The product now rejects
    // credential forwarding while OPEN reads the section, before any route can be published.
    let error = match try_publish_door(
        "tools",
        r#"{"base-tools": {"url": "https://pass.example/rpc", "pin": {"mechanism": "cert_spki", "key": "sha256/l5WGzHWyALvI/qjcwI1ctxb3Jp8+8Ztd0NTYTcL0Q4s="}, "upstream_credentials": "passthrough", "tools_allow": {"read": {"schema_hash": "sha256:aa"}}}}"#,
    ) {
        Err(error) => error,
        Ok(_) => panic!("a passthrough registration must not publish an admin route"),
    };
    assert!(
        error.contains("upstream_credentials: passthrough"),
        "{error}"
    );
    assert!(error.contains("is refused"), "{error}");
    assert!(error.contains("caller"), "{error}");
}

async fn drive_door_verb_errors() {
    assert_passthrough_is_refused_before_publication();
    let (tables, _admission) = publish_door(
        "tools",
        r#"{"base-tools": {"url": "https://pass.example/rpc", "pin": {"mechanism": "cert_spki", "key": "sha256/l5WGzHWyALvI/qjcwI1ctxb3Jp8+8Ztd0NTYTcL0Q4s="}, "upstream_credentials": "own", "tools_allow": {"read": {"schema_hash": "sha256:aa"}}}}"#,
    );
    let (_dir, _overlay, addr, handle) = named_map_app_serving("door-verbs", tables).await;
    let client = reqwest::Client::new();
    let send = |method: reqwest::Method, path: &str| {
        client
            .request(method, format!("http://{addr}/api/v1/admin{path}"))
            .header("x-admin-token", "admintok")
            .send()
    };
    for (method, path) in [
        (reqwest::Method::POST, "/tools/nope/connect"),
        (reqwest::Method::GET, "/tools/nope/changes"),
        (reqwest::Method::GET, "/tools/nope/health"),
    ] {
        let r = send(method.clone(), path).await.unwrap();
        assert_eq!(r.status(), 404, "{method} {path}");
        let body: serde_json::Value = r.json().await.unwrap();
        assert_eq!(body.pointer("/error/code").unwrap(), "not_found", "{body}");
    }
    let r = send(reqwest::Method::GET, "/tools/base-tools/changes")
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body.get("name").unwrap(), "base-tools", "{body}");
    assert!(body.get("error").is_none(), "{body}");
    handle.abort();
}

#[tokio::test]
async fn a_door_admin_route_is_served_only_by_the_generation_lent_its_table() {
    assert_passthrough_is_refused_before_publication();
    let (tables, _admission) = publish_door(
        "tools",
        r#"{"base-tools": {"url": "https://pass.example/rpc", "pin": {"mechanism": "cert_spki", "key": "sha256/l5WGzHWyALvI/qjcwI1ctxb3Jp8+8Ztd0NTYTcL0Q4s="}, "upstream_credentials": "own", "tools_allow": {"read": {"schema_hash": "sha256:aa"}}}}"#,
    );
    let (lent_dir, _lent_overlay, lent, lent_handle) =
        named_map_app_serving("door-table-lent", tables).await;
    let (unlent_dir, _unlent_overlay, unlent, unlent_handle) =
        named_map_app("door-table-unlent", false).await;
    let client = reqwest::Client::new();
    // A read observes this exact published generation without starting an unrelated
    // operator refresh that requires a fully composed connector and trust writer.
    let changes = |addr: std::net::SocketAddr| {
        client
            .get(format!(
                "http://{addr}/api/v1/admin/tools/base-tools/changes"
            ))
            .header("x-admin-token", "admintok")
            .send()
    };
    let r = changes(lent).await.unwrap();
    let status = r.status().as_u16();
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(status, 200, "the lent generation serves the door: {body}");
    assert_eq!(body.get("name").unwrap(), "base-tools", "{body}");
    assert!(body.get("error").is_none(), "{body}");
    let r = changes(unlent).await.unwrap();
    let status = r.status().as_u16();
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(
        status, 404,
        "a generation lent no table serves no door: {body}"
    );
    assert_eq!(body.pointer("/error/code").unwrap(), "not_found", "{body}");
    lent_handle.abort();
    unlent_handle.abort();
    let _ = std::fs::remove_dir_all(&lent_dir);
    let _ = std::fs::remove_dir_all(&unlent_dir);
}

fn issuer_key_info(issuer: &ed25519_dalek::SigningKey) -> String {
    use base64::Engine as _;
    let mut der = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    der.extend_from_slice(issuer.verifying_key().as_bytes());
    base64::engine::general_purpose::STANDARD.encode(der)
}

async fn drive_agent_door_verb_errors() {
    let issuer = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let section = serde_json::json!({
        "base-agent": {
            "url": "http://127.0.0.1:1/closed",
            "allow_private": true,
            "pin": {"mechanism": "jws_issuer_key", "key": issuer_key_info(&issuer)}
        }
    });
    let (tables, _admission) = publish_door("agents", &section.to_string());
    let (_dir, _overlay, addr, handle) = named_map_app_serving("agent-door-verbs", tables).await;
    let client = reqwest::Client::new();
    let send = |path: &str, body: &str| {
        client
            .post(format!("http://{addr}/api/v1/admin{path}"))
            .header("x-admin-token", "admintok")
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
    };
    for path in ["/agents/nope/connect", "/agents/nope/approve"] {
        let r = send(path, r#"{"fingerprint": "sha256:aa"}"#).await.unwrap();
        assert_eq!(r.status(), 404, "{path}");
        let body: serde_json::Value = r.json().await.unwrap();
        assert_eq!(body.pointer("/error/code").unwrap(), "not_found", "{body}");
    }
    let r = send(
        "/agents/base-agent/approve",
        r#"{"fingerprint": "sha256:aa", "and": "more"}"#,
    )
    .await
    .unwrap();
    assert_eq!(r.status(), 400, "approve with an unknown body field");
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(
        body.pointer("/error/code").unwrap(),
        "invalid_request",
        "{body}"
    );
    assert!(
        body.to_string().contains("fingerprint"),
        "the malformed-body refusal names the one field the body may carry: {body}"
    );
    let r = send(
        "/agents/base-agent/approve",
        r#"{"fingerprint": "sha256:aa"}"#,
    )
    .await
    .unwrap();
    assert_eq!(r.status(), 400, "approve of an unverified card");
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(
        body.pointer("/error/code").unwrap(),
        "invalid_request",
        "{body}"
    );
    handle.abort();
}

async fn drive_named_map_errors() {
    linked_export_axis();
    let big_settings = {
        let mut m = serde_json::Map::new();
        m.insert("blob".into(), serde_json::json!("x".repeat(70_000)));
        serde_json::json!({ "settings": m }).to_string()
    };
    let ok_def = |section: &str| match section {
        "identity-providers" => r#"{"module":"keys"}"#.to_string(),

        "tools" => r#"{"url":"https://x/","pin":{"mechanism":"unpinned"}}"#.to_string(),

        "agents" => {
            r#"{"url":"https://agent.example/x","pin":{"mechanism":"unpinned"}}"#.to_string()
        }
        _ => r#"{"module":"prometheus","settings":{"buffer_seconds":30}}"#.to_string(),
    };

    type Case = (
        String,
        &'static str,
        String,
        Option<&'static str>,
        Option<String>,
        u16,
        &'static str,
    );
    let mut cases: Vec<Case> = Vec::new();
    for (section, base) in [
        ("identity-providers", "base-idp"),
        ("export", "base-metrics"),
        ("tools", "base-tools"),
        ("agents", "base-agent"),
    ] {
        let c = |label: &str,
                 method: &'static str,
                 rel: String,
                 im: Option<&'static str>,
                 body: Option<String>,
                 status: u16,
                 code: &'static str|
         -> Case {
            (
                format!("{section}_{label}"),
                method,
                rel,
                im,
                body,
                status,
                code,
            )
        };
        cases.extend([
            c(
                "put_malformed_body",
                "PUT",
                format!("/{section}/x"),
                None,
                Some("{".into()),
                400,
                "invalid_request",
            ),
            c(
                "put_bad_ifmatch",
                "PUT",
                format!("/{section}/x"),
                Some("not-a-version"),
                Some(ok_def(section)),
                400,
                "invalid_request",
            ),
            c(
                "put_bad_definition",
                "PUT",
                format!("/{section}/x"),
                None,
                Some(if section == "agents" {
                    r#"{"url":"https://agent.example/x","pin":{"mechanism":"jws_issuer_key"}}"#
                        .to_string()
                } else {
                    r#"{"module":""}"#.to_string()
                }),
                400,
                "invalid_request",
            ),
            c(
                "put_base_defined",
                "PUT",
                format!("/{section}/{base}"),
                None,
                Some(ok_def(section)),
                409,
                "conflict",
            ),
            c(
                "put_stale_ifmatch",
                "PUT",
                format!("/{section}/x"),
                Some("\"9999\""),
                Some(ok_def(section)),
                409,
                "version_conflict",
            ),
            c(
                "patch_malformed_body",
                "PATCH",
                format!("/{section}/{base}/settings"),
                None,
                Some("{".into()),
                400,
                "invalid_request",
            ),
            c(
                "patch_bad_ifmatch",
                "PATCH",
                format!("/{section}/{base}/settings"),
                Some("not-a-version"),
                Some(r#"{"settings":{}}"#.into()),
                400,
                "invalid_request",
            ),
            c(
                "patch_oversized_settings",
                "PATCH",
                format!("/{section}/{base}/settings"),
                None,
                Some(big_settings.clone()),
                400,
                "invalid_request",
            ),
            c(
                "patch_unknown",
                "PATCH",
                format!("/{section}/ghost/settings"),
                None,
                Some(r#"{"settings":{}}"#.into()),
                404,
                "not_found",
            ),
            c(
                "patch_base_defined",
                "PATCH",
                format!("/{section}/{base}/settings"),
                None,
                Some(r#"{"settings":{}}"#.into()),
                409,
                "conflict",
            ),
            c(
                "patch_stale_ifmatch",
                "PATCH",
                format!("/{section}/{base}/settings"),
                Some("\"9999\""),
                Some(r#"{"settings":{}}"#.into()),
                409,
                "version_conflict",
            ),
            c(
                "delete_bad_ifmatch",
                "DELETE",
                format!("/{section}/{base}"),
                Some("not-a-version"),
                None,
                400,
                "invalid_request",
            ),
            c(
                "delete_unknown",
                "DELETE",
                format!("/{section}/ghost"),
                None,
                None,
                404,
                "not_found",
            ),
            c(
                "delete_base_defined",
                "DELETE",
                format!("/{section}/{base}"),
                None,
                None,
                409,
                "conflict",
            ),
            c(
                "delete_stale_ifmatch",
                "DELETE",
                format!("/{section}/{base}"),
                Some("\"9999\""),
                None,
                409,
                "version_conflict",
            ),
            c(
                "get_unknown",
                "GET",
                format!("/{section}/ghost"),
                None,
                None,
                404,
                "not_found",
            ),
        ]);
        if section == "identity-providers" {
            cases.push(c(
                "put_raises_trust_ceiling",
                "PUT",
                format!("/{section}/ceil"),
                None,
                Some(r#"{"module":"keys","max_admin_scope":"full"}"#.into()),
                409,
                "conflict",
            ));
        }
    }

    let client = reqwest::Client::new();
    for (batch_i, batch) in cases.chunks(8).enumerate() {
        let (dir, _overlay, addr, handle) =
            named_map_app(&format!("witness-{batch_i}"), false).await;
        for (label, method, rel, if_match, body, want_status, want_code) in batch {
            let mut req = client
                .request(
                    reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                    format!("http://{addr}/api/v1/admin{rel}"),
                )
                .header("x-admin-token", "admintok");
            if let Some(tag) = if_match {
                req = req.header("if-match", *tag);
            }
            if let Some(b) = body {
                req = req
                    .header("content-type", "application/json")
                    .body(b.clone());
            }
            let resp = req.send().await.unwrap();
            let status = resp.status().as_u16();
            let parsed: serde_json::Value = resp.json().await.unwrap();
            assert_eq!(
                status, *want_status,
                "{label}: expected {want_status}, got {status} ({parsed})"
            );
            assert_eq!(parsed["error"]["code"], *want_code, "{label}: {parsed}");
        }
        handle.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    for section in ["identity-providers", "export", "tools", "agents"] {
        crate::distribution::admin_cross_plane::ensure_seam();
        let store = crate::root::real_store::store();
        let gov = gov_with_signer(store, Some("admintok".to_string()));
        let app = {
            crate::distribution::admin_cross_plane::ensure_seam();
            let directory = super::plugins::scratch(&format!(
                "admin-root-{}",
                busbar_kernel::door::op_id().counter()
            ));
            let library_path = crate::root::test_plugins::application_store_library();
            let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
                .expect("the actual Store statement reads")
                .expect("the actual Store states itself");
            let facts = busbar_contract::abi::mechanism::rendering::read(&statement)
                .expect("the actual Store statement parses");
            let mut manifest =
                super::plugins::manifest("store", &facts.name, super::plugins::FIXTURE_PUBLISHER);
            manifest.version = facts.version;
            manifest.statement = Some(hex::encode(statement));
            let archive = super::plugins::signed(
                &crate::dist_root_install::release_key(),
                manifest,
                &std::fs::read(library_path).expect("the actual Store artifact reads"),
            );
            std::fs::write(directory.join("store.tar.gz"), archive)
                .expect("stage the actual Store product");
            std::fs::write(directory.join("admin.token"), "admintok")
                .expect("write the operator credential");
            let settings = crate::root::test_plugins::application_store_settings(&directory);
            let mut document = serde_json::json!({});
            document["providers"] = serde_json::json!({});
            document["models"] = serde_json::json!({});
            // These positive named-map surfaces are served only for configured planes.
            // Use the same actual plane definitions as the file-backed fixture below.
            document["tools"] = serde_json::json!({"base-tools": {
                "url": "https://tools.internal/fs",
                "pin": {"mechanism": "cert_spki", "key": "sha256/BASE="}
            }});
            document["agents"] = serde_json::json!({"base-agent": {
                "url": "https://agents.example/planner",
                "pin": {"mechanism": "unpinned"}
            }});
            document["store"] = serde_json::json!({"module": facts.name, "settings": settings});
            document["plugins"] =
                super::plugins::config_document(&super::plugins::trusted_config(&directory));
            document["auth"] = serde_json::json!({"chain": [], "admin_auth": ["admin-tokens"]});
            document["identity-providers"] = serde_json::json!({"admin-tokens": {
                "module": "admin-tokens", "token": {"file": directory.join("admin.token")}
            }});
            document["advanced"] = serde_json::json!({"allow_destinations": ["127.0.0.1"]});
            let deploy = busbar_kernel::config::deploy_from_deserializer(document)
                .expect("the actual admin deployment parses");
            let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
                .expect("the actual admin deployment resolves");
            assert!(
                cfg.plane_sections.contains("tools") && cfg.plane_sections.contains("agents"),
                "the actual parser configures both positive named-map planes"
            );
            let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
                as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
            let (mut app, rotate, limits) = busbar_kernel::build_app_from_config(
                cfg,
                super::plugins::trusted_config(&directory),
                None,
                Default::default(),
                Default::default(),
                (None, None),
                None,
                &rules,
            )
            .expect("the product root builds the actual admin application");
            limits.stage_boot();
            let _book = crate::root::boot::book(&app, "configured-store")
                .expect("the actual configured Store binds boot rate history before activation");
            limits.keep().expect("the product limits commit");
            if let Some(rotate) = rotate {
                rotate();
            }
            app.overlay_path = Some(
                busbar_kernel::config::overlay::OverlayStore::new(
                    app.governance
                        .as_ref()
                        .expect("the actual root opened governance")
                        .store_calls()
                        .expect("the actual Store exposes its calls"),
                )
                .expect("the actual Store opens its overlay"),
            );
            app.governance = Some(gov);

            std::sync::Arc::new(app)
        };
        let router = crate::distribution::admin_cross_plane::build_router(app);
        let (addr, handle, _) = spin_up(router).await;
        {
            for (label, method, rel, body) in [
                (
                    "put",
                    "PUT",
                    format!("/{section}/x"),
                    Some(r#"{"module":"keys"}"#),
                ),
                (
                    "patch",
                    "PATCH",
                    format!("/{section}/x/settings"),
                    Some(r#"{"settings":{}}"#),
                ),
                ("delete", "DELETE", format!("/{section}/x"), None),
            ] {
                let mut req = client
                    .request(
                        reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                        format!("http://{addr}/api/v1/admin{rel}"),
                    )
                    .header("x-admin-token", "admintok");
                if let Some(b) = body {
                    req = req.header("content-type", "application/json").body(b);
                }
                let resp = req.send().await.unwrap();
                let status = resp.status().as_u16();
                let parsed: serde_json::Value = resp.json().await.unwrap();
                assert_eq!(status, 400, "{section} {label} (ephemeral): {parsed}");
                assert_eq!(parsed["error"]["code"], "invalid_request");
            }
        }
        handle.abort();
    }

    {
        let (dir, _overlay, addr, handle) = named_map_app("witness-dangling", true).await;
        let admin = |r: reqwest::RequestBuilder| {
            r.header("x-admin-token", "admintok")
                .header("content-type", "application/json")
        };
        let r = admin(client.put(format!(
            "http://{addr}/api/v1/admin/identity-providers/corp-ad"
        )))
        .body(
            serde_json::json!({
                "module": "admin-tokens",
                "token": {"file": dir.join("corp.token").to_string_lossy()}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
        assert_eq!(r.status().as_u16(), 200, "{:?}", r.text().await);
        let r = admin(client.delete(format!(
            "http://{addr}/api/v1/admin/identity-providers/corp-ad"
        )))
        .send()
        .await
        .unwrap();
        let status = r.status().as_u16();
        let parsed: serde_json::Value = r.json().await.unwrap();
        assert_eq!(
            status, 409,
            "a dangling delete is a terminal conflict: {parsed}"
        );
        assert_eq!(parsed["error"]["code"], "conflict");

        let r = admin(client.delete(format!(
            "http://{addr}/api/v1/admin/overlay/identity-providers"
        )))
        .send()
        .await
        .unwrap();
        let status = r.status().as_u16();
        let parsed: serde_json::Value = r.json().await.unwrap();
        assert_eq!(
            status, 409,
            "a bulk reset that would dangle a reference is a terminal conflict: {parsed}"
        );
        assert_eq!(parsed["error"]["code"], "conflict");
        handle.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[tokio::test]
async fn named_map_error_surface_answers_its_declared_taxonomy() {
    drive_named_map_errors().await;
}

#[tokio::test]
async fn test_admin_v1_named_map_put_rejects_what_the_file_parser_rejects() {
    linked_export_axis();
    let (dir, overlay, addr, handle) = named_map_app("typedparse", false).await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| {
        r.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };

    let r = admin(client.put(format!("http://{addr}/api/v1/admin/export/spare")))
        .body(r#"{"module":"prometheus","buffer":30}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        400,
        "an unknown field is the same loud reject config.yaml gives"
    );
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["error"]["code"], "invalid_request");
    let msg = body["error"]["message"].as_str().unwrap();
    assert!(
        msg.contains("buffer"),
        "the refusal carries serde's own message naming the offending field: {body}"
    );

    let after = admin(client.get(format!("http://{addr}/api/v1/admin/export/spare")))
        .send()
        .await
        .unwrap();
    assert_eq!(
        after.status().as_u16(),
        404,
        "the rejected definition was never stored"
    );
    if let Some(bytes) = overlay
        .read_bytes()
        .expect("the actual Store overlay reads")
    {
        let doc: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(
            doc["named_maps"]["export"]["spare"].is_null(),
            "the rejected definition is absent from the overlay: {doc}"
        );
    }

    let good = serde_json::json!({
        "module": "request-log-file",
        "settings": {"path": dir.join("spare.jsonl").to_string_lossy()}
    });
    let r = admin(client.put(format!("http://{addr}/api/v1/admin/export/spare")))
        .body(good.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200, "{:?}", r.text().await);

    let r = admin(client.put(format!(
        "http://{addr}/api/v1/admin/identity-providers/typo-idp"
    )))
    .body(r#"{"module":"keys","max_admin_scopes":"none"}"#)
    .send()
    .await
    .unwrap();
    assert_eq!(
        r.status().as_u16(),
        400,
        "the typed parse is per-section and driven by the section's own struct: {:?}",
        r.text().await
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_admin_v1_named_map_read_flags_an_unparseable_overlay_entry() {
    linked_export_axis();
    let (dir, overlay, addr, handle) = named_map_app("unparseable", false).await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| r.header("x-admin-token", "admintok");

    busbar_kernel::config::overlay::write(
        &overlay,
        &serde_json::from_value(serde_json::json!({
            "version": 1,
            "named_maps": {
                "export": {
                    "ghost": {"module": "prometheus", "from_the_future": true,
                              "settings": {"buffer_seconds": 60}}
                }
            }
        }))
        .expect("the raw overlay document parses"),
    )
    .expect("the actual Store commits the overlay");

    let body: serde_json::Value = admin(client.get(format!("http://{addr}/api/v1/admin/export")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ghost = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["name"] == "ghost")
        .unwrap_or_else(|| {
            panic!("the stored-but-inert entry is discoverable in the list: {body}")
        });
    assert!(
        ghost["unparseable"]
            .as_str()
            .is_some_and(|e| e.contains("from_the_future")),
        "and is EXPLICITLY flagged with the parse error rather than looking live: {ghost}"
    );
    assert_eq!(
        ghost["module"], "prometheus",
        "the operator's own raw document is projected back so they can see what they wrote"
    );

    let one = admin(client.get(format!("http://{addr}/api/v1/admin/export/ghost")))
        .send()
        .await
        .unwrap();
    assert_eq!(one.status().as_u16(), 200);
    let one: serde_json::Value = one.json().await.unwrap();
    assert!(one["unparseable"].is_string(), "{one}");

    let base: serde_json::Value =
        admin(client.get(format!("http://{addr}/api/v1/admin/export/base-metrics")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    assert!(
        base["unparseable"].is_null(),
        "a parseable, live definition carries no flag: {base}"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn key_usage_over_an_unpriced_class_answers_named_409() {
    assert_unpriced_usage_read_is_named("/api/v1/admin/keys/").await;
}

#[tokio::test]
async fn group_usage_over_an_unpriced_class_answers_named_409() {
    assert_unpriced_usage_read_is_named("/api/v1/admin/groups/").await;
}

#[tokio::test]
async fn admin_usage_over_an_unpriced_class_answers_named_409() {
    assert_unpriced_usage_read_is_named("/api/v1/admin/usage").await;
}
