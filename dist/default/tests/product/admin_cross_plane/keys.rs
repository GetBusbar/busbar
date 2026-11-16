// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::json::{self, JsonValueTrait};
use busbar_kernel::governance::{GovState, NewKeySpec};
use busbar_kernel::plane_driver::serve::ServeTables;

const PROTO_ANTHROPIC: &str = "anthropic";

use std::sync::Arc;

// Each independent deployment gets a real process-owned price Store. Subcases
// execute the same existing test by exact name and emit an execution witness.
fn run_fixture_process(key: &str, value: &str, extra: &[(&str, &str)]) {
    let current = std::thread::current();
    let mut command = std::process::Command::new(std::env::current_exe().expect("test executable"));
    command
        .args(["--exact", current.name().expect("test name"), "--nocapture"])
        .env(key, value);
    for (name, value) in extra {
        command.env(name, value);
    }
    let output = command.output().expect("execute isolated native fixture");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let witness = format!("BUSBAR_FIXTURE_SELECTED:{key}={value}");
    assert!(
        output.status.success()
            && stdout.contains("test result: ok. 1 passed; 0 failed; 0 ignored;")
            && (stdout.contains(&witness) || stderr.contains(&witness)),
        "isolated fixture {key}={value} failed: {}\n{stdout}\n{stderr}",
        output.status
    );
}

fn isolated_fixture(key: &str, value: &str) -> bool {
    match std::env::var(key) {
        Ok(selected) if selected == value => {
            eprintln!("BUSBAR_FIXTURE_SELECTED:{key}={value}");
            false
        }
        Ok(_) => true,
        Err(_) => {
            run_fixture_process(key, value, &[]);
            true
        }
    }
}

async fn attach_fixture_prices(app: &busbar_kernel::state::App) {
    let store = app
        .governance
        .as_ref()
        .expect("fixture governance")
        .core_store_handle()
        .expect("fixture native Store");
    if let Some(previous) = crate::root::kernel::ROOT_CARD.card_store() {
        assert!(
            previous.is_bound_to(&store),
            "independent deployments must use isolated fixture processes"
        );
    } else {
        crate::root::kernel::ROOT_CARD
            .keep_in_store(store, busbar_kernel::door::op_id().counter())
            .expect("the fixture binds its actual native price Store");
        crate::root::kernel::ROOT_CARD
            .boot_in_store(None)
            .await
            .expect("the fixture boots its actual native price history");
    }
}

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

async fn gov_with_signer(
    store: Arc<busbar_kernel::persistence::facade::CoreStore>,
    admin_token: Option<String>,
) -> Arc<GovState> {
    Arc::new(
        GovState::new_with_core(
            store,
            admin_token,
            Some(
                busbar_kernel::governance::signing::TokenSigner::from_secret_bytes(
                    &[9u8; 32],
                    busbar_kernel::governance::signing::DEFAULT_KID,
                ),
            ),
        )
        .await
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

async fn drive_unpriced_usage_reads() -> Vec<(String, u16, json::Value)> {
    if isolated_fixture("BUSBAR_ADMIN_FIXTURE_DRIVER", "unpriced_usage_reads") {
        return Vec::new();
    }
    crate::distribution::admin_cross_plane::ensure_seam();
    let store = crate::root::real_store::core().await;
    let gov = gov_with_signer(store, Some("admintok".to_string())).await;
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
            }],
            ..Default::default()
        },
    )]);
    let cost = busbar_kernel::cost::CostModel::resolve_parts(Some(&card), 0, &groups);
    let now = busbar_kernel::store::now();
    let (minted, _secret) = gov
        .mint_signed_async(
            NewKeySpec {
                name: "k".to_string(),
                ..Default::default()
            },
            now + 3600,
            now,
        )
        .await
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
        let deploy = busbar_kernel::config::deploy_from_deserializer(
            document,
            &crate::root::boot::axis_test_grammar(),
        )
        .expect("the actual admin deployment parses");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the actual admin deployment resolves");
        let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
            as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
        let (mut app, rotate, limits) = crate::root::real_store::build_app(
            cfg,
            super::plugins::trusted_config(&directory),
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
        )
        .await
        .expect("the product root builds the actual admin application");
        limits.stage_boot();
        attach_fixture_prices(&app).await;
        limits.keep().await.expect("the product limits commit");
        if let Some(rotate) = rotate {
            rotate.await;
        }
        app.overlay_path = Some(
            busbar_kernel::config::overlay::OverlayStore::from_core(
                app.governance
                    .as_ref()
                    .expect("the actual root opened governance")
                    .core_store_handle()
                    .expect("the actual Store exposes its calls"),
            )
            .expect("the actual Store opens its overlay"),
        );

        let historical = busbar_kernel::config::card::CardFields {
            rate_card: Some(card.clone()),
            ..Default::default()
        };
        let rates = historical.rates();
        busbar_kernel::rate_apply::prepare_with_origin(
            &historical,
            &rates.raw(),
            "historical unpriced usage fixture",
        )
        .await
        .expect("the actual Store prepares the historical unpriced card")
        .confirm_activation()
        .await
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
        gov.flush_metering().await;
        app.governance = Some(gov);
        app.cost = std::sync::Arc::new(cost);

        std::sync::Arc::new(app)
    };
    let router = crate::distribution::admin_cross_plane::build_router(
        crate::root::real_store::hydrated(app).await,
    );
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
        let body = resp
            .bytes()
            .await
            .ok()
            .and_then(|b| json::parse_value(&b).ok())
            .unwrap_or_default();
        out.push((path, status, body));
    }
    handle.abort();
    out
}

async fn assert_unpriced_usage_read_is_named(prefix: &str) {
    if isolated_fixture("BUSBAR_ADMIN_FIXTURE_DRIVER", "unpriced_usage_reads") {
        return;
    }
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
    let store = crate::root::real_store::core().await;
    let gov = gov_with_signer(store, Some("admintok".to_string())).await;
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(
        crate::root::real_store::core().await,
    )
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
        let deploy = busbar_kernel::config::deploy_from_deserializer(
            document,
            &crate::root::boot::axis_test_grammar(),
        )
        .expect("the actual admin deployment parses");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the actual admin deployment resolves");
        let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
            as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
        let (mut app, rotate, limits) = crate::root::real_store::build_app(
            cfg,
            super::plugins::trusted_config(&directory),
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
        )
        .await
        .expect("the product root builds the actual admin application");
        limits.stage_boot();
        attach_fixture_prices(&app).await;
        limits.keep().await.expect("the product limits commit");
        if let Some(rotate) = rotate {
            rotate.await;
        }
        app.overlay_path = Some(
            busbar_kernel::config::overlay::OverlayStore::from_core(
                app.governance
                    .as_ref()
                    .expect("the actual root opened governance")
                    .core_store_handle()
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

    let apply = |config: json::Value| {
        let handle = handle.clone();
        async move {
            let body = axum::body::Bytes::from(
                json::json!({ "config": config, "providers": {} }).to_string(),
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
        json::json!({
            "providers": {},
            "models": {},
            "store": {"module": "memory"}
        })
    };

    let mut with_plane = base();
    with_plane[section] = json::json!({ "fees": { "per_request": 7 } });
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
    unknown["no_plane_declares_this"] = json::json!({});
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
    let store = crate::root::real_store::core().await;
    let gov = gov_with_signer(store, Some("admintok".to_string())).await;
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
        let deploy = busbar_kernel::config::deploy_from_deserializer(
            document,
            &crate::root::boot::axis_test_grammar(),
        )
        .expect("the actual admin deployment parses");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the actual admin deployment resolves");
        let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
            as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
        let (mut app, rotate, limits) = crate::root::real_store::build_app(
            cfg,
            super::plugins::trusted_config(&directory),
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
        )
        .await
        .expect("the product root builds the actual admin application");
        limits.stage_boot();
        attach_fixture_prices(&app).await;
        limits.keep().await.expect("the product limits commit");
        if let Some(rotate) = rotate {
            rotate.await;
        }
        app.overlay_path = Some(
            busbar_kernel::config::overlay::OverlayStore::from_core(
                app.governance
                    .as_ref()
                    .expect("the actual root opened governance")
                    .core_store_handle()
                    .expect("the actual Store exposes its calls"),
            )
            .expect("the actual Store opens its overlay"),
        );
        app.governance = Some(gov);

        std::sync::Arc::new(app)
    };
    let router = crate::distribution::admin_cross_plane::build_router(
        crate::root::real_store::hydrated(app).await,
    );
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
        abi_version: busbar_plugin_loader::supported_abi("store").expect("store abi"),
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
    if isolated_fixture(
        "BUSBAR_ADMIN_FIXTURE_DRIVER",
        "key_cap_and_delegation_errors",
    ) {
        return;
    }
    crate::distribution::admin_cross_plane::ensure_seam();
    let store = crate::root::real_store::core().await;
    let gov = gov_with_signer(store, Some("admintok".to_string())).await;
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
        let deploy = busbar_kernel::config::deploy_from_deserializer(
            document,
            &crate::root::boot::axis_test_grammar(),
        )
        .expect("the actual admin deployment parses");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the actual admin deployment resolves");
        let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
            as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
        let (mut app, rotate, limits) = crate::root::real_store::build_app(
            cfg,
            super::plugins::trusted_config(&directory),
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
        )
        .await
        .expect("the product root builds the actual admin application");
        limits.stage_boot();
        attach_fixture_prices(&app).await;
        limits.keep().await.expect("the product limits commit");
        if let Some(rotate) = rotate {
            rotate.await;
        }
        app.overlay_path = Some(
            busbar_kernel::config::overlay::OverlayStore::from_core(
                app.governance
                    .as_ref()
                    .expect("the actual root opened governance")
                    .core_store_handle()
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
    busbar_kernel::audit::auditlog::register_test_audit_stream(&app).await;
    let router = crate::distribution::admin_cross_plane::build_router(
        crate::root::real_store::hydrated(app).await,
    );
    let (addr, server, client) = spin_up(router).await;
    let keys_url = format!("http://{addr}/api/v1/admin/keys");

    let mint = |name: &'static str, group: &'static str| {
        let (c, u) = (client.clone(), keys_url.clone());
        async move {
            let r = c
                .post(&u)
                .header("x-admin-token", "admintok")
                .json(&json::json!({"name": name, "group": group}))
                .send()
                .await
                .unwrap();
            assert_eq!(r.status().as_u16(), 201, "mint {name}/{group}");
            let b = json::parse_value(&r.bytes().await.unwrap()).unwrap();
            b["id"].as_str().unwrap().to_string()
        }
    };
    let patch = |id: String, body: json::Value| {
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

    let r = patch(roamer.clone(), json::json!({"group": "capped"})).await;
    assert_eq!(r.status().as_u16(), 409, "rebind into an at-cap group");
    let body = json::parse_value(&r.bytes().await.unwrap()).unwrap();
    assert_eq!(body["error"]["code"], "conflict");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("max_keys_per_principal"),
        "the rebind 409 names the cap: {body}"
    );

    assert_eq!(
        patch(cap_a.clone(), json::json!({"enabled": false}))
            .await
            .status()
            .as_u16(),
        200,
        "disabling is always allowed — it can only free a slot"
    );
    let _cap_c = mint("c", "capped").await;

    let r = patch(cap_a.clone(), json::json!({"enabled": true})).await;
    assert_eq!(
        r.status().as_u16(),
        409,
        "re-enabling past the cap is the same admission as a rebind past the cap"
    );
    let body = json::parse_value(&r.bytes().await.unwrap()).unwrap();
    assert_eq!(body["error"]["code"], "conflict");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("max_keys_per_principal"),
        "the re-enable 409 names the cap: {body}"
    );

    assert_eq!(
        patch(cap_a.clone(), json::json!({"enabled": false}))
            .await
            .status()
            .as_u16(),
        200,
        "a no-op disable of a key in an at-cap bucket is not an admission"
    );

    let r = client
        .post(&keys_url)
        .header("x-admin-token", "admintok")
        .json(&json::json!({"name": "unbound-by-operator"}))
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
            let b = json::parse_value(&r.bytes().await.unwrap()).unwrap();
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
    let store = crate::root::real_store::core().await;
    let gov = gov_with_signer(store, Some("admintok".to_string())).await;
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
        let deploy = busbar_kernel::config::deploy_from_deserializer(
            document,
            &crate::root::boot::axis_test_grammar(),
        )
        .expect("the actual admin deployment parses");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the actual admin deployment resolves");
        assert!(
            cfg.plane_sections.contains("tools") && cfg.plane_sections.contains("agents"),
            "the actual parser configures both positive named-map planes"
        );
        let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
            as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
        let (mut app, rotate, limits) = crate::root::real_store::build_app(
            cfg,
            super::plugins::trusted_config(&directory),
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
        )
        .await
        .expect("the product root builds the actual admin application");
        limits.stage_boot();
        attach_fixture_prices(&app).await;
        limits.keep().await.expect("the product limits commit");
        if let Some(rotate) = rotate {
            rotate.await;
        }
        app.overlay_path = Some(
            busbar_kernel::config::overlay::OverlayStore::from_core(
                app.governance
                    .as_ref()
                    .expect("the actual root opened governance")
                    .core_store_handle()
                    .expect("the actual Store exposes its calls"),
            )
            .expect("the actual Store opens its overlay"),
        );
        app.governance = Some(gov);

        std::sync::Arc::new(app)
    };
    let router = crate::distribution::admin_cross_plane::build_router(
        crate::root::real_store::hydrated(app).await,
    );
    let (addr, handle, _) = spin_up(router).await;

    let r = reqwest::Client::new()
        .delete(format!("http://{addr}/api/v1/admin/overlay/limits"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 400);
    let body = json::parse_value(&r.bytes().await.unwrap()).unwrap();
    assert_eq!(body["error"]["code"], "invalid_request");

    assert_eq!(
        body["error"]["message"],
        "unknown overlay section `limits`: expected `groups`, `hooks`, `root`, \
         `plugin_versions`, `identity-providers`, `export`, `tools`, or `agents`",
        "1.5.5's sentence shape (serial comma, `or` before the last name) with the longer list"
    );

    handle.abort();
}

async fn serve_keys_fixture(
    fixture: KeysFixture,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>, String) {
    let store: Arc<busbar_kernel::persistence::facade::CoreStore> =
        crate::root::real_store::core().await;
    let app = match fixture {
        KeysFixture::Signing => {
            let gov = gov_with_signer(store, Some("admintok".to_string())).await;
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
                let deploy = busbar_kernel::config::deploy_from_deserializer(
                    document,
                    &crate::root::boot::axis_test_grammar(),
                )
                .expect("the actual admin deployment parses");
                let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
                    .expect("the actual admin deployment resolves");
                let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
                    as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
                let (mut app, rotate, limits) = crate::root::real_store::build_app(
                    cfg,
                    super::plugins::trusted_config(&directory),
                    None,
                    Default::default(),
                    Default::default(),
                    (None, None),
                    None,
                    &rules,
                )
                .await
                .expect("the product root builds the actual admin application");
                limits.stage_boot();
                attach_fixture_prices(&app).await;
                limits.keep().await.expect("the product limits commit");
                if let Some(rotate) = rotate {
                    rotate.await;
                }
                app.overlay_path = Some(
                    busbar_kernel::config::overlay::OverlayStore::from_core(
                        app.governance
                            .as_ref()
                            .expect("the actual root opened governance")
                            .core_store_handle()
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
                GovState::new_with_core(store, Some("admintok".to_string()), None)
                    .await
                    .unwrap(),
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
                let deploy = busbar_kernel::config::deploy_from_deserializer(
                    document,
                    &crate::root::boot::axis_test_grammar(),
                )
                .expect("the actual admin deployment parses");
                let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
                    .expect("the actual admin deployment resolves");
                let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
                    as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
                let (mut app, rotate, limits) = crate::root::real_store::build_app(
                    cfg,
                    super::plugins::trusted_config(&directory),
                    None,
                    Default::default(),
                    Default::default(),
                    (None, None),
                    None,
                    &rules,
                )
                .await
                .expect("the product root builds the actual admin application");
                limits.stage_boot();
                attach_fixture_prices(&app).await;
                limits.keep().await.expect("the product limits commit");
                if let Some(rotate) = rotate {
                    rotate.await;
                }
                app.overlay_path = Some(
                    busbar_kernel::config::overlay::OverlayStore::from_core(
                        app.governance
                            .as_ref()
                            .expect("the actual root opened governance")
                            .core_store_handle()
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
            let deploy = busbar_kernel::config::deploy_from_deserializer(
                document,
                &crate::root::boot::axis_test_grammar(),
            )
            .expect("the actual admin deployment parses");
            let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
                .expect("the actual admin deployment resolves");
            let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
                as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
            let (mut app, rotate, limits) = crate::root::real_store::build_app(
                cfg,
                super::plugins::trusted_config(&directory),
                None,
                Default::default(),
                Default::default(),
                (None, None),
                None,
                &rules,
            )
            .await
            .expect("the product root builds the actual admin application");
            limits.stage_boot();
            attach_fixture_prices(&app).await;
            limits.keep().await.expect("the product limits commit");
            if let Some(rotate) = rotate {
                rotate.await;
            }
            app.overlay_path = Some(
                busbar_kernel::config::overlay::OverlayStore::from_core(
                    app.governance
                        .as_ref()
                        .expect("the actual root opened governance")
                        .core_store_handle()
                        .expect("the actual Store exposes its calls"),
                )
                .expect("the actual Store opens its overlay"),
            );
            // Finish real native startup before disabling this resource in the
            // synthetic posture. Rejected mutations still publish their audit
            // record through this deployment's original configured Store.
            let mut app = crate::root::real_store::hydrated(Arc::new(app)).await;
            Arc::get_mut(&mut app)
                .expect("fixture hydration leaves this unserved App uniquely owned")
                .governance = None;
            app
        }
    };
    let serving = if fixture == KeysFixture::Off {
        app.clone()
    } else {
        crate::root::real_store::hydrated(app.clone()).await
    };
    let router = crate::distribution::admin_cross_plane::build_router(serving);
    let (addr, handle, _) = spin_up(router).await;

    let live = if fixture == KeysFixture::Signing {
        let (key, _) = app
            .governance
            .as_ref()
            .unwrap()
            .mint_signed_async(
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
            .await
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
    if isolated_fixture("BUSBAR_ADMIN_FIXTURE_DRIVER", "keys_error_surface") {
        return;
    }
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
    let mut observed = json::Map::new();
    if let Ok(selected) = std::env::var("BUSBAR_KEYS_FIXTURE_CASE") {
        eprintln!("BUSBAR_FIXTURE_SELECTED:BUSBAR_KEYS_FIXTURE_CASE={selected}");
        for fixture in [
            KeysFixture::Signing,
            KeysFixture::NoSigner,
            KeysFixture::Off,
        ]
        .into_iter()
        .enumerate()
        .filter_map(|(index, fixture)| (selected == index.to_string()).then_some(fixture))
        {
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
                    case.name,
                    json::json!({"status": status, "content_type": content_type, "body": body}),
                );
            }
            server.abort();
        }

        let output = std::env::var("BUSBAR_KEYS_FIXTURE_OUTPUT").expect("child result path");
        assert!(
            !observed.is_empty(),
            "selected governance fixture executed its cases"
        );
        std::fs::write(output, json::to_vec(&observed).unwrap()).unwrap();
        return;
    }
    let outputs = super::plugins::scratch("isolated-key-wire");
    for index in 0..3 {
        let path = outputs.join(format!("{index}.json"));
        let path_text = path.to_str().unwrap();
        run_fixture_process(
            "BUSBAR_KEYS_FIXTURE_CASE",
            &index.to_string(),
            &[("BUSBAR_KEYS_FIXTURE_OUTPUT", path_text)],
        );
        let mut part: json::Map = json::parse(&std::fs::read(path).unwrap()).unwrap();
        observed.append(&mut part);
    }
    std::fs::remove_dir_all(outputs).unwrap();

    let fresh = format!(
        "{}\n",
        json::to_string_pretty(&observed).expect("serialize keys error wire")
    );
    if std::env::var("UPDATE_KEYS_ERROR_GOLDEN").is_ok_and(|v| v == "1") {
        std::fs::write(KEYS_ERROR_GOLDEN, &fresh)
            .unwrap_or_else(|e| panic!("write {KEYS_ERROR_GOLDEN}: {e}"));
        return;
    }
    let committed = std::fs::read_to_string(KEYS_ERROR_GOLDEN)
        .unwrap_or_else(|e| panic!("read {KEYS_ERROR_GOLDEN}: {e}"));
    // The outer object is fixture bookkeeping, not HTTP bytes. Keep each response
    // body as an exact string while ignoring only that wrapper's member order.
    let committed =
        json::parse_value(committed.as_bytes()).expect("parse committed wire fixture wrapper");
    let fresh = json::parse_value(fresh.as_bytes()).expect("parse observed wire fixture wrapper");
    assert_eq!(
        committed, fresh,
        "the keys error WIRE changed — status/content-type/body bytes on a FROZEN surface. If this \
         is deliberate, regenerate with `UPDATE_KEYS_ERROR_GOLDEN=1`."
    );
    let mut changed_body = fresh.clone();
    let body = fresh["list_bad_cursor"]["body"].as_str().unwrap();
    let changed = format!("{body} ");
    assert_eq!(
        json::parse_value(body.as_bytes()).unwrap(),
        json::parse_value(changed.as_bytes()).unwrap(),
        "the negative control changes bytes without changing JSON meaning"
    );
    changed_body["list_bad_cursor"]["body"] = json::Value::from(changed.as_str());
    assert_ne!(
        committed, changed_body,
        "fixture comparison must detect even one extra byte in an HTTP body"
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
    let store = crate::root::real_store::core().await;
    let gov = gov_with_signer(store, Some("admintok".to_string())).await;
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
        let deploy = busbar_kernel::config::deploy_from_deserializer(
            document,
            &crate::root::boot::axis_test_grammar(),
        )
        .expect("the actual admin deployment parses");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the actual admin deployment resolves");
        let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
            as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
        let plugin_config = super::plugins::trusted_config(&directory);
        let anchor = crate::root::test_plugins::bootstrap_fresh_application_store(
            &cfg,
            &plugin_config,
            &directory,
        )
        .await
        .expect("the new fixture Store initializes the admitted OIDC principal namespace");
        let (mut app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
            cfg,
            plugin_config,
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
            Some(anchor),
            true,
        )
        .await
        .expect("the product root builds the actual admin application");
        limits.stage_boot();
        attach_fixture_prices(&app).await;
        limits.keep().await.expect("the product limits commit");
        if let Some(rotate) = rotate {
            rotate.await;
        }
        app.overlay_path = Some(
            busbar_kernel::config::overlay::OverlayStore::from_core(
                app.governance
                    .as_ref()
                    .unwrap()
                    .core_store_handle()
                    .unwrap(),
            )
            .unwrap(),
        );
        app.governance = Some(gov);
        app.base_group_names.insert("team".into());
        app.base_hook_names.insert("basehook".into());
        std::sync::Arc::new(app)
    };
    let router = crate::distribution::admin_cross_plane::build_router(
        crate::root::real_store::hydrated(app).await,
    );
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
    if isolated_fixture("BUSBAR_ADMIN_FIXTURE_DRIVER", "admin_error_surface") {
        return;
    }
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
            "kinds_bad_category",
            "GET",
            "/kinds?category=maybe",
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
            "instance_unknown",
            "GET",
            "/kinds/core/instances/ghost",
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
            "plugin_schema_unknown_source",
            "GET",
            "/plugins/ghost/schema?source=unknown",
            None,
            None,
            400,
            "invalid_request",
        ),
        (
            "plugin_schema_guarded_missing",
            "GET",
            "/plugins/ghost.tar.gz/schema?source=installed_archive&expected_archive_sha256=0000000000000000000000000000000000000000000000000000000000000000",
            None,
            None,
            409,
            "conflict",
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
            "restart_malformed_if_match",
            "POST",
            "/restart",
            Some(BAD_ETAG),
            Some(r#"{"confirm":true}"#),
            400,
            "invalid_request",
        ),
        (
            "restart_stale_if_match",
            "POST",
            "/restart",
            Some(STALE),
            Some(r#"{"confirm":true}"#),
            409,
            "version_conflict",
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
    for (index, batch) in cases.chunks(6).enumerate() {
        if isolated_fixture("BUSBAR_ADMIN_ERROR_BATCH", &index.to_string()) {
            continue;
        }
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
            let parsed = json::parse_value(&resp.bytes().await.unwrap()).unwrap();
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
    if isolated_fixture("BUSBAR_ADMIN_FIXTURE_DRIVER", "plugin_reload_errors") {
        return;
    }
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
    let store = crate::root::real_store::core().await;
    let gov = gov_with_signer(store, Some("admintok".to_string())).await;
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
        let deploy = busbar_kernel::config::deploy_from_deserializer(
            document,
            &crate::root::boot::axis_test_grammar(),
        )
        .expect("the actual admin deployment parses");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the actual admin deployment resolves");
        let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
            as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
        let (mut app, rotate, limits) = crate::root::real_store::build_app(
            cfg,
            super::plugins::trusted_config(&directory),
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
        )
        .await
        .expect("the product root builds the actual admin application");
        limits.stage_boot();
        attach_fixture_prices(&app).await;
        limits.keep().await.expect("the product limits commit");
        if let Some(rotate) = rotate {
            rotate.await;
        }
        app.overlay_path = Some(
            busbar_kernel::config::overlay::OverlayStore::from_core(
                app.governance
                    .as_ref()
                    .expect("the actual root opened governance")
                    .core_store_handle()
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
    let router = crate::distribution::admin_cross_plane::build_router(
        crate::root::real_store::hydrated(app).await,
    );
    let (addr, server, client) = spin_up(router).await;

    let r = client
        .post(format!("http://{addr}/api/v1/admin/plugins/reload"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    let status = r.status().as_u16();
    let body = json::parse_value(&r.bytes().await.unwrap()).unwrap();
    assert_eq!(status, 400, "an unrebuildable disk config: {body}");
    assert_eq!(body["error"]["code"], "invalid_request");

    server.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

async fn drive_plugin_rollback_errors() {
    if isolated_fixture("BUSBAR_ADMIN_FIXTURE_DRIVER", "plugin_rollback_errors") {
        return;
    }
    crate::distribution::admin_cross_plane::ensure_seam();

    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "busbar-admin-rollback-witness-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(
        crate::root::real_store::core().await,
    )
    .expect("the actual Store opens the overlay");

    std::fs::write(dir.join("invalid-schema.tar.gz"), b"not an archive").unwrap();
    let tarball = admin_test_tarball("rollme", "rollme");
    let file = "rollme-1.0.0.tar.gz";
    std::fs::write(dir.join(file), &tarball).unwrap();
    let store = crate::root::real_store::core().await;
    let gov = gov_with_signer(store, Some("admintok".to_string())).await;
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
        let deploy = busbar_kernel::config::deploy_from_deserializer(
            document,
            &crate::root::boot::axis_test_grammar(),
        )
        .expect("the actual admin deployment parses");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the actual admin deployment resolves");
        let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
            as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
        let (mut app, rotate, limits) = crate::root::real_store::build_app(
            cfg,
            super::plugins::trusted_config(&directory),
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
        )
        .await
        .expect("the product root builds the actual admin application");
        limits.stage_boot();
        attach_fixture_prices(&app).await;
        limits.keep().await.expect("the product limits commit");
        if let Some(rotate) = rotate {
            rotate.await;
        }
        app.overlay_path = Some(
            busbar_kernel::config::overlay::OverlayStore::from_core(
                app.governance
                    .as_ref()
                    .expect("the actual root opened governance")
                    .core_store_handle()
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
    let router = crate::distribution::admin_cross_plane::build_router(
        crate::root::real_store::hydrated(app).await,
    );
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
    let body = json::parse_value(&r.bytes().await.unwrap()).unwrap();
    assert_eq!(
        status, 404,
        "a target that is not in the plugins dir: {body}"
    );
    assert_eq!(body["error"]["code"], "not_found");

    let guarded = rollback(format!(
        r#"{{"file":"{file}","expected_archive_sha256":"{}"}}"#,
        "0".repeat(64)
    ))
    .await
    .unwrap();
    assert_eq!(guarded.status().as_u16(), 409);
    assert_eq!(
        json::parse_value(&guarded.bytes().await.unwrap()).unwrap()["error"]["code"],
        "conflict"
    );

    let r = rollback(format!(r#"{{"file":"{file}"}}"#)).await.unwrap();
    let status = r.status().as_u16();
    let body = json::parse_value(&r.bytes().await.unwrap()).unwrap();
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
            "schema_invalid_archive",
            "/plugins/invalid-schema.tar.gz/schema?source=installed_archive",
            "GET",
            None,
            400,
            "invalid_request",
        ),
        (
            "schema_invalid_filename",
            "/plugins/not-an-archive/schema?source=installed_archive",
            "GET",
            None,
            400,
            "invalid_request",
        ),
        (
            "remove_bad_archive_digest",
            "/plugins/ghost-1.0.0.tar.gz?expected_archive_sha256=bad",
            "DELETE",
            None,
            400,
            "invalid_request",
        ),
        (
            "remove_guarded_missing",
            "/plugins/ghost-1.0.0.tar.gz?expected_archive_sha256=0000000000000000000000000000000000000000000000000000000000000000",
            "DELETE",
            None,
            409,
            "conflict",
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
        let parsed = json::parse_value(&r.bytes().await.unwrap()).unwrap();
        assert_eq!(status, want_status, "{label}: {parsed}");
        assert_eq!(parsed["error"]["code"], want_code, "{label}");
    }
    server.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

async fn drive_plugin_inspect_errors() {
    if isolated_fixture("BUSBAR_ADMIN_FIXTURE_DRIVER", "plugin_inspect_errors") {
        return;
    }
    crate::distribution::admin_cross_plane::ensure_seam();
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "busbar-admin-inspect-witness-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(
        crate::root::real_store::core().await,
    )
    .expect("the actual Store opens the overlay");
    let store = crate::root::real_store::core().await;
    let gov = gov_with_signer(store, Some("admintok".to_string())).await;
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
        let deploy = busbar_kernel::config::deploy_from_deserializer(
            document,
            &crate::root::boot::axis_test_grammar(),
        )
        .expect("the actual admin deployment parses");
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the actual admin deployment resolves");
        let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
            as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
        let (mut app, rotate, limits) = crate::root::real_store::build_app(
            cfg,
            super::plugins::trusted_config(&directory),
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
        )
        .await
        .expect("the product root builds the actual admin application");
        limits.stage_boot();
        attach_fixture_prices(&app).await;
        limits.keep().await.expect("the product limits commit");
        if let Some(rotate) = rotate {
            rotate.await;
        }
        app.overlay_path = Some(
            busbar_kernel::config::overlay::OverlayStore::from_core(
                app.governance
                    .as_ref()
                    .expect("the actual root opened governance")
                    .core_store_handle()
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
    let router = crate::distribution::admin_cross_plane::build_router(
        crate::root::real_store::hydrated(app).await,
    );
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
    let body = json::parse_value(&r.bytes().await.unwrap()).unwrap();
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
    let doc = json::parse_value(busbar_core_admin::test_support::openapi_json().as_bytes())
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
            busbar_export_prometheus::door,
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
    named_map_app_opts(tag, reference_corp_ad, true, false, ServeTables::default()).await
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
    named_map_app_opts(tag, false, true, false, tables).await
}

async fn named_map_app_opts(
    tag: &str,
    reference_corp_ad: bool,
    base_export: bool,
    ephemeral: bool,
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
    use busbar_contract::yaml::{self, prelude::*};
    let mut disk: Value = yaml::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
    *disk.at_mut("store") =
        yaml::to_value(&serde_json::json!({"module": facts.name, "settings": settings})).unwrap();
    *disk.at_mut("plugins") = yaml::to_value(&super::plugins::config_document(
        &super::plugins::trusted_config(&plugin_dir),
    ))
    .expect("the disk baseline retains the actual signed Store configuration");
    std::fs::write(&config_path, yaml::to_string(&disk).unwrap())
        .expect("write the actual Store selection");

    let mut live = disk;
    *live.at_mut("auth") = yaml::from_str("chain: []\nadmin_auth: [admin-tokens]\n").unwrap();
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        yaml::deserializer(live),
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the admin deployment parses");
    let defs = busbar_kernel::config::providers::catalog_from_str(
        &std::fs::read_to_string(&providers_path).unwrap(),
    )
    .expect("the provider catalog parses");
    let cfg = busbar_kernel::config::resolve(&deploy, &defs)
        .expect("the actual admin deployment resolves");
    let store = if ephemeral {
        crate::root::real_store::core_over(Arc::new(crate::root::real_store::EphemeralInfo(
            crate::root::real_store::native_backend().await,
        )))
        .await
    } else {
        crate::root::real_store::core().await
    };
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(store.clone())
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
        Some(store),
        false,
    )
    .await
    .expect("the actual product builds the named-map application");
    limits.stage_boot();
    attach_fixture_prices(&app).await;
    limits.keep().await.expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    app.serve_tables = tables;
    let app = Arc::new(app);
    busbar_kernel::audit::auditlog::register_test_audit_stream(&app).await;
    let router = crate::distribution::admin_cross_plane::build_router(
        crate::root::real_store::hydrated(app).await,
    );
    let (addr, handle, _) = spin_up(router).await;
    (dir, overlay, addr, handle)
}

async fn try_publish_door(
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

    let store = crate::root::real_store::core().await;
    let gov = gov_with_signer(store.clone(), None).await;
    let services = crate::root::serve::LateServices::new();
    let kernel = Arc::new(
        busbar_kernel::host_services::KernelServices::new()
            .with_signer(gov.clone())
            .with_pool(Arc::new(busbar_kernel::host_services::BlockingPool::new(
                tokio::runtime::Handle::current(),
                busbar_kernel::host_records::QUEUE_CAP,
            ))),
    );
    assert!(kernel.attach_persistence(store));
    services
        .install_kernel(kernel.clone(), kernel.clone())
        .unwrap();
    let dispatcher = Arc::new(Dispatcher::with_services(
        DispatchConfig::default(),
        services.served(),
        busbar_kernel::host_services::caller_binding(),
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
                    conns: busbar_plugin_loader::dispatch::ConnTable::Host(
                        crate::root::connector::admit(conns.clone()),
                    ),
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
    let settings = busbar_contract::yaml::from_str(settings)
        .expect("the exact opened section also supplies the normal host admission");

    let admission = Arc::new(
        busbar_kernel::plane_driver::PlaneDriver::new(
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
        )
        .await?,
    );
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

async fn publish_door(
    section: &str,
    settings: &str,
) -> (ServeTables, Arc<busbar_kernel::plane_driver::PlaneDriver>) {
    try_publish_door(section, settings)
        .await
        .expect("the door opens")
}

async fn assert_passthrough_is_refused_before_publication() {
    let error = match try_publish_door(
        "tools",
        r#"{"base-tools": {"url": "https://pass.example/rpc", "pin": {"mechanism": "cert_spki", "key": "sha256/l5WGzHWyALvI/qjcwI1ctxb3Jp8+8Ztd0NTYTcL0Q4s="}, "upstream_credentials": "passthrough", "tools_allow": {"read": {"schema_hash": "sha256:aa"}}}}"#,
    ).await {
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
    if isolated_fixture("BUSBAR_ADMIN_FIXTURE_DRIVER", "door_verb_errors") {
        return;
    }
    assert_passthrough_is_refused_before_publication().await;
    let (tables, _admission) = publish_door(
        "tools",
        r#"{"base-tools": {"url": "https://pass.example/rpc", "pin": {"mechanism": "cert_spki", "key": "sha256/l5WGzHWyALvI/qjcwI1ctxb3Jp8+8Ztd0NTYTcL0Q4s="}, "upstream_credentials": "own", "tools_allow": {"read": {"schema_hash": "sha256:aa"}}}}"#,
    ).await;
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
        let body = json::parse_value(&r.bytes().await.unwrap()).unwrap();
        assert_eq!(
            json::pointer(&body, "/error/code").unwrap(),
            "not_found",
            "{body}"
        );
    }
    let r = send(reqwest::Method::GET, "/tools/base-tools/changes")
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let body = json::parse_value(&r.bytes().await.unwrap()).unwrap();
    assert_eq!(body.get("name").unwrap(), "base-tools", "{body}");
    assert!(body.get("error").is_none(), "{body}");
    handle.abort();
}

#[tokio::test]
async fn a_door_admin_route_is_served_only_by_the_generation_lent_its_table() {
    let selected = match std::env::var("BUSBAR_ADMIN_TABLE_CASE") {
        Ok(selected) => selected,
        Err(_) => {
            for case in ["lent", "unlent"] {
                run_fixture_process("BUSBAR_ADMIN_TABLE_CASE", case, &[]);
            }
            return;
        }
    };
    assert!(matches!(selected.as_str(), "lent" | "unlent"));
    eprintln!("BUSBAR_FIXTURE_SELECTED:BUSBAR_ADMIN_TABLE_CASE={selected}");
    assert_passthrough_is_refused_before_publication().await;
    let (dir, _overlay, _addr, handle) = if selected == "lent" {
        let (tables, _admission) = publish_door(
            "tools",
            r#"{"base-tools": {"url": "https://pass.example/rpc", "pin": {"mechanism": "cert_spki", "key": "sha256/l5WGzHWyALvI/qjcwI1ctxb3Jp8+8Ztd0NTYTcL0Q4s="}, "upstream_credentials": "own", "tools_allow": {"read": {"schema_hash": "sha256:aa"}}}}"#,
        ).await;
        // Admission stays alive through the fixture's requests, as in the original witness.
        let fixture = named_map_app_serving("door-table-lent", tables).await;
        let client = reqwest::Client::new();
        let response = client
            .get(format!(
                "http://{}/api/v1/admin/tools/base-tools/changes",
                fixture.2
            ))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        let status = response.status().as_u16();
        let body = json::parse_value(&response.bytes().await.unwrap()).unwrap();
        assert_eq!(status, 200, "the lent generation serves the door: {body}");
        assert_eq!(body.get("name").unwrap(), "base-tools", "{body}");
        assert!(body.get("error").is_none(), "{body}");
        fixture
    } else {
        let fixture = named_map_app("door-table-unlent", false).await;
        let response = reqwest::Client::new()
            .get(format!(
                "http://{}/api/v1/admin/tools/base-tools/changes",
                fixture.2
            ))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        let status = response.status().as_u16();
        let body = json::parse_value(&response.bytes().await.unwrap()).unwrap();
        assert_eq!(
            status, 404,
            "a generation lent no table serves no door: {body}"
        );
        assert_eq!(
            json::pointer(&body, "/error/code").unwrap(),
            "not_found",
            "{body}"
        );
        fixture
    };
    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

fn issuer_key_info(issuer: &busbar_contract::crypto::ed25519::SigningKey) -> String {
    use base64::Engine as _;
    let mut der = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    der.extend_from_slice(&issuer.verifying_key().to_bytes());
    base64::engine::general_purpose::STANDARD.encode(der)
}

async fn drive_agent_door_verb_errors() {
    if isolated_fixture("BUSBAR_ADMIN_FIXTURE_DRIVER", "agent_door_verb_errors") {
        return;
    }
    let issuer = busbar_contract::crypto::ed25519::SigningKey::from_seed(&[7; 32])
        .expect("a valid Ed25519 seed");
    let section = json::json!({
        "base-agent": {
            "url": "http://127.0.0.1:1/closed",
            "pin": {"mechanism": "jws_issuer_key", "key": issuer_key_info(&issuer)}
        }
    });
    let (tables, _admission) = publish_door("agents", &section.to_string()).await;
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
        let body = json::parse_value(&r.bytes().await.unwrap()).unwrap();
        assert_eq!(
            json::pointer(&body, "/error/code").unwrap(),
            "not_found",
            "{body}"
        );
    }
    let r = send(
        "/agents/base-agent/approve",
        r#"{"fingerprint": "sha256:aa", "and": "more"}"#,
    )
    .await
    .unwrap();
    assert_eq!(r.status(), 400, "approve with an unknown body field");
    let body = json::parse_value(&r.bytes().await.unwrap()).unwrap();
    assert_eq!(
        json::pointer(&body, "/error/code").unwrap(),
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
    let body = json::parse_value(&r.bytes().await.unwrap()).unwrap();
    assert_eq!(
        json::pointer(&body, "/error/code").unwrap(),
        "invalid_request",
        "{body}"
    );
    handle.abort();
}

async fn drive_named_map_errors() {
    if isolated_fixture("BUSBAR_ADMIN_FIXTURE_DRIVER", "named_map_errors") {
        return;
    }
    linked_export_axis();
    let big_settings = {
        let mut m = json::Map::new();
        m.insert("blob", json::json!("x".repeat(70_000)));
        json::json!({ "settings": m }).to_string()
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
    // `/identity-providers` and `/export` are removed in 1.6.0 (ADMIN-API-1.6 §0.2, CON-6): the
    // named-map surface is the plane-owned sections'.
    for (section, base) in [("tools", "base-tools"), ("agents", "base-agent")] {
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
        if isolated_fixture("BUSBAR_NAMED_MAP_CASE", &format!("batch-{batch_i}")) {
            continue;
        }
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
            let parsed = json::parse_value(&resp.bytes().await.unwrap()).unwrap();
            assert_eq!(
                status, *want_status,
                "{label}: expected {want_status}, got {status} ({parsed})"
            );
            assert_eq!(parsed["error"]["code"], *want_code, "{label}: {parsed}");
        }
        handle.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    for section in ["tools", "agents"] {
        if isolated_fixture("BUSBAR_NAMED_MAP_CASE", &format!("ephemeral-{section}")) {
            continue;
        }
        crate::distribution::admin_cross_plane::ensure_seam();
        let store = crate::root::real_store::core().await;
        let gov = gov_with_signer(store, Some("admintok".to_string())).await;
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
            let deploy = busbar_kernel::config::deploy_from_deserializer(
                document,
                &crate::root::boot::axis_test_grammar(),
            )
            .expect("the actual admin deployment parses");
            let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
                .expect("the actual admin deployment resolves");
            assert!(
                cfg.plane_sections.contains("tools") && cfg.plane_sections.contains("agents"),
                "the actual parser configures both positive named-map planes"
            );
            let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
                as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
            let (mut app, rotate, limits) = crate::root::real_store::build_app(
                cfg,
                super::plugins::trusted_config(&directory),
                None,
                Default::default(),
                Default::default(),
                (None, None),
                None,
                &rules,
            )
            .await
            .expect("the product root builds the actual admin application");
            limits.stage_boot();
            attach_fixture_prices(&app).await;
            limits.keep().await.expect("the product limits commit");
            if let Some(rotate) = rotate {
                rotate.await;
            }
            app.overlay_path = Some(
                busbar_kernel::config::overlay::OverlayStore::from_core(
                    app.governance
                        .as_ref()
                        .expect("the actual root opened governance")
                        .core_store_handle()
                        .expect("the actual Store exposes its calls"),
                )
                .expect("the actual Store opens its overlay"),
            );
            app.governance = Some(gov);

            std::sync::Arc::new(app)
        };
        let router = crate::distribution::admin_cross_plane::build_router(
            crate::root::real_store::hydrated(app).await,
        );
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
                let parsed = json::parse_value(&resp.bytes().await.unwrap()).unwrap();
                assert_eq!(status, 400, "{section} {label} (ephemeral): {parsed}");
                assert_eq!(parsed["error"]["code"], "invalid_request");
            }
        }
        handle.abort();
    }
}

#[tokio::test]
async fn named_map_error_surface_answers_its_declared_taxonomy() {
    drive_named_map_errors().await;
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
