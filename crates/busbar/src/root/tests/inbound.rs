// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use busbar_contract::abi::host::service::{UnitRef, LINE_NONE};
use busbar_kernel::guest::{GuestList, Matched};
use busbar_kernel::inbound::{self as kin, Inbound};
use json::Value;

use crate::root::loader::dispatch::auth_handle::{self, RefSpace};

const OWNER: u64 = 11;
const GEN: u64 = 1;

#[path = "inbound_admin_sender_constraint.rs"]
mod admin_sender_constraint;

#[path = "inbound_publication_admission.rs"]
mod publication_admission;

fn captured_rates() -> std::collections::BTreeMap<String, busbar_kernel::config::RateEntryCfg> {
    let plane = busbar_kernel::plane_driver::registry::plane_decl_for(
        busbar_kernel::plane_driver::dispatch::fallback_key(),
    )
    .expect("the actual linked fallback declares its billable unit vocabulary");
    let mut entry = busbar_kernel::config::RateEntryCfg {
        input_utok: 1.0,
        ..Default::default()
    };
    let free = json::from_value(&json::json!(0)).expect("an exact explicit free unit price");
    for class in plane.billable_classes {
        if !busbar_contract::records::RESERVED_UNITS.contains(&class.class)
            && !plane.fee_units.contains(&class.class)
        {
            entry.units.insert(class.class.to_owned(), free);
        }
    }
    std::collections::BTreeMap::from([("priced-context".into(), entry)])
}

pub(super) async fn app(
    with_llm: bool,
) -> (
    Arc<busbar_kernel::state::App>,
    busbar_kernel::config::RootCfg,
    crate::root::durability::NodeBook,
) {
    app_with_admin_reader(with_llm, false).await
}

async fn app_with_admin_reader(
    with_llm: bool,
    reader: bool,
) -> (
    Arc<busbar_kernel::state::App>,
    busbar_kernel::config::RootCfg,
    crate::root::durability::NodeBook,
) {
    app_generation(with_llm, reader, None).await
}

async fn app_generation(
    with_llm: bool,
    reader: bool,
    prior: Option<Arc<busbar_kernel::state::App>>,
) -> (
    Arc<busbar_kernel::state::App>,
    busbar_kernel::config::RootCfg,
    crate::root::durability::NodeBook,
) {
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let module = crate::root::test_plugins::native_image(&library_path).name;
    let manifest = crate::root::test_plugins::native_manifest(
        "store",
        &library_path,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = crate::root::test_plugins::scratch(&format!(
        "inbound-app-{}",
        busbar_kernel::door::op_id().counter(),
    ));
    let archive = crate::root::test_plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &library,
    );
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings = crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let signing = directory.join("signing-key");
    std::fs::write(&signing, hex::encode([7u8; 32]))
        .expect("write the real configured signing key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&operator_token, "actual-inbound-operator")
        .expect("write the real operator credential");
    let operator = busbar_kernel::config::operator_provider();
    let mut document = json::json!({
        "public_url": "https://gw.example",
        "providers": {},
        "models": {},
        "auth": { "chain": ["keys"], "admin_auth": [operator], "signing_key": {"file": signing} },
        "identity-providers": {},
        "store": { "module": module, "settings": settings },
        "advanced": {  },
    });
    document["identity-providers"][operator] = json::json!({
        "module": operator, "token": {"file": operator_token},
    });
    if reader {
        let path = crate::test_common::plugins::token_verifier_cdylib_path()
            .expect("the qualified actual OIDC verifier is required for the scope control");
        let statement = crate::root::loader::dispatch::rendering_of_library(&path)
            .expect("the actual verifier statement reads")
            .expect("the verifier exports its statement");
        let module = busbar_contract::abi::mechanism::rendering::read(&statement)
            .expect("the actual verifier declaration is valid")
            .name;
        crate::test_common::credentials::install_auth_plugin(
            &directory,
            &module,
            "body-cap-reader",
            true,
        );
        document["identity-providers"]["body-cap-reader"] = json::json!({
            "module": module,
            "settings": crate::test_common::credentials::settings("api://inbound-body-cap"),
            "max_admin_scope": "read-only",
        });
        document["auth"]["admin_auth"] = json::json!(["body-cap-reader", operator]);
        document["auth"]["role_bindings"] = json::json!({
            "body-cap-reader": {"readers": {"admin_scope": "read-only"}},
        });
    }
    let mut providers = Default::default();
    if with_llm {
        let dialects: Value =
            json::parse_value(include_str!("fixtures/plane_node_dialects.json").as_bytes())
                .expect("the actual linked model dialect fixture reads");
        let dialect = dialects["body_model"]
            .as_object()
            .and_then(|rows| rows.keys().next())
            .expect("the actual model plane declares a body-model dialect");
        let credential = directory.join("unused-provider-credential");
        std::fs::write(&credential, "inbound-context-provider-credential")
            .expect("the actual context provider's credential exists");
        providers = busbar_kernel::config::providers::catalog_from_str(
            &format!("wire:\n  protocol: {dialect}\n  base_url: http://127.0.0.1:9\n"),
            &crate::root::boot::axis_test_grammar(),
        )
        .expect("the actual context provider has its catalogue declaration");
        document["providers"] = json::json!({"wire": {
            "protocol": dialect, "base_url": "http://127.0.0.1:9", "api_key": {"file": credential}
        }});
        document["models"] = json::json!({"priced-context": {"provider": "wire"}});
        document["pools"] = json::json!({});
        document["rate_card"] =
            json::to_value(&captured_rates()).expect("the actual complete card serializes");
    }
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        &document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &providers)
        .expect("the product deployment resolves");
    assert!(
        !config.models.contains_key("nope"),
        "the captured no-rate model remains unconfigured"
    );
    if with_llm {
        assert!(
            config
                .rate_card
                .as_ref()
                .is_some_and(|card| !card.contains_key("nope")),
            "the valid authoritative card does not price the captured unknown model"
        );
    }
    let listener_config = busbar_kernel::config::resolve(&deploy, &providers)
        .expect("the same actual deployment resolves for listener topology");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (core, rules) = if let Some(prior) = &prior {
        (
            prior
                .governance
                .as_ref()
                .expect("prior governance")
                .core_store_handle()
                .expect("prior admitted CoreStore"),
            crate::root::min3_boot::fixture::carry(prior.root_rules.clone(), rules),
        )
    } else if reader {
        let opened = crate::root::test_plugins::bootstrap_fresh_application_store(
            &config,
            &plugin_config,
            &directory,
        )
        .await
        .expect("provision the actual new marked-auth fixture Store");
        (
            opened.core,
            crate::root::min3_boot::fixture::carry(opened.rules, rules),
        )
    } else {
        let opened = crate::root::min3_boot::fixture::open(&config, &plugin_config, rules)
            .await
            .expect("actual native backend")
            .admit()
            .await;
        (opened.core, opened.rules)
    };
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        prior.as_deref(),
        &rules,
        Some(core),
        false,
    )
    .await
    .expect("the actual product builds the door deployment");
    limits.stage_boot();
    let budget = busbar_kernel::persistence::journal::BufferBudget {
        records: 4096,
        bytes: 4 * 1024 * 1024,
    };
    let core = app
        .governance
        .as_ref()
        .expect("the fixture App retains its native governance owner")
        .core_store_handle()
        .expect("the fixture App retains its admitted CoreStore");
    let node = busbar_kernel::door::op_id().counter();
    if let Some(prior) = &prior {
        let previous = prior
            .governance
            .as_ref()
            .expect("prior governance")
            .core_store_handle()
            .expect("prior admitted CoreStore");
        assert!(
            Arc::ptr_eq(&core, &previous),
            "a listener reload retains the exact admitted CoreStore"
        );
        assert!(
            crate::root::kernel::ROOT_CARD.keeps_store(),
            "the original generation booted native prices"
        );
    } else {
        assert!(
            !crate::root::kernel::ROOT_CARD.keeps_store(),
            "an independent first application requires a fresh process"
        );
        crate::root::kernel::ROOT_CARD
            .keep_in_store(core.clone(), node)
            .expect("bind the first application's native price owner");
        crate::root::kernel::ROOT_CARD
            .boot_in_store(None)
            .await
            .expect("boot the actual native price history before limits activation");
    }
    let journal = busbar_kernel::persistence::journal::RuntimeJournal::open(core, node, budget)
        .await
        .expect("the fixture listener journal opens on its App's native Store");
    let book = crate::root::durability::node_book(journal, budget)
        .await
        .expect("the fixture listener retains its native NodeBook");
    limits
        .keep()
        .await
        .expect("the normal configured limits activate");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    (Arc::new(app), listener_config, book)
}

fn selected_line(guests: &GuestList, head: &kin::Head) -> u32 {
    let fields: Vec<_> = head
        .fields
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_slice()))
        .collect();
    let line = match guests.matched(&head.method, &head.target, &fields) {
        Matched::Line(line) | Matched::MethodMiss(line) => line,
        _ => return LINE_NONE,
    };
    guests
        .lines()
        .iter()
        .position(|candidate| std::ptr::eq(candidate, line))
        .expect("the selected line belongs to this actual sealed guest list") as u32
}

fn field<'a>(r: &'a kin::Refusal, name: &str) -> Option<&'a str> {
    r.fields
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .and_then(|(_, v)| std::str::from_utf8(v).ok())
}

fn crosscut(family: &str) -> Vec<(String, kin::Head)> {
    let path = format!(
        "{}/../../testing/shadow-oracle/cells.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let cells: Value = json::parse_value(text.as_bytes()).expect("the cell catalogue is JSON");
    let prefix = format!("http.crosscut|{family}|");
    cells["cells"]
        .as_array()
        .expect("the catalogue lists cells")
        .iter()
        .filter(|c| c["id"].as_str().is_some_and(|id| id.starts_with(&prefix)))
        .filter(|c| !c["needs_fixture"].as_bool().unwrap_or(false))
        .map(|c| {
            let r = &c["request"];
            let head = kin::Head {
                method: r["method"].as_str().unwrap_or_default().to_string(),
                target: r["path"].as_str().unwrap_or_default().to_string(),
                authority: String::new(),
                query: None,
                fields: r["headers"]
                    .as_object()
                    .map(|h| {
                        h.iter()
                            .map(|(n, v)| {
                                (
                                    n.to_ascii_lowercase(),
                                    v.as_str().unwrap_or_default().as_bytes().to_vec(),
                                )
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
            };
            let name = c["id"].as_str().unwrap_or_default().replace('|', "__");
            (name, head)
        })
        .collect()
}

fn captured_request(name: &str) -> Value {
    let path = format!(
        "{}/../../testing/shadow-oracle/cells.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let catalogue: Value =
        json::parse_value(&std::fs::read(path).expect("the actual request catalogue reads"))
            .expect("the request catalogue is JSON");
    catalogue["cells"]
        .as_array()
        .expect("the catalogue lists cells")
        .iter()
        .find(|cell| {
            cell["id"]
                .as_str()
                .is_some_and(|id| id.replace('|', "__") == name)
        })
        .expect("the retained golden names an actual captured request")["request"]
        .clone()
}

async fn captured_router_crossing(
    router: axum::Router,
    head: &kin::Head,
    captured: &Value,
) -> kin::Refusal {
    use tower::ServiceExt as _;
    let raw = captured["body"].as_str().unwrap_or("");
    let body = if let Some(size) = raw
        .strip_prefix("@oversize:")
        .and_then(|value| value.strip_suffix("MiB"))
    {
        vec![
            b'x';
            size.parse::<usize>()
                .expect("the captured MiB count parses")
                * 1024
                * 1024
        ]
    } else {
        raw.as_bytes().to_vec()
    };
    let mut request = axum::http::Request::builder()
        .method(head.method.as_str())
        .uri(head.target.as_str());
    for (name, value) in &head.fields {
        request = request.header(name.as_str(), value.as_slice());
    }
    assert_eq!(
        captured["listener"], "admin",
        "only captured admin crossings reach the actual admin router"
    );
    request = request.header("x-admin-token", "actual-inbound-operator");
    let request = request
        .body(axum::body::Body::from(body))
        .expect("the captured real request builds");
    let response = router
        .oneshot(request)
        .await
        .expect("the actual router answers");
    let (head, body) = response.into_parts();
    let body = axum::body::to_bytes(body, usize::MAX)
        .await
        .expect("the actual response body drains");
    kin::Refusal {
        status: u32::from(head.status.as_u16()),
        fields: head
            .headers
            .iter()
            .map(|(name, value)| (name.as_str().into(), value.as_bytes().to_vec()))
            .collect(),
        body: body.to_vec(),
    }
}

fn assert_current_admin_body_cap(response: &kin::Refusal) {
    assert_eq!(
        response.status, 413,
        "admin body caps retain the current status"
    );
    assert_eq!(field(response, "content-type"), Some("application/json"));
    assert_eq!(field(response, "cache-control"), Some("no-store"));
    let body: Value =
        json::parse_value(&response.body).expect("the current admin cap response is JSON");
    assert_eq!(body["error"]["code"], "request_too_large");
}

/// The actual admin router over the App, with a 32 MiB request-body cap.
fn admin_router(app: &Arc<busbar_kernel::state::App>) -> axum::Router {
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(Arc::clone(app)));
    busbar_kernel::router::build_admin_router_on(&handle, 32 * 1024 * 1024, false)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn captured_admin_over_gate_cells_follow_the_current_413_contract() {
    let (app, _config, _book) = app(true).await;
    let admin = admin_router(&app);
    let cells: Vec<_> = crosscut("413")
        .into_iter()
        .filter(|(name, _)| captured_request(name)["listener"] == "admin")
        .collect();
    assert!(
        cells
            .iter()
            .any(|(_, head)| head.target == "/api/v1/admin/keys"),
        "the existing catalogue captures the admin keys over-gate request"
    );
    for (name, head) in cells {
        let captured = captured_request(&name);
        let response = captured_router_crossing(admin.clone(), &head, &captured).await;
        // The old admin 404 oracle remains historical evidence, not current acceptance.
        assert_current_admin_body_cap(&response);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_admin_body_cap_uses_current_413_contract_and_preserves_authority() {
    async fn send(
        router: axum::Router,
        method: &str,
        path: &str,
        token: Option<&str>,
        size: usize,
    ) -> kin::Refusal {
        use tower::ServiceExt as _;
        let mut request = axum::http::Request::builder().method(method).uri(path);
        if let Some(token) = token {
            request = request.header("x-admin-token", token);
        }
        let response = router
            .oneshot(
                request
                    .body(axum::body::Body::from(vec![b'x'; size]))
                    .unwrap(),
            )
            .await
            .expect("the actual admin router answers");
        let (head, body) = response.into_parts();
        kin::Refusal {
            status: u32::from(head.status.as_u16()),
            fields: head
                .headers
                .iter()
                .map(|(name, value)| (name.as_str().into(), value.as_bytes().to_vec()))
                .collect(),
            body: axum::body::to_bytes(body, usize::MAX)
                .await
                .expect("the actual admin response drains")
                .to_vec(),
        }
    }
    const EXISTING: &str = "/api/v1/admin/keys";
    const NEW: &str = "/api/v1/admin/ledger/recovery/list";
    const OVERSIZE: usize = 33 * 1024 * 1024;
    let (app, _config, _book) = app_with_admin_reader(false, true).await;
    let gov = app
        .governance
        .as_ref()
        .expect("the actual Store owns the key collection")
        .clone();
    let before = gov
        .all_keys_async()
        .await
        .expect("the actual key collection reads")
        .len();
    let admin = admin_router(&app);
    let existing = send(
        admin.clone(),
        "POST",
        EXISTING,
        Some("actual-inbound-operator"),
        OVERSIZE,
    )
    .await;
    // The retained 1.5.5 oracle's 404 is historical evidence, not the current acceptance rule.
    assert_current_admin_body_cap(&existing);
    let new = send(
        admin.clone(),
        "POST",
        NEW,
        Some("actual-inbound-operator"),
        OVERSIZE,
    )
    .await;
    assert_current_admin_body_cap(&new);
    let unauthorized = send(admin.clone(), "POST", EXISTING, None, OVERSIZE).await;
    assert_eq!(
        unauthorized.status, 401,
        "body projection cannot bypass the actual credential gate"
    );
    let reader = crate::test_common::credentials::token_for(
        "body-cap-viewer",
        &["readers"],
        "api://inbound-body-cap",
    );
    let allowed = send(admin.clone(), "GET", EXISTING, Some(&reader), 0).await;
    assert_eq!(
        allowed.status, 200,
        "the actual verifier identifies a genuinely read-only principal"
    );
    let forbidden = send(admin, "POST", EXISTING, Some(&reader), OVERSIZE).await;
    assert_eq!(
        forbidden.status, 403,
        "an oversized write cannot bypass the actual read-only grant"
    );
    assert_eq!(
        gov.all_keys_async()
            .await
            .expect("the actual key collection reads after refusal")
            .len(),
        before,
        "neither oversized write executes a key mutation"
    );
}

#[test]
fn the_roots_line_ids_and_the_kernels_rule_are_one_space() {
    for _ in 0..64 {
        let id = auth_handle::next_ref_id(RefSpace::Line);
        assert!(kin::is_line_id(id), "{id:#x}");
        assert_eq!(auth_handle::space_of(id), Some(RefSpace::Line));
    }
    let binding = auth_handle::next_ref_id(RefSpace::Binding);
    assert_eq!(auth_handle::space_of(binding), Some(RefSpace::Binding));
    assert!(!kin::is_line_id(binding));
    assert_ne!(binding & kin::BINDING_BIT, 0);
}

#[path = "inbound_close.rs"]
mod close_tests;

#[path = "operator_admission_identity.rs"]
mod operator_admission_identity;

/// UPG-A20: the models plane's doors carry the card qualifier `""` (`DoorFacts.plane`), and the
/// served `/v1/models` catalogue passes that qualifier to `catalog_names`. It must list the models
/// plane's catalogue (the fallback plane), not an empty set, and still honour the key's scope.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn models_plane_qualifier_lists_the_fallback_catalog() {
    use busbar_kernel::plane_driver::dispatch::LaneQualifier;
    let (app, _config, _book) = app(true).await;
    let fallback = busbar_kernel::plane_driver::dispatch::fallback_key();
    assert!(
        !fallback.is_empty(),
        "the linked model plane is the registered fallback plane"
    );
    let open = busbar_kernel::governance::GovCtx::default();
    let listed =
        busbar_kernel::endpoints::catalog_names(&app, &open, &LaneQualifier::parse("").unwrap());
    assert!(
        listed.iter().any(|name| name == "priced-context"),
        "the models plane qualifier lists the configured model: {listed:?}"
    );
    assert_eq!(
        listed,
        busbar_kernel::endpoints::catalog_names(
            &app,
            &open,
            &LaneQualifier::parse(fallback).unwrap()
        ),
        "the models plane qualifier names the fallback plane's catalogue"
    );
    let scoped_to_nothing = busbar_kernel::governance::GovCtx {
        key: Some(Arc::new(busbar_contract::records::VirtualKey {
            allowed_scopes: Some(vec![]),
            ..busbar_contract::records::VirtualKey::default()
        })),
    };
    assert!(
        busbar_kernel::endpoints::catalog_names(
            &app,
            &scoped_to_nothing,
            &LaneQualifier::parse("").unwrap()
        )
        .is_empty(),
        "an explicit empty scope still lists nothing"
    );
    assert_eq!(
        LaneQualifier::parse("").unwrap().plane_key(),
        fallback,
        "the models plane qualifier names the fallback plane"
    );
    assert_eq!(
        LaneQualifier::parse("x").unwrap().plane_key(),
        "x",
        "a real qualifier names its own plane"
    );
}
