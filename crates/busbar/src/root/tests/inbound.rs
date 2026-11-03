// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use busbar_contract::abi::host::service::{
    UnitRef, LINE_NONE, REFUSE_METHOD_MISS, REFUSE_NO_ROUTE, REFUSE_OVER_GATE, REFUSE_STOPPED,
};
use busbar_kernel::guest::{GuestList, Matched};
use busbar_kernel::inbound::{self as kin, Inbound};
use serde_json::Value;

use crate::root::loader::dispatch::auth_handle::{self, RefSpace};

const OWNER: u64 = 11;
const GEN: u64 = 1;

fn captured_rates() -> std::collections::BTreeMap<String, busbar_kernel::config::RateEntryCfg> {
    let plane = busbar_kernel::plane_driver::registry::plane_decl_for(
        busbar_kernel::plane_driver::dispatch::fallback_key(),
    )
    .expect("the actual linked fallback declares its billable unit vocabulary");
    let mut entry = busbar_kernel::config::RateEntryCfg {
        input_utok: 1.0,
        ..Default::default()
    };
    let free =
        serde_json::from_value(serde_json::json!(0)).expect("an exact explicit free unit price");
    for class in plane.billable_classes {
        if !busbar_contract::records::RESERVED_UNITS.contains(&class.class)
            && !plane.fee_units.contains(&class.class)
        {
            entry.units.insert(class.class.to_owned(), free);
        }
    }
    std::collections::BTreeMap::from([("priced-context".into(), entry)])
}

fn app(
    with_llm: bool,
) -> (
    Arc<busbar_kernel::state::App>,
    busbar_kernel::config::RootCfg,
    crate::root::durability::NodeBook,
) {
    app_with_admin_reader(with_llm, false)
}

fn app_with_admin_reader(
    with_llm: bool,
    reader: bool,
) -> (
    Arc<busbar_kernel::state::App>,
    busbar_kernel::config::RootCfg,
    crate::root::durability::NodeBook,
) {
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = crate::root::test_plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
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
    let mut document = serde_json::json!({
        "public_url": "https://gw.example",
        "providers": {},
        "models": {},
        "auth": { "chain": ["keys"], "admin_auth": [operator], "signing_key": {"file": signing} },
        "identity-providers": {},
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    });
    document["identity-providers"][operator] = serde_json::json!({
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
        document["identity-providers"]["body-cap-reader"] = serde_json::json!({
            "module": module,
            "settings": crate::test_common::credentials::settings("api://inbound-body-cap"),
            "max_admin_scope": "read-only",
        });
        document["auth"]["admin_auth"] = serde_json::json!(["body-cap-reader", operator]);
        document["auth"]["role_bindings"] = serde_json::json!({
            "body-cap-reader": {"readers": {"admin_scope": "read-only"}},
        });
    }
    let mut providers = Default::default();
    if with_llm {
        let dialects: Value =
            serde_json::from_str(include_str!("fixtures/plane_node_dialects.json"))
                .expect("the actual linked model dialect fixture reads");
        let dialect = dialects["body_model"]
            .as_object()
            .and_then(|rows| rows.keys().next())
            .expect("the actual model plane declares a body-model dialect");
        let credential = directory.join("unused-provider-credential");
        std::fs::write(&credential, "inbound-context-provider-credential")
            .expect("the actual context provider's credential exists");
        providers = busbar_kernel::config::providers::catalog_from_str(&format!(
            "wire:\n  protocol: {dialect}\n  base_url: http://127.0.0.1:9\n"
        ))
        .expect("the actual context provider has its catalogue declaration");
        document["providers"] = serde_json::json!({"wire": {
            "protocol": dialect, "base_url": "http://127.0.0.1:9", "api_key": {"file": credential}
        }});
        document["models"] = serde_json::json!({"priced-context": {"provider": "wire"}});
        document["pools"] = serde_json::json!({});
        document["rate_card"] =
            serde_json::to_value(captured_rates()).expect("the actual complete card serializes");
    }
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
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
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the actual product builds the door deployment");
    limits.stage_boot();
    let book = crate::root::boot::book(&app, &module)
        .expect("the actual Store binds rate history before request admission");
    limits
        .keep()
        .expect("the normal configured limits activate");
    if let Some(rotate) = rotate {
        rotate();
    }
    (Arc::new(app), listener_config, book)
}

fn actual_listener_with_routers(
    app: Arc<busbar_kernel::state::App>,
    config: &busbar_kernel::config::RootCfg,
    book: &crate::root::durability::NodeBook,
    with_llm: bool,
) -> (kin::Listener, axum::Router, axum::Router) {
    use crate::root::loader::dispatch::{
        kinds::plane::Plane, load_linked, Bind, ConnTable, LinkedRow, NoSink,
    };
    use crate::root::serve::{LateServices, ListenerPlan};
    let late = LateServices::new();
    let (credentials, _handle) = crate::root::credentials::AppCredentials::late();
    crate::root::serve::compose(
        crate::root::connector::dest_judge(config),
        &late,
        credentials,
    );
    let declarations: Vec<_> = busbar_kernel::plane_driver::registry::plane_decls()
        .iter()
        .map(|decl| &decl.declaration)
        .collect();
    crate::root::serve::attach(
        &late,
        app.governance.as_deref(),
        None,
        &app.demotion_record,
        &declarations,
    );
    let dispatcher = Arc::new(crate::root::dispatch::build(2, &late));
    crate::root::connector::install_io(&dispatcher);
    let connector = crate::root::connector::the().clone();
    let row = LinkedRow::of(busbar_plane_llm::plane_door::door)
        .expect("the normal linked LLM product states its actual memory ABI");
    let plugin = Arc::new(
        load_linked::<Plane>(
            &row,
            Bind {
                instance: "inbound-actual-llm".into(),
                max_inflight_cap: 64,
                sink: Arc::new(NoSink),
                dispatcher: dispatcher.adopter(),
                conns: ConnTable::Host(connector.clone()),
            },
        )
        .expect("the actual linked LLM image binds to normal host services"),
    );
    let section = plugin.served().section;
    let mut sections = std::collections::BTreeMap::new();
    if with_llm {
        sections = app
            .config_projection
            .as_ref()
            .and_then(|projection| projection.downcast_ref::<crate::root::door_steps::DoorConfig>())
            .expect("the normal root retains the actual resolved plane-owned sections")
            .sections
            .clone();
        assert!(
            sections.contains_key(section),
            "the actual fallback section is configured"
        );
    }
    let gov = app
        .governance
        .as_ref()
        .expect("the actual Store owns governance")
        .clone();
    let node = Arc::new(crate::root::plane_node::Node::new());
    node.bind_book(Arc::clone(&book.durability));
    let post = Arc::new(crate::root::plane_node::NodeEndPost::new(node));
    let money = || {
        Arc::new(busbar_kernel::plane_driver::PlaneMoney::new(
            gov.clone(),
            post.clone(),
        ))
    };
    let served = crate::root::serve::compose_planes(
        &[("inbound-actual-llm".into(), plugin)],
        &dispatcher,
        &late,
        &sections,
        Some("https://gw.example"),
        &money,
        None,
        None,
        &Default::default(),
    )
    .expect("the actual linked LLM OPEN claims are admitted by the normal driver");
    let framer = move |scheme: &str| connector.framer_for(scheme);
    let topology = crate::root::boot::configured_listener_needs(config, &sections)
        .expect("the actual configuration declares its normal physical listener needs");
    let plan = Arc::new(ListenerPlan::new(
        topology,
        crate::root::serve::transport_offers(crate::LINKED.transports, &[]),
        &framer,
    ));
    plan.mount_planes(&served, &app, &[])
        .expect("the actual LLM claims prepare the normal listener and refusal renderer");
    let source = kin::Listener {
        guests: GuestList::default(),
        auths: Default::default(),
        body_limit: 16,
        app,
        door_refusals: Vec::new(),
        ids: Vec::new(),
        signed_ingress: Arc::new(|_, _| false),
        scope: None,
    };
    let mut listener = plan.policy("listen".into())(&source)
        .expect("the actual prepared listener retains its generation's producer");
    if with_llm {
        let plane = served
            .planes
            .iter()
            .find(|plane| plane.instance == "inbound-actual-llm")
            .expect("the actual LLM instance owns this listener's producer");
        let (rung, claim) = plane
            .snapshot
            .claims
            .iter()
            .enumerate()
            .find(|(_, claim)| {
                claim.verb == "POST"
                    && claim.target == "/"
                    && claim.flags & busbar_contract::abi::plane::CLAIM_EXACT == 0
            })
            .expect("the actual OPEN snapshot declares its non-exact POST root fallback");
        let rung = u32::try_from(rung).expect("the actual claim index fits the host route field");
        let mounted = listener.guests.lines().iter().find(|line| {
            matches!(&line.claimant, busbar_kernel::guest::Claimant::Plane(owner) if owner == &plane.instance)
                && line.route.rung == rung
        }).expect("the normal listener plan mounts that exact actual claim");
        assert_eq!(
            mounted.dialect,
            u32::from(claim.refusal_dialect),
            "the mounted line retains the actual claim's opaque refusal dialect"
        );
        assert!(
            matches!(listener.guests.matched("POST", "/definitely/unknown", &[]),
            Matched::Line(line) if std::ptr::eq(line, mounted)),
            "the captured unknown path reaches the actual mounted fallback claim"
        );
    }
    listener.ids = listener
        .guests
        .lines()
        .iter()
        .map(|_| auth_handle::next_ref_id(RefSpace::Line))
        .collect();
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(Arc::clone(
        &source.app,
    )));
    let select = Arc::clone(&plan);
    let data = busbar_kernel::router::serve_listener_generations(
        Arc::clone(&handle),
        move |app| select.prepared(app, "listen"),
        32 * 1024 * 1024,
        0,
        false,
    );
    let admin = busbar_kernel::router::build_admin_router_on(&handle, 32 * 1024 * 1024, false);
    (listener, data, admin)
}

fn actual_listener(
    app: Arc<busbar_kernel::state::App>,
    config: &busbar_kernel::config::RootCfg,
    book: &crate::root::durability::NodeBook,
    with_llm: bool,
) -> kin::Listener {
    actual_listener_with_routers(app, config, book, with_llm).0
}

fn side() -> (Arc<Inbound>, GuestList) {
    let (app, config, book) = app(true);
    let listener = actual_listener(app, &config, &book, true);
    let guests = listener.guests.clone();
    let next = Arc::new(AtomicU64::new(1));
    let inbound = Inbound::new(
        kin::Seals {
            mint: Arc::new(move || next.fetch_add(1, Ordering::SeqCst)),
            mac: Arc::new(|t: &kin::UnitTag| Some(t.unit ^ t.secret[0])),
        },
        Arc::new(|_| {}),
        Arc::new(|_: &kin::RefusedUnit| {}),
    );
    inbound
        .install(OWNER, GEN, listener)
        .expect("the actual declared line ids install");
    (inbound, guests)
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

fn golden(name: &str) -> Value {
    let path = format!(
        "{}/../../testing/shadow-oracle/golden/1.5.5/cells/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&text).expect("a golden cell is JSON")
}

fn field<'a>(r: &'a kin::Refusal, name: &str) -> Option<&'a str> {
    r.fields
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .and_then(|(_, v)| std::str::from_utf8(v).ok())
}

fn differences(r: &kin::Refusal, name: &str) -> Vec<String> {
    let cell = golden(name);
    let mut wrong = Vec::new();
    if Some(u64::from(r.status)) != cell["status"].as_u64() {
        wrong.push(format!("status {} not {}", r.status, cell["status"]));
    }
    if let Some(headers) = cell["headers"].as_object() {
        for (n, want) in headers {
            if n == "date" || n == "content-length" {
                continue;
            }
            let want = want.as_str().unwrap_or_default();
            let got = field(r, n).unwrap_or_default();
            let holds = match want.split_once("<ID>") {
                Some((prefix, suffix)) => {
                    got.starts_with(prefix) && got.ends_with(suffix) && got.len() > want.len() - 4
                }
                None => got == want,
            };
            if !holds {
                wrong.push(format!("field {n}: {got:?} not {want:?}"));
            }
        }
    }
    match serde_json::from_slice::<Value>(&r.body) {
        Ok(mut body) => {
            if body.get("request_id").is_some() {
                body["request_id"] = Value::from("<ID>");
            }
            if body != cell["body"]["json"] {
                wrong.push(format!("body {body} not {}", cell["body"]["json"]));
            }
        }
        Err(e) => wrong.push(format!("body is not JSON: {e}")),
    }
    if let Some(len) = cell["headers"]["content-length"]
        .as_str()
        .and_then(|l| l.parse::<usize>().ok())
    {
        if r.body.len() != len {
            wrong.push(format!("length {} not {len}", r.body.len()));
        }
    }
    wrong
}

fn crosscut(family: &str) -> Vec<(String, kin::Head, bool)> {
    let path = format!(
        "{}/../../testing/shadow-oracle/cells.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let cells: Value = serde_json::from_str(&text).expect("the cell catalogue is JSON");
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
            (name, head, r["auth"].as_str() != Some("none"))
        })
        .collect()
}

fn captured_request(name: &str) -> Value {
    let path = format!(
        "{}/../../testing/shadow-oracle/cells.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let catalogue: Value =
        serde_json::from_slice(&std::fs::read(path).expect("the actual request catalogue reads"))
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

fn captured_key(app: &busbar_kernel::state::App) -> busbar_contract::Secret<String> {
    let now = busbar_kernel::store::now();
    let gov = app
        .governance
        .as_ref()
        .expect("the actual Store owns the captured caller's key");
    let (_, token) = gov
        .mint_signed(
            busbar_kernel::governance::NewKeySpec {
                name: "inbound-captured-caller".into(),
                ..Default::default()
            },
            now + 3600,
            now,
        )
        .expect("the actual configured signer mints the captured authenticated caller");
    gov.hydrate_budgets(&app.cost, now)
        .expect("the actual caller's budgets hydrate");
    assert!(
        app.cost.model_unpriced("nope"),
        "the captured no-rate request has an authoritative card without that model's rate"
    );
    token
}

async fn captured_router_crossing(
    router: axum::Router,
    head: &kin::Head,
    captured: &Value,
    token: &busbar_contract::Secret<String>,
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
    if captured["listener"] == "admin" {
        request = request.header("x-admin-token", "actual-inbound-operator");
    } else if captured["auth"] == "ok" {
        request = request.header(
            "authorization",
            format!("Bearer {}", token.expose(&busbar_kernel::seal::lend())),
        );
    }
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
        status: head.status.as_u16(),
        fields: head
            .headers
            .iter()
            .map(|(name, value)| (name.as_str().into(), value.as_bytes().to_vec()))
            .collect(),
        body: body.to_vec(),
    }
}

async fn refused_against(family: &str, cause: u32) -> Vec<String> {
    let (side, guests) = side();
    let (router_app, router_config, router_book) = app(true);
    let token = captured_key(&router_app);
    let (_, data, admin) =
        actual_listener_with_routers(router_app, &router_config, &router_book, true);
    let mut failing = Vec::new();
    for (name, head, credentialed) in crosscut(family) {
        let captured = captured_request(&name);
        // Arrival can classify a declared fallback path before the transport calls
        // unit.refuse. Native admin availability likewise belongs to its real router.
        if cause == REFUSE_NO_ROUTE || captured["listener"] == "admin" {
            let router = if captured["listener"] == "admin" {
                admin.clone()
            } else {
                data.clone()
            };
            let refusal = captured_router_crossing(router, &head, &captured, &token).await;
            let wrong = differences(&refusal, &name);
            if !wrong.is_empty() {
                failing.push(format!("{name}: {}", wrong.join("; ")));
            }
            continue;
        }
        let line = selected_line(&guests, &head);
        let cause = if credentialed { cause } else { REFUSE_STOPPED };
        let refusal = side
            .refuse(kin::Refuse {
                owner: OWNER,
                generation: GEN,
                unit: UnitRef::NONE,
                cause,
                line,
                request: Some(head),
                conn: 1,
                stream: 1,
                framing: None,
            })
            .expect("refused");
        let wrong = differences(&refusal, &name);
        if !wrong.is_empty() {
            failing.push(format!("{name}: {}", wrong.join("; ")));
        }
    }
    failing
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn red_every_no_route_cell_answers_its_1_5_5_bytes() {
    let failing: Vec<String> = refused_against("unknown-path", REFUSE_NO_ROUTE)
        .await
        .into_iter()
        .filter(|f| !f.contains("status 404 not 400"))
        .collect();
    assert!(failing.is_empty(), "{failing:#?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn red_the_method_miss_cell_answers_its_1_5_5_bytes() {
    let failing = refused_against("wrong-method", REFUSE_METHOD_MISS).await;
    assert!(failing.is_empty(), "{failing:#?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn red_every_over_gate_cell_answers_its_1_5_5_bytes() {
    let failing = refused_against("413", REFUSE_OVER_GATE).await;
    assert!(failing.is_empty(), "{failing:#?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn captured_rate_and_admin_availability_requests_match_their_unchanged_wire_goldens() {
    let (app, config, book) = app(true);
    let token = captured_key(&app);
    let (_, data, admin) = actual_listener_with_routers(app, &config, &book, true);
    for (family, target, router) in [
        ("unknown-path", "/x/v1/chat/completions", data),
        ("413", "/api/v1/admin/keys", admin),
    ] {
        let (name, head, _) = crosscut(family)
            .into_iter()
            .find(|(_, head, _)| head.target == target)
            .expect("the existing catalogue captures the actual request");
        let captured = captured_request(&name);
        let response = captured_router_crossing(router, &head, &captured, &token).await;
        let wrong = differences(&response, &name);
        assert!(wrong.is_empty(), "{name}: {wrong:#?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_listener_refusal_uses_only_its_sealed_claimant_route_and_dialect() {
    let (app, config, book) = app(true);
    let listener = actual_listener(app, &config, &book, true);
    let (name, head, _) = crosscut("wrong-method")
        .into_iter()
        .find(|(_, head, credentialed)| head.target == "/v1/messages" && *credentialed)
        .expect("the actual dialect has a retained method-miss golden");
    let selected = selected_line(&listener.guests, &head);
    let line = &listener.guests.lines()[selected as usize];
    let renderer = listener
        .scope
        .as_ref()
        .and_then(|scope| scope.refuse.as_ref())
        .expect("the actual prepared listener retains its real refusal producer");
    let render = |selected_line| {
        renderer(&busbar_kernel::plane_routes::KernelRefusal {
            reason: busbar_contract::caps::ReasonCode::MethodNotAllowed,
            status: 405,
            text: "method not allowed for this resource",
            path: &head.target,
            target: &head.target,
            selected_line: Some(selected_line),
        })
    };
    let actual = kin::Refusal::of(render(line).expect("the actual sealed claimant renders"));
    assert!(differences(&actual, &name).is_empty());
    let mut foreign = line.clone();
    foreign.claimant = busbar_kernel::guest::Claimant::Plane("unpublished-foreign-plane".into());
    assert!(
        render(&foreign).is_none(),
        "a foreign claimant cannot borrow the actual image"
    );
    let mut foreign_route = line.clone();
    foreign_route.route.rung = foreign_route.route.rung.wrapping_add(1);
    assert!(
        render(&foreign_route).is_none(),
        "an unsealed route rung cannot select another operation"
    );
    let mut caller_dialect = line.clone();
    caller_dialect.dialect = caller_dialect.dialect.wrapping_add(1);
    let sealed = kin::Refusal::of(
        render(&caller_dialect).expect("the sealed actual route remains selected"),
    );
    assert!(
        differences(&sealed, &name).is_empty(),
        "the renderer reads the actual sealed dialect instead of caller-supplied metadata"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retained_listener_refusals_keep_the_actual_llm_producer_after_its_claims_are_removed() {
    let (side, guests) = side();
    let (name, head, _) = crosscut("wrong-method")
        .into_iter()
        .find(|(_, head, credentialed)| head.target == "/v1/messages" && *credentialed)
        .expect("the existing golden catalogue has the actual LLM dialect's method miss");
    let line = selected_line(&guests, &head);
    assert_ne!(line, LINE_NONE, "the real LLM claim selects the dialect");
    let refuse = |generation, cause, line, request: kin::Head| {
        side.refuse(kin::Refuse {
            owner: OWNER,
            generation,
            unit: UnitRef::NONE,
            cause,
            line,
            request: Some(request),
            conn: 1,
            stream: 1,
            framing: None,
        })
        .expect("the installed actual listener refuses")
    };
    let before = refuse(GEN, REFUSE_METHOD_MISS, line, head.clone());
    assert!(
        differences(&before, &name).is_empty(),
        "the actual linked producer matches the retained wire golden"
    );

    let (next_app, next_config, next_book) = app(false);
    let generic = kin::Refusal::of(busbar_kernel::router::fallback_error_response(
        &next_app.planes,
        &head.target,
        axum::http::StatusCode::NOT_FOUND,
        busbar_contract::protocol::ERR_TYPE_NOT_FOUND,
        "the requested resource was not found",
    ));
    let next = actual_listener(next_app, &next_config, &next_book, false);
    assert!(
        matches!(
            next.guests.matched(&head.method, &head.target, &[]),
            Matched::NoRoute
        ),
        "the replacement listener has no LLM claimant"
    );
    side.install(OWNER, GEN + 1, next)
        .expect("the replacement generation publishes");
    let retained = refuse(GEN, REFUSE_METHOD_MISS, line, head.clone());
    assert!(
        differences(&retained, &name).is_empty(),
        "the retained listener still invokes its actual LLM image after publication"
    );
    let current = refuse(GEN + 1, REFUSE_NO_ROUTE, LINE_NONE, head);
    assert_eq!(
        current, generic,
        "the current no-claim listener uses the normal generic builder"
    );
    assert_ne!(
        retained, current,
        "the removed actual producer cannot leak into another generation"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_admin_body_cap_keeps_legacy_projection_new_verbs_and_authority_separate() {
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
            status: head.status.as_u16(),
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
    const LEGACY: &str = "/api/v1/admin/keys";
    const NEW: &str = "/api/v1/admin/ledger/recovery/list";
    const OVERSIZE: usize = 33 * 1024 * 1024;
    let (app, config, book) = app_with_admin_reader(false, true);
    let gov = app
        .governance
        .as_ref()
        .expect("the actual Store owns the key collection")
        .clone();
    let before = gov
        .store()
        .list_keys()
        .expect("the actual key collection reads")
        .len();
    let (_, _, admin) = actual_listener_with_routers(app, &config, &book, false);
    assert!(busbar_kernel::admin::seam::admin_verb_is_legacy(
        "POST", LEGACY
    ));
    assert!(!busbar_kernel::admin::seam::admin_verb_is_legacy(
        "TRACE", LEGACY
    ));
    assert!(!busbar_kernel::admin::seam::admin_verb_is_legacy(
        "POST", NEW
    ));
    let legacy = send(
        admin.clone(),
        "POST",
        LEGACY,
        Some("actual-inbound-operator"),
        OVERSIZE,
    )
    .await;
    assert!(
        differences(&legacy, "http.crosscut__413__api-prefix").is_empty(),
        "the real registered legacy operation retains every frozen error byte"
    );
    let new = send(
        admin.clone(),
        "POST",
        NEW,
        Some("actual-inbound-operator"),
        OVERSIZE,
    )
    .await;
    assert_eq!(
        new.status, 413,
        "new verbs retain the native body-cap status"
    );
    let new_body: Value =
        serde_json::from_slice(&new.body).expect("the native cap response is JSON");
    assert_eq!(new_body["error"]["code"], "request_too_large");
    let unauthorized = send(admin.clone(), "POST", LEGACY, None, OVERSIZE).await;
    assert_eq!(
        unauthorized.status, 401,
        "body projection cannot bypass the actual credential gate"
    );
    let reader = crate::test_common::credentials::token_for(
        "body-cap-viewer",
        &["readers"],
        "api://inbound-body-cap",
    );
    let allowed = send(admin.clone(), "GET", LEGACY, Some(&reader), 0).await;
    assert_eq!(
        allowed.status, 200,
        "the actual verifier identifies a genuinely read-only principal"
    );
    let forbidden = send(admin, "POST", LEGACY, Some(&reader), OVERSIZE).await;
    assert_eq!(
        forbidden.status, 403,
        "an oversized write cannot bypass the actual read-only grant"
    );
    assert_eq!(
        gov.store()
            .list_keys()
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
