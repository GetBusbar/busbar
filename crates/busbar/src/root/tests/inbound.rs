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

fn app(
    with_llm: bool,
) -> (
    Arc<busbar_kernel::state::App>,
    busbar_kernel::config::RootCfg,
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
    let mut document = serde_json::json!({
        "public_url": "https://gw.example",
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    });
    if with_llm {
        document["pools"] = serde_json::json!({});
    }
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
        config.clone(),
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the actual product builds the door deployment");
    drop(limits);
    drop(rotate);
    (Arc::new(app), config)
}

fn actual_listener(
    app: Arc<busbar_kernel::state::App>,
    config: &busbar_kernel::config::RootCfg,
    with_llm: bool,
) -> kin::Listener {
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
        sections.insert(section, serde_yaml::Value::Mapping(Default::default()));
    }
    let gov = app
        .governance
        .as_ref()
        .expect("the actual Store owns governance")
        .clone();
    let node = Arc::new(crate::root::plane_node::Node::new());
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
    listener.ids = listener
        .guests
        .lines()
        .iter()
        .map(|_| auth_handle::next_ref_id(RefSpace::Line))
        .collect();
    listener
}

fn side() -> (Arc<Inbound>, GuestList) {
    let (app, config) = app(true);
    let listener = actual_listener(app, &config, true);
    let guests = listener.guests.clone();
    assert!(
        guests.lines().iter().any(|line| line.route.path == "/"),
        "the qualified actual LLM product declares its root fallback claim"
    );
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

fn refused_against(family: &str, cause: u32) -> Vec<String> {
    let (side, guests) = side();
    let mut failing = Vec::new();
    for (name, head, credentialed) in crosscut(family) {
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

#[test]
fn red_every_no_route_cell_answers_its_1_5_5_bytes() {
    let failing: Vec<String> = refused_against("unknown-path", REFUSE_NO_ROUTE)
        .into_iter()
        .filter(|f| !f.contains("status 404 not 400"))
        .collect();
    assert!(failing.is_empty(), "{failing:#?}");
}

#[test]
fn red_the_method_miss_cell_answers_its_1_5_5_bytes() {
    let failing = refused_against("wrong-method", REFUSE_METHOD_MISS);
    assert!(failing.is_empty(), "{failing:#?}");
}

#[test]
fn red_every_over_gate_cell_answers_its_1_5_5_bytes() {
    let failing = refused_against("413", REFUSE_OVER_GATE);
    assert!(failing.is_empty(), "{failing:#?}");
}

#[test]
fn retained_listener_refusals_keep_the_actual_llm_producer_after_its_claims_are_removed() {
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

    let (next_app, next_config) = app(false);
    let generic = kin::Refusal::of(busbar_kernel::router::fallback_error_response(
        &next_app.planes,
        &head.target,
        axum::http::StatusCode::NOT_FOUND,
        busbar_contract::protocol::ERR_TYPE_NOT_FOUND,
        "the requested resource was not found",
    ));
    let next = actual_listener(next_app, &next_config, false);
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
