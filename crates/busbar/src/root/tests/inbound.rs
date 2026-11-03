// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use busbar_contract::abi::auth::{AuthPoints, POINT_HEAD, POINT_HEAD_BODY, POINT_PEER};
use busbar_contract::abi::host::service::{
    UnitRef, LINE_NONE, REFUSE_METHOD_MISS, REFUSE_NO_ROUTE, REFUSE_OVER_GATE, REFUSE_STOPPED,
};
use busbar_contract::abi::transport::route::{METHOD_POST, PATH_EXACT};
use busbar_kernel::guest::{Claimant, GuestList, Line, LineAuth, Route};
use busbar_kernel::inbound::{self as kin, Inbound};
use serde_json::Value;

use crate::root::loader::dispatch::auth_handle::{self, RefSpace};

const OWNER: u64 = 11;
const GEN: u64 = 1;

const NATIVE: &str = "/api/v1/things";

fn line(path: &str, methods: u32) -> Line {
    Line {
        route: Route {
            methods,
            path_form: PATH_EXACT,
            path: path.to_string(),
            fields: Vec::new(),
            rung: 0,
        },
        claimant: Claimant::Plane("plane".to_string()),
        dialect: 0,
        auth: LineAuth::Chain(vec!["a".to_string()], AuthPoints::HEAD_BODY),
        upgrade: None,
        offered: AuthPoints(POINT_PEER | POINT_HEAD | POINT_HEAD_BODY),
    }
}

fn app() -> Arc<busbar_kernel::state::App> {
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
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
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
    drop(limits);
    drop(rotate);
    Arc::new(app)
}

fn side() -> (Arc<Inbound>, GuestList) {
    crate::dist_root_install::install();
    let guests = GuestList::seal(vec![line(NATIVE, METHOD_POST)]).expect("the list seals");
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
        .install(
            OWNER,
            GEN,
            kin::Listener {
                guests: guests.clone(),
                auths: std::collections::HashMap::new(),
                body_limit: 16,
                app: app(),
                door_refusals: Vec::new(),
                ids: guests
                    .lines()
                    .iter()
                    .map(|_| auth_handle::next_ref_id(RefSpace::Line))
                    .collect(),
                signed_ingress: Arc::new(|_, _| false),
                scope: None,
            },
        )
        .expect("the root's line ids are line ids");
    (inbound, guests)
}

fn ix(guests: &GuestList, path: &str) -> u32 {
    guests
        .lines()
        .iter()
        .position(|l| l.route.path == path)
        .expect("on the list") as u32
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
    let line = if cause == REFUSE_NO_ROUTE {
        LINE_NONE
    } else {
        ix(&guests, NATIVE)
    };
    let mut failing = Vec::new();
    for (name, head, credentialed) in crosscut(family) {
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
