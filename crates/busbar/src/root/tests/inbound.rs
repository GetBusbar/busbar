// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE INBOUND HANDLE'S REFUSALS, HELD TO 1.5.5 (`BUSBAR-1.6.0.md` THE DESIGN §6, "Auth points and
//! guest lists", step 4, l.950-952 and l.962-964): with this build's protocol declarations linked,
//! the kernel's `unit.refuse` answers, for the request the transport hands it
//! (`UnitRefuseIn::request`, ruling 1), the bytes the 1.5.5 oracle recorded for every crosscut cell
//! a refusal answers: the no-route cells, the method-miss cell, and the over-gate cells (an
//! unauthenticated one answers its 401 first). The cells are READ from the oracle's own catalogue
//! (`testing/shadow-oracle/cells.json`, by family), so this crate names no dialect (Law 0).

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
/// A line under the native API's root (`admin::gate::API_ROOT`).
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

/// The kernel side over this build's protocols, the data listener holding `NATIVE` (POST only).
fn side() -> (Arc<Inbound>, GuestList) {
    for decls in crate::LINKED.protocols {
        busbar_kernel::proto::register_test_protocols(decls);
    }
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
                app: busbar_kernel::test_support::TestApp::new().build(),
                door_refusals: Vec::new(),
                ids: guests
                    .lines()
                    .iter()
                    .map(|_| auth_handle::next_ref_id(RefSpace::Line))
                    .collect(),
                signed_ingress: kin::signed_by_dialect(),
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

/// The golden cell `name`.
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

/// `r` against golden cell `name`: its status, every head field the cell pins but the date and
/// the length (its `<ID>` normalisation applied), its body (a request id normalised the same way),
/// and its content-length where the cell pins one. The differences, worded; none when it holds.
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

/// The oracle's crosscut cells of `family` (`http.crosscut|<family>|…`) that run without a
/// fixture: (the golden cell's name, the request's method, path and head fields, whether it
/// presents a credential).
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

/// Every cell of `family` refused for `cause`, held to its golden bytes: the cells that differ, and
/// how. A cell whose 1.5.5 answer is no refusal of this cause (it was routed) is named apart.
fn refused_against(family: &str, cause: u32) -> Vec<String> {
    let (side, guests) = side();
    let line = if cause == REFUSE_NO_ROUTE {
        LINE_NONE
    } else {
        ix(&guests, NATIVE)
    };
    let mut failing = Vec::new();
    for (name, head, credentialed) in crosscut(family) {
        // An unauthenticated over-gate request is a stop at its head, before the body (its 401).
        let cause = if credentialed { cause } else { REFUSE_STOPPED };
        let refusal = side
            .refuse(kin::Refuse {
                owner: OWNER,
                generation: GEN,
                unit: UnitRef::NONE,
                cause,
                line,
                request: Some(head),
            })
            .expect("refused");
        let wrong = differences(&refusal, &name);
        if !wrong.is_empty() {
            failing.push(format!("{name}: {}", wrong.join("; ")));
        }
    }
    failing
}

/// RED (ruling 1): every no-route crosscut cell answers its 1.5.5 bytes, shaped by the request's
/// path. A suffix-routed cell is excluded by its own answer: 1.5.5 ROUTED that request (a
/// 400 from its dialect), which is the guest list's parity, not a refusal's.
#[test]
fn red_every_no_route_cell_answers_its_1_5_5_bytes() {
    let failing: Vec<String> = refused_against("unknown-path", REFUSE_NO_ROUTE)
        .into_iter()
        .filter(|f| !f.contains("status 404 not 400"))
        .collect();
    assert!(failing.is_empty(), "{failing:#?}");
}

/// RED (ruling 1): the method-miss crosscut cell answers its 1.5.5 bytes in the path's dialect,
/// its request id included.
#[test]
fn red_the_method_miss_cell_answers_its_1_5_5_bytes() {
    let failing = refused_against("wrong-method", REFUSE_METHOD_MISS);
    assert!(failing.is_empty(), "{failing:#?}");
}

/// RED (ruling 1): every over-gate crosscut cell answers its 1.5.5 bytes in the path's dialect,
/// before any verdict; the unauthenticated one its 401 first.
#[test]
fn red_every_over_gate_cell_answers_its_1_5_5_bytes() {
    let failing = refused_against("413", REFUSE_OVER_GATE);
    assert!(failing.is_empty(), "{failing:#?}");
}

/// The kernel's line half of the ref-id space is the loader's: every id the root mints for a line
/// keeps the binding bit clear and is a line's, and the bit the kernel refuses is the one a binding
/// id carries (one rule both ways, #74).
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
