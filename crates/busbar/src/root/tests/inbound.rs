// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE INBOUND HANDLE'S REFUSALS, HELD TO 1.5.5 (`BUSBAR-1.6.0.md` THE DESIGN §6, "Auth points and
//! guest lists", step 4, l.950-952 and l.962-964): with this build's protocol declarations linked,
//! the kernel's `unit.refuse` answers the bytes the 1.5.5 oracle recorded for no route and for an
//! over-gate body under the native API's root (`testing/shadow-oracle/golden/1.5.5/cells/`
//! `http.crosscut__unknown-path__bare`, `http.crosscut__413__api-prefix`). The dialect-shaped cells
//! (a 405 or 413 on a protocol path) name a vendor, which this crate does not (Law 0); the kernel's
//! own cells hold those refusals to the very builders that answer them.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use busbar_contract::abi::auth::{AuthPoints, POINT_HEAD, POINT_HEAD_BODY, POINT_PEER};
use busbar_contract::abi::host::service::{UnitRef, LINE_NONE, REFUSE_NO_ROUTE, REFUSE_OVER_GATE};
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

/// `r` against golden cell `name`: its status, its content-type, its body (the cell's `<ID>`
/// normalisation applied to a request id), and its content-length where the cell pins one.
fn held_to(r: &kin::Refusal, name: &str) {
    let cell = golden(name);
    assert_eq!(
        u64::from(r.status),
        cell["status"].as_u64().unwrap(),
        "{name}: status"
    );
    assert_eq!(
        field(r, "content-type"),
        cell["headers"]["content-type"].as_str(),
        "{name}: content-type"
    );
    let mut body: Value = serde_json::from_slice(&r.body).expect("the refusal body is JSON");
    if body.get("request_id").is_some() {
        body["request_id"] = Value::from("<ID>");
    }
    assert_eq!(body, cell["body"]["json"], "{name}: body");
    if let Some(len) = cell["headers"]["content-length"]
        .as_str()
        .and_then(|l| l.parse::<usize>().ok())
    {
        assert_eq!(r.body.len(), len, "{name}: content-length");
    }
}

fn refuse(side: &Inbound, cause: u32, line: u32, target: &str) -> kin::Refusal {
    side.refuse(kin::Refuse {
        owner: OWNER,
        generation: GEN,
        unit: UnitRef::NONE,
        cause,
        line,
        target: Some(target.to_string()),
    })
    .expect("refused")
}

/// RED: no route is the listener's 1.5.5 404, byte for byte (`http.crosscut__unknown-path__bare`).
#[test]
fn red_no_route_is_the_1_5_5_not_found() {
    let (side, _) = side();
    held_to(
        &refuse(&side, REFUSE_NO_ROUTE, LINE_NONE, "/no/such/route"),
        "http.crosscut__unknown-path__bare",
    );
}

/// RED: an over-gate body on a line under the native API's root is 1.5.5's answer there, before
/// any verdict (`http.crosscut__413__api-prefix`).
#[test]
fn red_an_over_gate_body_under_the_native_root_is_the_1_5_5_answer() {
    let (side, guests) = side();
    held_to(
        &refuse(&side, REFUSE_OVER_GATE, ix(&guests, NATIVE), NATIVE),
        "http.crosscut__413__api-prefix",
    );
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
