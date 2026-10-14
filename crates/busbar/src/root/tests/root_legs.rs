// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ROOT LEGS, RUN OVER THE LINKED ROSTER FROM EACH PLANE'S OWN TABLE (ARCHITECT ruling, Law 0
//! root lane, option A; BUSBAR-1.6.0.md K3/S10: cross-plane tests run black-box and iterate the
//! linked roster from each plane's declared data).
//!
//! A root leg of `qa/capability-equality.json` proves a capability reaches a REAL linked plane
//! through the composition root. The root names no plane, so the plane states its scenario as data —
//! its `testkit::ROOT_LEG`, a JSON table behind its `test-support` feature — and the root drives every
//! linked plane door through its own table:
//!
//! - `[package.metadata.busbar.root-leg]` (the root's manifest: packaging may name its plugins) maps
//!   a linked plane-door row to the crate declaring its table; `build.rs` writes `ROOT_LEGS`, every
//!   enabled plane-door row with its door and its table, or none.
//! - [`pair`] refuses a linked plane door with no table: a root leg is never skipped.
//! - [`RootLeg::not_applicable_agrees`] holds a table's `not_applicable` entries to the ledger: each is
//!   a capability the ledger itself marks not applicable on that plane's root leg, for the same
//!   reason. A plane cannot opt out of a capability the ledger says it has.
//! - [`served`] drives a table's request through the composition (`compose_planes`, `door_routes`, the
//!   data router) and holds the answer to the table's expectation.
//!
//! The in-tree fixture plane (`plane_driver_test_plane`, dropped in) carries the table this file
//! drives today (`fixtures/root_leg_test_plane.json`); each linked plane's table pins in through its
//! own `testkit::ROOT_LEG`.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::Value;

use busbar_contract::abi::mechanism::door::DoorFn;
use busbar_kernel::cost::CostModel;
use busbar_kernel::governance::signing::{TokenSigner, DEFAULT_KID};
use busbar_kernel::governance::{GovState, MemoryStore, NewKeySpec};
use busbar_kernel::plane_driver::{EndPost, PlaneMoney};

use super::planes_tests::{bound, composed_services, Published, PUBLISHING};
use super::{compose_planes, door_routes};
use crate::root::loader::dispatch::{DispatchConfig, Dispatcher};
use crate::root::plane_node::{Node, NodeEndPost};

include!(concat!(env!("OUT_DIR"), "/root_legs.rs"));

/// The capability-equality ledger the `not_applicable` entries answer to.
const LEDGER: &str = include_str!("../../../../../qa/capability-equality.json");

/// The fixture plane's root-leg table: the in-tree double's own scenario, as a linked plane states
/// its `testkit::ROOT_LEG`.
const FIXTURE_LEG: &str = include_str!("fixtures/root_leg_test_plane.json");

/// One caller request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Call {
    pub(super) method: String,
    pub(super) path: String,
    pub(super) headers: Vec<(String, String)>,
    pub(super) body: String,
}

// The cells beyond the served one read these fields as each linked plane's table pins in.
#[allow(dead_code)]
/// One far-end reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Reply {
    pub(super) status: u16,
    pub(super) headers: Vec<(String, String)>,
    pub(super) body: String,
}

/// What a caller must get back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Expect {
    pub(super) status: u16,
    pub(super) body_contains: Vec<String>,
}

// The cells beyond the served one read these fields as each linked plane's table pins in.
#[allow(dead_code)]
/// A capability cell that needs more than the table's common fields. Capability-generic only: a
/// cell one plane alone could use belongs in that plane's own suite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Cell {
    /// The caller's catalogue: the listing a grant sees.
    Catalogue { list: Call, sees: Vec<String> },
    /// Trust pinning: the listing before and after it moves, and the refusal that follows.
    TrustPinning {
        listing_before: Reply,
        listing_after: Reply,
        refused: Expect,
    },
    /// A rewrite hook: the JSON pointer of the argument it changes.
    HookRewrite { field: String },
    /// The plane's argument guard: a call it refuses before anything is sent.
    ArgumentGuard { call: Call, refused: Expect },
    /// Failover: a section naming two members.
    Failover { pool_members: String },
}

// The cells beyond the served one read these fields as each linked plane's table pins in.
#[allow(dead_code)]
/// ONE PLANE'S ROOT-LEG TABLE, as its `testkit::ROOT_LEG` states it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RootLeg {
    /// Its capability-equality columns.
    pub(super) columns: Vec<String>,
    /// Its configuration section (placeholders `{far_end}`, `{credential_file}`).
    pub(super) section: String,
    /// The `providers:` its members name, same placeholders.
    pub(super) providers: String,
    /// The request the caller sends.
    pub(super) request: Call,
    /// The far end's success, transient failure and client fault.
    pub(super) far_end: (Reply, Reply, Reply),
    /// What the caller gets back when it is served.
    pub(super) served: Expect,
    /// The unit classes the far end's success reports, as the book records them.
    pub(super) units: Vec<(String, u64)>,
    /// The op class a served unit is audited under.
    pub(super) op_class: String,
    /// The cells beyond the common fields.
    pub(super) cells: Vec<Cell>,
    /// `(capability, reason)`: what the plane's root leg does not owe.
    pub(super) not_applicable: Vec<(String, String)>,
}

/// `value`'s object, every key one of `known` (an unknown key is a misspelt field, refused).
fn object<'a>(
    value: &'a Value,
    what: &str,
    known: &[&str],
) -> Result<&'a serde_json::Map<String, Value>, String> {
    let map = value
        .as_object()
        .ok_or_else(|| format!("{what}: not an object"))?;
    if let Some(unknown) = map.keys().find(|k| !known.contains(&k.as_str())) {
        return Err(format!("{what}: unknown field `{unknown}`"));
    }
    Ok(map)
}

fn text(map: &serde_json::Map<String, Value>, what: &str, key: &str) -> Result<String, String> {
    map.get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("{what}.{key}: a string is required"))
}

fn status(map: &serde_json::Map<String, Value>, what: &str) -> Result<u16, String> {
    map.get("status")
        .and_then(Value::as_u64)
        .and_then(|n| u16::try_from(n).ok())
        .ok_or_else(|| format!("{what}.status: a status is required"))
}

fn texts(
    map: &serde_json::Map<String, Value>,
    what: &str,
    key: &str,
) -> Result<Vec<String>, String> {
    match map.get(key) {
        None => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| format!("{what}.{key}: strings only"))
            })
            .collect(),
        Some(_) => Err(format!("{what}.{key}: a list is required")),
    }
}

fn pairs(
    map: &serde_json::Map<String, Value>,
    what: &str,
    key: &str,
) -> Result<Vec<(String, String)>, String> {
    match map.get(key) {
        None => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| match v.as_array().map(Vec::as_slice) {
                Some([Value::String(a), Value::String(b)]) => Ok((a.clone(), b.clone())),
                _ => Err(format!("{what}.{key}: `[name, value]` pairs only")),
            })
            .collect(),
        Some(_) => Err(format!("{what}.{key}: a list is required")),
    }
}

fn call(value: &Value, what: &str) -> Result<Call, String> {
    let map = object(value, what, &["method", "path", "headers", "body"])?;
    Ok(Call {
        method: text(map, what, "method")?,
        path: text(map, what, "path")?,
        headers: pairs(map, what, "headers")?,
        body: text(map, what, "body")?,
    })
}

fn reply(value: &Value, what: &str) -> Result<Reply, String> {
    let map = object(value, what, &["status", "headers", "body"])?;
    Ok(Reply {
        status: status(map, what)?,
        headers: pairs(map, what, "headers")?,
        body: text(map, what, "body")?,
    })
}

fn expect(value: &Value, what: &str) -> Result<Expect, String> {
    let map = object(value, what, &["status", "body_contains"])?;
    Ok(Expect {
        status: status(map, what)?,
        body_contains: texts(map, what, "body_contains")?,
    })
}

fn field<'a>(
    map: &'a serde_json::Map<String, Value>,
    what: &str,
    key: &str,
) -> Result<&'a Value, String> {
    map.get(key)
        .ok_or_else(|| format!("{what}.{key}: required"))
}

fn cell(value: &Value) -> Result<Cell, String> {
    let kind = value
        .get("cell")
        .and_then(Value::as_str)
        .ok_or("cells[]: a `cell` name is required")?;
    let what = format!("cells[{kind}]");
    let what = what.as_str();
    match kind {
        "catalogue" => {
            let map = object(value, what, &["cell", "list", "sees"])?;
            Ok(Cell::Catalogue {
                list: call(field(map, what, "list")?, what)?,
                sees: texts(map, what, "sees")?,
            })
        }
        "trust-pinning" => {
            let map = object(
                value,
                what,
                &["cell", "listing_before", "listing_after", "refused"],
            )?;
            Ok(Cell::TrustPinning {
                listing_before: reply(field(map, what, "listing_before")?, what)?,
                listing_after: reply(field(map, what, "listing_after")?, what)?,
                refused: expect(field(map, what, "refused")?, what)?,
            })
        }
        "hook-rewrite" => {
            let map = object(value, what, &["cell", "field"])?;
            Ok(Cell::HookRewrite {
                field: text(map, what, "field")?,
            })
        }
        "argument-guard" => {
            let map = object(value, what, &["cell", "call", "refused"])?;
            Ok(Cell::ArgumentGuard {
                call: call(field(map, what, "call")?, what)?,
                refused: expect(field(map, what, "refused")?, what)?,
            })
        }
        "failover" => {
            let map = object(value, what, &["cell", "pool_members"])?;
            Ok(Cell::Failover {
                pool_members: text(map, what, "pool_members")?,
            })
        }
        other => Err(format!("cells[]: `{other}` is no capability cell")),
    }
}

impl RootLeg {
    /// A plane's `testkit::ROOT_LEG`, read; `Err` names the field it cannot read.
    pub(super) fn parse(json: &str) -> Result<Self, String> {
        let doc: Value = serde_json::from_str(json).map_err(|e| format!("not JSON: {e}"))?;
        let what = "root-leg";
        let map = object(
            &doc,
            what,
            &[
                "columns",
                "section",
                "providers",
                "request",
                "far_end",
                "served",
                "units",
                "op_class",
                "cells",
                "not_applicable",
            ],
        )?;
        let far = object(
            field(map, what, "far_end")?,
            "far_end",
            &["ok", "transient", "client_fault"],
        )?;
        let units = match field(map, what, "units")? {
            Value::Array(items) => items
                .iter()
                .map(|v| match v.as_array().map(Vec::as_slice) {
                    Some([Value::String(class), Value::Number(n)]) => n
                        .as_u64()
                        .map(|n| (class.clone(), n))
                        .ok_or_else(|| "units: a count is a whole number".to_string()),
                    _ => Err("units: `[class, count]` pairs only".to_string()),
                })
                .collect::<Result<Vec<_>, _>>()?,
            _ => return Err("units: a list is required".to_string()),
        };
        let cells = match map.get("cells") {
            None => Vec::new(),
            Some(Value::Array(items)) => items.iter().map(cell).collect::<Result<Vec<_>, _>>()?,
            Some(_) => return Err("cells: a list is required".to_string()),
        };
        Ok(Self {
            columns: texts(map, what, "columns")?,
            section: text(map, what, "section")?,
            providers: text(map, what, "providers")?,
            request: call(field(map, what, "request")?, "request")?,
            far_end: (
                reply(field(far, "far_end", "ok")?, "far_end.ok")?,
                reply(field(far, "far_end", "transient")?, "far_end.transient")?,
                reply(
                    field(far, "far_end", "client_fault")?,
                    "far_end.client_fault",
                )?,
            ),
            served: expect(field(map, what, "served")?, "served")?,
            units,
            op_class: text(map, what, "op_class")?,
            cells,
            not_applicable: pairs(map, what, "not_applicable")?,
        })
    }

    /// EVERY `not_applicable` ENTRY IS THE LEDGER'S OWN: a cell of `ledger` (capability-equality's
    /// shape) on one of this table's columns, for that capability, whose root verdict is
    /// `not-applicable` with the same reason. `Err` names the entry the ledger does not back.
    pub(super) fn not_applicable_agrees(&self, ledger: &Value) -> Result<(), String> {
        let cells = ledger
            .get("cells")
            .and_then(Value::as_array)
            .ok_or("the ledger has no `cells`")?;
        for (capability, reason) in &self.not_applicable {
            let backed = cells.iter().any(|c| {
                let root = c.get("root");
                c.get("capability").and_then(Value::as_str) == Some(capability.as_str())
                    && c.get("plane")
                        .and_then(Value::as_str)
                        .is_some_and(|p| self.columns.iter().any(|col| col == p))
                    && root.and_then(|r| r.get("state")).and_then(Value::as_str)
                        == Some("not-applicable")
                    && root.and_then(|r| r.get("reason")).and_then(Value::as_str)
                        == Some(reason.as_str())
            });
            if !backed {
                return Err(format!(
                    "`{capability}` is declared not applicable (\"{reason}\"), but no ledger cell \
                     on {:?} marks its root leg not applicable for that reason",
                    self.columns
                ));
            }
        }
        Ok(())
    }
}

/// EVERY LINKED PLANE DOOR WITH ITS TABLE, in roster order: `rows` as `ROOT_LEGS` states them. A
/// door with no table is refused, naming its row — a root leg is never skipped — and so is a table
/// that does not read.
pub(super) fn pair<'a>(
    rows: &[(&'a str, DoorFn, Option<&str>)],
) -> Result<Vec<(&'a str, DoorFn, RootLeg)>, String> {
    rows.iter()
        .map(|&(row, door, table)| {
            let table = table.ok_or_else(|| {
                format!(
                    "the linked plane door `{row}` declares no root-leg table (`testkit::ROOT_LEG`): \
                     its root leg cannot run"
                )
            })?;
            RootLeg::parse(table)
                .map(|leg| (row, door, leg))
                .map_err(|e| format!("the linked plane door `{row}`'s root-leg table: {e}"))
        })
        .collect()
}

/// THE SERVED CELL: `plane` (bound on `dispatcher`, its instance `instance`) composed with the
/// table's section, its claims mounted on a data router, and the table's request sent as a keyed
/// caller; the answer is held to the table's `served`, and the request is on the governance book.
pub(super) async fn served(
    instance: &'static str,
    plane: crate::root::boot::DoorPlane,
    dispatcher: &Arc<Dispatcher>,
    services: &Arc<super::LateServices>,
    leg: &RootLeg,
) {
    use tower::ServiceExt as _;
    let signer = TokenSigner::from_secret_bytes(&[11u8; 32], DEFAULT_KID);
    let gov = Arc::new(
        GovState::new_with_signer(Arc::new(MemoryStore::new()), None, Some(signer))
            .expect("governance"),
    );
    let (key, token) = gov
        .mint_signed(
            NewKeySpec {
                name: "root-leg".to_string(),
                ..Default::default()
            },
            4_000_000_000,
            1_700_000_000,
        )
        .expect("mint");
    let cost = CostModel::flat(1);
    gov.hydrate_budgets(&cost, 0).expect("hydrate");
    // The node's one book, as the boot binds it: every unit's one line and its audit record.
    let book_of_node = Arc::new(std::sync::Mutex::new(
        crate::root::durability::build(
            &crate::root::durability::DurabilityConfig { data_dir: None },
            Box::new(busbar_kernel_wal::NullShipper::new()),
            Box::new(busbar_kernel_ledger::legacy::RecordingRows::new()),
        )
        .expect("a memory-buffered journal opens"),
    ));
    let node = Arc::new(Node::new());
    node.bind_book(book_of_node);
    let post = Arc::new(NodeEndPost::new(node));
    let book = Arc::clone(&gov);
    let site = Arc::clone(&post);
    let money = move || {
        Arc::new(PlaneMoney::new(
            Arc::clone(&book),
            Arc::clone(&site) as Arc<dyn EndPost>,
        ))
    };
    let mut sections = BTreeMap::new();
    sections.insert(
        plane.served().section,
        serde_yaml::from_str(&leg.section).expect("the table's section is YAML"),
    );
    let mut composed = compose_planes(
        &[(instance.to_string(), plane)],
        dispatcher,
        services,
        &sections,
        None,
        &money,
        None,
        None,
    )
    .expect("the plane composes with its table's section");
    composed.post = Some(Arc::clone(&post));
    let routes = door_routes(composed, || crate::root::kernel::ROOT_CARD.pin(), &[], &[])
        .expect("its claims mount");
    let app = busbar_kernel::test_support::TestApp::new()
        .governance(Arc::clone(&gov))
        .cost(cost)
        .build();
    let (router, _admin, _handle) =
        busbar_kernel::build_split_routers_serving(Arc::clone(&app), routes, 1 << 20, 0, false);

    let mut req = axum::http::Request::builder()
        .method(leg.request.method.as_str())
        .uri(leg.request.path.as_str())
        .header("authorization", format!("Bearer {}", token.expose_secret()));
    for (name, value) in &leg.request.headers {
        req = req.header(name.as_str(), value.as_str());
    }
    let req = req
        .body(axum::body::Body::from(leg.request.body.clone()))
        .expect("the table's request");
    let response = router.oneshot(req).await.expect("the router answers");
    let got = response.status().as_u16();
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("the body");
    let body = String::from_utf8_lossy(&body);
    assert_eq!(got, leg.served.status, "served through the door: {body}");
    for part in &leg.served.body_contains {
        assert!(
            body.contains(part.as_str()),
            "`{part}` in the answer: {body}"
        );
    }
    let usage = gov
        .usage_for(&app.cost, &key.id, busbar_kernel::store::now())
        .expect("a read")
        .expect("the key exists");
    assert_eq!(
        usage.requests, 1,
        "the served request is on the governance book"
    );
}

/// A roster row's door, for the pairing alone: [`pair`] never opens a door.
extern "C" fn no_door() -> *const busbar_contract::abi::mechanism::door::Door {
    std::ptr::null()
}

/// A ROSTER ROW WITH NO TABLE IS REFUSED, NAMING IT — the RED of the no-silent-skip rule: a linked
/// plane door whose plane declares no root-leg table fails its root leg rather than passing it.
#[test]
fn a_linked_plane_door_declaring_no_table_fails_its_root_leg() {
    let rows = [
        ("with-table", no_door as DoorFn, Some(FIXTURE_LEG)),
        ("without-table", no_door as DoorFn, None),
    ];
    let refusal = pair(&rows).expect_err("a door with no table is never skipped");
    assert!(refusal.contains("`without-table`"), "{refusal}");
    assert!(refusal.contains("declares no root-leg table"), "{refusal}");
    let paired = pair(&rows[..1]).expect("a door with its table pairs");
    assert_eq!(paired.len(), 1);
    assert_eq!(paired[0].0, "with-table");
}

/// A TABLE THAT DOES NOT READ IS REFUSED, naming the row and the field: a misspelt field is an
/// unknown one, never ignored.
#[test]
fn a_table_that_does_not_read_is_refused_naming_its_field() {
    let misspelt = FIXTURE_LEG.replacen("\"op_class\"", "\"op_klass\"", 1);
    let refusal = RootLeg::parse(&misspelt).expect_err("an unknown field");
    assert!(refusal.contains("op_klass"), "{refusal}");
    let rows = [("misspelt", no_door as DoorFn, Some(misspelt.as_str()))];
    let refusal = pair(&rows).expect_err("refused at the pairing");
    assert!(refusal.contains("`misspelt`"), "{refusal}");
}

/// NOT APPLICABLE IS NEVER A FREE PASS: an entry the ledger backs (a cell on the table's column,
/// for that capability, whose root verdict is not applicable for the same reason) agrees; the same
/// capability with another reason, or one the ledger says the plane HAS, is refused.
#[test]
fn a_not_applicable_entry_must_be_the_ledgers_own() {
    let ledger: Value = serde_json::json!({ "cells": [
        { "capability": "net-guard", "plane": "p-client",
          "root": { "state": "not-applicable", "leg": "root-p", "reason": "it dials nothing" } },
        { "capability": "breaker-trip", "plane": "p-client",
          "root": { "state": "proven", "leg": "root-p", "test": "x::y" } },
    ]});
    let mut leg = RootLeg::parse(FIXTURE_LEG).expect("the fixture table reads");
    leg.columns = vec!["p-client".to_string()];
    leg.not_applicable = vec![("net-guard".to_string(), "it dials nothing".to_string())];
    leg.not_applicable_agrees(&ledger)
        .expect("the ledger backs it");

    leg.not_applicable = vec![("net-guard".to_string(), "another reason".to_string())];
    let refusal = leg
        .not_applicable_agrees(&ledger)
        .expect_err("a reason the ledger does not give");
    assert!(refusal.contains("net-guard"), "{refusal}");

    leg.not_applicable = vec![("breaker-trip".to_string(), "it dials nothing".to_string())];
    leg.not_applicable_agrees(&ledger)
        .expect_err("a capability the ledger says the plane has");
}

/// The roster table covers every linked plane door, one row each, and the ledger reads.
#[test]
fn the_roster_table_is_every_linked_plane_door() {
    assert_eq!(ROOT_LEGS.len(), crate::LINKED.plane_doors.len());
    let ledger: Value = serde_json::from_str(LEDGER).expect("the ledger is JSON");
    assert!(ledger.get("cells").and_then(Value::as_array).is_some());
}

/// THE FIXTURE PLANE'S ROOT LEG, DRIVEN FROM ITS OWN TABLE: its table reads, its `not_applicable`
/// agrees with the ledger's shape, and its served cell runs through the composition root.
#[tokio::test]
async fn the_fixture_plane_is_served_through_the_root_from_its_own_table() {
    let leg = RootLeg::parse(FIXTURE_LEG).expect("the fixture table reads");
    let ledger: Value = serde_json::from_str(LEDGER).expect("the ledger is JSON");
    leg.not_applicable_agrees(&ledger)
        .expect("the fixture opts out of nothing the ledger does not");
    let _one = PUBLISHING.lock().await;
    let instance = "root-leg-fixture";
    let _published = Published(instance);
    let services = composed_services();
    let dispatcher = Arc::new(Dispatcher::with_services(
        DispatchConfig::default(),
        Arc::clone(&services) as Arc<dyn busbar_contract::services::HostServices>,
    ));
    let plane = bound(instance, &dispatcher);
    served(instance, plane, &dispatcher, &services, &leg).await;
}
