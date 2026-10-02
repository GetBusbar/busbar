// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR PLANES' COMPOSITION (TODO U6-U7, ARCHITECT Q-SW4 2026-10-02), over the test plane
//! linked into this test: a bound plane whose section the deployment writes is opened, driven and
//! its admin routes published; one whose section is absent stays unopened (LAW 7).

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use busbar_contract::abi::plane::UnitCount;
use busbar_kernel::host_services::{KernelServices, SystemResolver};
use busbar_kernel::plane_driver::{CancelBill, Checkpoint, MoneySeam};
use busbar_kernel::teller::{Ended, UnitCtx};

use super::{compose_planes, LateServices};
use crate::root::loader::dispatch::{
    load_linked, Bind, DispatchConfig, Dispatcher, LinkedRow, NoSink,
};

#[path = "../../../tests/fixtures/plane_driver_test_plane.rs"]
#[allow(dead_code)]
mod plane;

/// No money moves in a composition: nothing runs a unit.
struct NoUnits;

impl MoneySeam for NoUnits {
    fn checkpoint(&self, _: &UnitCtx, _: &[UnitCount]) -> Checkpoint {
        Checkpoint::Continue
    }
    fn cancelled(&self, _: &UnitCtx, _: &CancelBill) {}
    fn abandoned(&self, _: &UnitCtx, _: Ended) {}
}

/// The test plane, bound through its linked door on `dispatcher` as `instance`.
fn bound(instance: &str, dispatcher: &Arc<Dispatcher>) -> crate::root::linked::DoorPlane {
    let row = LinkedRow::of(plane::door).expect("the plane states its Statement");
    load_linked(
        &row,
        Bind {
            instance: Arc::from(instance),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: None,
        },
    )
    .expect("the linked door binds")
}

fn composed_services() -> Arc<LateServices> {
    let late = LateServices::new();
    late.install_kernel(Arc::new(KernelServices::new(
        HashMap::new(),
        Arc::new(SystemResolver),
    )))
    .expect("installed once");
    late
}

/// An admin request on the admin router's plane table: its status, or `None` (the router's 404).
fn admin(path: &str) -> Option<u16> {
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("{}{path}", busbar_kernel::api::ADMIN_PREFIX))
        .body(axum::body::Body::from("go"))
        .expect("a request");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    rt.block_on(async {
        busbar_kernel::plane_driver::serve::answer(req)
            .await
            .map(|r| r.status().as_u16())
    })
}

#[test]
fn a_configured_door_plane_is_opened_driven_and_its_admin_routes_published() {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let instance = "serve-compose-configured";
    let doors = vec![(instance.to_string(), bound(instance, &dispatcher))];
    let mut sections = BTreeMap::new();
    sections.insert("test_plane", serde_yaml::Value::Mapping(Default::default()));
    let late = composed_services();
    let served = compose_planes(&doors, &dispatcher, &late, &sections, &|| {
        Arc::new(NoUnits) as Arc<dyn MoneySeam>
    })
    .expect("the door plane composes");
    assert_eq!(served.planes.len(), 1, "one plane composed");
    let p = &served.planes[0];
    assert_eq!(p.instance, instance);
    let claims: Vec<(&str, &str)> = p
        .snapshot
        .claims
        .iter()
        .map(|c| (c.verb.as_str(), c.target.as_str()))
        .collect();
    assert_eq!(claims, [("POST", "/call")], "its open published its claims");
    assert_eq!(
        admin("/items/composed/act"),
        Some(200),
        "its audited admin route is served by its `serve` op"
    );
    assert_eq!(
        admin("/items/composed/hook"),
        None,
        "a public route is never on the admin table"
    );
    busbar_kernel::plane_driver::serve::withdraw(instance);
}

#[test]
fn a_door_plane_whose_section_is_absent_stays_unopened() {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let instance = "serve-compose-unconfigured";
    let doors = vec![(instance.to_string(), bound(instance, &dispatcher))];
    let late = composed_services();
    let served = compose_planes(&doors, &dispatcher, &late, &BTreeMap::new(), &|| {
        Arc::new(NoUnits) as Arc<dyn MoneySeam>
    })
    .expect("nothing to compose is not a refusal");
    assert!(served.planes.is_empty(), "LAW 7: no section, no plane");
}

#[test]
fn no_door_plane_composes_nothing_and_needs_no_services() {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let served = compose_planes(
        &[],
        &dispatcher,
        &LateServices::new(),
        &BTreeMap::new(),
        &|| Arc::new(NoUnits) as Arc<dyn MoneySeam>,
    )
    .expect("an empty composition");
    assert!(served.planes.is_empty());
}
