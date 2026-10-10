// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR PLANES' COMPOSITION (TODO U6-U7, ARCHITECT Q-SW4 2026-10-02), over the test plane
//! dropped in (its `plane_driver_test_plane` example `cdylib`, admitted against the Statement its
//! own library states; the binary forbids unsafe code, so the fixture's source is never compiled
//! into it): a bound plane whose section the deployment writes is opened, driven and its admin
//! routes published; one whose section is absent stays unopened (LAW 7).

use std::collections::BTreeMap;
use std::sync::Arc;

use busbar_kernel::governance::{GovState, MemoryStore};
use busbar_kernel::host_services::KernelServices;
use busbar_kernel::plane_driver::{EndPost, PlaneMoney};

use crate::root::plane_node::NodeEndPost;
use crate::root::test_plugins::{missing, BUILD_BUSBAR_EXAMPLES};

use super::{compose_planes, LateServices};
use crate::root::loader::dispatch::{
    load_dropped, rendering_of_library, Bind, DispatchConfig, Dispatcher, NoSink,
};

/// The money steps of a composition: an ungoverned book (a unit that runs here admits nothing that
/// bills), posting abandoned ends onto the process's one node.
pub(crate) fn money() -> Arc<PlaneMoney> {
    let gov = Arc::new(GovState::new(Arc::new(MemoryStore::new()), None).expect("governance"));
    Arc::new(PlaneMoney::new(gov, post() as Arc<dyn EndPost>))
}

/// The process's one posting site, over its one node.
pub(super) fn post() -> Arc<NodeEndPost> {
    Arc::new(NodeEndPost::new(crate::root::plane_node::node()))
}

/// THE ADMIN TABLE IS THE PROCESS'S ONE: every test that publishes a plane's admin routes holds
/// this while its plane is published, and withdraws it ([`Published`]) before letting go.
pub(crate) static PUBLISHING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A published instance, withdrawn from the admin table when the test lets go of it.
pub(crate) struct Published(pub(crate) &'static str);

impl Drop for Published {
    fn drop(&mut self) {
        busbar_kernel::plane_driver::serve::withdraw(self.0);
    }
}

/// The test plane's example `cdylib` beside this test binary. Not built is a failure in every run,
/// never a skip: a composition proof without its plane proves nothing.
fn dropped_path() -> std::path::PathBuf {
    let name = "plane_driver_test_plane";
    let exe = std::env::current_exe().expect("the test binary's path");
    let path = exe
        .parent()
        .and_then(|deps| deps.parent())
        .expect("the test binary sits in target/<profile>/deps")
        .join("examples")
        .join(format!(
            "{}{name}{}",
            std::env::consts::DLL_PREFIX,
            std::env::consts::DLL_SUFFIX
        ));
    if !path.exists() {
        missing(name, BUILD_BUSBAR_EXAMPLES);
    }
    path
}

/// The test plane, dropped in and bound on `dispatcher` as `instance`.
pub(super) fn bound(instance: &str, dispatcher: &Arc<Dispatcher>) -> crate::root::boot::DoorPlane {
    let path = dropped_path();
    let stated = rendering_of_library(&path)
        .expect("the test plane's library reads")
        .expect("the test plane states its Statement");
    load_dropped(
        &path,
        &stated,
        Bind {
            instance: Arc::from(instance),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            // These rows never dial (the plane's far end is not reached): its need is not
            // declared, bound as a probe.
            conns: crate::root::loader::dispatch::ConnTable::Probe,
        },
    )
    .expect("the dropped-in door binds")
}

pub(crate) fn composed_services() -> Arc<LateServices> {
    let late = LateServices::new();
    let kernel = Arc::new(KernelServices::new());
    late.install_kernel(Arc::clone(&kernel), kernel)
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
    let _one = PUBLISHING.blocking_lock();
    let _published = Published(instance);
    let plane = bound(instance, &dispatcher);
    let doors = vec![(instance.to_string(), plane)];
    let mut sections = BTreeMap::new();
    sections.insert("test_plane", serde_yaml::Value::Mapping(Default::default()));
    let late = composed_services();
    let served = compose_planes(
        &doors,
        &dispatcher,
        &late,
        &sections,
        None,
        &money,
        None,
        None,
    )
    .expect("the door plane composes (the plane_driver_test_plane example cdylib, current: run `cargo build --workspace --examples`)");
    assert_eq!(served.planes.len(), 1, "one plane composed");
    let p = &served.planes[0];
    assert_eq!(p.instance, instance);
    let claims: Vec<(&str, &str)> = p
        .snapshot
        .claims
        .iter()
        .map(|c| (c.verb.as_str(), c.target.as_str()))
        .collect();
    assert_eq!(
        claims,
        [("POST", "/call"), ("POST", "/open"), ("POST", "/framed")],
        "its open published its claims"
    );
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
}

#[test]
fn a_door_plane_whose_section_is_absent_stays_unopened() {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let instance = "serve-compose-unconfigured";
    let plane = bound(instance, &dispatcher);
    let doors = vec![(instance.to_string(), plane)];
    let late = composed_services();
    let served = compose_planes(
        &doors,
        &dispatcher,
        &late,
        &BTreeMap::new(),
        None,
        &money,
        None,
        None,
    )
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
        None,
        &money,
        None,
        None,
    )
    .expect("an empty composition");
    assert!(served.planes.is_empty());
}

/// RED, THE DIALECT FACTS AT OPEN (THE DESIGN §4: a plane receives, at open, the dialect fields of
/// the providers it references): the providers its section's `models.<m>.provider` entries name,
/// once each in the order first referenced, cross `PlaneOpenIn::providers` with their resolved
/// `protocol` and `error_map` (absent when none). An unreferenced provider is not handed, and a
/// section that references none hands none. The test plane echoes what it was handed.
#[test]
fn a_door_plane_is_handed_its_referenced_providers_dialect_facts_at_open() {
    use crate::root::door_steps::{dialect_facts, ProviderRoute, StyleParams};
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let plane = bound("serve-open-dialect-facts", &dispatcher);
    // The kernel's host services the plane's open is handed, as a composition installs them.
    let _late = composed_services();
    let route = |protocol: &str, error_map: &[(&str, &str)]| ProviderRoute {
        base_url: "http://127.0.0.1:9".to_string(),
        protocol: protocol.to_string(),
        error_map: error_map
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect(),
        credential: busbar_contract::secret_ref::SecretRef::none(),
        style: None,
        params: StyleParams::default(),
    };
    let providers: BTreeMap<String, ProviderRoute> = [
        ("eng-b".to_string(), route("dial-two", &[])),
        (
            "eng-a".to_string(),
            route("dial-one", &[("429", "rate_limited")]),
        ),
        ("unused".to_string(), route("dial-one", &[])),
    ]
    .into_iter()
    .collect();
    let section: serde_yaml::Value = serde_yaml::from_str(
        "models:\n  m1: {provider: eng-a}\n  m2: {provider: eng-b}\n  m3: {provider: eng-a}\n",
    )
    .expect("a section");
    let facts = dialect_facts(&section, &providers);
    let names: Vec<&str> = facts.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["eng-a", "eng-b"], "referenced, once each, in order");
    let snapshot =
        super::open(&plane, &section, None, &Default::default(), &facts).expect("the door opens");
    let handed: serde_json::Value = serde_json::from_slice(
        snapshot
            .resource_facts
            .as_deref()
            .expect("the plane was handed its providers' facts"),
    )
    .expect("JSON");
    assert_eq!(
        handed,
        serde_json::json!([
            ["eng-a", "dial-one", {"429": "rate_limited"}],
            ["eng-b", "dial-two", null]
        ])
    );
    let none = dialect_facts(&serde_yaml::Value::Null, &providers);
    assert!(none.is_empty(), "a section that references none hands none");
    // A second instance (an instance opens once): a section that references none is handed none.
    let plane = bound("serve-open-dialect-none", &dispatcher);
    let snapshot = super::open(
        &plane,
        &serde_yaml::Value::Null,
        None,
        &Default::default(),
        &none,
    )
    .expect("the door opens");
    assert_eq!(snapshot.resource_facts, None);
}

/// THE RED ARM OF "NEVER SKIPS": a fixture that is not built fails the test, naming what builds it.
#[test]
#[should_panic(expected = "is not built: run")]
fn a_missing_fixture_cdylib_fails_the_test_and_names_its_build() {
    missing("no_such_fixture", BUILD_BUSBAR_EXAMPLES);
}
