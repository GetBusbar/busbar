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

use super::{compose_planes, LateServices};
use crate::root::loader::dispatch::{
    load_dropped, rendering_of_library, Bind, DispatchConfig, Dispatcher, NoSink,
};

/// The money steps of a composition: an ungoverned book (a unit that runs here admits nothing that
/// bills), posting abandoned ends onto the process's one node.
pub(super) fn money() -> Arc<PlaneMoney> {
    let gov = Arc::new(GovState::new(Arc::new(MemoryStore::new()), None).expect("governance"));
    Arc::new(PlaneMoney::new(gov, post() as Arc<dyn EndPost>))
}

/// The process's one posting site, over its one node.
pub(super) fn post() -> Arc<NodeEndPost> {
    Arc::new(NodeEndPost::new(crate::root::plane_node::node()))
}

/// THE ADMIN TABLE IS THE PROCESS'S ONE: every test that publishes a plane's admin routes holds
/// this while its plane is published, and withdraws it ([`Published`]) before letting go.
pub(super) static PUBLISHING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A published instance, withdrawn from the admin table when the test lets go of it.
pub(super) struct Published(pub(super) &'static str);

impl Drop for Published {
    fn drop(&mut self) {
        busbar_kernel::plane_driver::serve::withdraw(self.0);
    }
}

/// The test plane's example `cdylib` beside this test binary; `None` where a scoped run did not
/// build it. Under CI a missing artifact is a failure.
fn dropped_path() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let path = exe.parent()?.parent()?.join("examples").join(format!(
        "{}plane_driver_test_plane{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    ));
    let found = path.exists().then_some(path);
    assert!(
        found.is_some() || std::env::var_os("CI").is_none(),
        "the plane_driver_test_plane example cdylib is not built under CI"
    );
    found
}

/// The test plane, dropped in and bound on `dispatcher` as `instance`; `None` where its `cdylib`
/// is not built.
pub(super) fn bound(
    instance: &str,
    dispatcher: &Arc<Dispatcher>,
) -> Option<crate::root::boot::DoorPlane> {
    let path = dropped_path()?;
    let stated = rendering_of_library(&path)
        .expect("the test plane's library reads")
        .expect("the test plane states its Statement");
    let plane = load_dropped(
        &path,
        &stated,
        Bind {
            instance: Arc::from(instance),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: None,
        },
    )
    .expect("the dropped-in door binds");
    Some(plane)
}

pub(super) fn composed_services() -> Arc<LateServices> {
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
    let Some(plane) = bound(instance, &dispatcher) else {
        eprintln!("skip: the test plane's cdylib is not built in this scoped run");
        return;
    };
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
    let Some(plane) = bound(instance, &dispatcher) else {
        eprintln!("skip: the test plane's cdylib is not built in this scoped run");
        return;
    };
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

/// THE RESERVED CORE-OWNED SUB-KEYS, as every one is spelled in a section (spec Part 1, config, :552-554,
/// :565-567; `pools` by the 2026-10-07 ruling).
const RESERVED: [&str; 12] = [
    "breaker",
    "on_exhausted",
    "gates",
    "hooks",
    "upstream_credentials",
    "affinity",
    "tier",
    "repeatable",
    "rate_card",
    "fees",
    "work",
    "pools",
];

/// Every reserved key `blob` carries at the exact depths the strip reads (the section's own level,
/// each registration's), by path.
fn reserved_in(blob: &[u8]) -> Vec<String> {
    let v: serde_json::Value = serde_json::from_slice(blob).expect("the blob is JSON");
    let mut found = Vec::new();
    let Some(top) = v.as_object() else {
        return found;
    };
    for (k, inner) in top {
        if RESERVED.contains(&k.as_str()) {
            found.push(k.clone());
        }
        for key in inner.as_object().into_iter().flat_map(|m| m.keys()) {
            if RESERVED.contains(&key.as_str()) {
                found.push(format!("{k}.{key}"));
            }
        }
    }
    found
}

/// P1b (spec Part 1, config, :561-570, ARCHITECT 2026-10-07): a door plane's settings reach it at `open`
/// and at `refresh`, and its owned sections at `open`, with every reserved core-owned sub-key
/// stripped by the deal's one strip; its pools' `affinity` reaches it only as the kernel's
/// projection beside them. Asserted on the bytes the plane itself recorded at the ABI.
#[test]
fn a_door_planes_open_and_refresh_carry_no_reserved_key() {
    let dir = std::env::temp_dir().join(format!("p1b-crossing-{}", std::process::id()));
    let reserved_block = "breaker: {threshold: 5}\n  on_exhausted: reject\n  gates: [g]\n  \
        hooks: [h]\n  upstream_credentials: own\n  affinity: {header_name: x-section}\n  \
        tier: gold\n  repeatable: [reg1]\n  rate_card: {lane: {input: 1}}\n  \
        fees: {per_request: 3}\n  work: {max_live: 4, retain_s: 10}\n";
    let text = format!(
        "test_plane:\n  capture_to: {dir:?}\n  {reserved_block}  pools:\n    p1:\n      \
         members: [reg1]\n      breaker: {{threshold: 2}}\n      \
         affinity: {{mode: session, header_name: x-user-id}}\n  reg1:\n    \
         url: http://upstream.invalid\n    nested: {{breaker: kept, tier: kept}}\n    \
         breaker: {{threshold: 1}}\n    on_exhausted: reject\n    gates: [g]\n    hooks: [h]\n    \
         upstream_credentials: passthrough\n    affinity: {{header_name: x-reg}}\n    tier: t\n    \
         repeatable: [x]\n    rate_card: {{lane: {{input: 2}}}}\n    fees: {{per_request: 1}}\n    \
         work: {{max_live: 1}}\n    pools: {{q: {{members: [x]}}}}\n\
         test_plane_owned:\n  breaker: {{threshold: 9}}\n  reg:\n    url: http://owned.invalid\n    \
         hooks: [h]\n    tier: t\n"
    );
    let doc: serde_yaml::Mapping = serde_yaml::from_str(&text).expect("the document parses");
    let mut sections = BTreeMap::new();
    for key in ["test_plane", "test_plane_owned"] {
        sections.insert(key, doc.get(key).cloned().expect("written"));
    }
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let instance = "serve-compose-crossing";
    let _one = PUBLISHING.blocking_lock();
    let _published = Published(instance);
    let Some(plane) = bound(instance, &dispatcher) else {
        eprintln!("skip: the test plane's cdylib is not built in this scoped run");
        return;
    };
    let doors = vec![(instance.to_string(), plane)];
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
    .expect("the door plane composes");
    let secrets = busbar_kernel::config::secret::SecretResolver::builtins_only();
    served.planes[0]
        .live
        .refreshed(&sections["test_plane"], 2, &secrets)
        .expect("the door plane refreshes");
    let read = |name: &str| std::fs::read(dir.join(name)).unwrap_or_default();
    let (open, owned, refresh) = (
        read("open.settings"),
        read("open.owned"),
        read("refresh.settings"),
    );
    for (what, blob) in [
        ("open settings", &open),
        ("open owned", &owned),
        ("refresh settings", &refresh),
    ] {
        assert!(!blob.is_empty(), "the plane recorded its {what}");
        assert_eq!(
            reserved_in(blob),
            Vec::<String>::new(),
            "a reserved key reached the plane's {what}: {}",
            String::from_utf8_lossy(blob)
        );
        assert!(
            !String::from_utf8_lossy(blob).contains("affinity"),
            "`affinity` reached the plane's {what}: {}",
            String::from_utf8_lossy(blob)
        );
    }
    // What is not reserved crosses as written, a reserved word below the exact depths included.
    let open: serde_json::Value = serde_json::from_slice(&open).expect("JSON");
    assert_eq!(open["reg1"]["url"], "http://upstream.invalid");
    assert_eq!(open["reg1"]["nested"]["breaker"], "kept");
    let owned: serde_json::Value = serde_json::from_slice(&owned).expect("JSON");
    assert_eq!(
        owned["test_plane_owned"]["reg"]["url"],
        "http://owned.invalid"
    );
    // The pools' affinity crosses beside the settings, as the kernel's projection.
    for tag in ["open", "refresh"] {
        let projected: serde_json::Value =
            serde_json::from_slice(&read(&format!("{tag}.pool_affinity")))
                .unwrap_or(serde_json::Value::Null);
        assert_eq!(
            projected,
            serde_json::json!({"p1": {"header_name": "x-user-id"}}),
            "the {tag} pool affinity projection"
        );
    }
}
