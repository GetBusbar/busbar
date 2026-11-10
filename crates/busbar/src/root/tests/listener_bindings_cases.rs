// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::mechanism::door::{Door, DoorFn};
use busbar_contract::abi::sdk::test_support::RestatedTransport;
use busbar_contract::abi::transport::listener_bindings::EXT_LISTENER_BINDINGS;
use busbar_core_connector::framer::FramerDoor;

fn configured(data: &str) -> ListenerNeeds {
    crate::dist_root_install::install();
    let deploy = busbar_kernel::config::deploy_from_yaml_str(&format!(
        "store: {{module: memory}}\nauth: {{chain: [], admin_auth: []}}\nproviders: {{}}\nmodels: {{}}\n{data}"
    ))
    .expect("the listener configuration parses");
    let cfg = busbar_kernel::config::resolve(&deploy, &Default::default()).unwrap();
    crate::root::boot::configured_listener_needs(&cfg, &Default::default()).unwrap()
}

fn actual_http() -> DoorFn {
    crate::dist_root_install::install();
    crate::LINKED_TRANSPORT_DOORS
        .iter()
        .find_map(|(_, door)| {
            crate::root::loader::dispatch::kinds::transport::stated(*door)
                .unwrap()
                .claims
                .contains(&"http")
                .then_some(*door)
        })
        .expect("the assembled product supplies its actual HTTP declaration")
}

// Keep the actual operation table and OPEN lifecycle. Only immutable declaration data is
// restated, then admitted by the ordinary loader, so no host protocol table selects the bind.
fn restated(cell: &RestatedTransport, binding: bool) -> &'static Door {
    let source = busbar_transport_http::MACRO_DOOR;
    let facts = crate::root::loader::dispatch::kinds::transport::stated(source.door_fn()).unwrap();
    assert!(
        facts.claims.len() >= 2,
        "the actual product has claim aliases"
    );
    let claims: Vec<_> = (0..facts.claims.len())
        .map(|index| match index {
            0 => "third-a".into(),
            1 => "third-b".into(),
            _ => format!("third-extra-{index}"),
        })
        .collect::<Vec<String>>();
    let names: Vec<_> = claims.iter().map(String::as_str).collect();
    let mapping = br#"[{"slot":"listen","claim":"third-b"}]"#;
    cell.get_or_init(
        source,
        &names,
        &[(EXT_LISTENER_BINDINGS, binding.then_some(mapping.as_slice()))],
    )
}

extern "C" fn third_binding() -> &'static Door {
    static CELL: RestatedTransport = RestatedTransport::new();
    restated(&CELL, true)
}

extern "C" fn third_without_binding() -> &'static Door {
    static CELL: RestatedTransport = RestatedTransport::new();
    restated(&CELL, false)
}

fn opened(doors: &[DoorFn]) -> Vec<Arc<dyn FramerDoor>> {
    let late = crate::root::serve::LateServices::new();
    let dispatcher = Arc::new(crate::root::dispatch::build(2, &late));
    let rows: Vec<_> = doors
        .iter()
        .map(|door| ("listener-fixture", *door))
        .collect();
    crate::root::connector::entries_on(
        &dispatcher,
        &rows,
        &crate::root::policy::client_settings(&Default::default()),
    )
    .expect("the actual transport operation table opens through the ordinary loader")
    .into_iter()
    .map(|entry| entry.door)
    .collect()
}

fn declared_plan(topology: ListenerNeeds, doors: Vec<Arc<dyn FramerDoor>>) -> Arc<ListenerPlan> {
    let offers = doors
        .iter()
        .flat_map(|door| {
            door.facts()
                .claims
                .iter()
                .map(|claim| (*claim, AuthPoints::HEAD))
        })
        .collect();
    Arc::new(ListenerPlan::new(topology, offers, &move |claim| {
        doors
            .iter()
            .find(|door| door.facts().claims.contains(&claim))
            .cloned()
    }))
}

#[tokio::test]
async fn implicit_zero_data_configuration_keeps_admin_without_a_data_listener() {
    let topology = configured("");
    assert!(!topology.root_required);
    assert!(topology.needs.is_empty());
    let plan = declared_plan(topology.clone(), Vec::new());
    assert!(!plan.has_root_listener());
    assert!(plan.binds().iter().all(|bind| bind.at != "listen"));
    assert!(plan.binds().iter().any(|bind| bind.at == "admin_listen"));
    assert_eq!(plan.stream_binds().count(), 0);
    let app = projection_boundary_app(topology, Vec::new(), 1).await;
    plan.mount_planes(&super::super::Served::default(), &app, &[])
        .expect("engine/admin-only boot seals without any data declarations");
    plan.check(&app).unwrap();
    assert!(plan.lists(&app).unwrap().is_empty());
    assert!(plan.prepared(&app, "listen").is_none());
}

#[tokio::test]
async fn explicit_default_listen_requires_a_declared_accepting_root_framer() {
    let default = configured("");
    let address = default
        .binds
        .iter()
        .find(|bind| bind.at == "listen")
        .unwrap()
        .listen;
    let topology = configured(&format!("listen: {address}\n"));
    assert!(
        topology.root_required,
        "writing the default address remains an explicit bind"
    );
    let plan = declared_plan(topology.clone(), Vec::new());
    assert!(plan.has_root_listener());
    let app = projection_boundary_app(topology, Vec::new(), 1).await;
    let error = plan.check(&app).unwrap_err();
    assert!(
        error.contains("listen") && error.contains("no accepting transport"),
        "{error}"
    );
    assert!(plan.prepared(&app, "listen").is_none());
}

#[tokio::test]
async fn a_required_plugin_listener_refuses_a_missing_accepting_declaration() {
    let mut topology = topology();
    topology.root_required = false;
    topology.binds.retain(|bind| bind.at != "listen");
    topology.needs[0].transport = "absent-third-claim".into();
    topology
        .binds
        .iter_mut()
        .find(|bind| bind.at == PRIVATE_LISTENER)
        .unwrap()
        .transport = "absent-third-claim".into();
    let plan = declared_plan(topology.clone(), Vec::new());
    let app = projection_boundary_app(topology, vec![labeled_route("unavailable")], 1).await;
    let error = plan.check(&app).unwrap_err();
    assert!(
        error.contains("no accepting framer for absent-third-claim"),
        "{error}"
    );
    assert!(plan.prepared(&app, PRIVATE_LISTENER).is_none());
}

#[tokio::test]
async fn an_installed_accepting_framer_without_a_bind_declaration_is_not_a_default() {
    let topology = configured("");
    let doors = opened(&[third_without_binding]);
    assert!(doors[0].accepts());
    assert!(doors[0].listener_bindings().is_empty());
    let plan = declared_plan(topology.clone(), doors);
    let app = projection_boundary_app(topology, Vec::new(), 1).await;
    let error = plan.check(&app).unwrap_err();
    assert!(error.contains("no accepting transport declares"), "{error}");
}

#[tokio::test]
async fn a_foreign_second_claim_owns_the_root_independently_of_tls_and_offer_order() {
    for tls in [None, Some(serde_json::from_value(serde_json::json!({"cert":{"module":"source","settings":{"id":"cert"}},"key":{"module":"source","settings":{"id":"key"}}})).unwrap())] {
        let mut topology = configured("listen: 127.0.0.1:8080\n");
        topology
            .binds
            .iter_mut()
            .find(|bind| bind.at == "listen")
            .unwrap()
            .tls = tls.clone();
        let doors = opened(&[third_binding]);
        let owner = doors[0].instance().unwrap();
        assert_eq!(&doors[0].facts().claims[..2], &["third-a", "third-b"]);
        for reverse in [false, true] {
            let mut plan = declared_plan(topology.clone(), doors.clone());
            if reverse {
                Arc::get_mut(&mut plan).unwrap().offers.reverse();
                // Reconstruct through the public constructor with the opposite offered order.
                let offers = plan.offers.clone();
                let doors = doors.clone();
                plan = Arc::new(ListenerPlan::new(topology.clone(), offers, &move |claim| {
                    doors
                        .iter()
                        .find(|door| door.facts().claims.contains(&claim))
                        .cloned()
                }));
            }
            assert_eq!(plan.root_claim().unwrap(), "third-b");
            assert_eq!(plan.framers.get("third-b"), Some(&(owner, false)));
            let root = plan
                .binds()
                .iter()
                .find(|bind| bind.at == "listen")
                .unwrap();
            assert_eq!(root.transport, "third-b");
            assert_eq!(root.tls, tls);
            assert_eq!(
                plan.stream_binds().count(),
                0,
                "root is not served again as a plugin bind"
            );
            let app = projection_boundary_app(topology.clone(), Vec::new(), 1).await;
            plan.check(&app)
                .expect("aliases of one owner are not ambiguous root declarations");
        }
    }
}

#[tokio::test]
async fn two_accepting_root_declarations_refuse_both_offer_orders() {
    for doors in [
        [actual_http(), third_binding],
        [third_binding, actual_http()],
    ] {
        let topology = configured("listen: 127.0.0.1:8080\n");
        let doors = opened(&doors);
        assert_ne!(doors[0].instance(), doors[1].instance());
        let plan = declared_plan(topology.clone(), doors);
        let app = projection_boundary_app(topology, Vec::new(), 1).await;
        let error = plan.check(&app).unwrap_err();
        assert!(error.contains("multiple accepting transports"), "{error}");
        assert!(plan.prepared(&app, "listen").is_none());
    }
}

#[tokio::test]
async fn legacy_root_and_tls_keep_the_actual_products_declared_application_claim() {
    for tls in [None, Some(serde_json::from_value(serde_json::json!({"cert":{"module":"source","settings":{"id":"cert"}},"key":{"module":"source","settings":{"id":"key"}}})).unwrap())] {
        let mut topology = configured("listen: 127.0.0.1:8080\n");
        topology
            .binds
            .iter_mut()
            .find(|bind| bind.at == "listen")
            .unwrap()
            .tls = tls.clone();
        let doors = opened(&[actual_http()]);
        assert!(doors[0].facts().claims.contains(&"https"));
        let plan = declared_plan(topology.clone(), doors);
        assert_eq!(plan.root_claim().unwrap(), "http");
        let root = plan
            .binds()
            .iter()
            .find(|bind| bind.at == "listen")
            .unwrap();
        assert_eq!(root.transport, "http");
        assert_eq!(root.tls, tls);
        let app = projection_boundary_app(topology, Vec::new(), 1).await;
        plan.mount_planes(&super::super::Served::default(), &app, &[])
            .expect("the legacy listener seals with either connector security policy");
        assert!(plan.prepared(&app, "listen").is_some());
    }
}

#[tokio::test]
async fn incompatible_transport_or_owner_reload_retains_the_published_listener_policy() {
    let topology = topology();
    let plan = declared_plan(
        topology.clone(),
        opened(&[actual_http(), third_without_binding]),
    );
    let boot = projection_boundary_app(topology.clone(), vec![labeled_route("boot")], 1).await;
    plan.mount_planes(&super::super::Served::default(), &boot, &[])
        .unwrap();
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(boot.clone()));
    let private = plan.router(&handle, PRIVATE_LISTENER.into(), TEST_BODY_LIMIT, 0, false);
    let source = busbar_kernel::inbound::Listener {
        guests: GuestList::default(),
        auths: Default::default(),
        body_limit: TEST_BODY_LIMIT as u64,
        app: boot.clone(),
        door_refusals: Vec::new(),
        ids: Vec::new(),
        signed_ingress: Arc::new(|_, _| false),
        scope: None,
    };
    let retained = plan.policy(PRIVATE_LISTENER.into())(&source).unwrap();
    for change in ["dedicated transport", "dedicated owner", "root transport"] {
        let mut incompatible = topology.clone();
        if change == "root transport" {
            incompatible
                .binds
                .iter_mut()
                .find(|bind| bind.at == "listen")
                .unwrap()
                .transport = "third-b".into();
        } else {
            incompatible.needs[0].transport = "third-b".into();
        }
        if change == "dedicated transport" {
            incompatible
                .binds
                .iter_mut()
                .find(|bind| bind.at == PRIVATE_LISTENER)
                .unwrap()
                .transport = "third-b".into();
        }
        let rejected =
            projection_boundary_app(incompatible, vec![labeled_route("rejected")], 2).await;
        let error = plan.check(&rejected).unwrap_err();
        assert!(
            error.contains(if change == "dedicated owner" {
                "incompatible physical framing"
            } else {
                "requires a restart"
            }),
            "{change}: {error}"
        );
        assert!(plan.prepared(&rejected, "listen").is_none());
        assert!(plan.prepared(&rejected, PRIVATE_LISTENER).is_none());
        assert!(Arc::ptr_eq(&handle.load(), &boot));
        assert!(Arc::ptr_eq(&retained.app, &boot));
        assert!(Arc::ptr_eq(
            &plan.policy(PRIVATE_LISTENER.into())(&source).unwrap().app,
            &boot
        ));
        assert_eq!(physical_answer(&private, None).await.1.as_ref(), b"boot");
    }
}

#[tokio::test]
async fn an_admin_only_generation_refuses_a_new_explicit_root_before_publication() {
    let topology = configured("");
    let plan = declared_plan(topology.clone(), Vec::new());
    let boot = projection_boundary_app(topology.clone(), Vec::new(), 1).await;
    plan.mount_planes(&super::super::Served::default(), &boot, &[])
        .unwrap();
    let handle = busbar_kernel::state::AppHandle::new(boot.clone());
    let mut next = topology;
    next.root_required = true;
    let rejected = projection_boundary_app(next, Vec::new(), 2).await;
    let error = plan.check(&rejected).unwrap_err();
    assert!(
        error.contains("listen") && error.contains("restart"),
        "{error}"
    );
    assert!(Arc::ptr_eq(&handle.load(), &boot));
    assert!(plan.prepared(&rejected, "listen").is_none());
    assert!(plan.lists(&boot).unwrap().is_empty());
}
