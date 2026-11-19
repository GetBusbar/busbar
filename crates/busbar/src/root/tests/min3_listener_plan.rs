// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::root::boot::ListenerNeed;
use crate::root::min3_boot::transports::tests::initial;
use busbar_contract::kinds::codes::KindCode;

fn bind(slot: &str, port: u16) -> InboundBind {
    InboundBind {
        owner: BindOwner::Root,
        transport: String::new(),
        at: slot.into(),
        listen: ([127, 0, 0, 1], port).into(),
        tls: None,
        max_conns: 20,
    }
}

#[test]
fn native_plan_retains_exact_suppliers_and_configured_binds() {
    let supplier = initial("opaque-http-instance", &["listen", "admin_listen"]);
    let port = supplier.port.clone();
    let needs = ListenerNeeds {
        root_required: true,
        binds: vec![
            bind("listen", 8080),
            bind("listen", 8082),
            bind("admin_listen", 8081),
        ],
        needs: vec![],
    };
    let expected = needs.binds.clone();
    let plan = NativeListenerPlan::new(needs, &NativeFramers::new(vec![supplier])).unwrap();
    assert_eq!(plan.binds(), expected);
    assert!(Arc::ptr_eq(&plan.supplier("listen").unwrap().port, &port));
    assert!(Arc::ptr_eq(
        &plan.supplier("admin_listen").unwrap().port,
        &port
    ));
    assert!(plan.supplier("LISTEN").is_none());
    assert!(plan.supplier("http").is_none());
}

#[test]
fn native_plan_refuses_missing_or_ambiguous_declared_slot() {
    let needs = ListenerNeeds {
        binds: vec![bind("admin_listen", 8081)],
        ..Default::default()
    };
    let wrong = NativeFramers::new(vec![initial("only-data", &["listen"])]);
    assert!(NativeListenerPlan::new(needs.clone(), &wrong).is_err());
    let duplicate = NativeFramers::new(vec![
        initial("first", &["admin_listen"]),
        initial("second", &["admin_listen"]),
    ]);
    assert!(NativeListenerPlan::new(needs, &duplicate).is_err());
}

#[test]
fn native_plan_refuses_need_routes_unknown_slots_and_duplicate_addresses() {
    let framers = NativeFramers::new(vec![initial(
        "server",
        &["listen", "admin_listen", "other"],
    )]);
    let needs = ListenerNeeds {
        binds: vec![bind("listen", 8080)],
        needs: vec![ListenerNeed {
            instance: "export/one".into(),
            module: "export/one".into(),
            kind: KindCode::Export,
            need: 0,
            transport: "http".into(),
            auth: String::new(),
            at: "listen".into(),
        }],
        ..Default::default()
    };
    assert!(NativeListenerPlan::new(needs, &framers).is_err());
    for binds in [
        vec![bind("other", 8080)],
        vec![bind("listen", 8080), bind("admin_listen", 8080)],
        vec![InboundBind {
            owner: BindOwner::Need {
                instance: "export/one".into(),
                kind: KindCode::Export,
                need: 0,
            },
            ..bind("listen", 8080)
        }],
    ] {
        assert!(NativeListenerPlan::new(
            ListenerNeeds {
                binds,
                ..Default::default()
            },
            &framers
        )
        .is_err());
    }
}

#[test]
fn a_plane_with_upgrade_routes_is_assembled_while_no_instance_could_be_handed_one() {
    // E9a: the blanket "native plane upgrades have no complete physical producer" is gone. With
    // no admitted websocket instance every authorized upgrade request is answered 501.
    assert_eq!(upgrades_honoured(true, None), Ok(()));
    assert_eq!(upgrades_honoured(false, None), Ok(()));
    let websocket = ServedTransport {
        instance: Arc::from("transport-ws"),
        port: crate::root::min3_boot::transports::tests::framer(&["websocket"]),
    };
    assert_eq!(upgrades_honoured(false, Some(&websocket)), Ok(()));
    // With one, the request would have to be handed over, and no adopter is linked (E9b).
    let refused = upgrades_honoured(true, Some(&websocket)).unwrap_err();
    assert!(refused.contains("`transport-ws`") && refused.contains("not linked"));
}

#[test]
fn native_plan_records_the_admitted_websocket_upgrade_target() {
    let needs = ListenerNeeds {
        binds: vec![bind("listen", 8080)],
        ..Default::default()
    };
    let none = NativeListenerPlan::new(
        needs.clone(),
        &NativeFramers::new(vec![initial("http", &["listen"])]),
    )
    .unwrap();
    assert!(none.websocket.is_none());
    let websocket = ServedTransport {
        instance: Arc::from("transport-ws"),
        port: crate::root::min3_boot::transports::tests::framer(&["WebSocket"]),
    };
    let port = Arc::clone(&websocket.port);
    let some = NativeListenerPlan::new(
        needs,
        &NativeFramers::new(vec![initial("http", &["listen"]), websocket]),
    )
    .unwrap();
    assert!(Arc::ptr_eq(&some.websocket.unwrap().port, &port));
}

#[test]
fn an_explicit_root_bind_cannot_disappear_from_native_plan() {
    assert!(NativeListenerPlan::new(
        ListenerNeeds {
            root_required: true,
            ..Default::default()
        },
        &NativeFramers::new(vec![]),
    )
    .is_err());
}

/// §12.11 "Route credential header" as the engine owner ruled it: an unread credential header leaves
/// its route unmounted (never a boot refusal); the operator's explicit `routes.<id>.auth_instances` is
/// the only refusal, and only for a name that is not an opened instance or does not read the header.
mod route_credential_header {
    use super::*;
    use busbar_kernel::config::min3::RouteAuthInstances;
    use busbar_kernel::plane_driver::port_routes::Mounted;

    const TWILIO: &str = "x-twilio-signature";

    fn route(id: u32, cred_header: Option<&str>) -> Mounted {
        Mounted {
            record: None,
            route: id,
            methods: 1,
            flags: 0,
            auth: busbar_plugin_abi::plane::AUTH_PRINCIPAL,
            effective: busbar_plugin_abi::plane::AUTH_PRINCIPAL,
            pattern: format!("/r{id}").into(),
            cred_header: cred_header.map(Box::from),
            resource_kinds: Default::default(),
            catalog: false,
        }
    }

    fn explicit(names: &[&str]) -> RouteAuthInstances {
        RouteAuthInstances::from([(
            (Box::from("streaming"), 5),
            names.iter().map(|name| Box::from(*name)).collect(),
        )])
    }

    #[test]
    fn a_header_no_opened_instance_reads_leaves_the_route_unmounted() {
        let twilio = route(5, Some(TWILIO));
        let plain = route(1, None);
        let bearer: [Box<str>; 1] = [Box::from("authorization")];
        let readers = [Reader {
            name: "keys",
            cred_headers: &bearer,
        }];
        let names = plan_route_names(
            [("streaming", &twilio), ("streaming", &plain)],
            &readers,
            &RouteAuthInstances::new(),
        )
        .expect("the default configuration is never refused");
        assert_eq!(names["streaming"][&5], None, "not served");
        assert!(
            !names["streaming"].contains_key(&1),
            "a route without a header keeps the data chain"
        );
        assert_eq!(
            unserved_line("streaming", 5, TWILIO),
            "route 'streaming/5' is not served: no configured auth instance reads 'x-twilio-signature'"
        );
    }

    #[test]
    fn a_configured_instance_that_reads_the_header_mounts_the_route() {
        let twilio = route(5, Some(TWILIO));
        let headers: [Box<str>; 1] = [Box::from(TWILIO)];
        let readers = [
            Reader {
                name: "keys",
                cred_headers: &[],
            },
            Reader {
                name: "twilio",
                cred_headers: &headers,
            },
        ];
        let names = plan_route_names(
            [("streaming", &twilio)],
            &readers,
            &RouteAuthInstances::new(),
        )
        .unwrap();
        assert_eq!(names["streaming"][&5], Some(vec!["twilio".to_owned()]));
        // Named explicitly, it mounts the same way.
        let names =
            plan_route_names([("streaming", &twilio)], &readers, &explicit(&["twilio"])).unwrap();
        assert_eq!(names["streaming"][&5], Some(vec!["twilio".to_owned()]));
    }

    #[test]
    fn an_explicit_wrong_name_refuses_naming_the_route() {
        let twilio = route(5, Some(TWILIO));
        let headers: [Box<str>; 1] = [Box::from(TWILIO)];
        let readers = [
            Reader {
                name: "keys",
                cred_headers: &[],
            },
            Reader {
                name: "twilio",
                cred_headers: &headers,
            },
        ];
        let missing =
            plan_route_names([("streaming", &twilio)], &readers, &explicit(&["nope"])).unwrap_err();
        assert!(
            missing.contains("streaming.routes.5.auth_instances")
                && missing.contains("'nope'")
                && missing.contains("not a configured auth instance"),
            "{missing}"
        );
        let deaf =
            plan_route_names([("streaming", &twilio)], &readers, &explicit(&["keys"])).unwrap_err();
        assert!(
            deaf.contains("streaming.routes.5.auth_instances")
                && deaf.contains("'keys'")
                && deaf.contains(TWILIO),
            "{deaf}"
        );
        let stray = plan_route_names(
            [("streaming", &twilio)],
            &readers,
            &RouteAuthInstances::from([((Box::from("streaming"), 9), vec![Box::from("twilio")])]),
        )
        .unwrap_err();
        assert!(stray.contains("streaming.routes.9"), "{stray}");
    }

    /// SECURITY: an instance opened only for the admin chain (`auth.admin_auth`) is never a data or
    /// plane route's chain, even when it reads the route's credential header: an operator's admin
    /// token must never be verified on a data route. With nothing else reading the header, the route
    /// is unmounted. In the data chain, or named by the route's `auth_instances`, it is chosen.
    #[test]
    fn an_instance_opened_only_for_the_admin_chain_never_judges_a_plane_route() {
        let bedrock = route(7, Some("authorization"));
        let bearer: [Box<str>; 1] = [Box::from("authorization")];
        let admin = vec!["admin-tokens".to_owned()];
        let opened = || [("admin-tokens", &bearer[..])];
        let llm = |names: &[&str]| {
            RouteAuthInstances::from([(
                (Box::from("llm"), 7),
                names.iter().map(|name| Box::from(*name)).collect(),
            )])
        };

        let readers = route_readers(opened(), &[], &admin, &RouteAuthInstances::new());
        let names =
            plan_route_names([("llm", &bedrock)], &readers, &RouteAuthInstances::new()).unwrap();
        assert_eq!(
            names["llm"][&7], None,
            "an admin-only instance does not judge llm/7: it is unmounted"
        );

        let data = vec!["admin-tokens".to_owned()];
        let readers = route_readers(opened(), &data, &admin, &RouteAuthInstances::new());
        let names =
            plan_route_names([("llm", &bedrock)], &readers, &RouteAuthInstances::new()).unwrap();
        assert_eq!(
            names["llm"][&7],
            Some(vec!["admin-tokens".to_owned()]),
            "also in the data chain, it is a data instance"
        );

        let named = llm(&["admin-tokens"]);
        let readers = route_readers(opened(), &[], &admin, &named);
        let names = plan_route_names([("llm", &bedrock)], &readers, &named).unwrap();
        assert_eq!(
            names["llm"][&7],
            Some(vec!["admin-tokens".to_owned()]),
            "named by the route's auth_instances, it is the operator's explicit choice"
        );
    }
}
