// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::root::boot::ListenerNeed;
use crate::root::min3_transports::tests::initial;
use busbar_contract::abi::mechanism::KindCode;

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
