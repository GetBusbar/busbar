// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The control-route registry's two properties: it is EMPTY until the composition root writes, and
//! it accepts exactly one write.
//!
//! Both are about the same failure — a surface that is served without the root having said so, or
//! two roots disagreeing about which surfaces exist — and the empty default is the one that carries
//! the "costs nothing when it is off" claim at the registry layer.

use super::*;

/// UNINSTALLED IS EMPTY, not "the built-ins". There is no built-in control surface and there is not
/// going to be one: "the built-in control surfaces" would be the closed match the plane registry
/// exists to have removed.
#[test]
fn an_uninstalled_registry_is_empty() {
    // Nothing in this crate's test binary calls `install_control_surfaces`, so this reads the
    // uninstalled state — which is the state every `--no-default-features` build serves in.
    assert!(control_decls().is_empty());
}

/// A DECL CARRIES ONLY A KEY AND A ROUTE TABLE. Written as a test rather than as a comment because
/// the claim is about what is ABSENT: a control surface declares no meter class, no scope kind and
/// no audience binding, and the way to keep it that way is for a field added here to be a change
/// somebody has to make to this file.
#[test]
fn a_control_decl_declares_a_key_and_routes_and_nothing_else() {
    static DECL: ControlDecl = ControlDecl {
        key: "fixture",
        routes: |_| Vec::new(),
    };
    assert_eq!(DECL.key, "fixture");
    assert!((DECL.routes)(&() as &dyn std::any::Any).is_empty());
    assert_eq!(format!("{DECL:?}"), r#"ControlDecl { key: "fixture" }"#);
}
