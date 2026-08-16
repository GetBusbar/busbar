// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The PLANE contract's own pins. These assert the two properties the contract exists to carry —
//! the dlopen verdict is READ OFF THE DECLARATION, and the method token is the wire token — rather
//! than the presence of the types.

use super::*;

/// The linked-only verdict is DERIVED from the declared routes, not asserted alongside them. A
/// plane author cannot declare a streaming route and separately claim to be loadable: there is one
/// statement of the fact and `requires_linking` reads it.
#[test]
fn a_streaming_route_makes_the_whole_plane_linked_only() {
    static UNARY: &[PlaneRoute] = &[PlaneRoute {
        path: "/example/ping",
        method: PlaneMethod::Get,
        auth: PlaneAuth::Key,
        streaming: false,
    }];
    static MIXED: &[PlaneRoute] = &[
        PlaneRoute {
            path: "/example/ping",
            method: PlaneMethod::Get,
            auth: PlaneAuth::Key,
            streaming: false,
        },
        PlaneRoute {
            path: "/example/events",
            method: PlaneMethod::Get,
            auth: PlaneAuth::Key,
            streaming: true,
        },
    ];

    fn decl(routes: &'static [PlaneRoute]) -> PlaneDecl {
        PlaneDecl {
            key: "example",
            config_section: "example",
            scope_kinds: &["example"],
            subject_noun: "example",
            audit_kind: "example",
            wire_format_names: || &[],
            routes,
            handler: None,
        }
    }

    // A wholly unary plane is loadable.
    assert!(!decl(UNARY).requires_linking());
    // ONE streaming route is enough: the plugin wire is one buffered request and one buffered
    // response, so a plane carrying any stream cannot cross it at all.
    assert!(decl(MIXED).requires_linking());
}

/// The method token a plane declares is the token that rides the plugin wire, verbatim. This is the
/// property that lets the SAME declaration serve the linked and the dlopen'd form; if these
/// spellings drifted, a plane's routes would be reserved under one name and dispatched under
/// another.
#[test]
fn the_method_token_is_the_uppercase_wire_spelling() {
    assert_eq!(PlaneMethod::Get.as_str(), "GET");
    assert_eq!(PlaneMethod::Post.as_str(), "POST");
    assert_eq!(PlaneMethod::Put.as_str(), "PUT");
    assert_eq!(PlaneMethod::Patch.as_str(), "PATCH");
    assert_eq!(PlaneMethod::Delete.as_str(), "DELETE");
}
