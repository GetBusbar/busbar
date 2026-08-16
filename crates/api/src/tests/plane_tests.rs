// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The PLANE contract's own pins. These assert the properties the contract exists to carry — the
//! dlopen verdict is READ OFF THE DECLARATION, the method token is the wire token, and ratification
//! is scoped so it cannot quietly over-grant.

use super::*;

fn route(path: &str, auth: PlaneAuth, streaming: bool) -> PlaneRoute {
    PlaneRoute {
        path: path.to_string(),
        method: PlaneMethod::Get,
        auth,
        streaming,
    }
}

fn decl(routes: fn(&str) -> Vec<PlaneRoute>) -> PlaneDecl {
    PlaneDecl {
        key: "example",
        config_section: "example",
        scope_kinds: &["example"],
        subject_noun: "example",
        audit_kind: "example",
        wire_format_names: || &[],
        routes,
        verified_headers: &[],
        handler: None,
    }
}

/// The linked-only verdict is DERIVED from the declared routes, not asserted alongside them. A plane
/// author cannot declare a streaming route and separately claim to be loadable: there is one
/// statement of the fact and `requires_linking` reads it.
#[test]
fn a_streaming_route_makes_the_whole_plane_linked_only() {
    let unary = decl(|_| vec![route("/example/ping", PlaneAuth::Key, false)]);
    assert!(!unary.requires_linking("{}"));

    // ONE streaming route is enough: the plugin wire is one buffered request and one buffered
    // response, so a plane carrying any stream cannot cross it at all.
    let mixed = decl(|_| {
        vec![
            route("/example/ping", PlaneAuth::Key, false),
            route("/example/events", PlaneAuth::Key, true),
        ]
    });
    assert!(mixed.requires_linking("{}"));
}

/// ROUTES ARE A FUNCTION OF CONFIG — the v2 change MCP forced. A path derived from the operator's
/// text is a path core cannot know statically, and the declaration has to be able to express it.
#[test]
fn a_plane_derives_its_route_paths_from_the_operator_config() {
    let d = decl(|cfg| {
        // Stand-in for MCP reading `canonical_uri` out of its own section.
        let base = if cfg.contains("\"base\":\"/agent\"") {
            "/agent"
        } else {
            "/mcp"
        };
        vec![route(
            &format!("{base}/.well-known/oauth-protected-resource"),
            PlaneAuth::None,
            false,
        )]
    });
    assert_eq!(
        (d.routes)(r#"{"base":"/agent"}"#)[0].path,
        "/agent/.well-known/oauth-protected-resource"
    );
    assert_eq!(
        (d.routes)("{}")[0].path,
        "/mcp/.well-known/oauth-protected-resource"
    );
}

/// The method token a plane declares is the token that rides the plugin wire, verbatim — the
/// property that lets the SAME declaration serve the linked and the dlopen'd form.
#[test]
fn the_method_token_is_the_uppercase_wire_spelling() {
    assert_eq!(PlaneMethod::Get.as_str(), "GET");
    assert_eq!(PlaneMethod::Post.as_str(), "POST");
    assert_eq!(PlaneMethod::Put.as_str(), "PUT");
    assert_eq!(PlaneMethod::Patch.as_str(), "PATCH");
    assert_eq!(PlaneMethod::Delete.as_str(), "DELETE");
}

/// EXACTLY THE TWO BARS THAT MOVE ADMISSION AWAY FROM CORE need a reviewed entry. If `Key` or
/// `Admin` ever required one, ratification would become routine paperwork and stop being read —
/// and if `PlaneVerified` did not, a dropped-in crate could receive unauthenticated traffic while
/// appearing to check it.
#[test]
fn only_the_bars_that_leave_cores_auth_chain_require_ratification() {
    assert!(PlaneAuth::None.requires_ratification());
    assert!(PlaneAuth::PlaneVerified.requires_ratification());
    assert!(!PlaneAuth::Key.requires_ratification());
    assert!(!PlaneAuth::Admin.requires_ratification());
}

/// A ratification entry is scoped to ONE plane, ONE path shape and ONE bar. All three must match,
/// so ratifying MCP's metadata document cannot ratify another plane's identically-shaped path, nor
/// the same path at a different bar.
#[test]
fn a_ratification_is_scoped_to_one_plane_one_shape_and_one_bar() {
    let r = RatifiedRoute {
        plane: "mcp",
        pattern: "/*/.well-known/oauth-protected-resource",
        auth: PlaneAuth::None,
        reason: "RFC 9728: the caller that needs this document is by definition tokenless",
    };
    assert!(r.ratifies(
        "mcp",
        "/mcp/.well-known/oauth-protected-resource",
        PlaneAuth::None
    ));
    // Same shape, different plane.
    assert!(!r.ratifies(
        "a2a",
        "/a2a/.well-known/oauth-protected-resource",
        PlaneAuth::None
    ));
    // Same plane and shape, different bar.
    assert!(!r.ratifies(
        "mcp",
        "/mcp/.well-known/oauth-protected-resource",
        PlaneAuth::PlaneVerified
    ));
    // Not the ratified shape.
    assert!(!r.ratifies("mcp", "/mcp/tools/call", PlaneAuth::None));
}

/// THE OVER-GRANT THE PATTERN MATCHER EXISTS TO PREVENT. A `*` that could span `/` would let a
/// ratification for one document also cover a traversal into an unrelated surface. The wildcard is
/// segment-bounded, and it must consume at least one character.
#[test]
fn a_ratification_wildcard_never_crosses_a_path_separator() {
    let r = RatifiedRoute {
        plane: "mcp",
        pattern: "/mcp/*/metadata",
        auth: PlaneAuth::None,
        reason: "test",
    };
    assert!(r.ratifies("mcp", "/mcp/v1/metadata", PlaneAuth::None));
    // The traversal a greedy `*` would have admitted.
    assert!(!r.ratifies("mcp", "/mcp/../../admin/metadata", PlaneAuth::None));
    // An empty segment is not a match: `/mcp//metadata` normalises differently downstream.
    assert!(!r.ratifies("mcp", "/mcp//metadata", PlaneAuth::None));
    // A wildcard matches within one segment only.
    assert!(!r.ratifies("mcp", "/mcp/a/b/metadata", PlaneAuth::None));
}

/// A plane must be testable WITHOUT booting the engine — a property `auth-admin-tokens` has and no
/// plugin should lose. `#[non_exhaustive]` alone would have taken it away, so the builder is part of
/// the contract. It also documents the grants: a context's construction site reads as the list of
/// powers that plane was given.
#[test]
fn a_plane_can_build_its_own_context_and_is_granted_only_what_it_was_given() {
    struct C;
    impl PlaneClock for C {
        fn now_secs(&self) -> u64 {
            1_700_000_000
        }
    }
    struct M;
    impl PlaneMetrics for M {
        fn counter(&self, _n: &str, _v: u64, _l: &[(&str, &str)]) {}
        fn histogram(&self, _n: &str, _v: f64, _l: &[(&str, &str)]) {}
    }
    let ctx = PlaneCtx::builder(Arc::from("{}"), Arc::new(C), Arc::new(M)).build();
    assert_eq!(ctx.clock.now_secs(), 1_700_000_000);
    // NOT granted is the default. A plane that never asked for durability cannot reach it, and the
    // `Option` is what makes "this plane cannot touch the journal" a fact rather than a convention.
    assert!(ctx.journal.is_none());
    assert!(ctx.tasks.is_none());
    assert!(ctx.egress.is_none());
}
