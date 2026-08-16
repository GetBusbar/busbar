// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PROOF, END TO END: a crate that depends on `busbar-api` ALONE declares routes and a config
//! section, core mounts them into the router production builds, and a real request is answered by
//! the plugin's own code.
//!
//! `busbar-plane-example` is a DEV-dependency of core (see `Cargo.toml`) — core's production build
//! has no edge to it and names it nowhere. Everything below reaches it through the same
//! `install_plane_plugins` seam an external plane would use.

use super::*;
use busbar_plane_example::DECL as EXAMPLE;

/// Install once for the whole test binary — the seam is a `OnceLock` because there is one
/// composition root, and a test binary is one process.
fn install_once() {
    static DECLS: &[&PlaneDecl] = &[&EXAMPLE];
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        crate::plane_plugin::install_plane_plugins(DECLS);
        crate::plane_plugin::install_plane_config(vec![(
            "example",
            std::sync::Arc::from(r#"{"greeting":"hei"}"#),
        )]);
    });
}

/// THE HEADLINE. A request lands on a path core does not know, and the answer is composed by a
/// crate whose entire dependency list is `busbar-api`.
///
/// The greeting in the response body is the OPERATOR'S text, carried through
/// `PlaneCtx::config` as opaque bytes and parsed by the plugin into a type core cannot name —
/// which is the "typed config section without core naming the type" property, proven rather than
/// asserted. The timestamp comes from `PlaneCtx::clock`, the granted capability that replaces the
/// `store::now` module import the extracted dialects reach for today.
#[tokio::test]
async fn a_plane_that_depends_only_on_busbar_api_answers_a_real_request() {
    install_once();
    let handler = EXAMPLE.handler.expect("the example plane serves");
    let ctx = crate::plane_plugin::test_ctx(std::sync::Arc::from(r#"{"greeting":"hei"}"#));

    let req = crate::plane_plugin::to_plane_request(
        &axum::http::Method::GET,
        &"/example/hello".parse().unwrap(),
        &axum::http::HeaderMap::new(),
        axum::body::Bytes::new(),
    )
    .await;

    let resp = crate::plane_plugin::to_axum_response(handler.serve(&ctx, &req));
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .expect("body");
    let body = String::from_utf8(body.to_vec()).unwrap();
    // The operator's word, round-tripped through an opaque-text seam core never parsed.
    assert!(
        body.contains("\"greeting\":\"hei\""),
        "the plugin composed the answer; body was {body}"
    );
    // The clock came from the granted capability.
    assert!(body.contains("\"at\":"), "body was {body}");
}

/// THE MOUNT, through the function PRODUCTION builds the router with. A table assembled by hand
/// here could describe a surface no deployment serves, and then this assertion would be about a
/// fiction.
#[test]
fn core_mounts_exactly_the_routes_the_plane_declared_with_the_bar_it_declared() {
    install_once();
    let app = crate::test_support::TestApp::new().build();
    let (_router, table) = crate::base_data_router(
        &app.plugin_routes,
        app.mcp.as_deref(),
        app.a2a.as_ref(),
        app.oauth_as.as_ref(),
    );
    let served: std::collections::BTreeMap<String, busbar_plugin_loader::RouteAuth> = table
        .routes()
        .iter()
        .map(|r| (r.path.clone(), r.auth))
        .collect();

    // Every declared route is served...
    for route in EXAMPLE.routes {
        assert!(
            served.contains_key(route.path),
            "core did not mount the declared route {}",
            route.path
        );
    }
    // ...under the bar CORE settled on, which is not always the one the plane asked for.
    //
    // A PLANE MAY NOT LOWER ITS OWN BAR. `/example/hello` DECLARES `PlaneAuth::None`, and core
    // serves it behind `Key` because it is not in `RATIFIED_PUBLIC_PLANE_ROUTES`. This assertion is
    // the discovered security property of the whole seam: `plugin_routes::confine` already refuses
    // to let a plugin's self-report place a route outside its namespace, and this is the same rule
    // on the admission axis. Were it absent, any dropped-in crate could open an unauthenticated
    // route on the data plane by declaring one.
    assert_eq!(
        EXAMPLE
            .routes
            .iter()
            .find(|r| r.path == "/example/hello")
            .unwrap()
            .auth,
        busbar_api::plane::PlaneAuth::None,
        "the plane asks for an unauthenticated route"
    );
    assert_eq!(
        served.get("/example/hello"),
        Some(&busbar_plugin_loader::RouteAuth::Key),
        "core must NOT honour an unratified request for an unauthenticated route"
    );
    // A bar the plane declared that core does not have to second-guess passes through unchanged.
    assert_eq!(
        served.get("/example/echo"),
        Some(&busbar_plugin_loader::RouteAuth::Key)
    );
}

/// THE CONTROL, and the property the owner named: a plane whose config section the operator did not
/// write is DECLARED AND NOT MOUNTED. This is the same red the deletion gate makes structural —
/// with nothing installed at all, `mount_plane_routes` is the identity function and core serves its
/// own surface unchanged.
#[test]
fn a_plane_with_no_config_section_mounts_nothing() {
    // Deliberately does NOT call `install_once`: this exercises the fold over a section list that
    // does not contain this plane's section.
    let mounted = crate::plane_plugin::mounted_paths_for(&EXAMPLE, None);
    assert!(
        mounted.is_empty(),
        "an unconfigured plane must mount nothing, got {mounted:?}"
    );
    // ...and with the section present, exactly the declared paths appear. Same function, one input
    // changed — so the emptiness above is a decision, not an accident of the fixture.
    let mounted =
        crate::plane_plugin::mounted_paths_for(&EXAMPLE, Some(std::sync::Arc::from("{}")));
    assert_eq!(mounted, vec!["/example/hello", "/example/echo"]);
}
