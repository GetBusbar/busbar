// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE GATING PROOF: `oauth_as:` absent means the authorization server is not there.
//!
//! The ruling this plane ships under is three things at once — built in, taken as a published crate,
//! and INERT unless the operator's config asks for it — and only the third is a claim about running
//! behaviour, so only the third can be got wrong silently. A binary that links `oauth-as` and mounts
//! `/token` for every deployment is indistinguishable, from the outside, from one that does not,
//! right up until somebody points a scanner at it. This file is what makes the difference
//! observable.
//!
//! ## Why there are three tests and not one
//!
//! The obvious test — "with no config block, no `/authorize` in the route table" — is worth almost
//! nothing on its own, because it passes just as happily if the mount was deleted, if the plane
//! never worked, or if a route was renamed out from under the assertion. Each test below closes one
//! of those:
//!
//! 1. [`without_the_config_block_the_plane_serves_nothing`] is the claim itself.
//! 2. [`the_inventory_is_exactly_what_the_mount_registers`] is the FLOOR that makes (1) mean
//!    something: it takes the same two route tables, subtracts one from the other, and requires the
//!    difference to equal [`inventory`] EXACTLY. A route added to [`super::super::routes::mount`]
//!    and forgotten here fails as a surplus; a mount deleted fails as a shortfall. So (1) covering
//!    the inventory is (1) covering the whole plane.
//! 3. [`an_absent_block_resolves_to_no_authorization_server`] guards the layer above the router,
//!    where the realistic regression actually lives: nothing can mount an `AsPlane` that was never
//!    built, so the way this property dies is a `.unwrap_or_default()` on the config, not a stray
//!    `.route()` call.
//!
//! ## The inventory's shape is borrowed on purpose
//!
//! [`inventory`] destructures [`AsIdentity`] EXHAUSTIVELY, with no `..`, which is the same device
//! `config_validate::secret_refs` uses and for the same reason: a path field added to the identity
//! is then a COMPILE ERROR here until somebody has decided, in this file, whether it names a mounted
//! route. Omission is not something anybody has to remember.

use std::sync::Arc;

use crate::oauth_as::config::{AsIdentity, OauthAsCfg};
use crate::test_support::TestApp;

/// The issuer every test here configures. An origin root rather than a tenant path, because the
/// path-prefixed derivation already has its own coverage in `config_tests` and repeating it here
/// would make these tests fail for that reason instead of their own.
const ISSUER: &str = "https://as.example.com";

/// An `oauth_as:` block as an operator would write it. There is deliberately nothing to vary:
/// the 1.6.0 ruling removed the `dynamic_registration` toggle, so ONE config produces the whole
/// mounted set — `/register` included, unconditionally.
fn cfg() -> OauthAsCfg {
    OauthAsCfg {
        issuer: ISSUER.to_string(),
        signing_key: None,
        key_id: None,
        dynamic_registration: None,
        default_grant: Vec::new(),
        access_token_ttl_secs: None,
    }
}

/// EVERY path this plane serves, derived from the validated identity the mount derives its own from.
///
/// EXHAUSTIVE DESTRUCTURE, NO `..`. If you are here because the compiler stopped you, the question
/// is "does this field name an HTTP path this plane mounts?" — and if the answer is yes it belongs in
/// the returned vector, because everything below is only as complete as this list.
fn inventory(id: &AsIdentity) -> Vec<String> {
    let AsIdentity {
        // ── PATHS: the mounted surface, and the whole of it ──
        metadata_path,
        authorize_path,
        token_path,
        jwks_path,
        consent_path,
        // Mounted UNCONDITIONALLY: registration is one of the three always-on mechanisms, so the
        // single most dangerous path on this plane is inside every assertion below by construction.
        register_path,
        // ── NOT PATHS: identity, policy and key material. None of these adds a route. ──
        issuer: _,
        // The path COMPONENT of the issuer, which is a prefix the six paths above already carry;
        // it is not itself served.
        issuer_path: _,
        default_grant: _,
        access_token_ttl: _,
        key_id: _,
        signing_key: _,
    } = id;

    vec![
        metadata_path.clone(),
        authorize_path.clone(),
        token_path.clone(),
        jwks_path.clone(),
        consent_path.clone(),
        register_path.clone(),
    ]
}

/// The CORE ROUTE TABLE of the served router, built by the same function production builds it with.
///
/// `base_data_router` rather than a hand-rolled router: a table assembled here could describe a
/// surface no deployment serves, and then every assertion below would be about a fiction.
fn served_paths(app: &crate::state::App) -> std::collections::BTreeSet<String> {
    crate::base_data_router(&app.plugin_routes, &app.plane_slots, app.oauth_as.as_ref())
        .1
        .routes()
        .iter()
        .map(|r| r.path.clone())
        .collect()
}

/// THE CLAIM. With no `oauth_as:` block, not one path of the authorization server is served.
///
/// The inventory is derived from a validated identity that no `App` in this test ever holds: the
/// point is to ask the unconfigured router about the paths a CONFIGURED one would serve, which is
/// the question an operator is really asking when they ask what the block costs them when it is
/// absent.
#[test]
fn without_the_config_block_the_plane_serves_nothing() {
    crate::metrics::init();
    let app = TestApp::new().build();
    assert!(
        app.oauth_as.is_none(),
        "the default TestApp must not be an authorization server"
    );
    let served = served_paths(&app);

    let id = AsIdentity::from_cfg(&cfg()).expect("valid");
    for path in inventory(&id) {
        assert!(
            !served.contains(&path),
            "`oauth_as:` is absent, so `{path}` must not be mounted. A deployment that did not \
             ask to be an authorization server is not one, and this is the property the whole \
             built-in placement rests on."
        );
    }

    // The well-known document by PREFIX as well as by exact path, because it is the one route a
    // client discovers rather than guesses: an authorization server that leaks its existence leaks
    // it here first, and a renamed suffix would slip past the exact-match loop above.
    for path in &served {
        assert!(
            !path.starts_with("/.well-known/oauth-authorization-server"),
            "unconfigured, no RFC 8414 metadata document may be served; found `{path}`"
        );
    }
}

/// THE FLOOR that stops the test above being vacuous, and the anti-omission guard in one.
///
/// The set of routes the config block ADDS must equal [`inventory`] exactly — not contain it, not be
/// contained by it. Equality is what makes this a guard rather than a smoke test: a surplus means a
/// route is mounted that the gating assertion never checks for, and a shortfall means the mount is
/// gone and the gating assertion is passing for the wrong reason.
#[test]
fn the_inventory_is_exactly_what_the_mount_registers() {
    crate::metrics::init();
    let without = served_paths(&TestApp::new().build());

    let block = cfg();
    let app = TestApp::new().oauth_as(&block).build();
    assert!(
        app.oauth_as.is_some(),
        "the config block was given, so the plane must exist"
    );
    let with = served_paths(&app);

    let added: std::collections::BTreeSet<String> = with.difference(&without).cloned().collect();
    let expected: std::collections::BTreeSet<String> =
        inventory(&AsIdentity::from_cfg(&block).expect("valid"))
            .into_iter()
            .collect();

    assert_eq!(
        added, expected,
        "the routes `oauth_as:` adds must be exactly the inventory this file gates on. A path in \
         `added` and not `expected` is a route the gating test above never looks for; a path in \
         `expected` and not `added` is a mount that no longer happens."
    );
    assert!(
        !expected.is_empty(),
        "an empty inventory would make the gating test pass by asserting nothing"
    );
    // THE FLIPPED ASSERTION. This line used to pin `/register` to the operator's
    // `dynamic_registration` toggle; the 1.6.0 ruling deleted the toggle, so the same line now
    // pins the UNCONDITIONAL mount: an AS plane without its registration endpoint is a shortfall
    // this test names, exactly as its accidental presence used to be.
    assert!(
        expected.contains("/register"),
        "`/register` is mounted whenever the plane is: registration is one of the three always-on \
         mechanisms, with no toggle"
    );
    assert!(
        without.is_subset(&with),
        "turning `oauth_as:` on must ADD routes and remove none: the plane is additive, and a \
         route it displaced would be an existing surface it silently took over"
    );
}

/// The layer where this property actually dies. Nothing can mount a plane that was never built, so
/// the realistic regression is not a stray `.route()` — it is a default on the config, and the
/// config is where the block is either present or absent.
#[test]
fn an_absent_block_resolves_to_no_authorization_server() {
    let deploy: crate::config::DeployCfg =
        serde_json::from_value(serde_json::json!({"providers": {}, "models": {}}))
            .expect("a minimal deploy config parses");
    let resolved = crate::config::resolve(&deploy, &std::collections::HashMap::new())
        .expect("a minimal config resolves");
    assert!(
        resolved.oauth_as.is_none(),
        "no `oauth_as:` in the config means no authorization server in the resolved config. There \
         is deliberately no default here: a default issuer would make every deployment on earth an \
         authorization server for a host it does not own."
    );

    // And the same resolve WITH the block does produce one, so the assertion above is about the
    // block's absence rather than about `resolve` having quietly stopped reading the field at all.
    let deploy: crate::config::DeployCfg = serde_json::from_value(serde_json::json!({
        "providers": {},
        "models": {},
        "oauth_as": { "issuer": ISSUER },
    }))
    .expect("a deploy config carrying `oauth_as:` parses");
    let resolved = crate::config::resolve(&deploy, &std::collections::HashMap::new())
        .expect("a config carrying a well-formed `oauth_as:` resolves");
    let identity = resolved
        .oauth_as
        .as_ref()
        .expect("`oauth_as:` was written, so the resolved config must carry the identity");
    assert_eq!(identity.issuer(), ISSUER);
}

/// `App::oauth_as` and the mounted surface are the same decision, and the router must not be able to
/// disagree with the state it was built from.
#[test]
fn the_mounted_surface_and_the_app_state_cannot_disagree() {
    crate::metrics::init();
    let app = TestApp::new().oauth_as(&cfg()).build();
    let plane: &Arc<crate::oauth_as::plane::AsPlane> =
        app.oauth_as.as_ref().expect("configured, so present");
    let served = served_paths(&app);
    for path in inventory(plane.identity()) {
        assert!(
            served.contains(&path),
            "`{path}` is derived from the identity the App holds, so the router built from that \
             same App must serve it"
        );
    }
}
