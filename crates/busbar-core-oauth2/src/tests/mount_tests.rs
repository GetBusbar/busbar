// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE GATING PROOF: `oauth_as:` absent means the authorization server is not there.
//!
//! This plane ships as three things at once — built in, taken as a published crate,
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

use crate::config::{AsIdentity, OauthAsCfg};
use busbar_kernel_testkit::test_support::TestApp;

use crate::testkit::{oauth_as_plane, TestAppOauthExt};

const ISSUER: &str = "https://as.example.com";

fn cfg() -> OauthAsCfg {
    OauthAsCfg {
        issuer: ISSUER.to_string(),
        signing_key: None,
        key_id: None,
        default_grant: Vec::new(),
        access_token_ttl_secs: None,
        refresh_token_ttl_secs: None,
        fapi2: false,
        clients: Vec::new(),
    }
}

fn inventory(id: &AsIdentity) -> Vec<String> {
    let AsIdentity {
        metadata_path,
        authorize_path,
        token_path,
        device_authorization_path,
        verification_path,
        revocation_path,
        jwks_path,
        consent_path,

        register_path,

        par_path,

        issuer: _,

        issuer_path: _,
        default_grant: _,
        access_token_ttl: _,
        refresh_token_ttl: _,
        key_id: _,
        signing_key: _,

        fapi2,

        clients: _,
    } = id;

    let mut paths = vec![
        metadata_path.clone(),
        authorize_path.clone(),
        token_path.clone(),
        device_authorization_path.clone(),
        verification_path.clone(),
        revocation_path.clone(),
        jwks_path.clone(),
        consent_path.clone(),
        register_path.clone(),
    ];
    if *fapi2 {
        paths.push(par_path.clone());
    }
    paths
}

fn served_paths(app: &busbar_kernel::state::App) -> std::collections::BTreeSet<String> {
    busbar_kernel_testkit::routes::base_data_route_table_view(app)
        .into_iter()
        .map(|(path, _auth)| path)
        .collect()
}

#[test]
fn without_the_config_block_the_plane_serves_nothing() {
    busbar_kernel_testkit::test_support::metrics::init();
    let app = TestApp::new().build();
    assert!(
        oauth_as_plane(&app).is_none(),
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

    for path in &served {
        assert!(
            !path.starts_with("/.well-known/oauth-authorization-server"),
            "unconfigured, no RFC 8414 metadata document may be served; found `{path}`"
        );
    }
}

#[test]
fn the_inventory_is_exactly_what_the_mount_registers() {
    busbar_kernel_testkit::test_support::metrics::init();
    let without = served_paths(&TestApp::new().build());

    let block = cfg();
    let app = TestApp::new().oauth_as(&block).build();
    assert!(
        oauth_as_plane(&app).is_some(),
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

#[test]
fn the_fapi2_posture_adds_exactly_the_par_endpoint() {
    busbar_kernel_testkit::test_support::metrics::init();
    let without = served_paths(&TestApp::new().build());
    let plain = served_paths(&TestApp::new().oauth_as(&cfg()).build());

    let mut block = cfg();
    block.fapi2 = true;
    let fapi2 = served_paths(&TestApp::new().oauth_as(&block).build());

    let added: std::collections::BTreeSet<String> = fapi2.difference(&without).cloned().collect();
    let expected: std::collections::BTreeSet<String> =
        inventory(&AsIdentity::from_cfg(&block).expect("valid"))
            .into_iter()
            .collect();
    assert_eq!(
        added, expected,
        "under `fapi2: true` the routes `oauth_as:` adds must still be exactly the inventory"
    );
    assert_eq!(
        fapi2.difference(&plain).cloned().collect::<Vec<_>>(),
        vec!["/par".to_string()],
        "the posture adds the RFC 9126 endpoint and nothing else"
    );
    assert!(
        plain.is_subset(&fapi2),
        "the posture removes no plain endpoint"
    );
}

#[test]
fn an_absent_block_resolves_to_no_authorization_server() {
    let deploy: busbar_kernel::config::DeployCfg =
        serde_json::from_value(serde_json::json!({"providers": {}, "models": {}}))
            .expect("a minimal deploy config parses");
    let resolved = busbar_kernel::config::resolve(&deploy, &std::collections::HashMap::new())
        .expect("a minimal config resolves");
    assert!(
        resolved.oauth_as.is_none(),
        "no `oauth_as:` in the config means no authorization server in the resolved config. There \
         is deliberately no default here: a default issuer would make every deployment on earth an \
         authorization server for a host it does not own."
    );

    crate::testkit::install_test_seam();
    let deploy: busbar_kernel::config::DeployCfg =
        busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
            "providers": {},
            "models": {},
            "oauth_as": { "issuer": ISSUER },
        }))
        .expect("a deploy config carrying `oauth_as:` parses");
    let resolved = busbar_kernel::config::resolve(&deploy, &std::collections::HashMap::new())
        .expect("a config carrying a well-formed `oauth_as:` resolves");
    let checked = resolved
        .oauth_as
        .as_ref()
        .expect("`oauth_as:` was written, so the resolved config must carry the accepted block");
    let identity = crate::config::identity_of(&checked.block).expect("the accepted block is valid");
    assert_eq!(identity.issuer(), ISSUER);
}

#[test]
fn the_mounted_surface_and_the_app_state_cannot_disagree() {
    busbar_kernel_testkit::test_support::metrics::init();
    let app = TestApp::new().oauth_as(&cfg()).build();
    let plane: Arc<crate::plane::AsPlane> = oauth_as_plane(&app).expect("configured, so present");
    let served = served_paths(&app);
    for path in inventory(plane.identity()) {
        assert!(
            served.contains(&path),
            "`{path}` is derived from the identity the App holds, so the router built from that \
             same App must serve it"
        );
    }
}
