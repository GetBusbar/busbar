// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

// App/router assertions run in the actual distribution binary. This owner unit
// case retains access to the private config identity without widening its API.
const ISSUER: &str = "https://as.example.com";

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

#[tokio::test]
async fn the_owner_seam_keeps_the_complete_configured_identity() {
    let config = crate::config::OauthAsCfg {
        issuer: ISSUER.into(),
        ..Default::default()
    };
    let expected = crate::config::AsIdentity::from_cfg(&config).expect("valid identity");
    let block = serde_yaml::to_value(config).expect("the owner config serializes");
    let carried = crate::plane::seam_build::<crate::NoConnections>(
        &block,
        Vec::new(),
        Vec::new(),
        None,
        Some(crate::testkit::store_calls()),
    )
    .expect("the owner's generation builds");
    let plane = carried
        .downcast::<crate::plane::AsPlane>()
        .unwrap_or_else(|_| panic!("the owner seam returns its AsPlane"));
    assert_eq!(plane.identity(), &expected);
}
