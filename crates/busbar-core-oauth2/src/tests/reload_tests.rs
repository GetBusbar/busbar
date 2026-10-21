// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A RELOAD CARRIES THE AUTHORIZATION SERVER (audit core-oauth2#3). Every config apply or reload
//! builds a new generation through the kernel's one construction path (`build_app_from_config`
//! with the prior `App`). What the server HOLDS must survive the swap: a replay-ledger entry
//! (a DPoP proof or client-assertion `jti` seen once stays refused), a registered client, the
//! operator's consent session with its staked answer, and the ephemeral signing key the tokens it
//! issued verify against.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use oauth_as::store::Storage as _;

use crate::plane::AsPlane;
use crate::testkit::oauth_as_plane;

/// The resolved config of a deployment that is an authorization server (no `signing_key`: the
/// key is an ephemeral one). Its `store:` is the kernel's own compiled-in module, named by the
/// kernel: this crate names no store instance.
fn cfg() -> busbar_kernel::config::RootCfg {
    crate::testkit::install_test_seam();
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        serde_json::json!({
            "providers": {},
            "models": {},
            "store": { "module": busbar_kernel::config::MIGRATED_STORE_MODULE },
            "oauth_as": { "issuer": "https://as.example.com" },
        }),
        busbar_kernel::plane_driver::doors::Doors::NONE,
    )
    .expect("a deploy config carrying `oauth_as:` parses");
    busbar_kernel::config::resolve(&deploy, &HashMap::new()).expect("the config resolves")
}

/// One generation, built as boot (`prior` = `None`) or a reload builds it.
fn generation(
    rt: &tokio::runtime::Runtime,
    prior: Option<&busbar_kernel::state::App>,
) -> (busbar_kernel::state::App, Arc<AsPlane>) {
    let _on = rt.enter();
    let app = busbar_kernel::test_support::build_once(cfg(), prior).expect("the generation builds");
    let plane = oauth_as_plane(&app).expect("`oauth_as:` is configured");
    (app, plane)
}

fn client(id: &str) -> oauth_as::client::Client {
    oauth_as::client::Client {
        client_id: oauth_as::client::ClientId::new(id),
        auth: oauth_as::client::ClientAuth::Public,
        grant_types: vec![oauth_as::grant::GrantType::AuthorizationCode],
        redirect_uris: vec!["https://app.example.com/cb".to_string()],
        allowed_scopes: oauth_as::scope::ScopeSet::default(),
        default_scopes: oauth_as::scope::ScopeSet::default(),
        name: None,
        registration: None,
    }
}

/// RED (audit core-oauth2#3): before the fix the reload built the server from nothing, so the
/// `jti` was claimable again, the client unknown, the session gone and the key another.
#[test]
fn a_reload_carries_the_servers_records_sessions_and_key() {
    busbar_kernel::snapshot::init();
    let rt = tokio::runtime::Runtime::new().expect("a runtime");
    let until = SystemTime::now() + Duration::from_secs(300);

    let (boot, first) = generation(&rt, None);
    rt.block_on(async {
        assert!(matches!(
            first.server().store().claim_replay_id("jti-1", until).await,
            Ok(true)
        ));
        first
            .server()
            .store()
            .put_client(client("registered-1"))
            .await
            .expect("the client is stored");
    });
    let session = first.sessions().open("operator", "session-1".to_string());
    first
        .sessions()
        .stake(&session, "request-1".to_string(), true);
    let key = first.server().jwks();
    assert!(key.is_some(), "the server publishes its key");

    let (_reload, second) = generation(&rt, Some(&boot));
    assert!(
        !Arc::ptr_eq(&first, &second),
        "the reload built a new generation"
    );
    rt.block_on(async {
        assert!(
            matches!(
                second
                    .server()
                    .store()
                    .claim_replay_id("jti-1", until)
                    .await,
                Ok(false)
            ),
            "a `jti` seen before the reload is a replay after it"
        );
        assert!(
            matches!(
                second
                    .server()
                    .store()
                    .get_client(&oauth_as::client::ClientId::new("registered-1"))
                    .await,
                Ok(Some(_))
            ),
            "a client registered before the reload is known after it"
        );
    });
    assert!(
        second.sessions().is_staked(&session, "request-1"),
        "the operator's consent session and its staked answer survive the reload"
    );
    assert_eq!(
        second.server().jwks(),
        key,
        "the ephemeral key the issued tokens verify against survives the reload"
    );
}
