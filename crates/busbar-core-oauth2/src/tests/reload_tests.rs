// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::any::Any;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use oauth_as::store::Storage as _;

use crate::plane::AsPlane;

async fn generation(
    prior: Option<&Arc<dyn Any + Send + Sync>>,
) -> (Arc<dyn Any + Send + Sync>, Arc<AsPlane>) {
    let config = crate::config::OauthAsCfg {
        issuer: "https://as.example.com".into(),
        ..Default::default()
    };
    let block = busbar_contract::yaml::to_value(
        config.authoring(&busbar_kernel::test_hooks::tokens::seal()),
    )
    .expect("the owner config serializes");
    let carried = crate::plane::seam_build::<crate::NoConnections>(
        block,
        Vec::new(),
        Vec::new(),
        prior.cloned(),
        crate::testkit::memory_store().await,
        crate::testkit::ADMIN_ORIGIN.to_string(),
    )
    .await
    .expect("the owner's real generation builds");
    let plane = Arc::clone(&carried)
        .downcast::<AsPlane>()
        .unwrap_or_else(|_| panic!("the owner seam returns its AsPlane"));
    (carried, plane)
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

#[tokio::test]
async fn a_reload_carries_the_servers_records_sessions_and_key() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let until = SystemTime::now() + Duration::from_secs(300);

    let (boot, first) = generation(None).await;
    {
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
    }
    let session = first
        .open_session("operator", "session-1".to_string())
        .await
        .expect("the store keeps the session");
    first
        .stake(&session, "request-1".to_string(), true)
        .await
        .expect("the store keeps the answer");
    let key = first.server().jwks();
    assert!(key.is_some(), "the server publishes its key");

    let (_reload, second) = generation(Some(&boot)).await;
    assert!(
        !Arc::ptr_eq(&first, &second),
        "the reload built a new generation"
    );
    {
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
    }
    assert!(
        second.is_staked(&session, "request-1").await,
        "the operator's consent session and its staked answer survive the reload"
    );
    assert_eq!(
        second.server().jwks(),
        key,
        "the ephemeral key the issued tokens verify against survives the reload"
    );
}

/// #140: the admin listener is bound once at boot and the approval pages are published at its
/// address, so an apply that moves it (a changed `admin_listen` or `admin_tls`) is refused: restart.
#[tokio::test]
async fn a_reload_that_moves_the_admin_listener_is_refused() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (boot, _first) = generation(None).await;
    let config = crate::config::OauthAsCfg {
        issuer: "https://as.example.com".into(),
        ..Default::default()
    };
    let block = busbar_contract::yaml::to_value(
        config.authoring(&busbar_kernel::test_hooks::tokens::seal()),
    )
    .expect("the owner config serializes");
    let refused = crate::plane::seam_build::<crate::NoConnections>(
        block,
        Vec::new(),
        Vec::new(),
        Some(boot),
        crate::testkit::memory_store().await,
        "https://127.0.0.1:8081".to_string(),
    )
    .await
    .err()
    .expect("a generation that moves the admin origin must not build");
    assert!(
        refused.contains("Restart busbar") && refused.contains(crate::testkit::ADMIN_ORIGIN),
        "{refused}"
    );
}
