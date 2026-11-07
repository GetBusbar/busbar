// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! OAuth application assertions compiled by the actual distribution binary.

use std::collections::HashSet;
use std::sync::Arc;

use busbar_core_oauth2::config::OauthAsCfg;
use busbar_kernel::state::App;

use crate::root::test_plugins as plugins;

mod browser;
mod code_flow_tests;
mod consent_tests;
mod device_tests;
mod directory;
mod fapi2_tests;
mod hosted_credential_tests;
mod hosted_provider_tests;
mod hosted_routes_tests;
mod issuer;
mod mount_tests;
mod registration_tests;

fn tls_identity() -> (Arc<rustls::ServerConfig>, &'static str) {
    static IDENTITY: std::sync::LazyLock<(Arc<rustls::ServerConfig>, String)> =
        std::sync::LazyLock::new(|| {
            let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()])
                .expect("the actual OAuth TLS identity");
            let config = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("OAuth TLS versions")
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                rustls_pki_types::PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(
                    cert.signing_key.serialize_der(),
                )),
            )
            .expect("the actual OAuth TLS certificate and key");
            (Arc::new(config), cert.cert.pem())
        });
    (Arc::clone(&IDENTITY.0), &IDENTITY.1)
}

fn client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder().add_root_certificate(
        reqwest::Certificate::from_pem(tls_identity().1.as_bytes())
            .expect("the explicit OAuth test CA"),
    )
}

fn client() -> reqwest::Client {
    client_builder().build().expect("the OAuth TLS client")
}

async fn serve_tls(listener: tokio::net::TcpListener, router: axum::Router) {
    let acceptor = tokio_rustls::TlsAcceptor::from(tls_identity().0);
    loop {
        let (socket, _) = listener.accept().await.expect("accept OAuth TLS socket");
        let (acceptor, router) = (acceptor.clone(), router.clone());
        tokio::spawn(async move {
            let stream = acceptor
                .accept(socket)
                .await
                .expect("authenticate OAuth TLS");
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    hyper_util::rt::TokioIo::new(stream),
                    hyper_util::service::TowerToHyperService::new(router),
                )
                .await;
        });
    }
}

fn serve_boot_jwks(listener: std::net::TcpListener, app: Arc<App>) {
    struct Server {
        stop: Option<tokio::sync::oneshot::Sender<()>>,
        thread: Option<std::thread::JoinHandle<()>>,
    }
    impl Drop for Server {
        fn drop(&mut self) {
            let _ = self.stop.take().expect("one shutdown signal").send(());
            self.thread
                .take()
                .expect("one owned server thread")
                .join()
                .expect("OAuth JWKS server joins");
        }
    }
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let thread = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("the owned OAuth JWKS runtime");
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener)
                .expect("the actual JWKS listener enters its runtime");
            tokio::select! {
                _ = serve_tls(listener, busbar_kernel::build_router(app)) => {},
                _ = stopped => {},
            }
        });
    });
    let server = Server {
        stop: Some(stop),
        thread: Some(thread),
    };

    tokio::spawn(async move {
        let _server = server;
        std::future::pending::<()>().await;
    });
}

/// Build through the shipped root and its normal plugin loader. The required store
async fn application(oauth_as: Option<&OauthAsCfg>, prior: Option<&App>) -> Arc<App> {
    application_with_resource_auth(oauth_as, prior, false).await
}

async fn application_with_resource_auth(
    oauth_as: Option<&OauthAsCfg>,
    prior: Option<&App>,
    resource_auth: bool,
) -> Arc<App> {
    build_application(oauth_as, prior, resource_auth, None, None).await
}

async fn application_with_document(document: serde_json::Value) -> Arc<App> {
    build_application(None, None, false, Some(document), None).await
}

async fn application_with_auth_plugin(
    document: serde_json::Value,
    library: &std::path::Path,
) -> Arc<App> {
    build_application(None, None, false, Some(document), Some(library)).await
}

async fn build_application(
    oauth_as: Option<&OauthAsCfg>,
    prior: Option<&App>,
    resource_auth: bool,
    document: Option<serde_json::Value>,
    auth_library: Option<&std::path::Path>,
) -> Arc<App> {
    let hosted_credentials = auth_library.is_some();
    static BUILDING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let _building = BUILDING.lock().await;
    crate::dist_root_install::install();

    let store_library = crate::root::test_plugins::application_store_library();
    let stated = busbar_plugin_loader::dispatch::rendering_of_library(&store_library)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&stated)
        .expect("the actual store statement is valid")
        .name;
    let library = std::fs::read(&store_library).expect("the actual store library reads");
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(stated));
    let instance = busbar_kernel::door::op_id().counter();
    let directory = plugins::scratch(&format!("oauth-application-{instance}"));
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");

    let settings = crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let mut document = document.unwrap_or_else(|| {
        serde_json::json!({
            "providers": {},
            "models": {},
            "auth": { "chain": [], "admin_auth": [] },
            "advanced": { "allow_destinations": ["127.0.0.1"] },
        })
    });
    document["store"] = serde_json::json!({"module":module,"settings":settings});
    if let Some(block) = oauth_as {
        document["oauth_as"] = serde_json::to_value(block).expect("the OAuth config serializes");
    }
    let auth_library = auth_library.map(std::path::Path::to_owned).or_else(|| {
        resource_auth.then(|| {
            plugins::token_verifier_cdylib_path().expect(
                "build the pinned auth-oidc product cdylib before running OAuth application tests",
            )
        })
    });
    let auth_name = auth_library.map(|path| {
        let statement = busbar_plugin_loader::dispatch::rendering_of_library(&path)
            .expect("the actual auth statement reads")
            .expect("the actual auth library states itself");
        let name = busbar_contract::abi::mechanism::rendering::read(&statement)
            .expect("the actual auth statement is valid")
            .name;
        let mut manifest =
            plugins::manifest("auth", &name, crate::root::test_plugins::FIXTURE_PUBLISHER);
        manifest.statement = Some(hex::encode(statement));
        let library = std::fs::read(&path).expect("the actual auth library reads");
        let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
        std::fs::write(directory.join("auth-product.tar.gz"), archive)
            .expect("stage the actual auth archive");
        name
    });
    let plugins = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;

    let mut fresh_store = None;
    let authorization_server = if resource_auth {
        let deploy = busbar_kernel::config::deploy_from_deserializer(document.clone())
            .expect("the authorization-server bootstrap deployment parses");
        let config = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the authorization-server bootstrap deployment resolves");
        // Retain the exclusive creation provenance across construction stages. A prior
        // App never acquires a fresh receipt merely because this helper rebuilds it.
        fresh_store = if prior.is_none() {
            Some(
                plugins::provision_fresh_application_store(&config, &plugins, &directory)
                    .await
                    .expect(
                        "the fixture exclusively provisions its new authorization-server Store",
                    ),
            )
        } else {
            None
        };
        let opened_store = match &fresh_store {
            Some(fresh) => fresh.opened(),
            None => prior
                .expect("retained authorization-server app")
                .governance
                .as_ref()
                .expect("retained governance")
                .core_store_handle()
                .unwrap(),
        };
        let (app, _rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
            config,
            plugins.clone(),
            None,
            HashSet::new(),
            HashSet::new(),
            (None, None),
            prior,
            &rules,
            Some(opened_store),
            false,
        )
        .await
        .expect("the actual authorization server builds before resource-auth READY");
        if let Some(fresh) = &fresh_store {
            assert!(
                Arc::ptr_eq(
                    &fresh.opened(),
                    &app.governance
                        .as_ref()
                        .expect("the AS owns governance")
                        .core_store_handle()
                        .unwrap(),
                ),
                "the AS construction must retain the provisioner's actual Store"
            );
        }
        drop(limits);
        Some(Arc::new(app))
    } else {
        None
    };
    let jwks_tls = authorization_server.as_ref().map(|_| {
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("the OAuth JWKS TLS listener");
        listener
            .set_nonblocking(true)
            .expect("nonblocking JWKS listener");
        let url = format!("https://{}/jwks", listener.local_addr().unwrap());
        (tls_identity().1, url, listener)
    });
    if resource_auth {
        let block = oauth_as.expect("resource auth verifies this configured authorization server");
        let name = auth_name.expect("the actual resource verifier was staged");
        document["identity-providers"] = serde_json::json!({
            "oauth-resource": {
                "module": name,
                "settings": {
                    "issuer": block.issuer,
                    "audience": block.issuer,
                    "jwks_url": jwks_tls.as_ref().expect("the JWKS TLS listener").1,
                    "ca_cert_pem": jwks_tls.as_ref().expect("the JWKS TLS certificate").0,
                    "role_claim": "scope",
                },
            },
        });
        document["auth"]["chain"] = serde_json::json!(["oauth-resource"]);
        document["auth"]["role_bindings"] = serde_json::json!({
            "oauth-resource": { "read": {} },
        });
    }
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    // Only construction has occurred: no JWKS or application listener serves yet.
    // Finalize the originally created namespace against its eventual marked domain.
    let initialized_store = if let Some(fresh) = fresh_store {
        Some(
            fresh
                .initialize_principal_format(&config, &plugins)
                .await
                .expect("the new Store receives its baseline before serving"),
        )
    } else {
        None
    };
    if let Some((_, _, listener)) = jwks_tls {
        serve_boot_jwks(
            listener,
            Arc::clone(
                authorization_server
                    .as_ref()
                    .expect("the actual AS is ready"),
            ),
        );
    }
    let opened_store = initialized_store.or_else(|| {
        authorization_server.as_ref().map(|app| {
            let gov = app
                .governance
                .as_ref()
                .expect("the actual AS owns governance");
            gov.core_store_handle()
                .expect("the actual AS owns native persistence")
        })
    });

    let (opened_store, overlay) = if hosted_credentials {
        assert!(
            prior.is_none(),
            "hosted fixture provisioning requires a new namespace"
        );
        let registry = busbar_kernel::plugins_preflight(
            config.store.as_ref(),
            config.auth.as_ref(),
            &config.identity_providers,
            &config.hooks,
            &plugins,
            &config.export,
        )
        .expect("the actual hosted-login plugins are admitted");
        let requirements = busbar_kernel::governance::principal_transition::requirements(
            &config,
            registry.as_ref(),
        )
        .expect("the admitted hosted-login principal requirements resolve");
        let opened = if requirements
            .iter()
            .any(|requirement| !requirement.format.is_empty())
        {
            plugins::bootstrap_fresh_application_store(&config, &plugins, &directory).await
        } else {
            Ok::<_, String>(
                crate::root::real_store::core_over(
                    busbar_kernel::appbuild::bootstrap_config_store(&config, &plugins)
                        .await
                        .expect("the actual backend opens"),
                )
                .await,
            )
        }
        .expect("the actual hosted-login Store anchors its config authority");
        let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(opened.clone())
            .expect("the actual hosted-login Store supports a writable config overlay");
        (Some(opened), Some(overlay))
    } else {
        (opened_store, None)
    };
    let carried = authorization_server.as_deref().or(prior);
    let opened_store = match opened_store {
        Some(opened) => opened,
        None => {
            if let Some(app) = carried {
                app.governance
                    .as_ref()
                    .expect("retained governance")
                    .core_store_handle()
                    .unwrap()
            } else {
                crate::root::real_store::core_over(
                    busbar_kernel::appbuild::bootstrap_config_store(&config, &plugins)
                        .await
                        .expect("the actual backend opens"),
                )
                .await
            }
        }
    };
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugins,
        overlay,
        HashSet::new(),
        HashSet::new(),
        (None, None),
        carried,
        &rules,
        Some(opened_store),
        false,
    )
    .await
    .expect("the actual product builds the OAuth deployment");
    limits.stage_boot();
    let price_store = app
        .governance
        .as_ref()
        .expect("the OAuth deployment owns governance")
        .core_store_handle()
        .expect("the OAuth deployment retains its admitted Store");
    if let Some(bound) = crate::root::kernel::ROOT_CARD.card_store() {
        assert!(
            bound.is_bound_to(&price_store),
            "OAuth reloads must retain the price authority's exact CoreStore"
        );
    } else {
        crate::root::kernel::ROOT_CARD
            .keep_in_store(price_store, busbar_kernel::door::op_id().counter())
            .expect("the first OAuth deployment binds its native price Store");
        crate::root::kernel::ROOT_CARD
            .boot_in_store(None)
            .await
            .expect("the first OAuth deployment boots its native price history");
    }
    limits.keep().await.expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    Arc::new(app)
}
