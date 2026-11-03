// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[path = "../../../../../dist/default/tests/common/mod.rs"]
mod common;

use busbar_kernel::auth::{AuthMiddleware, ChainVerdict};

const AUDIENCE: &str = "api://auth-ordinary-chain";

fn chain_cfg(modules: &[&str]) -> busbar_kernel::config::AuthCfg {
    let mut cfg = busbar_kernel::config::AuthCfg::default_none();
    cfg.chain = modules
        .iter()
        .map(|module| {
            let mut entry = busbar_kernel::config::AuthChainEntry::bare(*module);
            if *module == "test-groups-module" {
                entry.settings = common::credentials::settings(AUDIENCE);
            }
            entry
        })
        .collect();
    cfg
}

#[test]
fn test_chain_identifies_with_module_and_principal() {
    crate::dist_root_install::install();
    let artifact = common::plugins::token_verifier_cdylib_path()
        .expect("the freshly built actual OIDC product is required");
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&artifact)
        .expect("the actual OIDC statement reads")
        .expect("the actual OIDC product exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual OIDC statement is valid")
        .name;
    let directory = common::plugins::scratch(
        "auth-ordinary-chain-test_chain_identifies_with_module_and_principal",
    );
    common::credentials::install_auth_plugin(&directory, &module, "test-groups-module", true);
    let plugins = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let registry = busbar_kernel::plugins_preflight(
        None,
        None,
        &Default::default(),
        &Default::default(),
        &plugins,
        &Default::default(),
    )
    .expect("the actual root admits the signed OIDC product");
    let mw = AuthMiddleware::new(
        &chain_cfg(&["test-groups-module"]),
        &registry,
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
    .expect("the real auth chain constructs");
    match mw.run_chain(Some(&common::credentials::token_for(
        "dev",
        &["dev"],
        AUDIENCE,
    ))) {
        ChainVerdict::Identified {
            module, principal, ..
        } => {
            assert_eq!(module, "test-groups-module");
            assert_eq!(principal.id, "oidc:dev");
            assert_eq!(principal.roles, vec!["dev".to_string()]);
        }
        other => panic!("expected Identified, got {other:?}"),
    }
    assert!(mw.validate_token(Some(&common::credentials::token_for(
        "dev",
        &["dev"],
        AUDIENCE
    ))));
    assert!(!mw.is_open());
}

#[test]
fn test_nonempty_chain_fails_closed_on_all_pass() {
    crate::dist_root_install::install();
    let artifact = common::plugins::token_verifier_cdylib_path()
        .expect("the freshly built actual OIDC product is required");
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&artifact)
        .expect("the actual OIDC statement reads")
        .expect("the actual OIDC product exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual OIDC statement is valid")
        .name;
    let directory = common::plugins::scratch(
        "auth-ordinary-chain-test_nonempty_chain_fails_closed_on_all_pass",
    );
    common::credentials::install_auth_plugin(&directory, &module, "test-groups-module", true);
    let plugins = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let registry = busbar_kernel::plugins_preflight(
        None,
        None,
        &Default::default(),
        &Default::default(),
        &plugins,
        &Default::default(),
    )
    .expect("the actual root admits the signed OIDC product");
    let mw = AuthMiddleware::new(
        &chain_cfg(&["test-groups-module"]),
        &registry,
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
    .expect("the real auth chain constructs");
    assert_eq!(
        mw.run_chain(Some("not-a-recognized-credential")),
        ChainVerdict::Denied,
        "an unrecognized credential must be denied by a configured chain"
    );
    assert_eq!(
        mw.run_chain(None),
        ChainVerdict::Denied,
        "no credential at all must be denied by a configured chain"
    );
    assert_eq!(
        mw.run_chain(Some("not-a-grp")),
        ChainVerdict::Denied,
        "the old unrecognized admin credential is refused by the real OIDC product"
    );
    assert!(!mw.validate_token(Some("tok3")));
    assert!(!mw.validate_token(None));
    assert!(!mw.validate_token(Some("")));
}

#[test]
fn test_empty_chain_is_open_front_door() {
    crate::dist_root_install::install();
    let registry =
        busbar_kernel::preflight::linked().expect("the actual root registry is installed");
    let mw = AuthMiddleware::new(
        &busbar_kernel::config::AuthCfg::default_none(),
        &registry,
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
    .expect("the real auth chain constructs");
    assert!(mw.is_open());
    assert_eq!(mw.run_chain(None), ChainVerdict::Open);
    assert_eq!(mw.run_chain(Some("anything")), ChainVerdict::Open);
    assert!(mw.validate_token(None));
    assert!(mw.validate_token(Some("anything")));
}

#[test]
fn test_keys_in_chain_sets_flag_not_module() {
    crate::dist_root_install::install();
    let artifact = common::plugins::token_verifier_cdylib_path()
        .expect("the freshly built actual OIDC product is required");
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&artifact)
        .expect("the actual OIDC statement reads")
        .expect("the actual OIDC product exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual OIDC statement is valid")
        .name;
    let directory =
        common::plugins::scratch("auth-ordinary-chain-test_keys_in_chain_sets_flag_not_module");
    common::credentials::install_auth_plugin(&directory, &module, "test-groups-module", true);
    let plugins = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let registry = busbar_kernel::plugins_preflight(
        None,
        None,
        &Default::default(),
        &Default::default(),
        &plugins,
        &Default::default(),
    )
    .expect("the actual root admits the signed OIDC product");
    let mw = AuthMiddleware::new(
        &chain_cfg(&["keys"]),
        &registry,
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
    .expect("the real auth chain constructs");
    assert!(mw.keys_in_chain, "chain: [keys] must set keys_in_chain");
    assert!(
        mw.chain_names().is_empty(),
        "keys is engine-handled, never a boxed module"
    );

    let mw = AuthMiddleware::new(
        &busbar_kernel::config::AuthCfg::default_none(),
        &registry,
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
    .expect("the real auth chain constructs");
    assert!(!mw.keys_in_chain, "an empty chain must not claim keys");

    let mw = AuthMiddleware::new(
        &chain_cfg(&["keys", "test-groups-module"]),
        &registry,
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
    .expect("the real auth chain constructs");
    assert!(mw.keys_in_chain);
    assert_eq!(mw.chain_names(), vec![module.clone()]);
    assert!(mw.validate_token(Some(&common::credentials::token_for(
        "dev",
        &["dev"],
        AUDIENCE
    ))));
    assert!(!mw.validate_token(Some("wrong")), "still fail-closed");
}

#[test]
fn test_auth_middleware_debug_redacts_tokens() {
    crate::dist_root_install::install();
    let artifact = common::plugins::token_verifier_cdylib_path()
        .expect("the freshly built actual OIDC product is required");
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&artifact)
        .expect("the actual OIDC statement reads")
        .expect("the actual OIDC product exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual OIDC statement is valid")
        .name;
    let directory =
        common::plugins::scratch("auth-ordinary-chain-test_auth_middleware_debug_redacts_tokens");
    common::credentials::install_auth_plugin(&directory, &module, "test-groups-module", true);
    let plugins = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let registry = busbar_kernel::plugins_preflight(
        None,
        None,
        &Default::default(),
        &Default::default(),
        &plugins,
        &Default::default(),
    )
    .expect("the actual root admits the signed OIDC product");
    let cfg = chain_cfg(&["keys", "test-groups-module"]);
    let mw = AuthMiddleware::new(
        &cfg,
        &registry,
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
    .expect("the real auth chain constructs");
    let dbg = format!("{mw:?}");
    assert!(
        dbg.contains("chain_len"),
        "AuthMiddleware Debug should report the chain length: {dbg}"
    );
    assert!(
        dbg.contains("keys_in_chain"),
        "AuthMiddleware Debug should report the keys flag: {dbg}"
    );

    for forbidden in ["token", "secret", "credential"] {
        assert!(
            !dbg.to_ascii_lowercase()
                .replace("keys_in_chain", "")
                .contains(forbidden),
            "AuthMiddleware Debug printed an unexpected field '{forbidden}': {dbg}"
        );
    }
}

#[test]
fn a_keys_only_chain_is_not_an_open_front_door() {
    crate::dist_root_install::install();
    let artifact = common::plugins::token_verifier_cdylib_path()
        .expect("the freshly built actual OIDC product is required");
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&artifact)
        .expect("the actual OIDC statement reads")
        .expect("the actual OIDC product exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual OIDC statement is valid")
        .name;
    let directory =
        common::plugins::scratch("auth-ordinary-chain-a_keys_only_chain_is_not_an_open_front_door");
    common::credentials::install_auth_plugin(&directory, &module, "test-groups-module", true);
    let plugins = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let registry = busbar_kernel::plugins_preflight(
        None,
        None,
        &Default::default(),
        &Default::default(),
        &plugins,
        &Default::default(),
    )
    .expect("the actual root admits the signed OIDC product");
    let mw = AuthMiddleware::new(
        &chain_cfg(&["keys"]),
        &registry,
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
    .expect("the real auth chain constructs");
    assert!(mw.keys_in_chain, "precondition: keys sets the flag");
    assert!(
        mw.chain_names().is_empty(),
        "precondition: keys installs no boxed module"
    );
    assert!(
        !mw.is_open(),
        "chain: [keys] authenticates, so the front door is CLOSED — reporting it open grants \
         VerbScope::Full to every caller at Root::admin_grant"
    );

    let none = AuthMiddleware::new(
        &busbar_kernel::config::AuthCfg::default_none(),
        &registry,
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
    .expect("the real auth chain constructs");
    assert!(none.is_open(), "no module and no keys arm IS the open door");

    let both = AuthMiddleware::new(
        &chain_cfg(&["keys", "test-groups-module"]),
        &registry,
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
    .expect("the real auth chain constructs");
    assert!(!both.is_open(), "a boxed module closes the door regardless");
}

#[test]
fn a_verified_oidc_role_is_bound_under_the_provider_name() {
    crate::dist_root_install::install();
    let artifact = common::plugins::token_verifier_cdylib_path()
        .expect("the freshly built actual OIDC product is required");
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&artifact)
        .expect("the actual OIDC statement reads")
        .expect("the actual OIDC product exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual OIDC statement is valid")
        .name;
    let directory = common::plugins::scratch(
        "auth-ordinary-chain-a_verified_oidc_role_is_bound_under_the_provider_name",
    );
    common::credentials::install_auth_plugin(&directory, &module, "idp", true);
    let plugins = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let registry = busbar_kernel::plugins_preflight(
        None,
        None,
        &Default::default(),
        &Default::default(),
        &plugins,
        &Default::default(),
    )
    .expect("the actual root admits the signed OIDC product");
    let mut provider = busbar_kernel::config::AuthChainEntry::bare(module);
    provider.name = "idp".to_string();
    provider.settings = common::credentials::settings(AUDIENCE);
    let cfg = busbar_kernel::config::AuthCfg {
        chain: vec![provider],
        ..busbar_kernel::config::AuthCfg::default_none()
    };
    let mw = AuthMiddleware::new(
        &cfg,
        &registry,
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
    .expect("the actual named provider constructs");
    match mw.run_chain(Some(&common::credentials::token_for(
        "alice",
        &["platform"],
        AUDIENCE,
    ))) {
        ChainVerdict::Identified {
            module, principal, ..
        } => {
            assert_eq!(module, "idp");
            assert_eq!(principal.id, "oidc:alice");
            assert_eq!(principal.roles, vec!["platform".to_string()]);
        }
        other => panic!("expected Identified, got {other:?}"),
    }
    assert!(mw.validate_token(Some(&common::credentials::token_for(
        "alice",
        &["platform"],
        AUDIENCE
    ))));
    assert!(!mw.is_open());
}

#[test]
fn a_slow_auth_door_does_not_park_the_reactor() {
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    crate::dist_root_install::install();
    let artifact = common::plugins::token_verifier_cdylib_path()
        .expect("the freshly built actual OIDC product is required");
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&artifact)
        .expect("the actual OIDC statement reads")
        .expect("the actual OIDC product exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual OIDC statement is valid")
        .name;
    let directory = common::plugins::scratch("auth-real-pending-jwks");
    common::credentials::install_auth_plugin(&directory, &module, "slow-idp", true);
    let plugins = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let registry = busbar_kernel::plugins_preflight(
        None,
        None,
        &Default::default(),
        &Default::default(),
        &plugins,
        &Default::default(),
    )
    .expect("the actual root admits the signed OIDC product");
    let mut settings = common::credentials::settings(AUDIENCE);
    let target = settings["jwks_url"]
        .as_str()
        .unwrap()
        .strip_prefix("https://")
        .expect("the existing issuer uses real TLS")
        .split_once('/')
        .unwrap()
        .0
        .parse()
        .expect("the issuer endpoint is an actual loopback socket");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the one-connection external peer");
    listener.set_nonblocking(true).unwrap();
    settings.insert(
        "jwks_url".into(),
        serde_json::json!(format!("https://{}/jwks", listener.local_addr().unwrap())),
    );
    let token = common::credentials::token_for("alice", &["platform"], AUDIENCE);
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();

    // One owned external wire peer. It holds the first genuine TLS byte, then forwards every
    // byte unchanged to the existing real TLS/JWKS issuer; it fabricates no protocol or outcome.
    std::thread::scope(|peers| {
        let wire = peers.spawn(move || {
            let accept_deadline = Instant::now() + Duration::from_secs(10);
            let mut downstream = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < accept_deadline,
                            "the actual verifier must connect"
                        );
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("actual peer accept failed: {error}"),
                }
            };
            downstream.set_nonblocking(false).unwrap();
            downstream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            downstream
                .set_write_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut first = [0u8; 1];
            downstream
                .read_exact(&mut first)
                .expect("the actual verifier starts TLS");
            let entered = Instant::now();
            entered_tx.send(entered).unwrap();
            release_rx
                .recv_timeout(Duration::from_secs(10))
                .expect("the pending verifier is released after the unrelated-job observation");
            if let Some(remaining) = Duration::from_secs(3).checked_sub(entered.elapsed()) {
                std::thread::sleep(remaining);
            }
            let held = entered.elapsed();
            let mut upstream = TcpStream::connect_timeout(&target, Duration::from_secs(5))
                .expect("connect the existing actual TLS/JWKS issuer");
            upstream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            upstream
                .set_write_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            upstream
                .write_all(&first)
                .expect("forward the held TLS byte unchanged");
            let mut downstream_read = downstream.try_clone().unwrap();
            let mut upstream_write = upstream.try_clone().unwrap();
            let (client_bytes, issuer_bytes) = std::thread::scope(|copies| {
                let forward = copies.spawn(move || {
                    let count = std::io::copy(
                        &mut (&mut downstream_read).take(64 * 1024),
                        &mut upstream_write,
                    )
                    .expect("forward actual client TLS bytes");
                    let _ = upstream_write.shutdown(Shutdown::Write);
                    assert!(count < 64 * 1024, "client wire overflow is a failure");
                    count + 1
                });
                let count =
                    std::io::copy(&mut (&mut upstream).take(64 * 1024 + 1), &mut downstream)
                        .expect("forward actual issuer TLS bytes");
                let _ = downstream.shutdown(Shutdown::Both);
                assert!(count <= 64 * 1024, "issuer wire overflow is a failure");
                (forward.join().expect("the owned forwarder joins"), count)
            });
            (held, client_bytes, issuer_bytes)
        });
        let mut provider = busbar_kernel::config::AuthChainEntry::bare(module);
        provider.name = "slow-idp".into();
        provider.settings = settings;
        let cfg = busbar_kernel::config::AuthCfg {
            chain: vec![provider],
            ..busbar_kernel::config::AuthCfg::default_none()
        };
        let auth = Arc::new(
            AuthMiddleware::new(
                &cfg,
                &registry,
                &busbar_kernel::config::secret::SecretResolver::builtins_only(),
            )
            .expect("the actual OIDC verifier constructs without fetching its keys"),
        );
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("the one-worker runtime");
        let verify = runtime.spawn(async move {
            AuthMiddleware::run_chain_on_request_path(
                &auth,
                Some(token),
                busbar_kernel::auth::ChainHead::default(),
                None,
                None,
            )
            .await
        });
        entered_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the real verifier reaches its actual TLS/JWKS need");
        let pending_before_probe = !verify.is_finished();
        let (probe_tx, probe_rx) = std::sync::mpsc::channel();
        runtime.spawn(async move {
            let _ = probe_tx.send("healthz ok");
        });
        let served = probe_rx.recv_timeout(Duration::from_secs(2));
        let pending_after_probe = !verify.is_finished();
        release_tx
            .send(())
            .expect("release the owned external peer");
        let verdict = runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(10), verify)
                .await
                .expect("the released actual verify completes")
                .expect("the actual verify task joins")
        });
        let (held, client_bytes, issuer_bytes) = wire.join().expect("the owned wire peer joins");
        assert!(
            matches!(served, Ok("healthz ok")),
            "the one worker serves while the actual OIDC verifier awaits JWKS: {served:?}"
        );
        assert!(
            pending_before_probe && pending_after_probe,
            "the unrelated job must be observed during actual verifier Pending"
        );
        assert!(
            held >= Duration::from_secs(3),
            "the real network need stayed held for three seconds"
        );
        assert!(
            client_bytes > 1 && issuer_bytes > 0,
            "actual TLS request and response bytes crossed"
        );
        assert!(
            matches!(verdict, ChainVerdict::Identified { module, principal, .. }
            if module == "slow-idp" && principal.id == "oidc:alice"),
            "only the genuine signed token/real JWKS response qualifies the completion"
        );
    });
}
