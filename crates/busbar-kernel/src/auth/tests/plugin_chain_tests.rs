// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::auth::{AuthMiddleware, ChainVerdict};
use crate::config::{AuthCfg, AuthChainEntry, PluginsCfg};
use crate::tests::{dropped, tmp_plugin_dir};
use std::path::Path;

fn plugins_cfg_allow_unsigned(dir: &Path) -> PluginsCfg {
    let mut cfg = PluginsCfg {
        enabled: true,
        dir: dir.to_string_lossy().into_owned(),
        ..Default::default()
    };
    cfg.trust.allow_unsigned = true;
    cfg
}

fn chain_with(module: &str, settings: serde_json::Map<String, serde_json::Value>) -> AuthCfg {
    let mut entry = AuthChainEntry::bare(module);
    entry.settings = settings;
    AuthCfg {
        chain: vec![entry],
        ..AuthCfg::default_none()
    }
}

struct PlatformRole;
impl busbar_contract::auth::AuthModule for PlatformRole {
    fn name(&self) -> &'static str {
        "platform-role-module"
    }
    fn authenticate(&self, candidate: Option<&str>) -> busbar_contract::auth::AuthVerdict {
        match candidate {
            Some("alice") => busbar_contract::auth::AuthVerdict::Identify(crate::auth::Principal {
                id: "oidc:alice".to_string(),
                name: None,
                roles: vec!["platform".to_string()],
                ttl_secs: None,
            }),
            _ => busbar_contract::auth::AuthVerdict::Pass,
        }
    }
}

#[test]
fn auth_plugin_role_binding_and_scope_cap_apply() {
    use busbar_contract::authz::Scope;
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));

    let mut cfg = chain_with("idp", serde_json::Map::new());

    cfg.chain[0].max_admin_scope = Some("read-only".into());

    let mut roles = std::collections::BTreeMap::new();
    roles.insert(
        "platform".to_string(),
        crate::config::RoleBindingCfg {
            admin_scope: Some("full".into()),
            ..Default::default()
        },
    );
    cfg.role_bindings.insert("idp".into(), roles);

    let mw = AuthMiddleware::from_doors_for_test(vec![(
        "idp".to_string(),
        std::sync::Arc::new(crate::auth::stand_in::InProcessAuth::new(Box::new(
            PlatformRole,
        ))) as std::sync::Arc<dyn busbar_contract::auth_calls::AuthCalls>,
    )]);

    let principal = match mw.run_chain(Some("alice")) {
        ChainVerdict::Identified {
            module, principal, ..
        } => {
            assert_eq!(module, "idp", "role_bindings key = the PROVIDER NAME");
            principal
        }
        other => panic!("expected Identify, got {other:?}"),
    };

    let bound = crate::auth::admin_scope_for(
        &crate::test_support::TestApp::new()
            .role_bindings(cfg.role_bindings.clone())
            .build(),
        Some("idp"),
        Some(&principal),
    );
    assert_eq!(
        bound,
        busbar_contract::authz::Grants::of(Scope::Full),
        "role binds full under the provider name"
    );

    for (configured, expected) in [("read-only", Scope::ReadOnly), ("full", Scope::Full)] {
        cfg.chain[0].max_admin_scope = Some(configured.into());
        let mut app = crate::test_support::TestApp::new()
            .admin_chain(vec!["idp".into()])
            .admin_module("idp", Box::new(PlatformRole))
            .role_bindings(cfg.role_bindings.clone())
            .build();
        std::sync::Arc::get_mut(&mut app)
            .expect("fresh app is unshared")
            .auth_scope_caps = crate::router::project_auth_scope_caps(&cfg);
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("authorization", "Bearer alice".parse().unwrap());
        assert_eq!(
            crate::auth::dry_run_admin_scope(&app, &headers),
            busbar_contract::authz::Grants::of(expected),
            "the configured {configured} ceiling must reach the real admin authorization path"
        );
    }
}

#[test]
fn missing_auth_plugin_is_loud_boot_failure() {
    let dir = tmp_plugin_dir("auth-plugin-missing");

    crate::test_support::rows::drop_in(
        &dir,
        vec![dropped(
            "acme-store-x",
            "x",
            busbar_contract::abi::mechanism::kind::STORE,
        )],
        Vec::new(),
    );
    let plugins = plugins_cfg_allow_unsigned(&dir);
    let cfg = chain_with("test-idp-double", serde_json::Map::new());

    let err = crate::plugins_preflight(
        None,
        Some(&cfg),
        &Default::default(),
        &Default::default(),
        &plugins,
        &Default::default(),
    )
    .unwrap_err();
    assert!(
        err.contains("test-idp-double"),
        "names the missing module: {err}"
    );
    assert!(
        err.contains("no plugin matching") && err.contains("is installed in"),
        "explains it is unresolved: {err}"
    );

    assert!(
        err.contains("enabled") && err.contains("plugins.fetch"),
        "gives the two-part enabled?/in-folder? diagnosis: {err}"
    );

    let registry = crate::plugins_preflight(
        None,
        None,
        &Default::default(),
        &Default::default(),
        &plugins,
        &Default::default(),
    )
    .expect("the directory builds");
    let mw_err = AuthMiddleware::new(
        &cfg,
        &registry,
        &crate::config::secret::SecretResolver::builtins_only(),
    )
    .unwrap_err();
    assert!(
        mw_err.contains("test-idp-double"),
        "middleware names it: {mw_err}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn auth_plugin_with_plugins_disabled_is_boot_error_naming_the_flag() {
    let dir = tmp_plugin_dir("auth-plugin-disabled");
    let plugins = PluginsCfg {
        enabled: false,
        dir: dir.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let cfg = chain_with("test-idp-double", serde_json::Map::new());
    let err = crate::plugins_preflight(
        None,
        Some(&cfg),
        &Default::default(),
        &Default::default(),
        &plugins,
        &Default::default(),
    )
    .unwrap_err();
    assert!(err.contains("plugins.enabled"), "names the flag: {err}");
    assert!(
        err.contains("test-idp-double"),
        "names the auth module: {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn keys_module_is_not_a_plugin_ref() {
    let cfg = AuthCfg {
        chain: vec![AuthChainEntry::bare(crate::config::KEYS_MODULE)],
        ..AuthCfg::default_none()
    };

    let plugins = PluginsCfg::default();
    let registry = crate::plugins_preflight(
        None,
        Some(&cfg),
        &Default::default(),
        &Default::default(),
        &plugins,
        &Default::default(),
    )
    .expect("keys needs no plugin");
    let mw = AuthMiddleware::new(
        &cfg,
        &registry,
        &crate::config::secret::SecretResolver::builtins_only(),
    )
    .expect("keys chain builds");
    assert!(mw.keys_in_chain, "keys sets the engine flag");
    assert!(mw.chain_names().is_empty(), "keys is not a boxed module");
}

struct SlowDoor {
    entered: std::sync::Mutex<std::sync::mpsc::Sender<()>>,
    hold: std::time::Duration,
}

struct Later(tokio::sync::oneshot::Receiver<busbar_contract::auth_calls::VerifyAnswer>);

impl std::future::Future for Later {
    type Output = busbar_contract::auth_calls::VerifyAnswer;
    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::future::Future::poll(std::pin::Pin::new(&mut self.0), cx).map(|answer| {
            answer.unwrap_or_else(|_| busbar_contract::auth_calls::Verified::Failed.into())
        })
    }
}

impl busbar_contract::auth_calls::Verifying for Later {
    fn settled(&mut self) -> Option<busbar_contract::auth_calls::VerifyAnswer> {
        self.0.try_recv().ok()
    }
}

impl busbar_contract::auth_calls::AuthCalls for SlowDoor {
    fn name(&self) -> &str {
        "slow-door"
    }
    fn facts(&self) -> u32 {
        0
    }
    fn verify_now(
        &self,
        _: &busbar_contract::auth_calls::VerifyRequest,
    ) -> Option<busbar_contract::auth_calls::VerifyAnswer> {
        None
    }
    fn verify(
        &self,
        _: busbar_contract::auth_calls::VerifyRequest,
    ) -> Box<dyn busbar_contract::auth_calls::Verifying> {
        let _ = self.entered.lock().unwrap().send(());
        let (tx, rx) = tokio::sync::oneshot::channel();
        let hold = self.hold;
        std::thread::spawn(move || {
            std::thread::sleep(hold);
            let _ = tx.send(busbar_contract::auth_calls::Verified::Pass.into());
        });
        Box::new(Later(rx))
    }
    fn refresh(&self) -> Result<u64, String> {
        Ok(0)
    }
}

#[test]
fn a_slow_auth_door_does_not_park_the_reactor() {
    let (tx, entered) = std::sync::mpsc::channel();
    let door = SlowDoor {
        entered: std::sync::Mutex::new(tx),
        hold: std::time::Duration::from_secs(3),
    };
    let auth = std::sync::Arc::new(AuthMiddleware::from_doors_for_test(vec![(
        "slow".to_string(),
        std::sync::Arc::new(door) as std::sync::Arc<dyn busbar_contract::auth_calls::AuthCalls>,
    )]));
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("runtime");

    rt.spawn(async move {
        let _ = AuthMiddleware::run_chain_on_request_path(
            &auth,
            Some("tok".into()),
            crate::auth::ChainHead::default(),
            None,
            None,
        )
        .await;
    });
    entered
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("the door must actually have been asked");

    let (ptx, probe) = std::sync::mpsc::channel();
    rt.spawn(async move {
        let _ = ptx.send("healthz ok");
    });
    let served = probe.recv_timeout(std::time::Duration::from_secs(2));
    assert!(
        matches!(served, Ok("healthz ok")),
        "the runtime must keep serving while an auth door answers; the worker is parked on the \
         plugin (got {served:?})"
    );
}

#[test]
fn chain_open_wipes_the_resolved_settings() {
    fn wiped_when_dropped<T: zeroize::ZeroizeOnDrop>(_: &T) {}
    let var = format!("BUSBAR_CHAIN_WIPE_{}", std::process::id());
    std::env::set_var(&var, "chain-open-secret\n");
    let settings: serde_json::Map<String, serde_json::Value> = [
        (
            "client_secret".to_string(),
            serde_json::json!({ "env": var }),
        ),
        (
            "issuer".to_string(),
            serde_json::json!("https://idp.example"),
        ),
    ]
    .into_iter()
    .collect();
    let mut resolved = crate::config::secret::resolve_settings(
        &settings,
        &["client_secret".to_string()],
        &[],
        "busbar-auth-oidc",
        &crate::config::secret::SecretResolver::builtins_only(),
        &busbar_contract::config_time::ConfigScope::config_time(),
    )
    .expect("the declared reference resolves");
    std::env::remove_var(&var);
    assert_eq!(
        resolved.as_value()["client_secret"],
        serde_json::json!("chain-open-secret"),
        "the plugin is handed the resolved value"
    );

    wiped_when_dropped(&resolved);

    zeroize::Zeroize::zeroize(&mut resolved);
    assert!(
        !resolved
            .as_value()
            .to_string()
            .contains("chain-open-secret"),
        "the wipe left the secret: {resolved:?}"
    );
}
