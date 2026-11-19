// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUTH ROLES WITH NO PLUGIN AUTH AXIS: a module that is neither `keys`, an unset operator row
//! nor one a native auth image answers is refused, after its settings resolve (a settings refusal
//! wins); the operator carries nothing; the chain's default inbound style and issued credential are
//! empty. These pin the behaviour the build has when no `kind: auth` plugin axis exists.

use std::sync::Arc;

use crate::auth::login::LoginMethods;
use crate::auth::{AdminAuthChain, AuthMiddleware};
use crate::config::{AuthCfg, AuthChainEntry, AuthMethodCfg};

const MODULE: &str = "idp-plugin";

#[derive(Debug, Default)]
struct Rows;

impl busbar_contract::plugin_rows::PluginRows for Rows {
    fn resolve(&self, name: &str) -> Option<busbar_contract::plugin_rows::Row> {
        (name == MODULE).then(|| crate::tests::dropped(MODULE, MODULE, "auth"))
    }
    fn archive_sha256(&self, _: &str) -> Option<String> {
        None
    }
    fn unresolved_reason(&self, _: &str) -> Option<busbar_contract::plugin_rows::Skipped> {
        None
    }
    fn loadable(&self) -> Vec<busbar_contract::plugin_rows::Row> {
        Vec::new()
    }
    fn linked(&self) -> Vec<busbar_contract::plugin_rows::Row> {
        Vec::new()
    }
    fn skipped(&self) -> Vec<busbar_contract::plugin_rows::Skipped> {
        Vec::new()
    }
    fn secret_refusal(&self, name: &str) -> String {
        format!("no secret '{name}'")
    }
    fn kind_refusal(&self, kind: &str, _: &str, name: &str) -> String {
        format!("no {kind} '{name}'")
    }
    fn secret_slots(&self, _: &str) -> Vec<String> {
        Vec::new()
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn into_any(self: Arc<Self>) -> Arc<dyn std::any::Any + Send + Sync> {
        self
    }
}

fn registry() -> Arc<dyn busbar_contract::plugin_rows::PluginRows> {
    Arc::new(Rows)
}

/// Settings holding a secret reference at a path the plugin does not declare: resolution refuses.
fn refused_settings() -> busbar_contract::plugin_settings::Settings {
    let mut map = serde_json::Map::new();
    map.insert(
        "token".into(),
        serde_json::json!({"$secret": {"module": "env", "settings": {"name": "IDP_TOKEN"}}}),
    );
    map.into()
}

fn entry(settings: Option<busbar_contract::plugin_settings::Settings>) -> AuthChainEntry {
    let mut entry = AuthChainEntry::bare(MODULE);
    entry.name = "idp".into();
    if let Some(settings) = settings {
        entry.settings = settings;
    }
    entry
}

fn chain_of(entries: Vec<AuthChainEntry>) -> AuthCfg {
    let mut cfg = AuthCfg::default_none();
    cfg.chain = entries;
    cfg
}

fn admin_of(entry: AuthChainEntry) -> AuthCfg {
    let mut cfg = AuthCfg::default_none();
    cfg.admin_auth = vec![entry];
    cfg
}

fn method_of(settings: Option<busbar_contract::plugin_settings::Settings>) -> AuthCfg {
    let mut cfg = AuthCfg::default_none();
    cfg.methods.insert(
        "idp".into(),
        AuthMethodCfg {
            module: MODULE.into(),
            browser_login: None,
            settings: settings.unwrap_or_else(|| serde_json::Map::new().into()),
        },
    );
    cfg
}

fn secrets() -> crate::config::secret::SecretResolver {
    crate::config::secret::SecretResolver::builtins_only()
}

fn login(cfg: &AuthCfg) -> Result<LoginMethods, String> {
    LoginMethods::build_on(cfg, registry().as_ref(), &secrets())
}

#[test]
fn a_chain_module_no_axis_answers_is_refused() {
    let Err(refusal) = AuthMiddleware::new(&chain_of(vec![entry(None)]), &registry(), &secrets())
    else {
        panic!("a chain module no auth axis answers built");
    };
    assert_eq!(
        refusal,
        "auth.chain module 'idp-plugin' could not be loaded as a `kind: auth` plugin: no `kind: \
         auth` plugin answers to 'idp-plugin'"
    );
}

#[test]
fn a_chain_module_settings_refusal_wins_over_the_missing_axis() {
    let cfg = chain_of(vec![entry(Some(refused_settings()))]);
    let Err(refusal) = AuthMiddleware::new(&cfg, &registry(), &secrets()) else {
        panic!("a chain module whose settings refuse built");
    };
    assert!(
        refusal.starts_with("auth.chain module 'idp-plugin' settings: ")
            && !refusal.contains("no `kind: auth` plugin answers"),
        "{refusal}"
    );
}

#[test]
fn a_keys_chain_has_no_readers_carriers_or_issued_credential() {
    let mw = AuthMiddleware::new(
        &chain_of(vec![AuthChainEntry::bare(crate::config::KEYS_MODULE)]),
        &registry(),
        &secrets(),
    )
    .expect("a keys-only chain builds");
    assert!(mw.keys_in_chain);
    assert!(mw.chain.is_empty());
    assert!(mw.readers.is_empty());
    assert!(mw.reader_by_carrier.is_empty());
    assert!(mw.carriers.is_empty());
    assert!(mw.issued.is_none());
}

#[test]
fn an_empty_chain_has_no_carriers_or_issued_credential() {
    let mw = AuthMiddleware::new(&chain_of(Vec::new()), &registry(), &secrets())
        .expect("an empty chain builds");
    assert!(!mw.keys_in_chain);
    assert!(mw.readers.is_empty());
    assert!(mw.carriers.is_empty());
    assert!(mw.issued.is_none());
}

#[test]
fn an_admin_module_no_axis_answers_is_refused() {
    let Err(refusal) = AdminAuthChain::build(&admin_of(entry(None)), &registry(), &secrets())
    else {
        panic!("an admin module no auth axis answers built");
    };
    assert_eq!(
        refusal,
        "auth.admin_auth provider 'idp' (module 'idp-plugin') could not be loaded as a `kind: \
         auth` plugin: no `kind: auth` plugin answers to 'idp-plugin'"
    );
}

#[test]
fn an_admin_module_settings_refusal_wins_over_the_missing_axis() {
    let cfg = admin_of(entry(Some(refused_settings())));
    let Err(refusal) = AdminAuthChain::build(&cfg, &registry(), &secrets()) else {
        panic!("an admin module whose settings refuse built");
    };
    assert!(
        refusal.starts_with("identity-providers.idp settings: ")
            && !refusal.contains("no `kind: auth` plugin answers"),
        "{refusal}"
    );
}

#[test]
fn a_keys_admin_chain_opens_nothing_and_the_operator_carries_nothing() {
    let cfg = admin_of(AuthChainEntry::bare(crate::config::KEYS_MODULE));
    let admin = AdminAuthChain::build(&cfg, &registry(), &secrets()).expect("keys admin builds");
    assert!(admin.modules.is_empty());
    assert!(admin.operator.carriers().is_empty());
}

/// D-OPERATOR (E6's finding (a)): an `admin_auth` module a native (MIN-3) auth image answers opens nothing here: the root
/// builds that admin chain natively over the image's opened instance (`root::min3_admin_auth`).
#[test]
fn an_admin_module_a_native_image_answers_opens_no_door_instance() {
    crate::preflight::publish_root_rows(crate::preflight::RootInstall {
        native_auth: Some(|module| module == "native-op"),
        ..Default::default()
    });
    let mut entry = AuthChainEntry::bare("native-op");
    entry.name = "native-op".into();
    if let Err(refusal) = AdminAuthChain::build(&admin_of(entry), &registry(), &secrets()) {
        panic!("a natively answered admin module opens no door instance, yet the build refused: {refusal}");
    }
}

#[test]
fn a_login_method_no_axis_answers_is_refused() {
    let Err(refusal) = login(&method_of(None)) else {
        panic!("a login method no auth axis answers built");
    };
    assert_eq!(
        refusal,
        "identity-providers.idp (module 'idp-plugin') could not be loaded as a `kind: auth` login \
         plugin: no `kind: auth` plugin answers to 'idp-plugin'"
    );
}

#[test]
fn a_login_method_settings_refusal_wins_over_the_missing_axis() {
    let Err(refusal) = login(&method_of(Some(refused_settings()))) else {
        panic!("a login method whose settings refuse built");
    };
    assert!(
        refusal.starts_with("identity-providers.idp settings: ")
            && !refusal.contains("no `kind: auth` plugin answers"),
        "{refusal}"
    );
}

#[test]
fn no_login_methods_build_empty() {
    let methods = login(&AuthCfg::default_none()).expect("no methods build");
    assert!(methods.methods.is_empty());
}
