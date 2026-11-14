// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WASTE-AUTH-SECRETS W1: one identity provider named by the chain, admin_auth and the hosted
//! login methods is ONE instance per build (one OPEN, one READY, one tick schedule, one verdict
//! cache), and an admin flush refreshes that instance once.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use busbar_contract::auth_calls::{AuthAxis, AuthCalls, VerifyAnswer, VerifyRequest, Verifying};

use crate::auth::instances::{flush_distinct, AuthInstances};
use crate::auth::login::LoginMethods;
use crate::auth::{AdminAuthChain, AuthMiddleware};
use crate::config::{AuthCfg, AuthChainEntry, AuthMethodCfg};

const MODULE: &str = "idp-plugin";

#[derive(Default)]
struct Counts {
    opens: AtomicUsize,
    refreshes: AtomicUsize,
}

struct Calls(Arc<Counts>);

struct Answered(Option<VerifyAnswer>);

impl std::future::Future for Answered {
    type Output = VerifyAnswer;
    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<VerifyAnswer> {
        std::task::Poll::Ready(
            self.0
                .take()
                .unwrap_or_else(|| busbar_contract::auth_calls::Verified::Pass.into()),
        )
    }
}

impl Verifying for Answered {
    fn settled(&mut self) -> Option<VerifyAnswer> {
        self.0.take()
    }
}

impl AuthCalls for Calls {
    fn name(&self) -> &str {
        MODULE
    }
    fn facts(&self) -> u32 {
        0
    }
    fn verify_now(&self, _: &VerifyRequest) -> Option<VerifyAnswer> {
        Some(busbar_contract::auth_calls::Verified::Pass.into())
    }
    fn verify(&self, _: VerifyRequest) -> Box<dyn Verifying> {
        Box::new(Answered(Some(
            busbar_contract::auth_calls::Verified::Pass.into(),
        )))
    }
    fn refresh(&self) -> Result<u64, String> {
        self.0.refreshes.fetch_add(1, Ordering::SeqCst);
        Ok(7)
    }
}

struct Axis(Arc<Counts>);

impl AuthAxis for Axis {
    fn linked_names(&self) -> Vec<String> {
        vec![MODULE.to_string()]
    }
    fn answers(&self, module: &str) -> bool {
        module == MODULE
    }
    fn linked(&self, module: &str) -> bool {
        module == MODULE
    }
    fn operator(&self) -> Option<(String, String)> {
        None
    }
    fn open(
        &self,
        _: &str,
        _: &str,
        _: &busbar_contract::plugin_settings::ResolvedSettings,
    ) -> Result<Arc<dyn AuthCalls>, String> {
        self.0.opens.fetch_add(1, Ordering::SeqCst);
        Ok(Arc::new(Calls(Arc::clone(&self.0))))
    }
}

#[derive(Debug)]
struct Rows;

impl busbar_contract::plugin_rows::PluginRows for Rows {
    fn resolve(&self, _: &str) -> Option<busbar_contract::plugin_rows::Row> {
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
    fn store_door(
        &self,
        name: &str,
    ) -> Result<busbar_contract::persistence::axis::StoreDoor, String> {
        Err(format!("no store '{name}'"))
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

/// One provider `idp` (module `idp-plugin`) in all three roles.
fn three_roles() -> AuthCfg {
    let mut entry = AuthChainEntry::bare(MODULE);
    entry.name = "idp".into();
    let mut cfg = AuthCfg::default_none();
    cfg.chain = vec![entry.clone()];
    cfg.admin_auth = vec![entry];
    cfg.methods.insert(
        "idp".into(),
        AuthMethodCfg {
            module: MODULE.into(),
            browser_login: None,
            settings: serde_json::Map::new().into(),
        },
    );
    cfg
}

struct Built {
    counts: Arc<Counts>,
    chain: AuthMiddleware,
    admin: AdminAuthChain,
    login: LoginMethods,
}

fn build(cfg: &AuthCfg) -> Built {
    let counts = Arc::new(Counts::default());
    let axis: Arc<dyn AuthAxis> = Arc::new(Axis(Arc::clone(&counts)));
    let open_axis = || Some(Arc::clone(&axis));
    let secrets = crate::config::secret::SecretResolver::builtins_only();
    let mut instances = AuthInstances::default();
    let chain = AuthMiddleware::build_on(cfg, &Rows, &secrets, &mut instances, &open_axis)
        .expect("the chain builds");
    let admin = AdminAuthChain::build_on(cfg, &Rows, &secrets, &mut instances, &open_axis)
        .expect("admin_auth builds");
    let login = LoginMethods::build_on(cfg, &Rows, &secrets, &mut instances, &open_axis)
        .expect("the login methods build");
    Built {
        counts,
        chain,
        admin,
        login,
    }
}

/// T1a: one provider in chain + admin_auth + methods is opened once per build, and every role
/// holds that one instance.
#[test]
fn one_provider_three_roles_opens_once() {
    let built = build(&three_roles());
    assert_eq!(
        built.counts.opens.load(Ordering::SeqCst),
        1,
        "one OPEN per provider"
    );
    let chain = built
        .chain
        .chain_instances(Some("idp"))
        .next()
        .expect("the chain holds idp");
    let admin = &built.admin.modules["idp"].calls;
    let login = &built.login.methods["idp"].module;
    assert!(Arc::ptr_eq(chain, admin), "chain and admin_auth share it");
    assert!(Arc::ptr_eq(chain, login), "chain and login share it");
}

/// Two providers are two instances: sharing is by provider name, never by module.
#[test]
fn two_providers_of_one_module_open_twice() {
    let mut cfg = three_roles();
    let mut other = AuthChainEntry::bare(MODULE);
    other.name = "idp-two".into();
    cfg.chain.push(other);
    cfg.methods.insert(
        "idp-two".into(),
        AuthMethodCfg {
            module: MODULE.into(),
            browser_login: None,
            settings: serde_json::Map::new().into(),
        },
    );
    let built = build(&cfg);
    assert_eq!(built.counts.opens.load(Ordering::SeqCst), 2);
}

/// T1d: an admin flush with the provider in chain and admin_auth refreshes the shared instance
/// once and counts its flushed total once.
#[test]
fn admin_flush_refreshes_shared_instance_once() {
    let built = build(&three_roles());
    assert_eq!(flush_distinct(&built.admin, &built.chain, None), Ok(7));
    assert_eq!(
        built.counts.refreshes.load(Ordering::SeqCst),
        1,
        "one REFRESH"
    );
    assert_eq!(
        flush_distinct(&built.admin, &built.chain, Some("idp")),
        Ok(7)
    );
    assert_eq!(built.counts.refreshes.load(Ordering::SeqCst), 2);
    assert_eq!(
        flush_distinct(&built.admin, &built.chain, Some("other")),
        Ok(0)
    );
    assert_eq!(built.counts.refreshes.load(Ordering::SeqCst), 2);
}
