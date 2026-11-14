// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WASTE-AUTH-SECRETS W1: one identity provider named by the chain, admin_auth and the hosted
//! login methods is ONE instance per build (one OPEN, one READY, one tick schedule, one verdict
//! cache), and an admin flush refreshes that instance once.
//!
//! WASTE-AUTH-SECRETS W2: the next build carries an instance whose inputs are unchanged and that
//! reports `reusable()`; a changed provider, a changed binary or an unhealthy instance is opened
//! again, with why.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use busbar_contract::auth_calls::{AuthAxis, AuthCalls, VerifyAnswer, VerifyRequest, Verifying};

use crate::auth::instances::{flush_distinct, AuthInstances, Opening};
use crate::auth::login::LoginMethods;
use crate::auth::{AdminAuthChain, AuthMiddleware};
use crate::config::{AuthCfg, AuthChainEntry, AuthMethodCfg};

const MODULE: &str = "idp-plugin";

#[derive(Default)]
struct Counts {
    opens: AtomicUsize,
    refreshes: AtomicUsize,
    /// What every instance this axis opened answers to `reusable()`.
    unhealthy: AtomicBool,
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
    fn answering(&self) -> bool {
        true
    }
    fn reusable(&self) -> bool {
        !self.0.unhealthy.load(Ordering::SeqCst)
    }
}

/// An implementor that states no health: the trait's defaults.
struct Silent;

impl AuthCalls for Silent {
    fn name(&self) -> &str {
        MODULE
    }
    fn facts(&self) -> u32 {
        0
    }
    fn verify_now(&self, _: &VerifyRequest) -> Option<VerifyAnswer> {
        None
    }
    fn verify(&self, _: VerifyRequest) -> Box<dyn Verifying> {
        Box::new(Answered(None))
    }
    fn refresh(&self) -> Result<u64, String> {
        Ok(0)
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

/// The build's rows: `idp-plugin` admitted, from the archive `archive` names.
#[derive(Debug, Default)]
struct Rows {
    archive: Option<&'static str>,
}

impl busbar_contract::plugin_rows::PluginRows for Rows {
    fn resolve(&self, name: &str) -> Option<busbar_contract::plugin_rows::Row> {
        (name == MODULE).then(|| crate::tests::dropped(MODULE, MODULE, "auth"))
    }
    fn archive_sha256(&self, name: &str) -> Option<String> {
        (name == MODULE).then(|| self.archive.unwrap_or("a1").to_string())
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
    build_over(cfg, &Arc::new(Counts::default()), &Rows::default(), None).0
}

/// One build of the three roles over `prior` (the build before it), as `build_app_from_config`
/// makes it; answers the roles and the build's sealed instances.
fn build_over(
    cfg: &AuthCfg,
    counts: &Arc<Counts>,
    rows: &Rows,
    prior: Option<Arc<AuthInstances>>,
) -> (Built, Arc<AuthInstances>) {
    let axis: Arc<dyn AuthAxis> = Arc::new(Axis(Arc::clone(counts)));
    let open_axis = || Some(Arc::clone(&axis));
    let secrets = crate::config::secret::SecretResolver::builtins_only();
    let mut instances = AuthInstances::carrying(prior);
    let chain = AuthMiddleware::build_on(cfg, rows, &secrets, &mut instances, &open_axis)
        .expect("the chain builds");
    let admin = AdminAuthChain::build_on(cfg, rows, &secrets, &mut instances, &open_axis)
        .expect("admin_auth builds");
    let login = LoginMethods::build_on(cfg, rows, &secrets, &mut instances, &open_axis)
        .expect("the login methods build");
    (
        Built {
            counts: Arc::clone(counts),
            chain,
            admin,
            login,
        },
        instances.sealed(),
    )
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

fn opens(counts: &Counts) -> usize {
    counts.opens.load(Ordering::SeqCst)
}

fn with_settings(mut cfg: AuthCfg, provider: &str, key: &str, value: &str) -> AuthCfg {
    let set = |settings: &mut busbar_contract::plugin_settings::Settings| {
        let mut map = serde_json::Map::new();
        map.insert(key.into(), serde_json::Value::String(value.into()));
        *settings = map.into();
    };
    for entry in cfg.chain.iter_mut().chain(cfg.admin_auth.iter_mut()) {
        if entry.name == provider {
            set(&mut entry.settings);
        }
    }
    if let Some(method) = cfg.methods.get_mut(provider) {
        set(&mut method.settings);
    }
    cfg
}

/// T2a: a reload that changes nothing about auth opens nothing: every role of the new build holds
/// the prior build's instance.
#[test]
fn reload_with_no_auth_change_reopens_nothing() {
    let counts = Arc::new(Counts::default());
    let cfg = three_roles();
    let (boot, first) = build_over(&cfg, &counts, &Rows::default(), None);
    assert_eq!(opens(&counts), 1);
    assert_eq!(first.opened(), &[("idp".to_string(), Opening::New)]);

    let (reload, second) = build_over(&cfg, &counts, &Rows::default(), Some(first));
    assert_eq!(opens(&counts), 1, "no OPEN on a reload with no auth change");
    assert!(second.opened().is_empty());
    assert_eq!(second.reused(), &["idp".to_string()]);
    let was = boot.chain.chain_instances(None).next().expect("idp");
    let now = reload.chain.chain_instances(None).next().expect("idp");
    assert!(
        Arc::ptr_eq(was, now),
        "the chain holds the carried instance"
    );
    assert!(Arc::ptr_eq(now, &reload.admin.modules["idp"].calls));
    assert!(Arc::ptr_eq(now, &reload.login.methods["idp"].module));

    let (_, third) = build_over(&cfg, &counts, &Rows::default(), Some(second));
    assert_eq!(opens(&counts), 1, "carried again on the next reload");
    assert_eq!(third.reused(), &["idp".to_string()]);
}

/// T2b: two providers, one changed: only it is opened again, `reason = settings`.
#[test]
fn changed_provider_reopens_only_it() {
    let counts = Arc::new(Counts::default());
    let mut cfg = three_roles();
    let mut other = AuthChainEntry::bare(MODULE);
    other.name = "idp-two".into();
    cfg.chain.push(other);
    let (_, first) = build_over(&cfg, &counts, &Rows::default(), None);
    assert_eq!(opens(&counts), 2);

    let changed = with_settings(cfg, "idp-two", "issuer", "https://changed.example");
    let (_, second) = build_over(&changed, &counts, &Rows::default(), Some(first));
    assert_eq!(opens(&counts), 3, "one OPEN: the changed provider");
    assert_eq!(
        second.opened(),
        &[("idp-two".to_string(), Opening::Settings)]
    );
    assert_eq!(second.reused(), &["idp".to_string()]);
}

/// T2e: a replaced plugin archive is opened again, `reason = binary`.
#[test]
fn replaced_binary_reopens() {
    let counts = Arc::new(Counts::default());
    let cfg = three_roles();
    let (_, first) = build_over(
        &cfg,
        &counts,
        &Rows {
            archive: Some("a1"),
        },
        None,
    );
    let (_, second) = build_over(
        &cfg,
        &counts,
        &Rows {
            archive: Some("a2"),
        },
        Some(first),
    );
    assert_eq!(opens(&counts), 2);
    assert_eq!(second.opened(), &[("idp".to_string(), Opening::Binary)]);
}

/// T2g/T2h: an instance that is not `reusable()` (quarantined, closed, a failed tick schedule)
/// is opened again on the next reload, `reason = unhealthy`.
#[test]
fn unhealthy_instance_reopens() {
    let counts = Arc::new(Counts::default());
    let cfg = three_roles();
    let (_, first) = build_over(&cfg, &counts, &Rows::default(), None);
    counts.unhealthy.store(true, Ordering::SeqCst);
    let (_, second) = build_over(&cfg, &counts, &Rows::default(), Some(first));
    assert_eq!(opens(&counts), 2);
    assert_eq!(second.opened(), &[("idp".to_string(), Opening::Unhealthy)]);
}

/// An implementor that states no health is never carried: the trait's `reusable()` is `false`.
#[test]
fn the_default_reusable_is_false() {
    assert!(!Silent.reusable());
    assert!(!Silent.answering());
}

/// A failed build (here: one that never seals) leaves the prior build's instances with the prior:
/// the live map is unchanged and its instance is still held.
#[test]
fn a_failed_build_keeps_the_prior_instances() {
    let counts = Arc::new(Counts::default());
    let cfg = three_roles();
    let (boot, first) = build_over(&cfg, &counts, &Rows::default(), None);
    let mut abandoned = AuthInstances::carrying(Some(Arc::clone(&first)));
    let axis: Arc<dyn AuthAxis> = Arc::new(Axis(Arc::clone(&counts)));
    let open_axis = || Some(Arc::clone(&axis));
    let secrets = crate::config::secret::SecretResolver::builtins_only();
    let _ = AuthMiddleware::build_on(&cfg, &Rows::default(), &secrets, &mut abandoned, &open_axis);
    drop(abandoned);
    let live = boot.chain.chain_instances(None).next().expect("idp");
    assert!(Arc::strong_count(live) >= 2, "the live App still holds it");
    assert_eq!(first.reused().len() + first.opened().len(), 1);
    assert_eq!(opens(&counts), 1);
}
