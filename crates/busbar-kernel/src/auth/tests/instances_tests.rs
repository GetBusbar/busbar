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
    fn operator_claims(&self) -> busbar_contract::auth_calls::OperatorClaims {
        busbar_contract::auth_calls::OperatorClaims::default()
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

/// OPERATOR-FROM-ADMITTED-AUTH R14: the operator row as an ordinary auth instance, opened with its
/// own `settings` and judged through the same bounded admission call as every admin module.
mod operator_instance {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use busbar_contract::auth::AuthVerdict;
    use busbar_contract::auth_calls::{
        AuthAxis, AuthCalls, Verified, VerifiedIdentity, VerifyAnswer, VerifyRequest, Verifying,
    };

    use crate::auth::instances::AuthInstances;
    use crate::auth::AdminAuthChain;
    use crate::config::{AuthCfg, AuthChainEntry};

    const OP: &str = "op-row";
    const DIGEST: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    #[derive(Default)]
    struct Opened {
        count: AtomicUsize,
        settings: Mutex<Vec<String>>,
    }

    struct Admin;

    fn admin() -> VerifyAnswer {
        Verified::Identity(VerifiedIdentity {
            subject: "admin".into(),
            key_id: None,
            key_name: None,
            user: None,
            provider: None,
            name: None,
            groups: Vec::new(),
            ttl_secs: None,
            replay: None,
            credential: None,
        })
        .into()
    }

    struct Ready(Option<VerifyAnswer>);

    impl std::future::Future for Ready {
        type Output = VerifyAnswer;
        fn poll(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<VerifyAnswer> {
            std::task::Poll::Ready(self.0.take().unwrap_or_else(admin))
        }
    }

    impl Verifying for Ready {
        fn settled(&mut self) -> Option<VerifyAnswer> {
            self.0.take()
        }
    }

    impl AuthCalls for Admin {
        fn name(&self) -> &str {
            OP
        }
        fn facts(&self) -> u32 {
            0
        }
        fn verify_now(&self, _: &VerifyRequest) -> Option<VerifyAnswer> {
            Some(admin())
        }
        fn verify(&self, _: VerifyRequest) -> Box<dyn Verifying> {
            Box::new(Ready(Some(admin())))
        }
        fn refresh(&self) -> Result<u64, String> {
            Ok(0)
        }
    }

    struct OpAxis(Arc<Opened>);

    impl AuthAxis for OpAxis {
        fn linked_names(&self) -> Vec<String> {
            Vec::new()
        }
        fn answers(&self, module: &str) -> bool {
            module == OP
        }
        fn linked(&self, _: &str) -> bool {
            false
        }
        fn operator_claims(&self) -> busbar_contract::auth_calls::OperatorClaims {
            busbar_contract::auth_calls::OperatorClaims::default()
        }
        fn open(
            &self,
            _: &str,
            _: &str,
            settings: &busbar_contract::plugin_settings::ResolvedSettings,
        ) -> Result<Arc<dyn AuthCalls>, String> {
            self.0.count.fetch_add(1, Ordering::SeqCst);
            let encoded = settings.encode().map_err(|e| e.to_string())?;
            let text = String::from_utf8(encoded.expose(&crate::seal::lend()).clone())
                .map_err(|e| e.to_string())?;
            self.0
                .settings
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(text);
            Ok(Arc::new(Admin))
        }
    }

    #[derive(Debug)]
    struct OpRows;

    impl busbar_contract::plugin_rows::PluginRows for OpRows {
        fn resolve(&self, name: &str) -> Option<busbar_contract::plugin_rows::Row> {
            (name == OP).then(|| crate::tests::dropped(OP, OP, "auth"))
        }
        fn archive_sha256(&self, name: &str) -> Option<String> {
            (name == OP).then(|| "a1".to_string())
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

    fn install_words() {
        busbar_kernel_identity::operator::install_operator(
            busbar_kernel_identity::operator::OperatorBinding::Bound(
                busbar_kernel_identity::operator::Judged {
                    words: Ok(Some(busbar_contract::auth_calls::OperatorClaim {
                        provider: OP.to_owned(),
                        canonical: OP.to_owned(),
                        principal: "admin".to_owned(),
                        first_party: true,
                        version: "1.6.0".to_owned(),
                        signer: "busbar".to_owned(),
                    })),
                    inert: Vec::new(),
                },
            ),
        );
    }

    fn admin_auth(settings: serde_json::Value) -> AuthCfg {
        let mut entry = AuthChainEntry::bare(OP);
        entry.settings = match settings {
            serde_json::Value::Object(map) => map.into(),
            _ => serde_json::Map::new().into(),
        };
        let mut cfg = AuthCfg::default_none();
        cfg.admin_auth = vec![entry];
        cfg
    }

    fn built(cfg: &AuthCfg) -> (Arc<Opened>, AdminAuthChain) {
        install_words();
        let opened = Arc::new(Opened::default());
        let axis: Arc<dyn AuthAxis> = Arc::new(OpAxis(Arc::clone(&opened)));
        let open_axis = || Some(Arc::clone(&axis));
        let secrets = crate::config::secret::SecretResolver::builtins_only();
        let admin = AdminAuthChain::build_on(
            cfg,
            &OpRows,
            &secrets,
            &mut AuthInstances::default(),
            &open_axis,
        )
        .expect("admin_auth builds");
        (opened, admin)
    }

    fn head() -> VerifyRequest {
        VerifyRequest {
            lines: Vec::new(),
            point: busbar_contract::route::AuthPoint::Head,
            conn: 0,
            unit: 0,
            credential: None,
            peer: None,
            body: None,
            method: "GET".into(),
            authority: String::new(),
            path: "/api/v1/admin/keys".into(),
            query: None,
            timestamp: 0,
        }
    }

    #[tokio::test]
    async fn the_operator_instance_opened_with_settings_is_the_one_judged() {
        let (opened, admin) = built(&admin_auth(serde_json::json!({ "sha256": DIGEST })));
        assert_eq!(
            opened.count.load(Ordering::SeqCst),
            1,
            "the operator entry with settings opens one instance"
        );
        let seen = opened
            .settings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert_eq!(
            seen.iter()
                .map(|s| serde_json::from_str::<serde_json::Value>(s).expect("settings json"))
                .collect::<Vec<_>>(),
            vec![serde_json::json!({ "sha256": DIGEST })],
            "it opens over its own settings, verbatim"
        );
        assert!(admin.operator.is(OP));
        let calls = admin
            .operator
            .instance(OP)
            .expect("the backed provider has its opened instance");
        let judged = crate::auth::judge_admin_calls(calls, head(), true).await;
        let principal = match judged.verdict {
            AuthVerdict::Identify(p) => p,
            other => panic!("the operator instance identifies the operator: {other:?}"),
        };
        assert_eq!(principal.id, "admin");
        let async_judged = crate::auth::judge_admin_calls(calls, head(), false).await;
        assert!(matches!(async_judged.verdict, AuthVerdict::Identify(_)));
        let grants = crate::auth::admin_scope_from_bindings(
            &crate::config::RoleBindings::new(),
            &admin.operator,
            "admin",
            Some(OP),
            Some(&principal),
        );
        assert_eq!(
            grants,
            busbar_contract::authz::Grants::of(busbar_contract::authz::Scope::Full),
            "the role-less operator principal holds Full"
        );
    }

    #[test]
    fn an_operator_entry_without_settings_is_unset_and_opens_nothing() {
        let (opened, admin) = built(&admin_auth(serde_json::json!({})));
        assert_eq!(opened.count.load(Ordering::SeqCst), 0, "nothing opens");
        assert!(admin.operator.instance(OP).is_none());
        assert!(
            admin.operator.unset(OP),
            "an operator entry with no settings is unset"
        );
    }

    #[tokio::test]
    async fn the_operator_call_is_refused_through_the_saturated_admission_permit() {
        let (_, admin) = built(&admin_auth(serde_json::json!({ "sha256": DIGEST })));
        let calls = admin
            .operator
            .instance(OP)
            .expect("the backed provider has its opened instance");
        let refused = {
            tokio::time::pause();
            let held = crate::auth::ADMIN_ADMISSION_PERMITS
                .acquire_many(
                    u32::try_from(crate::auth::ADMIN_ADMISSION_MAX_INFLIGHT)
                        .expect("the admission budget fits a u32"),
                )
                .await
                .expect("the admission permits");
            let judged = crate::auth::judge_admin_calls(calls, head(), false).await;
            drop(held);
            judged
        };
        assert!(
            matches!(refused.verdict, AuthVerdict::Reject),
            "a saturated admission budget refuses the operator as it refuses any admin module: {:?}",
            refused.verdict
        );
    }
}

/// D-OPERATOR (E6's finding (a)): an `admin_auth` module a native (MIN-3) auth image answers opens nothing through the door
/// auth axis: the root builds that admin chain natively over the image's opened instance (`root::min3_admin_auth`). Before,
/// the kernel looked for a door row and refused the build, so `admin_auth: [admin-tokens]` on the default binary failed.
#[test]
fn an_admin_module_a_native_image_answers_opens_no_door_instance() {
    crate::preflight::publish_root_rows(crate::preflight::RootInstall {
        native_auth: Some(|module| module == "native-op"),
        ..Default::default()
    });
    let mut entry = AuthChainEntry::bare("native-op");
    entry.name = "native-op".into();
    let mut cfg = AuthCfg::default_none();
    cfg.admin_auth = vec![entry];
    let secrets = crate::config::secret::SecretResolver::builtins_only();
    let mut instances = AuthInstances::carrying(None);
    let open_axis = || -> Option<Arc<dyn AuthAxis>> { None };
    if let Err(refusal) =
        AdminAuthChain::build_on(&cfg, &Rows::default(), &secrets, &mut instances, &open_axis)
    {
        panic!("a natively answered admin module opens no door instance, yet the build refused: {refusal}");
    }
}
