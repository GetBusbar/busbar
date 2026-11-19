// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn grants() -> BTreeMap<Box<str>, BTreeSet<Box<str>>> {
    BTreeMap::from([("reader".into(), BTreeSet::from(["signed".into()]))])
}

fn instance<'a>(name: &'a str, id: u64, kind: Option<&'a str>) -> GrantInstance<'a> {
    GrantInstance {
        name,
        id,
        kind,
        verifies: true,
    }
}

#[test]
fn issued_grants_require_explicit_matching_instance_kind_and_custody() {
    let allowed =
        resolve_grants(&grants(), [instance("reader", 41, Some("signed"))], true).unwrap();
    assert_eq!(
        allowed,
        BTreeMap::from([(41, BTreeSet::from(["signed".into()]))])
    );
    let no_grants = resolve_grants(
        &BTreeMap::new(),
        [instance("reader", 41, Some("signed"))],
        false,
    )
    .unwrap();
    assert!(no_grants.is_empty(), "a describe grants nothing");
    for opened in [
        vec![],
        vec![instance("other", 41, Some("signed"))],
        vec![instance("reader", 41, Some("other"))],
        vec![instance("reader", 41, None)],
        vec![instance("reader", 0, Some("signed"))],
        vec![GrantInstance {
            verifies: false,
            ..instance("reader", 41, Some("signed"))
        }],
    ] {
        assert!(resolve_grants(&grants(), opened, true).is_err());
    }
    assert!(resolve_grants(&grants(), [instance("reader", 41, Some("signed"))], false).is_err());
}

#[test]
fn issued_grants_refuse_duplicate_runtime_reservations_and_builtin_keys() {
    for opened in [
        vec![
            instance("reader", 41, Some("signed")),
            instance("reader", 42, Some("signed")),
        ],
        vec![
            instance("reader", 41, Some("signed")),
            instance("other", 41, Some("signed")),
        ],
    ] {
        assert!(resolve_grants(&grants(), opened, true).is_err());
    }
    let keys = BTreeMap::from([(
        busbar_kernel::config::KEYS_MODULE.into(),
        BTreeSet::from(["signed".into()]),
    )]);
    assert!(resolve_grants(
        &keys,
        [instance(
            busbar_kernel::config::KEYS_MODULE,
            41,
            Some("signed")
        )],
        true
    )
    .is_err());
}

#[test]
fn issued_grants_keep_explicit_empty_policy_without_inventing_custody() {
    let empty = BTreeMap::from([("reader".into(), BTreeSet::new())]);
    assert!(
        resolve_grants(&empty, [instance("reader", 41, None)], false)
            .unwrap()
            .get(&41)
            .unwrap()
            .is_empty()
    );
    assert!(
        resolve_grants(&empty, [], false).is_err(),
        "explicit policy still names an actual instance"
    );
}

/// A deployment of the operator-credential reload test: the operator credential is the definition
/// whose settings digest is `token`'s, or, with `None`, the default chain's bare operator with no
/// definition.
fn operator_deployment(operator: &str, token: Option<&str>) -> busbar_kernel::config::RootCfg {
    crate::root::linked::register_stores();
    // Written as the operator writes it: config.yaml text.
    let mut document = format!(
        "providers: {{}}\nmodels: {{}}\nstore:\n  module: memory\nauth:\n  chain: []\n  \
         admin_auth: [\"{operator}\"]\n"
    );
    if let Some(token) = token {
        let digest = crate::root::test_plugins::sha256(token.as_bytes());
        document.push_str(&format!(
            "identity-providers:\n  \"{operator}\":\n    module: \"{operator}\"\n    settings:\n      \
             sha256: \"{digest}\"\n"
        ));
    }
    let deploy = busbar_kernel::config::deploy_from_yaml_str(
        &document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the operator deployment parses");
    crate::root::test_plugins::plaintext_listeners(
        busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the operator deployment resolves"),
    )
}

/// The generation an operator-credential reload test starts with, built as a boot builds it.
async fn booted_with(
    cfg: busbar_kernel::config::RootCfg,
    rules: &Arc<dyn busbar_kernel::appbuild::RootRules>,
) -> App {
    let store = crate::root::real_store::core().await;
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        cfg,
        Default::default(),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        rules,
        Some(store),
        false,
    )
    .await
    .expect("the boot builds");
    limits.stage_boot();
    crate::root::kernel::ROOT_CARD
        .keep_in_store(
            app.governance
                .as_ref()
                .expect("the deployment configures governance")
                .core_store_handle()
                .expect("the configured Store exposes its rate-history slots"),
            123,
        )
        .expect("native rate history attaches");
    crate::root::kernel::ROOT_CARD
        .boot_in_store(None)
        .await
        .expect("the configured Store boots its rate history");
    limits.keep().await.expect("the boot commits its limits");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    app
}

/// A reload candidate built over the running generation `running`, as every rebuild (`POST
/// /config/reload`, `PUT /config/settings`, the plugin reload and rollback) builds it.
async fn reloaded(
    cfg: busbar_kernel::config::RootCfg,
    running: &App,
    rules: &Arc<dyn busbar_kernel::appbuild::RootRules>,
) -> Result<(), String> {
    busbar_kernel::appbuild::build_app_from_config_with_store(
        cfg,
        Default::default(),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        Some(running),
        rules,
        Some(crate::root::real_store::core().await),
        false,
    )
    .await
    .map(drop)
}

/// THE OPERATOR CREDENTIAL IS BOUND AT START (owner's ruling, 18 Nov 2026), the fixture of its two
/// tests: a reload whose operator credential differs from the running one's (its settings digest
/// changed, the definition removed, or one added where start had none) is refused as a whole,
/// naming the definition and that a restart is required, and revealing nothing of either
/// credential; the running generation keeps its credential. Before the ruling the candidate was
/// applied and its admin chain rebuilt from the new settings at once: the new digest took over the
/// admin plane, and a removed one left the position unset so every admin request was refused. A
/// reload that leaves the binding byte-identical is applied as before.
struct OperatorReload {
    operator: &'static str,
    rules: Arc<dyn busbar_kernel::appbuild::RootRules>,
}

const TOKEN_A: &str = "operator-token-a";
const TOKEN_B: &str = "operator-token-b";

impl OperatorReload {
    /// The linked first-party operator bound through the production process-start binding, its
    /// image published as a native auth image (as the start stage's image prepare publishes it).
    fn new() -> Self {
        #[cfg(distribution_root)]
        crate::dist_root_install::install();
        crate::root::test_plane_registry::register();
        let operator = crate::root::test_plugins::bind_operator();
        assert!(!operator.is_empty(), "the linked operator credential binds");
        crate::root::native_operator::NATIVE
            .publish_auth_names(std::iter::once(operator.to_owned()).collect());
        Self {
            operator,
            rules: Arc::new(crate::root::door_steps::Rules::default()),
        }
    }

    fn deployment(&self, token: Option<&str>) -> busbar_kernel::config::RootCfg {
        operator_deployment(self.operator, token)
    }

    /// `refusal` refuses the candidate as a whole for `what` it does to the operator credential,
    /// says a restart is required, and reveals neither credential.
    fn refused_as_a_whole(&self, refusal: &str, what: &str) {
        let operator = self.operator;
        assert!(
            refusal.starts_with(&format!(
                "identity-providers.{operator} is the operator credential, which is bound at \
                 process start: this configuration {what}, so the change was refused and nothing \
                 was changed"
            )),
            "{refusal}"
        );
        assert!(
            refusal.contains("Restart the process to change the operator credential"),
            "{refusal}"
        );
        no_credential_in(refusal);
    }
}

fn no_credential_in(text: &str) {
    for token in [TOKEN_A, TOKEN_B] {
        let digest = crate::root::test_plugins::sha256(token.as_bytes());
        assert!(
            !text.contains(token) && !text.contains(&digest),
            "a credential is revealed: {text}"
        );
    }
}

fn held_refusals() -> Vec<String> {
    busbar_kernel::audit::auditlog::held_operator_rows()
        .into_iter()
        .filter(|row| row.starts_with("auth.operator.refused"))
        .collect()
}

#[tokio::test]
async fn a_reload_that_changes_or_removes_the_operator_credential_is_refused_and_it_stays() {
    let test = OperatorReload::new();
    let operator = test.operator;
    let rules = &test.rules;
    let booted = booted_with(test.deployment(Some(TOKEN_A)), rules).await;
    let bound = booted.identity_providers.get(operator).cloned();
    assert!(bound.is_some(), "the boot binds credential A");

    assert_eq!(
        reloaded(test.deployment(Some(TOKEN_A)), &booted, rules).await,
        Ok(()),
        "a byte-identical operator credential reloads as before"
    );
    assert!(held_refusals().is_empty(), "nothing refused yet");

    let changed = reloaded(test.deployment(Some(TOKEN_B)), &booted, rules)
        .await
        .expect_err("a reload that changes the operator credential is refused");
    test.refused_as_a_whole(&changed, "changes it");
    let removed = reloaded(test.deployment(None), &booted, rules)
        .await
        .expect_err("a reload that removes the operator credential is refused");
    test.refused_as_a_whole(&removed, "removes it");
    assert_eq!(
        booted.identity_providers.get(operator).cloned(),
        bound,
        "the running generation keeps credential A"
    );
    let rows = held_refusals();
    assert_eq!(
        rows.len(),
        2,
        "one refusal row per refused reload: {rows:?}"
    );
    for row in &rows {
        assert!(
            row.contains(operator),
            "the row names the definition: {row}"
        );
        no_credential_in(row);
    }
}

#[tokio::test]
async fn a_reload_that_adds_an_operator_credential_where_start_had_none_is_refused() {
    let test = OperatorReload::new();
    let rules = &test.rules;
    let unset = booted_with(test.deployment(None), rules).await;
    assert_eq!(
        reloaded(test.deployment(None), &unset, rules).await,
        Ok(()),
        "no credential at start and none in the reload: applied as before"
    );
    let added = reloaded(test.deployment(Some(TOKEN_B)), &unset, rules)
        .await
        .expect_err("a reload that adds an operator credential where start had none is refused");
    test.refused_as_a_whole(&added, "adds it");
    assert_eq!(held_refusals().len(), 1, "the refused reload is audited");
}
