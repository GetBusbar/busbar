// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel::appbuild::RootRules;
use busbar_kernel::config::grammar::{Grammar, GrammarRefusal, PhaseOneIn};

struct Reader(&'static str);
impl RootRules for Reader {
    fn check(&self, _: &busbar_kernel::config::RootCfg) -> Result<(), String> {
        Ok(())
    }
    fn grammar(&self, _: &PhaseOneIn<'_>) -> Result<Grammar, GrammarRefusal> {
        Ok(Grammar::new(
            Default::default(),
            Default::default(),
            vec![self.0.into()],
        ))
    }
}

#[test]
fn separate_readers_keep_their_owned_grammar_context() {
    let plugins = busbar_kernel::config::PluginsCfg::default();
    let input = PhaseOneIn::of(&plugins);
    let first = Reader("first process");
    let second = Reader("second process");
    assert_eq!(
        busbar_kernel::config::grammar::grammar_for(&input, &first)
            .unwrap()
            .report(),
        &["first process"]
    );
    assert_eq!(
        busbar_kernel::config::grammar::grammar_for(&input, &second)
            .unwrap()
            .report(),
        &["second process"]
    );
    assert_eq!(
        busbar_kernel::config::grammar::grammar_for(&input, &first)
            .unwrap()
            .report(),
        &["first process"]
    );
}

#[test]
fn named_secret_is_bound_before_the_document_reads_shorthand() {
    use busbar_contract::abi::mechanism::door::REWRITE_SUGAR;
    use busbar_kernel::config::grammar::SecretSource;
    let mut sugars = busbar_contract::secret_ref::Sugars::default();
    sugars
        .declare(
            "fixture-secret",
            &[(REWRITE_SUGAR, "fixture-word".into(), "slot".into())],
        )
        .unwrap();
    let grammar = Grammar::new(sugars, Default::default(), Vec::new()).with_secret_sources(
        std::collections::BTreeMap::from([(
            "fixture-secret".into(),
            SecretSource {
                identity: "fixture-secret".into(),
                ref_schema: "{}".into(),
            },
        )]),
    );
    let deploy = busbar_kernel::config::deploy_from_yaml_str(
        "secrets:\n  selected:\n    module: fixture-secret\n    settings: {}\nauth:\n  admin_auth: []\n  signing_key: {fixture-word: signing}\n",
        &grammar,
    ).expect("shorthand is parsed after its named instance is known");
    let bound = deploy.grammar.get().unwrap();
    assert!(bound.secret_instances.contains_key("selected"));
    assert!(!bound.secret_instances.contains_key("fixture-word"));
    assert_eq!(bound.sugars.iter().next().unwrap().module(), "selected");
}

#[test]
fn an_admission_with_no_secret_images_refuses_explicit_instances() {
    let grammar = Grammar::empty().with_secret_sources(Default::default());
    let refused = busbar_kernel::config::deploy_from_yaml_str(
        "secrets:\n  selected:\n    module: missing-secret\n    settings: {}\n",
        &grammar,
    )
    .expect_err("an empty admitted image set cannot supply a configured secret");
    assert!(refused.to_string().contains("not an admitted secret image"));
}

#[tokio::test]
async fn a_reader_without_boot_owners_cannot_open_configured_secrets() {
    let deploy = busbar_kernel::config::deploy_from_yaml_str(
        "providers: {}\nmodels: {}\nauth:\n  admin_auth: []\nsecrets:\n  selected:\n    module: fixture-secret\n    settings: {}\n",
        &Grammar::empty(),
    ).expect("fixture configuration");
    let root =
        busbar_kernel::config::resolve(&deploy, &Default::default()).expect("fixture projection");
    let result = busbar_kernel::appbuild::AcceptAll
        .secret_resolver(&root, &deploy.plugins)
        .await;
    assert!(
        matches!(result, Err(ref error) if error.contains("no composition root supplied the candidate secret plan"))
    );
}
