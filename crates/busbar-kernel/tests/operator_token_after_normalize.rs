// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! OPERATOR-FROM-ADMITTED-AUTH R21 (kernel half): the 1.5.5 configuration as normalization leaves
//! it (its `token:` definition passed through untouched, `fixtures/operator_token_after_normalize
//! .yaml`) is refused with the one named remedy, `operator_token("admin-tokens")` plus the install
//! remedy (no operator row is admitted in this binary), and never with the generic no-mint-path
//! refusal. No words are installed: this test owns its binary.

const FIXTURE: &str = include_str!("fixtures/operator_token_after_normalize.yaml");

/// The 1.5.5 configuration spells its secrets `{ env: … }` and `{ file: … }`. Core declares no
/// source shorthand itself: an admitted secret module does. Read the fixture as a deployment whose
/// admitted secret module declares both words.
fn fixture_sources() -> busbar_contract::secret_ref::Sugars {
    use busbar_contract::abi::mechanism::door::REWRITE_SUGAR;
    let mut sources = busbar_contract::secret_ref::Sugars::default();
    sources
        .declare(
            "fixture-source",
            &[
                (REWRITE_SUGAR, "env".into(), "slot".into()),
                (REWRITE_SUGAR, "file".into(), "path".into()),
            ],
        )
        .expect("the fixture source declares its shorthand");
    sources
}

/// One provider definition per configured provider, as a providers.yaml would give.
fn defs_for(
    deploy: &busbar_kernel::config::DeployCfg,
) -> std::collections::HashMap<String, busbar_kernel::config::ProviderDef> {
    deploy
        .providers
        .keys()
        .map(|name| {
            let def: busbar_kernel::config::ProviderDef = busbar_contract::yaml::from_str(
                "{ protocol: proto-a, base_url: \"https://provider.invalid\" }",
            )
            .expect("the fixed ProviderDef literal parses");
            (name.clone(), def)
        })
        .collect()
}

#[test]
fn a_normalized_1_5_5_token_config_is_refused_with_its_named_remedy() {
    let sources = fixture_sources();
    let deploy = busbar_contract::yaml::with_deserializer(FIXTURE, |d| {
        busbar_kernel::config::deploy_with_sources(d, &sources)
    })
    .expect("the fixture parses");
    let errors = match busbar_kernel::config::resolve(&deploy, &defs_for(&deploy)) {
        Err(errors) => errors,
        Ok(cfg) => busbar_kernel::config_validate::validate(&cfg)
            .err()
            .unwrap_or_default(),
    };
    let remedy = busbar_kernel_identity::operator::operator_token("admin-tokens");
    let install = busbar_kernel_identity::operator::operator_install_remedy();
    assert!(
        errors
            .iter()
            .any(|e| e.contains(&remedy) && e.contains(&install)),
        "refused with operator_token(\"admin-tokens\") and the install remedy: {errors:?}"
    );
    assert!(
        errors
            .iter()
            .all(|e| !e.contains("no admin credential can mint") && !e.contains("``")),
        "never the generic no-mint-path refusal, never an empty word: {errors:?}"
    );
}
