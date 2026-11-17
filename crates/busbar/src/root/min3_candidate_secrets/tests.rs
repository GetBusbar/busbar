// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::BTreeMap;

use busbar_contract::abi::mechanism::door::REWRITE_SUGAR;
use busbar_contract::secret_ref::SecretRef;
use busbar_kernel::config::grammar::SecretSource;
use busbar_kernel::config::{Grammar, SecretModuleCfg};

use super::{bound_read_grammar, new_binder};

fn admitted() -> Grammar {
    admitted_with_report(Vec::new())
}

fn admitted_with_report(report: Vec<String>) -> Grammar {
    let mut grammar = Grammar::new(Default::default(), BTreeMap::new(), report).with_secret_sources(BTreeMap::from([(
        "native-secret".into(),
        SecretSource {
            identity: "native-secret".into(),
            ref_schema: r#"{"type":"object","properties":{"name":{"type":"string"}},"required":["name"],"additionalProperties":false}"#.into(),
        },
    )]));
    grammar
        .sugars
        .declare(
            "native-secret",
            &[(REWRITE_SUGAR, "secret".into(), "name".into())],
        )
        .unwrap();
    grammar
}

fn named(name: &str) -> BTreeMap<String, SecretModuleCfg> {
    BTreeMap::from([(
        name.into(),
        busbar_contract::yaml::from_str("module: native-secret\nsettings: {}\n").unwrap(),
    )])
}

#[test]
fn candidate_uses_the_exact_reads_canonical_named_grammar() {
    let read = admitted();
    let configured = named("vault");
    let typed = read.bind_secret_instances(&configured).unwrap();
    let accepted = bound_read_grammar(&read, &configured, &typed).unwrap();
    assert_eq!(accepted, typed);
    assert!(accepted.secret_instances.contains_key("vault"));
    assert!(!accepted.secret_instances.contains_key("secret"));

    let previous = read.bind_secret_instances(&named("previous")).unwrap();
    assert!(bound_read_grammar(&read, &configured, &previous).is_err());
}

#[test]
fn same_name_does_not_authorize_a_different_read_schema() {
    let read = admitted();
    let configured = named("vault");
    let mut foreign = read.bind_secret_instances(&configured).unwrap();
    foreign
        .secret_instances
        .get_mut("vault")
        .unwrap()
        .ref_schema = "{}".into();
    assert!(bound_read_grammar(&read, &configured, &foreign).is_err());
}

#[test]
fn candidate_binders_preserve_named_reference_schemas_without_sharing_handles() {
    let grammar = admitted().bind_secret_instances(&named("vault")).unwrap();
    let previous = new_binder(&grammar);
    let candidate = new_binder(&grammar);
    previous
        .bind(
            7,
            br#"{"token":{"module":"vault","settings":{"name":"old"}}}"#,
            &["/token"],
            &[],
            &[],
            &[],
        )
        .unwrap();
    assert!(candidate.secret(7, 1).is_none());
    candidate
        .bind(
            7,
            br#"{"token":{"module":"vault","settings":{"name":"new"}}}"#,
            &["/token"],
            &[],
            &[],
            &[],
        )
        .unwrap();
    let previous_ref = previous.secret(7, 1).unwrap();
    let candidate_ref = candidate.secret(7, 1).unwrap();
    assert_ne!(previous_ref, candidate_ref);
    assert!(matches!(candidate_ref, SecretRef::Source(source) if source.module == "vault"));
    assert!(candidate
        .bind(
            8,
            br#"{"token":{"module":"vault","settings":{"name":false}}}"#,
            &["/token"],
            &[],
            &[],
            &[],
        )
        .is_err());
}

#[test]
fn diagnostic_reports_do_not_change_candidate_read_authority() {
    let read = admitted();
    let configured = named("vault");
    let reported = admitted_with_report(vec!["pending fetch diagnostic".into()])
        .bind_secret_instances(&configured)
        .unwrap();
    assert!(bound_read_grammar(&read, &configured, &reported).is_ok());
    assert!(bound_read_grammar(&read, &configured, &reported.trimmed()).is_ok());
}
