// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::{abi::mechanism::door::REWRITE_SUGAR, secret_ref::Sugars};

#[test]
fn native_document_uses_admitted_source_declarations() {
    for (word, owner, member) in [
        ("cabinet", "first-source", "entry"),
        ("drawer", "second-source", "location"),
    ] {
        let mut sources = Sugars::default();
        sources
            .declare(owner, &[(REWRITE_SUGAR, word.into(), member.into())])
            .unwrap();
        let raw = format!(
            "credentials:\n  at_rest:\n    key: {{ {word}: descriptor }}\nidentity-providers:\n  external:\n    module: arbitrary-auth\n    token: {{ {word}: another }}\n"
        );
        let read = |sources: &Sugars| {
            busbar_contract::yaml::with_deserializer(&raw, |d| {
                deploy_from_deserializer(
                    d,
                    &crate::config::Grammar::new(sources.clone(), Default::default(), Vec::new()),
                )
            })
        };
        let parsed = read(&sources).unwrap();
        let key = parsed.credentials.at_rest.unwrap().key;
        assert_eq!(key.source_module(), Some(owner));
        assert_eq!(key, sources.get(word).unwrap().reference("descriptor"));
        assert_eq!(
            parsed.identity_providers["external"]
                .token
                .as_ref()
                .unwrap()
                .source_module(),
            Some(owner)
        );
        let error = read(&Sugars::default()).unwrap_err().to_string();
        assert!(error.contains("is a secret shorthand"), "{error}");
        assert!(!error.contains("descriptor"), "{error}");
    }
}
