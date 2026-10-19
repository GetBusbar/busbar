// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OUTBOUND AUTH STYLES THE LINKED ROWS DECLARE (arch-audit u29 F1; BUSBAR-1.6.0.md #50: "the
//! auth style resolves ... as opaque strings"), and the committed fixture the config-schema gate
//! reads them from (`qa/declared-auth-styles.json`, coordinator ruling (b)): the gate holds every
//! style the previous release's closed enum accepted in that fixture, and THIS test is its only
//! writer, from the LINKED rows' own Statements, so the fixture can never claim a style the build
//! does not declare.

use busbar_contract::auth_calls::{listed_styles, DeclaredStyle};

/// The fixture's path, from the repo root.
const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../qa/declared-auth-styles.json"
);

/// The command that rewrites the fixture from the linked rows.
const REGENERATE: &str =
    "BUSBAR_UPDATE_DECLARED=1 cargo test -p busbar the_declared_auth_styles_fixture_is_the_linked_rows";

/// The styles the build's LINKED auth rows declare, in the host's one listing order, read off each
/// row's Statement (nothing opened).
fn linked_declared() -> Vec<String> {
    use crate::root::loader::auth_axis::door_facts;
    listed_styles(
        crate::LINKED
            .auths
            .iter()
            .filter_map(|(_, _, door)| door_facts(*door).ok())
            .flat_map(|f| {
                f.styles.into_iter().map(|s| DeclaredStyle {
                    name: s.name,
                    flags: s.flags,
                })
            }),
    )
    .into_iter()
    .map(|s| s.name)
    .collect()
}

/// The fixture's bytes for `styles`: the gate's input, keyed by the config type it governs.
fn rendered(styles: &[String]) -> String {
    let doc = serde_json::json!({ "ProviderAuth": styles });
    format!(
        "{}\n",
        serde_json::to_string_pretty(&doc).expect("a list of strings renders")
    )
}

/// The drift between the committed fixture and the fresh render: `None` when byte-identical.
fn drift(committed: &str, fresh: &str) -> Option<String> {
    (committed != fresh).then(|| {
        format!(
            "qa/declared-auth-styles.json is stale: it is not the linked rows' declared styles. \
             Regenerate it with `{REGENERATE}`.\ncommitted:\n{committed}\nfresh:\n{fresh}"
        )
    })
}

/// THE FIXTURE IS THE LINKED ROWS' DECLARATION, byte for byte (coordinator ruling (b), condition
/// 2): written only by this test, from the linked rows, and red on any mismatch, naming the
/// regenerate command.
#[cfg(linked_every_auth)]
#[test]
fn the_declared_auth_styles_fixture_is_the_linked_rows() {
    let fresh = rendered(&linked_declared());
    if std::env::var_os("BUSBAR_UPDATE_DECLARED").is_some() {
        std::fs::write(FIXTURE, &fresh).expect("write the fixture");
    }
    let committed = std::fs::read_to_string(FIXTURE).unwrap_or_default();
    if let Some(why) = drift(&committed, &fresh) {
        panic!("{why}");
    }
}

/// SELFTEST PLANT (coordinator ruling (b), condition 5): a stale fixture, one that drops a style
/// the rows declare, is drift; the fresh render is not.
#[test]
fn a_stale_declared_styles_fixture_is_drift() {
    let fresh = rendered(&["first".to_string(), "second".to_string()]);
    let stale = rendered(&["first".to_string()]);
    assert!(drift(&stale, &fresh).is_some_and(|why| why.contains(REGENERATE)));
    assert_eq!(drift(&fresh, &fresh), None);
}

/// THE PREVIOUS RELEASE'S FOUR WORDS STILL PARSE, AND AN UNKNOWN ONE IS REFUSED WITH ITS TEXT AS A
/// PREFIX (coordinator ruling (b), condition 4; ruling (a) on the list: 1.5.5's four first, in its
/// order, by the plugins' ranks, then the styles 1.6.0 adds). Over the LINKED rows.
#[cfg(linked_every_auth)]
#[test]
fn each_1_5_5_auth_word_parses_and_an_unknown_one_is_refused_in_1_5_5_words() {
    busbar_kernel::preflight::install_linked_auth(
        crate::LINKED.auths,
        crate::root::auth_bindings::operator_words(),
    );
    for word in [
        "bearer",
        "api-key",
        "jwt-bearer",
        "oauth-client-credentials",
    ] {
        let parsed: busbar_kernel::config::ProviderAuth =
            serde_json::from_value(serde_json::Value::String(word.to_string()))
                .unwrap_or_else(|e| panic!("`{word}` parses as 1.5.5 parsed it: {e}"));
        assert_eq!(
            serde_json::to_value(&parsed).ok(),
            Some(serde_json::Value::String(word.to_string()))
        );
    }
    let refused = serde_json::from_value::<busbar_kernel::config::ProviderAuth>(
        serde_json::Value::String("oauth2".to_string()),
    )
    .expect_err("an undeclared word is refused")
    .to_string();
    assert!(
        refused.starts_with(
            "unknown variant `oauth2`, expected one of `bearer`, `api-key`, `jwt-bearer`, \
             `oauth-client-credentials`"
        ),
        "the 1.5.5 refusal is the prefix: {refused}"
    );
    // The linked rows declare exactly the fixture's styles, in its order, 1.5.5's four first.
    assert_eq!(
        linked_declared()[..4],
        [
            "bearer",
            "api-key",
            "jwt-bearer",
            "oauth-client-credentials"
        ]
    );
}
