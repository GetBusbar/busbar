// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

/// A directory a test can state the whole truth of in one line.
struct Directory {
    revoked: Vec<String>,
}

impl RevocationView for Directory {
    fn is_revoked(&self, credential: &str) -> bool {
        self.revoked.iter().any(|r| r == credential)
    }
}

fn a_directory() -> Arc<Directory> {
    Arc::new(Directory {
        revoked: vec!["vk_gone".to_string()],
    })
}

#[test]
fn the_revocation_view_reads_the_same_directory() {
    let bindings = AuthBindings::new(a_directory() as Arc<dyn RevocationView>);
    let revocations = bindings
        .revocations()
        .expect("a bound directory is a revocation view");
    assert!(revocations.is_revoked("vk_gone"));
    assert!(!revocations.is_revoked("vk_1"));
}

#[test]
fn an_unbound_node_binds_no_authority() {
    let bindings = AuthBindings::without_directory();
    assert!(bindings.revocations().is_none());
}

fn hand_in_the_root_words() {
    busbar_kernel::preflight::install_linked_auth(crate::LINKED.auths);
    busbar_kernel::preflight::install_operator(crate::root::auth_bindings::operator_binding(None));
}

/// The operator words process start judges from this root's admitted rows (OPERATOR-FROM-ADMITTED-AUTH
/// §3.4): the linked operator row stating the operator fact.
fn operator_words() -> busbar_kernel_identity::operator::OperatorWords {
    hand_in_the_root_words();
    busbar_kernel_identity::operator::words()
}

#[test]
fn the_operator_provider_is_the_row_the_manifest_names() {
    let words = operator_words();
    assert!(
        !words.provider.is_empty(),
        "the manifest names an operator row"
    );
    assert_eq!(
        words.principal_id, "admin",
        "the principal the operator row states"
    );
}

fn operator_1_5_5() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../../../../testing/shadow-oracle/fixtures/law0/operator-1.5.5.json"
    ))
    .expect("the 1.5.5 operator fixture is JSON")
}

fn word_1_5_5(key: &str) -> String {
    operator_1_5_5()[key]
        .as_str()
        .unwrap_or_else(|| panic!("the 1.5.5 operator fixture states `{key}`"))
        .to_string()
}

#[test]
fn the_kernel_answers_to_the_root_words_once_handed_in() {
    hand_in_the_root_words();
    let words = operator_words();
    assert_eq!(
        words.provider,
        word_1_5_5("provider"),
        "1.5.5's operator word"
    );
    assert_eq!(
        words.principal_id,
        word_1_5_5("principal"),
        "1.5.5's operator principal"
    );
    assert_eq!(busbar_kernel::config::operator_provider(), words.provider);
    assert_eq!(
        busbar_kernel::config::operator_principal_id(),
        words.principal_id
    );

    assert_eq!(
        busbar_kernel::config::default_admin_auth_names(),
        [words.provider]
    );
    assert_eq!(
        busbar_kernel::config::builtin_identity_providers(),
        ["keys", words.provider]
    );
}

#[test]
fn the_hook_name_word_space_is_the_frozen_words_and_the_operator_word() {
    hand_in_the_root_words();
    let op = operator_words().provider;
    for word in busbar_kernel::config::FROZEN_HOOK_NAME_WORD_SPACE
        .iter()
        .copied()
        .chain([op])
    {
        assert!(
            busbar_kernel::config::is_reserved_hook_name(word),
            "`{word}` is reserved"
        );
    }
    assert!(
        !busbar_kernel::config::FROZEN_HOOK_NAME_WORD_SPACE.contains(&op),
        "the operator word is the root's, never the kernel's"
    );
    assert!(!busbar_kernel::config::is_reserved_hook_name(&format!(
        "{op}-2"
    )));

    let mut space: Vec<&str> = busbar_kernel::config::FROZEN_HOOK_NAME_WORD_SPACE.to_vec();
    space.push(op);
    space.sort();
    let want: Vec<String> = operator_1_5_5()["hook_word_space"]
        .as_array()
        .expect("the 1.5.5 hook-name word space")
        .iter()
        .map(|w| w.as_str().expect("a word").to_string())
        .collect();
    assert_eq!(space, want, "1.5.5's whole hook-name word space");
}

#[test]
fn the_shipped_config_needs_no_admin_token_to_boot() {
    let config_raw =
        std::fs::read_to_string(concat!(env!("BUSBAR_CORE_DIR"), "/../../config.yaml")).unwrap();
    assert!(
        !config_raw.contains("${BUSBAR_ADMIN_TOKEN}"),
        "the shipped config must not force a mandatory boot failure on unset BUSBAR_ADMIN_TOKEN"
    );
    assert!(
        config_raw.contains(&format!("admin_auth: [{}]", operator_words().provider)),
        "the shipped config guards the admin API with the root's operator credential"
    );
}

#[test]
fn the_operator_refusals_name_the_root_words() {
    let op = operator_words().provider;
    // A configured `token:` the build cannot answer: 1.5.5's "built WITHOUT the `auth-<op>`
    // feature" refusal went with the compiled-in operator (c1b9b9e234, OPERATOR-FROM-ADMITTED-AUTH
    // r3.1 OP-3); a 1.5 `token:` is now refused with its 1.6 remedy, at the definition it names.
    let unanswered = busbar_kernel_identity::operator::operator_token(op);
    assert!(
        unanswered.starts_with(&format!(
            "identity-providers.{op}: `token:` is the 1.5 operator credential"
        )),
        "{unanswered}"
    );
    assert!(
        unanswered.contains("docs/migration-1.6.md#operator-credential"),
        "{unanswered}"
    );
    let misplaced = busbar_kernel_identity::operator::misplaced_token(op, "keys");
    assert_eq!(
        misplaced,
        word_1_5_5("misplaced_token"),
        "1.5.5's line, byte for byte"
    );
    assert!(
        misplaced.starts_with("auth chain entry 'keys' sets `token:`"),
        "{misplaced}"
    );
    assert!(
        misplaced.contains(&format!("built-in `{op}` module only")),
        "{misplaced}"
    );
    assert!(
        misplaced.contains(&format!(
            "- {op}: {{ token: {{ env: BUSBAR_ADMIN_TOKEN }} }}"
        )),
        "{misplaced}"
    );
}
