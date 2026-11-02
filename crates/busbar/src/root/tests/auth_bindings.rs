use super::*;
use busbar_kernel_identity::module::AuthOutcome;
use std::sync::Mutex;

/// A directory a test can state the whole truth of in four lines.
#[derive(Default)]
struct Directory {
    keys: Vec<(String, KeyFacts)>,
    revoked: Vec<String>,
    asked: Mutex<Vec<String>>,
}

impl VirtualKeyDirectory for Directory {
    fn verify(&self, credential: &str, _now: u64, _expected_aud: Option<&str>) -> Option<KeyFacts> {
        self.asked
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(credential.to_string());
        self.keys
            .iter()
            .find(|(c, _)| c == credential)
            .map(|(_, f)| f.clone())
    }

    fn revoked(&self, credential: &str) -> bool {
        self.revoked.iter().any(|r| r == credential)
    }
}

fn a_directory() -> Arc<Directory> {
    Arc::new(Directory {
        keys: vec![(
            "tok-live".to_string(),
            KeyFacts {
                id: "vk_1".to_string(),
                name: "the operator's key".to_string(),
            },
        )],
        revoked: vec!["vk_gone".to_string()],
        asked: Mutex::new(Vec::new()),
    })
}

#[test]
fn a_revoked_credential_is_never_answered_from_a_cache_no_flush_reaches() {
    use std::sync::atomic::{AtomicBool, Ordering};

    struct Revocable(Arc<AtomicBool>);
    impl busbar_kernel_identity::module::AuthModule for Revocable {
        fn name(&self) -> &'static str {
            "revocable"
        }
        fn authenticate(&self, candidate: Option<&str>) -> AuthOutcome {
            match candidate {
                Some(_) if self.0.load(Ordering::SeqCst) => AuthOutcome::Reject,
                Some(id) => {
                    AuthOutcome::Identify(busbar_kernel_identity::principal::Principal::from_id(id))
                }
                None => AuthOutcome::Pass,
            }
        }
        fn cacheable(&self) -> bool {
            true
        }
    }

    for bindings in [
        AuthBindings::without_directory(),
        AuthBindings::new(a_directory() as Arc<dyn VirtualKeyDirectory>),
    ] {
        let revoked = Arc::new(AtomicBool::new(false));
        let chain = busbar_kernel_identity::AuthChain::new(
            vec![busbar_kernel_identity::chain::ChainEntry {
                provider: "revocable".to_string(),
                module: Box::new(Revocable(Arc::clone(&revoked))),
            }],
            false,
        );
        let first = chain.run_chain_with(Some("vk_live"), bindings.keys(), 10, None);
        assert!(matches!(
            first,
            busbar_kernel_identity::chain::ChainVerdict::Identified { .. }
        ));
        revoked.store(true, Ordering::SeqCst);
        let second = chain.run_chain_with(Some("vk_live"), bindings.keys(), 11, None);
        assert!(
            matches!(second, busbar_kernel_identity::chain::ChainVerdict::Denied),
            "the revoked credential was answered out of a cache: {second:?}"
        );
    }
}

#[test]
fn the_bound_verifier_resolves_through_the_directory() {
    let directory = a_directory();
    let bindings = AuthBindings::new(directory.clone() as Arc<dyn VirtualKeyDirectory>);

    let keys = bindings.keys().expect("a bound directory is a verifier");
    assert_eq!(
        keys.verify_token("tok-live", 10, None),
        Some(ResolvedKey {
            id: "vk_1".to_string(),
            name: "the operator's key".to_string(),
        })
    );
    assert_eq!(keys.verify_token("tok-unknown", 10, None), None);
    assert_eq!(
        directory.asked.lock().expect("asked").len(),
        2,
        "both questions reached the directory rather than a second table here"
    );
}

#[test]
fn the_revocation_view_reads_the_same_directory() {
    let bindings = AuthBindings::new(a_directory() as Arc<dyn VirtualKeyDirectory>);
    let revocations = bindings
        .revocations()
        .expect("a bound directory is a revocation view");
    assert!(revocations.is_revoked("vk_gone"));
    assert!(!revocations.is_revoked("vk_1"));
}

#[test]
fn an_unbound_node_binds_no_authority() {
    let bindings = AuthBindings::without_directory();
    assert!(bindings.keys().is_none());
    assert!(bindings.revocations().is_none());
}

fn hand_in_the_root_words() {
    busbar_kernel::preflight::install_linked_auth(crate::LINKED.auths, operator_words());
}

#[test]
fn the_operator_provider_is_the_row_the_manifest_names() {
    let words = operator_words();
    assert!(
        !words.provider.is_empty(),
        "the manifest names an operator row"
    );
    assert_eq!(words.provider, crate::LINKED.operator_auth);
    assert_eq!(words.principal_id, ADMIN_PRINCIPAL_ID);
    let stating: Vec<&str> = crate::LINKED
        .auths
        .iter()
        .filter(|&&(_, _, door)| {
            crate::root::loader::dispatch::kinds::auth::operator_principal(door).is_some()
        })
        .map(|&(key, _, _)| key)
        .collect();
    if crate::LINKED.auths.iter().any(|r| r.0 == words.provider) {
        assert_eq!(
            stating,
            [words.provider],
            "the named row is the one that states it"
        );
        let (_, _, door) = crate::LINKED
            .auths
            .iter()
            .find(|r| r.0 == words.provider)
            .copied()
            .expect("linked");
        assert_eq!(
            crate::root::loader::dispatch::kinds::auth::operator_principal(door).as_deref(),
            Some(words.principal_id)
        );
    } else {
        assert!(
            stating.is_empty(),
            "no unnamed row states the operator: {stating:?}"
        );
    }
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
    space.sort_unstable();
    let want: Vec<String> = operator_1_5_5()["hook_word_space"]
        .as_array()
        .expect("the 1.5.5 hook-name word space")
        .iter()
        .map(|w| w.as_str().expect("a word").to_string())
        .collect();
    assert_eq!(space, want, "1.5.5's whole hook-name word space");
}

fn dig<'a>(doc: &'a serde_yaml::Value, path: &[&str]) -> Option<&'a serde_yaml::Value> {
    let mut cur = doc;
    for k in path {
        cur = cur.as_mapping()?.get(serde_yaml::Value::from(*k))?;
    }
    Some(cur)
}

#[test]
fn migration_writes_the_14x_admin_token_as_1_5_5_did() {
    hand_in_the_root_words();
    let raw = "governance:\n  enabled: true\n  admin_token: \"${BUSBAR_ADMIN_TOKEN}\"\n\
               providers: {}\nmodels: {}\n";
    let out = busbar_kernel::config::migrate::migrate_config(raw).expect("migrates");
    let doc: serde_yaml::Value = serde_yaml::from_str(&out.yaml).expect("output is valid YAML");
    assert_eq!(
        dig(&doc, &["auth", "admin_auth"])
            .and_then(|v| v.as_sequence())
            .and_then(|s| s.first())
            .and_then(|v| v.as_str()),
        Some(word_1_5_5("provider").as_str())
    );
    assert_eq!(
        dig(
            &doc,
            &[
                "identity-providers",
                operator_words().provider,
                "token",
                "env"
            ]
        )
        .and_then(|v| v.as_str()),
        Some("BUSBAR_ADMIN_TOKEN")
    );
}

#[test]
fn migration_lifts_the_inline_operator_entry_as_1_5_5_did() {
    hand_in_the_root_words();
    let op = operator_words().provider;
    let raw = format!(
        "auth:\n  admin_auth:\n    - {op}: {{ token: {{ env: BUSBAR_ADMIN_TOKEN }} }}\n\
         providers: {{}}\nmodels: {{}}\n"
    );
    let out = busbar_kernel::config::migrate::migrate_config(&raw).expect("migrates");
    let doc: serde_yaml::Value = serde_yaml::from_str(&out.yaml).expect("output is valid YAML");
    let chain: Vec<&str> = dig(&doc, &["auth", "admin_auth"])
        .and_then(|v| v.as_sequence())
        .expect("an admin chain")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(chain, [word_1_5_5("provider").as_str()]);
    assert_eq!(
        dig(&doc, &["identity-providers", op, "token", "env"]).and_then(|v| v.as_str()),
        Some("BUSBAR_ADMIN_TOKEN")
    );
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
    let unanswered = busbar_kernel_identity::operator::unanswered_token(op);
    assert!(
        unanswered.starts_with(&format!("an {op} token is configured")),
        "{unanswered}"
    );
    assert!(
        unanswered.contains(&format!("`auth-{op}` feature")),
        "{unanswered}"
    );
    assert_eq!(
        unanswered,
        word_1_5_5("unanswered_token"),
        "1.5.5's line, byte for byte"
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
