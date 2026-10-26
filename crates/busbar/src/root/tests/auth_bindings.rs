//! Tests for `auth_bindings.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

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

/// NO SECOND CREDENTIAL CACHE (item 249): the bindings hand the chain none, so a verdict the
/// operator's flush was meant to kill is never served from a cache the flush cannot reach.
///
/// The root used to build its own cache here, a port of the kernel's, while the admin flush
/// endpoint reaches only the kernel's. Driven through the chain with a CACHEABLE module that
/// identifies a credential and is then told the credential is revoked: with a cache held here the
/// second run answered the first verdict out of it; with none, the module is asked again and its
/// refusal stands.
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

/// The verifier the root binds resolves through the directory and hands back the unit's own
/// shape, so the chain's signed-key arm has something to identify with.
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

/// The revocation view answers from the same directory the verifier does, which is the point of
/// binding one value rather than two.
#[test]
fn the_revocation_view_reads_the_same_directory() {
    let bindings = AuthBindings::new(a_directory() as Arc<dyn VirtualKeyDirectory>);
    let revocations = bindings
        .revocations()
        .expect("a bound directory is a revocation view");
    assert!(revocations.is_revoked("vk_gone"));
    assert!(!revocations.is_revoked("vk_1"));
}

/// An unbound node binds no authority, which is a posture rather than a gap: the chain's own answer
/// with no verifier is to deny, and the gate that never runs would have had nothing to refuse that
/// the denial had not already refused.
#[test]
fn an_unbound_node_binds_no_authority() {
    let bindings = AuthBindings::without_directory();
    assert!(bindings.keys().is_none());
    assert!(bindings.revocations().is_none());
}

// ------------------------------------------------------------------------------------------------
// THE ROOT LEGACY TABLE'S OPERATOR WORDS — 1.5.5's bytes, pinned where the words live. The kernel's own tests
// run on a kind-neutral double; these run on the words this root hands in at boot.
// ------------------------------------------------------------------------------------------------

/// Hand the root's words in with its linked auth rows, as `register_planes` does at boot (the first
/// install stands, and every install in this binary is this one).
fn hand_in_the_root_words() {
    busbar_kernel::preflight::install_linked_auth(crate::LINKED.auths, operator_words());
}

/// THE OPERATOR'S PROVIDER WORD IS THE MANIFEST'S: the registry key of the row the manifest's
/// operator table names, and — where this build links that row — the row whose own Statement states
/// it is the operator credential, identifying the operator as the principal the words carry. The
/// root's source spells neither.
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

/// THE OPERATOR CREDENTIAL'S 1.5.5 WORDS AND LINES, as DATA in the oracle corpus
/// (`testing/shadow-oracle/fixtures/law0/operator-1.5.5.json`, verbatim from the 1.5.5 binary):
/// what the root's words must still read as, byte for byte.
fn operator_1_5_5() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../../../../testing/shadow-oracle/fixtures/law0/operator-1.5.5.json"
    ))
    .expect("the 1.5.5 operator fixture is JSON")
}

/// A string field of the 1.5.5 operator fixture.
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
    // The `auth.admin_auth:` default: the operator credential, referenced bare.
    assert_eq!(
        busbar_kernel::config::default_admin_auth_names(),
        [words.provider]
    );
    assert_eq!(
        busbar_kernel::config::builtin_identity_providers(),
        ["keys", words.provider]
    );
}

/// The 1.5.3 hook-name word space, WHOLE: the kernel's frozen words and the root's operator word —
/// every one reserved, a word beside them not, and the whole set 1.5.5's
/// (v1.5.5:crates/busbar/src/config/mod.rs:1891, held as DATA).
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
    // Exactly 1.5.5's set (v1.5.5:crates/busbar/src/config/mod.rs:1891), as DATA.
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

/// Walk `path` down a migrated document.
fn dig<'a>(doc: &'a serde_yaml::Value, path: &[&str]) -> Option<&'a serde_yaml::Value> {
    let mut cur = doc;
    for k in path {
        cur = cur.as_mapping()?.get(serde_yaml::Value::from(*k))?;
    }
    Some(cur)
}

/// 1.4.x `governance.admin_token: ${VAR}` migrates onto the operator credential as 1.5.5 wrote it:
/// `auth.admin_auth: [<operator word>]` and the secret ref on `identity-providers.<operator word>`.
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

/// A 1.5.x inline admin chain entry for the operator credential lifts onto its definition, and the
/// chain keeps the bare name, as 1.5.5 wrote it.
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

/// The shipped example config.yaml must not force a mandatory boot failure on an unset
/// `BUSBAR_ADMIN_TOKEN`: no brace-form interpolation of it may appear anywhere (comments included,
/// since `interpolate_env` scans the whole file).
///
/// RE-HOMED from the kernel's `test_shipped_example_config_resolves`: the shipped config names the operator credential by the root legacy
/// table's word, so it resolves only on the words this root hands in. Its parse-and-resolve half is
/// `tests/docs_examples.rs::shipped_config_artifacts_validate`, which runs the real binary's
/// `--validate` (parse, resolve, validate) on the same config.yaml against providers.yaml. The
/// kernel test's neutral plane registration does not come along: it is process-wide, and this
/// binary's plane-node tests run on the root's own planes.
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

/// The operator credential's refusals name the root's operator word where 1.5.5 named it (its
/// feature, its module, the chain entry an operator moves the token to), and read as 1.5.5's lines
/// byte for byte (v1.5.5:crates/busbar/src/config_validate/mod.rs:1175), held as DATA.
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
