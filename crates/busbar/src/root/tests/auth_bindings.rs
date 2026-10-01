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
        assert!(
            bindings.cache().is_none(),
            "the bindings hold a credential cache the admin flush cannot reach"
        );
        let revoked = Arc::new(AtomicBool::new(false));
        let chain = busbar_kernel_identity::AuthChain::new(
            vec![busbar_kernel_identity::chain::ChainEntry {
                provider: "revocable".to_string(),
                module: Box::new(Revocable(Arc::clone(&revoked))),
            }],
            false,
        );
        let first = chain.run_chain_cached(Some("vk_live"), bindings.cache(), None, 10, None);
        assert!(matches!(
            first,
            busbar_kernel_identity::chain::ChainVerdict::Identified { .. }
        ));
        revoked.store(true, Ordering::SeqCst);
        let second = chain.run_chain_cached(Some("vk_live"), bindings.cache(), None, 11, None);
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
    assert!(bindings.cache().is_none());
    assert!(bindings.keys().is_none());
    assert!(bindings.revocations().is_none());
}

/// THE FACADE DOES NOT DOCUMENT A SWAP THAT ALREADY HAPPENED ELSEWHERE (item 289).
///
/// The header used to describe relocating the authenticate step as a pending one-line edit here
/// ("swap `pub use crate::auth;` for `pub use busbar_kernel_identity;`") and to call itself the
/// target consumers migrate onto. The relocated crate was already live in the composition root and
/// its consumers went around the facade, so a maintainer reading it concluded the step had not moved
/// and fixed only `crate::auth`. While the binary depends on the relocated crate, the facade must say
/// so and must not present that swap as still to come.
///
/// It lives here, in the binary, because the premise is the binary's own manifest: the kernel has
/// no dependency edge on `busbar` and may not read its files (kind-isolation build-inputs), while
/// `busbar` depends on `busbar-kernel` and reads the facade through that edge.
#[test]
fn the_facade_names_the_relocated_authenticate_step_it_does_not_point_at() {
    let binary = include_str!("../../../Cargo.toml");
    let facade = include_str!("../../../../busbar-kernel/src/drain.rs");
    let relocated_is_live = binary
        .lines()
        .any(|l| l.trim_start().starts_with("busbar-kernel-identity"));
    if !relocated_is_live {
        return;
    }
    assert!(
        !facade.contains("for `pub use busbar_kernel_identity;`"),
        "drain.rs still presents the authenticate swap as pending while the binary runs the relocated crate"
    );
    assert!(
        !facade.contains("stable target consumers migrate ONTO"),
        "drain.rs still claims consumers migrate onto it; they migrated around it"
    );
    assert!(
        facade.contains("ALREADY RELOCATED") && facade.contains("`busbar-kernel-identity`"),
        "drain.rs's authenticate step must say it already runs from `busbar-kernel-identity`"
    );
}

// ------------------------------------------------------------------------------------------------
// THE ROOT LEGACY TABLE'S OPERATOR WORDS — 1.5.5's bytes, pinned where the words live (ARCHITECT
// 2026-09-30, KERNEL-AUTH-ZERO Q2: the byte-pin tests move to crates/busbar). The kernel's own tests
// run on a kind-neutral double; these run on the words this root hands in at boot.
// ------------------------------------------------------------------------------------------------

/// Hand the root's words in with its linked auth rows, as `register_planes` does at boot (the first
/// install stands, and every install in this binary is this one).
fn hand_in_the_root_words() {
    busbar_kernel::preflight::install_linked_auth(crate::LINKED.auths, operator_words());
}

#[test]
fn the_legacy_table_spells_the_operator_credential_as_1_5_5_did() {
    let words = operator_words();
    assert_eq!(words.provider, "admin-tokens");
    assert_eq!(words.principal_id, "admin");
}

#[test]
fn the_kernel_answers_to_the_root_words_once_handed_in() {
    hand_in_the_root_words();
    assert_eq!(busbar_kernel::config::operator_provider(), "admin-tokens");
    assert_eq!(busbar_kernel::config::operator_principal_id(), "admin");
    // The `auth.admin_auth:` default: the operator credential, referenced bare.
    assert_eq!(
        busbar_kernel::config::default_admin_auth_names(),
        ["admin-tokens"]
    );
    assert_eq!(
        busbar_kernel::config::builtin_identity_providers(),
        ["keys", "admin-tokens"]
    );
}

/// The 1.5.3 hook-name word space, WHOLE: the kernel's frozen words and the root's operator word.
/// Exactly 1.5.5's set (v1.5.5:crates/busbar/src/config/mod.rs:1891).
#[test]
fn the_frozen_hook_name_word_space_is_1_5_5_s() {
    hand_in_the_root_words();
    let mut space: Vec<&str> = busbar_kernel::config::FROZEN_HOOK_NAME_WORD_SPACE.to_vec();
    space.push(busbar_kernel::config::operator_provider());
    space.sort_unstable();
    assert_eq!(
        space,
        [
            "admin-tokens",
            "cheapest",
            "fastest",
            "first",
            "least_busy",
            "nothing",
            "reject",
            "tokens",
            "usage",
            "weighted",
        ]
    );
    assert!(busbar_kernel::config::is_reserved_hook_name("admin-tokens"));
    assert!(busbar_kernel::config::is_reserved_hook_name("tokens"));
    assert!(!busbar_kernel::config::is_reserved_hook_name(
        "admin-tokens-2"
    ));
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
/// `auth.admin_auth: [admin-tokens]` and the secret ref on `identity-providers.admin-tokens`.
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
        Some("admin-tokens")
    );
    assert_eq!(
        dig(
            &doc,
            &["identity-providers", "admin-tokens", "token", "env"]
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
    let raw = "auth:\n  admin_auth:\n    - admin-tokens: { token: { env: BUSBAR_ADMIN_TOKEN } }\n\
               providers: {}\nmodels: {}\n";
    let out = busbar_kernel::config::migrate::migrate_config(raw).expect("migrates");
    let doc: serde_yaml::Value = serde_yaml::from_str(&out.yaml).expect("output is valid YAML");
    let chain: Vec<&str> = dig(&doc, &["auth", "admin_auth"])
        .and_then(|v| v.as_sequence())
        .expect("an admin chain")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(chain, ["admin-tokens"]);
    assert_eq!(
        dig(
            &doc,
            &["identity-providers", "admin-tokens", "token", "env"]
        )
        .and_then(|v| v.as_str()),
        Some("BUSBAR_ADMIN_TOKEN")
    );
}

/// The shipped example config.yaml must not force a mandatory boot failure on an unset
/// `BUSBAR_ADMIN_TOKEN`: no brace-form interpolation of it may appear anywhere (comments included,
/// since `interpolate_env` scans the whole file).
///
/// RE-HOMED from the kernel's `test_shipped_example_config_resolves` (ARCHITECT 2026-09-30,
/// KERNEL-AUTH-ZERO Q2): the shipped config names the operator credential by the root legacy
/// table's word, so it resolves only on the words this root hands in. Its parse-and-resolve half is
/// `tests/docs_examples.rs::shipped_config_artifacts_validate`, which runs the real binary's
/// `--validate` (parse, resolve, validate) on the same config.yaml against providers.yaml. The
/// kernel test's neutral plane registration does not come along: it is process-wide, and this
/// binary's plane-node tests run on the root's own planes.
#[test]
fn the_shipped_config_needs_no_admin_token_to_boot() {
    let config_raw =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../config.yaml")).unwrap();
    assert!(
        !config_raw.contains("${BUSBAR_ADMIN_TOKEN}"),
        "the shipped config must not force a mandatory boot failure on unset BUSBAR_ADMIN_TOKEN"
    );
    assert!(
        config_raw.contains(&format!("admin_auth: [{}]", operator_words().provider)),
        "the shipped config guards the admin API with the root's operator credential"
    );
}

/// The operator credential's refusals, byte for byte v1.5.5's, over the root's words (moved from the
/// kernel's config_validate tests, which now assert the same text over the kernel's double).
/// `git show v1.5.5:crates/busbar/src/config_validate/mod.rs`, 1175.
#[test]
fn the_operator_refusals_are_1_5_5_s_bytes() {
    let op = operator_words().provider;
    assert_eq!(
        busbar_kernel_identity::operator::unanswered_token(op),
        "an admin-tokens token is configured but this binary was built WITHOUT the \
         `auth-admin-tokens` feature — the admin API would be silently disabled. Rebuild \
         with default features or wire an external admin auth module."
    );
    assert_eq!(
        busbar_kernel_identity::operator::misplaced_token(op, "keys"),
        "auth chain entry 'keys' sets `token:`, which belongs to the built-in \
         `admin-tokens` module only; move it, e.g.:\n\n    admin_auth:\n      - \
         admin-tokens: { token: { env: BUSBAR_ADMIN_TOKEN } }\n"
    );
}
