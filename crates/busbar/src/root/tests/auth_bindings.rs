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
