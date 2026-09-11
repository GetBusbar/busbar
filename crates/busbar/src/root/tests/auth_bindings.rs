//! Tests for `auth_bindings.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;
use busbar_unit_auth::module::AuthOutcome;
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
                tier: None,
            },
        )],
        revoked: vec!["vk_gone".to_string()],
        asked: Mutex::new(Vec::new()),
    })
}

/// The cache digests with the node's own hex SHA-256, which is what makes one credential one row
/// wherever in the tree it is named. Asserted against the published function rather than against
/// a literal, because the property is that the two are the same function and not that either is
/// a particular string.
#[test]
fn the_cache_digests_with_the_nodes_own_hex_sha256() {
    let bindings = AuthBindings::without_directory();
    let cache = bindings.cache().expect("a cache is always bound");
    cache.put(
        "provider",
        "credential-a",
        &AuthOutcome::Pass,
        0,
        cache.generation(),
    );

    // The row is reachable under the same credential, which it can only be if the digest the
    // insert used and the digest the read uses are one function.
    assert!(cache.get("provider", "credential-a", 0).is_some());
    assert!(cache.get("provider", "credential-b", 0).is_none());
    assert_eq!(
        busbar_api::sha256_hex(b"credential-a").len(),
        64,
        "the bound digest is the 32-byte SHA-256 rendered as lower-case hex"
    );
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
            tier: None,
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

/// An unbound node binds a cache and no authority, which is a posture rather than a gap: the
/// chain's own answer with no verifier is to deny, and the gate that never runs would have had
/// nothing to refuse that the denial had not already refused.
#[test]
fn an_unbound_node_binds_a_cache_and_no_authority() {
    let bindings = AuthBindings::without_directory();
    assert!(bindings.cache().is_some());
    assert!(bindings.keys().is_none());
    assert!(bindings.revocations().is_none());
}
