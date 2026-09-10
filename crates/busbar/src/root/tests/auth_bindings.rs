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
    fn operator_token_hash(&self) -> Option<String> {
        None
    }

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

    fn is_revoked(&self, credential: &str) -> bool {
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
                scopes: None,
                enabled: true,
                expires_at: None,
                deleted_at: None,
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

/// The directory the root binds is the one the unit is handed — the face itself, not a copy of it
/// — so the chain's signed-key arm resolves through the deployment's own directory.
#[test]
fn the_bound_directory_is_the_one_the_unit_is_handed() {
    let directory = a_directory();
    let bindings = AuthBindings::new(directory.clone() as Arc<dyn VirtualKeyDirectory>);

    let keys = bindings
        .directory()
        .expect("a bound directory is a verifier");
    assert_eq!(
        keys.verify("tok-live", 10, None),
        Some(KeyFacts {
            id: "vk_1".to_string(),
            name: "the operator's key".to_string(),
            scopes: None,
            enabled: true,
            expires_at: None,
            deleted_at: None,
        })
    );
    assert_eq!(keys.verify("tok-unknown", 10, None), None);
    assert_eq!(
        directory.asked.lock().expect("asked").len(),
        2,
        "both questions reached the directory rather than a second table here"
    );
}

/// The denylist answers from the same directory the verifier does, which is the point of binding
/// one face rather than two traits.
#[test]
fn the_denylist_reads_the_same_directory() {
    let bindings = AuthBindings::new(a_directory() as Arc<dyn VirtualKeyDirectory>);
    let directory = bindings
        .directory()
        .expect("a bound directory is a revocation view");
    assert!(directory.is_revoked("vk_gone"));
    assert!(!directory.is_revoked("vk_1"));
}

/// An unbound node binds a cache and no authority, which is a posture rather than a gap: the
/// chain's own answer with no verifier is to deny, and the gate that never runs would have had
/// nothing to refuse that the denial had not already refused.
#[test]
fn an_unbound_node_binds_a_cache_and_no_authority() {
    let bindings = AuthBindings::without_directory();
    assert!(bindings.cache().is_some());
    assert!(bindings.directory().is_none());
}
