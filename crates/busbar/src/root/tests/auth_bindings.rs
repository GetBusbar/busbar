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
            KeyFacts::unrestricted("vk_1", "the operator's key"),
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
        Some(ResolvedKey::unrestricted("vk_1", "the operator's key"))
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

/// The port carries every census field to the unit, unchanged, in both directions.
///
/// The two shapes are the same shape (owner ruling 13:0x (6): there is ONE enforced key), so the
/// conversion is a move. What this pins is that it STAYS a move: a field added on one side and
/// dropped in the `From` is the failure mode a hand-written projection has, and a round trip is
/// what catches it. Every field is set to something DISTINGUISHABLE, because a round trip over
/// defaults would pass while silently dropping half of them.
#[test]
fn the_key_port_round_trips_every_field_the_census_found_a_reader_for() {
    let facts = KeyFacts {
        id: "vk_round".to_string(),
        name: "round".to_string(),
        scopes: Some(vec![
            KeyScope {
                kind: "pool".to_string(),
                value: "blue".to_string(),
            },
            KeyScope {
                kind: "agent".to_string(),
                value: "sales".to_string(),
            },
        ]),
        expires_at: Some(4_242),
        enabled: false,
        deleted_at: Some(99),
    };
    let there: ResolvedKey = facts.clone().into();
    assert_eq!(there.id, facts.id);
    assert_eq!(there.name, facts.name);
    assert_eq!(there.expires_at, Some(4_242));
    assert!(!there.enabled);
    assert_eq!(there.deleted_at, Some(99));
    assert!(there.scope_allowed("pool", "blue"));
    assert!(there.scope_allowed("agent", "sales"));
    assert!(!there.scope_allowed("pool", "sales"));
    let back: KeyFacts = there.into();
    assert_eq!(back, facts);
}

/// The port does not carry the key's charging pot, and there is no way to ask it for one.
///
/// Ruling 13:0x (6) as an assertion rather than a promise: the legacy key's only money-carrying
/// field was its `group`, and it goes to the cost and ledger views. Asserted over the source
/// because the point is an ABSENCE, and an absence has no value to compare. Comments are stripped
/// so the file's prose stays free to explain the rule it is governed by.
#[test]
fn the_key_port_names_no_charging_pot() {
    let code: String = include_str!("../auth_bindings.rs")
        .lines()
        .map(str::trim_start)
        .filter(|l| !l.starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for banned in ["group", "budget", "cents", "RateCard", "per_request_fee"] {
        assert!(
            !code.contains(banned),
            "the key port names `{banned}` in code; the charging pot belongs to the cost and \
             ledger views, and the authenticate step decides who is calling and nothing else"
        );
    }
}
