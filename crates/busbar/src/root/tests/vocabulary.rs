//! Tests for `vocabulary.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;

fn a_configured_deployment() -> ConfigKeys {
    ConfigKeys {
        lanes: vec!["lane-primary".into(), "lane-standby".into()],
        pools: vec!["pool-main".into()],
        models: vec!["model-a".into(), "model-b".into()],
        hosts: vec!["upstream.example".into()],
        dialects: vec!["dialect-one".into()],
        agents: vec!["agent-alpha".into()],
        servers: vec!["server-one".into()],
        plugin_keys: vec!["store-memory".into()],
        egress_auth_fields: vec![
            "authorization".into(),
            "AKIAEXAMPLE".into(),
            "eu-west-1".into(),
            "service-name".into(),
        ],
        unpriced_messages: vec!["no configured rate for pool-main".into()],
        slot_fingerprints: vec!["fingerprint-0".into()],
        groups: vec!["tenant-acme".into(), "team-platform".into()],
        bucket_windows: vec!["60s".into()],
    }
}

/// The whole list goes through, and every key is distinct, so the interned count is the key
/// count. This is the fixed memory term, and it is a number a reader can check.
#[test]
fn every_config_derived_key_is_interned_once() {
    let keys = a_configured_deployment();
    let mut vocabulary = Vocabulary::new();
    let interned = vocabulary.intern_all(&keys);

    assert_eq!(interned.len(), keys.all().count());
    assert_eq!(vocabulary.len(), 19);
    for (name, value) in interned.iter().zip(keys.all()) {
        assert_eq!(*name, value);
    }
}

/// A group's name goes through the one interning every other config key does. That is what lets
/// the composition root hand the door a static name at registration, and the kernel count a
/// concurrency lease under it for the life of a unit — neither can hold a `String` the config
/// owns, and neither may leak one per request.
#[test]
fn a_group_name_is_interned_like_every_other_config_key() {
    let keys = a_configured_deployment();
    let mut vocabulary = Vocabulary::new();
    let interned = vocabulary.intern_all(&keys);

    let at = keys
        .all()
        .position(|n| n == "team-platform")
        .expect("the group is in the walk");
    assert_eq!(interned[at], "team-platform");
    assert!(
        std::ptr::eq(interned[at], vocabulary.key("team-platform")),
        "a group name is leaked once, so the door's name and the kernel's are one name"
    );
}

/// The same configuration read twice — a reload that changes nothing — leaks nothing the second
/// time. Idempotence is what makes a reload cost no memory.
#[test]
fn interning_the_same_configuration_twice_leaks_nothing_further() {
    let keys = a_configured_deployment();
    let mut vocabulary = Vocabulary::new();

    let first = vocabulary.intern_all(&keys);
    let after_first = vocabulary.len();
    let second = vocabulary.intern_all(&keys);

    assert_eq!(vocabulary.len(), after_first);
    for (a, b) in first.iter().zip(&second) {
        assert!(std::ptr::eq(*a, *b), "a repeated key was leaked twice");
    }
}

/// A deployment that declares nothing interns nothing. The fixed term is zero, which is what
/// makes a zero-config boot indistinguishable from the previous release's.
#[test]
fn a_zero_config_boot_interns_nothing() {
    let mut vocabulary = Vocabulary::new();
    let interned = vocabulary.intern_all(&ConfigKeys::default());
    assert!(interned.is_empty());
    assert!(vocabulary.is_empty());
    assert_eq!(vocabulary.len(), 0);
}

/// The seal is the whole point of the wrapper: after it, a key is a defect, and EVERY build says
/// so rather than quietly leaking. No `cfg(debug_assertions)` on this test, because the refusal
/// it pins no longer has one — a release build that reached this line would leak per call, and a
/// test that only ran in debug would never have noticed.
#[test]
#[should_panic(expected = "root vocabulary sealed")]
fn interning_after_the_seal_is_a_defect() {
    let mut vocabulary = Vocabulary::new();
    vocabulary.intern_all(&a_configured_deployment());
    vocabulary.seal();
    let _ = vocabulary.key("a-lane-discovered-on-the-thousandth-connection");
}

/// And before the seal it is ordinary work: the assertion is about when, not about what.
#[test]
fn interning_before_the_seal_is_ordinary() {
    let mut vocabulary = Vocabulary::new();
    assert!(!vocabulary.is_sealed());
    let name = vocabulary.key("lane-late-but-still-at-boot");
    assert_eq!(name, "lane-late-but-still-at-boot");
    vocabulary.seal();
    assert!(vocabulary.is_sealed());
    assert_eq!(vocabulary.len(), 1);
}

/// The walk order is fixed, so two boots on one configuration intern in one sequence. Without
/// that the count is reproducible but the ordering is not, and a memory comparison across
/// restarts stops meaning anything.
#[test]
fn the_walk_order_is_stable() {
    let keys = a_configured_deployment();
    let first: Vec<&str> = keys.all().collect();
    let second: Vec<&str> = keys.all().collect();
    assert_eq!(first, second);
    assert_eq!(first[0], "lane-primary");
    assert_eq!(first[first.len() - 1], "60s");
}

/// A key that appears in two sections — a pool and a lane sharing a name, which configuration
/// permits — is one leak, not two, and both sections get the same static name back.
#[test]
fn a_name_used_in_two_sections_is_leaked_once() {
    let keys = ConfigKeys {
        lanes: vec!["shared".into()],
        pools: vec!["shared".into()],
        ..ConfigKeys::default()
    };
    let mut vocabulary = Vocabulary::new();
    let interned = vocabulary.intern_all(&keys);

    assert_eq!(interned.len(), 2);
    assert!(std::ptr::eq(interned[0], interned[1]));
    assert_eq!(vocabulary.len(), 1);
}
