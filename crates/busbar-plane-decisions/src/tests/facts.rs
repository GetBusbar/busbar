use super::*;

#[test]
fn never_read_members_names_state_and_answers() {
    assert_eq!(NEVER_READ_MEMBERS, &["state", "answers"]);
}

#[test]
fn no_declared_fact_key_is_a_forbidden_member_name() {
    let declared = SESSION_FACTS.iter().chain(CONTENT_FACTS.iter());
    for key in declared {
        assert!(
            !NEVER_READ_MEMBERS.contains(key),
            "a declared fact key names a member this plane must never read: {key}"
        );
    }
}

#[test]
fn content_facts_names_no_pii_bearing_key() {
    // A coarse but real guard: every content-fact key this plane declares is metadata, spelled to
    // say so, never `state`/`answers`/a synonym of either.
    for key in CONTENT_FACTS {
        assert!(!key.contains("state"));
        assert!(!key.contains("answer"));
    }
}
