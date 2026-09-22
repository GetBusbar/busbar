// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TWO SEAMS A MINT GOES THROUGH THAT NOBODY WAS WATCHING.
//!
//! `plan_mint_group` has its own batteries and they are thorough — but they run against a lookup
//! double declared beside them, so they exercise the DECISION and never the ADAPTER that carries a
//! real governance answer into it. An adapter that dropped the group's actual parent on the floor
//! would leave every one of those batteries green while the shipped path refused (or worse,
//! accepted) every mint that named a parent. So these go through `Verbs::create_key`.
//!
//! And the rotate slot: the id and the header value are BOTH caller-chosen text, so joining them on
//! a separator either may contain does not make a key, it makes a coincidence. The length of the id
//! is written ahead of it for the same reason the audit preimage frames its fields. A rotate that
//! landed on another rotate's slot goes wrong twice in one breath — the key the caller named is
//! never rotated, so its old credential goes on authenticating, and what comes back is the
//! credential minted for a DIFFERENT key.

use super::*;
use crate::verbs::MintOutcome;

/// THE ADAPTER CARRIES THE GROUP'S REAL PARENT, NOT A CONSTANT.
///
/// A mint that names an existing group AND its correct parent is a bind-as-is and must succeed.
/// This is the only assertion in the crate that makes the adapter's answer matter: an adapter
/// answering `None`, or the empty string, or any name of its own, turns this legitimate mint into a
/// re-homing conflict and no operator can bind a key to a group they correctly described.
#[test]
fn a_mint_naming_an_existing_groups_real_parent_binds_as_is() {
    let gov = FakeGovernance::new()
        .with_group("root", None)
        .with_group("team", Some("root"));
    let verbs = make_verbs(gov);
    let admin = admin();

    verbs
        .create_key(
            &admin,
            "alice",
            VerbScope::Full,
            0,
            UnitKey::new(1),
            None,
            Some("team"),
            Some("root"),
        )
        .expect("naming a group's actual parent is a bind-as-is, not a re-homing");
}

/// AND IT REFUSES THE RE-HOMING IT IS THERE TO CATCH.
///
/// The control for the test above: the same call with the WRONG parent must conflict. Without this
/// half, an adapter that always answered with whatever it was asked for would pass the test above
/// and silently let a mint move an existing group under a new parent.
#[test]
fn a_mint_naming_the_wrong_parent_for_an_existing_group_is_refused_as_a_conflict() {
    let gov = FakeGovernance::new()
        .with_group("root", None)
        .with_group("elsewhere", None)
        .with_group("team", Some("root"));
    let verbs = make_verbs(gov);
    let admin = admin();

    let Err(err) = verbs.create_key(
        &admin,
        "alice",
        VerbScope::Full,
        0,
        UnitKey::new(1),
        None,
        Some("team"),
        Some("elsewhere"),
    ) else {
        panic!("a mint must never re-home an existing group");
    };
    assert_eq!(err.reason, crate::refusal::ReasonCode::Conflict);
    assert_eq!(err.step, crate::refusal::RefusalStep::Verify);
}

/// A ROOT GROUP'S PARENT IS ABSENT, AND NAMING ONE FOR IT IS STILL A CONFLICT.
///
/// The adapter has to be able to say "this group has no parent" as distinct from "this group has a
/// parent I did not fetch". An adapter that answered a name here would let a caller re-home a root
/// group by asserting a parent it does not have.
#[test]
fn a_root_group_has_no_parent_and_claiming_one_conflicts() {
    let gov = FakeGovernance::new()
        .with_group("root", None)
        .with_group("other", None);
    let verbs = make_verbs(gov);
    let admin = admin();

    let Err(err) = verbs.create_key(
        &admin,
        "alice",
        VerbScope::Full,
        0,
        UnitKey::new(1),
        None,
        Some("root"),
        Some("other"),
    ) else {
        panic!("a root group must not be re-homed by a mint");
    };
    assert_eq!(err.reason, crate::refusal::ReasonCode::Conflict);

    // And naming no parent at all for the same root group is the bind-as-is it always was.
    verbs
        .create_key(
            &admin,
            "alice",
            VerbScope::Full,
            0,
            UnitKey::new(1),
            None,
            Some("root"),
            None,
        )
        .expect("binding to an existing root group names nothing to re-home");
}

/// TWO ROTATES WHOSE ID AND HEADER JOIN TO THE SAME STRING ARE TWO SLOTS.
///
/// `("a:b", "c")` and `("a", "b:c")` join to one string on a colon. Under a joined key the second
/// rotate would REPLAY the first: the second key is never rotated at all — so the credential the
/// operator believes they have retired goes on authenticating — and the response hands back the
/// credential minted for the first. The id's length is written ahead of it, so the boundary sits
/// somewhere no id's content can move it.
#[test]
fn two_rotates_whose_id_and_header_join_to_one_string_do_not_replay_each_other() {
    let gov = FakeGovernance::new()
        .with_key("a:b", false)
        .with_key("a", false);
    let verbs = make_verbs(gov);
    let admin = admin();

    let first = verbs
        .rotate_key(
            &admin,
            "alice",
            VerbScope::Full,
            0,
            UnitKey::new(1),
            Some("c"),
            "a:b",
        )
        .expect("the first rotate is served");
    let second = verbs
        .rotate_key(
            &admin,
            "alice",
            VerbScope::Full,
            0,
            UnitKey::new(1),
            Some("b:c"),
            "a",
        )
        .expect("the second rotate is served on its own slot");

    let (first_body, second_body) = (body_of(&first), body_of(&second));
    assert_ne!(
        first_body, second_body,
        "the second rotate replayed the first -- the key it named was never rotated"
    );
    // The bodies name the two DIFFERENT keys that were actually asked for.
    assert!(
        first_body.starts_with(b"a:b\0"),
        "the first rotate did not answer for the key it named"
    );
    assert!(
        second_body.starts_with(b"a\0"),
        "the second rotate did not answer for the key it named"
    );
}

/// AND A GENUINE RETRY OF ONE OF THEM STILL REPLAYS.
///
/// Framing the slot must not have broken the thing the slot is for. The same id and the same header
/// is the same call, and the second arrival returns the first response verbatim without rotating
/// again.
#[test]
fn a_genuine_rotate_retry_replays_the_first_response_verbatim() {
    let gov = FakeGovernance::new().with_key("a:b", false);
    let verbs = make_verbs(gov);
    let admin = admin();

    let first = verbs
        .rotate_key(
            &admin,
            "alice",
            VerbScope::Full,
            0,
            UnitKey::new(1),
            Some("c"),
            "a:b",
        )
        .expect("the first rotate is served");
    let retry = verbs
        .rotate_key(
            &admin,
            "alice",
            VerbScope::Full,
            1,
            UnitKey::new(1),
            Some("c"),
            "a:b",
        )
        .expect("the retry is served from the slot");

    assert!(
        matches!(retry, MintOutcome::Replayed { .. }),
        "an identical rotate retry re-ran the rotation instead of replaying it"
    );
    assert_eq!(
        body_of(&first),
        body_of(&retry),
        "the replay did not return the first response verbatim"
    );
}

/// A CREATE AND A ROTATE SHARING A HEADER VALUE NEVER REPLAY EACH OTHER.
///
/// They are separate caches AND separately named slots. A create replaying a rotate's response (or
/// the reverse) would hand back a credential for a key the caller never asked about.
#[test]
fn a_create_and_a_rotate_sharing_a_header_value_are_separate_slots() {
    let gov = FakeGovernance::new().with_key("a", false);
    let verbs = make_verbs(gov);
    let admin = admin();

    let created = verbs
        .create_key(
            &admin,
            "alice",
            VerbScope::Full,
            0,
            UnitKey::new(1),
            Some("shared"),
            None,
            None,
        )
        .expect("the create is served");
    let rotated = verbs
        .rotate_key(
            &admin,
            "alice",
            VerbScope::Full,
            0,
            UnitKey::new(1),
            Some("shared"),
            "a",
        )
        .expect("the rotate is served");

    assert!(
        matches!(rotated, MintOutcome::Minted { .. }),
        "a rotate replayed a create that happened to share its header value"
    );
    assert_ne!(body_of(&created), body_of(&rotated));
}

/// The response bytes a mint outcome carries, however it was produced.
fn body_of(outcome: &MintOutcome) -> &[u8] {
    match outcome {
        MintOutcome::Minted { body, .. } => body,
        MintOutcome::Replayed { body } => body,
    }
}
