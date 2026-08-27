// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The card reader and the two hashes taken over a card.
//!
//! The tests that matter here are the ones about what is hashed and what is NOT, because those are
//! the ones an attacker gets a say in.

use super::*;
use serde_json::json;

/// A card with the members busbar actually acts on, plus one member busbar does not model. The
/// unmodelled member is deliberate and load-bearing for the first test below.
fn a_card() -> Value {
    json!({
        "protocolVersion": "0.3.0",
        "name": "planner",
        "description": "plans things",
        "version": "1.4.0",
        "provider": { "organization": "Vendor", "url": "https://vendor.example" },
        "supportedInterfaces": [
            { "url": "https://a2a.vendor.example/planner", "protocolBinding": "JSONRPC" }
        ],
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "capabilities": {
            "streaming": true,
            "pushNotifications": false,
            "stateTransitionHistory": false,
            "extendedAgentCard": false
        },
        "skills": [
            {
                "id": "plan",
                "name": "Plan",
                "description": "decompose a goal",
                "tags": ["planning"],
                "inputModes": ["application/json"],
                "outputModes": ["application/json"],
                "examples": []
            },
            {
                "id": "summarize",
                "name": "Summarize",
                "description": "shorten a document",
                "tags": ["text"],
                "inputModes": ["application/json"],
                "outputModes": ["application/json"],
                "examples": []
            }
        ],
        "securitySchemes": { "busbar": { "type": "apiKey", "in": "header", "name": "x-api-key" } },
        "security": [ { "busbar": [] } ],
        "signatures": [ { "protected": "eyJhbGciOiJFZERTQSJ9", "signature": "SIG", "header": {} } ]
    })
}

/// THE LOAD-BEARING ONE. The fingerprint is taken over the RECEIVED document, so a change to a
/// member busbar does not model is still drift. If the fingerprint were taken over the busbar-owned
/// projection, an upstream could rewrite everything busbar cannot read and stay `approved`, which is
/// exactly the silent rug-pull the pin exists to catch.
#[test]
fn the_fingerprint_covers_members_busbar_does_not_model() {
    let plain = a_card();
    let mut extended = a_card();
    extended.as_object_mut().expect("object").insert(
        "vendorExtension".to_string(),
        json!({ "mode": "aggressive" }),
    );

    // busbar reads the two cards IDENTICALLY: the extension is not a member it models.
    assert_eq!(
        parse(&plain).expect("parse"),
        parse(&extended).expect("parse")
    );
    // And the fingerprint still tells them apart.
    assert_ne!(
        fingerprint(&plain).expect("fingerprint"),
        fingerprint(&extended).expect("fingerprint")
    );
}

/// The other half of the same property: a card that was merely RE-SERIALIZED is the same card. A
/// proxy that re-indents a document must not manufacture a drift alarm, or the alarm gets ignored.
#[test]
fn two_spellings_of_one_card_have_one_fingerprint() {
    let terse = a_card();
    let pretty: Value =
        serde_json::from_str(&serde_json::to_string_pretty(&terse).expect("pretty"))
            .expect("parse");
    assert_eq!(
        fingerprint(&terse).expect("fingerprint"),
        fingerprint(&pretty).expect("fingerprint")
    );
}

/// A signature cannot cover itself, so the JWS payload excludes `signatures`. The pinned fingerprint
/// INCLUDES them, because which key signed a card is part of what the operator approved.
#[test]
fn the_signing_payload_excludes_signatures_and_the_fingerprint_does_not() {
    let card = a_card();
    let payload = signing_payload(&card).expect("payload");
    assert!(
        !payload.contains("signatures"),
        "the signed payload must not contain the member carrying the signature: {payload}"
    );

    let mut resigned = a_card();
    resigned.as_object_mut().expect("object").insert(
        "signatures".to_string(),
        json!([{ "protected": "eyJhbGciOiJFZERTQSJ9", "signature": "DIFFERENT", "header": {} }]),
    );
    // The same document under a different signature signs the same payload...
    assert_eq!(payload, signing_payload(&resigned).expect("payload"));
    // ...and is a different pinned card.
    assert_ne!(
        fingerprint(&card).expect("fingerprint"),
        fingerprint(&resigned).expect("fingerprint")
    );
}

/// REMOVING a member is not EMPTYING it. A signer that hashed `"signatures":[]` and a verifier that
/// hashed an absent member would disagree on every signed card ever issued, and the disagreement
/// would present as "this vendor's signatures never verify" rather than as a bug here.
#[test]
fn removing_signatures_is_not_the_same_as_emptying_them() {
    let mut emptied = a_card();
    emptied
        .as_object_mut()
        .expect("object")
        .insert("signatures".to_string(), json!([]));
    let mut absent = a_card();
    absent.as_object_mut().expect("object").remove("signatures");

    assert_eq!(
        signing_payload(&emptied).expect("payload"),
        signing_payload(&absent).expect("payload"),
        "both must sign the SAME payload: the member is removed, not emptied"
    );
    assert!(!signing_payload(&emptied)
        .expect("payload")
        .contains("signatures"));
}

/// Digests are PER SKILL, keyed by the id an operator approves by, so editing one skill moves one
/// row of the changes queue. A single set-wide hash would make one edited description look identical
/// to a wholesale replacement, and the only available response would be to re-approve everything.
#[test]
fn one_edited_skill_moves_exactly_one_digest() {
    let before = skill_digests(&a_card()).expect("digests");
    assert_eq!(
        before.keys().collect::<Vec<_>>(),
        vec!["plan", "summarize"],
        "keyed by the skill id, not by array position"
    );

    let mut edited = a_card();
    edited["skills"][0]["description"] = json!("decompose a goal, aggressively");
    let after = skill_digests(&edited).expect("digests");

    assert_ne!(before["plan"], after["plan"]);
    assert_eq!(before["summarize"], after["summarize"]);
}

/// Approval is keyed by the skill ID, so re-ordering the array moves nothing. Keying by array index
/// would silently transfer every approval to a different skill on a cosmetic reorder.
#[test]
fn reordering_the_skills_array_moves_no_digest() {
    let mut reordered = a_card();
    let skills = reordered["skills"].as_array_mut().expect("array");
    skills.reverse();
    assert_eq!(
        skill_digests(&a_card()).expect("digests"),
        skill_digests(&reordered).expect("digests")
    );
    // The whole-card fingerprint DOES move, because array order is data and the canonical form
    // preserves it. That is the honest behaviour: a reorder is a new card, so it is a pin change the
    // operator settles with `approve-pin`, and no skill approval is disturbed by it.
    assert_ne!(
        fingerprint(&a_card()).expect("fingerprint"),
        fingerprint(&reordered).expect("fingerprint")
    );
}

/// A skill with no `id` has nothing for an operator to approve it BY, and falling back to its array
/// position would mean a reorder silently moved every approval. So it is refused.
#[test]
fn a_skill_with_no_id_is_refused_rather_than_indexed() {
    let mut card = a_card();
    card["skills"][0]
        .as_object_mut()
        .expect("object")
        .remove("id");
    assert_eq!(skill_digests(&card), Err(CardError::SkillWithoutId));

    let mut empty_id = a_card();
    empty_id["skills"][0]["id"] = json!("");
    assert_eq!(skill_digests(&empty_id), Err(CardError::SkillWithoutId));
}

/// Two skills under one id make "approved `plan` at this digest" ambiguous. Silently keeping the
/// last one would let an upstream shadow an approved skill with a second declaration of it.
#[test]
fn a_duplicate_skill_id_is_refused_rather_than_resolved() {
    let mut card = a_card();
    let dup = card["skills"][0].clone();
    card["skills"].as_array_mut().expect("array").push(dup);
    assert_eq!(
        skill_digests(&card),
        Err(CardError::DuplicateSkillId("plan".to_string()))
    );
}

/// The reader maps the protocol's camelCase wire names onto busbar's own field names, and an absent
/// member is a default rather than a parse failure: an upstream on an older revision must stay
/// readable.
#[test]
fn the_reader_mirrors_the_wire_names_and_tolerates_absent_members() {
    let card = parse(&a_card()).expect("parse");
    assert_eq!(card.protocol_version, "0.3.0");
    assert!(card.capabilities.streaming);
    assert!(!card.capabilities.push_notifications);
    assert_eq!(card.supported_interfaces[0].protocol_binding, "JSONRPC");
    assert_eq!(card.default_input_modes, vec!["application/json"]);
    assert_eq!(card.skills[0].tags, vec!["planning"]);
    assert_eq!(card.signatures.len(), 1);
    assert!(card.security_schemes.contains_key("busbar"));

    let sparse = parse(&json!({ "name": "minimal" })).expect("parse");
    assert_eq!(sparse.name, "minimal");
    assert!(sparse.skills.is_empty());
    assert_eq!(sparse.protocol_version, "");
}

/// An unknown member does not make a card unreadable. An upstream that adds one on a newer protocol
/// revision must not become un-fetchable, because the fingerprint is what notices the change and it
/// cannot notice anything about a document that was refused.
#[test]
fn an_unknown_member_does_not_make_a_card_unreadable() {
    let mut card = a_card();
    card.as_object_mut()
        .expect("object")
        .insert("somethingNewInV4".to_string(), json!({ "a": [1, 2, 3] }));
    assert_eq!(parse(&card).expect("parse").name, "planner");
}

/// Not every JSON document is a card, and the refusal is at the boundary rather than a default-filled
/// empty card that would then fingerprint and approve like a real one.
#[test]
fn a_document_that_is_not_an_object_is_not_a_card() {
    for v in [json!([]), json!("card"), json!(null), json!(7)] {
        assert_eq!(fingerprint(&v), Err(CardError::NotAnObject));
        assert_eq!(parse(&v), Err(CardError::NotAnObject));
        assert_eq!(signing_payload(&v), Err(CardError::NotAnObject));
    }
}

/// Both discovery paths are named, because the path moved between protocol revisions and an upstream
/// pinned to an older `protocolVersion` is still serving the old one.
#[test]
fn both_discovery_paths_are_named() {
    assert_eq!(WELL_KNOWN_CARD_PATH, "/.well-known/agent-card.json");
    assert_eq!(WELL_KNOWN_CARD_PATH_LEGACY, "/.well-known/agent.json");
    assert_ne!(WELL_KNOWN_CARD_PATH, WELL_KNOWN_CARD_PATH_LEGACY);
}

/// The observation handed to the plane-neutral machine carries the identity the caller established
/// and the capability set read off the card, and nothing else. Everything the machine then does with
/// it is the machine's.
#[test]
fn the_observation_carries_the_identity_and_the_capability_set() {
    let card = a_card();
    let pin = CardPin::JwsIssuerKey {
        issuer_key: "KEY-1".to_string(),
        card_fingerprint: fingerprint(&card).expect("fingerprint"),
    };
    let obs = observation(&card, Some(pin.clone())).expect("observation");
    assert_eq!(obs.pin, Some(pin));
    assert_eq!(obs.capabilities, skill_digests(&card).expect("digests"));
}
