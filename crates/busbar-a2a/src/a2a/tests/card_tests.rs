// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The card reader, its discovery paths and the observation it hands the trust machine (the
//! hashes are the plane's, tested there).
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

/// The reader maps the protocol's camelCase wire names onto busbar's own field names, and an absent
/// member is a default rather than a parse failure: an upstream on an older revision must stay
/// readable.
#[test]
fn the_reader_mirrors_the_wire_names_and_tolerates_absent_members() {
    let card = parse(&a_card()).expect("parse");
    assert_eq!(card.protocol_version, "0.3.0");
    assert!(card.capabilities.is_stream);
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
        assert_eq!(parse(&v), Err(CardError::NotAnObject));
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
