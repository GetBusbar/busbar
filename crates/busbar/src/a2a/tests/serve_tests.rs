// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the served Agent Card.
//!
//! The load-bearing test is `the_backend_authority_appears_nowhere_in_the_served_card`, and it is
//! deliberately not a check of the members busbar models: it walks EVERY string at EVERY depth,
//! including members busbar has never heard of, because a rewrite that covers the modelled fields
//! and misses an upstream extension has published the way around busbar just as effectively.

use super::*;
use serde_json::json;

const BACKEND: &str = "https://internal-planner.corp.example:8443";
const PUBLIC: &str = "https://gateway.acme.example";

fn backend_card() -> Value {
    json!({
        "protocolVersion": "0.3.0",
        "name": "planner",
        "description": "decomposes goals",
        "version": "2.1.0",
        "provider": { "organization": "Acme", "url": "https://acme.example" },
        "url": format!("{BACKEND}/a2a"),
        "supportedInterfaces": [
            { "url": format!("{BACKEND}/a2a/jsonrpc"), "protocolBinding": "JSONRPC" },
            { "url": format!("{BACKEND}/a2a/grpc"), "protocolBinding": "GRPC" }
        ],
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "capabilities": { "streaming": true },
        "skills": [{ "id": "plan", "name": "Plan", "description": "decompose a goal" }],
        "securitySchemes": {
            "corpMtls": { "type": "mutualTLS" },
            "vendorKey": { "type": "apiKey", "in": "header", "name": "x-internal-key" }
        },
        "security": [{ "corpMtls": [] }],
        "signatures": [{ "protected": "eyJhbGciOiJFZERTQSJ9", "signature": "AAAA" }],
        // A member busbar does not model, carrying the backend endpoint. THIS is the one a
        // field-by-field rewrite misses.
        "x-vendor-extensions": {
            "adminConsole": format!("{BACKEND}/admin"),
            "mirrors": [format!("{BACKEND}/a2a/eu")]
        }
    })
}

/// Every string in a document, at every depth, including object KEYS.
fn every_string(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.push(s.clone()),
        Value::Array(a) => a.iter().for_each(|x| every_string(x, out)),
        Value::Object(o) => {
            for (k, x) in o {
                out.push(k.clone());
                every_string(x, out);
            }
        }
        _ => {}
    }
}

#[test]
fn the_endpoint_a_caller_sees_is_busbars_and_names_the_agent() {
    assert_eq!(
        agent_endpoint(PUBLIC, "planner").expect("endpoint"),
        "https://gateway.acme.example/a2a/agents/planner"
    );
    // A public URL with a path, query or fragment does not leak them into the endpoint.
    assert_eq!(
        agent_endpoint("https://gateway.acme.example/base?x=1#frag", "planner").expect("endpoint"),
        "https://gateway.acme.example/a2a/agents/planner"
    );
}

#[test]
fn every_endpoint_member_is_rewritten_through_busbar() {
    let served = rewrite_card(&backend_card(), BACKEND, PUBLIC, "planner", None).expect("rewrite");
    let endpoint = "https://gateway.acme.example/a2a/agents/planner";

    assert_eq!(served["url"], endpoint, "the pre-v0.3 top-level `url` too");
    for iface in served["supportedInterfaces"]
        .as_array()
        .expect("interfaces")
        .iter()
    {
        assert_eq!(iface["url"], endpoint);
    }
    // The bindings themselves are untouched: rewriting WHERE a caller goes is not rewriting WHAT
    // the agent speaks.
    assert_eq!(
        served["supportedInterfaces"][0]["protocolBinding"],
        "JSONRPC"
    );
    assert_eq!(served["supportedInterfaces"][1]["protocolBinding"], "GRPC");
}

#[test]
fn the_backend_authority_appears_nowhere_in_the_served_card() {
    // THE ASSERTION THAT MATTERS. Not "the fields I remembered are rewritten" — every string, at
    // every depth, including `x-vendor-extensions.mirrors[0]`, which no modelled field covers.
    let served = rewrite_card(&backend_card(), BACKEND, PUBLIC, "planner", None).expect("rewrite");
    let mut strings = Vec::new();
    every_string(&served, &mut strings);

    let offenders: Vec<&String> = strings
        .iter()
        .filter(|s| s.contains("internal-planner.corp.example"))
        .collect();
    assert!(
        offenders.is_empty(),
        "the served card publishes the backend endpoint, which is the way around busbar: \
         {offenders:?}\nserved card: {}",
        serde_json::to_string_pretty(&served).expect("pretty")
    );
}

#[test]
fn the_vendors_signature_is_removed_rather_than_carried_over_a_document_it_no_longer_covers() {
    // busbar rewrote the document, so the vendor's signature over it cannot verify. Publishing a
    // signature that fails is worse than publishing none: a client that checks rejects busbar's
    // card, and a client that does not check is shown a credential-shaped member meaning nothing.
    let served = rewrite_card(&backend_card(), BACKEND, PUBLIC, "planner", None).expect("rewrite");
    assert!(
        served.get("signatures").is_none(),
        "a rewritten card must not carry the signature of the document it used to be"
    );
}

#[test]
fn the_backends_security_schemes_are_replaced_by_busbars_own_inbound_credential() {
    // The backend's schemes say how to authenticate TO THE BACKEND, which no external caller ever
    // reaches. Publishing them tells a caller to present something busbar does not accept, and
    // leaks the backend's auth posture on the way.
    let served = rewrite_card(&backend_card(), BACKEND, PUBLIC, "planner", None).expect("rewrite");
    let schemes = served["securitySchemes"].as_object().expect("schemes");

    assert_eq!(
        schemes.keys().collect::<Vec<_>>(),
        vec![INBOUND_SCHEME_NAME],
        "exactly one scheme, and it is busbar's"
    );
    assert!(schemes.get("corpMtls").is_none());
    assert!(schemes.get("vendorKey").is_none());
    assert_eq!(served["security"], json!([{ INBOUND_SCHEME_NAME: [] }]));
    assert!(
        schemes[INBOUND_SCHEME_NAME]["description"]
            .as_str()
            .expect("description")
            .contains(CREDENTIAL_KIND_A2A_INBOUND),
        "the served card must name the credential KIND a caller has to present"
    );

    // And the backend's internal header name is gone with the scheme that carried it.
    let mut strings = Vec::new();
    every_string(&served, &mut strings);
    assert!(
        !strings.iter().any(|s| s == "x-internal-key"),
        "the backend's auth posture leaked through the scheme bodies"
    );
}

#[test]
fn everything_that_is_not_an_endpoint_or_a_credential_survives_verbatim() {
    // The rewrite is narrow on purpose. A card that arrives with members busbar does not model must
    // still be servable, and dropping them would make busbar's card a lossy projection of the
    // vendor's.
    let served = rewrite_card(&backend_card(), BACKEND, PUBLIC, "planner", None).expect("rewrite");
    assert_eq!(served["name"], "planner");
    assert_eq!(served["description"], "decomposes goals");
    assert_eq!(served["version"], "2.1.0");
    assert_eq!(served["protocolVersion"], "0.3.0");
    assert_eq!(served["capabilities"]["streaming"], true);
    assert_eq!(served["skills"][0]["id"], "plan");
    assert_eq!(
        served["provider"]["url"], "https://acme.example",
        "the provider URL is PROVENANCE, not an endpoint, and is left alone"
    );
    assert!(
        served["x-vendor-extensions"].is_object(),
        "an unmodelled member survives, with its endpoint-shaped values rewritten"
    );
}

#[test]
fn the_backend_card_itself_is_never_mutated() {
    // The cached card is what the fingerprint was taken over. Rewriting in place would change what
    // an operator approved.
    let original = backend_card();
    let before = serde_json::to_string(&original).expect("serialize");
    let _ = rewrite_card(&original, BACKEND, PUBLIC, "planner", None).expect("rewrite");
    assert_eq!(
        serde_json::to_string(&original).expect("serialize"),
        before,
        "the cached card must be untouched"
    );
}

#[test]
fn a_misconfigured_public_url_refuses_rather_than_serving_the_backends_own_endpoints() {
    let err = rewrite_card(&backend_card(), BACKEND, "not a url", "planner", None)
        .expect_err("a bad public URL must refuse");
    assert_eq!(err, ServeError::BadPublicUrl("not a url".to_string()));
    assert!(
        err.to_string()
            .contains("Refused rather than served un-rewritten"),
        "the refusal must say what it refused to do: {err}"
    );
}

#[test]
fn a_document_that_is_not_an_object_is_not_a_card() {
    for v in [json!([]), json!("card"), json!(null), json!(7)] {
        assert_eq!(
            rewrite_card(&v, BACKEND, PUBLIC, "planner", None).expect_err("not a card"),
            ServeError::Card(CardError::NotAnObject)
        );
    }
}

#[test]
fn an_unmodelled_member_carrying_the_backend_endpoint_is_rewritten_not_missed() {
    // THE CASE THAT CAUGHT THE FIRST IMPLEMENTATION. `x-vendor-extensions.mirrors[0]` is not a
    // member the specification defines, so a rewrite over the modelled fields published it intact.
    let served = rewrite_card(&backend_card(), BACKEND, PUBLIC, "planner", None).expect("rewrite");
    let endpoint = "https://gateway.acme.example/a2a/agents/planner";
    assert_eq!(served["x-vendor-extensions"]["adminConsole"], endpoint);
    assert_eq!(served["x-vendor-extensions"]["mirrors"][0], endpoint);
}

#[test]
fn a_backend_mention_the_sweep_cannot_rewrite_refuses_the_card_and_names_where() {
    // A bare authority in a free-text member is not a URL the sweep can replace. Serving it anyway
    // would publish the way around busbar in the one document whose purpose is to point at busbar.
    let mut card = backend_card();
    card.as_object_mut().expect("object").insert(
        "description".to_string(),
        Value::String("mirrors internal-planner.corp.example for the EU region".to_string()),
    );
    let err =
        rewrite_card(&card, BACKEND, PUBLIC, "planner", None).expect_err("a leak must refuse");
    match err {
        ServeError::BackendLeak {
            ref agent_id,
            ref host,
            ref at,
        } => {
            assert_eq!(agent_id, "planner");
            assert_eq!(host, "internal-planner.corp.example");
            assert_eq!(
                at,
                &vec!["$.description".to_string()],
                "the path must be named"
            );
        }
        other => panic!("got {other:?}"),
    }
    assert!(err.to_string().contains("$.description"), "{err}");
}

#[test]
fn a_string_that_merely_mentions_a_different_host_is_left_alone() {
    // Only URL-shaped strings whose host IS the backend's are touched. A description mentioning the
    // vendor's public site is not an endpoint, and rewriting it would make busbar's card say
    // something the vendor did not.
    let served = rewrite_card(&backend_card(), BACKEND, PUBLIC, "planner", None).expect("rewrite");
    assert_eq!(served["provider"]["url"], "https://acme.example");
    assert_eq!(served["description"], "decomposes goals");
}
