// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The cards busbar serves: the engine's `serve_tests`, over the moved builders.

use super::*;

const PUBLIC: &str = "https://gw.example";

fn backend_card() -> Value {
    json!({
        "name": "Planner",
        "description": "plans",
        "url": "https://internal.corp.example/a2a",
        "supportedInterfaces": [
            { "url": "https://internal.corp.example/a2a", "protocolBinding": "JSONRPC" },
            { "url": "internal.corp.example:443", "protocolBinding": "GRPC" },
        ],
        "securitySchemes": { "vendor": { "apiKeySecurityScheme": {} } },
        "security": [{ "vendor": [] }],
        "signatures": [{ "protected": "x", "signature": "y" }],
        "x-vendor": { "mirrors": ["https://internal.corp.example/eu"] },
    })
}

#[test]
fn a_fronted_card_names_busbar_and_nothing_of_the_backend() {
    let served = rewrite_card(
        &backend_card(),
        "https://internal.corp.example/a2a",
        PUBLIC,
        "planner",
    )
    .expect("served");
    let endpoint = "https://gw.example/a2a/agents/planner";
    assert_eq!(served["url"], endpoint);
    assert_eq!(
        served["supportedInterfaces"],
        json!([{ "url": endpoint, "protocolBinding": "JSONRPC" }]),
        "the gRPC entry is dropped: busbar does not serve it at one agent's address"
    );
    assert_eq!(served["x-vendor"]["mirrors"][0], endpoint);
    assert!(served.get("signatures").is_none());
    assert!(served.get("security").is_none());
    assert_eq!(
        served["securityRequirements"],
        json!([{ "schemes": { INBOUND_SCHEME_NAME: { "list": [] } } }])
    );
    assert_eq!(
        served["capabilities"],
        json!({}),
        "the agent states no capability, so busbar promises none on its behalf"
    );
    assert!(!served.to_string().contains("internal.corp.example"));
}

/// A FRONTED AGENT'S CAPABILITIES ARE THE AGENT'S: busbar relays the agent's extended card read to
/// the agent itself, so the served card carries `extendedAgentCard` (and every other capability)
/// exactly as the agent's card states it, `false` included, and never promises one the agent's
/// card does not.
/// RED before the fix: `rewrite_card` set `extendedAgentCard: true` on every fronted card.
#[test]
fn a_fronted_card_carries_the_agents_own_capabilities_and_promises_no_extended_card() {
    let backend = "https://internal.corp.example/a2a";
    for stated in [
        json!({ "extendedAgentCard": false, "streaming": true, "pushNotifications": false }),
        json!({ "streaming": false }),
        json!({ "extendedAgentCard": true }),
    ] {
        let mut card = backend_card();
        card["capabilities"] = stated.clone();
        let served = rewrite_card(&card, backend, PUBLIC, "planner").expect("served");
        assert_eq!(served["capabilities"], stated, "the agent's own: {stated}");
    }
    let mut card = backend_card();
    card["capabilities"] = json!({ "extendedAgentCard": false });
    let served = rewrite_card(&card, backend, PUBLIC, "planner").expect("served");
    assert_eq!(
        served["capabilities"]["extendedAgentCard"], false,
        "an agent with no extended card is not served as having one"
    );
}

#[test]
fn a_card_still_naming_its_backend_or_offering_nothing_servable_is_refused() {
    let mut leaky = backend_card();
    leaky["description"] = json!("ask internal.corp.example directly");
    assert!(matches!(
        rewrite_card(&leaky, "https://internal.corp.example/a2a", PUBLIC, "planner"),
        Err(ServeError::BackendLeak(at)) if at == vec!["$.description".to_string()]
    ));
    let mut grpc_only = backend_card();
    grpc_only["supportedInterfaces"] =
        json!([{ "url": "internal.corp.example:443", "protocolBinding": "GRPC" }]);
    assert_eq!(
        rewrite_card(
            &grpc_only,
            "https://internal.corp.example/a2a",
            PUBLIC,
            "planner"
        ),
        Err(ServeError::NoServableBinding)
    );
}

#[test]
fn busbars_own_card_publishes_every_binding_at_every_version_newest_first() {
    let card = self_card_document(PUBLIC, Vec::new()).expect("a card");
    let interfaces = card["supportedInterfaces"].as_array().expect("interfaces");
    let got: Vec<(String, String, String)> = interfaces
        .iter()
        .map(|i| {
            (
                i["url"].as_str().unwrap().to_string(),
                i["protocolBinding"].as_str().unwrap().to_string(),
                i["protocolVersion"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    let http = "https://gw.example/a2a".to_string();
    let grpc = "gw.example:443".to_string();
    let row = |u: &String, b: &str, v: &str| (u.clone(), b.to_string(), v.to_string());
    assert_eq!(
        got,
        vec![
            row(&http, "JSONRPC", "1.0"),
            row(&http, "JSONRPC", "0.3"),
            row(&http, "HTTP+JSON", "1.0"),
            row(&http, "HTTP+JSON", "0.3"),
            row(&grpc, "GRPC", "1.0"),
            row(&grpc, "GRPC", "0.3"),
        ]
    );
    assert_eq!(card["skills"], json!([]));
    assert_eq!(card["version"], crate::agent_door::VERSION);
    assert!(self_card_document("not a url", Vec::new()).is_none());
}

struct Fixed(Option<&'static str>);

impl Signer for Fixed {
    fn kid(&mut self) -> Option<String> {
        self.0.map(str::to_string)
    }
    fn sign(&mut self, input: &[u8]) -> Option<Vec<u8>> {
        Some(input.len().to_be_bytes().to_vec())
    }
}

#[test]
fn a_card_is_signed_under_busbars_kid_or_served_unsigned_with_no_key() {
    let card = self_card_document(PUBLIC, Vec::new()).expect("a card");
    let signed = sign_card(&card, &mut Fixed(Some("busbar-a2a-card-k1"))).expect("signed");
    let sig = &signed["signatures"][0];
    let protected = sig["protected"].as_str().expect("protected");
    assert_eq!(
        protected,
        b64url(br#"{"alg":"EdDSA","kid":"busbar-a2a-card-k1"}"#)
    );
    assert!(!protected.contains('='));
    assert_eq!(sign_card(&card, &mut Fixed(None)).expect("unsigned"), card);
}

#[test]
fn the_extended_card_names_each_entitled_agent_once_and_omits_a_leaking_one() {
    let clean = json!({ "name": "Planner", "description": "plans" });
    let leaky = json!({ "name": "Leaky", "description": "see leak.example" });
    let card = extended_card_document(
        PUBLIC,
        &[
            EntitledAgent {
                agent_id: "planner",
                backend_url: "https://internal.corp.example/a2a",
                card: Some(&clean),
            },
            EntitledAgent {
                agent_id: "leaky",
                backend_url: "https://leak.example/a2a",
                card: Some(&leaky),
            },
        ],
    )
    .expect("a card");
    let skills = card["skills"].as_array().expect("skills");
    assert_eq!(skills.len(), 1);
    assert_eq!(skills[0]["id"], "planner");
    assert_eq!(skills[0]["name"], "Planner");
}

/// The card tells a caller where to send its request. If that string and the path the door claims
/// were derived separately, the card would advertise an endpoint that 404s and nothing would notice,
/// because each half is individually correct: so the advertised endpoint IS a claimed route.
/// Ported from busbar-a2a a2a/tests/ingress_tests.rs::the_served_endpoint_and_the_mounted_path_are_one_derivation.
#[test]
fn the_served_endpoint_and_the_mounted_path_are_one_derivation() {
    let endpoint = agent_endpoint(PUBLIC, "planner").expect("an endpoint");
    assert_eq!(endpoint, "https://gw.example/a2a/agents/planner");
    let served = rewrite_card(
        &backend_card(),
        "https://internal.corp.example/a2a",
        PUBLIC,
        "planner",
    )
    .expect("served");
    assert_eq!(
        served["url"], endpoint,
        "the card advertises the one derivation"
    );

    let served_path = endpoint
        .strip_prefix(PUBLIC)
        .expect("the endpoint is under the public base");
    for verb in ["GET", "POST"] {
        let claimed = crate::door_statement::ROUTES
            .iter()
            .find(|r| r.verb == verb && r.target.contains("{agent_id}"))
            .unwrap_or_else(|| panic!("a claimed {verb} route names an agent"));
        assert_eq!(
            claimed.target.replace("{agent_id}", "planner"),
            served_path,
            "the card advertises an endpoint the door does not claim ({verb})"
        );
    }
}
// ---- Ported from the engine's `serve_tests` and `sign_tests` (A2A-FLIP, F25). ----

const BACKEND: &str = "https://internal.corp.example/a2a";

/// A backend card rich enough for the ported cells: a vendor scheme, a vendor requirement, a vendor
/// signature, a provider URL that is provenance, and an unmodelled member carrying the endpoint.
fn rich_backend_card() -> Value {
    json!({
        "protocolVersion": "0.3.0",
        "name": "planner",
        "description": "decomposes goals",
        "version": "2.1.0",
        "provider": { "organization": "Acme", "url": "https://acme.example" },
        "url": "https://internal.corp.example/a2a",
        "supportedInterfaces": [
            { "url": "https://internal.corp.example/a2a/jsonrpc", "protocolBinding": "JSONRPC" },
            { "url": "internal.corp.example:443", "protocolBinding": "GRPC" },
        ],
        "capabilities": { "streaming": true },
        "skills": [{ "id": "plan", "name": "Plan", "description": "decompose a goal" }],
        "securitySchemes": {
            "corpMtls": { "type": "mutualTLS" },
            "vendorKey": { "type": "apiKey", "in": "header", "name": "x-internal-key" },
        },
        "security": [{ "corpMtls": [] }],
        "signatures": [{ "protected": "eyJhbGciOiJFZERTQSJ9", "signature": "AAAA" }],
        "x-vendor-extensions": { "mirrors": ["https://internal.corp.example/eu"] },
    })
}

/// Every string in a document, at every depth, object keys included.
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

/// Ported from busbar-a2a a2a/tests/serve_tests.rs::a_binding_the_plane_serves_only_at_its_own_mount_is_not_published_at_an_agents_address.
#[test]
fn a_binding_the_plane_serves_only_at_its_own_mount_is_not_published_at_an_agents_address() {
    let mut card = rich_backend_card();
    card["supportedInterfaces"] = json!([
        { "url": "https://internal.corp.example/a2a/jsonrpc", "protocolBinding": "JSONRPC" },
        { "url": "https://internal.corp.example/a2a/rest", "protocolBinding": "HTTP+JSON" },
    ]);
    let served = rewrite_card(&card, BACKEND, PUBLIC, "planner").expect("rewrite");
    let bindings: Vec<&str> = served["supportedInterfaces"]
        .as_array()
        .expect("interfaces")
        .iter()
        .filter_map(|i| i["protocolBinding"].as_str())
        .collect();
    assert_eq!(
        bindings,
        vec!["JSONRPC"],
        "the fronted-agent address answers the JSON-RPC envelope alone: {served}"
    );
}

/// Ported from busbar-a2a a2a/tests/serve_tests.rs::an_interface_entry_that_names_no_binding_survives.
#[test]
fn an_interface_entry_that_names_no_binding_survives() {
    let mut card = rich_backend_card();
    card["supportedInterfaces"] = json!([{ "url": "https://internal.corp.example/a2a" }]);
    let served = rewrite_card(&card, BACKEND, PUBLIC, "planner").expect("rewrite");
    assert_eq!(
        served["supportedInterfaces"]
            .as_array()
            .expect("interfaces")
            .len(),
        1
    );
    assert_eq!(
        served["supportedInterfaces"][0]["url"],
        "https://gw.example/a2a/agents/planner"
    );
}

/// Ported from busbar-a2a a2a/tests/serve_tests.rs::the_backends_security_schemes_are_replaced_by_busbars_own_inbound_credential.
#[test]
fn the_backends_security_schemes_are_replaced_by_busbars_own_inbound_credential() {
    let served = rewrite_card(&rich_backend_card(), BACKEND, PUBLIC, "planner").expect("rewrite");
    let schemes = served["securitySchemes"].as_object().expect("schemes");
    assert_eq!(
        schemes.keys().collect::<Vec<_>>(),
        vec![INBOUND_SCHEME_NAME],
        "exactly one scheme, and it is busbar's"
    );
    assert!(schemes.get("corpMtls").is_none());
    assert!(schemes.get("vendorKey").is_none());
    let description = schemes[INBOUND_SCHEME_NAME]["httpAuthSecurityScheme"]["description"].clone();
    assert_eq!(
        schemes[INBOUND_SCHEME_NAME],
        json!({ "httpAuthSecurityScheme": { "scheme": "Bearer", "description": description } }),
        "the served scheme selects exactly one proto SecurityScheme variant"
    );
    assert!(description
        .as_str()
        .expect("description")
        .contains(CREDENTIAL_KIND_A2A_INBOUND));
    assert_eq!(
        served["securityRequirements"],
        json!([{ "schemes": { INBOUND_SCHEME_NAME: { "list": [] } } }])
    );
    assert!(served.get("security").is_none(), "{served}");
    let mut strings = Vec::new();
    every_string(&served, &mut strings);
    assert!(
        !strings.iter().any(|s| s == "x-internal-key"),
        "the backend's auth posture leaked through the scheme bodies"
    );
}

/// Ported from busbar-a2a a2a/tests/serve_tests.rs::everything_that_is_not_an_endpoint_or_a_credential_survives_verbatim.
#[test]
fn everything_that_is_not_an_endpoint_or_a_credential_survives_verbatim() {
    let served = rewrite_card(&rich_backend_card(), BACKEND, PUBLIC, "planner").expect("rewrite");
    assert_eq!(served["name"], "planner");
    assert_eq!(served["description"], "decomposes goals");
    assert_eq!(served["version"], "2.1.0");
    assert_eq!(served["protocolVersion"], "0.3.0");
    assert_eq!(served["capabilities"]["streaming"], true);
    assert_eq!(served["skills"][0]["id"], "plan");
    assert_eq!(
        served["provider"]["url"], "https://acme.example",
        "the provider URL is provenance, not an endpoint"
    );
    assert!(served["x-vendor-extensions"].is_object());
}

/// Ported from busbar-a2a a2a/tests/serve_tests.rs::a_misconfigured_public_url_refuses_rather_than_serving_the_backends_own_endpoints.
#[test]
fn a_misconfigured_public_url_refuses_rather_than_serving_the_backends_own_endpoints() {
    let err = rewrite_card(&rich_backend_card(), BACKEND, "not a url", "planner")
        .expect_err("a bad public URL must refuse");
    match err {
        ServeError::Unbuildable(why) => assert!(why.contains("not a url"), "{why}"),
        other => panic!("expected Unbuildable, got {other:?}"),
    }
}

/// Ported from busbar-a2a a2a/tests/serve_tests.rs::a_document_that_is_not_an_object_is_not_a_card.
#[test]
fn a_document_that_is_not_an_object_is_not_a_card() {
    for v in [json!([]), json!("card"), json!(null), json!(7)] {
        assert!(
            matches!(
                rewrite_card(&v, BACKEND, PUBLIC, "planner"),
                Err(ServeError::Unbuildable(_))
            ),
            "{v}"
        );
    }
}

/// Ported from busbar-a2a a2a/tests/serve_tests.rs::a_string_that_merely_mentions_a_different_host_is_left_alone.
#[test]
fn a_string_that_merely_mentions_a_different_host_is_left_alone() {
    let served = rewrite_card(&rich_backend_card(), BACKEND, PUBLIC, "planner").expect("rewrite");
    assert_eq!(served["provider"]["url"], "https://acme.example");
    assert_eq!(served["description"], "decomposes goals");
}

/// Ported from busbar-a2a a2a/tests/serve_tests.rs::busbars_own_endpoint_is_not_a_leak_when_it_shares_a_host_with_the_backend.
#[test]
fn busbars_own_endpoint_is_not_a_leak_when_it_shares_a_host_with_the_backend() {
    let backend = "http://127.0.0.1:9110";
    let public = "http://127.0.0.1:9100";
    let card = json!({
        "name": "planner",
        "description": "decomposes goals",
        "url": format!("{backend}/a2a"),
        "supportedInterfaces": [{ "url": format!("{backend}/a2a"), "protocolBinding": "JSONRPC" }],
    });
    let served = rewrite_card(&card, backend, public, "planner")
        .expect("a co-located backend must still be servable");
    assert_eq!(served["url"], format!("{public}/a2a/agents/planner"));

    let mut leaky = card.clone();
    leaky["description"] = json!("the real one is at 127.0.0.1:9110/internal");
    assert_eq!(
        rewrite_card(&leaky, backend, public, "planner"),
        Err(ServeError::BackendLeak(vec!["$.description".to_string()]))
    );
}

/// Ported from busbar-a2a a2a/tests/serve_tests.rs::every_published_capability_is_one_the_normative_proto_defines.
#[test]
fn every_published_capability_is_one_the_normative_proto_defines() {
    let proto_members = [
        "streaming",
        "pushNotifications",
        "extensions",
        "extendedAgentCard",
    ];
    let card = rich_backend_card();
    let public = self_card_document(PUBLIC, Vec::new()).expect("the public card builds");
    let extended = extended_card_document(
        PUBLIC,
        &[EntitledAgent {
            agent_id: "planner",
            backend_url: BACKEND,
            card: Some(&card),
        }],
    )
    .expect("it builds");
    let fronted = rewrite_card(&card, BACKEND, PUBLIC, "planner").expect("rewrite");
    for (name, doc) in [
        ("public", &public),
        ("extended", &extended),
        ("fronted", &fronted),
    ] {
        for member in doc["capabilities"]
            .as_object()
            .expect("capabilities")
            .keys()
        {
            assert!(
                proto_members.contains(&member.as_str()),
                "the {name} card publishes `capabilities.{member}`, which `AgentCapabilities` \
                 does not define"
            );
        }
    }
}

/// Ported from busbar-a2a a2a/tests/serve_tests.rs::the_extended_card_differs_from_the_public_card_in_skills_and_in_nothing_else.
#[test]
fn the_extended_card_differs_from_the_public_card_in_skills_and_in_nothing_else() {
    let card = rich_backend_card();
    let public = self_card_document(PUBLIC, Vec::new()).expect("the public card builds");
    let extended = extended_card_document(
        PUBLIC,
        &[EntitledAgent {
            agent_id: "planner",
            backend_url: BACKEND,
            card: Some(&card),
        }],
    )
    .expect("it builds");
    let (mut a, mut b) = (
        public.as_object().expect("object").clone(),
        extended.as_object().expect("object").clone(),
    );
    let public_skills = a.remove("skills").expect("a skills member");
    let extended_skills = b.remove("skills").expect("a skills member");
    assert_eq!(
        a, b,
        "the two cards disagree about something other than skills"
    );
    assert_eq!(public_skills, json!([]), "the public card names an agent");
    assert_ne!(
        extended_skills,
        json!([]),
        "the extended card names nothing"
    );
}

/// Ported from busbar-a2a a2a/tests/serve_tests.rs::the_extended_card_publishes_one_skill_per_agent_and_never_a_duplicate_id.
#[test]
fn the_extended_card_publishes_one_skill_per_agent_and_never_a_duplicate_id() {
    // Two agents whose backends declare THE SAME skill id, which is the collision.
    let first = rich_backend_card();
    let mut second = rich_backend_card();
    second["name"] = json!("scheduler");
    let extended = extended_card_document(
        PUBLIC,
        &[
            EntitledAgent {
                agent_id: "planner",
                backend_url: BACKEND,
                card: Some(&first),
            },
            EntitledAgent {
                agent_id: "scheduler",
                backend_url: "https://internal-scheduler.corp.example",
                card: Some(&second),
            },
        ],
    )
    .expect("it builds");
    let ids: Vec<&str> = extended["skills"]
        .as_array()
        .expect("an array")
        .iter()
        .map(|s| s["id"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(ids, vec!["planner", "scheduler"], "{extended}");
    let digests = crate::a2a::card::skill_digests(&extended).expect("busbar's own card is legal");
    assert_eq!(digests.len(), 2, "{digests:?}");
}

// ---- signing: the door builds the signing input; the host holds the key ----

/// A deterministic stand-in for the host's card-signing service: 64 bytes that are a pure function
/// of the exact signing input, so a verifier that recomputes it proves WHICH BYTES the door handed
/// the host to sign (the door holds no key and no ed25519; the host's `sign` service is the key).
fn stand_in_signature(input: &[u8]) -> Vec<u8> {
    use std::hash::{Hash, Hasher};
    (0u8..8)
        .flat_map(|round| {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            round.hash(&mut h);
            input.hash(&mut h);
            h.finish().to_be_bytes()
        })
        .collect()
}

/// Records every signing input it is asked to sign.
struct Recording {
    seen: Vec<Vec<u8>>,
}

impl Signer for Recording {
    fn kid(&mut self) -> Option<String> {
        Some("busbar-a2a-card-k1".to_string())
    }
    fn sign(&mut self, input: &[u8]) -> Option<Vec<u8>> {
        self.seen.push(input.to_vec());
        Some(stand_in_signature(input))
    }
}

/// The served card for the signing cells: rewritten, then signed, as the door serves it.
fn served_and_signed(signer: &mut Recording) -> Value {
    let rewritten =
        rewrite_card(&rich_backend_card(), BACKEND, PUBLIC, "planner").expect("rewrite");
    sign_card(&rewritten, signer).expect("signed")
}

/// Why a served card's signature does not verify (the stand-in for the host's published key).
#[derive(Debug, PartialEq)]
enum NotVerified {
    NoSignature,
    Mismatch,
}

/// Verify `doc` the way the inbound verifier reads a card: signing input is
/// `protected.b64url(signing_payload(doc))`, checked against the signature.
fn verify_served(doc: &Value) -> Result<String, NotVerified> {
    use base64::Engine as _;
    let sig = doc["signatures"].get(0).ok_or(NotVerified::NoSignature)?;
    let protected = sig["protected"].as_str().ok_or(NotVerified::NoSignature)?;
    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(sig["signature"].as_str().ok_or(NotVerified::NoSignature)?)
        .map_err(|_| NotVerified::Mismatch)?;
    let payload = crate::a2a::card::signing_payload(doc).map_err(|_| NotVerified::Mismatch)?;
    let input = format!("{protected}.{}", b64url(payload.as_bytes()));
    if stand_in_signature(input.as_bytes()) == signature {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(protected)
            .map_err(|_| NotVerified::Mismatch)?;
        let header: Value = serde_json::from_slice(&header).map_err(|_| NotVerified::Mismatch)?;
        Ok(header["kid"].as_str().unwrap_or_default().to_string())
    } else {
        Err(NotVerified::Mismatch)
    }
}

/// Ported from busbar-a2a a2a/tests/sign_tests.rs::a_served_card_carries_a_signature_that_verifies_against_busbars_published_key.
#[test]
fn a_served_card_carries_a_signature_that_verifies_against_busbars_published_key() {
    let mut signer = Recording { seen: Vec::new() };
    let served = served_and_signed(&mut signer);
    assert_eq!(
        verify_served(&served),
        Ok("busbar-a2a-card-k1".to_string()),
        "the served card verifies, and under the kid busbar publishes (the card kid prefix, not the token kid)"
    );
}

/// Ported from busbar-a2a a2a/tests/sign_tests.rs::the_served_card_carries_busbars_signature_and_only_busbars.
#[test]
fn the_served_card_carries_busbars_signature_and_only_busbars() {
    let mut signer = Recording { seen: Vec::new() };
    let served = served_and_signed(&mut signer);
    let signatures = served["signatures"]
        .as_array()
        .expect("the served card is signed");
    assert_eq!(
        signatures.len(),
        1,
        "the vendor's signature cannot verify over a rewritten document: {signatures:?}"
    );
    assert_ne!(
        signatures[0]["signature"].as_str(),
        Some("AAAA"),
        "the vendor's signature value must be gone, not merely reordered"
    );
    assert_ne!(
        signatures[0]["protected"].as_str(),
        Some("eyJhbGciOiJFZERTQSJ9")
    );
}

/// Ported from busbar-a2a a2a/tests/sign_tests.rs::tampering_with_one_byte_of_the_served_document_breaks_verification.
#[test]
fn tampering_with_one_byte_of_the_served_document_breaks_verification() {
    use base64::Engine as _;
    let mut signer = Recording { seen: Vec::new() };
    let served = served_and_signed(&mut signer);
    verify_served(&served).expect("the untampered card verifies: the control");

    let mut tampered = served.clone();
    let description = tampered["description"]
        .as_str()
        .expect("a description")
        .to_string();
    tampered["description"] = Value::String(description.replacen('d', "D", 1));
    assert_ne!(tampered, served, "the tamper must change something");
    assert_eq!(verify_served(&tampered), Err(NotVerified::Mismatch));

    // A member busbar never models is still under the signature.
    let mut extended = served.clone();
    extended
        .as_object_mut()
        .expect("object")
        .insert("x-vendor-extension".to_string(), json!({ "region": "eu" }));
    assert_eq!(verify_served(&extended), Err(NotVerified::Mismatch));

    // And a flipped byte of the signature itself is a forgery.
    let mut resigned = served.clone();
    let mut raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(
            resigned["signatures"][0]["signature"]
                .as_str()
                .expect("sig"),
        )
        .expect("base64url");
    raw[0] ^= 0x01;
    resigned["signatures"][0]["signature"] =
        Value::String(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&raw));
    assert_eq!(verify_served(&resigned), Err(NotVerified::Mismatch));
}

/// Ported from busbar-a2a a2a/tests/sign_tests.rs::the_signature_covers_exactly_the_inbound_paths_signing_payload.
#[test]
fn the_signature_covers_exactly_the_inbound_paths_signing_payload() {
    let mut signer = Recording { seen: Vec::new() };
    let served = served_and_signed(&mut signer);
    assert_eq!(signer.seen.len(), 1, "one card, one signing request");
    let protected = served["signatures"][0]["protected"]
        .as_str()
        .expect("protected");
    let payload = crate::a2a::card::signing_payload(&served).expect("the inbound path's payload");
    assert_eq!(
        String::from_utf8(signer.seen[0].clone()).expect("utf-8"),
        format!("{protected}.{}", b64url(payload.as_bytes())),
        "the host was handed EXACTLY the bytes the inbound verifier reconstructs"
    );
}

/// Ported from busbar-a2a a2a/tests/sign_tests.rs::the_signature_is_taken_over_the_document_that_is_actually_served.
#[test]
fn the_signature_is_taken_over_the_document_that_is_actually_served() {
    let mut signer = Recording { seen: Vec::new() };
    let served = served_and_signed(&mut signer);
    let flattened = serde_json::to_string(&served).expect("serialize");
    assert!(
        !flattened.contains("internal.corp.example"),
        "the backend must not appear in the served card at all: {flattened}"
    );
    assert_eq!(served["url"], format!("{PUBLIC}/a2a/agents/planner"));
    assert!(served["securitySchemes"].get(INBOUND_SCHEME_NAME).is_some());
    verify_served(&served).expect("and THAT document is the one the signature covers");
}

/// Ported from busbar-a2a a2a/tests/sign_tests.rs::the_card_signing_domain_derives_the_exact_pinned_bytes.
/// The door's half: the domain and the kid prefix are the pinned literals (a change rotates every
/// deployment's card key and every caller's pin). The host derives the key from the domain; its
/// seed vectors are the kernel's own to hold.
#[test]
fn the_card_signing_domain_derives_the_exact_pinned_bytes() {
    assert_eq!(
        crate::door_statement::CARD_SIGNING_DOMAIN,
        "a2a/agent-card-signing/v1"
    );
    assert_eq!(crate::door_statement::CARD_KID_PREFIX, "busbar-a2a-card-");
}
