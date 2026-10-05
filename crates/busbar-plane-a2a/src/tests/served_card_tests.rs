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
    assert_eq!(served["capabilities"]["extendedAgentCard"], true);
    assert!(!served.to_string().contains("internal.corp.example"));
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
    assert_eq!(card["version"], crate::plane_door::VERSION);
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
