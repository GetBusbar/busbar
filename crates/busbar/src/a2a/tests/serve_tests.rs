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
    // The binding of a SURVIVING entry is untouched: rewriting WHERE a caller goes is not rewriting
    // WHAT is spoken there. The backend's GRPC entry is not among the survivors — see
    // `a_binding_busbar_cannot_serve_is_not_published_at_busbars_own_address` — because the address
    // in a served entry is BUSBAR'S, and busbar answers JSON-RPC there and nothing else.
    assert_eq!(
        served["supportedInterfaces"][0]["protocolBinding"],
        "JSONRPC"
    );
}

#[test]
fn a_binding_busbar_cannot_serve_is_not_published_at_busbars_own_address() {
    // THE DEFECT THIS TEST WAS WRITTEN FOR. The rewrite replaced every `supportedInterfaces[].url`
    // with busbar's endpoint and passed `protocolBinding` through untouched, so a backend offering
    // `{"url": ..., "protocolBinding": "GRPC"}` made busbar publish a gRPC interface AT BUSBAR'S OWN
    // ADDRESS — a protocol busbar does not implement and its router does not answer.
    //
    // It is reachable rather than theoretical: `supportedInterfaces` is an ORDERED list a client
    // selects from, so a conformant client picking the gRPC entry is sent to busbar to speak
    // something nothing there serves. That is the same shape as a card advertising an address its
    // own router does not serve, one member down: the binding rather than the path.
    let served = rewrite_card(&backend_card(), BACKEND, PUBLIC, "planner", None).expect("rewrite");
    let bindings: Vec<&str> = served["supportedInterfaces"]
        .as_array()
        .expect("interfaces")
        .iter()
        .filter_map(|i| i["protocolBinding"].as_str())
        .collect();

    assert!(
        !bindings.contains(&"GRPC"),
        "busbar published a gRPC interface at its own address, which it does not serve: {}",
        serde_json::to_string_pretty(&served).expect("pretty")
    );
    assert_eq!(
        bindings,
        vec!["JSONRPC"],
        "exactly the bindings busbar serves, and no others"
    );
}

/// THE SAME DEFECT, ONE ADDRESS DOWN, AND IT RE-ENTERED THE DAY THE PLANE ARMED A SECOND BINDING.
///
/// The filter above asks "can busbar serve this binding", and while the plane spoke one dialect that
/// was the same question as "does busbar answer this binding AT THE ADDRESS THIS ENTRY NOW POINTS
/// AT". It stopped being the same question when `a2a::rest` mounted the HTTP+JSON paths: those hang
/// off the PLANE'S mount (`/a2a/message:send`, `/a2a/tasks/{id}`, …), and a fronted agent's card is
/// rewritten to point at `/a2a/agents/{id}`, where `POST` answers a JSON-RPC envelope and no request
/// line names an operation at all.
///
/// So a backend offering HTTP+JSON would have had that entry KEPT — the plane can serve it — and its
/// url rewritten to an address that does not, publishing exactly the "interface at busbar's address
/// for a protocol nothing there answers" the test above exists to prevent.
#[test]
fn a_binding_the_plane_serves_only_at_its_own_mount_is_not_published_at_an_agents_address() {
    let mut card = backend_card();
    card.as_object_mut().expect("object").insert(
        "supportedInterfaces".to_string(),
        json!([
            { "url": format!("{BACKEND}/a2a/jsonrpc"), "protocolBinding": "JSONRPC" },
            { "url": format!("{BACKEND}/a2a/rest"), "protocolBinding": "HTTP+JSON" }
        ]),
    );
    let served = rewrite_card(&card, BACKEND, PUBLIC, "planner", None).expect("rewrite");
    let bindings: Vec<&str> = served["supportedInterfaces"]
        .as_array()
        .expect("interfaces")
        .iter()
        .filter_map(|i| i["protocolBinding"].as_str())
        .collect();

    assert_eq!(
        bindings,
        vec!["JSONRPC"],
        "the fronted-agent address answers the JSON-RPC envelope and nothing else, so that is the \
         only binding its card may advertise: {}",
        serde_json::to_string_pretty(&served).expect("pretty")
    );
}

/// AND BUSBAR'S OWN CARD STILL ADVERTISES BOTH, because its address is the one that serves both.
/// Pinned beside the test above so the fix for that one cannot be "stop publishing HTTP+JSON" —
/// the two addresses answer different sets, and both statements have to stay true.
#[test]
fn the_planes_own_card_advertises_every_binding_the_plane_mounts() {
    let card = self_card(PUBLIC, None).expect("self card");
    let bindings: Vec<&str> = card["supportedInterfaces"]
        .as_array()
        .expect("interfaces")
        .iter()
        .filter_map(|i| i["protocolBinding"].as_str())
        .collect();
    assert_eq!(bindings, vec!["JSONRPC", "HTTP+JSON"]);
    // ORDERED, and the order is the plane's. `supportedInterfaces` is a preference list, and the
    // first entry is also what `Ingress::shaping_wire_format` names for a refusal that reached no
    // handler — one order, read in two places.
    assert_eq!(
        bindings.len(),
        crate::plane::Plane::A2a.wire_format_names().len(),
        "every wire format the plane declares is published, and nothing else"
    );
}

#[test]
fn every_published_binding_is_one_the_a2a_plane_declares_a_wire_format_for() {
    // THE RULE, not today's answer. The published set is derived from `Plane::A2a`'s wire formats,
    // so when the HTTP+JSON and gRPC bindings land on the plane this starts publishing them without
    // anyone editing `rewrite_card` — and until they do, it cannot publish them by accident.
    let served = rewrite_card(&backend_card(), BACKEND, PUBLIC, "planner", None).expect("rewrite");
    let declared = crate::plane::Plane::A2a.wire_format_names();
    for iface in served["supportedInterfaces"]
        .as_array()
        .expect("interfaces")
        .iter()
    {
        let binding = iface["protocolBinding"].as_str().expect("binding");
        assert!(
            declared.iter().any(|f| f.eq_ignore_ascii_case(binding)),
            "the served card publishes `{binding}`, which the A2A plane does not declare a wire \
             format for: {declared:?}"
        );
    }
    // And busbar's OWN card is held to the same rule, from the same source.
    let self_card = self_card(PUBLIC, None).expect("self card");
    for iface in self_card["supportedInterfaces"]
        .as_array()
        .expect("interfaces")
        .iter()
    {
        let binding = iface["protocolBinding"].as_str().expect("binding");
        assert!(
            declared.iter().any(|f| f.eq_ignore_ascii_case(binding)),
            "busbar's own card publishes `{binding}`, which the A2A plane does not declare"
        );
    }
}

#[test]
fn a_card_offering_nothing_busbar_can_serve_is_refused_rather_than_served_interface_less() {
    // A2A makes `supportedInterfaces` the list a client selects its transport from, and an entry is
    // the only thing that names one. Stripping the last entry would leave a card that says busbar
    // fronts this agent and gives a client no way to reach it — so the refusal is explicit rather
    // than an empty array nobody decided to publish.
    let mut card = backend_card();
    let obj = card.as_object_mut().expect("object");
    obj.insert(
        "supportedInterfaces".to_string(),
        json!([{ "url": format!("{BACKEND}/a2a/grpc"), "protocolBinding": "GRPC" }]),
    );
    let err = rewrite_card(&card, BACKEND, PUBLIC, "planner", None)
        .expect_err("nothing servable must refuse");
    match err {
        ServeError::NoServableBinding {
            ref agent_id,
            ref offered,
            ref served,
        } => {
            assert_eq!(agent_id, "planner");
            assert_eq!(offered, &vec!["GRPC".to_string()]);
            assert!(
                served.iter().any(|b| b.eq_ignore_ascii_case("jsonrpc")),
                "the refusal must say what busbar DOES serve: {served:?}"
            );
        }
        other => panic!("got {other:?}"),
    }
    assert!(err.to_string().contains("GRPC"), "{err}");
}

#[test]
fn an_interface_entry_that_names_no_binding_survives() {
    // A binding busbar cannot serve is a CLAIM busbar would be making falsely. An entry that names
    // no binding makes no such claim — the specification's default reading is JSON-RPC, which is
    // exactly what busbar answers at the rewritten address — so it is kept rather than silently
    // dropped, which would take an interface away from a caller for no stated reason.
    let mut card = backend_card();
    card.as_object_mut().expect("object").insert(
        "supportedInterfaces".to_string(),
        json!([{ "url": format!("{BACKEND}/a2a") }]),
    );
    let served = rewrite_card(&card, BACKEND, PUBLIC, "planner", None).expect("rewrite");
    assert_eq!(
        served["supportedInterfaces"]
            .as_array()
            .expect("interfaces")
            .len(),
        1
    );
    assert_eq!(
        served["supportedInterfaces"][0]["url"],
        "https://gateway.acme.example/a2a/agents/planner"
    );
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

#[test]
fn busbars_own_endpoint_is_not_a_leak_when_it_shares_a_host_with_the_backend() {
    // THE CASE THE LEAK GUARD USED TO REFUSE OUTRIGHT, and it is not exotic: a sidecar, a
    // single-node development deployment and a hermetic conformance rig all put busbar and the
    // agent it fronts on ONE host. The rewrite then replaces every backend URL with busbar's own —
    // which, sharing that host, still CONTAINS the backend authority — and the post-rewrite scan
    // reported busbar's own published endpoint as a leak of the backend. The result was a hard
    // refusal to serve any card at all, so a busbar co-located with its agent could not front it.
    //
    // The string the rewrite itself just wrote is by definition not a way around busbar; it IS
    // busbar. Nothing else is softened: the free-text case below still refuses.
    let backend = "http://127.0.0.1:9110";
    let public = "http://127.0.0.1:9100";
    let mut card = backend_card();
    let obj = card.as_object_mut().expect("object");
    obj.insert("url".to_string(), json!(format!("{backend}/a2a")));
    obj.insert(
        "supportedInterfaces".to_string(),
        json!([{ "url": format!("{backend}/a2a"), "protocolBinding": "JSONRPC" }]),
    );
    obj.remove("x-vendor-extensions");
    obj.insert("description".to_string(), json!("decomposes goals"));

    let served = rewrite_card(&card, backend, public, "planner", None)
        .expect("a co-located backend must still be servable");
    assert_eq!(served["url"], format!("{public}/a2a/agents/planner"));

    // AND THE GUARD IS STILL LIVE ON THE SAME HOST. A free-text mention of the backend's authority
    // is not the endpoint the rewrite wrote, and must still refuse.
    let mut leaky = card.clone();
    leaky.as_object_mut().expect("object").insert(
        "description".to_string(),
        json!("the real one is at 127.0.0.1:9110/internal"),
    );
    let err = rewrite_card(&leaky, backend, public, "planner", None)
        .expect_err("a free-text mention must still refuse");
    assert!(
        matches!(err, ServeError::BackendLeak { ref at, .. } if at == &vec!["$.description".to_string()]),
        "got {err:?}"
    );
}
