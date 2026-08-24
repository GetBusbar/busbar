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
    // EACH SURVIVOR POINTS AT THE ADDRESS ITS OWN BINDING IS ANSWERED ON, which is not one string
    // any more. The HTTP bindings take busbar's agent endpoint; gRPC takes busbar's AUTHORITY,
    // because a gRPC channel is opened against `host:port` and a URL is not dialable. Writing the
    // endpoint into every entry — which is what this loop used to assert — became, the moment the
    // plane started serving gRPC, exactly the defect the binding filter beside it exists to prevent.
    let grpc_endpoint = "gateway.acme.example:443";
    for iface in served["supportedInterfaces"]
        .as_array()
        .expect("interfaces")
        .iter()
    {
        let expected = if iface["protocolBinding"] == "GRPC" {
            grpc_endpoint
        } else {
            endpoint
        };
        assert_eq!(iface["url"], expected, "for {iface}");
    }
    // The binding of a SURVIVING entry is untouched: rewriting WHERE a caller goes is not rewriting
    // WHAT is spoken there.
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
    // ADDRESS — a protocol busbar did not implement and its router did not answer.
    //
    // IT IS THE SAME TEST, AND THE EXAMPLE HAD TO MOVE. busbar now really does serve gRPC, so `GRPC`
    // is no longer an unservable binding and asserting it is absent would assert the opposite of
    // what shipped. The property is unchanged — a served card advertises exactly the bindings this
    // deployment answers, no more — so it is now driven by a binding the plane does not speak, and
    // the surviving set is compared against `servable_bindings()` rather than a literal, which is
    // what makes this a rule instead of a snapshot of today.
    let mut card = backend_card();
    card.as_object_mut().expect("object").insert(
        "supportedInterfaces".to_string(),
        json!([
            { "url": format!("{BACKEND}/a2a/jsonrpc"), "protocolBinding": "JSONRPC" },
            { "url": format!("{BACKEND}/a2a/ws"), "protocolBinding": "WEBSOCKET" }
        ]),
    );
    let served = rewrite_card(&card, BACKEND, PUBLIC, "planner", None).expect("rewrite");
    let bindings: Vec<&str> = served["supportedInterfaces"]
        .as_array()
        .expect("interfaces")
        .iter()
        .filter_map(|i| i["protocolBinding"].as_str())
        .collect();

    assert!(
        !bindings.contains(&"WEBSOCKET"),
        "busbar published a binding at its own address which it does not serve: {}",
        serde_json::to_string_pretty(&served).expect("pretty")
    );
    for binding in &bindings {
        assert!(
            servable_bindings()
                .iter()
                .any(|b| b.eq_ignore_ascii_case(binding)),
            "`{binding}` survived and busbar serves {:?}",
            servable_bindings()
        );
    }
}

/// AND THE OTHER HALF, which is the half that arming this binding is FOR: busbar publishes gRPC on
/// its OWN card, at its own gRPC address, because busbar really answers there. Nobody edited a list
/// to make this true — `servable_bindings()` reads `Plane::A2a`'s wire formats, so adding the
/// binding to the plane is the single act that flipped it.
///
/// ON THE PLANE'S CARD AND NOT ON A FRONTED AGENT'S, and that pairing is the whole of what the merge
/// of the two binding branches decided. gRPC is served at `/lf.a2a.v1.A2AService` FOR THE PLANE,
/// where the agent is resolved from the caller's catalogue; there is no gRPC address that names one
/// fronted agent. So the binding is published where it is answered — see
/// `agent_address_bindings` — and the second half of this test is the statement that it is not
/// published anywhere else.
#[test]
fn a_binding_busbar_does_serve_is_published_at_the_address_it_is_served_on() {
    let card = self_card(PUBLIC, None).expect("self card");
    let grpc = card["supportedInterfaces"]
        .as_array()
        .expect("interfaces")
        .iter()
        .find(|i| i["protocolBinding"] == "GRPC")
        .expect("the plane speaks gRPC, so its own card must advertise it");
    assert_eq!(
        grpc["url"], "gateway.acme.example:443",
        "a gRPC interface must publish an authority a channel can be opened against, never a URL"
    );

    // AND NOT AT A FRONTED AGENT'S ADDRESS, where a gRPC call would resolve the agent from the
    // caller's catalogue rather than from the path the card was fetched from.
    let served = rewrite_card(&backend_card(), BACKEND, PUBLIC, "planner", None).expect("rewrite");
    let bindings: Vec<&str> = served["supportedInterfaces"]
        .as_array()
        .expect("interfaces")
        .iter()
        .filter_map(|i| i["protocolBinding"].as_str())
        .collect();
    assert!(
        !bindings.contains(&"GRPC"),
        "the backend offered GRPC and busbar republished it at an agent address it does not answer \
         gRPC on: {}",
        serde_json::to_string_pretty(&served).expect("pretty")
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

/// AND BUSBAR'S OWN CARD STILL ADVERTISES ALL OF THEM, because its address is the one that serves
/// them. Pinned beside the test above so the fix for that one cannot be "stop publishing HTTP+JSON"
/// — the two addresses answer different sets, and both statements have to stay true.
///
/// DISTINCT bindings, because the published list is a CROSS PRODUCT: one entry per binding per
/// protocol version this endpoint admits (`published_interfaces`, SPEC 3.6.2). What this pins is the
/// binding axis of that product — every wire format the plane declares, in the plane's order, and
/// nothing else.
#[test]
fn the_planes_own_card_advertises_every_binding_the_plane_mounts() {
    let card = self_card(PUBLIC, None).expect("self card");
    let mut bindings: Vec<&str> = Vec::new();
    for iface in card["supportedInterfaces"].as_array().expect("interfaces") {
        let b = iface["protocolBinding"].as_str().expect("a binding");
        if !bindings.contains(&b) {
            bindings.push(b);
        }
    }
    assert_eq!(bindings, vec!["JSONRPC", "HTTP+JSON", "GRPC"]);
    // ORDERED, and the order is the plane's. `supportedInterfaces` is a preference list, and the
    // first entry is also what `Ingress::shaping_wire_format` names for a refusal that reached no
    // handler — one order, read in two places.
    assert_eq!(
        bindings.len(),
        crate::plane::wire_format_names("a2a").len(),
        "every wire format the plane declares is published, and nothing else"
    );
    // AND EVERY ENTRY IS ADDRESSED THE WAY ITS OWN BINDING IS DIALED. gRPC publishes the AUTHORITY
    // — a channel is opened against `host:port` — and the HTTP bindings publish the plane's mount.
    for iface in card["supportedInterfaces"].as_array().expect("interfaces") {
        let want = if iface["protocolBinding"] == "GRPC" {
            grpc_endpoint(PUBLIC).expect("authority")
        } else {
            canonical_uri(PUBLIC).expect("mount")
        };
        assert_eq!(iface["url"], want, "for {iface}");
    }
}

#[test]
fn every_published_binding_is_one_the_a2a_plane_declares_a_wire_format_for() {
    // THE RULE, not today's answer. The published set is derived from `Plane::A2a`'s wire formats,
    // so when the HTTP+JSON and gRPC bindings land on the plane this starts publishing them without
    // anyone editing `rewrite_card` — and until they do, it cannot publish them by accident.
    let served = rewrite_card(&backend_card(), BACKEND, PUBLIC, "planner", None).expect("rewrite");
    let declared = crate::plane::wire_format_names("a2a");
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
        json!([{ "url": format!("{BACKEND}/a2a/ws"), "protocolBinding": "WEBSOCKET" }]),
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
            assert_eq!(offered, &vec!["WEBSOCKET".to_string()]);
            assert!(
                served.iter().any(|b| b.eq_ignore_ascii_case("jsonrpc")),
                "the refusal must say what busbar DOES serve: {served:?}"
            );
        }
        other => panic!("got {other:?}"),
    }
    assert!(err.to_string().contains("WEBSOCKET"), "{err}");
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

    // PROTO `SecurityScheme` is a oneof, so the mechanism IS the variant key. The OpenAPI spelling
    // this replaced (`{"type": "http", …}`) sets no variant, and a client parsing the card into the
    // protobuf message cannot classify it — which is a 401 nobody can act on, not a cosmetic gap.
    assert_eq!(
        schemes[INBOUND_SCHEME_NAME],
        json!({
            "httpAuthSecurityScheme": {
                "scheme": "Bearer",
                "description": schemes[INBOUND_SCHEME_NAME]["httpAuthSecurityScheme"]["description"],
            }
        }),
        "the served scheme must select exactly one PROTO SecurityScheme variant"
    );
    assert_eq!(
        served["securityRequirements"],
        json!([{ "schemes": { INBOUND_SCHEME_NAME: { "list": [] } } }])
    );
    // The backend's requirement member is removed under the OTHER spelling too. Left behind, it
    // would ride through the unmodelled-member passthrough and publish the backend's auth posture
    // beside busbar's.
    assert!(
        served.get("security").is_none(),
        "the backend's `security` survived beside busbar's `securityRequirements`: {served}"
    );
    assert!(
        schemes[INBOUND_SCHEME_NAME]["httpAuthSecurityScheme"]["description"]
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

/// A FRONTED AGENT'S CARD CLAIMS THE EXTENDED-CARD CAPABILITY, because the VERB at that address is
/// busbar's. `GetExtendedAgentCard` is answered by busbar itself before the catalogue is consulted,
/// on every inbound path — so a backend that (correctly, about its own endpoint) declared nothing
/// used to leave the served card DENYING a capability its address actually serves. SPEC 3.3.4 cuts
/// both ways: a card saying `false`-or-absent obliges the endpoint to answer
/// `UnsupportedOperationError`, and an endpoint that serves the card obliges the declaration. The
/// declaration follows the verb, exactly as the auth posture already does.
#[test]
fn a_fronted_agents_card_claims_the_extended_card_capability_busbar_serves() {
    // The backend declares only what is true about ITSELF: streaming, and no extended card.
    let served = rewrite_card(&backend_card(), BACKEND, PUBLIC, "planner", None).expect("rewrite");
    assert_eq!(
        served.pointer("/capabilities/extendedAgentCard"),
        Some(&json!(true)),
        "busbar answers GetExtendedAgentCard at this address, so the card it serves there must \
         say so: {served}"
    );
    // The backend's own true claims still ride through: the override is one member, not a rewrite
    // of the backend's capability set.
    assert_eq!(
        served.pointer("/capabilities/streaming"),
        Some(&json!(true)),
        "the backend's own declared capabilities survive: {served}"
    );

    // And a backend card with NO capabilities member at all still gains the claim.
    let mut bare = backend_card();
    bare.as_object_mut().expect("object").remove("capabilities");
    let served = rewrite_card(&bare, BACKEND, PUBLIC, "planner", None).expect("rewrite");
    assert_eq!(
        served.pointer("/capabilities/extendedAgentCard"),
        Some(&json!(true)),
        "a capability-less backend card still serves busbar's verb: {served}"
    );
}

/// EVERY `capabilities` MEMBER BUSBAR PUBLISHES IS ONE THE NORMATIVE PROTO DEFINES.
///
/// SPEC 1.4 makes `a2a.proto` the normative definition of every structure on the wire, and its
/// `AgentCapabilities` has exactly four fields: `streaming`, `push_notifications`, `extensions`
/// and `extended_agent_card`. The 1.0 revision REMOVED `state_transition_history`, and the
/// specification's own strict schema (`a2a.json`, the artifact the TCK's `CARD-EXT-001` validates
/// the extended card against) refuses a card that still carries it — a member a ProtoJSON reader
/// cannot even parse is a claim no conformant client can read. busbar kept publishing it, and that
/// single member was the last thing keeping `CARD-EXT-001` red.
///
/// Asserted on BOTH documents, because SPEC 3.1.11 tells a client to replace one with the other:
/// a member that vanished on authentication would be the same class of silent claim change the
/// one-builder test above exists to prevent.
#[test]
fn every_published_capability_is_one_the_normative_proto_defines() {
    let proto_members = [
        "streaming",
        "pushNotifications",
        "extensions",
        "extendedAgentCard",
    ];
    let card = backend_card();
    let public = self_card(PUBLIC, None).expect("the public card builds");
    let extended =
        extended_card(PUBLIC, &[entitled("planner", BACKEND, &card)], None).expect("it builds");
    for (name, doc) in [("public", &public), ("extended", &extended)] {
        let caps = doc["capabilities"]
            .as_object()
            .expect("a capabilities object");
        for member in caps.keys() {
            assert!(
                proto_members.contains(&member.as_str()),
                "the {name} card publishes `capabilities.{member}`, which the normative \
                 `a2a.proto` `AgentCapabilities` does not define — no ProtoJSON reader can parse \
                 it and the specification's strict schema refuses the card for it"
            );
        }
    }
}

// ══ THE EXTENDED AGENT CARD ══════════════════════════════════════════════════════════════════════

fn entitled<'a>(agent_id: &'a str, backend_url: &'a str, card: &'a Value) -> EntitledAgent<'a> {
    EntitledAgent {
        agent_id,
        backend_url,
        card: Some(card),
    }
}

/// THE PUBLIC CARD AND THE EXTENDED CARD DIFFER IN EXACTLY ONE MEMBER, and that is the whole design.
///
/// SPEC 3.1.11 tells a client to REPLACE its cached public card with the extended one for the
/// duration of its session, so any other difference between the two is a claim about this endpoint
/// that silently changes when a client authenticates — a different interface list, a different
/// scheme to present, a different capability set. One builder is what makes that impossible; this
/// is what makes the one builder observable.
#[test]
fn the_extended_card_differs_from_the_public_card_in_skills_and_in_nothing_else() {
    let card = backend_card();
    let public = self_card(PUBLIC, None).expect("the public card builds");
    let extended =
        extended_card(PUBLIC, &[entitled("planner", BACKEND, &card)], None).expect("it builds");

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

/// ONE SKILL PER AGENT, IDENTIFIED BY BUSBAR'S OWN AGENT ID — and the reason is mechanical.
///
/// The obvious implementation unions the backends' own `skills[]`. Skill ids are upstream-authored
/// and namespaced by nothing, so two fronted vendors both declaring `plan` produce one id twice —
/// and `card::skill_digests` REFUSES a card with a duplicate skill id, so a peer applying to busbar
/// the rule busbar applies to everyone else would reject busbar's own card outright. This asserts
/// the property that makes that impossible: the published ids are the AGENT ids, which are unique
/// by construction, and they are the ids the caller addresses.
#[test]
fn the_extended_card_publishes_one_skill_per_agent_and_never_a_duplicate_id() {
    // Two agents whose backends declare THE SAME skill id, which is the collision.
    let mut second = backend_card();
    second
        .as_object_mut()
        .expect("object")
        .insert("name".to_string(), json!("scheduler"));
    let first = backend_card();
    let extended = extended_card(
        PUBLIC,
        &[
            entitled("planner", BACKEND, &first),
            entitled(
                "scheduler",
                "https://internal-scheduler.corp.example",
                &second,
            ),
        ],
        None,
    )
    .expect("it builds");

    let ids: Vec<&str> = extended["skills"]
        .as_array()
        .expect("an array")
        .iter()
        .map(|s| s["id"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(ids, vec!["planner", "scheduler"], "{extended}");
    // AND THE PUBLISHED DOCUMENT PASSES BUSBAR'S OWN CARD RULES, which is the claim that matters:
    // whatever busbar demands of a card it verifies, its own must satisfy.
    let digests = super::super::card::skill_digests(&extended).expect("busbar's own card is legal");
    assert_eq!(digests.len(), 2, "{digests:?}");
}

/// AN AGENT THIS CALLER IS NOT ENTITLED TO IS NOT IN THE DOCUMENT AT ALL.
///
/// This is the data-exposure half, and for a gateway it is the whole design question: the naive
/// extended card is a merge of everything busbar fronts, which hands every authenticated caller the
/// full inventory — every agent id, every vendor, every capability — including the agents it may not
/// invoke. Asserted over the SERIALISED document rather than over `skills`, because the hazard is a
/// member nobody thought to check.
#[test]
fn an_agent_outside_this_callers_catalogue_appears_nowhere_in_the_extended_card() {
    let card = backend_card();
    let extended =
        extended_card(PUBLIC, &[entitled("planner", BACKEND, &card)], None).expect("it builds");
    let rendered = extended.to_string();
    assert!(rendered.contains("planner"), "{rendered}");
    assert!(
        !rendered.contains("scheduler"),
        "an agent this caller was not handed is named in its extended card: {rendered}"
    );
}

/// THE BACKEND AUTHORITY APPEARS NOWHERE, AT ANY DEPTH — the same property the served fronted card
/// has, re-asserted here because this is the ONE busbar document built from several vendors' text
/// at once, so `rewrite_card`'s per-card sweep cannot cover it.
///
/// And the failure is CONTAINED. One vendor whose description names its own backend must not be able
/// to deny every other agent's entry to every caller, so that agent is dropped and the rest are
/// served — which is what the second half asserts.
#[test]
fn the_backend_authority_appears_nowhere_in_the_extended_card_and_one_leak_drops_one_agent() {
    let mut leaky = backend_card();
    leaky.as_object_mut().expect("object").insert(
        "description".to_string(),
        json!("reach it directly at internal-planner.corp.example:8443/a2a"),
    );
    let clean = backend_card();
    let extended = extended_card(
        PUBLIC,
        &[
            entitled("planner", BACKEND, &leaky),
            entitled(
                "scheduler",
                "https://internal-scheduler.corp.example",
                &clean,
            ),
        ],
        None,
    )
    .expect("one careless upstream must not deny every other agent");

    let mut strings = Vec::new();
    every_string(&extended, &mut strings);
    for s in &strings {
        assert!(
            !s.to_lowercase().contains("internal-planner.corp.example"),
            "the extended card names the backend authority: {s}"
        );
    }
    let ids: Vec<&str> = extended["skills"]
        .as_array()
        .expect("an array")
        .iter()
        .map(|s| s["id"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(
        ids,
        vec!["scheduler"],
        "the leaking agent was published, or the clean one was dropped with it: {extended}"
    );
}

/// A CALLER ENTITLED TO NOTHING GETS A CARD WITH NOTHING IN IT, rather than a refusal.
///
/// "You may reach no agent here" is a true and useful answer, and it is a statement about the
/// CALLER. `ExtendedAgentCardNotConfiguredError` is a statement about the DEPLOYMENT, and the
/// ingress reserves it for the one shape that means it: a busbar fronting nothing at all.
#[test]
fn a_caller_entitled_to_no_agent_gets_an_empty_extended_card_rather_than_a_refusal() {
    let extended = extended_card(PUBLIC, &[], None).expect("an empty catalogue is still a card");
    assert_eq!(extended["skills"], json!([]), "{extended}");
    assert_eq!(extended["capabilities"]["extendedAgentCard"], json!(true));
}

// ══ THE CARD'S PROTOCOL VERSIONS ═════════════════════════════════════════════════════════════════

/// EVERY INTERFACE DECLARES A PROTOCOL VERSION, AND THE VERSIONS ARE THE ONES THE INGRESS ADMITS.
///
/// `AgentInterface.protocol_version` is REQUIRED in the 1.0 card and busbar published none, so a
/// client reading the card had to fall back to the top-level member — which said `0.3.0`: the wrong
/// spelling (SPEC 3.6: patch numbers "SHOULD NOT be used in … Agent Cards") of a version busbar was
/// no longer alone in speaking. The list is read off `ingress::SUPPORTED_A2A_VERSIONS` rather than
/// written here, so this test compares the card against the thing that actually admits requests.
#[test]
fn every_published_interface_declares_a_version_the_ingress_actually_admits() {
    let card = self_card(PUBLIC, None).expect("the card builds");
    let ifaces = card["supportedInterfaces"].as_array().expect("an array");
    assert!(!ifaces.is_empty());
    for iface in ifaces {
        let v = iface["protocolVersion"].as_str().unwrap_or_default();
        assert!(
            crate::a2a::receive::SUPPORTED_A2A_VERSIONS.contains(&v),
            "the card advertises `{v}`, which this endpoint does not admit: {iface}"
        );
        assert!(
            !v.contains("0.3.0"),
            "a card version carries a patch number, which SPEC 3.6 says it must not: {v}"
        );
    }
    // ORDERED, NEWEST FIRST. `supportedInterfaces` is an ordered list whose first entry the
    // specification makes preferred, so a client taking entry zero must be steered at the current
    // protocol rather than at the compatibility one.
    assert_eq!(ifaces[0]["protocolVersion"], "1.0", "{ifaces:?}");
    // AND EVERY VERSION THE INGRESS ADMITS IS PUBLISHED. A version admitted and not advertised is a
    // capability no client can discover.
    for want in crate::a2a::receive::SUPPORTED_A2A_VERSIONS {
        assert!(
            ifaces.iter().any(|i| i["protocolVersion"] == *want),
            "the ingress admits `{want}` and the card does not advertise it: {ifaces:?}"
        );
    }
}
