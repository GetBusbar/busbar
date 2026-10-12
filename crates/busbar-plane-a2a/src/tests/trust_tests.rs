// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The trust surface, plane side, against the served engine's words: the card fetch's refusals,
//! the verification per mechanism, the kernel's verdict in the admission's words, the `connect`
//! view and the cadence. The DECISION (approval, quarantine) is the
//! kernel's trust book's, tested there and end to end on the root's agent door.

use serde_json::json;

use super::*;

fn pin(mechanism: PinMechanism, key: Option<&str>) -> AgentPinCfg {
    AgentPinCfg {
        mechanism,
        key: key.map(str::to_string),
        fingerprint: None,
    }
}

fn card(description: &str) -> Value {
    json!({
        "name": "planner",
        "skills": [{"id": "plan", "name": "Plan", "description": description}],
    })
}

fn signed_root() -> AgentPinCfg {
    pin(PinMechanism::JwsIssuerKey, Some("MCowBQYDK2VwAyEA"))
}

fn seen(card: &Value) -> Sighting {
    Sighting::Seen(
        verify(&signed_root(), card, &Handshake::default(), || Ok(())).expect("verifies"),
    )
}

#[test]
fn the_discovery_urls_are_the_origin_s_two_well_known_paths_canonical_first() {
    assert_eq!(
        discovery_urls("https://agent.example/agents/planner?x=1").unwrap(),
        [
            "https://agent.example/.well-known/agent-card.json".to_string(),
            "https://agent.example/.well-known/agent.json".to_string(),
        ]
    );
    assert_eq!(
        discovery_urls("not a url").unwrap_err(),
        "agent card URL is not a URL: `not a url`"
    );
}

#[test]
fn plaintext_is_admitted_only_where_the_registration_allows_private() {
    let url = "http://127.0.0.1:9/.well-known/agent-card.json";
    assert_eq!(scheme_refusal(url, true), None);
    assert_eq!(scheme_refusal("https://a.example/x", false), None);
    assert!(scheme_refusal(url, false).unwrap().starts_with(
        "agent card URL `http://127.0.0.1:9/.well-known/agent-card.json` uses scheme `http`"
    ));
}

#[test]
fn a_card_read_refuses_what_is_not_a_card_in_the_engine_s_words() {
    let url = "https://a.example/.well-known/agent-card.json";
    assert_eq!(
        read_card(url, Err("refused".to_string())).unwrap_err(),
        format!("agent card fetch of `{url}` failed: refused")
    );
    assert_eq!(
        read_card(url, Ok((404, b"{}"))).unwrap_err(),
        format!("agent card fetch of `{url}` returned HTTP 404")
    );
    assert_eq!(
        read_card(url, Ok((200, b"[1]"))).unwrap_err(),
        format!("the document at `{url}` is not an agent card: the document is not a JSON object")
    );
    let big = vec![b' '; MAX_CARD_BYTES + 1];
    assert!(read_card(url, Ok((200, &big)))
        .unwrap_err()
        .ends_with("bytes, over the configured ceiling"));
    assert_eq!(
        read_card(url, Ok((200, b"{\"a\":1}"))).unwrap(),
        json!({"a": 1})
    );
}

#[test]
fn each_mechanism_verifies_as_the_engine_did() {
    let c = card("plans");
    let rooted = verify(&signed_root(), &c, &Handshake::default(), || Ok(())).unwrap();
    assert_eq!(
        rooted.pin.fingerprint(),
        Some(card::fingerprint(&c).unwrap().as_str())
    );
    assert_eq!(rooted.skills.len(), 1);
    assert_eq!(
        verify(&signed_root(), &c, &Handshake::default(), || Err(
            "not by the key".to_string()
        ))
        .unwrap_err(),
        "not by the key"
    );
    assert!(verify(
        &pin(PinMechanism::JwsIssuerKey, None),
        &c,
        &Handshake::default(),
        || Ok(())
    )
    .unwrap_err()
    .contains("carries no `pin.key:`"));
    assert!(verify(
        &pin(PinMechanism::CertKeyPin, Some("sha256/K=")),
        &c,
        &Handshake::default(),
        || Ok(())
    )
    .unwrap_err()
    .contains("this fetch observed none"));
    assert_eq!(
        verify(
            &pin(PinMechanism::Unpinned, None),
            &c,
            &Handshake::default(),
            || unreachable!()
        )
        .unwrap()
        .pin,
        CardPin::Unpinned
    );
    assert!(verify(
        &pin(PinMechanism::Unpinned, Some("k")),
        &c,
        &Handshake::default(),
        || Ok(())
    )
    .unwrap_err()
    .starts_with("`pin.mechanism: unpinned` carries `pin.key:`"));
}

#[test]
fn the_kernel_s_signature_verdicts_are_worded_as_the_engine_worded_them() {
    let c = json!({"signatures": [{}, {}]});
    assert_eq!(jws_refusal(svc::SIGNED_VERIFIED, "", &c), None);
    assert_eq!(
        jws_refusal(svc::SIGNED_TOO_MANY, "", &c).unwrap(),
        "the agent card carries 2 signatures, more than any legitimate card needs"
    );
    assert_eq!(
        jws_refusal(svc::SIGNED_NOT_BY_ROOT, "", &c).unwrap(),
        "the agent card is signed, but not by the pinned issuer key"
    );
    assert_eq!(
        jws_refusal(svc::SIGNED_NONE, "", &c).unwrap(),
        "the agent card carries no signature"
    );
    assert!(jws_refusal(svc::SIGNED_ALGORITHM, "none", &c)
        .unwrap()
        .starts_with("signature algorithm `none` is refused"));
}

#[test]
fn the_kernel_s_verdict_reads_as_the_admission_s_state() {
    assert_eq!(state_of(svc::DISTRUST_NONE), State::Approved);
    for pending in [
        svc::DISTRUST_UNKNOWN,
        svc::DISTRUST_UNSIGHTED,
        svc::DISTRUST_NOT_APPROVED,
        svc::DISTRUST_UNKNOWN_ITEM,
    ] {
        assert_eq!(state_of(pending), State::Pending, "{pending}");
    }
    for quarantined in [svc::DISTRUST_QUARANTINED, svc::DISTRUST_CHANGED] {
        assert_eq!(state_of(quarantined), State::Quarantined, "{quarantined}");
    }
}

/// The skills `card` presents, as `approve` holds them.
fn skills_of(card: &Value) -> BTreeMap<String, String> {
    card::skill_digests(card).expect("digestible")
}

/// A FIRST `connect` previews a card nobody approved: every skill it presents is `added` (predev
/// `busbar-kernel/src/trust/mod.rs:319`, a skill with no standing approval, read by
/// `busbar-a2a/src/a2a/verbs.rs:229` off `Approval::registered()`), corrected from this cell's
/// lane-written empty lists under the standing rule.
#[test]
fn the_connect_view_is_a_preview_of_the_card_under_the_key_s_state() {
    let s = seen(&card("plans"));
    let fp = card::fingerprint(&card("plans")).unwrap();
    assert_eq!(
        connect_view("planner", State::Pending, &s, None),
        format!(
            r#"{{"name":"planner","state":"pending","pin_mechanism":"jws_issuer_key","fingerprint":"{fp}","pin_changed":false,"added":["plan"],"changed":[],"removed":[],"observed_skills":1,"failure":null}}"#
        )
    );
    let approved = skills_of(&card("plans"));
    let preview: Value = serde_json::from_str(&connect_view(
        "planner",
        State::Approved,
        &s,
        Some(&approved),
    ))
    .unwrap();
    assert_eq!(
        preview["state"], "pending",
        "a preview never reports approved"
    );
    let approved: Value = serde_json::from_str(&registration_view(
        "planner",
        State::Approved,
        &s,
        Some(&approved),
    ))
    .unwrap();
    assert_eq!(approved["state"], "approved");
    assert_eq!(approved["fingerprint"], fp.as_str());
    let quarantined: Value =
        serde_json::from_str(&connect_view("planner", State::Quarantined, &s, None)).unwrap();
    assert_eq!(
        quarantined["pin_changed"], true,
        "the kernel quarantined a moved card"
    );
    let failed: Value = serde_json::from_str(&connect_view(
        "planner",
        State::Approved,
        &Sighting::Failed("down".to_string()),
        None,
    ))
    .unwrap();
    assert_eq!(failed["state"], "error", "a failed contact reads as error");
    assert_eq!(failed["failure"], "down");
    assert_eq!(failed["fingerprint"], Value::Null);
    assert_eq!(
        (&failed["added"], &failed["changed"], &failed["removed"]),
        (&json!([]), &json!([]), &json!([])),
        "a contact that presented no card has no drift"
    );
}

/// Ported from busbar-a2a registry_tests.rs::the_records_trust_answers_are_the_machines_answers_and_not_a_second_opinion
/// (its drift half; the serving half is the kernel's trust book).
///
/// Approved at `d1`, the view reports nothing to work; the same skill sighted at a moved digest is
/// `changed`, the rug-pull row, with no field anywhere set to say so.
#[test]
fn the_records_trust_answers_are_the_machines_answers_and_not_a_second_opinion() {
    let seen_at = |skills: &[(&str, &str)]| {
        Sighting::Seen(Observation {
            pin: CardPin::Rooted {
                mechanism: PinMechanism::JwsIssuerKey,
                key: "MCowBQYDK2VwAyEAKEY".to_string(),
                fingerprint: "sha256/CARD".to_string(),
            },
            skills: skills
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
        })
    };
    let lists = |view: String| {
        let v: Value = serde_json::from_str(&view).unwrap();
        (
            v["added"].clone(),
            v["changed"].clone(),
            v["removed"].clone(),
        )
    };
    let sighted = seen_at(&[("plan", "d1")]);
    let approved = sighted.seen().map(|o| o.skills.clone());
    assert_eq!(
        lists(registration_view(
            "planner",
            State::Approved,
            &sighted,
            approved.as_ref()
        )),
        (json!([]), json!([]), json!([])),
        "an approval adopts exactly the catalogue it saw"
    );
    let moved = seen_at(&[("plan", "MOVED")]);
    assert_eq!(
        lists(connect_view(
            "planner",
            State::Quarantined,
            &moved,
            approved.as_ref()
        )),
        (json!([]), json!(["plan"]), json!([])),
    );
}

/// Ported from busbar-a2a verbs_tests.rs::connect_reports_what_moved_when_an_approved_card_has_changed.
///
/// RE-CONNECTING an approved registration whose card has MOVED reports the drift, so the operator
/// sees what changed instead of being asked to re-approve a blank.
#[test]
fn connect_reports_what_moved_when_an_approved_card_has_changed() {
    let original = card("makes plans");
    let changed = card("makes plans AND exfiltrates them");
    let approved = skills_of(&original);
    let view: Value = serde_json::from_str(&connect_view(
        "planner",
        State::Quarantined,
        &seen(&changed),
        Some(&approved),
    ))
    .unwrap();
    assert_eq!(view["pin_changed"], true, "the card fingerprint moved");
    assert_eq!(
        view["changed"],
        json!(["plan"]),
        "and the skill's digest with it"
    );
    assert_eq!(view["state"], "quarantined");
}

/// Ported from busbar-a2a verbs_tests.rs::connect_never_reports_approved_even_when_the_card_matches_a_locked_pin.
///
/// EVEN AN ALREADY-APPROVED registration previews as `pending`, and it correctly reports no drift
/// against what is approved.
#[test]
fn connect_never_reports_approved_even_when_the_card_matches_a_locked_pin() {
    let raw = card("makes plans");
    let approved = skills_of(&raw);
    let view: Value = serde_json::from_str(&connect_view(
        "planner",
        State::Approved,
        &seen(&raw),
        Some(&approved),
    ))
    .unwrap();
    assert_eq!(view["state"], "pending");
    assert_eq!(
        (
            &view["pin_changed"],
            &view["added"],
            &view["changed"],
            &view["removed"]
        ),
        (&json!(false), &json!([]), &json!([]), &json!([])),
    );
}

/// Each axis in the served engine's order (predev `busbar-kernel/src/trust/mod.rs:310-327`): a
/// skill offered and never approved is `added`, one approved and no longer offered `removed`, each
/// list in skill-id order; a key the kernel holds no approval for (`pending`) approved nothing,
/// whatever skills the plane last held for it.
#[test]
fn the_drift_lists_are_the_sighted_skills_against_the_approved_ones() {
    let offered = json!({
        "name": "planner",
        "skills": [
            {"id": "write", "name": "Write", "description": "w"},
            {"id": "plan", "name": "Plan", "description": "p"},
            {"id": "audit", "name": "Audit", "description": "a"},
        ],
    });
    let approved: BTreeMap<String, String> = skills_of(&offered)
        .into_iter()
        .filter(|(id, _)| id == "plan")
        .chain([
            ("scout".to_string(), "sha256/S".to_string()),
            ("index".to_string(), "sha256/I".to_string()),
        ])
        .collect();
    let view: Value = serde_json::from_str(&connect_view(
        "planner",
        State::Quarantined,
        &seen(&offered),
        Some(&approved),
    ))
    .unwrap();
    assert_eq!(view["added"], json!(["audit", "write"]));
    assert_eq!(view["changed"], json!([]));
    assert_eq!(view["removed"], json!(["index", "scout"]));
    let pending: Value = serde_json::from_str(&connect_view(
        "planner",
        State::Pending,
        &seen(&offered),
        Some(&approved),
    ))
    .unwrap();
    assert_eq!(pending["added"], json!(["audit", "plan", "write"]));
    assert_eq!(pending["removed"], json!([]));
}

#[test]
fn an_unpinned_registration_presents_no_fingerprint_to_sight() {
    let c = card("plans");
    let unpinned = Sighting::Seen(
        verify(
            &pin(PinMechanism::Unpinned, None),
            &c,
            &Handshake::default(),
            || Ok(()),
        )
        .unwrap(),
    );
    let view: Value =
        serde_json::from_str(&connect_view("a", State::Pending, &unpinned, None)).unwrap();
    assert_eq!(view["state"], "pending");
    assert_eq!(view["fingerprint"], Value::Null);
    assert_eq!(view["pin_mechanism"], "unpinned");
}

#[test]
fn agreement_refuses_every_arm_but_the_named_fingerprint() {
    let s = seen(&card("plans"));
    let fp = card::fingerprint(&card("plans")).unwrap();
    assert_eq!(agrees(&s, &fp), Ok(()));
    assert!(agrees(&s, "")
        .unwrap_err()
        .starts_with("`fingerprint` must name"));
    assert!(agrees(&s, "sha256:other")
        .unwrap_err()
        .contains("The card moved between the preview and the approval"));
    assert!(agrees(&Sighting::Failed("down".to_string()), &fp)
        .unwrap_err()
        .ends_with("nothing to approve: down"));
}

#[test]
fn the_approve_body_is_read_as_the_engine_s_extractor_read_it() {
    let json = Some("application/json");
    assert_eq!(
        approve_body(json, br#"{"fingerprint":"sha256:a"}"#),
        Ok("sha256:a".to_string())
    );
    assert_eq!(
        approve_body(
            Some("application/merge+json; charset=utf-8"),
            br#"{"fingerprint":"f"}"#
        ),
        Ok("f".to_string())
    );
    let prefix =
        "the approve body must be `{\"fingerprint\": \"…\"}` naming the fingerprint `connect` reported: ";
    assert_eq!(
        approve_body(None, b"{}").unwrap_err(),
        format!("{prefix}Expected request with `Content-Type: application/json`")
    );
    assert_eq!(
        approve_body(json, b"{").unwrap_err(),
        format!("{prefix}Failed to parse the request body as JSON: EOF while parsing an object at line 1 column 1")
    );
    assert_eq!(
        approve_body(json, b"{}").unwrap_err(),
        format!("{prefix}Failed to deserialize the JSON body into the target type: missing field `fingerprint` at line 1 column 2")
    );
    assert_eq!(
        approve_body(json, br#"{"fingerprint":5}"#).unwrap_err(),
        format!("{prefix}Failed to deserialize the JSON body into the target type: fingerprint: invalid type: integer `5`, expected a string at line 1 column 16")
    );
    assert!(approve_body(json, br#"{"x":1}"#)
        .unwrap_err()
        .contains("unknown field `x`, expected `fingerprint`"));
    assert!(approve_body(json, br#"{"fingerprint":"a"} x"#)
        .unwrap_err()
        .contains("Failed to parse the request body as JSON: trailing characters"));
}

fn def_of(pin: AgentPinCfg, cadence: serde_json::Value) -> AgentDefCfg {
    let mut def = json!({"url": "https://a.example/x", "pin": pin});
    if let (Some(d), Some(c)) = (def.as_object_mut(), cadence.as_object()) {
        d.extend(c.clone());
    }
    serde_json::from_value(def).unwrap()
}

#[test]
fn a_unit_whose_agent_is_not_serving_is_refused_in_the_engine_s_words() {
    let addressed = not_serving(Some("planner"), State::Pending, UNTRUSTED_STATUS);
    assert_eq!(addressed.status, 403, "the kernel's trust refusal");
    assert_eq!(
        serde_json::to_value(addressed.envelope()).unwrap()["error"]["message"],
        "fronted agent `planner` is not serving (Pending)"
    );
    assert_eq!(addressed.envelope()["id"], Value::Null);
    assert_eq!(addressed.envelope()["error"]["code"], -32004);
    let scoped = not_serving(None, State::Quarantined, UNTRUSTED_STATUS);
    assert_eq!(scoped.status, 400);
    assert_eq!(
        scoped.envelope()["error"]["message"],
        "no agent this key may reach can serve this shape of task"
    );
}

#[test]
fn the_cadence_reads_the_registration_and_its_defaults() {
    let defaults = Cadence::of(&def_of(signed_root(), json!({})));
    assert_eq!(defaults.ttl_ms, 5_000);
    let spelled = Cadence::of(&def_of(
        signed_root(),
        json!({"reverify_ttl": "0s", "recovery_backoff": "1m"}),
    ));
    assert_eq!(spelled.ttl_ms, 0);
    let mut ledger = Ledger::default();
    assert!(defaults.due(&ledger, 1), "never looked is due");
    ledger.last_checked_ms = Some(1_000);
    assert!(!defaults.due(&ledger, 5_999));
    assert!(defaults.due(&ledger, 6_000), "a lapsed ttl is due");
    assert!(
        defaults.due(&ledger, 999),
        "a clock that went backwards is due"
    );
    assert!(spelled.due(&ledger, 1_000), "strict-live is always due");
}

#[test]
fn settling_stamps_the_look_and_records_what_it_observed() {
    let cadence = Cadence { ttl_ms: 0 };
    let mut ledger = Ledger::default();
    let drifted = seen(&card("moved"));
    assert_eq!(cadence.settle(drifted.clone(), &mut ledger, 10), drifted);
    assert_eq!(ledger.last_checked_ms, Some(10));
    let failed = Sighting::Failed("down".to_string());
    assert_eq!(
        cadence.settle(failed.clone(), &mut ledger, 2_000),
        failed,
        "a failed contact is recorded, never read as unchanged"
    );
    assert_eq!(ledger.last_checked_ms, Some(2_000));
}

#[test]
fn a_redirect_is_followed_within_the_bound_in_the_engine_s_words() {
    let at = "https://a.example/.well-known/agent-card.json";
    assert_eq!(next_hop(at, 200, None, 0), Ok(None));
    assert_eq!(
        next_hop(at, 302, Some(" /cards/planner.json "), 0),
        Ok(Some("https://a.example/cards/planner.json".to_string()))
    );
    assert_eq!(
        next_hop(at, 301, Some("https://b.example/c"), 2),
        Ok(Some("https://b.example/c".to_string()))
    );
    assert_eq!(
        next_hop(at, 302, Some("/x"), 3).unwrap_err(),
        format!("agent card fetch exceeded 3 redirect(s), still redirecting at `{at}`")
    );
    assert_eq!(
        next_hop(at, 307, None, 0).unwrap_err(),
        format!("agent card fetch got HTTP 307 from `{at}` with no usable Location header")
    );
    assert!(next_hop(at, 307, Some("   "), 0).is_err());
}

#[test]
fn the_guard_s_verdicts_are_worded_as_the_engine_worded_them() {
    use busbar_contract::abi::host::service as svc;
    let url = "https://agent.internal./.well-known/agent-card.json";
    assert_eq!(host_of(url).as_deref(), Some("agent.internal"));
    assert_eq!(host_of("https://[::1]:8443/x").as_deref(), Some("::1"));
    assert_eq!(refused_name(url, svc::DEST_ALLOWED), None);
    assert_eq!(
        refused_name(url, svc::DEST_INTERNAL).unwrap(),
        "SSRF guard refused the agent card fetch: host `agent.internal` is a loopback name; set \
         this registration's `allow_private: true` if that is deliberate"
    );
    assert_eq!(
        refused_name(url, svc::DEST_METADATA).unwrap(),
        "SSRF guard refused the agent card fetch: host `agent.internal` is a cloud-metadata name"
    );
    assert!(refused_name(url, svc::DEST_OBFUSCATED).unwrap().ends_with(
        "is an alternate IPv4 encoding a resolver still expands to an internal address"
    ));
    assert_eq!(
        refused_name(url, svc::DEST_NO_ADDRESSES).unwrap(),
        "agent card host `agent.internal` resolved to no addresses at all; there is nothing to \
         connect to and nothing to have judged"
    );
    assert_eq!(
        refused_address(url, "10.0.0.7"),
        "SSRF guard refused the agent card fetch: host `agent.internal` resolved to the internal \
         address 10.0.0.7; set this registration's `allow_private: true` if reaching it is \
         deliberate. A cloud-metadata address is refused whatever that is set to."
    );
}

/// THE JUDGEMENT'S REFUSAL IN 1.5.5's WORDS (ARCHITECT Q-DEL-A2A-GUARD-WORDS): a name that
/// resolved to a cloud-metadata or internal address names that address; a literal host names
/// itself; a failed resolution names the resolver's reason; a refusal the name alone decided is
/// the name's.
#[test]
fn a_judged_refusal_names_the_address_or_the_resolvers_reason() {
    let named = "https://card.example/.well-known/agent-card.json";
    let internal = |host: &str, addr: &str| {
        format!(
            "SSRF guard refused the agent card fetch: host `{host}` resolved to the internal \
             address {addr}; set this registration's `allow_private: true` if reaching it is \
             deliberate. A cloud-metadata address is refused whatever that is set to."
        )
    };
    assert_eq!(
        refused_judgement(named, svc::DEST_METADATA, Some("169.254.169.254")),
        internal("card.example", "169.254.169.254")
    );
    assert_eq!(
        refused_judgement(named, svc::DEST_INTERNAL, Some("10.1.2.3")),
        internal("card.example", "10.1.2.3")
    );
    assert_eq!(
        refused_judgement("https://10.0.0.7/x", svc::DEST_INTERNAL, None),
        internal("10.0.0.7", "10.0.0.7")
    );
    assert_eq!(
        refused_judgement(named, svc::DEST_UNRESOLVABLE, Some("no such host")),
        "agent card host `card.example` did not resolve: no such host"
    );
    assert_eq!(
        refused_judgement("https://localhost/x", svc::DEST_INTERNAL, None),
        "SSRF guard refused the agent card fetch: host `localhost` is a loopback name; set this \
         registration's `allow_private: true` if that is deliberate"
    );
    assert_eq!(
        refused_judgement(named, svc::DEST_METADATA, None),
        "SSRF guard refused the agent card fetch: host `card.example` is a cloud-metadata name"
    );
}

#[test]
fn an_address_literal_is_read_as_one_and_a_name_is_not() {
    assert_eq!(
        literal_url("127.0.0.1").as_deref(),
        Some("https://127.0.0.1/")
    );
    assert_eq!(literal_url("::1").as_deref(), Some("https://[::1]/"));
    assert_eq!(literal_url("agent.example"), None);
}

/// THE CONNECTION'S FAILURE IN predev's WORDS: the engine's HTTP client error with its cause
/// chain, by the stage the connector named; with none named, the connector's own text.
#[test]
fn a_failed_card_hop_is_named_as_the_engines_client_named_it() {
    use busbar_contract::abi::host::conn::connector::{
        CAUSE_CONNECT, CAUSE_DEADLINE, CAUSE_EXCHANGE, CAUSE_FRAMER, CAUSE_NONE, CAUSE_SECURITY,
    };
    use busbar_contract::abi::sdk::conn::ConnFailure;
    let refused = ConnFailure::Refused("Connection refused (os error 111)".into());
    assert_eq!(
        transport_err(CAUSE_CONNECT, &refused),
        "client error (Connect): tcp connect error: Connection refused (os error 111)"
    );
    let unknown = ConnFailure::Refused("invalid peer certificate: UnknownIssuer".into());
    assert_eq!(
        transport_err(CAUSE_SECURITY, &unknown),
        "client error (Connect): invalid peer certificate: UnknownIssuer"
    );
    let reset = ConnFailure::Failed("Connection reset by peer (os error 104)".into());
    assert_eq!(
        transport_err(CAUSE_EXCHANGE, &reset),
        "client error (SendRequest): connection error: Connection reset by peer (os error 104)"
    );
    let unanswered = ConnFailure::Failed("connection closed before message completed".into());
    assert_eq!(
        transport_err(CAUSE_FRAMER, &unanswered),
        "client error (SendRequest): connection closed before message completed"
    );
    assert_eq!(
        transport_err(CAUSE_DEADLINE, &ConnFailure::Failed(String::new())),
        "governed egress hop exceeded its deadline"
    );
    assert_eq!(
        transport_err(CAUSE_NONE, &ConnFailure::Refused(String::new())),
        "the connector refused the call"
    );
}

/// A key pin seen on the hop.
fn hop(peer_key_pin: Option<&str>, client_identity_offered: bool) -> Handshake {
    Handshake {
        peer_key_pin: peer_key_pin.map(str::to_string),
        client_identity_offered,
    }
}

/// THE TRANSPORT PIN (Q-DEL-A2A-SPKI), the served engine's verdicts and words: the connector's
/// observed key matching the pin is observed and approvable (`cert_spki`, and `mtls` once busbar
/// presented its client identity), the OBSERVED key is what is recorded; no key observed is
/// refused as not observed; another key as a mismatch naming both; `mtls` whose hop presented no
/// identity of busbar's as one-way, the peer half judged first.
#[test]
fn a_transport_pin_is_observed_approvable_and_enforced_as_the_engine_judged_it() {
    let c = card("plans");
    let key = "R2V0IHRoZSBrZXkgcmlnaHQ=";
    let spki = pin(PinMechanism::CertKeyPin, Some(&format!(" {key} ")));
    let seen = verify(&spki, &c, &hop(Some(key), false), || unreachable!()).unwrap();
    assert_eq!(
        seen.pin,
        CardPin::Rooted {
            mechanism: PinMechanism::CertKeyPin,
            key: key.to_string(),
            fingerprint: card::fingerprint(&c).unwrap(),
        }
    );
    assert!(
        seen.pin.fingerprint().is_some(),
        "an observed key is sighted by its fingerprint"
    );

    assert_eq!(
        verify(&spki, &c, &hop(None, false), || Ok(())).unwrap_err(),
        "`pin.mechanism: cert_spki` binds the CARD ENDPOINT's certificate, and this fetch observed \
         none — the hop was plaintext, or the peer's certificate yielded no \
         subject-public-key-info. Refused rather than recorded as satisfied: a fetch that \
         succeeded is not a transport binding that was checked."
    );
    assert_eq!(
        verify(&spki, &c, &hop(Some("b3RoZXI="), false), || Ok(())).unwrap_err(),
        format!(
            "`pin.mechanism: cert_spki`: the card endpoint served a certificate whose \
             subject-public-key-info is `b3RoZXI=`, and the operator pinned `{key}`. The endpoint \
             answered and it is not the endpoint the operator supplied a root for."
        )
    );
    // Base64 is case-significant: a key in another case is another key.
    assert!(
        verify(&spki, &c, &hop(Some(&key.to_lowercase()), false), || Ok(()))
            .unwrap_err()
            .contains("the operator pinned")
    );

    let mutual = pin(PinMechanism::MutualTls, Some(key));
    let both = verify(&mutual, &c, &hop(Some(key), true), || unreachable!()).unwrap();
    assert_eq!(both.pin.mechanism(), "mtls");
    assert!(verify(&mutual, &c, &hop(Some(key), false), || Ok(()))
        .unwrap_err()
        .starts_with("`pin.mechanism: mtls` requires busbar to present a client certificate"));
    // The peer half first: a mismatched endpoint is a mismatch, not a missing identity.
    assert!(
        verify(&mutual, &c, &hop(Some("b3RoZXI="), false), || Ok(()))
            .unwrap_err()
            .starts_with("`pin.mechanism: mtls`: the card endpoint served a certificate")
    );
}

/// A card fetch the connector refused for the pinned key reads as the pin's refusal (the key it
/// served named); a refused plaintext card URL of a transport-pinned registration as not observed;
/// any other fetch failure, and any other mechanism, keeps the fetch's own words.
#[test]
fn a_refused_hop_of_a_transport_pinned_registration_reads_as_the_pin_s_refusal() {
    let key = "R2V0IHRoZSBrZXkgcmlnaHQ=";
    let spki = pin(PinMechanism::CertKeyPin, Some(key));
    let https = "https://agent.example/a";
    assert!(hop_refusal(&spki, &hop(Some("b3RoZXI="), false), https)
        .unwrap()
        .contains("subject-public-key-info is `b3RoZXI=`"));
    assert_eq!(hop_refusal(&spki, &hop(None, false), https), None);
    assert!(
        hop_refusal(&spki, &hop(None, false), "http://127.0.0.1:9/a")
            .unwrap()
            .contains("this fetch observed none")
    );
    assert_eq!(hop_refusal(&spki, &hop(Some(key), false), https), None);
    assert_eq!(
        hop_refusal(&signed_root(), &hop(Some("b3RoZXI="), false), https),
        None
    );
}

/// `file:` and `data:` are the two that turn a fetch into a local read. Neither is reachable by
/// opting into plaintext, because `allow_private` is about TRANSPORT confidentiality and these are
/// not transports at all: any scheme other than `https` (and `http` under the opt-in) is refused.
/// Ported from busbar-a2a a2a/tests/fetch_tests.rs::a_non_http_scheme_is_refused_however_the_plaintext_knob_is_set.
#[test]
fn a_non_http_scheme_is_refused_however_the_plaintext_knob_is_set() {
    for allow_private in [false, true] {
        for url in [
            "file:///etc/passwd",
            "data:application/json,{}",
            "gopher://x/",
            "ftp://a2a.vendor/card",
            "FILE:///etc/passwd",
        ] {
            let refusal = scheme_refusal(url, allow_private).unwrap_or_else(|| {
                panic!("`{url}` must be refused (allow_private {allow_private})")
            });
            assert!(refusal.contains("uses scheme"), "{url}: {refusal}");
        }
    }
    // The opt-in admits plaintext http and nothing else.
    assert_eq!(scheme_refusal("http://a2a.vendor/card", true), None);
    assert!(scheme_refusal("http://a2a.vendor/card", false).is_some());
}

/// The redirect target is an ordinary-looking public NAME; only judging what it RESOLVED to catches
/// it. The next hop is the target resolved against the hop that sent it (a name, judged from
/// scratch like the first), and its refusal, for an internal answer, names the address in 1.5.5's
/// words. The door's judgement of a hop is the host's; these are the plane's two halves of it.
/// Ported from busbar-a2a a2a/tests/fetch_tests.rs::a_redirect_to_a_name_that_resolves_internally_is_refused_on_the_answer.
#[test]
fn a_redirect_to_a_name_that_resolves_internally_is_refused_on_the_answer() {
    let next = next_hop(
        "https://a2a.vendor/.well-known/agent-card.json",
        302,
        Some("https://cdn.partner/card.json"),
        0,
    )
    .expect("a followable redirect")
    .expect("a next hop");
    assert_eq!(next, "https://cdn.partner/card.json");
    assert_eq!(
        refused_judgement(&next, svc::DEST_INTERNAL, Some("10.0.0.7")),
        "SSRF guard refused the agent card fetch: host `cdn.partner` resolved to the internal \
         address 10.0.0.7; set this registration's `allow_private: true` if reaching it is \
         deliberate. A cloud-metadata address is refused whatever that is set to."
    );
}
/// THE RATCHET (predev `verify_tests::the_cadence_grammar_has_no_knob_that_slows_detection_or_delays_demotion`):
/// the asymmetry is one line away from being lost to a well-meaning `detection_backoff:` or
/// `demotion_grace:`, and either would be a window an upstream opens for itself by flapping. The
/// door's grammar and cadence are scanned and the cadence's own field set is enumerated: the ONLY
/// held direction anything may name is recovery. The plane tests itself; the kernel's trust book
/// and verify gate, which hold drift, quarantine and the recovery backoff, are held to the same
/// rule by the kernel's own `book_tests`.
#[test]
fn the_cadence_grammar_has_no_knob_that_slows_detection_or_delays_demotion() {
    // The sources are compiled in (the plane performs no input or output): a file that moved
    // fails to build here, so the ratchet moves with it rather than quietly covering nothing.
    let code = |s: &str| -> String {
        s.lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    for (rel, src) in [
        ("a2a/config.rs", include_str!("../a2a/config.rs")),
        ("trust.rs", include_str!("../trust.rs")),
    ] {
        let src = code(src);
        for banned in [
            "detection_backoff",
            "detection_grace",
            "demotion_backoff",
            "demotion_grace",
            "demotion_delay",
            "quarantine_grace",
            "quarantine_delay",
            "drift_grace",
            "suppress_drift",
            "min_drift",
        ] {
            assert!(
                !src.contains(banned),
                "{rel} names `{banned}`. Detection is never rate-limited and demotion is never \
                 held; the only direction that may be held is RECOVERY. A window an upstream can \
                 open for itself by flapping is a window it will use."
            );
        }
    }
    // The door's cadence carries exactly one knob (its recovery backoff is the kernel book's), so a
    // second cannot arrive unnoticed. Exhaustive destructure, no `..`.
    let Cadence { ttl_ms } = Cadence { ttl_ms: 1 };
    assert_eq!(ttl_ms, 1);
}
/// Ported from busbar-a2a a2a/tests/transport_pin_tests.rs::a_transport_pinned_registration_with_no_pin_material_is_refused_rather_than_degraded.
#[test]
fn a_transport_pinned_registration_with_no_pin_material_is_refused_rather_than_degraded() {
    let c = card("plans");
    for mechanism in [PinMechanism::CertKeyPin, PinMechanism::MutualTls] {
        // Absent, and present-but-blank, are the same: nothing to compare against.
        for key in [None, Some("   ")] {
            let refusal = verify(
                &pin(mechanism, key),
                &c,
                &hop(Some("c29tZSBrZXk="), true),
                || unreachable!("a transport pin never asks for a signature verdict"),
            )
            .expect_err("a mechanism with nothing to compare against has no root");
            assert_eq!(
                refusal,
                format!(
                    "`pin.mechanism: {}` carries no `pin.key:`; it binds the card endpoint's \
                     certificate and there is no SubjectPublicKeyInfo hash to bind it to",
                    mechanism.token()
                ),
                "{mechanism:?} with key {key:?}"
            );
        }
    }
}

/// Ported from busbar-a2a a2a/tests/pin_tests.rs::the_mechanism_is_part_of_the_identity_not_a_label_beside_it.
#[test]
fn the_mechanism_is_part_of_the_identity_not_a_label_beside_it() {
    let rooted = |mechanism| CardPin::Rooted {
        mechanism,
        key: "KEY".to_string(),
        fingerprint: "sha256/FP".to_string(),
    };
    let jws = rooted(PinMechanism::JwsIssuerKey);
    let key_pin = rooted(PinMechanism::CertKeyPin);
    let mutual = rooted(PinMechanism::MutualTls);
    assert_ne!(jws, key_pin);
    assert_ne!(key_pin, mutual);
    assert_ne!(jws, mutual);
    assert_ne!(jws.mechanism(), key_pin.mechanism());
    assert_eq!(
        jws.fingerprint(),
        key_pin.fingerprint(),
        "the same fingerprint under two mechanisms is two identities"
    );
    assert_ne!(jws, CardPin::Unpinned);
    assert_ne!(CardPin::Unpinned, key_pin);
    assert_eq!(rooted(PinMechanism::CertKeyPin), key_pin);
}
