// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The door's declarations pass the dispatcher's own validators, and `read_settings` judges a
//! section with the grammar's words.

use super::*;
use busbar_contract::abi::plane::check::{check_admin_routes, check_tail, check_trust_keys};
use busbar_contract::plane::TrustRole;

/// A fixture endpoint: the secure scheme and a reserved example host, spelled once for every test.
fn endpoint(host: &str, rest: &str) -> String {
    format!("https://{host}.example{rest}")
}

/// A one-entry `agents:` section named `name` whose endpoint is `url`.
fn one_agent(name: &str, url: &str) -> Vec<u8> {
    format!(r#"{{"{name}": {{"url": "{url}", "pin": {{"mechanism": "unpinned"}}}}}}"#).into_bytes()
}

fn s(a: AbiStr) -> &'static str {
    if a.ptr.is_null() {
        return "";
    }
    // The tail's strings are `'static` constants of this crate.
    std::str::from_utf8(known_bytes(a)).expect("utf-8")
}

/// The tail's own strings, read back through the `&'static str` each was built from.
fn known_bytes(a: AbiStr) -> &'static [u8] {
    [
        SCOPE,
        LABEL,
        SUBJECT_NOUN,
        ADMIN_NOUN,
        AUDIT_KIND,
        CARD_SIGNING_DOMAIN,
        CARD_KID_PREFIX,
        "pin",
        "reverify_ttl",
        "recovery_backoff",
        PRIVATE_REACH_KEY,
        DEFAULT_REVERIFY_TTL,
        DEFAULT_RECOVERY_BACKOFF,
        "jws_issuer_key",
        "cert_spki",
        "mtls",
        "unpinned",
        crate::a2a::config::REFUSE_PASSTHROUGH_SECTION,
        crate::records::KIND_TASK,
        crate::records::KIND_TASK_EVENT,
        crate::records::KIND_PUSH_CONFIG,
        crate::records::KIND_CARD,
    ]
    .into_iter()
    .find(|c| c.as_ptr() == a.ptr && c.len() == a.len)
    .expect("a tail string this test knows")
    .as_bytes()
}

#[test]
fn the_tail_passes_the_dispatchers_check() {
    assert_eq!(check_tail(TAIL), Ok(()));
    assert_eq!(check_trust_keys(TRUST_KEYS), Ok(()));
}

#[test]
fn the_tail_states_the_planes_nouns() {
    assert_eq!(s(TAIL.scope), SCOPE);
    assert_eq!(s(TAIL.subject_noun), SUBJECT_NOUN);
    assert_eq!(s(TAIL.admin_noun), ADMIN_NOUN);
    assert_eq!(s(TAIL.audit_kind), AUDIT_KIND);
    assert_eq!(s(TAIL.signing_domain), CARD_SIGNING_DOMAIN);
    assert_eq!(s(TAIL.signing_kid_prefix), CARD_KID_PREFIX);
    assert_eq!(TAIL.dialects_len, 3);
    assert_eq!(TAIL.record_kinds_len, crate::records::HELD_KINDS.len());
    for (abi, kind) in RECORD_KINDS.iter().zip(crate::records::HELD_KINDS) {
        assert_eq!(s(*abi), *kind);
    }
}

#[test]
fn the_abi_trust_keys_are_the_grammars_trust_keys() {
    let grammar = crate::a2a::config::TRUST_KEYS;
    assert_eq!(TRUST_KEYS.len(), grammar.len() + 1);
    let reach = TRUST_KEYS[grammar.len()];
    assert_eq!(
        (s(reach.key), reach.role, reach.flags, reach.mechanisms_len),
        (PRIVATE_REACH_KEY, TRUST_PRIVATE_REACH, 0, 0),
        "the private reach rides last, on the key the grammar reads"
    );
    assert!(reach.default.ptr.is_null());
    for (abi, decl) in TRUST_KEYS.iter().zip(grammar) {
        assert_eq!(s(abi.key), decl.key);
        let role = match decl.role {
            TrustRole::Pin => TRUST_PIN,
            TrustRole::ReverifyTtl => TRUST_REVERIFY_TTL,
            TrustRole::RecoveryBackoff => TRUST_RECOVERY_BACKOFF,
            TrustRole::PrivateReach => TRUST_PRIVATE_REACH,
            TrustRole::ItemApprovals => busbar_contract::abi::plane::TRUST_ITEM_APPROVALS,
        };
        assert_eq!(abi.role, role, "{}", decl.key);
        assert_eq!(
            abi.flags & PIN_FINGERPRINT != 0,
            decl.fingerprint,
            "{}",
            decl.key
        );
        assert_eq!(s(abi.default), decl.default.unwrap_or(""), "{}", decl.key);
        assert_eq!(abi.mechanisms_len, decl.mechanisms.len(), "{}", decl.key);
    }
    for (abi, decl) in PIN_MECHANISMS.iter().zip(grammar[0].mechanisms) {
        assert_eq!(s(abi.token), decl.token);
        assert_eq!(abi.flags & MECHANISM_ROOT != 0, decl.root, "{}", decl.token);
        assert_eq!(
            abi.flags & MECHANISM_PEER_KEY != 0,
            decl.peer_key,
            "{}",
            decl.token
        );
    }
}

#[test]
fn an_open_route_claims_open_and_a_templated_target_claims_a_pattern() {
    let spec = snapshot_spec(Some(&endpoint("gw", "")));
    for (c, r) in spec.claims.iter().zip(ROUTES) {
        let templated = r.target.contains('{');
        assert_eq!((c.verb.as_str(), c.target.as_str()), (r.verb, r.target));
        assert_eq!(c.flags & CLAIM_OPEN != 0, r.open, "{}", r.target);
        assert_eq!(c.flags & CLAIM_EXACT != 0, !templated, "{}", r.target);
        assert_eq!(c.flags & CLAIM_PATTERN != 0, templated, "{}", r.target);
        assert_eq!(
            busbar_contract::abi::plane::check::check_claim_target(r.target, c.flags),
            Ok(()),
            "{}",
            r.target
        );
    }
}

#[test]
fn the_tail_states_the_sentence_that_refuses_a_forwarded_caller_credential() {
    assert_eq!(
        s(TAIL.caller_credential_refusal),
        crate::a2a::config::REFUSE_PASSTHROUGH_SECTION
    );
}

#[test]
fn an_admitted_generation_claims_every_route_and_states_its_audience() {
    let spec = snapshot_spec(Some(&endpoint("gw", "/base?x=1")));
    assert_eq!(spec.claims.len(), ROUTES.len());
    assert_eq!(spec.audience, Some(endpoint("gw", "/a2a")));
    assert_eq!(
        spec.resource_metadata,
        Some(endpoint("gw", "/.well-known/oauth-protected-resource/a2a"))
    );
    assert_eq!(spec.admin_routes.len(), ADMIN_ROUTES.len());
    assert_eq!(
        spec.openapi,
        Some(openapi_fragment("").to_string().into_bytes())
    );
}

#[test]
fn a_generation_with_no_readable_public_base_claims_nothing() {
    for public in [None, Some("not a url")] {
        let spec = snapshot_spec(public);
        assert!(spec.claims.is_empty());
        assert_eq!((spec.audience, spec.resource_metadata), (None, None));
        assert_eq!(spec.admin_routes.len(), ADMIN_ROUTES.len());
    }
}

#[test]
fn the_admin_routes_pass_the_dispatchers_check() {
    assert_eq!(check_admin_routes(ADMIN_ROUTES), Ok(()));
}

#[test]
fn the_abi_admin_routes_are_the_admin_verbs() {
    assert_eq!(ADMIN_ROUTES.len(), ADMIN_VERBS.len());
    for (abi, (verb, target)) in ADMIN_ROUTES.iter().zip(ADMIN_VERBS) {
        assert_eq!((abi.verb.ptr, abi.verb.len), (verb.as_ptr(), verb.len()));
        assert_eq!(
            (abi.target.ptr, abi.target.len),
            (target.as_ptr(), target.len())
        );
    }
}

#[test]
fn exactly_the_discovery_documents_are_open_claims() {
    let open: Vec<&str> = ROUTES.iter().filter(|r| r.open).map(|r| r.target).collect();
    assert_eq!(open, [crate::METADATA_PATH, crate::WELL_KNOWN_CARD_PATH]);
}

/// BUSBAR'S OWN PUSH CALLBACK is the plane's one PUBLIC route, served by `serve` (ARCHITECT ruling
/// Q3c), never a claim: the plane is not a second claimant of its path.
#[test]
fn the_push_callback_is_a_public_route_and_no_claim() {
    use busbar_contract::abi::plane::ROUTE_PUBLIC;
    assert_eq!(ADMIN_VERBS[PUSH_ROUTE], ("POST", "/a2a/push"));
    assert_eq!(ADMIN_ROUTES[PUSH_ROUTE].flags, ROUTE_PUBLIC);
    assert_eq!(
        ADMIN_AUDIT_VERBS[PUSH_ROUTE], "",
        "the callback is never audited"
    );
    for (i, r) in ADMIN_ROUTES.iter().enumerate() {
        assert_eq!(r.flags == ROUTE_PUBLIC, i == PUSH_ROUTE);
    }
    assert!(ROUTES.iter().all(|r| r.target != "/a2a/push"));
}

#[test]
fn the_openapi_fragment_keys_its_paths_under_the_prefix_given() {
    let doc = openapi_fragment("/api/v1/admin");
    let mut keys: Vec<&String> = doc.as_object().expect("an object").keys().collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "/api/v1/admin/agents/{name}/approve",
            "/api/v1/admin/agents/{name}/connect",
            "components"
        ]
    );
}

/// THE ADMIN OPENAPI BLOB CARRIES ITS OWN BODIES (ARCHITECT Q2): every trust verb's `200` names a
/// typed body by `$ref`, and every `$ref` in the blob, its schemas' included, names a schema the
/// blob's `components.schemas` states. The schemas' bytes are held to the committed admin document
/// by the admin crate's drift test.
#[test]
fn the_admin_openapi_blob_states_every_body_its_verbs_name() {
    fn refs(v: &serde_json::Value, out: &mut Vec<String>) {
        match v {
            serde_json::Value::Object(m) => {
                if let Some(r) = m.get("$ref").and_then(|r| r.as_str()) {
                    out.push(r.to_string());
                }
                m.values().for_each(|v| refs(v, out));
            }
            serde_json::Value::Array(a) => a.iter().for_each(|v| refs(v, out)),
            _ => {}
        }
    }
    let blob: serde_json::Value = serde_json::from_str(ADMIN_OPENAPI).expect("a JSON object");
    let schemas = blob["components"]["schemas"]
        .as_object()
        .expect("the blob states its schemas");
    for (i, (verb, target)) in ADMIN_VERBS.iter().enumerate() {
        if i == PUSH_ROUTE {
            continue;
        }
        let op = &blob[*target][verb.to_ascii_lowercase()];
        let body = &op["responses"]["200"]["content"]["application/json"]["schema"]["$ref"];
        assert!(body.is_string(), "{verb} {target} names no typed body");
    }
    let mut named = Vec::new();
    refs(&blob, &mut named);
    for r in &named {
        let name = r
            .strip_prefix("#/components/schemas/")
            .unwrap_or_else(|| panic!("`{r}` is no component reference"));
        assert!(schemas.contains_key(name), "`{r}` names no stated schema");
    }
    for name in schemas.keys() {
        assert!(
            named.iter().any(|r| r.ends_with(&format!("/{name}"))),
            "the blob states `{name}` and nothing names it"
        );
    }
}

#[test]
fn an_empty_blob_is_the_empty_section() {
    assert_eq!(read_settings(b"").expect("empty"), AgentsCfg::default());
}

#[test]
fn a_valid_section_reads_and_a_bad_entry_is_refused_in_the_grammars_words() {
    let ok = one_agent("vendor", &endpoint("vendor", "/a2a"));
    assert_eq!(read_settings(&ok).expect("valid").agents.len(), 1);
    let bad = one_agent("vendor", "ftp://vendor.example");
    let err = read_settings(&bad).expect_err("refused");
    assert!(err.contains("`agents.vendor`: `url:` must be an"), "{err}");
}

#[test]
fn every_route_is_one_line_of_the_dialect_in_mount_order() {
    use Line::{Document, Framed, Open, Target};
    let lines: Vec<Line> = ROUTES.iter().map(line_of).collect();
    assert_eq!(
        lines,
        [
            Target, Target, Target, Target, Target, Target, Target, Target, Target, Target, Open,
            Open, Open, Document, Document, Document, Framed,
        ]
    );
    // Each line's refusals speak the binding its dialect index names.
    let lens: Vec<usize> = [Document, Target, Framed]
        .iter()
        .map(|l| DIALECTS[l.dialect().expect("a line") as usize].len)
        .collect();
    assert_eq!(
        lens,
        [
            BINDING_DOCUMENT.len(),
            BINDING_TARGET.len(),
            BINDING_FRAMED.len()
        ]
    );
    assert_eq!(Open.dialect(), None);
}

#[test]
fn the_tail_declares_the_op_class_of_every_method_arrive_can_name() {
    assert_eq!(TAIL.op_classes_len, crate::ops::OP_CLASSES.len());
    for (i, class) in OP_CLASS_TABLE.iter().enumerate() {
        assert_eq!(class.op.len, crate::ops::OP_CLASSES[i].as_str().len());
    }
    for row in crate::ops::METHODS {
        let i = op_class_index(row.op).expect("declared");
        assert_eq!(crate::ops::OP_CLASSES[i as usize], row.op);
    }
}

/// THE DEALT VALIDATE BLOB: the boot's deal hands `{agents: <section>}`, which is unwrapped to the
/// section; a bare section passes through as it is.
#[test]
fn a_dealt_validate_blob_is_unwrapped_to_its_section() {
    let dealt =
        br#"{"agents":{"probe":{"url":"https://a.example/","pin":{"mechanism":"unpinned"}}}}"#;
    let section: serde_json::Value =
        serde_json::from_slice(&crate::door::dealt_section(dealt)).expect("JSON");
    assert_eq!(
        section,
        serde_json::json!({"probe": {"url": "https://a.example/", "pin": {"mechanism": "unpinned"}}})
    );
    let bare = br#"{"probe":{"url":"https://a.example/"},"hooks":[]}"#;
    assert_eq!(&*crate::door::dealt_section(bare), &bare[..]);
    assert!(crate::door::read_settings(&crate::door::dealt_section(dealt)).is_ok());
}

/// Two constants, and both are wire-visible: the credential kind appears on a stored credential row
/// and the scope kind on every scope reference an operator writes. Changing either silently
/// orphans every existing row, so they are pinned by value.
/// Ported from busbar-a2a a2a/tests/inbound_tests.rs::the_credential_kind_and_the_scope_kind_are_the_spellings_the_rest_of_the_tree_uses.
#[test]
fn the_credential_kind_and_the_scope_kind_are_the_spellings_the_rest_of_the_tree_uses() {
    assert_eq!(
        crate::served_card::CREDENTIAL_KIND_A2A_INBOUND,
        "a2a_inbound"
    );
    assert_eq!(SCOPE, "agent");
    assert_eq!(s(TAIL.scope), "agent");
}
/// THE AGENT FEE (the engine's `agents.fees`): the door counts `per_request` and only it, so the
/// kernel's one rule over declared fee units validates `agents.fees.per_request` and refuses
/// `agents.fees.per_session` naming `per_request` as the counted list; the fee unit is a billable
/// class at the index the door reports it under, once per served unit.
#[test]
fn the_door_counts_the_per_request_fee_and_never_a_per_session_one() {
    let same = |a: AbiStr, b: &str| a.ptr == b.as_ptr() && a.len == b.len();
    assert_eq!(FEE_PER_REQUEST, busbar_contract::plane::PER_REQUEST);
    assert_ne!(FEE_PER_REQUEST, busbar_contract::plane::PER_SESSION);
    assert_eq!(FEE_UNITS.len(), 1, "one fee unit");
    assert!(same(FEE_UNITS[0], FEE_PER_REQUEST));
    assert!(same(
        BILLABLE_CLASSES[CLASS_FEE_INDEX as usize].class,
        FEE_PER_REQUEST
    ));
}
