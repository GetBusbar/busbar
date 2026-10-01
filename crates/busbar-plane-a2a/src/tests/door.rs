// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The door's declarations pass the dispatcher's own validators, and `read_settings` judges a
//! section with the grammar's words.

use super::*;
use busbar_contract::abi::plane::check::{
    check_admin_routes, check_claims, check_snapshot, check_tail, check_trust_keys,
};
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
        DEFAULT_REVERIFY_TTL,
        DEFAULT_RECOVERY_BACKOFF,
        "jws_issuer_key",
        "cert_spki",
        "mtls",
        "unpinned",
        crate::a2a::config::REFUSE_PASSTHROUGH_SECTION,
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
    assert_eq!(TAIL.record_kinds_len, crate::records::RECORD_KINDS.len());
}

#[test]
fn the_abi_trust_keys_are_the_grammars_trust_keys() {
    let grammar = crate::a2a::config::TRUST_KEYS;
    assert_eq!(TRUST_KEYS.len(), grammar.len());
    for (abi, decl) in TRUST_KEYS.iter().zip(grammar) {
        assert_eq!(s(abi.key), decl.key);
        let role = match decl.role {
            TrustRole::Pin => TRUST_PIN,
            TrustRole::ReverifyTtl => TRUST_REVERIFY_TTL,
            TrustRole::RecoveryBackoff => TRUST_RECOVERY_BACKOFF,
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
    }
}

#[test]
fn an_open_route_claims_open_and_a_templated_target_claims_a_pattern() {
    let g = Generation::build(1, Some(&endpoint("gw", "")));
    for (c, r) in g.claims.iter().zip(ROUTES) {
        let templated = r.target.contains('{');
        assert_eq!(c.flags & CLAIM_OPEN != 0, r.open, "{}", r.target);
        assert_eq!(c.flags & CLAIM_EXACT != 0, !templated, "{}", r.target);
        assert_eq!(c.flags & CLAIM_PATTERN != 0, templated, "{}", r.target);
        assert_eq!(
            busbar_contract::abi::plane::check::check_claim_target(r.target, c.flags),
            Ok(()),
            "{}",
            r.target
        );
        let selector = busbar_contract::abi::plane::check::claim_selector(r.target, c.flags, |v| {
            Box::leak(v.into_boxed_slice())
        });
        assert!(
            selector.is_ok(),
            "{} reads as a claim: {selector:?}",
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
    let g = Generation::build(7, Some(&endpoint("gw", "/base?x=1")));
    assert_eq!(g.generation(), 7);
    assert_eq!(check_snapshot(g.snapshot(), 7), Ok(()));
    assert_eq!(g.claims.len(), ROUTES.len());
    assert_eq!(check_claims(&g.claims), Ok(()));
    assert_eq!(g.audience, endpoint("gw", "/a2a"));
    assert_eq!(
        g.resource_metadata,
        endpoint("gw", "/.well-known/oauth-protected-resource/a2a")
    );
    assert_eq!(g.snapshot().admin_routes_len, ADMIN_ROUTES.len());
}

#[test]
fn a_generation_with_no_readable_public_base_claims_nothing() {
    for public in [None, Some("not a url")] {
        let g = Generation::build(1, public);
        assert_eq!(check_snapshot(g.snapshot(), 1), Ok(()));
        assert!(g.claims.is_empty());
        assert!(g.snapshot().audience.ptr.is_null());
        assert!(g.snapshot().resource_metadata.ptr.is_null());
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
fn exactly_the_discovery_documents_and_the_callback_are_open() {
    let open: Vec<&str> = ROUTES.iter().filter(|r| r.open).map(|r| r.target).collect();
    assert_eq!(
        open,
        [
            crate::METADATA_PATH,
            crate::WELL_KNOWN_CARD_PATH,
            "/a2a/push",
        ]
    );
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
            "/api/v1/admin/agents/{name}/connect"
        ]
    );
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
