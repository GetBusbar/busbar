// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `agents:` section's grammar, and the value rules that make the object pin worth having,
//! read as the door reads them: through [`crate::door::read_settings`] over the section's JSON.

use super::*;
use crate::door::read_settings;
use busbar_contract::config::UpstreamCreds;
use busbar_contract::secret_ref::{SecretRef, SECRET_MODULE_FILE};
use serde_json::json;

/// One registration as the section reads it: unpinned, over `url`.
fn def(url: &str, pin: PinMechanism) -> AgentDefCfg {
    AgentDefCfg {
        url: url.to_string(),
        pin: AgentPinCfg {
            mechanism: pin,
            key: None,
            fingerprint: None,
        },
        client_identity: None,
        reverify_ttl: None,
        recovery_backoff: None,
        protocol_version: None,
        allow_private: false,
        upstream_credentials: None,
        upstream_credential: None,
        egress_scopes: Vec::new(),
        hooks: Vec::new(),
    }
}

/// Parse a section document the way the door does.
fn parse(section: &serde_json::Value) -> Result<AgentsCfg, String> {
    read_settings(section.to_string().as_bytes())
}

const ALL: [PinMechanism; 4] = [
    PinMechanism::JwsIssuerKey,
    PinMechanism::CertKeyPin,
    PinMechanism::MutualTls,
    PinMechanism::Unpinned,
];

/// The mechanisms declared to the kernel are exactly the grammar's own, each with the root-ness it
/// gives them, and the cadence defaults are the named ones.
/// Ported from busbar-a2a a2a/tests/config_tests.rs::the_declared_trust_keys_match_the_grammar.
#[test]
fn the_declared_trust_keys_match_the_grammar() {
    let pin = &TRUST_KEYS[0];
    assert_eq!(pin.key, "pin");
    assert_eq!(pin.mechanisms.len(), ALL.len());
    for m in ALL {
        let declared = pin
            .mechanisms
            .iter()
            .find(|d| d.token == m.token())
            .unwrap_or_else(|| panic!("`{}` is declared", m.token()));
        assert_eq!(declared.root, m.is_a_root(), "{}", m.token());
    }
    let ttl = TRUST_KEYS
        .iter()
        .find(|k| k.key == "reverify_ttl")
        .expect("the reverify ttl is a declared trust key");
    assert_eq!(ttl.default, Some(DEFAULT_REVERIFY_TTL));
    let backoff = TRUST_KEYS
        .iter()
        .find(|k| k.key == "recovery_backoff")
        .expect("the recovery backoff is a declared trust key");
    assert_eq!(backoff.default, Some("15m"));
    assert_eq!(DEFAULT_RECOVERY_BACKOFF_MS, 15 * 60 * 1_000);
}

/// Each mechanism's SERIALIZED token is the token its declared `TRUST_KEYS` spells, and the pin
/// object reads that token back, so a drift between the two would read a rooted pin as no pin.
/// Ported from busbar-a2a a2a/tests/config_tests.rs::every_serialized_pin_token_is_the_declared_trust_key_token.
#[test]
fn every_serialized_pin_token_is_the_declared_trust_key_token() {
    let declared: Vec<&str> = TRUST_KEYS[0].mechanisms.iter().map(|m| m.token).collect();
    for m in ALL {
        let serialized = serde_json::to_value(m).expect("a mechanism serialises");
        let token = serialized.as_str().expect("a mechanism is a string");
        assert!(declared.contains(&token), "`{token}` is not declared");
        assert_eq!(token, m.token());
        let pin: AgentPinCfg = serde_json::from_value(json!({"mechanism": token, "key": "K"}))
            .unwrap_or_else(|e| panic!("`{token}` must read back: {e}"));
        assert_eq!(pin.mechanism, m);
        let declared_root = TRUST_KEYS[0]
            .mechanisms
            .iter()
            .find(|d| d.token == token)
            .expect("declared")
            .root;
        assert_eq!(declared_root, m.is_a_root(), "{token}");
    }
}

/// The shape the design specifies parses, field for field.
/// Ported from busbar-a2a a2a/tests/config_tests.rs::the_designed_entry_parses_as_written.
#[test]
fn the_designed_entry_parses_as_written() {
    let cfg = parse(&json!({
        "hooks": ["agent-sanitizer"],
        "planner": {
            "url": "https://a2a.vendor/planner",
            "pin": {
                "mechanism": "jws_issuer_key",
                "key": "MCowBQYDK2VwAyEA",
                "fingerprint": "sha256/CARD=="
            },
            "reverify_ttl": "6h",
            "upstream_credentials": "own",
            "hooks": ["dispatch-order"]
        }
    }))
    .expect("the designed entry must parse");

    assert_eq!(cfg.all_agent_hooks, vec!["agent-sanitizer".to_string()]);
    let planner = cfg.agents.get("planner").expect("planner is registered");
    assert_eq!(planner.url, "https://a2a.vendor/planner");
    assert_eq!(planner.pin.mechanism, PinMechanism::JwsIssuerKey);
    assert_eq!(planner.pin.key.as_deref(), Some("MCowBQYDK2VwAyEA"));
    assert_eq!(planner.pin.fingerprint.as_deref(), Some("sha256/CARD=="));
    assert_eq!(planner.reverify_ttl.as_deref(), Some("6h"));
    assert_eq!(planner.upstream_credentials, Some(UpstreamCreds::Own));
    assert_eq!(planner.hooks, vec!["dispatch-order".to_string()]);
}

/// A typo'd key fails the parse rather than silently un-pinning an agent.
/// Ported from busbar-a2a a2a/tests/config_tests.rs::an_unknown_key_is_refused_rather_than_ignored.
#[test]
fn an_unknown_key_is_refused_rather_than_ignored() {
    let err = parse(&json!({
        "planner": {
            "url": "https://a2a.vendor/planner",
            "pin": {"mechanism": "unpinned"},
            "reverfy_ttl": "6h"
        }
    }))
    .expect_err("a typo'd key must not parse");
    assert!(
        err.contains("reverfy_ttl"),
        "the error must name the offending key, got: {err}"
    );
}

/// A URL with no scheme, or an empty one, fails at parse rather than at a delegation later.
/// Ported from busbar-a2a a2a/tests/config_tests.rs::a_url_without_a_scheme_fails_at_parse.
#[test]
fn a_url_without_a_scheme_fails_at_parse() {
    for url in ["", "   ", "a2a.vendor/planner", "ftp://a2a.vendor/"] {
        let d = def(url, PinMechanism::Unpinned);
        let err = validate_agent("planner", &d).expect_err(&format!("`{url}` must be refused"));
        assert!(err.contains("`url:`"), "got: {err}");
        let read = parse(&json!({"planner": {"url": url, "pin": {"mechanism": "unpinned"}}}))
            .expect_err(&format!("`{url}` must be refused on the read path too"));
        assert!(read.contains("`url:`"), "got: {read}");
    }
    assert_eq!(
        validate_agent(
            "planner",
            &def("https://a2a.vendor/", PinMechanism::Unpinned)
        ),
        Ok(())
    );
    assert_eq!(
        validate_agent(
            "planner",
            &def("http://a2a.vendor/", PinMechanism::Unpinned)
        ),
        Ok(())
    );
}

/// An agent may not be NAMED by a reserved word: every word in the one declaration is refused here.
/// Ported from busbar-a2a a2a/tests/config_tests.rs::an_agent_may_not_be_named_by_a_reserved_word.
#[test]
fn an_agent_may_not_be_named_by_a_reserved_word() {
    for reserved in busbar_contract::section::RESERVED_SECTION_KEYS {
        let mut section = serde_json::Map::new();
        section.insert(
            (*reserved).to_string(),
            json!({"url": "https://x/", "pin": {"mechanism": "unpinned"}}),
        );
        let err = parse(&serde_json::Value::Object(section)).unwrap_err();
        assert!(
            err.contains("RESERVED"),
            "`{reserved}` must be refused as an agent name, got: {err}"
        );
    }
}

/// The section-level reserved keys still WORK as knobs, and are not agents.
/// Ported from busbar-a2a a2a/tests/config_tests.rs::the_reserved_words_still_function_as_section_knobs.
#[test]
fn the_reserved_words_still_function_as_section_knobs() {
    let cfg = parse(&json!({
        "hooks": ["a", "b"],
        "upstream_credentials": "own",
        "planner": {"url": "https://x/", "pin": {"mechanism": "unpinned"}}
    }))
    .unwrap();
    assert_eq!(cfg.all_agent_hooks, vec!["a".to_string(), "b".to_string()]);
    assert_eq!(cfg.all_agent_upstream_credentials, Some(UpstreamCreds::Own));
    assert_eq!(cfg.agents.len(), 1, "the knobs are not agents");
}

/// THE CALLER'S CREDENTIAL IS NEVER FORWARDED TO A DELEGATE: refused per entry and at the section
/// level, in this plane's own sentence; `own` is accepted in both places.
/// Ported from busbar-a2a a2a/tests/config_tests.rs::passthrough_is_refused_at_the_section_level_as_well_as_per_entry.
#[test]
fn passthrough_is_refused_at_the_section_level_as_well_as_per_entry() {
    let err = parse(&json!({
        "upstream_credentials": "passthrough",
        "planner": {"url": "https://x/", "pin": {"mechanism": "unpinned"}}
    }))
    .unwrap_err();
    assert!(
        err.contains("delegates AS ITSELF"),
        "the section-level refusal must explain itself, got: {err}"
    );

    let per_entry = parse(&json!({
        "planner": {
            "url": "https://x/",
            "pin": {"mechanism": "unpinned"},
            "upstream_credentials": "passthrough"
        }
    }))
    .unwrap_err();
    assert!(
        per_entry.contains("delegates AS ITSELF"),
        "the per-entry refusal must explain itself, got: {per_entry}"
    );

    parse(&json!({
        "upstream_credentials": "own",
        "planner": {
            "url": "https://x/",
            "pin": {"mechanism": "unpinned"},
            "upstream_credentials": "own"
        }
    }))
    .expect("`own` is the supported mode on both");
}

/// An entry round-trips to a document and back unchanged, which is what the overlay's per-entry
/// PATCH merge needs: patching one field must not rewrite the rest of the entry.
/// Ported from busbar-a2a a2a/tests/config_tests.rs::an_entry_round_trips_through_its_document_form.
#[test]
fn an_entry_round_trips_through_its_document_form() {
    let d = AgentDefCfg {
        url: "https://a2a.vendor/planner".to_string(),
        pin: AgentPinCfg {
            mechanism: PinMechanism::CertKeyPin,
            key: Some("sha256/KEYPIN==".to_string()),
            fingerprint: Some("sha256/CARD==".to_string()),
        },
        reverify_ttl: Some("15m".to_string()),
        recovery_backoff: Some("1h".to_string()),
        protocol_version: Some("1.0".to_string()),
        allow_private: true,
        upstream_credentials: Some(UpstreamCreds::Own),
        upstream_credential: Some(crate::a2a::creds::OutboundCredential {
            secret: SecretRef::env("VENDOR_TOKEN"),
            placement: crate::a2a::creds::CredentialPlacement::Header("x-api-key".to_string()),
            lease_ttl_ms: 60_000,
        }),
        egress_scopes: vec!["orchestrator".to_string()],
        // BOTH HALVES OF THE CLIENT IDENTITY: a `client_identity:` an admin PATCH silently dropped
        // would leave a registration unable to complete a handshake it completed a moment earlier.
        client_identity: Some(ClientIdentityCfg {
            cert: SecretRef::env("BUSBAR_CLIENT_CERT"),
            key: SecretRef::env("BUSBAR_CLIENT_KEY"),
        }),
        hooks: vec!["dispatch-order".to_string()],
    };
    let doc = serde_json::to_value(&d).expect("an entry must project to a document");
    let back: AgentDefCfg =
        serde_json::from_value(doc).expect("and must parse back from that document");
    assert_eq!(back, d);
}

/// The registration an operator writes for a peer behind mutual TLS, parsed field for field: the
/// client certificate is named by REFERENCE (`file:` sugar), never by key material.
/// Ported from busbar-a2a a2a/tests/config_tests.rs::a_mutual_tls_registration_names_its_client_certificate_by_reference.
#[test]
fn a_mutual_tls_registration_names_its_client_certificate_by_reference() {
    let cfg = parse(&json!({
        "planner": {
            "url": "https://a2a.vendor/planner",
            "pin": {"mechanism": "mtls", "key": "sha256/KEYPIN=="},
            "client_identity": {
                "cert": {"file": "/run/secrets/busbar-client.crt"},
                "key": {"file": "/run/secrets/busbar-client.key"}
            }
        }
    }))
    .expect("a mutual-TLS registration with a client identity must parse");

    let planner = cfg.agents.get("planner").expect("planner is registered");
    let identity = planner
        .client_identity
        .as_ref()
        .expect("the client identity is carried through");
    assert_eq!(identity.cert.module, SECRET_MODULE_FILE);
    assert_eq!(identity.key.module, SECRET_MODULE_FILE);
    // The REFERENCE is what the config holds; nothing here is key material.
    assert!(!format!("{identity:?}").contains("BEGIN"));
}

/// `mtls` with nothing to present is refused at parse, naming the missing key and what the peer
/// would have answered.
/// Ported from busbar-a2a a2a/tests/config_tests.rs::mutual_tls_without_a_client_identity_is_refused_at_parse.
#[test]
fn mutual_tls_without_a_client_identity_is_refused_at_parse() {
    let err = parse(&json!({
        "planner": {
            "url": "https://a2a.vendor/planner",
            "pin": {"mechanism": "mtls", "key": "sha256/KEYPIN=="}
        }
    }))
    .expect_err("mutual TLS with no client certificate must not parse");
    assert!(
        err.contains("`pin.mechanism: mtls` needs `client_identity:`")
            && err.contains("CertificateRequired"),
        "the refusal must name the missing key AND what the peer would have done: {err}"
    );
}

/// A client certificate over `http://` has no handshake to be presented in.
/// Ported from busbar-a2a a2a/tests/config_tests.rs::a_client_identity_on_a_plaintext_endpoint_is_refused.
#[test]
fn a_client_identity_on_a_plaintext_endpoint_is_refused() {
    let err = parse(&json!({
        "planner": {
            "url": "http://a2a.vendor/planner",
            "pin": {"mechanism": "cert_spki", "key": "sha256/KEYPIN=="},
            "client_identity": {
                "cert": {"file": "/run/secrets/c.crt"},
                "key": {"file": "/run/secrets/c.key"}
            }
        }
    }))
    .expect_err("a client certificate on a plaintext endpoint must not parse");
    assert!(
        err.contains("has no handshake to present it in"),
        "the refusal must say why the field cannot work here: {err}"
    );
}

/// A client certificate is legal under the OTHER mechanisms: only `mtls` REQUIRES it.
/// Ported from busbar-a2a a2a/tests/config_tests.rs::a_client_identity_is_legal_alongside_a_signed_card.
#[test]
fn a_client_identity_is_legal_alongside_a_signed_card() {
    parse(&json!({
        "planner": {
            "url": "https://a2a.vendor/planner",
            "pin": {"mechanism": "jws_issuer_key", "key": "MCowBQYDK2VwAyEA"},
            "client_identity": {
                "cert": {"file": "/run/secrets/c.crt"},
                "key": {"file": "/run/secrets/c.key"}
            }
        }
    }))
    .expect("a signed card behind a client-certificate-demanding endpoint must be spellable");
}

/// The admin write path runs the SAME rule: `validate_agent` is the one function both call.
/// Ported from busbar-a2a a2a/tests/config_tests.rs::the_admin_write_path_refuses_mutual_tls_without_a_client_identity_too.
#[test]
fn the_admin_write_path_refuses_mutual_tls_without_a_client_identity_too() {
    let mut d = def("https://a2a.vendor/planner", PinMechanism::MutualTls);
    d.pin.key = Some("sha256/KEYPIN==".to_string());
    let err = validate_agent("planner", &d)
        .expect_err("the admin path must refuse what the file refuses");
    assert!(err.contains("needs `client_identity:`"), "{err}");
}
