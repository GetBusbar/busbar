// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn advanced(yaml: &str) -> Result<crate::config::AdvancedCfg, String> {
    busbar_contract::yaml::from_str(yaml).map_err(|e| e.to_string())
}

#[test]
fn an_omitted_tls_block_is_the_bundled_roots_alone() {
    let a = advanced("rate_sweep_interval: 256\n").expect("parses");
    assert!(a.tls.is_default());
    assert_eq!(a.tls.roots, TlsRoots::Bundled);
}

#[test]
fn the_whole_grammar_parses_under_advanced_tls() {
    let a = advanced(
        "tls:\n  roots: system\n  trust_anchors:\n    - { file: /etc/busbar/ca/corp.pem }\n    - { env: CORP_CA }\n    - \"-----BEGIN CERTIFICATE-----\\nAA==\\n-----END CERTIFICATE-----\\n\"\n  destinations:\n    - match: ldap.corp.internal\n      trust_anchors: [ { file: /etc/busbar/ca/ldap.pem } ]\n      include_roots: true\n      pin_spki_sha256: sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n      client_identity: { cert: { file: /c.pem }, key: { env: KEY } }\n",
    )
    .expect("the advanced.tls grammar parses");
    assert_eq!(a.tls.roots, TlsRoots::System);
    assert_eq!(
        a.tls.trust_anchors[..2],
        [
            TlsSource::File("/etc/busbar/ca/corp.pem".into()),
            TlsSource::Env("CORP_CA".into())
        ]
    );
    assert!(matches!(a.tls.trust_anchors[2], TlsSource::Inline(_)));
    let d = &a.tls.destinations[0];
    assert_eq!(d.matches, "ldap.corp.internal");
    assert!(d.include_roots);
    assert_eq!(d.pin_spki_sha256.len(), 1, "one pin may be written bare");
    assert!(d.client_identity.is_some());
}

#[test]
fn a_secret_store_reference_never_feeds_the_trust_store() {
    let err = advanced("tls:\n  trust_anchors:\n    - { module: vault, settings: { path: ca } }\n")
        .expect_err("a secret-store reference is refused");
    assert!(err.contains("secret-store reference"), "{err}");
}

#[test]
fn there_is_no_key_that_skips_verification() {
    for key in ["insecure", "skip_verify", "danger_accept_invalid_certs"] {
        let err =
            advanced(&format!("tls:\n  {key}: true\n")).expect_err("no key disables verification");
        assert!(err.contains("unknown field"), "{key}: {err}");
        let err = advanced(&format!(
            "tls:\n  destinations:\n    - {{ match: a.example, {key}: true }}\n"
        ))
        .expect_err("no destination key disables verification");
        assert!(err.contains("unknown field"), "{key}: {err}");
    }
}

#[test]
fn an_unknown_roots_value_is_refused() {
    let err = advanced("tls:\n  roots: insecure\n").expect_err("roots is bundled, system or none");
    assert!(err.contains("unknown variant"), "{err}");
}

#[test]
fn the_resolved_config_carries_the_store_as_written() {
    let mut deploy = crate::config::tests::base_deploy();
    deploy.advanced = advanced(
        "tls:\n  roots: none\n  destinations:\n    - { match: db.internal, pin_spki_sha256: sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=, verify: pin }\n",
    )
    .expect("parses");
    let cfg = crate::config::resolve(&deploy, &std::collections::HashMap::new()).expect("resolve");
    assert_eq!(cfg.outbound_tls.roots, TlsRoots::None);
    assert_eq!(
        cfg.outbound_tls.destinations[0].verify,
        Some(TlsVerify::Pin)
    );
}

#[test]
fn verify_pin_parses_with_a_pin_and_is_refused_without_one() {
    let a = advanced(
        "tls:\n  destinations:\n    - { match: ldap.corp.internal, verify: pin, pin_spki_sha256: sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= }\n",
    )
    .expect("verify: pin with a pin parses");
    assert_eq!(a.tls.destinations[0].verify, Some(TlsVerify::Pin));
    let err = advanced("tls:\n  destinations:\n    - { match: ldap.corp.internal, verify: pin }\n")
        .expect_err("verify: pin without a pin is refused");
    assert!(err.contains("pin_spki_sha256"), "{err}");
}

#[test]
fn verify_takes_only_pin() {
    let err = advanced("tls:\n  destinations:\n    - { match: a.example, verify: none }\n")
        .expect_err("only `pin` is a verify value");
    assert!(err.contains("unknown variant"), "{err}");
}

#[test]
fn a_plaintext_destination_entry_is_refused_at_parse() {
    let err = advanced("tls:\n  destinations:\n    - { match: 10.0.0.5, plaintext: true }\n")
        .expect_err("plaintext: true is refused");
    assert!(err.contains("insecure_transport"), "{err}");
    advanced("tls:\n  destinations:\n    - { match: 10.0.0.5, plaintext: false }\n")
        .expect("plaintext: false still parses");
}
