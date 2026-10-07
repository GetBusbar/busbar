// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The static styles, ported from the identity unit's `egress_auth/tests.rs` in the kernel and
//! `declared_tests.rs`: the same vectors, now asserted on the headers the plugin builds.

use super::*;
use busbar_contract::header::is_legal_header_value;

/// Keys, and whether the wire admits them (the `HeaderValue::from_str` rule).
const KEY_VECTORS: &[(&str, bool)] = &[
    ("sk-test-123", true),
    ("", true),
    ("sk\tkey", true),
    ("klucz-\u{142}-\u{e9}", true),
    ("sk\r\ninjected", false),
    ("sk\nkey", false),
    ("sk\u{0}key", false),
    ("sk\u{1}key", false),
    ("sk\u{7f}key", false),
];

/// Bearer: `authorization: Bearer <key>` for every key the wire admits, nothing for the rest.
#[test]
fn bearer_builder_presents_every_admitted_key_and_omits_the_rest() {
    for &(key, legal) in KEY_VECTORS {
        let expected = if legal {
            vec![("authorization".to_string(), format!("Bearer {key}"))]
        } else {
            Vec::new()
        };
        assert_eq!(bearer_auth_headers(key), expected, "key {key:?}");
        assert_eq!(
            StaticScheme::uniform(Presentation::BEARER).present(key, Mode::Own),
            expected,
            "the bearer style, key {key:?}"
        );
    }
}

/// The custom-header builder carries the raw key verbatim under the declared name, with the same
/// omission rule, and the style presents exactly the builder's bytes.
#[test]
fn custom_header_builder_presents_the_raw_key_under_its_own_name() {
    for &(key, legal) in KEY_VECTORS {
        let built = api_key_auth_headers("x-goog-api-key", key);
        let expected = if legal {
            vec![("x-goog-api-key".to_string(), key.to_string())]
        } else {
            Vec::new()
        };
        assert_eq!(built, expected, "builder, key {key:?}");
        assert_eq!(
            StaticScheme::uniform(Presentation::raw("x-goog-api-key")).present(key, Mode::Own),
            built,
            "the x-goog-api-key style, key {key:?}"
        );
    }
}

/// `api-key` and `x-goog-api-key` never cross-contaminate each other's header name.
#[test]
fn the_two_custom_header_styles_keep_their_own_names() {
    assert_eq!(
        StaticScheme::uniform(Presentation::raw("api-key")).present("azure-key-xyz", Mode::Own),
        vec![("api-key".to_string(), "azure-key-xyz".to_string())]
    );
    assert_eq!(
        StaticScheme::uniform(Presentation::raw("x-goog-api-key")).present("goog-key", Mode::Own),
        vec![("x-goog-api-key".to_string(), "goog-key".to_string())]
    );
}

/// A raw-header key carrying CR/LF is a header-split request smuggled upstream: the style omits it.
#[test]
fn a_custom_header_style_omits_a_key_with_crlf_in_it() {
    for (header, secret) in [
        ("api-key", "azure-key-\r\nX-Forwarded-For: 10.0.0.1"),
        ("x-goog-api-key", "goog-key-\r\ninjected"),
        ("api-key", "azure-key-\u{0}-nul"),
    ] {
        assert!(
            StaticScheme::uniform(Presentation::raw(header))
                .present(secret, Mode::Own)
                .is_empty(),
            "{header} put an un-encodable key on the wire"
        );
    }
}

/// The legality rule is the `HeaderValue::from_str` rule, written out over every ASCII byte
/// ([`busbar_contract::header::is_legal_header_value`], a shared pure helper this crate uses
/// alongside busbar-auth-sigv4/-oauth).
#[test]
fn header_value_rule_is_the_header_value_type_rule() {
    for b in 0u8..=0x7F {
        let refused = (b < 0x20 && b != b'\t') || b == 0x7F;
        let s = format!("k{}k", b as char);
        assert_eq!(is_legal_header_value(&s), !refused, "byte {b:#04x}");
    }
    for &(key, legal) in KEY_VECTORS {
        assert_eq!(is_legal_header_value(key), legal, "key {key:?}");
    }
}

/// A dialect's credential-family table (as a dialect declares one): an API key
/// presents as `x-api-key` with its leading whitespace trimmed, an OAuth token as a bearer, and a
/// credential of neither family by the mode — own as `x-api-key`, a caller's as a bearer.
fn family_scheme() -> StaticScheme {
    StaticScheme {
        families: vec![
            Family {
                prefix: "sk-ant-api".to_string(),
                presented: Presentation {
                    header: Some("x-api-key".to_string()),
                    trim_start: true,
                },
            },
            Family {
                prefix: "sk-ant-oat".to_string(),
                presented: Presentation::BEARER,
            },
        ],
        own: Presentation::raw("x-api-key"),
        passthrough: Presentation::BEARER,
    }
}

#[test]
fn a_family_table_presents_by_prefix_then_by_mode() {
    let s = family_scheme();
    assert_eq!(
        s.present("  sk-ant-api03-abc", Mode::Own),
        vec![("x-api-key".to_string(), "sk-ant-api03-abc".to_string())],
        "an API key: x-api-key, leading whitespace trimmed"
    );
    assert_eq!(
        s.present("sk-ant-api03-abc", Mode::Passthrough),
        vec![("x-api-key".to_string(), "sk-ant-api03-abc".to_string())],
        "the family decides whatever the mode"
    );
    assert_eq!(
        s.present("sk-ant-oat01-xyz", Mode::Own),
        vec![(
            "authorization".to_string(),
            "Bearer sk-ant-oat01-xyz".to_string()
        )]
    );
    assert_eq!(
        s.present("other", Mode::Own),
        vec![("x-api-key".to_string(), "other".to_string())],
        "no family, own: the own presentation"
    );
    assert_eq!(
        s.present("other", Mode::Passthrough),
        vec![("authorization".to_string(), "Bearer other".to_string())],
        "no family, a caller's: the passthrough presentation"
    );
}

/// The family table reads as settings data, exactly the shape the kernel resolves at seal.
#[test]
fn a_family_table_reads_from_settings_json() {
    let families: Vec<Family> = serde_json::from_str(
        r#"[{"prefix":"sk-ant-api","header":"x-api-key","trim_start":true},{"prefix":"sk-ant-oat"}]"#,
    )
    .expect("the family table parses");
    assert_eq!(families, family_scheme().families);
}

/// THE DIFFERENTIAL OVER THE SHARED FIXTURE (ported from the kernel's deleted
/// `egress_auth/tests/prebuilt_auth_tests.rs`: `each_twin_carries_the_fixture_scheme_of_its_dialect`,
/// `each_declared_scheme_presents_what_its_dialect_builder_wrote`,
/// `a_static_credential_is_presented_verbatim_or_omitted_never_emptied`; ARCHITECT F25 ruling
/// 2026-10-07). `testing/plane-copies/declared-credentials.json` records, for every static dialect,
/// the scheme it declares (the declaring plane's own suite holds each real declaration to it,
/// `codec/tests/proto/declared_scheme_tests.rs`) and the credential headers that dialect's own 1.5.5
/// builder wrote, per credential and mode. Presented under each recorded scheme, this plugin writes
/// exactly those headers, in order — a credential no header value may carry is omitted, never sent
/// empty. The two halves together are the byte-identity proof of the presentation.
#[test]
fn every_static_dialects_recorded_credential_is_presented_as_its_builder_wrote() {
    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }
    fn presentation(v: &serde_json::Value) -> Presentation {
        if v["bearer"] == true {
            Presentation::BEARER
        } else {
            Presentation {
                header: Some(v["header"].as_str().expect("header").to_string()),
                trim_start: v["trim_start"].as_bool().expect("trim_start"),
            }
        }
    }
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testing/plane-copies/declared-credentials.json"
    );
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("the fixture")).expect("JSON");
    let mut compared = 0;
    for row in doc["rows"].as_array().expect("rows") {
        let dialect = row["dialect"].as_str().expect("dialect");
        let scheme = &doc["schemes"][dialect];
        if scheme["kind"] != "static" {
            continue;
        }
        let scheme = StaticScheme {
            families: scheme["families"]
                .as_array()
                .expect("families")
                .iter()
                .map(|f| Family {
                    prefix: f["prefix"].as_str().expect("prefix").to_string(),
                    presented: presentation(&f["presented_as"]),
                })
                .collect(),
            own: presentation(&scheme["own"]),
            passthrough: presentation(&scheme["passthrough"]),
        };
        let key = String::from_utf8(unhex(row["key_hex"].as_str().expect("key"))).expect("utf-8");
        let mode = if row["mode"] == "own" {
            Mode::Own
        } else {
            Mode::Passthrough
        };
        let presented: Vec<serde_json::Value> = scheme
            .present(&key, mode)
            .into_iter()
            .map(|(k, v)| {
                let hex: String = v.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
                serde_json::json!([k, hex])
            })
            .collect();
        assert_eq!(
            serde_json::Value::Array(presented),
            row["headers"],
            "{dialect}: key {key:?}, mode {}",
            row["mode"]
        );
        compared += 1;
    }
    assert_eq!(
        compared, 220,
        "every static dialect's recorded row was presented"
    );
}
