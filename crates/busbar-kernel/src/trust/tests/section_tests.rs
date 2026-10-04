// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kernel reads a plane's declared trust keys and refuses a bad pin or a bad cadence with the
//! exact sentence the plane spoke before the keys moved. The plane here is one busbar does not
//! have, with its own key names and tokens, so nothing below is true of one instance only.

use busbar_contract::plane::{PinMechanismDecl, TrustKeyDecl, TrustRole};

use super::{judge_entry, parse_entry, parse_section, DeclaredPin};
use crate::trust::reverify::Policy;

const MECHANISMS: &[PinMechanismDecl] = &[
    PinMechanismDecl {
        token: "sealed_key",
        root: true,
        peer_key: false,
    },
    PinMechanismDecl {
        token: "open",
        root: false,
        peer_key: false,
    },
];

const KEYS: &[TrustKeyDecl] = &[
    TrustKeyDecl {
        key: "anchor",
        role: TrustRole::Pin,
        fingerprint: true,
        default: None,
        mechanisms: MECHANISMS,
    },
    TrustKeyDecl {
        key: "recheck_after",
        role: TrustRole::ReverifyTtl,
        fingerprint: false,
        default: Some("5s"),
        mechanisms: &[],
    },
    TrustKeyDecl {
        key: "calm_down",
        role: TrustRole::RecoveryBackoff,
        fingerprint: false,
        default: Some("15m"),
        mechanisms: &[],
    },
];

fn entry(yaml: &str) -> serde_yaml::Value {
    serde_yaml::from_str(yaml).expect("test yaml parses")
}

fn refusal(yaml: &str) -> String {
    parse_entry("`bays.dock`", &entry(yaml), KEYS).expect_err("the kernel must refuse this entry")
}

#[test]
fn a_rooted_mechanism_with_no_key_is_refused_by_the_kernel() {
    for yaml in [
        "anchor: { mechanism: sealed_key }",
        "anchor: { mechanism: sealed_key, key: \"   \" }",
    ] {
        assert_eq!(
            refusal(yaml),
            "`bays.dock`: `anchor.mechanism: sealed_key` needs `anchor.key:` — the out-of-band \
             material this registration is verified against. A pin with nothing to verify with is \
             not a pin."
        );
    }
}

#[test]
fn the_no_root_mechanism_carrying_a_key_is_refused_by_the_kernel() {
    assert_eq!(
        refusal("anchor: { mechanism: open, key: k }"),
        "`bays.dock`: `anchor.mechanism: open` must not carry `anchor.key:`. `open` means there is \
         no authenticity root; key material that is never verified against reads to an operator \
         as protection that does not exist. Name the real mechanism, or drop the key."
    );
}

#[test]
fn a_bad_cadence_is_refused_by_the_kernel() {
    assert_eq!(
        refusal("recheck_after: \"5\""),
        "`bays.dock`: `recheck_after:` duration needs a unit (s|m|h|d), e.g. 7d"
    );
    assert_eq!(
        refusal("recheck_after: soon"),
        "`bays.dock`: `recheck_after:` invalid duration 'soon': expected <number><s|m|h|d>"
    );
    assert_eq!(
        refusal("calm_down: 5x"),
        "`bays.dock`: `calm_down:` invalid duration unit 'x': use s|m|h|d"
    );
}

#[test]
fn a_pin_the_declaration_does_not_describe_is_refused() {
    assert_eq!(
        refusal("anchor: { mechanism: nope, key: k }"),
        "`bays.dock`: `anchor.mechanism: nope` is not one of `sealed_key`, `open`"
    );
    assert_eq!(
        refusal("anchor: { key: k }"),
        "`bays.dock`: `anchor.mechanism:` is required: name the authenticity root this \
         registration has"
    );
    assert_eq!(
        refusal("anchor: sealed_key"),
        "`bays.dock`: `anchor:` must be a pin object naming its `mechanism:`"
    );
    assert_eq!(
        refusal("anchor: { mechanism: open, colour: red }"),
        "`bays.dock`: `anchor.colour:` is not a field of `anchor:`"
    );
}

#[test]
fn a_fingerprint_is_a_pin_field_only_where_the_declaration_allows_one() {
    let no_fingerprint: Vec<TrustKeyDecl> = KEYS
        .iter()
        .map(|k| TrustKeyDecl {
            fingerprint: false,
            ..*k
        })
        .collect();
    let e = entry("anchor: { mechanism: sealed_key, key: k, fingerprint: f }");
    assert_eq!(
        parse_entry("`bays.dock`", &e, &no_fingerprint).unwrap_err(),
        "`bays.dock`: `anchor.fingerprint:` is not a field of `anchor:`"
    );
    let parsed = parse_entry("`bays.dock`", &e, KEYS).expect("allowed here");
    assert_eq!(parsed.pin.and_then(|p| p.fingerprint).as_deref(), Some("f"));
}

#[test]
fn a_good_entry_yields_its_pin_and_cadence() {
    let parsed = parse_entry(
        "`bays.dock`",
        &entry("anchor: { mechanism: sealed_key, key: K }\nrecheck_after: 0s\ncalm_down: 2m"),
        KEYS,
    )
    .expect("a well-formed entry parses");
    assert_eq!(
        parsed.pin,
        Some(DeclaredPin {
            mechanism: "sealed_key".into(),
            root: true,
            peer_key: false,
            key: Some("K".into()),
            fingerprint: None,
        })
    );
    assert_eq!(
        parsed.policy,
        Policy {
            ttl_ms: 0,
            recovery_backoff_ms: 120_000,
        }
    );
}

#[test]
fn an_absent_or_null_key_takes_the_declared_default() {
    for yaml in ["url: x", "recheck_after: ~\ncalm_down: ~"] {
        let parsed = parse_entry("`bays.dock`", &entry(yaml), KEYS).expect("defaults apply");
        assert_eq!(parsed.pin, None);
        assert_eq!(
            parsed.policy,
            Policy {
                ttl_ms: 5_000,
                recovery_backoff_ms: 900_000,
            }
        );
    }
    // A plane that declares no default for a key reads its absence as zero.
    let parsed = parse_entry("`bays.dock`", &entry("url: x"), &[]).expect("no keys, no rules");
    assert_eq!(
        parsed.policy,
        Policy {
            ttl_ms: 0,
            recovery_backoff_ms: 0,
        }
    );
}

#[test]
fn a_section_is_read_per_registration_skipping_the_reserved_words() {
    let section = entry(
        "hooks: [h]\nupstream_credentials: own\n\
         a:\n  anchor: { mechanism: open }\n\
         b:\n  anchor: { mechanism: sealed_key, key: K }\n  recheck_after: 1m\n",
    );
    let book = parse_section("bays", &section, KEYS).expect("the section parses");
    assert_eq!(book.keys().collect::<Vec<_>>(), ["a", "b"]);
    assert_eq!(book["b"].policy.ttl_ms, 60_000);

    let bad = entry("a:\n  anchor: { mechanism: open }\nb:\n  recheck_after: never\n");
    assert_eq!(
        parse_section("bays", &bad, KEYS).unwrap_err(),
        "`bays.b`: `recheck_after:` invalid duration 'never': expected <number><s|m|h|d>"
    );
}

/// Before the plane parses its section, the kernel judges only VALUES: a malformed shape is left for
/// the plane's own parse to refuse in its own words, while a value rule still fires.
#[test]
fn the_pre_parse_judgement_leaves_a_malformed_shape_to_the_plane() {
    for yaml in [
        "anchor: sealed_key",
        "anchor: { mechanism: nope }",
        "anchor: { key: k }",
        "anchor: { mechanism: open, colour: red }",
        "anchor: { mechanism: [x] }",
        "recheck_after: 5",
    ] {
        judge_entry("`bays.dock`", &entry(yaml), KEYS)
            .unwrap_or_else(|e| panic!("`{yaml}` is the plane's to refuse, got: {e}"));
    }
    assert_eq!(
        judge_entry(
            "`bays.dock`",
            &entry("anchor: { mechanism: sealed_key }"),
            KEYS
        )
        .unwrap_err(),
        refusal("anchor: { mechanism: sealed_key }")
    );
    assert_eq!(
        judge_entry("`bays.dock`", &entry("calm_down: 5x"), KEYS).unwrap_err(),
        "`bays.dock`: `calm_down:` invalid duration unit 'x': use s|m|h|d"
    );
}
