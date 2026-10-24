// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::{decode, encode, stated, Key, ProviderKeys, Shape, Table, EXT_PROVIDER_KEYS};
use crate::abi::mechanism::extensions;

fn key(name: &str, shape: Shape, required: bool) -> Key {
    Key {
        name: name.to_string(),
        shape,
        required,
        rank: None,
    }
}

/// A descriptor naming every one of the seven neutral shapes, nested where a shape nests.
fn every_shape() -> ProviderKeys {
    let nested = Table {
        deny_unknown: true,
        keys: vec![
            key("globs", Shape::List(Box::new(Shape::Str)), true),
            key(
                "speed",
                Shape::OneOf(vec!["slow".into(), "fast".into()]),
                false,
            ),
        ],
        expecting: None,
    };
    ProviderKeys {
        catalog: Table {
            deny_unknown: false,
            keys: vec![
                key("color", Shape::Str, true),
                key("weights", Shape::StrMap, false),
                key("count", Shape::Int, false),
                key("on", Shape::Bool, false),
                key(
                    "rules",
                    Shape::List(Box::new(Shape::Table(nested.clone()))),
                    false,
                ),
            ],
            expecting: None,
        },
        deployment: Table {
            deny_unknown: true,
            keys: vec![
                key("color", Shape::Str, false),
                key("inner", Shape::Table(nested), false),
            ],
            expecting: None,
        },
        entry: Table {
            deny_unknown: true,
            keys: vec![key("weights", Shape::StrMap, true)],
            expecting: None,
        },
        limits: None,
        pool_member: None,
    }
}

/// THE DESCRIPTOR ROUND-TRIPS: what is encoded decodes to the same descriptor, every shape, every
/// flag and every key order kept; and a descriptor written by hand decodes to what its encoding
/// decodes to.
#[test]
fn a_descriptor_round_trips_through_its_encoding() {
    let keys = every_shape();
    assert_eq!(decode(&encode(&keys)), Ok(keys));

    let written = br#"{
        "catalog": {"deny_unknown": false, "keys": [
            {"name": "b", "shape": {"one-of": ["y", "x"]}, "required": true},
            {"name": "a", "shape": {"list": {"table": {"deny_unknown": true, "keys": []}}}, "required": false}
        ]},
        "deployment": {"deny_unknown": true, "keys": []},
        "entry": {"deny_unknown": true, "keys": [{"name": "c", "shape": "int", "required": false}]}
    }"#;
    let read = decode(written).expect("a written descriptor decodes");
    assert_eq!(
        read.catalog
            .keys
            .iter()
            .map(|k| k.name.as_str())
            .collect::<Vec<_>>(),
        ["b", "a"],
        "the written key order is kept"
    );
    assert_eq!(
        read.catalog.keys[0].shape,
        Shape::OneOf(vec!["y".into(), "x".into()])
    );
    assert_eq!(decode(&encode(&read)), Ok(read));
}

/// A STATEMENT'S EXTENSIONS carry the descriptor under the one key, beside keys the reader passes
/// over; extensions that state no descriptor state none.
#[test]
fn the_descriptor_is_read_off_the_one_extensions_key() {
    let keys = every_shape();
    let bytes = encode(&keys);
    let blob = extensions::encode(&[("other", b"x"), (EXT_PROVIDER_KEYS, &bytes)]);
    assert_eq!(stated(&blob), Ok(Some(keys)));
    assert_eq!(stated(&extensions::encode(&[("other", b"x")])), Ok(None));
    assert_eq!(stated(&[]), Ok(None));
    let bad = extensions::encode(&[(EXT_PROVIDER_KEYS, b"not json")]);
    assert!(stated(&bad).is_err());
}

/// RED: A DESCRIPTOR NAMING A SHAPE OUTSIDE THE NEUTRAL VOCABULARY IS REFUSED, as a word and as a
/// shape object alike, at any depth, and the refusal names the word and the vocabulary.
#[test]
fn a_non_neutral_shape_word_is_refused() {
    let with_shape = |shape: &str| {
        format!(
            r#"{{"catalog": {{"deny_unknown": false, "keys": [{{"name": "k", "shape": {shape}, "required": false}}]}},
                "deployment": {{"deny_unknown": true, "keys": []}},
                "entry": {{"deny_unknown": true, "keys": []}}}}"#
        )
    };
    for (shape, word) in [
        (r#""secret""#, "secret"),
        (r#""string""#, "string"),
        (r#""duration""#, "duration"),
        (r#"{"enum": ["a", "b"]}"#, "enum"),
        (r#"{"list": "url"}"#, "url"),
        (
            r#"{"table": {"deny_unknown": true, "keys": [{"name": "n", "shape": "float", "required": false}]}}"#,
            "float",
        ),
    ] {
        let err = decode(with_shape(shape).as_bytes())
            .expect_err("a shape outside the neutral vocabulary is refused");
        assert!(
            err.contains(&format!(
                "the shape `{word}`, which is not a neutral shape word"
            )),
            "{shape}: {err}"
        );
        assert!(
            err.contains("str, one-of, int, u32, u64, usize, bool, list, str-map, table"),
            "{err}"
        );
    }
    // Each neutral word is accepted where the same position refused the others.
    for shape in [
        r#""str""#,
        r#""int""#,
        r#""u32""#,
        r#""u64""#,
        r#""usize""#,
        r#""bool""#,
        r#""str-map""#,
    ] {
        assert!(decode(with_shape(shape).as_bytes()).is_ok(), "{shape}");
    }
}

/// THE ENCODING IS CLOSED: an unstated member, a missing member, a key named twice in one table and
/// an empty or repeated `one-of` are each refused.
#[test]
fn the_encoding_states_exactly_its_members() {
    let tables = |catalog: &str| {
        format!(
            r#"{{"catalog": {catalog}, "deployment": {{"deny_unknown": true, "keys": []}}, "entry": {{"deny_unknown": true, "keys": []}}}}"#
        )
    };
    for (catalog, why) in [
        (
            r#"{"deny_unknown": false, "keys": [], "extra": 1}"#,
            "`extra`",
        ),
        (r#"{"keys": []}"#, "`deny_unknown`"),
        (
            r#"{"deny_unknown": false, "keys": [{"name": "k", "shape": "str", "required": false}, {"name": "k", "shape": "int", "required": true}]}"#,
            "the key `k` twice",
        ),
        (
            r#"{"deny_unknown": false, "keys": [{"name": "k", "shape": {"one-of": []}, "required": false}]}"#,
            "lists no word",
        ),
        (
            r#"{"deny_unknown": false, "keys": [{"name": "k", "shape": {"one-of": ["a", "a"]}, "required": false}]}"#,
            "lists `a` twice",
        ),
        (
            r#"{"deny_unknown": false, "keys": [{"name": "", "shape": "str", "required": false}]}"#,
            "non-empty string",
        ),
        (
            r#"{"deny_unknown": false, "keys": [{"name": "k", "shape": "str"}]}"#,
            "`required`",
        ),
    ] {
        let err = decode(tables(catalog).as_bytes()).expect_err(why);
        assert!(err.contains(why), "{why}: {err}");
    }
    assert!(decode(br#"{"catalog": {"deny_unknown": false, "keys": []}}"#).is_err());
}

// ── arch-audit u29 F2 (coordinator rulings): rank, widths, `expecting`, the limits and pool-member forms ──

/// A descriptor stating every member the u29 F2 ruling adds: a ranked key, the three unsigned
/// widths, a table's `expecting`, and the `limits` and `pool_member` forms.
fn with_rulings() -> ProviderKeys {
    let ranked = |name: &str, shape: Shape, rank: u16| Key {
        rank: Some(rank),
        ..key(name, shape, false)
    };
    let mut keys = every_shape();
    keys.deployment.keys.push(ranked("budget", Shape::U32, 13));
    keys.catalog.keys[4] = key(
        "rules",
        Shape::List(Box::new(Shape::Table(Table {
            deny_unknown: true,
            keys: vec![key("globs", Shape::List(Box::new(Shape::Str)), true)],
            expecting: Some("struct Rule".into()),
        }))),
        false,
    );
    keys.limits = Some(Table {
        deny_unknown: true,
        keys: vec![
            ranked("cap", Shape::U32, 14),
            ranked("budgets", Shape::Table(Table::default()), 15),
        ],
        expecting: None,
    });
    keys.pool_member = Some(Table {
        deny_unknown: true,
        keys: vec![
            ranked("window", Shape::Usize, 3),
            key("huge", Shape::U64, false),
        ],
        expecting: None,
    });
    keys
}

/// THE RULED MEMBERS ROUND-TRIP (RED before they existed: a descriptor stating any of them was
/// refused as a member the encoding does not state).
#[test]
fn the_ruled_members_round_trip() {
    let keys = with_rulings();
    assert_eq!(decode(&encode(&keys)), Ok(keys));
    let written = br#"{
        "catalog": {"deny_unknown": false, "keys": [], "expecting": "struct Entry"},
        "deployment": {"deny_unknown": true, "keys": [
            {"name": "n", "shape": "u64", "required": false, "rank": 2},
            {"name": "m", "shape": "usize", "required": true}
        ]},
        "entry": {"deny_unknown": true, "keys": []},
        "pool_member": {"deny_unknown": true, "keys": [{"name": "w", "shape": "u32", "required": false, "rank": 0}]}
    }"#;
    let read = decode(written).expect("a written descriptor with the ruled members decodes");
    assert_eq!(read.catalog.expecting.as_deref(), Some("struct Entry"));
    assert_eq!(read.deployment.keys[0].rank, Some(2));
    assert_eq!(read.deployment.keys[0].shape, Shape::U64);
    assert_eq!(read.deployment.keys[1].rank, None);
    assert_eq!(read.deployment.keys[1].shape, Shape::Usize);
    assert_eq!(read.limits, None);
    assert_eq!(
        read.pool_member
            .map(|t| (t.keys[0].shape.clone(), t.keys[0].rank)),
        Some((Shape::U32, Some(0)))
    );
}

/// A DESCRIPTOR STATING NONE OF THE RULED MEMBERS ENCODES AS IT DID: every optional member is
/// written only when stated, so a plane's descriptor is unchanged until it states one.
#[test]
fn a_descriptor_stating_no_ruled_member_encodes_without_them() {
    let bytes = String::from_utf8(encode(&every_shape())).expect("UTF-8");
    for member in ["\"rank\"", "\"expecting\"", "\"limits\"", "\"pool_member\""] {
        assert!(!bytes.contains(member), "{member} in {bytes}");
    }
}

/// THE RULED MEMBERS ARE CHECKED: a rank outside `u16`, an empty or non-string `expecting`, a
/// limits form that is no table, and a member no form states are each refused.
#[test]
fn a_malformed_ruled_member_is_refused() {
    let base = |deployment: &str, extra: &str| {
        format!(
            r#"{{"catalog": {{"deny_unknown": false, "keys": []}}, "deployment": {deployment},
                "entry": {{"deny_unknown": true, "keys": []}}{extra}}}"#
        )
    };
    for (why, doc) in [
        (
            "a rank over u16",
            base(
                r#"{"deny_unknown": true, "keys": [{"name": "n", "shape": "str", "required": false, "rank": 70000}]}"#,
                "",
            ),
        ),
        (
            "an empty expecting",
            base(r#"{"deny_unknown": true, "keys": [], "expecting": ""}"#, ""),
        ),
        (
            "a limits form that is no table",
            base(r#"{"deny_unknown": true, "keys": []}"#, r#", "limits": 7"#),
        ),
        (
            "an unknown form",
            base(r#"{"deny_unknown": true, "keys": []}"#, r#", "routes": {}"#),
        ),
        (
            "an unknown key member",
            base(
                r#"{"deny_unknown": true, "keys": [{"name": "n", "shape": "u128", "required": false}]}"#,
                "",
            ),
        ),
    ] {
        assert!(decode(doc.as_bytes()).is_err(), "{why}");
    }
}
