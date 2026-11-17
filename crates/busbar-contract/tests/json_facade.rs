// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE JSON FACADE (`busbar_contract::json`, SERDE-NUMBERS r17 MR 3, SERDE-JSON-EXIT §1-§2): numbers
//! keep their lexemes through every reader, buffered `untagged`/`flatten` containers and YAML
//! included; a third-party type is filled in binary64 through `parse_foreign`; the error text
//! never carries the input; `SchemaCheck` keeps dev's integer-token profile; `Body` answers
//! `application/json` with the writer's bytes.

use std::collections::BTreeMap;
use std::fmt;

use busbar_contract::json::{self, JsonValueTrait};
use busbar_contract::yaml;
use serde::de::{self, IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

/// Numbers no binary64 holds: beyond `u64`, more digits than an `f64` keeps, and a tiny fraction.
const EXACT: &str =
    r#""n":18446744073709551617,"c":12345678901.1234567,"d":0.1000000000000000000001"#;

#[derive(Deserialize, Serialize)]
#[serde(untagged)]
enum Untagged {
    Object {
        n: json::Value,
        c: json::Value,
        d: json::Value,
    },
}

#[derive(Deserialize)]
struct Flattened {
    id: u32,
    #[serde(flatten)]
    rest: json::Value,
}

/// `out` holds every `"name":value` member of `members` and nothing else (member order is the
/// input's, or sorted under sonic's `sort_keys`).
fn same_members(out: &str, members: &str) {
    for member in members.split(',') {
        assert!(out.contains(member), "{member} in {out}");
    }
    assert_eq!(out.len(), members.len() + 2, "{out}");
}

/// A `json::Value` under serde's buffering (`untagged`, `flatten`) keeps every lexeme, whether the
/// document is JSON or YAML (r17 MR 3; sonic's `Value` could not be built by any deserializer but
/// its own before the fork's P1/P2).
#[test]
fn buffered_value_exact() {
    let input = format!("{{{EXACT}}}");
    let parsed: Untagged = json::parse(input.as_bytes()).expect("untagged from JSON");
    assert_eq!(json::to_string(&parsed).expect("written"), input);

    let input = format!(r#"{{"id":7,{EXACT}}}"#);
    let parsed: Flattened = json::parse(input.as_bytes()).expect("flatten from JSON");
    assert_eq!(parsed.id, 7);
    same_members(&json::to_string(&parsed.rest).expect("written"), EXACT);

    // YAML holds these numbers exactly; the tree built from YAML writes them unchanged.
    let members = r#""n":18446744073709551615,"c":-9223372036854775808,"d":0.5"#;
    let parsed: Untagged =
        yaml::from_str("n: 18446744073709551615\nc: -9223372036854775808\nd: 0.5\n")
            .expect("untagged from YAML");
    assert_eq!(
        json::to_string(&parsed).expect("written"),
        format!("{{{members}}}")
    );
    let parsed: Flattened =
        yaml::from_str("id: 7\nn: 18446744073709551615\nc: -9223372036854775808\nd: 0.5\n")
            .expect("flatten from YAML");
    assert_eq!(parsed.id, 7);
    same_members(&json::to_string(&parsed.rest).expect("written"), members);
}

#[derive(Deserialize)]
struct Settings {
    settings: json::Map,
}

/// A YAML key spelled like sonic's number token is an ordinary key: its value stays the string.
#[test]
fn yaml_settings_map_keeps_token_spelled_key() {
    let parsed: Settings =
        yaml::from_str("settings:\n  '$sonic_rs::private::JsonNumber': 'abc'\n  n: 27\n")
            .expect("settings map from YAML");
    assert_eq!(
        parsed
            .settings
            .get(&"$sonic_rs::private::JsonNumber")
            .and_then(|value| value.as_str()),
        Some("abc")
    );
    assert_eq!(
        parsed.settings.get(&"n").and_then(|value| value.as_u64()),
        Some(27)
    );
}

/// `parse_value` keeps every lexeme, and the last of duplicate keys (as serde's maps do).
#[test]
fn parse_value_keeps_lexemes_and_last_duplicate() {
    let text = r#"[1e400,18446744073709551617,0.1000000000000000000001,-0]"#;
    let value = json::parse_value(text.as_bytes()).expect("parsed");
    assert_eq!(json::to_string(&value).expect("written"), text);

    let value = json::parse_value(br#"{"a":1,"b":{"x":1,"x":2},"a":3}"#).expect("parsed");
    assert_eq!(value.get("a").and_then(|a| a.as_u64()), Some(3));
    assert_eq!(
        value
            .get("b")
            .and_then(|b| b.get("x"))
            .and_then(|x| x.as_u64()),
        Some(2)
    );
    same_members(
        &json::to_string(&value).expect("written"),
        r#""b":{"x":2},"a":3"#,
    );
}

/// `parse_typed` reads each number as a typed field does: `u64`, else `i64`, else finite `f64`.
#[test]
fn parse_typed_reads_numbers_as_typed_fields() {
    let value = json::parse_typed(b"[-0,1e3,18446744073709551615,-1,18446744073709551616,1.0]")
        .expect("typed");
    let item = |at: usize| value.get(at).expect("item");
    let zero = item(0).as_f64().expect("-0 is a float");
    assert!(zero == 0.0 && zero.is_sign_negative(), "-0 reads -0.0");
    assert!(item(1).is_f64() && item(1).as_f64() == Some(1000.0));
    assert_eq!(item(2).as_u64(), Some(u64::MAX));
    assert_eq!(item(3).as_i64(), Some(-1));
    assert!(item(4).is_f64(), "beyond u64 reads as a float");
    assert!(item(5).is_f64() && item(5).as_f64() == Some(1.0));
    assert!(
        json::parse_typed(b"[1e400]").is_err(),
        "beyond f64 is refused"
    );
}

/// `from_value` refuses a number the target cannot hold; it never answers `None` or a rounding.
#[test]
fn from_value_refuses_not_none() {
    let huge = json::parse_value(b"1e400").expect("parsed");
    assert!(json::from_value::<Option<f64>>(&huge).is_err());
    assert!(json::from_value::<f64>(&huge).is_err());
    let beyond = json::parse_value(b"18446744073709551617").expect("parsed");
    assert!(json::from_value::<u64>(&beyond).is_err());
    assert!(json::from_value::<Option<u64>>(&beyond).is_err());
    let fits = json::parse_value(b"27").expect("parsed");
    assert_eq!(json::from_value::<u64>(&fits).expect("27"), 27);
}

/// Nesting beyond the facade's bound is refused before any parser recurses, and says so.
#[test]
fn depth_error_names_nesting() {
    let deep = format!("{}{}", "[".repeat(129), "]".repeat(129));
    for error in [
        json::parse::<json::Value>(deep.as_bytes()).expect_err("too deep"),
        json::parse_value(deep.as_bytes()).expect_err("too deep"),
        json::parse_foreign::<IgnoredAny>(deep.as_bytes()).expect_err("too deep"),
    ] {
        assert!(
            error.to_string().contains("JSON nesting exceeds 128"),
            "{error}"
        );
    }
    let at_bound = format!("{}{}", "[".repeat(128), "]".repeat(128));
    assert!(json::parse_value(at_bound.as_bytes()).is_ok());
}

/// No 4-byte window of `secret` appears in `text`.
fn holds_no_part_of(text: &str, secret: &str) {
    for window in secret.as_bytes().windows(4) {
        let window = std::str::from_utf8(window).expect("ASCII secret");
        assert!(
            !text.contains(window),
            "{window:?} of the input in {text:?}"
        );
    }
}

/// S1: the facade's error text stops at sonic's position; the input fragment sonic appends after it
/// is never shown (Display and Debug alike).
#[test]
fn json_error_never_echoes_input() {
    let error = json::parse::<BTreeMap<String, u64>>(br#"{"n":"hunter2"}"#)
        .expect_err("a string is no u64");
    assert_eq!(error.line(), 1);
    let end = format!(" at line 1 column {}", error.column());
    for text in [error.to_string(), format!("{error:?}")] {
        assert!(!text.contains('\n'), "{text:?}");
        assert!(text.ends_with(&end), "{text:?}");
    }

    let error = json::parse::<json::Value>(br#"{"k":"pw8bytes"x}"#).expect_err("bad syntax");
    for text in [error.to_string(), format!("{error:?}")] {
        assert!(!text.contains('\n'), "{text:?}");
        holds_no_part_of(&text, "pw8bytes");
    }
}

/// What a deserializer handed a test-local (foreign) type.
#[derive(Debug, PartialEq)]
enum Seen {
    Unsigned(u64),
    Signed(i64),
    Float(f64),
    Map,
}

/// A type that records the first thing `deserialize_any` hands it, as a third-party type would.
#[derive(Debug, PartialEq)]
struct Record(Seen);

struct Recorder;

impl<'de> Visitor<'de> for Recorder {
    type Value = Record;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON number")
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Record, E> {
        Ok(Record(Seen::Unsigned(v)))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Record, E> {
        Ok(Record(Seen::Signed(v)))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Record, E> {
        Ok(Record(Seen::Float(v)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Record, A::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(Record(Seen::Map))
    }
}

impl<'de> Deserialize<'de> for Record {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(Recorder)
    }
}

/// `parse_foreign` hands a third-party type numbers (binary64); the exact readers hand
/// `deserialize_any` sonic's number-token map instead, which only our types read.
#[test]
fn parse_foreign_sees_numbers_not_token_maps() {
    for (text, seen) in [
        ("1", Seen::Unsigned(1)),
        ("-2", Seen::Signed(-2)),
        ("1.5", Seen::Float(1.5)),
        ("{}", Seen::Map),
    ] {
        assert_eq!(
            json::parse_foreign::<Record>(text.as_bytes()).expect("parsed"),
            Record(seen),
            "{text}"
        );
    }
    assert_eq!(
        json::parse::<Record>(b"1").expect("parsed"),
        Record(Seen::Map),
        "the exact reader hands a number to deserialize_any as the token map"
    );
}

/// `parse_foreign` reads one whole document: trailing bytes and invalid UTF-8 (even in a member no
/// one reads) are refused.
#[test]
fn parse_foreign_refuses_trailing_bytes() {
    assert!(json::parse_foreign::<IgnoredAny>(b"{} \n").is_ok());
    assert!(json::parse_foreign::<IgnoredAny>(b"{} {}").is_err());
    assert!(json::parse_foreign::<IgnoredAny>(b"1 x").is_err());
    assert!(json::parse_foreign::<IgnoredAny>(b"").is_err());
    assert!(json::parse_foreign::<IgnoredAny>(b"{\"k\":\"\xff\"}").is_err());
}

/// Dev's integer-token profile (plugin-loader `integer_token_tests`), as bytes through `SchemaCheck`.
#[cfg(feature = "schema")]
#[test]
fn schema_check_profile_matches_dev() {
    use busbar_contract::json::SchemaCheck;

    // A token is native when a typed integer field of the facade's binary64 door reads it.
    let native = |text: &str, signed: bool| {
        if signed {
            json::parse_foreign::<i64>(text.as_bytes()).is_ok()
        } else {
            json::parse_foreign::<u64>(text.as_bytes()).is_ok()
        }
    };

    // Mathematical integers versus tokens.
    for (kind, minimum, maximum) in [
        ("unsigned", "0", "18446744073709551615"),
        ("signed", "-9223372036854775808", "9223372036854775807"),
    ] {
        let signed = kind == "signed";
        let schema = format!(
            r#"{{"x-busbar-settings-profile":"integer-token-v1","type":"integer","minimum":{minimum},"maximum":{maximum},"x-busbar-integer-token":"{kind}"}}"#
        );
        let standard = SchemaCheck::new(schema.as_bytes()).expect("standard");
        let profile = SchemaCheck::with_settings_profile(schema.as_bytes()).expect("profile");
        for token in ["1.0", "1e0", "1E+0", "0.0", "0e0", "-0.0", "-0e0"] {
            assert!(standard.is_valid(token.as_bytes()), "standard: {token}");
            assert!(!profile.is_valid(token.as_bytes()), "profile: {token}");
            assert!(
                profile.validate(token.as_bytes()).is_err(),
                "validate: {token}"
            );
        }
        for token in ["0", "1", "4294967295"] {
            assert!(profile.is_valid(token.as_bytes()), "{kind}: {token}");
        }
        for token in [
            "true",
            "null",
            "\"1\"",
            "1.5",
            "18446744073709551616",
            "-9223372036854775809",
        ] {
            assert!(!profile.is_valid(token.as_bytes()), "{kind}: {token}");
        }
        assert_eq!(profile.is_valid(b"-0"), native("-0", signed), "{kind}: -0");
        assert!(profile.is_valid(b"9223372036854775807"));
        assert_eq!(profile.is_valid(b"-1"), signed);
        assert_eq!(profile.is_valid(b"18446744073709551615"), !signed);
        assert_eq!(profile.is_valid(b"-9223372036854775808"), signed);
        // An instance that does not parse is not valid (`1e400` was accepted under AP).
        assert!(!profile.is_valid(b"1e400"));
        assert!(!profile.is_valid(b"{"));
    }

    // Applicator branches keep the keyword, and non-integer members stay standard.
    let profile = SchemaCheck::with_settings_profile(
        br##"{"x-busbar-settings-profile":"integer-token-v1","$defs":{"count":{"type":"integer","minimum":0,"maximum":4294967295,"x-busbar-integer-token":"unsigned"}},"type":"object","properties":{"count":{"anyOf":[{"$ref":"#/$defs/count"},{"type":"null"}]},"ratio":{"type":"number"},"opaque":{}}}"##,
    )
    .expect("profile");
    for text in [
        r#"{"count":0,"ratio":1.0,"opaque":{"n":1e0}}"#,
        r#"{"count":null}"#,
        r#"{"count":4294967295}"#,
    ] {
        assert!(profile.is_valid(text.as_bytes()), "{text}");
    }
    for text in [
        r#"{"count":1.0}"#,
        r#"{"count":1e0}"#,
        r#"{"count":4294967296}"#,
    ] {
        assert!(!profile.is_valid(text.as_bytes()), "{text}");
    }
    // Negative zero is governed by the native reading, through $ref/anyOf too.
    let native_zero = json::parse_foreign::<u32>(b"-0").is_ok();
    assert_eq!(profile.is_valid(br#"{"count":-0}"#), native_zero);
    assert_eq!(profile.validate(br#"{"count":-0}"#).is_ok(), native_zero);
    let refusal = profile
        .validate(br#"{"count":1.5}"#)
        .expect_err("not a token");
    assert!(refusal.starts_with("/count: "), "{refusal}");

    // The keyword needs the profile, a known profile, a known kind and an integer type.
    for schema in [
        r#"{"type":"integer","x-busbar-integer-token":"unsigned"}"#,
        r#"{"x-busbar-settings-profile":"future"}"#,
        r#"{"x-busbar-settings-profile":"integer-token-v1","type":"integer","x-busbar-integer-token":true}"#,
        r#"{"x-busbar-settings-profile":"integer-token-v1","type":"number","x-busbar-integer-token":"unsigned"}"#,
    ] {
        assert!(
            SchemaCheck::with_settings_profile(schema.as_bytes()).is_err(),
            "{schema}"
        );
    }
    let standard = SchemaCheck::with_settings_profile(br#"{"type":"integer"}"#).expect("standard");
    assert!(standard.is_valid(b"1.0"));

    // Nullable integer unions.
    let profile = SchemaCheck::with_settings_profile(
        br##"{"x-busbar-settings-profile":"integer-token-v1","$defs":{"count":{"type":["integer","null"],"minimum":0,"maximum":18446744073709551615,"x-busbar-integer-token":"unsigned"}},"type":"object","properties":{"count":{"$ref":"#/$defs/count"}},"allOf":[{"if":{"required":["null_only"]},"then":{"properties":{"count":{"type":"null"}}}}]}"##,
    )
    .expect("profile");
    for text in [
        r#"{}"#,
        r#"{"count":null}"#,
        r#"{"count":0}"#,
        r#"{"count":18446744073709551615}"#,
        r#"{"count":null,"null_only":true}"#,
    ] {
        assert!(profile.is_valid(text.as_bytes()), "{text}");
    }
    for text in [
        r#"{"count":1.0}"#,
        r#"{"count":1e0}"#,
        r#"{"count":-1}"#,
        r#"{"count":18446744073709551616}"#,
        r#"{"count":1,"null_only":true}"#,
    ] {
        assert!(!profile.is_valid(text.as_bytes()), "{text}");
    }
    let nonnullable = SchemaCheck::with_settings_profile(
        br#"{"x-busbar-settings-profile":"integer-token-v1","type":"integer","x-busbar-integer-token":"unsigned"}"#,
    )
    .expect("profile");
    assert!(!nonnullable.is_valid(b"null"));
}

/// A built or edited object is written in key order whatever order it was built in (#162: the
/// workspace's sonic `sort_keys`, the order serde_json's `Map` wrote), and twice the same.
#[test]
fn built_objects_write_in_key_order() {
    let built = json::json!({
        "kilo": 1, "echo": 2, "alpha": 3, "golf": 4, "delta": 5, "juliet": 6, "bravo": 7,
        "hotel": 8, "charlie": 9, "india": 10, "foxtrot": 11,
    });
    let sorted = r#"{"alpha":3,"bravo":7,"charlie":9,"delta":5,"echo":2,"foxtrot":11,"golf":4,"hotel":8,"india":10,"juliet":6,"kilo":1}"#;
    assert_eq!(json::to_string(&built).expect("written"), sorted);

    let mut map = json::Map::new();
    for key in [
        "zulu", "mike", "alpha", "yankee", "bravo", "xray", "charlie",
    ] {
        map.insert(key, json::Value::from(key));
    }
    assert_eq!(
        json::to_string(&json::Value::from(map)).expect("written"),
        r#"{"alpha":"alpha","bravo":"bravo","charlie":"charlie","mike":"mike","xray":"xray","yankee":"yankee","zulu":"zulu"}"#
    );

    // `parse_value` edits every object (its duplicate-key pass), so its trees are in key order too.
    let read = json::parse_value(br#"{"z":{"y":1,"b":2},"a":[{"d":1,"c":2}]}"#).expect("parsed");
    assert_eq!(
        json::to_string(&read).expect("written"),
        r#"{"a":[{"c":2,"d":1}],"z":{"b":2,"y":1}}"#
    );
}

/// `to_value`, the pretty writers and `to_writer` agree with `to_vec`; `number_text` is the lexeme.
#[test]
fn to_value_pretty_writer_and_number_text() {
    #[derive(Serialize)]
    struct Row {
        name: &'static str,
        count: u64,
        exact: json::Value,
    }
    let exact = json::parse_value(b"18446744073709551617").expect("parsed");
    let row = Row {
        name: "n",
        count: 7,
        exact,
    };
    let compact = r#"{"count":7,"exact":18446744073709551617,"name":"n"}"#;
    let tree = json::to_value(&row).expect("tree");
    assert_eq!(json::to_string(&tree).expect("written"), compact);
    assert_eq!(tree.get("count").and_then(|n| n.as_u64()), Some(7));

    let mut streamed = Vec::new();
    json::to_writer(&mut streamed, &tree).expect("streamed");
    assert_eq!(streamed, compact.as_bytes());

    let pretty = "{\n  \"count\": 7,\n  \"exact\": 18446744073709551617,\n  \"name\": \"n\"\n}";
    assert_eq!(json::to_string_pretty(&tree).expect("pretty"), pretty);
    assert_eq!(
        json::to_vec_pretty(&tree).expect("pretty"),
        pretty.as_bytes()
    );

    assert_eq!(
        json::number_text(tree.get("exact").expect("member")).as_deref(),
        Some("18446744073709551617")
    );
    assert_eq!(
        json::number_text(&json::Value::from(7_u64)).as_deref(),
        Some("7")
    );
    assert_eq!(json::number_text(&json::Value::from("7")), None);
}

/// `pointer` / `pointer_mut` read RFC 6901 as serde_json's `Value::pointer` did: `""` is the whole
/// tree, `~1` and `~0` unescape, an array index has no sign and no leading zero.
#[test]
fn pointer_reads_rfc_6901() {
    let mut tree = json::json!({"a": {"b/c": [10, {"~d": true}]}, "": 1});
    assert_eq!(json::pointer(&tree, ""), Some(&tree.clone()));
    assert_eq!(
        json::pointer(&tree, "/a/b~1c/0").and_then(|n| n.as_u64()),
        Some(10)
    );
    assert_eq!(
        json::pointer(&tree, "/a/b~1c/1/~0d").and_then(|b| b.as_bool()),
        Some(true)
    );
    assert_eq!(json::pointer(&tree, "/").and_then(|n| n.as_u64()), Some(1));
    for absent in [
        "a",
        "/a/b~1c/01",
        "/a/b~1c/+1",
        "/a/b~1c/2",
        "/a/x",
        "/a/b~1c/0/z",
    ] {
        assert!(json::pointer(&tree, absent).is_none(), "{absent}");
    }
    *json::pointer_mut(&mut tree, "/a/b~1c/0").expect("slot") = json::json!(11);
    assert_eq!(
        json::pointer(&tree, "/a/b~1c/0").and_then(|n| n.as_u64()),
        Some(11)
    );
    assert!(json::pointer_mut(&mut tree, "/a/missing").is_none());
}
