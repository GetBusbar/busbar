// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! YAML keeps the meaning 1.5.5 gave a configuration file.
//!
//! 1.5.5 read YAML with serde_yaml_ng 0.10 on libyaml: YAML 1.1 syntax with a resolver close to
//! YAML 1.2 Core. busbar now reads it with serde-saphyr, a YAML 1.2 parser whose defaults differ.
//! Each test pins one spelling from the YAML-1.1-versus-1.2 table (YAML-LADDER.md) to the meaning
//! 1.5.5 gave it, through `busbar_contract::yaml`, the one place the parser options are set.

use busbar_contract::yaml::{self, prelude::*};
use serde::Deserialize;

fn tree(text: &str) -> Value {
    yaml::from_str(text).expect("valid YAML")
}

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

#[derive(Debug, Deserialize)]
struct Flag {
    #[allow(dead_code)]
    flag: bool,
}

#[derive(Debug, Deserialize, PartialEq)]
struct Named {
    name: String,
}

/// Rows 1 and 3: `yes`, `no`, `on`, `off`, `y`, `n`, in any case, were strings in 1.5.5.
#[test]
fn yaml_1_1_booleans_are_strings() {
    for word in [
        "yes", "no", "on", "off", "y", "n", "Yes", "NO", "On", "OFF", "Y", "N",
    ] {
        let doc = tree(&format!("k: {word}\n"));
        assert_eq!(doc.at("k"), &text(word), "`{word}` must stay a string");
    }
}

/// Rows 1 and 3: into a `bool` field the same spellings were a load error in 1.5.5.
#[test]
fn yaml_1_1_booleans_are_refused_for_bool_fields() {
    for word in ["yes", "no", "on", "off", "y", "n", "Yes", "ON"] {
        assert!(
            yaml::from_str::<Flag>(&format!("flag: {word}\n")).is_err(),
            "`flag: {word}` must be refused, as 1.5.5 refused it"
        );
    }
}

/// Row 2: the YAML 1.2 Core spellings stay booleans.
#[test]
fn core_booleans_stay_booleans() {
    for (word, b) in [
        ("true", true),
        ("True", true),
        ("TRUE", true),
        ("false", false),
        ("False", false),
        ("FALSE", false),
    ] {
        assert_eq!(tree(&format!("k: {word}\n")).at("k"), &Value::Bool(b));
    }
}

/// Row 5: integers with redundant leading zeros were strings in 1.5.5, never octal or decimal.
#[test]
fn leading_zero_integers_are_strings() {
    for word in ["0644", "0755", "-007", "+00", "00", "007"] {
        let doc = tree(&format!("mode: {word}\n"));
        assert_eq!(doc.at("mode"), &text(word), "`{word}` must stay a string");
    }
}

/// Row 5: a leading-zero spelling into a `String` field keeps its digits.
#[test]
fn leading_zero_integers_keep_their_digits_in_string_fields() {
    let read: Named = yaml::from_str("name: 0644\n").unwrap();
    assert_eq!(read.name, "0644");
}

/// Rows 6 and 7: explicit radix prefixes stay integers.
#[test]
fn radix_prefixed_integers_stay_integers() {
    assert_eq!(tree("k: 0o17\n").at("k").as_u64(), Some(15));
    assert_eq!(tree("k: 0x1F\n").at("k").as_u64(), Some(31));
    assert_eq!(tree("k: 0\n").at("k").as_u64(), Some(0));
    assert_eq!(tree("k: 644\n").at("k").as_u64(), Some(644));
}

/// Row 9: numbers with underscores were strings in 1.5.5.
#[test]
fn underscored_numbers_are_strings() {
    for word in ["1_000", "0xFF_FF"] {
        assert_eq!(tree(&format!("k: {word}\n")).at("k"), &text(word));
    }
}

/// Row 10: sexagesimal spellings were strings in 1.5.5.
#[test]
fn sexagesimal_spellings_are_strings() {
    for word in ["1:30", "190:20:30", "12:00"] {
        assert_eq!(tree(&format!("k: {word}\n")).at("k"), &text(word));
    }
}

/// Row 12: `.inf`, `-.inf` and `.nan` were floats in an untyped section.
#[test]
fn non_finite_floats_are_floats() {
    assert_eq!(tree("k: .inf\n").at("k"), &Value::Float(f64::INFINITY));
    assert_eq!(tree("k: -.inf\n").at("k"), &Value::Float(f64::NEG_INFINITY));
    assert!(tree("k: .nan\n").at("k").as_f64().is_some_and(f64::is_nan));
}

/// Row 16: `<<` was a literal key in 1.5.5; merge keys are not expanded.
#[test]
fn merge_key_is_a_literal_key() {
    let doc = tree("base: &base {a: 1}\nitem: {<<: *base, b: 2}\n");
    let item = doc.at("item").as_mapping().expect("a mapping");
    assert!(item.contains_key("<<"), "`<<` must be kept as a key");
    assert!(!item.contains_key("a"), "the merge must not be expanded");
}

/// Row 17: a duplicate key is refused, naming the line and column of the repeat.
#[test]
fn duplicate_keys_are_refused_with_line_and_column() {
    let doc = "a: 1\nb: 2\na: 3\n";
    let error = yaml::from_str::<Value>(doc).expect_err("duplicate key refused");
    let at = error.location().expect("the refusal names a position");
    assert_eq!((at.line(), at.column()), (3, 1), "{error}");

    let error = yaml::from_str::<Named>("name: x\nname: y\n").expect_err("duplicate field");
    assert_eq!(error.location().map(|l| l.line()), Some(2), "{error}");

    let error = yaml::from_str::<std::collections::BTreeMap<String, u32>>("k: 1\nk: 2\n")
        .expect_err("duplicate map key refused");
    assert_eq!(error.location().map(|l| l.line()), Some(2), "{error}");
}

/// Row 19: an application tag is accepted, as 1.5.5 accepted it; an untyped read gives the
/// tagged node's value.
#[test]
fn application_tags_are_accepted() {
    assert_eq!(tree("k: !Variant payload\n").at("k"), &text("payload"));
}

/// The tree keeps key order, after reading and after edits.
#[test]
fn mappings_keep_key_order() {
    let mut doc = tree("zeta: 1\nalpha: 2\nmid: 3\n");
    let keys: Vec<_> = doc
        .as_mapping()
        .unwrap()
        .keys()
        .filter_map(ValueExt::as_str)
        .collect();
    assert_eq!(keys, ["zeta", "alpha", "mid"]);

    let map = doc.as_mapping_mut().unwrap();
    map.insert_key("alpha", Value::from(20));
    map.insert_key("new", Value::from(4));
    map.remove_key("zeta");
    // A removal moves the last pair into the gap, as serde_yaml's `Mapping::remove` did.
    let keys: Vec<_> = map.keys().filter_map(ValueExt::as_str).collect();
    assert_eq!(keys, ["new", "alpha", "mid"]);
    assert_eq!(doc.at("alpha").as_u64(), Some(20));
}

/// Writing a tree and reading it back gives the same tree, strings that look like other
/// scalars included.
#[test]
fn written_yaml_reads_back_to_the_same_tree() {
    let doc = tree(
        "a: yes\nb: '0644'\nc: \"123\"\nd: 1.5\ne: null\nf: [1, two, '3']\ng: {x: 1}\n429: retry\n",
    );
    let written = yaml::to_string(&doc).unwrap();
    assert_eq!(tree(&written), doc, "{written}");
}

/// A tree read into a typed value means what reading the text directly means: an integer into
/// an `f64` field, as serde_yaml's `from_value` accepted.
#[test]
fn from_value_reads_like_the_text() {
    #[derive(Debug, Deserialize, PartialEq)]
    struct Trip {
        threshold: f64,
        name: String,
    }
    let doc = tree("threshold: 1\nname: 0644\n");
    let trip: Trip = yaml::from_value(doc).unwrap();
    assert_eq!(
        trip,
        Trip {
            threshold: 1.0,
            name: "0644".into()
        }
    );
}

/// Row 5, typed: 1.5.5 refused `0644` for an integer field. serde-saphyr has no option to refuse
/// it yet (upstream request: https://github.com/bourumir-wyngs/serde-saphyr/issues/274), so it
/// reads as decimal 644 meanwhile (owner ACCEPT 282). When the option lands, pin it in
/// `yaml::options()` and flip this test to `is_err()`.
#[test]
fn leading_zero_into_an_integer_field_reads_as_decimal_until_upstream_274() {
    #[derive(Debug, Deserialize)]
    struct Mode {
        mode: u32,
    }
    assert_eq!(yaml::from_str::<Mode>("mode: 0644\n").unwrap().mode, 644);
}

/// Tags are found anywhere in a document, keys included, for readers that must refuse or carry
/// them; core-schema tags are not application tags.
#[test]
fn application_tags_are_found_wherever_they_are() {
    assert_eq!(
        yaml::first_application_tag("a: 1\nb: [x, {c: d}]\n").unwrap(),
        None
    );
    assert_eq!(yaml::first_application_tag("a: !!str 1\n").unwrap(), None);
    assert_eq!(
        yaml::first_application_tag("a: {b: [x, !Deep y]}\n")
            .unwrap()
            .as_deref(),
        Some("!Deep")
    );
    assert_eq!(
        yaml::first_application_tag("!Key k: v\n")
            .unwrap()
            .as_deref(),
        Some("!Key")
    );
}
