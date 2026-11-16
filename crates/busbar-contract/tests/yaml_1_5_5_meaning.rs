// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! YAML keeps the meaning 1.5.5 gave a configuration file.
//!
//! 1.5.5 read YAML with serde_yaml_ng 0.10 on libyaml: YAML 1.1 syntax with a resolver close to
//! YAML 1.2 Core. busbar now reads it with serde-saphyr, a YAML 1.2 parser whose defaults differ.
//! Each test pins one spelling from the YAML-1.1-versus-1.2 table (YAML-LADDER.md) to the meaning
//! 1.5.5 gave it, through `busbar_contract::yaml`, the one place the parser options are set.
//!
//! The recorded config surface (`every_recorded_1_5_5_input_means_what_it_meant`):
//! `fixtures/yaml_1_5_5/serde_yaml_ng-0.10.0-config-surface.jsonl` holds the 1,141 inputs that
//! busbar-yaml's parity test recorded with serde_yaml_ng 0.10.0 on unsafe-libyaml 0.2.11 (the
//! 1.5.5 stack): the oracle's whole config surface, every YAML file the repository read or
//! shipped, and 400 seeded corruptions of oracle configs. That recording stored a SHA-256 of each
//! `Value`'s `Debug` form; this fixture spells each value out instead (`null`, `true`, `"text"`,
//! `[..]`, `{"int": "n"}`, `{"float": "x"}` with `.inf`/`-.inf`/`.nan`, `{"map": [[k, v], ..]}` in
//! document order, `{"tag": "!T", "value": v}`), and every spelled-out value was checked against
//! its recorded digest when the fixture was made: all 587 accepted inputs matched, none differ.
//! The other 554 inputs were refused by 1.5.5 and carry `"refused": true`.
//!
//! Every one of the 1,141 recorded cases is ported. Excluded from each record, as crate-internal
//! rather than meaning: the SHA-256 of the 1.5.5 re-serialization (emitter byte layout), the
//! refusal's libyaml wording and position, and the per-document results of the multi-document
//! `Deserializer` iterator (3 records; `busbar_contract::yaml` has no multi-document reader, and
//! the whole-input read those records also hold, a refusal, is checked). A tagged node is
//! compared with its tag, as 1.5.5's `Value::Tagged` kept it (row 19; 1 record,
//! `mutated-oracle-config#117`, with a non-specific `!` key tag). `ACCEPTED_DIFFERENCES` names any
//! recorded case the owner accepts reading differently; it is empty.
//!
//! Also ported, as ordinary tests below, the meaning cases of serde_yaml_ng's own suite that
//! busbar-yaml carried (`test_de.rs`, `test_value.rs`, `test_error.rs`, `test_serde.rs`): what
//! an input reads as, untyped and into typed targets, and what it refuses; and, for typed enums,
//! units and `Mapping` fields, what a typed value is written as and that it reads back as itself
//! (1.5.5 wrote an enum variant with content as `!Variant`). Not ported: other emitter
//! output, error wording and positions, `Value`/`Number`/`Mapping` API internals, `Debug`
//! output, seeds, `apply_merge`, the multi-document iterator and bytes (APIs this module does not
//! offer). The typed `0644` case is pinned by `leading_zero_into_an_integer_field_is_refused`.
//!
//! PROPOSED ACCEPTS, awaiting the owner. Each is still asserted as 1.5.5 read it, so each is red
//! until the owner approves it (then the assertion flips to the new reading) or it is fixed.
//! Each test or record concerned carries a `// PROPOSED ACCEPT:` comment. None is skipped.
//!
//! Typed reads go straight to serde-saphyr's deserializer, which decides these before any code
//! of ours runs; untyped reads are not affected. They could be fixed only by a forwarding layer
//! between serde and serde-saphyr that reads each scalar's source text through `Spanned`
//! byte spans (granit-parser reports an empty node as the scalar `~`; only its span says it was
//! empty). That layer is not built.
//! 1. `empty:\ntilde: ~\n` into `{ empty: String, tilde: String }`: 1.5.5 read `""` and `"~"`
//!    (its `deserialize_str` took any scalar's text); now refused, `cannot deserialize null into
//!    string; use Option<String>`. Likewise `null` into a `String` (1.5.5: `"null"`).
//! 2. `- !String\n` into `Vec<Enum>` with `String(String)`: 1.5.5 read `[String("")]`; now
//!    refused, the same null-into-string error on the variant's empty payload.
//! 3. `thing:\n` into `{ thing: Vec<_> }` or `{ thing: BTreeMap<_, _> }`: 1.5.5 read an empty
//!    collection (an empty plain scalar was an empty sequence or mapping); now refused, `expected
//!    sequence start` / `expected mapping start`. Likewise the explicit empty document `---\n`
//!    into a struct, `Vec` or map (1.5.5: empty; now refused). `""` and `# comment` still match.
//! 4. `{}` into a unit struct: 1.5.5 refused it (`invalid type: map, expected unit struct ..`); now
//!    read as the unit struct (serde-saphyr allows an empty mapping for one).
//! 5. `0XFF`, `0O17`, `0B1` (upper-case radix prefixes): 1.5.5 read strings untyped and refused
//!    them for integer fields (its prefixes were lower-case only); now the integers 255, 15, 1.
//!    Lower-case `0x`/`0o`/`0b`, signed or not (`+0xF0`, `-0o70`, `-0b10`), read alike.
//! 6. The alias bomb in fields a struct ignores (`an_alias_bomb_is_refused_even_in_ignored_fields`,
//!    owner ACCEPT 2026-11-15: "accept sounds correct, 1.5.5 was broken"): 1.5.5 read it (it
//!    skipped ignored events without following aliases); now refused by serde-saphyr's alias
//!    replay budget, as serde-saphyr walks an ignored value with `deserialize_any`. serde has no
//!    skip, so no forwarding layer could fix it either.
//! 7. U+2028 / U+2029: libyaml read them as line breaks, YAML 1.2 (granit-parser) as content.
//!    Recorded inputs 1.5.5 refused for that break inside an implicit key or indentation
//!    (`mutated-oracle-config#211` `st\u{2028}ore:`, `#249` `  \u{2028}  limits:`) are expected
//!    to read now (as maps with those keys). `#147` and `#269` also hold one, but are expected to
//!    be refused alike for their other corruption (`~{` after a key; a leading backtick). The
//!    recorded inputs 1.5.5 accepted with one inside a multi-line scalar (`#91`, `#234`) read
//!    alike.
//! 8. Typed reads only: a byte order mark that starts a token (`k: \u{feff}[x]`): 1.5.5 read the
//!    string `"\u{feff}[x]"`; now refused, `BomInsideDocument`. Untyped reads are fixed (below).
//!
//! FIXED in `busbar_contract::yaml` (each with a test below): a character outside YAML's
//! printable set anywhere in the text is refused, as libyaml's reader refused it (the 12 recorded
//! control-character refusals, `\u{7}` and `\u{7f}`, which granit-parser reads inside a plain
//! scalar); a byte order mark after the first character is content in an untyped read
//! (`mutated-oracle-config#58`, `admin_auth: \u{feff}[admin-tokens]`); nesting is allowed 128
//! deep and refused at 129, serde_yaml's recursion limit (serde-saphyr's default stopped at 64).
//!
//! Traced and already reading as 1.5.5 did: `!!int |-` on a block scalar; `Unit`, `'Unit'`,
//! `!Unit`, `!Unit ~`, `!Unit null` into a unit variant; `[0, 0]` into a struct and a two-key
//! untagged map into an enum, both refused; a self-referencing alias and nesting 1,000 deep, both
//! refused; billion laughs refused; repeated `null`/`~` and `{}` keys refused at the repeat; the
//! recorded tab inputs libyaml tolerated (`#121`, `#155`, `#185`, `#234`); a byte order mark
//! inside a scalar (`#98`, `#117`, `#150`, `#282`, `#302`, `#354`); record `#117`'s bare `!` key
//! tag, kept as the tag `!`.

use std::collections::BTreeMap;

use busbar_contract::json::{self, JsonContainerTrait as _, JsonValueTrait as _};
use busbar_contract::yaml::{self, prelude::*};
use serde::Deserialize;

fn tree(text: &str) -> Value {
    yaml::from_str(text).expect("valid YAML")
}

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

#[derive(Debug, Deserialize, PartialEq)]
struct Flag {
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

/// Row 17: a duplicate key means what it meant to 1.5.5's reader. An untyped read refuses it in
/// serde_yaml's words, naming the line and column of the repeat; a struct refuses it with serde's
/// `duplicate field`; a map keeps the last value.
#[test]
fn duplicate_keys_mean_what_they_meant_to_each_reader() {
    let error = yaml::from_str::<Value>("a: 1\nb: 2\na: 3\n").expect_err("duplicate key refused");
    assert_eq!(
        error.to_string(),
        "duplicate entry with key \"a\" at line 3 column 1"
    );
    let at = error.location().expect("the refusal names a position");
    assert_eq!((at.line(), at.column()), (3, 1), "{error}");

    let error = yaml::from_str::<Value>("outer:\n  a: 1\n  a: 2\n").expect_err("nested");
    assert_eq!(
        error.to_string(),
        "outer: duplicate entry with key \"a\" at line 3 column 3"
    );

    let error = yaml::mapping_from_str("k: 1\nk: 2\n").expect_err("a mapping refuses it too");
    assert!(
        error
            .to_string()
            .starts_with("duplicate entry with key \"k\""),
        "{error}"
    );

    let error = yaml::from_str::<Named>("name: x\nname: y\n").expect_err("duplicate field");
    assert!(
        error.to_string().starts_with("duplicate field `name`"),
        "{error}"
    );

    let read: BTreeMap<String, u32> = yaml::from_str("k: 1\nk: 2\n").expect("a map keeps the last");
    assert_eq!(read, BTreeMap::from([("k".to_owned(), 2)]));
}

/// Row 17, through a tree already read: a `Mapping` built from a `Value` with a repeated key is
/// refused, as serde_yaml's `Mapping` refused it.
#[test]
fn a_mapping_from_a_tree_refuses_a_repeated_key() {
    let repeated = Value::Map(vec![
        (text("k"), Value::from(1)),
        (text("k"), Value::from(2)),
    ]);
    let error = yaml::from_value::<Mapping>(repeated).expect_err("duplicate key refused");
    assert_eq!(error.to_string(), "duplicate entry with key \"k\"");
}

/// Row 19: an application tag is accepted, as 1.5.5 accepted it, and an untyped read keeps it
/// on the node, as 1.5.5's `Value::Tagged` did; lookups see through it to the value.
#[test]
fn application_tags_are_kept_by_untyped_reads() {
    let doc = tree("k: !Variant payload\n");
    assert_eq!(doc.at("k"), &yaml::tagged("!Variant", text("payload")));
    assert_eq!(yaml::tag_of(doc.at("k")).as_deref(), Some("!Variant"));
    assert_eq!(doc.at("k").as_str(), Some("payload"));
    assert_eq!(tree("k: !!str payload\n").at("k"), &text("payload"));
}

/// Row 19: `!Variant` in a tree read on into an enum field selects the variant, as serde_yaml's
/// `from_value` read a `Value::Tagged`.
#[test]
fn tags_in_a_tree_select_enum_variants() {
    #[derive(Debug, Deserialize, PartialEq)]
    enum Shape {
        Unit,
        Circle(f64),
        Rect { w: u32, h: u32 },
        Pair(u8, u8),
    }
    #[derive(Debug, Deserialize, PartialEq)]
    struct Shapes {
        plain: Shape,
        circle: Shape,
        rect: Shape,
        pair: Shape,
        maybe: Option<Shape>,
    }
    let doc = tree(
        "plain: Unit\ncircle: !Circle 1.5\nrect: !Rect {w: 2, h: 3}\npair: !Pair [1, 2]\n\
         maybe: !Circle 2\n",
    );
    assert_eq!(
        yaml::from_value::<Shapes>(doc).unwrap(),
        Shapes {
            plain: Shape::Unit,
            circle: Shape::Circle(1.5),
            rect: Shape::Rect { w: 2, h: 3 },
            pair: Shape::Pair(1, 2),
            maybe: Some(Shape::Circle(2.0)),
        }
    );
}

/// A tagged tree writes its tags back and reads back to the same tree, as serde_yaml wrote a
/// `Value::Tagged`.
#[test]
fn tagged_trees_round_trip_through_text() {
    let doc = tree("shape: !Circle 1.5\nlist:\n- !Rect {w: 2, h: 3}\n- plain\n");
    let written = yaml::to_string(&doc).unwrap();
    assert!(written.contains("!Circle"), "{written}");
    assert!(written.contains("!Rect"), "{written}");
    assert_eq!(tree(&written), doc, "{written}");

    let through_value: Value = yaml::from_value(doc.clone()).unwrap();
    assert_eq!(through_value, doc, "a tree read from a tree keeps its tags");
}

/// A tagged tree inside a typed value (a struct field, an `Option`, a map value, a `Vec`
/// element) writes its tag back as `!Name value`, as serde_yaml 0.9 wrote a `Value::Tagged`
/// (a tagged mapping: the tag, then the block), never as ciborium's internal `@@TAGGED@@`
/// tuple variant. Migrate rewrites customer config files through these writes.
///
/// Red before the fix: `yaml::to_string` handed the typed value straight to serde-saphyr, so a
/// nested `Value::Tag` came out as ciborium's `@@TAGGED@@` variant with the registry number.
#[test]
fn tagged_trees_inside_typed_values_write_their_tags() {
    #[derive(serde::Serialize)]
    struct Fields {
        variant: Value,
        thing: Value,
        maybe: Option<Value>,
        named: BTreeMap<String, Value>,
        after: String,
    }
    #[derive(serde::Serialize)]
    struct Listed {
        list: Vec<Value>,
        after: String,
    }
    let variant = tree("!Variant x\n");
    let thing = tree("!Thing {a: 1}\n");
    assert_eq!(variant, yaml::tagged("!Variant", text("x")));
    assert_eq!(yaml::tag_of(&thing).as_deref(), Some("!Thing"));

    let fields = Fields {
        variant: variant.clone(),
        thing: thing.clone(),
        maybe: Some(variant.clone()),
        named: BTreeMap::from([("k".to_owned(), thing.clone())]),
        after: "end".to_owned(),
    };
    let written = yaml::to_string(&fields).unwrap();
    assert!(!written.contains("@@TAG"), "{written}");
    // serde_yaml 0.9's bytes for this struct.
    assert_eq!(
        written,
        "variant: !Variant x\nthing: !Thing\n  a: 1\nmaybe: !Variant x\nnamed:\n  k: !Thing\n    a: 1\nafter: end\n",
    );
    let mut through_writer = Vec::new();
    yaml::to_writer(&mut through_writer, &fields).unwrap();
    assert_eq!(String::from_utf8(through_writer).unwrap(), written);
    assert_eq!(
        tree(&written),
        tree("variant: !Variant x\nthing: !Thing {a: 1}\nmaybe: !Variant x\nnamed: {k: !Thing {a: 1}}\nafter: end\n"),
        "{written}"
    );

    let listed = Listed {
        list: vec![variant, thing, text("plain")],
        after: "end".to_owned(),
    };
    let written = yaml::to_string(&listed).unwrap();
    assert!(!written.contains("@@TAG"), "{written}");
    assert!(written.contains("- !Variant x\n"), "{written}");
    assert!(written.contains("- !Thing\n"), "{written}");
    assert!(written.contains("after: end\n"), "{written}");
    assert_eq!(
        tree(&written),
        tree("list: [!Variant x, !Thing {a: 1}, plain]\nafter: end\n"),
        "{written}"
    );
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

/// Row 5, typed: 1.5.5 refused `0644` for an integer field, and so does serde-saphyr 2.1.1: it
/// reads a zero-prefixed integer spelling only under `legacy_octal_numbers`, which
/// `yaml::options()` leaves off. (The owner-accepted interim reading as decimal 644, ACCEPT 282,
/// pending upstream issue 274, is no longer needed.)
#[test]
fn leading_zero_into_an_integer_field_is_refused() {
    #[derive(Debug, Deserialize)]
    struct Mode {
        mode: u32,
    }
    if let Ok(Mode { mode }) = yaml::from_str::<Mode>("mode: 0644\n") {
        panic!("a zero-prefixed integer was accepted as {mode}");
    }
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

// ---- The recorded 1.5.5 config surface ----

/// Recorded cases the owner accepts reading differently from 1.5.5: (record name, why). Each is
/// skipped by name. Empty: every recorded case is held to its 1.5.5 meaning.
/// Owner ACCEPT 2026-11-15 ("accept sounds correct, 1.5.5 was broken"): U+0085 (NEL) is content in YAML
/// 1.2; libyaml read it as a line break.
const ACCEPTED_DIFFERENCES: &[(&str, &str)] = &[
    (
        "mutated-oracle-config#0",
        "U+0085 (NEL) is YAML 1.2 content, a libyaml line break",
    ),
    (
        "mutated-oracle-config#112",
        "U+0085 (NEL) is YAML 1.2 content, a libyaml line break",
    ),
    (
        "mutated-oracle-config#149",
        "U+0085 (NEL) is YAML 1.2 content, a libyaml line break",
    ),
    (
        "mutated-oracle-config#323",
        "U+0085 (NEL) is YAML 1.2 content, a libyaml line break",
    ),
    (
        "mutated-oracle-config#372",
        "U+0085 (NEL) is YAML 1.2 content, a libyaml line break",
    ),
];

/// Recorded cases proposed to the owner as accepted differences (item 7 in the module docs), not
/// yet approved: still checked and still failing when they differ. This list only labels their
/// failures `PROPOSED ACCEPT`; it skips nothing.
// PROPOSED ACCEPT: U+2028 / U+2029 are content in YAML 1.2, line breaks to libyaml.
const PROPOSED_ACCEPTS: &[(&str, &str)] = &[
    (
        "mutated-oracle-config#211",
        "U+2028 inside an implicit key (`st<U+2028>ore:`): a libyaml line break, YAML 1.2 content",
    ),
    (
        "mutated-oracle-config#249",
        "U+2028 in indentation (`  <U+2028>  limits:`): a libyaml line break, YAML 1.2 content",
    ),
];

const RECORDED_CASES: usize = 1141;

/// A recorded 1.5.5 value, spelled out in the fixture, as the tree it means.
fn recorded(want: &json::Value) -> Value {
    use json::JsonType as J;
    match want.get_type() {
        J::Null => Value::Null,
        J::Boolean => Value::Bool(want.as_bool().unwrap_or_default()),
        J::String => Value::Text(want.as_str().unwrap_or_default().to_owned()),
        J::Array => Value::Array(
            want.as_array()
                .into_iter()
                .flatten()
                .map(recorded)
                .collect(),
        ),
        J::Object => {
            let form = want;
            if let Some(int) = form.get("int").and_then(|v| v.as_str()) {
                return match int.parse::<u64>() {
                    Ok(u) => Value::from(u),
                    Err(_) => Value::from(int.parse::<i64>().expect("a recorded integer")),
                };
            }
            if let Some(float) = form.get("float").and_then(|v| v.as_str()) {
                return Value::Float(match float {
                    ".inf" => f64::INFINITY,
                    "-.inf" => f64::NEG_INFINITY,
                    ".nan" => f64::NAN,
                    finite => finite.parse().expect("a recorded float"),
                });
            }
            if let Some(pairs) = form.get("map").and_then(|v| v.as_array()) {
                return Value::Map(
                    pairs
                        .iter()
                        .map(|pair| (recorded(&pair[0]), recorded(&pair[1])))
                        .collect(),
                );
            }
            if let Some(tag) = form.get("tag").and_then(|v| v.as_str()) {
                return yaml::tagged(tag, recorded(&form["value"]));
            }
            panic!("an unknown recorded form: {want}");
        }
        J::Number => panic!("recorded numbers are spelled out: {want}"),
    }
}

fn brief(value: &Value) -> String {
    let text = format!("{value:?}");
    let mut short: String = text.chars().take(160).collect();
    if short.len() < text.len() {
        short.push('…');
    }
    short
}

/// Where `got` first differs from the 1.5.5 tree `want`: same kinds (an integer is not a float,
/// a string is not a number), same values (NaN equals NaN), same keys in the same order.
fn first_difference(want: &Value, got: &Value, at: &str) -> Option<String> {
    match (want, got) {
        (Value::Float(x), Value::Float(y)) if x == y || (x.is_nan() && y.is_nan()) => None,
        (Value::Array(x), Value::Array(y)) if x.len() == y.len() => x
            .iter()
            .zip(y)
            .enumerate()
            .find_map(|(i, (x, y))| first_difference(x, y, &format!("{at}[{i}]"))),
        (Value::Map(x), Value::Map(y)) if x.len() == y.len() => {
            x.iter().zip(y).find_map(|((xk, xv), (yk, yv))| {
                let here = match xk {
                    Value::Text(k) => format!("{at}.{k}"),
                    other => format!("{at}.{}", brief(other)),
                };
                first_difference(xk, yk, &format!("{here} (key)"))
                    .or_else(|| first_difference(xv, yv, &here))
            })
        }
        (Value::Tag(x, xv), Value::Tag(y, yv)) if x == y => first_difference(xv, yv, at),
        (Value::Float(_) | Value::Array(_) | Value::Map(_) | Value::Tag(..), _) => Some(format!(
            "at `{at}` 1.5.5 read {}, now {}",
            brief(want),
            brief(got)
        )),
        _ if want == got => None,
        _ => Some(format!(
            "at `{at}` 1.5.5 read {}, now {}",
            brief(want),
            brief(got)
        )),
    }
}

/// Every input of the recorded 1.5.5 config surface is accepted or refused as 1.5.5 did, and an
/// accepted one reads as the same tree: the same scalar kinds and values, keys and order.
#[test]
fn every_recorded_1_5_5_input_means_what_it_meant() {
    let fixture = include_str!("fixtures/yaml_1_5_5/serde_yaml_ng-0.10.0-config-surface.jsonl");
    let (mut accepted, mut refused, mut skipped) = (0usize, 0usize, 0usize);
    let mut failures = Vec::new();
    for line in fixture.lines() {
        let record: json::Value = json::parse_value(line.as_bytes()).expect("a fixture record");
        let name = record["name"].as_str().expect("a name");
        let input = record["input"].as_str().expect("an input");
        if ACCEPTED_DIFFERENCES.iter().any(|(n, _)| *n == name) {
            skipped += 1;
            continue;
        }
        // A proposed accept is still checked; only its failure is labelled.
        let label = match PROPOSED_ACCEPTS.iter().find(|(n, _)| *n == name) {
            Some((_, why)) => format!("PROPOSED ACCEPT ({why}): {name}"),
            None => name.to_owned(),
        };
        match (record.get("value"), yaml::from_str::<Value>(input)) {
            (None, Err(_)) => refused += 1,
            (None, Ok(got)) => failures.push(format!(
                "{label}: 1.5.5 refused it, now read as {}",
                brief(&got)
            )),
            (Some(_), Err(error)) => {
                failures.push(format!("{label}: 1.5.5 accepted it, now refused: {error}"));
            }
            (Some(want), Ok(got)) => match first_difference(&recorded(want), &got, "") {
                None => accepted += 1,
                Some(difference) => failures.push(format!("{label}: {difference}")),
            },
        }
    }
    assert_eq!(
        accepted + refused + skipped + failures.len(),
        RECORDED_CASES,
        "every recorded case is checked"
    );
    assert!(
        failures.is_empty(),
        "{} of {RECORDED_CASES} recorded inputs differ from 1.5.5 ({accepted} read alike, \
         {refused} refused alike, {skipped} accepted differences):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

// ---- serde_yaml_ng 0.10's own meaning cases, as busbar-yaml carried them ----

/// test_de `test_tag_resolution`: the YAML 1.2 Core nulls, and an empty node, are null.
#[test]
fn core_nulls_are_null() {
    assert_eq!(
        tree("- null\n- Null\n- NULL\n- ~\n-\n"),
        Value::Array(vec![Value::Null; 5])
    );
}

/// test_de `test_numbers`: signed and radix-prefixed integers, and the non-finite floats in
/// every case 1.5.5 knew, are numbers.
#[test]
fn signed_and_radix_numbers_are_numbers() {
    for (word, want) in [
        ("0xF0", 240i64),
        ("+0xF0", 240),
        ("-0xF0", -240),
        ("0o70", 56),
        ("+0o70", 56),
        ("-0o70", -56),
        ("0b10", 2),
        ("+0b10", 2),
        ("-0b10", -2),
        ("127", 127),
        ("+127", 127),
        ("-127", -127),
    ] {
        assert_eq!(
            tree(word),
            Value::from(want),
            "`{word}` must be the integer {want}"
        );
    }
    for (word, want) in [
        (".inf", f64::INFINITY),
        (".Inf", f64::INFINITY),
        (".INF", f64::INFINITY),
        ("-.inf", f64::NEG_INFINITY),
        ("-.Inf", f64::NEG_INFINITY),
        ("-.INF", f64::NEG_INFINITY),
        ("0.1", 0.1),
    ] {
        assert_eq!(
            tree(word),
            Value::Float(want),
            "`{word}` must be the float {want}"
        );
    }
    for word in [".nan", ".NaN", ".NAN"] {
        assert!(
            matches!(tree(word), Value::Float(f) if f.is_nan()),
            "`{word}` must be NaN"
        );
    }
}

/// test_de `test_numbers`, test_value `test_nan` and `test_digits`: spellings 1.5.5 kept as
/// strings although they look numeric.
#[test]
fn near_numbers_are_strings() {
    for word in [
        "0127", "+0127", "-0127", "++.inf", "+-.inf", "++1", "+-1", "-+1", "--1", "0x+1", "0x-1",
        "-0x+1", "-0x-1", "++0x1", "+-0x1", "-+0x1", "--0x1", "-.nan", "01",
    ] {
        assert_eq!(tree(word), text(word), "`{word}` must stay a string");
    }
}

/// test_de `test_nan`: there is no negative NaN in YAML.
#[test]
fn nan_is_positive() {
    assert!(yaml::from_str::<f64>(".nan").unwrap().is_sign_positive());
    assert!(yaml::from_str::<f32>(".nan").unwrap().is_sign_positive());
}

/// test_serde `test_int*`, `test_i128_small`, `test_u128_small`, `test_float*`; test_de
/// `test_i128_big`, `test_u128_big`: typed integer and float reads, at their limits.
#[test]
fn typed_numbers_read_as_1_5_5_read_them() {
    assert_eq!(yaml::from_str::<i32>("256\n").unwrap(), 256);
    assert_eq!(
        yaml::from_str::<u64>("18446744073709551615\n").unwrap(),
        u64::MAX
    );
    assert_eq!(
        yaml::from_str::<i64>("-9223372036854775808\n").unwrap(),
        i64::MIN
    );
    assert_eq!(
        yaml::from_str::<i64>("9223372036854775807\n").unwrap(),
        i64::MAX
    );
    assert_eq!(yaml::from_str::<i128>("-256\n").unwrap(), -256);
    assert_eq!(yaml::from_str::<u128>("256\n").unwrap(), 256);

    let below_i64 = i128::from(i64::MIN) - 1;
    assert_eq!(
        yaml::from_str::<i128>("-9223372036854775809\n").unwrap(),
        below_i64
    );
    assert_eq!(
        yaml::from_str::<i128>("-0o1000000000000000000001\n").unwrap(),
        below_i64
    );
    let above_u64 = u128::from(u64::MAX) + 1;
    assert_eq!(
        yaml::from_str::<u128>("18446744073709551616\n").unwrap(),
        above_u64
    );
    assert_eq!(
        yaml::from_str::<u128>("0o2000000000000000000000\n").unwrap(),
        above_u64
    );

    assert_eq!(yaml::from_str::<f64>("25.6\n").unwrap(), 25.6);
    assert_eq!(yaml::from_str::<f64>("25.0\n").unwrap(), 25.0);
    assert_eq!(yaml::from_str::<f64>(".inf\n").unwrap(), f64::INFINITY);
    assert_eq!(yaml::from_str::<f64>("-.inf\n").unwrap(), f64::NEG_INFINITY);
    assert!(yaml::from_str::<f64>(".nan\n").unwrap().is_nan());
    assert_eq!(yaml::from_str::<f32>("25.5\n").unwrap(), 25.5);
    assert_eq!(yaml::from_str::<f32>(".inf\n").unwrap(), f32::INFINITY);
    assert_eq!(yaml::from_str::<f32>("-.inf\n").unwrap(), f32::NEG_INFINITY);
    assert!(yaml::from_str::<f32>(".nan\n").unwrap().is_nan());
}

/// test_de `test_number_as_string`, `test_number_alias_as_string`: into a `String` field a
/// number keeps its spelling, beyond `u128` and through an alias (`1.10`, not `1.1`).
#[test]
fn numbers_into_string_fields_keep_their_spelling() {
    #[derive(Debug, Deserialize, PartialEq)]
    struct Num {
        value: String,
    }
    let doc = "# Cannot be represented as u128\nvalue: 340282366920938463463374607431768211457\n";
    assert_eq!(
        yaml::from_str::<Num>(doc).unwrap().value,
        "340282366920938463463374607431768211457"
    );

    #[derive(Debug, Deserialize, PartialEq)]
    struct Versioned {
        version: String,
        value: String,
    }
    assert_eq!(
        yaml::from_str::<Versioned>("version: &a 1.10\nvalue: *a\n").unwrap(),
        Versioned {
            version: "1.10".into(),
            value: "1.10".into()
        }
    );
}

/// test_de `test_empty_string`: into a `String` field an empty node is `""` and `~` is `"~"`.
// PROPOSED ACCEPT (item 1): 1.5.5 read `""` and `"~"`; serde-saphyr refuses both, `cannot
// deserialize null into string; use Option<String>`. Red until approved or fixed.
#[test]
fn empty_and_tilde_into_string_fields() {
    #[derive(Debug, Deserialize, PartialEq)]
    struct Struct {
        empty: String,
        tilde: String,
    }
    assert_eq!(
        yaml::from_str::<Struct>("empty:\ntilde: ~\n").unwrap(),
        Struct {
            empty: String::new(),
            tilde: "~".into()
        }
    );
}

/// test_de `test_option`, `test_option_alias`: an absent or null node is `None`, through
/// aliases too.
#[test]
fn null_and_absent_options_are_none() {
    #[derive(Debug, Deserialize, PartialEq)]
    struct Data {
        a: Option<f64>,
        b: Option<String>,
        c: Option<bool>,
    }
    assert_eq!(
        yaml::from_str::<Data>("b:\nc: true\n").unwrap(),
        Data {
            a: None,
            b: None,
            c: Some(true)
        }
    );

    #[derive(Debug, Deserialize, PartialEq)]
    struct Aliased {
        a: Option<f64>,
        b: Option<String>,
        c: Option<bool>,
        d: Option<f64>,
        e: Option<String>,
        f: Option<bool>,
    }
    let doc = "none_f:\n  &none_f\n  ~\nnone_s:\n  &none_s\n  ~\nnone_b:\n  &none_b\n  ~\n\n\
               some_f:\n  &some_f\n  1.0\nsome_s:\n  &some_s\n  x\nsome_b:\n  &some_b\n  true\n\n\
               a: *none_f\nb: *none_s\nc: *none_b\nd: *some_f\ne: *some_s\nf: *some_b\n";
    assert_eq!(
        yaml::from_str::<Aliased>(doc).unwrap(),
        Aliased {
            a: None,
            b: None,
            c: None,
            d: Some(1.0),
            e: Some("x".into()),
            f: Some(true)
        }
    );
}

/// test_de `test_alias`: an alias reads as its anchored node.
#[test]
fn aliases_read_as_their_anchor() {
    let read: BTreeMap<String, i32> =
        yaml::from_str("first:\n  &alias\n  1\nsecond:\n  *alias\nthird: 3\n").unwrap();
    assert_eq!(
        read,
        BTreeMap::from([
            ("first".to_owned(), 1),
            ("second".to_owned(), 1),
            ("third".to_owned(), 3)
        ])
    );
}

/// test_de `test_borrowed`, test_serde `test_string_escapes`, `test_multiline_string`,
/// `test_strings_needing_quote`: plain, quoted, escaped and block strings.
#[test]
fn strings_read_as_1_5_5_read_them() {
    assert_eq!(
        yaml::from_str::<Vec<String>>("- plain nonàscii\n- 'single quoted'\n- \"double quoted\"\n")
            .unwrap(),
        ["plain nonàscii", "single quoted", "double quoted"]
    );
    assert_eq!(
        yaml::from_str::<String>(r#""\0\a\b\t\n\v\f\r\e\"\\\N\L\P""#).unwrap(),
        "\0\u{7}\u{8}\t\n\u{b}\u{c}\r\u{1b}\"\\\u{85}\u{2028}\u{2029}"
    );
    assert_eq!(
        yaml::from_str::<String>(r#""\x1F\uFEFF""#).unwrap(),
        "\u{1f}\u{feff}"
    );
    assert_eq!(yaml::from_str::<String>("🎉\n").unwrap(), "\u{1f389}");

    let doc = tree("trailing_newline: |\n  aaa\n  bbb\nno_trailing_newline: |-\n  aaa\n  bbb\n");
    assert_eq!(doc.at("trailing_newline"), &text("aaa\nbbb\n"));
    assert_eq!(doc.at("no_trailing_newline"), &text("aaa\nbbb"));

    let doc = tree("boolean: 'true'\ninteger: '1'\nvoid: 'null'\nleading_zeros: '007'\n");
    for (key, word) in [
        ("boolean", "true"),
        ("integer", "1"),
        ("void", "null"),
        ("leading_zeros", "007"),
    ] {
        assert_eq!(doc.at(key), &text(word), "a quoted `{word}` is a string");
    }
}

/// test_serde `test_value`: an untyped section of a typed read keeps each scalar's kind.
#[test]
fn untyped_sections_keep_scalar_kinds() {
    #[derive(Debug, Deserialize, PartialEq)]
    struct Instructions {
        #[serde(rename = "type")]
        typ: String,
        config: Value,
    }
    let read: Instructions =
        yaml::from_str("type: primary\nconfig:\n- null\n- true\n- 65535\n- 0.54321\n- s\n- {}\n")
            .unwrap();
    assert_eq!(read.typ, "primary");
    assert_eq!(
        read.config,
        Value::Array(vec![
            Value::Null,
            Value::Bool(true),
            Value::from(65535u64),
            Value::Float(0.54321),
            text("s"),
            Value::Map(Vec::new()),
        ])
    );
}

/// test_de `test_byte_order_mark`: a leading byte order mark is not content.
#[test]
fn byte_order_mark_is_not_content() {
    assert_eq!(yaml::from_str::<Vec<i32>>("\u{feff}- 0\n").unwrap(), [0]);
}

/// test_de `test_no_required_fields`: an empty document, or one of only comments, is null: an
/// all-optional struct, an empty sequence or map, `None`, or `Null`.
#[test]
fn empty_documents_are_null() {
    #[derive(Debug, Deserialize, PartialEq)]
    struct NoRequiredFields {
        optional: Option<usize>,
    }
    for document in ["", "# comment\n"] {
        assert_eq!(
            yaml::from_str::<NoRequiredFields>(document).unwrap(),
            NoRequiredFields { optional: None },
            "{document:?}"
        );
        assert!(yaml::from_str::<Vec<String>>(document).unwrap().is_empty());
        assert!(yaml::from_str::<BTreeMap<char, usize>>(document)
            .unwrap()
            .is_empty());
        assert_eq!(yaml::from_str::<Option<String>>(document).unwrap(), None);
        assert_eq!(yaml::from_str::<Value>(document).unwrap(), Value::Null);
    }
}

/// test_de `test_empty_scalar`: an empty node into a sequence or mapping field is empty.
// PROPOSED ACCEPT (item 3): 1.5.5 read empty collections; serde-saphyr refuses `thing:` for a
// `Vec` (`expected sequence start`) and a map (`expected mapping start`). Red until approved.
#[test]
fn empty_node_into_collection_fields_is_empty() {
    #[derive(Debug, Deserialize, PartialEq)]
    struct Thing<T> {
        thing: T,
    }
    assert!(yaml::from_str::<Thing<Vec<Value>>>("thing:\n")
        .unwrap()
        .thing
        .is_empty());
    assert!(yaml::from_str::<Thing<BTreeMap<String, Value>>>("thing:\n")
        .unwrap()
        .thing
        .is_empty());
}

/// test_de `test_python_safe_dump`: a core `!!int` tag on a block scalar reads as the integer.
#[test]
fn core_int_tag_on_a_block_scalar() {
    #[derive(Debug, Deserialize, PartialEq)]
    struct Frob {
        foo: u32,
    }
    assert_eq!(
        yaml::from_str::<Frob>("\"foo\": !!int |-\n    7200\n").unwrap(),
        Frob { foo: 7200 }
    );
}

/// test_de `test_ignore_tag`: into non-enum typed targets an application tag is ignored.
#[test]
fn application_tags_are_ignored_by_typed_reads() {
    #[derive(Debug, Deserialize, PartialEq)]
    struct Data {
        struc: Struc,
        tuple: Tuple,
        newtype: Newtype,
        map: BTreeMap<char, usize>,
        vec: Vec<usize>,
    }
    #[derive(Debug, Deserialize, PartialEq)]
    struct Struc {
        x: usize,
    }
    #[derive(Debug, Deserialize, PartialEq)]
    struct Tuple(usize, usize);
    #[derive(Debug, Deserialize, PartialEq)]
    struct Newtype(usize);

    let doc =
        "struc: !wat\n  x: 0\ntuple: !wat\n  - 0\n  - 0\nnewtype: !wat 0\nmap: !wat\n  x: 0\n\
               vec: !wat\n  - 0\n";
    assert_eq!(
        yaml::from_str::<Data>(doc).unwrap(),
        Data {
            struc: Struc { x: 0 },
            tuple: Tuple(0, 0),
            newtype: Newtype(0),
            map: BTreeMap::from([('x', 0)]),
            vec: vec![0],
        }
    );
}

/// test_de `test_enum_representations`, `test_enum_alias`, test_serde `test_tagged_map_value`:
/// into an enum, a plain name is a unit variant and `!Variant` selects the variant.
#[test]
fn tags_select_enum_variants() {
    #[derive(Debug, Deserialize, PartialEq)]
    enum Enum {
        Unit,
        Tuple(i32, i32),
        Struct { x: i32, y: i32 },
        String(String),
        Number(f64),
    }
    let doc = "- Unit\n- 'Unit'\n- !Unit\n- !Unit ~\n- !Unit null\n- !Tuple [0, 0]\n\
               - !Tuple\n  - 0\n  - 0\n- !Struct {x: 0, y: 0}\n- !Struct\n  x: 0\n  y: 0\n\
               - !String '...'\n- !String ...\n- !Number 0\n";
    assert_eq!(
        yaml::from_str::<Vec<Enum>>(doc).unwrap(),
        [
            Enum::Unit,
            Enum::Unit,
            Enum::Unit,
            Enum::Unit,
            Enum::Unit,
            Enum::Tuple(0, 0),
            Enum::Tuple(0, 0),
            Enum::Struct { x: 0, y: 0 },
            Enum::Struct { x: 0, y: 0 },
            Enum::String("...".into()),
            Enum::String("...".into()),
            Enum::Number(0.0),
        ]
    );
    // PROPOSED ACCEPT (item 2): 1.5.5 read `[String("")]`; serde-saphyr refuses the empty payload,
    // `cannot deserialize null into string`. Red until approved or fixed.
    assert_eq!(
        yaml::from_str::<Vec<Enum>>("- !String\n").unwrap(),
        [Enum::String(String::new())]
    );

    #[derive(Debug, Deserialize, PartialEq)]
    enum E {
        A,
        B(u8, u8),
    }
    #[derive(Debug, Deserialize, PartialEq)]
    struct Data {
        a: E,
        b: E,
    }
    let doc = "aref:\n  &aref\n  A\nbref:\n  &bref\n  !B\n    - 1\n    - 2\n\na: *aref\nb: *bref\n";
    assert_eq!(
        yaml::from_str::<Data>(doc).unwrap(),
        Data {
            a: E::A,
            b: E::B(1, 2)
        }
    );

    #[derive(Debug, Deserialize, PartialEq)]
    struct Bindings {
        profile: Profile,
    }
    #[derive(Debug, Deserialize, PartialEq)]
    enum Profile {
        ClassValidator { class_name: String },
    }
    assert_eq!(
        yaml::from_str::<Bindings>("profile: !ClassValidator\n  class_name: ApplicationConfig\n")
            .unwrap(),
        Bindings {
            profile: Profile::ClassValidator {
                class_name: "ApplicationConfig".into()
            }
        }
    );
}

/// test_de `test_enum_untagged`: an untagged enum sees `True` as a boolean and `T` as a string.
#[test]
fn untagged_enums_see_resolved_scalars() {
    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(untagged)]
    enum Untagged {
        A {
            r#match: bool,
        },
        AB {
            r#match: String,
        },
        B {
            #[serde(rename = "if")]
            r#match: bool,
        },
        C(String),
    }
    assert_eq!(
        yaml::from_str::<Untagged>("match: True").unwrap(),
        Untagged::A { r#match: true }
    );
    assert_eq!(
        yaml::from_str::<Untagged>("match: T").unwrap(),
        Untagged::AB {
            r#match: "T".into()
        }
    );
    assert_eq!(
        yaml::from_str::<Untagged>("if: True").unwrap(),
        Untagged::B { r#match: true }
    );
    assert_eq!(
        yaml::from_str::<Untagged>("match").unwrap(),
        Untagged::C("match".into())
    );
}

/// test_de `test_bomb`, as an owner-accepted difference (2026-11-15, "accept sounds correct, 1.5.5
/// was broken"): 1.5.5 read `Data { expected: "string" }` because it skipped aliases in fields a
/// typed read ignores. 1.6.0 refuses an alias bomb on its replay budget wherever it sits, so a
/// hostile document cannot reach the expansion at all.
#[test]
fn an_alias_bomb_is_refused_even_in_ignored_fields() {
    #[derive(Debug, Deserialize, PartialEq)]
    struct Data {
        expected: String,
    }
    let mut doc = String::from("a: &a ~\nb: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\n");
    for (name, previous) in ('c'..='z').zip('b'..='y') {
        let row = vec![format!("*{previous}"); 9].join(",");
        doc.push_str(&format!("{name}: &{name} [{row}]\n"));
    }
    doc.push_str("expected: string\n");
    let refused = yaml::from_str::<Data>(&doc).expect_err("an alias bomb is refused");
    assert!(refused.to_string().contains("budget"), "{refused}");
}

/// test_error: inputs 1.5.5 refused, by kind: syntax, wrong type, missing, unknown anchor, more
/// than one document, a core tag on a value it cannot mean, wrong length. Refusal only, not
/// wording.
#[test]
fn inputs_1_5_5_refused_are_refused() {
    #[derive(Debug, Deserialize, PartialEq)]
    struct A {
        b: Vec<B>,
    }
    #[derive(Debug, Deserialize, PartialEq)]
    enum B {
        C(C),
    }
    #[derive(Debug, Deserialize, PartialEq)]
    struct C {
        d: bool,
    }
    #[derive(Debug, Deserialize, PartialEq)]
    struct Basic {
        v: bool,
        w: bool,
    }
    #[derive(Debug, Deserialize, PartialEq)]
    struct Wrapper {
        c: (),
    }
    #[derive(Debug, Deserialize, PartialEq)]
    enum E {
        V(usize),
    }
    #[derive(Debug, Deserialize, PartialEq)]
    struct Struct {
        x: usize,
        y: usize,
    }
    #[derive(Debug, Deserialize, PartialEq)]
    struct Array {
        x: [i32; 1],
    }

    let refused = [
        ("scan error", yaml::from_str::<Value>(">\n@").is_err()),
        (
            "string into i16",
            yaml::from_str::<i16>("---\nstr\n").is_err(),
        ),
        (
            "`fase` into a nested bool",
            yaml::from_str::<A>("b:\n  - !C\n    d: fase\n").is_err(),
        ),
        (
            "empty document into String",
            yaml::from_str::<String>("").is_err(),
        ),
        (
            "missing field",
            yaml::from_str::<Basic>("---\nv: true\n").is_err(),
        ),
        (
            "unknown anchor",
            yaml::from_str::<String>("---\n*some\n").is_err(),
        ),
        (
            "unknown anchor in an ignored field",
            yaml::from_str::<Wrapper>("b: [*a]\nc: ~\n").is_err(),
        ),
        (
            "two documents",
            yaml::from_str::<usize>("---\n0\n---\n1\n").is_err(),
        ),
        (
            "untagged map into an enum",
            yaml::from_str::<E>("\"V\": 16\n\"other\": 32\n").is_err(),
        ),
        (
            "map into a newtype variant",
            yaml::from_str::<E>("---\n!V\nvalue: 0\n").is_err(),
        ),
        (
            "sequence into a struct",
            yaml::from_str::<Struct>("[0, 0]\n").is_err(),
        ),
        (
            "!!bool str",
            yaml::from_str::<bool>("---\n!!bool str\n").is_err(),
        ),
        (
            "!!int str",
            yaml::from_str::<i64>("---\n!!int str\n").is_err(),
        ),
        (
            "!!float str",
            yaml::from_str::<f64>("---\n!!float str\n").is_err(),
        ),
        (
            "!!null str",
            yaml::from_str::<()>("---\n!!null str\n").is_err(),
        ),
        (
            "short tuple",
            yaml::from_str::<(u8, u8, u8)>("---\n[0, 0]\n").is_err(),
        ),
        (
            "long tuple",
            yaml::from_str::<(u8, u8)>("---\n[0, 0, 0]\n").is_err(),
        ),
        (
            "string into an array",
            yaml::from_str::<Array>("x: ''\n").is_err(),
        ),
    ];
    let accepted: Vec<_> = refused
        .iter()
        .filter(|(_, is_err)| !is_err)
        .map(|(case, _)| *case)
        .collect();
    assert!(accepted.is_empty(), "1.5.5 refused these: {accepted:?}");
}

/// test_error `test_infinite_recursion_*`, `test_finite_recursion_*`: a self-referencing alias,
/// and nesting 1,000 deep, are refused rather than followed.
#[test]
fn unbounded_recursion_is_refused() {
    #[derive(Debug, Deserialize, PartialEq)]
    struct Objects {
        x: Option<Box<Objects>>,
    }
    #[derive(Debug, Deserialize, PartialEq)]
    struct Arrays(usize, Option<Box<Arrays>>);
    #[derive(Debug, Deserialize, PartialEq)]
    struct Newtype(Option<Box<Newtype>>);

    assert!(yaml::from_str::<Objects>("&a {'x': *a}").is_err());
    assert!(yaml::from_str::<Arrays>("&a [0, *a]").is_err());
    assert!(yaml::from_str::<Newtype>("&a [*a]").is_err());

    let deep = "{'x':".repeat(1_000) + &"}".repeat(1_000);
    assert!(yaml::from_str::<Objects>(&deep).is_err());
    let deep = "[0, ".repeat(1_000) + &"]".repeat(1_000);
    assert!(yaml::from_str::<Arrays>(&deep).is_err());
}

/// test_error `test_billion_laughs`: aliases a reader would expand exponentially are refused.
#[test]
fn billion_laughs_is_refused() {
    struct X;
    impl<'de> serde::de::Visitor<'de> for X {
        type Value = X;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("exponential blowup")
        }
        fn visit_unit<E>(self) -> Result<X, E> {
            Ok(X)
        }
        fn visit_seq<S: serde::de::SeqAccess<'de>>(self, mut seq: S) -> Result<X, S::Error> {
            while let Some(X) = seq.next_element()? {}
            Ok(X)
        }
    }
    impl<'de> Deserialize<'de> for X {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<X, D::Error> {
            d.deserialize_any(X)
        }
    }
    let mut doc = String::from("a: &a ~\nb: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\n");
    for (name, previous) in ('c'..='i').zip('b'..='h') {
        let row = vec![format!("*{previous}"); 9].join(",");
        doc.push_str(&format!("{name}: &{name} [{row}]\n"));
    }
    assert!(yaml::from_str::<BTreeMap<String, X>>(&doc).is_err());
}

/// test_error `test_duplicate_keys`: a repeated key is refused whatever its kind, a string, null
/// spelled two ways, an integer, an empty mapping, each named as serde_yaml named it, at the
/// repeat.
#[test]
fn duplicate_keys_of_every_kind_are_refused() {
    for (doc, refusal) in [
        (
            "---\nthing: true\nthing: false\n",
            "duplicate entry with key \"thing\"",
        ),
        (
            "---\nnull: true\n~: false\n",
            "duplicate entry with null key",
        ),
        ("---\n99: true\n99: false\n", "duplicate entry with key 99"),
        ("---\n{}: true\n{}: false\n", "duplicate entry in YAML map"),
    ] {
        let error = yaml::from_str::<Value>(doc).expect_err(doc);
        assert!(error.to_string().starts_with(refusal), "{doc:?}: {error}");
        assert_eq!(
            error.location().map(|l| l.line()),
            Some(3),
            "{doc:?}: {error}"
        );
    }
}

/// test_error `test_deserialize_nested_enum`: into `Outer::Inner(Inner)`, 1.5.5 refused `!Inner []`
/// (the inner enum has no variant), `!Variant []` (not a variant of `Outer`) and
/// `!Inner !Variant []` (two tags on one node).
#[test]
fn nested_enums_1_5_5_refused_are_refused() {
    #[derive(Debug, Deserialize, PartialEq)]
    enum Outer {
        Inner(Inner),
    }
    #[derive(Debug, Deserialize, PartialEq)]
    enum Inner {
        Variant(Vec<usize>),
    }
    for doc in [
        "---\n!Inner []\n",
        "---\n!Variant []\n",
        "---\n!Inner !Variant []\n",
    ] {
        assert!(
            yaml::from_str::<Outer>(doc).is_err(),
            "{doc:?} must be refused, as 1.5.5 refused it"
        );
    }
    for doc in ["---\n!Inner []\n", "---\n!Variant []\n"] {
        assert!(
            yaml::from_value::<Outer>(tree(doc)).is_err(),
            "{doc:?} read from a tree must be refused, as 1.5.5 refused it"
        );
    }
}

/// test_serde `test_nested_enum`: `Outer::Inner(Inner::Unit)` is written `!Inner Unit`, and
/// `!Inner Unit` reads back as it, from the text and from a tree.
#[test]
fn nested_enum_with_a_unit_inner_variant_round_trips() {
    #[derive(Debug, Deserialize, serde::Serialize, PartialEq)]
    enum Outer {
        Inner(Inner),
    }
    #[derive(Debug, Deserialize, serde::Serialize, PartialEq)]
    enum Inner {
        Unit,
    }
    let thing = Outer::Inner(Inner::Unit);
    assert_eq!(yaml::to_string(&thing).unwrap(), "!Inner Unit\n");
    assert_eq!(yaml::from_str::<Outer>("!Inner Unit\n").unwrap(), thing);
    assert_eq!(
        yaml::from_value::<Outer>(tree("!Inner Unit\n")).unwrap(),
        thing
    );
    let value = yaml::to_value(&thing).unwrap();
    assert_eq!(value, yaml::tagged("!Inner", text("Unit")));
    assert_eq!(yaml::to_string(&value).unwrap(), "!Inner Unit\n");
    assert_eq!(yaml::from_value::<Outer>(value).unwrap(), thing);
}

/// test_serde `test_unit`, `test_unit_struct`: every null spelling reads as `()` and as a unit
/// struct (plain `null`, `Null`, `NULL`, `~`, and an empty node), from the text and from a tree;
/// both are written `null`.
#[test]
fn null_reads_as_unit_and_as_a_unit_struct() {
    #[derive(Debug, Deserialize, serde::Serialize, PartialEq)]
    struct Foo;
    let nulls = "- null\n- Null\n- NULL\n- ~\n-\n";
    assert_eq!(yaml::from_str::<Vec<()>>(nulls).unwrap(), vec![(); 5]);
    assert_eq!(
        yaml::from_value::<Vec<()>>(tree(nulls)).unwrap(),
        vec![(); 5]
    );
    assert_eq!(
        yaml::from_str::<Vec<Foo>>(nulls).unwrap(),
        vec![Foo, Foo, Foo, Foo, Foo]
    );
    assert_eq!(
        yaml::from_value::<Vec<Foo>>(tree(nulls)).unwrap(),
        vec![Foo, Foo, Foo, Foo, Foo]
    );
    assert_eq!(yaml::from_str::<Foo>("null\n").unwrap(), Foo);
    assert_eq!(yaml::from_value::<Foo>(tree("null\n")).unwrap(), Foo);
    yaml::from_str::<()>("null\n").unwrap();

    let units = vec![(), ()];
    assert_eq!(yaml::to_string(&units).unwrap(), "- null\n- null\n");
    assert_eq!(
        yaml::from_str::<Vec<()>>("- null\n- null\n").unwrap(),
        units
    );
    assert_eq!(yaml::to_string(&Foo).unwrap(), "null\n");
}

/// test_serde `test_unit_variant`, `test_newtype_variant`, `test_tuple_variant`,
/// `test_struct_variant`, `test_tagged_map_value`: a typed enum is written as 1.5.5 wrote it (a
/// unit variant as its plain name, any other as `!Variant` over its content), and what is written
/// reads back as the value, from the text, from a tree, and through `to_value`.
#[test]
fn typed_enums_are_written_as_1_5_5_wrote_them_and_read_back() {
    #[derive(Debug, Deserialize, serde::Serialize, PartialEq)]
    enum Variant {
        First,
        Second,
        Size(usize),
        Rgb(u8, u8, u8),
        Color { r: u8, g: u8, b: u8 },
    }
    for (thing, written) in [
        (Variant::First, "First\n"),
        (Variant::Second, "Second\n"),
        (Variant::Size(127), "!Size 127\n"),
        (Variant::Rgb(32, 64, 96), "!Rgb\n- 32\n- 64\n- 96\n"),
        (
            Variant::Color {
                r: 32,
                g: 64,
                b: 96,
            },
            "!Color\nr: 32\ng: 64\nb: 96\n",
        ),
    ] {
        assert_eq!(yaml::to_string(&thing).unwrap(), written, "{thing:?}");
        let mut through_writer = Vec::new();
        yaml::to_writer(&mut through_writer, &thing).unwrap();
        assert_eq!(String::from_utf8(through_writer).unwrap(), written);
        assert_eq!(yaml::from_str::<Variant>(written).unwrap(), thing);
        assert_eq!(yaml::from_value::<Variant>(tree(written)).unwrap(), thing);
        let value = yaml::to_value(&thing).unwrap();
        assert_eq!(value, tree(written), "{thing:?}");
        assert_eq!(yaml::to_string(&value).unwrap(), written, "{thing:?}");
        assert_eq!(yaml::from_value::<Variant>(value).unwrap(), thing);
    }

    #[derive(Debug, Deserialize, serde::Serialize, PartialEq)]
    struct Bindings {
        profile: Profile,
    }
    #[derive(Debug, Deserialize, serde::Serialize, PartialEq)]
    enum Profile {
        ClassValidator { class_name: String },
    }
    let thing = Bindings {
        profile: Profile::ClassValidator {
            class_name: "ApplicationConfig".to_owned(),
        },
    };
    let written = "profile: !ClassValidator\n  class_name: ApplicationConfig\n";
    assert_eq!(yaml::to_string(&thing).unwrap(), written);
    assert_eq!(yaml::from_str::<Bindings>(written).unwrap(), thing);
    assert_eq!(yaml::from_value::<Bindings>(tree(written)).unwrap(), thing);

    // Inside an `Option` and a sequence, each variant still writes its tag and reads back.
    #[derive(Debug, Deserialize, serde::Serialize, PartialEq)]
    struct Nested {
        maybe: Option<Variant>,
        list: Vec<Variant>,
    }
    let thing = Nested {
        maybe: Some(Variant::Size(1)),
        list: vec![
            Variant::First,
            Variant::Size(2),
            Variant::Rgb(1, 2, 3),
            Variant::Color { r: 4, g: 5, b: 6 },
        ],
    };
    let written = yaml::to_string(&thing).unwrap();
    for tag in ["!Size", "!Rgb", "!Color"] {
        assert!(written.contains(tag), "{tag} in {written}");
    }
    assert!(!written.contains("Size:"), "{written}");
    assert_eq!(
        yaml::from_str::<Nested>(&written).unwrap(),
        thing,
        "{written}"
    );
    assert_eq!(
        yaml::from_value::<Nested>(tree(&written)).unwrap(),
        thing,
        "{written}"
    );
}

/// test_de `test_de_mapping`, test_serde `test_mapping`: a `Mapping` field of a typed struct reads
/// its pairs in order, from the text and from a tree, and is written back as a block mapping.
#[test]
fn a_mapping_field_reads_its_pairs() {
    #[derive(Debug, Deserialize, serde::Serialize, PartialEq)]
    struct Data {
        substructure: Mapping,
    }
    let doc = "substructure:\n  a: 'foo'\n  b: 'bar'\n";
    let expected = Data {
        substructure: Mapping::from(vec![(text("a"), text("foo")), (text("b"), text("bar"))]),
    };
    let read: Data = yaml::from_str(doc).unwrap();
    assert_eq!(read, expected);
    let keys: Vec<_> = read
        .substructure
        .keys()
        .filter_map(ValueExt::as_str)
        .collect();
    assert_eq!(keys, ["a", "b"]);
    assert_eq!(yaml::from_value::<Data>(tree(doc)).unwrap(), expected);
    assert_eq!(
        yaml::to_string(&expected).unwrap(),
        "substructure:\n  a: foo\n  b: bar\n"
    );
}

// ---- Cases traced against the 1.5.5 source (busbar-yaml's `de.rs`, libyaml's reader) ----

/// The explicit empty document `---` is one empty node: `None` and null, and (1.5.5's
/// `deserialize_map`/`deserialize_seq` took an empty plain scalar as empty) an all-optional
/// struct, an empty sequence and an empty map.
#[test]
fn an_explicit_empty_document_is_empty() {
    #[derive(Debug, Deserialize, PartialEq)]
    struct NoRequiredFields {
        optional: Option<usize>,
    }
    assert_eq!(yaml::from_str::<Option<String>>("---\n").unwrap(), None);
    assert_eq!(yaml::from_str::<Value>("---\n").unwrap(), Value::Null);
    // PROPOSED ACCEPT (item 3): 1.5.5 read these as empty; serde-saphyr refuses `---` for a
    // struct, a `Vec` and a map (its own port of `test_no_required_fields` asserts the refusal).
    // Red until approved or fixed.
    assert_eq!(
        yaml::from_str::<NoRequiredFields>("---\n").unwrap(),
        NoRequiredFields { optional: None }
    );
    assert!(yaml::from_str::<Vec<String>>("---\n").unwrap().is_empty());
    assert!(yaml::from_str::<BTreeMap<String, usize>>("---\n")
        .unwrap()
        .is_empty());
}

/// 1.5.5 read a unit struct as unit only (`deserialize_unit_struct` was `deserialize_unit`):
/// an empty mapping was refused, from the text and from a tree.
#[test]
fn an_empty_mapping_is_not_a_unit_struct() {
    #[derive(Debug, Deserialize, PartialEq)]
    struct Foo;
    assert!(yaml::from_value::<Foo>(tree("{}\n")).is_err());
    // PROPOSED ACCEPT (item 4): serde-saphyr reads `{}` as the unit struct. Red until approved.
    assert!(yaml::from_str::<Foo>("{}\n").is_err());
}

/// 1.5.5's radix prefixes were lower-case only (`0x`, `0o`, `0b`): an upper-case one was a
/// string untyped and refused for an integer field.
// PROPOSED ACCEPT (item 5): serde-saphyr also takes `0X`, `0O`, `0B`, so `0XFF` is 255, `0O17` 15,
// `0B1` 1 and `-0XFF` -255, untyped and typed. Red until approved or fixed.
#[test]
fn upper_case_radix_prefixes_are_not_numbers() {
    for word in ["0XFF", "0O17", "0B1", "+0XFF", "-0XFF"] {
        assert_eq!(tree(word), text(word), "`{word}` must stay a string");
    }
    assert!(yaml::from_str::<u32>("0XFF\n").is_err());
    assert!(yaml::from_str::<i64>("-0XFF\n").is_err());
}

/// libyaml's reader refused a character outside YAML's printable set anywhere in the text
/// (`control characters are not allowed`), in a plain or quoted scalar or in a comment, for
/// every reader; the 12 recorded refusals hold `\u{7}` or `\u{7f}`.
#[test]
fn control_characters_are_refused() {
    for doc in [
        "k: a\u{7}b\n",
        "k: \"a\u{7f}b\"\n",
        "# a\u{7}comment\nk: v\n",
        "k: a\u{80}b\n",
        "k: v\u{1b}\n",
    ] {
        assert!(yaml::from_str::<Value>(doc).is_err(), "{doc:?}");
    }
    let error = yaml::from_str::<BTreeMap<String, String>>("k: v\nl: a\u{7}b\n")
        .expect_err("typed reads refuse it too");
    assert!(
        error
            .to_string()
            .starts_with("control characters are not allowed"),
        "{error}"
    );
    let at = error.location().expect("the refusal names a position");
    assert_eq!((at.line(), at.column()), (2, 5), "{error}");
    // A tab, a line break and the rest of Unicode are printable.
    assert_eq!(
        tree("k: a\tb \u{e9}\u{1f389}\n").at("k"),
        &text("a\tb \u{e9}\u{1f389}")
    );
}

/// libyaml read a byte order mark after the first character as an ordinary character: content
/// of the scalar it is in, or the start of a plain scalar (recorded `mutated-oracle-config#58`,
/// `admin_auth: \u{feff}[admin-tokens]`). Only a leading mark is skipped.
#[test]
fn an_inner_byte_order_mark_is_content() {
    assert_eq!(tree("k: \u{feff}[x]\n").at("k"), &text("\u{feff}[x]"));
    assert_eq!(tree("k: a\u{feff}b\n").at("k"), &text("a\u{feff}b"));
    assert_eq!(tree("\u{feff}k: \u{feff}v\n").at("k"), &text("\u{feff}v"));
    assert_eq!(tree("k: '\u{feff}v'\n").at("k"), &text("\u{feff}v"));
    let doc = tree("k: 1\n\u{feff}l: 2\n");
    assert_eq!(doc.at("\u{feff}l").as_u64(), Some(2), "{doc:?}");
}

/// The same byte order mark, read into a typed field.
// PROPOSED ACCEPT (item 8): 1.5.5 read `"\u{feff}[x]"`; serde-saphyr refuses a mark that starts a
// token (`BomInsideDocument`). Untyped reads are fixed; typed reads would need the forwarding
// layer. Red until approved or fixed.
#[test]
fn an_inner_byte_order_mark_is_content_in_typed_reads() {
    #[derive(Debug, Deserialize, PartialEq)]
    struct K {
        k: String,
    }
    assert_eq!(
        yaml::from_str::<K>("k: \u{feff}[x]\n").unwrap(),
        K {
            k: "\u{feff}[x]".to_owned()
        }
    );
}

/// serde_yaml's recursion limit: 128 nested sequences or mappings read, the 129th refused
/// (`remaining_depth: 128`), untyped and typed.
#[test]
fn nesting_is_allowed_128_deep() {
    let nested = |depth: usize| "[".repeat(depth) + &"]".repeat(depth);
    assert!(yaml::from_str::<Value>(&nested(128)).is_ok());
    assert!(yaml::from_str::<Value>(&nested(129)).is_err());
    let block = |depth: usize| {
        (0..depth)
            .map(|level| format!("{}k:\n", "  ".repeat(level)))
            .collect::<String>()
    };
    assert!(yaml::from_str::<Value>(&block(128)).is_ok());
    assert!(yaml::from_str::<Value>(&block(129)).is_err());
    assert!(yaml::from_str::<BTreeMap<String, Value>>(&block(128)).is_ok());
}
