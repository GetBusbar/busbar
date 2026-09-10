// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HALF OF THE CATALOG SEAM THAT WAS MISSING.
//!
//! A catalog could always find the words for a code and nothing could finish them: every caller of
//! `Catalog::template` in the tree asserted the template existed and none of them filled its holes,
//! so a template reached its reader with `{key}` still in it. These tests are about `render`, and
//! the last one runs it against the catalog a shipped example plugin actually declares.

use busbar_contract::{Catalog, ErrorClass, Param, ParamValue, PluginError};

/// The catalog `secret-example-plugin` ships, verbatim from `crates/secret-example-plugin/src/lib.rs`.
const SHIPPED: &str = r#"{
  "default_locale": "en",
  "entries": [
    { "code": "secret_example.key_missing", "templates": [
      { "locale": "en", "text": "the reference settings carry no string `key`" },
      { "locale": "de", "text": "die Referenz-Einstellungen enthalten keinen `key`" } ] },
    { "code": "secret_example.no_entry", "templates": [
      { "locale": "en", "text": "no entry named {key} in the map" },
      { "locale": "de", "text": "kein Eintrag namens {key} in der Tabelle" } ] }
  ]
}"#;

fn catalog() -> Catalog {
    serde_json::from_str(SHIPPED).expect("the shipped catalog parses")
}

fn err(code: &str) -> PluginError {
    PluginError::new(ErrorClass::NotFound, code)
}

#[test]
fn a_hole_is_filled_from_the_errors_own_parameters() {
    let e = err("secret_example.no_entry").with_param("key", ParamValue::Str("api_token".into()));
    assert_eq!(
        catalog().render(&e, "en").as_deref(),
        Some("no entry named api_token in the map")
    );
}

#[test]
fn a_locale_falls_back_exactly_as_the_template_lookup_does() {
    let e = err("secret_example.no_entry").with_param("key", ParamValue::Str("k".into()));
    // Declared locale.
    assert_eq!(
        catalog().render(&e, "de").as_deref(),
        Some("kein Eintrag namens k in der Tabelle")
    );
    // Undeclared locale falls back to the default, never to the developer message.
    assert_eq!(
        catalog().render(&e, "fr").as_deref(),
        Some("no entry named k in the map")
    );
}

#[test]
fn an_undeclared_code_renders_nothing_rather_than_something_wrong() {
    assert_eq!(catalog().render(&err("secret_example.nope"), "en"), None);
}

#[test]
fn a_hole_with_no_parameter_behind_it_is_left_visible() {
    // Blanking it would hide a missing parameter inside a plausible sentence; keeping it says so.
    let e = err("secret_example.no_entry");
    assert_eq!(
        catalog().render(&e, "en").as_deref(),
        Some("no entry named {key} in the map")
    );
}

#[test]
fn a_template_with_no_holes_is_returned_whole() {
    let e = err("secret_example.key_missing");
    assert_eq!(
        catalog().render(&e, "en").as_deref(),
        Some("the reference settings carry no string `key`")
    );
}

#[test]
fn every_kind_of_parameter_renders() {
    let cat: Catalog = serde_json::from_str(
        r#"{"default_locale":"en","entries":[{"code":"c","templates":[
             {"locale":"en","text":"s={s} i={i} b={b}"}]}]}"#,
    )
    .expect("parses");
    let e = PluginError::new(ErrorClass::Internal, "c")
        .with_param("s", ParamValue::Str("x".into()))
        .with_param("i", ParamValue::Int(-7))
        .with_param("b", ParamValue::Bool(true));
    assert_eq!(cat.render(&e, "en").as_deref(), Some("s=x i=-7 b=true"));
}

#[test]
fn a_value_carrying_braces_is_data_and_never_a_template() {
    // One left-to-right pass, never re-reading what it wrote: a plugin supplies both the codes and
    // the parameters, so a second pass would let it write a hole into a value and have the host
    // expand it — a plugin choosing what the host interpolates.
    let cat: Catalog = serde_json::from_str(
        r#"{"default_locale":"en","entries":[{"code":"c","templates":[
             {"locale":"en","text":"a={a} b={b}"}]}]}"#,
    )
    .expect("parses");
    let e = PluginError::new(ErrorClass::Internal, "c")
        .with_param("a", ParamValue::Str("{b}".into()))
        .with_param("b", ParamValue::Str("SECRET".into()));
    assert_eq!(cat.render(&e, "en").as_deref(), Some("a={b} b=SECRET"));
}

#[test]
fn an_unclosed_brace_is_a_brace_and_not_a_hole() {
    let cat: Catalog = serde_json::from_str(
        r#"{"default_locale":"en","entries":[{"code":"c","templates":[
             {"locale":"en","text":"a { b {c"}]}]}"#,
    )
    .expect("parses");
    let e = PluginError::new(ErrorClass::Internal, "c");
    assert_eq!(cat.render(&e, "en").as_deref(), Some("a { b {c"));
}

#[test]
fn the_developer_message_never_reaches_the_rendering() {
    // `developer_message` is for the log. A render that fell back to it would put a plugin's raw
    // words in front of a client, which is what the catalog exists to prevent.
    let e = PluginError::new(ErrorClass::NotFound, "secret_example.no_entry")
        .with_message("raw internal detail nobody outside should read")
        .with_param("key", ParamValue::Str("k".into()));
    let rendered = catalog().render(&e, "en").expect("the code is declared");
    assert!(!rendered.contains("raw internal detail"));
    assert_eq!(rendered, "no entry named k in the map");
}

#[test]
fn a_param_is_matched_by_its_whole_name() {
    let cat: Catalog = serde_json::from_str(
        r#"{"default_locale":"en","entries":[{"code":"c","templates":[
             {"locale":"en","text":"{ke} {key}"}]}]}"#,
    )
    .expect("parses");
    let e =
        PluginError::new(ErrorClass::Internal, "c").with_param("key", ParamValue::Str("V".into()));
    // `{ke}` is not `{key}`: a prefix is not a match, so it stays visible.
    assert_eq!(cat.render(&e, "en").as_deref(), Some("{ke} V"));
    let _ = Param {
        key: "unused".into(),
        value: ParamValue::Bool(false),
    };
}
