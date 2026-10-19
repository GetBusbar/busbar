// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-contract/src/secret_ref.rs`. The sugars here are the suite's own two
//! Statements (`alpha`, `beta`), declared through the one path a host's loaded Statements take: the
//! contract names no plugin and no sugar word.

use super::*;
use crate::abi::mechanism::door::{
    REWRITE_ALIAS, REWRITE_SUGAR, REWRITE_SUGAR_NAMES, REWRITE_SUGAR_ROLE, REWRITE_SUGAR_SHOWN,
    SUGAR_ROLE_FILL, SUGAR_ROLE_PATH,
};

fn rw(class: u32, from: &str, to: &str) -> (u32, String, String) {
    (class, from.to_string(), to.to_string())
}

/// The suite's two Statements: `alpha` (`{ alpha: X }` ⇒ `settings.name`, shown `<NAME>`, the fill)
/// and `beta` (`{ beta: X }` ⇒ `settings.loc`, the path role, its placeholder unstated).
fn sugars() -> Sugars {
    let mut s = Sugars::default();
    s.declare(
        "plugin-alpha",
        &[
            rw(REWRITE_ALIAS, "alpha", ""),
            rw(REWRITE_SUGAR, "alpha", "name"),
            rw(REWRITE_SUGAR_SHOWN, "alpha", "NAME"),
            rw(REWRITE_SUGAR_NAMES, "alpha", "the alpha name"),
            rw(REWRITE_SUGAR_ROLE, "alpha", SUGAR_ROLE_FILL),
        ],
    )
    .expect("alpha declares");
    s.declare(
        "plugin-beta",
        &[
            rw(REWRITE_SUGAR, "beta", "loc"),
            rw(REWRITE_SUGAR_ROLE, "beta", SUGAR_ROLE_PATH),
        ],
    )
    .expect("beta declares");
    s
}

/// Read `yaml` against the suite's sugars; a refusal is its text without the library's
/// ` at line L column C` (the oracle cells pin the positions over a whole configuration).
fn declared(yaml: &str) -> Result<SecretRef, String> {
    SecretRef::deserialize_declared(serde_yaml::Deserializer::from_str(yaml), &sugars())
        .map_err(|e| body(&e.to_string()))
}

/// `text` without a trailing ` at line L column C`.
fn body(text: &str) -> String {
    match text.rfind(" at line ") {
        Some(at) if text[at..].contains(" column ") => text[..at].to_string(),
        _ => text.to_string(),
    }
}

/// The declared reading: each sugar lands on its Statement's settings key; the canonical form
/// parses; mixed / unknown / empty forms are refused.
#[test]
fn a_declared_sugar_lands_on_its_statements_settings_key() {
    let s = sugars();
    assert_eq!(
        declared("{ alpha: MY_VAR }"),
        Ok(s.get("alpha").unwrap().reference("MY_VAR"))
    );
    assert_eq!(
        serde_json::to_value(declared("{ beta: /run/x }").unwrap()).unwrap(),
        serde_json::json!({"module": "beta", "settings": {"loc": "/run/x"}})
    );
    let r = declared("{ module: vault, settings: { path: kv/data/x } }").unwrap();
    assert_eq!(r.module, "vault");
    for bad in [
        "{ alpha: A, beta: B }",
        "{ module: vault, alpha: A }",
        "{ alpha: A, settings: {} }",
        "{ unknown_key: A }",
        "{}",
        "{ alpha: \"\" }",
        "{ module: \"\" }",
        "plain-string",
    ] {
        assert!(declared(bad).is_err(), "must reject: {bad}");
    }
}

/// RED (owner law 2026-09-27): a sugar no loaded Statement declares is REFUSED, in serde's own
/// unknown-field words, the declared sugars listed after the canonical keys.
#[test]
fn a_sugar_no_loaded_statement_declares_is_refused() {
    assert_eq!(
        declared("{ gamma: X }").unwrap_err(),
        "unknown field `gamma`, expected one of `module`, `settings`, `alpha`, `beta`"
    );
    // With no Statement declaring any, nothing but the core grammar reads.
    let none = SecretRef::deserialize_declared(
        serde_yaml::Deserializer::from_str("{ alpha: X }"),
        &Sugars::default(),
    )
    .unwrap_err()
    .to_string();
    assert_eq!(
        body(&none),
        "unknown field `alpha`, expected `module` or `settings`"
    );
}

/// Every refusal that lists the sugars renders the declared ones, in the words 1.5.5 used for its
/// two (oracle BOOT-P33..P38 pin the same sentences over the linked Statements).
#[test]
fn every_refusal_lists_the_declared_sugars() {
    for (yaml, want) in [
        (
            "{ alpha: A, beta: B }",
            "a secret reference takes exactly one of `alpha:` / `beta:`",
        ),
        (
            "{ module: vault, alpha: A }",
            "a secret reference is either `{ module: …, settings: … }` or the `{ alpha: … }` / \
             `{ beta: … }` sugar, not both",
        ),
        (
            "{ alpha: A, settings: {} }",
            "the `{ alpha: … }` / `{ beta: … }` sugar takes no `settings:` (use the canonical \
             `{ module: …, settings: … }` form instead)",
        ),
        (
            "{ alpha: \"\" }",
            "a `{ alpha: … }` secret reference must name a non-empty value",
        ),
        (
            "{}",
            "a secret reference needs `module:` (with optional `settings:`) or the \
             `{ alpha: <NAME> }` / `{ beta: <loc> }` sugar",
        ),
    ] {
        assert_eq!(declared(yaml).unwrap_err(), want, "{yaml}");
    }
    assert_eq!(
        declared("s3cret").unwrap_err(),
        "a secret value must be a REFERENCE, never an inline literal (the value is not echoed): \
         use { alpha: <NAME> }, { beta: <loc> }, { module: <secret-module>, settings: {…} }, or \
         the bare scalar `none` to declare an upstream that takes NO credential"
    );
}

/// The CONTEXT-FREE reading (a plugin's own settings; no host table): any non-core one-key map is
/// a sugar, its value under its own word; the host binds it.
#[test]
fn the_context_free_reading_takes_the_sugar_shape_and_the_host_binds_it() {
    let r: SecretRef = serde_yaml::from_str("{ alpha: MY_VAR }").unwrap();
    assert_eq!(r, SecretRef::sugar("alpha", "MY_VAR"));
    assert_eq!(r.sugar_parts(), Some(("alpha", "MY_VAR")));
    assert_eq!(r.describe(), "alpha:MY_VAR");
    let s = sugars();
    assert_eq!(s.canonical(&r), s.get("alpha").unwrap().reference("MY_VAR"));
    // A word no Statement declares stays as read: no plugin answers it.
    let gamma: SecretRef = serde_yaml::from_str("{ gamma: X }").unwrap();
    assert_eq!(s.canonical(&gamma), gamma);
    // Core grammar is never a sugar.
    for bad in [
        "{ literal: x }",
        "{ none: x }",
        "{ alpha: A, beta: B }",
        "{}",
        "{ alpha: \"  \" }",
    ] {
        assert!(
            serde_yaml::from_str::<SecretRef>(bad).is_err(),
            "must reject: {bad}"
        );
    }
}

/// `describe()`'s forms, table-free and declared: a declared sugar's reference reads `<word>:<value>`
/// whichever way it was spelled.
#[test]
fn describe_renders_sugar_and_module_forms() {
    let s = sugars();
    let canonical = declared("{ module: alpha, settings: { name: MY_VAR } }").unwrap();
    assert_eq!(s.describe(&canonical), "alpha:MY_VAR");
    assert_eq!(s.describe(&declared("{ beta: /x }").unwrap()), "beta:/x");
    let vault = declared("{ module: vault, settings: { path: kv/data/x } }").unwrap();
    assert_eq!(vault.describe(), "secret module 'vault'");
    assert_eq!(s.describe(&vault), "secret module 'vault'");
    assert_eq!(s.describe(&SecretRef::none()), "none");
}

/// RED: two Statements claiming one sugar word, or one role, are refused at load, naming both.
#[test]
fn two_statements_claiming_one_sugar_or_one_role_are_refused() {
    let mut s = sugars();
    assert_eq!(
        s.declare("plugin-gamma", &[rw(REWRITE_SUGAR, "alpha", "k")]),
        Err(
            "plugin claim conflict: the sugar `alpha:` is declared by both \
             'plugin-alpha' and 'plugin-gamma' - a reference key must name one plugin; remove \
             one"
            .to_string()
        )
    );
    assert_eq!(
        s.declare(
            "plugin-gamma",
            &[
                rw(REWRITE_SUGAR, "gamma", "k"),
                rw(REWRITE_SUGAR_ROLE, "gamma", SUGAR_ROLE_FILL),
            ]
        ),
        Err(
            "plugin claim conflict: the sugar role 'fill' is claimed by both \
             'plugin-alpha' (`alpha:`) and 'plugin-gamma' (`gamma:`) - a role names one sugar; \
             remove one"
                .to_string()
        )
    );
    // A refused Statement declares nothing.
    assert!(s.get("gamma").is_none());
    assert_eq!(s, sugars());
    // The core grammar, a missing settings key, a fact about an undeclared word and an unknown role
    // are each refused.
    for rewrites in [
        vec![rw(REWRITE_SUGAR, "module", "k")],
        vec![rw(REWRITE_SUGAR, "literal", "k")],
        vec![rw(REWRITE_SUGAR, "gamma", "")],
        vec![rw(REWRITE_SUGAR_SHOWN, "delta", "D")],
        vec![
            rw(REWRITE_SUGAR, "gamma", "k"),
            rw(REWRITE_SUGAR_ROLE, "gamma", "other"),
        ],
    ] {
        assert!(
            Sugars::default()
                .declare("plugin-gamma", &rewrites)
                .is_err(),
            "{rewrites:?}"
        );
    }
    assert_eq!(
        s.with_role(SUGAR_ROLE_FILL).map(|x| x.word.as_str()),
        Some("alpha")
    );
    assert_eq!(
        s.with_role(SUGAR_ROLE_PATH).map(|x| x.word.as_str()),
        Some("beta")
    );
}

/// `none` — the EXPLICIT keyless declaration — parses from the bare scalar and from the canonical
/// `{ module: none }`, and `describe()` renders it as the word itself.
///
/// The near-misses matter as much as the hit: `none` is a reserved WORD, so anything that is not
/// exactly it must still take the non-echoing inline-literal refusal, and the `{ none: … }` map
/// form must not exist at all (it would invite settings on a reference that names no source).
#[test]
fn none_is_the_one_scalar_a_secret_field_accepts() {
    let r: SecretRef = serde_yaml::from_str("none").unwrap();
    assert_eq!(r, SecretRef::none());
    assert!(r.is_none());
    assert!(r.settings.is_empty());
    assert_eq!(r.describe(), "none");
    assert!(serde_yaml::from_str::<SecretRef>("{ module: none }")
        .unwrap()
        .is_none());
    assert!(serde_json::from_str::<SecretRef>("\"none\"")
        .unwrap()
        .is_none());
    for bad in ["None", "NONE", "no", "nones", "{ none: true }"] {
        assert!(serde_yaml::from_str::<SecretRef>(bad).is_err(), "{bad}");
        assert!(declared(bad).is_err(), "{bad}");
    }
    let err = serde_yaml::from_str::<SecretRef>("sk-live-abc123")
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("never an inline literal") && !err.contains("sk-live-abc123"),
        "{err}"
    );
}

/// The `Visitor::expecting` error message names the accepted shapes, through serde's own
/// invalid-type path (a sequence: no `visit_*` override catches it).
#[test]
fn deserialize_error_message_names_the_accepted_shapes() {
    assert_eq!(
        declared("[1, 2]").unwrap_err(),
        "invalid type: sequence, expected a secret reference map: { module: <secret-module>, \
         settings: {…} }, { alpha: <NAME> }, { beta: <loc> }, or the bare scalar `none`"
    );
    let free = serde_yaml::from_str::<SecretRef>("[1, 2]")
        .unwrap_err()
        .to_string();
    assert!(free.contains("a secret reference map"), "{free}");
}

/// The derived fragment is written out by hand next to the deserializer, not generated from it, so
/// what actually keeps the two in step is this: ONE table of shapes, each put to BOTH the schema and
/// the declared reading, with the two verdicts asserted EQUAL.
#[test]
fn the_schema_and_the_deserializer_agree_shape_for_shape() {
    let s = sugars();
    let mut full = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
    })
    .as_object()
    .unwrap()
    .clone();
    for (k, v) in s.oneof_schema().as_object().unwrap() {
        full.insert(k.clone(), v.clone());
    }
    let validator = jsonschema::validator_for(&serde_json::Value::Object(full))
        .expect("the derived fragment is a valid 2020-12 schema");

    let cases = [
        (serde_json::json!({"module": "vault"}), true),
        (
            serde_json::json!({"module": "vault", "settings": {"key": "x"}}),
            true,
        ),
        (serde_json::json!({"alpha": "MY_VAR"}), true),
        (serde_json::json!({"beta": "/run/secrets/x"}), true),
        (serde_json::json!("none"), true),
        (serde_json::json!({"module": "none"}), true),
        (serde_json::json!("None"), false),
        (serde_json::json!({"none": true}), false),
        (serde_json::json!({"alpha": "   "}), false),
        (serde_json::json!({"beta": "\t"}), false),
        (serde_json::json!({"module": " "}), false),
        (serde_json::json!({"alpha": ""}), false),
        (serde_json::json!({"module": ""}), false),
        (serde_json::json!({}), false),
        (serde_json::json!({"alpha": "A", "beta": "B"}), false),
        (serde_json::json!({"module": "vault", "alpha": "A"}), false),
        (serde_json::json!({"alpha": "A", "settings": {}}), false),
        (serde_json::json!({"literal": "s3cret"}), false),
        (serde_json::json!({"gamma": "x"}), false),
        (serde_json::json!("s3cret"), false),
        (serde_json::json!(483_920_175_534u64), false),
        (serde_json::json!(true), false),
    ];
    for (shape, expected) in &cases {
        let by_schema = validator.is_valid(shape);
        let by_serde = SecretRef::from_value_declared(shape.clone(), &s).is_ok();
        assert_eq!(
            by_schema, by_serde,
            "schema and deserializer disagree about {shape}"
        );
        assert_eq!(by_serde, *expected, "{shape}");
    }
}

/// A secret is not always quoted: an inline literal of any scalar spelling, and a non-string sugar
/// value, are refused without echoing the value, in both readings.
#[test]
fn an_inline_secret_is_refused_without_echoing_it() {
    for (yaml, value) in [
        ("\"hunter2secret\"", "hunter2secret"),
        ("483920175534", "483920175534"),
        ("-42", "42"),
        ("true", "true"),
        ("1.5", "1.5"),
        ("{ alpha: 12345 }", "12345"),
        ("{ beta: true }", "true"),
        (
            "{ module: vault, settings: \"sk-live-abc123\" }",
            "sk-live-abc123",
        ),
    ] {
        for err in [
            declared(yaml).expect_err("refused"),
            serde_yaml::from_str::<SecretRef>(yaml)
                .expect_err("refused")
                .to_string(),
        ] {
            assert!(!err.contains(value), "the refusal echoed the value: {err}");
            assert!(err.contains("never an inline literal"), "{err}");
        }
    }
}

/// A non-string `module:` names no module, and is refused without echoing it.
#[test]
fn a_non_string_module_is_refused_without_echoing_it() {
    let err = declared("{ module: 12345 }").expect_err("refused");
    assert!(
        !err.contains("12345") && err.contains("must be a string"),
        "{err}"
    );
}

/// Duplicate `module:` / `settings:` keys are refused with serde's `duplicate_field`.
#[test]
fn duplicate_keys_are_refused() {
    let err = serde_json::from_str::<SecretRef>(r#"{"module":"vault","module":"other"}"#)
        .expect_err("a duplicate module: is malformed")
        .to_string();
    assert!(
        err.contains("duplicate field") && err.contains("module"),
        "{err}"
    );
    let err = serde_json::from_str::<SecretRef>(
        r#"{"module":"vault","settings":{"key":"x"},"settings":{"key":"y"}}"#,
    )
    .expect_err("a duplicate settings: is malformed")
    .to_string();
    assert!(
        err.contains("duplicate field") && err.contains("settings"),
        "{err}"
    );
}

/// Serialize: every accepted spelling lands on the canonical `{ module, settings }` wire shape
/// (the admin redaction keys off `settings`), a declared sugar on its Statement's settings key.
#[test]
fn serialize_yields_the_canonical_module_settings_wire_shape() {
    for (r, want) in [
        (
            declared("{ alpha: MY_VAR }").unwrap(),
            serde_json::json!({"module": "alpha", "settings": {"name": "MY_VAR"}}),
        ),
        (
            declared("{ module: vault, settings: { key: kv/data/x } }").unwrap(),
            serde_json::json!({"module": "vault", "settings": {"key": "kv/data/x"}}),
        ),
        (
            declared("none").unwrap(),
            serde_json::json!({"module": "none", "settings": {}}),
        ),
    ] {
        assert_eq!(serde_json::to_value(&r).unwrap(), want);
    }
}

/// A TEMPLATE reference resolves each `${VAR}` through the FILL sugar's reference; any other
/// reference is handed to the resolver whole; a `$` that opens no `${VAR}` stays as written; with no
/// fill sugar declared, a template with a `${VAR}` does not resolve (fail-closed).
#[test]
fn a_template_reference_resolves_each_variable_through_the_fill_sugar() {
    let resolve = |r: &SecretRef| match r.sugar_parts() {
        Some(("alpha", "A")) => Ok(crate::secret::Resolved::new("alpha-v".to_string())),
        Some(("alpha", "B")) => Ok(crate::secret::Resolved::new("beta-v".to_string())),
        _ => Err(format!("{} does not resolve", r.describe())),
    };
    let text = |r: Result<crate::secret::Resolved<String>, String>| r.map(|r| r.0.clone());
    let t = SecretRef::template("Bearer ${A}:${B} $5 ${ and ${");
    assert_eq!(t.module, SECRET_MODULE_TEMPLATE);
    assert_eq!(t.template_text(), Some("Bearer ${A}:${B} $5 ${ and ${"));
    assert_eq!(
        text(t.resolve_template(Some("alpha"), &resolve)).as_deref(),
        Ok("Bearer alpha-v:beta-v $5 ${ and ${")
    );
    assert_eq!(
        text(SecretRef::sugar("alpha", "B").resolve_template(Some("alpha"), &resolve)).as_deref(),
        Ok("beta-v")
    );
    assert_eq!(
        text(SecretRef::template("x ${C}").resolve_template(Some("alpha"), &resolve)),
        Err("alpha:C does not resolve".to_string())
    );
    assert!(t.resolve_template(None, &resolve).is_err());
    let back: SecretRef = serde_json::from_value(serde_json::to_value(&t).unwrap()).unwrap();
    assert_eq!(back, t);
}
