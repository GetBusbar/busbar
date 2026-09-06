// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/plugin-testkit/src/lib.rs`.

use super::*;

fn ok_open(_cfg: &str) -> Result<(), String> {
    Ok(())
}

fn always_err_open(_cfg: &str) -> Result<(), String> {
    Err("some descriptive failure".to_string())
}

fn empty_err_open(_cfg: &str) -> Result<(), String> {
    Err(String::new())
}

/// A well-behaved plugin's rejection: it names the config as the problem AND the field that is
/// missing, which is exactly what the two assertions below hold every plugin to. The testkit's own
/// fixture has to satisfy its own rulings, or the tests here are checking nothing.
fn descriptive_err_open(_cfg: &str) -> Result<(), String> {
    Err("invalid config: missing required field `issuer`".to_string())
}

/// Fails, but says nothing an operator can act on: no field name, no mention of config.
fn vague_err_open(_cfg: &str) -> Result<(), String> {
    Err("something went wrong".to_string())
}

#[test]
#[should_panic(expected = "expected open() to fail")]
fn expect_err_panics_when_open_succeeds() {
    expect_err(ok_open(""));
}

#[test]
fn expect_err_returns_the_error_string() {
    assert_eq!(expect_err(always_err_open("")), "some descriptive failure");
}

#[test]
fn assert_empty_config_rejected_passes_for_a_well_behaved_plugin() {
    assert_empty_config_rejected(descriptive_err_open);
}

/// The ruling the doc always claimed and the helper never enforced: a rejection that does not name
/// what is wrong is not a rejection an operator can debug from their boot log.
#[test]
#[should_panic(expected = "must say WHAT is missing")]
fn assert_empty_config_rejected_catches_an_error_that_names_nothing() {
    assert_empty_config_rejected(vague_err_open);
}

#[test]
#[should_panic(expected = "expected open() to fail")]
fn assert_empty_config_rejected_catches_a_plugin_that_accepts_empty_config() {
    assert_empty_config_rejected(ok_open);
}

#[test]
#[should_panic(expected = "NON-empty, descriptive error")]
fn assert_empty_config_rejected_catches_a_blank_error_message() {
    assert_empty_config_rejected(empty_err_open);
}

#[test]
fn assert_whitespace_only_config_rejected_passes_for_a_well_behaved_plugin() {
    assert_whitespace_only_config_rejected(descriptive_err_open);
}

#[test]
fn assert_malformed_json_rejected_passes_for_a_well_behaved_plugin() {
    assert_malformed_json_rejected(descriptive_err_open);
}

#[test]
fn assert_missing_required_field_rejected_passes_for_a_well_behaved_plugin() {
    assert_missing_required_field_rejected(descriptive_err_open, r#"{"other":"field"}"#, "issuer");
}

/// A plugin that rejects the config but never says which field is missing leaves the operator
/// guessing across every field it has. That is the case this helper exists to catch, and did not.
#[test]
#[should_panic(expected = "must NAME the missing field")]
fn assert_missing_required_field_rejected_catches_an_error_that_omits_the_field() {
    assert_missing_required_field_rejected(vague_err_open, r#"{"other":"field"}"#, "issuer");
}

/// The field name is matched case-insensitively, as the doc says: a plugin that spells the field
/// `Issuer` in its message has still named it.
#[test]
fn assert_missing_required_field_rejected_matches_the_field_name_case_insensitively() {
    fn shouty_open(_cfg: &str) -> Result<(), String> {
        Err("Config error: `Issuer` is required".to_string())
    }
    assert_missing_required_field_rejected(shouty_open, r#"{"other":"field"}"#, "issuer");
}
