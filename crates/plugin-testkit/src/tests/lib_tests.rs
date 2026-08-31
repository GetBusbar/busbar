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
    assert_empty_config_rejected(always_err_open);
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
    assert_whitespace_only_config_rejected(always_err_open);
}

#[test]
fn assert_malformed_json_rejected_passes_for_a_well_behaved_plugin() {
    assert_malformed_json_rejected(always_err_open);
}

#[test]
fn assert_missing_required_field_rejected_passes_for_a_well_behaved_plugin() {
    assert_missing_required_field_rejected(always_err_open, r#"{"other":"field"}"#, "issuer");
}
