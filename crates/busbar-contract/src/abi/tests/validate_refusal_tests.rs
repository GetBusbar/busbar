// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The validate refusal rule (`abi/mechanism/lifecycle.rs`): one RED per arm of
//! `check_validate_refusal`, and the host's rendering pinned against the 1.5.5 words.

use super::*;
use crate::abi::mechanism::check::{Fault, Rule};

fn red(field: &'static str) -> Result<(), Fault> {
    Err(Fault {
        rule: Rule::Missing,
        field,
    })
}

#[test]
fn an_empty_refusal_faults() {
    assert_eq!(check_validate_refusal(b""), red("validate.error.empty"));
}

#[test]
fn a_leading_newline_faults() {
    assert_eq!(
        check_validate_refusal(b"\nsettings: x"),
        red("validate.error.leading_newline")
    );
}

#[test]
fn a_trailing_newline_faults() {
    assert_eq!(
        check_validate_refusal(b"settings: x\n"),
        red("validate.error.trailing_newline")
    );
}

#[test]
fn an_empty_line_faults() {
    assert_eq!(
        check_validate_refusal(b"settings: x\n\nsettings: y"),
        red("validate.error.empty_line")
    );
}

#[test]
fn several_lines_pass() {
    assert_eq!(check_validate_refusal(b"settings: x\nsentence"), Ok(()));
}

/// 1.5.5's prometheus refusal of a malformed settings bag, byte for byte.
#[test]
fn a_settings_path_line_renders_under_the_instance_as_1_5_5_spelled_it() {
    assert_eq!(
        refusal_lines(
            "export",
            "metrics",
            "settings: missing field `buffer_seconds`"
        ),
        vec!["export.metrics.settings: missing field `buffer_seconds`".to_string()]
    );
}

/// 1.5.5's prometheus zero-retention refusal: a sentence with no prefix, verbatim.
#[test]
fn a_sentence_renders_verbatim_as_1_5_5_spelled_it() {
    const ZERO: &str = "the `module: prometheus` export instance sets settings.buffer_seconds: 0, \
         which retains no observations — every scrape would report empty quantiles while still paying \
         the recording cost. Name a positive retention window in seconds, or remove the instance to \
         turn metrics off";
    assert_eq!(
        refusal_lines("export", "metrics", ZERO),
        vec![ZERO.to_string()]
    );
}

#[test]
fn only_a_first_segment_of_settings_is_instance_relative() {
    assert_eq!(
        refusal_lines(
            "export",
            "a",
            "settings.path: x\nsettingsx: y\nsettings[0]: z"
        ),
        vec![
            "export.a.settings.path: x".to_string(),
            "settingsx: y".to_string(),
            "export.a.settings[0]: z".to_string(),
        ]
    );
}
