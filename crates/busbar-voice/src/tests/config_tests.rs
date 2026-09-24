// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-voice/src/config.rs`.

use super::*;

/// An ABSENT section (`default_section`) and an empty `streams: {}` must decode to the SAME value,
/// or a present-but-empty block would silently differ from an omitted one.
#[test]
fn empty_section_equals_default() {
    let empty: StreamsCfg =
        serde_yaml::from_value(serde_yaml::Value::Mapping(Default::default())).unwrap();
    assert_eq!(empty, StreamsCfg::default());
}

/// The plane defaults are the DoD ceilings, and the synthesized VAD carries the `streams:`-level
/// 500ms silence (not the IR wire default of 200ms).
#[test]
fn defaults_are_the_dod_values() {
    let c = StreamsCfg::default();
    assert_eq!(
        c.session_max_secs, None,
        "no ceiling unless configured (Q21a)"
    );
    assert_eq!(c.context_window_tokens, 32_768);
    assert_eq!(c.max_output_tokens, 4096);
    match c.session.turn_detection {
        Some(Some(IrVad::ServerVad {
            silence_duration_ms,
            ..
        })) => assert_eq!(silence_duration_ms, 500),
        other => panic!("expected synthesized server_vad, got {other:?}"),
    }
}

/// A valid `streams:` block — session/VAD knobs plus the three ceilings — parses through the
/// owned `parse_section` hook (the boot-validate leg's (a) assertion).
#[test]
fn a_valid_streams_block_parses_through_parse_section() {
    let y: serde_yaml::Value = serde_yaml::from_str(
        "session:\n  \
             voice: alloy\n  \
             turn_detection:\n    \
             type: server_vad\n    \
             silence_duration_ms: 700\n\
             session_max_secs: 1800\n\
             context_window_tokens: 8192\n\
             max_output_tokens: 2048\n",
    )
    .unwrap();
    let boxed = streams_parse_section(&y).expect("a valid streams: block must parse");
    assert!(
        boxed.is_present(),
        "an operator-written streams: block is present"
    );
}

/// `deny_unknown_fields` refuses a typo'd key at parse — the boot-validate leg's (b) assertion.
#[test]
fn unknown_key_is_refused() {
    let mut m = serde_yaml::Mapping::new();
    m.insert("nonsense_key".into(), 1.into());
    let err = streams_parse_section(&serde_yaml::Value::Mapping(m)).unwrap_err();
    assert!(err.contains("nonsense_key"), "{err}");
}

/// `default_section` is the empty section, and it is NOT `is_present` (an omitted block names no
/// plane and is not refused).
#[test]
fn default_section_is_absent() {
    let s = streams_default_section();
    assert!(!s.is_present());
}

/// OWNER RULING Q21a: the session wall-clock ceiling is optional and plane-owned. Absent reads as no
/// ceiling; a positive figure is kept; zero and a negative figure are refused at parse.
#[test]
fn the_session_ceiling_is_optional_and_refuses_zero_and_negative() {
    let parse = |yaml: &str| {
        streams_parse_section(&serde_yaml::from_str::<serde_yaml::Value>(yaml).unwrap()).map(|b| {
            b.as_any()
                .downcast_ref::<StreamsCfg>()
                .expect("the plane's own section")
                .session_max_secs
        })
    };
    assert_eq!(parse("{}").unwrap(), None, "absent: no ceiling");
    assert_eq!(
        parse("session_max_secs: 1800")
            .unwrap()
            .map(std::num::NonZeroU32::get),
        Some(1800)
    );
    assert!(parse("session_max_secs: 0").is_err(), "zero is refused");
    assert!(
        parse("session_max_secs: -5").is_err(),
        "a negative figure is refused"
    );
}
