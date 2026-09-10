// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-voice/src/config.rs`.

use super::*;
use crate::ir::control::IrVad;

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
    assert_eq!(c.session_max_secs, 3600);
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

/// THE OPEN-PASS DENIAL SET IS A CONFIGURATION KEY, and it reaches the runtime the gate reads.
///
/// It was neither before this landing: the set lived on `VoiceRuntime` with a builder no
/// configuration file could reach, so a policy the plane refused sessions with could only be turned
/// on from inside the plane's own tests. This cell is the whole of the migration's operator half —
/// the key parses, an absent key is an empty set, and `with_streams` carries it onto the runtime the
/// open-pass gate is handed.
#[test]
fn the_denial_set_is_declared_in_the_section_and_carried_onto_the_runtime() {
    let y: serde_yaml::Value =
        serde_yaml::from_str("denied_destinations:\n  - blocked-model\n  - also-blocked\n")
            .unwrap();
    let cfg: StreamsCfg = serde_yaml::from_value(y).unwrap();
    assert_eq!(
        cfg.denied_destinations,
        ["blocked-model".to_string(), "also-blocked".to_string()],
        "the operator's list is what the section carries, in the order they wrote it"
    );

    // ABSENT is EMPTY, and empty is what every deployment that names nothing keeps.
    assert!(
        StreamsCfg::default().denied_destinations.is_empty(),
        "an absent key refuses nothing — the byte-identical posture for every deployment today"
    );

    // AND IT REACHES THE RUNTIME the gate is built from. A key that parsed and went nowhere would
    // be a policy an operator could write down and never have applied.
    //
    // Feature-gated for the same reason the runtime is: `crate::runtime` is behind `runtime`, and
    // the default feature-off build has a config section and no session engine to carry it onto.
    // The parse above is what that build can answer for, and it answers for it.
    #[cfg(feature = "runtime")]
    {
        let rt = crate::runtime::VoiceRuntime::new(
            std::sync::Arc::new(busbar_substrate::plane::handle_engine::DurableHandleEngine::new()),
            std::sync::Arc::new(crate::runtime::metering::LocalMeteringPort),
            std::sync::Arc::new(crate::runtime::tools::EchoToolExecutor),
        )
        .with_streams(&cfg);
        assert_eq!(
            rt.denied_destinations, cfg.denied_destinations,
            "the section's list IS the runtime's list — one reading, carried, never re-derived"
        );
    }
}
