// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `streams:` SECTION — the voice plane's config grammar, and the one place its values are read.
//!
//! ## The section IS the plane
//!
//! `streams:` is the fourth plane noun beside `pools:` / `tools:` / `agents:`, and — like them —
//! there is no `plane:`/`bind:`/`target:` selector: writing a `streams:` block IS declaring the voice
//! plane's configuration. It is a SINGULAR typed section, not a named-definition map: a deployment has
//! ONE live-voice posture, so the section is one object (the locked session defaults + the three
//! session ceilings), never a map of registrations. That is why it is not in `NamedMapSection`.
//!
//! ## The VAD/session grammar is REUSED, not restated
//!
//! Its media/VAD/session shape IS the GA `session` object ([`SessionConfig`], which already carries
//! `turn_detection: Option<IrVad>` with the `server_vad` knobs threshold / prefix_padding_ms /
//! silence_duration_ms / create_response / interrupt_response). The plane adds only the three
//! plane-imposed ceilings — session wall-clock, context window, per-response output tokens — as the
//! sole NEW scalars. No second copy of the VAD grammar exists to drift from the wire one.
//!
//! ## It is NOT in the config-schema tracked set (voice is dev-only)
//!
//! Unlike `tools:`/`agents:`, this file is not yet fingerprinted by `scripts/config-schema.py`: only
//! the neutral `StreamsSection` FIELD reference on `DeployCfg` is (an additive optional field). Voice
//! is dev-only until DoD, so its per-key grammar is not frozen yet; adding this file to `SOURCES` is a
//! later, additive step taken WITH the plane's DoD.

use crate::ir::config::SessionConfig;
use crate::ir::control::IrVad;
use serde::{Deserialize, Serialize};

/// Hard session wall-clock ceiling default — 3600s (60 minutes).
fn default_session_max_secs() -> u32 {
    3600
}
/// Context-window ceiling default — 32768 tokens.
fn default_context_window_tokens() -> u32 {
    32_768
}
/// Per-response output-token ceiling default — 4096 tokens.
fn default_max_output_tokens() -> u32 {
    4096
}

/// THE LOCKED SESSION DEFAULTS an absent `streams.session:` opens with.
///
/// The IR's own `IrVad::ServerVad` wire default is `silence_duration_ms = 200` (`ir/control.rs`),
/// which is what a RAW wire decode round-trip must keep. The `streams:`-LEVEL default is 500ms — a
/// plane posture, not a wire fact — so it is synthesized HERE (when the operator writes no
/// `turn_detection`) rather than by changing the IR's own default, keeping the two distinct.
fn default_session() -> SessionConfig {
    SessionConfig {
        turn_detection: Some(IrVad::ServerVad {
            threshold: 0.5,
            prefix_padding_ms: 300,
            silence_duration_ms: 500,
            create_response: true,
            interrupt_response: true,
        }),
        ..SessionConfig::default()
    }
}

/// THE `streams:` SECTION — the voice plane's owned config. Its VAD/session/media shape IS the GA
/// `session` object ([`SessionConfig`]); the three limits are the only plane-imposed ceilings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)] // a typo'd key is refused HERE exactly as the file refuses it
pub struct StreamsCfg {
    /// The locked session defaults every live session opens with (media formats, voice, instructions,
    /// turn_detection/VAD, tool set, per-response max_output_tokens). Absent ⇒ [`default_session`]
    /// (server_vad, 500ms silence).
    #[serde(default = "default_session")]
    pub session: SessionConfig,
    /// Hard session wall-clock ceiling. Default 3600s (60 min).
    #[serde(default = "default_session_max_secs")]
    pub session_max_secs: u32,
    /// Context-window ceiling. Default 32768.
    #[serde(default = "default_context_window_tokens")]
    pub context_window_tokens: u32,
    /// Output-token ceiling per response. Default 4096.
    #[serde(default = "default_max_output_tokens")]
    pub max_output_tokens: u32,
}

// MANUAL `Default`, not derived: the serde field defaults above are non-trivial (the three ceilings
// and the synthesized `server_vad`), and `#[derive(Default)]` would give `0`/`SessionConfig::default`
// instead — so `StreamsCfg::default()` (what `streams_default_section` returns for an ABSENT section)
// would NOT equal the parse of an empty `streams: {}`. Spelling it by hand keeps those two byte-equal.
impl Default for StreamsCfg {
    fn default() -> Self {
        StreamsCfg {
            session: default_session(),
            session_max_secs: default_session_max_secs(),
            context_window_tokens: default_context_window_tokens(),
            max_output_tokens: default_max_output_tokens(),
        }
    }
}

impl busbar_substrate::plane::config::PlaneCfg for StreamsCfg {
    /// The voice plane's `streams:` section carries NO secret reference — the exhaustive destructure
    /// (no `..`) is kept anyway so a future secret-bearing field fails to compile until someone
    /// decides, HERE, whether it is a secret, exactly as `AgentsCfg`/`ToolsCfg` do.
    fn secret_refs(&self) -> Vec<(String, &busbar_api::SecretRef)> {
        let StreamsCfg {
            session: _,
            session_max_secs: _,
            context_window_tokens: _,
            max_output_tokens: _,
        } = self;
        Vec::new()
    }

    /// `streams:` is a SINGULAR section, not a named-definition registry — there are no definitions to
    /// contain, name, project, or insert. The registry methods are therefore trivial.
    fn contains_def(&self, _name: &str) -> bool {
        false
    }

    fn def_names(&self) -> Vec<&str> {
        Vec::new()
    }

    fn entry_document(&self, _name: &str) -> Option<serde_json::Value> {
        None
    }

    fn insert_def(&mut self, _name: &str, _def: &serde_json::Value) -> Result<(), String> {
        Err("`streams:` has no named definitions".into())
    }

    fn container_gates(&self) -> busbar_substrate::plane::config::ContainerGateInputs {
        busbar_substrate::plane::config::ContainerGateInputs {
            section_hooks: Vec::new(),
            containers: Vec::new(),
        }
    }

    fn validate_registry(&self) -> Result<(), String> {
        Ok(())
    }

    /// Present only when the operator wrote CONTENT — i.e. anything other than the plane's own
    /// defaults. Read by the config deletion-gate leg to refuse a present `streams:` naming a
    /// compiled-out voice plane.
    fn is_present(&self) -> bool {
        self != &StreamsCfg::default()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn clone_box(&self) -> Box<dyn busbar_substrate::plane::config::PlaneCfg> {
        Box::new(self.clone())
    }

    fn clone_arc_any(&self) -> std::sync::Arc<dyn std::any::Any + Send + Sync> {
        std::sync::Arc::new(self.clone())
    }
}

/// PLANE_DECL.parse_section — deserialize `streams:` through the plane's own typed shape, boxed as the
/// neutral [`busbar_substrate::plane::config::PlaneCfg`]. Mirror of `mcp_parse_section` /
/// `a2a_parse_section`. UNCONDITIONAL (outside the `runtime` gate): config parse/validate is needed
/// even in the skeleton/no-`runtime` build.
pub fn streams_parse_section(
    v: &serde_yaml::Value,
) -> Result<Box<dyn busbar_substrate::plane::config::PlaneCfg>, String> {
    serde_yaml::from_value::<StreamsCfg>(v.clone())
        .map(|c| Box::new(c) as Box<dyn busbar_substrate::plane::config::PlaneCfg>)
        .map_err(|e| e.to_string())
}

/// PLANE_DECL.default_section — the empty `streams:` (mirror of `mcp_default_section` /
/// `a2a_default_section`), so an ABSENT `streams:` decodes byte-identically to the plane's own
/// [`StreamsCfg::default`].
pub fn streams_default_section() -> Box<dyn busbar_substrate::plane::config::PlaneCfg> {
    Box::<StreamsCfg>::default()
}

#[cfg(test)]
mod tests {
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
        assert_eq!(c.session_max_secs, 3600);
        assert_eq!(c.context_window_tokens, 32_768);
        assert_eq!(c.max_output_tokens, 4096);
        match c.session.turn_detection {
            Some(IrVad::ServerVad {
                silence_duration_ms,
                ..
            }) => assert_eq!(silence_duration_ms, 500),
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
}
