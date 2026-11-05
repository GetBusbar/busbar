// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel::config::{
    default_on_error, default_policy_timeout_ms, HookCfg, HookKind, HookStage, PolicyOnError,
    PromptAccess, UserAccess,
};

/// The supported admin write surface accepts a single stage as well as a stage list. Normalize
/// that input before constructing runtime state or persisting the canonical configuration.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HookInput {
    kind: HookKind,
    #[serde(rename = "module")]
    plugin: String,
    #[serde(default = "default_policy_timeout_ms")]
    timeout_ms: u64,
    #[serde(default = "default_on_error")]
    on_error: String,
    #[serde(default)]
    prompt: PromptAccess,
    #[serde(default)]
    user: UserAccess,
    #[serde(default)]
    priority: u16,
    #[serde(default)]
    on_empty: Option<PolicyOnError>,
    #[serde(default)]
    at: Option<HookStage>,
    #[serde(default)]
    settings: serde_json::Map<String, serde_json::Value>,
    #[serde(default)]
    signals: Vec<busbar_contract::signal::Signal>,
    #[serde(default)]
    global: bool,
    #[serde(default)]
    default: bool,
    #[serde(default)]
    groups: Vec<String>,
    #[serde(default)]
    phase: Vec<HookStage>,
}

impl From<HookInput> for HookCfg {
    fn from(input: HookInput) -> Self {
        let phase = if input.phase.is_empty() {
            input.at.into_iter().collect()
        } else {
            input.phase
        };
        Self {
            kind: input.kind,
            plugin: input.plugin,
            timeout_ms: input.timeout_ms,
            on_error: input.on_error,
            prompt: input.prompt,
            user: input.user,
            priority: input.priority,
            on_empty: input.on_empty,
            settings: input.settings,
            signals: input.signals,
            global: input.global,
            default: input.default,
            groups: input.groups,
            phase,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_single_stage_is_persisted_as_a_canonical_phase_list() {
        let input: HookInput =
            serde_json::from_str(r#"{"kind":"tap","module":"observer","at":"response"}"#).unwrap();
        let config = HookCfg::from(input);
        assert_eq!(config.phase, vec![HookStage::Response]);
        assert_eq!(config.resolved_stages(), vec![HookStage::Response]);
        let saved = serde_json::to_value(&config).unwrap();
        assert!(saved.get("at").is_none());
        assert_eq!(saved["phase"], serde_json::json!(["response"]));
        let reopened: HookCfg = serde_json::from_value(saved).unwrap();
        assert_eq!(reopened.resolved_stages(), vec![HookStage::Response]);
    }

    #[test]
    fn admin_explicit_phase_wins_and_duplicate_fields_are_refused() {
        let input: HookInput = serde_json::from_str(
            r#"{"kind":"tap","module":"observer","at":"request","phase":["response"]}"#,
        )
        .unwrap();
        assert_eq!(
            HookCfg::from(input).resolved_stages(),
            vec![HookStage::Response]
        );
        for text in [
            r#"{"kind":"tap","module":"observer","at":"request","at":"response"}"#,
            r#"{"kind":"tap","module":"observer","unknown":true}"#,
            r#"{"kind":"tap","plugin":"observer"}"#,
        ] {
            assert!(serde_json::from_str::<HookInput>(text).is_err(), "{text}");
        }
    }
}
