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
//! ## It IS in the config-schema tracked set
//!
//! Exactly like `tools:`/`agents:`, this file is fingerprinted by `cargo xtask gate config-schema` (it is a
//! `SOURCES` entry). Both the neutral `StreamsSection` FIELD on `DeployCfg` AND this per-key grammar —
//! the three plane-imposed session ceilings — are covered by the additive-only gate, so a deployment's
//! live-voice CEILINGS cannot be retyped or removed without the gate flagging it.

use crate::ir::config::SessionConfig;
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
///
/// ONE VALUE, not a copy of one: the posture itself lives beside the type it configures
/// (`crate::ir::config::default_session`), because the plane's own session-parameter projector has
/// to render the same bytes this section's default renders. This function is the `serde` default
/// hook and nothing more.
fn default_session() -> SessionConfig {
    crate::ir::config::default_session()
}

/// ONE CONFIGURED UPSTREAM THIS SECTION DECLARES — what it speaks, the host it is reached at, and
/// the priced lane it is charged on.
///
/// **THE FIRST FIELD IS A NAME AND NOTHING ELSE**, exactly as a claim's is: this grammar links no
/// crate, and the name an operator writes is resolved in the composition root's own table at boot.
/// A name the build does not carry is a BOOT REFUSAL there, not a row this grammar drops — a
/// deployment whose configured leg is quietly unserved is the posture this whole line exists to end.
///
/// **AND IT CARRIES NO CREDENTIAL**, for the reason the section around it carries none: the
/// provider secret is resolved through the deployment's ordinary `models:`/`providers:` catalog and
/// the same secret seam every other lane's key is, and a field here would be a second place it
/// lives. What the row carries instead is the ADDRESS of that catalog entry — [`UpstreamRow::model`],
/// a `models:` key — which is the same address every other plane uses to reach the same table.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)] // a typo'd key is refused HERE exactly as the file refuses it
pub struct UpstreamRow {
    /// Which wire vocabulary this upstream speaks, by the name its own crate declares.
    pub dialect: String,
    /// THE `models:` KEY THIS ROW DRAWS ITS ORIGIN AND CREDENTIAL FROM — the deployment's own
    /// catalog entry, addressed the same way every other plane addresses it.
    ///
    /// The entry supplies two things this grammar therefore does not: the provider `base_url` and
    /// the resolved provider credential. [`UpstreamRow::host`] and [`UpstreamRow::lane`] stay the
    /// DIAL TARGET — what socket is opened and what lane it is charged on — and the host must AGREE
    /// with the entry's origin: a row that dials one authority on another's credential is a
    /// deployment sending a secret somewhere its own catalog never said it goes, so the disagreement
    /// REFUSES THE BOOT by name rather than resolving to either answer.
    ///
    /// A name the deployment's `models:` does not declare is likewise a boot refusal, for the reason
    /// an unregistered dialect is one: a configured leg this node cannot authenticate is a claimed
    /// URL served as silence.
    ///
    /// **OPTIONAL, AND THE ABSENCE IS A DECLARED ANSWER RATHER THAN A DEFAULT.** The config grammar
    /// is additive-only after 1.5.3, so a key that a written row must carry is not a key this
    /// grammar may grow. What makes the optionality honest rather than a hole is where it is
    /// refused: a row whose DIALECT declares a credential presentation
    /// (`busbar_plane_streams::dialect::Dialect::credential_at`) and names no `model:` has nowhere
    /// to draw a credential from, and dialling it would reach the provider unauthenticated — so the
    /// composition REFUSES THE BOOT on exactly that pair. A dialect that declares no presentation
    /// (a carrier that authenticates its own signalling, a leg minted over a separate pass) needs no
    /// entry and a row for one is complete without this key, which is the posture every row on this
    /// branch already had.
    #[serde(default)]
    pub model: Option<String>,
    /// The host to dial.
    pub host: String,
    /// The priced lane this upstream is reached on.
    pub lane: String,
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
    /// THE UPSTREAMS THIS SECTION DECLARES, one row per configured wire, in declaration order.
    ///
    /// Declaration order is load-bearing the same way the registration order it resolves against is:
    /// the answer to "this session's wire has no configured upstream" is the FIRST row, so
    /// re-ordering this list moves where an un-matched session dials. An ABSENT or empty list
    /// composes nothing at all, byte-identically the posture a deployment that wrote no block had.
    #[serde(default)]
    pub upstreams: Vec<UpstreamRow>,
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
            upstreams: Vec::new(),
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
            // No row carries a credential, by [`UpstreamRow`]'s own declaration: the provider
            // secret is resolved through the deployment's `models:`/`providers:` catalog and never
            // written here. The destructure is exhaustive so the day a row grows a secret-bearing
            // field, this line fails to compile until somebody decides HERE.
            upstreams: _,
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

/// THIS PLANE'S OWN `streams:` POSTURE AS THE COMPOSITION HANDED IT TO `build` — the section the ROOT
/// parsed, carried across `BuildCtx` keyed by the key this plane's own declaration spells, and
/// downcast back HERE, inside the plane, which is the only place that key has a type.
///
/// The plane's own defaults when the deployment wrote no block (or the grammar carries no such
/// section at all): an unwritten `streams:` is byte-identically what a deployment that writes nothing
/// already got.
#[must_use]
pub fn section_of(ctx: &busbar_substrate::plane::registry::BuildCtx) -> StreamsCfg {
    ctx.section(crate::PLANE_DECL.config_section)
        .and_then(<dyn std::any::Any>::downcast_ref::<StreamsCfg>)
        .cloned()
        .unwrap_or_default()
}

/// The upstream model a parsed `streams:` posture targets (`streams.session.model`), or `None` when
/// the operator pinned none. This is the ONE name the composition root looks up in the deployment's
/// existing model/provider catalog to find the realtime provider credential to compose — the voice
/// grammar declares no credential field of its own and gains none here. Takes the section the root
/// already resolved, behind the neutral carrier the root already holds it in, so the root reads THIS
/// deployment's posture without naming a type of this plane's or the erasure seam's.
#[must_use]
pub fn session_model(section: &dyn busbar_substrate::plane::config::PlaneCfg) -> Option<String> {
    section
        .as_any()
        .downcast_ref::<StreamsCfg>()
        .and_then(|parsed| parsed.session.model.clone())
}

/// THE UPSTREAM ROWS A PARSED POSTURE CONFIGURES, in the order the operator wrote them.
///
/// The composition root's read, and the exact shape [`session_model`] beside it is: it takes the
/// section the root already resolved, behind the neutral carrier the root already holds it in, so
/// the root reads THIS deployment's posture without naming a type of this crate's or the erasure
/// seam's. A section the root cannot downcast — a build with this crate compiled out — configures
/// no row, which is the same answer an unwritten list gives.
#[must_use]
pub fn upstream_rows(section: &dyn busbar_substrate::plane::config::PlaneCfg) -> Vec<UpstreamRow> {
    section
        .as_any()
        .downcast_ref::<StreamsCfg>()
        .map(|parsed| parsed.upstreams.clone())
        .unwrap_or_default()
}

/// PLANE_DECL.parse_section — deserialize `streams:` through the plane's own typed shape, boxed as the
/// neutral [`busbar_substrate::plane::config::PlaneCfg`]. Mirror of `mcp_parse_section` /
/// `a2a_parse_section`. UNCONDITIONAL (outside the `runtime` gate): config parse/validate is needed
/// even in the skeleton/no-`runtime` build.
pub fn streams_parse_section(
    v: &serde_yaml::Value,
) -> Result<Box<dyn busbar_substrate::plane::config::PlaneCfg>, String> {
    let parsed = serde_yaml::from_value::<StreamsCfg>(v.clone()).map_err(|e| e.to_string())?;
    Ok(Box::new(parsed) as Box<dyn busbar_substrate::plane::config::PlaneCfg>)
}

/// PLANE_DECL.default_section — the empty `streams:` (mirror of `mcp_default_section` /
/// `a2a_default_section`), so an ABSENT `streams:` decodes byte-identically to the plane's own
/// [`StreamsCfg::default`].
pub fn streams_default_section() -> Box<dyn busbar_substrate::plane::config::PlaneCfg> {
    Box::<StreamsCfg>::default()
}

#[cfg(test)]
#[path = "tests/config_tests.rs"]
mod config_tests;
