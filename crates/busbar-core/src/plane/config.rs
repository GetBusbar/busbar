// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PARSE-TIME RULES A PLANE SECTION IS READ BY, owned once: how the section MAP is split, and
//! whether a hook reference stays inside its plane.
//!
//! ## Where the rules now live
//!
//! Every rule this module used to hold is now in [`busbar_substrate::plane::config`], beside the
//! registry population half it reads. The move is what lets the CONFIG LAYER — the document grammar,
//! the loader, the validator — name the plane-section carriers and the derived section grammar with no
//! edge back into core. This file is the shim wall that keeps core's own `crate::plane::config::…`
//! spellings resolving unchanged, plus the tests that drive the rules through them.
//!
//! ## Why the whole rule lives in ONE place and not on a plane
//!
//! It was written twice — `a2a/config.rs` and `mcp/config.rs` each carried a
//! `refuse_cross_plane_reference` and a `validate_section_hooks`, and the two were byte-identical
//! down to the sentence an operator reads. Two of them included the same HARDCODED section list,
//! `["pools", "tools", "agents", "export", "identity-providers"]`, in two protocol-local files that
//! no compiler links. Nothing made them agree; they agreed because one was copied from the other.
//!
//! That list is the part that rots. It is a fact about the top-level config grammar, and the config
//! grammar is declared in two tables that already exist: the plane registry keys name the plane
//! sections and `NAMED_MAP_SECTIONS` names the 1.5.3 named-definition maps. A plane or a section added
//! to either table used to leave both copies of the literal behind, and a section missing from the
//! literal is not a loud failure — it is `agents.planner` being accepted as a bare hook name,
//! resolving to nothing, and an operator believing a control is attached that is not.
//!
//! So the list is DERIVED ([`config_sections`]) and passed in as a PARAMETER rather than written.
//! The judgement takes the sections it is judging against, which is also what lets a plane busbar
//! does not have be validated by this code with nothing written for it (see
//! `plane/tests/config_tests.rs`).
//!
//! **What the grammar owns:** the trim, the empty-name refusal, the section-prefix scan, the
//! bare-name requirement, and every SENTENCE. **What a caller owns:** its own WORDING for WHERE the
//! refusal happened — `at` is "`agents.planner`" or "`tools.hooks`", and those are different
//! sentences to an operator diagnosing a boot failure. A caller keeps its refusal vocabulary, not its
//! decision.
//!
//! ## THIS IS NOT THE OTHER CROSS-PLANE REFUSAL, and the two must not be merged
//!
//! [`super::PlaneSections::resolve`] also refuses a cross-plane reference, with
//! [`super::RefError::CrossPlane`]. It is a SECOND, STRUCTURAL check and not a duplicate of this
//! one. They answer different questions at different moments:
//!
//!   * THIS one runs at PARSE time, on a STRING, before anything is known to exist. It refuses
//!     `agents.planner` written where a bare name belongs — a SHAPE that names a plane, whether or
//!     not any `planner` exists anywhere.
//!   * [`super::PlaneSections::resolve`] runs at RESOLVE time, on a name that EXISTS. It refuses a
//!     bare `planner` that resolves on a sibling plane — a name whose shape is legal and whose
//!     BINDING crosses the boundary.
//!
//! Neither subsumes the other: this one fires on a name nothing defines, and that one fires on a
//! name with no dot in it. Collapsing them would not deduplicate a check, it would delete one.
//!
//! ## THE SECTION SPLIT, and why it is stated once rather than three times
//!
//! `pools:`, `tools:` and `agents:` are SIBLINGS OF ONE SHAPE — that is the sentence every one of
//! the three section modules opens with — and the shape is: a map whose keys are registrations,
//! except for the two words reserved at the section level on EVERY plane
//! ([`busbar_substrate::plane::config::RESERVED_SECTION_KEYS`]), which are lifted out first as the
//! all-plane `hooks:` attach (a LIST, so ADDITIVE) and the all-plane `upstream_credentials:` default
//! (a SCALAR, so OVERRIDE).
//!
//! That shape was READ THREE TIMES — the pools registry, `mcp/config.rs`'s `ToolsCfg` and
//! `a2a/config.rs`'s `AgentsCfg` each carried its own `Deserialize` doing the same six steps in the
//! same order: refuse a reserved key holding a MAPPING before the typed lifts (so the operator reads
//! "that name is reserved" instead of "expected a sequence"), lift `hooks`, lift
//! `upstream_credentials`, then walk the remainder refusing a reserved NAME, parse each value and
//! run the plane's value rules. Three copies of a parse ORDER is the shape this repo's plane ledger
//! calls DEBT, and it is the dangerous kind: the pre-lift refusal is the step a fourth plane would
//! be likeliest to omit, and omitting it does not fail — it produces a confusing type error on a
//! config that should have been named.
//!
//! So [`split_section`] owns the ORDER and every SENTENCE, and a plane supplies the only three
//! things that genuinely differ: WHICH plane it is (the section word and the noun an operator reads
//! back both come off its `PlaneDecl`, so there is no second vocabulary to keep in step), the TYPE
//! one registration parses into, and its own VALUE RULES. Everything a plane keeps after that is a
//! rule about ITS OWN values — which is why `mcp/config.rs` and `a2a/config.rs` share a filename and
//! nothing else.

// THE NEUTRAL CONFIG-SEAM CONTRACTS and, since the registry population moved down with them, the
// PLANE-SECTION CARRIERS and the DERIVED SECTION GRAMMAR — all in `busbar_substrate::plane::config`.
// Re-exported here so core's own call sites and every `crate::plane::config::{PlaneCfg,
// PlaneEndpointCfg, ToolsSection, AgentsSection, StreamsSection, McpEndpointSection, config_sections,
// validate_section_hooks, split_section, Section}` reach in `config/mod.rs`, `config/prepass.rs`,
// `config_validate/`, `a2a/` and `registry.rs` resolve unchanged.
pub use busbar_substrate::plane::config::{
    config_sections_from, refuse_cross_plane_reference, validate_section_hooks, AgentsSection,
    ContainerGateInputs, PlaneCfg, PlaneEndpointCfg, RawPlaneSection, Section, StreamsSection,
    ToolsSection,
};
// The `mcp:` endpoint carrier is re-exported on its own line because its NAME is a frozen wire fact,
// recorded verbatim in config-schema.snapshot.json as the `mcp:` field's type — so the spelling
// carries the same pragma here that it carries at its declaration.
pub use busbar_substrate::plane::config::McpEndpointSection; // plane-purity: frozen-wire McpEndpointSection is recorded verbatim in config-schema.snapshot.json as the mcp: field type

/// EVERY TOP-LEVEL CONFIG SECTION a bare hook reference could be reaching onto, at core's historical
/// spelling — see [`busbar_substrate::plane::config::config_sections`]. This is the provider the
/// composition root binds into the substrate's section-list seam (`install_plane_sections`).
pub fn config_sections() -> Vec<&'static str> {
    super::registry::ensure_host_builtins();
    busbar_substrate::plane::config::config_sections()
}
// `judge_hook_ref`/`HookRefError` are reached only by this module's `#[cfg(test)]` config tests now
// that their one production caller (`refuse_cross_plane_reference`) lives on the substrate — gate the
// re-export to test builds so it is not an unused import under `-D warnings`.
#[cfg(test)]
pub(crate) use busbar_substrate::plane::config::{judge_hook_ref, HookRefError};

/// THE SECTION-MAP SPLIT for core's callers: turn a plane KEY into the section/noun WORDS via the
/// plane registry, then hand off to the neutral split. Core's spelling of
/// [`busbar_substrate::plane::config::split_section_for_plane`], which is where the rule lives; the
/// registry lookup it does is the only difference from the neutral
/// [`busbar_substrate::plane::config::split_section`] an extracted plane crate calls with its own
/// `PLANE_DECL.config_section` / `subject_noun` consts.
pub fn split_section<'de, D, T>(
    deserializer: D,
    plane_key: &'static str,
    validate: impl Fn(&str, &T) -> Result<(), String>,
) -> Result<Section<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    super::registry::ensure_host_builtins();
    busbar_substrate::plane::config::split_section_for_plane(deserializer, plane_key, validate)
}

#[cfg(test)]
#[path = "tests/config_tests.rs"]
mod config_tests;
