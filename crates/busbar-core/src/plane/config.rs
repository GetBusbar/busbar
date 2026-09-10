// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PARSE-TIME RULES A PLANE SECTION IS READ BY, owned once: how the section MAP is split, and
//! whether a hook reference stays inside its plane.
//!
//! ## Why the whole rule lives here and not on a plane
//!
//! It was written twice — `a2a/config.rs` and `mcp/config.rs` each carried a
//! `refuse_cross_plane_reference` and a `validate_section_hooks`, and the two were byte-identical
//! down to the sentence an operator reads. Two of them included the same HARDCODED section list,
//! `["pools", "tools", "agents", "export", "identity-providers"]`, in two protocol-local files that
//! no compiler links. Nothing made them agree; they agreed because one was copied from the other.
//!
//! That list is the part that rots. It is a fact about the top-level config grammar, and the config
//! grammar is declared in two tables that already exist: the plane registry keys name the plane sections and
//! [`NamedMapSection::ALL`] names the 1.5.3 named-definition maps. A plane or a section added to
//! either table used to leave both copies of the literal behind, and a section missing from the
//! literal is not a loud failure — it is `agents.planner` being accepted as a bare hook name,
//! resolving to nothing, and an operator believing a control is attached that is not.
//!
//! So the list is DERIVED ([`config_sections`]) and passed in as a PARAMETER rather than written.
//! The judgement takes the sections it is judging against, which is also what lets a plane busbar
//! does not have be validated by this code with nothing written for it (see
//! `plane/tests/config_tests.rs`).
//!
//! **What the grammar owns:** the trim, the empty-name refusal, the section-prefix scan, the
//! bare-name requirement, and every SENTENCE. **What a caller owns:** its own WORDING for WHERE the refusal
//! happened — `at` is "`agents.planner`" or "`tools.hooks`", and those are different sentences to an
//! operator diagnosing a boot failure. A caller keeps its refusal vocabulary, not its decision.
//!
//! The sentences survive the move through a TOTAL `From<Refusal<'_>> for String`. Totality is the
//! point: a refusal added to [`HookRefError`] later has to be given a sentence of its own rather
//! than being folded silently into a nearby arm, which is how two refusals become one wording that
//! is wrong for one of them.
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
//! ## THE SECTION SPLIT, and why it is here rather than three times
//!
//! `pools:`, `tools:` and `agents:` are SIBLINGS OF ONE SHAPE — that is the sentence every one of
//! the three section modules opens with — and the shape is: a map whose keys are registrations,
//! except for the two words reserved at the section level on EVERY plane
//! ([`busbar_substrate::plane::config::RESERVED_SECTION_KEYS`]), which are lifted out first as the
//! all-plane `hooks:` attach (a LIST, so ADDITIVE) and the all-plane `upstream_credentials:` default
//! (a SCALAR, so OVERRIDE).
//!
//! That shape was READ THREE TIMES — `config/mod.rs`'s `PoolsCfg`, `mcp/config.rs`'s `ToolsCfg` and
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
//! back both come off [`Plane`], so there is no second vocabulary to keep in step), the TYPE one
//! registration parses into, and its own VALUE RULES. Everything a plane keeps after that is a rule
//! about ITS OWN values — which is why `mcp/config.rs` and `a2a/config.rs` share a filename and
//! nothing else.

// Phase-C config-seam: the NEUTRAL config-seam contracts moved to `busbar_substrate::plane::config`
// (they name only `busbar_api::SecretRef` + `serde_json`/`std`). Core re-exports them so its own call
// sites — and every `crate::plane::config::{PlaneCfg, PlaneEndpointCfg, ContainerGateInputs,
// refuse_cross_plane_reference}` reach in `config/mod.rs`, `a2a/`, `registry.rs` — are unchanged. The
// neutral section-map split (`split_section`, its `Section`, the reserved-key literal) ALSO moved to
// substrate; core keeps only the thin `split_section` WRAPPER below that turns a plane key into the
// section/noun words via `super::registry`, plus the `config_sections` binding. The plane-section
// CARRIERS the config document holds (`RawPlaneSection`, the four `*Section` newtypes) left with the
// config layer for `busbar_core_config::planes` and are re-exported below.
pub use busbar_substrate::plane::config::{
    refuse_cross_plane_reference, ContainerGateInputs, PlaneCfg, PlaneEndpointCfg,
};
// `judge_hook_ref`/`HookRefError` are reached only by this module's `#[cfg(test)]` config tests now
// that their one production caller (`refuse_cross_plane_reference`) moved to substrate — gate the
// re-export to test builds so it is not an unused import under `-D warnings`.
#[cfg(test)]
pub(crate) use busbar_substrate::plane::config::{judge_hook_ref, HookRefError};

// THE PLANE-SECTION CARRIERS moved with the config layer to `busbar_core_config::planes` — the
// config document is what holds them, and the crate that owns the document owns its carriers.
// Re-exported here so core's own readers (`test_support::fixtures`, `state.rs`'s deletion-gate
// leg) keep the `crate::plane::config::…` spelling. Transitional: falls with this crate.
pub use busbar_core_config::planes::{
    AgentsSection, RawPlaneSection, StreamsSection, ToolsSection,
};
// The endpoint-door carrier on its own line because its NAME is a frozen wire fact, recorded
// verbatim in config-schema.snapshot.json as that field's type.
pub use busbar_core_config::planes::McpEndpointSection; // plane-purity: frozen-wire McpEndpointSection is recorded verbatim in config-schema.snapshot.json as the mcp: field type

// THE SECTION LIST is the substrate's wrapper of the contract's fold. Its production readers (the
// config layer, the composition root) bind it at the substrate now; core's own `cfg(test)` config
// tests still reach it through the seeding shim, for the reason the registry binds every list read.
#[cfg(test)]
pub(crate) use crate::plane::registry::registry_tests::seeded::config_sections;

// A whole attach list, judged by the same rule one entry is — pure over
// `refuse_cross_plane_reference`, so it lives beside it on the substrate; core's spelling stays.
pub use busbar_substrate::plane::config::validate_section_hooks;

// THE SECTION-MAP SPLIT and its `Section<T>` carrier relocated to `busbar_substrate::plane::config`
// (the neutral half — the reserved-key refusals + the two typed lifts, taking its section/noun WORDS
// as params so it names no plane registry). Re-exported here so `crate::plane::config::Section` still
// resolves; the core `split_section` below is the thin wrapper that supplies the words from the plane
// registry so core's own callers (`config/mod.rs` pools, `a2a/config.rs`) pass a plane KEY unchanged.
pub use busbar_substrate::plane::config::Section;

/// THE SECTION-MAP SPLIT for core's callers: turn a plane KEY into the section/noun WORDS via the
/// plane registry, then hand off to the neutral [`busbar_substrate::plane::config::split_section`].
///
/// `plane_key` supplies the WORDS (its decl's `config_section` and `subject_noun`) so no caller
/// carries a second vocabulary for its own section; `validate` is the plane's VALUE RULES, run on
/// each entry as it is parsed, so the file and the admin write path refuse the same definitions —
/// the ONE GRAMMAR, TWO PATHS rule. A plane with no value rules passes `|_, _| Ok(())`.
///
/// The extracted MCP plane crate skips this wrapper and calls the substrate split directly with its
/// OWN `PLANE_DECL.config_section` / `subject_noun` consts — it holds no plane registry to look up.
pub fn split_section<'de, D, T>(
    deserializer: D,
    plane_key: &'static str,
    validate: impl Fn(&str, &T) -> Result<(), String>,
) -> Result<Section<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    let d = super::plane_decl(plane_key);
    busbar_substrate::plane::config::split_section(
        deserializer,
        d.config_section,
        d.subject_noun,
        validate,
    )
}

#[cfg(test)]
#[path = "tests/config_tests.rs"]
mod config_tests;
