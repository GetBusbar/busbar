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
//! **What core owns:** the trim, the empty-name refusal, the section-prefix scan, the bare-name
//! requirement, and every SENTENCE. **What a caller owns:** its own WORDING for WHERE the refusal
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

use serde::Deserialize;

// Phase-C config-seam: the NEUTRAL config-seam contracts moved to `busbar_substrate::plane::config`
// (they name only `busbar_api::SecretRef` + `serde_json`/`std`). Core re-exports them so its own call
// sites — and every `crate::plane::config::{PlaneCfg, PlaneEndpointCfg, ContainerGateInputs,
// refuse_cross_plane_reference}` reach in `config/mod.rs`, `a2a/`, `registry.rs` — are unchanged. The
// neutral section-map split (`split_section`, its `Section`, the reserved-key literal) ALSO moved to
// substrate; core keeps only the thin `split_section` WRAPPER below that turns a plane key into the
// section/noun words via `super::registry`, plus `config_sections`, which reaches that registry.
pub use busbar_substrate::plane::config::{
    refuse_cross_plane_reference, ContainerGateInputs, PlaneCfg, PlaneEndpointCfg,
};
// `judge_hook_ref`/`HookRefError` are reached only by this module's `#[cfg(test)]` config tests now
// that their one production caller (`refuse_cross_plane_reference`) moved to substrate — gate the
// re-export to test builds so it is not an unused import under `-D warnings`.
#[cfg(test)]
pub(crate) use busbar_substrate::plane::config::{judge_hook_ref, HookRefError};

/// A PLANE'S TOP-LEVEL CONFIG SECTION, CAPTURED RAW — the neutral carrier `DeployCfg`/`RootCfg` use
/// for a plane's section in a build where the plane that would LOWER it is compiled out.
///
/// The MCP plane's `tools:`/`mcp:` sections and the A2A plane's `agents:` section deserialize into
/// `crate::mcp::config::ToolsCfg` / `crate::mcp::McpCfg` / `crate::a2a::config::AgentsCfg` — types
/// that do not exist when their plane is compiled out (`plane-mcp` / `plane-a2a`). So in that build
/// the field is typed `RawPlaneSection` instead (behind `#[cfg(not(feature = "plane-<x>"))]`), which
/// captures whatever the operator wrote without naming a plane type. A section that carries CONTENT
/// in such a build names a plane that is not present; `resolve` REFUSES it (see the config
/// deletion-gate leg), exactly as the protocol registry refuses a config naming a deleted dialect.
///
/// This type lives OUTSIDE `config/` on purpose: `scripts/config-schema.py` fingerprints the
/// `config/` directory, and the `#[cfg(feature = "plane-<x>")]` twin field (declared LAST) is what
/// that fingerprint records — so the `tools:`/`mcp:`/`agents:` schema is unchanged by this capture. A
/// `RawPlaneSection` type declared under `config/` would add a new fingerprinted type and drift the
/// committed snapshot; declared here it never enters the config surface.
///
/// Compiled UNCONDITIONALLY: besides the compiled-out-plane capture, it is the empty-section fallback
/// the neutral `*Section` newtypes take when a plane hook is absent, so it must exist in every feature
/// combination (including both planes on, where it is simply never constructed).
#[derive(Debug, Clone, Default)]
pub(crate) struct RawPlaneSection {
    /// The captured value, or `None` when the section was absent or explicitly null.
    raw: Option<serde_yaml::Value>,
}

impl<'de> serde::Deserialize<'de> for RawPlaneSection {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_yaml::Value::deserialize(deserializer)?;
        let raw = if value.is_null() { None } else { Some(value) };
        Ok(RawPlaneSection { raw })
    }
}

// A raw-captured section carries no ENUMERABLE secrets: it is unparsed, and a non-empty one is
// refused at resolve, so it never reaches a running deployment. Implementing the seam with an empty
// answer lets `config_validate::secret_refs` loop the trait over the section bindings uniformly, the
// same way it does for the typed plane configs, without naming the compiled-out plane's types.
impl PlaneCfg for RawPlaneSection {
    fn secret_refs(&self) -> Vec<(String, &crate::config::SecretRef)> {
        Vec::new()
    }
    // A raw-captured section holds no PARSED registry: it names a compiled-out plane and is refused at
    // resolve, so every registry query answers empty. These are reached only for the neutral carrier's
    // uniform loop; the deletion-gate refusal is what actually fires for a present raw section.
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
        // Unreachable in practice: the named-map write path refuses a compiled-out plane's section
        // BEFORE install (see `NamedMapSection::parse_def`). Fail closed if a caller ever reaches it.
        Err("this build was compiled without the plane that owns this section".to_string())
    }
    fn container_gates(&self) -> ContainerGateInputs {
        ContainerGateInputs {
            section_hooks: Vec::new(),
            containers: Vec::new(),
        }
    }
    fn validate_registry(&self) -> Result<(), String> {
        Ok(())
    }
    fn is_present(&self) -> bool {
        RawPlaneSection::is_present(self)
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn clone_box(&self) -> Box<dyn PlaneCfg> {
        Box::new(self.clone())
    }
    fn clone_arc_any(&self) -> std::sync::Arc<dyn std::any::Any + Send + Sync> {
        std::sync::Arc::new(self.clone())
    }
}

// The `mcp:` ENDPOINT carrier when the MCP plane is compiled out: a present `mcp:` block names a
// plane this build cannot serve, refused at resolve (the deletion-gate leg) exactly as a present
// `tools:` section is.
impl PlaneEndpointCfg for RawPlaneSection {
    fn is_present(&self) -> bool {
        RawPlaneSection::is_present(self)
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl RawPlaneSection {
    /// True when the operator actually wrote CONTENT for this section (a non-empty mapping or any
    /// non-null scalar/sequence). An absent, null, or empty-mapping section is not "present": it
    /// names no plane and is not refused.
    pub(crate) fn is_present(&self) -> bool {
        match &self.raw {
            None | Some(serde_yaml::Value::Null) => false,
            Some(serde_yaml::Value::Mapping(m)) => !m.is_empty(),
            Some(_) => true,
        }
    }
}

/// This plane's EMPTY registry section, via its `default_section` seam hook — the value a neutral
/// `*Section` newtype takes when its `#[serde(default)]` field is ABSENT. A plane compiled out has no
/// hook and falls back to an empty raw capture (never present, never refused). Byte-identical to the
/// pre-seam typed field's `Default`.
fn default_plane_section(config_section: &str) -> Box<dyn PlaneCfg> {
    match crate::plane::registry::plane_decl_for_config_section(config_section)
        .and_then(|d| d.default_section)
    {
        Some(f) => f(),
        None => Box::new(RawPlaneSection::default()),
    }
}

/// Deserialize this plane's top-level registry section through its `parse_section` seam hook, so the
/// neutral carrier names no plane registry type. A plane compiled out has no hook and captures the
/// section RAW (refused at `resolve` if present). The hook's `Err(String)` is surfaced through
/// `de::Error::custom`, so it rides the SAME `from_str::<DeployCfg>` channel a typed field's parse
/// error rode — the operator sees the plane's own sentence, byte-identical bar any `at line` suffix.
fn deserialize_plane_section<'de, D>(
    config_section: &str,
    deserializer: D,
) -> Result<Box<dyn PlaneCfg>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_yaml::Value::deserialize(deserializer)?;
    match crate::plane::registry::plane_decl_for_config_section(config_section)
        .and_then(|d| d.parse_section)
    {
        Some(parse) => parse(&value).map_err(serde::de::Error::custom),
        None => {
            let raw = if value.is_null() { None } else { Some(value) };
            Ok(Box::new(RawPlaneSection { raw }))
        }
    }
}

/// Deserialize this plane's top-level ENDPOINT block (the MCP plane's `mcp:` door) through its
/// `parse_endpoint` seam hook — the twin of [`deserialize_plane_section`] for the one plane section
/// that is an endpoint rather than a registry. Compiled out ⇒ raw capture, refused at `resolve`.
fn deserialize_plane_endpoint<'de, D>(
    config_section: &str,
    deserializer: D,
) -> Result<Option<Box<dyn PlaneEndpointCfg>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_yaml::Value::deserialize(deserializer)?;
    if value.is_null() {
        return Ok(None);
    }
    match crate::plane::registry::plane_decl_for_config_section(config_section)
        .and_then(|d| d.parse_endpoint)
    {
        Some(parse) => parse(&value).map(Some).map_err(serde::de::Error::custom),
        None => Ok(Some(Box::new(RawPlaneSection { raw: Some(value) }))),
    }
}

/// THE `tools:` MCP SERVER REGISTRY as it lands in `DeployCfg`, type-erased behind [`PlaneCfg`] — the
/// neutral seam the MCP plane's `ToolsCfg` deserializes through, so `DeployCfg` names no `crate::mcp`
/// type. Absent ⇒ the plane's `Default` (an empty registry).
#[derive(Debug)]
pub struct ToolsSection(pub Box<dyn PlaneCfg>);

impl Default for ToolsSection {
    fn default() -> Self {
        ToolsSection(default_plane_section(
            busbar_substrate::plane::config::NAMED_MAP_SECTIONS[2],
        ))
    }
}
impl<'de> serde::Deserialize<'de> for ToolsSection {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserialize_plane_section(
            busbar_substrate::plane::config::NAMED_MAP_SECTIONS[2],
            deserializer,
        )
        .map(ToolsSection)
    }
}

/// THE `agents:` A2A REGISTRY as it lands in `DeployCfg`, type-erased behind [`PlaneCfg`] — the
/// neutral seam the A2A plane's `AgentsCfg` deserializes through. Absent ⇒ an empty registry.
#[derive(Debug)]
pub struct AgentsSection(pub Box<dyn PlaneCfg>);

impl Default for AgentsSection {
    fn default() -> Self {
        AgentsSection(default_plane_section(
            busbar_substrate::plane::config::NAMED_MAP_SECTIONS[3],
        ))
    }
}
impl<'de> serde::Deserialize<'de> for AgentsSection {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserialize_plane_section(
            busbar_substrate::plane::config::NAMED_MAP_SECTIONS[3],
            deserializer,
        )
        .map(AgentsSection)
    }
}

/// THE `streams:` VOICE-PLANE SECTION as it lands in `DeployCfg`, type-erased behind [`PlaneCfg`] —
/// the neutral seam the voice plane's `StreamsCfg` deserializes through, so `DeployCfg` names no
/// `busbar_voice` type. Absent ⇒ the plane's `Default` (the empty `streams:`).
///
/// `streams` is a SINGULAR typed section (one live-voice posture per deployment), NOT a
/// named-definition map, so it is keyed by the bare `"streams"` config-section literal rather than a
/// `NamedMapSection` index — the generic seam resolves the voice decl by that config section. The
/// plane compiled out (voice off, the default build) captures it RAW and refuses a present section at
/// `resolve`, exactly as `tools:`/`agents:` are.
#[derive(Debug)]
pub struct StreamsSection(pub Box<dyn PlaneCfg>);

impl Default for StreamsSection {
    fn default() -> Self {
        StreamsSection(default_plane_section("streams"))
    }
}
impl<'de> serde::Deserialize<'de> for StreamsSection {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserialize_plane_section("streams", deserializer).map(StreamsSection)
    }
}

/// THE `mcp:` ENDPOINT BLOCK as it lands in `DeployCfg`, type-erased behind [`PlaneEndpointCfg`] — the
/// neutral seam the MCP plane's `McpCfg` deserializes through. Absent/null ⇒ `None` (not an MCP
/// server), byte-identical to the pre-seam `Option<McpCfg>::default()`.
#[derive(Debug, Default)]
pub(crate) struct McpEndpointSection(pub(crate) Option<Box<dyn PlaneEndpointCfg>>); // plane-purity: frozen-wire McpEndpointSection is recorded verbatim in config-schema.snapshot.json as the mcp: field type

// plane-purity: frozen-wire the impl below is for McpEndpointSection, the snapshot-recorded mcp: field type
impl<'de> serde::Deserialize<'de> for McpEndpointSection {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // The endpoint door is owned by the `tools:` plane, so it is keyed by that CONFIG SECTION —
        // no plane key is named here.
        deserialize_plane_endpoint(
            busbar_substrate::plane::config::NAMED_MAP_SECTIONS[2],
            deserializer,
        )
        .map(McpEndpointSection) // plane-purity: frozen-wire the snapshot-recorded mcp: field type
    }
}

/// EVERY TOP-LEVEL CONFIG SECTION a bare hook reference could be reaching onto, DERIVED from the two
/// tables that declare the config grammar rather than written as a literal.
///
/// [`super::registry::PlaneDecl::config_section`] over [`super::registry::plane_decls`] gives the
/// plane sections (`pools:`, `tools:`, `agents:`, and any registered plane's own section);
/// [`NamedMapSection::key`] over [`NamedMapSection::ALL`] gives the 1.5.3 named-definition maps
/// (`identity-providers:`, `export:`, and the two plane sections again, which is why this
/// de-duplicates). Both tables state that their variant set is the only thing a new section adds —
/// this function is what makes that true for the hook-reference rule too.
///
/// Order is deterministic (plane tables first, in layering order) so a refusal naming a section
/// names the same one on every run. A nondeterministic diagnostic makes a boot failure
/// unreproducible.
pub fn config_sections() -> Vec<&'static str> {
    config_sections_from(super::registry::plane_decls())
}

/// THE SECTION FOLD, over a GIVEN plane declaration list rather than the process one — so a test can
/// pass a plane busbar does not have and watch its section reach this grammar with nothing written
/// for it in core (see `plane/tests/registry_tests.rs`). [`config_sections`] passes the process
/// [`super::registry::plane_decls`]; the plane sections come off each decl's
/// [`super::registry::PlaneDecl::config_section`] rather than an enum `match`, which is what lets a
/// registered plane's section into the hook-reference grammar.
pub(crate) fn config_sections_from(
    decls: &[&'static super::registry::PlaneDecl],
) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for section in decls
        .iter()
        .map(|decl| decl.config_section)
        .chain(busbar_substrate::plane::config::NAMED_MAP_SECTIONS)
    {
        if !out.contains(&section) {
            out.push(section);
        }
    }
    out
}

/// A whole attach list, judged by the same rule one entry is — the SECTION-level `hooks:` list has
/// no per-entry parse to hang off, and a looser rule there would be a hole in exactly the place an
/// operator attaches a control to everything.
pub fn validate_section_hooks(
    at: &str,
    hooks: &[String],
    sections: &[&'static str],
) -> Result<(), String> {
    for hook in hooks {
        refuse_cross_plane_reference(at, hook, sections)?;
    }
    Ok(())
}

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
