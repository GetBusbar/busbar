// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE QUESTIONS THE CONFIG LAYER ASKS THE PLANE AXIS, and nothing else — plus the neutral CARRIERS a
//! plane's top-level section lands in on the config document.
//!
//! The config document's grammar is not closed: a plane declares its own top-level section, its
//! parse hook, its value rules, the noun an operator reads back and the section a bare hook
//! reference may not reach onto. So the config layer must be able to ask "which planes exist",
//! "which plane owns this section" and "what does that plane DO for it" — and it asks the two neutral
//! tables that answer those, never a plane crate and never the engine:
//!
//!   * the FACTS — which planes exist, by key and section, which one is the fallback — are contract
//!     DATA ([`busbar_contract::plane::registry`]), written once by the composition root;
//!   * the BEHAVIOUR — a plane's parse / default / lower / validate hooks — is the substrate's table
//!     ([`busbar_substrate::plane::registry`]), keyed by the same key.
//!
//! That is the whole of this layer's coupling to the plane axis, listed here so it stays the whole
//! of it: a question added to this file is a design decision someone makes on purpose. Nothing here
//! spells a plane key or a dialect; every plane-specific fact is read off a row the plane itself
//! registered. A test binary that drives this crate seeds those rows before its first read (the
//! engine's own test binary does, at process start), exactly as a shipped binary's composition root
//! installs them before any config is read.

use busbar_substrate::plane::config::{ContainerGateInputs, PlaneCfg, PlaneEndpointCfg};
use serde::Deserialize;

// THE FACTS, from the contract list: which plane owns a section (or none — `is_none()` is the
// deletion-gate question), the noun it reads back, the fallback plane's key.
pub use busbar_contract::plane::registry::{fallback_key, plane_decl_for_config_section};
// THE BEHAVIOUR, from the substrate's table: every reader of a fn-pointer seam.
pub use busbar_substrate::plane::registry::{behaviour_for_config_section, plane_behaviours};
// THE SECTION LIST a bare hook reference is judged against: the contract's fold over the process
// list with the frozen 1.5.3 named-map sections as its trailing half.
pub use busbar_substrate::plane::config::{config_sections, validate_section_hooks};

/// THE SECTION-MAP SPLIT for a caller that holds a plane KEY: the contract list supplies the section
/// and noun WORDS, so no caller carries a second vocabulary for its own section; the neutral
/// [`busbar_substrate::plane::config::split_section`] owns the ORDER and every SENTENCE.
pub fn split_section<'de, D, T>(
    deserializer: D,
    plane_key: &'static str,
    validate: impl Fn(&str, &T) -> Result<(), String>,
) -> Result<busbar_substrate::plane::config::Section<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    let d = busbar_contract::plane::registry::plane_decl_for(plane_key)
        .unwrap_or_else(|| panic!("no registered plane declared for key `{plane_key}`"));
    busbar_substrate::plane::config::split_section(
        deserializer,
        d.config_section,
        d.subject_noun,
        validate,
    )
}

// ── THE PLANE-SECTION CARRIERS ───────────────────────────────────────────────────────────────────
//
// Moved verbatim from the engine's `plane::config` with the document that holds them. They are
// type-erased (`PlaneCfg` / `PlaneEndpointCfg`), so the document names no plane type; every
// plane-specific answer comes off the behaviour row the plane registered.

/// A PLANE'S TOP-LEVEL CONFIG SECTION, CAPTURED RAW — the neutral carrier `DeployCfg`/`RootCfg` use
/// for a plane's section in a build where the plane that would LOWER it is compiled out.
///
/// The MCP plane's `tools:`/`mcp:` sections and the A2A plane's `agents:` section deserialize into
/// that plane's own registry type — types that do not exist when their plane is compiled out
/// (`plane-mcp` / `plane-a2a`). So in that build
/// the field is typed `RawPlaneSection` instead (behind `#[cfg(not(feature = "plane-<x>"))]`), which
/// captures whatever the operator wrote without naming a plane type. A section that carries CONTENT
/// in such a build names a plane that is not present; `resolve` REFUSES it (see the config
/// deletion-gate leg), exactly as the protocol registry refuses a config naming a deleted dialect.
///
/// This type lives OUTSIDE `config/` on purpose: `cargo xtask gate config-schema` fingerprints the
/// `config/` directory, so the `tools:`/`mcp:`/`agents:` schema is unchanged by this capture. A
/// `RawPlaneSection` type declared under `config/` would add a new fingerprinted type and drift the
/// committed snapshot; declared here it never enters the config surface.
///
/// Compiled UNCONDITIONALLY: besides the compiled-out-plane capture, it is the empty-section fallback
/// the neutral `*Section` newtypes take when a plane hook is absent, so it must exist in every feature
/// combination (including both planes on, where it is simply never constructed).
#[derive(Debug, Clone, Default)]
pub struct RawPlaneSection {
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
    fn secret_refs(&self) -> Vec<(String, &busbar_api::SecretRef)> {
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
    pub fn is_present(&self) -> bool {
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
    match behaviour_for_config_section(config_section).and_then(|d| d.default_section) {
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
    match behaviour_for_config_section(config_section).and_then(|d| d.parse_section) {
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
    match behaviour_for_config_section(config_section).and_then(|d| d.parse_endpoint) {
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
pub struct McpEndpointSection(pub Option<Box<dyn PlaneEndpointCfg>>); // plane-purity: frozen-wire McpEndpointSection is recorded verbatim in config-schema.snapshot.json as the mcp: field type

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
