// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FIVE QUESTIONS THE CONFIG LAYER ASKS THE PLANE REGISTRY, and nothing else.
//!
//! The config document's grammar is not closed: a plane declares its own top-level section, its
//! parse hook, its value rules, the noun an operator reads back and the section a bare hook
//! reference may not reach onto. So the config layer must be able to ask "which planes exist" and
//! "which plane owns this section" — and it asks the NEUTRAL registry
//! ([`busbar_substrate::plane::registry`]), never a plane crate and never the engine. That is the
//! whole of its coupling to the plane axis, listed here so it stays the whole of it: a sixth
//! question added to this file is a design decision someone has to make on purpose.
//!
//! ## Why these are functions rather than `use` statements
//!
//! In a shipped build every one of them is a zero-cost forward. In THIS CRATE'S OWN TEST BINARY they
//! are also the point where the process registry is populated: a config test that writes `pools:`,
//! `tools:` or `agents:` needs the plane that OWNS that section registered, exactly as a shipped
//! binary does, and a test binary has no composition root to do it. So each forward first runs the
//! `Once`-guarded registration in `tests/planes.rs` — the one file that names the plane crates, kept
//! off this crate's production source where the kind-isolation lint scans.

/// Populate the process plane registry for this crate's own test binary. A no-op — and an empty
/// function body the optimiser deletes — in every other build, where the composition root has
/// already installed the planes through `busbar_substrate::plane::registry::install_planes`.
#[cfg(not(test))]
#[inline(always)]
fn ensure_planes() {}

#[cfg(test)]
fn ensure_planes() {
    crate::testplanes::ensure();
}

// THE FOUR NEUTRAL CARRIERS a plane's top-level section lands in on the config document. They are
// type-erased (`PlaneCfg` / `PlaneEndpointCfg`), so the document names no plane type; they are
// re-exported through this module rather than named at each use site because their SPELLINGS are
// frozen wire facts — `config-schema.snapshot.json` records `McpEndpointSection` verbatim as the
// `mcp:` field's type — and a spelling that must stay put wants one place to stay put in.
pub(crate) use busbar_substrate::plane::config::McpEndpointSection; // plane-purity: frozen-wire McpEndpointSection is recorded verbatim in config-schema.snapshot.json as the mcp: field type
pub(crate) use busbar_substrate::plane::config::{AgentsSection, StreamsSection, ToolsSection};

/// EVERY REGISTERED PLANE'S DECLARATION, in the operator-visible layering order. Read by the
/// named-definition map to fold the plane-owned sections into the frozen 1.5.3 section list.
pub(crate) fn plane_decls() -> &'static [&'static busbar_substrate::plane::registry::PlaneDecl] {
    ensure_planes();
    busbar_substrate::plane::registry::plane_decls()
}

/// THE PLANE THAT OWNS A TOP-LEVEL CONFIG SECTION, or `None` when no registered plane claims it —
/// the bridge the parse, lower, validate and named-map write paths cross to reach a plane's hooks
/// without naming the plane.
pub(crate) fn plane_decl_for_config_section(
    section: &str,
) -> Option<&'static busbar_substrate::plane::registry::PlaneDecl> {
    ensure_planes();
    busbar_substrate::plane::registry::plane_decl_for_config_section(section)
}

/// THE FALLBACK PLANE'S KEY — the plane whose section is `pools:`, asked for rather than spelled, so
/// the config layer names no dialect.
pub(crate) fn fallback_key() -> &'static str {
    ensure_planes();
    busbar_substrate::plane::registry::fallback_key()
}

/// EVERY TOP-LEVEL SECTION A BARE HOOK REFERENCE COULD BE REACHING ONTO — the registered planes'
/// sections followed by the frozen 1.5.3 named-definition maps, deduped.
pub(crate) fn config_sections() -> Vec<&'static str> {
    ensure_planes();
    busbar_substrate::plane::config::config_sections()
}

/// THE SECTION-MAP SPLIT for a caller that holds a plane KEY: the registry supplies the section and
/// noun WORDS, so no caller carries a second vocabulary for its own section.
pub(crate) fn split_section<'de, D, T>(
    deserializer: D,
    plane_key: &'static str,
    validate: impl Fn(&str, &T) -> Result<(), String>,
) -> Result<busbar_substrate::plane::config::Section<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    ensure_planes();
    busbar_substrate::plane::config::split_section_for_plane(deserializer, plane_key, validate)
}
