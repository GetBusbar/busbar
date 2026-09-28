// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `streams:` SECTION'S KERNEL SEAM — the plane's grammar ([`StreamsCfg`], owned by the
//! streaming plane) behind the kernel's config-section trait, and the parse/default hooks.
//!
//! The grammar itself, its defaults and the session ceilings live with the plane. What stays here is
//! what the kernel's registry reaches: [`StreamsSection`] carries a parsed `StreamsCfg` as the
//! kernel's section object, and its `as_any` answers the inner `StreamsCfg`, so a reader that
//! downcasts the section finds the plane's own type.

pub use crate::plane_config::StreamsCfg;

/// A parsed `streams:` section as the kernel's config-section object.
#[derive(Debug, Clone, PartialEq)]
pub struct StreamsSection(pub StreamsCfg);

impl busbar_kernel::plane::config::PlaneCfg for StreamsSection {
    /// The voice plane's `streams:` section carries NO secret reference — the exhaustive destructure
    /// (no `..`) is kept anyway so a future secret-bearing field fails to compile until someone
    /// decides, HERE, whether it is a secret, exactly as `AgentsCfg`/`ToolsCfg` do.
    fn secret_refs(&self) -> Vec<(String, &busbar_contract::secret_ref::SecretRef)> {
        let StreamsCfg {
            session: _,
            session_max_secs: _,
            context_window_tokens: _,
            max_output_tokens: _,
        } = &self.0;
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

    fn container_gates(&self) -> busbar_kernel::plane::config::ContainerGateInputs {
        busbar_kernel::plane::config::ContainerGateInputs {
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
        self.0 != StreamsCfg::default()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        &self.0
    }

    fn clone_box(&self) -> Box<dyn busbar_kernel::plane::config::PlaneCfg> {
        Box::new(self.clone())
    }

    fn clone_arc_any(&self) -> std::sync::Arc<dyn std::any::Any + Send + Sync> {
        std::sync::Arc::new(self.0.clone())
    }
}

/// THE LAST `streams:` SECTION THIS PROCESS PARSED — the plane's own copy of its operator posture.
///
/// The engine's resolved config carries the named-map plane registries forward, but a SINGULAR plane
/// section like `streams:` is read at deserialize time and not re-handed to the plane afterwards: the
/// voice dispatch slot is built from `public_url` alone, and nothing calls the plane's runtime-build
/// hook. So the plane keeps what it parsed, here, and the mount reads it back when it assembles a
/// generation's runtime. A config reload re-parses and replaces it, so this always holds the posture
/// of the most recently loaded config rather than a boot-frozen one. Absent (no `streams:` block in
/// the file, so nothing was parsed) reads back as the plane's own defaults — byte-identical to what a
/// deployment that writes nothing already got.
static PARSED_SECTION: std::sync::RwLock<Option<StreamsCfg>> = std::sync::RwLock::new(None);

/// The operator's `streams:` posture, or the plane's defaults when no block was written. Read by the
/// mount when it builds a generation's session runtime, and by the composition root when it resolves
/// the realtime provider credential for the session's configured model.
#[must_use]
pub fn configured() -> StreamsCfg {
    PARSED_SECTION
        .read()
        .ok()
        .and_then(|held| held.clone())
        .unwrap_or_default()
}

/// The upstream model the configured session posture targets (`streams.session.model`), or `None`
/// when the operator pinned none. This is the ONE name the composition root looks up in the
/// deployment's existing model/provider catalog to find the realtime provider credential to compose —
/// the voice grammar declares no credential field of its own and gains none here.
#[must_use]
pub fn configured_session_model() -> Option<String> {
    configured().session.model
}

/// PLANE_HOOKS.parse_section — deserialize `streams:` through the plane's own typed shape, boxed as the
/// neutral [`busbar_kernel::plane::config::PlaneCfg`]. Mirror of `mcp_parse_section` /
/// `a2a_parse_section`. UNCONDITIONAL (outside the `runtime` gate): config parse/validate is needed
/// even in the skeleton/no-`runtime` build.
pub fn streams_parse_section(
    v: &serde_yaml::Value,
) -> Result<Box<dyn busbar_kernel::plane::config::PlaneCfg>, String> {
    let parsed = serde_yaml::from_value::<StreamsCfg>(v.clone()).map_err(|e| e.to_string())?;
    // Keep what we just parsed (see `PARSED_SECTION`). Only a SUCCESSFUL parse is kept, so a refused
    // config never replaces the posture a good one installed. A poisoned lock is ignored rather than
    // panicking here — the read side then falls back to the plane defaults.
    if let Ok(mut held) = PARSED_SECTION.write() {
        *held = Some(parsed.clone());
    }
    Ok(Box::new(StreamsSection(parsed)) as Box<dyn busbar_kernel::plane::config::PlaneCfg>)
}

/// PLANE_HOOKS.default_section — the empty `streams:` (mirror of `mcp_default_section` /
/// `a2a_default_section`), so an ABSENT `streams:` decodes byte-identically to the plane's own
/// [`StreamsCfg::default`].
pub fn streams_default_section() -> Box<dyn busbar_kernel::plane::config::PlaneCfg> {
    Box::new(StreamsSection(StreamsCfg::default()))
}

#[cfg(test)]
#[path = "tests/config_tests.rs"]
mod config_tests;
