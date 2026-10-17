//! THE PLUGIN REGISTRY as xtask reads it (`plugins.yaml`): the gates that walk the first-party
//! plugin repos (abi-location) take the plugin list from here.
//!
//! The fleet's GENERATOR is not here. Every plugin repo is rendered, synced and checked by ONE tool,
//! `busbar-release plugin new|sync|check` (GetBusbar/busbar-release, `template/`), from this
//! registry and busbar's dependency policy (`.github/fleet/deps.toml`, read at each repo's pin).
//! The CI every plugin repo runs is this tree's reusable `.github/workflows/plugin-ci.yml`, taken at
//! the repo's pin (OWNER 2026-10-02).

pub mod plugin_gates;
pub mod registry;

#[cfg(test)]
#[path = "fleet/registry_tests.rs"]
mod registry_tests;
