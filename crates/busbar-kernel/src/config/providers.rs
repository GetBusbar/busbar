// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `providers:` section's historical kernel path. The SHAPES are the LLM plane's vocabulary and
//! are declared in `busbar_substrate_values::ir::providers` (architect ruling PROVIDERS-MOVE under
//! Q67/Q50; spec Part 1, Law 1), moved VERBATIM, so every parse, refusal text and the config-schema
//! snapshot are byte-identical. They are re-exported here so every existing `config::providers::`
//! (and, through `config/mod.rs`, `config::`) spelling keeps resolving. The kernel declares none of
//! these shapes; it parses the section into them and hands each entry to the plane's
//! `resolve_provider` hook (or its own plane-absent fallback merge).
//!
//! `ModelCfg` (the per-entry config) lives in `busbar-contract` (DECISIONS #40/#38) because a
//! plugin crate (`busbar-plane-decision`) reuses it verbatim for its own `decisions.models.<name>`;
//! it is re-exported below at its historical path.

pub use busbar_contract::config::{neg1, ModelCfg};
pub use busbar_substrate_values::ir::providers::{
    default_protocol, HealthCfg, HealthMode, ProviderAuth, ProviderCfg, ProviderDef,
    ProviderDeploy, DEFAULT_PROTOCOL,
};
