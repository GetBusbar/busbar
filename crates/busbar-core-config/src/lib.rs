// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONFIG LAYER — busbar's config GRAMMAR and everything that reads it.
//!
//! ## Why this is a crate
//!
//! The config document is not residue of the engine, it is the product's own grammar: the 1.5.5
//! document root (`RootCfg`/`DeployCfg`/`PluginsCfg`/`ExportCfg`), the loader, env interpolation, the
//! 1.4.x→1.5.0 migrator and its corpus, the overlay, the named-definition map, the byte-identity
//! PREPASS, the validator (the `config validation failed:` refusal an operator's runbook is written
//! against) and the `SecretResolver`. None of it has a replacement anywhere else in the tree, so
//! "delete, do not relocate" — the rule for engine residue — does not apply to it. It gets a HOME.
//!
//! The home is a CORE crate (`kind = core`, `name = config`), because config is core: every plugin
//! kind is configured by this grammar and none of them owns it.
//!
//! ## What it may name, and what it may not
//!
//! It depends on the neutral substrate and NEVER on `busbar-core`. That direction is the whole point:
//! the engine's retirement cannot proceed while the config layer is inside the engine, and every
//! attempt to cut it while it still reached UP into ten core modules produced a Cargo cycle. The last
//! of those reaches — the plane registry — was closed by moving the registry's population half down
//! to `busbar_substrate::plane::registry`, which is why this crate can ask "which planes exist"
//! without an edge back into the engine.
//!
//! It names NO plane crate and NO dialect. Every plane-specific fact it needs — a section's owning
//! plane, its parse hook, its subject noun, its validator — is read off a `PlaneDecl` the plane
//! itself registered. `busbar-core` re-exports both modules at their historical `busbar_core::config`
//! / `busbar_core::config_validate` spellings, so every existing caller resolves unchanged.

/// THE CONFIG DOCUMENT: its grammar, its loader, its overlay, its migrator and its resolution.
pub mod config;

/// THE FIVE QUESTIONS THIS CRATE ASKS THE PLANE REGISTRY — the whole of its coupling to the plane
/// axis, listed in one file so it stays the whole of it.
mod planes;

/// THE COMPOSITION ROOT FOR THIS CRATE'S OWN TEST BINARY: the one file here that names a plane crate,
/// kept under `tests/` so the production source the kind-isolation lint scans names none.
#[cfg(test)]
#[path = "tests/planes.rs"]
mod testplanes;

/// THE VALIDATOR: the pass that turns a parsed document into the `config errors:` an operator reads.
pub mod config_validate;
