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
//! of those reaches — the plane list — was closed when the plane declaration list became contract
//! DATA (`busbar_contract::plane::registry`) and a plane's behaviour the substrate's table, which is
//! why this crate can ask "which planes exist" and "what does one do" without an edge back into the
//! engine.
//!
//! It names NO plane crate and NO dialect. Every plane-specific fact it needs — a section's owning
//! plane, its parse hook, its subject noun, its validator — is read off a row the plane itself
//! registered. `busbar-core` re-exports both modules at their historical `busbar_core::config` /
//! `busbar_core::config_validate` spellings, so every existing caller resolves unchanged.
//!
//! ## Where its proofs live
//!
//! The config layer's test battery (and the 1.4.x->1.5.0 migrator's corpus, and the config-schema
//! snapshot) stays in `busbar-core`'s tree and runs in the engine's test binary. A test that writes
//! a plane's own top-level section needs the plane that OWNS it registered, and only a
//! composition root or a legacy crate may name a plane crate — a core-kind crate may not, not even
//! as a dev-dependency. The engine's test binary already carries the shipped plane set as its
//! built-in rows, so the proofs stay where the rows are; what is `#[cfg(test)]` in this crate is
//! reachable to them under the `test-support` feature.

/// THE CONFIG DOCUMENT: its grammar, its loader, its overlay, its migrator and its resolution.
pub mod config;

/// THE QUESTIONS THIS CRATE ASKS THE PLANE AXIS — the whole of its coupling to it, listed in one file
/// so it stays the whole of it — and the neutral carriers a plane's section lands in.
pub mod planes;

/// THE VALIDATOR: the pass that turns a parsed document into the `config errors:` an operator reads.
pub mod config_validate;
