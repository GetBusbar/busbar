// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONFIG LAYER'S PROOFS, hosted in the engine's test binary at their unmoved paths.
//!
//! The grammar, the loader, the migrator, the overlay, the named-definition map, the prepass and the
//! `SecretResolver` moved to `busbar-core-config`; the tests that prove them did not, and the
//! reason is a rule rather than an accident. A test that writes a plane's own top-level section
//! needs the plane that OWNS that section registered, exactly as a shipped binary does. Only a
//! composition root or a retiring 1.5.x crate may name a plane crate — a core-kind crate may not,
//! not even as a dev-dependency — and THIS binary already carries the shipped plane set as its
//! built-in rows, seeded at process start. So the proofs stay where the rows are.
//!
//! Each file below still opens with `use super::*;` and reads the module it proves through
//! `super::` — the shape it has always had — so every scope module here re-exports the config
//! crate's module under the name the file expects. The config crate's `test-support` feature
//! carries the few `#[cfg(test)]` helpers these files reach.

#![allow(unused_imports)]

pub use std::collections::{BTreeMap, HashMap, HashSet};
pub use std::path::{Path, PathBuf};

pub use busbar_core_config::config::*;

#[path = "config_backcompat_corpus.rs"]
mod config_backcompat_corpus;
#[path = "named_map_merge_tests.rs"]
mod named_map_merge_tests;
#[path = "tests.rs"]
pub(crate) mod tests;

/// `config::groups`'s proofs.
#[path = "groups_scope.rs"]
mod groups_scope;
/// `config::migrate`'s proofs.
#[path = "migrate_scope.rs"]
mod migrate_scope;
/// `config::named_map`'s proofs.
#[path = "named_map_scope.rs"]
mod named_map_scope;
/// `config::overlay`'s proofs, in the scope the files expect.
#[path = "overlay_scope.rs"]
mod overlay_scope;
/// `config::patch`'s proofs.
#[path = "patch_scope.rs"]
mod patch_scope;
/// `config::secret`'s proofs.
#[path = "secret_scope.rs"]
mod secret_scope;
