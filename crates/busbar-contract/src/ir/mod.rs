// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CROSS-PLANE IR SHAPES (DECISIONS #83: contract = shapes) — what a plane reads and writes and

pub mod facts;
pub mod handle;
pub mod invoke;
pub mod neutral_handles;
pub mod subscribe;

use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// Request/response extras NAMESPACED BY SOURCE PROTOCOL. Outer key = source protocol name, inner
pub type SourceScopedExtra = BTreeMap<String, Map<String, Value>>;

#[cfg(test)]
#[path = "tests/source_scoped_extra_tests.rs"]
mod source_scoped_extra_tests;
