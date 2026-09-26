// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Source-scoped extras namespace: request/response fields the IR does not model first-class,
//! kept keyed by their SOURCE protocol so an egress OperationHandler may opt in to honoring a
//! foreign knob it recognizes without merging namespaces across protocols.
//!
//! ONE DEFINITION. This module used to declare a second alias of the type
//! `ir::SourceScopedExtra` declares; the two resolved to the same concrete type, so the duplicate
//! died and this path re-exports the one definition, now in `busbar_contract::ir`.

pub use busbar_contract::ir::SourceScopedExtra;

// The relocated test reaches the map and value types through `super::*`, exactly as it did when
// this module named them for its own alias.
#[cfg(test)]
use serde_json::Value;
#[cfg(test)]
use std::collections::BTreeMap;

#[cfg(test)]
#[path = "tests/lossless_tests.rs"]
mod tests;
