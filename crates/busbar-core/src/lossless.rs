// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Source-scoped extras namespace: request/response fields the IR does not model first-class,
//! kept keyed by their SOURCE protocol so an egress OperationHandler may opt in to honoring a
//! foreign knob it recognizes without merging namespaces across protocols.
//!
//! Protocols are identified by name (the codebase uses a string-keyed protocol registry).

use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// Request/response extras NAMESPACED BY SOURCE PROTOCOL. Outer key = source protocol name (e.g.
/// `"openai"`), inner map = that protocol's unmodeled fields. An egress OperationHandler may CHOOSE to honor a
/// foreign knob it recognizes; anything it does not consume is warn-and-dropped by the handler that
/// declines it. Same-protocol round-trips re-emit the whole map verbatim.
pub(crate) type SourceScopedExtra = BTreeMap<String, Map<String, Value>>;

#[cfg(test)]
#[path = "tests/lossless_tests.rs"]
mod tests;
