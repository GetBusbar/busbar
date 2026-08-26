// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The NEUTRAL cross-plane IR leaves — the two protocol-surface operations `Invoke` and `Subscribe`
//! that a plane crate (`busbar-mcp`, `busbar-a2a`) reads and writes without reaching into
//! `busbar-core`.
//!
//! These are PURE DATA: a request/response pair per operation, carried by value. The `IrFacts`
//! projection (the family-blind walk the shared pipeline reads a request through) and the neutral
//! `IrHandle` wrappers stay in `busbar-core` — those name the core-owned engine seam — and core
//! `impl`s the projection for these very types. Core re-exports each type from its historical path
//! (`busbar_core::ir::invoke::InvokeReq`, …) so the in-core call sites are unchanged.

pub mod invoke;
pub mod subscribe;

use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// Request/response extras NAMESPACED BY SOURCE PROTOCOL — the transparent alias `busbar-core`
/// spells `crate::lossless::SourceScopedExtra`. Outer key = source protocol name, inner map = that
/// protocol's unmodeled fields, so a cross-protocol hop cannot leak a source-only key into a foreign
/// dialect. Declared here beside the neutral IR that carries it; the two aliases resolve to the same
/// concrete type, so a value flows between core and substrate with no conversion.
pub type SourceScopedExtra = BTreeMap<String, Map<String, Value>>;
