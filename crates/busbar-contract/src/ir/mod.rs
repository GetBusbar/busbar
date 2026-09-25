// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CROSS-PLANE IR SHAPES (DECISIONS #83: contract = shapes) — what a plane reads and writes and
//! the shared pipeline reads back, which every implementation must agree on.
//!
//! - [`egress_prep`]: the resolved-primitives param bag a cross-protocol egress hop passes to a
//!   request handle, and a lane's declared request-shape capabilities.
//! - [`facts`]: THE ONE PROJECTION — the family-blind seam the shared pipeline reads a request
//!   through, and the render-once screening view over it.
//! - [`invoke`] / [`subscribe`]: the two protocol-surface operations' request/response pairs.
//!
//! Relocated, module-path-only, from `busbar-substrate-values::ir`, which re-exports every module
//! here under its historical path. The sealed request/response handle and the neutral handle
//! wrappers stay there for now (their byte-carrier signatures name a buffer type this crate does not
//! take), as do the `providers:`/`models:` config grammars, which are not shapes.

pub mod egress_prep;
pub mod facts;
pub mod invoke;
pub mod subscribe;

use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// Request/response extras NAMESPACED BY SOURCE PROTOCOL. Outer key = source protocol name, inner
/// map = that protocol's unmodeled fields, so a cross-protocol hop cannot leak a source-only key into
/// a foreign dialect. An egress codec may CHOOSE to honor a foreign knob it recognizes; anything it
/// does not consume is warn-and-dropped by the codec that declines it. Same-protocol round-trips
/// re-emit the whole map verbatim.
///
/// THE ONE DEFINITION: the substrate's `lossless::SourceScopedExtra` was a second alias of
/// this same type; it is now a re-export of this one.
pub type SourceScopedExtra = BTreeMap<String, Map<String, Value>>;
