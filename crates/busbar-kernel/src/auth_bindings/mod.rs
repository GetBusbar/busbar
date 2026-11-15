// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Auth outbound bindings: one auth instance per binding, implicit dialect and upstream bindings, credential mode (IF §12.18). W0-ABI stub: frozen signatures, `todo!()` bodies; W1-K6 fills it.

// W0-ABI: IF §12.18 freezes no Rust item in this module: `CORE_DIALECT_STYLES`, `CORE_UPSTREAM_STYLES` and
// `outbound_owner` live in `busbar_contract::config::dialect_styles`, and `UpstreamAuth` in `crate::upstreams`.
