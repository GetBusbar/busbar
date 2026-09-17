// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Pluggable routing policies — the RE-EXPORT SHIM over the carved-out hook-dispatch home.
//!
//! The hook DISPATCH core (`HookEnv`, the `resolve_*` lowering, the `gate`/`wire`/`plugin`
//! submodules and their tests) moved OUT of `busbar-core` into the `busbar-core-hooks` sibling crate
//! (DECISIONS #19: `busbar-core` dissolves into `busbar-kernel` + `busbar-unit-*` + the three
//! `core`-kind homes `busbar-core-config`, `busbar-core-hooks`, `busbar-oauth2`). It is a PURE
//! RELOCATION — zero behaviour change; hook ordering, ranking and gate verdicts are identical.
//!
//! This module is the byte-safe SHIM: it re-exports everything from `busbar_core_hooks::*` at the
//! historical `crate::hooks::…` path, so every busbar-core callsite and `App`'s hooks-typed fields
//! compile UNCHANGED. `busbar-core-hooks` reaches only the neutral spine (`busbar-substrate` /
//! `busbar-api`) and NEVER names `busbar-core` — the reverse edge Cargo refuses.
//!
//! ONE piece stayed core-side: [`scrape`], the `/metrics/hooks` Prometheus renderer, which reads the
//! live `App` (`render(&Arc<App>)`, a `CurrentApp` handler). It is a co-located METRICS reader, not
//! the dispatch core; keeping it here avoids dragging `App` into `busbar-core-hooks`. It calls INTO
//! the dispatch home (`HookEnv`, `fetch_status`, `wire::*`) through this shim's re-export.

pub use busbar_core_hooks::*;

/// The `/metrics/hooks` Prometheus renderer — a core-side metrics reader over the live `App` that
/// drives the dispatch home's `fetch_status`/`wire` seam. Stayed in `busbar-core` (it names `App`)
/// rather than moving into `busbar-core-hooks`.
pub mod scrape;
