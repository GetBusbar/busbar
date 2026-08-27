// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
// busbar-core — the busbar engine LIBRARY. Everything a request touches lives here: the protocol
// registry and dialects, the MCP/A2A planes, the admin plane and its transaction choke point, the
// config load/validate pipeline, the proxy engine, auth, governance, trust, audit, the durability
// sink, hooks, ingress, the IR, TLS termination and the router builders. The `busbar` BINARY is a
// thin composition root over this crate: argument parsing, config location, process lifecycle and
// (from step 4 of 1.6.0) protocol registration. See docs/code-layout.md and the split plan.
//
// VISIBILITY DOCTRINE: `pub` here is the lib/bin seam, not an API promise (`publish = false`; the
// manifest header says the same). Security-relevant internals — the audit chain's sink, the token
// signer, the durable-state statics, the trust sweeper — stay `pub(crate)` behind one boot entry
// point each; see `boot.rs`.

// busbar contains ZERO `unsafe` code OUTSIDE the audited `plane_host` FFI seam; enforce that as a
// compile-time guarantee so any future PR that introduces an `unsafe` block elsewhere fails to build
// rather than slipping in unreviewed. `deny` (not `forbid`) so the ONE module that MUST speak the
// `#[repr(C)]` plane ABI — recovering `&HostState` from the opaque `HostCtx` a plane hands back across
// the seam — can opt in with a narrow, documented `#[allow(unsafe_code)]`; every other module still
// hard-fails on `unsafe`. See `plane_host`.
#![deny(unsafe_code)]

// The crate's own name, aliased. The extracted protocol dialects are written against
// `busbar_core::` paths so ONE set of sources compiles both as its own crate (the production
// shape) and — under `cfg(any(test, feature = "test-support"))`, via a `#[path]` module decl in
// `proto/mod.rs` — back INTO this crate, where the pre-extraction fixture surface (hundreds of
// `Protocol::anthropic()` fixtures and `protocol: anthropic` test configs) still exercises it.
// This alias is what makes those `busbar_core::` spellings resolve here too.
extern crate self as busbar_core;

// The lib's TEST binary runs on jemalloc for two reasons: (1) the telemetry recovery tests
// (src/tests/telemetry_tests.rs) measure per-thread jemalloc counters via `tikv_jemalloc_ctl`
// (the mallctl C API), which is only real when jemalloc actually services allocations; and (2) the
// SHIPPED binary runs on jemalloc, so measurements match production. Test-only: the library itself
// declares no allocator (that is the BINARY's property, and only one crate in a link may).
//
// The allocator is WRAPPED in `CountingJemalloc`, a zero-overhead-in-production (test-only) shim
// that DELEGATES every operation to `tikv_jemallocator::Jemalloc` — so jemalloc's own mallctl
// counters the telemetry tests read stay byte-accurate — while incrementing a PER-THREAD counter on
// each allocation. That counter is the instrument behind the ALLOCATION-COUNT PERF GATE
// (`src/proxy/tests/alloc_gate.rs`): it drives one openai>openai passthrough request through the
// real forward path and asserts the heap-allocation count has not regressed past a committed bound,
// so a stray per-request allocation (the "FIX-9" class — a redundant `Box::new` on the hot path)
// turns CI red. Per-thread (a `const`-init `Cell`, no heap, no destructor) so concurrent
// `cargo test` threads never inflate the measured thread's count, and so `.with()` is safe to call
// from inside `GlobalAlloc` (jemalloc never re-enters this shim). See the alloc gate for the design.
#[cfg(all(test, not(target_env = "msvc")))]
pub(crate) use alloc_gate_instrument::CountingJemalloc;

#[cfg(all(test, not(target_env = "msvc")))]
#[global_allocator]
static GLOBAL: CountingJemalloc = CountingJemalloc;

// The counting `GlobalAlloc` impl is the ONLY test-only `unsafe` in core; every method delegates to
// jemalloc verbatim (see the SAFETY note on the impl). Narrowly allowed here, exactly as the
// `plane_host` FFI seam is, so the crate-wide `deny(unsafe_code)` still guards everything else.
#[cfg(all(test, not(target_env = "msvc")))]
#[allow(unsafe_code)]
mod alloc_gate_instrument {
    use std::alloc::{GlobalAlloc, Layout};
    use tikv_jemallocator::Jemalloc;

    thread_local! {
        static ALLOC_COUNT: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }

    /// A jemalloc wrapper that counts allocations per-thread. See the module header at the
    /// `#[global_allocator]` site.
    pub(crate) struct CountingJemalloc;

    impl CountingJemalloc {
        /// Allocations observed on THIS thread since process start (or last `reset`).
        pub(crate) fn count() -> u64 {
            ALLOC_COUNT.with(|c| c.get())
        }
        /// Reset this thread's counter to zero, returning the previous value.
        pub(crate) fn reset() -> u64 {
            ALLOC_COUNT.with(|c| c.replace(0))
        }
        #[inline]
        fn bump() {
            ALLOC_COUNT.with(|c| c.set(c.get() + 1));
        }
    }

    // SAFETY: every method delegates verbatim to `Jemalloc` (a sound `GlobalAlloc`); the only added
    // work is a per-thread `Cell` increment, which allocates nothing and cannot re-enter the
    // allocator. `dealloc` is NOT counted — the gate measures allocation COUNT, and jemalloc's own
    // deallocation accounting (which the telemetry tests read) is untouched.
    unsafe impl GlobalAlloc for CountingJemalloc {
        #[inline]
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            Self::bump();
            Jemalloc.alloc(layout)
        }
        #[inline]
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            Jemalloc.dealloc(ptr, layout)
        }
        #[inline]
        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            Self::bump();
            Jemalloc.alloc_zeroed(layout)
        }
        #[inline]
        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            Self::bump();
            Jemalloc.realloc(ptr, layout, new_size)
        }
    }
}

// THE A2A + MCP PLANES are NO LONGER dual-compiled into this crate's test binary. Their sources live
// in `crates/busbar-a2a/src/a2a` and `crates/busbar-mcp/src/mcp` and are exercised by this crate's own
// integration tests through the REAL, externally-linked crates (added as `[dev-dependencies]` with
// `test-support`), and by each plane crate's OWN `--lib` tests under `feature = "test-support"`. Core
// names NO plane type: `test_support::TestApp` installs type-erased plane runtimes through its neutral
// `install_plane_runtime` seam, and each plane's `testkit` builds+installs its own. The former
// `#[path = "../../busbar-*/src/*/mod.rs"] pub mod a2a|mcp;` shims (and the `busbar_*_native`
// build-script cfgs that gated them) are GONE — the engine no longer reaches into its plugins' source.
pub mod admin;
/// THE APPEND-ONLY HASH CHAIN, in core. One append, one digest, one verifier, for every stream of
/// evidence busbar keeps — a plane supplies the record type and nothing else. `admin::audit` is the
/// admin-mutation STREAM that runs on it, not a second mechanism.
pub mod audit;
pub mod auth;
pub mod auth_cache;
pub mod billing;
/// THE BOOT SEAM: one entry point per boot action, so the internals each action composes stay
/// crate-private. See the module header.
pub mod boot;
/// THE DURABLE PER-CALL LOG: one hash-chained record per MCP tool call. A plane-specific RECORD
/// SHAPE for core's one audit chain — named honestly at the crate root rather than under the
/// neutral `plane::` namespace. See the module header.
pub mod calllog;
/// THE PER-TASK PROVENANCE RECORD — the A2A plane's contribution to core's one audit chain. A
/// plane-specific RECORD SHAPE, named honestly at the crate root rather than under the neutral
/// `plane::` namespace. See the module header.
// Widened to `pub` ONLY under the test-support surface so the extracted A2A plane's own test binary
// can name the provenance types its front-door tests assert against; production keeps it `pub(crate)`.
#[cfg(not(any(test, feature = "test-support")))]
pub(crate) mod provenance;
#[cfg(any(test, feature = "test-support"))]
pub mod provenance;
pub use busbar_substrate::breaker;
pub mod catalogue;
pub mod config;
pub mod config_validate;
pub mod core_routes;
pub mod cost;
pub mod diagnostics;
// The durable-write choke point moved to the shared `busbar-api` crate so the plugin-loader
// (plugins.fetch cache write) can route through the SAME primitive. Re-exported here so every
// existing `crate::durable::*` call site in this binary resolves unchanged.
pub use busbar_api::durable;
// The host-owned neutral outbound backend, shared across protocol planes AND the plugin egress
// vtable — always compiled, like `net_guard`, because the host owns every outbound byte whether or
// not a protocol plane is built. The pooled client + the neutral return surface it hands back are
// gated INSIDE the module to their consumers (the pool to either plane; the A2A return types to A2A).
pub mod egress;
pub mod egress_auth;
pub mod endpoints;
pub mod eventstream;
pub mod export;
pub mod failover;
pub mod governance;
pub mod handlers;
pub mod health;
pub mod hooks;
pub mod ingress;
pub mod ir;
pub mod json;
pub mod limits;
pub mod lineage;
pub mod lossless;
pub mod media;
pub mod metrics;
pub mod net_guard;
pub mod oauth_as;
pub mod observability;
pub use busbar_api::operation;

#[cfg(test)]
#[path = "tests/operation_tests.rs"]
mod operation_tests;
pub mod plane;
// The ONLY module permitted `unsafe`: it recovers `&HostState` from the opaque `HostCtx` the
// `#[repr(C)]` plane ABI threads through every host call — a raw-pointer deref that cannot be
// expressed safely. The `unsafe` is confined here and audited (see `plane_host::recover`).
#[allow(unsafe_code)]
pub mod plane_host;
pub mod plugin_routes;
pub mod profile;
pub mod proto;
pub mod proxy;
pub mod session;
pub mod sigv4;
pub mod state;
pub mod store;
pub mod telemetry;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
pub mod tls;
pub use busbar_substrate::transport;

#[cfg(test)]
#[path = "tests/transport_tests.rs"]
mod transport_tests;
pub mod trust;

// ── THE CRATE-ROOT SURFACE ───────────────────────────────────────────────────────────────────────
// The moved crate-root items live in three modules split by concern (`appbuild`, `preflight`,
// `router`) plus the boot seam (`boot`); these re-exports keep every existing `crate::X` /
// `busbar_core::X` path resolving unchanged, and each item's crate-root VISIBILITY is exactly what
// the lib/bin seam demanded — nothing widened for convenience.
pub mod appbuild;
pub mod preflight;
pub mod router;
#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;

pub use appbuild::{
    build_app_from_config, inert_durable_keys_banner, load_config_from_disk, open_relay_banner,
    resolve_model_context_max, GovCredentialRotation, LoadedConfig, DEFAULT_CONFIG_PATH,
    ENV_CONFIG,
};
pub use preflight::{
    plugins_preflight, preflight_plugins_and_secrets, validate_builtin_secrets_resolve,
};
pub use router::{
    build_router, build_split_routers_with_limits, fallback_error_response, REQUEST_ACTIVITY_TICKS,
};
// Referenced as `crate::...` only from the test trees (`#[cfg(test)]`), so the production lib
// build sees them as unused — allowed, with the reason written down rather than widened away.
#[allow(unused_imports)]
pub(crate) use router::{base_data_router, build_router_with_limits};

/// TEST-SUPPORT ROUTER-SURFACE VIEW: the `(path, declared admission bar)` pairs the base data router
/// mounts for `app`, built through the very same `router::base_data_router` production calls (off the
/// App's neutral slots). Exposed as a curated `pub` seam — over PUBLIC types (`String`,
/// [`busbar_plugin_loader::RouteAuth`]) — ONLY under the test-support surface, so the extracted A2A
/// plane's own ingress tests can assert the mounted surface (which paths appear, at which bar) WITHOUT
/// core widening the `pub(crate)` router fn or the `CoreRouteTable`/`CoreRoute` types to `pub`.
#[cfg(any(test, feature = "test-support"))]
pub fn base_data_route_table_view(
    app: &state::App,
) -> Vec<(String, busbar_plugin_loader::RouteAuth)> {
    router::base_data_router(&app.plugin_routes, &app.plane_slots, app.oauth_as.as_ref())
        .1
        .routes()
        .iter()
        .map(|r| (r.path.clone(), r.auth))
        .collect()
}
