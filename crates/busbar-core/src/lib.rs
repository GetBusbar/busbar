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

// busbar contains ZERO `unsafe` code; enforce that as a compile-time guarantee so any future PR
// that introduces an `unsafe` block fails to build rather than slipping in unreviewed.
#![forbid(unsafe_code)]

// The crate's own name, aliased. The extracted protocol dialects are written against
// `busbar_core::` paths so ONE set of sources compiles both as its own crate (the production
// shape) and — under `cfg(any(test, feature = "test-support"))`, via a `#[path]` module decl in
// `proto/mod.rs` — back INTO this crate, where the pre-extraction fixture surface (hundreds of
// `Protocol::anthropic()` fixtures and `protocol: anthropic` test configs) still exercises it.
// This alias is what makes those `busbar_core::` spellings resolve here too.
extern crate self as busbar_core;

// The telemetry recovery tests (src/tests/telemetry_tests.rs) measure per-thread jemalloc
// counters, and the SHIPPED binary runs on jemalloc — so the lib's TEST binary declares the same
// allocator, keeping those measurements real rather than vacuously zero. Test-only: the library
// itself declares no allocator (that is the BINARY's property, and only one crate in a link may).
#[cfg(all(test, not(target_env = "msvc")))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

pub mod a2a;
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
pub mod breaker;
pub mod catalogue;
pub mod config;
pub mod config_validate;
pub mod core_routes;
pub mod cost;
// The durable-write choke point moved to the shared `busbar-api` crate so the plugin-loader
// (plugins.fetch cache write) can route through the SAME primitive. Re-exported here so every
// existing `crate::durable::*` call site in this binary resolves unchanged.
pub use busbar_api::durable;
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
pub mod mcp;
pub mod media;
pub mod metrics;
pub mod net_guard;
pub mod oauth_as;
pub mod observability;
pub mod operation;
pub mod plane;
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
pub mod transport;
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
    resolve_model_context_max, upstream_bool_env_override, GovCredentialRotation, LoadedConfig,
    DEFAULT_CONFIG_PATH, ENV_CONFIG, ENV_PROVIDERS,
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
