// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
// busbar-core — the busbar engine LIBRARY. Everything a request touches lives here: the protocol
// registry and dialects, the generic plugin/plane host and its FFI seam, the admin plane and its
// transaction choke point, the config load/validate pipeline, the proxy engine, auth, governance,
// trust, audit, the durability sink, hooks, ingress, the IR, TLS termination and the router
// builders. The `busbar` BINARY is a thin composition root over this crate: argument parsing,
// config location, process lifecycle and (from step 4 of 1.6.0) protocol registration. See
// docs/code-layout.md and the split plan.
//
// VISIBILITY DOCTRINE: `pub` here is the lib/bin seam, not an API promise (`publish = false`; the
// manifest header says the same). Security-relevant internals — the audit chain's sink, the token
// signer, the durable-state statics, the trust sweeper — stay `pub(crate)` behind one boot entry
// point each; see `boot.rs`.

#![deny(unsafe_code)]

extern crate self as busbar_kernel;

#[cfg(all(test, not(target_env = "msvc")))]
pub(crate) use alloc_gate_instrument::CountingJemalloc;

#[cfg(all(test, not(target_env = "msvc")))]
#[global_allocator]
static GLOBAL: CountingJemalloc = CountingJemalloc;

#[cfg(all(test, not(target_env = "msvc")))]
#[allow(unsafe_code)]
mod alloc_gate_instrument {
    use std::alloc::{GlobalAlloc, Layout};
    use tikv_jemallocator::Jemalloc;

    thread_local! {
        static ALLOC_COUNT: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }

    pub(crate) struct CountingJemalloc;

    impl CountingJemalloc {
        #[allow(dead_code)]
        pub(crate) fn count() -> u64 {
            ALLOC_COUNT.with(|c| c.get())
        }

        #[allow(dead_code)]
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

pub mod canary;
pub mod door;
pub mod grammar;
pub mod guest;
pub mod inbound;
pub mod inflight;
pub mod plane_driver;
pub mod probe;
pub mod pump;
pub mod registry;
pub mod scratch;
pub mod seal;
mod settlement;
pub mod teller;
pub mod tick;

pub use busbar_kernel_seams::slice;

pub use busbar_contract::Millis;

pub type Nanos = u64;

pub trait Clock: Send + Sync {
    fn now(&self) -> Millis;
}

/// A clock a test drives by hand.
#[derive(Debug, Default)]
pub struct ManualClock {
    now: std::sync::atomic::AtomicU64,
}

impl ManualClock {
    pub fn new() -> Self {
        ManualClock::default()
    }

    pub fn advance(&self, by: Millis) {
        self.now.fetch_add(by, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Millis {
        self.now.load(std::sync::atomic::Ordering::Relaxed)
    }
}

pub mod admin;

pub mod audit;

pub mod audit_ring;
pub mod auth;

pub mod boot;
pub mod catalogue;
pub mod config;
pub mod config_validate;
pub mod core_routes;
pub mod cost;
pub mod diagnostics;

pub mod bound_credential;
pub mod durable;
pub mod endpoints;
pub mod export;

pub mod failover {
    pub use crate::config::pools::CandidatePoolCfg;
}
pub mod governance;
pub mod hooks;
pub mod host_chains;
pub mod host_disk;
pub mod host_records;
pub mod host_units;
pub mod host_verify;
pub mod host_work;
pub mod ingress;
pub mod ir;

pub mod host_services;
pub mod json;
pub mod limits;
pub mod oauth_as;
pub mod observability;
pub mod snapshot;

pub mod operation {
    pub use busbar_contract::operation::*;
}

pub mod admission;
#[cfg(test)]
#[path = "tests/members/mod.rs"]
mod member_tests;
#[cfg(test)]
#[path = "tests/operation_tests.rs"]
mod operation_tests;
pub mod plugin_routes;

pub mod profile;

pub mod ratelimit;

pub mod session;
pub mod state;
pub mod store;

pub mod admin_verbs;
pub mod api;
pub mod detached;
pub mod plane_routes;
pub mod rate_apply;
pub mod telemetry;

pub mod timing;

#[cfg(any(test, feature = "test-support"))]
pub mod test_hooks;
#[cfg(test)]
#[allow(dead_code, unused_imports)]
#[path = "../../busbar-kernel-testkit/src/test_support/mod.rs"]
mod test_support;
#[cfg(test)]
#[allow(dead_code)]
#[path = "../../busbar-kernel-testkit/src/testkit.rs"]
mod testkit;
pub mod topology;

pub use busbar_contract::transport::transport;

#[cfg(test)]
#[path = "tests/billing_tests.rs"]
mod billing_tests;
#[cfg(test)]
#[path = "tests/breaker_tests.rs"]
mod breaker_tests;
#[cfg(test)]
#[path = "tests/handler_contract_tests.rs"]
mod handler_contract_tests;
#[cfg(test)]
#[path = "tests/transport_tests.rs"]
mod transport_tests;
pub mod trust;
pub mod vocabulary;

pub use vocabulary::{Registration, MAX_VOCABULARY};

pub mod appbuild;

pub mod preflight;
pub mod router;
#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/caps_tests/mod.rs"]
mod caps_tests;

pub use appbuild::{
    build_app_from_config, inert_durable_keys_banner, load_config_from_disk,
    load_config_from_disk_judged, load_config_from_disk_with_store, open_relay_banner,
    resolve_model_context_max, CommittedLimits, ConfirmedLimits, GovCredentialRotation,
    InstalledLimits, LoadedConfig, PreparedLimits, DEFAULT_CONFIG_PATH, ENV_CONFIG, ENV_PROVIDERS,
};
pub use preflight::plugins_preflight;
pub use router::{
    build_data_router_on, build_router, build_split_routers_serving,
    build_split_routers_serving_doors, build_split_routers_serving_listener,
    build_split_routers_serving_sessions, build_split_routers_with_limits, fallback_error_response,
    REQUEST_ACTIVITY_TICKS,
};

#[allow(unused_imports)]
pub(crate) use router::base_data_router;

#[cfg(not(any(test, feature = "test-support")))]
#[allow(unused_imports)]
pub(crate) use router::build_router_with_limits;
#[cfg(any(test, feature = "test-support"))]
pub use router::build_router_with_limits;

#[must_use]
pub fn base_data_core_lines(
    app: &state::App,
) -> Vec<(
    String,
    busbar_contract::abi::mechanism::route::RouteMethod,
    busbar_contract::abi::mechanism::route::RouteAuth,
)> {
    router::base_data_router(
        &app.plugin_routes,
        &app.plane_slots,
        app.oauth_as.as_ref(),
        Vec::new(),
        Vec::new(),
    )
    .1
    .routes()
    .iter()
    .map(|r| (r.path.clone(), r.method, r.auth))
    .collect()
}

#[cfg(any(test, feature = "test-support"))]
pub fn boot_route_paths_of(app: &state::App) -> Vec<String> {
    app.boot_route_paths.iter().cloned().collect()
}
