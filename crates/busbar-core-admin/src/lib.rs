// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ADMIN API SERVICE (`/api/v1/admin/*`), extracted out of busbar-core (1.6.0).
//!
//! This crate owns the admin route table, every handler (keys, groups, hooks, plugins, config,
//! overlay, openapi), the committed `openapi.json`, the transport port and the test-support
//! recording layer. It depends on busbar-core ONE-WAY (Cargo refuses the reverse edge).
//!
//! busbar-core mounts this service through the fn-pointer seam
//! `busbar_kernel::admin::seam::AdminMountSeam`; [`install`] registers this crate's implementation,
//! and the composition root (`crates/busbar`'s `main`) calls it once, unconditionally — this crate
//! is a MANDATORY, always-linked sibling, not a plugin.
//!
//! What STAYED in busbar-core: `admin::v1::contract` (the frozen `AdminError`/`PATH_*` surface),
//! `admin::v1::json` (the `err_json`/`ok_json`/`err_json_cond` envelope primitives),
//! `admin::planeverbs` (`CorePlaneAdminEnvelope`), and `admin::versions` (the `VersionLog` state).

pub mod keys;
pub mod restart;
pub mod transport;
pub mod v1;

// THE ADMIN SURFACE'S DECLARATIONS (folded in from the former
// `busbar-core-admin`/`busbar-plane-admin` crate, #37/#34: the roster carries exactly one
// `busbar-core-admin`, and this crate — the admin service, formerly `busbar-admin` — is its
// survivor). The closed kernel-verb table, the one claim, and the frozen error envelope. Nested
// rather than flattened to crate root because this module and this crate each independently declare
// a `verbs` and a `refusal` — see `admin_codec::verbs` / `admin_codec::refusal` vs. the service's
// own `crate::verbs` / `crate::refusal` below.
//
// THERE IS NO PLANE ENTRY FACE HERE, and the module doc comment says why: that trait is how TRAFFIC
// enters the dispatch loop, and this crate serves OPERATORS on their own listener (#3/#5/#83 def
// 11). The implementation this module used to carry was never dispatched through — an admin request
// is matched against `admin_codec::verbs::resolve` and walks the loop as the admin units — so it was
// a claim made to the compiler that disagreed with the crate's kind, and nothing else.
//
// The literal spelling of that impl header is deliberately NOT written anywhere in this crate's
// shipped source: `admin_codec::tests` scans for it, and `kind-isolation:faces` is the gate of
// record. A comment that quoted it would red both.
pub mod admin_codec;

// ── KERNEL-VERB EXECUTION (absorbed from busbar-unit-verbs, W4.b #36) ────────────────────────────
// The admin units resolve a request to a `KernelVerb` and hand it here; this is the only place a
// kernel verb's SEMANTICS live. The store face (`Store`/`StoreError`) and the idempotency window
// (`IDEMPOTENCY_TTL_SECS`) it binds against now live on `busbar_contract::verb_store` (DECISIONS
// #38/#40), so this unit and `busbar-plugin-loader`'s store adapter reach one face rather than
// naming each other's crate.
pub mod governance;
pub mod idempotency;
pub mod mint;
pub mod posture;
pub mod rate;
pub mod refusal;
pub mod verb;
pub mod verbs;

pub use governance::{Governance, GovernanceError, MintedKey, RotateOutcome};
pub use idempotency::ReplayEncoder;
pub use posture::{ApprovalState, DualControl, OperatorState, PostureCtx};
pub use rate::ConfigClassRule;
pub use refusal::{ReasonCode, Refusal, RefusalStep};
pub use verb::{
    verb_name, KernelVerb, VerbScope, AUDIT_VERBS, IRREDUCIBLE_VERBS, LEDGER_VERBS, LEGACY_VERBS,
    NAMED_SURFACES, NEW_VERBS, READ_ONLY_NEW_VERBS,
};
pub use verbs::{required_scope, MintOutcome, MintedKeyOutcome, NonceSource, Verbs};

#[cfg(test)]
#[path = "tests/table_matches_openapi.rs"]
mod table_matches_openapi;

pub use v1::service::mark_start;

/// Register this crate's implementation of the admin-service mount seam
/// (`busbar_kernel::admin::seam::AdminMountSeam`). Called EXACTLY ONCE, by the composition root
/// (`crates/busbar`'s `main`), unconditionally — the admin API carries no feature flag at the
/// composition root; it is always mounted.
pub fn install() {
    busbar_kernel::admin::seam::install_admin_mount_seam(
        busbar_kernel::admin::seam::AdminMountSeam { mount: seam_mount },
    );
}

/// The mount the seam calls: nest the JSON v1 admin surface onto `router` at `/api/v1/admin`.
fn seam_mount(
    router: axum::Router<std::sync::Arc<busbar_kernel::state::AppHandle>>,
) -> axum::Router<std::sync::Arc<busbar_kernel::state::AppHandle>> {
    crate::transport::mount(router, &crate::v1::json::JsonV1)
}

/// TEST/TEST-SUPPORT router builder: register this crate's admin mount seam (idempotently, once per
/// process) and delegate to `busbar_kernel::build_router`. busbar-core's own `build_router` mounts the
/// admin surface through the seam, which is unregistered until the composition root (production) or
/// this helper (tests) installs it — so every moved test that wants the admin routes builds through
/// here instead of naming `busbar_kernel::build_router` directly.
/// Install the process-wide test environment exactly once: the admin mount seam PLUS the LLM/MCP/A2A
/// plane+protocol test seams (protocols/codecs, plane runtimes, ingress hooks). busbar-core's own
/// unit-test binary auto-registers these from its `cfg(test)` builtins, but a test-support CONSUMER
/// (this crate) has `cfg(test)` false for its busbar-core dependency, so it must install them
/// explicitly — the same three `install_test_seams()` calls busbar-core's `tests/plane_integration.rs`
/// makes. All are idempotent (first-wins), so calling this from every router builder is safe.
#[cfg(test)]
fn ensure_seam() {
    static SEAM_ONCE: std::sync::Once = std::sync::Once::new();
    SEAM_ONCE.call_once(|| {
        busbar_llm::testkit::install_test_seams();
        busbar_mcp::testkit::install_test_seams();
        busbar_a2a::testkit::install_test_seams();
        // Having registered the MCP plane above, seed its always-present default runtime for every
        // `TestApp` — the test-support analogue of busbar-core's own `cfg(test)` seeding.
        busbar_kernel::test_support::install_test_mcp_runtime_factory(
            busbar_mcp::testkit::default_mcp_runtime,
        );
        install();
    });
}

/// Build a `TestApp` after ensuring the process-wide test seams (planes, protocols, runtimes, mount
/// seam) are installed — moved admin tests use this in place of `TestApp::new()` so the seams are in
/// place BEFORE `.build()` resolves providers/planes.
#[cfg(test)]
pub(crate) fn new_test_app() -> busbar_kernel::test_support::TestApp {
    ensure_seam();
    busbar_kernel::test_support::TestApp::new()
}
#[cfg(all(not(test), feature = "test-support"))]
fn ensure_seam() {
    static SEAM_ONCE: std::sync::Once = std::sync::Once::new();
    SEAM_ONCE.call_once(install);
}

#[cfg(any(test, feature = "test-support"))]
pub fn build_router(app: std::sync::Arc<busbar_kernel::state::App>) -> axum::Router {
    ensure_seam();
    busbar_kernel::build_router(app)
}

/// TEST/TEST-SUPPORT split-router builder: register the admin mount seam (once) and delegate to
/// `busbar_kernel::router::build_split_routers_with_limits`, so the moved split-listener test mounts
/// the admin surface on the admin router.
#[cfg(any(test, feature = "test-support"))]
pub fn build_split_routers_with_limits(
    app: std::sync::Arc<busbar_kernel::state::App>,
    request_body_max_bytes: usize,
    max_inbound_concurrent: usize,
    server_timing_enabled: bool,
) -> (
    axum::Router,
    axum::Router,
    std::sync::Arc<busbar_kernel::state::AppHandle>,
) {
    ensure_seam();
    busbar_kernel::router::build_split_routers_with_limits(
        app,
        request_body_max_bytes,
        max_inbound_concurrent,
        server_timing_enabled,
    )
}

// The config-transaction behavior suite drives this crate's admin mutation handlers; it moved here
// with the service from `busbar_kernel::config::transaction`'s tests (busbar-core can no longer name
// the handlers). Wired at the crate root, the direct analogue of its old `#[path]` wiring.
#[cfg(all(test, feature = "auth-admin-tokens"))]
#[path = "tests/txn_tests.rs"]
mod txn_tests;

// The key-revoke tombstone suite drives the admin key-revoke HTTP surface; it moved here from
// busbar-core with the service.
#[cfg(all(test, feature = "auth-admin-tokens"))]
#[path = "tests/key_revoke_tombstone_tests.rs"]
mod key_revoke_tombstone_tests;

// Admin-surface HTTP tests moved from busbar-core (auth-token behavior + split-listener exposure).
#[cfg(all(test, feature = "auth-admin-tokens"))]
#[path = "tests/core_moved_tests.rs"]
mod core_moved_tests;
