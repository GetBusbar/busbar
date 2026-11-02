// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

pub mod admin_state;
pub mod keys;
pub mod restart;
pub mod transport;
pub mod v1;

pub mod admin_codec;

pub mod governance;
pub mod idempotency;

pub mod planeverbs;
pub mod rate;
mod recovery;
pub mod refusal;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
pub mod verb;
pub mod verbs;
pub mod versions;

pub use admin_state::{AdminState, AppAdmin};
pub use governance::{Governance, GovernanceError};
pub use rate::ConfigClassRule;
pub use refusal::{ReasonCode, Refusal, RefusalStep};
pub use verb::{
    verb_name, KernelVerb, VerbScope, AUDIT_VERBS, LEDGER_VERBS, LEGACY_VERBS, NAMED_SURFACES,
    NEW_VERBS,
};
pub use verbs::{required_scope, Verbs};

#[cfg(test)]
#[path = "tests/table_matches_openapi.rs"]
mod table_matches_openapi;

pub use v1::service::mark_start;

pub fn install() {
    busbar_kernel::admin::seam::install_admin_mount_seam(
        busbar_kernel::admin::seam::AdminMountSeam {
            mount: seam_mount,
            record_boot: seam_record_boot,
        },
    );

    busbar_kernel::admin::seam::install_admin_verb_table(
        busbar_kernel::admin::seam::AdminVerbTable {
            rung_of: admin_codec::verbs::named_rung,
            verb_at: admin_codec::verbs::name_at,
        },
    );
}

fn seam_record_boot(app: &busbar_kernel::state::App) {
    use AppAdmin as _;
    app.record_version_at(0, "system", "boot");
}

fn seam_mount(
    router: axum::Router<std::sync::Arc<busbar_kernel::state::AppHandle>>,
) -> axum::Router<std::sync::Arc<busbar_kernel::state::AppHandle>> {
    crate::transport::mount(router, &crate::v1::json::JsonV1)
}

#[cfg(test)]
mod test_seams {
    pub(crate) fn ensure_seam() {
        static SEAM_ONCE: std::sync::Once = std::sync::Once::new();
        SEAM_ONCE.call_once(|| {
            busbar_kernel_testkit::test_support::operator_double::install();

            (busbar_kernel_testkit::testkit::TEST_SEAM.install)();
            super::install();
        });
    }
}
#[cfg(test)]
use test_seams::ensure_seam;

#[cfg(test)]
pub(crate) fn new_test_app() -> busbar_kernel_testkit::test_support::TestApp {
    ensure_seam();
    busbar_kernel_testkit::test_support::TestApp::new()
}

#[cfg(test)]
pub(crate) fn linked_protocol() -> &'static str {
    ensure_seam();
    busbar_kernel_testkit::ingress::protocols::known_protocols()
        .first()
        .copied()
        .expect("this test binary registers a codec protocol")
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

#[cfg(test)]
#[path = "tests/txn_tests.rs"]
mod txn_tests;

#[cfg(test)]
#[path = "tests/hook_route_timeout_tests.rs"]
mod hook_route_timeout_tests;

#[cfg(test)]
#[path = "tests/core_moved_tests.rs"]
mod core_moved_tests;

#[cfg(test)]
#[path = "tests/secret_once_tests.rs"]
mod secret_once_tests;
