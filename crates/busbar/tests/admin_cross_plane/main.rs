// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ADMIN SURFACE OVER THE LINKED PLANES — the admin service's tests that need a real plane
//! (a plane-owned named-map section, a plane's admin trust verbs, the plane operations the committed
//! `openapi.json` documents), moved here from busbar-core-admin with their assertions unchanged.
//! busbar-core-admin is core: it names zero plane types, its tests included (ARCHITECT ruling on
//! kind-isolation `test-deps`), so these live where a plane may be linked, the composition root.
//!
//! The planes are the root's test-linked roster (`linked/mod.rs`, data in this crate's
//! `[package.metadata.busbar.test-linked]`); the operator credential's registry row is the root's
//! own operator auth plugin, named there as data too. [`ensure_seam`] installs both, then the admin
//! mount seam, exactly as busbar-core-admin's own test environment does.

#[path = "../linked/mod.rs"]
mod linked;

mod keys;
#[cfg(feature = "openapi-schema")]
mod openapi;
mod served_surface;
mod service;

include!(concat!(env!("OUT_DIR"), "/test_operator_auth.rs"));
// `LINKED_HOOK_NAMES`: the root's own generated list of the hook rows this build links, as the
// admin surface prints them (`main.rs` includes the same file onto the root's install record).
include!(concat!(env!("OUT_DIR"), "/linked_hook_names.rs"));

// The served-surface reconciliation reads the plane-complete document through its sibling's helper.
#[cfg(feature = "openapi-schema")]
use openapi::openapi_doc_seamed;

// The admin service's modules, by the paths the moved tests spell (`crate::verb::…`).
#[allow(unused_imports)]
use busbar_core_admin::{admin_codec, restart, v1, verb, witness};

/// Install the process-wide test environment exactly once: the root's linked hook names, then the
/// operator credential's registry row, every test-linked plane (`linked::install`) and the admin
/// mount seam — the order busbar-core-admin's own test environment installs those three in.
pub(crate) fn ensure_seam() {
    static SEAM_ONCE: std::sync::Once = std::sync::Once::new();
    SEAM_ONCE.call_once(|| {
        // The root's hook names, as the root's install record carries them
        // (`root::linked::register_stores`), before anything renders the admin surface: the
        // document this binary renders lists the hooks the shipped binary lists (1.5.5's served
        // `build.hook_plugins` description), not a root-less test build's none.
        busbar_kernel::test_support::install_root_hook_names(LINKED_HOOK_NAMES);
        // The operator credential's test registry row, before anything resolves the auth axis, in
        // the root's own words (`root::auth_bindings::operator_auth_module`; ARCHITECT
        // 2026-09-30, KERNEL-AUTH-ZERO Q2).
        for_each_operator_auth_row!(install_operator_row);
        fn install_operator_row(door: busbar_kernel::test_support::AuthDoor) {
            const ROOT_WORDS: busbar_kernel::test_support::OperatorWords =
                busbar_kernel::test_support::OperatorWords {
                    provider: "admin-tokens",
                    principal_id: "admin",
                };
            busbar_kernel::test_support::install_operator_auth_row_as(ROOT_WORDS, door);
        }
        linked::install();
        busbar_core_admin::install();
    });
}

/// A `TestApp` after [`ensure_seam`], so the planes and the admin mount seam are in place before
/// `.build()` resolves them.
pub(crate) fn new_test_app() -> busbar_kernel::test_support::TestApp {
    ensure_seam();
    busbar_kernel::test_support::TestApp::new()
}

/// The admin service's router over `app`, after [`ensure_seam`].
pub(crate) fn build_router(app: std::sync::Arc<busbar_kernel::state::App>) -> axum::Router {
    ensure_seam();
    busbar_core_admin::build_router(app)
}

/// Every test-linked door plane's door, by its crate's label (`crate::test_seams::linked_doors`, the
/// path the moved tests spell).
mod test_seams {
    pub(crate) fn linked_doors(
    ) -> &'static [(&'static str, busbar_contract::abi::mechanism::door::DoorFn)] {
        crate::linked::doors()
    }
}
