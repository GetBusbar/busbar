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
// admin surface prints them (`main.rs` includes the same file onto the install record it lends).
// The document this binary renders is lent them (`openapi::openapi_doc_seamed`), so it lists the
// hooks the shipped binary lists (1.5.5's served `build.hook_plugins` description), not a root-less
// test build's none.
#[cfg(feature = "openapi-schema")]
include!(concat!(env!("OUT_DIR"), "/linked_hook_names.rs"));

// The served-surface reconciliation reads the plane-complete document through its sibling's helper.
#[cfg(feature = "openapi-schema")]
use openapi::openapi_doc_seamed;

// The admin service's modules, by the paths the moved tests spell (`crate::verb::…`).
#[allow(unused_imports)]
use busbar_core_admin::{admin_codec, restart, v1, verb, witness};

/// The root's operator words (`root::auth_bindings::operator_auth_module`; ARCHITECT 2026-09-30,
/// KERNEL-AUTH-ZERO Q2), which the committed document's operator-credential examples name.
pub(crate) const ROOT_WORDS: busbar_kernel::test_support::OperatorWords =
    busbar_kernel::test_support::OperatorWords {
        provider: "admin-tokens",
        principal_id: "admin",
    };

/// The operator credential's registry row: the root's own operator auth plugin, under its words.
const ROOT_AUTH_ROWS: &[busbar_kernel::preflight::LinkedAuth] =
    operator_auth_rows!(ROOT_WORDS.provider);

/// THE RECORD THIS BINARY LENDS its apps and configurations: the stand-in, lending the root's
/// operator credential row and words as the root's install record lends them.
pub(crate) const ROOT_RECORD: busbar_kernel::preflight::RootInstall =
    busbar_kernel::test_support::lending_auth(ROOT_AUTH_ROWS, ROOT_WORDS);

/// Install the process-wide test environment exactly once: every test-linked plane
/// (`linked::install`) and the admin mount seam — the order busbar-core-admin's own test
/// environment installs them in. The operator credential's row rides [`ROOT_RECORD`].
pub(crate) fn ensure_seam() {
    static SEAM_ONCE: std::sync::Once = std::sync::Once::new();
    SEAM_ONCE.call_once(|| {
        linked::install();
        busbar_core_admin::install();
    });
}

/// A `TestApp` after [`ensure_seam`], so the planes and the admin mount seam are in place before
/// `.build()` resolves them, lent [`ROOT_RECORD`].
pub(crate) fn new_test_app() -> busbar_kernel::test_support::TestApp {
    ensure_seam();
    busbar_kernel::test_support::TestApp::new().root(ROOT_RECORD)
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
