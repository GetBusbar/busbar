// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! TEST-SCAFFOLDING: bind the self-enveloping admin-verb backing the composition root's `main` binds
//! in production — core's own `CorePlaneAdminEnvelope`. The A2A plane's `Prebuilt` admin verbs
//! (`connect`/`approve`) reach the frozen `err_json`/`err_json_cond` helpers through it, so the router
//! that serves a plane verb in a test MUST have THIS crate's dependency copy of `busbar_core` bound —
//! not some other copy's — or the response's condition `Tag` (a `busbar_core` type, distinct per copy)
//! never matches the router's recording middleware and the taxonomy witness is lost.
//!
//! It therefore stays PLANE-SIDE (bound by this crate's `testkit::install_test_seams`, from THIS
//! crate's core copy) rather than being moved into core's neutral `TestApp::build()`. The one
//! `busbar_core::` name that names the backing lives HERE, in this `tests/`-path file the
//! neutral-purity lint excludes (the sanctioned twin of core's own `plane/tests/registry_tests.rs`,
//! which likewise holds the `busbar_{plane}::PLANE_DECL` names the neutral source cannot spell), so the
//! plane's shipped `src/testkit.rs` reaches no `busbar_core::` implementation item.

/// Bind core's `CorePlaneAdminEnvelope` into the substrate seam, idempotently (first-wins `OnceLock`).
pub(crate) fn install() {
    busbar_substrate::admin_verbs::install_plane_admin_envelope(
        &busbar_core::admin::planeverbs::CorePlaneAdminEnvelope,
    );
}
