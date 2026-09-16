// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AS PLANE'S TEST-KIT — the fixture surface that names `AsPlane`, kept ON THE PLANE, so
//! busbar-core's neutral `test_support::TestApp` names none of it.
//!
//! Before the extraction, `TestApp::oauth_as(cfg)` lived in busbar-core and built the real
//! `AsPlane` directly. Now that builder lives here, as an extension trait over `TestApp`'s public
//! `oauth_as_plane` seam (`busbar_core::test_support::TestApp::oauth_as_plane`) — the same relation
//! `TestAppMcpExt`/`TestAppA2aExt` have to the CRUD-shaped planes' `TestAppSeam`, sized down for a
//! singleton plane with no scratch accumulation: one config in, one plane out, no finalizer needed.

use std::sync::Arc;

use busbar_core::oauth_as::config::{AsIdentity, OauthAsCfg};
use busbar_core::state::App;
use busbar_core::test_support::TestApp;

use crate::plane::AsPlane;

/// Downcast an `App`'s type-erased authorization-server slot back to the concrete plane. For tests
/// that hold an `App`/`Arc<App>` and need to reach the plane directly (register a client, introspect
/// a token, swap the CIMD fetcher) rather than only through HTTP — the cross-crate analogue of the
/// old `app.oauth_as.as_ref()` field reach, which stopped compiling once the field's type erased.
pub(crate) fn oauth_as_plane(app: &App) -> Option<Arc<AsPlane>> {
    app.oauth_as_any()?.clone().downcast::<AsPlane>().ok()
}

/// The AS plane's fixture builder, as an extension of `TestApp`. Keeps the exact name/shape the
/// in-core builder had, so a test that moved with the plane reads unchanged aside from
/// `use busbar_oauth2::testkit::TestAppOauthExt;`.
pub trait TestAppOauthExt {
    /// Make the built App an OAuth 2.1 AUTHORIZATION SERVER, from the same `oauth_as:` config shape
    /// an operator writes.
    ///
    /// Takes the CONFIG and runs the real `AsIdentity::from_cfg` validation and the real
    /// `AsPlane::build`, for the same reason `TestApp::mcp` does: a test that hand-assembled the
    /// plane could mount a combination boot refuses, and would then be asserting against a
    /// deployment that cannot exist. The signing key is left unset, so the plane generates the
    /// ephemeral one — the tests that use this builder assert about the MOUNTED SURFACE, and the
    /// surface does not depend on which key signs.
    fn oauth_as(self, cfg: &OauthAsCfg) -> Self;
}

impl TestAppOauthExt for TestApp {
    fn oauth_as(self, cfg: &OauthAsCfg) -> Self {
        install_test_seam();
        let identity =
            AsIdentity::from_cfg(cfg).expect("test oauth_as config must be valid");
        let plane = AsPlane::build(identity, None, Vec::new()).expect("test oauth_as plane must build");
        self.oauth_as_plane(Arc::new(plane))
    }
}

/// Register this crate's `AsPlaneSeam` into busbar-core's process-wide slot, EXACTLY ONCE for the
/// whole test binary — the test-binary analogue of `crates/busbar`'s `main` calling
/// `busbar_oauth2::install()`. Needed because busbar-oauth2's OWN test binary never runs `main`, so
/// nothing else registers the seam here; without it, `router::base_data_router` would see no seam
/// and mount nothing, and every mount/flow test below would silently exercise dead code instead of
/// the real mount. `std::sync::Once`-guarded because `install_as_plane_seam` panics on a second
/// registration and every plane-building test calls this via `.oauth_as(cfg)`.
fn install_test_seam() {
    static INSTALLED: std::sync::Once = std::sync::Once::new();
    INSTALLED.call_once(crate::install);
}
