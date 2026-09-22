// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CROSS-PLANE `App::upstream_creds()` TEST, relocated here from `src/auth/tests/tests.rs` (the
//! "fix the 38" pass after the A6/HostCtx dev-dependency-cycle cleanup): `App::upstream_creds()`
//! reads through `engine_tables_view()`, which — same as `endpoints_cross_plane.rs`/
//! `metrics_cross_plane.rs` (see their headers) — projects the FALLBACK plane's own runtime slot
//! through that plane decl's `viewer` fn-pointer. Only the REAL `busbar_llm` plane's `build_runtime`
//! actually carries the configured `upstream_credentials` into that runtime; a neutral fake plane (no
//! `build_runtime`) would leave `upstream_creds()` reading the EMPTY-VIEW default regardless of what
//! `TestApp::upstream_creds` was set to, which is a different, false-negative failure than what this
//! test exists to pin. The assertion itself (the front door admits regardless of the upstream-creds
//! knob) is core's own auth behaviour, not anything about the LLM dialect.
//!
//! Every other test in `auth/tests/tests.rs` builds no lane/pool topology and stays there.

use busbar_kernel::auth::{AuthMiddleware, UpstreamCreds};
use busbar_kernel::config::AuthCfg;
use busbar_kernel::test_support::TestApp;

fn register_planes() {
    busbar_llm::testkit::install_test_seams();
}

/// `AuthMiddleware` with an empty chain admits ANY bearer (or none) at the front door. With an
/// empty chain both modes admit everything (the old none/passthrough split is now chain-shape for
/// the front door + this knob for egress). 1.5.3: the knob itself moved OFF `auth:` onto the
/// `pools:` section, so the middleware no longer carries it at all — which is the strongest
/// possible form of "it does not gate the front door".
#[test]
fn test_open_door_regardless_of_upstream_creds() {
    register_planes();
    for uc in [UpstreamCreds::Own, UpstreamCreds::Passthrough] {
        let cfg = AuthCfg::default_none();
        let mw = AuthMiddleware::new_builtin(&cfg);
        assert!(mw.validate_token(None));
        assert!(mw.validate_token(Some("anything")));
        // The mode lives on the App (all-pools default + per-pool override), not on the chain.
        let app = TestApp::new().upstream_creds(uc).build();
        assert_eq!(app.upstream_creds(), uc);
    }
}
