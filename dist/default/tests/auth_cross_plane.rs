// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

mod linked;

use busbar_kernel::auth::UpstreamCreds;
use busbar_kernel::config::AuthCfg;
use busbar_kernel_testkit::test_support::TestApp;

fn register_planes() {
    linked::install();
}

#[test]
fn test_open_door_regardless_of_upstream_creds() {
    register_planes();
    for uc in [UpstreamCreds::Own, UpstreamCreds::Passthrough] {
        let cfg = AuthCfg::default_none();
        let mw = busbar_kernel_testkit::test_support::auth_helpers::new_builtin(&cfg);
        assert!(mw.validate_token(None));
        assert!(mw.validate_token(Some("anything")));

        let app = TestApp::new().upstream_creds(uc).build();
        assert_eq!(app.upstream_creds(), uc);
    }
}
