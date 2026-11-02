// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use crate::config::{AsIdentity, OauthAsCfg};
#[cfg(test)]
use busbar_kernel::state::App;
use busbar_kernel_testkit::test_support::TestApp;

use crate::plane::AsPlane;

#[cfg(test)]
pub(crate) fn oauth_as_plane(app: &App) -> Option<Arc<AsPlane>> {
    app.oauth_as_any()?.clone().downcast::<AsPlane>().ok()
}

pub trait TestAppOauthExt {
    fn oauth_as(self, cfg: &OauthAsCfg) -> Self;
}

impl TestAppOauthExt for TestApp {
    fn oauth_as(self, cfg: &OauthAsCfg) -> Self {
        install_test_seam();
        let identity = AsIdentity::from_cfg(cfg).expect("test oauth_as config must be valid");
        let plane = AsPlane::build(identity, None, Vec::new(), crate::cimd::unconnected())
            .expect("test oauth_as plane must build");
        self.oauth_as_plane(Arc::new(plane))
    }
}

pub(crate) fn install_test_seam() {
    static INSTALLED: std::sync::Once = std::sync::Once::new();
    INSTALLED.call_once(crate::install::<crate::NoConnections>);
}
