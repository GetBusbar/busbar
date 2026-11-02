// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[path = "../../linked/mod.rs"]
mod linked;

use crate::dist_root_install as root_install;

mod keys;
#[cfg(feature = "openapi-schema")]
mod openapi;
mod served_surface;
mod service;

#[path = "../../../../../crates/busbar/src/root/tests/test_plugins.rs"]
mod plugins;

#[cfg(feature = "openapi-schema")]
use self::openapi::openapi_doc_seamed;

#[allow(unused_imports)]
use busbar_core_admin::{admin_codec, restart, v1, verb};

pub(crate) fn ensure_seam() {
    static SEAM_ONCE: std::sync::Once = std::sync::Once::new();
    SEAM_ONCE.call_once(|| {
        root_install::install();

        linked::install();
        busbar_core_admin::install();
    });
}

pub(crate) fn build_router(app: std::sync::Arc<busbar_kernel::state::App>) -> axum::Router {
    ensure_seam();
    busbar_core_admin::build_router(app)
}

mod test_seams {
    pub(crate) fn linked_doors(
    ) -> &'static [(&'static str, busbar_contract::abi::mechanism::door::DoorFn)] {
        crate::distribution::admin_cross_plane::linked::doors()
    }
}
