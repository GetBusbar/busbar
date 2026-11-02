// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[path = "../linked/mod.rs"]
mod linked;

use crate::dist_root_install as root_install;

mod keys;
#[cfg(feature = "openapi-schema")]
mod openapi;
mod served_surface;
mod service;

include!(concat!(env!("OUT_DIR"), "/test_operator_auth.rs"));

include!(concat!(env!("OUT_DIR"), "/linked_hook_names.rs"));

#[cfg(feature = "openapi-schema")]
use self::openapi::openapi_doc_seamed;

#[allow(unused_imports)]
use busbar_core_admin::{admin_codec, restart, v1, verb};

pub(crate) fn ensure_seam() {
    static SEAM_ONCE: std::sync::Once = std::sync::Once::new();
    SEAM_ONCE.call_once(|| {
        root_install::install();

        busbar_kernel_testkit::test_support::install_root_hook_names(LINKED_HOOK_NAMES);

        for_each_operator_auth_row!(install_operator_row);
        fn install_operator_row(door: busbar_kernel_testkit::test_support::AuthDoor) {
            const ROOT_WORDS: busbar_kernel_testkit::test_support::OperatorWords =
                busbar_kernel_testkit::test_support::OperatorWords {
                    provider: "admin-tokens",
                    principal_id: "admin",
                };
            busbar_kernel_testkit::test_support::install_operator_auth_row_as(ROOT_WORDS, door);
        }
        linked::install();
        busbar_core_admin::install();
    });
}

pub(crate) fn new_test_app() -> busbar_kernel_testkit::test_support::TestApp {
    ensure_seam();
    busbar_kernel_testkit::test_support::TestApp::new().plugin_admission(&root_install::ADMISSION)
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
