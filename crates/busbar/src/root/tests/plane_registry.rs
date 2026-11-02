// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

pub(crate) fn fallback() -> &'static busbar_kernel::plane_driver::registry::PlaneDecl {
    #[cfg(linked_section_pools)]
    {
        static ROW: std::sync::OnceLock<&'static busbar_kernel::plane_driver::registry::PlaneDecl> =
            std::sync::OnceLock::new();
        ROW.get_or_init(|| {
            let door = crate::root::serve::door_rig::door_declaring(
                busbar_contract::section::RESERVED_POOLS_KEY,
            )
            .expect("the linked pools cohort declares its plane");
            crate::root::serve::door_rig::folded_door(door, "pools-door-row")
                .expect("the linked pools fixture folds")
        })
    }
    #[cfg(not(linked_section_pools))]
    {
        busbar_kernel_testkit::test_support::neutral_fallback_plane()
    }
}

pub(crate) fn register() {
    busbar_kernel_testkit::test_support::planes::register_test_plane(fallback());
}
