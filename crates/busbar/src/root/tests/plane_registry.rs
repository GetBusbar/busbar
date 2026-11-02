// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

pub(crate) fn fallback() -> &'static busbar_kernel::plane_driver::registry::PlaneDecl {
    use crate::root::loader::dispatch::kinds::plane::{linked_probe, registration};
    static ROW: std::sync::OnceLock<&'static busbar_kernel::plane_driver::registry::PlaneDecl> =
        std::sync::OnceLock::new();
    ROW.get_or_init(|| {
        let mut fallback = crate::LINKED
            .plane_doors
            .iter()
            .map(|door| {
                registration(linked_probe(*door, "root-fallback"))
                    .expect("the actual linked plane registers through its ABI")
            })
            .filter(|registration| registration.fallback);
        let registration = fallback.next().expect("the product links a fallback plane");
        assert!(fallback.next().is_none(), "one product plane owns fallback");
        busbar_kernel::plane_driver::door::fold(registration)
            .expect("the actual fallback plane folds into the host registry")
    })
}

pub(crate) fn register() {
    let mut registered = busbar_kernel::plane_driver::registry::plane_decls().to_vec();
    let fallback = fallback();
    if !registered.iter().any(|decl| decl.key == fallback.key) {
        registered.push(fallback);
        busbar_kernel::plane_driver::registry::publish_planes(&registered);
    }
}
