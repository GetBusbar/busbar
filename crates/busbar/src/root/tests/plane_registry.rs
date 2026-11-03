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
        let registration = fallback.next().unwrap_or_else(|| {
            use crate::root::loader::dispatch::kinds::plane::{Plane, ProbeBind};
            use crate::root::loader::dispatch::{
                load_dropped, rendering_of_library, Bind, ConnTable, DispatchConfig, Dispatcher,
                NoSink,
            };
            let path = std::path::PathBuf::from(
                std::env::var_os("BUSBAR_GOVERNANCE_TEST_PLANE_PLUGIN").expect(
                    "BUSBAR_GOVERNANCE_TEST_PLANE_PLUGIN names the actual fallback plane library",
                ),
            );
            let stated = rendering_of_library(&path)
                .expect("the actual fallback plane library reads")
                .expect("the actual fallback plane carries its Statement");
            let dispatcher = std::sync::Arc::new(Dispatcher::new(DispatchConfig::default()));
            let bind: ProbeBind = std::sync::Arc::new(move || {
                load_dropped::<Plane>(
                    &path,
                    &stated,
                    Bind {
                        instance: "root-fallback".into(),
                        max_inflight_cap: 64,
                        sink: std::sync::Arc::new(NoSink),
                        dispatcher: dispatcher.adopter(),
                        conns: ConnTable::Probe,
                    },
                )
                .map_err(|error| error.to_string())
            });
            let actual = registration(bind)
                .expect("the actual dropped fallback plane registers through its ABI");
            assert!(actual.fallback, "the supplied product plane owns fallback");
            actual
        });
        assert!(fallback.next().is_none(), "one product plane owns fallback");
        busbar_kernel::plane_driver::door::fold(registration)
            .expect("the actual fallback plane folds into the host registry")
    })
}

pub(crate) fn register() {
    // The ordinary composition root registers before a config query freezes the registry.
    #[cfg(distribution_root)]
    crate::dist_root_install::install();
    let mut registered = busbar_kernel::plane_driver::registry::plane_decls().to_vec();
    let fallback = fallback();
    if !registered.iter().any(|decl| decl.key == fallback.key) {
        registered.push(fallback);
        busbar_kernel::plane_driver::registry::publish_planes(&registered);
    }
}
