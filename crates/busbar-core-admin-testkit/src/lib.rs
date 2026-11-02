// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Dev-only orchestration over the admin service's real seams.

/// Force the real restart handler to see no supervisor on this thread while `f` runs.
/// Restores the prior override when the future completes, panics, or is dropped. Like the
/// underlying thread-local seam, this requires a current-thread executor.
pub async fn with_forced_unsupervised<F, Fut, T>(f: F) -> T
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = T>,
{
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            busbar_core_admin::restart::swap_forced_unsupervised(self.0);
        }
    }
    let _restore = Restore(busbar_core_admin::restart::swap_forced_unsupervised(true));
    f().await
}

/// Every component schema a registered plane's `openapi_schemas` contributes, as
/// `(plane key, schema name, schema)`, each plane folded over the two generators `openapi_doc` hands
/// every contributor, configured as it configures them (the composition root's admin tests hold
/// them to the committed document with the door planes registered).
#[cfg(feature = "openapi-schema")]
pub fn plane_component_schemas() -> Vec<(&'static str, String, serde_json::Value)> {
    let generator = |serialize: bool| {
        let settings = schemars::generate::SchemaSettings::draft2020_12().with(|s| {
            s.definitions_path = "/components/schemas".into();
            s.meta_schema = None;
        });
        if serialize {
            settings.for_serialize().into_generator()
        } else {
            settings.for_deserialize().into_generator()
        }
    };
    let mut out = Vec::new();
    for decl in busbar_kernel::plane_driver::registry::plane_decls() {
        let Some(schemas) = decl.openapi_schemas else {
            continue;
        };
        let (mut gen, mut req_gen) = (generator(true), generator(false));
        let mut paths = match decl.openapi.map(|openapi| openapi(decl)) {
            Some(serde_json::Value::Object(paths)) => paths,
            _ => serde_json::Map::new(),
        };
        schemas(decl, &mut gen, &mut req_gen, &mut paths);
        for (name, schema) in gen.definitions().iter().chain(req_gen.definitions()) {
            out.push((decl.key, name.clone(), schema.clone()));
        }
    }
    out
}
