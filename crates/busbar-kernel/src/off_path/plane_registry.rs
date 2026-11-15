// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `plane_driver::registry`'s off-path code: the process plane list's fold (once, at first read, or
//! once per registration set a test binary publishes), the plane dispatch table's build (once per
//! generation), and the config- and schema-time hook types and the door's stated admin schemas
//! (once per configuration or OpenAPI document build).

use crate::plane_driver::registry::{PlaneDecl, PlaneDeclaration};

/// THE CONFIG-TIME VALIDATE HOOK's shape ([`PlaneDecl::config_validate`]): one raw named-definition
/// document, judged on an admin write.
pub(crate) type ConfigValidateHook =
    fn(&PlaneDecl, name: &str, def: &serde_json::Value) -> Result<(), String>;

/// THE ADMIN OpenAPI PATH FRAGMENT HOOK's shape ([`PlaneDecl::openapi`]), read per OpenAPI document
/// build.
pub(crate) type OpenapiHook = fn(&PlaneDecl) -> serde_json::Value;

#[cfg(feature = "openapi-schema")]
pub(crate) type OpenapiSchemasHook = fn(
    &PlaneDecl,
    &mut schemars::SchemaGenerator,
    &mut schemars::SchemaGenerator,
    &mut serde_json::Map<String, serde_json::Value>,
);

#[cfg(not(feature = "openapi-schema"))]
pub(crate) type OpenapiSchemasHook = fn(&PlaneDecl, std::convert::Infallible);

#[cfg(feature = "openapi-schema")]
pub(crate) fn stated_schemas(
    decl: &PlaneDecl,
    schema_gen: &mut schemars::SchemaGenerator,
    _req_gen: &mut schemars::SchemaGenerator,
    _paths: &mut serde_json::Map<String, serde_json::Value>,
) {
    let schemas = crate::plane_driver::door::admin_openapi(decl)
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok())
        .and_then(|mut blob| {
            blob.get_mut(crate::plane_driver::door::OPENAPI_COMPONENTS)
                .map(serde_json::Value::take)
        })
        .and_then(|mut components| components.get_mut("schemas").map(serde_json::Value::take))
        .and_then(|schemas| match schemas {
            serde_json::Value::Object(schemas) => Some(schemas),
            _ => None,
        });
    if let Some(schemas) = schemas {
        schema_gen.definitions_mut().extend(schemas);
    }
}

pub(crate) fn merged_boot_plane_decls(
    installed: &[&'static PlaneDecl],
    builtins: &[&'static PlaneDecl],
) -> Vec<&'static PlaneDecl> {
    let mut decls: Vec<&'static PlaneDecl> = Vec::new();
    for d in installed.iter().chain(builtins) {
        if decls.iter().any(|p| p.key == d.key) {
            tracing::info!(
                plane = d.key,
                "skipping a later registration of an already-declared plane (composition-root copy \
                 and built-in copy of one plane)"
            );
            continue;
        }
        decls.push(d);
    }

    // Every key is distinct (deduplicated above) and has a distinct canonical position, so a
    // stable sort orders them exactly as one without ties would.
    let canonical = canonical_key_order(installed, builtins);
    decls.sort_by_key(|d| {
        canonical
            .iter()
            .position(|k| *k == d.key)
            .unwrap_or(canonical.len())
    });

    let declared: Vec<&PlaneDeclaration> = decls.iter().map(|d| &d.declaration).collect();
    if let Err(refusal) = crate::plane_driver::registry::check_owned_config_claims(
        &declared,
        crate::plane_driver::registry::CORE_OWNED_CONCRETE_SECTIONS,
    ) {
        panic!("plane-owned-config dup-claim guard: {refusal}");
    }
    decls
}

pub(crate) fn canonical_key_order(
    installed: &[&'static PlaneDecl],
    builtins: &[&'static PlaneDecl],
) -> Vec<&'static str> {
    let mut order: Vec<&'static str> = Vec::new();
    for d in builtins.iter().chain(installed) {
        if !order.contains(&d.key) {
            order.push(d.key);
        }
    }
    order
}

/// The fold of the installed declarations plus `registered` (ahead of the built-ins), leaked for
/// the process: what [`crate::plane_driver::registry::publish_planes`] publishes.
pub(crate) fn published_fold(
    installed: &[&'static PlaneDecl],
    registered: &[&'static PlaneDecl],
) -> &'static [&'static PlaneDecl] {
    let mut all: Vec<&'static PlaneDecl> = installed.to_vec();
    all.extend_from_slice(registered);
    merged_boot_plane_decls(&all, crate::plane_driver::registry::builtin_plane_decls()).leak()
}

pub fn build_dispatch(
    decls: &[&'static PlaneDecl],
    slots: &std::collections::BTreeMap<&'static str, &dyn std::any::Any>,
    key_chain: bool,
) -> Result<crate::plane_driver::dispatch::PlaneDispatch, String> {
    let mut dispatch = crate::plane_driver::dispatch::PlaneDispatch::default();
    for decl in decls {
        let Some(slot) = slots.get(decl.key).copied() else {
            continue;
        };
        let claims = (decl.claims)(slot);
        let admission = (decl.admission)(slot);

        let key_admitted = key_chain && crate::plane_driver::door::is_door(decl);
        if !claims.is_empty() && admission.is_none() && !key_admitted {
            return Err(format!(
                "plane `{}` mounts {} path(s) but bound no admission; a mounted plane must bind an \
                 RFC 8707 audience (see PlaneDispatch::admission_for) or claim no path — serving a \
                 claimed path with no audience admits a token minted for any other resource",
                decl.key,
                claims.len()
            ));
        }
        for (path, wire) in claims {
            dispatch = dispatch.mount_key(decl.key, &path, wire);
        }
        if let Some(admission) = admission {
            dispatch = dispatch.admit_key(decl.key, admission);
        }
    }
    Ok(dispatch)
}
