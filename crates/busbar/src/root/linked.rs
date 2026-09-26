// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE REGISTRATION PATH — every linked entry the composition root holds, folded into the
//! kernel's registration seams axis by axis, in the order the entries arrive.
//!
//! The root names no plugin. `build.rs` reads the manifest's `[package.metadata.busbar.linked]`
//! (cargo feature → plugin crate), `linked-axes` (crate → the registration axes it fills),
//! `linked-entry` and `root-units` tables and emits `$OUT_DIR/linked.rs`: `extern crate <crate> as _;`
//! for every ENABLED feature, [`Linked`] — one table per registration axis over each crate's
//! `linked` entry module — a `linked_*` cfg per root-bound seam an enabled entry drives, and the
//! `ROOT_UNITS` table of each enabled root module's [`RootUnit`]. `main.rs` includes it and hands the
//! tables to the functions below — and they are the SAME functions a plugin dropped into `plugins/`
//! feeds (#2 rule (1): compiled in or dropped in, same contract, same loading path). On the plane
//! axis that is literal: a HOT-lane plane dropped into `plugins/` ([`dropped_planes`]) and the same
//! plane linked into the build ([`Linked::hot_planes`]) are both admitted by the loader into a
//! `DynPlane` and adapted onto the axis by the one [`hot_plane_row`]. Nothing here asks where a row
//! came from.
//!
//! What a plugin STATES about itself (its plane declaration) is contract data; what the kernel RUNS
//! for it is typed by the kernel's own seams (its plane hooks, protocol declarations, arrivals,
//! diagnostics) — the split `PlaneDeclaration` / `PlaneHooks` already has, joined kernel-side by
//! `PlaneDecl::assemble` in the generated plane table. The kernel defines nothing for this path.
//!
//! Every function keeps the shape of the per-crate write it replaced: the same seam, called the same
//! number of times, with the same contributions in the same order — the table's order, which is the
//! manifest's, which is the order the root always registered in. A build with a feature off has no
//! row for it, so its axis gets nothing from it, exactly as the feature-gated line it replaces did.

use std::sync::Arc;

use busbar_contract::plane::MetricFamily;
use busbar_kernel::ingress::arrival::{BodyIngressEntry, PathIngressEntry};
use busbar_kernel::plane::registry::PlaneDecl;
use busbar_kernel::plane::registry::{BillableClass, BuildCtx, PlaneDeclaration, PlaneHooks};
use busbar_kernel::plane::PlaneAdmission;
use busbar_kernel::plane_host::{EngineHost, LiveHostFactory};
use busbar_kernel::plane_routes::{PlaneReqCtx, PlaneResponse, PlaneRouteSpec};
use busbar_plugin_loader::{DynPlane, HotHostVtable, HotPlaneDecl, RouteAuth, RouteMethod};
use busbar_plugin_loader::{HotStatusClass as StatusClass, ServedPlane};

/// A provider composition step, captured off the resolved configuration before the app is built and
/// run once the deployment's secret resolver exists.
pub type Compose = Box<dyn FnOnce(&dyn busbar_api::SecretResolve)>;

/// The stdio serve mode: frames on stdin/stdout instead of a listener; resolves to the exit code.
pub type StdioServe =
    fn(LiveHostFactory) -> std::pin::Pin<Box<dyn std::future::Future<Output = i32>>>;

/// EVERY LINKED ENTRY'S ITEMS, one table per registration axis, in manifest order.
pub struct Linked {
    /// The plane axis: each entry's contract declaration joined kernel-side to its hooks.
    pub planes: &'static [PlaneDecl],
    /// The plane axis, HOT lane: each linked plane that exports a `#[repr(C)]` plane declaration
    /// (`busbar_plugin::hot::PlaneDecl`) instead of Rust hooks — admitted and adapted exactly as the
    /// same plane dropped into `plugins/` is (see [`register_planes`]).
    pub hot_planes: &'static [&'static HotPlaneDecl],
    /// Protocol declarations, appended to the installed protocol set in this order.
    pub protocols: &'static [&'static [&'static busbar_kernel::proto::ProtocolDecl]],
    /// URL-model arrivals, by protocol name.
    pub path_ingress: &'static [&'static [PathIngressEntry]],
    /// Body-model arrivals, by protocol name.
    pub body_ingress: &'static [&'static [BodyIngressEntry]],
    /// Installers of the protocol-axis seams an entry provides beside its declarations (a completion
    /// synthesizer, a stream-translator factory), each set once.
    pub protocol_seams: &'static [fn()],
    /// Owned diagnostics, joining the rendered catalog.
    pub diagnostics:
        &'static [&'static [&'static busbar_substrate_values::diagnostics::Diagnostic]],
    /// Installers of a duplex plane's inbound WS-accept arrivals (the seam is set once: the first
    /// duplex entry in table order is the one installed).
    pub ws_arrivals: &'static [fn()],
    /// Background work re-anchored on every generation's engine host (boot, then each swap).
    pub on_host: &'static [fn(&Arc<dyn EngineHost>)],
    /// Providers composed off the resolved configuration (see [`Compose`]).
    pub compose: &'static [fn(&busbar_kernel::config::RootCfg) -> Option<Compose>],
    /// The stdio serve mode (see [`StdioServe`]).
    pub stdio_serve: &'static [StdioServe],
    /// The export axis: each linked export sink's statement and boundary (see [`LinkedExport`]).
    pub exports: &'static [LinkedExport],
    /// The kernel-loop axes (#28): the declaration key of each plane `gauntlet_install::install()`
    /// flips onto the unified loop's ONE-SHOT runner, and of each it flips onto the SESSION runner.
    pub gauntlet_one_shot: &'static [&'static str],
    pub gauntlet_session: &'static [&'static str],
    /// The transport axis (#3, #30): each linked wire's key, declared layers and build, in manifest
    /// order — the boot seal folds them bottom-up (see `crate::root::registry`).
    pub transports: &'static [LinkedTransport],
    /// Each linked plane's pure plane, as the boot seal registers it, and the claims it declares.
    pub claims: &'static [LinkedClaims],
}

/// One linked wire, as its crate's entry states it: the registry key, the layers it declares it can
/// be built over, and its build — handed the layer the root built beneath it, where one is, and the
/// deployment's transport settings.
#[derive(Clone, Copy)]
pub struct LinkedTransport {
    /// The wire's registry key.
    pub key: &'static str,
    /// The layers it declares, in the order it would take one.
    pub composes_over: &'static [&'static str],
    /// Build the wire over `lower`.
    pub build: BuildTransport,
}

/// A wire's build: handed the layer built beneath it, where one is, and the deployment's settings.
pub type BuildTransport = fn(
    Option<Arc<dyn busbar_contract::Transport>>,
    &busbar_contract::transport::TransportSettings,
) -> Arc<dyn busbar_contract::Transport>;

/// One linked plane's contribution to the boot seal: the pure plane registered under its own key,
/// and the claims that plane declares.
#[derive(Clone, Copy)]
pub struct LinkedClaims {
    /// The pure plane, as the seal's registry holds it.
    pub plane: fn() -> Arc<dyn busbar_contract::Plugin>,
    /// The bytes it claims.
    pub claims: &'static [busbar_contract::grammar::Claim],
}

/// A linked EXPORT sink's entry (K9b): `(name, alias, declares, boundary)` — what its signed tarball
/// states (the manifest `declares` section as JSON) and the boundary the one cold load runs over.
pub type LinkedExport = (
    &'static str,
    &'static str,
    &'static str,
    &'static busbar_plugin_loader::ColdEntry,
);

/// The newest export payload schema this binary speaks — what a linked sink states.
fn export_abi() -> u32 {
    let supported = busbar_plugin_loader::supported_abi("export");
    supported.iter().copied().max().unwrap_or_default()
}

/// The registry rows the linked export sinks state: first-party manifests of `kind: export` at this
/// binary's payload schema, exactly what a release-signed tarball of each carries but `sha256` and
/// `signature`, which describe a file a linked row does not have.
pub fn linked_exports(
    exports: &[LinkedExport],
) -> Result<Vec<busbar_plugin_loader::LinkedPlugin>, String> {
    let row = |&(name, alias, declares, entry): &LinkedExport| {
        let declares = serde_json::from_str(declares)
            .map_err(|e| format!("linked export '{name}': its declares section: {e}"))?;
        let manifest = busbar_plugin_loader::sign::Manifest {
            name: name.into(),
            alias: alias.into(),
            kind: "export".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            publisher: busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER.into(),
            abi_version: export_abi(),
            sha256: String::new(),
            signature: String::new(),
            description: String::new(),
            homepage: String::new(),
            license: String::new(),
            needs: Default::default(),
            settings_schema: None,
            schema_derived: false,
            host: None,
            declares,
        };
        Ok(busbar_plugin_loader::LinkedPlugin::boundary(
            manifest, entry,
        ))
    };
    exports.iter().map(row).collect()
}

/// What the composition root wires for one of its own unit modules — the kernel-loop half of a plane
/// that still lives in the root. Addressed through the same generated tables as a plugin: the module
/// exports a `ROOT_UNIT` of this type, the manifest maps the cargo feature that compiles the module
/// to it, and the root's source names neither.
pub struct RootUnit {
    /// The boot-time self-check of what this unit composes. `Err` carries the refusal as the operator
    /// reads it after `busbar: `; the process exits 2 before any listener binds.
    pub seal: Option<fn() -> Result<(), String>>,
    /// Path-model arrivals that REPLACE the linked plugins' own arrivals of the same protocol name.
    pub path_ingress: &'static [PathIngressEntry],
    /// Body-model arrivals that replace the linked plugins' own of the same protocol name.
    pub body_ingress: &'static [BodyIngressEntry],
    /// Runs once the deployment's limits are resolved, before the app is built.
    pub on_config: Option<fn(&busbar_kernel::config::limits::LimitsResolved)>,
    /// TRUE for a unit that settles onto the node's book: the book is opened for it.
    pub opens_book: bool,
    /// Runs once the node's book is open, before any listener binds.
    pub on_book: Option<fn(&BookCtx<'_>)>,
}

/// What a unit's [`RootUnit::on_book`] step is handed: the node's one book and the boot generation.
/// No secret resolver and no listener TLS block: the listeners' material is resolved by the path
/// that serves them, once, and a book step has no second reading of it to make.
pub struct BookCtx<'a> {
    /// The process's one book, opening already sealed.
    pub book: &'a crate::root::durability::NodeBook,
    /// The boot generation.
    pub app: &'a busbar_kernel::state::App,
}

/// THE PROTOCOL AXIS: every entry's declarations and its path- and body-model arrivals (a root unit's
/// arrival of the same name standing in for the plugin's), then each entry's protocol-axis seams.
pub fn register_protocols(linked: &Linked, units: &[&RootUnit]) {
    let installed: Vec<&'static busbar_kernel::proto::ProtocolDecl> = linked
        .protocols
        .iter()
        .flat_map(|decls| decls.iter().copied())
        .collect();
    let path_ingress: Vec<PathIngressEntry> = linked
        .path_ingress
        .iter()
        .flat_map(|arrivals| arrivals.iter())
        .map(|&arrival| replaced(arrival, units.iter().map(|u| u.path_ingress)))
        .collect();
    busbar_kernel::proto::install_protocols_with_path_ingress(installed, path_ingress);
    let body_ingress: Vec<BodyIngressEntry> = linked
        .body_ingress
        .iter()
        .flat_map(|arrivals| arrivals.iter())
        .map(|&arrival| replaced(arrival, units.iter().map(|u| u.body_ingress)))
        .collect();
    busbar_kernel::ingress::arrival::install_body_ingress(body_ingress);
    for install in linked.protocol_seams {
        install();
    }
}

/// `arrival`, or the first stand-in of the same protocol name the root's units carry.
fn replaced<F: Copy + 'static>(
    arrival: (&'static str, F),
    mut stand_ins: impl Iterator<Item = &'static [(&'static str, F)]>,
) -> (&'static str, F) {
    stand_ins
        .find_map(|table| table.iter().find(|(name, _)| *name == arrival.0).copied())
        .unwrap_or(arrival)
}

/// THE PLANE AXIS: every entry's registry row and every HOT-lane plane's — linked or dropped in —
/// installed once. A plane whose declaration the loader will not admit refuses the boot (exit 2)
/// whichever door it came in by, before any listener binds.
pub fn register_planes(linked: &Linked, dropped: Vec<DynPlane>) {
    match plane_rows(linked, dropped) {
        Ok(rows) => busbar_kernel::plane::registry::install_planes(rows.leak()),
        Err(refusal) => {
            eprintln!("busbar: {refusal}");
            std::process::exit(2);
        }
    }
}

/// The rows [`register_planes`] installs, in install order: the linked Rust-hook planes, then the
/// linked HOT-lane planes, then the dropped-in ones — each HOT-lane plane admitted by the loader
/// (`link_plane` for a linked decl, the `plugins/` load for a dropped one) and adapted by the one
/// [`hot_plane_row`]. The kernel's boot fold (`merged_boot_plane_decls`) then orders, dedups and
/// claim-checks them without knowing which door any came in by.
pub fn plane_rows(
    linked: &Linked,
    dropped: Vec<DynPlane>,
) -> Result<Vec<&'static PlaneDecl>, String> {
    let mut hot = linked
        .hot_planes
        .iter()
        .map(|decl| busbar_plugin_loader::link_plane(decl, "linked plane"))
        .collect::<Result<Vec<DynPlane>, String>>()?;
    hot.extend(dropped);
    // The HOT-lane planes live as long as the process, as a linked plane's image does, and so do the
    // rows read off them: the batch is kept once, the same way the installed row list is.
    let hot: &'static [DynPlane] = hot.leak();
    let hot_rows: &'static [PlaneDecl] = hot
        .iter()
        .map(hot_plane_row)
        .collect::<Result<Vec<PlaneDecl>, String>>()?
        .leak();
    let rows: Vec<&'static PlaneDecl> = linked.planes.iter().chain(hot_rows).collect();
    let declared: Vec<&PlaneDeclaration> = rows.iter().map(|d| &d.declaration).collect();
    busbar_contract::plane::check_metric_families(&declared, PLANE_CARRIED_SERIES)?;
    Ok(rows)
}

/// THE FIRST-PARTY SERIES A PLANE MAY CARRY — the host-owned list a plane's `busbar_`-named metric
/// family must be on, with exactly these label keys in this order, to be admitted (ARCHITECT RULING
/// S2-c; #65: a plane cannot mint an arbitrary `busbar_` series, and a carried one renders byte for
/// byte as the host's). A plane adds to a family only through `counter_add`, so only COUNTERS are
/// listed.
///
/// SOURCE: every `counter` row of the 1.5.5 metrics inventory, `v1.5.5:docs/observability.md`
/// (the metric table, lines 95–119), with its label keys in the order the host emits them — which
/// is the order the 1.5.5 exposition renders them (`busbar_route_policy_*` emit `policy` before
/// `pool`). Plus ONE row the ruling names that 1.5.5 did not have:
/// `busbar_billing_tap_decode_fail_total{protocol,reason}` is absent at the v1.5.5 tag (introduced
/// at 4cab71389) and is listed because S2-c requires the seam to carry it byte-identically.
pub const PLANE_CARRIED_SERIES: &[(&str, &[&str])] = &[
    (
        "busbar_requests_total",
        &["ingress_protocol", "pool", "outcome"],
    ),
    ("busbar_upstream_attempts_total", &["pool", "lane"]),
    (
        "busbar_upstream_failures_total",
        &["pool", "lane", "disposition"],
    ),
    ("busbar_breaker_trips_total", &["pool", "lane"]),
    ("busbar_failovers_total", &["pool", "reason"]),
    ("busbar_translations_total", &["from", "to"]),
    ("busbar_route_policy_selections_total", &["policy", "pool"]),
    (
        "busbar_route_policy_rejections_total",
        &["policy", "pool", "status"],
    ),
    ("busbar_billing_truncated_total", &[]),
    ("busbar_tap_notifications_dropped_total", &[]),
    ("busbar_webhook_logs_dropped_total", &[]),
    ("busbar_file_logs_dropped_total", &[]),
    (
        "busbar_billing_tap_decode_fail_total",
        &["protocol", "reason"],
    ),
];

/// ADAPT ONE HOT-LANE PLANE onto the plane axis — the ONE function a linked and a dropped-in plane
/// both pass through. The row's contract declaration is the plane's own statement, field for field:
/// its `name` is the registry key, its `section_key` the declaring section, and every other fact is
/// read off the decl's declaration tail (the loader refuses a decl that states none). Nothing is
/// defaulted and nothing stands in for anything. The plane lives for the process, so every string
/// and list here is borrowed from it or kept once, as the installed row list is. Its hooks are
/// [`HOT_PLANE_HOOKS`], and the plane is recorded where their shared `build` finds it.
pub fn hot_plane_row(plane: &'static DynPlane) -> Result<PlaneDecl, String> {
    let key = plane.name();
    if key.is_empty() || plane.section_key().is_empty() {
        return Err(format!(
            "plane {plane:?} declares no name or no config section; a plane is installed by its \
             name and configured by its section"
        ));
    }
    let stated = plane.declaration();
    let list = |items: &'static [String]| -> &'static [&'static str] {
        items.iter().map(String::as_str).collect::<Vec<_>>().leak()
    };
    let declaration = PlaneDeclaration {
        key,
        fallback: stated.fallback,
        config_section: plane.section_key(),
        scope_kinds: list(&stated.scope_kinds),
        subject_noun: &stated.subject_noun,
        admin_noun: &stated.admin_noun,
        audit_kind: &stated.audit_kind,
        card_signing_domain: stated.signing_domain.as_deref(),
        card_kid_prefix: stated.signing_kid_prefix.as_deref(),
        owned_config_sections: list(&stated.owned_sections),
        billable_classes: stated
            .billable_classes
            .iter()
            .map(|(class, family)| BillableClass { class, family })
            .collect::<Vec<_>>()
            .leak(),
        fee_units: list(&stated.fee_units),
        metric_families: stated
            .metric_families
            .iter()
            .map(|f| MetricFamily {
                name: &f.name,
                kind: &f.kind,
                label_keys: list(&f.label_keys),
            })
            .collect::<Vec<_>>()
            .leak(),
    };
    HOT_PLANES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(plane);
    Ok(PlaneDecl::assemble(declaration, HOT_PLANE_HOOKS))
}

/// Every HOT-lane plane [`hot_plane_row`] adapted, in adaptation (= install) order: where the one
/// shared [`hot_build`] finds the plane a row is for, by the section its resource names. The first
/// plane with a section is the one the boot fold kept (it keeps the first row of a key).
static HOT_PLANES: std::sync::Mutex<Vec<&'static DynPlane>> = std::sync::Mutex::new(Vec::new());

/// THE HOST EVERY HOT-LANE PLANE IS BUILT AGAINST: the kernel's own vtable, all 44 slots, built once
/// and kept for the process — a built plane may hold the table it was handed at `build`, so the
/// table outlives it (the ABI's build contract). Each dispatch is handed a table and `HostCtx` of its
/// own, minted for it.
static HOT_HOST: std::sync::LazyLock<HotHostVtable> =
    std::sync::LazyLock::new(busbar_kernel::plane_host::build_plane_host_vtable);

/// A HOT-lane plane's runtime slot for one config generation: the plane as built, and the door it
/// stated through its `claims` and `admission` slots when it was built.
struct HotSlot {
    /// The built plane.
    served: ServedPlane,
    /// Each path it answers on: the method, the path, and the wire format (one the host speaks).
    claims: Vec<(RouteMethod, String, &'static str)>,
    /// The audience it binds, if it binds one.
    admission: Option<PlaneAdmission>,
}

/// BUILD a HOT-lane plane's slot for this generation, over the ABI. The kernel hands a plane whose
/// section it carries raw that section as its resource, `(section, value)`; the section names the
/// plane. The value crosses as JSON bytes, beside the deployment's public URL, into the plane's own
/// `build` slot (against [`HOT_HOST`]); what the built plane states through `claims` and `admission`
/// is read once, here. A plane that will not build, or states a door the host cannot mount, gets no
/// slot — it serves nothing this generation, and the refusal is logged, naming it.
fn hot_build(ctx: &BuildCtx) -> Option<std::sync::Arc<dyn std::any::Any + Send + Sync>> {
    let resource = ctx.endpoint_slot.as_deref()?;
    let (section, value) = resource.downcast_ref::<(&'static str, serde_yaml::Value)>()?;
    let plane = HOT_PLANES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .copied()
        .find(|p| p.section_key() == *section)?;
    match hot_slot(plane, value, ctx.public_url) {
        Ok(slot) => Some(std::sync::Arc::new(slot)),
        Err(refusal) => {
            tracing::error!(plane = plane.name(), "{refusal}");
            None
        }
    }
}

/// [`hot_build`]'s body: serve `plane` over `section`, then read and check the door it states.
fn hot_slot(
    plane: &'static DynPlane,
    section: &serde_yaml::Value,
    public_url: Option<&str>,
) -> Result<HotSlot, String> {
    let name = plane.name();
    let bytes = serde_json::to_vec(section)
        .map_err(|e| format!("plane `{name}`'s section is not representable as JSON: {e}"))?;
    let served = plane.serve(&HOT_HOST, &bytes, public_url)?;
    let methods = [
        RouteMethod::Get,
        RouteMethod::Post,
        RouteMethod::Put,
        RouteMethod::Patch,
        RouteMethod::Delete,
    ];
    let wires = [
        busbar_kernel::plane::WIRE_HTTP_JSON,
        busbar_kernel::plane::WIRE_JSONRPC,
        busbar_kernel::plane::WIRE_GRPC,
    ];
    let claims = served
        .claims()?
        .into_iter()
        .map(|c| {
            let method = methods.into_iter().find(|m| m.as_str() == c.method);
            let wire = wires.into_iter().find(|w| *w == c.wire);
            match (method, wire) {
                (Some(method), Some(wire)) => Ok((method, c.path, wire)),
                _ => Err(format!(
                    "plane `{name}` claims `{} {} {}`, a method or wire format the host does not serve",
                    c.method, c.path, c.wire
                )),
            }
        })
        .collect::<Result<Vec<_>, String>>()?;
    let admission = served
        .admission()?
        .map(|(audience, resource_metadata)| PlaneAdmission {
            audience,
            resource_metadata,
        });
    Ok(HotSlot {
        served,
        claims,
        admission,
    })
}

/// THE PATHS A HOT-LANE PLANE ANSWERS ON, as its `claims` slot stated them at build.
fn hot_claims(slot: &dyn std::any::Any) -> Vec<(String, &'static str)> {
    slot.downcast_ref::<HotSlot>().map_or_else(Vec::new, |s| {
        s.claims
            .iter()
            .map(|(_, path, wire)| (path.clone(), *wire))
            .collect()
    })
}

/// THE AUDIENCE A HOT-LANE PLANE BINDS, as its `admission` slot stated it at build.
fn hot_admission(slot: &dyn std::any::Any) -> Option<PlaneAdmission> {
    slot.downcast_ref::<HotSlot>()?.admission.clone()
}

/// THE DATA ROUTES A HOT-LANE PLANE SERVES: one per claimed path, at the data-plane bar
/// ([`RouteAuth::Key`]), each driving [`hot_dispatch`].
fn hot_routes(slot: &dyn std::any::Any) -> Vec<PlaneRouteSpec> {
    let Some(slot) = slot.downcast_ref::<HotSlot>() else {
        return Vec::new();
    };
    slot.claims
        .iter()
        .map(|(method, path, _)| PlaneRouteSpec {
            path: path.clone(),
            method: *method,
            auth: RouteAuth::Key,
            handler: std::sync::Arc::new(|ctx| {
                let response = hot_dispatch(&ctx);
                Box::pin(async move { response })
            }),
        })
        .collect()
}

/// DRIVE ONE REQUEST THROUGH A HOT-LANE PLANE: the request body is the work item's finite inbound
/// buffer, dispatched through the plane's `dispatch` slot inside the kernel's attributed host mint
/// (`with_borrowed_host_as`, under the plane's registry key, over this request's engine snapshot and
/// a fresh arena) — so every host call the plane makes back is recovered, governed, metered and
/// journalled as this plane's. The plane's reply is the response body; its status class is the
/// response status (`Ok` 200, `Refused` 403, `Gone` 410, `Unsupported` 501, anything else 500).
fn hot_dispatch(ctx: &PlaneReqCtx) -> PlaneResponse {
    let slot = ctx.slot.downcast_ref::<HotSlot>();
    let handle = ctx.engine.downcast_ref::<busbar_kernel::state::AppHandle>();
    let (class, reply) = match (slot, handle) {
        (Some(slot), Some(handle)) => {
            let app = handle.load();
            let scope = busbar_kernel::plane_host::DispatchScope::new();
            let key = slot.served.plane().name();
            busbar_kernel::plane_host::with_borrowed_host_as(key, &app, &scope, |host_ctx, vt| {
                slot.served.dispatch(vt, host_ctx, &ctx.body)
            })
        }
        _ => (StatusClass::Fault, Vec::new()),
    };
    let status = match class {
        StatusClass::Ok => axum::http::StatusCode::OK,
        StatusClass::Refused => axum::http::StatusCode::FORBIDDEN,
        StatusClass::Gone => axum::http::StatusCode::GONE,
        StatusClass::Unsupported => axum::http::StatusCode::NOT_IMPLEMENTED,
        StatusClass::Fault => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
    };
    axum::http::Response::builder()
        .status(status)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(reply))
        .unwrap_or_default()
}

/// THE KERNEL HOOKS OF A HOT-LANE PLANE — the same set for every HOT-lane plane, whichever door it
/// came in by: its claims, admission, build and data routes each run over the plane's C-ABI slots
/// (the loader's [`DynPlane`] / [`ServedPlane`] against the kernel's own host vtable), and the
/// request loop drives it through the same plane-route mount every linked plane's routes take.
pub const HOT_PLANE_HOOKS: PlaneHooks = PlaneHooks {
    wire_format_names: || &[],
    claims: hot_claims,
    admission: hot_admission,
    build: hot_build,
    routes: Some(hot_routes),
    admin_routes: None,
    openapi: None,
    hydrate: None,
    start: None,
    config_validate: None,
    named_def_list: None,
    named_def_get: None,
    registry_contains: None,
    reresolve_gates: None,
    openapi_schemas: None,
    on_swap: None,
    parse_section: None,
    parse_endpoint: None,
    lower_endpoint: None,
    build_runtime: None,
    viewer: None,
    retain_verify_gates: None,
    default_section: None,
    resolve_provider: None,
};

/// THE PLANES DROPPED INTO `dir`: every tarball the loader's three-phase scan admits under `policy`
/// whose signed kind is `plane`, loaded over the HOT-tier ABI from its verified bytes, in the scan's
/// (filename) order. A scan the loader refuses yields no plane here — the plugins preflight reads the
/// same directory under the same policy later in boot and refuses it there with every problem named;
/// a trusted plane that will not LOAD is a refusal here, as a linked plane's would be.
pub fn dropped_planes(
    dir: &std::path::Path,
    policy: &busbar_plugin_loader::sign::TrustPolicy,
) -> Result<Vec<DynPlane>, String> {
    let Ok(registry) = busbar_plugin_loader::scan_and_validate(dir, policy) else {
        return Ok(Vec::new());
    };
    registry.open_planes()
}

/// THE PLUGINS DROPPED INTO THE CONFIGURED `plugins.dir`, scanned ONCE before any axis is installed —
/// so before the configuration is parsed, which needs those axes — and kept for the process, whose
/// dropped-in planes and export modules are opened from it. Only the kernel-owned `plugins:` block is
/// read, off the same file and environment interpolation the boot load uses; the trust policy and
/// the persisted first-party floors are resolved as the preflight resolves them. No `plugins:`
/// block, `enabled: false`, or no readable file: `None`, and the directory is not read. A scan the
/// loader refuses is `None` here too — the plugins preflight reads the same directory under the same
/// policy later in boot and refuses it there with every problem named.
///
/// The build's LINKED export sinks ([`Linked::exports`], K9b) are registered into the same registry
/// ahead of the directory's rows, through the one admission (`PluginRegistry::link`) — so the export
/// axis holds both doors' rows, and a build that links a sink has an axis with no `plugins:` block.
pub fn dropped_from_config(
    linked: &Linked,
) -> Option<&'static busbar_plugin_loader::PluginRegistry> {
    let rows = linked_exports(linked.exports).unwrap_or_else(|refusal| {
        eprintln!("busbar: {refusal}");
        std::process::exit(2);
    });
    let scanned = scan_configured();
    if scanned.is_none() && rows.is_empty() {
        return None;
    }
    let registry = scanned.unwrap_or_else(busbar_plugin_loader::PluginRegistry::empty);
    let registry = registry.link(rows).unwrap_or_else(|refusal| {
        eprintln!("busbar: {refusal}");
        std::process::exit(2);
    });
    // Kept for the process — the export axis and the diagnostics axis read it for as long as it
    // serves — in the one registry slot boot fills.
    Some(REGISTRY.get_or_init(|| registry))
}

/// The one plugin registry [`dropped_from_config`] builds, held for the process.
static REGISTRY: std::sync::OnceLock<busbar_plugin_loader::PluginRegistry> =
    std::sync::OnceLock::new();

/// The configured `plugins.dir`'s admitted rows (see [`dropped_from_config`]).
fn scan_configured() -> Option<busbar_plugin_loader::PluginRegistry> {
    let path =
        crate::root::cli::resolve_config_path(crate::root::cli::config_path_flag().as_deref());
    let raw = std::fs::read_to_string(path).ok()?;
    let text = busbar_kernel::config::interpolate_env_with(
        &raw,
        busbar_kernel::config::EnvSubst::Lenient,
        &mut Vec::new(),
    )
    .ok()?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&text).ok()?;
    let plugins =
        serde_yaml::from_value::<busbar_kernel::config::PluginsCfg>(doc.get("plugins")?.clone())
            .ok()
            .filter(|p| p.enabled)?;
    let mut policy = plugins.to_policy().ok()?;
    let data_dir = busbar_kernel::preflight::fleet_data_dir();
    policy.first_party_high_water = busbar_plugin_loader::HighWaterMarks::load(data_dir.as_deref())
        .0
        .marks();
    busbar_plugin_loader::scan_and_validate(std::path::Path::new(&plugins.dir), &policy).ok()
}

/// THE PLANES DROPPED INTO `dropped` (see [`dropped_from_config`]): every `kind: plane` plugin it
/// admitted, loaded over the HOT-tier ABI — a trusted plane that will not LOAD refuses the boot,
/// as a linked plane's would.
pub fn dropped_planes_of(dropped: Option<&busbar_plugin_loader::PluginRegistry>) -> Vec<DynPlane> {
    dropped
        .map_or(Ok(Vec::new()), |registry| registry.open_planes())
        .unwrap_or_else(|refusal| {
            eprintln!("busbar: {refusal}");
            std::process::exit(2);
        })
}

/// THE EXPORT AXIS: the registry an `export:` instance's `module:` resolves against — every
/// `kind: export` row the plugin registry's one registration admitted, dropped in here (and, as a
/// linked export crate lands, linked through `PluginRegistry::link`, the same admission) — installed
/// once, before the configuration is resolved (`busbar_kernel::export::plugin::install`). A row the
/// axis refuses (one spelling a built-in's module name) refuses the boot before any listener binds.
pub fn register_exports(dropped: Option<&'static busbar_plugin_loader::PluginRegistry>) {
    busbar_plugin_loader::observe::install_host_series(host_series);
    // The host's egress, which every sink's outbound request rides (K9a S5) — whatever else this
    // build links.
    busbar_plugin_loader::install_egress_carrier(&HostEgressCarrier);
    let Some(registry) = dropped else {
        return;
    };
    let _ = DROPPED.set(registry);
    if let Err(refusal) = shadowed_export(registry) {
        eprintln!("busbar: {refusal}");
        std::process::exit(2);
    }
    busbar_kernel::export::plugin::install(registry);
}

/// THE HOST'S METRIC CATALOG — every series the host itself emits, which a first-party plugin's
/// declared series may not claim (K9a S1: a claim on one is refused at open rather than merged into
/// the host's writes). The composition root is the one place that names it; the root's tests hold
/// it to every `busbar_*` series constant the kernel's metric modules define, so it cannot drift.
pub const HOST_SERIES: &[&str] = &[
    busbar_kernel::metrics::ROUTE_POLICY_SELECTIONS_TOTAL,
    busbar_kernel::metrics::ROUTE_POLICY_REJECTIONS_TOTAL,
    busbar_kernel::metrics::HOOK_CONTENT_TRUNCATED_TOTAL,
    busbar_kernel::metrics::BILLING_TRUNCATED_TOTAL,
    busbar_kernel::metrics::JOURNAL_QUARANTINED_TOTAL,
    busbar_kernel::metrics::REQUESTS_TOTAL,
    busbar_kernel::metrics::BREAKER_TRIPS_TOTAL,
    busbar_kernel::metrics::FAILOVERS_TOTAL,
    busbar_kernel::metrics::REQUEST_DURATION_SECONDS,
    busbar_kernel::metrics::TRANSLATIONS_TOTAL,
    busbar_kernel::metrics::PLANE_REQUESTS_TOTAL,
    busbar_kernel::metrics::PLANE_REQUEST_DURATION_SECONDS,
    busbar_kernel::metrics::ADMISSION_DENIED_TOTAL,
    busbar_kernel::metrics::METERING_PENDING_COALESCED_TOTAL,
    busbar_kernel::metrics::PLUGIN_REQUEST_HEADERS_TRUNCATED_TOTAL,
    busbar_kernel::metrics::PLUGIN_RESPONSE_HEADERS_REJECTED_TOTAL,
    busbar_kernel::metrics::KEY_SPEND_CENTS,
    busbar_kernel::metrics::KEY_TOKENS_TOTAL,
    busbar_kernel::metrics::BUCKET_TOKENS,
    busbar_kernel::metrics::BUCKET_SPEND_CENTS,
    busbar_kernel::metrics::BUCKET_BUDGET_REMAINING_CENTS,
    busbar_kernel::metrics::LANE_STATE,
    busbar_kernel::metrics::LANE_AVAILABLE,
    busbar_kernel::metrics::LANE_RECOVERY_HINT_MS,
    busbar_kernel::metrics::LANE_INFLIGHT,
    busbar_kernel::metrics::LANE_AVAILABLE_PERMITS,
    busbar_kernel::metrics::POOL_QUEUED,
    busbar_kernel::telemetry::UPSTREAM_ATTEMPTS_TOTAL,
    busbar_kernel::telemetry::UPSTREAM_FAILURES_TOTAL,
    busbar_substrate_values::handlers::BILLING_TAP_DECODE_FAIL_TOTAL,
    // `proxy_vocab`'s crate-private constant, spelled here as it renders.
    "busbar_tap_notifications_dropped_total",
];

/// Is `name` a series the host emits — one of [`HOST_SERIES`], or a histogram/summary's derived
/// `_sum` / `_count` / `_bucket` series of one?
pub fn host_series(name: &str) -> bool {
    let base = ["_sum", "_count", "_bucket"]
        .iter()
        .find_map(|suffix| name.strip_suffix(suffix));
    HOST_SERIES.iter().any(|s| *s == name || Some(*s) == base)
}

/// A `kind: export` row spelling a built-in export module's name — as its name or its alias — is
/// refused: every instance naming it would reach the built-in, and the plugin would sit on the axis
/// unreachable, silently.
pub fn shadowed_export(registry: &busbar_plugin_loader::PluginRegistry) -> Result<(), String> {
    let built_in = busbar_kernel::export::built_in;
    let rows = registry.linked().iter().chain(registry.loadable());
    let shadows = |p: &&busbar_plugin_loader::LoadablePlugin| {
        p.manifest.kind == "export" && (built_in(&p.manifest.name) || built_in(&p.manifest.alias))
    };
    match rows.into_iter().find(shadows) {
        Some(p) => Err(format!(
            "export plugin '{}' spells a built-in export module",
            p.manifest.name
        )),
        None => Ok(()),
    }
}

/// The plugin registry [`register_exports`] installed — read again by [`register_diagnostics`], so
/// the configured `plugins.dir` is scanned once.
static DROPPED: std::sync::OnceLock<&'static busbar_plugin_loader::PluginRegistry> =
    std::sync::OnceLock::new();

/// THE DIAGNOSTICS AXIS: every entry's owned diagnostics, and every first-party plugin's DECLARED
/// ones (K9a S3), installed once. A declaration the catalogue refuses refuses the boot.
pub fn register_diagnostics(linked: &Linked) {
    let mut installed: Vec<&'static busbar_substrate_values::diagnostics::Diagnostic> = linked
        .diagnostics
        .iter()
        .flat_map(|diags| diags.iter().copied())
        .collect();
    if let Some(registry) = DROPPED.get() {
        match declared_diagnostics(registry, &installed) {
            Ok(declared) => installed.extend(declared),
            Err(refusal) => {
                eprintln!("busbar: {refusal}");
                std::process::exit(2);
            }
        }
    }
    busbar_substrate_values::diagnostics::install_diagnostics(installed.leak());
}

/// PLUGIN DIAGNOSTICS (K9a S3): the catalogue entries `registry`'s plugins DECLARE
/// (`declares.diagnostics`), one for one, beside the `taken` ones already installed. Only a
/// first-party plugin (linked door, or signed by the release key) may declare a code; a code the
/// catalogue already holds, a class that is not the host's, or a severity that is not a severity
/// token is refused naming the plugin — a code is REGISTERED, never shadowed or renumbered.
pub fn declared_diagnostics(
    registry: &busbar_plugin_loader::PluginRegistry,
    taken: &[&'static busbar_substrate_values::diagnostics::Diagnostic],
) -> Result<Vec<&'static busbar_substrate_values::diagnostics::Diagnostic>, String> {
    use busbar_substrate_values::diagnostics::{Class, Diagnostic, Severity, REGISTRY};
    let leak = |s: &str| -> &'static str { Box::leak(s.to_string().into_boxed_str()) };
    let mut declared: Vec<&'static Diagnostic> = Vec::new();
    for p in registry.linked().iter().chain(registry.loadable()) {
        let (name, decls) = (&p.manifest.name, &p.manifest.declares.diagnostics);
        if !decls.is_empty() && !p.first_party() {
            return Err(format!(
                "plugin '{name}' declares diagnostics but is not first-party; only a first-party \
                 plugin's codes join the catalogue"
            ));
        }
        for d in decls {
            let refuse = |why: &str| {
                Err(format!(
                    "plugin '{name}' declares BUSBAR-{:04}: {why}",
                    d.code
                ))
            };
            let class = Class::ALL
                .into_iter()
                .find(|c| c.ordinal() == d.code / 1000);
            let severity = [
                Severity::BenignRecurring,
                Severity::Actionable,
                Severity::Fatal,
            ]
            .into_iter()
            .find(|s| s.as_str() == d.severity);
            let held = REGISTRY.iter().chain(taken).chain(&declared);
            let (Some(class), Some(severity)) = (class, severity) else {
                return refuse("its class or severity is not the host's");
            };
            if held.map(|h| h.code).any(|code| code == d.code) {
                return refuse("the catalogue already holds that code");
            }
            declared.push(Box::leak(Box::new(Diagnostic {
                code: d.code,
                class,
                slug: leak(&d.slug),
                title: leak(&d.title),
                severity,
                summary: leak(&d.summary),
                action: leak(&d.action),
                since: leak(&d.since),
                retired: false,
            })));
        }
    }
    Ok(declared)
}

/// THE WS-ACCEPT AXIS: each duplex entry installs its inbound arrivals — and none does when no entry
/// is duplex, so the router mounts no WS-accept route.
pub fn register_ws_arrivals(linked: &Linked) {
    for install in linked.ws_arrivals {
        install();
    }
}

/// THE ROOT-BOUND SEAMS an enabled entry drives, each bound once and only when some entry drives it
/// (the manifest's `egress` / `plane-sections` / `admin-envelope` axes, emitted by the build script as
/// `linked_*` cfgs): the hostless-egress driver and the egress-trust host, the parse-time section
/// list a cross-plane hook refusal reads, and the envelope a self-enveloping admin verb replies
/// through. Each backing is a ZST unit struct, so it promotes to `'static`.
pub fn register_seams() {
    #[cfg(linked_egress)]
    {
        busbar_kernel::egress::seam::install_hostless_egress(
            &busbar_kernel::egress::seam::CoreHostlessEgress,
        );
        busbar_kernel::plane_host::egress_trust::install_egress_trust_host(
            &busbar_kernel::plane_host::egress_trust::PassThroughEgressTrust,
        );
    }
    #[cfg(linked_plane_sections)]
    busbar_kernel::plane::config::install_plane_sections(
        busbar_kernel::plane::config::config_sections,
    );
    #[cfg(linked_admin_envelope)]
    busbar_kernel::admin_verbs::install_plane_admin_envelope(
        &busbar_kernel::admin::planeverbs::CorePlaneAdminEnvelope,
    );
}

/// THE EGRESS CARRIER (K9a S5): how the host carries an outbound HTTP request a plugin sink asks it
/// to make — the sink never dials. The request meets the host's webhook URL policy first (https
/// only; loopback, link-local, private, CGNAT and cloud-metadata targets refused), then rides the
/// host's egress engine on the pooled open-web posture the request-log webhook has always POSTed
/// over (webpki trust, system DNS, the boot environment's proxy tunnel), under the request's own
/// deadline over the exchange up to the response head. Headers are set in order, a later one
/// replacing an earlier of the same name; one that is not a valid header is left off. The answer's
/// status is read back; its body is not read.
pub struct HostEgressCarrier;

/// The carrier's one client, built on the first request it carries.
static CARRIER_CLIENT: std::sync::OnceLock<busbar_kernel::proxy::EgressClient> =
    std::sync::OnceLock::new();

impl HostEgressCarrier {
    /// The request as the hop sends it — after the URL policy — and its deadline; or the refusal.
    fn prepare(
        request: &busbar_plugin_loader::HttpRequest,
    ) -> Result<(CarriedRequest, tokio::time::Instant), busbar_plugin_loader::HostResult> {
        use busbar_plugin_loader::EgressCarrier as _;
        if let Err(refusal) = HostEgressCarrier.admit(&request.url) {
            return Err(carried_failure("refused", refusal));
        }
        let (Ok(uri), Ok(method)) = (
            request.url.parse::<axum::http::Uri>(),
            axum::http::Method::from_bytes(request.method.as_bytes()),
        ) else {
            return Err(carried_failure(
                "request",
                "target URL does not parse".to_string(),
            ));
        };
        let mut headers = axum::http::HeaderMap::new();
        for (name, value) in &request.headers {
            if let (Ok(n), Ok(v)) = (
                axum::http::header::HeaderName::from_bytes(name.as_bytes()),
                axum::http::HeaderValue::from_str(value),
            ) {
                headers.insert(n, v);
            }
        }
        let body = axum::body::Bytes::from(request.body.clone());
        let deadline =
            tokio::time::Instant::now() + std::time::Duration::from_millis(request.timeout_ms);
        Ok(((method, uri, headers, body), deadline))
    }

    /// Send a prepared request on the carrier's one client, under its deadline.
    async fn send(
        (method, uri, headers, body): CarriedRequest,
        deadline: tokio::time::Instant,
    ) -> busbar_plugin_loader::HostResult {
        let req = busbar_kernel::egress::engine::request(method, uri, headers, body);
        let client = CARRIER_CLIENT.get_or_init(|| {
            busbar_kernel::proxy::build_egress_client(
                &busbar_kernel::proxy::EgressClientSpec::pooled_webpki(
                    usize::MAX,
                    90,
                    false,
                    false,
                ),
            )
        });
        match busbar_kernel::egress::engine::send_bounded(client, req, deadline).await {
            Ok(answer) => {
                busbar_plugin_loader::HostResult::Http(busbar_plugin_loader::HttpResponse {
                    status: answer.status().as_u16(),
                    body: String::new(),
                })
            }
            Err(e) => carried_failure("request", e.into_cause()),
        }
    }
}

/// A request the carrier sends: method, target, headers, body.
type CarriedRequest = (
    axum::http::Method,
    axum::http::Uri,
    axum::http::HeaderMap,
    axum::body::Bytes,
);

/// A carried request's failure at `step`.
fn carried_failure(step: &str, error: String) -> busbar_plugin_loader::HostResult {
    busbar_plugin_loader::HostResult::Failed {
        step: step.to_string(),
        error,
        rotation: None,
    }
}

impl busbar_plugin_loader::EgressCarrier for HostEgressCarrier {
    fn carry(
        &self,
        request: &busbar_plugin_loader::HttpRequest,
    ) -> busbar_plugin_loader::HostResult {
        let (req, deadline) = match HostEgressCarrier::prepare(request) {
            Ok(prepared) => prepared,
            Err(refused) => return refused,
        };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return carried_failure("refused", "this host carries no plugin egress".to_string());
        };
        runtime.block_on(HostEgressCarrier::send(req, deadline))
    }

    /// The same hop, awaited by the delivery's task: no thread waits on the far end.
    fn carry_async(
        &'static self,
        request: busbar_plugin_loader::HttpRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = busbar_plugin_loader::HostResult> + Send>>
    {
        Box::pin(async move {
            match HostEgressCarrier::prepare(&request) {
                Ok((req, deadline)) => HostEgressCarrier::send(req, deadline).await,
                Err(refused) => refused,
            }
        })
    }

    fn admit(&self, url: &str) -> Result<(), String> {
        busbar_kernel::observability::validate_webhook_url(Some(url.to_string())).map(|_| ())
    }
}

/// THE ROOT UNITS' SEALS, in table order. A composition that disagrees with itself must not bind a
/// listener: the first refusal is written to standard error and the process exits 2.
pub fn seal(units: &[&RootUnit]) {
    for seal in units.iter().filter_map(|u| u.seal) {
        if let Err(refusal) = seal() {
            eprintln!("busbar: {refusal}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
#[path = "tests/linked.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/linked_exports.rs"]
mod export_tests;

#[cfg(test)]
#[path = "tests/export_webhook_conformance.rs"]
mod export_webhook_conformance;

#[cfg(test)]
#[path = "tests/linked_scrape.rs"]
mod scrape_tests;

#[cfg(test)]
#[path = "tests/metric_family_conformance.rs"]
mod metric_family_conformance;
