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

use busbar_kernel::ingress::arrival::{BodyIngressEntry, PathIngressEntry};
use busbar_kernel::plane::registry::PlaneDecl;
use busbar_kernel::plane::registry::{BillableClass, PlaneDeclaration, PlaneHooks};
use busbar_kernel::plane_host::{EngineHost, LiveHostFactory};
use busbar_plugin_loader::{DynPlane, HotPlaneDecl};

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

/// What a unit's [`RootUnit::on_book`] step is handed: the node's one book and the boot facts beside
/// it that were resolved before any listener binds.
pub struct BookCtx<'a> {
    /// The process's one book, opening already sealed.
    pub book: &'a crate::root::durability::NodeBook,
    /// The boot generation.
    pub app: &'a busbar_kernel::state::App,
    /// The deployment's secret resolver.
    pub resolver: &'a dyn busbar_api::SecretResolve,
    /// The data listener: bind address and TLS block.
    pub data: (&'a str, Option<&'a busbar_kernel::config::TlsCfg>),
    /// The admin listener: bind address and TLS block.
    pub admin: (&'a str, Option<&'a busbar_kernel::config::TlsCfg>),
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
    Ok(linked.planes.iter().chain(hot_rows).collect())
}

/// ADAPT ONE HOT-LANE PLANE onto the plane axis — the ONE function a linked and a dropped-in plane
/// both pass through. The row's contract declaration is the plane's own statement, field for field:
/// its `name` is the registry key, its `section_key` the declaring section, and every other fact is
/// read off the decl's declaration tail (the loader refuses a decl that states none). Nothing is
/// defaulted and nothing stands in for anything. The plane lives for the process, so every string
/// and list here is borrowed from it or kept once, as the installed row list is. Its hooks are
/// [`HOT_PLANE_HOOKS`].
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
    };
    Ok(PlaneDecl::assemble(declaration, HOT_PLANE_HOOKS))
}

/// THE KERNEL HOOKS OF A HOT-LANE PLANE: the inert set (claims no path, binds no audience, builds no
/// slot), because the kernel's request loop does not yet drive a plane through its C-ABI slots —
/// `docs/design/1.6.0-TRACKER.md` H6 part 1. The same set for every HOT-lane plane, whichever door.
pub const HOT_PLANE_HOOKS: PlaneHooks = PlaneHooks {
    wire_format_names: || &[],
    claims: |_| Vec::new(),
    admission: |_| None,
    build: |_| None,
    routes: None,
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

/// THE PLANES DROPPED INTO THE CONFIGURED `plugins.dir`, read before the plane axis is installed —
/// so before the configuration is parsed, which needs that axis. Only the kernel-owned `plugins:`
/// block is read, off the same file and environment interpolation the boot load uses; the trust
/// policy and the persisted first-party floors are resolved as the preflight resolves them. No
/// `plugins:` block, `enabled: false`, or no readable file: no planes, and the directory is not read.
pub fn dropped_planes_from_config() -> Vec<DynPlane> {
    let path =
        crate::root::cli::resolve_config_path(crate::root::cli::config_path_flag().as_deref());
    let plugins = std::fs::read_to_string(path).ok().and_then(|raw| {
        let text = busbar_kernel::config::interpolate_env_with(
            &raw,
            busbar_kernel::config::EnvSubst::Lenient,
            &mut Vec::new(),
        )
        .ok()?;
        let doc: serde_yaml::Value = serde_yaml::from_str(&text).ok()?;
        serde_yaml::from_value::<busbar_kernel::config::PluginsCfg>(doc.get("plugins")?.clone())
            .ok()
    });
    let Some(plugins) = plugins.filter(|p| p.enabled) else {
        return Vec::new();
    };
    let Ok(mut policy) = plugins.to_policy() else {
        return Vec::new();
    };
    let data_dir = busbar_kernel::preflight::fleet_data_dir();
    policy.first_party_high_water = busbar_plugin_loader::HighWaterMarks::load(data_dir.as_deref())
        .0
        .marks();
    dropped_planes(std::path::Path::new(&plugins.dir), &policy).unwrap_or_else(|refusal| {
        eprintln!("busbar: {refusal}");
        std::process::exit(2);
    })
}

/// THE DIAGNOSTICS AXIS: every entry's owned diagnostics, installed once.
pub fn register_diagnostics(linked: &Linked) {
    let installed: Vec<&'static busbar_substrate_values::diagnostics::Diagnostic> = linked
        .diagnostics
        .iter()
        .flat_map(|diags| diags.iter().copied())
        .collect();
    busbar_substrate_values::diagnostics::install_diagnostics(installed.leak());
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
