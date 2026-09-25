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
//! feeds, once its loaded declaration is adapted onto the same axes (#2 rule (1): compiled in or
//! dropped in, same contract, same loading path). Nothing here asks where a row came from.
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
use busbar_kernel::plane_host::{EngineHost, LiveHostFactory};

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

/// THE PLANE AXIS: every entry's registry row, installed once.
pub fn register_planes(linked: &Linked) {
    let installed: Vec<&'static PlaneDecl> = linked.planes.iter().collect();
    busbar_kernel::plane::registry::install_planes(installed.leak());
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
