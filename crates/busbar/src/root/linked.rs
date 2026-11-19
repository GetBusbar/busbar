// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use busbar_kernel::plane_driver::EngineHost;
use busbar_kernel::preflight::RootInstall;

pub type Compose = Box<dyn FnOnce(&dyn busbar_contract::secret::SecretResolve) + Send>;

/// The build's linked table (`$OUT_DIR/linked.rs`, written by `linked_gen.rs`). Every plugin is a
/// MIN-3 image ([`LinkedImage`]); the other axes are the linked crates' Rust entries.
pub struct Linked {
    /// Compiled MIN-3 headers, admitted through the same checked loader path on every platform.
    pub images: &'static [LinkedImage],

    pub protocol_seams: &'static [fn()],

    pub diagnostics: &'static [&'static [&'static busbar_contract::diagnostic::Diagnostic]],

    pub on_host: &'static [fn(&Arc<dyn EngineHost>)],

    pub compose: &'static [fn(&busbar_kernel::config::RootCfg) -> Option<Compose>],

    pub claims: &'static [LinkedClaims],
}

/// The generated root calls the loader with the plugin's unforgeable static header. Keeping the
/// admission function here avoids exposing the FFI header representation in the composition root.
pub struct LinkedImage {
    pub alias: &'static str,
    pub admit: fn() -> Result<
        busbar_plugin_loader::admit::Admitted,
        busbar_plugin_loader::refusal::Refusal,
    >,
}

/// One linked plane's contribution to the boot seal: the pure plane registered under its own key,
/// and the claims that plane declares.
#[derive(Clone, Copy)]
pub struct LinkedClaims {
    /// The pure plane, as the seal's registry holds it.
    pub plane: fn() -> Arc<dyn busbar_contract::Plugin>,
    /// The bytes it claims.
    pub claims: &'static [busbar_contract::grammar::Claim],
}

pub struct RootUnit {
    pub seal: Option<fn() -> Result<(), String>>,

    pub on_config: Option<fn(&busbar_kernel::config::limits::LimitsResolved)>,

    #[cfg(test)]
    pub opens_book: bool,

    #[cfg(any(test, distribution_root))]
    pub on_book: Option<fn(&BookCtx<'_>)>,
}

#[cfg(any(test, distribution_root))]
pub struct BookCtx<'a> {
    pub book: &'a crate::root::durability::NodeBook,
    /// The app the book was opened for: what the mounted owner tests' steps read.
    #[cfg(test)]
    pub app: &'a busbar_kernel::state::App,
}

pub fn register_protocols(linked: &Linked) {
    for install in linked.protocol_seams {
        install();
    }
}

/// The root's install record: the seams the kernel reads of the composition root. A seam the old
/// plugin interface served (the door auth axis, the auth chain module, the dispatcher latch) has no
/// root half any more and is stated absent.
pub fn register_stores() {
    busbar_kernel::preflight::install_linked_rows(RootInstall {
        linked_images: linked_images(),
        registry_build: Some(crate::root::boot::registry_rows),
        endpoint_locate: Some(crate::root::boot::locate_provider_destination),
        plugins_fetch: Some(crate::root::boot::plugins_fetch),
        // WP3 hook step: native hooks open only in the serving walk; the kernel opens none.
        // WP3 step 2: the native secret images, through custody; their set is the images prepare's.
        secret_axis: Some(&crate::root::native_secrets::NATIVE),

        rate_apply: Some(&crate::root::kernel::CardRepricer),
        rate_epoch: Some(&crate::root::kernel::CardRepricer),
        export_axis: Some(&crate::root::exports::EXPORTS),
        admission: Some(&crate::root::admission::ADMISSION),
        durable: Some(&crate::root::admission::DURABLE),
        hook_facts: Some(&crate::root::off_path::hooks::NATIVE),

        in_process_auth: None,
        native_auth: Some(crate::root::native_operator::answers_auth),
        config_projection: Some(crate::root::door_steps::door_config),
        admitted_grammar: Some(crate::root::boot::admitted_grammar),
    });
}

static DISK: std::sync::OnceLock<std::sync::Arc<busbar_kernel::host_disk::DiskLane>> =
    std::sync::OnceLock::new();

pub(crate) fn disk_lane() -> std::sync::Arc<busbar_kernel::host_disk::DiskLane> {
    DISK.get_or_init(std::sync::Arc::default).clone()
}

/// Hold the start scan's registry of `plugins.dir` for the readers that answer from it (the export
/// axis's secret and reference fields, the diagnostics catalogue).
pub(crate) fn register_dropped(dropped: Option<&'static crate::root::loader::PluginRegistry>) {
    if let Some(registry) = dropped {
        let _ = DROPPED.set(registry);
    }
}

pub(crate) fn dropped() -> Option<&'static crate::root::loader::PluginRegistry> {
    DROPPED.get().copied()
}

static DROPPED: std::sync::OnceLock<&'static crate::root::loader::PluginRegistry> =
    std::sync::OnceLock::new();

/// The diagnostics catalogue: the host's codes, each linked crate's `diagnostics` axis, and the codes
/// a first-party dropped-in plugin declares.
pub fn register_diagnostics(linked: &Linked) -> busbar_kernel::diagnostics::Catalogue {
    let mut installed: Vec<&'static busbar_contract::diagnostic::Diagnostic> = linked
        .diagnostics
        .iter()
        .flat_map(|diags| diags.iter().copied())
        .collect();
    if let Some(registry) = DROPPED.get().copied() {
        match declared_diagnostics(registry, &installed) {
            Ok(declared) => installed.extend(declared),
            Err(refusal) => {
                eprintln!("busbar: {refusal}");
                crate::root::exit::exit(2);
            }
        }
    }
    busbar_kernel::diagnostics::Catalogue::lent(installed.leak())
}

pub(crate) fn declared_diagnostics(
    registry: &crate::root::loader::PluginRegistry,
    taken: &[&'static busbar_contract::diagnostic::Diagnostic],
) -> Result<Vec<&'static busbar_contract::diagnostic::Diagnostic>, String> {
    let mut declared = Vec::new();
    for p in registry.loadable() {
        let name = p.key();
        let declarations = p.declarations().map_err(|e| {
            format!("plugin '{name}' states a `declares` section that does not read: {e}")
        })?;
        let decls = &declarations.diagnostics;
        if !decls.is_empty() && !p.first_party() {
            return Err(format!(
                "plugin '{name}' declares diagnostics but is not first-party; only a first-party \
                 plugin's codes join the catalogue"
            ));
        }
        let held: Vec<_> = taken.iter().chain(&declared).copied().collect();
        declared.extend(catalogue_entries(name, decls, &held)?);
    }
    Ok(declared)
}

fn catalogue_entries(
    name: &str,
    decls: &[crate::root::loader::sign::DiagnosticDecl],
    held_already: &[&'static busbar_contract::diagnostic::Diagnostic],
) -> Result<Vec<&'static busbar_contract::diagnostic::Diagnostic>, String> {
    use busbar_contract::diagnostic::{Class, Diagnostic, Severity};
    use busbar_kernel::diagnostics::REGISTRY;
    let taken = held_already;
    let leak = |s: &str| -> &'static str { Box::leak(s.to_string().into_boxed_str()) };
    let mut declared: Vec<&'static Diagnostic> = Vec::new();
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
    Ok(declared)
}

pub fn seal(units: &[&RootUnit]) {
    for seal in units.iter().filter_map(|u| u.seal) {
        if let Err(refusal) = seal() {
            eprintln!("busbar: {refusal}");
            crate::root::exit::exit(2);
        }
    }
}

#[cfg(test)]
#[path = "tests/linked_store_double.rs"]
mod linked_store_double;

/// The build's compiled-in MIN-3 images (`LINKED.images`), each admitted (the loader's `admit_linked`, a read of
/// the static header) for its verified identity and kind: the kernel's `RootInstall::linked_images` rows. An image
/// that does not admit has no row; the boot's own admission of the same rows refuses it.
fn linked_images() -> &'static [busbar_kernel::preflight::LinkedImage] {
    static ROWS: std::sync::OnceLock<Vec<busbar_kernel::preflight::LinkedImage>> =
        std::sync::OnceLock::new();
    ROWS.get_or_init(|| {
        crate::LINKED
            .images
            .iter()
            .filter_map(|row| {
                let admitted = (row.admit)().ok()?;
                Some(busbar_kernel::preflight::LinkedImage {
                    identity: admitted.identity().to_owned(),
                    alias: row.alias.to_owned(),
                    kind: crate::root::loader::admit::kind_word(admitted.kind()),
                })
            })
            .collect()
    })
}
