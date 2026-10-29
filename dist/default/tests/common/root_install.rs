// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A LOADER-BACKED ROOT FOR THE IN-PROCESS TESTS OF THIS PACKAGE.
//!
//! The kernel never names the loader (BUSBAR-1.6.0.md THE DESIGN l.322), so a test build of the
//! kernel stands in-process doubles in for the composition root's seams: its registry build admits
//! no dropped-in tarball, and its auth axis opens only the kit's linked doubles. A test here that
//! drives the kernel in process over a REAL dropped-in plugin (a signed tarball the loader scans, a
//! cdylib the loader loads) installs this instead — the loader's own registry build and auth rows,
//! as the root composes them — through the kernel's test seams
//! (`busbar_kernel::test_support::{install_test_root, install_test_auth_axis}`, read ahead of the
//! stand-in). An integration test cannot call the root's code (the root is a binary), so this is the
//! root's composition restated over the loader; the root's own unit tests prove the root's.
//!
//! The trust a scan judges under is the test build's: the `plugins:` block through the loader's
//! `TrustPolicy::from_config`, its first-party key [`release_key`] (the embedded release key's
//! private half no test holds).

// Each test binary that includes this module uses its own part of it.
#![allow(dead_code)]

use std::sync::Arc;

use busbar_contract::auth_calls::{AuthAxis, AuthCalls, OutboundServing};
use busbar_contract::plugin_rows::PluginRows;
use busbar_kernel::config::PluginsCfg;
use busbar_kernel::preflight::{BuildNote, CopyLine, LinkedRow, RegistryIn, RootInstall};
use busbar_plugin_loader::boot::{Build, Note, Scan};
use busbar_plugin_loader::sign::{SigningKey, TrustInput, TrustPolicy};
use busbar_plugin_loader::{LinkedPlugin, PluginRegistry};

/// The test build's release key: the first-party key [`trust_policy`] holds in place of the
/// embedded one. A test signs a first-party plugin with it (publisher `busbar`).
#[must_use]
pub fn release_key() -> SigningKey {
    SigningKey::from_bytes(&[0x5a; 32])
}

/// The test build's trust resolution: `cfg` through the loader's `TrustPolicy::from_config`, as the
/// root resolves it, its first-party key [`release_key`].
///
/// # Errors
/// A reserved or malformed publisher.
pub fn trust_policy(cfg: &PluginsCfg) -> Result<TrustPolicy, String> {
    let mut policy = TrustPolicy::from_config(TrustInput {
        publishers: &cfg.publisher_keys(),
        allow_unsigned: cfg.trust.allow_unsigned,
        allow_third_party: cfg.trust.allow_third_party,
        min_versions: &cfg.min_versions,
        first_party_floors: &cfg.first_party_floors,
        binary_version: env!("CARGO_PKG_VERSION"),
    })?;
    policy.first_party_key = Some(release_key().verifying_key());
    Ok(policy)
}

/// The registry row one of the kernel's linked rows states (the root's `boot::linked_row`).
fn linked_row(row: &LinkedRow) -> LinkedPlugin {
    let row = match *row {
        LinkedRow::Store((key, ephemeral, door, canonical)) => {
            LinkedPlugin::store_named(canonical, key, door, ephemeral)
        }
        LinkedRow::Auth((key, canonical, door)) => {
            LinkedPlugin::auth_door_named(canonical, key, door)
        }
    };
    let former = busbar_kernel::config::migration_table::former_names(&row.manifest.alias);
    row.with_former_names(former)
}

/// The loader's registry build over the kernel's linked rows (the root's `boot::registry_rows`).
fn registry_rows(
    i: RegistryIn<'_>,
    note: &mut dyn FnMut(BuildNote<'_>),
) -> Result<Arc<dyn PluginRows>, String> {
    let linked = i.linked.iter().map(linked_row).collect();
    let scan = match i.plugins {
        None => None,
        Some(p) => Some(Scan {
            policy: trust_policy(p).map_err(|e| format!("plugins.trust is invalid: {e}"))?,
            data_dir: i.data_dir,
            dir: p.enabled.then_some(std::path::Path::new(&p.dir)),
        }),
    };
    let registry =
        busbar_plugin_loader::boot::registry(Build { linked, scan }, &mut |n| match n {
            Note::FloorUnreadable(detail) => note(BuildNote::FloorUnreadable(detail)),
            Note::Off => note(BuildNote::Off),
            Note::Scanned(scanned) => {
                let copies: Vec<CopyLine> = scanned
                    .linked_copies()
                    .iter()
                    .map(|c| CopyLine {
                        name: c.name.clone(),
                        version: c.version.clone(),
                        file: c.file.clone(),
                        line: c.line(),
                    })
                    .collect();
                note(BuildNote::Scanned {
                    rows: scanned,
                    copies: &copies,
                });
            }
            Note::FloorUnwritable(e) => note(BuildNote::FloorUnwritable(e)),
        })?;
    Ok(Arc::new(registry))
}

/// Whether a dropped-in `kind: hook` row of `rows` answers `module` (the root's `hook_answers`).
fn hook_answers(rows: &dyn PluginRows, module: &str) -> bool {
    busbar_plugin_loader::rows::registry_of(rows)
        .is_some_and(|registry| busbar_plugin_loader::hook_door::dropped_answers(registry, module))
}

/// The registry of this build's linked rows alone.
fn linked_registry() -> PluginRegistry {
    let linked = busbar_kernel::preflight::linked_rows()
        .iter()
        .map(linked_row)
        .collect();
    PluginRegistry::empty()
        .link(linked)
        .unwrap_or_else(|_| PluginRegistry::empty())
}

/// The loader's auth rows over `rows` on a dispatcher of their own, lent the kernel's seal, with the
/// kit's outbound double serving every outbound style and its carriers where no row states them
/// (what the kernel's stand-in axis answers for a build that links no auth plugin).
fn auth_axis(rows: Arc<dyn PluginRows>) -> Arc<dyn AuthAxis> {
    let registry = busbar_plugin_loader::rows::registry_arc(rows)
        .unwrap_or_else(|| Arc::new(linked_registry()));
    Arc::new(LoaderAuth(busbar_test_kit::auth_axis::stand_in(
        registry,
        busbar_kernel::seal::lend(),
    )))
}

/// The loader's auth rows, the kit's outbound double beside them.
struct LoaderAuth(Arc<dyn AuthAxis>);

impl AuthAxis for LoaderAuth {
    fn linked_names(&self) -> Vec<String> {
        self.0.linked_names()
    }

    fn answers(&self, module: &str) -> bool {
        self.0.answers(module)
    }

    fn linked(&self, module: &str) -> bool {
        self.0.linked(module)
    }

    fn operator(&self) -> Option<(String, String)> {
        self.0.operator()
    }

    fn open(
        &self,
        module: &str,
        label: &str,
        settings: &serde_json::Value,
    ) -> Result<Arc<dyn AuthCalls>, String> {
        self.0.open(module, label, settings)
    }

    fn credential_readers(&self) -> Vec<String> {
        self.0.credential_readers()
    }

    fn carriers(&self, module: &str) -> Vec<String> {
        let rows = self.0.carriers(module);
        if rows.is_empty() && module == busbar_kernel::config::operator_provider() {
            return busbar_kernel::test_support::outbound_auth::double_operator_carriers();
        }
        rows
    }

    fn default_inbound_style(&self) -> Result<Vec<String>, String> {
        let rows = self.0.default_inbound_style()?;
        if rows.is_empty() {
            return Ok(busbar_kernel::test_support::outbound_auth::double_inbound_style());
        }
        Ok(rows)
    }

    fn serving(
        &self,
        style: &str,
        settings: &serde_json::Value,
    ) -> Result<Option<OutboundServing>, String> {
        busbar_kernel::test_support::outbound_auth::axis().serving(style, settings)
    }
}

/// One FIRST-PARTY export sink a test links: its name, its alias and its door (`plugin_door!`).
pub type ExportDoor = (
    &'static str,
    &'static str,
    busbar_contract::abi::mechanism::door::DoorFn,
);

/// The export sinks [`link_exports`] linked, as a registry held for the test binary's life.
static EXPORT_REGISTRY: std::sync::OnceLock<PluginRegistry> = std::sync::OnceLock::new();

/// The loader's export rows over [`EXPORT_REGISTRY`], on a dispatcher of their own carrying the
/// kernel's host services (so an opened sink's `serve` reads the host snapshot service as it does in
/// a booted process).
fn export_rows() -> Option<busbar_plugin_loader::export_axis::ExportRows<'static>> {
    static DISPATCHER: std::sync::OnceLock<Arc<busbar_plugin_loader::dispatch::Dispatcher>> =
        std::sync::OnceLock::new();
    let registry = EXPORT_REGISTRY.get()?;
    let dispatcher = DISPATCHER.get_or_init(|| {
        Arc::new(busbar_plugin_loader::dispatch::Dispatcher::with_services(
            busbar_plugin_loader::dispatch::DispatchConfig::default(),
            Arc::new(busbar_kernel::host_services::KernelServices::new()),
        ))
    });
    Some(busbar_plugin_loader::export_axis::ExportRows::new(
        registry,
        dispatcher.clone(),
    ))
}

/// The export axis: the linked sinks over the loader, and the kernel kit's stand-in for every word
/// none of them answers.
struct LoaderExports;

/// The kit's stand-in export axis.
fn kit() -> &'static dyn busbar_contract::export_calls::ExportAxis {
    &busbar_kernel::test_support::export_axis::STAND_IN
}

/// Whether a linked sink answers `module`.
fn sink(module: &str) -> Option<busbar_plugin_loader::export_axis::ExportRows<'static>> {
    export_rows().filter(|r| r.linked(module))
}

impl busbar_contract::export_calls::ExportAxis for LoaderExports {
    fn probe(
        &self,
        module: &str,
        instance: &str,
        settings: &serde_json::Value,
    ) -> Option<busbar_contract::export_calls::Probed> {
        match sink(module) {
            Some(rows) => rows.probe(module, instance, settings),
            None => kit().probe(module, instance, settings),
        }
    }

    fn check(
        &self,
        module: &str,
        phase: u32,
        instances: &[(String, serde_json::Value)],
    ) -> Option<Vec<String>> {
        match sink(module) {
            Some(rows) => rows.check(module, phase, instances),
            None => kit().check(module, phase, instances),
        }
    }

    fn open(
        &self,
        module: &str,
        label: &str,
        settings: &serde_json::Value,
    ) -> Result<Arc<dyn busbar_contract::export_calls::ExportCalls>, String> {
        match sink(module) {
            Some(rows) => rows.open(module, label, settings),
            None => kit().open(module, label, settings),
        }
    }

    fn linked(&self, module: &str) -> bool {
        sink(module).is_some() || kit().linked(module)
    }

    fn first_party(&self, module: &str) -> bool {
        match sink(module) {
            Some(rows) => rows.first_party(module),
            None => kit().first_party(module),
        }
    }

    fn one_instance(&self, module: &str) -> bool {
        match sink(module) {
            Some(rows) => rows.one_instance(module),
            None => kit().one_instance(module),
        }
    }

    fn linked_modules(&self) -> Vec<String> {
        let mut linked = export_rows()
            .map(|r| r.linked_modules())
            .unwrap_or_default();
        for module in kit().linked_modules() {
            if !linked.contains(&module) {
                linked.push(module);
            }
        }
        linked
    }

    fn routes(&self, module: &str) -> Vec<busbar_contract::abi::mechanism::route::Route> {
        match sink(module) {
            Some(rows) => rows.routes(module),
            None => kit().routes(module),
        }
    }
}

/// The axis [`install`] installs.
static EXPORTS: LoaderExports = LoaderExports;

/// INSTALL the loader-backed registry build, auth axis and export axis over the kernel's stand-in
/// (the first install stands). Call it at the top of every test that needs them, before the test
/// touches the kernel.
pub fn install() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        busbar_kernel::test_support::install_test_root(RootInstall {
            registry_build: Some(registry_rows),
            export_axis: Some(&EXPORTS),
            auth_chain_module: Some(
                busbar_plugin_loader::dispatch::kinds::auth::declares_chain_module,
            ),
            hook_answers: Some(hook_answers),
            ..busbar_kernel::preflight::root_rows()
        });
        busbar_kernel::test_support::install_test_auth_axis(auth_axis);
    });
}

/// LINK `exports` on the installed export axis as the composition root links its sinks (each a
/// first-party row over its door), ahead of the kit's stand-in. The first link stands.
///
/// The kit's stand-in is installed with them: its neutral rows answer every other FIRST-PARTY
/// sink's frozen 1.5.5 module word (`request-log-file` among them), as a linked build resolves
/// each, so a configuration naming one resolves here as it did when the kit linked these sinks
/// itself (`install_export_axis`).
pub fn link_exports(exports: &'static [ExportDoor]) {
    install();
    busbar_kernel::test_support::export_axis::install_export_axis();
    let _ = EXPORT_REGISTRY.get_or_init(|| {
        let linked = exports
            .iter()
            .map(|&(name, alias, door)| LinkedPlugin::first_party_door("export", name, alias, door))
            .collect();
        PluginRegistry::empty()
            .link(linked)
            .expect("the linked export sinks admit")
    });
}

// ── THE PLUGIN ADMISSION, OVER THE LOADER ───────────────────────────────────────────────────────
//
// The composition root's admission (`crates/busbar/src/root/admission.rs`, `ADMISSION`) restated
// over the loader under the test build's trust ([`trust_policy`]), for the in-process admin tests
// of this package: the same pipeline in the same words. The root's own unit tests prove the root's.

use busbar_kernel::admission::{Admitted, Inventoried, Judged, PluginAdmission, Refusal, Stated};
use busbar_plugin_loader::sign::{evaluate, validate_structure, Manifest, Verdict, HOST_IDENTITY};

/// The admission an admin test's `TestApp` carries (`TestApp::plugin_admission`).
pub static ADMISSION: LoaderAdmission = LoaderAdmission;

/// What a manifest states, in the kernel's words.
fn stated(m: &Manifest) -> Stated {
    Stated {
        name: m.name.clone(),
        alias: m.alias.clone(),
        kind: m.kind.clone(),
        version: m.version.clone(),
        publisher: m.publisher.clone(),
        abi_version: m.abi_version,
        settings_schema: m.settings_schema.clone(),
    }
}

/// `tarball` unpacked and its manifest checked (the root's `unpack_checked`).
fn unpack_checked(
    tarball: &[u8],
    what: &str,
) -> Result<busbar_plugin_loader::tarball::UnpackedPlugin, Refusal> {
    let unpacked = busbar_plugin_loader::tarball::unpack(tarball)
        .map_err(|e| Refusal::Validation(format!("invalid plugin tarball{what}: {e}")))?;
    validate_structure(
        &unpacked.manifest,
        &unpacked.lib_bytes,
        &busbar_plugin_loader::supported_abi,
        HOST_IDENTITY,
    )
    .map_err(|e| Refusal::Validation(format!("invalid plugin manifest{what}: {e}")))?;
    Ok(unpacked)
}

/// The admission over the loader.
#[derive(Debug)]
pub struct LoaderAdmission;

impl PluginAdmission for LoaderAdmission {
    fn is_tarball(&self, file: &str) -> bool {
        busbar_plugin_loader::tarball::is_plugin_tarball(file)
    }

    fn max_tarball_bytes(&self) -> u64 {
        busbar_plugin_loader::tarball::MAX_TARBALL_FILE_BYTES
    }

    fn restart_default(&self, kind: &str) -> bool {
        busbar_plugin_loader::sign::kind_restart_default(kind)
    }

    fn policy_resolves(&self, cfg: &PluginsCfg) -> Result<(), String> {
        trust_policy(cfg).map(|_| ())
    }

    fn inventory(
        &self,
        dir: &std::path::Path,
        cfg: &PluginsCfg,
    ) -> Result<Vec<Inventoried>, String> {
        let policy = trust_policy(cfg)?;
        Ok(busbar_plugin_loader::inventory_tarballs(dir, &policy)
            .into_iter()
            .map(|row| Inventoried {
                stated: row.manifest.as_ref().map(stated),
                file: row.file,
                signature: row.signature,
                status: row.status,
            })
            .collect())
    }

    fn admit_upload(
        &self,
        dir: &std::path::Path,
        file: &str,
        tarball: &[u8],
        cfg: &PluginsCfg,
    ) -> Result<Admitted, Refusal> {
        let policy = trust_policy(cfg).map_err(Refusal::Validation)?;
        let unpacked = unpack_checked(tarball, "")?;
        let manifest = &unpacked.manifest;
        let judged = match evaluate(&unpacked.lib_bytes, manifest, &policy) {
            Ok(Verdict::Trusted { publisher, .. }) => Judged::Trusted { publisher },
            Ok(Verdict::Allowed { .. }) => Judged::Allowed,
            Err(rejected) => {
                return Err(Refusal::Conflict(format!(
                    "plugin rejected by the trust policy: {}",
                    rejected.reason
                )));
            }
        };
        let installed =
            busbar_plugin_loader::scan_and_validate(dir, &policy).map_err(|errors| {
                Refusal::Conflict(format!(
                "cannot validate the installed plugin set before publishing (fix or remove the \
                 offending tarball first): {}",
                errors.join("; ")
            ))
            })?;
        for existing in installed.loadable() {
            if existing.file == file {
                continue;
            }
            if manifest
                .identities()
                .any(|word| existing.manifest.answers_to(word))
            {
                return Err(Refusal::Conflict(format!(
                    "plugin name/alias conflict: uploaded '{}' (alias '{}', file {}) collides with \
                     installed '{}' (alias '{}', file {}); a same-name upgrade must reuse the \
                     existing filename, not add a second file (boot would reject two files claiming \
                     the same plugin name)",
                    manifest.name,
                    manifest.alias,
                    file,
                    existing.manifest.name,
                    existing.manifest.alias,
                    existing.file
                )));
            }
        }
        let linked: Vec<_> = busbar_kernel::preflight::linked_rows()
            .iter()
            .map(linked_row)
            .collect();
        let linked_serves = PluginRegistry::empty()
            .link(linked)
            .and_then(|rows| rows.linked_copy(manifest, file))
            .map_err(Refusal::Conflict)?
            .is_some();
        Ok(Admitted {
            stated: stated(manifest),
            judged,
            linked_serves,
        })
    }

    fn inspect(&self, tarball: &[u8], cfg: &PluginsCfg) -> Result<(Stated, Judged), Refusal> {
        let policy = trust_policy(cfg).map_err(Refusal::Validation)?;
        let unpacked = unpack_checked(tarball, "")?;
        let judged = match evaluate(&unpacked.lib_bytes, &unpacked.manifest, &policy) {
            Ok(Verdict::Trusted { publisher, .. }) => Judged::Trusted { publisher },
            Ok(Verdict::Allowed { .. }) => Judged::Allowed,
            Err(rejected) => Judged::Rejected {
                reason: rejected.reason,
            },
        };
        Ok((stated(&unpacked.manifest), judged))
    }

    fn rollback_target(
        &self,
        file: &str,
        bytes: &[u8],
        cfg: &PluginsCfg,
    ) -> Result<Stated, Refusal> {
        let what = format!(" `{file}`");
        let unpacked = unpack_checked(bytes, &what)?;
        let manifest = &unpacked.manifest;
        let mut policy = trust_policy(cfg).map_err(Refusal::Validation)?;
        policy
            .min_versions
            .insert(manifest.name.clone(), manifest.version.clone());
        match evaluate(&unpacked.lib_bytes, manifest, &policy) {
            Ok(Verdict::Trusted { .. } | Verdict::Allowed { .. }) => Ok(stated(manifest)),
            Err(rejected) => Err(Refusal::Conflict(format!(
                "rollback target `{file}` is not loadable under the trust policy even with the \
                 floor lowered to its own version {}: {}. A rollback lowers the anti-downgrade \
                 floor for an explicit operator action; it cannot load an untrusted artifact.",
                manifest.version, rejected.reason
            ))),
        }
    }
}
