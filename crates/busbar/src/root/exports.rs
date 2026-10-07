// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EXPORT AXIS, THE ROOT'S (WIRE-EXPORT; ARCHITECT ruling 2026-09-29, the opener seam: a kind's
//! `<Kind>Axis` is the contract's, implemented HERE over the ONE dispatcher and the registry, and
//! installed through the kernel's `RootInstall`). [`EXPORTS`] answers the contract's `ExportAxis`
//! over the registry boot scanned and linked (`linked::dropped_from_config`, kept by
//! `linked::register_exports`) and the process's one dispatcher (`root::dispatch`), through the
//! loader's export rows. It is installed with the root rows before the registry exists, so it reads
//! the registry on each question: before boot keeps one, and in a build with neither a plugins
//! directory nor a linked sink, no export module resolves.
//!
//! An instance OPENED to deliver logs to its own file under `plugins.logs` and declares its needs
//! on the process's one connector (`root::connector::the()`), so it is opened only once that
//! connector is built; a module only probed or checked while a configuration is judged binds with
//! neither.

use busbar_contract::export_calls::{ExportAxis, ExportCalls, Probed};
use std::sync::Arc;

use crate::root::loader::export_axis::ExportRows;

/// The root's export axis.
#[derive(Debug)]
pub struct RootExports;

/// The export axis the root rows carry (`busbar_kernel::preflight::RootInstall::export_axis`).
pub static EXPORTS: RootExports = RootExports;

/// The registry's export rows on the process's one dispatcher; `None` before boot keeps a registry.
fn rows() -> Option<ExportRows<'static>> {
    let registry = crate::root::linked::dropped()?;
    Some(ExportRows::new(
        registry,
        crate::root::dispatch::dispatcher(),
    ))
}

impl ExportAxis for RootExports {
    fn probe(&self, module: &str, instance: &str, settings: &serde_json::Value) -> Option<Probed> {
        rows()?.probe(module, instance, settings)
    }

    fn check(
        &self,
        module: &str,
        phase: u32,
        instances: &[(String, serde_json::Value)],
    ) -> Option<Vec<String>> {
        rows()?.check(module, phase, instances)
    }

    fn open(
        &self,
        module: &str,
        label: &str,
        settings: &serde_json::Value,
    ) -> Result<Arc<dyn ExportCalls>, String> {
        let rows =
            rows().ok_or_else(|| format!("no `kind: export` plugin answers to '{module}'"))?;
        let conns: Arc<dyn busbar_contract::conn::DeclaredConns> =
            crate::root::connector::the().clone();
        rows.with_logs(crate::root::linked::logs())
            .with_conns(conns)
            .open(module, label, settings)
    }

    fn linked(&self, module: &str) -> bool {
        rows().is_some_and(|r| r.linked(module))
    }

    fn first_party(&self, module: &str) -> bool {
        rows().is_some_and(|r| r.first_party(module))
    }

    fn one_instance(&self, module: &str) -> bool {
        rows().is_some_and(|r| r.one_instance(module))
    }

    fn linked_modules(&self) -> Vec<String> {
        rows().map(|r| r.linked_modules()).unwrap_or_default()
    }

    fn routes(&self, module: &str) -> Vec<busbar_contract::abi::mechanism::route::Route> {
        rows().map(|r| r.routes(module)).unwrap_or_default()
    }
}
