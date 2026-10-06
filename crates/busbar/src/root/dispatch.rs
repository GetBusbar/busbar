// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PROCESS'S ONE DISPATCHER (BUSBAR-1.6.0.md THE DESIGN, §11.2: one entry point per plugin,
//! one loading path, one dispatcher). The composition root builds it at boot, one plugin worker per
//! data worker, and every kind's wiring reaches its plugins through it: the root opens each kind's
//! instances on it and hands the kernel contract-level per-kind handles (`busbar_contract::*_calls`),
//! so the kernel never names the loader or this dispatcher.
//!
//! Built once; the first build stands. A build that never booted (a test binary) gets the default
//! shape on first use.

use std::sync::{Arc, OnceLock};

use busbar_contract::services::HostServices;

use crate::root::loader::dispatch::{DispatchConfig, Dispatcher};

static DISPATCHER: OnceLock<Arc<Dispatcher>> = OnceLock::new();

/// The dispatcher's shape for `workers` data workers: one plugin worker each, the default watchdog
/// budgets. Host services are bound when the kernel serves them (BUSBAR-1.6.0.md THE DESIGN, §11.5,
/// `abi/host/`).
#[must_use]
pub fn config(workers: usize) -> DispatchConfig {
    DispatchConfig {
        workers: u32::try_from(workers).unwrap_or(u32::MAX).max(1),
        ..DispatchConfig::default()
    }
}

/// Build the process's dispatcher for `workers` data workers, at boot, before any plugin loads,
/// serving `services` (the composition's [`crate::root::serve::LateServices`], installed once the
/// configuration loads). The first build stands; a later call answers it.
pub fn boot(workers: usize, services: Arc<dyn HostServices>) -> Arc<Dispatcher> {
    Arc::clone(DISPATCHER.get_or_init(|| Arc::new(build(workers, services))))
}

/// The dispatcher [`boot`] builds, for `workers` data workers, serving `services`.
#[must_use]
pub fn build(workers: usize, services: Arc<dyn HostServices>) -> Dispatcher {
    Dispatcher::with_services(config(workers), services)
}

/// The process's dispatcher (built at boot; built with one worker and no installed services on
/// first use where no boot ran).
#[must_use]
pub fn dispatcher() -> Arc<Dispatcher> {
    boot(1, crate::root::serve::LateServices::new())
}

/// THE AUTH AXIS of one build: that build's registry's auth rows, opened on the process's dispatcher
/// (ARCHITECT ruling 2026-09-30, AUTH-DOOR Q1). Installed on the kernel as its auth-axis opener
/// (`busbar_kernel::preflight::install_auth_axis`), so the kernel opens every auth instance through
/// the contract's `AuthAxis` and names neither the loader's rows nor this dispatcher.
///
/// Its outbound half ([`busbar_contract::auth_calls::AuthAxis::serving`]) is the process's one set
/// of outbound auth instances ([`crate::root::door_steps::process_auths`]): an outbound style is
/// served by the same opened instance whichever build binds it, its tick schedule running once.
pub fn auth_axis(
    registry: Arc<crate::root::loader::PluginRegistry>,
) -> Arc<dyn busbar_contract::auth_calls::AuthAxis> {
    Arc::new(RootAuthAxis(crate::root::loader::auth_axis::AuthRows::new(
        registry,
        dispatcher(),
    )))
}

/// One build's auth rows, with the process's outbound auth instances as its outbound half.
struct RootAuthAxis(crate::root::loader::auth_axis::AuthRows);

impl busbar_contract::auth_calls::AuthAxis for RootAuthAxis {
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
    ) -> Result<Arc<dyn busbar_contract::auth_calls::AuthCalls>, String> {
        self.0.open(module, label, settings)
    }

    fn credential_readers(&self) -> Vec<String> {
        self.0.credential_readers()
    }

    fn check_outbound(
        &self,
        style: &str,
        credential: &[u8],
        settings: &serde_json::Value,
    ) -> Result<Vec<String>, String> {
        crate::root::door_steps::process_auths().check(style, credential, settings)
    }

    fn serving(
        &self,
        style: &str,
        settings: &serde_json::Value,
    ) -> Result<Option<busbar_contract::auth_calls::OutboundServing>, String> {
        Ok(crate::root::door_steps::process_auths()
            .serving(style, settings)?
            .map(
                |(auth, decl)| busbar_contract::auth_calls::OutboundServing {
                    auth,
                    flags: decl.flags,
                    points: decl.points,
                },
            ))
    }
}

#[cfg(test)]
#[path = "tests/dispatch.rs"]
mod tests;

// The suite binds each dialect's declared scheme on the LINKED auth plugins serving its style: the
// static schemes on `busbar-auth-header`, the signing scheme on `busbar-auth-sigv4` (the default
// distribution links both). A build without either links no plugin serving that style, so the bind
// is refused there, exactly as `door_steps`' positive binding proof is gated on `auth-header`.
#[cfg(all(test, feature = "auth-header", feature = "auth-sigv4"))]
#[path = "tests/declared_credentials.rs"]
mod declared_credentials_tests;
