// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A TEST BINARY'S INSTALL RECORD. A test build has no composition root: it publishes the rows it
//! stands in ([`crate::preflight::publish_root_rows`]) — the stand-in below, or a root test
//! binary's own rows ([`super::install_test_root`]) — with what the binary hands in over them (the
//! root's hook names, its auth-axis opener, a rate holder and dater). Each hand-in republishes the
//! record; the first hand-in of each stands.

use crate::preflight::RootInstall;
use std::sync::{Mutex, OnceLock};

/// A test build has no root: its store double ([`crate::test_support::store_double`]) and ranking
/// double stand in for the root's entries, the in-crate secret double
/// ([`crate::test_support::secrets`]) as the secret axis, and the test axis for the exports.
pub const STAND_IN: RootInstall = RootInstall {
    stores: &[crate::test_support::store_double::STORE],
    registry_build: Some(crate::test_support::registry_stand_in),
    plugins_fetch: Some(crate::test_support::fetch_stand_in),
    hook_axis: Some(crate::test_support::hook_axis_stand_in),
    // A test build links no hook row of the root's: the operator surface lists none, unless the
    // root's own test binary hands its names in (`test_support::install_root_hook_names`).
    hook_names: &[],
    store_axis: Some(crate::test_support::store_axis_stand_in),
    secret_axis: Some(&crate::test_support::SecretsStandIn),
    secret_admit: None,
    // A test build has no root ledger: no holder hears an apply and no dater dates an accrual,
    // unless a test binary hands its own in (`test_support::rate_holders`).
    rate_apply: None,
    rate_epoch: None,
    export_axis: Some(&crate::test_support::export_axis::STAND_IN),
    admission: Some(&crate::test_support::AdmissionStandIn),
    durable: Some(&crate::test_support::DurableStandIn),
    plugin_logs: None,
    hook_answers: None,
    auth_chain_module: Some(crate::test_support::auth_chain_module_stand_in),
    dispatch_latched: None,
    // The in-process stand-in (no loader): the build's linked auth rows answered in process, a
    // dropped-in auth row refused at its open, the double for every outbound style.
    auth_axis: Some(crate::test_support::outbound_auth::stand_in),
    // The test auth modules the stand-in axis answers in process.
    in_process_auth: Some(crate::test_support::auth_modules::answers),
    // A test build has no root to project a configuration for its door planes.
    config_projection: None,
};

/// A root test binary's own rows ([`super::install_test_root`]), read in place of the stand-in.
static ROOT: OnceLock<RootInstall> = OnceLock::new();

/// The root's hook names a root test binary hands in ([`super::install_root_hook_names`]).
static HOOK_NAMES: OnceLock<&'static [&'static str]> = OnceLock::new();

/// Serialises the publishes, so the last publish always composes every hand-in.
static PUBLISH: Mutex<()> = Mutex::new(());

/// The record this test binary stands in: its own rows, else the stand-in, with each hand-in over
/// them.
#[must_use]
pub fn composed() -> RootInstall {
    let mut rows = ROOT.get().copied().unwrap_or(STAND_IN);
    if let Some(names) = HOOK_NAMES.get().copied() {
        rows.hook_names = names;
    }
    if let Some(open) = super::root_auth_axis() {
        rows.auth_axis = Some(open);
    }
    if let Some(holder) = super::rate_holders::apply() {
        rows.rate_apply = Some(holder);
    }
    if let Some(dater) = super::rate_holders::epoch() {
        rows.rate_epoch = Some(dater);
    }
    rows
}

/// Publish [`composed`] as the process's install record.
pub fn publish() {
    let _serial = PUBLISH.lock().unwrap_or_else(|e| e.into_inner());
    crate::preflight::publish_root_rows(composed());
}

/// Publish the record once, if nothing this binary handed in has yet: what a fixture entry point
/// calls before it reads the record.
pub fn ensure() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(publish);
}

/// Hand in a root test binary's own rows (the first stands) and republish.
pub(crate) fn install_root(rows: RootInstall) {
    let _ = ROOT.set(rows);
    publish();
}

/// Hand in the root's hook names (the first stands) and republish.
pub(crate) fn install_hook_names(names: &'static [&'static str]) {
    let _ = HOOK_NAMES.set(names);
    publish();
}
