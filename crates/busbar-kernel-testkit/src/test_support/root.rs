// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::preflight::RootInstall;
use std::sync::{Mutex, OnceLock};

pub const STAND_IN: RootInstall = RootInstall {
    stores: &[crate::test_support::store_double::STORE],
    registry_build: Some(crate::test_support::registry_stand_in),
    plugins_fetch: Some(crate::test_support::fetch_stand_in),
    hook_axis: Some(crate::test_support::hook_axis_stand_in),

    hook_names: &[],
    store_axis: Some(crate::test_support::store_axis_stand_in),
    secret_axis: Some(&crate::test_support::SecretsStandIn),
    secret_admit: None,

    rate_apply: None,
    rate_epoch: None,
    export_axis: Some(&crate::test_support::export_axis::STAND_IN),
    admission: Some(&crate::test_support::AdmissionStandIn),
    durable: Some(&crate::test_support::DurableStandIn),
    plugin_logs: None,
    hook_answers: None,
    auth_chain_module: Some(crate::test_support::auth_chain_module_stand_in),
    dispatch_latched: None,

    auth_axis: Some(crate::test_support::outbound_auth::stand_in),

    in_process_auth: Some(crate::test_support::auth_modules::answers),

    config_projection: None,
};

static ROOT: OnceLock<RootInstall> = OnceLock::new();

static HOOK_NAMES: OnceLock<&'static [&'static str]> = OnceLock::new();

static PUBLISH: Mutex<()> = Mutex::new(());

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

pub fn publish() {
    let _serial = PUBLISH.lock().unwrap_or_else(|e| e.into_inner());
    crate::preflight::publish_root_rows(composed());
}

pub fn ensure() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        super::migration::install();

        busbar_kernel_identity::operator::install_test_words(super::operator_double::words());
        publish();
    });
}

pub(crate) fn install_root(rows: RootInstall) {
    let _ = ROOT.set(rows);
    publish();
}

pub(crate) fn install_hook_names(names: &'static [&'static str]) {
    let _ = HOOK_NAMES.set(names);
    publish();
}
