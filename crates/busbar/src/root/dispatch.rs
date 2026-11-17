// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::{Arc, OnceLock};

use crate::root::loader::dispatch::{DispatchConfig, Dispatcher};
use crate::root::serve::Services;

// The boot-time auth axis (its rows are opened and its styles bound off the request path).
pub(crate) use crate::root::off_path::dispatch::auth_axis;

static DISPATCHER: OnceLock<Arc<Dispatcher>> = OnceLock::new();

#[must_use]
pub fn config(workers: usize) -> DispatchConfig {
    DispatchConfig {
        workers: u32::try_from(workers).unwrap_or(u32::MAX).max(1),
        ..DispatchConfig::default()
    }
}

pub fn boot(workers: usize, services: &Services) -> Arc<Dispatcher> {
    Arc::clone(DISPATCHER.get_or_init(|| Arc::new(build(workers, services))))
}

#[must_use]
pub fn build(workers: usize, services: &Services) -> Dispatcher {
    let dispatcher = Dispatcher::with_slot(
        config(workers),
        services.slot(),
        busbar_kernel::host_services::caller_binding(),
    );
    let _ = dispatcher.lend_seal(busbar_kernel::seal::lend());
    assert!(
        dispatcher
            .set_measurement_authority(super::measurements::authority())
            .is_ok(),
        "new dispatcher must accept the root measurement authority"
    );
    dispatcher
}

#[must_use]
pub fn dispatcher() -> Arc<Dispatcher> {
    boot(1, &Services::bootstrap())
}

#[cfg(test)]
#[path = "tests/dispatch.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/diagnostic_logging.rs"]
mod diagnostic_logging_tests;
