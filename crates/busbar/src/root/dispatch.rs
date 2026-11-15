// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::{Arc, OnceLock};

use crate::root::loader::dispatch::{DispatchConfig, Dispatcher};
use crate::root::serve::LateServices;

// The boot-time auth axis (its rows are opened and its styles bound off the request path).
pub(crate) use crate::root::off_path::dispatch::auth_axis;

static DISPATCHER: OnceLock<Arc<Dispatcher>> = OnceLock::new();

#[must_use]
pub fn config(workers: usize) -> DispatchConfig {
    DispatchConfig {
        workers: u32::try_from(workers).unwrap_or(u32::MAX).max(1),
        #[cfg(any(test, feature = "test-harness"))]
        budgets: harness_budgets(),
        ..DispatchConfig::default()
    }
}

/// The watch budgets of a test or test-harness build. The shipped budgets (1 s per call
/// crossing, quarantine on the first breach) are calibrated for an optimized binary. An
/// unoptimized fixture process doing a durable SQLite commit can exceed 1 s when the CI
/// confinement runs 16 such processes at once and their fsyncs and CPU contend. The breach
/// faults the commit (`Pending`) and quarantines the only Store for the rest of the process.
/// The watchdog still faults a wedged crossing; only the wall-clock allowance is wider.
#[cfg(any(test, feature = "test-harness"))]
#[must_use]
pub fn harness_budgets() -> crate::root::loader::dispatch::Budgets {
    let shipped = crate::root::loader::dispatch::Budgets::default();
    crate::root::loader::dispatch::Budgets {
        call: HARNESS_CROSSING_BUDGET.max(shipped.call),
        stream: HARNESS_CROSSING_BUDGET.max(shipped.stream),
        connection: HARNESS_CROSSING_BUDGET.max(shipped.connection),
        write_behind: HARNESS_CROSSING_BUDGET.max(shipped.write_behind),
        lifecycle: shipped.lifecycle,
    }
}

#[cfg(any(test, feature = "test-harness"))]
const HARNESS_CROSSING_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);

pub fn boot(workers: usize, services: &LateServices) -> Arc<Dispatcher> {
    Arc::clone(DISPATCHER.get_or_init(|| Arc::new(build(workers, services))))
}

#[must_use]
pub fn build(workers: usize, services: &LateServices) -> Dispatcher {
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
    boot(1, &LateServices::new())
}

#[cfg(test)]
#[path = "tests/dispatch.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/diagnostic_logging.rs"]
mod diagnostic_logging_tests;
