// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The boot's `migrate.admit` answer for a store's data step. The legacy door-migration caller
//! (settings, reference and credential migration through a dropped or linked door) had no live
//! caller and is deleted (LIFECYCLE-A-PLAN WP2): plugins self-migrate in their own open
//! (ABI-MIN3 r34 round 31), and the credential channel is replaced by the deferred style binding
//! (MIGRATE-ON-BOOT r41 §A4).

use busbar_contract::abi::mechanism::lifecycle::slot;

/// THE BOOT'S ANSWER TO `migrate.admit` (MIGRATE-ON-BOOT §3 step 2, §4): installed once by the
/// gateway's migration seam, which decides from core's own config (`auth.signing_key`). The
/// loader holds no decision of its own: with no answer installed, every call is refused.
static ADMIT: std::sync::OnceLock<fn(u64) -> Result<(), &'static str>> = std::sync::OnceLock::new();

/// Install the boot's `migrate.admit` answer. `false` when one is installed already (the first
/// stands).
pub fn install_admit(admit: fn(u64) -> Result<(), &'static str>) -> bool {
    ADMIT.set(admit).is_ok()
}

/// The refusal of a call made with no answer installed.
pub const NO_ADMIT: &str = "CONFIG: this host cannot seal recoverable credentials: no migration \
                            admission is installed; nothing was written";

/// The refusal of a call made by anything but a store instance inside its `open`.
pub const NOT_IN_OPEN: &str = "migrate.admit is valid only for a store instance inside its open, \
                               before its first write";

/// The verdict on one `migrate.admit` call: the calling instance `wake` must be a store (the
/// kind's ceiling, as every service) inside its `open`, where today's ABI runs the data step (or
/// its door `migrate`, where MIN-3 runs it). Then the boot's answer for `recoverable` rows.
pub(crate) fn admit_verdict(
    wake: Option<&super::ticket::InstanceWake>,
    operation: Option<u32>,
    recoverable: u64,
) -> Result<(), &'static str> {
    let policy = busbar_contract::abi::host::access::service(
        busbar_contract::abi::host::service::op::MIGRATE_ADMIT,
    );
    let inside = matches!(operation, Some(slot::OPEN | slot::MIGRATE));
    match wake {
        Some(wake) if inside && super::access::admit(wake, policy, operation).is_ok() => ADMIT
            .get()
            .map_or(Err(NO_ADMIT), |admit| admit(recoverable)),
        _ => Err(NOT_IN_OPEN),
    }
}
