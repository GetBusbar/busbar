// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RATE HOLDER AND DATER A TEST BINARY HANDS IN, in place of the composition root's.
//!
//! A shipped build's holder and dater ride the root's install record
//! ([`crate::preflight::RootInstall::rate_apply`] and [`crate::preflight::RootInstall::rate_epoch`]);
//! a test build's record is the stand-in, which carries neither. A test binary that has to hear a
//! rate apply, or date an accrual, hands its own in here, and the record this binary publishes
//! ([`super::root`]) carries it. The first hand-in stands, as the root's one install does.

use crate::rate_apply::{RateApply, RateEpoch};

/// The holder a test binary handed in ([`install_rate_apply`]).
static APPLY_HANDED_IN: std::sync::OnceLock<&'static dyn RateApply> = std::sync::OnceLock::new();

/// The dater a test binary handed in ([`install_rate_epoch`]).
static EPOCH_HANDED_IN: std::sync::OnceLock<&'static dyn RateEpoch> = std::sync::OnceLock::new();

/// THE TEST BINARY'S RATE HOLDER: every rate resolution of this process is staged with and raised
/// to `holder`, as a shipped root's install record has them raised to its own. The first hand-in
/// stands.
pub fn install_rate_apply(holder: &'static dyn RateApply) {
    let _ = APPLY_HANDED_IN.set(holder);
    super::root::publish();
}

/// THE TEST BINARY'S RATE DATER: every accrual of this process is dated by `holder`, and the
/// ledger reads price through its history, as a shipped root's install record has them dated by its
/// own. The first hand-in stands.
pub fn install_rate_epoch(holder: &'static dyn RateEpoch) {
    let _ = EPOCH_HANDED_IN.set(holder);
    super::root::publish();
}

/// The holder a test binary handed in, if one did.
pub(crate) fn apply() -> Option<&'static dyn RateApply> {
    APPLY_HANDED_IN.get().copied()
}

/// The dater a test binary handed in, if one did.
pub(crate) fn epoch() -> Option<&'static dyn RateEpoch> {
    EPOCH_HANDED_IN.get().copied()
}
