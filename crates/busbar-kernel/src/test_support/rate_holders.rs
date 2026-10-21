// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RATE HOLDER AND DATER A TEST BINARY HANDS IN, in place of the composition root's.
//!
//! A shipped build's holder and dater ride the root's install record
//! ([`crate::preflight::RootInstall::rate_apply`] and [`crate::preflight::RootInstall::rate_epoch`]);
//! a test build's record is the stand-in, which carries neither. A test binary that has to hear a
//! rate apply, or date an accrual, hands its own in here, and the kernel's rate seam
//! ([`crate::rate_apply`]) reads it in front of the record's. The first hand-in stands, as the
//! root's one install does.
//!
//! Each hand-in slot carries the test gate on its own declaration as well as through the module's:
//! the binary-closure scans read a declaration's lines, not the module gate, and a slot no shipped
//! build has must read as one.

use crate::rate_apply::{RateApply, RateEpoch};

/// The holder a test binary handed in ([`install_rate_apply`]).
#[cfg(any(test, feature = "test-support"))]
static APPLY_HANDED_IN: std::sync::OnceLock<&'static dyn RateApply> = std::sync::OnceLock::new();

/// The dater a test binary handed in ([`install_rate_epoch`]).
#[cfg(any(test, feature = "test-support"))]
static EPOCH_HANDED_IN: std::sync::OnceLock<&'static dyn RateEpoch> = std::sync::OnceLock::new();

/// THE TEST BINARY'S RATE HOLDER: every rate resolution of this process is staged with and raised
/// to `holder`, as a shipped root's install record has them raised to its own. The first hand-in
/// stands.
pub fn install_rate_apply(holder: &'static dyn RateApply) {
    let _ = APPLY_HANDED_IN.set(holder);
}

/// THE TEST BINARY'S RATE DATER: every accrual of this process is dated by `holder`, and the
/// ledger reads price through its history, as a shipped root's install record has them dated by its
/// own. The first hand-in stands.
pub fn install_rate_epoch(holder: &'static dyn RateEpoch) {
    let _ = EPOCH_HANDED_IN.set(holder);
}

/// The holder a test binary handed in, if one did.
pub(crate) fn apply() -> Option<&'static dyn RateApply> {
    APPLY_HANDED_IN.get().copied()
}

/// The dater a test binary handed in, if one did.
pub(crate) fn epoch() -> Option<&'static dyn RateEpoch> {
    EPOCH_HANDED_IN.get().copied()
}
