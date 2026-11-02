// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::rate_apply::{RateApply, RateEpoch};

static APPLY_HANDED_IN: std::sync::OnceLock<&'static dyn RateApply> = std::sync::OnceLock::new();

static EPOCH_HANDED_IN: std::sync::OnceLock<&'static dyn RateEpoch> = std::sync::OnceLock::new();

pub fn install_rate_apply(holder: &'static dyn RateApply) {
    let _ = APPLY_HANDED_IN.set(holder);
    super::root::publish();
}

pub fn install_rate_epoch(holder: &'static dyn RateEpoch) {
    let _ = EPOCH_HANDED_IN.set(holder);
    super::root::publish();
}

pub(crate) fn apply() -> Option<&'static dyn RateApply> {
    APPLY_HANDED_IN.get().copied()
}

pub(crate) fn epoch() -> Option<&'static dyn RateEpoch> {
    EPOCH_HANDED_IN.get().copied()
}
