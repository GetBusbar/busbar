// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Current-format import preparation over the persistence facade.

pub mod candidate_codec;
pub mod r0;
pub mod records;
pub mod target;

pub use target::{ActivationChange, ActivationRequest, TargetIdentity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportError {
    Bounds,
    Corrupt,
    UnsupportedFormat,
    Identity,
    Authority,
    Conflict,
    ReconciliationRequired,
    Backend(busbar_contract::persistence::Failure),
}
