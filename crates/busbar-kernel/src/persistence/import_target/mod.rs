// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Current-format import preparation. Historical profiles and upgrade routing
//! live in busbar-migrations, which depends on this facade; kernel never imports it.

pub mod candidate_codec;
pub mod journal;
pub mod records;
pub mod recovery;
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
