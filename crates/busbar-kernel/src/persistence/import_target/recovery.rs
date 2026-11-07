// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Current recovery ancestry and adoption verification over verified originals.
//! This read-only capability grants neither a writer nor business replay rights.

pub use super::journal::{RecoveryHistory, inspect_recovery_operation};
pub use crate::governance::recovery::{RecoveryError, RecoverySelection};

pub use crate::governance::persistence::recovery::imported::{
    AppliedImportEvidence, applied_disposition_authorizes, applied_disposition_rows,
};
