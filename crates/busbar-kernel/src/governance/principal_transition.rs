// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Cold, explicit principal continuity. No identity inference, aliases, or historical rewrites.
//!
//! The facility runs only at boot or from the offline quiescent CLI, never per request, so its
//! code lives in `crate::off_path::governance::principal_transition`; this module re-exports its
//! public surface under the established path.

pub use crate::off_path::governance::principal_transition::*;
