// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Staged core-owned governance records; runtime attachment is a separate cutover. None of it
//! runs per request, so the code lives in `crate::off_path::governance::persistence`.
pub use crate::off_path::governance::persistence::{identity, ledger, prices, recovery};
