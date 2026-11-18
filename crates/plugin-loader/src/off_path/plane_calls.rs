// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `dispatch::plane_calls`' configuration copy: the plane driver's configuration takes the
//! instance's refusal table once (its one caller: the root's `off_path::serve` plane build), never
//! per request.

use busbar_contract::abi::plane::RefusalStatus;

use crate::dispatch::plane_calls::PlaneInstance;

impl PlaneInstance {
    pub fn refusal_statuses(&self) -> Vec<RefusalStatus> {
        // The plane driver's config takes its own copy of the refusal table once.
        crate::cold::dispatch::runtime::refusal_table(self.plugin.refusal_statuses())
    }
}
