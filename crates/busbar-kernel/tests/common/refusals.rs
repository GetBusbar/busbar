// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::caps::{ReasonCode, StepName};

use super::units::TestUnits;

impl TestUnits {
    pub fn refusing(step: StepName, reason: ReasonCode) -> Self {
        TestUnits {
            refuse_at: Some((step, reason)),
            ..TestUnits::default()
        }
    }

    pub fn called(&self) -> Vec<StepName> {
        self.calls.lock().unwrap().clone()
    }
}
