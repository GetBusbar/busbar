// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Current-policy reservation uses the same short boundary as application publication.

use std::sync::Arc;

use crate::governance::selected_policy::SelectedPolicyRefusal;
use crate::governance::selected_resource::{RateRejected, RateReservation};
use crate::plane_driver::PreparedRateAttempt;

use super::AppHandle;

/// Root lends the actual application's publication owner to an original request.
/// Neither an App snapshot nor a caller-supplied rule vector constructs this facade.
#[derive(Clone)]
pub struct SelectedRateAdmission {
    handle: Arc<AppHandle>,
}

/// Every refusal retains the same prepared exchange; no replacement token is minted.
#[derive(Debug)]
pub(crate) enum SelectedRateRejected {
    Policy {
        reason: SelectedPolicyRefusal,
        prepared: PreparedRateAttempt,
    },
    Rate(RateRejected),
}

impl AppHandle {
    pub fn selected_rate_admission(self: &Arc<Self>) -> SelectedRateAdmission {
        SelectedRateAdmission {
            handle: Arc::clone(self),
        }
    }
}

impl SelectedRateAdmission {
    pub(crate) fn reserve(
        &self,
        prepared: PreparedRateAttempt,
    ) -> Result<RateReservation, SelectedRateRejected> {
        let now = crate::store::now();
        // Scheduling is coalesced by the actual credential owner and happens outside the gate.
        // A publication during this step is judged against its own cached state below.
        if let Some(governance) = &self.handle.load().governance {
            governance.refresh_current_credential(now);
        }
        let _admission = self
            .handle
            .admission
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let current = self.handle.current.load_full();
        let Some(policy) = &current.selected_policy else {
            return Err(SelectedRateRejected::Policy {
                reason: SelectedPolicyRefusal::CurrentAuthority,
                prepared,
            });
        };
        let resolved = match policy.resolve_current(&current, &prepared, now) {
            Ok(resolved) => resolved,
            Err(reason) => return Err(SelectedRateRejected::Policy { reason, prepared }),
        };
        let Some(governance) = &current.governance else {
            return Err(SelectedRateRejected::Policy {
                reason: SelectedPolicyRefusal::CurrentAuthority,
                prepared,
            });
        };
        governance
            .selected_rates()
            .reserve(&resolved, prepared)
            .map_err(SelectedRateRejected::Rate)
    }
}
