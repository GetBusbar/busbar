// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Linear input to the selected-resource governor. Selection and preparation minting remain
//! private to the money consumer; configuration metadata alone cannot authorize an attempt.

use std::sync::Arc;

use busbar_contract::MeterClassId;

use super::UnitMoney;
use crate::governance::AdmitGrant;
use crate::host_services::InvocationContext;
use crate::plane_driver::port_session::UpExchange;

/// One prepared exchange under an actual request admission.
///
/// The governor moves this value through reservation, commit and refusal. It never copies the
/// request admission or reconstructs the exchange from its descriptive fields. In particular,
/// a refusal returns this same value only after releasing its own provisional rate cells.
///
/// There is deliberately no public or crate-wide constructor: the native money consumer must
/// check the live invocation, original Open identity and selected member before minting it.
/// Until that producer is integrated this input cannot activate selected-attempt dispatch.
pub(crate) struct PreparedRateAttempt {
    money: Arc<UnitMoney>,
    instance: Box<str>,
    resource: Option<Box<str>>,
    physical_classes: Box<[MeterClassId]>,
    // Retain actual ownership, not copied identifiers. None of these fields contributes a
    // second fee participation or admission; the grant is the original Open's shared grant.
    _invocation: InvocationContext,
    _book: Arc<()>,
    _open_identity: Arc<()>,
    _grant: Arc<AdmitGrant>,
    _exchange: UpExchange,
}

impl PreparedRateAttempt {
    /// The authenticated request payer captured by the original monetary admission.
    pub(crate) fn key_id(&self) -> &str {
        &self.money.key.id
    }

    pub(crate) fn instance(&self) -> &str {
        &self.instance
    }

    /// Absent only when the selected-policy resolver produces no resource rule rows.
    pub(crate) fn resource(&self) -> Option<&str> {
        self.resource.as_deref()
    }

    /// The frozen, validated physical class set; aggregates must not overlap its classes.
    pub(crate) fn physical_classes(&self) -> &[MeterClassId] {
        &self.physical_classes
    }
}

impl std::fmt::Debug for PreparedRateAttempt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedRateAttempt")
            .finish_non_exhaustive()
    }
}
