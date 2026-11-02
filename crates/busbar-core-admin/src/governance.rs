// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::refusal::{ReasonCode, Refusal, RefusalStep};
use crate::verb::KernelVerb;
use busbar_contract::caps::{AdminVerb, Grant};

/// A governance-layer error, mapped to a [`Refusal`] by [`GovernanceError::into_refusal`] rather
/// than exposed to the caller directly — the same fail-closed shape 1.5.5's admin handlers use
/// (`internal_error`/`join_error`): a store failure never echoes its cause past this boundary,
/// because several governance calls carry secrets.
#[derive(Debug)]
pub enum GovernanceError {
    /// The named resource does not exist.
    NotFound,
    /// The request conflicts with existing state.
    Conflict,
    /// The request failed validation.
    Validation,
    /// The underlying store failed; details are for the integrator's own logs only.
    Store,
}

impl GovernanceError {
    pub fn into_refusal(self) -> Refusal {
        let reason = match self {
            GovernanceError::NotFound => ReasonCode::NotFound,
            GovernanceError::Conflict => ReasonCode::Conflict,
            GovernanceError::Validation => ReasonCode::Validation,
            GovernanceError::Store => ReasonCode::StoreError,
        };
        Refusal::new(RefusalStep::Verify, reason)
    }
}

pub trait Governance {
    type Answer;

    fn execute_legacy(
        &self,
        verb: KernelVerb,
        admin: &Grant<AdminVerb>,
        request: &[u8],
    ) -> Result<Self::Answer, GovernanceError>;

    fn execute_new_verb(
        &self,
        verb: KernelVerb,
        admin: &Grant<AdminVerb>,
        request: &[u8],
    ) -> Result<Self::Answer, GovernanceError>;

    fn execute_ledger_read(
        &self,
        verb: KernelVerb,
        admin: &Grant<AdminVerb>,
        request: &[u8],
    ) -> Result<Self::Answer, GovernanceError> {
        let (_, _, _) = (verb, admin, request);
        Err(GovernanceError::NotFound)
    }

    fn execute_audit_read(
        &self,
        verb: KernelVerb,
        admin: &Grant<AdminVerb>,
        request: &[u8],
    ) -> Result<Self::Answer, GovernanceError> {
        let (_, _, _) = (verb, admin, request);
        Err(GovernanceError::NotFound)
    }
}
