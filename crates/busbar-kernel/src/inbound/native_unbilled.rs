// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The "verified, not billed" authority of a plane route (inbound admission C4): the right to
//! answer a request on a route whose record says money none. Two producers and no other: the
//! route's real authorization (its chain verified the caller and key policy passed), and a route
//! whose record admits nobody in particular (public). No unit is opened, no limit is counted, and
//! the answer is recorded.
//!
//! A refusal decided after verification on such a route (the key may not see what it named, the
//! route keeps state per caller and the caller is shared) is answered under the same authority:
//! it is an answer to a verified caller that moved no money.

use std::sync::{Arc, PoisonError};
use std::time::Instant;

use busbar_plugin_abi::plane::{AUTH_OPTIONAL, AUTH_PUBLIC};

use super::refusal::PreparationState;
use super::{
    ArrivalRefusal, BindError, CompletingPhysicalRequest, Phase, RequestBinding, RouteTarget,
};
use crate::auth::native_data::DataAuthorization;
use crate::state::AdmissionLease;

/// What admitted the request.
enum UnbilledProof {
    /// The route's chain verified the caller and its key policy passed. The authorization keeps
    /// its own lease on the serving generation.
    Verified { _authorization: DataAuthorization },
    /// The route's record admits a caller that presents nothing.
    Unverified { _lease: AdmissionLease },
}

/// One plane request admitted with no unit. Dropping it cancels the request.
pub struct PhysicalUnbilledExecution {
    binding: Arc<RequestBinding>,
    proof: UnbilledProof,
}

impl PhysicalUnbilledExecution {
    pub fn binding(&self) -> &Arc<RequestBinding> {
        &self.binding
    }

    /// The caller was verified (a principal's identity is given to the plane).
    pub fn verified(&self) -> bool {
        matches!(self.proof, UnbilledProof::Verified { .. })
    }

    /// The authorization of a verified request: its identity and its key.
    pub fn authorization(&self) -> Option<&DataAuthorization> {
        match &self.proof {
            UnbilledProof::Verified { _authorization } => Some(_authorization),
            UnbilledProof::Unverified { .. } => None,
        }
    }

    pub fn check_executing(&self) -> Result<(), ArrivalRefusal> {
        self.binding.check_executing()
    }
}

impl Drop for PhysicalUnbilledExecution {
    fn drop(&mut self) {
        self.binding.state.cancel();
    }
}

impl CompletingPhysicalRequest {
    fn enter_unbilled(&self, preparation: PreparationState) -> Result<(), ArrivalRefusal> {
        let mut phase = self
            .binding
            .state
            .phase
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if *phase != Phase::Completing {
            return Err(ArrivalRefusal::Cancelled);
        }
        if *self
            .binding
            .state
            .preparation
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            != preparation
        {
            return Err(ArrivalRefusal::Cancelled);
        }
        if self.binding.deadline.is_some_and(|at| Instant::now() >= at) {
            return Err(ArrivalRefusal::Deadline);
        }
        *phase = Phase::Executing {
            deadline: self.binding.deadline,
        };
        Ok(())
    }

    /// Join the route's real authorization to this exact physical arrival, with no unit. Only a
    /// route whose record says money none is completed here: a route that moves money is completed
    /// by [`CompletingPhysicalRequest::complete`] and can be answered only after money.
    pub fn complete_unbilled(
        mut self,
        authorization: DataAuthorization,
    ) -> Result<PhysicalUnbilledExecution, ArrivalRefusal> {
        if !Arc::ptr_eq(&self.binding, authorization.binding())
            || !Arc::ptr_eq(&self.binding, authorization.preparation().binding())
            || !Arc::ptr_eq(self.binding.route(), authorization.route().binding())
        {
            return Err(ArrivalRefusal::ForeignInput);
        }
        if authorization.route().billed() {
            return Err(ArrivalRefusal::Class);
        }
        self.enter_unbilled(PreparationState::Authorized)?;
        self.cancel_on_drop = false;
        Ok(PhysicalUnbilledExecution {
            binding: self.binding.clone(),
            proof: UnbilledProof::Verified {
                _authorization: authorization,
            },
        })
    }

    /// Answer a refusal decided after this route's authorization on a route that moves money,
    /// before any unit exists (the key is disabled, the caller is shared on a route that keeps
    /// state per caller). The authorization is consumed: nothing can be served from it.
    pub fn refuse_authorized(
        mut self,
        authorization: DataAuthorization,
    ) -> Result<PhysicalUnbilledExecution, ArrivalRefusal> {
        if !Arc::ptr_eq(&self.binding, authorization.binding())
            || !Arc::ptr_eq(&self.binding, authorization.preparation().binding())
        {
            return Err(ArrivalRefusal::ForeignInput);
        }
        self.enter_unbilled(PreparationState::Authorized)?;
        self.cancel_on_drop = false;
        Ok(PhysicalUnbilledExecution {
            binding: self.binding.clone(),
            proof: UnbilledProof::Verified {
                _authorization: authorization,
            },
        })
    }

    /// Complete a plane route whose record admits a caller that presents nothing: a public route,
    /// or an optional route on a request with no credential. The route's own declared auth mask is
    /// the proof; no other route can enter here.
    pub fn complete_unverified(mut self) -> Result<PhysicalUnbilledExecution, ArrivalRefusal> {
        let RouteTarget::Plane(target) = self.binding.route.target() else {
            return Err(ArrivalRefusal::Class);
        };
        let auth = target.mounted().auth;
        if auth != AUTH_PUBLIC && auth != AUTH_OPTIONAL {
            return Err(ArrivalRefusal::Class);
        }
        self.binding.check_live()?;
        let lease = self
            .binding
            .handle
            .admit_current(self.binding.app(), self.binding.invocation(), |_| {
                Ok::<(), std::convert::Infallible>(())
            })
            .map_err(|_| ArrivalRefusal::Binding(BindError::Generation))?;
        self.enter_unbilled(PreparationState::Unused)?;
        self.cancel_on_drop = false;
        Ok(PhysicalUnbilledExecution {
            binding: self.binding.clone(),
            proof: UnbilledProof::Unverified { _lease: lease },
        })
    }
}
