// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Consumed physical refusal custody; cancellation is never reversed.

use super::*;
use crate::auth::native_data::PreparedDataDenial;
use crate::auth::native_upgrade::{UpgradeAuthorization, UpgradeRefused};
use crate::plane_driver::port::NativeTaskRetirement;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum PreparationState {
    Unused,
    Running,
    Authorized,
    Denied,
}

/// One preparation attempt, taken before verification. Abandonment cancels the original.
pub struct DataPreparation {
    binding: Arc<RequestBinding>,
    armed: bool,
}
pub struct DataPreparationSuccess {
    binding: Arc<RequestBinding>,
}
pub struct DataPreparationDenied {
    binding: Arc<RequestBinding>,
}
impl DataPreparationSuccess {
    pub(crate) fn binding(&self) -> &Arc<RequestBinding> {
        &self.binding
    }
}
impl DataPreparationDenied {
    pub(crate) fn binding(&self) -> &Arc<RequestBinding> {
        &self.binding
    }
}
impl DataPreparation {
    pub fn binding(&self) -> &Arc<RequestBinding> {
        &self.binding
    }
    fn finish(&mut self, target: PreparationState) -> Result<(), ArrivalRefusal> {
        let phase = self
            .binding
            .state
            .phase
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if *phase != Phase::Completing {
            return Err(ArrivalRefusal::Cancelled);
        }
        if self.binding.deadline.is_some_and(|at| Instant::now() >= at) {
            return Err(ArrivalRefusal::Deadline);
        }
        let mut preparation = self
            .binding
            .state
            .preparation
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if *preparation != PreparationState::Running {
            return Err(ArrivalRefusal::Cancelled);
        }
        *preparation = target;
        self.armed = false;
        Ok(())
    }
    pub(crate) fn authorize(mut self) -> Result<DataPreparationSuccess, ArrivalRefusal> {
        self.finish(PreparationState::Authorized)?;
        Ok(DataPreparationSuccess {
            binding: self.binding.clone(),
        })
    }
    pub(crate) fn deny(mut self) -> Result<DataPreparationDenied, ArrivalRefusal> {
        self.finish(PreparationState::Denied)?;
        Ok(DataPreparationDenied {
            binding: self.binding.clone(),
        })
    }
}
impl Drop for DataPreparation {
    fn drop(&mut self) {
        if self.armed {
            self.binding.state.cancel();
        }
    }
}

/// The original pending owner and a terminal classified decision jointly grant one output.
pub struct PhysicalRefusal {
    binding: Arc<RequestBinding>,
    // Keep the actual decision and its producer custody, not a reconstructed status.
    _provenance: RefusalProvenance,
}
enum RefusalProvenance {
    Admin {
        _outcome: busbar_contract::caps::Outcome,
    },
    Data {
        _denied: PreparedDataDenial,
    },
    Allocated {
        _owner: PhysicalExecutionOwner,
        _witness: NativeTaskRetirement,
    },
    /// Core's answer before any 101 on an authorized upgrade request (§12.27 steps 1-2).
    Upgrade {
        _authorization: UpgradeAuthorization,
    },
    /// The route's chain denied an upgrade request (credential, policy or replay).
    UpgradeDenied {
        _denied: DataPreparationDenied,
    },
    /// No route of this listener matched the head: answered as an unauthenticated request is, so
    /// the answer does not tell a caller whether a route exists.
    Unrouted,
    /// Durability is unavailable (design 2, A8): refused before any preparation.
    Unavailable,
}
impl PhysicalRefusal {
    pub fn binding(&self) -> &Arc<RequestBinding> {
        &self.binding
    }

    /// Where and why a refusal that names no unit was decided, for the core's per-interval count
    /// (design 2, A5). `None` for a refusal recorded otherwise: an admin refusal (its admin unit
    /// records or counts it) and one that already holds a unit (its unit's own line records it).
    #[must_use]
    pub fn counted(
        &self,
    ) -> Option<(
        busbar_contract::caps::StepName,
        busbar_contract::caps::ReasonCode,
    )> {
        use crate::auth::native_data::DataRefused;
        use busbar_contract::caps::{ReasonCode, StepName};
        match &self._provenance {
            RefusalProvenance::Data { _denied } => Some(match _denied.decision() {
                DataRefused::Credential => (StepName::Authenticate, ReasonCode::Unauthenticated),
                DataRefused::Policy => (StepName::Approve, ReasonCode::ScopeDenied),
                DataRefused::Replay => (StepName::Authenticate, ReasonCode::Replayed),
                DataRefused::Capacity => (StepName::Arrival, ReasonCode::InFlightCap),
                DataRefused::Unavailable => (StepName::Arrival, ReasonCode::DurabilityUnavailable),
                DataRefused::Unsupported
                | DataRefused::Binding
                | DataRefused::Cancelled
                | DataRefused::Unit => (StepName::Decode, ReasonCode::DecodeFailed),
            }),
            RefusalProvenance::Upgrade { .. } => {
                Some((StepName::Decode, ReasonCode::MethodNotAllowed))
            }
            RefusalProvenance::Unavailable => {
                Some((StepName::Arrival, ReasonCode::DurabilityUnavailable))
            }
            RefusalProvenance::Admin { .. } | RefusalProvenance::Allocated { .. } => None,
        }
    }
    pub fn unit(&self) -> Option<busbar_contract::UnitKey> {
        match &self._provenance {
            RefusalProvenance::Allocated { _witness, .. } => Some(_witness.unit()),
            RefusalProvenance::Admin { .. }
            | RefusalProvenance::Data { .. }
            | RefusalProvenance::Upgrade { .. }
            | RefusalProvenance::UpgradeDenied { .. }
            | RefusalProvenance::Unrouted => None,
        }
    }
}
impl Drop for PhysicalRefusal {
    fn drop(&mut self) {
        self.binding.state.cancel();
    }
}

impl CompletingPhysicalRequest {
    pub fn begin_data_preparation(&mut self) -> Result<DataPreparation, ArrivalRefusal> {
        if !matches!(self.binding.route.target(), RouteTarget::Plane(_)) {
            return Err(ArrivalRefusal::Class);
        }
        let phase = self
            .binding
            .state
            .phase
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if *phase != Phase::Completing {
            return Err(ArrivalRefusal::Cancelled);
        }
        if self.binding.deadline.is_some_and(|at| Instant::now() >= at) {
            return Err(ArrivalRefusal::Deadline);
        }
        let mut preparation = self
            .binding
            .state
            .preparation
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if *preparation != PreparationState::Unused {
            return Err(ArrivalRefusal::Cancelled);
        }
        *preparation = PreparationState::Running;
        Ok(DataPreparation {
            binding: self.binding.clone(),
            armed: true,
        })
    }

    pub fn refuse_data(
        mut self,
        denied: PreparedDataDenial,
    ) -> Result<PhysicalRefusal, ArrivalRefusal> {
        if !Arc::ptr_eq(&self.binding, denied.binding())
            || !Arc::ptr_eq(&self.binding, denied.preparation().binding())
        {
            return Err(ArrivalRefusal::ForeignInput);
        }
        self.enter_refusal(Some(PreparationState::Denied))?;
        self.cancel_on_drop = false;
        Ok(PhysicalRefusal {
            binding: self.binding.clone(),
            _provenance: RefusalProvenance::Data { _denied: denied },
        })
    }

    /// Root calls only after its admin unit decided the refusal and recorded it: a line handed to
    /// the core's outbox, or one count of a request with no identity (design 2, A5). `unit` and
    /// `outcome` are that admin unit's own.
    pub fn refuse_admin(
        mut self,
        unit: busbar_contract::UnitKey,
        outcome: busbar_contract::caps::Outcome,
    ) -> Result<PhysicalRefusal, ArrivalRefusal> {
        self.check_admin_route()?;
        if unit.get() != self.binding.invocation().request_id().get()
            || !matches!(outcome, busbar_contract::caps::Outcome::Refused(..))
        {
            return Err(ArrivalRefusal::ForeignInput);
        }
        self.enter_refusal(Some(PreparationState::Unused))?;
        self.cancel_on_drop = false;
        Ok(PhysicalRefusal {
            binding: self.binding.clone(),
            _provenance: RefusalProvenance::Admin { _outcome: outcome },
        })
    }

    /// Durability is unavailable (design 2, A8): refuse a request that would create a record
    /// before any preparation, so it is answered with the catalogue's refusal, never closed.
    pub fn refuse_unavailable(mut self) -> Result<PhysicalRefusal, ArrivalRefusal> {
        self.enter_refusal(Some(PreparationState::Unused))?;
        self.cancel_on_drop = false;
        Ok(PhysicalRefusal {
            binding: self.binding.clone(),
            _provenance: RefusalProvenance::Unavailable,
        })
    }

    /// Core's answer before any 101 on this exact upgrade request (a 400 for a request that does not
    /// ask to switch to websocket, a 501 when no admitted instance can carry it). Only an
    /// authorization of this same request can produce it: no upgrade refusal is written before the
    /// route's auth chain, key policy and replay claim passed.
    pub fn refuse_upgrade(
        mut self,
        authorization: UpgradeAuthorization,
    ) -> Result<PhysicalRefusal, ArrivalRefusal> {
        self.check_upgrade(&authorization)?;
        self.enter_refusal(Some(PreparationState::Authorized))?;
        self.cancel_on_drop = false;
        Ok(PhysicalRefusal {
            binding: self.binding.clone(),
            _provenance: RefusalProvenance::Upgrade {
                _authorization: authorization,
            },
        })
    }

    /// The hand-over of this exact authorized upgrade request (§12.27 steps 2-5): consumed once,
    /// Completing becomes Executing. The owner is what the upgrade carrier is handed; dropping it
    /// cancels the request.
    pub fn complete_upgrade(
        mut self,
        authorization: UpgradeAuthorization,
    ) -> Result<PhysicalUpgrade, ArrivalRefusal> {
        self.check_upgrade(&authorization)?;
        {
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
                != PreparationState::Authorized
            {
                return Err(ArrivalRefusal::Cancelled);
            }
            if self.binding.deadline.is_some_and(|at| Instant::now() >= at) {
                return Err(ArrivalRefusal::Deadline);
            }
            *phase = Phase::Executing {
                deadline: self.binding.deadline,
            };
        }
        self.cancel_on_drop = false;
        Ok(PhysicalUpgrade {
            binding: self.binding.clone(),
            authorization,
        })
    }

    /// The answer to an upgrade request its route's chain denied: only that denial of this same
    /// request produces it. A failure that is not a denial (an unavailable verifier, a deadline)
    /// grants no answer: the request stays cancelled.
    pub fn refuse_upgrade_denied(
        mut self,
        refused: UpgradeRefused,
    ) -> Result<PhysicalRefusal, ArrivalRefusal> {
        let UpgradeRefused::Denied { preparation, .. } = refused else {
            return Err(ArrivalRefusal::Cancelled);
        };
        if !Arc::ptr_eq(&self.binding, preparation.binding()) {
            return Err(ArrivalRefusal::ForeignInput);
        }
        self.enter_refusal(Some(PreparationState::Denied))?;
        self.cancel_on_drop = false;
        Ok(PhysicalRefusal {
            binding: self.binding.clone(),
            _provenance: RefusalProvenance::UpgradeDenied {
                _denied: preparation,
            },
        })
    }

    /// The answer to a head no route of this listener matched (the plan's unrouted binding).
    pub fn refuse_unrouted(mut self) -> Result<PhysicalRefusal, ArrivalRefusal> {
        if !matches!(self.binding.route.target(), RouteTarget::Unrouted) {
            return Err(ArrivalRefusal::Class);
        }
        self.enter_refusal(Some(PreparationState::Unused))?;
        self.cancel_on_drop = false;
        Ok(PhysicalRefusal {
            binding: self.binding.clone(),
            _provenance: RefusalProvenance::Unrouted,
        })
    }

    fn check_upgrade(&self, authorization: &UpgradeAuthorization) -> Result<(), ArrivalRefusal> {
        if !Arc::ptr_eq(&self.binding, authorization.binding())
            || !Arc::ptr_eq(&self.binding, authorization.preparation().binding())
            || !Arc::ptr_eq(self.binding.route(), authorization.route().binding())
        {
            return Err(ArrivalRefusal::ForeignInput);
        }
        Ok(())
    }

    fn enter_refusal(&self, expected: Option<PreparationState>) -> Result<(), ArrivalRefusal> {
        let mut phase = self
            .binding
            .state
            .phase
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if *phase != Phase::Completing {
            return Err(ArrivalRefusal::Cancelled);
        }
        if self.binding.deadline.is_some_and(|at| Instant::now() >= at) {
            return Err(ArrivalRefusal::Deadline);
        }
        if expected.is_some_and(|expected| {
            *self
                .binding
                .state
                .preparation
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                != expected
        }) {
            return Err(ArrivalRefusal::Cancelled);
        }
        *phase = Phase::Refusing;
        Ok(())
    }
}

/// An authorized upgrade request handed to its carrier: the executing physical owner and the
/// authorization it was admitted under. Dropping it cancels the request.
pub struct PhysicalUpgrade {
    binding: Arc<RequestBinding>,
    authorization: UpgradeAuthorization,
}
impl PhysicalUpgrade {
    pub fn binding(&self) -> &Arc<RequestBinding> {
        &self.binding
    }
    pub fn authorization(&self) -> &UpgradeAuthorization {
        &self.authorization
    }
    pub fn check_executing(&self) -> Result<(), ArrivalRefusal> {
        self.binding.check_executing()
    }
}
impl Drop for PhysicalUpgrade {
    fn drop(&mut self) {
        self.binding.state.cancel();
    }
}

impl PhysicalExecutionOwner {
    pub(crate) fn refuse_data(
        self,
        witness: NativeTaskRetirement,
    ) -> Result<PhysicalRefusal, ArrivalRefusal> {
        if !witness.permits_refusal(&self.binding) {
            return Err(ArrivalRefusal::ForeignInput);
        }
        {
            let mut phase = self
                .binding
                .state
                .phase
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if *phase != Phase::Admitted {
                return Err(ArrivalRefusal::Cancelled);
            }
            if self.binding.deadline.is_some_and(|at| Instant::now() >= at) {
                return Err(ArrivalRefusal::Deadline);
            }
            *phase = Phase::Refusing;
        }
        // Retain the original owner itself. Neither cancellation Drop runs during transfer;
        // both continue to close the same state when the final refusal owner is dropped.
        Ok(PhysicalRefusal {
            binding: self.binding.clone(),
            _provenance: RefusalProvenance::Allocated {
                _owner: self,
                _witness: witness,
            },
        })
    }
}
