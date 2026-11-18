// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Consumed physical refusal custody; cancellation is never reversed.

use super::*;
use crate::auth::native_data::PreparedDataDenial;
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
}
impl PhysicalRefusal {
    pub fn check_output_live(&self) -> Result<(), ArrivalRefusal> {
        let phase = self
            .binding
            .state
            .phase
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if *phase != Phase::Refusing || self.binding.state.cancelled.is_cancelled() {
            return Err(ArrivalRefusal::Cancelled);
        }
        if self.binding.deadline.is_some_and(|at| Instant::now() >= at) {
            return Err(ArrivalRefusal::Deadline);
        }
        Ok(())
    }
    pub fn binding(&self) -> &Arc<RequestBinding> {
        &self.binding
    }
    pub fn unit(&self) -> Option<busbar_contract::UnitKey> {
        match &self._provenance {
            RefusalProvenance::Allocated { _witness, .. } => Some(_witness.unit()),
            RefusalProvenance::Admin { .. } | RefusalProvenance::Data { .. } => None,
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

    /// Root calls only after its actual pre-claim denial seal and original confirmation.
    pub fn refuse_admin(
        mut self,
        record: &busbar_kernel_audit::AuditRecord,
    ) -> Result<PhysicalRefusal, ArrivalRefusal> {
        self.check_admin_route()?;
        if record.what.unit_key.get() != self.binding.invocation().request_id().get()
            || !matches!(
                record.outcome.unit_end,
                busbar_contract::caps::Outcome::Refused(..)
            )
        {
            return Err(ArrivalRefusal::ForeignInput);
        }
        self.enter_refusal(Some(PreparationState::Unused))?;
        self.cancel_on_drop = false;
        Ok(PhysicalRefusal {
            binding: self.binding.clone(),
            _provenance: RefusalProvenance::Admin {
                _outcome: record.outcome.unit_end,
            },
        })
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
