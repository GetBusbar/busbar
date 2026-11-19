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
//!
//! A third producer is the signed class: a route whose record admits a signed sender is
//! completed by the value its signature verifier returned for this exact request
//! (`complete_signed`), which is also the only way to the request's body; a request that
//! verifier did not admit is answered by core under `refuse_signed` and serves nothing.

use std::sync::{Arc, PoisonError};
use std::time::Instant;

use busbar_plugin_abi::plane::{AUTH_OPTIONAL, AUTH_PUBLIC, AUTH_SIGNED_INGRESS};

use super::refusal::PreparationState;
use super::{
    ArrivalRefusal, BindError, CompletingPhysicalRequest, Phase, RequestBinding, RouteTarget,
};
use crate::auth::native_data::DataAuthorization;
use crate::auth::native_signed::SignedIngressVerified;
use crate::auth::native_signed_route::SignedUnserved;
use crate::inbound::request_snapshot::ChargedRequestSnapshot;
use crate::state::AdmissionLease;

/// What admitted the request.
enum UnbilledProof {
    /// The route's chain verified the caller and its key policy passed. The authorization keeps
    /// its own lease on the serving generation.
    Verified { _authorization: DataAuthorization },
    /// The route's record admits a caller that presents nothing.
    Unverified { _lease: AdmissionLease },
    /// The route's signature verifier admitted the sender and its replay claim was won. A signed
    /// sender earns no key: there is no authorization, only the request that was verified. Its
    /// snapshot is kept here because it is the one way to the body
    /// ([`PhysicalUnbilledExecution::signed_request`]).
    Signed {
        _lease: AdmissionLease,
        subject: Box<str>,
        request: Arc<ChargedRequestSnapshot>,
    },
    /// A signed route's request that was not admitted: core answers it and nothing is served.
    SignedUnserved { _why: SignedUnserved },
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
            UnbilledProof::Unverified { .. }
            | UnbilledProof::Signed { .. }
            | UnbilledProof::SignedUnserved { .. } => None,
        }
    }

    /// The request a signature verified, whole: its head and the body that was verified, byte for
    /// byte as received. `None` unless the route's signature verifier admitted this request: a
    /// signed route's body is parsed from here and from nowhere else, so nothing parses a body
    /// that was not verified.
    pub fn signed_request(&self) -> Option<&Arc<ChargedRequestSnapshot>> {
        match &self.proof {
            UnbilledProof::Signed { request, .. } => Some(request),
            UnbilledProof::Verified { .. }
            | UnbilledProof::Unverified { .. }
            | UnbilledProof::SignedUnserved { .. } => None,
        }
    }

    /// Who a verified signed sender is recorded as; `None` unless a signature admitted this
    /// request.
    pub fn signed_subject(&self) -> Option<&str> {
        match &self.proof {
            UnbilledProof::Signed { subject, .. } => Some(&**subject),
            UnbilledProof::Verified { .. }
            | UnbilledProof::Unverified { .. }
            | UnbilledProof::SignedUnserved { .. } => None,
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
        self.binding.watch_revocation(&authorization.key().id);
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

// ---- signed ingress ----

impl CompletingPhysicalRequest {
    /// Whether this request's route is a plane route mounted as the signed class, by the route's
    /// own declaration and with the operator's choice the same.
    fn check_signed_route(&self) -> Result<(), ArrivalRefusal> {
        let RouteTarget::Plane(target) = self.binding.route.target() else {
            return Err(ArrivalRefusal::Class);
        };
        let mounted = target.mounted();
        if mounted.auth != AUTH_SIGNED_INGRESS || mounted.effective != AUTH_SIGNED_INGRESS {
            return Err(ArrivalRefusal::Class);
        }
        Ok(())
    }

    /// Complete a signed route's request for the sender its signature verifier admitted. The
    /// proof is the verified value itself, and it must be this request's: the body it leads to
    /// is this request's own snapshot's body, where it lies (the same bytes, not equal ones). No
    /// key and no unit: a signed sender is "verified, not billed".
    ///
    /// Only [`crate::auth::native_signed_route::NativeSignedRoute::admit`] calls this, with the
    /// value it has just been handed for this same request.
    pub(crate) fn complete_signed(
        mut self,
        verified: &SignedIngressVerified<'_>,
    ) -> Result<PhysicalUnbilledExecution, ArrivalRefusal> {
        self.check_signed_route()?;
        let request = self
            .binding
            .snapshot()
            .map_err(|_| ArrivalRefusal::ForeignInput)?;
        if !std::ptr::eq(verified.body(), request.body()) || verified.subject().is_empty() {
            return Err(ArrivalRefusal::ForeignInput);
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
            proof: UnbilledProof::Signed {
                _lease: lease,
                subject: verified.subject().into(),
                request,
            },
        })
    }

    /// Answer a signed route's request that was not admitted: core's refusal by the table (the
    /// one 401, 413 for a body over the bound, 400 for trailers, 503 when the verifier or the
    /// replay store could not answer). The request is consumed into `Refusing`: nothing can be
    /// served from it, and its owner leads to no body.
    pub(crate) fn refuse_signed(
        mut self,
        why: SignedUnserved,
    ) -> Result<PhysicalUnbilledExecution, ArrivalRefusal> {
        self.check_signed_route()?;
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
                != PreparationState::Unused
            {
                return Err(ArrivalRefusal::Cancelled);
            }
            if self.binding.deadline.is_some_and(|at| Instant::now() >= at) {
                return Err(ArrivalRefusal::Deadline);
            }
            *phase = Phase::Refusing;
        }
        self.cancel_on_drop = false;
        Ok(PhysicalUnbilledExecution {
            binding: self.binding.clone(),
            proof: UnbilledProof::SignedUnserved { _why: why },
        })
    }
}

/// What verified the caller of a core route that requires a key.
pub struct CoreKeyAuthorization {
    binding: Arc<RequestBinding>,
    key: Arc<busbar_contract::records::VirtualKey>,
    _lease: AdmissionLease,
}

impl CoreKeyAuthorization {
    /// Minted only by [`crate::auth::native_data::verify_core_key`], after the data chain verified
    /// the caller, key policy passed and the replay claim was won.
    pub(crate) fn new(
        binding: Arc<RequestBinding>,
        key: Arc<busbar_contract::records::VirtualKey>,
        lease: AdmissionLease,
    ) -> Self {
        Self {
            binding,
            key,
            _lease: lease,
        }
    }
}

/// One request on a core route that requires a key (`RouteAuth::Key`: `/stats`, an export or hook
/// plugin's own keyed route), verified by the data chain. No unit: a listing of the caller's own
/// figures, or a scrape, uses nothing. Dropping it cancels the request.
pub struct PhysicalKeyExecution {
    authorization: CoreKeyAuthorization,
}

impl PhysicalKeyExecution {
    pub fn binding(&self) -> &Arc<RequestBinding> {
        &self.authorization.binding
    }

    /// Execute only the original request against its retained prepared generation, with the
    /// verified caller's key attached: the handler filters its answer by that key's grants.
    pub async fn http_response(&self) -> Result<axum::response::Response, ArrivalRefusal> {
        use tower::ServiceExt;
        let binding = &self.authorization.binding;
        binding.check_executing()?;
        let snapshot = binding.snapshot().map_err(|_| ArrivalRefusal::Capacity)?;
        let mut request =
            crate::inbound::http_projection::HttpProjection::from_snapshot(snapshot.clone())
                .map_err(|_| ArrivalRefusal::Capacity)?
                .into_request(axum::body::Body::from(snapshot.body_bytes()));
        request.extensions_mut().insert(binding.app.clone());
        request.extensions_mut().insert(crate::governance::GovCtx {
            key: Some(Arc::clone(&self.authorization.key)),
        });
        let prepared = &binding.prepared;
        let router =
            (prepared.dispatch_layer)(prepared.router.clone()).with_state(binding.handle.clone());
        Ok(router
            .oneshot(request)
            .await
            .unwrap_or_else(|never| match never {}))
    }
}

impl Drop for PhysicalKeyExecution {
    fn drop(&mut self) {
        self.authorization.binding.state.cancel();
    }
}

/// The answer to a request on a core keyed route that was not verified (or whose verifier could
/// not answer): the refusal row core decided, and nothing of the route.
pub struct PhysicalKeyRefusal {
    binding: Arc<RequestBinding>,
    _reason: crate::auth::native_data::DataRefused,
}

impl PhysicalKeyRefusal {
    pub fn binding(&self) -> &Arc<RequestBinding> {
        &self.binding
    }
}

impl Drop for PhysicalKeyRefusal {
    fn drop(&mut self) {
        self.binding.state.cancel();
    }
}

impl CompletingPhysicalRequest {
    fn check_key_route(&self) -> Result<(), ArrivalRefusal> {
        if !matches!(
            self.binding.route.target(),
            RouteTarget::Core(busbar_contract::route::RouteAuth::Key)
        ) {
            return Err(ArrivalRefusal::Class);
        }
        Ok(())
    }

    /// Complete a core keyed route for the caller its authorization verified.
    pub fn complete_core_key(
        mut self,
        authorization: CoreKeyAuthorization,
    ) -> Result<PhysicalKeyExecution, ArrivalRefusal> {
        self.check_key_route()?;
        if !Arc::ptr_eq(&self.binding, &authorization.binding) {
            return Err(ArrivalRefusal::ForeignInput);
        }
        self.enter_unbilled(PreparationState::Unused)?;
        self.binding.watch_revocation(&authorization.key.id);
        self.cancel_on_drop = false;
        Ok(PhysicalKeyExecution { authorization })
    }

    /// Refuse a core keyed route for a reason the refusal table answers.
    pub fn refuse_core_key(
        mut self,
        reason: crate::auth::native_data::DataRefused,
    ) -> Result<PhysicalKeyRefusal, ArrivalRefusal> {
        self.check_key_route()?;
        if reason.refusal(false).is_none() {
            return Err(ArrivalRefusal::Cancelled);
        }
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
            if self.binding.deadline.is_some_and(|at| Instant::now() >= at) {
                return Err(ArrivalRefusal::Deadline);
            }
            *phase = Phase::Refusing;
        }
        self.cancel_on_drop = false;
        Ok(PhysicalKeyRefusal {
            binding: self.binding.clone(),
            _reason: reason,
        })
    }
}

/// The answer to a request refused at the gate (refusal rows 1 and 22: the gateway is full, or
/// draining): step 0 of the sequence, before any route, caller or unit is looked at. It is
/// counted, not audited; the request is answered and its connection kept.
pub struct PhysicalGateRefusal {
    binding: Arc<RequestBinding>,
}

impl PhysicalGateRefusal {
    pub fn binding(&self) -> &Arc<RequestBinding> {
        &self.binding
    }
}

impl Drop for PhysicalGateRefusal {
    fn drop(&mut self) {
        self.binding.state.cancel();
    }
}

impl CompletingPhysicalRequest {
    /// Refuse this request at the gate, whatever its route: nothing of it was judged.
    pub fn refuse_at_gate(mut self) -> Result<PhysicalGateRefusal, ArrivalRefusal> {
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
                != PreparationState::Unused
            {
                return Err(ArrivalRefusal::Cancelled);
            }
            *phase = Phase::Refusing;
        }
        self.cancel_on_drop = false;
        Ok(PhysicalGateRefusal {
            binding: self.binding.clone(),
        })
    }
}
