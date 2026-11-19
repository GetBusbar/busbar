// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

enum RetainedAnswer {
    NonNative(AdminAnswer),
    Executed {
        answer: AdminAnswer,
        physical: Arc<busbar_kernel::inbound::native::PhysicalAdminExecution>,
    },
    PendingRefusal {
        answer: AdminAnswer,
        pending: busbar_kernel::inbound::native::CompletingPhysicalRequest,
        carrier: busbar_kernel::inbound::native::AdminPhysicalRequest,
    },
    Refused {
        answer: AdminAnswer,
        carrier: busbar_kernel::inbound::native::PhysicalRefusalCarrier,
    },
    NativeFailed(AdminAnswer),
}

type SealedAnswer = (
    RetainedAnswer,
    Option<AuditRecord>,
    Option<busbar_kernel::auth::native_admin::AdminCompletionRefused>,
);

impl RetainedAnswer {
    fn confirm(self, record: Option<&AuditRecord>) -> Self {
        match self {
            Self::PendingRefusal {
                answer,
                pending,
                carrier,
            } => {
                let unit = pending.binding().invocation().request_id().get();
                let Some(record) = record else {
                    no_authority("a refusal with no audit record", unit, answer.status);
                    return Self::NativeFailed(unavailable_answer());
                };
                let physical = match pending
                    .refuse_admin(record.what.unit_key, record.outcome.unit_end)
                {
                    Ok(physical) => physical,
                    Err(why) => {
                        tracing::warn!(unit, ?why, "the physical request refused its own refusal");
                        no_authority("refuse_admin", unit, answer.status);
                        return Self::NativeFailed(unavailable_answer());
                    }
                };
                match carrier.retain_refusal(physical) {
                    Ok(carrier) => Self::Refused { answer, carrier },
                    Err(why) => {
                        tracing::warn!(unit, ?why, "the admin carrier refused to hold its refusal");
                        no_authority("retain_refusal", unit, answer.status);
                        Self::NativeFailed(unavailable_answer())
                    }
                }
            }
            other => other,
        }
    }

    fn publication_failed(self) -> Self {
        let answer = bound::journal_unavailable(
            "the administrative result's audit publication is unconfirmed; do not re-submit",
        );
        match self {
            Self::NonNative(_) => Self::NonNative(answer),
            _ => Self::NativeFailed(answer),
        }
    }

    #[cfg(test)]
    fn into_answer(self) -> AdminAnswer {
        match self {
            Self::NonNative(answer)
            | Self::NativeFailed(answer)
            | Self::Executed { answer, .. }
            | Self::PendingRefusal { answer, .. }
            | Self::Refused { answer, .. } => answer,
        }
    }

    fn into_response(self) -> axum::response::Response {
        match self {
            Self::NonNative(answer) | Self::NativeFailed(answer) => http_response(answer),
            Self::Executed { answer, physical } => {
                busbar_kernel::auth::native_admin::retain_physical_response(
                    http_response(answer),
                    physical,
                )
            }
            Self::Refused { answer, carrier } => {
                let mut response = http_response(answer);
                response.extensions_mut().insert(carrier);
                response
            }
            // Only confirmed_request's successful result may consume the pending denial.
            Self::PendingRefusal { .. } => http_response(unavailable_answer()),
        }
    }
}

pub(crate) struct AdminNode {
    pub(super) kernel: busbar_kernel::teller::Kernel,
    pub(super) units: crate::root::kernel::ProductionUnits,
}

impl AdminNode {
    #[must_use]
    pub(crate) fn new(
        kernel: busbar_kernel::teller::Kernel,
        units: crate::root::kernel::ProductionUnits,
    ) -> Self {
        AdminNode { kernel, units }
    }

    pub(crate) fn next_unit(&self) -> u64 {
        crate::root::plane_node::node().mint().get()
    }

    #[cfg(test)]
    pub(crate) async fn answer(&self, request: AdminRequest) -> AdminAnswer {
        self.answer_with_admission(request, None, None)
            .await
            .into_answer()
    }

    async fn answer_with_admission(
        &self,
        request: AdminRequest,
        admission: Option<busbar_kernel::inbound::RequestAdmission>,
        physical: Option<busbar_kernel::inbound::native::CompletingPhysicalRequest>,
    ) -> RetainedAnswer {
        let unit = request.unit;
        let native = physical.is_some() || request.binding.is_some();
        let ((answer, record, claim_failure), publication) =
            busbar_kernel::audit::auditlog::confirmed_request(Box::pin(
                self.answer_confirmed(request, admission, physical),
            ))
            .await;
        if publication.is_err() {
            if native {
                no_authority("the request's audit publication is unconfirmed", unit, 503);
            }
            return answer.publication_failed();
        }
        let answer = answer.confirm(record.as_ref());
        // Store retains any unresolved operation; keep its original preparation through
        // this request's audit confirmation without minting response authority.
        drop(claim_failure);
        answer
    }

    /// RECORD A REFUSAL THE KERNEL'S ADMIN MIDDLEWARE DECIDED for a native request, as that
    /// request's own admin unit, and make it the request's refusal owner. The middleware judged
    /// the credential (a verb this node does not serve, or an undeclared path) and handed the
    /// unspent pending owner back; a refusal is output authority only once it is recorded, and
    /// only this node records an admin unit. `None`: the record was not confirmed, or the owner
    /// was cancelled or reached its deadline meanwhile; the caller answers unavailable.
    async fn record_denial(
        &self,
        ended: Outcome,
        pending: busbar_kernel::inbound::native::CompletingPhysicalRequest,
        carrier: busbar_kernel::inbound::native::AdminPhysicalRequest,
    ) -> Option<busbar_kernel::inbound::native::PhysicalRefusalCarrier> {
        let ((answer, record, _), publication) = busbar_kernel::audit::auditlog::confirmed_request(
            Box::pin(self.denial_sealed(ended, pending, carrier)),
        )
        .await;
        if publication.is_err() {
            return None;
        }
        match answer.confirm(record.as_ref()) {
            RetainedAnswer::Refused { carrier, .. } => Some(carrier),
            _ => None,
        }
    }

    async fn denial_sealed(
        &self,
        ended: Outcome,
        pending: busbar_kernel::inbound::native::CompletingPhysicalRequest,
        carrier: busbar_kernel::inbound::native::AdminPhysicalRequest,
    ) -> SealedAnswer {
        let binding = pending.binding().clone();
        let Ok(snapshot) = binding.snapshot() else {
            return (
                RetainedAnswer::NativeFailed(unavailable_answer()),
                None,
                None,
            );
        };
        // The unit is the request's own: `refuse_admin` accepts no other.
        let key = UnitKey::new(binding.invocation().request_id().get());
        let mono = crate::root::plane_node::node().checked_mono().ok();
        let facts = match busbar_core_admin::admin_codec::verbs::resolve(
            snapshot.method(),
            snapshot.target(),
        ) {
            Some(resolved) => busbar_contract::AuditFacts {
                op_class: resolved.op_class(),
                finish: super::finish_of(&ended),
            },
            None => super::unresolved_facts(Some(snapshot.method()), &ended),
        };
        match self
            .seal(key, snapshot.now_s(), mono, None, facts, ended)
            .await
        {
            Some(record) => (
                RetainedAnswer::PendingRefusal {
                    answer: door_answer(),
                    pending,
                    carrier,
                },
                Some(record),
                None,
            ),
            None => (
                RetainedAnswer::NativeFailed(unavailable_answer()),
                None,
                None,
            ),
        }
    }

    async fn answer_confirmed(
        &self,
        request: AdminRequest,
        admission: Option<busbar_kernel::inbound::RequestAdmission>,
        physical: Option<busbar_kernel::inbound::native::CompletingPhysicalRequest>,
    ) -> SealedAnswer {
        let native = physical.is_some() || request.binding.is_some();
        if admission
            .as_ref()
            .is_some_and(|admission| !admission.begin_execution())
        {
            return (
                if native {
                    RetainedAnswer::NativeFailed(unavailable_answer())
                } else {
                    RetainedAnswer::NonNative(unavailable_answer())
                },
                None,
                None,
            );
        }
        let key = UnitKey::new(request.unit);

        let arrived_at = request.at();
        // This unit's one monotonic reading, taken with its arrival: where its record sits in the
        // node's merged order. `None` only when the node's clock is exhausted (no record, no ack).
        let mono = crate::root::plane_node::node().checked_mono().ok();
        let mut walk = AdminWalk::new(request);
        walk.admission = admission;
        walk.physical_pending = physical;
        let ended = decide(&self.units, &mut walk).await;
        let facts = audit(&walk, &ended);
        let answer = walk
            .answer
            .take()
            .unwrap_or_else(|| refused_answer(ended, &walk.request));

        let record = self
            .seal(key, arrived_at, mono, walk.principal.as_ref(), facts, ended)
            .await;
        let Some(record) = record else {
            return (
                if native {
                    RetainedAnswer::NativeFailed(answer)
                } else {
                    RetainedAnswer::NonNative(answer)
                }
                .publication_failed(),
                None,
                walk.claim_failure.take(),
            );
        };
        if let Some(physical) = walk.request.physical.take() {
            return (
                RetainedAnswer::Executed { answer, physical },
                None,
                walk.claim_failure.take(),
            );
        }
        if native {
            if walk.expected_refusal == Some(ended) {
                if let (Some(pending), Some(carrier)) = (
                    walk.physical_pending.take(),
                    walk.request.refusal_carrier.take(),
                ) {
                    return (
                        RetainedAnswer::PendingRefusal {
                            answer,
                            pending,
                            carrier,
                        },
                        Some(record),
                        walk.claim_failure.take(),
                    );
                }
            }
            // Neither an execution nor a refusal this unit expected (a verifier that gave no
            // verdict ends `Refused(Authenticate, Internal)`; a refusal after the claim; a pending
            // owner or carrier already gone): the answer below has no output authority.
            tracing::warn!(
                unit = key.get(),
                status = answer.status,
                ended = ?ended,
                expected_refusal = ?walk.expected_refusal,
                pending = walk.physical_pending.is_some(),
                carrier = walk.request.refusal_carrier.is_some(),
                "a native admin unit ended as neither an execution nor an expected refusal"
            );
            no_authority("the admin unit's end", key.get(), answer.status);
            return (
                RetainedAnswer::NativeFailed(answer),
                None,
                walk.claim_failure.take(),
            );
        }
        (
            RetainedAnswer::NonNative(answer),
            None,
            walk.claim_failure.take(),
        )
    }

    async fn seal(
        &self,
        key: UnitKey,
        arrived_at: u64,
        mono: Option<u64>,
        principal: Option<&PrincipalId>,
        facts: busbar_contract::AuditFacts,
        ended: Outcome,
    ) -> Option<AuditRecord> {
        use busbar_kernel_audit::{AuditInputs, Controls, OutcomeFacts, Subject, Usage, What};
        let mono = mono?;
        let card = crate::root::kernel::ROOT_CARD.pin();
        let arrived_ms = arrived_at.saturating_mul(1_000);
        let subject =
            principal.map_or(Subject::Arrival, |p| Subject::PrincipalId(p.text().clone()));
        let inputs = AuditInputs {
            subject,
            what: What {
                unit_key: key,
                incarnation: 0,
                op_class: busbar_kernel_audit::OpClassId::new(facts.op_class.as_str()),
                destination: None,
                parent: None,
                pre_hook_head: None,
                post_hook_head: None,
            },
            wall: arrived_at,

            mono,
            origin: self
                .kernel
                .origin(busbar_contract::caps::OriginKind::Client),
            outcome: OutcomeFacts {
                unit_end: ended,
                step: ended.step(),
                finish: crate::root::plane_node::audit_finish(facts.finish),
                hook_failed: false,
                emission_delta: 0,
                stale_policy: false,
            },
            usage: Usage {
                lines: Vec::new(),
                tier_bp: 10_000,
                fee_count: 0,
                rate_card_version: crate::root::plane_node::card_in_force(
                    card.as_ref(),
                    arrived_ms,
                ),
                bucket_chain_ref: String::new(),
            },
            controls: Controls {
                policy_epoch: crate::root::plane_node::policy_in_force(card.as_ref(), arrived_ms),
                ..Controls::default()
            },
            correlation_label: None,
            unit: busbar_kernel_audit::UnitFacts {
                boot_nonce: busbar_kernel::snapshot::boot_nonce(),
                ..busbar_kernel_audit::UnitFacts::at(arrived_ms)
            },
        };
        let token = self.kernel.durability_token();
        let sealed = crate::root::durability::Durability::seal_unit(
            &self.units.durability,
            inputs,
            busbar_kernel::teller::verb_audit_pass(&self.kernel),
            &token,
        )
        .await;
        match sealed {
            Ok(record) => Some(record),
            Err(lost) => {
                tracing::error!(
                    step = lost.step().as_str(),
                    unit = key.get(),
                    "the journal has not confirmed an admin unit's audit record"
                );
                None
            }
        }
    }
}

pub(crate) struct ExitPath {
    pub(super) unit: u64,
}

impl Drop for ExitPath {
    fn drop(&mut self) {
        busbar_core_admin::restart::UnitDrain::of_unit(self.unit).release();
    }
}

pub(crate) fn refused_answer(ended: Outcome, request: &AdminRequest) -> AdminAnswer {
    if is_credential_refusal(ended) {
        return door_answer();
    }
    if is_scope_refusal(ended) {
        return scope_answer(request);
    }
    if is_rate_refusal(ended) {
        return rate_limited_answer();
    }
    if let Some(explained) = explained_answer(request, ended) {
        return explained;
    }
    answer_for(ended)
}

pub(crate) fn is_credential_refusal(outcome: Outcome) -> bool {
    matches!(
        outcome,
        Outcome::Refused(_, ReasonCode::Unauthenticated | ReasonCode::Revoked)
            | Outcome::Failed(_, ReasonCode::Unauthenticated | ReasonCode::Revoked)
    )
}

pub(crate) fn is_scope_refusal(outcome: Outcome) -> bool {
    matches!(
        outcome,
        Outcome::Refused(_, ReasonCode::ScopeDenied) | Outcome::Failed(_, ReasonCode::ScopeDenied)
    )
}

pub(crate) fn is_rate_refusal(outcome: Outcome) -> bool {
    matches!(
        outcome,
        Outcome::Refused(_, ReasonCode::RateLimited) | Outcome::Failed(_, ReasonCode::RateLimited)
    )
}

pub(crate) fn rate_limited_answer() -> AdminAnswer {
    let refused = busbar_kernel::admin::gate::ApiError::RateLimited;
    AdminAnswer {
        status: refused.http_status(),
        headers: vec![
            (
                "retry-after".to_string(),
                busbar_kernel::ratelimit::MUTATION_RATE_WINDOW_SECS.to_string(),
            ),
            ("content-type".to_string(), "application/json".to_string()),
        ],
        body: busbar_core_admin::admin_codec::refusal::envelope_of(
            refused.code(),
            &refused.message(),
        )
        .into_bytes(),
    }
}

pub(crate) fn scope_answer(request: &AdminRequest) -> AdminAnswer {
    let needed =
        busbar_kernel::admin::scope::admin_required_scope(request.method(), request.path());
    error_answer_with_message(
        403,
        "forbidden",
        &format!(
            "insufficient scope: this endpoint requires `{}`",
            needed.as_str()
        ),
    )
}

pub(crate) const DOOR_STATUS: u16 = 401;

pub(crate) const DOOR_CODE: &str = "unauthorized";

pub(crate) const DOOR_MESSAGE: &str = "missing or invalid admin credential (Bearer)";

pub(crate) fn door_answer() -> AdminAnswer {
    let mut answer = error_answer_with_message(DOOR_STATUS, DOOR_CODE, DOOR_MESSAGE);
    answer
        .headers
        .push(("www-authenticate".to_string(), "Bearer".to_string()));
    answer
}

pub(crate) fn authentication_unavailable_answer() -> AdminAnswer {
    let refused = busbar_kernel::admin::gate::ApiError::Unavailable(
        busbar_kernel::auth::ADMIN_AUTH_UNAVAILABLE_MESSAGE.to_string(),
    );
    let mut answer =
        error_answer_with_message(refused.http_status(), refused.code(), &refused.message());
    answer.headers.push((
        "retry-after".to_string(),
        busbar_kernel::auth::ADMIN_AUTH_RETRY_AFTER.to_string(),
    ));
    answer
}

pub(crate) fn answer_for(outcome: Outcome) -> AdminAnswer {
    use busbar_contract::plane::codes::{class_of, RefusalClass};
    let (status, code) = match outcome {
        Outcome::Refused(_, reason) | Outcome::Failed(_, reason) => match class_of(reason) {
            RefusalClass::Unreadable => (400, "invalid_request"),

            RefusalClass::NotFound => (404, "not_found"),

            RefusalClass::QuotaExhausted | RefusalClass::Busy => (429, "rate_limited"),

            RefusalClass::Unavailable => (503, "unavailable"),
            RefusalClass::Unauthenticated => (401, "unauthenticated"),

            RefusalClass::Rejected | RefusalClass::Forbidden => (403, "forbidden"),

            RefusalClass::TooLarge => (413, "too_large"),

            RefusalClass::Throttled => (429, "rate_limited"),

            RefusalClass::Timeout => (504, "timeout"),

            RefusalClass::Unreachable | RefusalClass::PlaneFault | RefusalClass::NodeFault => {
                (502, "upstream_error")
            }
        },
        _ => (500, "internal_error"),
    };
    error_answer(status, code)
}

pub(crate) fn error_answer(status: u16, code: &str) -> AdminAnswer {
    error_answer_with_message(status, code, code)
}

pub(crate) fn error_answer_with_message(status: u16, code: &str, message: &str) -> AdminAnswer {
    AdminAnswer {
        status,
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body: busbar_core_admin::admin_codec::refusal::envelope_of(code, message).into_bytes(),
    }
}

pub(crate) const AMEND_RATE_HISTORY_PATH: &str = "/api/v1/admin/ledger/amend-rate-history";

pub(crate) const AMEND_RATE_HISTORY_SHAPE: &str = "amend-rate-history: body must carry effective_from, reason, and rates and/or per_request_fee; rate_card/window is the pre-1.6.0 shape";

pub(crate) fn explained_answer(request: &AdminRequest, outcome: Outcome) -> Option<AdminAnswer> {
    use busbar_contract::plane::codes::{class_of, RefusalClass};
    let unreadable = matches!(
        outcome,
        Outcome::Refused(_, reason) | Outcome::Failed(_, reason)
            if class_of(reason) == RefusalClass::Unreadable
    );
    let path = request.path().split('?').next().unwrap_or("");
    (unreadable && request.method() == "POST" && path == AMEND_RATE_HISTORY_PATH)
        .then(|| error_answer_with_message(400, "invalid_request", AMEND_RATE_HISTORY_SHAPE))
}

pub(crate) fn unavailable_answer() -> AdminAnswer {
    error_answer(503, "unavailable")
}

pub(crate) type Errand = (
    AdminRequest,
    Option<busbar_kernel::inbound::RequestAdmission>,
    Option<Arc<busbar_kernel::auth::native_admin::ExecutionAdmission>>,
    tokio::sync::oneshot::Sender<AdminAnswer>,
);

pub(crate) struct RouterDispatch {
    errands: tokio::sync::mpsc::UnboundedSender<Errand>,
}

use busbar_core_admin::keys::KeyReplayCache;

impl RouterDispatch {
    #[must_use]
    pub(crate) fn new(
        inner: axum::Router,
        runtime: &tokio::runtime::Handle,
        replays: Arc<KeyReplayCache>,
    ) -> Self {
        let (errands, mut inbox) = tokio::sync::mpsc::unbounded_channel::<Errand>();
        runtime.spawn(async move {
            while let Some((request, admission, execution, reply)) = inbox.recv().await {
                let inner = inner.clone();
                let replays = replays.clone();

                tokio::spawn(async move {
                    let unit = request.unit;
                    let answer = busbar_core_admin::restart::UnitDrain::of_unit(unit)
                        .scoping(call(inner, &request, &replays, admission, execution))
                        .await;
                    let _ = reply.send(answer);
                });
            }
        });
        RouterDispatch { errands }
    }
}

async fn call(
    inner: axum::Router,
    request: &AdminRequest,
    replays: &Arc<KeyReplayCache>,
    admission: Option<busbar_kernel::inbound::RequestAdmission>,
    execution: Option<Arc<busbar_kernel::auth::native_admin::ExecutionAdmission>>,
) -> AdminAnswer {
    use tower::ServiceExt;

    let projection = request
        .projection
        .lock()
        .ok()
        .and_then(|mut slot| slot.take());
    let mut http = if let Some(projection) = projection {
        let Ok(projection) = Arc::try_unwrap(projection) else {
            return unavailable_answer();
        };
        projection.into_request(axum::body::Body::from(request.snapshot().body_bytes()))
    } else {
        if request.binding.is_some() {
            return unavailable_answer();
        }
        // The explicit legacy path still obtains its own funded projection from the
        // actual retained request. It cannot enter native dispatch without its carrier.
        let Ok(projection) = busbar_kernel::inbound::http_projection::HttpProjection::from_snapshot(
            Arc::clone(request.snapshot()),
        ) else {
            return unavailable_answer();
        };
        projection.into_request(axum::body::Body::from(request.snapshot().body_bytes()))
    };
    http.extensions_mut().insert(Arc::clone(replays));
    http.extensions_mut().insert(Arc::clone(request.snapshot()));
    http.extensions_mut()
        .insert(request.snapshot().request().clone());
    if let Some(admission) = admission {
        http.extensions_mut().insert(admission);
    }
    if let Some(physical) = &request.physical {
        if physical.check_executing().is_err() {
            return door_answer();
        }
        if !execution
            .as_ref()
            .is_some_and(|execution| Arc::ptr_eq(execution, physical.admission()))
        {
            return door_answer();
        }
        http.extensions_mut().insert(physical.clone());
    }
    if let Some(execution) = execution {
        if let Some((lease, prepared)) = execution.native() {
            if request.physical.is_none()
                || lease.invocation().request_id().get() != request.unit
                || !Arc::ptr_eq(prepared.request(), request.snapshot())
            {
                return door_answer();
            }
            http.extensions_mut().insert(Arc::clone(lease.generation()));
            http.extensions_mut().insert(execution);
        }
    }
    let response = inner.oneshot(http).await.unwrap_or_else(|e| match e {});
    let (parts, body) = response.into_parts();

    let Ok(bytes) = axum::body::to_bytes(body, usize::MAX).await else {
        return unavailable_answer();
    };
    AdminAnswer {
        status: parts.status.as_u16(),
        headers: header_pairs(&parts.headers),
        body: bytes.to_vec(),
    }
}

#[async_trait::async_trait]
impl AdminDispatch for RouterDispatch {
    async fn execute(&self, _verb: KernelVerb, request: &AdminRequest) -> AdminAnswer {
        self.dispatch(request, None, None).await
    }

    async fn execute_admitted(
        &self,
        _verb: KernelVerb,
        request: &AdminRequest,
        admission: &busbar_kernel::inbound::RequestAdmission,
    ) -> AdminAnswer {
        self.dispatch(request, Some(admission.clone()), None).await
    }

    async fn execute_authorized(
        &self,
        _verb: KernelVerb,
        request: &AdminRequest,
        admission: Option<&busbar_kernel::inbound::RequestAdmission>,
        execution: Option<&Arc<busbar_kernel::auth::native_admin::ExecutionAdmission>>,
    ) -> AdminAnswer {
        self.dispatch(request, admission.cloned(), execution.cloned())
            .await
    }
}

impl RouterDispatch {
    async fn dispatch(
        &self,
        request: &AdminRequest,
        admission: Option<busbar_kernel::inbound::RequestAdmission>,
        execution: Option<Arc<busbar_kernel::auth::native_admin::ExecutionAdmission>>,
    ) -> AdminAnswer {
        let (reply, answer) = tokio::sync::oneshot::channel();
        if self
            .errands
            .send((request.clone(), admission, execution, reply))
            .is_err()
        {
            return unavailable_answer();
        }
        answer.await.unwrap_or_else(|_| unavailable_answer())
    }
}

pub(crate) fn header_pairs(headers: &axum::http::HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect()
}

pub(crate) fn http_response(answer: AdminAnswer) -> axum::http::Response<axum::body::Body> {
    let mut response = axum::http::Response::builder().status(answer.status);
    for (name, value) in &answer.headers {
        response = response.header(name.as_str(), value.as_str());
    }
    let mut response = response
        .body(axum::body::Body::from(answer.body))
        .unwrap_or_else(|_| {
            axum::http::Response::builder()
                .status(500)
                .body(axum::body::Body::empty())
                .expect("an empty 500 always builds")
        });
    // Root-owned verbs and admission refusals bypass the inner admin router's boundary.
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

#[cfg(test)]
#[tokio::test]
async fn root_admin_answers_are_never_stored() {
    for (status, effect) in [
        (200, "applied"),
        (400, "not_applied"),
        (409, "unknown"),
        (503, "unknown"),
    ] {
        for existing in [None, Some("public, max-age=60")] {
            let body = format!("{{\"effect\":\"{effect}\"}}").into_bytes();
            let mut headers = vec![
                ("content-type".into(), "application/json".into()),
                ("x-busbar-adjust-effect".into(), effect.into()),
            ];
            if let Some(value) = existing {
                headers.push(("cache-control".into(), value.into()));
            }
            let response = http_response(AdminAnswer {
                status,
                headers,
                body: body.clone(),
            });
            assert_eq!(response.status().as_u16(), status);
            assert_eq!(response.headers()["cache-control"], "no-store");
            assert_eq!(
                response.headers().get_all("cache-control").iter().count(),
                1
            );
            assert_eq!(response.headers()["x-busbar-adjust-effect"], effect);
            assert_eq!(
                axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap()
                    .as_ref(),
                body.as_slice()
            );
        }
    }
}

/// A native request's answer that carries no output authority (neither its physical execution nor
/// a recorded refusal) is never delivered: the native listener closes the request with nothing
/// written. Every place on the admin path that gives the authority up says so here, by stage, so a
/// request that gets zero bytes names the layer that left it without one.
fn no_authority(stage: &'static str, unit: u64, status: u16) {
    tracing::warn!(
        stage,
        unit,
        status,
        "a native admin answer has no output authority and will not be delivered"
    );
}

/// An exit of [`mount`] that answers before any admin unit exists: said, when the request is a
/// native one, as [`no_authority`] says it.
fn before_the_unit(
    stage: &'static str,
    physical: Option<&busbar_kernel::inbound::native::CompletingPhysicalRequest>,
    answer: AdminAnswer,
) -> axum::response::Response {
    if let Some(pending) = physical {
        no_authority(
            stage,
            pending.binding().invocation().request_id().get(),
            answer.status,
        );
    }
    http_response(answer)
}

/// The refusal a kernel admin answer states, for the admin unit that records it: the middleware's
/// credential refusal (401), its scope refusal (403), its refusals of the request itself (400,
/// 413) and its spent mutation budget (429). `None` for every other status: an answer that is not a refusal of this request.
fn denial_outcome(status: axum::http::StatusCode) -> Option<Outcome> {
    use busbar_contract::caps::StepName;
    match status.as_u16() {
        401 => Some(Outcome::Refused(
            StepName::Authenticate,
            ReasonCode::Unauthenticated,
        )),
        403 => Some(Outcome::Refused(StepName::Approve, ReasonCode::ScopeDenied)),
        400 | 413 => Some(Outcome::Refused(StepName::Decode, ReasonCode::DecodeFailed)),
        // The principal's mutation budget is spent (admin-api.md, "Mutation rate limits"): the
        // middleware refused it at admission, as its own `refuse` records.
        429 => Some(Outcome::Refused(StepName::Admit, ReasonCode::RateLimited)),
        _ => None,
    }
}

/// A REQUEST THE KERNEL'S ROUTER SERVES: an admin route no row of the closed verb table declares
/// (a plane's own admin routes are such). Its admin middleware judges the credential. A native
/// request it refuses comes back still holding its pending physical owner
/// ([`AdminDenialReturn`]): this node records the refusal as that request's own unit and only then
/// makes it the answer's output authority, as it does for a verb it serves. Before this, such an
/// answer reached the native listener with no authority and the listener, rightly, wrote nothing.
/// Every verb of the table (`info`, `openapi.json`, `kinds`, `usage` among them) is served by this
/// node itself and never comes through here.
///
/// [`AdminDenialReturn`]: busbar_kernel::inbound::native::AdminDenialReturn
async fn through_inner(
    node: &Arc<AdminNode>,
    inner: axum::Router,
    req: axum::http::Request<axum::body::Body>,
) -> axum::response::Response {
    use tower::ServiceExt;

    let mut response = inner.oneshot(req).await.unwrap_or_else(|e| match e {});
    let Some((pending, carrier)) = response
        .extensions_mut()
        .remove::<busbar_kernel::inbound::native::AdminDenialReturn>()
        .and_then(|returned| returned.take())
    else {
        return response;
    };
    let status = response.status();
    let Some(ended) = denial_outcome(status) else {
        // Not a refusal this node can record. The owner drops here and cancels its request: the
        // listener writes nothing, and this line says which layer left it with no authority.
        tracing::error!(
            status = status.as_u16(),
            unit = pending.binding().invocation().request_id().get(),
            "the admin middleware answered a native request with no physical execution and no \
             recordable refusal; the answer has no output authority and is not delivered"
        );
        return response;
    };
    let node = Arc::clone(node);
    // The record keeps custody through client cancellation, as a served verb's does.
    let recorded =
        tokio::spawn(async move { node.record_denial(ended, pending, carrier).await }).await;
    match recorded {
        Ok(Some(carrier)) => {
            response.extensions_mut().insert(carrier);
            response
        }
        _ => {
            tracing::error!(
                status = status.as_u16(),
                "a native admin refusal was not recorded; it is not delivered"
            );
            http_response(unavailable_answer())
        }
    }
}

pub(crate) fn mount(
    inner: axum::Router,
    kernel: busbar_kernel::teller::Kernel,
    request_body_max_bytes: usize,
    build_units: impl FnOnce(Arc<dyn AdminDispatch>) -> crate::root::kernel::ProductionUnits,
) -> axum::Router {
    let runtime = tokio::runtime::Handle::current();

    busbar_core_admin::restart::drain_released_at_exit();

    let replays = Arc::new(KeyReplayCache::new());
    let dispatch: Arc<dyn AdminDispatch> =
        Arc::new(RouterDispatch::new(inner.clone(), &runtime, replays));
    let node = Arc::new(AdminNode::new(kernel, build_units(dispatch)));

    axum::Router::new().fallback(axum::routing::any(
        move |req: axum::http::Request<axum::body::Body>| {
            let node = Arc::clone(&node);
            let inner = inner.clone();
            async move {
                let path = req.uri().path();
                let claimed = path.starts_with(busbar_contract::surface::ADMIN_PREFIX);

                let declared =
                    busbar_core_admin::admin_codec::verbs::resolve(req.method().as_str(), path)
                        .is_some_and(|resolved| served_here(&resolved));
                if !claimed || !declared {
                    return through_inner(&node, inner, req).await;
                }

                let declared = req
                    .headers()
                    .get(axum::http::header::CONTENT_LENGTH)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<usize>().ok());
                if declared.is_some_and(|len| len > request_body_max_bytes)
                    && req
                        .extensions()
                        .get::<busbar_kernel::inbound::native::AdminPhysicalRequest>()
                        .is_none()
                {
                    return through_inner(&node, inner, req).await;
                }

                let (mut parts, body) = req.into_parts();
                let (physical, refusal_carrier) =
                    match parts
                        .extensions
                        .remove::<busbar_kernel::inbound::native::AdminPhysicalRequest>()
                    {
                        Some(carrier) => match carrier.take() {
                            Ok(pending) => (Some(pending), Some(carrier)),
                            Err(why) => {
                                tracing::warn!(
                                    ?why,
                                    "a native admin request's pending owner was already taken; its \
                                     answer has no output authority and will not be delivered"
                                );
                                return http_response(door_answer());
                            }
                        },
                        None => (None, None),
                    };
                let admission = parts
                    .extensions
                    .get::<busbar_kernel::inbound::RequestAdmission>()
                    .cloned();

                use busbar_kernel::inbound::request_snapshot::ChargedRequestSnapshot;
                use busbar_kernel::limits::{input_body, process_admission::RequestLease};
                // The transport owns the original admission and complete peer/TLS/head facts.
                // Neither a new count permit nor a reconstructed empty transport view can replace it.
                let Some(lease) = parts.extensions.get::<RequestLease>().cloned() else {
                    return before_the_unit(
                        "no request lease",
                        physical.as_ref(),
                        unavailable_answer(),
                    );
                };
                let Some(snapshot) = parts
                    .extensions
                    .get::<Arc<ChargedRequestSnapshot>>()
                    .cloned()
                else {
                    return before_the_unit(
                        "no request snapshot",
                        physical.as_ref(),
                        unavailable_answer(),
                    );
                };
                if !snapshot.request().same_request(&lease)
                    || physical.as_ref().is_some_and(|pending| {
                        admission.is_some()
                            || !pending.binding().request().same_request(&lease)
                            || !pending
                                .binding()
                                .snapshot()
                                .is_ok_and(|original| Arc::ptr_eq(&original, &snapshot))
                    })
                {
                    return before_the_unit(
                        "not the physical request's own lease and snapshot",
                        physical.as_ref(),
                        unavailable_answer(),
                    );
                }
                let bytes = match input_body::gather(body, &lease, request_body_max_bytes).await {
                    Ok(bytes) => bytes,
                    Err(input_body::GatherError::Capacity(_)) => {
                        return before_the_unit(
                            "the body's capacity",
                            physical.as_ref(),
                            unavailable_answer(),
                        )
                    }
                    Err(error) => {
                        if let Some(admission) = &admission {
                            admission.refuse(
                                busbar_contract::caps::StepName::Decode,
                                ReasonCode::DecodeFailed,
                            );
                        }
                        let _ = error;
                        let status = 400;
                        return before_the_unit(
                            "the body could not be gathered",
                            physical.as_ref(),
                            error_answer(status, "invalid_request"),
                        );
                    }
                };
                let target = parts
                    .uri
                    .path_and_query()
                    .map_or(parts.uri.path(), |v| v.as_str());
                if !busbar_kernel::auth::native_admin::snapshot_matches_http(
                    &snapshot,
                    parts.method.as_str(),
                    target,
                    &parts.headers,
                    &bytes,
                ) {
                    return before_the_unit(
                        "the HTTP projection differs from the request's snapshot",
                        physical.as_ref(),
                        error_answer(400, "invalid_request"),
                    );
                }
                drop(bytes);
                let mut request = match physical.as_ref() {
                    Some(pending) => {
                        let projection =
                            match busbar_kernel::inbound::http_projection::HttpProjection::from_parts(
                                parts,
                            ) {
                                Ok(projection) => projection,
                                Err(_) => return before_the_unit(
                                    "the HTTP projection was refused",
                                    Some(pending),
                                    unavailable_answer(),
                                ),
                            };
                        match AdminRequest::from_binding(
                            pending.binding().clone(),
                            Some(projection),
                        ) {
                            Ok(request) => request,
                            Err(_) => return before_the_unit(
                                "the request binding gave no snapshot",
                                Some(pending),
                                unavailable_answer(),
                            ),
                        }
                    }
                    None => {
                        let unit = admission.as_ref().map_or_else(
                            || node.next_unit(),
                            |admission| admission.unit_key().get(),
                        );
                        AdminRequest::from_snapshot(snapshot, unit)
                    }
                };
                request.refusal_carrier = refusal_carrier;
                let unit = request.unit;

                let exit = ExitPath { unit };
                // The operation keeps custody through client cancellation, including
                // publishing its durable replay receipt after a native write.
                let answer = tokio::spawn(async move {
                    Box::pin(node.answer_with_admission(request, admission, physical)).await
                })
                .await
                .unwrap_or_else(|_| {
                    no_authority("the admin unit's task ended abnormally", unit, 503);
                    RetainedAnswer::NativeFailed(unavailable_answer())
                });

                let response = answer.into_response();

                drop(exit);
                response
            }
        },
    ))
}

pub(crate) fn mount_node(
    admin_router: axum::Router,
    request_body_max_bytes: usize,
    app: &Arc<busbar_kernel::state::AppHandle>,
    core: Arc<busbar_kernel::persistence::facade::CoreStore>,
    book: &crate::root::durability::NodeBook,
    retired_operator_key: Option<[u8; 32]>,
    trust: Option<Arc<busbar_kernel::host_services::KernelServices>>,
    retired_breaker: crate::root::adapters::BreakerPolicy,
) -> Result<axum::Router, busbar_kernel::persistence::scoped::Error> {
    let _ = (retired_operator_key, retired_breaker);
    let replay_store = live_replay_store(Arc::clone(&core))?;
    Ok(mount(
        admin_router,
        crate::root::kernel::new_kernel(),
        request_body_max_bytes,
        |dispatch| {
            let mut units = crate::root::kernel::ProductionUnits::admin_over_book(
                dispatch,
                live_admin_door(Arc::clone(app)),
                book,
            );

            let authority_handle = Arc::clone(app);
            units.admin.effect_admission = Some(Arc::new(move |context| {
                let authority_handle = Arc::clone(&authority_handle);
                Box::pin(async move {
                    busbar_kernel::config::transaction::admit_effect(
                        &authority_handle,
                        Some(context),
                    )
                    .await
                })
            }));
            let live = Arc::clone(app);
            units.admin.pools = Arc::new(move |pool: &str| {
                busbar_kernel::governance::group_provision::pool_known(&live.load(), pool)
            });

            units.admin.ledger = Arc::new(super::CountsLedger::new(Arc::clone(app)));
            units.admin.adjuster = super::live_adjuster(Arc::clone(app));

            units.admin.planes = live_planes(Arc::clone(app));

            units.admin.node_amendments = Some(Arc::clone(&app.load().amendments));
            units.admin.records = Some(live_records(Arc::clone(&core)));

            units.admin.replay_store = Some(Arc::clone(&replay_store));

            units.admin.trust.clone_from(&trust);

            match app.load().governance.clone() {
                Some(gov) => {
                    units.with_auth_bindings(crate::root::kernel::auth_bindings::AuthBindings::new(
                        Arc::new(crate::root::kernel::auth_bindings::GovernanceDirectory::new(gov)),
                    ))
                }
                None => units,
            }
        },
    ))
}

pub(crate) fn served_here(resolved: &ResolvedVerb) -> bool {
    kernel_verb(resolved).is_none_or(busbar_core_admin::verb::effect_bound)
}

#[cfg(test)]
#[path = "tests/admin_path_without_plane_face.rs"]
mod admin_path_without_plane_face;
