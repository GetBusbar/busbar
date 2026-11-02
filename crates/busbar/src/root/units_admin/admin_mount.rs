use super::*;

#[cfg(feature = "root-admin")]
pub struct AdminNode {
    pub(super) kernel: busbar_kernel::teller::Kernel,
    pub(super) units: crate::root::kernel::ProductionUnits,
    pub(super) next_key: std::sync::atomic::AtomicU64,
}

#[cfg(feature = "root-admin")]
impl AdminNode {
    #[must_use]
    pub fn new(
        kernel: busbar_kernel::teller::Kernel,
        units: crate::root::kernel::ProductionUnits,
    ) -> Self {
        AdminNode {
            kernel,
            units,
            next_key: std::sync::atomic::AtomicU64::new(1),
        }
    }

    pub fn next_unit(&self) -> u64 {
        self.next_key
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    pub fn answer(&self, request: AdminRequest) -> AdminAnswer {
        let key = UnitKey::new(request.unit);

        let arrived_at = request.at;
        let mut walk = AdminWalk::new(request);
        let ended = decide(&self.units, &mut walk);
        let facts = audit(&walk, &ended);
        let answer = walk
            .answer
            .take()
            .unwrap_or_else(|| refused_answer(ended, &walk.request));

        self.seal(key, arrived_at, walk.principal.as_ref(), facts, ended);
        answer
    }

    fn seal(
        &self,
        key: UnitKey,
        arrived_at: u64,
        principal: Option<&PrincipalId>,
        facts: busbar_contract::AuditFacts,
        ended: Outcome,
    ) {
        use busbar_kernel_audit::{AuditInputs, Controls, OutcomeFacts, Subject, Usage, What};
        let card = crate::root::kernel::ROOT_CARD.pin();
        let arrived_ms = arrived_at.saturating_mul(1_000);
        let subject = principal.map_or(Subject::Arrival, |p| {
            Subject::PrincipalId(p.as_str().to_string())
        });
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

            mono: key.get(),
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
        };
        let token = self.kernel.durability_token();
        let sealed = self
            .units
            .durability
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .seal_unit(
                inputs,
                busbar_kernel::teller::verb_audit_pass(&self.kernel),
                &token,
            );
        if let Err(lost) = sealed {
            tracing::error!(
                step = lost.step().as_str(),
                unit = key.get(),
                "the journal lost an admin unit's audit record: it is sealed on the chain and \
                 cached, and a restart will not read it back"
            );
        }
    }
}

#[cfg(feature = "root-admin")]
pub(crate) struct ExitPath {
    pub(super) unit: u64,
}

#[cfg(feature = "root-admin")]
impl Drop for ExitPath {
    fn drop(&mut self) {
        busbar_core_admin::restart::UnitDrain::of_unit(self.unit).release();
    }
}

#[cfg(feature = "root-admin")]
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

#[cfg(feature = "root-admin")]
pub(crate) fn is_credential_refusal(outcome: Outcome) -> bool {
    matches!(
        outcome,
        Outcome::Refused(_, ReasonCode::Unauthenticated | ReasonCode::Revoked)
            | Outcome::Failed(_, ReasonCode::Unauthenticated | ReasonCode::Revoked)
    )
}

#[cfg(feature = "root-admin")]
pub(crate) fn is_scope_refusal(outcome: Outcome) -> bool {
    matches!(
        outcome,
        Outcome::Refused(_, ReasonCode::ScopeDenied) | Outcome::Failed(_, ReasonCode::ScopeDenied)
    )
}

#[cfg(feature = "root-admin")]
pub(crate) fn is_rate_refusal(outcome: Outcome) -> bool {
    matches!(
        outcome,
        Outcome::Refused(_, ReasonCode::RateLimited) | Outcome::Failed(_, ReasonCode::RateLimited)
    )
}

#[cfg(feature = "root-admin")]
pub(crate) fn rate_limited_answer() -> AdminAnswer {
    let refused = busbar_kernel::admin::gate::ApiError::RateLimited;
    AdminAnswer {
        status: refused.http_status(),
        headers: vec![
            (
                "retry-after".to_string(),
                busbar_core_admin::rate::MUTATION_RATE_WINDOW_SECS.to_string(),
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

#[cfg(feature = "root-admin")]
pub(crate) fn scope_answer(request: &AdminRequest) -> AdminAnswer {
    let needed = busbar_kernel::admin::scope::admin_required_scope(&request.method, &request.path);
    error_answer_with_message(
        403,
        "forbidden",
        &format!(
            "insufficient scope: this endpoint requires `{}`",
            needed.as_str()
        ),
    )
}

#[cfg(feature = "root-admin")]
pub(crate) const DOOR_STATUS: u16 = 401;

#[cfg(feature = "root-admin")]
pub(crate) const DOOR_CODE: &str = "unauthorized";

#[cfg(feature = "root-admin")]
pub(crate) const DOOR_MESSAGE: &str =
    "missing or invalid admin credential (Bearer or x-admin-token)";

#[cfg(feature = "root-admin")]
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

#[cfg(feature = "root-admin")]
pub(crate) fn answer_for(outcome: Outcome) -> AdminAnswer {
    use busbar_contract::abi::plane::{class_of, RefusalClass};
    let (status, code) = match outcome {
        Outcome::Refused(_, reason) | Outcome::Failed(_, reason) => match class_of(reason) {
            RefusalClass::Unreadable => (400, "invalid_request"),

            RefusalClass::NotFound => (404, "not_found"),

            RefusalClass::QuotaExhausted | RefusalClass::Busy => (429, "rate_limited"),

            RefusalClass::Unavailable => (503, "unavailable"),
            RefusalClass::Rejected
            | RefusalClass::Unauthenticated
            | RefusalClass::Forbidden
            | RefusalClass::TooLarge
            | RefusalClass::Throttled
            | RefusalClass::Unreachable
            | RefusalClass::Timeout
            | RefusalClass::PlaneFault
            | RefusalClass::NodeFault => (403, "forbidden"),
        },
        _ => (403, "forbidden"),
    };
    error_answer(status, code)
}

#[cfg(feature = "root-admin")]
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

#[cfg(feature = "root-admin")]
pub(crate) const AMEND_RATE_HISTORY_PATH: &str = "/api/v1/admin/ledger/amend-rate-history";

#[cfg(feature = "root-admin")]
pub(crate) const AMEND_RATE_HISTORY_SHAPE: &str = "amend-rate-history: body must carry effective_from, reason, and rates and/or per_request_fee; rate_card/window is the pre-1.6.0 shape";

#[cfg(feature = "root-admin")]
pub(crate) fn explained_answer(request: &AdminRequest, outcome: Outcome) -> Option<AdminAnswer> {
    use busbar_contract::abi::plane::{class_of, RefusalClass};
    let unreadable = matches!(
        outcome,
        Outcome::Refused(_, reason) | Outcome::Failed(_, reason)
            if class_of(reason) == RefusalClass::Unreadable
    );
    let path = request.path.split('?').next().unwrap_or("");
    (unreadable && request.method == "POST" && path == AMEND_RATE_HISTORY_PATH)
        .then(|| error_answer_with_message(400, "invalid_request", AMEND_RATE_HISTORY_SHAPE))
}

#[cfg(feature = "root-admin")]
pub(crate) fn unavailable_answer() -> AdminAnswer {
    error_answer(503, "unavailable")
}

#[cfg(feature = "root-admin")]
pub(crate) type Errand = (AdminRequest, std::sync::mpsc::SyncSender<AdminAnswer>);

#[cfg(feature = "root-admin")]
pub struct RouterDispatch {
    errands: tokio::sync::mpsc::UnboundedSender<Errand>,
}

#[cfg(feature = "root-admin")]
use busbar_core_admin::keys::KeyReplayCache;

#[cfg(feature = "root-admin")]
impl RouterDispatch {
    #[must_use]
    pub fn new(
        inner: axum::Router,
        runtime: &tokio::runtime::Handle,
        replays: Arc<KeyReplayCache>,
    ) -> Self {
        let (errands, mut inbox) = tokio::sync::mpsc::unbounded_channel::<Errand>();
        runtime.spawn(async move {
            while let Some((request, reply)) = inbox.recv().await {
                let inner = inner.clone();
                let replays = replays.clone();

                tokio::spawn(async move {
                    let unit = request.unit;
                    let answer = busbar_core_admin::restart::UnitDrain::of_unit(unit)
                        .scoping(call(inner, &request, &replays))
                        .await;
                    let _ = reply.send(answer);
                });
            }
        });
        RouterDispatch { errands }
    }
}

#[cfg(feature = "root-admin")]
async fn call(
    inner: axum::Router,
    request: &AdminRequest,
    replays: &Arc<KeyReplayCache>,
) -> AdminAnswer {
    use tower::ServiceExt;

    let mut builder = axum::http::Request::builder()
        .method(request.method.as_str())
        .uri(request.path.as_str());
    for (name, value) in &request.headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    builder = builder.extension(Arc::clone(replays));
    let Ok(http) = builder.body(axum::body::Body::from(request.body.clone())) else {
        return error_answer(400, "invalid_request");
    };

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

#[cfg(feature = "root-admin")]
impl AdminDispatch for RouterDispatch {
    fn execute(&self, _verb: KernelVerb, request: &AdminRequest) -> AdminAnswer {
        let (reply, answer) = std::sync::mpsc::sync_channel(1);
        if self.errands.send((request.clone(), reply)).is_err() {
            return unavailable_answer();
        }
        answer.recv().unwrap_or_else(|_| unavailable_answer())
    }
}

#[cfg(feature = "root-admin")]
pub(crate) const ADMIN_TOKEN_HEADER: &str = "x-admin-token";

#[cfg(feature = "root-admin")]
pub(crate) fn presented_credential(headers: &axum::http::HeaderMap) -> Option<String> {
    let authorization = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            let trimmed = value.trim_start();
            match trimmed.split_once(' ') {
                Some((scheme, rest)) if scheme.eq_ignore_ascii_case("bearer") => {
                    rest.trim_start().to_string()
                }
                _ => trimmed.to_string(),
            }
        })
        .filter(|credential| !credential.is_empty());

    authorization.or_else(|| {
        headers
            .get(ADMIN_TOKEN_HEADER)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
            .filter(|credential| !credential.is_empty())
    })
}

#[cfg(feature = "root-admin")]
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

#[cfg(feature = "root-admin")]
pub(crate) fn http_response(answer: AdminAnswer) -> axum::http::Response<axum::body::Body> {
    let mut response = axum::http::Response::builder().status(answer.status);
    for (name, value) in &answer.headers {
        response = response.header(name.as_str(), value.as_str());
    }
    response
        .body(axum::body::Body::from(answer.body))
        .unwrap_or_else(|_| {
            axum::http::Response::builder()
                .status(500)
                .body(axum::body::Body::empty())
                .expect("an empty 500 always builds")
        })
}

#[cfg(feature = "root-admin")]
pub fn mount(
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
                use tower::ServiceExt;

                let path = req.uri().path().to_string();
                let claimed = path.starts_with(busbar_contract::surface::ADMIN_PREFIX);

                let declared =
                    busbar_core_admin::admin_codec::verbs::resolve(req.method().as_str(), &path)
                        .is_some_and(|resolved| served_here(&resolved));
                if !claimed || !declared {
                    return inner.oneshot(req).await.unwrap_or_else(|e| match e {});
                }

                let declared = req
                    .headers()
                    .get(axum::http::header::CONTENT_LENGTH)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<usize>().ok());
                if declared.is_some_and(|len| len > request_body_max_bytes) {
                    return inner.oneshot(req).await.unwrap_or_else(|e| match e {});
                }

                let (parts, body) = req.into_parts();

                let Ok(bytes) = axum::body::to_bytes(body, request_body_max_bytes).await else {
                    return http_response(error_answer(400, "invalid_request"));
                };

                let unit = node.next_unit();
                let request = AdminRequest {
                    method: parts.method.as_str().to_string(),
                    path: parts
                        .uri
                        .path_and_query()
                        .map_or_else(|| parts.uri.path().to_string(), ToString::to_string),
                    credential: presented_credential(&parts.headers),
                    headers: header_pairs(&parts.headers),
                    body: bytes.to_vec(),
                    at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.as_secs()),
                    unit,
                };

                let exit = ExitPath { unit };
                let answer = tokio::task::spawn_blocking(move || node.answer(request))
                    .await
                    .unwrap_or_else(|_| unavailable_answer());

                let response = http_response(answer);

                drop(exit);
                response
            }
        },
    ))
}

#[cfg(feature = "root-admin")]
pub fn mount_node(
    admin_router: axum::Router,
    request_body_max_bytes: usize,
    app: &Arc<busbar_kernel::state::AppHandle>,
    book: &crate::root::durability::NodeBook,
    retired_operator_key: Option<[u8; 32]>,
    late: &Arc<crate::root::serve::LateServices>,
    retired_breaker: crate::root::adapters::BreakerPolicy,
) -> axum::Router {
    let _ = (retired_operator_key, retired_breaker);
    mount(
        admin_router,
        crate::root::kernel::new_kernel(),
        request_body_max_bytes,
        |dispatch| {
            let mut units = crate::root::kernel::ProductionUnits::admin_over_book(
                dispatch,
                live_admin_door(Arc::clone(app)),
                book,
            );

            let live = Arc::clone(app);
            units.admin.pools = Arc::new(move |pool: &str| {
                busbar_kernel::governance::group_provision::pool_known(&live.load(), pool)
            });

            units.admin.ledger = Arc::new(super::CountsLedger::new(Arc::clone(app)));
            units.admin.adjuster = super::live_adjuster(Arc::clone(app));

            units.admin.planes = live_planes(Arc::clone(app));

            units.admin.node_amendments = Some(Arc::clone(&app.load().amendments));
            units.admin.records = Some(live_records(Arc::clone(app)));

            units.admin.replay_store = Some(live_replay_store(Arc::clone(app)));

            let late = Arc::clone(late);
            units.admin.trust = Arc::new(move || late.kernel());

            match app.load().governance.clone() {
                Some(gov) => {
                    units.with_auth_bindings(crate::root::kernel::auth_bindings::AuthBindings::new(
                        Arc::new(crate::root::kernel::auth_bindings::GovernanceDirectory::new(gov)),
                    ))
                }
                None => units,
            }
        },
    )
}

#[cfg(feature = "root-admin")]
pub(crate) fn served_here(resolved: &ResolvedVerb) -> bool {
    kernel_verb(resolved).is_none_or(busbar_core_admin::verb::effect_bound)
}

#[cfg(test)]
#[path = "tests/admin_path_without_plane_face.rs"]
mod admin_path_without_plane_face;
