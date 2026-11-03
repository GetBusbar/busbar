use super::*;

fn a_fresh_unit() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

fn a_request() -> AdminRequest {
    AdminRequest {
        method: "GET".to_string(),
        path: "/api/v1/admin/audit?limit=4".to_string(),
        credential: Some("admin-token".to_string()),
        headers: vec![("accept".to_string(), "application/json".to_string())],
        body: Vec::new(),
        at: 1_700_000_000,
        unit: a_fresh_unit(),
    }
}

#[test]
fn debug_redacts_the_presented_credential_and_the_header_it_arrived_in() {
    const SECRET: &str = "a-distinctive-admin-secret-7f31c9";
    let request = AdminRequest {
        method: "POST".to_string(),
        path: "/api/v1/admin/config/apply".to_string(),
        credential: Some(SECRET.to_string()),
        headers: vec![
            ("authorization".to_string(), format!("Bearer {SECRET}")),
            ("x-admin-token".to_string(), SECRET.to_string()),
            ("content-type".to_string(), "application/json".to_string()),
        ],
        body: b"{}".to_vec(),
        at: 1_700_000_000,
        unit: a_fresh_unit(),
    };

    let rendered = format!("{request:?}");
    assert!(
        !rendered.contains(SECRET),
        "Debug must never carry the presented credential — not in the field, not in the header it \
         arrived in. Got: {rendered}"
    );
    assert!(
        rendered.matches("<redacted>").count() >= 3,
        "the field and BOTH carriers must be redacted, got: {rendered}"
    );

    assert!(rendered.contains("AdminRequest"), "got: {rendered}");
    assert!(
        rendered.contains("/api/v1/admin/config/apply"),
        "got: {rendered}"
    );
    assert!(
        rendered.contains("content-type") && rendered.contains("application/json"),
        "a header that carries no credential still prints as itself, got: {rendered}"
    );
    assert!(rendered.contains("\"POST\""), "got: {rendered}");

    let nothing_presented = AdminRequest {
        credential: None,
        headers: vec![(
            "authorization".to_string(),
            "Bearer not-what-was-presented".to_string(),
        )],
        ..request
    };
    let rendered = format!("{nothing_presented:?}");
    assert!(rendered.contains("credential: None"), "got: {rendered}");
    assert!(
        !rendered.contains("<redacted>"),
        "nothing was presented, so nothing is redacted, got: {rendered}"
    );
    assert!(
        rendered.contains("Bearer not-what-was-presented"),
        "got: {rendered}"
    );
}

#[cfg(feature = "root-admin")]
#[test]
fn the_door_answers_the_published_releases_own_bytes() {
    const GOLDEN: &str = include_str!(concat!(
        env!("BUSBAR_CORE_DIR"),
        "/../../testing/shadow-oracle/golden/1.5.5/cells/admin.ops__GetConfig__unauth.json"
    ));
    let cell: serde_json::Value = serde_json::from_str(GOLDEN).expect("the golden cell parses");
    let answer = door_answer();
    assert!(
        answer.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("www-authenticate") && value == "Bearer"
        }),
        "an unidentified admin caller receives the supported authentication challenge"
    );

    assert_eq!(
        u64::from(answer.status),
        cell["status"].as_u64().expect("the cell records a status"),
        "the door's status is the recorded one"
    );

    let recorded = serde_json::to_vec(&cell["body"]["json"]).expect("the recorded body serialises");
    assert_eq!(
        answer.body, recorded,
        "the door's bytes are the recorded answer's bytes"
    );
    assert_eq!(
        answer.body.len().to_string(),
        cell["headers"]["content-length"]
            .as_str()
            .expect("the cell records a content length"),
        "the length the caller is told is the length the recorded answer had"
    );
}

#[cfg(feature = "root-admin")]
#[test]
fn a_grant_that_does_not_reach_the_endpoint_is_answered_with_the_scope_it_needed() {
    let answer = scope_answer(&a_request());
    assert_eq!(answer.status, 403);
    assert_eq!(
        String::from_utf8(answer.body).expect("the envelope is text"),
        r#"{"error":{"code":"forbidden","message":"insufficient scope: this endpoint requires `read-only`"}}"#
    );
}

#[cfg(feature = "root-admin")]
#[tokio::test]
async fn a_walk_dropped_before_its_answer_still_releases_the_drain_it_asked_for() {
    busbar_core_admin::restart::drain_released_at_exit();
    let unit = a_fresh_unit();

    busbar_core_admin::restart::UnitDrain::of_unit(unit)
        .scoping(async {
            busbar_core_admin::restart::begin_drain();
        })
        .await;

    let exit = ExitPath { unit };
    drop(exit);

    assert!(
        !busbar_core_admin::restart::UnitDrain::of_unit(unit).release(),
        "the drop released the ask, so there is nothing left for a later exit to release — \
         which is the leak: without the guard this would still be standing"
    );
}

#[cfg(feature = "root-admin")]
#[tokio::test]
async fn a_body_the_wrap_will_not_read_is_refused_rather_than_emptied() {
    use tower::ServiceExt;

    let inner = axum::Router::new().fallback(axum::routing::any(|| async { "the surface" }));
    let wrapped = mount(inner, busbar_kernel::teller::Kernel::new(), 4, |dispatch| {
        crate::root::kernel::ProductionUnits::admin_only(dispatch, open_door())
    });

    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/api/v1/admin/keys")
        .body(axum::body::Body::from(b"0123456789".to_vec()))
        .expect("the request builds");
    let response = wrapped
        .clone()
        .oneshot(request)
        .await
        .expect("the router answers");
    assert_eq!(response.status(), 400);

    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/api/v1/admin/keys")
        .header(axum::http::header::CONTENT_LENGTH, "10")
        .body(axum::body::Body::from(b"0123456789".to_vec()))
        .expect("the request builds");
    let response = wrapped.oneshot(request).await.expect("the router answers");
    assert_eq!(
        response.status(),
        200,
        "the request reached the surface below, which is where the cap is enforced"
    );
}

#[cfg(feature = "root-admin")]
#[test]
fn an_unreadable_amendment_is_told_what_the_body_must_carry() {
    let refused = Outcome::Refused(
        busbar_contract::caps::StepName::Route,
        ReasonCode::DecodeFailed,
    );
    let amend = AdminRequest {
        method: "POST".to_string(),
        path: "/api/v1/admin/ledger/amend-rate-history".to_string(),
        body: br#"{"rate_card":{},"window":{}}"#.to_vec(),
        ..a_request()
    };
    let answer = explained_answer(&amend, refused).expect("the amendment's refusal is explained");
    assert_eq!(answer.status, 400);
    assert_eq!(
        answer.body,
        br#"{"error":{"code":"invalid_request","message":"amend-rate-history: body must carry effective_from, reason, and rates and/or per_request_fee; rate_card/window is the pre-1.6.0 shape"}}"#.to_vec()
    );

    assert!(explained_answer(&a_request(), refused).is_none());
    let unavailable = Outcome::Failed(
        busbar_contract::caps::StepName::Route,
        ReasonCode::DurabilityUnavailable,
    );
    assert!(explained_answer(&amend, unavailable).is_none());
}

#[cfg(feature = "root-admin")]
#[test]
fn a_refused_units_status_is_the_one_its_ending_earned() {
    let status = |reason| {
        answer_for(Outcome::Refused(
            busbar_contract::caps::StepName::Admit,
            reason,
        ))
    };
    assert_eq!(status(ReasonCode::DecodeFailed).status, 400);
    assert_eq!(status(ReasonCode::NoDestination).status, 404);
    assert_eq!(status(ReasonCode::InFlightCap).status, 429);
    assert_eq!(status(ReasonCode::OverBudget).status, 429);
    assert_eq!(status(ReasonCode::DurabilityUnavailable).status, 503);
    assert_eq!(status(ReasonCode::ScopeDenied).status, 403);
    assert_eq!(status(ReasonCode::Unauthenticated).status, 403);
    assert_eq!(
        status(ReasonCode::PlanePanic).status,
        403,
        "an ending nobody mapped keeps the pinned answer rather than inventing one"
    );

    assert_eq!(
        answer_for(Outcome::Failed(
            busbar_contract::caps::StepName::Route,
            ReasonCode::DurabilityUnavailable
        )),
        error_answer(503, "unavailable")
    );

    assert_eq!(
        status(ReasonCode::NoDestination).body,
        br#"{"error":{"code":"not_found","message":"not_found"}}"#.to_vec()
    );
    assert_eq!(
        status(ReasonCode::NoDestination).headers,
        vec![("content-type".to_string(), "application/json".to_string())]
    );
}

#[test]
fn the_audit_doors_carry_no_credential_into_the_sealed_facts() {
    for ended in [
        Outcome::Completed,
        Outcome::Refused(
            busbar_contract::caps::StepName::Approve,
            ReasonCode::ScopeDenied,
        ),
    ] {
        let mut request = a_request();
        request.method = "PUT".to_string();
        request.path = "/api/v1/admin/config/settings".to_string();
        request.credential = Some("sk-live-the-presented-secret".to_string());
        let mut walk = AdminWalk::new(request);
        let _ = decode(&mut walk);
        let _ = verify(&mut walk, &PrincipalId::new("key_operator_7"));

        let facts = audit(&walk, &ended);
        assert!(
            !format!("{facts:?}").contains("sk-live-the-presented-secret"),
            "the presented credential reached the sealed facts"
        );
    }
}

#[test]
#[cfg(feature = "root-admin")]
fn the_formerly_irreducible_verbs_are_authorized_by_the_grant_alone() {
    let admin = crate::root::kernel::new_kernel().admin_token();

    let under = |path: &str, granted: VerbScope| -> Result<(), ReasonCode> {
        let binding = AdminBinding::new(Arc::new(AnsweringDispatch), open_door());
        let mut request = a_request();
        request.method = "POST".to_string();
        request.path = path.to_string();

        request.body = b"{\"backup_ref\":\"backup-1\"}".to_vec();
        let mut walk = AdminWalk::new(request);
        decode(&mut walk).expect("the plane's table declares this operation");
        walk.granted = Some(granted);
        route(&binding, None, &admin, &mut walk)
    };

    for path in [
        "/api/v1/admin/chain-break",
        "/api/v1/admin/store-restore",
        "/api/v1/admin/commit-upgrade",
        "/api/v1/admin/adjust",
        "/api/v1/admin/ledger/amend-rate-history",
    ] {
        assert_ne!(
            under(path, VerbScope::Full),
            Err(ReasonCode::ScopeDenied),
            "{path}: a grant that covers the verb was refused with no operator key configured"
        );
        assert_eq!(
            under(path, VerbScope::ReadOnly),
            Err(ReasonCode::ScopeDenied),
            "{path}: a grant that does not cover the verb was not refused"
        );
    }
}

#[cfg(feature = "root-admin")]
fn a_door_answering(door: busbar_kernel::auth::AdminDoor) -> AdminDoorFn {
    Arc::new(move |_: &AdminRequest| busbar_kernel::auth::AdminVerdict::from(door.clone()))
}

#[cfg(feature = "root-admin")]
fn listed_door(named: &[&str], needs: Scope) -> busbar_kernel::auth::AdminDoor {
    busbar_kernel::auth::AdminDoor::Listed(
        busbar_contract::auth::Principal::from_id("acct:verb-listed"),
        busbar_contract::authz::Grants::of(needs),
        busbar_kernel::auth::VerbAllowList {
            rungs: busbar_contract::authz::Grants::default(),
            named: named.iter().map(|verb| verb.to_string()).collect(),
        },
    )
}

#[cfg(feature = "root-admin")]
fn approved_under(
    door: busbar_kernel::auth::AdminDoor,
    method: &str,
    path: &str,
) -> Result<(), ReasonCode> {
    let binding = AdminBinding::new(Arc::new(AnsweringDispatch), a_door_answering(door));
    let mut request = a_request();
    request.method = method.to_string();
    request.path = path.to_string();
    let mut walk = AdminWalk::new(request);
    decode(&mut walk).expect("the plane's table declares this operation");
    let bindings = crate::root::auth_bindings::AuthBindings::without_directory();
    authenticate(&binding, &bindings, &mut walk)?;
    approve(&walk)
}

#[cfg(feature = "root-admin")]
fn answered_under(door: busbar_kernel::auth::AdminDoor, request: AdminRequest) -> AdminAnswer {
    let units = crate::root::kernel::ProductionUnits::admin_only(
        Arc::new(AnsweringDispatch),
        a_door_answering(door),
    );
    AdminNode::new(crate::root::kernel::new_kernel(), units).answer(request)
}

#[cfg(feature = "root-admin")]
#[test]
fn a_verb_the_allow_list_names_is_admitted() {
    let door = || listed_door(&["post_keys", "get_audit"], Scope::Full);
    assert_eq!(
        approved_under(door(), "POST", "/api/v1/admin/keys"),
        Ok(()),
        "a mutation the list names is admitted"
    );
    assert_eq!(
        approved_under(door(), "GET", "/api/v1/admin/audit?limit=4"),
        Ok(()),
        "a read the list names is admitted"
    );
    assert_eq!(
        answered_under(door(), a_request()).status,
        200,
        "and the named read reaches its operation"
    );
}

#[cfg(feature = "root-admin")]
#[test]
fn a_verb_the_allow_list_does_not_name_is_refused_with_the_scope_answer() {
    let door = || listed_door(&["post_keys"], Scope::Full);
    assert_eq!(
        approved_under(door(), "POST", "/api/v1/admin/hooks"),
        Err(ReasonCode::ScopeDenied),
        "a mutation the list does not name is refused at approve"
    );
    assert_eq!(
        approved_under(door(), "GET", "/api/v1/admin/audit?limit=4"),
        Err(ReasonCode::ScopeDenied),
        "a read the list does not name is refused at approve"
    );
    let read = a_request();
    let refused = answered_under(door(), read.clone());
    assert_eq!(refused, scope_answer(&read), "the existing scope refusal");
    assert_eq!(refused.status, 403);
    assert_eq!(
        String::from_utf8(refused.body).expect("the envelope is text"),
        "{\"error\":{\"code\":\"forbidden\",\"message\":\"insufficient scope: this endpoint \
         requires `read-only`\"}}"
    );
    let mut mutation = a_request();
    mutation.method = "POST".to_string();
    mutation.path = "/api/v1/admin/hooks".to_string();
    assert_eq!(
        answered_under(door(), mutation.clone()),
        scope_answer(&mutation),
        "a mutation the list does not name is answered with the scope it needed"
    );
}

#[cfg(feature = "root-admin")]
#[test]
fn a_rung_held_whole_beside_a_list_admits_exactly_as_full() {
    let full = || {
        busbar_kernel::auth::AdminDoor::Identified(
            busbar_contract::auth::Principal::from_id("acct:verb-listed"),
            busbar_contract::authz::Grants::of(Scope::Full),
        )
    };
    let whole = || {
        busbar_kernel::auth::AdminDoor::Listed(
            busbar_contract::auth::Principal::from_id("acct:verb-listed"),
            busbar_contract::authz::Grants::of(Scope::Full),
            busbar_kernel::auth::VerbAllowList {
                rungs: busbar_contract::authz::Grants::of(Scope::Full),
                named: ["get_audit".to_string()].into_iter().collect(),
            },
        )
    };
    for (method, path) in [
        ("POST", "/api/v1/admin/hooks"),
        ("POST", "/api/v1/admin/keys"),
        ("GET", "/api/v1/admin/audit?limit=4"),
    ] {
        assert_eq!(
            approved_under(full(), method, path),
            Ok(()),
            "{method} {path}"
        );
        assert_eq!(
            approved_under(whole(), method, path),
            approved_under(full(), method, path),
            "{method} {path}: a full rung held whole admits exactly as `full` does"
        );
    }
}

#[cfg(feature = "root-admin")]
#[test]
fn a_grant_with_no_verbs_key_is_decided_by_its_rung_as_before() {
    let rung = |scope: Scope| {
        busbar_kernel::auth::AdminDoor::Identified(
            busbar_contract::auth::Principal::from_id("acct:verb-listed"),
            busbar_contract::authz::Grants::of(scope),
        )
    };
    let read = "/api/v1/admin/audit?limit=4";
    let mutation = "/api/v1/admin/hooks";
    assert_eq!(approved_under(rung(Scope::ReadOnly), "GET", read), Ok(()));
    assert_eq!(
        approved_under(rung(Scope::ReadOnly), "POST", mutation),
        Err(ReasonCode::ScopeDenied)
    );
    assert_eq!(approved_under(rung(Scope::Full), "GET", read), Ok(()));
    assert_eq!(approved_under(rung(Scope::Full), "POST", mutation), Ok(()));
    let mut refused = a_request();
    refused.method = "POST".to_string();
    refused.path = mutation.to_string();
    assert_eq!(
        answered_under(rung(Scope::ReadOnly), refused.clone()),
        scope_answer(&refused)
    );
}

#[test]
fn every_row_the_plane_decodes_names_a_verb_the_unit_knows() {
    let mut unmatched = Vec::new();
    for row in busbar_core_admin::admin_codec::verbs::table() {
        if kernel_verb(&row).is_none() {
            unmatched.push(row.verb);
        }
    }
    assert!(
        unmatched.is_empty(),
        "rows with no kernel verb: {unmatched:?}"
    );
}

#[test]
fn the_rate_class_is_the_shipped_table_and_not_the_default() {
    assert_eq!(
        mutation_class(KernelVerb::PostConfigApply),
        MutationClass::Config
    );
    assert_eq!(
        mutation_class(KernelVerb::PostConfigReload),
        MutationClass::Config
    );
    assert_eq!(
        mutation_class(KernelVerb::PostRestart),
        MutationClass::Config
    );
    assert_eq!(
        mutation_class(KernelVerb::PutAdminAuth),
        MutationClass::Config
    );
    assert_eq!(mutation_class(KernelVerb::PostKeys), MutationClass::Crud);
    assert_eq!(
        mutation_class(KernelVerb::PostPluginsInspect),
        MutationClass::PluginInspect
    );

    assert_eq!(
        mutation_class(KernelVerb::GetAudit),
        MutationClass::Forbidden
    );
    assert_eq!(MutationClass::Forbidden.limit(), 0);
    assert!(
        busbar_kernel::admin::scope::admin_required_scope("GET", "/api/v1/admin/audit")
            == Scope::ReadOnly
    );
}

#[test]
fn the_two_spellings_of_the_scope_split_agree() {
    assert_eq!(scope_as_verb_scope(Scope::ReadOnly), VerbScope::ReadOnly);
    assert_eq!(scope_as_verb_scope(Scope::Full), VerbScope::Full);
    assert!(VerbScope::Full.allows(VerbScope::ReadOnly));
    assert!(!VerbScope::ReadOnly.allows(VerbScope::Full));
}

#[test]
fn a_replayed_idempotency_key_answers_the_first_answers_bytes() {
    let store: Arc<dyn busbar_contract::records::RecordStore> = crate::root::real_store::records();
    let held = Arc::clone(&store);
    let replay_store: bound::ReplayStore = Arc::new(move || Some(Arc::clone(&held)));
    let request = AdminRequest {
        method: "POST".to_string(),
        path: "/api/v1/admin/commit-upgrade".to_string(),
        credential: None,
        headers: vec![("idempotency-key".to_string(), "idem-1".to_string())],
        body: br#"{"version":"once"}"#.to_vec(),
        at: 1_700_000_000,
        unit: a_fresh_unit(),
    };
    let minted = std::sync::atomic::AtomicUsize::new(0);

    let mint = || {
        let n = minted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(bound::EffectAnswer::applied(AdminAnswer {
            status: 201,
            headers: vec![
                ("content-type".to_string(), "application/json".to_string()),
                ("location".to_string(), format!("/api/v1/admin/keys/vk_{n}")),
            ],
            body: format!(r#"{{"id":"vk_{n}","secret":"once-{n}"}}"#).into_bytes(),
        }))
    };
    let first_answer = AdminAnswer {
        status: 201,
        headers: vec![
            ("content-type".to_string(), "application/json".to_string()),
            (
                "location".to_string(),
                "/api/v1/admin/keys/vk_0".to_string(),
            ),
        ],
        body: br#"{"id":"vk_0","secret":"once-0"}"#.to_vec(),
    };
    let node = bound::ReplayCache::new();
    let ask = |cache: &bound::ReplayCache| {
        bound::replayable(
            cache,
            Some(&replay_store),
            bound::ReplayScope {
                verb: KernelVerb::CommitUpgrade,
                actor: "operator",
            },
            &request,
            &request.body,
            None,
            mint,
        )
        .expect("the write answers")
    };

    let first = ask(&node);
    assert_eq!(first, first_answer, "the first call runs and answers");
    let again = ask(&node);
    let restarted = ask(&bound::ReplayCache::new());
    let sibling = ask(&bound::ReplayCache::new());
    for (who, replayed) in [
        ("the same node", &again),
        ("a restarted node", &restarted),
        ("another node", &sibling),
    ] {
        assert_eq!(replayed.status, first.status, "{who}: the first status");
        assert_eq!(replayed.headers, first.headers, "{who}: the first headers");
        assert_eq!(replayed.body, first.body, "{who}: the first body's bytes");
    }
    assert_eq!(
        minted.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the one-time secret was minted once"
    );
}

#[cfg(feature = "root-admin")]
struct AnsweringDispatch;

#[cfg(feature = "root-admin")]
impl AdminDispatch for AnsweringDispatch {
    fn execute(&self, _verb: KernelVerb, _request: &AdminRequest) -> AdminAnswer {
        AdminAnswer {
            status: 200,
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            body: br#"{"entries":[]}"#.to_vec(),
        }
    }
}

#[cfg(feature = "root-admin")]
struct Denylist(bool);

#[cfg(feature = "root-admin")]
impl crate::root::auth_bindings::VirtualKeyDirectory for Denylist {
    fn verify(
        &self,
        credential: &str,
        _now: u64,
        _expected_aud: Option<&str>,
    ) -> Option<crate::root::auth_bindings::KeyFacts> {
        (credential == "admin-token").then(|| crate::root::auth_bindings::KeyFacts {
            id: "key-admin-1".to_string(),
            name: "the operator credential these cells present".to_string(),
        })
    }

    fn revoked(&self, _credential: &str) -> bool {
        self.0
    }
}

#[cfg(feature = "root-admin")]
struct IdentifiesOperator;

#[cfg(feature = "root-admin")]
impl busbar_kernel_identity::module::AuthModule for IdentifiesOperator {
    fn name(&self) -> &'static str {
        "identifies-operator"
    }
    fn authenticate(&self, candidate: Option<&str>) -> busbar_kernel_identity::module::AuthOutcome {
        match candidate {
            Some("admin-token") => busbar_kernel_identity::module::AuthOutcome::Identify(
                busbar_kernel_identity::principal::Principal::from_id(
                    crate::root::auth_bindings::ADMIN_PRINCIPAL_ID,
                ),
            ),
            _ => busbar_kernel_identity::module::AuthOutcome::Pass,
        }
    }
}

#[cfg(feature = "root-admin")]
fn a_door_that_identifies_the_operator() -> busbar_kernel_identity::AuthChain {
    busbar_kernel_identity::AuthChain::new(
        vec![busbar_kernel_identity::chain::ChainEntry {
            provider: "identifies-operator".to_string(),
            module: Box::new(IdentifiesOperator),
        }],
        false,
    )
}

#[cfg(feature = "root-admin")]
fn answer_under_denylist(revoked: bool) -> AdminAnswer {
    let units = crate::root::kernel::ProductionUnits::admin_only(
        Arc::new(AnsweringDispatch),
        door_of_chain(a_door_that_identifies_the_operator()),
    )
    .with_auth_bindings(crate::root::auth_bindings::AuthBindings::new(Arc::new(
        Denylist(revoked),
    )));
    AdminNode::new(crate::root::kernel::new_kernel(), units).answer(a_request())
}

#[cfg(feature = "root-admin")]
#[test]
fn a_revoked_credential_is_refused_before_the_operation_runs() {
    assert_eq!(
        answer_under_denylist(false).status,
        200,
        "a credential on nobody's denylist reaches the operation"
    );
    let refused = answer_under_denylist(true);
    assert_eq!(
        refused,
        door_answer(),
        "a credential the node took away is the door's answer, written and not re-run"
    );
}

#[cfg(feature = "root-admin")]
#[test]
fn an_open_door_does_not_consult_the_denylist_for_a_string_it_never_identified() {
    let units =
        crate::root::kernel::ProductionUnits::admin_only(Arc::new(AnsweringDispatch), open_door())
            .with_auth_bindings(crate::root::auth_bindings::AuthBindings::new(Arc::new(
                Denylist(true),
            )));
    let answer = AdminNode::new(crate::root::kernel::new_kernel(), units).answer(a_request());
    assert_eq!(
        answer.status, 200,
        "the open door admits, and the denylist is not a probe"
    );
}

#[cfg(feature = "root-admin")]
struct IdentifiesSomebodyElse;

#[cfg(feature = "root-admin")]
impl busbar_kernel_identity::module::AuthModule for IdentifiesSomebodyElse {
    fn name(&self) -> &'static str {
        "identifies-somebody-else"
    }
    fn authenticate(&self, candidate: Option<&str>) -> busbar_kernel_identity::module::AuthOutcome {
        match candidate {
            Some("a-tenants-token") => busbar_kernel_identity::module::AuthOutcome::Identify(
                busbar_kernel_identity::principal::Principal::from_id("acct:not-the-operator"),
            ),
            _ => busbar_kernel_identity::module::AuthOutcome::Pass,
        }
    }
}

#[cfg(feature = "root-admin")]
fn answer_at_the_closed_door(
    door: busbar_kernel_identity::AuthChain,
    credential: Option<&str>,
) -> AdminAnswer {
    let units = crate::root::kernel::ProductionUnits::admin_only(
        Arc::new(AnsweringDispatch),
        door_of_chain(door),
    )
    .with_auth_bindings(crate::root::auth_bindings::AuthBindings::new(Arc::new(
        Denylist(false),
    )));
    let mut request = a_request();
    request.credential = credential.map(str::to_string);
    AdminNode::new(crate::root::kernel::new_kernel(), units).answer(request)
}

#[cfg(feature = "root-admin")]
#[test]
fn a_wrong_or_absent_credential_is_refused_at_the_door() {
    assert_eq!(
        answer_at_the_closed_door(a_door_that_identifies_the_operator(), Some("admin-token"))
            .status,
        200,
        "the control must actually be admitted, or the refusals below prove only that the fixture \
         refuses everything"
    );

    let wrong = answer_at_the_closed_door(
        a_door_that_identifies_the_operator(),
        Some("not-the-admin-token"),
    );
    assert_eq!(
        wrong,
        door_answer(),
        "a credential no arm of the chain identifies must be the door's answer"
    );
    assert_eq!(wrong.status, 401, "and that answer's status is the door's");

    let absent = answer_at_the_closed_door(a_door_that_identifies_the_operator(), None);
    assert_eq!(
        absent,
        door_answer(),
        "a caller who presented NO credential must be the door's answer — this is the arm a step \
         that never reads `request.credential` cannot produce"
    );
    assert_eq!(absent.status, 401, "and that answer's status is the door's");
}

#[cfg(feature = "root-admin")]
#[test]
fn the_refusal_the_loop_hands_back_is_the_frozen_envelope_byte_for_byte() {
    let absent = answer_at_the_closed_door(a_door_that_identifies_the_operator(), None);
    assert_eq!(absent.status, 401);
    assert_eq!(
        String::from_utf8(absent.body).expect("the envelope is text"),
        r#"{"error":{"code":"unauthorized","message":"missing or invalid admin credential (Bearer or x-admin-token)"}}"#
    );
    assert_eq!(
        absent.headers,
        vec![
            ("content-type".to_string(), "application/json".to_string()),
            ("www-authenticate".to_string(), "Bearer".to_string()),
        ],
        "the refused caller receives the JSON envelope and supported authentication challenge"
    );
}

#[cfg(feature = "root-admin")]
#[test]
fn a_caller_the_door_identifies_as_somebody_else_is_answered_with_the_scope_it_needed() {
    let door = busbar_kernel_identity::AuthChain::new(
        vec![busbar_kernel_identity::chain::ChainEntry {
            provider: "identifies-somebody-else".to_string(),
            module: Box::new(IdentifiesSomebodyElse),
        }],
        false,
    );
    let refused = answer_at_the_closed_door(door, Some("a-tenants-token"));
    assert_eq!(
        refused.status, 403,
        "an identified caller with no grant is the authorization ending, not the door's"
    );
    assert_ne!(
        refused,
        door_answer(),
        "and it is not the door's answer: the two endings must stay distinguishable"
    );
    assert_eq!(
        String::from_utf8(refused.body).expect("the envelope is text"),
        r#"{"error":{"code":"forbidden","message":"insufficient scope: this endpoint requires `read-only`"}}"#
    );
}

#[cfg(feature = "root-admin")]
fn a_bound_unit(request: AdminRequest) -> AdminWalk {
    let mut walk = AdminWalk::new(request);

    let _ = decode(&mut walk);
    walk
}

#[cfg(feature = "root-admin")]
#[tokio::test]
async fn the_admin_listener_is_exempt_from_the_cap_the_data_listener_is_refused_at() {
    use busbar_contract::caps::{OriginKind, StepName};
    use busbar_kernel::inflight::{arrival_hold, cap_refusal_step, Enter, InFlight};

    let units = crate::root::kernel::ProductionUnits::admin_only(
        Arc::new(real_admin_dispatch()),
        open_door(),
    );
    let node = AdminNode::new(crate::root::kernel::new_kernel(), units);
    let full = InFlight::new(0);
    assert_eq!(full.cap(), 0, "a table with no room");

    let entering = Enter {
        key: UnitKey::new(9_000),
        origin: OriginKind::Client,
        session: None,
        admin_listener: false,
        zero_hold_tick: false,
        now: 0,
        arrival: arrival_hold(
            &node.kernel,
            &node.units.arrival_door,
            PrincipalId::new("caller"),
            node.kernel.next_call(),
        ),
    };
    let Err(refused) = full.insert(entering) else {
        panic!("a table with no room admits nothing that is under the cap");
    };
    assert_eq!(refused.reason, ReasonCode::InFlightCap);
    assert_eq!(refused.step, StepName::Arrival);
    assert_eq!(refused.step, cap_refusal_step(OriginKind::Client));
    let handed_back = refused.hold;
    assert_eq!(
        handed_back.principal(),
        &PrincipalId::new("caller"),
        "the refused unit's hold comes back to its caller, untouched"
    );

    let request = authenticated_admin_request();
    let key = UnitKey::new(request.unit);
    let admitted = full
        .insert(Enter {
            key,
            origin: OriginKind::Client,
            session: None,
            admin_listener: true,
            zero_hold_tick: false,
            now: 0,
            arrival: arrival_hold(
                &node.kernel,
                &node.units.arrival_door,
                PrincipalId::new("admin"),
                node.kernel.next_call(),
            ),
        })
        .expect("the administrative request is exempt on the same zero-cap table");
    assert_eq!(admitted.key(), key);
    assert_eq!(full.len(), 1, "the admitted unit is actually retained");
    let answer = tokio::task::spawn_blocking(move || node.answer(request))
        .await
        .expect("the administrative operation completes");
    assert_eq!(
        answer.status, 200,
        "the admin listener answers while shedding"
    );
    assert_ne!(answer, unavailable_answer());
    assert_ne!(
        answer,
        answer_for(Outcome::Refused(StepName::Arrival, ReasonCode::InFlightCap)),
        "the answer is the request's own, not the gate's refusal"
    );
    let document: serde_json::Value = serde_json::from_slice(&answer.body).expect("audit JSON");
    assert!(
        document["items"].is_array(),
        "the real audit handler answered"
    );
    drop(
        full.remove(key)
            .expect("release the admitted administrative unit"),
    );
    drop(admitted);
    assert!(full.is_empty());
}

#[cfg(feature = "root-admin")]
#[test]
fn a_verb_the_table_never_named_has_nowhere_to_go_and_a_resolved_one_has_nowhere_priced() {
    let principal = PrincipalId::new("admin");

    let mut unknown = a_request();
    unknown.path = "/api/v1/admin/not-a-real-operation".to_string();
    let mut walk = a_bound_unit(unknown);
    assert!(
        walk.verb.is_none(),
        "the fixture must be a path the table never resolved"
    );
    assert_eq!(
        verify(&mut walk, &principal),
        Err(ReasonCode::NoDestination),
        "a verb that resolved to nothing has nowhere to go"
    );

    let mut walk = a_bound_unit(a_request());
    assert!(
        walk.verb.is_some(),
        "the fixture must be a path the table did resolve"
    );
    assert_eq!(
        verify(&mut walk, &principal),
        Ok(()),
        "a resolved verb has somewhere to go"
    );
}

#[cfg(feature = "root-admin")]
#[test]
fn the_audit_doors_seal_the_resolved_class_and_append_to_no_ring() {
    let mut mutating = a_request();
    mutating.method = "POST".to_string();
    mutating.path = "/api/v1/admin/plane-record-write".to_string();
    let mut walk = a_bound_unit(mutating.clone());
    let resolved = walk
        .verb
        .expect("the plane-record write is a row the table names");
    assert!(!resolved.read_only, "the fixture must be a mutation");
    walk.principal = Some(PrincipalId::new(AN_IDENTIFIED_OPERATOR));
    let facts = audit(&walk, &Outcome::Completed);
    assert_eq!(facts.op_class, resolved.op_class());
    assert_eq!(facts.finish, busbar_contract::FinishClass::Complete);

    let walk = a_bound_unit(a_request());
    let read = walk
        .verb
        .expect("the audit listing is a row the table names");
    assert!(read.read_only, "the fixture must be a read");
    let facts = audit(&walk, &Outcome::Completed);
    assert_eq!(facts.op_class, read.op_class());
    assert_ne!(
        facts.op_class,
        resolved.op_class(),
        "a read and a write seal under two classes"
    );

    for identified in [true, false] {
        let mut walk = a_bound_unit(mutating.clone());
        if identified {
            walk.principal = Some(PrincipalId::new(AN_IDENTIFIED_OPERATOR));
        }
        let facts = audit(
            &walk,
            &Outcome::Refused(
                busbar_contract::caps::StepName::Admit,
                ReasonCode::OverBudget,
            ),
        );
        assert_eq!(facts.op_class, resolved.op_class());
        assert_eq!(facts.finish, busbar_contract::FinishClass::Error);
    }
}

#[cfg(feature = "root-admin")]
fn the_one_rings_rows_by(principal: &str) -> Vec<busbar_kernel::audit_ring::AuditEntry> {
    busbar_kernel::audit::auditlog::AUDIT_LOG
        .list_filtered(0, usize::MAX, None, None)
        .into_iter()
        .filter(|entry| entry.principal == principal)
        .collect()
}

#[cfg(feature = "root-admin")]
#[test]
fn one_admin_unit_seals_exactly_one_entry_on_the_one_ring_and_a_read_seals_none() {
    const WHO: &str = "operator-cifollow-one-entry";

    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built Store"),
    );
    let statement = crate::root::loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual Store statement reads")
        .expect("the actual Store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual Store statement is valid")
        .name;
    let mut manifest = crate::root::test_plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual Store library reads");
    let directory = crate::root::test_plugins::scratch(&format!(
        "admin-unit-{}",
        busbar_kernel::door::op_id().counter(),
    ));
    let archive = crate::root::test_plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &library,
    );
    std::fs::write(directory.join("store.tar.gz"), archive).expect("stage the actual Store");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("actual Store settings are JSON");
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {}, "models": {},
        "auth": {"chain": [], "admin_auth": []},
        "store": {"module": module, "settings": settings},
        "advanced": {"allow_destinations": ["127.0.0.1"]},
    }))
    .expect("the real admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the real admin deployment resolves");
    let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
        as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (built, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        crate::root::test_plugins::trusted_config(&directory),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the product builds the actual admin application");
    limits.keep().expect("the real application limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let _app = std::sync::Arc::new(built);
    let linked = |entry: &busbar_kernel::audit_ring::AuditEntry| {
        let ring =
            busbar_kernel::audit::auditlog::AUDIT_LOG.list_filtered(0, usize::MAX, None, None);
        let at = ring
            .iter()
            .position(|e| e.seq == entry.seq)
            .expect("the entry just sealed is on the ring");
        assert!(!entry.hash.is_empty(), "the entry carries its digest");
        if let Some(before) = ring.get(at + 1) {
            assert_eq!(
                entry.prev_hash, before.hash,
                "the entry is chained to the one before it"
            );
        }
    };
    let mutating = |path: &str| {
        let mut request = a_request();
        request.method = "POST".to_string();
        request.path = path.to_string();
        request
    };

    let mut walk = a_bound_unit(mutating("/api/v1/admin/plane-record-write"));
    let resolved = walk
        .verb
        .expect("the plane-record write is a row the table names");
    assert!(!resolved.read_only, "the fixture must be a mutation");
    walk.principal = Some(PrincipalId::new(WHO));
    walk.answer = Some(AdminAnswer {
        status: 204,
        headers: Vec::new(),
        body: Vec::new(),
    });
    let before = the_one_rings_rows_by(WHO).len();
    let _ = audit(&walk, &Outcome::Completed);
    let rows = the_one_rings_rows_by(WHO);
    assert_eq!(rows.len(), before + 1, "one unit, one entry");
    assert_eq!(rows[0].action, resolved.verb);
    assert_eq!(rows[0].outcome, busbar_kernel::audit_ring::OUTCOME_APPLIED);
    assert!(
        !rows[0].principal.contains("admin-token"),
        "the entry names the identity, never the presented credential"
    );
    linked(&rows[0]);

    let mut walk = a_bound_unit(a_request());
    assert!(
        walk.verb
            .expect("the audit listing is a row the table names")
            .read_only,
        "the fixture must be a read"
    );
    walk.principal = Some(PrincipalId::new(WHO));
    let before = the_one_rings_rows_by(WHO).len();
    let _ = audit(&walk, &Outcome::Completed);
    assert_eq!(
        the_one_rings_rows_by(WHO).len(),
        before,
        "a read is not a mutation"
    );

    let mut walk = a_bound_unit(mutating("/api/v1/admin/keys"));
    assert!(
        !walk
            .verb
            .expect("the key mint is a row the table names")
            .read_only,
        "the fixture must be a mutation"
    );
    walk.principal = Some(PrincipalId::new(WHO));
    let before = the_one_rings_rows_by(WHO).len();
    let _ = audit(&walk, &Outcome::Completed);
    assert_eq!(
        the_one_rings_rows_by(WHO).len(),
        before,
        "the handler's row is the one row; the step writes no second copy"
    );

    let mut walk = a_bound_unit(mutating("/api/v1/admin/plane-record-write"));
    walk.principal = Some(PrincipalId::new(WHO));
    let before = the_one_rings_rows_by(WHO).len();
    let _ = audit(
        &walk,
        &Outcome::Refused(
            busbar_contract::caps::StepName::Admit,
            ReasonCode::OverBudget,
        ),
    );
    let rows = the_one_rings_rows_by(WHO);
    assert_eq!(rows.len(), before + 1, "the attempt is on the chain");
    assert_eq!(rows[0].action, resolved.verb);
    assert_eq!(rows[0].outcome, busbar_kernel::audit_ring::OUTCOME_REJECTED);
    linked(&rows[0]);
}

const AN_IDENTIFIED_OPERATOR: &str = "operator-alice";

#[cfg(feature = "root-admin")]
#[test]
fn each_recovery_verb_reaches_the_store_and_a_refusing_store_is_the_answer() {
    /// A store that records what reached it and refuses it.
    #[derive(Debug, Default)]
    struct RecordingStore(Mutex<Vec<String>>);

    impl busbar_kernel_seams::verb_store::Store for RecordingStore {
        fn chain_break(
            &self,
            _admin: &busbar_contract::caps::Grant<busbar_contract::caps::AdminVerb>,
        ) -> Result<(), busbar_kernel_seams::verb_store::StoreError> {
            self.0.lock().unwrap().push("chain_break".to_string());
            Err(busbar_kernel_seams::verb_store::StoreError::Failed)
        }

        fn store_restore(
            &self,
            _admin: &busbar_contract::caps::Grant<busbar_contract::caps::AdminVerb>,
            backup_ref: &str,
        ) -> Result<(), busbar_kernel_seams::verb_store::StoreError> {
            self.0
                .lock()
                .unwrap()
                .push(format!("store_restore:{backup_ref}"));
            Err(busbar_kernel_seams::verb_store::StoreError::Failed)
        }
    }

    struct NeverDispatched;
    impl AdminDispatch for NeverDispatched {
        fn execute(&self, verb: KernelVerb, _request: &AdminRequest) -> AdminAnswer {
            panic!("a recovery verb reached the governance seam: {verb:?}");
        }
    }

    let admin = crate::root::kernel::new_kernel().admin_token();

    for (path, body, reached) in [
        ("/api/v1/admin/chain-break", "{}", "chain_break"),
        (
            "/api/v1/admin/store-restore",
            "{\"backup_ref\":\"nightly-2026-09-05\"}",
            "store_restore:nightly-2026-09-05",
        ),
    ] {
        let store = Arc::new(RecordingStore::default());
        let binding = AdminBinding::new(Arc::new(NeverDispatched), open_door());
        let mut request = a_request();
        request.method = "POST".to_string();
        request.path = path.to_string();
        request.body = body.as_bytes().to_vec();
        let mut walk = AdminWalk::new(request);
        decode(&mut walk).unwrap_or_else(|_| panic!("{path} is a row the plane's table declares"));
        walk.granted = Some(VerbScope::Full);

        let outcome = route(
            &binding,
            Some(Arc::clone(&store)
                as Arc<
                    dyn busbar_kernel_seams::verb_store::Store + Send + Sync,
                >),
            &admin,
            &mut walk,
        );

        assert_eq!(
            store.0.lock().unwrap().as_slice(),
            [reached.to_string()],
            "{path} did not reach the store method it names"
        );
        assert_eq!(
            outcome.err(),
            Some(ReasonCode::DurabilityUnavailable),
            "{path} did not surface the refusing store's refusal"
        );
    }
}

#[test]
fn a_restore_that_names_no_backup_is_refused_rather_than_defaulted() {
    assert_eq!(
        backup_ref_of("{\"backup_ref\":\"nightly-2026-09-05\"}".as_bytes()),
        Some("nightly-2026-09-05".to_string())
    );
    assert_eq!(
        backup_ref_of("{ \"backup_ref\" : \"with \\\"quotes\\\" and \\\\slash\" }".as_bytes()),
        Some("with \"quotes\" and \\slash".to_string())
    );

    assert_eq!(
        backup_ref_of("{\"backup_ref\":\"\\u00e9t\\u00e9\"}".as_bytes()),
        Some("\u{e9}t\u{e9}".to_string())
    );

    assert_eq!(
        backup_ref_of("{\"backup_ref\":\"\u{e9}t\u{e9}\"}".as_bytes()),
        Some("\u{e9}t\u{e9}".to_string())
    );
    for malformed in [
        "{}",
        "{\"backup\":\"x\"}",
        "{\"backup_ref\":\"\"}",
        "{\"backup_ref\":null}",
        "{\"backup_ref\":42}",
        "{\"backup_ref\":\"unterminated",
        "{\"backup_ref\":\"\\q\"}",
        "",
    ] {
        assert_eq!(
            backup_ref_of(malformed.as_bytes()),
            None,
            "a body naming no usable reference must not resolve to one"
        );
    }

    assert_eq!(backup_ref_of(&[0xff, 0xfe]), None);
}

#[cfg(feature = "root-admin")]
#[test]
fn either_carrier_reaches_the_loop_as_the_credential_itself() {
    let presented = |name: &str, value: &str| -> Option<String> {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::HeaderName::from_bytes(name.as_bytes()).expect("a header name"),
            axum::http::HeaderValue::from_str(value).expect("a header value"),
        );
        presented_credential(&headers)
    };
    let secret = "shadow-oracle-admin";

    for value in [
        format!("Bearer {secret}"),
        format!("bearer {secret}"),
        format!("BEARER {secret}"),
        format!("Bearer  {secret}"),
        format!("  Bearer {secret}"),
    ] {
        assert_eq!(
            presented("authorization", &value).as_deref(),
            Some(secret),
            "{value:?} did not arrive as the secret"
        );
    }
    assert_eq!(
        presented(ADMIN_TOKEN_HEADER, secret).as_deref(),
        Some(secret),
        "the second carrier is a carrier"
    );

    assert_eq!(
        presented("authorization", "Bearer Bearer token").as_deref(),
        Some("Bearer token")
    );

    assert_eq!(
        presented("authorization", "Basic abc123").as_deref(),
        Some("Basic abc123")
    );

    assert_eq!(presented("authorization", "Bearer ").as_deref(), None);
    assert_eq!(presented(ADMIN_TOKEN_HEADER, "").as_deref(), None);
    assert_eq!(
        presented_credential(&axum::http::HeaderMap::new()),
        None,
        "a request with no carrier at all presents nothing"
    );
}

#[test]
fn exactly_two_verbs_land_on_the_store() {
    let landing: Vec<KernelVerb> = NEW_VERBS
        .iter()
        .copied()
        .filter(|verb| recovery_verb(*verb).is_some())
        .collect();
    assert_eq!(
        landing,
        vec![KernelVerb::ChainBreak, KernelVerb::StoreRestore]
    );
    for verb in LEGACY_VERBS
        .iter()
        .map(|row| row.verb)
        .chain(LEDGER_VERBS.iter().chain(NAMED_SURFACES.iter()).copied())
    {
        assert!(
            recovery_verb(verb).is_none(),
            "{verb:?} is not a recovery verb"
        );
    }
}

#[cfg(feature = "root-admin")]
#[test]
fn an_unresolved_unit_is_sealed_by_the_method_it_asked_with() {
    let refused = &Outcome::Refused(
        busbar_contract::caps::StepName::Decode,
        ReasonCode::DecodeFailed,
    );
    let read = busbar_contract::OpClassId::new(OP_UNRESOLVED_READ);
    let write = busbar_contract::OpClassId::new(OP_UNRESOLVED_WRITE);

    for method in ["GET", "HEAD", "head"] {
        assert_eq!(
            unresolved_facts(Some(method), refused).op_class,
            read,
            "{method} reads"
        );
    }
    for method in ["POST", "PUT", "PATCH", "DELETE", "delete", "WHAT"] {
        let facts = unresolved_facts(Some(method), refused);
        assert_ne!(facts.op_class, read, "{method} is not a read");
        assert_eq!(facts.op_class, write, "{method} seals as a write");
    }
    assert_eq!(
        unresolved_facts(None, refused).op_class,
        read,
        "a unit that presented no method attempted no mutation"
    );
    assert_eq!(
        unresolved_facts(None, refused).finish,
        busbar_contract::FinishClass::Error
    );
}

#[cfg(feature = "root-admin")]
#[test]
fn the_refused_door_seals_the_refusal_that_happened() {
    let mut unrouted = a_request();
    unrouted.method = "DELETE".to_string();
    unrouted.path = "/api/v1/admin/nothing-declares-this".to_string();
    let walk = a_bound_unit(unrouted);
    assert!(
        walk.verb.is_none(),
        "the fixture must be a unit whose verb never resolved"
    );

    let facts = audit(
        &walk,
        &Outcome::Refused(
            busbar_contract::caps::StepName::Authenticate,
            ReasonCode::Unauthenticated,
        ),
    );
    assert_eq!(
        facts.op_class,
        busbar_contract::OpClassId::new(OP_UNRESOLVED_WRITE),
        "the DELETE it asked with, not the read it used to be sealed as"
    );
    assert_eq!(facts.finish, busbar_contract::FinishClass::Error);
}

const A_DAY: u64 = 1_767_225_600;

struct SeededLedger;

impl LedgerView for SeededLedger {
    fn priced(&self) -> Result<crate::root::units_admin::PricedLedger, String> {
        use crate::root::units_admin::{LedgerRow, PricedLedger, RefusedRow};
        Ok(PricedLedger {
            rows: vec![
                LedgerRow {
                    bucket: "key-1".to_string(),
                    day: A_DAY,
                    priced_nanos: 7_000_000,
                    fee_count: 2,
                },
                LedgerRow {
                    bucket: "key-2".to_string(),
                    day: A_DAY,
                    priced_nanos: 1_000_000,
                    fee_count: 1,
                },
            ],
            refused: vec![RefusedRow {
                bucket: "key-3".to_string(),
                day: A_DAY,
                refusal: "ClassUnpriced(cache_read)".to_string(),
            }],
        })
    }
}

const LEDGER_PATHS: &[&str] = &[
    "/api/v1/admin/ledger/totals",
    "/api/v1/admin/ledger/checkpoints",
    "/api/v1/admin/ledger/reconciliation",
    "/api/v1/admin/ledger/migration",
    "/api/v1/admin/ledger/openapi.json",
];

fn a_ledger_request(path: &str) -> AdminRequest {
    AdminRequest {
        method: "GET".to_string(),
        path: path.to_string(),
        credential: Some("admin-token".to_string()),
        headers: vec![("accept".to_string(), "application/json".to_string())],
        body: Vec::new(),
        at: 1_700_000_000,
        unit: a_fresh_unit(),
    }
}

#[cfg(feature = "root-admin")]
fn answer_over_seeded_ledger(request: AdminRequest) -> AdminAnswer {
    let mut units =
        crate::root::kernel::ProductionUnits::admin_only(Arc::new(AnsweringDispatch), open_door());
    units.admin = AdminBinding::new(Arc::new(AnsweringDispatch), open_door())
        .with_ledger_view(Arc::new(SeededLedger));
    AdminNode::new(crate::root::kernel::new_kernel(), units).answer(request)
}

#[cfg(feature = "root-admin")]
fn one_lane_card() -> busbar_kernel::cost::CostModel {
    let rates = std::collections::BTreeMap::from([(
        "m".to_string(),
        busbar_kernel::config::RateEntryCfg {
            input_utok: 2.5,
            ..Default::default()
        },
    )]);
    busbar_kernel::cost::CostModel::resolve_parts(
        Some(&rates),
        0,
        &std::collections::BTreeMap::new(),
    )
}

#[cfg(feature = "root-admin")]
fn answer_over_counts(
    gov: Arc<busbar_kernel::governance::GovState>,
    path: &str,
) -> serde_json::Value {
    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built Store"),
    );
    let statement = crate::root::loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual Store statement reads")
        .expect("the actual Store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual Store statement is valid")
        .name;
    let mut manifest = crate::root::test_plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual Store library reads");
    let directory = crate::root::test_plugins::scratch(&format!(
        "admin-unit-{}",
        busbar_kernel::door::op_id().counter(),
    ));
    let archive = crate::root::test_plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &library,
    );
    std::fs::write(directory.join("store.tar.gz"), archive).expect("stage the actual Store");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("actual Store settings are JSON");
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {}, "models": {},
        "auth": {"chain": [], "admin_auth": []},
        "store": {"module": module, "settings": settings},
        "advanced": {"allow_destinations": ["127.0.0.1"]},
    }))
    .expect("the real admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the real admin deployment resolves");
    let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
        as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (mut built, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        crate::root::test_plugins::trusted_config(&directory),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the product builds the actual admin application");
    limits.keep().expect("the real application limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    built.governance = Some(gov);
    built.cost = std::sync::Arc::new(one_lane_card());
    let app = std::sync::Arc::new(built);
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(app));
    let mut units =
        crate::root::kernel::ProductionUnits::admin_only(Arc::new(AnsweringDispatch), open_door());
    units.admin = AdminBinding::new(Arc::new(AnsweringDispatch), open_door()).with_ledger_view(
        Arc::new(crate::root::units_admin::CountsLedger::new(handle)),
    );
    let answer =
        AdminNode::new(crate::root::kernel::new_kernel(), units).answer(a_ledger_request(path));
    assert_eq!(answer.status, 200, "{path} did not answer");
    serde_json::from_slice(&answer.body).unwrap_or_else(|e| panic!("{path}: {e}"))
}

#[cfg(feature = "root-admin")]
#[test]
fn the_ledger_paths_answer_counts_times_card_and_survive_a_restart() {
    use busbar_kernel::governance::{GovState, VirtualKey};
    let store = crate::root::real_store::records();
    let key = VirtualKey {
        id: "vk_one_ledger".to_string(),
        generation_hash: "h:vk_one_ledger".to_string(),
        name: "one-ledger".to_string(),
        enabled: true,
        revision: 1,
        ..Default::default()
    };
    store.put_key(&key).expect("the key persists");
    let gov = Arc::new(GovState::new(store.clone(), None).expect("governance builds"));
    let now = busbar_kernel::store::now();
    let input = std::collections::BTreeMap::from([(
        busbar_contract::records::UNIT_INPUT.to_string(),
        1_000u64,
    )]);
    gov.record_usage(&one_lane_card(), &key, "", "m", &input, now);
    gov.flush_budgets();

    let stored = store.get_usage(&key.id, 0).expect("the row reads");
    assert_eq!(
        stored.tokens_for("m"),
        Some(1_000),
        "the store holds the spend"
    );

    let totals = answer_over_counts(Arc::clone(&gov), "/api/v1/admin/ledger/totals");
    let rows = totals["rows"].as_array().expect("rows");
    let row = rows
        .iter()
        .find(|r| r["bucket"] == "vk_one_ledger")
        .unwrap_or_else(|| panic!("the key's row is served: {totals}"));
    assert_eq!(row["priced_micros"], "2500", "1,000 tokens x 2.5: {totals}");
    assert_eq!(row["priced_nanos"], "2500000");
    assert_eq!(
        answer_over_counts(Arc::clone(&gov), "/api/v1/admin/ledger/reconciliation")["holds"],
        true
    );

    let restarted = Arc::new(GovState::new(store, None).expect("governance builds"));
    restarted
        .hydrate_budgets(&one_lane_card(), now)
        .expect("the boot hydrates");
    assert_eq!(
        answer_over_counts(restarted, "/api/v1/admin/ledger/totals"),
        totals,
        "a restart serves the same money from the same counts"
    );
}

#[cfg(feature = "root-admin")]
#[test]
fn every_ledger_view_answers_from_the_ledger_and_not_from_the_dispatch() {
    let mut bodies = Vec::new();
    for path in LEDGER_PATHS {
        let answer = answer_over_seeded_ledger(a_ledger_request(path));
        assert_eq!(answer.status, 200, "{path} did not answer");
        assert_eq!(
            answer.headers,
            vec![("content-type".to_string(), "application/json".to_string())],
            "{path} carried a header the view does not set"
        );
        let parsed: serde_json::Value =
            serde_json::from_slice(&answer.body).unwrap_or_else(|e| panic!("{path}: {e}"));
        assert!(parsed.is_object(), "{path} did not answer a JSON object");
        assert_ne!(
            answer.body, br#"{"entries":[]}"#,
            "{path} fell through to the dispatch"
        );
        bodies.push(answer.body);
    }
    let mut distinct = bodies.clone();
    distinct.sort_unstable();
    distinct.dedup();
    assert_eq!(
        distinct.len(),
        LEDGER_PATHS.len(),
        "two views answered the same bytes"
    );
}

#[cfg(feature = "root-admin")]
#[test]
fn each_view_serves_the_figures_the_ledger_holds() {
    let body = |path: &str| -> serde_json::Value {
        serde_json::from_slice(&answer_over_seeded_ledger(a_ledger_request(path)).body)
            .expect("valid JSON")
    };

    let totals = body("/api/v1/admin/ledger/totals");
    let rows = totals["rows"].as_array().expect("rows");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["bucket"], "key-1");
    assert_eq!(rows[0]["day"], A_DAY);
    assert_eq!(rows[0]["lane"], "");
    assert_eq!(rows[0]["provider"], "");

    assert_eq!(rows[0]["priced_nanos"], "7000000");
    assert_eq!(rows[0]["priced_micros"], "7000");
    assert_eq!(rows[0]["fee_count"], 2);
    let refused = totals["refused"].as_array().expect("refused");
    assert_eq!(refused.len(), 1, "the refused row is named, never served");
    assert_eq!(refused[0]["bucket"], "key-3");
    assert_eq!(refused[0]["refusal"], "ClassUnpriced(cache_read)");

    assert_eq!(
        body("/api/v1/admin/ledger/checkpoints"),
        serde_json::json!({"checkpoints": []})
    );
    assert_eq!(
        body("/api/v1/admin/ledger/migration"),
        serde_json::json!({"migrated": false, "marker": null})
    );

    let document = body("/api/v1/admin/ledger/openapi.json");
    assert_eq!(document["info"]["version"], "1.6.0");
}

#[cfg(feature = "root-admin")]
fn real_admin_dispatch() -> RouterDispatch {
    crate::dist_root_install::install();
    busbar_core_admin::install();
    let gov = Arc::new(
        busbar_kernel::governance::GovState::new(
            crate::root::real_store::records(),
            Some("admin-token".into()),
        )
        .expect("governance"),
    );
    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built Store"),
    );
    let statement = crate::root::loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual Store statement reads")
        .expect("the actual Store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual Store statement is valid")
        .name;
    let mut manifest = crate::root::test_plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual Store library reads");
    let directory = crate::root::test_plugins::scratch(&format!(
        "admin-unit-{}",
        busbar_kernel::door::op_id().counter(),
    ));
    let archive = crate::root::test_plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &library,
    );
    std::fs::write(directory.join("store.tar.gz"), archive).expect("stage the actual Store");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("actual Store settings are JSON");
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {}, "models": {},
        "auth": {"chain": [], "admin_auth": []},
        "store": {"module": module, "settings": settings},
        "advanced": {"allow_destinations": ["127.0.0.1"]},
    }))
    .expect("the real admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the real admin deployment resolves");
    let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
        as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (mut built, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        crate::root::test_plugins::trusted_config(&directory),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the product builds the actual admin application");
    limits.keep().expect("the real application limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let digest = gov.admin_token_hash();
    built.governance = Some(gov);
    built.admin_chain = vec![busbar_kernel::config::operator_provider().to_string()];
    let operator = busbar_kernel::auth::open_operator(
        &built.hook_env.registry,
        digest,
        &built.identity_providers,
    )
    .expect("the actual operator auth plugin opens with the configured digest");
    std::sync::Arc::get_mut(&mut built.admin_modules)
        .expect("the newly built admin chain has one owner")
        .operator = operator;
    let app = std::sync::Arc::new(built);
    RouterDispatch::new(
        busbar_kernel::build_router(app),
        &tokio::runtime::Handle::current(),
        Arc::new(busbar_core_admin::keys::KeyReplayCache::new()),
    )
}

#[cfg(feature = "root-admin")]
fn authenticated_admin_request() -> AdminRequest {
    let mut request = a_request();
    request
        .headers
        .push(("x-admin-token".into(), "admin-token".into()));
    request
}

#[cfg(feature = "root-admin")]
struct PanickingDispatch {
    calls: std::sync::atomic::AtomicUsize,
    next: RouterDispatch,
}

#[cfg(feature = "root-admin")]
impl AdminDispatch for PanickingDispatch {
    fn execute(&self, verb: KernelVerb, request: &AdminRequest) -> AdminAnswer {
        if self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
            panic!("the operation's body panicked");
        }
        self.next.execute(verb, request)
    }
}

#[cfg(feature = "root-admin")]
#[tokio::test]
async fn a_panicking_step_leaves_the_node_serving_valid_operations() {
    let dispatch = Arc::new(PanickingDispatch {
        calls: std::sync::atomic::AtomicUsize::new(0),
        next: real_admin_dispatch(),
    });
    let units = crate::root::kernel::ProductionUnits::admin_only(dispatch.clone(), open_door());
    let node = AdminNode::new(crate::root::kernel::new_kernel(), units);
    let answer = tokio::task::spawn_blocking(move || {
        let ended = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            node.answer(authenticated_admin_request())
        }));
        assert!(ended.is_err(), "the fixture's first dispatch panics");
        node.answer(authenticated_admin_request())
    })
    .await
    .expect("the second administrative walk completes");
    assert_eq!(answer.status, 200);
    let document: serde_json::Value = serde_json::from_slice(&answer.body).expect("audit JSON");
    assert!(
        document["items"].is_array(),
        "a real valid operation answered after the panic"
    );
    assert_eq!(dispatch.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[cfg(feature = "root-admin")]
#[test]
fn an_unopened_ledger_answers_empty_rather_than_absent() {
    let units =
        crate::root::kernel::ProductionUnits::admin_only(Arc::new(AnsweringDispatch), open_door());
    let node = AdminNode::new(crate::root::kernel::new_kernel(), units);
    let body = |path: &str| -> serde_json::Value {
        let answer = node.answer(a_ledger_request(path));
        assert_eq!(answer.status, 200, "{path}");
        serde_json::from_slice(&answer.body).expect("valid JSON")
    };
    assert_eq!(
        body("/api/v1/admin/ledger/totals")["rows"],
        serde_json::json!([])
    );
    assert_eq!(
        body("/api/v1/admin/ledger/checkpoints")["checkpoints"],
        serde_json::json!([])
    );
    assert_eq!(body("/api/v1/admin/ledger/migration")["migrated"], false);
    assert_eq!(
        body("/api/v1/admin/ledger/migration")["marker"],
        serde_json::Value::Null
    );

    assert_eq!(body("/api/v1/admin/ledger/reconciliation")["holds"], true);
}

#[cfg(feature = "root-admin")]
#[test]
fn the_reconciliation_holds_unless_a_row_is_refused_and_names_it() {
    let served: serde_json::Value = serde_json::from_slice(
        &answer_over_seeded_ledger(a_ledger_request("/api/v1/admin/ledger/reconciliation")).body,
    )
    .expect("valid JSON");
    assert_eq!(
        served["holds"], false,
        "a refused row is a row not measured"
    );
    assert_eq!(served["discrepancies"], serde_json::json!([]));
    let refused = served["refused"].as_array().expect("refused");
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0]["bucket"], "key-3");
}

#[cfg(feature = "root-admin")]
#[test]
fn verify_names_a_refused_row_and_every_other_finding() {
    let node_book = crate::root::durability::node_book();
    node_book
        .durability
        .lock()
        .expect("unpoisoned")
        .restart_findings
        .push("the journal does not verify: a forged record".to_string());
    let audit =
        crate::root::units_admin::NodeAudit::new(std::sync::Arc::clone(&node_book.durability));
    let answer = crate::root::units_admin::bound::verify_effect(&SeededLedger, Some(&audit), None)
        .expect("a refused row must not take /admin/verify down");
    let body: serde_json::Value = serde_json::from_slice(&answer.body).expect("valid JSON");
    let findings: Vec<&str> = body["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    assert!(
        findings
            .iter()
            .any(|f| f.starts_with("restart: ") && f.contains("a forged record")),
        "the independent finding must still be reported: {body}"
    );
    assert!(
        findings.iter().any(|f| f.starts_with("refused counts: ")
            && f.contains("key-3")
            && f.contains(&A_DAY.to_string())
            && f.contains("ClassUnpriced(cache_read)")),
        "the refused row must be a named finding: {body}"
    );
    assert_eq!(body["identity_holds"], false, "{body}");
    assert_eq!(body["ok"], false, "{body}");
}

#[cfg(feature = "root-admin")]
#[test]
fn a_ledger_view_answers_an_unauthenticated_caller_exactly_as_the_legacy_usage_read_does() {
    let under = |path: &str, credential: Option<&str>, revoked: bool| -> AdminAnswer {
        let mut request = a_ledger_request(path);
        request.credential = credential.map(ToString::to_string);

        let door = if revoked {
            door_of_chain(a_door_that_identifies_the_operator())
        } else {
            open_door()
        };
        let units =
            crate::root::kernel::ProductionUnits::admin_only(Arc::new(AnsweringDispatch), door)
                .with_auth_bindings(crate::root::auth_bindings::AuthBindings::new(Arc::new(
                    Denylist(revoked),
                )));
        AdminNode::new(crate::root::kernel::new_kernel(), units).answer(request)
    };

    let refused = under("/api/v1/admin/usage", Some("admin-token"), true);
    assert_ne!(
        refused.status, 200,
        "the control must actually be a refusal, or this test compares two successes"
    );
    for path in LEDGER_PATHS {
        assert_eq!(
            under(path, Some("admin-token"), true),
            refused,
            "{path} does not refuse a revoked credential the way /usage does"
        );
    }

    let admitted = under("/api/v1/admin/usage", None, false);
    assert_eq!(admitted.status, 200, "the open chain admits the control");
    for path in LEDGER_PATHS {
        assert_eq!(
            under(path, None, false).status,
            admitted.status,
            "{path} does not admit a credential-less caller the way /usage does"
        );
    }
}

#[test]
fn a_read_only_credential_reaches_every_view_and_still_no_mutation() {
    let decide = |path: &str, method: &str, granted: VerbScope| -> bool {
        let mut request = a_ledger_request(path);
        request.method = method.to_string();
        let mut walk = AdminWalk::new(request);
        walk.granted = Some(granted);
        approve(&walk).is_ok()
    };

    for path in LEDGER_PATHS {
        assert!(
            decide(path, "GET", VerbScope::ReadOnly),
            "{path} refused a read-only credential"
        );
        assert!(
            decide(path, "GET", VerbScope::Full),
            "{path} refused a full credential"
        );
    }
    assert!(
        !decide("/api/v1/admin/config/settings", "PUT", VerbScope::ReadOnly),
        "the scope gate is not checking anything: a read-only credential reached a mutation"
    );
}

#[test]
fn a_ledger_view_is_read_only_in_every_table_that_has_an_opinion() {
    for path in LEDGER_PATHS {
        let row = busbar_core_admin::admin_codec::verbs::resolve("GET", path)
            .unwrap_or_else(|| panic!("{path} is not in the plane's table"));
        assert!(
            row.read_only,
            "{path} is not read-only in the plane's table"
        );
        assert_eq!(
            row.op_class(),
            busbar_contract::ids::OpClassId::new("admin_read")
        );

        let verb = kernel_verb(&row).unwrap_or_else(|| panic!("{path} names no kernel verb"));
        assert!(LEDGER_VERBS.contains(&verb), "{path} is not a ledger verb");
        assert_eq!(
            busbar_core_admin::required_scope(verb),
            busbar_core_admin::required_scope(KernelVerb::GetUsage),
            "{path} does not require what the legacy /usage read requires"
        );
        assert_eq!(
            mutation_class(verb),
            MutationClass::Forbidden,
            "{path} would spend a mutation slot per read"
        );
        assert_eq!(
            busbar_kernel::admin::scope::admin_required_scope("GET", path),
            Scope::ReadOnly
        );
    }
}

#[test]
fn a_view_never_reaches_the_dispatch_and_answers_a_read_only_grant() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingDispatch(Arc<AtomicUsize>);
    impl AdminDispatch for CountingDispatch {
        fn execute(&self, _verb: KernelVerb, _request: &AdminRequest) -> AdminAnswer {
            self.0.fetch_add(1, Ordering::Relaxed);

            AdminAnswer {
                status: 599,
                headers: Vec::new(),
                body: b"the dispatch was reached".to_vec(),
            }
        }
    }

    let calls = Arc::new(AtomicUsize::new(0));
    let admin = crate::root::kernel::new_kernel().admin_token();

    for verb in LEDGER_VERBS {
        let verbs = busbar_core_admin::Verbs::new(
            CoreGovernance::new(
                Arc::new(CountingDispatch(Arc::clone(&calls))),
                Arc::new(SeededLedger),
                None,
                *verb,
                a_ledger_request("/api/v1/admin/ledger/totals"),
            ),
            None::<Arc<dyn busbar_kernel_seams::verb_store::Store + Send + Sync>>,
            CONFIG_CLASS_RULES,
            Arc::new(busbar_core_admin::rate::MutationLimiter::new()),
        );
        let answer = verbs
            .execute(
                *verb,
                &admin,
                "admin",
                VerbScope::ReadOnly,
                1_700_000_000,
                b"",
            )
            .unwrap_or_else(|r| panic!("{verb:?} was refused: {r:?}"));
        assert_eq!(answer.status, 200);
    }
    assert_eq!(
        calls.load(Ordering::Relaxed),
        0,
        "a ledger view reached the dispatch, which has no handler for it"
    );

    let verbs = busbar_core_admin::Verbs::new(
        CoreGovernance::new(
            Arc::new(CountingDispatch(Arc::clone(&calls))),
            Arc::new(SeededLedger),
            None,
            KernelVerb::Adjust,
            a_ledger_request("/api/v1/admin/adjust"),
        ),
        None::<Arc<dyn busbar_kernel_seams::verb_store::Store + Send + Sync>>,
        CONFIG_CLASS_RULES,
        Arc::new(busbar_core_admin::rate::MutationLimiter::new()),
    );
    assert!(verbs
        .execute(
            KernelVerb::Adjust,
            &admin,
            "admin",
            VerbScope::ReadOnly,
            1_700_000_000,
            b"",
        )
        .is_err());
}

#[cfg(feature = "root-admin")]
const AUDIT_PATHS: &[&str] = &[
    "/api/v1/admin/audit/head",
    "/api/v1/admin/audit/range",
    "/api/v1/admin/audit/keys",
];

#[cfg(feature = "root-admin")]
struct SealedChain {
    chain: busbar_kernel_audit::AuditChain,
    records: Vec<busbar_kernel_audit::AuditRecord>,
    keys: busbar_kernel_audit::AuditKeySet,
}

#[cfg(feature = "root-admin")]
impl AuditView for SealedChain {
    fn read(
        &self,
        take: &mut dyn FnMut(
            &busbar_kernel_audit::AuditChain,
            Option<&[busbar_kernel_audit::AuditRecord]>,
        ),
    ) {
        take(&self.chain, Some(&self.records));
    }

    fn keys(&self) -> busbar_kernel_audit::AuditKeySet {
        self.keys.clone()
    }
}

#[cfg(feature = "root-admin")]
fn an_audit_pass() -> busbar_contract::caps::Pass<busbar_contract::caps::Audit> {
    busbar_kernel::teller::verb_audit_pass(&crate::root::kernel::new_kernel())
}

#[cfg(feature = "root-admin")]
fn a_sealed_chain() -> SealedChain {
    use busbar_contract::caps::{OriginKind, Outcome as UnitOutcome, UnitKey};
    use busbar_kernel_audit::{
        Audit as _, AuditInputs, Controls, FinishClass, OpClassId, OutcomeFacts, Subject, Usage,
        What,
    };

    let signer = busbar_kernel_audit::AuditSigningKey::from_seed(&[7u8; 32]);
    let mut keys = busbar_kernel_audit::AuditKeySet::new();
    keys.insert(
        busbar_kernel_audit::AuditVerifyingKey::from_hex(&signer.public_key_hex())
            .expect("a public key"),
    );
    let mut chain = busbar_kernel_audit::AuditChain::new().signing_with(signer);

    let token = an_audit_pass();
    let mut records = Vec::new();
    for unit in 1..=3u64 {
        records.push(chain.seal(
            AuditInputs {
                subject: Subject::PrincipalId(format!("pseudonym-{unit}")),
                what: What {
                    unit_key: UnitKey::new(unit),
                    incarnation: 0,
                    op_class: OpClassId::new("chat.completion"),
                    destination: Some("upstream-a".into()),
                    parent: None,
                    pre_hook_head: None,
                    post_hook_head: None,
                },
                wall: 1_700_000_000 + unit,
                mono: unit * 1_000,
                origin: crate::root::kernel::new_kernel().origin(OriginKind::Client),
                outcome: OutcomeFacts {
                    unit_end: UnitOutcome::Completed,
                    step: None,
                    finish: FinishClass::Complete,
                    hook_failed: false,
                    emission_delta: 0,
                    stale_policy: false,
                },
                usage: Usage {
                    lines: Vec::new(),
                    tier_bp: 9_000,
                    fee_count: 1,
                    rate_card_version: Some([3; 20]),
                    bucket_chain_ref: "chain:free>paid".into(),
                },
                controls: Controls {
                    lease_epoch: 4,
                    policy_epoch: 7,
                    ..Controls::default()
                },
                correlation_label: None,
            },
            &token,
        ));
    }
    SealedChain {
        chain,
        records,
        keys,
    }
}

#[cfg(feature = "root-admin")]
fn answer_over_a_sealed_chain(request: AdminRequest) -> AdminAnswer {
    let mut units =
        crate::root::kernel::ProductionUnits::admin_only(Arc::new(AnsweringDispatch), open_door());
    units.admin = AdminBinding::new(Arc::new(AnsweringDispatch), open_door())
        .with_audit_view(Arc::new(a_sealed_chain()) as Arc<dyn AuditView>);
    AdminNode::new(crate::root::kernel::new_kernel(), units).answer(request)
}

#[test]
#[cfg(feature = "root-admin")]
fn the_three_chain_reads_answer_with_the_chains_own_bytes() {
    let head = answer_over_a_sealed_chain(a_ledger_request("/api/v1/admin/audit/head"));
    assert_eq!(head.status, 200, "the head read did not answer");
    let head_body = String::from_utf8(head.body).expect("the head read answers UTF-8");
    assert!(
        head_body.contains(r#""signature_domain":"busbar.audit.record.v1""#),
        "the head read did not come from the chain: {head_body}"
    );

    assert!(
        head_body.contains(r#""next_seq":4"#),
        "the head read does not see the sealed records: {head_body}"
    );
    assert!(
        head_body.contains(r#""head":{"#) && head_body.contains(r#""seq":3"#),
        "the head read reports no tip: {head_body}"
    );

    let range =
        answer_over_a_sealed_chain(a_ledger_request("/api/v1/admin/audit/range?from=2&to=3"));
    assert_eq!(range.status, 200, "the range read did not answer");
    let range_body = String::from_utf8(range.body).expect("the range read answers UTF-8");
    assert!(
        range_body.contains(r#""from":2"#) && range_body.contains(r#""to":3"#),
        "the range read did not take its window from the query: {range_body}"
    );

    assert!(
        range_body.contains("pseudonym-2") && range_body.contains("pseudonym-3"),
        "the range read is missing records inside its window: {range_body}"
    );
    assert!(
        !range_body.contains("pseudonym-1"),
        "the range read returned a record outside its window: {range_body}"
    );

    let keys = answer_over_a_sealed_chain(a_ledger_request("/api/v1/admin/audit/keys"));
    assert_eq!(keys.status, 200, "the key read did not answer");
    let keys_body = String::from_utf8(keys.body).expect("the key read answers UTF-8");
    let signer = busbar_kernel_audit::AuditSigningKey::from_seed(&[7u8; 32]);
    assert!(
        keys_body.contains(&signer.public_key_hex()),
        "the key read does not publish the key that signed the chain: {keys_body}"
    );
    assert!(
        keys_body.contains(r#""algorithm":"ed25519""#),
        "the key read names no algorithm: {keys_body}"
    );

    assert!(
        !keys_body.contains(&"07".repeat(32)),
        "the key read published secret key material: {keys_body}"
    );
}

#[test]
#[cfg(feature = "root-admin")]
fn an_unbound_chain_refuses_rather_than_answering_an_empty_head() {
    let mut units =
        crate::root::kernel::ProductionUnits::admin_only(Arc::new(AnsweringDispatch), open_door());

    units.admin = AdminBinding::new(Arc::new(AnsweringDispatch), open_door());
    let node = AdminNode::new(crate::root::kernel::new_kernel(), units);
    for path in AUDIT_PATHS {
        let answer = node.answer(a_ledger_request(path));
        assert_eq!(answer.status, 404, "{path} answered over an unbound chain");
        assert!(
            !String::from_utf8_lossy(&answer.body).contains("entries"),
            "{path} reached the legacy dispatch"
        );
    }
}

#[test]
#[cfg(feature = "root-admin")]
fn a_range_read_that_names_no_window_is_refused_rather_than_widened() {
    for target in [
        "/api/v1/admin/audit/range",
        "/api/v1/admin/audit/range?from=2",
        "/api/v1/admin/audit/range?to=3",
        "/api/v1/admin/audit/range?from=3&to=2",
        "/api/v1/admin/audit/range?from=two&to=three",
    ] {
        let answer = answer_over_a_sealed_chain(a_ledger_request(target));
        assert_eq!(answer.status, 400, "{target} was not refused as malformed");
    }

    assert_eq!(
        answer_over_a_sealed_chain(a_ledger_request("/api/v1/admin/audit/range?from=1&to=3"))
            .status,
        200
    );
}

#[test]
#[cfg(feature = "root-admin")]
fn a_chain_read_is_read_only_in_every_table_that_has_an_opinion() {
    for path in AUDIT_PATHS {
        let row = busbar_core_admin::admin_codec::verbs::resolve("GET", path)
            .unwrap_or_else(|| panic!("{path} is not in the plane's table"));
        assert!(
            row.read_only,
            "{path} is not read-only in the plane's table"
        );
        assert_eq!(
            row.op_class(),
            busbar_contract::ids::OpClassId::new("admin_read")
        );

        let verb = kernel_verb(&row).unwrap_or_else(|| panic!("{path} names no kernel verb"));
        assert!(AUDIT_VERBS.contains(&verb), "{path} is not an audit verb");
        assert_eq!(
            busbar_core_admin::required_scope(verb),
            busbar_core_admin::required_scope(KernelVerb::GetAudit),
            "{path} does not require what the legacy /audit read requires"
        );
        assert_eq!(
            mutation_class(verb),
            MutationClass::Forbidden,
            "{path} would spend a mutation slot per read"
        );
        assert_eq!(
            busbar_kernel::admin::scope::admin_required_scope("GET", path),
            Scope::ReadOnly
        );
    }
}

#[test]
#[cfg(feature = "root-admin")]
fn every_1_6_0_row_names_a_kernel_verb_and_no_name_is_empty() {
    for verb in NEW_VERBS
        .iter()
        .chain(LEDGER_VERBS.iter())
        .chain(AUDIT_VERBS.iter())
    {
        let name = busbar_core_admin::verb_name(*verb)
            .unwrap_or_else(|| panic!("{verb:?} has no name, so no row can ever reach it"));
        assert!(!name.is_empty(), "{verb:?} names the empty string");
        let row = busbar_core_admin::admin_codec::verbs::table()
            .into_iter()
            .find(|row| row.verb == name)
            .unwrap_or_else(|| panic!("{verb:?} ({name}) has no row in the closed table"));
        assert_eq!(
            kernel_verb(&row),
            Some(*verb),
            "{name} resolves to a different verb than the one that names it"
        );
    }

    assert_eq!(busbar_core_admin::verb_name(KernelVerb::GetAudit), None);
    assert_eq!(
        kernel_verb(
            &busbar_core_admin::admin_codec::verbs::resolve("GET", "/api/v1/admin/audit")
                .expect("the legacy audit read is in the table")
        ),
        Some(KernelVerb::GetAudit)
    );
}

#[cfg(feature = "root-admin")]
#[test]
fn the_ledger_document_path_serves_the_one_document_and_it_describes_the_views() {
    let answer = answer_over_seeded_ledger(a_ledger_request("/api/v1/admin/ledger/openapi.json"));
    assert_eq!(answer.status, 200);
    let served = String::from_utf8(answer.body).expect("the document is text");
    assert_eq!(
        served,
        busbar_core_admin::v1::json::openapi_document(),
        "the ledger's document path must serve the one generated document, byte for byte"
    );
    let document: serde_json::Value = serde_json::from_str(&served).expect("it is JSON");
    let paths = document["paths"].as_object().expect("it declares paths");
    assert!(
        paths.contains_key("/api/v1/admin/usage"),
        "the ledger path serves a document that is not the administrative one"
    );

    for path in LEDGER_PATHS {
        let op = &paths
            .get(*path)
            .unwrap_or_else(|| panic!("{path} is served and in no document"))["get"];
        assert!(
            op.is_object(),
            "{path} is described under a method the table does not declare"
        );
        assert_eq!(
            op["x-busbar-required-scope"], "read-only",
            "{path} is documented at a scope it is not served at"
        );
        let operation_id = op["operationId"].as_str().expect("an operationId");
        let verb = busbar_core_admin::admin_codec::verbs::resolve("GET", path)
            .expect("the table declares it")
            .verb;
        assert_eq!(
            snake_of(operation_id),
            verb,
            "{path}: the document's operationId is not the table's verb"
        );
    }

    let pinned: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("BUSBAR_CORE_DIR"),
        "/../../testing/shadow-oracle/fixtures/openapi-1.5.5.json"
    )))
    .expect("the pinned fixture is JSON");
    let pinned_paths = pinned["paths"].as_object().expect("it declares paths");
    assert!(
        !pinned_paths
            .keys()
            .any(|p| p.starts_with("/api/v1/admin/ledger/")),
        "the ledger views are 1.6.0 surface; the pinned 1.5.5 document must not carry them"
    );
}

#[cfg(feature = "root-admin")]
fn snake_of(operation_id: &str) -> String {
    let mut out = String::new();
    for (i, c) in operation_id.chars().enumerate() {
        if c.is_uppercase() {
            if i != 0 {
                out.push('_');
            }
            out.extend(c.to_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

#[test]
fn a_configured_name_cannot_break_out_of_the_document() {
    use crate::root::units_admin::{LedgerRow, PricedLedger, RefusedRow};

    let hostile = "a\"b\\c\nd\te\u{1}";
    let ledger = PricedLedger {
        rows: vec![LedgerRow {
            bucket: hostile.to_string(),
            day: A_DAY,
            priced_nanos: 1_000,
            fee_count: 0,
        }],
        refused: vec![RefusedRow {
            bucket: hostile.to_string(),
            day: A_DAY,
            refusal: hostile.to_string(),
        }],
    };
    let parsed: serde_json::Value =
        serde_json::from_str(&render_totals(&ledger).expect("projects"))
            .expect("a hostile name still renders JSON");
    assert_eq!(parsed["rows"][0]["bucket"], hostile);
    assert_eq!(parsed["refused"][0]["bucket"], hostile);
    assert_eq!(parsed["refused"][0]["refusal"], hostile);
}

#[cfg(test)]
fn a_seeded_history() -> crate::root::kernel::RootHistory {
    let history = crate::root::kernel::RootHistory::default();
    let opening = busbar_kernel_ledger::cost::RateCard::from_micro_rates(
        [(
            busbar_kernel_ledger::cost::LaneClass::new(
                "gpt",
                busbar_kernel_ledger::cost::CLASS_INPUT,
            ),
            2.0,
        )],
        0,
    );
    history.apply(opening, 1_000);
    history
}

#[cfg(test)]
fn a_body(body: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&body).expect("the correction serialises")
}

#[cfg(test)]
fn a_memory_book() -> Arc<Mutex<crate::root::durability::Durability>> {
    Arc::new(Mutex::new(
        crate::root::durability::build(
            &crate::root::durability::DurabilityConfig { data_dir: None },
            Box::new(busbar_kernel_wal::NullShipper::new()),
        )
        .expect("a memory-buffered journal cannot fail to open"),
    ))
}

#[cfg(test)]
fn a_journal_over(book: &Arc<Mutex<crate::root::durability::Durability>>) -> AmendmentJournal {
    AmendmentJournal::new(
        Arc::clone(book),
        crate::root::kernel::new_kernel().durability_token(),
    )
}

#[cfg(test)]
fn an_attribution() -> AmendAttribution {
    AmendAttribution {
        principal: "admin".to_string(),
    }
}

#[cfg(test)]
fn amend_through_a_journal(
    history: &crate::root::kernel::RootHistory,
    body: &[u8],
    arrival_secs: u64,
) -> Result<AdminAnswer, busbar_core_admin::GovernanceError> {
    let book = a_memory_book();
    amend_rate_history_effect(
        history,
        Some(&a_journal_over(&book)),
        body,
        arrival_secs,
        &an_attribution(),
    )
}

#[cfg(test)]
fn replayed_amendments(durability: &crate::root::durability::Durability) -> Vec<AmendmentRecord> {
    durability
        .chain()
        .expect("the journal reads back")
        .expect("the journal verifies")
        .iter()
        .filter(|r| r.class == busbar_kernel_wal::RecordClass::Policy)
        .map(|r| amendment_from_body(&r.body).expect("a Policy record is an amendment"))
        .collect()
}

#[cfg(test)]
const ARRIVED: u64 = 86_406;

#[cfg(test)]
fn a_correction_body() -> Vec<u8> {
    a_body(serde_json::json!({
        "effective_from": 0,
        "effective_until": 86_400_000,
        "rates": [ { "lane": "gpt", "class": "input", "micro_per_unit": 1.0 } ],
        "reason": "vendor corrected the March price sheet",
    }))
}

#[test]
fn amend_rate_history_appends_a_signed_back_dated_correction_and_rewrites_nothing() {
    let history = a_seeded_history();
    let instant = 5_000u64;

    let before = history.pin().expect("the opening pinned");
    let (before_seq, _) = before
        .view()
        .card_at(instant)
        .expect("the opening prices the instant");
    assert_eq!(before_seq, before.seq());

    let answer = amend_through_a_journal(&history, &a_correction_body(), ARRIVED)
        .expect("the correction applies");
    assert_eq!(answer.status, 200);
    let doc: serde_json::Value = serde_json::from_slice(&answer.body).expect("the answer is JSON");
    assert_eq!(doc["history_seq"], 1);
    assert_eq!(doc["effective_from"], 0);
    assert_eq!(doc["effective_until"], 86_400_000);
    assert_eq!(doc["amended_at"], ARRIVED * 1_000);
    assert!(
        doc.get("operator_fingerprint").is_none(),
        "the answer names no signer: {doc}"
    );
    assert!(
        doc["reason_sha256"].as_str().is_some_and(|s| s.len() == 64),
        "the reason is sealed as its 32-byte SHA-256, hex-encoded"
    );

    assert_eq!(history.len(), 2);
    let after = history.pin().expect("pinned after");
    let view = after.view();
    let entries = view.entries();
    assert_eq!(entries[0].seq(), busbar_kernel_ledger::cost::HistorySeq(0));
    assert_eq!(entries[0].effective_from(), 0);
    assert!(matches!(
        entries[0].author(),
        busbar_kernel_ledger::cost::Author::Config { .. }
    ));

    let (now_seq, _) = view
        .card_at(instant)
        .expect("the correction prices the instant");
    assert_eq!(now_seq, after.seq());
    assert!(
        matches!(
            entries[1].author(),
            busbar_kernel_ledger::cost::Author::Amend { .. }
        ),
        "the appended entry must be an amendment, got {:?}",
        entries[1].author()
    );

    let old = crate::root::kernel::PinnedHistory::for_test_at(
        &after,
        busbar_kernel_ledger::cost::HistorySeq(0),
    );
    let (old_seq, _) = old
        .view()
        .card_at(instant)
        .expect("the old snapshot still prices the instant");
    assert_eq!(old_seq, before.seq());
}

#[test]
fn amend_rate_history_refuses_a_correction_that_names_a_currency() {
    for named in [
        serde_json::json!("JPY"),
        serde_json::json!("USD"),
        serde_json::json!("nonsense"),
        serde_json::json!(null),
    ] {
        let history = a_seeded_history();
        let body = a_body(serde_json::json!({
            "effective_from": 0,
            "effective_until": 86_400_000,
            "currency": named,
            "rates": [ { "lane": "gpt", "class": "input", "micro_per_unit": 1.0 } ],
            "reason": "vendor corrected the March price sheet",
        }));
        let err = amend_through_a_journal(&history, &body, ARRIVED)
            .expect_err("a correction naming a currency must be refused");
        assert!(
            matches!(err, busbar_core_admin::GovernanceError::Validation),
            "a correction naming {named} must refuse Validation, got {err:?}"
        );
        assert_eq!(
            history.len(),
            1,
            "a refused correction appends nothing: {named}"
        );
    }

    let history = a_seeded_history();
    amend_through_a_journal(&history, &a_correction_body(), ARRIVED)
        .expect("the same correction with no `currency` key applies");
    assert_eq!(history.len(), 2);
}

#[test]
fn the_canonical_amend_payload_names_no_currency() {
    let body = serde_json::json!({
        "effective_from": 0,
        "effective_until": 86_400_000,
        "rates": [ { "lane": "gpt", "class": "input", "micro_per_unit": 1.0 } ],
        "reason": "vendor corrected the March price sheet",
    });
    let payload = canonical_amend_payload(body.as_object().expect("an object"));
    let text = String::from_utf8(payload).expect("the payload is text");
    assert!(
        !text.contains("currency"),
        "the signed payload still names a currency: {text}"
    );

    assert!(text.starts_with("busbar/amend-rate-history/v1\n"), "{text}");
    for key in [
        "effective_from=",
        "effective_until=",
        "per_request_fee=",
        "reason=",
        "rates=",
    ] {
        assert!(text.contains(key), "the payload dropped {key}: {text}");
    }
}

#[test]
fn amend_rate_history_refuses_a_negative_fee_and_appends_nothing() {
    for fee in [-1_i64, -5, i64::MIN] {
        let history = a_seeded_history();
        let body = a_body(serde_json::json!({
            "effective_from": 0,
            "effective_until": 86_400_000,
            "per_request_fee": fee,
            "rates": [ { "lane": "gpt", "class": "input", "micro_per_unit": 1.0 } ],
            "reason": "vendor corrected the March price sheet",
        }));
        let err = amend_through_a_journal(&history, &body, ARRIVED)
            .expect_err("a correction carrying a negative fee must be refused");
        assert!(
            matches!(err, busbar_core_admin::GovernanceError::Validation),
            "fee {fee} must refuse Validation, got {err:?}"
        );
        assert_eq!(history.len(), 1, "a refused fee {fee} appends nothing");
    }

    for fee in [5_i64, 0] {
        let history = a_seeded_history();
        let body = a_body(serde_json::json!({
            "effective_from": 0,
            "effective_until": 86_400_000,
            "per_request_fee": fee,
            "rates": [ { "lane": "gpt", "class": "input", "micro_per_unit": 1.0 } ],
            "reason": "vendor corrected the March price sheet",
        }));
        amend_through_a_journal(&history, &body, ARRIVED).expect("a non-negative fee applies");
        assert_eq!(history.len(), 2);
        let pinned = history.pin().expect("pinned");
        let view = pinned.view();
        let (_, card) = view
            .card_at(5_000)
            .expect("the correction prices its window");
        assert_eq!(card.fee(), fee, "the sealed fee is the signed fee");
    }
}

#[cfg(test)]
fn a_full_card_history() -> crate::root::kernel::RootHistory {
    use busbar_kernel_ledger::cost::TierRates;
    let history = crate::root::kernel::RootHistory::default();
    let card = busbar_kernel_ledger::cost::RateCard::from_config(
        Some([
            (
                "gpt",
                TierRates {
                    input: busbar_kernel_ledger::cost::representable_nano_rate(2.0),
                    output: busbar_kernel_ledger::cost::representable_nano_rate(8.0),
                    cache_read: busbar_kernel_ledger::cost::representable_nano_rate(0.5),
                    cache_write: busbar_kernel_ledger::cost::representable_nano_rate(2.5),
                },
            ),
            (
                "claude",
                TierRates {
                    input: busbar_kernel_ledger::cost::representable_nano_rate(3.0),
                    output: busbar_kernel_ledger::cost::representable_nano_rate(15.0),
                    cache_read: busbar_kernel_ledger::cost::representable_nano_rate(0.3),
                    cache_write: busbar_kernel_ledger::cost::representable_nano_rate(3.75),
                },
            ),
            (
                "plane-b\u{1f}search",
                TierRates {
                    input: busbar_kernel_ledger::cost::representable_nano_rate(5.0),
                    output: busbar_kernel_ledger::cost::representable_nano_rate(6.0),
                    cache_read: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
                    cache_write: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
                },
            ),
        ]),
        3,
    );
    history.apply(card, 1_000);
    history
}

#[cfg(test)]
fn priced_at(
    history: &crate::root::kernel::RootHistory,
    lane: &str,
    class: &str,
    count: u64,
    fee_count: u64,
    at: u64,
) -> Result<u128, busbar_kernel_ledger::cost::MoneyError> {
    use busbar_kernel_ledger::cost::{nanos_of_exact, whole, Tally, STANDARD_TIER_BP};
    let pinned = history.pin().expect("a history");
    let mut tally = Tally::in_view(pinned.view());
    tally.row(
        lane,
        at,
        STANDARD_TIER_BP,
        [(class, whole(count))],
        whole(fee_count),
    )?;
    nanos_of_exact(tally.exact()?)
}

#[test]
fn a_correction_of_one_cell_keeps_every_other_price_and_the_fee() {
    let history = a_full_card_history();
    let inside = 5_000;
    let outside = 100_000_000;

    let configured = |history: &crate::root::kernel::RootHistory, lane: &str, class: &str| {
        priced_at(history, lane, class, 1_000, 1, outside).expect("the configured card prices it")
    };
    let gpt_output = configured(&history, "gpt", "output");
    let claude_input = configured(&history, "claude", "input");
    let plane_b_input = configured(&history, "plane-b\u{1f}search", "input");

    amend_through_a_journal(&history, &a_correction_body(), ARRIVED)
        .expect("the correction applies");

    assert_eq!(
        priced_at(&history, "gpt", "input", 1_000, 1, inside).expect("the corrected cell prices"),
        1_000_000 + 30_000_000,
        "the corrected rate and the configured fee"
    );

    for (lane, class, want) in [
        ("gpt", "output", gpt_output),
        ("claude", "input", claude_input),
        ("plane-b\u{1f}search", "input", plane_b_input),
    ] {
        assert_eq!(
            priced_at(&history, lane, class, 1_000, 1, inside),
            Ok(want),
            "{lane}/{class} inside the corrected window prices at the configured card, fee included"
        );
    }
    assert_eq!(
        configured(&history, "gpt", "input"),
        2_000_000 + 30_000_000,
        "outside the window the configured card still prices the corrected cell"
    );
}

#[test]
fn a_fee_or_plane_correction_moves_only_what_it_names() {
    let history = a_full_card_history();
    let body = a_body(serde_json::json!({
        "effective_from": 0,
        "effective_until": 86_400_000,
        "per_request_fee": 7,
        "rates": [ { "lane": "plane-b\u{1f}search", "class": "input", "micro_per_unit": 9.0 } ],
        "reason": "vendor corrected the March price sheet",
    }));
    amend_through_a_journal(&history, &body, ARRIVED).expect("the correction applies");
    assert_eq!(
        priced_at(&history, "gpt", "output", 1_000, 1, 5_000),
        Ok(8_000_000 + 70_000_000),
        "gpt/output keeps its configured rate; the fee is the corrected 7"
    );
    assert_eq!(
        priced_at(&history, "plane-b\u{1f}search", "input", 1_000, 0, 5_000),
        Ok(9_000_000),
        "the plane's own cell is corrected"
    );
    assert_eq!(
        priced_at(&history, "plane-b\u{1f}search", "output", 1_000, 0, 5_000),
        Ok(6_000_000),
        "the plane's other cell is kept"
    );
}

fn a_card_at(micro_per_unit: f64, fee_minor: i64) -> busbar_kernel_ledger::cost::RateCard {
    busbar_kernel_ledger::cost::RateCard::from_micro_rates(
        [(
            busbar_kernel_ledger::cost::LaneClass::new(
                "gpt",
                busbar_kernel_ledger::cost::CLASS_INPUT,
            ),
            micro_per_unit,
        )],
        fee_minor,
    )
}

#[test]
fn a_correction_across_a_card_boundary_or_onto_an_absent_plane_is_refused() {
    let history = a_full_card_history();
    history.apply(a_card_at(4.0, 0), 6_000);
    let before = history.len();
    let refused = amend_through_a_journal(&history, &a_correction_body(), ARRIVED + 1);
    assert!(
        matches!(refused, Err(busbar_core_admin::GovernanceError::Validation)),
        "{refused:?}"
    );
    assert_eq!(
        history.len(),
        before,
        "a refused correction appends nothing"
    );

    let history = a_full_card_history();
    let body = a_body(serde_json::json!({
        "effective_from": 0,
        "effective_until": 86_400_000,
        "rates": [ { "lane": "plane-c\u{1f}hop", "class": "bytes", "micro_per_unit": 1.0 } ],
        "reason": "vendor corrected the March price sheet",
    }));
    let refused = amend_through_a_journal(&history, &body, ARRIVED);
    assert!(
        matches!(refused, Err(busbar_core_admin::GovernanceError::Validation)),
        "{refused:?}"
    );
    assert_eq!(history.len(), 1, "a refused correction appends nothing");
}

#[cfg(test)]
const DAY_MS: u64 = 86_400_000;
#[cfg(test)]
const HOUR_MS: u64 = 3_600_000;

#[cfg(test)]
fn a_window_correction(from: u64, until: Option<u64>) -> Vec<u8> {
    a_body(serde_json::json!({
        "effective_from": from,
        "effective_until": until,
        "rates": [ { "lane": "gpt", "class": "input", "micro_per_unit": 1.0 } ],
        "reason": "vendor corrected the March price sheet",
    }))
}

#[cfg(test)]
fn amend_at(
    history: &crate::root::kernel::RootHistory,
    body: &[u8],
    arrival_ms: u64,
) -> (
    Result<AdminAnswer, busbar_core_admin::GovernanceError>,
    usize,
) {
    let book = a_memory_book();
    let result = amend_rate_history_effect(
        history,
        Some(&a_journal_over(&book)),
        body,
        arrival_ms / 1_000,
        &an_attribution(),
    );
    let records = replayed_amendments(&book.lock().unwrap()).len();
    (result, records)
}

#[test]
fn a_correction_that_would_cut_inside_a_stored_row_is_refused() {
    let arrival = 2 * DAY_MS + 10 * HOUR_MS;
    for (from, until) in [
        (DAY_MS + 12 * HOUR_MS, Some(DAY_MS + 18 * HOUR_MS)),
        (DAY_MS, Some(DAY_MS + 6 * HOUR_MS)),
        (DAY_MS + 12 * HOUR_MS, None),
        (2 * DAY_MS + 12 * HOUR_MS, Some(3 * DAY_MS + 6 * HOUR_MS)),
    ] {
        let history = a_seeded_history();
        let (result, records) = amend_at(&history, &a_window_correction(from, until), arrival);
        assert!(
            matches!(result, Err(busbar_core_admin::GovernanceError::Validation)),
            "[{from}, {until:?}) cuts inside a row and must be refused: {result:?}"
        );
        assert_eq!(history.len(), 1, "[{from}, {until:?}): nothing appended");
        assert_eq!(records, 0, "[{from}, {until:?}): nothing recorded");
    }
}

#[test]
fn a_correction_on_row_boundaries_applies() {
    let arrival = 2 * DAY_MS + 10 * HOUR_MS;
    for (from, until) in [(DAY_MS, Some(2 * DAY_MS)), (0, Some(2 * DAY_MS))] {
        let history = a_seeded_history();
        let (result, records) = amend_at(&history, &a_window_correction(from, until), arrival);
        assert!(
            result.is_ok(),
            "[{from}, {until:?}) cuts no row: {result:?}"
        );
        assert_eq!((history.len(), records), (2, 1), "[{from}, {until:?})");
    }

    let era = DAY_MS;
    let history = a_seeded_history();
    history.apply(a_card_at(4.0, 0), era);
    let (result, records) = amend_at(
        &history,
        &a_window_correction(era, Some(2 * DAY_MS)),
        arrival,
    );
    assert!(
        result.is_ok(),
        "a config apply at a Store bucket boundary permits the complete bucket: {result:?}"
    );
    assert_eq!((history.len(), records), (3, 1));
}

#[test]
fn a_config_apply_inside_a_bucket_does_not_permit_a_partial_bucket_correction() {
    let era = DAY_MS + 12 * HOUR_MS;
    let history = a_seeded_history();
    history.apply(a_card_at(4.0, 0), era);
    let (result, records) = amend_at(
        &history,
        &a_window_correction(era, Some(2 * DAY_MS)),
        2 * DAY_MS + 10 * HOUR_MS,
    );
    assert!(matches!(
        result,
        Err(busbar_core_admin::GovernanceError::Validation)
    ));
    assert_eq!((history.len(), records), (2, 0));
}

#[test]
fn an_open_ended_amend_or_one_ending_after_its_arrival_is_refused() {
    let arrival = 2 * DAY_MS + 10 * HOUR_MS;
    for (from, until) in [
        (DAY_MS, None),
        (0, Some(3 * DAY_MS)),
        (DAY_MS, Some(arrival + 1)),
    ] {
        let history = a_seeded_history();
        let (result, records) = amend_at(&history, &a_window_correction(from, until), arrival);
        assert!(
            matches!(result, Err(busbar_core_admin::GovernanceError::Validation)),
            "[{from}, {until:?}) arriving at {arrival} must be refused: {result:?}"
        );
        assert_eq!(
            (history.len(), records),
            (1, 0),
            "nothing appended or recorded"
        );
    }
}

#[test]
fn a_future_dated_correction_is_refused_and_appends_nothing() {
    let arrival = 2 * DAY_MS + 10 * HOUR_MS;
    let future = (3 * DAY_MS, Some(4 * DAY_MS));
    for (from, until) in [
        future,
        (2 * DAY_MS + 12 * HOUR_MS, Some(2 * DAY_MS + 18 * HOUR_MS)),
        (2 * DAY_MS + 10 * HOUR_MS + 1_000, None),
    ] {
        let history = a_seeded_history();
        let (result, records) = amend_at(&history, &a_window_correction(from, until), arrival);
        assert!(
            matches!(result, Err(busbar_core_admin::GovernanceError::Validation)),
            "[{from}, {until:?}) opens after the arrival at {arrival} and must be refused: {result:?}"
        );
        assert_eq!(history.len(), 1, "[{from}, {until:?}): nothing appended");
        assert_eq!(records, 0, "[{from}, {until:?}): nothing recorded");
    }

    let history = a_seeded_history();
    let (result, records) = amend_at(
        &history,
        &a_window_correction(future.0, future.1),
        4 * DAY_MS + HOUR_MS,
    );
    assert!(
        result.is_ok(),
        "the same window, once past, applies: {result:?}"
    );
    assert_eq!((history.len(), records), (2, 1));
}

#[test]
fn a_replayed_signed_correction_is_refused_and_appends_nothing() {
    let book = a_memory_book();
    let journal = a_journal_over(&book);
    let history = a_seeded_history();
    let first = a_priced_correction(5, serde_json::json!(1.5));
    let apply = |body: &[u8], arrival_secs: u64| {
        amend_rate_history_effect(
            &history,
            Some(&journal),
            body,
            arrival_secs,
            &an_attribution(),
        )
    };
    apply(&first, ARRIVED).expect("the first correction applies");
    apply(&a_priced_correction(9, serde_json::json!(3.0)), ARRIVED + 1)
        .expect("a later correction of the same window applies");
    assert_eq!(history.len(), 3);

    let replayed = apply(&first, ARRIVED + 2);
    assert!(
        matches!(replayed, Err(busbar_core_admin::GovernanceError::Conflict)),
        "the first correction's signed bytes, sent again, must be refused: {replayed:?}"
    );
    assert_eq!(history.len(), 3, "a replay appends nothing");
    assert_eq!(
        replayed_amendments(&book.lock().unwrap()).len(),
        2,
        "a replay records nothing"
    );
    let pinned = history.pin().expect("pinned");
    let view = pinned.view();
    let (seq, card) = view.card_at(1_000).expect("the window is priced");
    assert_eq!(seq, view.seq().expect("the latest correction has a key"));
    assert_eq!(
        card.fee(),
        9,
        "the later correction still prices the window"
    );
}

#[cfg(test)]
struct AmendScratch(std::path::PathBuf, crate::root::store_double::RecordSlots);

#[cfg(test)]
impl AmendScratch {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "busbar-amend-journal-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("scratch directory");
        AmendScratch(path, crate::root::store_double::RecordSlots::new())
    }

    fn book(&self) -> Arc<Mutex<crate::root::durability::Durability>> {
        let lane =
            crate::root::durability::JournalLane::start(self.1.calls(), "test-store").unwrap();
        Arc::new(Mutex::new(
            crate::root::durability::build_on_store(
                &crate::root::durability::DurabilityConfig {
                    data_dir: Some(self.0.clone()),
                },
                0,
                lane,
                None,
            )
            .expect("the Store reads back"),
        ))
    }
}

#[cfg(test)]
impl Drop for AmendScratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
fn a_priced_correction(fee: i64, micro: serde_json::Value) -> Vec<u8> {
    a_body(serde_json::json!({
        "effective_from": 0,
        "effective_until": 86_400_000,
        "per_request_fee": fee,
        "rates": [ { "lane": "gpt", "class": "input", "micro_per_unit": micro } ],
        "reason": "vendor corrected the March price sheet",
    }))
}

#[test]
fn a_sealed_amendment_survives_a_restart_with_its_figures() {
    let scratch = AmendScratch::new("restart");
    {
        let book = scratch.book();
        let history = a_seeded_history();
        amend_rate_history_effect(
            &history,
            Some(&a_journal_over(&book)),
            &a_priced_correction(5, serde_json::json!(1.5)),
            ARRIVED,
            &an_attribution(),
        )
        .expect("the correction applies");
    }

    let restarted = scratch.book();
    assert!(restarted.lock().unwrap().durable_in_store());
    assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    let records = replayed_amendments(&restarted.lock().unwrap());
    assert_eq!(records.len(), 1, "the amendment survived the restart");
    let record = &records[0];
    assert_eq!(record.effective_from, 0);
    assert_eq!(record.effective_until, Some(86_400_000));
    assert_eq!(record.amended_at_ms, ARRIVED * 1_000);
    assert_eq!(record.sealed_fee, 5);
    assert_eq!(
        record.rates,
        vec![("gpt".to_string(), "input".to_string(), Some(1_500))],
        "1.5 micro per unit is sealed as 1500 nano per unit"
    );
    assert_eq!(record.operator_fingerprint, "");
    assert_eq!(record.principal, "admin");
    assert_eq!(record.dual_control, "single");
    assert_eq!(record.signature, "");
    assert!(
        record
            .signed_payload
            .starts_with(b"busbar/amend-rate-history/v1\n"),
        "the record keeps the correction's canonical bytes"
    );
}

#[test]
fn a_correction_rate_is_sealed_as_an_exact_integer_or_refused() {
    for (micro, nanos) in [
        (serde_json::json!(1.5), 1_500),
        (serde_json::json!(0.001), 1),
        (serde_json::json!(2e-3), 2),
        (serde_json::json!(7), 7_000),
        (serde_json::json!(0.0), 0),
    ] {
        let scratch = AmendScratch::new("exact-rate");
        let book = scratch.book();
        amend_rate_history_effect(
            &a_seeded_history(),
            Some(&a_journal_over(&book)),
            &a_priced_correction(0, micro.clone()),
            ARRIVED,
            &an_attribution(),
        )
        .unwrap_or_else(|e| panic!("{micro} is exactly {nanos} nano-units: {e:?}"));
        let records = replayed_amendments(&book.lock().unwrap());
        assert_eq!(
            records[0].rates,
            vec![("gpt".to_string(), "input".to_string(), Some(nanos))],
            "{micro} micro per unit is sealed as exactly {nanos} nano per unit"
        );
    }
    for micro in [
        serde_json::json!(0.0001),
        serde_json::json!(0.0015),
        serde_json::json!(-1.0),
        serde_json::json!(1e30),
        serde_json::json!("1.5"),
    ] {
        let scratch = AmendScratch::new("inexact-rate");
        let book = scratch.book();
        let history = a_seeded_history();
        let before = history.history().expect("a history").len();
        let refused = amend_rate_history_effect(
            &history,
            Some(&a_journal_over(&book)),
            &a_priced_correction(0, micro.clone()),
            ARRIVED,
            &an_attribution(),
        );
        assert!(
            matches!(refused, Err(busbar_core_admin::GovernanceError::Validation)),
            "{micro} is not an exact integer of nano-units and must be refused: {refused:?}"
        );
        assert_eq!(
            history.history().expect("a history").len(),
            before,
            "{micro}: a refused correction appends nothing to the history"
        );
        assert!(
            replayed_amendments(&book.lock().unwrap()).is_empty(),
            "{micro}: a refused correction journals nothing"
        );
    }
}

#[test]
fn a_thousand_later_amendments_do_not_erase_the_first() {
    let scratch = AmendScratch::new("volume");
    {
        let book = scratch.book();
        let journal = a_journal_over(&book);
        let history = a_seeded_history();
        amend_rate_history_effect(
            &history,
            Some(&journal),
            &a_priced_correction(7, serde_json::json!(2.0)),
            ARRIVED,
            &an_attribution(),
        )
        .expect("the first correction applies");

        for fee in 8..1_008 {
            amend_rate_history_effect(
                &history,
                Some(&journal),
                &a_priced_correction(fee, serde_json::json!(1.0)),
                ARRIVED + 1,
                &an_attribution(),
            )
            .expect("a later correction applies");
        }
    }
    let restarted = scratch.book();
    assert!(restarted.lock().unwrap().durable_in_store());
    assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    let records = replayed_amendments(&restarted.lock().unwrap());
    assert_eq!(records.len(), 1_001, "every amendment is on the journal");
    assert_eq!(
        records[0].sealed_fee, 7,
        "the first amendment is still first"
    );
    assert_eq!(
        records[0].rates,
        vec![("gpt".to_string(), "input".to_string(), Some(2_000))]
    );
    assert_eq!(records[0].amended_at_ms, ARRIVED * 1_000);
}

#[test]
fn an_amendment_with_no_journal_bound_is_refused_and_appends_nothing() {
    let history = a_seeded_history();
    let err = amend_rate_history_effect(
        &history,
        None,
        &a_correction_body(),
        ARRIVED,
        &an_attribution(),
    )
    .expect_err("no journal, no amendment");
    assert!(matches!(err, busbar_core_admin::GovernanceError::Store));
    assert_eq!(history.len(), 1);

    let book = a_memory_book();
    amend_rate_history_effect(
        &history,
        Some(&a_journal_over(&book)),
        &a_correction_body(),
        ARRIVED,
        &an_attribution(),
    )
    .expect("with a journal the correction applies");
    assert_eq!(history.len(), 2);
    assert_eq!(replayed_amendments(&book.lock().unwrap()).len(), 1);
}

#[test]
fn a_refused_amendment_leaves_no_record() {
    let book = a_memory_book();
    let history = a_seeded_history();
    amend_rate_history_effect(
        &history,
        Some(&a_journal_over(&book)),
        &a_priced_correction(-5, serde_json::json!(1.0)),
        ARRIVED,
        &an_attribution(),
    )
    .expect_err("refused");
    assert_eq!(history.len(), 1);
    assert!(replayed_amendments(&book.lock().unwrap()).is_empty());
}

#[test]
fn amend_rate_history_refuses_a_correction_that_names_no_reason_window_or_price() {
    let cases: &[serde_json::Value] = &[
        serde_json::json!({ "effective_from": 1, "rates": [{"lane":"gpt","class":"input","micro_per_unit":1.0}] }),
        serde_json::json!({ "effective_from": 9, "effective_until": 1, "rates": [{"lane":"gpt","class":"input","micro_per_unit":1.0}], "reason": "r" }),
        serde_json::json!({ "effective_from": 1, "reason": "r" }),
        serde_json::json!({ "rates": [{"lane":"gpt","class":"input","micro_per_unit":1.0}], "reason": "r" }),
    ];
    for case in cases {
        let history = a_seeded_history();
        let body = serde_json::to_vec(case).expect("serialises");
        let err = amend_through_a_journal(&history, &body, ARRIVED)
            .expect_err("a malformed correction must be refused");
        assert!(
            matches!(err, busbar_core_admin::GovernanceError::Validation),
            "{case} must refuse Validation, got {err:?}"
        );
        assert_eq!(
            history.len(),
            1,
            "a refused correction appends nothing: {case}"
        );
    }

    let history = a_seeded_history();
    assert!(matches!(
        amend_through_a_journal(&history, b"not json", ARRIVED),
        Err(busbar_core_admin::GovernanceError::Validation)
    ));
    assert_eq!(history.len(), 1);
}

#[test]
fn amend_rate_history_refuses_when_there_is_no_history_to_amend() {
    let empty = crate::root::kernel::RootHistory::default();
    let err = amend_through_a_journal(&empty, &a_correction_body(), ARRIVED)
        .expect_err("an empty history cannot be amended");
    assert!(matches!(err, busbar_core_admin::GovernanceError::NotFound));
    assert_eq!(empty.len(), 0);
}

#[test]
fn amend_rate_history_applies_a_correction_that_carries_no_signature() {
    let history = a_seeded_history();
    let body = a_correction_body();
    let doc: serde_json::Value = serde_json::from_slice(&body).expect("the body is JSON");
    assert!(doc.get("signature").is_none() && doc.get("operator_fingerprint").is_none());
    let answer =
        amend_through_a_journal(&history, &body, ARRIVED).expect("an unsigned correction applies");
    assert_eq!(answer.status, 200);
    let doc: serde_json::Value = serde_json::from_slice(&answer.body).expect("JSON");
    assert!(
        doc.get("operator_fingerprint").is_none(),
        "the answer names no signer: {doc}"
    );
    assert_eq!(history.len(), 2, "the correction appended one entry");
}

#[test]
fn amend_rate_history_ignores_a_signature_a_body_still_carries() {
    let history = a_seeded_history();
    let mut doc: serde_json::Value =
        serde_json::from_slice(&a_correction_body()).expect("the body is JSON");
    doc["operator_fingerprint"] = serde_json::json!("a-fingerprint-nothing-checks");
    doc["signature"] = serde_json::json!("00".repeat(64));
    let answer = amend_through_a_journal(&history, &a_body(doc), ARRIVED)
        .expect("a body carrying a stale signature still applies");
    let doc: serde_json::Value = serde_json::from_slice(&answer.body).expect("JSON");
    assert!(
        doc.get("operator_fingerprint").is_none(),
        "the answer names no signer: {doc}"
    );
}

#[cfg(feature = "root-admin")]
#[test]
fn a_signed_record_verifies_against_the_served_audit_keys() {
    use busbar_contract::caps::{OriginKind, Outcome as UnitOutcome, UnitKey};
    use busbar_kernel_audit::{
        Audit as _, AuditChain, AuditInputs, AuditVerifyingKey, Controls, FinishClass, OpClassId,
        OutcomeFacts, Subject, Usage, What,
    };

    let inputs = || AuditInputs {
        subject: Subject::PrincipalId("pseudonym-keyset".into()),
        what: What {
            unit_key: UnitKey::new(1),
            incarnation: 0,
            op_class: OpClassId::new("chat.completion"),
            destination: Some("upstream-a".into()),
            parent: None,
            pre_hook_head: None,
            post_hook_head: None,
        },
        wall: 1_700_000_001,
        mono: 1_000,
        origin: crate::root::kernel::new_kernel().origin(OriginKind::Client),
        outcome: OutcomeFacts {
            unit_end: UnitOutcome::Completed,
            step: None,
            finish: FinishClass::Complete,
            hook_failed: false,
            emission_delta: 0,
            stale_policy: false,
        },
        usage: Usage {
            lines: Vec::new(),
            tier_bp: 10_000,
            fee_count: 1,
            rate_card_version: Some([1; 20]),
            bucket_chain_ref: "chain:free".into(),
        },
        controls: Controls::default(),
        correlation_label: None,
    };
    let audit_token = an_audit_pass();
    let served_keys = |units: crate::root::kernel::ProductionUnits| -> Vec<String> {
        let node = AdminNode::new(crate::root::kernel::new_kernel(), units);
        let served: serde_json::Value = serde_json::from_slice(
            &node
                .answer(a_ledger_request("/api/v1/admin/audit/keys"))
                .body,
        )
        .expect("valid JSON");
        served["keys"]
            .as_array()
            .expect("keys")
            .iter()
            .map(|k| k["public_key"].as_str().expect("public_key").to_string())
            .collect()
    };

    let units =
        crate::root::kernel::ProductionUnits::admin_only(Arc::new(AnsweringDispatch), open_door());
    let record = {
        let mut durability = units.durability.lock().expect("durability lock");
        durability.record.seal(inputs(), &audit_token)
    };
    assert!(
        served_keys(units).is_empty(),
        "a keyless node publishes no key"
    );
    assert!(record.signature.is_none());

    let units =
        crate::root::kernel::ProductionUnits::admin_only(Arc::new(AnsweringDispatch), open_door());
    let record = {
        let mut durability = units.durability.lock().expect("durability lock");
        crate::root::keyset::bind_ephemeral(&mut durability).expect("the keyset binds");
        durability.record.seal(inputs(), &audit_token)
    };
    let published = served_keys(units);
    assert_eq!(published.len(), 1, "the one deployment key is published");
    let key = AuditVerifyingKey::from_hex(&published[0]).expect("a published public key");
    assert_eq!(record.key_id.as_deref(), Some(key.key_id()));
    AuditChain::verify_signature(&record, &key)
        .expect("the signed record verifies against the served key");
}

#[cfg(test)]
fn a_book_over_the_store(
    slots: &crate::root::store_double::RecordSlots,
) -> Arc<Mutex<crate::root::durability::Durability>> {
    let lane = crate::root::durability::JournalLane::start(slots.calls(), "test-store")
        .expect("the lane starts");
    Arc::new(Mutex::new(
        crate::root::durability::build_on_store(
            &crate::root::durability::DurabilityConfig { data_dir: None },
            0,
            lane,
            None,
        )
        .expect("the store reads back"),
    ))
}

#[cfg(test)]
fn status_and_body(answer: &AdminAnswer) -> (u16, String) {
    (
        answer.status,
        String::from_utf8_lossy(&answer.body).into_owned(),
    )
}

#[test]
fn a_correction_on_a_node_with_no_data_dir_is_kept_by_the_store_and_survives_a_restart() {
    let slots = crate::root::store_double::RecordSlots::new();
    {
        let book = a_book_over_the_store(&slots);
        let answered = amend_rate_history_effect(
            &a_seeded_history(),
            Some(&a_journal_over(&book)),
            &a_priced_correction(5, serde_json::json!(1.5)),
            ARRIVED,
            &an_attribution(),
        )
        .expect("the correction applies");
        let (status, body) = status_and_body(&answered);
        assert_eq!(status, 200, "{body}");
    }
    let restarted = a_book_over_the_store(&slots);
    let records = replayed_amendments(&restarted.lock().unwrap());
    assert_eq!(
        records.len(),
        1,
        "the store kept the amendment and the restart read it back"
    );
    assert_eq!(records[0].sealed_fee, 5);
}

#[test]
fn a_correction_the_store_refuses_answers_503_with_the_reason() {
    let slots = crate::root::store_double::RecordSlots::new();
    slots.refuse(true);
    let book = a_book_over_the_store(&slots);
    let answered = amend_rate_history_effect(
        &a_seeded_history(),
        Some(&a_journal_over(&book)),
        &a_priced_correction(5, serde_json::json!(1.5)),
        ARRIVED,
        &an_attribution(),
    )
    .expect("an answer, not an error");
    let (status, body) = status_and_body(&answered);
    assert_eq!(status, 503, "{body}");
    assert!(
        body.contains("the test store refuses writes"),
        "the store's reason is stated: {body}"
    );

    let before = book.lock().unwrap().journal.next_seq();
    let again = amend_rate_history_effect(
        &a_seeded_history(),
        Some(&a_journal_over(&book)),
        &a_priced_correction(6, serde_json::json!(2)),
        ARRIVED + 1,
        &an_attribution(),
    )
    .expect("an answer");
    assert_eq!(status_and_body(&again).0, 503);
    assert_eq!(
        book.lock().unwrap().journal.next_seq(),
        before,
        "nothing is recorded while the store refuses"
    );
}

#[test]
fn commit_upgrade_answers_only_once_the_store_kept_its_record() {
    let body = serde_json::to_vec(&serde_json::json!({ "version": bound::RUNNING_RELEASE }))
        .expect("json");

    let refusing = crate::root::store_double::RecordSlots::new();
    refusing.refuse(true);
    let book = a_book_over_the_store(&refusing);
    let answer =
        bound::commit_upgrade_effect(&body, 1_700_000_000, "admin", Some(&a_journal_over(&book)))
            .expect("an answer");
    assert_eq!(
        answer.status,
        503,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert!(String::from_utf8_lossy(&answer.body).contains("the test store refuses writes"));

    let taking = crate::root::store_double::RecordSlots::new();
    let book = a_book_over_the_store(&taking);
    let answer =
        bound::commit_upgrade_effect(&body, 1_700_000_000, "admin", Some(&a_journal_over(&book)))
            .expect("an answer");
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert!(taking.rows_under(crate::root::durability::JOURNAL_SCHEMA) >= 1);
}

#[cfg(test)]
struct SwitchShipper(Arc<std::sync::atomic::AtomicBool>);

#[cfg(test)]
impl busbar_kernel_wal::Shipper<busbar_kernel_wal::Record> for SwitchShipper {
    fn ship(
        &mut self,
        _records: &[busbar_kernel_wal::Record],
    ) -> Result<(), busbar_kernel_wal::ShipError> {
        if self.0.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(busbar_kernel_wal::ShipError::Unavailable(
                "the store is not answering".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
fn a_book_whose_store_switches(
    refusing: &Arc<std::sync::atomic::AtomicBool>,
) -> Arc<Mutex<crate::root::durability::Durability>> {
    Arc::new(Mutex::new(
        crate::root::durability::build(
            &crate::root::durability::DurabilityConfig { data_dir: None },
            Box::new(SwitchShipper(Arc::clone(refusing))),
        )
        .expect("a memory-buffered journal cannot fail to open"),
    ))
}

#[cfg(test)]
fn append_the_next_record(book: &Arc<Mutex<crate::root::durability::Durability>>) {
    book.lock()
        .unwrap()
        .journal
        .append(
            &crate::root::kernel::new_kernel().durability_token(),
            busbar_contract::caps::StepName::Meter,
            &[
                busbar_kernel_wal::Entry::new(busbar_kernel_wal::RecordClass::Load, vec![1])
                    .at(7, 0),
            ],
        )
        .expect("the store answers again and the next record lands");
}

#[test]
fn a_correction_the_journal_retained_is_in_force_and_answered_not_yet_kept() {
    let refusing = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let book = a_book_whose_store_switches(&refusing);
    refusing.store(true, std::sync::atomic::Ordering::SeqCst);
    let history = a_seeded_history();
    let answered = amend_rate_history_effect(
        &history,
        Some(&a_journal_over(&book)),
        &a_priced_correction(5, serde_json::json!(1.5)),
        ARRIVED,
        &an_attribution(),
    )
    .expect("a correction the journal chained is answered, never refused as unrecorded");
    let (status, body) = status_and_body(&answered);
    assert_eq!(status, 503, "{body}");
    assert!(body.contains("do not re-submit"), "{body}");
    assert_eq!(
        history.len(),
        2,
        "the correction is in force on the live node from the moment its record is chained"
    );

    refusing.store(false, std::sync::atomic::Ordering::SeqCst);
    append_the_next_record(&book);
    assert_eq!(
        replayed_amendments(&book.lock().unwrap()).len(),
        1,
        "the retained record landed on the chain a restart rebuilds the history from"
    );
    assert!(
        matches!(
            amend_rate_history_effect(
                &history,
                Some(&a_journal_over(&book)),
                &a_priced_correction(5, serde_json::json!(1.5)),
                ARRIVED + 1,
                &an_attribution(),
            ),
            Err(busbar_core_admin::GovernanceError::Conflict)
        ),
        "a re-submission is refused: the correction is already applied"
    );
    assert_eq!(history.len(), 2);
}

#[test]
fn a_commit_the_journal_retained_is_answered_not_yet_kept_and_lands() {
    let refusing = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let book = a_book_whose_store_switches(&refusing);
    refusing.store(true, std::sync::atomic::Ordering::SeqCst);
    let body = serde_json::to_vec(&serde_json::json!({ "version": bound::RUNNING_RELEASE }))
        .expect("json");
    let answer =
        bound::commit_upgrade_effect(&body, 1_700_000_000, "admin", Some(&a_journal_over(&book)))
            .expect("a commit the journal chained is answered, never refused as unrecorded");
    let text = String::from_utf8_lossy(&answer.body).into_owned();
    assert_eq!(answer.status, 503, "{text}");
    assert!(text.contains("do not re-submit"), "{text}");

    refusing.store(false, std::sync::atomic::Ordering::SeqCst);
    append_the_next_record(&book);
    let commits = book
        .lock()
        .unwrap()
        .journal
        .replay()
        .expect("the journal reads back")
        .expect("the journal verifies")
        .iter()
        .filter(|r| r.class == busbar_kernel_wal::RecordClass::Policy)
        .count();
    assert_eq!(commits, 1, "the retained commit landed on the chain");
}

#[test]
fn a_keyed_commit_with_a_late_store_ack_seals_one_policy() {
    let slots = crate::root::store_double::RecordSlots::new();
    let book = a_book_over_the_store(&slots);
    let journal = Arc::new(a_journal_over(&book));
    append_the_next_record(&book);
    journal
        .acked(journal.sealed_through())
        .expect("healthy journal");
    journal.admit().expect("admitted before the store pends");
    let store: Arc<dyn busbar_contract::records::RecordStore> = crate::root::real_store::records();
    let replay_store: bound::ReplayStore = Arc::new(move || Some(Arc::clone(&store)));
    let mut request = a_request();
    request.method = "POST".into();
    request.path = "/api/v1/admin/commit-upgrade".into();
    request.headers = vec![("idempotency-key".into(), "late-commit-ack".into())];
    request.body =
        serde_json::to_vec(&serde_json::json!({ "version": bound::RUNNING_RELEASE })).unwrap();
    let cache = Arc::new(bound::ReplayCache::new());
    let admin = crate::root::kernel::new_kernel().admin_token();
    let ask = |cache: Arc<bound::ReplayCache>,
               request: &AdminRequest,
               journal: Option<Arc<AmendmentJournal>>| {
        let governance = CoreGovernance::new(
            Arc::new(RefusingDispatch),
            Arc::new(UnopenedLedger),
            None,
            KernelVerb::CommitUpgrade,
            request.clone(),
        )
        .amending(
            journal,
            AmendAttribution {
                principal: "admin".into(),
            },
        )
        .replaying(cache, Some(Arc::clone(&replay_store)));
        busbar_core_admin::Governance::execute_new_verb(
            &governance,
            KernelVerb::CommitUpgrade,
            &admin,
            &request.body,
        )
        .expect("the production caller answers")
    };
    struct Unpause<'a>(&'a crate::root::store_double::RecordSlots);
    impl Drop for Unpause<'_> {
        fn drop(&mut self) {
            self.0.pause(false);
        }
    }
    slots.pause(true);
    let release = Unpause(&slots);
    let first = ask(Arc::clone(&cache), &request, Some(Arc::clone(&journal)));
    assert_eq!(
        first.status,
        503,
        "{}",
        String::from_utf8_lossy(&first.body)
    );
    assert!(String::from_utf8_lossy(&first.body).contains("do not re-submit"));
    assert!(slots.waiting() > 0, "the real Store future reached Pending");
    let sealed = journal.sealed_through();
    drop(release);
    journal
        .acked(sealed)
        .expect("the first receipt is now acknowledged");
    assert_eq!(
        ask(Arc::clone(&cache), &request, Some(Arc::clone(&journal))),
        first
    );
    request.at += busbar_core_admin::idempotency::IDEMPOTENCY_TTL_SECS + 1;
    assert_eq!(
        ask(Arc::clone(&cache), &request, Some(Arc::clone(&journal))),
        first,
        "TTL cannot release the retained receipt"
    );
    assert_eq!(
        ask(
            Arc::new(bound::ReplayCache::new()),
            &request,
            Some(Arc::clone(&journal))
        ),
        first,
        "restart keeps the receipt"
    );
    assert_eq!(
        ask(Arc::new(bound::ReplayCache::new()), &request, None),
        first,
        "a sibling cannot replace the originating receipt"
    );
    assert_eq!(
        journal.sealed_through(),
        sealed,
        "reconciliation seals nothing"
    );
    let chain = { book.lock().unwrap().chain_at() }.read().unwrap().unwrap();
    assert_eq!(
        chain
            .iter()
            .filter(|record| record.class == busbar_kernel_wal::RecordClass::Policy)
            .count(),
        1
    );
}

#[test]
fn a_keyed_commit_refused_before_sealing_accepts_corrected_input() {
    let book = a_memory_book();
    let journal = a_journal_over(&book);
    let store: Arc<dyn busbar_contract::records::RecordStore> = crate::root::real_store::records();
    let replay_store: bound::ReplayStore = Arc::new(move || Some(Arc::clone(&store)));
    let cache = bound::ReplayCache::new();
    let mut request = a_request();
    request.headers = vec![("idempotency-key".into(), "corrected-commit".into())];
    request.body = br#"{"version":"not-this-binary"}"#.to_vec();
    let ask = |request: &AdminRequest| {
        bound::replayable(
            &cache,
            Some(&replay_store),
            bound::ReplayScope {
                verb: KernelVerb::CommitUpgrade,
                actor: "admin",
            },
            request,
            &request.body,
            Some(&journal),
            || bound::commit_upgrade_effect(&request.body, request.at, "admin", Some(&journal)),
        )
        .expect("the write answers")
    };
    let before = journal.sealed_through();
    assert_eq!(ask(&request).status, 409);
    assert_eq!(
        journal.sealed_through(),
        before,
        "a definite refusal sealed nothing"
    );
    request.body =
        serde_json::to_vec(&serde_json::json!({ "version": bound::RUNNING_RELEASE })).unwrap();
    let accepted = ask(&request);
    assert_eq!(accepted.status, 200);
    assert_eq!(ask(&request), accepted);
    assert_eq!(journal.sealed_through(), before + 1);
}

#[test]
#[cfg(feature = "root-admin")]
fn route_refuses_a_unit_whose_grant_was_never_recorded() {
    let admin = crate::root::kernel::new_kernel().admin_token();
    let binding = AdminBinding::new(Arc::new(AnsweringDispatch), open_door());
    let mut request = a_request();
    request.method = "POST".to_string();
    request.path = "/api/v1/admin/chain-break".to_string();
    let mut walk = AdminWalk::new(request);
    decode(&mut walk).expect("the plane's table declares this operation");

    let outcome = route(&binding, None, &admin, &mut walk);
    assert_eq!(
        outcome,
        Err(ReasonCode::ScopeDenied),
        "a unit with no recorded grant reached the verb"
    );
}

#[test]
fn a_keyed_write_retried_after_a_restart_replays_and_runs_nothing_again() {
    let store: Arc<dyn busbar_contract::records::RecordStore> = crate::root::real_store::records();
    let held = Arc::clone(&store);
    let replay_store: bound::ReplayStore = Arc::new(move || Some(Arc::clone(&held)));
    let request = AdminRequest {
        method: "POST".to_string(),
        path: "/api/v1/admin/plane-records".to_string(),
        credential: None,
        headers: vec![("idempotency-key".to_string(), "restart-d3".to_string())],
        body: br#"{"record":1}"#.to_vec(),
        at: 1_700_000_000,
        unit: a_fresh_unit(),
    };
    let ran = std::sync::atomic::AtomicUsize::new(0);
    let effect = || {
        let n = ran.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(bound::EffectAnswer::applied(AdminAnswer {
            status: 201,
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            body: format!(r#"{{"run":{n}}}"#).into_bytes(),
        }))
    };
    let first = bound::replayable(
        &bound::ReplayCache::new(),
        Some(&replay_store),
        bound::ReplayScope {
            verb: KernelVerb::PlaneRecordWrite,
            actor: "operator",
        },
        &request,
        &request.body,
        None,
        effect,
    )
    .expect("the first write answers");

    let retried = bound::replayable(
        &bound::ReplayCache::new(),
        Some(&replay_store),
        bound::ReplayScope {
            verb: KernelVerb::PlaneRecordWrite,
            actor: "operator",
        },
        &request,
        &request.body,
        None,
        effect,
    )
    .expect("the retry answers");
    assert_eq!(retried, first, "the retry answers the first answer's bytes");
    assert_eq!(
        ran.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the effect ran once across the restart"
    );
}

#[cfg(feature = "root-admin")]
#[tokio::test]
async fn a_unit_this_root_did_not_compose_is_not_sealed_as_an_admin_read() {
    use tower::ServiceExt;

    let inner = axum::Router::new().fallback(axum::routing::any(|| async { "the surface" }));
    let book: Arc<std::sync::OnceLock<Arc<Mutex<crate::root::durability::Durability>>>> =
        Arc::new(std::sync::OnceLock::new());
    let kept = Arc::clone(&book);
    let wrapped = mount(
        inner,
        busbar_kernel::teller::Kernel::new(),
        1024,
        move |dispatch| {
            let units = crate::root::kernel::ProductionUnits::admin_only(dispatch, open_door());
            let _ = kept.set(Arc::clone(&units.durability));
            units
        },
    );
    let book = Arc::clone(book.get().expect("the mount built its units"));
    let sealed = || {
        let mut held = Vec::new();
        NodeAudit::new(Arc::clone(&book)).read(&mut |_, records| {
            held = records.map(<[_]>::to_vec).unwrap_or_default();
        });
        held
    };
    let get = |path: &str| {
        axum::http::Request::builder()
            .method("GET")
            .uri(path)
            .body(axum::body::Body::empty())
            .expect("the request builds")
    };
    let admin_read = busbar_kernel_audit::OpClassId::new(OP_UNRESOLVED_READ);

    for uncomposed in ["/v1/chat/completions", "/api/v1/admin/not-a-real-operation"] {
        let response = wrapped
            .clone()
            .oneshot(get(uncomposed))
            .await
            .expect("the router answers");
        let records = sealed();
        assert!(
            records.iter().all(|r| r.what.op_class != admin_read),
            "{uncomposed} was sealed as an administrative read: {records:?}"
        );
        assert!(
            records.is_empty(),
            "{uncomposed} is no admin unit and seals no admin record: {records:?}"
        );
        assert_eq!(
            response.status(),
            200,
            "{uncomposed} reached the surface below"
        );
    }

    let response = wrapped
        .oneshot(get("/api/v1/admin/audit?limit=4"))
        .await
        .expect("the router answers");
    assert_eq!(response.status(), 200);
    let records = sealed();
    assert_eq!(records.len(), 1, "one declared admin unit, one record");
    assert_eq!(records[0].what.op_class, admin_read);
}

#[cfg(feature = "root-admin")]
#[tokio::test]
async fn a_claimed_length_is_checked_against_the_bytes_not_trusted() {
    use tower::ServiceExt;

    let inner = axum::Router::new().fallback(axum::routing::any(|| async { "the surface" }));
    let wrapped = mount(inner, busbar_kernel::teller::Kernel::new(), 4, |dispatch| {
        crate::root::kernel::ProductionUnits::admin_only(dispatch, open_door())
    });
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/api/v1/admin/keys")
        .header(axum::http::header::CONTENT_LENGTH, "3")
        .body(axum::body::Body::from(b"0123456789".to_vec()))
        .expect("the request builds");
    let response = wrapped.oneshot(request).await.expect("the router answers");
    assert_eq!(
        response.status(),
        400,
        "a body longer than the cap is refused whatever length it declared"
    );
}

fn amendment_codec_fixture(version: u8, key_bytes: &[u8]) -> Vec<u8> {
    let mut body = busbar_kernel_wal::BodyWriter::new();
    body.text(&format!("busbar/rate-amendment/v{version}"));
    body.num(0);
    body.num(1);
    body.num(100);
    body.num(300);
    if version == 4 {
        body.bytes(key_bytes);
        body.bytes(&[7; 32]);
    }
    if version == 3 {
        body.num(17);
        body.bytes(&[7; 32]);
    }
    body.figure(9);
    body.num(1);
    body.text("model");
    body.text("input");
    if version >= 2 {
        body.num(1);
    }
    body.num(19);
    body.text("old-operator");
    body.bytes(&[8; 32]);
    body.text("admin");
    body.text("single");
    body.bytes(b"original payload");
    body.text("old-signature");
    body.finish()
}

#[test]
fn original_v1_v2_v3_and_keyed_v4_amendments_retain_their_exact_byte_formats() {
    for version in 1..=4 {
        let bytes = amendment_codec_fixture(version, &[0x4a; 20]);
        let record = amendment_from_body(&bytes).expect("the original durable format decodes");
        assert_eq!(amendment_body(&record).unwrap(), bytes);
        assert_eq!(
            record.version,
            match version {
                1 => AmendmentVersion::V1,
                2 => AmendmentVersion::V2,
                3 => AmendmentVersion::V3,
                _ => AmendmentVersion::V4,
            }
        );
        match record.sealed_over {
            Some(crate::root::kernel::CorrectionBase::Key { key, card_digest }) => {
                assert_eq!(version, 4);
                assert_eq!(key.as_bytes(), &[0x4a; 20]);
                assert_eq!(card_digest, [7; 32]);
            }
            Some(crate::root::kernel::CorrectionBase::LegacyOrdinal { seq, card_digest }) => {
                assert_eq!(version, 3);
                assert_eq!(seq.get(), 17);
                assert_eq!(card_digest, [7; 32]);
            }
            None => assert!(version <= 2),
        }
    }
}

#[test]
fn amendment_key_lengths_trailing_bytes_and_version_base_mismatches_fail_closed() {
    for len in [0, 19, 21] {
        assert!(amendment_from_body(&amendment_codec_fixture(4, &vec![0x4a; len])).is_none());
    }
    for version in 1..=4 {
        let mut bytes = amendment_codec_fixture(version, &[0x4a; 20]);
        bytes.push(0);
        assert!(amendment_from_body(&bytes).is_none());
    }
    let mut record = amendment_from_body(&amendment_codec_fixture(4, &[0x4a; 20])).unwrap();
    record.version = AmendmentVersion::V3;
    assert!(amendment_body(&record).is_err());
    record.version = AmendmentVersion::V1;
    record.sealed_over = None;
    record.rates[0].2 = None;
    assert!(amendment_body(&record).is_err());
    record.version = AmendmentVersion::V2;
    let encoded = amendment_body(&record).unwrap();
    assert_eq!(amendment_from_body(&encoded).unwrap(), record);
}
