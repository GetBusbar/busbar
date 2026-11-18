// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::json::JsonContainerTrait as _;
use busbar_contract::json::{self, JsonValueTrait};

#[test]
fn cloned_admin_carrier_keeps_original_empty_request_and_exact_query_presence() {
    use busbar_kernel::inbound::request_snapshot::{ChargedRequestSnapshot, SnapshotInput};
    use busbar_kernel::limits::process_admission::{AdmissionClass, ProcessAdmission};

    let process = ProcessAdmission::new(2);
    let lease = process.try_enter(AdmissionClass::Data).unwrap();
    let fields = [
        ("x-original", b"\xff".as_slice()),
        ("x-original", b"second"),
    ];
    let snapshot = ChargedRequestSnapshot::capture(
        SnapshotInput {
            method: "GET",
            path: "/api/v1/admin/audit",
            query: "",
            query_present: true,
            authority: "node.example",
            headers: fields.iter().copied(),
            peer: "192.0.2.1:42",
            tls_peer_cert: b"certificate",
            body: &[],
            now_s: 42,
        },
        &lease,
    )
    .unwrap();
    let request = AdminRequest::from_snapshot(snapshot.clone(), 7);
    let retained = request.clone();
    assert!(Arc::ptr_eq(request.snapshot(), retained.snapshot()));
    assert!(retained.snapshot().request().same_request(&lease));
    assert_eq!(retained.path(), "/api/v1/admin/audit?");
    assert_eq!(retained.headers().collect::<Vec<_>>(), fields);
    assert_eq!(retained.snapshot().peer(), "192.0.2.1:42");
    assert_eq!(retained.snapshot().tls_peer_cert(), b"certificate");
    drop((request, snapshot, lease));
    assert!(process.try_enter(AdmissionClass::Data).is_err());
    drop(retained);
    assert!(process.try_enter(AdmissionClass::Data).is_ok());
}

#[test]
fn admin_http_body_projection_retains_same_snapshot_without_copying() {
    use busbar_kernel::inbound::request_snapshot::{ChargedRequestSnapshot, SnapshotInput};
    use busbar_kernel::limits::process_admission::{AdmissionClass, ProcessAdmission};

    let process = ProcessAdmission::new(2);
    let lease = process.try_enter(AdmissionClass::Data).unwrap();
    let snapshot = ChargedRequestSnapshot::capture(
        SnapshotInput {
            method: "POST",
            path: "/api/v1/admin/config/apply",
            query: "",
            query_present: false,
            authority: "node",
            headers: std::iter::empty(),
            peer: "",
            tls_peer_cert: &[],
            body: b"original body",
            now_s: 1,
        },
        &lease,
    )
    .unwrap();
    let request = AdminRequest::from_snapshot(snapshot, 8);
    let projected = request.snapshot().body_bytes();
    assert_eq!(projected.as_ptr(), request.body().as_ptr());
    drop((request, lease));
    assert!(process.try_enter(AdmissionClass::Data).is_err());
    assert_eq!(projected.as_ref(), b"original body");
    drop(projected);
    assert!(process.try_enter(AdmissionClass::Data).is_ok());
}

fn a_fresh_unit() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

fn a_request() -> AdminRequest {
    AdminRequest::test_fixture(crate::root::units_admin::TestAdminRequest {
        method: "GET".to_string(),
        path: "/api/v1/admin/audit?limit=4".to_string(),
        credential: Some("admin-token".to_string()),
        headers: vec![("accept".to_string(), "application/json".to_string())],
        body: Vec::new(),
        at: 1_700_000_000,
        unit: a_fresh_unit(),
    })
}

#[test]
fn debug_redacts_the_presented_credential_and_the_header_it_arrived_in() {
    const SECRET: &str = "a-distinctive-admin-secret-7f31c9";
    let request = AdminRequest::test_fixture(crate::root::units_admin::TestAdminRequest {
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
    });

    let rendered = format!("{request:?}");
    assert!(
        !rendered.contains(SECRET),
        "Debug must never carry the presented credential — not in the field, not in the header it \
         arrived in. Got: {rendered}"
    );
    assert!(rendered.contains("AdminRequest"));
    for value in [
        "/api/v1/admin/config/apply",
        "authorization",
        "Bearer",
        "application/json",
        "{}",
    ] {
        assert!(
            !rendered.contains(value),
            "snapshot content leaked in Debug: {rendered}"
        );
    }
}

#[test]
fn the_door_answers_the_published_releases_own_bytes() {
    const GOLDEN: &str = include_str!(concat!(
        env!("BUSBAR_CORE_DIR"),
        "/../../testing/shadow-oracle/golden/1.5.5/cells/admin.ops__GetConfig__unauth.json"
    ));
    let cell: json::Value = json::parse_value(GOLDEN.as_bytes()).expect("the golden cell parses");
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

    let recorded = json::to_vec(&cell["body"]["json"]).expect("the recorded body serialises");
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

#[test]
fn a_grant_that_does_not_reach_the_endpoint_is_answered_with_the_scope_it_needed() {
    let answer = scope_answer(&a_request());
    assert_eq!(answer.status, 403);
    assert_eq!(
        String::from_utf8(answer.body).expect("the envelope is text"),
        r#"{"error":{"code":"forbidden","message":"insufficient scope: this endpoint requires `read-only`"}}"#
    );
}

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

#[tokio::test]
async fn a_body_the_wrap_will_not_read_is_refused_rather_than_emptied() {
    use tower::ServiceExt;

    let inner = axum::Router::new().fallback(axum::routing::any(|| async { "the surface" }));
    let mut units = crate::root::kernel::ProductionUnits::admin_only(
        Arc::new(RefusingDispatch),
        operator_door(),
    )
    .await;
    let wrapped = mount(
        inner,
        busbar_kernel::teller::Kernel::new(),
        4,
        move |dispatch| {
            units.admin.dispatch = dispatch;
            units
        },
    );

    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/api/v1/admin/keys")
        .body(axum::body::Body::from(b"0123456789".to_vec()))
        .expect("the request builds");
    let response = wrapped
        .clone()
        .oneshot(charged_http_for_test(request).await)
        .await
        .expect("the router answers");
    assert_eq!(response.status(), 400);

    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/api/v1/admin/keys")
        .header(axum::http::header::CONTENT_LENGTH, "10")
        .body(axum::body::Body::from(b"0123456789".to_vec()))
        .expect("the request builds");
    let response = wrapped
        .oneshot(charged_http_for_test(request).await)
        .await
        .expect("the router answers");
    assert_eq!(
        response.status(),
        200,
        "the request reached the surface below, which is where the cap is enforced"
    );
}

#[tokio::test]
async fn an_unreadable_amendment_is_told_what_the_body_must_carry() {
    let refused = Outcome::Refused(
        busbar_contract::caps::StepName::Route,
        ReasonCode::DecodeFailed,
    );
    let mut amend = a_request();
    amend.edit_for_test(|r| {
        r.method = "POST".to_string();
        r.path = "/api/v1/admin/ledger/amend-rate-history".to_string();
        r.body = br#"{"rate_card":{},"window":{}}"#.to_vec();
    });
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
    for (reason, expected_status, code) in [
        (ReasonCode::Unauthenticated, 401, "unauthenticated"),
        (ReasonCode::BodyTooLarge, 413, "too_large"),
        (ReasonCode::RateLimited, 429, "rate_limited"),
        (ReasonCode::DeadlineExceeded, 504, "timeout"),
        (ReasonCode::PlanePanic, 502, "upstream_error"),
    ] {
        let expected = error_answer(expected_status, code);
        assert_eq!(status(reason), expected, "refusal {reason:?}");
        assert_eq!(
            answer_for(Outcome::Failed(
                busbar_contract::caps::StepName::Route,
                reason
            )),
            expected,
            "failure {reason:?}"
        );
    }
    assert_eq!(
        answer_for(Outcome::Completed),
        error_answer(500, "internal_error")
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
        request.edit_for_test(|draft| draft.method = "PUT".to_string());
        request.edit_for_test(|draft| draft.path = "/api/v1/admin/config/settings".to_string());
        request.edit_for_test(|draft| {
            draft.credential = Some("sk-live-the-presented-secret".to_string())
        });
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

#[tokio::test]
async fn the_formerly_irreducible_verbs_are_authorized_by_the_grant_alone() {
    let admin = crate::root::kernel::new_kernel().admin_token();

    let under = async |path: &str, granted: VerbScope| -> Result<(), ReasonCode> {
        let binding = AdminBinding::new(Arc::new(AnsweringDispatch), operator_door());
        let mut request = a_request();
        request.edit_for_test(|draft| draft.method = "POST".to_string());
        request.edit_for_test(|draft| draft.path = path.to_string());

        request.edit_for_test(|draft| draft.body = b"{\"backup_ref\":\"backup-1\"}".to_vec());
        let mut walk = AdminWalk::new(request);
        decode(&mut walk).expect("the plane's table declares this operation");
        walk.granted = Some(granted);
        route(&binding, None, &admin, &mut walk).await
    };

    for path in [
        "/api/v1/admin/chain-break",
        "/api/v1/admin/store-restore",
        "/api/v1/admin/commit-upgrade",
        "/api/v1/admin/adjust",
        "/api/v1/admin/ledger/amend-rate-history",
    ] {
        assert_ne!(
            under(path, VerbScope::Full).await,
            Err(ReasonCode::ScopeDenied),
            "{path}: a grant that covers the verb was refused with no operator key configured"
        );
        assert_eq!(
            under(path, VerbScope::ReadOnly).await,
            Err(ReasonCode::ScopeDenied),
            "{path}: a grant that does not cover the verb was not refused"
        );
    }
}

fn a_door_answering(door: busbar_kernel::auth::AdminDoor) -> AdminDoorFn {
    Arc::new(move |_: &AdminRequest| {
        Box::pin(std::future::ready(busbar_kernel::auth::AdminVerdict::from(
            door.clone(),
        )))
    })
}

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

fn approved_under(
    door: busbar_kernel::auth::AdminDoor,
    method: &str,
    path: &str,
) -> Result<(), ReasonCode> {
    let binding = AdminBinding::new(Arc::new(AnsweringDispatch), a_door_answering(door));
    let mut request = a_request();
    request.edit_for_test(|draft| draft.method = method.to_string());
    request.edit_for_test(|draft| draft.path = path.to_string());
    let mut walk = AdminWalk::new(request);
    decode(&mut walk).expect("the plane's table declares this operation");
    let bindings = crate::root::auth_bindings::AuthBindings::without_directory();
    {
        let mut future = std::pin::pin!(authenticate(&binding, &bindings, &mut walk));
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        let std::task::Poll::Ready(answer) = std::future::Future::poll(future.as_mut(), &mut cx)
        else {
            panic!("this fixture is a ready door")
        };
        answer?;
    }
    approve(&walk)
}

async fn answered_under(
    door: busbar_kernel::auth::AdminDoor,
    request: AdminRequest,
) -> AdminAnswer {
    let units = crate::root::kernel::ProductionUnits::admin_only(
        Arc::new(AnsweringDispatch),
        a_door_answering(door),
    )
    .await;
    AdminNode::new(crate::root::kernel::new_kernel(), units)
        .answer(request)
        .await
}

#[tokio::test]
async fn a_verb_the_allow_list_names_is_admitted() {
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
        answered_under(door(), a_request()).await.status,
        200,
        "and the named read reaches its operation"
    );
}

#[tokio::test]
async fn a_verb_the_allow_list_does_not_name_is_refused_with_the_scope_answer() {
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
    let refused = answered_under(door(), read.clone()).await;
    assert_eq!(refused, scope_answer(&read), "the existing scope refusal");
    assert_eq!(refused.status, 403);
    assert_eq!(
        String::from_utf8(refused.body).expect("the envelope is text"),
        "{\"error\":{\"code\":\"forbidden\",\"message\":\"insufficient scope: this endpoint \
         requires `read-only`\"}}"
    );
    let mut mutation = a_request();
    mutation.edit_for_test(|r| {
        r.method = "POST".to_string();
        r.path = "/api/v1/admin/hooks".to_string();
    });
    assert_eq!(
        answered_under(door(), mutation.clone()).await,
        scope_answer(&mutation),
        "a mutation the list does not name is answered with the scope it needed"
    );
}

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

#[tokio::test]
async fn a_grant_with_no_verbs_key_is_decided_by_its_rung_as_before() {
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
    refused.edit_for_test(|r| {
        r.method = "POST".to_string();
        r.path = mutation.to_string();
    });
    assert_eq!(
        answered_under(rung(Scope::ReadOnly), refused.clone()).await,
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
fn the_legacy_audit_read_is_read_only_in_the_kernel() {
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

#[tokio::test]
async fn a_replayed_idempotency_key_answers_the_first_answers_bytes() {
    let store = crate::root::real_store::admin_scoped().await;
    let held = Arc::clone(&store);
    let replay_store: bound::ReplayStore = Arc::new(move || Some(Arc::clone(&held)));
    let request = AdminRequest::test_fixture(crate::root::units_admin::TestAdminRequest {
        method: "POST".to_string(),
        path: "/api/v1/admin/commit-upgrade".to_string(),
        credential: None,
        headers: vec![("idempotency-key".to_string(), "idem-1".to_string())],
        body: br#"{"version":"once"}"#.to_vec(),
        at: 1_700_000_000,
        unit: a_fresh_unit(),
    });
    let minted = std::sync::atomic::AtomicUsize::new(0);

    let mint = || async {
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
    let ask = async |cache: &bound::ReplayCache| {
        bound::replayable(
            cache,
            Some(&replay_store),
            bound::ReplayScope {
                verb: KernelVerb::CommitUpgrade,
                actor: "operator",
            },
            &request,
            request.body(),
            None,
            bound::ReplayContext::None,
            mint,
        )
        .await
        .expect("the write answers")
    };

    let first = ask(&node).await;
    assert_eq!(first, first_answer, "the first call runs and answers");
    let again = ask(&node).await;
    let restarted = ask(&bound::ReplayCache::new()).await;
    let sibling = ask(&bound::ReplayCache::new()).await;
    for (who, replayed) in [
        ("the same node", &again),
        ("a restarted node", &restarted),
        ("another node", &sibling),
    ] {
        assert_eq!(replayed.status, first.status, "{who}: the first status");
        let mut marked = first.headers.clone();
        marked.push(("idempotent-replayed".to_string(), "true".to_string()));
        assert_eq!(
            replayed.headers, marked,
            "{who}: the first headers, marked as replayed (r3 §4.6)"
        );
        assert_eq!(replayed.body, first.body, "{who}: the first body's bytes");
    }
    assert_eq!(
        minted.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the one-time secret was minted once"
    );
}

struct AnsweringDispatch;

#[async_trait::async_trait]
impl AdminDispatch for AnsweringDispatch {
    async fn execute(&self, _verb: KernelVerb, _request: &AdminRequest) -> AdminAnswer {
        AdminAnswer {
            status: 200,
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            body: br#"{"entries":[]}"#.to_vec(),
        }
    }
}

struct Denylist(bool);

impl busbar_kernel_identity::RevocationView for Denylist {
    fn is_revoked(&self, _credential: &str) -> bool {
        self.0
    }
}

fn a_door_that_identifies_the_operator() -> AdminDoorFn {
    door_identifying(
        "admin-token",
        busbar_kernel::config::operator_principal_id(),
    )
}

async fn answer_under_denylist(revoked: bool) -> AdminAnswer {
    let units = crate::root::kernel::ProductionUnits::admin_only(
        Arc::new(AnsweringDispatch),
        a_door_that_identifies_the_operator(),
    )
    .await
    .with_auth_bindings(crate::root::auth_bindings::AuthBindings::new(Arc::new(
        Denylist(revoked),
    )));
    AdminNode::new(crate::root::kernel::new_kernel(), units)
        .answer(a_request())
        .await
}

#[tokio::test]
async fn a_revoked_credential_is_refused_before_the_operation_runs() {
    assert_eq!(
        answer_under_denylist(false).await.status,
        200,
        "a credential on nobody's denylist reaches the operation"
    );
    let refused = answer_under_denylist(true).await;
    assert_eq!(
        refused,
        door_answer(),
        "a credential the node took away is the door's answer, written and not re-run"
    );
}

async fn answer_at_the_closed_door(door: AdminDoorFn, credential: Option<&str>) -> AdminAnswer {
    let units = crate::root::kernel::ProductionUnits::admin_only(Arc::new(AnsweringDispatch), door)
        .await
        .with_auth_bindings(crate::root::auth_bindings::AuthBindings::new(Arc::new(
            Denylist(false),
        )));
    let mut request = a_request();
    request.edit_for_test(|draft| draft.credential = credential.map(str::to_string));
    AdminNode::new(crate::root::kernel::new_kernel(), units)
        .answer(request)
        .await
}

#[tokio::test]
async fn authoritative_admin_door_awaits_before_revocation_and_approval() {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = calls.clone();
    let door: AdminDoorFn = Arc::new(move |_: &AdminRequest| {
        let calls = calls.clone();
        Box::pin(async move {
            tokio::task::yield_now().await;
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            busbar_kernel::auth::AdminDoor::Identified(
                busbar_contract::auth::Principal::from_id(
                    busbar_kernel::config::operator_principal_id(),
                ),
                busbar_contract::authz::Grants::of(Scope::Full),
            )
            .into()
        })
    });
    assert_eq!(
        answer_at_the_closed_door(door.clone(), Some("credential"))
            .await
            .status,
        200
    );
    let units = crate::root::kernel::ProductionUnits::admin_only(Arc::new(AnsweringDispatch), door)
        .await
        .with_auth_bindings(crate::root::auth_bindings::AuthBindings::new(Arc::new(
            Denylist(true),
        )));
    let mut request = a_request();
    request.edit_for_test(|draft| draft.credential = Some("credential".into()));
    let answer = AdminNode::new(crate::root::kernel::new_kernel(), units)
        .answer(request)
        .await;
    assert_eq!(answer.status, 401);
    assert_eq!(observed.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_wrong_or_absent_credential_is_refused_at_the_door() {
    assert_eq!(
        answer_at_the_closed_door(a_door_that_identifies_the_operator(), Some("admin-token"))
            .await
            .status,
        200,
        "the control must actually be admitted, or the refusals below prove only that the fixture \
         refuses everything"
    );

    let wrong = answer_at_the_closed_door(
        a_door_that_identifies_the_operator(),
        Some("not-the-admin-token"),
    )
    .await;
    assert_eq!(
        wrong,
        door_answer(),
        "a credential no arm of the chain identifies must be the door's answer"
    );
    assert_eq!(wrong.status, 401, "and that answer's status is the door's");

    let absent = answer_at_the_closed_door(a_door_that_identifies_the_operator(), None).await;
    assert_eq!(
        absent,
        door_answer(),
        "a caller who presented NO credential must be the door's answer — this is the arm a step \
         that never reads `request.credential()` cannot produce"
    );
    assert_eq!(absent.status, 401, "and that answer's status is the door's");
}

#[tokio::test]
async fn the_refusal_the_loop_hands_back_is_the_frozen_envelope_byte_for_byte() {
    let absent = answer_at_the_closed_door(a_door_that_identifies_the_operator(), None).await;
    assert_eq!(absent.status, 401);
    assert_eq!(
        String::from_utf8(absent.body).expect("the envelope is text"),
        r#"{"error":{"code":"unauthorized","message":"missing or invalid admin credential (Bearer)"}}"#
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

#[tokio::test]
async fn a_caller_the_door_identifies_as_somebody_else_is_answered_with_the_scope_it_needed() {
    let door = door_identifying("a-tenants-token", "acct:not-the-operator");
    let refused = answer_at_the_closed_door(door, Some("a-tenants-token")).await;
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

fn a_bound_unit(request: AdminRequest) -> AdminWalk {
    let mut walk = AdminWalk::new(request);

    let _ = decode(&mut walk);
    walk
}

#[tokio::test]
async fn the_admin_listener_is_exempt_from_the_cap_the_data_listener_is_refused_at() {
    use busbar_contract::caps::{OriginKind, StepName};
    use busbar_kernel::inflight::{arrival_hold, cap_refusal_step, Enter, InFlight};

    let units = crate::root::kernel::ProductionUnits::admin_only(
        Arc::new(real_admin_dispatch().await),
        operator_door(),
    )
    .await;
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
    let answer = node.answer(request).await;
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
    let document: json::Value = json::parse_value(&answer.body).expect("audit JSON");
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

#[test]
fn a_verb_the_table_never_named_has_nowhere_to_go_and_a_resolved_one_has_nowhere_priced() {
    let principal = PrincipalId::new("admin");

    let mut unknown = a_request();
    unknown.edit_for_test(|r| {
        r.path = "/api/v1/admin/not-a-real-operation".to_string();
    });
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

#[test]
fn the_audit_doors_seal_the_resolved_class_and_append_to_no_ring() {
    let mut mutating = a_request();
    mutating.edit_for_test(|r| {
        r.method = "POST".to_string();
        r.path = "/api/v1/admin/plane-record-write".to_string();
    });
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

fn the_one_rings_rows_by(principal: &str) -> Vec<busbar_kernel::audit_ring::AuditEntry> {
    busbar_kernel::audit::auditlog::AUDIT_LOG
        .list_filtered(0, usize::MAX, None, None)
        .into_iter()
        .filter(|entry| entry.principal == principal)
        .collect()
}

#[tokio::test]
async fn one_admin_unit_seals_exactly_one_entry_on_the_one_ring_and_a_read_seals_none() {
    const WHO: &str = "operator-cifollow-one-entry";

    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let module = crate::root::test_plugins::native_image(&library_path).name;
    let manifest = crate::root::test_plugins::native_manifest(
        "store",
        &library_path,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
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
    let settings = crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        &json::json!({
            "providers": {}, "models": {},
            "auth": {"chain": []},
            "store": {"module": module, "settings": settings},
            "advanced": {},
        }),
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the real admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the real admin deployment resolves");
    let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
        as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (built, rotate, limits) = crate::root::real_store::build_app(
        crate::root::test_plugins::plaintext_listeners(config),
        crate::root::test_plugins::trusted_config(&directory),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .await
    .expect("the product builds the actual admin application");
    if !crate::root::kernel::ROOT_CARD.keeps_store() {
        limits.stage_boot();
        crate::root::kernel::ROOT_CARD
            .keep_in_store(
                built
                    .governance
                    .as_ref()
                    .expect("the application has its configured governance Store")
                    .core_store_handle()
                    .expect("the configured Store exposes canonical persistence"),
                busbar_kernel::door::op_id().counter(),
            )
            .expect("the canonical rate history binds");
        crate::root::kernel::ROOT_CARD
            .boot_in_store(None)
            .await
            .expect("the actual configured Store boots its initial rate history");
    }
    limits
        .keep()
        .await
        .expect("the real application limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let _app = std::sync::Arc::new(built);
    busbar_kernel::audit::auditlog::register_test_audit_stream(&_app).await;
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
        request.edit_for_test(|draft| draft.method = "POST".to_string());
        request.edit_for_test(|draft| draft.path = path.to_string());
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
    busbar_kernel::audit::auditlog::flush_pending()
        .await
        .expect("native audit publication");
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
    busbar_kernel::audit::auditlog::flush_pending()
        .await
        .expect("native audit publication");
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
    busbar_kernel::audit::auditlog::flush_pending()
        .await
        .expect("native audit publication");
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
    busbar_kernel::audit::auditlog::flush_pending()
        .await
        .expect("native audit publication");
    let rows = the_one_rings_rows_by(WHO);
    assert_eq!(rows.len(), before + 1, "the attempt is on the chain");
    assert_eq!(rows[0].action, resolved.verb);
    assert_eq!(rows[0].outcome, busbar_kernel::audit_ring::OUTCOME_REJECTED);
    linked(&rows[0]);
}

const AN_IDENTIFIED_OPERATOR: &str = "operator-alice";

#[tokio::test]
async fn each_recovery_verb_reaches_the_store_and_a_refusing_store_is_the_answer() {
    /// A store that records what reached it and refuses it.
    #[derive(Debug, Default)]
    struct RecordingStore(Mutex<Vec<String>>);

    impl busbar_kernel::persistence::recovery_api::Store for RecordingStore {
        fn chain_break<'a>(
            &'a self,
            _admin: &'a busbar_contract::caps::Grant<busbar_contract::caps::AdminVerb>,
        ) -> busbar_kernel::persistence::recovery_api::StoreCall<'a> {
            Box::pin(async move {
                self.0.lock().unwrap().push("chain_break".to_string());
                Err(busbar_kernel::persistence::recovery_api::StoreError::Failed)
            })
        }
        fn store_restore<'a>(
            &'a self,
            _admin: &'a busbar_contract::caps::Grant<busbar_contract::caps::AdminVerb>,
            backup_ref: &'a str,
        ) -> busbar_kernel::persistence::recovery_api::StoreCall<'a> {
            Box::pin(async move {
                self.0
                    .lock()
                    .unwrap()
                    .push(format!("store_restore:{backup_ref}"));
                Err(busbar_kernel::persistence::recovery_api::StoreError::Failed)
            })
        }
    }

    struct NeverDispatched;
    #[async_trait::async_trait]
    impl AdminDispatch for NeverDispatched {
        async fn execute(&self, verb: KernelVerb, _request: &AdminRequest) -> AdminAnswer {
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
        let binding = AdminBinding::new(Arc::new(NeverDispatched), operator_door());
        let mut request = a_request();
        request.edit_for_test(|draft| draft.method = "POST".to_string());
        request.edit_for_test(|draft| draft.path = path.to_string());
        request.edit_for_test(|draft| draft.body = body.as_bytes().to_vec());
        let mut walk = AdminWalk::new(request);
        decode(&mut walk).unwrap_or_else(|_| panic!("{path} is a row the plane's table declares"));
        walk.granted = Some(VerbScope::Full);

        let outcome = route(
            &binding,
            Some(Arc::clone(&store)
                as Arc<
                    dyn busbar_kernel::persistence::recovery_api::Store + Send + Sync,
                >),
            &admin,
            &mut walk,
        )
        .await;

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

/// Aikido 1074606954 (#108): chain-break and store-restore are durable writes like the other
/// mutating verbs, so they pass the current-authority effect admission first (docs/admin-api.md).
/// An admin whose authority was revoked after the request was admitted reaches no store method.
#[tokio::test]
async fn a_recovery_verb_is_refused_when_current_authority_no_longer_admits_the_effect() {
    #[derive(Debug, Default)]
    struct RecordingStore(Mutex<Vec<String>>);

    impl busbar_kernel::persistence::recovery_api::Store for RecordingStore {
        fn chain_break<'a>(
            &'a self,
            _admin: &'a busbar_contract::caps::Grant<busbar_contract::caps::AdminVerb>,
        ) -> busbar_kernel::persistence::recovery_api::StoreCall<'a> {
            Box::pin(async move {
                self.0.lock().unwrap().push("chain_break".to_string());
                Ok(())
            })
        }
        fn store_restore<'a>(
            &'a self,
            _admin: &'a busbar_contract::caps::Grant<busbar_contract::caps::AdminVerb>,
            backup_ref: &'a str,
        ) -> busbar_kernel::persistence::recovery_api::StoreCall<'a> {
            Box::pin(async move {
                self.0
                    .lock()
                    .unwrap()
                    .push(format!("store_restore:{backup_ref}"));
                Ok(())
            })
        }
    }

    struct NeverDispatched;
    #[async_trait::async_trait]
    impl AdminDispatch for NeverDispatched {
        async fn execute(&self, verb: KernelVerb, _request: &AdminRequest) -> AdminAnswer {
            panic!("a recovery verb reached the governance seam: {verb:?}");
        }
    }

    fn revoked(
        _context: &busbar_kernel::auth::effect::Context,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<
                        busbar_kernel::config::transaction::EffectGuard,
                        busbar_kernel::config::transaction::TxnError,
                    >,
                > + Send
                + '_,
        >,
    > {
        Box::pin(async { Err(busbar_kernel::config::transaction::TxnError::Forbidden) })
    }

    let admin = crate::root::kernel::new_kernel().admin_token();

    for (path, body) in [
        ("/api/v1/admin/chain-break", "{}"),
        (
            "/api/v1/admin/store-restore",
            "{\"backup_ref\":\"nightly-2026-09-05\"}",
        ),
    ] {
        let store = Arc::new(RecordingStore::default());
        let mut binding = AdminBinding::new(Arc::new(NeverDispatched), operator_door());
        let admission: EffectAdmission = Arc::new(revoked);
        binding.effect_admission = Some(admission);
        let mut request = a_request();
        request.edit_for_test(|draft| draft.method = "POST".to_string());
        request.edit_for_test(|draft| draft.path = path.to_string());
        request.edit_for_test(|draft| draft.body = body.as_bytes().to_vec());
        let mut walk = AdminWalk::new(request);
        decode(&mut walk).unwrap_or_else(|_| panic!("{path} is a row the plane's table declares"));
        walk.granted = Some(VerbScope::Full);
        walk.effect_context = Some(busbar_kernel::auth::effect::Context::new(
            "POST",
            path,
            Default::default(),
            &busbar_kernel::auth::AdminDoor::Identified(
                busbar_contract::auth::Principal::from_id(
                    busbar_kernel::config::operator_principal_id(),
                ),
                busbar_contract::authz::Grants::of(busbar_contract::authz::Scope::Full),
            ),
        ));

        let outcome = route(
            &binding,
            Some(Arc::clone(&store)
                as Arc<
                    dyn busbar_kernel::persistence::recovery_api::Store + Send + Sync,
                >),
            &admin,
            &mut walk,
        )
        .await;

        assert!(
            store.0.lock().unwrap().is_empty(),
            "{path} reached the store without current authority"
        );
        assert_eq!(outcome, Ok(()), "{path}: the refusal is the answer");
        assert_eq!(
            walk.answer.as_ref().map(|answer| answer.status),
            Some(403),
            "{path} is refused as forbidden"
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

#[test]
fn the_refused_door_seals_the_refusal_that_happened() {
    let mut unrouted = a_request();
    unrouted.edit_for_test(|r| {
        r.method = "DELETE".to_string();
        r.path = "/api/v1/admin/nothing-declares-this".to_string();
    });
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

#[async_trait::async_trait]
impl LedgerView for SeededLedger {
    async fn priced(&self) -> Result<crate::root::units_admin::PricedLedger, String> {
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
];

fn a_ledger_request(path: &str) -> AdminRequest {
    AdminRequest::test_fixture(crate::root::units_admin::TestAdminRequest {
        method: "GET".to_string(),
        path: path.to_string(),
        credential: Some("admin-token".to_string()),
        headers: vec![("accept".to_string(), "application/json".to_string())],
        body: Vec::new(),
        at: 1_700_000_000,
        unit: a_fresh_unit(),
    })
}

async fn answer_over_seeded_ledger(request: AdminRequest) -> AdminAnswer {
    let mut units = crate::root::kernel::ProductionUnits::admin_only(
        Arc::new(AnsweringDispatch),
        operator_door(),
    )
    .await;
    units.admin = AdminBinding::new(Arc::new(AnsweringDispatch), operator_door())
        .with_ledger_view(Arc::new(SeededLedger));
    AdminNode::new(crate::root::kernel::new_kernel(), units)
        .answer(request)
        .await
}

fn one_lane_rates() -> std::collections::BTreeMap<String, busbar_kernel::config::RateEntryCfg> {
    crate::dist_root_install::install();
    let mut entry = busbar_kernel::config::RateEntryCfg {
        input_utok: 2.5,
        ..Default::default()
    };
    let plane = busbar_kernel::plane_driver::registry::plane_decl_for(
        busbar_kernel::plane_driver::dispatch::fallback_key(),
    )
    .expect("the actual fallback plane declares its billable classes");
    let zero = json::from_value(&json::json!(0)).expect("an exact free unit rate");
    for class in plane.billable_classes {
        if !busbar_contract::records::RESERVED_UNITS.contains(&class.class)
            && !plane.fee_units.contains(&class.class)
        {
            entry.units.insert(class.class.to_owned(), zero);
        }
    }
    std::collections::BTreeMap::from([("m".to_string(), entry)])
}

fn one_lane_card() -> busbar_kernel::cost::CostModel {
    busbar_kernel::cost::CostModel::resolve_parts(
        Some(&one_lane_rates()),
        0,
        &std::collections::BTreeMap::new(),
    )
}

async fn answer_over_counts(
    gov: Arc<busbar_kernel::governance::GovState>,
    path: &str,
) -> json::Value {
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let module = crate::root::test_plugins::native_image(&library_path).name;
    let manifest = crate::root::test_plugins::native_manifest(
        "store",
        &library_path,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
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
    let settings = crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let dialects: json::Value =
        json::parse_value(include_str!("../../tests/fixtures/plane_node_dialects.json").as_bytes())
            .expect("the actual model dialects are recorded");
    let dialect = dialects["body_model"]
        .as_object()
        .and_then(|rows| rows.iter().next().map(|(key, _)| key))
        .expect("the distribution links a model dialect");
    let providers = busbar_kernel::config::providers::catalog_from_str(
        &format!("wire:\n  protocol: {dialect}\n  base_url: http://127.0.0.1:9\n"),
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the actual wire provider has its catalog declaration");
    let deploy = busbar_kernel::config::deploy_from_deserializer(&json::json!({
        "providers": {"wire": {"protocol": dialect, "base_url": "http://127.0.0.1:9", "api_key": "none"}},
        "models": {"m": {"provider": "wire"}},
        "rate_card": one_lane_rates(),
        "auth": {"chain": []},
        "store": {"module": module, "settings": settings},
        "advanced": {},
    }), &crate::root::boot::axis_test_grammar())
    .expect("the real admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &providers)
        .expect("the real admin deployment resolves");
    let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
        as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (mut built, rotate, limits) = crate::root::real_store::build_app(
        crate::root::test_plugins::plaintext_listeners(config),
        crate::root::test_plugins::trusted_config(&directory),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .await
    .expect("the product builds the actual admin application");
    if !crate::root::kernel::ROOT_CARD.keeps_store() {
        limits.stage_boot();
        crate::root::kernel::ROOT_CARD
            .keep_in_store(
                built
                    .governance
                    .as_ref()
                    .expect("the application has its configured governance Store")
                    .core_store_handle()
                    .expect("the configured Store exposes canonical persistence"),
                busbar_kernel::door::op_id().counter(),
            )
            .expect("the canonical rate history binds");
        crate::root::kernel::ROOT_CARD
            .boot_in_store(None)
            .await
            .expect("the actual configured Store boots its initial rate history");
    }
    limits
        .keep()
        .await
        .expect("the real application limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    built.governance = Some(gov);
    built.cost = std::sync::Arc::new(one_lane_card());
    let app = std::sync::Arc::new(built);
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(app));
    let mut units = crate::root::kernel::ProductionUnits::admin_only(
        Arc::new(AnsweringDispatch),
        operator_door(),
    )
    .await;
    units.admin = AdminBinding::new(Arc::new(AnsweringDispatch), operator_door()).with_ledger_view(
        Arc::new(crate::root::units_admin::CountsLedger::new(handle)),
    );
    let answer = AdminNode::new(crate::root::kernel::new_kernel(), units)
        .answer(a_ledger_request(path))
        .await;
    assert_eq!(answer.status, 200, "{path} did not answer");
    json::parse_value(&answer.body).unwrap_or_else(|e| panic!("{path}: {e}"))
}

#[tokio::test]
async fn the_ledger_paths_answer_counts_times_card_and_survive_a_restart() {
    use busbar_kernel::governance::{GovState, VirtualKey};
    let core = crate::root::real_store::core().await;
    let key = VirtualKey {
        id: "vk_one_ledger".to_string(),
        generation_hash: "h:vk_one_ledger".to_string(),
        name: "one-ledger".to_string(),
        enabled: true,
        revision: 1,
        ..Default::default()
    };
    core.identity()
        .put_key(&key)
        .await
        .expect("the key persists");
    let gov = Arc::new(
        GovState::new_with_core(Arc::clone(&core), None, None)
            .await
            .expect("governance builds"),
    );
    let now = busbar_kernel::store::now();
    let input = std::collections::BTreeMap::from([(
        busbar_contract::records::UNIT_INPUT.to_string(),
        1_000u64,
    )]);
    gov.record_usage(&one_lane_card(), &key, "", "m", &input, now);
    gov.flush_budgets().await;

    let stored = core
        .ledger()
        .get_usage(&key.id, 0)
        .await
        .expect("the row reads");
    assert_eq!(
        stored.models.len(),
        1,
        "the store holds the one model's counts"
    );
    let model = &stored.models[0];
    assert_eq!(model.model, "m");
    assert_eq!(
        model.scale,
        busbar_contract::count::COUNT_SCALE,
        "the persisted envelope declares micro-units"
    );
    let expected_counts: std::collections::BTreeMap<_, _> = input
        .iter()
        .map(|(unit, quantity)| (unit.clone(), busbar_contract::count::Count::from(*quantity)))
        .collect();
    assert_eq!(
        model.counts().expect("the stored scale decodes exactly"),
        expected_counts,
        "the stored envelope retains the original whole-unit quantity, never spend"
    );

    let totals = answer_over_counts(Arc::clone(&gov), "/api/v1/admin/ledger/totals").await;
    let rows = totals["rows"].as_array().expect("rows");
    let row = rows
        .iter()
        .find(|r| r["bucket"] == "vk_one_ledger")
        .unwrap_or_else(|| panic!("the key's row is served: {totals}"));
    assert_eq!(row["priced_micros"], "2500", "1,000 tokens x 2.5: {totals}");
    assert_eq!(row["priced_nanos"], "2500000");
    assert_eq!(
        answer_over_counts(Arc::clone(&gov), "/api/v1/admin/ledger/reconciliation").await["holds"],
        true
    );

    let restarted = Arc::new(
        GovState::new_with_core(Arc::clone(&core), None, None)
            .await
            .expect("governance builds"),
    );
    restarted
        .hydrate_budgets_async(&one_lane_card(), now)
        .await
        .expect("the boot hydrates");
    assert_eq!(
        answer_over_counts(restarted, "/api/v1/admin/ledger/totals").await,
        totals,
        "a restart serves the same money from the same counts"
    );
}

#[tokio::test]
async fn every_ledger_view_answers_from_the_ledger_and_not_from_the_dispatch() {
    let mut bodies = Vec::new();
    for path in LEDGER_PATHS {
        let answer = answer_over_seeded_ledger(a_ledger_request(path)).await;
        assert_eq!(answer.status, 200, "{path} did not answer");
        assert_eq!(
            answer.headers,
            vec![("content-type".to_string(), "application/json".to_string())],
            "{path} carried a header the view does not set"
        );
        let parsed: json::Value =
            json::parse_value(&answer.body).unwrap_or_else(|e| panic!("{path}: {e}"));
        assert!(parsed.is_object(), "{path} did not answer a JSON object");
        assert_ne!(
            answer.body, br#"{"entries":[]}"#,
            "{path} fell through to the dispatch"
        );
        bodies.push(answer.body);
    }
    let mut distinct = bodies.clone();
    distinct.sort();
    distinct.dedup();
    assert_eq!(
        distinct.len(),
        LEDGER_PATHS.len(),
        "two views answered the same bytes"
    );
}

#[tokio::test]
async fn each_view_serves_the_figures_the_ledger_holds() {
    let body = async |path: &str| -> json::Value {
        json::parse_value(&answer_over_seeded_ledger(a_ledger_request(path)).await.body)
            .expect("valid JSON")
    };

    let totals = body("/api/v1/admin/ledger/totals").await;
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
        body("/api/v1/admin/ledger/checkpoints").await,
        json::json!({"checkpoints": []})
    );
    assert_eq!(
        body("/api/v1/admin/ledger/migration").await,
        json::json!({"migrated": false, "marker": null})
    );
}

async fn real_admin_dispatch() -> RouterDispatch {
    crate::dist_root_install::install();
    busbar_core_admin::install();
    let gov = Arc::new(
        busbar_kernel::governance::GovState::new_with_core(
            crate::root::real_store::core().await,
            Some("admin-token".into()),
            None,
        )
        .await
        .expect("governance"),
    );
    crate::dist_root_install::install();
    // The linked operator credential is bound and opened by the app build from its settings: the
    // SHA-256 digest of the fixture admin token (governance holds no operator digest, MR-D).
    busbar_kernel::preflight::install_linked_auth(crate::LINKED.auths);
    busbar_kernel::preflight::install_operator(crate::root::auth_bindings::operator_binding(None));
    let operator = busbar_kernel::config::operator_provider();
    let digest = busbar_contract::redacted::sha256_hex(b"admin-token");
    let library_path = crate::root::test_plugins::application_store_library();
    let module = crate::root::test_plugins::native_image(&library_path).name;
    let manifest = crate::root::test_plugins::native_manifest(
        "store",
        &library_path,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
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
    let settings = crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        &json::json!({
            "providers": {}, "models": {},
            "identity-providers": {
                (operator): {"module": operator, "settings": {"sha256": digest}},
            },
            "auth": {"chain": [], "admin_auth": [operator]},
            "store": {"module": module, "settings": settings},
            "advanced": {},
        }),
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the real admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the real admin deployment resolves");
    let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
        as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (mut built, rotate, limits) = crate::root::real_store::build_app(
        crate::root::test_plugins::plaintext_listeners(config),
        crate::root::test_plugins::trusted_config(&directory),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .await
    .expect("the product builds the actual admin application");
    if !crate::root::kernel::ROOT_CARD.keeps_store() {
        limits.stage_boot();
        crate::root::kernel::ROOT_CARD
            .keep_in_store(
                built
                    .governance
                    .as_ref()
                    .expect("the application has its configured governance Store")
                    .core_store_handle()
                    .expect("the configured Store exposes canonical persistence"),
                busbar_kernel::door::op_id().counter(),
            )
            .expect("the canonical rate history binds");
        crate::root::kernel::ROOT_CARD
            .boot_in_store(None)
            .await
            .expect("the actual configured Store boots its initial rate history");
    }
    limits
        .keep()
        .await
        .expect("the real application limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    built.governance = Some(gov);
    let app = std::sync::Arc::new(built);
    RouterDispatch::new(
        busbar_kernel::build_router(app),
        &tokio::runtime::Handle::current(),
        Arc::new(busbar_core_admin::keys::KeyReplayCache::new()),
    )
}

fn authenticated_admin_request() -> AdminRequest {
    let mut request = a_request();
    request.edit_for_test(|draft| {
        draft
            .headers
            .push(("authorization".into(), "Bearer admin-token".into()))
    });
    request
}

struct PanickingDispatch {
    calls: std::sync::atomic::AtomicUsize,
    next: RouterDispatch,
}

#[async_trait::async_trait]
impl AdminDispatch for PanickingDispatch {
    async fn execute(&self, verb: KernelVerb, request: &AdminRequest) -> AdminAnswer {
        if self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
            panic!("the operation's body panicked");
        }
        self.next.execute(verb, request).await
    }
}

#[tokio::test]
async fn a_panicking_step_leaves_the_node_serving_valid_operations() {
    let dispatch = Arc::new(PanickingDispatch {
        calls: std::sync::atomic::AtomicUsize::new(0),
        next: real_admin_dispatch().await,
    });
    let units =
        crate::root::kernel::ProductionUnits::admin_only(dispatch.clone(), operator_door()).await;
    let node = AdminNode::new(crate::root::kernel::new_kernel(), units);
    let node = Arc::new(node);
    let first = Arc::clone(&node);
    let ended =
        tokio::spawn(async move { first.answer(authenticated_admin_request()).await }).await;
    assert!(ended
        .expect_err("the fixture's first dispatch panics")
        .is_panic());
    let answer = node.answer(authenticated_admin_request()).await;
    assert_eq!(answer.status, 200);
    let document: json::Value = json::parse_value(&answer.body).expect("audit JSON");
    assert!(
        document["items"].is_array(),
        "a real valid operation answered after the panic"
    );
    assert_eq!(dispatch.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[tokio::test]
async fn an_unopened_ledger_answers_empty_rather_than_absent() {
    let units = crate::root::kernel::ProductionUnits::admin_only(
        Arc::new(AnsweringDispatch),
        operator_door(),
    )
    .await;
    let node = AdminNode::new(crate::root::kernel::new_kernel(), units);
    let body = async |path: &str| -> json::Value {
        let answer = node.answer(a_ledger_request(path)).await;
        assert_eq!(answer.status, 200, "{path}");
        json::parse_value(&answer.body).expect("valid JSON")
    };
    assert_eq!(
        body("/api/v1/admin/ledger/totals").await["rows"],
        json::json!([])
    );
    assert_eq!(
        body("/api/v1/admin/ledger/checkpoints").await["checkpoints"],
        json::json!([])
    );
    assert_eq!(
        body("/api/v1/admin/ledger/migration").await["migrated"],
        false
    );
    assert_eq!(
        body("/api/v1/admin/ledger/migration").await["marker"],
        json::Value::new()
    );

    assert_eq!(
        body("/api/v1/admin/ledger/reconciliation").await["holds"],
        true
    );
}

#[tokio::test]
async fn the_reconciliation_holds_unless_a_row_is_refused_and_names_it() {
    let served: json::Value = json::parse_value(
        &answer_over_seeded_ledger(a_ledger_request("/api/v1/admin/ledger/reconciliation"))
            .await
            .body,
    )
    .expect("valid JSON");
    assert_eq!(
        served["holds"], false,
        "a refused row is a row not measured"
    );
    assert_eq!(served["discrepancies"], json::json!([]));
    let refused = served["refused"].as_array().expect("refused");
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0]["bucket"], "key-3");
}

#[tokio::test]
async fn verify_names_a_refused_row_and_every_other_finding() {
    let fixture = crate::root::durability::tests::NativeFixture::new(7).await;
    let node_book = crate::root::durability::node_book(
        fixture.journal.clone(),
        crate::root::durability::tests::BUDGET,
    )
    .await
    .unwrap();
    node_book
        .durability
        .lock()
        .expect("unpoisoned")
        .restart_findings
        .push("the journal does not verify: a forged record".to_string());
    let audit =
        crate::root::units_admin::NodeAudit::new(std::sync::Arc::clone(&node_book.durability));
    let answer = crate::root::units_admin::bound::verify_effect(&SeededLedger, Some(&audit), None)
        .await
        .expect("a refused row must not take /admin/verify down");
    let body: json::Value = json::parse_value(&answer.body).expect("valid JSON");
    let findings: Vec<&str> = body["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .filter_map(json::Value::as_str)
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

#[tokio::test]
async fn a_ledger_view_answers_an_unauthenticated_caller_exactly_as_the_legacy_usage_read_does() {
    let under = async |path: &str, credential: Option<&str>, revoked: bool| -> AdminAnswer {
        let mut request = a_ledger_request(path);
        request.edit_for_test(|draft| draft.credential = credential.map(ToString::to_string));

        let door = if revoked {
            a_door_that_identifies_the_operator()
        } else {
            operator_door()
        };
        let units =
            crate::root::kernel::ProductionUnits::admin_only(Arc::new(AnsweringDispatch), door)
                .await
                .with_auth_bindings(crate::root::auth_bindings::AuthBindings::new(Arc::new(
                    Denylist(revoked),
                )));
        AdminNode::new(crate::root::kernel::new_kernel(), units)
            .answer(request)
            .await
    };

    let refused = under("/api/v1/admin/usage", Some("admin-token"), true).await;
    assert_ne!(
        refused.status, 200,
        "the control must actually be a refusal, or this test compares two successes"
    );
    for path in LEDGER_PATHS {
        assert_eq!(
            under(path, Some("admin-token"), true).await,
            refused,
            "{path} does not refuse a revoked credential the way /usage does"
        );
    }

    let admitted = under("/api/v1/admin/usage", None, false).await;
    assert_eq!(admitted.status, 200, "the open chain admits the control");
    for path in LEDGER_PATHS {
        assert_eq!(
            under(path, None, false).await.status,
            admitted.status,
            "{path} does not admit a credential-less caller the way /usage does"
        );
    }
}

#[test]
fn a_read_only_credential_reaches_every_view_and_still_no_mutation() {
    let decide = |path: &str, method: &str, granted: VerbScope| -> bool {
        let mut request = a_ledger_request(path);
        request.edit_for_test(|draft| draft.method = method.to_string());
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
            busbar_kernel::admin::scope::admin_required_scope("GET", path),
            Scope::ReadOnly
        );
    }
}

#[tokio::test]
async fn a_view_never_reaches_the_dispatch_and_answers_a_read_only_grant() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingDispatch(Arc<AtomicUsize>);
    #[async_trait::async_trait]
    impl AdminDispatch for CountingDispatch {
        async fn execute(&self, _verb: KernelVerb, _request: &AdminRequest) -> AdminAnswer {
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
            None::<Arc<dyn busbar_kernel::persistence::recovery_api::Store + Send + Sync>>,
            Arc::new(busbar_kernel::ratelimit::MutationLimiter::new()),
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
            .await
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
        None::<Arc<dyn busbar_kernel::persistence::recovery_api::Store + Send + Sync>>,
        Arc::new(busbar_kernel::ratelimit::MutationLimiter::new()),
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
        .await
        .is_err());
}

const AUDIT_PATHS: &[&str] = &[
    "/api/v1/admin/audit/head",
    "/api/v1/admin/audit/range",
    "/api/v1/admin/audit/keys",
];

struct SealedChain {
    chain: busbar_kernel_audit::AuditChain,
    records: Vec<busbar_kernel_audit::AuditRecord>,
    keys: busbar_kernel_audit::AuditKeySet,
}

#[async_trait::async_trait]
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

fn an_audit_pass() -> busbar_contract::caps::Pass<busbar_contract::caps::Audit> {
    busbar_kernel::teller::verb_audit_pass(&crate::root::kernel::new_kernel())
}

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
                unit: busbar_kernel_audit::UnitFacts::default(),
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

async fn answer_over_a_sealed_chain(request: AdminRequest) -> AdminAnswer {
    let mut units = crate::root::kernel::ProductionUnits::admin_only(
        Arc::new(AnsweringDispatch),
        operator_door(),
    )
    .await;
    units.admin = AdminBinding::new(Arc::new(AnsweringDispatch), operator_door())
        .with_audit_view(Arc::new(a_sealed_chain()) as Arc<dyn AuditView>);
    AdminNode::new(crate::root::kernel::new_kernel(), units)
        .answer(request)
        .await
}

#[tokio::test]
async fn audit_verifying_keys_use_the_shared_cursor_page() {
    let mut audit = a_sealed_chain();
    for seed in [11u8, 19, 23] {
        let signer = busbar_kernel_audit::AuditSigningKey::from_seed(&[seed; 32]);
        audit.keys.insert(
            busbar_kernel_audit::AuditVerifyingKey::from_hex(&signer.public_key_hex()).unwrap(),
        );
    }
    let mut expected: Vec<String> = audit
        .keys
        .keys()
        .iter()
        .map(|key| key.key_id().to_owned())
        .collect();
    expected.sort();
    let mut units = crate::root::kernel::ProductionUnits::admin_only(
        Arc::new(AnsweringDispatch),
        operator_door(),
    )
    .await;
    units.admin = AdminBinding::new(Arc::new(AnsweringDispatch), operator_door())
        .with_audit_view(Arc::new(audit) as Arc<dyn AuditView>);
    let node = AdminNode::new(crate::root::kernel::new_kernel(), units);
    let mut path = "/api/v1/admin/audit/keys?limit=1".to_string();
    let mut ids = Vec::new();
    for page in 0..4 {
        let answer = node.answer(a_ledger_request(&path)).await;
        assert_eq!(answer.status, 200);
        let body: json::Value = json::parse_value(&answer.body).unwrap();
        let items = body["items"].as_array().expect("every list uses items");
        assert_eq!(items.len(), 1);
        ids.push(items[0]["key_id"].as_str().unwrap().to_string());
        assert_eq!(body["algorithm"].as_str(), Some("ed25519"));
        assert!(body.get("keys").is_none(), "one collection member only");
        if page == 3 {
            assert!(body["next_cursor"].is_null());
        } else {
            let cursor = body["next_cursor"].as_str().expect("another key remains");
            assert!(cursor.starts_with("k1."), "use the common cursor format");
            path = format!("/api/v1/admin/audit/keys?limit=1&cursor={cursor}");
        }
    }
    assert_eq!(ids, expected, "each public key appears exactly once");
    let answer = node
        .answer(a_ledger_request("/api/v1/admin/audit/keys?cursor=invalid"))
        .await;
    assert_eq!(answer.status, 400);
    assert!(String::from_utf8(answer.body)
        .unwrap()
        .contains("malformed_cursor"));
}

#[tokio::test]
async fn the_three_chain_reads_answer_with_the_chains_own_bytes() {
    let head = answer_over_a_sealed_chain(a_ledger_request("/api/v1/admin/audit/head")).await;
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
        answer_over_a_sealed_chain(a_ledger_request("/api/v1/admin/audit/range?from=2&to=3")).await;
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

    let keys = answer_over_a_sealed_chain(a_ledger_request("/api/v1/admin/audit/keys")).await;
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

#[tokio::test]
async fn an_unbound_chain_refuses_rather_than_answering_an_empty_head() {
    let mut units = crate::root::kernel::ProductionUnits::admin_only(
        Arc::new(AnsweringDispatch),
        operator_door(),
    )
    .await;

    units.admin = AdminBinding::new(Arc::new(AnsweringDispatch), operator_door());
    let node = AdminNode::new(crate::root::kernel::new_kernel(), units);
    for path in AUDIT_PATHS {
        let answer = node.answer(a_ledger_request(path)).await;
        assert_eq!(answer.status, 404, "{path} answered over an unbound chain");
        assert!(
            !String::from_utf8_lossy(&answer.body).contains("entries"),
            "{path} reached the legacy dispatch"
        );
    }
}

#[tokio::test]
async fn a_range_read_that_names_no_window_is_refused_rather_than_widened() {
    for target in [
        "/api/v1/admin/audit/range",
        "/api/v1/admin/audit/range?from=2",
        "/api/v1/admin/audit/range?to=3",
        "/api/v1/admin/audit/range?from=3&to=2",
        "/api/v1/admin/audit/range?from=two&to=three",
    ] {
        let answer = answer_over_a_sealed_chain(a_ledger_request(target)).await;
        assert_eq!(answer.status, 400, "{target} was not refused as malformed");
    }

    assert_eq!(
        answer_over_a_sealed_chain(a_ledger_request("/api/v1/admin/audit/range?from=1&to=3"))
            .await
            .status,
        200
    );
}

#[test]
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
            busbar_kernel::admin::scope::admin_required_scope("GET", path),
            Scope::ReadOnly
        );
    }
}

#[test]
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

#[tokio::test]
async fn the_one_document_describes_the_ledger_views() {
    // The ledger no longer has a document path of its own (#304): the one document is `GET /openapi.json`.
    let served = busbar_core_admin::v1::json::openapi_document();
    let document: json::Value = json::parse_value(served.as_bytes()).expect("it is JSON");
    let paths = document["paths"].as_object().expect("it declares paths");
    assert!(
        paths.contains_key(&"/api/v1/admin/usage"),
        "the one document is the administrative one"
    );

    for path in LEDGER_PATHS {
        let op = &paths
            .get(path)
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

    let pinned: json::Value = json::parse_value(
        include_str!(concat!(
            env!("BUSBAR_CORE_DIR"),
            "/../../testing/shadow-oracle/fixtures/openapi-1.5.5.json"
        ))
        .as_bytes(),
    )
    .expect("the pinned fixture is JSON");
    let pinned_paths = pinned["paths"].as_object().expect("it declares paths");
    assert!(
        !pinned_paths
            .iter()
            .any(|(p, _)| p.starts_with("/api/v1/admin/ledger/")),
        "the ledger views are 1.6.0 surface; the pinned 1.5.5 document must not carry them"
    );
}

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
    let parsed: json::Value =
        json::parse_value(render_totals(&ledger).expect("projects").as_bytes())
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
fn a_body(body: json::Value) -> Vec<u8> {
    json::to_vec(&body).expect("the correction serialises")
}

#[cfg(test)]
struct JournalFaults {
    inner: Arc<dyn busbar_contract::persistence::PersistenceBackend>,
    refusing: Arc<std::sync::atomic::AtomicBool>,
    paused: std::sync::atomic::AtomicBool,
    uncertain: std::sync::atomic::AtomicUsize,
}
#[cfg(test)]
impl busbar_contract::persistence::PersistenceBackend for JournalFaults {
    fn info(&self) -> busbar_contract::persistence::BackendInfo {
        self.inner.info()
    }
    fn read(
        &self,
        request: Arc<busbar_contract::persistence::Read>,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::ReadResult> {
        self.inner.read(request)
    }
    fn scan(
        &self,
        request: Arc<busbar_contract::persistence::Scan>,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::Page> {
        self.inner.scan(request)
    }
    fn clock(
        &self,
        dataset: busbar_contract::persistence::DatasetId,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::ClockObservation>
    {
        self.inner.clock(dataset)
    }
    fn commit(
        &self,
        candidate: busbar_contract::persistence::PreparedCandidate,
        key: busbar_contract::persistence::CommitKey,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::Decision> {
        Box::pin(async move {
            use busbar_contract::persistence::{Decision, Failure};
            use std::sync::atomic::Ordering;
            if self.refusing.load(Ordering::SeqCst) {
                return Err(Failure::Unavailable);
            }
            let decision = self.inner.commit(candidate, key).await?;
            if self.paused.load(Ordering::SeqCst) && matches!(decision, Decision::Applied(_)) {
                self.uncertain.fetch_add(1, Ordering::SeqCst);
                return Err(Failure::Unknown);
            }
            Ok(decision)
        })
    }
}
#[cfg(test)]
struct NativeJournalStore {
    core: Arc<busbar_kernel::persistence::facade::CoreStore>,
    faults: Arc<JournalFaults>,
    node: u64,
}
#[cfg(test)]
impl NativeJournalStore {
    async fn new() -> Self {
        Self::switching(Arc::new(std::sync::atomic::AtomicBool::new(false))).await
    }
    async fn switching(refusing: Arc<std::sync::atomic::AtomicBool>) -> Self {
        assert!(
            !refusing.load(std::sync::atomic::Ordering::SeqCst),
            "enable faults after startup"
        );
        let faults = Arc::new(JournalFaults {
            inner: crate::root::real_store::native_backend().await,
            refusing,
            paused: std::sync::atomic::AtomicBool::new(false),
            uncertain: std::sync::atomic::AtomicUsize::new(0),
        });
        let core = crate::root::real_store::core_over(faults.clone()).await;
        Self {
            core,
            faults,
            node: busbar_kernel::door::op_id().counter(),
        }
    }
    fn refuse(&self, value: bool) {
        self.faults
            .refusing
            .store(value, std::sync::atomic::Ordering::SeqCst);
    }
    fn pause(&self, value: bool) {
        self.faults
            .paused
            .store(value, std::sync::atomic::Ordering::SeqCst);
    }
    fn waiting(&self) -> usize {
        self.faults
            .uncertain
            .load(std::sync::atomic::Ordering::SeqCst)
    }
    async fn book(&self) -> Arc<Mutex<crate::root::durability::Durability>> {
        use busbar_kernel::persistence::journal::runtime::{BufferBudget, RuntimeJournal};
        let budget = BufferBudget {
            records: 16_384,
            bytes: 32 * 1024 * 1024,
        };
        let journal = RuntimeJournal::open(Arc::clone(&self.core), self.node, budget)
            .await
            .expect("native journal opens");
        Arc::new(Mutex::new(
            crate::root::durability::build_on_store(
                &crate::root::durability::DurabilityConfig { data_dir: None },
                self.node,
                journal,
                None,
                budget,
            )
            .await
            .expect("native journal recovery"),
        ))
    }
}

#[cfg(test)]
async fn a_memory_book() -> Arc<Mutex<crate::root::durability::Durability>> {
    NativeJournalStore::new().await.book().await
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
async fn amend_through_a_journal(
    history: &crate::root::kernel::RootHistory,
    body: &[u8],
    arrival_secs: u64,
) -> Result<AdminAnswer, busbar_core_admin::GovernanceError> {
    let book = a_memory_book().await;
    amend_rate_history_effect(
        history,
        Some(&a_journal_over(&book)),
        body,
        arrival_secs,
        &an_attribution(),
    )
    .await
}

#[cfg(test)]
async fn replayed_amendments(
    book: &Arc<Mutex<crate::root::durability::Durability>>,
) -> Vec<AmendmentRecord> {
    let chain = { book.lock().unwrap().chain_at() };
    chain
        .read()
        .await
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
    a_body(json::json!({
        "effective_from": 0,
        "effective_until": 86_400_000,
        "rates": [ { "lane": "gpt", "class": "input", "micro_per_unit": 1.0 } ],
        "reason": "vendor corrected the March price sheet",
    }))
}

#[tokio::test]
async fn amend_rate_history_appends_a_signed_back_dated_correction_and_rewrites_nothing() {
    let history = a_seeded_history();
    let instant = 5_000u64;

    let before = history.pin().expect("the opening pinned");
    let (before_seq, _) = before
        .view()
        .card_at(instant)
        .expect("the opening prices the instant");
    assert_eq!(before_seq, before.seq());

    let answer = amend_through_a_journal(&history, &a_correction_body(), ARRIVED)
        .await
        .expect("the correction applies");
    assert_eq!(answer.status, 200);
    let doc: json::Value = json::parse_value(&answer.body).expect("the answer is JSON");
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

#[tokio::test]
async fn amend_rate_history_refuses_a_correction_that_names_a_currency() {
    for named in [
        json::json!("JPY"),
        json::json!("USD"),
        json::json!("nonsense"),
        json::json!(null),
    ] {
        let history = a_seeded_history();
        let body = a_body(json::json!({
            "effective_from": 0,
            "effective_until": 86_400_000,
            "currency": named,
            "rates": [ { "lane": "gpt", "class": "input", "micro_per_unit": 1.0 } ],
            "reason": "vendor corrected the March price sheet",
        }));
        let err = amend_through_a_journal(&history, &body, ARRIVED)
            .await
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
        .await
        .expect("the same correction with no `currency` key applies");
    assert_eq!(history.len(), 2);
}

#[test]
fn the_canonical_amend_payload_names_no_currency() {
    let body = json::json!({
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

    assert!(text.starts_with("busbar/amend-rate-history/v2\n"), "{text}");
    for key in [
        "effective_from=",
        "effective_until=",
        "per_request_fee=",
        "reason_sha256=",
        "rates=",
    ] {
        assert!(text.contains(key), "the payload dropped {key}: {text}");
    }
}

/// The amendment API keeps the reason's SHA-256, not its text (`kernel_verbs.rs`, openapi): the
/// canonical payload stored in the policy journal carries the hash, never the operator's words.
#[test]
fn the_canonical_amend_payload_keeps_the_reason_hash_not_its_text() {
    let reason = "vendor corrected the March price sheet";
    let body = json::json!({
        "effective_from": 0,
        "rates": [ { "lane": "gpt", "class": "input", "micro_per_unit": 1.0 } ],
        "reason": reason,
    });
    let payload = canonical_amend_payload(body.as_object().expect("an object"));
    let text = String::from_utf8(payload).expect("the payload is text");
    assert!(
        !text.contains(reason),
        "the signed payload carries the reason text: {text}"
    );
    let hash = hex::encode(busbar_contract::abi::sdk::digest::sha256(reason.as_bytes()));
    assert!(
        text.contains(&format!("reason_sha256=\"{hash}\"\n")),
        "the signed payload names the reason by its SHA-256: {text}"
    );
}

#[tokio::test]
async fn amend_rate_history_refuses_a_negative_fee_and_appends_nothing() {
    for fee in [-1_i64, -5, i64::MIN] {
        let history = a_seeded_history();
        let body = a_body(json::json!({
            "effective_from": 0,
            "effective_until": 86_400_000,
            "per_request_fee": fee,
            "rates": [ { "lane": "gpt", "class": "input", "micro_per_unit": 1.0 } ],
            "reason": "vendor corrected the March price sheet",
        }));
        let err = amend_through_a_journal(&history, &body, ARRIVED)
            .await
            .expect_err("a correction carrying a negative fee must be refused");
        assert!(
            matches!(err, busbar_core_admin::GovernanceError::Validation),
            "fee {fee} must refuse Validation, got {err:?}"
        );
        assert_eq!(history.len(), 1, "a refused fee {fee} appends nothing");
    }

    for fee in [5_i64, 0] {
        let history = a_seeded_history();
        let body = a_body(json::json!({
            "effective_from": 0,
            "effective_until": 86_400_000,
            "per_request_fee": fee,
            "rates": [ { "lane": "gpt", "class": "input", "micro_per_unit": 1.0 } ],
            "reason": "vendor corrected the March price sheet",
        }));
        amend_through_a_journal(&history, &body, ARRIVED)
            .await
            .expect("a non-negative fee applies");
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

#[tokio::test]
async fn a_correction_of_one_cell_keeps_every_other_price_and_the_fee() {
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
        .await
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

#[tokio::test]
async fn a_fee_or_plane_correction_moves_only_what_it_names() {
    let history = a_full_card_history();
    let body = a_body(json::json!({
        "effective_from": 0,
        "effective_until": 86_400_000,
        "per_request_fee": 7,
        "rates": [ { "lane": "plane-b\u{1f}search", "class": "input", "micro_per_unit": 9.0 } ],
        "reason": "vendor corrected the March price sheet",
    }));
    amend_through_a_journal(&history, &body, ARRIVED)
        .await
        .expect("the correction applies");
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

#[tokio::test]
async fn a_correction_across_a_card_boundary_or_onto_an_absent_plane_is_refused() {
    let history = a_full_card_history();
    history.apply(a_card_at(4.0, 0), 6_000);
    let before = history.len();
    let refused = amend_through_a_journal(&history, &a_correction_body(), ARRIVED + 1).await;
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
    let body = a_body(json::json!({
        "effective_from": 0,
        "effective_until": 86_400_000,
        "rates": [ { "lane": "plane-c\u{1f}hop", "class": "bytes", "micro_per_unit": 1.0 } ],
        "reason": "vendor corrected the March price sheet",
    }));
    let refused = amend_through_a_journal(&history, &body, ARRIVED).await;
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
    a_body(json::json!({
        "effective_from": from,
        "effective_until": until,
        "rates": [ { "lane": "gpt", "class": "input", "micro_per_unit": 1.0 } ],
        "reason": "vendor corrected the March price sheet",
    }))
}

#[cfg(test)]
async fn amend_at(
    history: &crate::root::kernel::RootHistory,
    body: &[u8],
    arrival_ms: u64,
) -> (
    Result<AdminAnswer, busbar_core_admin::GovernanceError>,
    usize,
) {
    let book = a_memory_book().await;
    let result = amend_rate_history_effect(
        history,
        Some(&a_journal_over(&book)),
        body,
        arrival_ms / 1_000,
        &an_attribution(),
    )
    .await;
    let records = replayed_amendments(&book).await.len();
    (result, records)
}

#[tokio::test]
async fn a_correction_that_would_cut_inside_a_stored_row_is_refused() {
    let arrival = 2 * DAY_MS + 10 * HOUR_MS;
    for (from, until) in [
        (DAY_MS + 12 * HOUR_MS, Some(DAY_MS + 18 * HOUR_MS)),
        (DAY_MS, Some(DAY_MS + 6 * HOUR_MS)),
        (DAY_MS + 12 * HOUR_MS, None),
        (2 * DAY_MS + 12 * HOUR_MS, Some(3 * DAY_MS + 6 * HOUR_MS)),
    ] {
        let history = a_seeded_history();
        let (result, records) =
            amend_at(&history, &a_window_correction(from, until), arrival).await;
        assert!(
            matches!(result, Err(busbar_core_admin::GovernanceError::Validation)),
            "[{from}, {until:?}) cuts inside a row and must be refused: {result:?}"
        );
        assert_eq!(history.len(), 1, "[{from}, {until:?}): nothing appended");
        assert_eq!(records, 0, "[{from}, {until:?}): nothing recorded");
    }
}

#[tokio::test]
async fn a_correction_on_row_boundaries_applies() {
    let arrival = 2 * DAY_MS + 10 * HOUR_MS;
    for (from, until) in [(DAY_MS, Some(2 * DAY_MS)), (0, Some(2 * DAY_MS))] {
        let history = a_seeded_history();
        let (result, records) =
            amend_at(&history, &a_window_correction(from, until), arrival).await;
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
    )
    .await;
    assert!(
        result.is_ok(),
        "a config apply at a Store bucket boundary permits the complete bucket: {result:?}"
    );
    assert_eq!((history.len(), records), (3, 1));
}

#[tokio::test]
async fn a_config_apply_inside_a_bucket_does_not_permit_a_partial_bucket_correction() {
    let era = DAY_MS + 12 * HOUR_MS;
    let history = a_seeded_history();
    history.apply(a_card_at(4.0, 0), era);
    let (result, records) = amend_at(
        &history,
        &a_window_correction(era, Some(2 * DAY_MS)),
        2 * DAY_MS + 10 * HOUR_MS,
    )
    .await;
    assert!(matches!(
        result,
        Err(busbar_core_admin::GovernanceError::Validation)
    ));
    assert_eq!((history.len(), records), (2, 0));
}

#[tokio::test]
async fn an_open_ended_amend_or_one_ending_after_its_arrival_is_refused() {
    let arrival = 2 * DAY_MS + 10 * HOUR_MS;
    for (from, until) in [
        (DAY_MS, None),
        (0, Some(3 * DAY_MS)),
        (DAY_MS, Some(arrival + 1)),
    ] {
        let history = a_seeded_history();
        let (result, records) =
            amend_at(&history, &a_window_correction(from, until), arrival).await;
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

#[tokio::test]
async fn a_future_dated_correction_is_refused_and_appends_nothing() {
    let arrival = 2 * DAY_MS + 10 * HOUR_MS;
    let future = (3 * DAY_MS, Some(4 * DAY_MS));
    for (from, until) in [
        future,
        (2 * DAY_MS + 12 * HOUR_MS, Some(2 * DAY_MS + 18 * HOUR_MS)),
        (2 * DAY_MS + 10 * HOUR_MS + 1_000, None),
    ] {
        let history = a_seeded_history();
        let (result, records) =
            amend_at(&history, &a_window_correction(from, until), arrival).await;
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
    )
    .await;
    assert!(
        result.is_ok(),
        "the same window, once past, applies: {result:?}"
    );
    assert_eq!((history.len(), records), (2, 1));
}

#[tokio::test]
async fn a_replayed_signed_correction_is_refused_and_appends_nothing() {
    let book = a_memory_book().await;
    let journal = a_journal_over(&book);
    let history = a_seeded_history();
    let first = a_priced_correction(5, json::json!(1.5));
    let apply = async |body: &[u8], arrival_secs: u64| {
        amend_rate_history_effect(
            &history,
            Some(&journal),
            body,
            arrival_secs,
            &an_attribution(),
        )
        .await
    };
    apply(&first, ARRIVED)
        .await
        .expect("the first correction applies");
    apply(&a_priced_correction(9, json::json!(3.0)), ARRIVED + 1)
        .await
        .expect("a later correction of the same window applies");
    assert_eq!(history.len(), 3);

    let replayed = apply(&first, ARRIVED + 2).await;
    assert!(
        matches!(replayed, Err(busbar_core_admin::GovernanceError::Conflict)),
        "the first correction's signed bytes, sent again, must be refused: {replayed:?}"
    );
    assert_eq!(history.len(), 3, "a replay appends nothing");
    assert_eq!(
        replayed_amendments(&book).await.len(),
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
struct AmendScratch(std::path::PathBuf, NativeJournalStore);

#[cfg(test)]
impl AmendScratch {
    async fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "busbar-amend-journal-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("scratch directory");
        AmendScratch(path, NativeJournalStore::new().await)
    }

    async fn book(&self) -> Arc<Mutex<crate::root::durability::Durability>> {
        self.1.book().await
    }
}

#[cfg(test)]
impl Drop for AmendScratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
fn a_priced_correction(fee: i64, micro: json::Value) -> Vec<u8> {
    a_body(json::json!({
        "effective_from": 0,
        "effective_until": 86_400_000,
        "per_request_fee": fee,
        "rates": [ { "lane": "gpt", "class": "input", "micro_per_unit": micro } ],
        "reason": "vendor corrected the March price sheet",
    }))
}

#[tokio::test]
async fn a_sealed_amendment_survives_a_restart_with_its_figures() {
    let scratch = AmendScratch::new("restart").await;
    {
        let book = scratch.book().await;
        let history = a_seeded_history();
        amend_rate_history_effect(
            &history,
            Some(&a_journal_over(&book)),
            &a_priced_correction(5, json::json!(1.5)),
            ARRIVED,
            &an_attribution(),
        )
        .await
        .expect("the correction applies");
    }

    let restarted = scratch.book().await;
    assert!(restarted.lock().unwrap().durable_in_store());
    assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    let records = replayed_amendments(&restarted).await;
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
            .starts_with(b"busbar/amend-rate-history/v2\n"),
        "the record keeps the correction's canonical bytes"
    );
}

#[tokio::test]
async fn a_correction_rate_is_sealed_as_an_exact_integer_or_refused() {
    for (micro, nanos) in [
        (json::json!(1.5), 1_500),
        (json::json!(0.001), 1),
        (json::json!(2e-3), 2),
        (json::json!(7), 7_000),
        (json::json!(0.0), 0),
    ] {
        let scratch = AmendScratch::new("exact-rate").await;
        let book = scratch.book().await;
        amend_rate_history_effect(
            &a_seeded_history(),
            Some(&a_journal_over(&book)),
            &a_priced_correction(0, micro.clone()),
            ARRIVED,
            &an_attribution(),
        )
        .await
        .unwrap_or_else(|e| panic!("{micro} is exactly {nanos} nano-units: {e:?}"));
        let records = replayed_amendments(&book).await;
        assert_eq!(
            records[0].rates,
            vec![("gpt".to_string(), "input".to_string(), Some(nanos))],
            "{micro} micro per unit is sealed as exactly {nanos} nano per unit"
        );
    }
    for micro in [
        json::json!(0.0001),
        json::json!(0.0015),
        json::json!(-1.0),
        json::json!(1e30),
        json::json!("1.5"),
    ] {
        let scratch = AmendScratch::new("inexact-rate").await;
        let book = scratch.book().await;
        let history = a_seeded_history();
        let before = history.history().expect("a history").len();
        let refused = amend_rate_history_effect(
            &history,
            Some(&a_journal_over(&book)),
            &a_priced_correction(0, micro.clone()),
            ARRIVED,
            &an_attribution(),
        )
        .await;
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
            replayed_amendments(&book).await.is_empty(),
            "{micro}: a refused correction journals nothing"
        );
    }
}

#[tokio::test]
async fn a_thousand_later_amendments_do_not_erase_the_first() {
    let scratch = AmendScratch::new("volume").await;
    {
        let book = scratch.book().await;
        let journal = a_journal_over(&book);
        let history = a_seeded_history();
        amend_rate_history_effect(
            &history,
            Some(&journal),
            &a_priced_correction(7, json::json!(2.0)),
            ARRIVED,
            &an_attribution(),
        )
        .await
        .expect("the first correction applies");

        for fee in 8..1_008 {
            amend_rate_history_effect(
                &history,
                Some(&journal),
                &a_priced_correction(fee, json::json!(1.0)),
                ARRIVED + 1,
                &an_attribution(),
            )
            .await
            .expect("a later correction applies");
        }
    }
    let restarted = scratch.book().await;
    assert!(restarted.lock().unwrap().durable_in_store());
    assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    let records = replayed_amendments(&restarted).await;
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

#[tokio::test]
async fn an_amendment_with_no_journal_bound_is_refused_and_appends_nothing() {
    let history = a_seeded_history();
    let err = amend_rate_history_effect(
        &history,
        None,
        &a_correction_body(),
        ARRIVED,
        &an_attribution(),
    )
    .await
    .expect_err("no journal, no amendment");
    assert!(matches!(err, busbar_core_admin::GovernanceError::Store));
    assert_eq!(history.len(), 1);

    let book = a_memory_book().await;
    amend_rate_history_effect(
        &history,
        Some(&a_journal_over(&book)),
        &a_correction_body(),
        ARRIVED,
        &an_attribution(),
    )
    .await
    .expect("with a journal the correction applies");
    assert_eq!(history.len(), 2);
    assert_eq!(replayed_amendments(&book).await.len(), 1);
}

#[tokio::test]
async fn a_refused_amendment_leaves_no_record() {
    let book = a_memory_book().await;
    let history = a_seeded_history();
    amend_rate_history_effect(
        &history,
        Some(&a_journal_over(&book)),
        &a_priced_correction(-5, json::json!(1.0)),
        ARRIVED,
        &an_attribution(),
    )
    .await
    .expect_err("refused");
    assert_eq!(history.len(), 1);
    assert!(replayed_amendments(&book).await.is_empty());
}

#[tokio::test]
async fn amend_rate_history_refuses_a_correction_that_names_no_reason_window_or_price() {
    let cases: &[json::Value] = &[
        json::json!({ "effective_from": 1, "rates": [{"lane":"gpt","class":"input","micro_per_unit":1.0}] }),
        json::json!({ "effective_from": 9, "effective_until": 1, "rates": [{"lane":"gpt","class":"input","micro_per_unit":1.0}], "reason": "r" }),
        json::json!({ "effective_from": 1, "reason": "r" }),
        json::json!({ "rates": [{"lane":"gpt","class":"input","micro_per_unit":1.0}], "reason": "r" }),
    ];
    for case in cases {
        let history = a_seeded_history();
        let body = json::to_vec(case).expect("serialises");
        let err = amend_through_a_journal(&history, &body, ARRIVED)
            .await
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
        amend_through_a_journal(&history, b"not json", ARRIVED).await,
        Err(busbar_core_admin::GovernanceError::Validation)
    ));
    assert_eq!(history.len(), 1);
}

#[tokio::test]
async fn amend_rate_history_refuses_when_there_is_no_history_to_amend() {
    let empty = crate::root::kernel::RootHistory::default();
    let err = amend_through_a_journal(&empty, &a_correction_body(), ARRIVED)
        .await
        .expect_err("an empty history cannot be amended");
    assert!(matches!(err, busbar_core_admin::GovernanceError::NotFound));
    assert_eq!(empty.len(), 0);
}

#[tokio::test]
async fn amend_rate_history_applies_a_correction_that_carries_no_signature() {
    let history = a_seeded_history();
    let body = a_correction_body();
    let doc: json::Value = json::parse_value(&body).expect("the body is JSON");
    assert!(doc.get("signature").is_none() && doc.get("operator_fingerprint").is_none());
    let answer = amend_through_a_journal(&history, &body, ARRIVED)
        .await
        .expect("an unsigned correction applies");
    assert_eq!(answer.status, 200);
    let doc: json::Value = json::parse_value(&answer.body).expect("JSON");
    assert!(
        doc.get("operator_fingerprint").is_none(),
        "the answer names no signer: {doc}"
    );
    assert_eq!(history.len(), 2, "the correction appended one entry");
}

#[tokio::test]
async fn amend_rate_history_ignores_a_signature_a_body_still_carries() {
    let history = a_seeded_history();
    let mut doc: json::Value = json::parse_value(&a_correction_body()).expect("the body is JSON");
    doc["operator_fingerprint"] = json::json!("a-fingerprint-nothing-checks");
    doc["signature"] = json::json!("00".repeat(64));
    let answer = amend_through_a_journal(&history, &a_body(doc), ARRIVED)
        .await
        .expect("a body carrying a stale signature still applies");
    let doc: json::Value = json::parse_value(&answer.body).expect("JSON");
    assert!(
        doc.get("operator_fingerprint").is_none(),
        "the answer names no signer: {doc}"
    );
}

#[tokio::test]
async fn a_signed_record_verifies_against_the_served_audit_keys() {
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
        unit: busbar_kernel_audit::UnitFacts::default(),
    };
    let audit_token = an_audit_pass();
    let served_keys = async |units: crate::root::kernel::ProductionUnits| -> Vec<String> {
        let node = AdminNode::new(crate::root::kernel::new_kernel(), units);
        let served: json::Value = json::parse_value(
            &node
                .answer(a_ledger_request("/api/v1/admin/audit/keys"))
                .await
                .body,
        )
        .expect("valid JSON");
        served["items"]
            .as_array()
            .expect("items")
            .iter()
            .map(|k| k["public_key"].as_str().expect("public_key").to_string())
            .collect()
    };

    let units = crate::root::kernel::ProductionUnits::admin_only(
        Arc::new(AnsweringDispatch),
        operator_door(),
    )
    .await;
    let record = {
        let mut durability = units.durability.lock().expect("durability lock");
        durability.record.seal(inputs(), &audit_token)
    };
    assert!(
        served_keys(units).await.is_empty(),
        "a keyless node publishes no key"
    );
    assert!(record.signature.is_none());

    let units = crate::root::kernel::ProductionUnits::admin_only(
        Arc::new(AnsweringDispatch),
        operator_door(),
    )
    .await;
    let record = {
        let mut durability = units.durability.lock().expect("durability lock");
        crate::root::keyset::bind_ephemeral(&mut durability).expect("the keyset binds");
        durability.record.seal(inputs(), &audit_token)
    };
    let published = served_keys(units).await;
    assert_eq!(published.len(), 1, "the one deployment key is published");
    let key = AuditVerifyingKey::from_hex(&published[0]).expect("a published public key");
    assert_eq!(record.key_id.as_deref(), Some(key.key_id()));
    AuditChain::verify_signature(&record, &key)
        .expect("the signed record verifies against the served key");
}

#[cfg(test)]
async fn a_book_over_the_store(
    slots: &NativeJournalStore,
) -> Arc<Mutex<crate::root::durability::Durability>> {
    slots.book().await
}

#[cfg(test)]
fn status_and_body(answer: &AdminAnswer) -> (u16, String) {
    (
        answer.status,
        String::from_utf8_lossy(&answer.body).into_owned(),
    )
}

#[tokio::test]
async fn a_correction_on_a_node_with_no_data_dir_is_kept_by_the_store_and_survives_a_restart() {
    let slots = NativeJournalStore::new().await;
    {
        let book = a_book_over_the_store(&slots).await;
        let answered = amend_rate_history_effect(
            &a_seeded_history(),
            Some(&a_journal_over(&book)),
            &a_priced_correction(5, json::json!(1.5)),
            ARRIVED,
            &an_attribution(),
        )
        .await
        .expect("the correction applies");
        let (status, body) = status_and_body(&answered);
        assert_eq!(status, 200, "{body}");
    }
    let restarted = a_book_over_the_store(&slots).await;
    let records = replayed_amendments(&restarted).await;
    assert_eq!(
        records.len(),
        1,
        "the store kept the amendment and the restart read it back"
    );
    assert_eq!(records[0].sealed_fee, 5);
}

#[tokio::test]
async fn a_correction_the_store_refuses_answers_503_with_the_reason() {
    let slots = NativeJournalStore::new().await;
    slots.refuse(true);
    let book = a_book_over_the_store(&slots).await;
    let answered = amend_rate_history_effect(
        &a_seeded_history(),
        Some(&a_journal_over(&book)),
        &a_priced_correction(5, json::json!(1.5)),
        ARRIVED,
        &an_attribution(),
    )
    .await
    .expect("an answer, not an error");
    let (status, body) = status_and_body(&answered);
    assert_eq!(status, 503, "{body}");
    assert!(
        body.contains("sealed at journal position")
            && body.contains("not yet kept by the store: Pending")
            && body.contains("do not re-submit"),
        "the native journal retains the correction instead of claiming durable success: {body}"
    );

    let before = book.lock().unwrap().journal.next_seq();
    let again = amend_rate_history_effect(
        &a_seeded_history(),
        Some(&a_journal_over(&book)),
        &a_priced_correction(6, json::json!(2)),
        ARRIVED + 1,
        &an_attribution(),
    )
    .await
    .expect("an answer");
    assert_eq!(status_and_body(&again).0, 503);
    assert_eq!(
        book.lock().unwrap().journal.next_seq(),
        before,
        "nothing is recorded while the store refuses"
    );
}

#[tokio::test]
async fn commit_upgrade_answers_only_once_the_store_kept_its_record() {
    let body = json::to_vec(&json::json!({ "version": bound::RUNNING_RELEASE })).expect("json");

    let refusing = NativeJournalStore::new().await;
    refusing.refuse(true);
    let book = a_book_over_the_store(&refusing).await;
    let answer =
        bound::commit_upgrade_effect(&body, 1_700_000_000, "admin", Some(&a_journal_over(&book)))
            .await
            .expect("an answer");
    assert_eq!(
        answer.status,
        503,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    let pending = String::from_utf8_lossy(&answer.body);
    assert!(
        pending.contains("sealed at journal position")
            && pending.contains("not yet kept by the store: Pending")
            && pending.contains("do not re-submit"),
        "the unconfirmed commit stays retained: {pending}"
    );

    let taking = NativeJournalStore::new().await;
    let book = a_book_over_the_store(&taking).await;
    let answer =
        bound::commit_upgrade_effect(&body, 1_700_000_000, "admin", Some(&a_journal_over(&book)))
            .await
            .expect("an answer");
    assert_eq!(
        answer.status,
        200,
        "{}",
        String::from_utf8_lossy(&answer.body)
    );
    assert!(book.lock().unwrap().journal.next_seq() > 1);
}

#[cfg(test)]
async fn a_book_whose_store_switches(
    refusing: &Arc<std::sync::atomic::AtomicBool>,
) -> Arc<Mutex<crate::root::durability::Durability>> {
    NativeJournalStore::switching(Arc::clone(refusing))
        .await
        .book()
        .await
}

#[cfg(test)]
async fn append_the_next_record(book: &Arc<Mutex<crate::root::durability::Durability>>) {
    let journal = Arc::clone(&book.lock().unwrap().journal);
    let run = journal
        .stage_run(&[
            busbar_kernel_wal::Entry::new(busbar_kernel_wal::RecordClass::Load, vec![1]).at(7, 0),
        ])
        .expect("stage exact next record");
    journal
        .confirm(&run)
        .await
        .expect("native Store confirms original runs before the next record");
}

#[tokio::test]
async fn a_correction_the_journal_retained_is_in_force_and_answered_not_yet_kept() {
    let refusing = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let book = a_book_whose_store_switches(&refusing).await;
    refusing.store(true, std::sync::atomic::Ordering::SeqCst);
    let history = a_seeded_history();
    let answered = amend_rate_history_effect(
        &history,
        Some(&a_journal_over(&book)),
        &a_priced_correction(5, json::json!(1.5)),
        ARRIVED,
        &an_attribution(),
    )
    .await
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
    append_the_next_record(&book).await;
    assert_eq!(
        replayed_amendments(&book).await.len(),
        1,
        "the retained record landed on the chain a restart rebuilds the history from"
    );
    assert!(
        matches!(
            amend_rate_history_effect(
                &history,
                Some(&a_journal_over(&book)),
                &a_priced_correction(5, json::json!(1.5)),
                ARRIVED + 1,
                &an_attribution(),
            )
            .await,
            Err(busbar_core_admin::GovernanceError::Conflict)
        ),
        "a re-submission is refused: the correction is already applied"
    );
    assert_eq!(history.len(), 2);
}

#[tokio::test]
async fn a_commit_the_journal_retained_is_answered_not_yet_kept_and_lands() {
    let refusing = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let book = a_book_whose_store_switches(&refusing).await;
    refusing.store(true, std::sync::atomic::Ordering::SeqCst);
    let body = json::to_vec(&json::json!({ "version": bound::RUNNING_RELEASE })).expect("json");
    let answer =
        bound::commit_upgrade_effect(&body, 1_700_000_000, "admin", Some(&a_journal_over(&book)))
            .await
            .expect("a commit the journal chained is answered, never refused as unrecorded");
    let text = String::from_utf8_lossy(&answer.body).into_owned();
    assert_eq!(answer.status, 503, "{text}");
    assert!(text.contains("do not re-submit"), "{text}");

    refusing.store(false, std::sync::atomic::Ordering::SeqCst);
    append_the_next_record(&book).await;
    let chain = { book.lock().unwrap().chain_at() };
    let records = chain
        .read()
        .await
        .expect("the native journal reads")
        .expect("the native journal verifies");
    let commits: Vec<_> = records
        .iter()
        .filter(|record| record.class == busbar_kernel_wal::RecordClass::Policy)
        .collect();
    assert_eq!(commits.len(), 1, "the retained commit landed on the chain");
    let mut commit = busbar_kernel_wal::BodyReader::new(&commits[0].body);
    assert_eq!(commit.text(), Some(bound::COMMIT_UPGRADE_RECORD_TAG));
    assert_eq!(commit.text(), Some(bound::RUNNING_RELEASE));
    assert_eq!(commit.num(), Some(1_700_000_000));
    assert_eq!(commit.text(), Some("admin"));
    assert!(commit.is_done(), "the exact original commit body survived");
}

#[tokio::test]
async fn a_keyed_commit_with_a_late_store_ack_seals_one_policy() {
    let slots = NativeJournalStore::new().await;
    let book = a_book_over_the_store(&slots).await;
    let journal = Arc::new(a_journal_over(&book));
    append_the_next_record(&book).await;
    journal
        .acked(journal.sealed_through())
        .await
        .expect("healthy journal");
    journal
        .admit()
        .await
        .expect("admitted before the store pends");
    let store = crate::root::real_store::admin_scoped().await;
    let replay_store: bound::ReplayStore = Arc::new(move || Some(Arc::clone(&store)));
    let mut request = a_request();
    request.edit_for_test(|draft| draft.method = "POST".into());
    request.edit_for_test(|draft| draft.path = "/api/v1/admin/commit-upgrade".into());
    request.edit_for_test(|draft| {
        draft.headers = vec![("idempotency-key".into(), "late-commit-ack".into())]
    });
    request.edit_for_test(|draft| {
        draft.body = json::to_vec(&json::json!({ "version": bound::RUNNING_RELEASE })).unwrap()
    });
    let cache = Arc::new(bound::ReplayCache::new());
    let admin = crate::root::kernel::new_kernel().admin_token();
    let ask = async |cache: Arc<bound::ReplayCache>,
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
            request.body(),
        )
        .await
        .expect("the production caller answers")
    };
    struct Unpause<'a>(&'a NativeJournalStore);
    impl Drop for Unpause<'_> {
        fn drop(&mut self) {
            self.0.pause(false);
        }
    }
    slots.pause(true);
    let release = Unpause(&slots);
    let first = ask(Arc::clone(&cache), &request, Some(Arc::clone(&journal))).await;
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
        .await
        .expect("the first receipt is now acknowledged");
    assert_eq!(
        ask(Arc::clone(&cache), &request, Some(Arc::clone(&journal))).await,
        first
    );
    request.edit_for_test(|draft| {
        draft.at += busbar_core_admin::idempotency::IDEMPOTENCY_TTL_SECS + 1
    });
    assert_eq!(
        ask(Arc::clone(&cache), &request, Some(Arc::clone(&journal))).await,
        first,
        "TTL cannot release the retained receipt"
    );
    assert_eq!(
        ask(
            Arc::new(bound::ReplayCache::new()),
            &request,
            Some(Arc::clone(&journal))
        )
        .await,
        first,
        "restart keeps the receipt"
    );
    assert_eq!(
        ask(Arc::new(bound::ReplayCache::new()), &request, None).await,
        first,
        "a sibling cannot replace the originating receipt"
    );
    assert_eq!(
        journal.sealed_through(),
        sealed,
        "reconciliation seals nothing"
    );
    let chain_at = {
        let book = book.lock().unwrap();
        book.chain_at()
    };
    let chain = chain_at.read().await.unwrap().unwrap();
    assert_eq!(
        chain
            .iter()
            .filter(|record| record.class == busbar_kernel_wal::RecordClass::Policy)
            .count(),
        1
    );
}

#[tokio::test]
async fn a_keyed_commit_refused_before_sealing_accepts_corrected_input() {
    let book = a_memory_book().await;
    let journal = a_journal_over(&book);
    let store = crate::root::real_store::admin_scoped().await;
    let replay_store: bound::ReplayStore = Arc::new(move || Some(Arc::clone(&store)));
    let cache = bound::ReplayCache::new();
    let mut request = a_request();
    request.edit_for_test(|draft| {
        draft.headers = vec![("idempotency-key".into(), "corrected-commit".into())]
    });
    request.edit_for_test(|draft| draft.body = br#"{"version":"not-this-binary"}"#.to_vec());
    let ask = async |request: &AdminRequest| {
        bound::replayable(
            &cache,
            Some(&replay_store),
            bound::ReplayScope {
                verb: KernelVerb::CommitUpgrade,
                actor: "admin",
            },
            request,
            request.body(),
            Some(&journal),
            bound::ReplayContext::None,
            || async {
                bound::commit_upgrade_effect(request.body(), request.at(), "admin", Some(&journal))
                    .await
            },
        )
        .await
        .expect("the write answers")
    };
    let before = journal.sealed_through();
    assert_eq!(ask(&request).await.status, 409);
    assert_eq!(
        journal.sealed_through(),
        before,
        "a definite refusal sealed nothing"
    );
    request.edit_for_test(|draft| {
        draft.body = json::to_vec(&json::json!({ "version": bound::RUNNING_RELEASE })).unwrap()
    });
    let accepted = ask(&request).await;
    assert_eq!(accepted.status, 200);
    let mut replayed = accepted.clone();
    replayed
        .headers
        .push(("idempotent-replayed".to_string(), "true".to_string()));
    assert_eq!(ask(&request).await, replayed);
    assert_eq!(journal.sealed_through(), before + 1);
}

#[tokio::test]
async fn route_refuses_a_unit_whose_grant_was_never_recorded() {
    let admin = crate::root::kernel::new_kernel().admin_token();
    let binding = AdminBinding::new(Arc::new(AnsweringDispatch), operator_door());
    let mut request = a_request();
    request.edit_for_test(|draft| draft.method = "POST".to_string());
    request.edit_for_test(|draft| draft.path = "/api/v1/admin/chain-break".to_string());
    let mut walk = AdminWalk::new(request);
    decode(&mut walk).expect("the plane's table declares this operation");

    let outcome = route(&binding, None, &admin, &mut walk).await;
    assert_eq!(
        outcome,
        Err(ReasonCode::ScopeDenied),
        "a unit with no recorded grant reached the verb"
    );
}

#[tokio::test]
async fn a_keyed_write_retried_after_a_restart_replays_and_runs_nothing_again() {
    let store = crate::root::real_store::admin_scoped().await;
    let held = Arc::clone(&store);
    let replay_store: bound::ReplayStore = Arc::new(move || Some(Arc::clone(&held)));
    let request = AdminRequest::test_fixture(crate::root::units_admin::TestAdminRequest {
        method: "POST".to_string(),
        path: "/api/v1/admin/plane-records".to_string(),
        credential: None,
        headers: vec![("idempotency-key".to_string(), "restart-d3".to_string())],
        body: br#"{"record":1}"#.to_vec(),
        at: 1_700_000_000,
        unit: a_fresh_unit(),
    });
    let ran = std::sync::atomic::AtomicUsize::new(0);
    let effect = || async {
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
        request.body(),
        None,
        bound::ReplayContext::None,
        effect,
    )
    .await
    .expect("the first write answers");

    let retried = bound::replayable(
        &bound::ReplayCache::new(),
        Some(&replay_store),
        bound::ReplayScope {
            verb: KernelVerb::PlaneRecordWrite,
            actor: "operator",
        },
        &request,
        request.body(),
        None,
        bound::ReplayContext::None,
        effect,
    )
    .await
    .expect("the retry answers");
    let mut marked = first.clone();
    marked
        .headers
        .push(("idempotent-replayed".to_string(), "true".to_string()));
    assert_eq!(
        retried, marked,
        "the retry answers the first answer's bytes, marked as replayed"
    );
    assert_eq!(
        ran.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the effect ran once across the restart"
    );
}

#[tokio::test]
async fn a_unit_this_root_did_not_compose_is_not_sealed_as_an_admin_read() {
    use tower::ServiceExt;

    let inner = axum::Router::new().fallback(axum::routing::any(|| async { "the surface" }));
    let book: Arc<std::sync::OnceLock<Arc<Mutex<crate::root::durability::Durability>>>> =
        Arc::new(std::sync::OnceLock::new());
    let kept = Arc::clone(&book);
    let mut units = crate::root::kernel::ProductionUnits::admin_only(
        Arc::new(RefusingDispatch),
        operator_door(),
    )
    .await;
    let wrapped = mount(
        inner,
        busbar_kernel::teller::Kernel::new(),
        1024,
        move |dispatch| {
            units.admin.dispatch = dispatch;
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
            .oneshot(charged_http_for_test(get(uncomposed)).await)
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
        .oneshot(charged_http_for_test(get("/api/v1/admin/audit?limit=4")).await)
        .await
        .expect("the router answers");
    assert_eq!(response.status(), 200);
    let records = sealed();
    assert_eq!(records.len(), 1, "one declared admin unit, one record");
    assert_eq!(records[0].what.op_class, admin_read);
}

#[tokio::test]
async fn a_claimed_length_is_checked_against_the_bytes_not_trusted() {
    use tower::ServiceExt;

    let inner = axum::Router::new().fallback(axum::routing::any(|| async { "the surface" }));
    let mut units = crate::root::kernel::ProductionUnits::admin_only(
        Arc::new(RefusingDispatch),
        operator_door(),
    )
    .await;
    let wrapped = mount(
        inner,
        busbar_kernel::teller::Kernel::new(),
        4,
        move |dispatch| {
            units.admin.dispatch = dispatch;
            units
        },
    );
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/api/v1/admin/keys")
        .header(axum::http::header::CONTENT_LENGTH, "3")
        .body(axum::body::Body::from(b"0123456789".to_vec()))
        .expect("the request builds");
    let response = wrapped
        .oneshot(charged_http_for_test(request).await)
        .await
        .expect("the router answers");
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
