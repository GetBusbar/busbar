// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

use busbar_contract::abi::auth::{AuthPoints, POINT_HEAD, POINT_HEAD_BODY, POINT_PEER};
use busbar_contract::abi::host::service::LINE_NONE;
use busbar_contract::abi::transport::route::{METHOD_GET, METHOD_POST, PATH_EXACT};
use busbar_contract::auth_calls::{VerifyAnswer, Verifying};

use super::*;
use crate::guest::{Claimant, Route};

#[path = "inbound_peer_points.rs"]
mod inbound_peer_points;

#[path = "inbound_reader_deadline.rs"]
mod inbound_reader_deadline;

struct Script {
    points: AuthPoints,
    answer: VerifyAnswer,
    calls: AtomicUsize,
    lent: Mutex<Vec<String>>,
    candidates: Mutex<Vec<Option<Secret<Vec<u8>>>>>,
}

impl Script {
    fn new(points: AuthPoints, verified: Verified, strips: Vec<Strip>) -> Arc<Self> {
        Arc::new(Self {
            points,
            answer: VerifyAnswer {
                strips,
                ..VerifyAnswer::from(verified)
            },
            calls: AtomicUsize::new(0),
            lent: Mutex::default(),
            candidates: Mutex::default(),
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

fn ticket_kit(gov: &Arc<crate::governance::GovState>, earlier: Arc<Script>) -> Kit {
    let points = AuthPoints(POINT_HEAD | earlier.points.bits());
    let k = kit_over(
        crate::test_support::TestApp::new()
            .keys_chain()
            .governance(Arc::clone(gov))
            .build(),
        vec!["earlier".into(), crate::config::KEYS_MODULE.into()],
        points,
        &[("earlier", earlier)],
    );
    let mut listener = k.inbound.table(OWNER, GEN).unwrap().listener.clone();
    listener.door_refusals = vec![crate::plane_routes::PlaneRefusalSpec {
        route: crate::plane_routes::DoorRouteId {
            path: MESSAGES.into(),
            method: busbar_contract::abi::mechanism::route::RouteMethod::Post,
        },
        refuse: Arc::new(|_, _| {
            axum::http::Response::builder()
                .status(401)
                .body(axum::body::Body::empty())
                .unwrap()
        }),
        ticket_prefix: Some("tk_".into()),
        signed_ingress: Arc::from([]),
    }];
    k.inbound.install_at(OWNER, 71, GEN, listener).unwrap();
    k.inbound.framing_started(OWNER, 71, 1, GEN).unwrap();
    k.inbound.grant_stream(OWNER, 1, 1, GEN).unwrap();
    k
}

async fn through_final_gate(
    k: &Kit,
    receipt: RequestAdmission,
    head: &Head,
) -> (u16, Option<Vec<u8>>) {
    let (status, ticket, _) = through_final_gate_identity(k, receipt, head).await;
    (status, ticket)
}

async fn through_final_gate_identity(
    k: &Kit,
    receipt: RequestAdmission,
    head: &Head,
) -> (u16, Option<Vec<u8>>, Option<String>) {
    use tower::ServiceExt as _;
    let observed = Arc::new(Mutex::new((None, None)));
    let held = Arc::clone(&observed);
    let handle = Arc::new(crate::state::AppHandle::new(Arc::clone(&k.app)));
    let table = k
        .inbound
        .request_table(
            OWNER,
            GEN,
            RequestBinding {
                conn: 1,
                stream: 1,
                framing: Some(1),
            },
            UnitRef::NONE,
            false,
        )
        .unwrap();
    let routes: &'static crate::core_routes::CoreRouteTable =
        Box::leak(Box::new(table.doors.clone()));
    let router = axum::Router::new()
        .route(
            MESSAGES,
            axum::routing::post(move |req: axum::extract::Request| {
                let held = Arc::clone(&held);
                async move {
                    let consumed = req
                        .extensions()
                        .get::<crate::auth::ConsumedCredentials>()
                        .unwrap();
                    let key = req
                        .extensions()
                        .get::<crate::governance::GovCtx>()
                        .and_then(|gov| gov.key.as_ref())
                        .map(|key| key.id.clone());
                    *held.lock().unwrap() = (consumed.ticket.clone(), key);
                    assert!(!req.headers().contains_key("authorization"));
                    axum::http::StatusCode::OK
                }
            }),
        )
        .layer(axum::middleware::from_fn_with_state(
            handle.clone(),
            move |app: crate::state::CurrentApp,
                  req: axum::extract::Request,
                  next: axum::middleware::Next| {
                crate::auth::auth_middleware(app, routes, req, next)
            },
        ))
        .with_state(handle);
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri(head.path_and_query())
        .body(axum::body::Body::empty())
        .unwrap();
    *request.headers_mut() = header_map(head);
    request.extensions_mut().insert(receipt);
    let response = router.oneshot(request).await.unwrap();
    let (record, key) = observed.lock().unwrap().clone();
    (response.status().as_u16(), record, key)
}

#[tokio::test]
async fn ticket_preflight_skips_the_chain_and_only_the_final_gate_spends_it() {
    crate::snapshot::init();
    let gov = signing_gov();
    let now = crate::store::now();
    let (id, _) = minted(&gov, now + 3600, now);
    let (ticket, _) = gov
        .mint_ticket(&id, "tk_", 600, None, b"ticket-record", now)
        .unwrap();
    let earlier = Script::new(AuthPoints::HEAD, Verified::Reject, Vec::new());
    let k = ticket_kit(&gov, Arc::clone(&earlier));
    for _ in 0..2 {
        let original = bearer(&ticket);
        let answer = k
            .call(MESSAGES, UnitRef::NONE, POINT_HEAD, original.clone())
            .unwrap();
        assert_eq!(
            answer.flow, FLOW_CONTINUE,
            "a checked ticket preempts an earlier rejecting plugin"
        );
        assert_eq!(earlier.calls(), 0);
        assert_eq!(
            k.inbound
                .admitted(answer.unit.id)
                .unwrap()
                .resolved
                .unwrap()
                .id,
            id
        );
        let mut changed = original.stripped(&answer.strips).unwrap();
        changed.target = OTHER.into();
        assert_eq!(
            k.hand_in(MESSAGES, MESSAGES, answer.unit, changed).0,
            FLOW_STOP
        );
        k.inbound.exit(answer.unit.id);
    }
    let original = bearer(&ticket);
    let answer = k
        .call(MESSAGES, UnitRef::NONE, POINT_HEAD, original.clone())
        .unwrap();
    assert_eq!(
        answer.flow, FLOW_CONTINUE,
        "abandoned and failed hand-ins did not spend the ticket"
    );
    let sanitized = original.stripped(&answer.strips).unwrap();
    assert_eq!(
        k.hand_in(MESSAGES, MESSAGES, answer.unit, sanitized.clone())
            .0,
        FLOW_CONTINUE
    );
    let receipt = k.inbound.claim_request(OWNER, 1, 1, &sanitized).unwrap();
    assert_eq!(
        through_final_gate(&k, receipt, &sanitized).await,
        (200, Some(b"ticket-record".to_vec()))
    );
    assert!(
        gov.admit_ticket("tk_", &ticket, now).is_none(),
        "the final gate spent exactly once"
    );
    assert_eq!(spend(&k, bearer(&ticket)).0, FLOW_STOP);
    assert_eq!(earlier.calls(), 0);
}

#[test]
fn ticket_preflight_checks_signature_expiry_standing_record_and_route_prefix() {
    let gov = signing_gov();
    let now = crate::store::now();
    let (id, key) = minted(&gov, now + 3600, now);
    let earlier = Script::new(
        AuthPoints::HEAD,
        identity("must-not-win", "wrong"),
        Vec::new(),
    );
    let k = ticket_kit(&gov, Arc::clone(&earlier));
    let (expired, _) = gov
        .mint_ticket(&id, "tk_", 1, None, b"record", now - 5)
        .unwrap();
    let relabeled_key = format!("tk_{}", key.strip_prefix("bbk_").unwrap());
    for invalid in ["tk_malformed", expired.as_str(), relabeled_key.as_str()] {
        assert_eq!(spend(&k, bearer(invalid)).0, FLOW_STOP);
        assert_eq!(
            earlier.calls(),
            0,
            "a matched-prefix failure cannot fall back to a plugin"
        );
    }
    let (ticket, _) = gov
        .mint_ticket(&id, "tk_", 600, None, b"record", now)
        .unwrap();
    gov.revoke(&id, "preflight").unwrap();
    assert_eq!(spend(&k, bearer(&ticket)).0, FLOW_STOP);
    assert_eq!(earlier.calls(), 0);
    let ordinary = Script::new(AuthPoints::HEAD, Verified::Pass, Vec::new());
    let fresh = signing_gov();
    let (id, token) = minted(&fresh, now + 3600, now);
    let k = ticket_kit(&fresh, Arc::clone(&ordinary));
    assert_eq!(
        spend(&k, bearer(&token)).0,
        FLOW_CONTINUE,
        "ordinary keys still work on ticket routes"
    );
    let (wrong_prefix, _) = fresh
        .mint_ticket(&id, "other_", 600, None, b"record", now)
        .unwrap();
    assert_eq!(spend(&k, bearer(&wrong_prefix)).0, FLOW_STOP);
    assert!(
        fresh.admit_ticket("other_", &wrong_prefix, now).is_some(),
        "the wrong route did not spend it"
    );
}

#[test]
fn the_inbound_verifier_receives_the_default_candidate_without_rewriting_lines() {
    for (configured_as, scheme, expected) in [
        (false, "Bearer", Some("candidate")),
        (false, "DPoP", None),
        (true, "DPoP", Some("candidate")),
    ] {
        let script = Script::new(
            AuthPoints::HEAD,
            identity("external-idp", "verified"),
            Vec::new(),
        );
        let mut app = crate::test_support::TestApp::new();
        if configured_as {
            app = app.oauth_as_plane(Arc::new(()));
        }
        let k = kit_over(
            app.build(),
            vec!["idp".into()],
            AuthPoints::HEAD,
            &[("idp", Arc::clone(&script))],
        );
        let head = post(
            MESSAGES,
            &[
                ("Authorization", &format!("{scheme} candidate")),
                ("x-safe", "unchanged"),
            ],
            None,
        );
        assert_eq!(spend(&k, head).0, FLOW_CONTINUE);
        let candidates = script.candidates.lock().unwrap();
        assert_eq!(
            candidates[0]
                .as_ref()
                .map(|c| c.expose(&crate::seal::lend()).as_slice()),
            expected.map(str::as_bytes)
        );
        assert_eq!(*script.lent.lock().unwrap(), ["authorization", "x-safe"]);
    }
}

#[test]
fn dpop_candidate_preflight_verifies_the_key_but_does_not_require_or_claim_a_proof() {
    let gov = signing_gov();
    let now = crate::store::now();
    let (_, token) = minted(&gov, now + 3600, now);
    for configured_as in [false, true] {
        let mut app = crate::test_support::TestApp::new()
            .keys_chain()
            .governance(Arc::clone(&gov));
        if configured_as {
            app = app.oauth_as_plane(Arc::new(()));
        }
        let k = kit_over(
            app.build(),
            vec![crate::config::KEYS_MODULE.into()],
            AuthPoints::HEAD,
            &[],
        );
        let head = post(
            MESSAGES,
            &[("Authorization", &format!("DPoP {token}"))],
            None,
        );
        assert_eq!(
            spend(&k, head).0,
            if configured_as {
                FLOW_CONTINUE
            } else {
                FLOW_STOP
            }
        );
        let invalid = post(
            MESSAGES,
            &[("Authorization", "DPoP bbk_not-a-signed-key")],
            None,
        );
        assert_eq!(
            spend(&k, invalid).0,
            FLOW_STOP,
            "extracting a candidate is never proof of identity"
        );
    }
}

#[test]
fn later_verifiers_and_keys_keep_the_original_candidate_after_declared_stripping() {
    let gov = signing_gov();
    let now = crate::store::now();
    let (_, token) = minted(&gov, now + 3600, now);
    for scheme in ["Bearer", "DPoP"] {
        let head_auth = Script::new(
            AuthPoints::HEAD,
            Verified::Pass,
            vec![Strip::field("authorization")],
        );
        let body_auth = Script::new(AuthPoints(POINT_HEAD_BODY), Verified::Pass, Vec::new());
        let app = crate::test_support::TestApp::new()
            .keys_chain()
            .governance(Arc::clone(&gov))
            .oauth_as_plane(Arc::new(()))
            .build();
        let k = kit_over(
            app,
            vec![
                "head".into(),
                "body".into(),
                crate::config::KEYS_MODULE.into(),
            ],
            AuthPoints(POINT_HEAD | POINT_HEAD_BODY),
            &[("head", head_auth), ("body", Arc::clone(&body_auth))],
        );
        let original = post(
            MESSAGES,
            &[("Authorization", &format!("{scheme} {token}"))],
            None,
        );
        let first = k
            .call(MESSAGES, UnitRef::NONE, POINT_HEAD, original.clone())
            .unwrap();
        let stripped = original.stripped(&first.strips).unwrap();
        let last = k
            .call(MESSAGES, first.unit, POINT_HEAD_BODY, stripped.clone())
            .unwrap();
        assert_eq!(last.flow, FLOW_CONTINUE);
        let candidates = body_auth.candidates.lock().unwrap();
        assert_eq!(
            candidates[0].as_ref().unwrap().expose(&crate::seal::lend()),
            token.as_bytes()
        );
        assert_eq!(
            k.hand_in(MESSAGES, MESSAGES, first.unit, stripped).0,
            FLOW_CONTINUE
        );
    }
}

#[test]
fn a_ticket_never_overrides_a_refused_connection() {
    let gov = signing_gov();
    let now = crate::store::now();
    let (id, _) = minted(&gov, now + 3600, now);
    let (ticket, _) = gov
        .mint_ticket(&id, "tk_", 600, None, b"record", now)
        .unwrap();
    let earlier = Script::new(AuthPoints(POINT_PEER), Verified::Reject, Vec::new());
    let k = ticket_kit(&gov, earlier);
    assert_eq!(
        k.call(MESSAGES, UnitRef::NONE, POINT_PEER, Head::default())
            .unwrap()
            .flow,
        FLOW_STOP
    );
    assert_eq!(spend(&k, bearer(&ticket)).0, FLOW_STOP);
    assert!(
        gov.admit_ticket("tk_", &ticket, now).is_some(),
        "a refused connection spent nothing"
    );
}

struct Answered(Option<VerifyAnswer>);

impl Future for Answered {
    type Output = VerifyAnswer;
    fn poll(
        mut self: Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<VerifyAnswer> {
        std::task::Poll::Ready(self.0.take().expect("polled once"))
    }
}

impl Verifying for Answered {
    fn settled(&mut self) -> Option<VerifyAnswer> {
        self.0.take()
    }
}

impl AuthCalls for Script {
    fn name(&self) -> &str {
        "script"
    }
    fn facts(&self) -> u32 {
        0
    }
    fn inbound_points(&self) -> AuthPoints {
        self.points
    }
    fn verify_now(&self, _: &VerifyRequest) -> Option<VerifyAnswer> {
        None
    }
    fn verify(&self, request: VerifyRequest) -> Box<dyn Verifying> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.candidates
            .lock()
            .unwrap()
            .push(request.credential.clone());
        self.lent
            .lock()
            .unwrap()
            .extend(request.lines.iter().map(|(n, _)| n.clone()));
        Box::new(Answered(Some(self.answer.clone())))
    }
    fn refresh(&self) -> Result<u64, String> {
        Ok(0)
    }
}

fn test_mac(t: &UnitTag) -> Option<u64> {
    let mut h: u64 = 0x9e37_79b9_7f4a_7c15;
    for v in [
        t.secret[0],
        t.secret[1],
        t.generation,
        t.owner,
        u64::from(t.line),
        t.unit,
    ] {
        h = (h ^ v).wrapping_mul(0x0100_0000_01b3).rotate_left(29);
    }
    Some(h)
}

struct Kit {
    inbound: Arc<Inbound>,
    refused: Arc<Mutex<Vec<RefusedUnit>>>,
    app: Arc<App>,
}

const OWNER: u64 = 7;
const GEN: u64 = 3;
const MESSAGES: &str = "/v1/messages";
const OTHER: &str = "/v1/other";
const HEALTHZ: &str = "/healthz";

fn line(path: &str, methods: u32, auth: LineAuth) -> Line {
    Line {
        route: Route {
            methods,
            path_form: PATH_EXACT,
            path: path.to_string(),
            fields: Vec::new(),
            rung: 0,
        },
        claimant: Claimant::Plane("plane".to_string()),
        dialect: 0,
        auth,
        upgrade: None,
        offered: AuthPoints(POINT_PEER | POINT_HEAD | POINT_HEAD_BODY),
    }
}

fn kit(auths: &[(&str, Arc<Script>)]) -> Kit {
    let names: Vec<String> = auths.iter().map(|(n, _)| (*n).to_string()).collect();
    let points = AuthPoints(auths.iter().fold(0, |p, (_, s)| p | s.points.bits()));
    kit_over(
        crate::test_support::TestApp::new().build(),
        names,
        points,
        auths,
    )
}

fn kit_over(
    app: Arc<App>,
    names: Vec<String>,
    points: AuthPoints,
    auths: &[(&str, Arc<Script>)],
) -> Kit {
    kit_signed(app, names, points, auths, kin_unsigned())
}

fn kin_unsigned() -> SignedIngress {
    Arc::new(|_: &App, _: &str| false)
}

fn kit_signed(
    app: Arc<App>,
    names: Vec<String>,
    points: AuthPoints,
    auths: &[(&str, Arc<Script>)],
    signed: SignedIngress,
) -> Kit {
    let chain = LineAuth::Chain(names, points);
    let guests = GuestList::seal(vec![
        line(MESSAGES, METHOD_POST, chain.clone()),
        line(OTHER, METHOD_POST, chain),
        line(HEALTHZ, METHOD_GET, LineAuth::None),
    ])
    .expect("the list seals");
    let next = Arc::new(AtomicU64::new(100));
    let refused: Arc<Mutex<Vec<RefusedUnit>>> = Arc::default();
    let sink = Arc::clone(&refused);
    let inbound = Inbound::new(
        Seals {
            mint: Arc::new(move || next.fetch_add(1, Ordering::SeqCst)),
            mac: Arc::new(test_mac),
        },
        Arc::new(|f: Pin<Box<dyn Future<Output = ()> + Send>>| {
            std::thread::spawn(move || futures::executor::block_on(f));
        }),
        Arc::new(move |r: &RefusedUnit| sink.lock().unwrap().push(*r)),
    );
    let listener = || Listener {
        guests: guests.clone(),
        auths: auths
            .iter()
            .map(|(n, s)| ((*n).to_string(), Arc::clone(s) as Arc<dyn AuthCalls>))
            .collect(),
        body_limit: 16,
        app: Arc::clone(&app),
        door_refusals: Vec::new(),
        ids: line_ids(3),
        signed_ingress: signed.clone(),
        scope: None,
    };
    inbound.install(OWNER, GEN, listener()).expect("installed");

    inbound
        .install(OWNER + 1, GEN, listener())
        .expect("installed");
    Kit {
        inbound,
        refused,
        app,
    }
}

fn line_ids(n: u64) -> Vec<u64> {
    (0..n).map(|i| 7_000 + 13 * i).collect()
}

impl Kit {
    fn id(&self, path: &str) -> u64 {
        self.inbound.specs(OWNER, GEN).expect("installed")[self.line(path) as usize].auth
    }

    fn line(&self, path: &str) -> u32 {
        self.inbound
            .table(OWNER, GEN)
            .expect("installed")
            .listener
            .guests
            .lines()
            .iter()
            .position(|l| l.route.path == path)
            .expect("on the list") as u32
    }

    fn call(
        &self,
        path: &str,
        unit: UnitRef,
        point: u32,
        head: Head,
    ) -> Result<Answer, &'static str> {
        self.call_as(OWNER, path, unit, point, head)
    }

    fn call_as(
        &self,
        owner: u64,
        path: &str,
        unit: UnitRef,
        point: u32,
        head: Head,
    ) -> Result<Answer, &'static str> {
        let body = (point == POINT_HEAD_BODY).then(|| b"{}".to_vec());
        self.inbound
            .auth_call(
                Call {
                    owner,
                    generation: GEN,
                    auth: self.id(path),
                    unit,
                    point,
                    conn: 1,
                    stream: 1,
                    framing: 1,
                    head,
                    body,
                    deadline: None,
                },
                Box::new(|_: Result<Answer, &'static str>| {
                    panic!("every scripted verify answers at once")
                }),
            )
            .expect("answered at once")
    }

    fn call_on(
        &self,
        conn: u64,
        path: &str,
        unit: UnitRef,
        point: u32,
        head: Head,
        deadline: Option<std::time::Instant>,
    ) -> Result<Answer, &'static str> {
        self.inbound
            .auth_call(
                Call {
                    owner: OWNER,
                    generation: GEN,
                    auth: self.id(path),
                    unit,
                    point,
                    conn,
                    stream: 1,
                    framing: conn,
                    head,
                    body: None,
                    deadline,
                },
                Box::new(|_: Result<Answer, &'static str>| {
                    panic!("every scripted verify answers at once")
                }),
            )
            .expect("answered at once")
    }

    fn hand_in_on(&self, conn: u64, path: &str, unit: UnitRef, head: Head) -> (u32, UnitRef) {
        self.inbound
            .hand_in(HandIn {
                owner: OWNER,
                generation: GEN,
                auth: self.id(path),
                unit,
                line: self.line(path),
                conn,
                stream: 1,
                framing: Some(conn),
                head,
            })
            .expect("handed in")
    }

    fn hand_in(&self, path: &str, line_path: &str, unit: UnitRef, head: Head) -> (u32, UnitRef) {
        self.inbound
            .hand_in(HandIn {
                owner: OWNER,
                generation: GEN,
                auth: self.id(path),
                unit,
                line: self.line(line_path),
                conn: 1,
                stream: 1,
                framing: Some(1),
                head,
            })
            .expect("handed in")
    }

    fn refuse(&self, cause: u32, line: u32, unit: UnitRef, target: &str) -> Refusal {
        self.inbound
            .refuse(Refuse {
                owner: OWNER,
                generation: GEN,
                unit,
                cause,
                line,
                request: Some(post(target, &[], None)),
                conn: 1,
                stream: 1,
                framing: Some(1),
            })
            .expect("refused")
    }
}

fn post(path: &str, fields: &[(&str, &str)], query: Option<&str>) -> Head {
    Head {
        method: "POST".to_string(),
        target: path.to_string(),
        authority: "a.example".to_string(),
        query: query.map(str::to_string),
        fields: fields
            .iter()
            .map(|(n, v)| ((*n).to_string(), v.as_bytes().to_vec()))
            .collect(),
    }
}

fn identity(subject: &str, credential: &str) -> Verified {
    Verified::Identity(VerifiedIdentity {
        subject: subject.to_string(),
        credential: Some(Secret::new(credential.to_string())),
        ..VerifiedIdentity::default()
    })
}

#[test]
fn only_the_successful_unchanged_hand_in_can_be_claimed_once() {
    let script = Script::new(
        AuthPoints::HEAD,
        identity("caller", "credential"),
        vec![Strip::field("authorization".to_string())],
    );
    let k = kit(&[("a", Arc::clone(&script))]);
    let listener = k.inbound.table(OWNER, GEN).unwrap().listener.clone();
    k.inbound.install_at(OWNER, 71, GEN, listener).unwrap();
    k.inbound.framing_started(OWNER, 71, 1, GEN).unwrap();
    k.inbound.grant_stream(OWNER, 1, 1, GEN).unwrap();
    let original = post(
        MESSAGES,
        &[("Authorization", "credential"), ("X-Trace", "one")],
        Some("a=1"),
    );
    let answer = k
        .call(MESSAGES, UnitRef::NONE, POINT_HEAD, original.clone())
        .unwrap();
    assert_eq!(answer.flow, FLOW_CONTINUE);
    assert!(k.inbound.claim_request(OWNER, 1, 1, &original).is_err());
    assert_eq!(
        k.hand_in(MESSAGES, MESSAGES, answer.unit, original).0,
        FLOW_STOP,
        "an unstripped credential refuses hand-in"
    );
    let sanitized = post(MESSAGES, &[("x-trace", "one")], Some("a=1"));
    assert!(k.inbound.claim_request(OWNER, 1, 1, &sanitized).is_err());
    let changed_field = post(MESSAGES, &[("x-trace", "changed")], Some("a=1"));
    assert_eq!(
        k.hand_in(MESSAGES, MESSAGES, answer.unit, changed_field).0,
        FLOW_STOP,
        "hand-in cannot change an authenticated non-credential field"
    );
    let changed_query = post(MESSAGES, &[("x-trace", "one")], Some("a=2"));
    assert_eq!(
        k.hand_in(MESSAGES, MESSAGES, answer.unit, changed_query).0,
        FLOW_STOP,
        "hand-in cannot change an authenticated query"
    );
    assert_eq!(
        k.hand_in(MESSAGES, MESSAGES, answer.unit, sanitized.clone())
            .0,
        FLOW_CONTINUE
    );
    assert!(k
        .inbound
        .claim_request(OWNER + 1, 1, 1, &sanitized)
        .is_err());
    assert!(k.inbound.claim_request(OWNER, 1, 2, &sanitized).is_err());
    let changed = post(OTHER, &[("x-trace", "one")], Some("a=1"));
    assert!(k.inbound.claim_request(OWNER, 1, 1, &changed).is_err());
    let emitted = post(MESSAGES, &[("X-TRACE", "one")], Some("a=1"));
    let admission = k
        .inbound
        .claim_request(OWNER, 1, 1, &emitted)
        .expect("the unchanged request claims its successful hand-in");
    assert!(Arc::ptr_eq(&admission.app(), &k.app));
    assert!(matches!(
        admission.verdict(),
        crate::auth::ChainVerdict::Identified { principal, .. } if principal.id == "caller"
    ));
    assert!(k.inbound.claim_request(OWNER, 1, 1, &emitted).is_err());
    assert_eq!(script.calls(), 1, "claiming does not re-run the verifier");
    k.inbound.stream_ended(OWNER, 1, 1);
    assert!(k.inbound.unit_secret(OWNER, answer.unit.id).is_none());
    assert!(k.inbound.grant_stream(OWNER, 1, 1, GEN).is_err());
    assert!(Arc::ptr_eq(&admission.app(), &k.app));
    assert!(!futures::executor::block_on(admission.claim_replay()));
}

#[test]
fn a_claimed_body_limit_keeps_its_listener_generation_across_reload() {
    for limit in [0, 7] {
        let script = Script::new(AuthPoints::HEAD, Verified::Reject, Vec::new());
        let k = kit(&[("a", script)]);
        let mut listener = k.inbound.table(OWNER, GEN).unwrap().listener.clone();
        listener.body_limit = limit;
        k.inbound
            .install_at(OWNER, 71, GEN, listener.clone())
            .unwrap();
        k.inbound.framing_started(OWNER, 71, 1, GEN).unwrap();
        k.inbound.grant_stream(OWNER, 1, 1, GEN).unwrap();
        let mut head = post(HEALTHZ, &[], None);
        head.method = "GET".into();
        assert_eq!(
            k.hand_in(HEALTHZ, HEALTHZ, UnitRef::NONE, head.clone()).0,
            FLOW_CONTINUE
        );
        let admitted = k.inbound.claim_request(OWNER, 1, 1, &head).unwrap();
        listener.body_limit = 19;
        k.inbound.install_at(OWNER, 71, GEN + 1, listener).unwrap();
        assert_eq!(
            admitted.body_limit(),
            limit,
            "the live replacement cannot change an admitted body, including zero"
        );
    }
}

#[test]
fn an_active_unit_keeps_its_policy_after_three_reloads_without_reopening_the_old_list() {
    let a = Script::new(
        AuthPoints::HEAD,
        identity("original", "credential"),
        Vec::new(),
    );
    let k = kit(&[("a", a)]);
    let auth = k.id(MESSAGES);
    let line = k.line(MESSAGES);
    let first = k
        .call(
            MESSAGES,
            UnitRef::NONE,
            POINT_HEAD,
            post(MESSAGES, &[], None),
        )
        .expect("the original policy admits the request");
    let old_app = Arc::downgrade(&k.app);
    let guests = k.inbound.table(OWNER, GEN).unwrap().listener.guests.clone();
    let replacement = crate::test_support::TestApp::new().build();
    for generation in GEN + 1..=GEN + 3 {
        for owner in [OWNER, OWNER + 1] {
            k.inbound
                .install(
                    owner,
                    generation,
                    Listener {
                        guests: guests.clone(),
                        auths: HashMap::new(),
                        body_limit: 16,
                        app: Arc::clone(&replacement),
                        door_refusals: Vec::new(),
                        ids: line_ids(3),
                        signed_ingress: kin_unsigned(),
                        scope: None,
                    },
                )
                .expect("the replacement is published");
        }
    }
    let Kit { inbound, app, .. } = k;
    drop(app);
    let pinned = old_app.upgrade().is_some();
    let call = |unit| Call {
        owner: OWNER,
        generation: GEN,
        auth,
        unit,
        point: POINT_HEAD,
        conn: 1,
        stream: 1,
        framing: 1,
        head: post(MESSAGES, &[], None),
        body: None,
        deadline: None,
    };
    let complete =
        || Box::new(|_: Result<Answer, &'static str>| panic!("settled verification")) as Done;
    let continuation = inbound.auth_call(call(first.unit), complete());
    let hand_in = inbound.hand_in(HandIn {
        owner: OWNER,
        generation: GEN,
        auth,
        unit: first.unit,
        line,
        conn: 1,
        stream: 1,
        framing: Some(1),
        head: post(MESSAGES, &[], None),
    });
    let stale_open = inbound.auth_call(call(UnitRef::NONE), complete());
    let mut foreign = call(first.unit);
    foreign.stream = 2;
    let foreign = inbound.auth_call(foreign, complete());
    let forged = inbound.auth_call(
        call(UnitRef {
            mac: first.unit.mac ^ 1,
            ..first.unit
        }),
        complete(),
    );
    inbound.exit(first.unit.id);
    let released = old_app.upgrade().is_none();

    assert!(pinned, "the active request retains its original App");
    assert_eq!(continuation.unwrap().unwrap().unit, first.unit);
    assert_eq!(hand_in, Ok((FLOW_CONTINUE, first.unit)));
    assert!(
        matches!(stale_open, Some(Err(NO_LIST))),
        "no new request may reopen an expired list"
    );
    assert!(
        matches!(foreign, Some(Err(_))),
        "the pin grants no other stream authority"
    );
    assert!(
        matches!(forged, Some(Err(_))),
        "a pinned table does not authenticate a forged unit"
    );
    assert!(released, "unit exit releases the last old-policy reference");
}

fn transfer_request() -> (Kit, UnitRef, RequestAdmission, Arc<Script>) {
    let script = Script::new(
        AuthPoints::HEAD,
        identity("session-caller", "credential"),
        Vec::new(),
    );
    let k = kit(&[("a", Arc::clone(&script))]);
    let listener = k.inbound.table(OWNER, GEN).unwrap().listener.clone();
    k.inbound.install_at(OWNER, 71, GEN, listener).unwrap();
    k.inbound.framing_started(OWNER, 71, 1, GEN).unwrap();
    k.inbound.grant_stream(OWNER, 1, 1, GEN).unwrap();
    let head = post(MESSAGES, &[], None);
    let unit = k
        .call(MESSAGES, UnitRef::NONE, POINT_HEAD, head.clone())
        .unwrap()
        .unit;
    assert_eq!(
        k.hand_in(MESSAGES, MESSAGES, unit, head.clone()).0,
        FLOW_CONTINUE
    );
    let admission = k.inbound.claim_request(OWNER, 1, 1, &head).unwrap();
    (k, unit, admission, script)
}

fn transfer_source() -> busbar_contract::framing_scope::AdoptionSource {
    busbar_contract::framing_scope::AdoptionSource {
        owner: OWNER,
        listener: 71,
        leg: 1,
        conn: 1,
    }
}

#[test]
fn an_adopted_session_moves_owner_token_and_mac_without_reauthenticating_or_changing_app() {
    for destination_owner in [OWNER, OWNER + 90] {
        let (k, old, admission, script) = transfer_request();
        let auth = k.id(MESSAGES);
        let line = k.line(MESSAGES);
        let old_secret = k.inbound.unit_secret(OWNER, old.id).unwrap().0;
        assert!(futures::executor::block_on(admission.claim_replay()));
        k.inbound.framing_detached(OWNER, 1).unwrap();
        let staged = k
            .inbound
            .framing_adopting(transfer_source(), destination_owner, 19)
            .unwrap();
        assert_eq!(staged.session.unit.id, old.id);
        assert_eq!(staged.session.stream, 1);
        assert_eq!(staged.generation, GEN);
        assert!(k.inbound.unit_secret(OWNER, old.id).is_none());
        assert!(
            k.inbound.unit_secret(destination_owner, old.id).is_none(),
            "staging grants no service authority"
        );
        assert!(k
            .inbound
            .grant_stream(destination_owner, 19, 2, GEN)
            .is_err());
        let binding = RequestBinding {
            conn: 803,
            stream: 1,
            framing: Some(19),
        };
        assert!(!k.inbound.verified(
            destination_owner,
            Some(GEN),
            Some(line),
            binding,
            staged.session.unit
        ));
        let mut replacement = k.inbound.table(OWNER, GEN).unwrap().listener.clone();
        replacement.app = crate::test_support::TestApp::new().build();
        for generation in GEN + 1..=GEN + 3 {
            k.inbound
                .install_at(OWNER, 71, generation, replacement.clone())
                .unwrap();
        }
        k.inbound
            .framing_adopted(destination_owner, 19, 803)
            .unwrap();
        assert_ne!(
            k.inbound.unit_secret(destination_owner, old.id).unwrap().0,
            old_secret
        );
        assert!(!k
            .inbound
            .verified(destination_owner, Some(GEN), Some(line), binding, old));
        assert!(k.inbound.verified(
            destination_owner,
            Some(GEN),
            Some(line),
            binding,
            staged.session.unit
        ));
        for foreign in [
            RequestBinding { conn: 1, ..binding },
            RequestBinding {
                stream: 2,
                ..binding
            },
            RequestBinding {
                framing: Some(1),
                ..binding
            },
        ] {
            assert!(!k.inbound.verified(
                destination_owner,
                Some(GEN),
                Some(line),
                foreign,
                staged.session.unit
            ));
        }
        assert!(!k.inbound.verified(
            destination_owner + 1,
            Some(GEN),
            Some(line),
            binding,
            staged.session.unit
        ));
        k.inbound.stream_ended(OWNER, 1, 1);
        k.inbound.framing_ended(1);
        assert!(k.inbound.verified(
            destination_owner,
            Some(GEN),
            Some(line),
            binding,
            staged.session.unit
        ));
        let continuation = k
            .inbound
            .auth_call(
                Call {
                    owner: destination_owner,
                    generation: GEN,
                    auth,
                    unit: staged.session.unit,
                    point: POINT_HEAD,
                    conn: 803,
                    stream: 1,
                    framing: 19,
                    head: post(MESSAGES, &[], None),
                    body: None,
                    deadline: None,
                },
                Box::new(|_| panic!("an existing verdict does not pend")),
            )
            .unwrap()
            .unwrap();
        assert_eq!(continuation.flow, FLOW_CONTINUE);
        assert_eq!(script.calls(), 1);
        assert!(Arc::ptr_eq(&admission.app(), &k.app));
        assert!(futures::executor::block_on(admission.claim_replay()));
        assert_eq!(
            k.inbound
                .with_credential(old.id, |c| c.expose(&crate::seal::lend()).clone()),
            Some("credential".to_string())
        );
        k.inbound.framing_ended(19);
        assert!(k.inbound.unit_secret(destination_owner, old.id).is_none());
        assert!(!futures::executor::block_on(admission.claim_replay()));
    }
}

#[test]
fn an_abandoned_session_transfer_retires_its_credential_and_cannot_commit_late() {
    for ended in [1, 19] {
        let (k, old, admission, _) = transfer_request();
        k.inbound.framing_detached(OWNER, 1).unwrap();
        let moved = k
            .inbound
            .framing_adopting(transfer_source(), OWNER + 90, 19)
            .unwrap();
        k.inbound.framing_ended(ended);
        assert!(k.inbound.framing_adopted(OWNER + 90, 19, 803).is_err());
        assert!(k.inbound.unit_secret(OWNER, old.id).is_none());
        assert!(k
            .inbound
            .unit_secret(OWNER + 90, moved.session.unit.id)
            .is_none());
        assert!(k.inbound.with_credential(old.id, |_| ()).is_none());
        assert!(!futures::executor::block_on(admission.claim_replay()));
        k.inbound.framing_ended(1);
        k.inbound.framing_ended(19);
    }
}

#[test]
fn transfer_requires_the_live_claimed_hand_in_on_the_exact_detached_source() {
    let (k, old, _, _) = transfer_request();
    assert!(
        k.inbound
            .framing_adopting(transfer_source(), OWNER + 90, 19)
            .is_err(),
        "a live source has not detached"
    );
    k.inbound.framing_detached(OWNER, 1).unwrap();
    for source in [
        busbar_contract::framing_scope::AdoptionSource {
            owner: OWNER + 1,
            ..transfer_source()
        },
        busbar_contract::framing_scope::AdoptionSource {
            listener: 72,
            ..transfer_source()
        },
        busbar_contract::framing_scope::AdoptionSource {
            leg: 2,
            ..transfer_source()
        },
        busbar_contract::framing_scope::AdoptionSource {
            conn: 2,
            ..transfer_source()
        },
    ] {
        assert!(k.inbound.framing_adopting(source, OWNER + 90, 19).is_err());
    }
    assert!(k.inbound.unit_secret(OWNER, old.id).is_some());
    k.inbound.stream_ended(OWNER, 1, 1);
    assert!(k
        .inbound
        .framing_adopting(transfer_source(), OWNER + 90, 19)
        .is_err());

    let script = Script::new(
        AuthPoints::HEAD,
        identity("caller", "credential"),
        Vec::new(),
    );
    let k = kit(&[("a", script)]);
    let listener = k.inbound.table(OWNER, GEN).unwrap().listener.clone();
    k.inbound.install_at(OWNER, 71, GEN, listener).unwrap();
    k.inbound.framing_started(OWNER, 71, 1, GEN).unwrap();
    k.inbound.grant_stream(OWNER, 1, 1, GEN).unwrap();
    let head = post(MESSAGES, &[], None);
    let unit = k
        .call(MESSAGES, UnitRef::NONE, POINT_HEAD, head.clone())
        .unwrap()
        .unit;
    assert_eq!(k.hand_in(MESSAGES, MESSAGES, unit, head).0, FLOW_CONTINUE);
    k.inbound.framing_detached(OWNER, 1).unwrap();
    assert!(
        k.inbound
            .framing_adopting(transfer_source(), OWNER + 90, 19)
            .is_err(),
        "a plugin hand-in alone is not the host's claimed admission"
    );
}

#[test]
fn two_claimed_requests_cannot_be_guessed_into_one_session_transfer() {
    let (k, first, _admission, _) = transfer_request();
    k.inbound.grant_stream(OWNER, 1, 2, GEN).unwrap();
    let head = post(MESSAGES, &[], None);
    let second = k
        .inbound
        .auth_call(
            Call {
                owner: OWNER,
                generation: GEN,
                auth: k.id(MESSAGES),
                unit: UnitRef::NONE,
                point: POINT_HEAD,
                conn: 1,
                stream: 2,
                framing: 1,
                head: head.clone(),
                body: None,
                deadline: None,
            },
            Box::new(|_| panic!("script answers immediately")),
        )
        .unwrap()
        .unwrap()
        .unit;
    assert_eq!(
        k.inbound
            .hand_in(HandIn {
                owner: OWNER,
                generation: GEN,
                auth: k.id(MESSAGES),
                unit: second,
                line: k.line(MESSAGES),
                conn: 1,
                stream: 2,
                framing: Some(1),
                head: head.clone(),
            })
            .unwrap()
            .0,
        FLOW_CONTINUE
    );
    let _second_admission = k.inbound.claim_request(OWNER, 1, 2, &head).unwrap();
    k.inbound.framing_detached(OWNER, 1).unwrap();
    assert!(k
        .inbound
        .framing_adopting(transfer_source(), OWNER + 90, 19)
        .is_err());
    assert!(k.inbound.unit_secret(OWNER, first.id).is_some());
    assert!(k.inbound.unit_secret(OWNER, second.id).is_some());
    k.inbound.framing_ended(1);
    assert!(k.inbound.unit_secret(OWNER, first.id).is_none());
    assert!(k.inbound.unit_secret(OWNER, second.id).is_none());
}

fn names() -> Vec<Strip> {
    vec![Strip::field("authorization"), Strip::query("key")]
}

#[test]
fn red_the_first_auth_call_mints_the_unit_and_a_subsequent_call_must_present_it() {
    let a = Script::new(AuthPoints::HEAD, identity("alice", "sk-1"), names());
    let k = kit(&[("a", a)]);
    let first = k
        .call(
            MESSAGES,
            UnitRef::NONE,
            POINT_HEAD,
            post(MESSAGES, &[], None),
        )
        .expect("answered");
    assert!(!first.unit.is_none(), "no unit was minted");
    let (secret, generation, line) = k
        .inbound
        .unit_secret(OWNER, first.unit.id)
        .expect("the kernel holds the unit");
    assert_eq!((generation, line), (GEN, k.line(MESSAGES)));
    assert_eq!(
        test_mac(&UnitTag {
            secret,
            generation: GEN,
            owner: OWNER,
            line,
            unit: first.unit.id,
        }),
        Some(first.unit.mac),
        "the unit's mac is not over its own request's tag"
    );
    let again = k
        .call(MESSAGES, first.unit, POINT_HEAD, post(MESSAGES, &[], None))
        .expect("a subsequent call presents the unit");
    assert_eq!(again.unit, first.unit);
    let forged = UnitRef {
        mac: first.unit.mac ^ 1,
        ..first.unit
    };
    assert_eq!(
        k.call(MESSAGES, forged, POINT_HEAD, post(MESSAGES, &[], None)),
        Err(UNIT_FOREIGN)
    );
    assert_eq!(
        k.call_as(
            OWNER + 1,
            MESSAGES,
            first.unit,
            POINT_HEAD,
            post(MESSAGES, &[], None)
        ),
        Err(UNIT_FOREIGN),
        "another owner presented the unit"
    );
    assert_eq!(
        k.call(OTHER, first.unit, POINT_HEAD, post(OTHER, &[], None)),
        Err(UNIT_FOREIGN),
        "the unit was presented on another line"
    );
    let other = k
        .call(
            MESSAGES,
            UnitRef::NONE,
            POINT_HEAD,
            post(MESSAGES, &[], None),
        )
        .expect("another request");
    assert_ne!(other.unit.id, first.unit.id, "two requests share a unit");
}

#[test]
fn red_the_verdict_is_first_hand_and_never_in_the_transports_answer() {
    let a = Script::new(AuthPoints::HEAD, identity("alice", "sk-live-123"), names());
    let k = kit(&[("a", Arc::clone(&a))]);
    let answer = k
        .call(
            MESSAGES,
            UnitRef::NONE,
            POINT_HEAD,
            post(
                MESSAGES,
                &[("Authorization", "Bearer sk-live-123")],
                Some("key=sk-live-123"),
            ),
        )
        .expect("answered");
    assert_eq!(answer.flow, FLOW_CONTINUE);
    assert_eq!(answer.strips, names());
    let shown = format!("{answer:?}");
    assert!(
        !shown.contains("alice"),
        "the verdict reached the transport: {shown}"
    );
    assert!(
        !shown.contains("sk-live"),
        "the credential reached the transport: {shown}"
    );
    let admitted = k
        .inbound
        .admitted(answer.unit.id)
        .expect("admitted first-hand");
    assert_eq!(admitted.provider, "a");
    assert_eq!(admitted.identity.subject, "alice");
    assert!(
        admitted.identity.credential.is_none(),
        "the credential stayed in the identity"
    );
    assert_eq!(
        k.inbound
            .with_credential(answer.unit.id, |c| c.expose(&crate::seal::lend()).clone()),
        Some("sk-live-123".to_string())
    );
    assert_eq!(
        k.inbound
            .with_credential(answer.unit.id, |c| format!("{c:?}")),
        Some("[REDACTED]".to_string())
    );
    assert_eq!(a.lent.lock().unwrap().as_slice(), ["authorization"]);
    k.inbound.exit(answer.unit.id);
    assert!(k.inbound.with_credential(answer.unit.id, |_| ()).is_none());
    assert!(k.inbound.admitted(answer.unit.id).is_none());
}

#[test]
fn red_the_chain_rule_holds_in_list_order() {
    let head = || post(MESSAGES, &[], None);

    let (a, b) = (
        Script::new(AuthPoints::HEAD, Verified::Pass, Vec::new()),
        Script::new(AuthPoints::HEAD, identity("bob", "k"), Vec::new()),
    );
    let k = kit(&[("a", Arc::clone(&a)), ("b", Arc::clone(&b))]);
    let ans = k.call(MESSAGES, UnitRef::NONE, POINT_HEAD, head()).unwrap();
    assert_eq!(ans.flow, FLOW_CONTINUE);
    assert_eq!(k.inbound.admitted(ans.unit.id).unwrap().provider, "b");
    assert_eq!((a.calls(), b.calls()), (1, 1));

    let (a, b) = (
        Script::new(AuthPoints::HEAD, Verified::Reject, Vec::new()),
        Script::new(AuthPoints::HEAD, identity("bob", "k"), Vec::new()),
    );
    let k = kit(&[("a", Arc::clone(&a)), ("b", Arc::clone(&b))]);
    let ans = k.call(MESSAGES, UnitRef::NONE, POINT_HEAD, head()).unwrap();
    assert_eq!(ans.flow, FLOW_STOP);
    assert_eq!(b.calls(), 0, "a reject did not stop the chain");
    assert!(k.inbound.admitted(ans.unit.id).is_none());

    let a = Script::new(AuthPoints::HEAD, Verified::Failed, Vec::new());
    let k = kit(&[("a", a)]);
    assert_eq!(
        k.call(MESSAGES, UnitRef::NONE, POINT_HEAD, head())
            .unwrap()
            .flow,
        FLOW_STOP
    );

    let (a, b) = (
        Script::new(AuthPoints::HEAD, Verified::Pass, Vec::new()),
        Script::new(AuthPoints::HEAD, Verified::Pass, Vec::new()),
    );
    let k = kit(&[("a", a), ("b", b)]);
    assert_eq!(
        k.call(MESSAGES, UnitRef::NONE, POINT_HEAD, head())
            .unwrap()
            .flow,
        FLOW_STOP
    );

    let a = Script::new(AuthPoints::HEAD, Verified::Overloaded, Vec::new());
    let k = kit(&[("a", a)]);
    let ans = k.call(MESSAGES, UnitRef::NONE, POINT_HEAD, head()).unwrap();
    assert_eq!(ans.flow, FLOW_STOP);
    let refusal = k.refuse(REFUSE_STOPPED, k.line(MESSAGES), ans.unit, MESSAGES);
    assert_eq!(
        refusal,
        Refusal::of(crate::auth::verifier_unavailable_response())
    );
    assert_eq!(refusal.status, 503);
}

#[test]
fn red_the_verdict_is_fixed_in_list_order_across_points() {
    let (a, b) = (
        Script::new(AuthPoints::HEAD_BODY, Verified::Pass, Vec::new()),
        Script::new(AuthPoints::HEAD, identity("bob", "k"), Vec::new()),
    );
    let k = kit(&[("a", Arc::clone(&a)), ("b", Arc::clone(&b))]);
    let at_head = k
        .call(
            MESSAGES,
            UnitRef::NONE,
            POINT_HEAD,
            post(MESSAGES, &[], None),
        )
        .unwrap();
    assert_eq!((a.calls(), b.calls()), (0, 1));
    assert_eq!(at_head.flow, FLOW_CONTINUE);
    assert!(
        k.inbound.admitted(at_head.unit.id).is_none(),
        "fixed before list order allowed"
    );
    let at_body = k
        .call(
            MESSAGES,
            at_head.unit,
            POINT_HEAD_BODY,
            post(MESSAGES, &[], None),
        )
        .unwrap();
    assert_eq!((a.calls(), b.calls()), (1, 1), "an auth was called twice");
    assert_eq!(at_body.flow, FLOW_CONTINUE);
    assert_eq!(k.inbound.admitted(at_head.unit.id).unwrap().provider, "b");
}

#[test]
fn red_hand_in_stops_a_line_that_is_not_the_lists_match() {
    let a = Script::new(AuthPoints::HEAD, identity("alice", "k"), Vec::new());
    let k = kit(&[("a", a)]);
    let ans = k
        .call(
            MESSAGES,
            UnitRef::NONE,
            POINT_HEAD,
            post(MESSAGES, &[], None),
        )
        .unwrap();
    assert_eq!(
        k.hand_in(MESSAGES, MESSAGES, ans.unit, post(MESSAGES, &[], None))
            .0,
        FLOW_CONTINUE,
        "the matched line, admitted, was stopped"
    );

    assert_eq!(
        k.hand_in(OTHER, MESSAGES, ans.unit, post(MESSAGES, &[], None))
            .0,
        FLOW_STOP
    );

    assert_eq!(
        k.hand_in(MESSAGES, MESSAGES, ans.unit, post(OTHER, &[], None))
            .0,
        FLOW_STOP
    );

    let mut get = post(MESSAGES, &[], None);
    get.method = "GET".to_string();
    assert_eq!(k.hand_in(MESSAGES, MESSAGES, ans.unit, get).0, FLOW_STOP);
}

#[test]
fn red_hand_in_stops_an_auth_line_with_no_verdict() {
    let a = Script::new(AuthPoints::HEAD, Verified::Reject, Vec::new());
    let k = kit(&[("a", a)]);
    let (flow, unit) = k.hand_in(MESSAGES, MESSAGES, UnitRef::NONE, post(MESSAGES, &[], None));
    assert_eq!(flow, FLOW_STOP);
    assert!(!unit.is_none(), "the stop names no unit");
    let ans = k
        .call(
            MESSAGES,
            UnitRef::NONE,
            POINT_HEAD,
            post(MESSAGES, &[], None),
        )
        .unwrap();
    assert_eq!(
        k.hand_in(MESSAGES, MESSAGES, ans.unit, post(MESSAGES, &[], None)),
        (FLOW_STOP, ans.unit)
    );
}

#[test]
fn red_hand_in_stops_while_a_named_line_is_still_present() {
    let a = Script::new(AuthPoints::HEAD, identity("alice", "k"), names());
    let k = kit(&[("a", a)]);
    for (head, expected) in [
        (post(MESSAGES, &[("Authorization", "x")], None), FLOW_STOP),
        (post(MESSAGES, &[], Some("a=1&key=x")), FLOW_STOP),
        (post(MESSAGES, &[], Some("Key=x&keys=1")), FLOW_CONTINUE),
        (
            post(MESSAGES, &[("x-other", "1")], Some("a=1")),
            FLOW_CONTINUE,
        ),
    ] {
        let ans = k
            .call(MESSAGES, UnitRef::NONE, POINT_HEAD, head.clone())
            .unwrap();
        assert_eq!(k.hand_in(MESSAGES, MESSAGES, ans.unit, head).0, expected);
    }
}

#[test]
fn red_a_none_line_mints_its_unit_at_hand_in() {
    let a = Script::new(AuthPoints::HEAD, Verified::Reject, Vec::new());
    let k = kit(&[("a", Arc::clone(&a))]);
    let mut get = post(HEALTHZ, &[], None);
    get.method = "GET".to_string();
    let (flow, unit) = k.hand_in(HEALTHZ, HEALTHZ, UnitRef::NONE, get);
    assert_eq!(flow, FLOW_CONTINUE);
    assert!(!unit.is_none(), "no unit was minted");
    assert_eq!(
        k.inbound.unit_secret(OWNER, unit.id).map(|(_, _, l)| l),
        Some(k.line(HEALTHZ))
    );
    assert_eq!(a.calls(), 0);
    assert_eq!(
        k.call(HEALTHZ, UnitRef::NONE, POINT_HEAD, post(HEALTHZ, &[], None)),
        Err(LINE_OPEN)
    );
}

#[test]
fn red_every_refusal_is_the_kernels_and_byte_identical_to_todays_builders() {
    use axum::http::StatusCode;
    let a = Script::new(AuthPoints::HEAD, Verified::Reject, Vec::new());
    let k = kit(&[("a", a)]);
    let units_before = k.inbound.units().len();

    let no_route = k.refuse(REFUSE_NO_ROUTE, LINE_NONE, UnitRef::NONE, "/nope");
    assert_eq!(
        no_route,
        Refusal::of(crate::router::fallback_error_response(
            &k.app.planes,
            "/nope",
            StatusCode::NOT_FOUND,
            busbar_contract::protocol::ERR_TYPE_NOT_FOUND,
            "the requested resource was not found",
        ))
    );
    assert_eq!(no_route.status, 404);
    assert!(no_route
        .fields
        .iter()
        .any(|(n, v)| n == "content-type" && v == b"application/json"));
    assert_eq!(
        k.inbound.units().len(),
        units_before,
        "a request with no line got a unit"
    );
    assert_eq!(k.refused.lock().unwrap()[0].unit, None);

    let miss = k.refuse(
        REFUSE_METHOD_MISS,
        k.line(MESSAGES),
        UnitRef::NONE,
        MESSAGES,
    );
    assert_eq!(
        miss,
        Refusal::of(crate::router::fallback_error_response(
            &k.app.planes,
            MESSAGES,
            StatusCode::METHOD_NOT_ALLOWED,
            busbar_contract::protocol::ERR_TYPE_INVALID_REQUEST,
            "method not allowed for this resource",
        ))
    );
    assert_eq!(miss.status, 405);

    let over = k.refuse(REFUSE_OVER_GATE, k.line(MESSAGES), UnitRef::NONE, MESSAGES);
    assert_eq!(
        over,
        Refusal::of(crate::router::fallback_error_response(
            &k.app.planes,
            MESSAGES,
            StatusCode::PAYLOAD_TOO_LARGE,
            busbar_contract::protocol::KIND_REQUEST_TOO_LARGE,
            "request body exceeds the maximum allowed size",
        ))
    );
    assert_eq!(over.status, 413);

    let ans = k
        .call(
            MESSAGES,
            UnitRef::NONE,
            POINT_HEAD,
            post(MESSAGES, &[], None),
        )
        .unwrap();
    assert_eq!(ans.flow, FLOW_STOP);
    let stopped = k.refuse(REFUSE_STOPPED, k.line(MESSAGES), ans.unit, MESSAGES);
    assert_eq!(
        stopped,
        Refusal::of(crate::auth::unauthorized_with_completion_taps(
            &k.app, MESSAGES, None
        ))
    );
    assert_eq!(stopped.status, 401);
    assert!(
        k.inbound.unit_secret(OWNER, ans.unit.id).is_none(),
        "the refused unit is still in the table"
    );
    let last = *k.refused.lock().unwrap().last().unwrap();
    assert_eq!((last.unit, last.status), (Some(ans.unit.id), 401));

    assert_eq!(
        k.inbound
            .refuse(Refuse {
                owner: OWNER,
                generation: GEN,
                unit: ans.unit,
                cause: REFUSE_STOPPED,
                line: k.line(MESSAGES),
                request: None,
                conn: 1,
                stream: 1,
                framing: Some(1),
            })
            .map(|r| r.status),
        Err(UNIT_FOREIGN)
    );
}

#[test]
fn red_a_line_id_never_carries_the_binding_bit() {
    let a = Script::new(AuthPoints::HEAD, Verified::Pass, Vec::new());
    let k = kit(&[("a", a)]);
    let specs = k.inbound.specs(OWNER, GEN).expect("installed");
    assert_eq!(specs.len(), 3);
    for s in &specs {
        assert_ne!(s.auth, 0);
        assert_eq!(
            s.auth & BINDING_BIT,
            0,
            "line {} carries the binding bit",
            s.line
        );
        assert!(is_line_id(s.auth));
    }
    assert_eq!(BINDING_BIT, 1 << 63);
    let table = k.inbound.table(OWNER, GEN).expect("installed");
    let with = |ids: Vec<u64>| Listener {
        guests: table.listener.guests.clone(),
        auths: HashMap::new(),
        body_limit: 0,
        app: Arc::clone(&k.app),
        door_refusals: Vec::new(),
        ids,
        signed_ingress: kin_unsigned(),
        scope: None,
    };
    for ids in [
        vec![1, 2, BINDING_BIT | 3],
        vec![0, 2, 3],
        vec![1, 1, 3],
        vec![1, 2],
    ] {
        assert_eq!(
            k.inbound.install(OWNER + 9, GEN, with(ids.clone())),
            Err(IDS_REFUSED),
            "{ids:?}"
        );
    }
    assert!(
        k.inbound.specs(OWNER + 9, GEN).is_none(),
        "a refused table was installed"
    );
    assert_eq!(
        k.inbound.install(OWNER + 9, GEN, with(vec![1, 2, 3])),
        Ok(())
    );
}

#[test]
fn red_the_peer_point_answers_flow_alone_and_its_verdict_is_the_connections() {
    let a = Script::new(AuthPoints::PEER, identity("peer", "cert"), names());
    let k = kit(&[("a", Arc::clone(&a))]);
    let ans = k
        .call_on(
            7,
            MESSAGES,
            UnitRef::NONE,
            POINT_PEER,
            Head::default(),
            None,
        )
        .expect("answered");
    assert_eq!(ans.flow, FLOW_CONTINUE);
    assert_eq!(ans.unit, UnitRef::NONE, "a peer answer named a unit");
    assert!(
        ans.strips.is_empty(),
        "a peer answer named lines: {:?}",
        ans.strips
    );
    let (flow, unit) = k.hand_in_on(7, MESSAGES, UnitRef::NONE, post(MESSAGES, &[], None));
    assert_eq!(
        flow, FLOW_CONTINUE,
        "the connection's verdict did not reach its unit"
    );
    assert_eq!(k.inbound.admitted(unit.id).expect("admitted").provider, "a");
    let (flow, _) = k.hand_in_on(8, MESSAGES, UnitRef::NONE, post(MESSAGES, &[], None));
    assert_eq!(
        flow, FLOW_STOP,
        "another connection's unit took this connection's verdict"
    );
    assert_eq!(a.calls(), 1);

    let r = Script::new(AuthPoints::PEER, Verified::Reject, names());
    let k = kit(&[("r", r)]);
    let ans = k
        .call_on(
            7,
            MESSAGES,
            UnitRef::NONE,
            POINT_PEER,
            Head::default(),
            None,
        )
        .expect("answered");
    assert_eq!(
        (ans.flow, ans.unit, ans.strips.len()),
        (FLOW_STOP, UnitRef::NONE, 0)
    );
}

#[test]
fn red_a_peer_call_presenting_bytes_is_refused() {
    let a = Script::new(AuthPoints::PEER, identity("peer", "cert"), Vec::new());
    let k = kit(&[("a", Arc::clone(&a))]);
    assert_eq!(
        k.call_on(
            7,
            MESSAGES,
            UnitRef::NONE,
            POINT_PEER,
            post(MESSAGES, &[], None),
            None
        ),
        Err(PEER_BYTES)
    );
    assert_eq!(
        k.call_on(
            7,
            MESSAGES,
            UnitRef { id: 9, mac: 9 },
            POINT_PEER,
            Head::default(),
            None
        ),
        Err(PEER_BYTES)
    );
    assert_eq!(a.calls(), 0);
}

#[test]
fn red_a_call_past_its_ops_deadline_runs_no_verify_and_stops() {
    let a = Script::new(AuthPoints::HEAD, identity("alice", "k"), Vec::new());
    let k = kit(&[("a", Arc::clone(&a))]);
    let past = std::time::Instant::now()
        .checked_sub(std::time::Duration::from_millis(5))
        .expect("a past instant");
    let ans = k
        .call_on(
            1,
            MESSAGES,
            UnitRef::NONE,
            POINT_HEAD,
            post(MESSAGES, &[], None),
            Some(past),
        )
        .expect("answered");
    assert_eq!(ans.flow, FLOW_STOP);
    assert_eq!(a.calls(), 0, "a verify ran past the op's deadline");
    let future = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let ans = k
        .call_on(
            1,
            MESSAGES,
            UnitRef::NONE,
            POINT_HEAD,
            post(MESSAGES, &[], None),
            Some(future),
        )
        .expect("answered");
    assert_eq!(ans.flow, FLOW_CONTINUE);
    assert_eq!(a.calls(), 1);
}

fn signing_gov() -> Arc<crate::governance::GovState> {
    let signer = crate::governance::signing::TokenSigner::from_secret_bytes(
        &[7u8; 32],
        crate::governance::signing::DEFAULT_KID,
    );
    let gov = Arc::new(
        crate::governance::GovState::new_with_signer(
            Arc::new(crate::governance::MemoryStore::new()),
            Some("admintok".to_string()),
            Some(signer),
        )
        .expect("a governance"),
    );
    gov.set_at_rest_keys(Some(crate::governance::at_rest::AtRestKeys::new(
        &[9; 32], None,
    )));
    gov
}

fn minted(gov: &crate::governance::GovState, exp: u64, now: u64) -> (String, String) {
    let (key, secret) = gov
        .mint_signed(
            crate::governance::NewKeySpec {
                name: "vk".to_string(),
                allowed_pools: Some(vec!["pa".to_string()]),
                ..Default::default()
            },
            exp,
            now,
        )
        .expect("minted");
    (key.id.clone(), secret.expose(&crate::seal::lend()).clone())
}

fn keys_kit(gov: &Arc<crate::governance::GovState>) -> Kit {
    kit_over(
        crate::test_support::TestApp::new()
            .keys_chain()
            .governance(Arc::clone(gov))
            .build(),
        vec![crate::config::KEYS_MODULE.to_string()],
        AuthPoints::HEAD,
        &[],
    )
}

fn bearer(token: &str) -> Head {
    post(
        MESSAGES,
        &[("Authorization", &format!("Bearer {token}"))],
        None,
    )
}

fn spend(k: &Kit, head: Head) -> (u32, UnitRef) {
    let ans = k
        .call(MESSAGES, UnitRef::NONE, POINT_HEAD, head)
        .expect("answered");
    (ans.flow, ans.unit)
}

#[test]
fn red_keys_a_revoked_key_is_refused() {
    let gov = signing_gov();
    let now = crate::store::now();
    let (id, token) = minted(&gov, now + 3_600, now);
    let k = keys_kit(&gov);
    let ans = k
        .call(MESSAGES, UnitRef::NONE, POINT_HEAD, bearer(&token))
        .expect("answered");
    assert_eq!(ans.flow, FLOW_CONTINUE);
    let admitted = k.inbound.admitted(ans.unit.id).expect("admitted");
    assert_eq!(admitted.provider, crate::config::KEYS_MODULE);
    assert_eq!(
        admitted.resolved.as_ref().map(|key| key.id.clone()),
        Some(id.clone())
    );
    assert!(ans.strips.contains(&Strip::field("authorization")));
    assert!(
        !format!("{ans:?}").contains(&token),
        "the token reached the transport"
    );
    gov.revoke(&id, "oracle key-revoke").expect("revoked");
    let (flow, unit) = spend(&k, bearer(&token));
    assert_eq!(flow, FLOW_STOP);
    let refusal = k.refuse(REFUSE_STOPPED, k.line(MESSAGES), unit, MESSAGES);
    assert_eq!(
        refusal,
        Refusal::of(crate::auth::unauthorized_with_completion_taps(
            &k.app, MESSAGES, None
        ))
    );
}

#[test]
fn red_keys_a_rotated_keys_old_token_is_refused() {
    let gov = signing_gov();
    let now = crate::store::now();
    let (id, old) = minted(&gov, now + 3_600, now);
    let k = keys_kit(&gov);
    assert_eq!(spend(&k, bearer(&old)).0, FLOW_CONTINUE);
    let rotated = gov
        .rotate_key(&id, now + 3_600)
        .expect("rotated")
        .expect("a key to rotate");
    let new = rotated.token.expose(&crate::seal::lend()).clone();
    assert_eq!(
        spend(&k, bearer(&old)).0,
        FLOW_STOP,
        "the old token still spends"
    );
    assert_eq!(
        spend(&k, bearer(&new)).0,
        FLOW_CONTINUE,
        "the rotated token does not"
    );
}

#[test]
fn red_keys_an_expired_key_is_refused() {
    let gov = signing_gov();
    let now = crate::store::now();
    let (_, token) = minted(&gov, now - 60, now - 3_600);
    let k = keys_kit(&gov);
    assert_eq!(spend(&k, bearer(&token)).0, FLOW_STOP);
}

#[test]
fn red_keys_a_bad_x_api_key_alone_is_refused() {
    let gov = signing_gov();
    let k = keys_kit(&gov);
    let (flow, unit) = spend(&k, post(MESSAGES, &[("x-api-key", "not-a-key")], None));
    assert_eq!(flow, FLOW_STOP);
    let refusal = k.refuse(REFUSE_STOPPED, k.line(MESSAGES), unit, MESSAGES);
    assert_eq!(refusal.status, 401);
    assert_eq!(spend(&k, post(MESSAGES, &[], None)).0, FLOW_STOP);
}

#[test]
fn red_keys_the_bearer_decides_beside_an_x_api_key() {
    let gov = signing_gov();
    let now = crate::store::now();
    let (_, token) = minted(&gov, now + 3_600, now);
    let k = keys_kit(&gov);
    let ans = k
        .call(
            MESSAGES,
            UnitRef::NONE,
            POINT_HEAD,
            post(
                MESSAGES,
                &[
                    ("Authorization", &format!("Bearer {token}")),
                    ("x-api-key", "stray"),
                ],
                None,
            ),
        )
        .expect("answered");
    assert_eq!(ans.flow, FLOW_CONTINUE);
    assert!(ans.strips.contains(&Strip::field("authorization")));
    assert!(ans.strips.contains(&Strip::field("x-api-key")));

    assert_eq!(
        k.hand_in(
            MESSAGES,
            MESSAGES,
            ans.unit,
            post(MESSAGES, &[("x-api-key", "stray")], None)
        )
        .0,
        FLOW_STOP
    );
    assert_eq!(
        k.hand_in(MESSAGES, MESSAGES, ans.unit, post(MESSAGES, &[], None))
            .0,
        FLOW_CONTINUE
    );
}

const SIGNED_LINE: &str = "x-signed-credential";

fn reader_kit<R: AuthCalls + 'static>(
    gov: &Arc<crate::governance::GovState>,
    reader: Arc<R>,
    signs: bool,
) -> Kit {
    let (kind, _) = crate::test_support::issued::double();
    let cfg = crate::config::AuthCfg {
        chain: vec![crate::config::AuthChainEntry::bare(
            crate::config::KEYS_MODULE,
        )],
        ..crate::config::AuthCfg::default_none()
    };
    let auth = crate::auth::AuthMiddleware::new_builtin(&cfg).with_reader_for_test(
        reader,
        vec![kind],
        &[SIGNED_LINE],
    );
    kit_signed(
        crate::test_support::TestApp::new()
            .auth(Arc::new(auth))
            .governance(Arc::clone(gov))
            .build(),
        vec![crate::config::KEYS_MODULE.to_string()],
        AuthPoints::HEAD_BODY,
        &[],
        Arc::new(move |_: &App, _: &str| signs),
    )
}

fn minted_with_credential(gov: &crate::governance::GovState) -> (String, String) {
    let (kind, shape) = crate::test_support::issued::double();
    let now = crate::store::now();
    let (key, _token, public_id, _secret) = gov
        .mint_signed_with_credential(
            crate::governance::NewKeySpec {
                name: "signed".to_string(),
                allowed_pools: Some(vec!["pa".to_string()]),
                ..Default::default()
            },
            now + 3_600,
            now,
            &kind,
            &shape,
        )
        .expect("minted");
    (key.id.clone(), public_id)
}

fn signed_head() -> Head {
    post(MESSAGES, &[(SIGNED_LINE, "signature")], None)
}

fn signed_call(k: &Kit, head: Head) -> Answer {
    k.call(MESSAGES, UnitRef::NONE, POINT_HEAD_BODY, head)
        .expect("answered")
}

fn declared_signed_ticket_kit(
    gov: &Arc<crate::governance::GovState>,
    reader: Arc<Script>,
    earlier: Arc<Script>,
) -> Kit {
    let k = reader_kit(gov, reader, false);
    let mut listener = k.inbound.table(OWNER, GEN).unwrap().listener.clone();
    listener.auths.insert("earlier".into(), earlier);
    let chain = LineAuth::Chain(
        vec!["earlier".into(), crate::config::KEYS_MODULE.into()],
        AuthPoints(POINT_HEAD | POINT_HEAD_BODY),
    );
    listener.guests = GuestList::seal(vec![
        line(MESSAGES, METHOD_POST, chain.clone()),
        line(OTHER, METHOD_POST, chain),
        line(HEALTHZ, METHOD_GET, LineAuth::None),
    ])
    .unwrap();
    listener.door_refusals = vec![crate::plane_routes::PlaneRefusalSpec {
        route: crate::plane_routes::DoorRouteId {
            path: MESSAGES.into(),
            method: busbar_contract::abi::mechanism::route::RouteMethod::Post,
        },
        refuse: Arc::new(|_, _| {
            axum::http::Response::builder()
                .status(401)
                .body(axum::body::Body::empty())
                .unwrap()
        }),
        ticket_prefix: Some("tk_".into()),
        signed_ingress: Arc::from(["/v1/*messages".to_string()]),
    }];
    k.inbound.install_at(OWNER, 71, GEN, listener).unwrap();
    k.inbound.framing_started(OWNER, 71, 1, GEN).unwrap();
    k.inbound.grant_stream(OWNER, 1, 1, GEN).unwrap();
    k
}

#[tokio::test]
async fn a_declared_signed_identity_preempts_ticket_and_plugins_through_the_final_gate() {
    crate::snapshot::init();
    for valid_ticket in [true, false] {
        let gov = signing_gov();
        let now = crate::store::now();
        let (signed_id, public_id) = minted_with_credential(&gov);
        let (ticket_id, _) = minted(&gov, now + 3600, now);
        let (ticket, _) = gov
            .mint_ticket(&ticket_id, "tk_", 600, None, b"record", now)
            .unwrap();
        let reader = Script::new(
            AuthPoints::HEAD_BODY,
            Verified::Identity(VerifiedIdentity {
                subject: public_id,
                ..VerifiedIdentity::default()
            }),
            vec![Strip::field(SIGNED_LINE), Strip::field("authorization")],
        );
        let earlier = Script::new(AuthPoints::HEAD, Verified::Reject, Vec::new());
        let k = declared_signed_ticket_kit(&gov, Arc::clone(&reader), Arc::clone(&earlier));
        let presented = if valid_ticket {
            ticket.as_str()
        } else {
            "tk_malformed"
        };
        let head = post(
            MESSAGES,
            &[
                (SIGNED_LINE, "signature"),
                ("authorization", &format!("Bearer {presented}")),
            ],
            None,
        );
        let first = k
            .call(MESSAGES, UnitRef::NONE, POINT_HEAD, head.clone())
            .unwrap();
        assert_eq!(first.flow, FLOW_CONTINUE);
        assert_eq!(reader.calls(), 0, "the body has not arrived");
        assert_eq!(earlier.calls(), 0, "the signed pre-step owns priority");
        assert_eq!(
            k.hand_in(MESSAGES, MESSAGES, first.unit, head.clone()).0,
            FLOW_STOP
        );
        let answer = k
            .call(MESSAGES, first.unit, POINT_HEAD_BODY, head.clone())
            .unwrap();
        assert_eq!(answer.flow, FLOW_CONTINUE);
        assert_eq!(reader.calls(), 1);
        assert_eq!(earlier.calls(), 0);
        let sanitized = head.stripped(&answer.strips).unwrap();
        assert_eq!(
            k.hand_in(MESSAGES, MESSAGES, answer.unit, sanitized.clone())
                .0,
            FLOW_CONTINUE
        );
        let receipt = k.inbound.claim_request(OWNER, 1, 1, &sanitized).unwrap();
        assert_eq!(
            through_final_gate_identity(&k, receipt, &sanitized).await,
            (200, None, Some(signed_id))
        );
        assert_eq!(
            reader.calls(),
            1,
            "the root reuses the actual signed result"
        );
        assert!(
            gov.admit_ticket("tk_", &ticket, now).is_some(),
            "signed identity leaves the accompanying ticket unspent"
        );
    }
}

#[tokio::test]
async fn a_signed_pass_reaches_ticket_once_but_a_signed_refusal_never_does() {
    crate::snapshot::init();
    for verdict in [
        Verified::Pass,
        Verified::Reject,
        Verified::Failed,
        Verified::Overloaded,
    ] {
        let pass = matches!(verdict, Verified::Pass);
        let gov = signing_gov();
        let now = crate::store::now();
        let (id, _) = minted(&gov, now + 3600, now);
        let (ticket, _) = gov
            .mint_ticket(&id, "tk_", 600, None, b"record", now)
            .unwrap();
        let reader = Script::new(
            AuthPoints::HEAD_BODY,
            verdict,
            vec![Strip::field(SIGNED_LINE)],
        );
        let earlier = Script::new(
            AuthPoints::HEAD_BODY,
            identity("wrong-plugin", "wrong"),
            Vec::new(),
        );
        let k = declared_signed_ticket_kit(&gov, Arc::clone(&reader), Arc::clone(&earlier));
        let head = post(
            MESSAGES,
            &[
                (SIGNED_LINE, "signature"),
                ("authorization", &format!("Bearer {ticket}")),
            ],
            None,
        );
        let answer = signed_call(&k, head.clone());
        assert_eq!(reader.calls(), 1);
        assert_eq!(earlier.calls(), 0);
        assert_eq!(answer.flow, if pass { FLOW_CONTINUE } else { FLOW_STOP });
        if pass {
            let sanitized = head.stripped(&answer.strips).unwrap();
            assert_eq!(
                k.hand_in(MESSAGES, MESSAGES, answer.unit, sanitized.clone())
                    .0,
                FLOW_CONTINUE
            );
            let receipt = k.inbound.claim_request(OWNER, 1, 1, &sanitized).unwrap();
            assert_eq!(
                through_final_gate_identity(&k, receipt, &sanitized).await,
                (200, Some(b"record".to_vec()), Some(id))
            );
            assert!(gov.admit_ticket("tk_", &ticket, now).is_none());
        } else {
            assert!(gov.admit_ticket("tk_", &ticket, now).is_some());
        }
    }
}

#[tokio::test]
async fn signed_receipt_replay_is_claimed_only_at_final_admission_and_ticket_stays_unspent() {
    use busbar_contract::store_calls::StoreDoor;

    crate::snapshot::init();
    let opened = crate::test_support::store_axis_stand_in()
        .open(
            StoreDoor::Linked(crate::test_support::store_double::door),
            crate::test_support::store_double::NAME,
            b"{}",
        )
        .expect("the replay store opens through its real door");
    let gov = Arc::new(
        crate::governance::GovState::new_with_signer(
            opened.records,
            Some("admintok".to_string()),
            Some(crate::governance::signing::TokenSigner::from_secret_bytes(
                &[7; 32],
                crate::governance::signing::DEFAULT_KID,
            )),
        )
        .expect("a signing governance"),
    );
    assert!(gov.attach_store_calls(opened.calls.expect("the door supplies atomic replay calls")));
    gov.set_at_rest_keys(Some(crate::governance::at_rest::AtRestKeys::new(
        &[9; 32], None,
    )));
    let now = crate::store::now();
    let (id, public_id) = minted_with_credential(&gov);
    let (ticket, _) = gov
        .mint_ticket(&id, "tk_", 600, None, b"record", now)
        .unwrap();
    let reader = Script::new(
        AuthPoints::HEAD_BODY,
        Verified::Identity(VerifiedIdentity {
            subject: public_id,
            replay: Some(Box::new(busbar_contract::auth_calls::Replay {
                key: "signed-ticket-message".into(),
                ttl_secs: 60,
            })),
            ..VerifiedIdentity::default()
        }),
        vec![Strip::field(SIGNED_LINE), Strip::field("authorization")],
    );
    let earlier = Script::new(AuthPoints::HEAD, Verified::Reject, Vec::new());
    let k = declared_signed_ticket_kit(&gov, Arc::clone(&reader), earlier);
    let head = post(
        MESSAGES,
        &[
            (SIGNED_LINE, "signature"),
            ("authorization", &format!("Bearer {ticket}")),
        ],
        None,
    );
    let waiting = k
        .call(MESSAGES, UnitRef::NONE, POINT_HEAD, head.clone())
        .unwrap();
    k.inbound.exit(waiting.unit.id);
    assert_eq!(
        k.call(MESSAGES, waiting.unit, POINT_HEAD_BODY, head.clone()),
        Err(UNIT_FOREIGN)
    );
    assert_eq!(
        reader.calls(),
        0,
        "cancelled waiting head invokes no reader"
    );
    for status in [200, 401] {
        let answer = signed_call(&k, head.clone());
        assert_eq!(answer.flow, FLOW_CONTINUE, "preflight never claims replay");
        let sanitized = head.stripped(&answer.strips).unwrap();
        assert_eq!(
            k.hand_in(MESSAGES, MESSAGES, answer.unit, sanitized.clone())
                .0,
            FLOW_CONTINUE
        );
        let receipt = k.inbound.claim_request(OWNER, 1, 1, &sanitized).unwrap();
        let (actual, record, _) = through_final_gate_identity(&k, receipt, &sanitized).await;
        assert_eq!(actual, status);
        assert_eq!(record, None);
    }
    assert_eq!(
        reader.calls(),
        2,
        "one signed verify per body, none repeated by middleware"
    );
    assert!(gov.admit_ticket("tk_", &ticket, now).is_some());
}

#[test]
fn red_signed_a_verified_signature_is_its_credentials_key() {
    let gov = signing_gov();
    let (key_id, public_id) = minted_with_credential(&gov);
    let reader = Script::new(
        AuthPoints::HEAD_BODY,
        Verified::Identity(VerifiedIdentity {
            subject: public_id,
            ..VerifiedIdentity::default()
        }),
        vec![Strip::field(SIGNED_LINE)],
    );
    let k = reader_kit(&gov, Arc::clone(&reader), true);
    let ans = signed_call(&k, signed_head());
    assert_eq!(ans.flow, FLOW_CONTINUE);
    assert_eq!(reader.calls(), 1);
    let admitted = k.inbound.admitted(ans.unit.id).expect("admitted");
    assert_eq!(
        admitted.resolved.as_ref().map(|key| key.id.clone()),
        Some(key_id)
    );
    assert!(ans.strips.contains(&Strip::field(SIGNED_LINE)));
}

#[test]
fn red_signed_a_rejected_or_revoked_signature_is_refused() {
    let gov = signing_gov();
    let (key_id, public_id) = minted_with_credential(&gov);
    let reject = Script::new(AuthPoints::HEAD_BODY, Verified::Reject, Vec::new());
    let k = reader_kit(&gov, reject, true);
    let ans = signed_call(&k, signed_head());
    assert_eq!(ans.flow, FLOW_STOP);
    assert_eq!(
        k.refuse(REFUSE_STOPPED, k.line(MESSAGES), ans.unit, MESSAGES)
            .status,
        401
    );
    gov.revoke(&key_id, "signed revoke").expect("revoked");
    let identity = Script::new(
        AuthPoints::HEAD_BODY,
        Verified::Identity(VerifiedIdentity {
            subject: public_id,
            ..VerifiedIdentity::default()
        }),
        Vec::new(),
    );
    let k = reader_kit(&gov, identity, true);
    assert_eq!(signed_call(&k, signed_head()).flow, FLOW_STOP);
}

#[test]
fn red_signed_a_pass_falls_to_the_token_path_and_an_unsigned_dialect_asks_no_verifier() {
    let gov = signing_gov();
    let now = crate::store::now();
    let (_, token) = minted(&gov, now + 3_600, now);
    let pass = Script::new(AuthPoints::HEAD_BODY, Verified::Pass, Vec::new());
    let k = reader_kit(&gov, Arc::clone(&pass), true);
    let both = post(
        MESSAGES,
        &[
            (SIGNED_LINE, "signature"),
            ("Authorization", &format!("Bearer {token}")),
        ],
        None,
    );
    assert_eq!(signed_call(&k, both).flow, FLOW_CONTINUE);
    assert_eq!(signed_call(&k, signed_head()).flow, FLOW_STOP);
    assert_eq!(pass.calls(), 2);
    let unasked = Script::new(AuthPoints::HEAD_BODY, Verified::Reject, Vec::new());
    let k = reader_kit(&gov, Arc::clone(&unasked), false);
    let _ = signed_call(&k, signed_head());
    assert_eq!(
        unasked.calls(),
        0,
        "a dialect that does not sign asked the verifier"
    );
}

#[test]
fn red_signed_a_body_over_the_gate_is_the_413_before_any_verdict() {
    let gov = signing_gov();
    let reader = Script::new(AuthPoints::HEAD_BODY, Verified::Reject, Vec::new());
    let k = reader_kit(&gov, Arc::clone(&reader), true);
    let over = k.inbound.auth_call(
        Call {
            owner: OWNER,
            generation: GEN,
            auth: k.id(MESSAGES),
            unit: UnitRef::NONE,
            point: POINT_HEAD_BODY,
            conn: 1,
            stream: 1,
            framing: 1,
            head: signed_head(),
            body: Some(vec![b'x'; 64]),
            deadline: None,
        },
        Box::new(|_: Result<Answer, &'static str>| {}),
    );
    assert_eq!(over, Some(Err(OVER_GATE)));
    assert_eq!(reader.calls(), 0);
    let refusal = k.refuse(REFUSE_OVER_GATE, k.line(MESSAGES), UnitRef::NONE, MESSAGES);
    assert_eq!(refusal.status, 413);
}

#[test]
fn red_ended_connections_leave_no_peer_verdict_and_a_live_one_survives() {
    let a = Script::new(AuthPoints::PEER, identity("peer", "cert"), Vec::new());
    let k = kit(&[("a", a)]);
    for conn in 100..140 {
        let ans = k
            .call_on(
                conn,
                MESSAGES,
                UnitRef::NONE,
                POINT_PEER,
                Head::default(),
                None,
            )
            .expect("answered");
        assert_eq!(ans.flow, FLOW_CONTINUE);
        k.inbound.framing_ended(conn);
    }
    assert_eq!(
        k.inbound.peer_verdicts(),
        0,
        "an ended connection's verdict is held"
    );
    k.call_on(
        7,
        MESSAGES,
        UnitRef::NONE,
        POINT_PEER,
        Head::default(),
        None,
    )
    .expect("answered");
    for conn in 200..260 {
        k.call_on(
            conn,
            MESSAGES,
            UnitRef::NONE,
            POINT_PEER,
            Head::default(),
            None,
        )
        .expect("answered");
        k.inbound.framing_ended(conn);
    }
    assert_eq!(k.inbound.peer_verdicts(), 1);
    let (flow, _) = k.hand_in_on(7, MESSAGES, UnitRef::NONE, post(MESSAGES, &[], None));
    assert_eq!(flow, FLOW_CONTINUE, "the live connection lost its verdict");
    k.inbound.framing_ended(7);
    let (flow, _) = k.hand_in_on(7, MESSAGES, UnitRef::NONE, post(MESSAGES, &[], None));
    assert_eq!(flow, FLOW_STOP);
}

#[test]
fn red_a_full_peer_table_refuses_a_new_connection_by_name_and_evicts_none() {
    let a = Script::new(AuthPoints::PEER, identity("peer", "cert"), Vec::new());
    let k = kit(&[("a", a)]);
    for conn in 0..PEER_CONNECTIONS_MAX as u64 {
        k.call_on(
            conn,
            MESSAGES,
            UnitRef::NONE,
            POINT_PEER,
            Head::default(),
            None,
        )
        .expect("answered");
    }
    assert_eq!(
        k.call_on(
            u64::MAX,
            MESSAGES,
            UnitRef::NONE,
            POINT_PEER,
            Head::default(),
            None
        ),
        Err(PEER_TABLE_FULL)
    );
    assert_eq!(k.inbound.peer_verdicts(), PEER_CONNECTIONS_MAX);
    let (flow, _) = k.hand_in_on(0, MESSAGES, UnitRef::NONE, post(MESSAGES, &[], None));
    assert_eq!(flow, FLOW_CONTINUE, "a held verdict was evicted");
}

#[test]
fn red_a_call_whose_conn_disagrees_with_its_framing_is_refused() {
    let a = Script::new(AuthPoints::HEAD, identity("alice", "k"), Vec::new());
    let k = kit(&[("a", Arc::clone(&a))]);
    let call = |framing: u64, conn: u64| {
        k.inbound
            .auth_call(
                Call {
                    owner: OWNER,
                    generation: GEN,
                    auth: k.id(MESSAGES),
                    unit: UnitRef::NONE,
                    point: POINT_HEAD,
                    conn,
                    stream: 1,
                    framing,
                    head: post(MESSAGES, &[], None),
                    body: None,
                    deadline: None,
                },
                Box::new(|_: Result<Answer, &'static str>| {}),
            )
            .expect("answered at once")
    };
    assert!(call(40, 5).is_ok());
    assert_eq!(call(40, 6), Err(CONN_MISMATCH));
    assert!(
        call(41, 6).is_ok(),
        "another framing may name another connection"
    );
    assert_eq!(
        k.inbound.hand_in(HandIn {
            owner: OWNER,
            generation: GEN,
            auth: k.id(MESSAGES),
            unit: UnitRef::NONE,
            line: k.line(MESSAGES),
            conn: 9,
            stream: 1,
            framing: Some(40),
            head: post(MESSAGES, &[], None),
        }),
        Err(CONN_MISMATCH)
    );

    k.inbound.framing_ended(40);
    assert!(call(40, 6).is_ok());
}

#[test]
fn a_unit_cannot_be_reused_by_another_connection_for_auth() {
    let a = Script::new(AuthPoints::HEAD, identity("alice", "k"), Vec::new());
    let k = kit(&[("a", a)]);
    let admitted = k
        .call(
            MESSAGES,
            UnitRef::NONE,
            POINT_HEAD,
            post(MESSAGES, &[], None),
        )
        .expect("first connection authenticated");
    assert_eq!(admitted.flow, FLOW_CONTINUE);
    assert_eq!(
        k.call_on(
            2,
            MESSAGES,
            admitted.unit,
            POINT_HEAD,
            post(MESSAGES, &[], None),
            None,
        ),
        Err(UNIT_FOREIGN),
        "a valid MAC does not transfer a unit to another connection"
    );
    assert_eq!(
        k.hand_in(MESSAGES, MESSAGES, admitted.unit, post(MESSAGES, &[], None))
            .0,
        FLOW_CONTINUE,
        "refused reuse must leave the original unit intact"
    );
}

#[test]
fn a_unit_cannot_be_handed_in_by_another_connection() {
    let a = Script::new(AuthPoints::HEAD, identity("alice", "k"), Vec::new());
    let k = kit(&[("a", a)]);
    let admitted = k
        .call(
            MESSAGES,
            UnitRef::NONE,
            POINT_HEAD,
            post(MESSAGES, &[], None),
        )
        .expect("first connection authenticated");
    assert_eq!(admitted.flow, FLOW_CONTINUE);
    assert_eq!(
        k.inbound.hand_in(HandIn {
            owner: OWNER,
            generation: GEN,
            auth: k.id(MESSAGES),
            unit: admitted.unit,
            line: k.line(MESSAGES),
            conn: 2,
            stream: 1,
            framing: Some(2),
            head: post(MESSAGES, &[], None),
        }),
        Err(UNIT_FOREIGN)
    );
    assert_eq!(
        k.hand_in(MESSAGES, MESSAGES, admitted.unit, post(MESSAGES, &[], None))
            .0,
        FLOW_CONTINUE,
        "refused reuse must leave the original unit intact"
    );
}

#[test]
fn a_unit_cannot_cross_streams_or_framings_at_any_inbound_operation() {
    for (conn, stream, framing) in [(1, 2, Some(1)), (1, 1, Some(2)), (1, 1, None)] {
        for operation in ["auth", "hand-in", "refuse"] {
            if operation == "auth" && framing.is_none() {
                continue;
            }
            let a = Script::new(AuthPoints::HEAD, identity("alice", "k"), Vec::new());
            let k = kit(&[("a", a)]);
            let unit = k
                .call(
                    MESSAGES,
                    UnitRef::NONE,
                    POINT_HEAD,
                    post(MESSAGES, &[], None),
                )
                .expect("original request authenticated")
                .unit;
            let head = post(MESSAGES, &[], None);
            let result = match operation {
                "auth" => k
                    .inbound
                    .auth_call(
                        Call {
                            owner: OWNER,
                            generation: GEN,
                            auth: k.id(MESSAGES),
                            unit,
                            point: POINT_HEAD,
                            conn,
                            stream,
                            framing: framing.expect("auth has a framing"),
                            head,
                            body: None,
                            deadline: None,
                        },
                        Box::new(|_| panic!("a refused reuse must answer immediately")),
                    )
                    .expect("answered immediately")
                    .map(|_| ()),
                "hand-in" => k
                    .inbound
                    .hand_in(HandIn {
                        owner: OWNER,
                        generation: GEN,
                        auth: k.id(MESSAGES),
                        unit,
                        line: k.line(MESSAGES),
                        conn,
                        stream,
                        framing,
                        head,
                    })
                    .map(|_| ()),
                "refuse" => k
                    .inbound
                    .refuse(Refuse {
                        owner: OWNER,
                        generation: GEN,
                        unit,
                        cause: REFUSE_STOPPED,
                        line: k.line(MESSAGES),
                        conn,
                        stream,
                        framing,
                        request: Some(head),
                    })
                    .map(|_| ()),
                _ => unreachable!(),
            };
            assert_eq!(
                result,
                Err(UNIT_FOREIGN),
                "{operation}: {conn}/{stream}/{framing:?}"
            );
            assert_eq!(
                k.hand_in(MESSAGES, MESSAGES, unit, post(MESSAGES, &[], None))
                    .0,
                FLOW_CONTINUE,
                "refused reuse must leave the original request intact"
            );
        }
    }
}

#[test]
fn red_a_unitless_refusal_is_shaped_by_the_requests_path() {
    use axum::http::StatusCode;
    let a = Script::new(AuthPoints::HEAD, Verified::Reject, Vec::new());
    let k = kit(&[("a", a)]);
    for (cause, line, status, kind, message) in [
        (
            REFUSE_NO_ROUTE,
            LINE_NONE,
            StatusCode::NOT_FOUND,
            busbar_contract::protocol::ERR_TYPE_NOT_FOUND,
            "the requested resource was not found",
        ),
        (
            REFUSE_METHOD_MISS,
            k.line(MESSAGES),
            StatusCode::METHOD_NOT_ALLOWED,
            busbar_contract::protocol::ERR_TYPE_INVALID_REQUEST,
            "method not allowed for this resource",
        ),
        (
            REFUSE_OVER_GATE,
            k.line(MESSAGES),
            StatusCode::PAYLOAD_TOO_LARGE,
            busbar_contract::protocol::KIND_REQUEST_TOO_LARGE,
            "request body exceeds the maximum allowed size",
        ),
    ] {
        for path in ["/api/v1/admin/keys", "/definitely/unknown"] {
            let got = k.refuse(cause, line, UnitRef::NONE, path);
            let want = Refusal::of(crate::router::fallback_error_response(
                &k.app.planes,
                path,
                status,
                kind,
                message,
            ));
            assert_eq!(got, want, "cause {cause} on {path}");
        }
    }
}

#[test]
fn a_head_body_continuation_cannot_authenticate_another_head_for_the_original_unit() {
    for mutation in [
        "method",
        "path",
        "authority",
        "field",
        "query",
        "credential",
        "added",
    ] {
        let head_auth = Script::new(
            AuthPoints::HEAD,
            Verified::Pass,
            vec![
                Strip::field("authorization".to_string()),
                Strip::query("token".to_string()),
            ],
        );
        let body_auth = Script::new(
            AuthPoints(POINT_HEAD_BODY),
            identity("identity-for-B", "verified-B"),
            Vec::new(),
        );
        let k = kit(&[("head", head_auth), ("body", Arc::clone(&body_auth))]);
        let original = post(
            MESSAGES,
            &[("Authorization", "secret-A"), ("X-Resource", "A")],
            Some("token=a&scope=A"),
        );
        let first = k
            .call(MESSAGES, UnitRef::NONE, POINT_HEAD, original.clone())
            .unwrap();
        let mut changed = original.clone();
        match mutation {
            "method" => changed.method = "PUT".into(),
            "path" => changed.target = OTHER.into(),
            "authority" => changed.authority = "other.example".into(),
            "field" => changed.fields[1].1 = b"B".to_vec(),
            "query" => changed.query = Some("token=a&scope=B".into()),
            "credential" => changed.fields[0].1 = b"secret-B".to_vec(),
            "added" => changed.fields.push(("X-Added".into(), b"B".to_vec())),
            _ => unreachable!(),
        }
        assert_eq!(
            k.call(MESSAGES, first.unit, POINT_HEAD_BODY, changed),
            Err(UNIT_FOREIGN),
            "{mutation}"
        );
        assert_eq!(
            body_auth.calls(),
            0,
            "a substituted head must not reach the body verifier"
        );
        let sanitized = original.stripped(&first.strips).unwrap();
        assert_eq!(
            k.hand_in(MESSAGES, MESSAGES, first.unit, sanitized.clone())
                .0,
            FLOW_STOP
        );
        assert_eq!(
            k.call(MESSAGES, first.unit, POINT_HEAD_BODY, original)
                .unwrap()
                .flow,
            FLOW_CONTINUE
        );
        assert_eq!(
            k.hand_in(MESSAGES, MESSAGES, first.unit, sanitized).0,
            FLOW_CONTINUE
        );
    }
}

#[test]
fn continuations_allow_only_original_bytes_and_declared_partial_stripping() {
    for form in ["original", "field", "query", "both", "case"] {
        let head_auth = Script::new(
            AuthPoints::HEAD,
            Verified::Pass,
            vec![
                Strip::field("authorization".to_string()),
                Strip::query("token".to_string()),
            ],
        );
        let body_auth = Script::new(
            AuthPoints(POINT_HEAD_BODY),
            identity("caller", "verified"),
            Vec::new(),
        );
        let k = kit(&[("head", head_auth), ("body", Arc::clone(&body_auth))]);
        let original = post(
            MESSAGES,
            &[("Authorization", "secret-A"), ("X-Resource", "A")],
            Some("token=a&scope=A&token=b"),
        );
        let first = k
            .call(MESSAGES, UnitRef::NONE, POINT_HEAD, original.clone())
            .unwrap();
        let mut continuation = original.clone();
        match form {
            "original" => {}
            "field" => {
                continuation.fields.remove(0);
            }
            "query" => continuation.query = Some("scope=A&token=b".into()),
            "both" => continuation = original.stripped(&first.strips).unwrap(),
            "case" => {
                continuation.fields[0].0 = "authorization".into();
                continuation.fields[1].0 = "x-resource".into();
            }
            _ => unreachable!(),
        }
        assert_eq!(
            k.call(MESSAGES, first.unit, POINT_HEAD_BODY, continuation)
                .unwrap()
                .flow,
            FLOW_CONTINUE,
            "{form}"
        );
        assert_eq!(body_auth.calls(), 1);
        assert_eq!(
            k.hand_in(
                MESSAGES,
                MESSAGES,
                first.unit,
                original.stripped(&first.strips).unwrap()
            )
            .0,
            FLOW_CONTINUE
        );
    }
    let head_auth = Script::new(AuthPoints::HEAD, Verified::Pass, Vec::new());
    let body_auth = Script::new(
        AuthPoints(POINT_HEAD_BODY),
        identity("caller", "verified"),
        Vec::new(),
    );
    let k = kit(&[("head", head_auth), ("body", Arc::clone(&body_auth))]);
    let original = post(MESSAGES, &[], None);
    let first = k
        .call(MESSAGES, UnitRef::NONE, POINT_HEAD, original.clone())
        .unwrap();
    k.inbound.exit(first.unit.id);
    assert_eq!(
        k.call(MESSAGES, first.unit, POINT_HEAD_BODY, original),
        Err(UNIT_FOREIGN)
    );
    assert_eq!(
        body_auth.calls(),
        0,
        "cancellation never revives the old unit"
    );
}

#[tokio::test]
async fn a_host_receipt_forwards_only_the_verifiers_credential_through_the_opaque_reference() {
    use tower::ServiceExt as _;
    crate::snapshot::init();
    for (carrier, verified) in [
        ("query", Some("query-verified")),
        ("custom", Some("custom-verified")),
        ("transformed", Some("normalized-verified")),
        ("absent", None),
    ] {
        let mut bindings = crate::config::RoleBindings::default();
        bindings
            .entry("a".into())
            .or_default()
            .entry("reader".into())
            .or_default();
        let app = crate::test_support::TestApp::new()
            .role_bindings(bindings)
            .build();
        let script = Script::new(
            AuthPoints::HEAD,
            Verified::Identity(VerifiedIdentity {
                subject: "caller".into(),
                groups: vec!["reader".into()],
                credential: verified.map(|s| Secret::new(s.to_owned())),
                ..VerifiedIdentity::default()
            }),
            vec![
                Strip::field("authorization"),
                Strip::field("x-custom"),
                Strip::query("token"),
            ],
        );
        let k = kit_over(
            Arc::clone(&app),
            vec!["a".into()],
            AuthPoints::HEAD,
            &[("a", script)],
        );
        let listener = k.inbound.table(OWNER, GEN).unwrap().listener.clone();
        k.inbound.install_at(OWNER, 71, GEN, listener).unwrap();
        k.inbound.framing_started(OWNER, 71, 1, GEN).unwrap();
        k.inbound.grant_stream(OWNER, 1, 1, GEN).unwrap();
        let original = match carrier {
            "query" => post(
                MESSAGES,
                &[("x-safe", "kept")],
                Some("token=wire-query&keep=1"),
            ),
            "custom" => post(
                MESSAGES,
                &[("x-custom", "wire-custom"), ("x-safe", "kept")],
                Some("keep=1"),
            ),
            _ => post(
                MESSAGES,
                &[("authorization", "Bearer wire-token"), ("x-safe", "kept")],
                Some("keep=1"),
            ),
        };
        let unit = k
            .call(MESSAGES, UnitRef::NONE, POINT_HEAD, original.clone())
            .unwrap()
            .unit;
        let sanitized = original
            .stripped(&[
                Strip::field("authorization"),
                Strip::field("x-custom"),
                Strip::query("token"),
            ])
            .unwrap();
        assert_eq!(
            k.hand_in(MESSAGES, MESSAGES, unit, sanitized.clone()).0,
            FLOW_CONTINUE
        );
        let receipt = k.inbound.claim_request(OWNER, 1, 1, &sanitized).unwrap();
        let observed = Arc::new(Mutex::new(None));
        let held = Arc::clone(&observed);
        let handle = Arc::new(crate::state::AppHandle::new(app));
        let routes: &'static crate::core_routes::CoreRouteTable = Box::leak(Box::default());
        let router = axum::Router::new()
            .route(
                MESSAGES,
                axum::routing::post(move |req: axum::extract::Request| {
                    let held = Arc::clone(&held);
                    async move {
                        let consumed = req
                            .extensions()
                            .get::<crate::auth::ConsumedCredentials>()
                            .expect("the gate supplied credentials");
                        let mut plane_headers = req.headers().clone();
                        consumed.strip(&mut plane_headers);
                        assert!(!plane_headers.contains_key("authorization"));
                        assert!(!plane_headers.contains_key("x-custom"));
                        assert_eq!(req.uri().query(), Some("keep=1"));
                        let egress = consumed
                            .caller
                            .as_ref()
                            .map(|caller| caller.lend().expose(&crate::seal::lend()).clone());
                        *held.lock().unwrap() = Some(egress);
                        axum::http::StatusCode::OK
                    }
                }),
            )
            .layer(axum::middleware::from_fn_with_state(
                handle.clone(),
                move |app: crate::state::CurrentApp,
                      req: axum::extract::Request,
                      next: axum::middleware::Next| {
                    crate::auth::auth_middleware(app, routes, req, next)
                },
            ))
            .with_state(handle);
        let mut request = axum::http::Request::builder()
            .method("POST")
            .uri(sanitized.path_and_query())
            .body(axum::body::Body::empty())
            .unwrap();
        for (name, value) in &sanitized.fields {
            request.headers_mut().append(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                axum::http::HeaderValue::from_bytes(value).unwrap(),
            );
        }
        request.extensions_mut().insert(receipt);
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK, "{carrier}");
        assert_eq!(
            *observed.lock().unwrap(),
            Some(verified.map(|s| s.as_bytes().to_vec())),
            "{carrier}"
        );
    }
}

#[test]
fn authenticated_framing_fields_cannot_disappear_before_hand_in_or_claim() {
    let script = Script::new(
        AuthPoints::HEAD,
        identity("signed-caller", "credential"),
        vec![Strip::field("authorization".to_string())],
    );
    let k = kit(&[("a", Arc::clone(&script))]);
    let listener = k.inbound.table(OWNER, GEN).unwrap().listener.clone();
    k.inbound.install_at(OWNER, 71, GEN, listener).unwrap();
    k.inbound.framing_started(OWNER, 71, 1, GEN).unwrap();
    k.inbound.grant_stream(OWNER, 1, 1, GEN).unwrap();
    let original = post(
        MESSAGES,
        &[
            ("authorization", "credential"),
            ("connection", "close, x-signed"),
            ("content-length", "3"),
            ("x-signed", "first"),
            ("x-signed", "second"),
        ],
        Some("x=1"),
    );
    let answer = k
        .call(MESSAGES, UnitRef::NONE, POINT_HEAD, original.clone())
        .unwrap();
    assert_eq!(answer.flow, FLOW_CONTINUE);
    let admitted = original.stripped(&answer.strips).unwrap();
    for removed in ["connection", "content-length", "x-signed"] {
        let mut changed = admitted.clone();
        changed.fields.retain(|(name, _)| name != removed);
        assert_eq!(
            k.hand_in(MESSAGES, MESSAGES, answer.unit, changed).0,
            FLOW_STOP,
            "auth permits only its own declared credential strip: {removed}"
        );
    }
    assert_eq!(
        k.hand_in(MESSAGES, MESSAGES, answer.unit, admitted.clone())
            .0,
        FLOW_CONTINUE
    );
    for removed in ["connection", "content-length", "x-signed"] {
        let mut changed = admitted.clone();
        changed.fields.retain(|(name, _)| name != removed);
        assert!(
            k.inbound.claim_request(OWNER, 1, 1, &changed).is_err(),
            "emission cannot delete an admitted field: {removed}"
        );
    }
    let receipt = k.inbound.claim_request(OWNER, 1, 1, &admitted).unwrap();
    assert!(
        matches!(receipt.verdict(), crate::auth::ChainVerdict::Identified { principal, .. }
        if principal.id == "signed-caller")
    );
    assert_eq!(script.calls(), 1);
    assert!(
        k.inbound.claim_request(OWNER, 1, 1, &admitted).is_err(),
        "claim remains single-use"
    );
}
