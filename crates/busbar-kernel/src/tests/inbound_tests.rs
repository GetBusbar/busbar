// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The inbound auth handle's kernel side (`BUSBAR-1.6.0.md` THE DESIGN §6, "Auth points and guest
//! lists", step 4, l.938-962; Part 2 #65, #74), over kind-neutral doubles: scripted auths, a
//! counting unit mint, a test MAC, and the generation's app as the test kit builds it.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

use busbar_contract::abi::auth::{AuthPoints, POINT_HEAD, POINT_HEAD_BODY, POINT_PEER};
use busbar_contract::abi::host::service::LINE_NONE;
use busbar_contract::abi::transport::route::{METHOD_GET, METHOD_POST, PATH_EXACT};
use busbar_contract::auth_calls::{VerifyAnswer, Verifying};

use super::*;
use crate::guest::{Claimant, Route};

/// One auth's double: answers every `verify` with `answer`, counting the calls and keeping the
/// field-line names it was lent.
struct Script {
    points: AuthPoints,
    answer: VerifyAnswer,
    calls: AtomicUsize,
    lent: Mutex<Vec<String>>,
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
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

/// A `verify` answered before anything crossed.
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

/// The test MAC: a keyed mix of every field the real one covers.
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

/// The kit: the kernel side, its refusals as the sink saw them, and the generation's app.
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

/// A kit whose data listener holds `MESSAGES` and `OTHER` (POST, the chain `auths` in order, at
/// the union of their points) and `HEALTHZ` (GET, `none`), for `OWNER` at `GEN`.
fn kit(auths: &[(&str, Arc<Script>)]) -> Kit {
    let names: Vec<String> = auths.iter().map(|(n, _)| (*n).to_string()).collect();
    let points = AuthPoints(auths.iter().fold(0, |p, (_, s)| p | s.points.bits()));
    let chain = LineAuth::Chain(names, points);
    let guests = GuestList::seal(vec![
        line(MESSAGES, METHOD_POST, chain.clone()),
        line(OTHER, METHOD_POST, chain),
        line(HEALTHZ, METHOD_GET, LineAuth::None),
    ])
    .expect("the list seals");
    let app = crate::test_support::TestApp::new().build();
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
    };
    inbound.install(OWNER, GEN, listener()).expect("installed");
    // The same list under another owner: a unit minted for one is not the other's.
    inbound
        .install(OWNER + 1, GEN, listener())
        .expect("installed");
    Kit {
        inbound,
        refused,
        app,
    }
}

/// `n` line ids as the root mints them: the line half of the ref-id space, not counting from `1`
/// so a line's id is never its index.
fn line_ids(n: u64) -> Vec<u64> {
    (0..n).map(|i| 7_000 + 13 * i).collect()
}

impl Kit {
    /// The handle id of the line at `path`.
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
                    head,
                    body,
                },
                Box::new(|_: Result<Answer, &'static str>| {
                    panic!("every scripted verify answers at once")
                }),
            )
            .expect("answered at once")
    }

    fn hand_in(&self, path: &str, line_path: &str, unit: UnitRef, head: Head) -> (u32, UnitRef) {
        self.inbound
            .hand_in(HandIn {
                owner: OWNER,
                generation: GEN,
                auth: self.id(path),
                unit,
                line: self.line(line_path),
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
                target: Some(target.to_string()),
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

fn names() -> Vec<Strip> {
    vec![Strip::field("authorization"), Strip::query("key")]
}

/// RED (l.949-950; #74): the request's FIRST `auth.call` mints its unit (MAC'd over the request's
/// own secret, the generation, the owner, the line and the unit); a subsequent call presents it and is
/// verified. A replayed (forged) unit, the same unit presented by another owner, and the unit
/// presented on another line are each refused.
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

/// RED (l.942-948): the verdict and the credential go to the kernel FIRST-HAND, held on the unit
/// (the credential a redacted secret, gone when the unit exits); the transport is answered only the
/// flow and the NAMES its auths named.
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

/// RED (l.921-926, 1.5.5's chain rule): the first identity admits, a pass tries the next, a reject
/// (or a verify that answered no verdict) stops before the next is called, all-pass stops, an
/// overloaded verifier stops and is refused with the 503.
#[test]
fn red_the_chain_rule_holds_in_list_order() {
    let head = || post(MESSAGES, &[], None);
    // pass, then identity: the second admits.
    let (a, b) = (
        Script::new(AuthPoints::HEAD, Verified::Pass, Vec::new()),
        Script::new(AuthPoints::HEAD, identity("bob", "k"), Vec::new()),
    );
    let k = kit(&[("a", Arc::clone(&a)), ("b", Arc::clone(&b))]);
    let ans = k.call(MESSAGES, UnitRef::NONE, POINT_HEAD, head()).unwrap();
    assert_eq!(ans.flow, FLOW_CONTINUE);
    assert_eq!(k.inbound.admitted(ans.unit.id).unwrap().provider, "b");
    assert_eq!((a.calls(), b.calls()), (1, 1));
    // reject, then identity: stopped, and the second is never called.
    let (a, b) = (
        Script::new(AuthPoints::HEAD, Verified::Reject, Vec::new()),
        Script::new(AuthPoints::HEAD, identity("bob", "k"), Vec::new()),
    );
    let k = kit(&[("a", Arc::clone(&a)), ("b", Arc::clone(&b))]);
    let ans = k.call(MESSAGES, UnitRef::NONE, POINT_HEAD, head()).unwrap();
    assert_eq!(ans.flow, FLOW_STOP);
    assert_eq!(b.calls(), 0, "a reject did not stop the chain");
    assert!(k.inbound.admitted(ans.unit.id).is_none());
    // no verdict (a failed verify) stops, fail closed.
    let a = Script::new(AuthPoints::HEAD, Verified::Failed, Vec::new());
    let k = kit(&[("a", a)]);
    assert_eq!(
        k.call(MESSAGES, UnitRef::NONE, POINT_HEAD, head())
            .unwrap()
            .flow,
        FLOW_STOP
    );
    // all pass on a non-empty list stops.
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
    // an overloaded verifier stops; its refusal is the at-capacity 503, byte for byte.
    let a = Script::new(AuthPoints::HEAD, Verified::Overloaded, Vec::new());
    let k = kit(&[("a", a)]);
    let ans = k.call(MESSAGES, UnitRef::NONE, POINT_HEAD, head()).unwrap();
    assert_eq!(ans.flow, FLOW_STOP);
    let refusal = k.refuse(REFUSE_STOPPED, k.line(MESSAGES), ans.unit, MESSAGES);
    assert_eq!(
        refusal,
        Refusal::of(crate::auth::verifier_overloaded_response())
    );
    assert_eq!(refusal.status, 503);
}

/// RED (l.924-926): at each point only the undecided auths that need it are called, and the
/// verdict is fixed in LIST order: a following auth's identity at `Head` does not admit while an
/// earlier auth that needs `HeadBody` is undecided; that auth's pass at `HeadBody` lets it stand.
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

/// RED (l.953-958 (a)): a hand-in whose handle is not the line's own, or whose line is not the
/// list's own match for the request, stops.
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
    // The handle of another line.
    assert_eq!(
        k.hand_in(OTHER, MESSAGES, ans.unit, post(MESSAGES, &[], None))
            .0,
        FLOW_STOP
    );
    // The request is not the line's: the list matches it to another line.
    assert_eq!(
        k.hand_in(MESSAGES, MESSAGES, ans.unit, post(OTHER, &[], None))
            .0,
        FLOW_STOP
    );
    // The method the line does not admit.
    let mut get = post(MESSAGES, &[], None);
    get.method = "GET".to_string();
    assert_eq!(k.hand_in(MESSAGES, MESSAGES, ans.unit, get).0, FLOW_STOP);
}

/// RED (l.955-957 (b)): a line with auth and no first-hand identity for the unit stops: a request
/// handed in with no auth call (its unit minted here) and a unit whose auth rejected.
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

/// RED (l.957-958 (c)): a name the auth named still present stops: a field line matched
/// case-insensitively, a query key case-sensitively.
#[test]
fn red_hand_in_stops_while_a_named_line_is_still_present() {
    let a = Script::new(AuthPoints::HEAD, identity("alice", "k"), names());
    let k = kit(&[("a", a)]);
    let ans = k
        .call(
            MESSAGES,
            UnitRef::NONE,
            POINT_HEAD,
            post(MESSAGES, &[], None),
        )
        .unwrap();
    let hand = |head| k.hand_in(MESSAGES, MESSAGES, ans.unit, head).0;
    assert_eq!(
        hand(post(MESSAGES, &[("Authorization", "x")], None)),
        FLOW_STOP
    );
    assert_eq!(hand(post(MESSAGES, &[], Some("a=1&key=x"))), FLOW_STOP);
    assert_eq!(
        hand(post(MESSAGES, &[], Some("Key=x&keys=1"))),
        FLOW_CONTINUE
    );
    assert_eq!(
        hand(post(MESSAGES, &[("x-other", "1")], Some("a=1"))),
        FLOW_CONTINUE
    );
}

/// RED (l.949-950): a `none` line's request is handed in with no unit, and the kernel mints it
/// there; it admits anonymously.
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

/// RED (l.950-952, l.962-964): the kernel owns every refusal, each byte-identical to the builder
/// the data router answers with today: no route (the listener's 404, no unit), a method miss
/// (405), an over-gate body (413, before any verdict) and a stop (the 401 the auth gate answers on
/// the path). A refused unit leaves the table and is reported; a request with no line has no unit.
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
            crate::taxonomy::ERR_TYPE_NOT_FOUND,
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
            crate::taxonomy::ERR_TYPE_INVALID_REQUEST,
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
            crate::proxy::KIND_REQUEST_TOO_LARGE,
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
    // The unit is gone: presenting it again is refused.
    assert_eq!(
        k.inbound
            .refuse(Refuse {
                owner: OWNER,
                generation: GEN,
                unit: ans.unit,
                cause: REFUSE_STOPPED,
                line: k.line(MESSAGES),
                target: None,
            })
            .map(|r| r.status),
        Err(UNIT_FOREIGN)
    );
}

/// THE GUARD of this module's isolation (kind-isolation #1196): the kernel side of the handle
/// names no plugin loader; the composition root glues the two.
#[test]
fn the_inbound_module_names_no_loader() {
    let source = include_str!("../inbound.rs");
    assert!(!source.contains(concat!("busbar_plugin", "_loader")));
    assert!(!source.contains(concat!("plugin", "-loader")));
}

/// RED (one type both ways, #74): a line's handle id comes from the line half of the ref-id space
/// the outbound bindings share: never `0` and never the binding bit. A table whose ids break that
/// (or repeat, or do not cover every line) is refused, and every id a transport is lent keeps the
/// top bit clear.
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
