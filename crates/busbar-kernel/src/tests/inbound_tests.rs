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
    kit_over(
        crate::test_support::TestApp::new().build(),
        names,
        points,
        auths,
    )
}

/// [`kit`] over `app`, its lines' chain `names` at `points`, the opened `auths` among them.
fn kit_over(
    app: Arc<App>,
    names: Vec<String>,
    points: AuthPoints,
    auths: &[(&str, Arc<Script>)],
) -> Kit {
    kit_signed(app, names, points, auths, kin_unsigned())
}

/// No path is answered by a dialect that signs.
fn kin_unsigned() -> SignedIngress {
    Arc::new(|_: &App, _: &str| false)
}

/// [`kit_over`], its paths' signing answered by `signed`.
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
                    deadline: None,
                },
                Box::new(|_: Result<Answer, &'static str>| {
                    panic!("every scripted verify answers at once")
                }),
            )
            .expect("answered at once")
    }

    /// `auth.call` on connection `conn`, with the op's `deadline`.
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

    /// `unit.hand_in` on connection `conn`.
    fn hand_in_on(&self, conn: u64, path: &str, unit: UnitRef, head: Head) -> (u32, UnitRef) {
        self.inbound
            .hand_in(HandIn {
                owner: OWNER,
                generation: GEN,
                auth: self.id(path),
                unit,
                line: self.line(path),
                conn,
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
        signed_ingress: kin_unsigned(),
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

// ── the peer point, the op's deadline, and the `keys` arm ────────────────────────────────────

/// RED (l.973-978, the Peer rule): a peer-point call answers ONLY continue or stop, with no unit
/// and no name, even when the auth named lines; its verdict is the connection's, applied to the
/// unit handed in on that connection, and to no unit on another connection.
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
    // A peer refusal stops, and still names nothing.
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

/// RED (the Peer rule, the call's side): a peer-point call that presents any byte of a request, or
/// a unit, is refused before any auth runs.
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

/// RED (deadline classes: the ticket the call pends on was minted for the framer op with its
/// class): past the op's deadline no verify runs, and the call answers stop.
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

/// A governance with a signer, as the `keys` arm verifies against.
fn signing_gov() -> Arc<crate::governance::GovState> {
    let signer = crate::governance::signing::TokenSigner::from_secret_bytes(
        &[7u8; 32],
        crate::governance::signing::DEFAULT_KID,
    );
    Arc::new(
        crate::governance::GovState::new_with_signer(
            Arc::new(crate::governance::MemoryStore::new()),
            Some("admintok".to_string()),
            Some(signer),
        )
        .expect("a governance"),
    )
}

/// A signed key minted on `gov` at `now`, standing until `exp`: (its id, its token).
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

/// A kit whose chain is the `keys` arm alone, over `gov`.
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

/// The kernel's `keys` arm through the inbound handle over `head`: (flow, unit).
fn spend(k: &Kit, head: Head) -> (u32, UnitRef) {
    let ans = k
        .call(MESSAGES, UnitRef::NONE, POINT_HEAD, head)
        .expect("answered");
    (ans.flow, ans.unit)
}

/// RED (oracle `auth.lifecycle__key-revoke`): a live signed key is admitted first-hand with the
/// governance key it resolves; once revoked, the same token is a stop, refused with the 401 the
/// auth gate answers on the path. The answer names the carriers, never the token.
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

/// RED (oracle `auth.lifecycle__key-rotate`): after a rotation the old token is a stop and the
/// rotated one is admitted.
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

/// RED (oracle `auth.lifecycle__key-expiry`): a key past its expiry is a stop.
#[test]
fn red_keys_an_expired_key_is_refused() {
    let gov = signing_gov();
    let now = crate::store::now();
    let (_, token) = minted(&gov, now - 60, now - 3_600);
    let k = keys_kit(&gov);
    assert_eq!(spend(&k, bearer(&token)).0, FLOW_STOP);
}

/// RED (oracle `http.crosscut__x-api-key-only__bad`): a bad credential on the second carrier
/// alone is a stop, refused with the gate's 401; no credential at all is a stop too.
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

/// RED (oracle `http.crosscut__bearer-and-x-api-key`): with both carriers presented the carriers'
/// order decides, as 1.5.5's gate read them: a valid bearer admits beside a stray `x-api-key`,
/// and both carriers are named to strip.
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
    // Handed in with the carriers still on it: stopped (c); stripped: admitted.
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

// ── the host-held credentials' verifier ahead of the `keys` arm (1.5.5's signed-ingress step) ──
//
// The 1.5.5 oracle exercises it in the signed-ingress dialect's request cells (`llm__<signing
// dialect>__*__request__*`, admitted, unauthenticated) and, over the size gate, in
// `http.crosscut__413__*`. The dialect is the registry's declared fact, so these cells answer it
// through the listener's `signed_ingress`.

/// The carrier a test verifier's credential sits on.
const SIGNED_LINE: &str = "x-signed-credential";

/// A kit whose chain is `keys` with `reader` as its host-held credentials' verifier reading the
/// issued kind, over `gov`; every path is answered by a dialect that signs when `signs`.
fn reader_kit(gov: &Arc<crate::governance::GovState>, reader: Arc<Script>, signs: bool) -> Kit {
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

/// A key minted with the issued credential: (its id, the credential's public id).
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

/// RED (signed ingress, admitted): a verifier's identity is the governance key holding that
/// credential, held first-hand; the verifier's named lines and the carriers are named to strip.
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

/// RED (signed ingress, unauthenticated): a signature the verifier rejects is a stop, refused with
/// the gate's 401; so is a verified credential whose key was revoked.
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

/// RED (1.5.5's order): a verifier that passes leaves the token path to decide: a valid bearer
/// admits, none stops; on a dialect that does not sign the verifier is never asked.
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

/// RED (`http.crosscut__413__*`): a signed body past the line's size gate is refused before any
/// verdict, with the 413 the data router answers on the path.
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

// ── the connection's end ─────────────────────────────────────────────────────────────────────

/// RED (the host's end notification): N connections that each end leave no peer verdict held,
/// and a live connection's verdict survives any number of others ending (and still admits).
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
        k.inbound.connection_ended(OWNER, conn);
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
        k.inbound.connection_ended(OWNER, conn);
    }
    assert_eq!(k.inbound.peer_verdicts(), 1);
    let (flow, _) = k.hand_in_on(7, MESSAGES, UnitRef::NONE, post(MESSAGES, &[], None));
    assert_eq!(flow, FLOW_CONTINUE, "the live connection lost its verdict");
    k.inbound.connection_ended(OWNER, 7);
    let (flow, _) = k.hand_in_on(7, MESSAGES, UnitRef::NONE, post(MESSAGES, &[], None));
    assert_eq!(flow, FLOW_STOP);
}

/// RED (the bound, LOUD): at [`PEER_CONNECTIONS_MAX`] held verdicts a NEW connection's peer call
/// is refused by name, and no held verdict is evicted for it.
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
