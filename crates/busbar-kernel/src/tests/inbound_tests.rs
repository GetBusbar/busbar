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

/// The role every scripted identity carries ([`identity`]), bound under each scripted auth's name
/// in the kit's `role_bindings` (all pools, no group), as a deployed IdP's role must be: an
/// identity that earns no governance key is refused `NoGrant`.
const ROLE: &str = "member";

/// The `role_bindings` table binding [`ROLE`] under each of `names`.
fn bound(names: &[String]) -> crate::config::RoleBindings {
    names
        .iter()
        .map(|n| {
            (
                n.clone(),
                std::iter::once((ROLE.to_string(), crate::config::RoleBindingCfg::default()))
                    .collect(),
            )
        })
        .collect()
}

/// A kit whose data listener holds `MESSAGES` and `OTHER` (POST, the chain `auths` in order, at
/// the union of their points) and `HEALTHZ` (GET, `none`), for `OWNER` at `GEN`; each auth's
/// [`ROLE`] is bound.
fn kit(auths: &[(&str, Arc<Script>)]) -> Kit {
    kit_gated(auths, None)
}

/// [`kit`], its listener's admission gate `admission`.
fn kit_gated(auths: &[(&str, Arc<Script>)], admission: Option<Arc<AdmissionGate>>) -> Kit {
    let names: Vec<String> = auths.iter().map(|(n, _)| (*n).to_string()).collect();
    let points = AuthPoints(auths.iter().fold(0, |p, (_, s)| p | s.points.bits()));
    kit_with(
        crate::test_support::TestApp::new()
            .role_bindings(bound(&names))
            .build(),
        names,
        points,
        auths,
        kin_unsigned(),
        admission,
        None,
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
    kit_with(app, names, points, auths, signed, None, None)
}

/// [`kit_signed`], its listener's admission gate `admission`.
fn kit_with(
    app: Arc<App>,
    names: Vec<String>,
    points: AuthPoints,
    auths: &[(&str, Arc<Script>)],
    signed: SignedIngress,
    admission: Option<Arc<AdmissionGate>>,
    door_refuser: Option<crate::plane_routes::PlaneRefuseByPathFn>,
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
        admission: admission.clone(),
        door_refuser: door_refuser.clone(),
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

/// An identity carrying [`ROLE`], which the kit binds: it earns a governance key.
fn identity(subject: &str, credential: &str) -> Verified {
    Verified::Identity(VerifiedIdentity {
        subject: subject.to_string(),
        credential: Some(Secret::new(credential.to_string())),
        groups: vec![ROLE.to_string()],
        ..VerifiedIdentity::default()
    })
}

/// An identity carrying no role: it earns no governance key (`NoGrant`).
fn ungranted(subject: &str) -> Verified {
    Verified::Identity(VerifiedIdentity {
        subject: subject.to_string(),
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
    // The unit is gone: presenting it again is refused.
    assert_eq!(
        k.inbound
            .refuse(Refuse {
                owner: OWNER,
                generation: GEN,
                unit: ans.unit,
                cause: REFUSE_STOPPED,
                line: k.line(MESSAGES),
                request: None,
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
        admission: None,
        door_refuser: None,
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
// The 1.5.5 oracle exercises it in the signed-ingress dialect's request cells (`<plane>__<signing
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
    // A recoverable credential is stored sealed, so the governance holds at-rest keys.
    gov.set_at_rest_keys(Some(crate::governance::at_rest::AtRestKeys::new(
        &[3u8; 32], None,
    )));
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

// ── the connection's end ─────────────────────────────────────────────────────────────────────

/// RED (the host's end notification, keyed by the host's framing): N framings that each end leave
/// no peer verdict held, and a live framing's verdict survives any number of others ending (and
/// still admits).
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

/// RED (the framing is the host's, the connection the transport's word): a call naming another
/// connection than its framing's earlier calls named is refused, at the call and at the hand-in.
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
    // Once the framing ends, its connection is no longer held.
    k.inbound.framing_ended(40);
    assert!(call(40, 6).is_ok());
}

/// RED (ruling 1: `UnitRefuseIn::request`): a refusal with no unit is shaped by the REQUEST's
/// path, as 1.5.5's router shaped it, not by the line's or the listener's root: a no-route, a
/// method miss and an over-gate body on a path under the native API's root answer its envelope,
/// and on any other path the data plane's.
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
            crate::taxonomy::ERR_TYPE_NOT_FOUND,
            "the requested resource was not found",
        ),
        (
            REFUSE_METHOD_MISS,
            k.line(MESSAGES),
            StatusCode::METHOD_NOT_ALLOWED,
            crate::taxonomy::ERR_TYPE_INVALID_REQUEST,
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

/// RED (/status row 192 B; THE DESIGN §6 steps 3 and 4): the guest list a listener's transport is
/// lent is the list installed under THAT transport's identity, at that generation: every line's
/// spec beside its own route, in the list's match order. No other owner, and no other generation,
/// is lent it.
#[test]
fn red_a_listeners_guest_list_is_lent_to_its_own_transport_alone() {
    let a = Script::new(AuthPoints::HEAD, Verified::Pass, Vec::new());
    let k = kit(&[("a", a)]);
    let lent = k
        .inbound
        .lent(OWNER, GEN)
        .expect("the owner's list is lent");
    let specs = k.inbound.specs(OWNER, GEN).expect("installed");
    let routes: Vec<Route> = k
        .inbound
        .table(OWNER, GEN)
        .expect("installed")
        .listener
        .guests
        .lines()
        .iter()
        .map(|l| l.route.clone())
        .collect();
    assert_eq!(
        lent,
        specs.into_iter().zip(routes).collect::<Vec<_>>(),
        "each line's spec beside its own route, in match order"
    );
    assert!(
        k.inbound.lent(0, GEN).is_none(),
        "the root's identity holds no listener's list"
    );
    assert!(
        k.inbound.lent(OWNER + 9, GEN).is_none(),
        "another owner is lent nothing"
    );
    assert!(
        k.inbound.lent(OWNER, GEN + 1).is_none(),
        "nor another generation"
    );
}

/// RED (/status row 192 B, the unit's pairing): a hand-in names the stream its request arrived on
/// (`HandIn::stream`), and the kernel keeps where each unit was handed in, so the request the
/// connector carries on (owner, framing, stream) pairs with the unit the kernel admitted it as;
/// another stream, framing or owner names none.
#[test]
fn red_a_hand_in_keeps_the_stream_its_request_arrived_on() {
    let a = Script::new(AuthPoints::HEAD, Verified::Reject, Vec::new());
    let k = kit(&[("a", a)]);
    let mut get = post(HEALTHZ, &[], None);
    get.method = "GET".to_string();
    let (flow, unit) = k
        .inbound
        .hand_in(HandIn {
            owner: OWNER,
            generation: GEN,
            auth: k.id(HEALTHZ),
            unit: UnitRef::NONE,
            line: k.line(HEALTHZ),
            conn: 3,
            stream: 5,
            framing: Some(30),
            head: get,
        })
        .expect("handed in");
    assert_eq!(flow, FLOW_CONTINUE);
    assert_eq!(k.inbound.handed_on(OWNER, 30, 5), Some(unit.id));
    assert_eq!(k.inbound.handed_on(OWNER, 30, 7), None, "another stream");
    assert_eq!(k.inbound.handed_on(OWNER, 31, 5), None, "another framing");
    assert_eq!(k.inbound.handed_on(OWNER + 1, 30, 5), None, "another owner");
}

/// RED (/status row 192 B; THE DESIGN §6 item 1, "HeadBody includes the head, so a set never
/// holds both"; `check_points`): a line whose chain needs the head point and the body point is
/// lent as needing the BODY point alone (a set the line table accepts, `check::check_lines`), and
/// the call the transport makes there judges the whole chain: the auth that needs the head is
/// answered at the body point, which includes the head.
#[test]
fn red_a_line_needing_head_and_body_is_lent_its_body_point_and_judged_whole_there() {
    let a = Script::new(AuthPoints::HEAD, identity("alice", "k-1"), Vec::new());
    let b = Script::new(AuthPoints::HEAD_BODY, Verified::Pass, Vec::new());
    let k = kit(&[("a", Arc::clone(&a)), ("b", Arc::clone(&b))]);
    let spec = k.inbound.specs(OWNER, GEN).expect("installed")[k.line(MESSAGES) as usize];
    assert_eq!(spec.points, POINT_HEAD_BODY, "lent at the body point alone");
    assert!(
        busbar_contract::abi::auth::check_points(spec.points, false).is_ok(),
        "a point set the line table accepts"
    );
    assert_ne!(
        spec.body_limit, 0,
        "held to the size gate at the body point"
    );
    let answered = k
        .call(
            MESSAGES,
            UnitRef::NONE,
            POINT_HEAD_BODY,
            post(MESSAGES, &[], None),
        )
        .expect("answered");
    assert_eq!(answered.flow, FLOW_CONTINUE);
    assert_eq!(
        a.calls(),
        1,
        "the head auth is judged at the body point, which includes the head"
    );
    assert_eq!(
        b.calls(),
        0,
        "the head auth's identity fixed the verdict first"
    );
}

/// RED (/status row 192 B; 1.5.5 parity, `crates/busbar/src/config_validate/mod.rs:1440-1445` at
/// v1.5.5: a request-body limit below the floor, 0 included, is refused at config load): a listener
/// table whose size gate is 0 while a line holds the body point is refused at install with 1.5.5's
/// text for 0, and nothing is installed, so no body-point line is ever lent a 0 limit. The config
/// path refuses the same 0 with the same text.
#[test]
fn red_a_listener_table_with_a_zero_body_limit_is_refused_as_1_5_5_refused_it() {
    let a = Script::new(AuthPoints::HEAD_BODY, Verified::Pass, Vec::new());
    let k = kit(&[("a", a)]);
    let table = k.inbound.table(OWNER, GEN).expect("installed");
    let with = |body_limit: u64| Listener {
        guests: table.listener.guests.clone(),
        auths: HashMap::new(),
        body_limit,
        app: Arc::clone(&k.app),
        door_refusals: Vec::new(),
        ids: line_ids(3),
        signed_ingress: kin_unsigned(),
        admission: None,
        door_refuser: None,
    };
    assert_eq!(
        k.inbound.install(OWNER + 9, GEN, with(0)),
        Err(BODY_LIMIT_ZERO)
    );
    assert!(
        k.inbound.specs(OWNER + 9, GEN).is_none(),
        "a refused table was installed"
    );
    assert_eq!(k.inbound.install(OWNER + 9, GEN, with(16)), Ok(()));
    let mut errors = Vec::new();
    crate::config_validate::validate_limits(
        &crate::config::LimitsResolved {
            request_body_max_bytes: 0,
            ..crate::config::LimitsResolved::default()
        },
        &mut errors,
    );
    assert!(
        errors.iter().any(|e| e == BODY_LIMIT_ZERO),
        "the config path refuses 0 with the same text: {errors:?}"
    );
}

// ── row 192 C, the kernel's inbound part: the root takes up a handed-in unit ─────────────────

/// `unit.hand_in` for a `none` line's GET on framing `framing`, stream `stream`.
fn hand_in_none(k: &Kit, framing: u64, stream: u64) -> (u32, UnitRef) {
    let mut get = post(HEALTHZ, &[], None);
    get.method = "GET".to_string();
    k.inbound
        .hand_in(HandIn {
            owner: OWNER,
            generation: GEN,
            auth: k.id(HEALTHZ),
            unit: UnitRef::NONE,
            line: k.line(HEALTHZ),
            conn: framing,
            stream,
            framing: Some(framing),
            head: get,
        })
        .expect("handed in")
}

/// RED (/status row 192 C): the root TAKES UP the unit handed in on (owner, framing, stream): the
/// unit, its line (the root dispatches by the line's claimant) and its generation. Taking consumes
/// the record [`Inbound::handed_on`] reads, so a request is driven once; the unit itself stays
/// live until it exits. A hand-in the kernel stopped records nothing to take up.
#[test]
fn red_take_handed_consumes_the_record_handed_on_reads() {
    let a = Script::new(AuthPoints::HEAD, Verified::Reject, Vec::new());
    let k = kit(&[("a", a)]);
    let (flow, unit) = hand_in_none(&k, 30, 5);
    assert_eq!(flow, FLOW_CONTINUE);
    assert_eq!(
        k.inbound.take_handed(OWNER + 1, 30, 5),
        None,
        "another owner"
    );
    assert_eq!(k.inbound.take_handed(OWNER, 30, 6), None, "another stream");
    assert_eq!(
        k.inbound.take_handed(OWNER, 30, 5),
        Some(Handed {
            unit: unit.id,
            line: k.line(HEALTHZ),
            generation: GEN,
        })
    );
    assert_eq!(
        k.inbound.handed_on(OWNER, 30, 5),
        None,
        "the record was read again"
    );
    assert_eq!(k.inbound.take_handed(OWNER, 30, 5), None, "taken twice");
    assert!(
        k.inbound.unit_secret(OWNER, unit.id).is_some(),
        "taking the record ended the unit"
    );
    k.inbound.exit(unit.id);
    assert!(k.inbound.unit_secret(OWNER, unit.id).is_none());
    // A stopped hand-in (an auth line with no verdict) leaves nothing to take up.
    let (flow, _) = k
        .inbound
        .hand_in(HandIn {
            owner: OWNER,
            generation: GEN,
            auth: k.id(MESSAGES),
            unit: UnitRef::NONE,
            line: k.line(MESSAGES),
            conn: 31,
            stream: 1,
            framing: Some(31),
            head: post(MESSAGES, &[], None),
        })
        .expect("handed in");
    assert_eq!(flow, FLOW_STOP);
    assert_eq!(k.inbound.take_handed(OWNER, 31, 1), None);
}

/// RED (/status row 192 C, the door's caller): `door_ctx` projects the unit's first-hand verdict
/// exactly as the data-plane gate resolves a chain verdict (`auth::resolve_data_plane_identity`):
/// a plugin identity is its principal and the key its bound role earns; a `keys` identity is the
/// governance key it resolved; a `none` line is the anonymous caller; a unit with no identity is
/// refused. The credential comes with it, a redacted secret.
#[test]
fn red_door_ctx_projects_the_verdict_as_the_data_plane_gate_resolves_it() {
    let a = Script::new(AuthPoints::HEAD, identity("alice", "sk-1"), Vec::new());
    let k = kit(&[("a", a)]);
    let ans = k
        .call(
            MESSAGES,
            UnitRef::NONE,
            POINT_HEAD,
            post(MESSAGES, &[], None),
        )
        .unwrap();
    let (principal, ctx, credential) = k.inbound.door_ctx(ans.unit.id, &k.app).expect("admitted");
    let (want_principal, want_ctx) = crate::auth::resolve_data_plane_identity(
        &k.app,
        crate::auth::ChainVerdict::Identified {
            module: "a".to_string(),
            principal: crate::auth::Principal {
                id: "alice".to_string(),
                name: None,
                roles: vec![ROLE.to_string()],
                ttl_secs: None,
            },
            resolved: None,
        },
    )
    .expect("the gate admits it");
    assert_eq!(principal.0, want_principal.0);
    let key = |c: &crate::governance::PlaneRequestCtx| {
        c.key
            .as_ref()
            .map(|k| (k.id.clone(), k.generation_hash.clone()))
    };
    assert!(key(&ctx).is_some(), "the bound role earned no key");
    assert_eq!(key(&ctx), key(&want_ctx));
    assert_eq!(
        credential.map(|c| c.expose(&crate::seal::lend()).clone()),
        Some(b"sk-1".to_vec())
    );
    // The `keys` arm: the governance key it resolved.
    let gov = signing_gov();
    let now = crate::store::now();
    let (id, token) = minted(&gov, now + 3_600, now);
    let kk = keys_kit(&gov);
    let ans = kk
        .call(MESSAGES, UnitRef::NONE, POINT_HEAD, bearer(&token))
        .unwrap();
    let (principal, ctx, _) = kk.inbound.door_ctx(ans.unit.id, &kk.app).expect("admitted");
    assert_eq!(principal.0.as_ref().map(|p| p.id.clone()), Some(id.clone()));
    assert_eq!(ctx.key.as_ref().map(|key| key.id.clone()), Some(id));
    // A `none` line: the anonymous caller, as the open front door.
    let (_, unit) = hand_in_none(&k, 40, 1);
    let (principal, ctx, credential) = k.inbound.door_ctx(unit.id, &k.app).expect("open");
    assert!(principal.0.is_none());
    assert!(ctx.key.is_none());
    assert!(credential.is_none());
    // No identity: refused, fail closed.
    let r = Script::new(AuthPoints::HEAD, Verified::Reject, Vec::new());
    let k = kit(&[("r", r)]);
    let ans = k
        .call(
            MESSAGES,
            UnitRef::NONE,
            POINT_HEAD,
            post(MESSAGES, &[], None),
        )
        .unwrap();
    assert_eq!(
        k.inbound.door_ctx(ans.unit.id, &k.app).map(|_| ()),
        Err(crate::auth::IdentityRefusal::Denied)
    );
}

/// RED (/status row 192 C; the data-plane gate's `NoGrant`): an identity that earns no governance
/// key is decided AT THE HAND-IN, before any continue: the hand-in stops, and the refusal is the
/// 401 the data-plane gate answers a `NoGrant` with on the path, byte for byte.
#[test]
fn red_a_no_grant_identity_is_stopped_at_hand_in_with_the_gates_401() {
    let a = Script::new(AuthPoints::HEAD, ungranted("nobody"), Vec::new());
    let k = kit(&[("a", a)]);
    let ans = k
        .call(
            MESSAGES,
            UnitRef::NONE,
            POINT_HEAD,
            post(MESSAGES, &[], None),
        )
        .unwrap();
    assert_eq!(ans.flow, FLOW_CONTINUE, "the chain identified it");
    assert_eq!(
        k.inbound.door_ctx(ans.unit.id, &k.app).map(|_| ()),
        Err(crate::auth::IdentityRefusal::NoGrant)
    );
    assert_eq!(
        k.hand_in(MESSAGES, MESSAGES, ans.unit, post(MESSAGES, &[], None)),
        (FLOW_STOP, ans.unit),
        "a no-grant identity was handed on"
    );
    let refusal = k.refuse(REFUSE_STOPPED, k.line(MESSAGES), ans.unit, MESSAGES);
    assert_eq!(
        refusal,
        Refusal::of(crate::auth::unauthorized_with_completion_taps(
            &k.app, MESSAGES, None
        ))
    );
    assert_eq!(refusal.status, 401);
}

/// 1.5.5's at-capacity bytes, as the outermost inbound layer shed with them.
const OVERLOADED_BODY: &str = r#"{"error":{"type":"overloaded","message":"The gateway is at capacity. Please retry shortly."}}"#;

/// RED (/status row 192 C; 1.5.5's outermost inbound cap): the admission slot is taken at the
/// request's FIRST kernel touch, ahead of any auth: with the gate full, a new request's first
/// `auth.call` stops without calling any auth, and a `none` line's hand-in stops.
#[test]
fn admission_sheds_before_any_auth_call() {
    let a = Script::new(AuthPoints::HEAD, identity("alice", "k"), Vec::new());
    let gate = admission_gate(1).expect("a gate");
    let k = kit_gated(&[("a", Arc::clone(&a))], Some(Arc::clone(&gate)));
    let first = k
        .call(
            MESSAGES,
            UnitRef::NONE,
            POINT_HEAD,
            post(MESSAGES, &[], None),
        )
        .unwrap();
    assert_eq!(first.flow, FLOW_CONTINUE);
    assert_eq!(a.calls(), 1);
    let shed = k
        .call(
            MESSAGES,
            UnitRef::NONE,
            POINT_HEAD,
            post(MESSAGES, &[], None),
        )
        .unwrap();
    assert_eq!(shed.flow, FLOW_STOP, "a request past the cap went on");
    assert!(!shed.unit.is_none(), "the shed names no unit to refuse");
    assert_eq!(a.calls(), 1, "an auth was called past the cap");
    let (flow, _) = hand_in_none(&k, 50, 1);
    assert_eq!(
        flow, FLOW_STOP,
        "a none line's request past the cap went on"
    );
}

/// RED (/status row 192 C): a shed request is refused with 1.5.5's at-capacity bytes: 503,
/// `content-type: application/json`, `retry-after: 1` and the 93-byte body, whatever the cause
/// the transport names, a no-route and a method miss among them.
#[test]
fn a_shed_answers_the_1_5_5_overloaded_bytes() {
    let a = Script::new(AuthPoints::HEAD, identity("alice", "k"), Vec::new());
    let gate = admission_gate(1).expect("a gate");
    let k = kit_gated(&[("a", a)], Some(gate));
    let held = k
        .call(
            MESSAGES,
            UnitRef::NONE,
            POINT_HEAD,
            post(MESSAGES, &[], None),
        )
        .unwrap();
    assert_eq!(held.flow, FLOW_CONTINUE);
    let shed = k
        .call(
            MESSAGES,
            UnitRef::NONE,
            POINT_HEAD,
            post(MESSAGES, &[], None),
        )
        .unwrap();
    let want = |r: &Refusal| {
        assert_eq!(r.status, 503);
        assert_eq!(r.body, OVERLOADED_BODY.as_bytes());
        assert_eq!(r.body.len(), 93);
        let field = |n: &str| {
            r.fields
                .iter()
                .find(|(f, _)| f.eq_ignore_ascii_case(n))
                .map(|(_, v)| v.clone())
        };
        assert_eq!(field("content-type"), Some(b"application/json".to_vec()));
        assert_eq!(field("retry-after"), Some(b"1".to_vec()));
        assert_eq!(
            *r,
            Refusal::of(crate::limits::admission::inbound_overloaded_response())
        );
    };
    want(&k.refuse(REFUSE_STOPPED, k.line(MESSAGES), shed.unit, MESSAGES));
    want(&k.refuse(REFUSE_NO_ROUTE, LINE_NONE, UnitRef::NONE, "/nope"));
    want(&k.refuse(
        REFUSE_METHOD_MISS,
        k.line(MESSAGES),
        UnitRef::NONE,
        MESSAGES,
    ));
    assert_eq!(
        k.refused.lock().unwrap().last().map(|r| r.status),
        Some(503)
    );
}

/// RED (/status row 192 C): the slot is given back when the unit exits and when the request is
/// refused (a unit-less refusal takes one for its own answer and gives it back), and when the
/// framing ends under a unit the root never took up.
#[test]
fn admission_is_released_at_exit_and_at_refusal() {
    let a = Script::new(AuthPoints::HEAD, identity("alice", "k"), Vec::new());
    let gate = admission_gate(1).expect("a gate");
    let k = kit_gated(&[("a", a)], Some(Arc::clone(&gate)));
    let call = || {
        k.call(
            MESSAGES,
            UnitRef::NONE,
            POINT_HEAD,
            post(MESSAGES, &[], None),
        )
        .unwrap()
    };
    let held = call();
    assert_eq!(held.flow, FLOW_CONTINUE);
    assert_eq!(gate.available_permits(), 0);
    k.inbound.exit(held.unit.id);
    assert_eq!(gate.available_permits(), 1, "the exit kept its slot");
    let held = call();
    assert_eq!(
        held.flow, FLOW_CONTINUE,
        "the slot an exit gave back was not taken"
    );
    let refused = k.refuse(REFUSE_OVER_GATE, k.line(MESSAGES), held.unit, MESSAGES);
    assert_eq!(refused.status, 413);
    assert_eq!(gate.available_permits(), 1, "the refusal kept its slot");
    let no_route = k.refuse(REFUSE_NO_ROUTE, LINE_NONE, UnitRef::NONE, "/nope");
    assert_eq!(no_route.status, 404);
    assert_eq!(
        gate.available_permits(),
        1,
        "a unit-less refusal kept a slot"
    );
    // A unit handed in and never taken up: its framing's end gives its slot back.
    let (flow, _) = hand_in_none(&k, 60, 1);
    assert_eq!(flow, FLOW_CONTINUE);
    assert_eq!(gate.available_permits(), 0);
    k.inbound.framing_ended(60);
    assert_eq!(
        gate.available_permits(),
        1,
        "an ended framing kept its slot"
    );
    // A unit the root took up is the root's to end: the framing's end leaves it.
    let (_, unit) = hand_in_none(&k, 61, 1);
    assert!(k.inbound.take_handed(OWNER, 61, 1).is_some());
    k.inbound.framing_ended(61);
    assert!(k.inbound.unit_secret(OWNER, unit.id).is_some());
    k.inbound.exit(unit.id);
    assert_eq!(gate.available_permits(), 1);
}

/// RED (/status row 192 C, the inventory's D2; `http.crosscut__413__*`): a body that grows past
/// the size gate AFTER its request was admitted at `Head` is refused with the 413 the router's
/// body-limit layer renders on the path (`router::oversized_refusal`, 1.5.5's per-dialect bytes),
/// and its unit leaves the table.
#[test]
fn red_an_over_gate_refusal_after_a_head_verdict_answers_the_routers_413() {
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
        FLOW_CONTINUE
    );
    let over = k.refuse(REFUSE_OVER_GATE, k.line(MESSAGES), ans.unit, MESSAGES);
    let handle = crate::state::AppHandle::new(Arc::clone(&k.app));
    assert_eq!(
        over,
        Refusal::of(crate::router::oversized_refusal(
            &handle, MESSAGES, MESSAGES
        ))
    );
    assert_eq!(over.status, 413);
    assert!(k.inbound.unit_secret(OWNER, ans.unit.id).is_none());
}

// ── every refusal through the very function the router answers with ─────────────────────────

/// A refusal's bytes as a client reads them off the old path: the status, the fields a refusal's
/// meaning rides on, the body.
type Read = (u16, Option<Vec<u8>>, Option<Vec<u8>>, Vec<u8>);

fn read_refusal(r: &Refusal) -> Read {
    let field = |n: &str| {
        r.fields
            .iter()
            .find(|(f, _)| f.eq_ignore_ascii_case(n))
            .map(|(_, v)| v.clone())
    };
    (
        r.status,
        field("www-authenticate"),
        field("content-type"),
        r.body.clone(),
    )
}

/// The OLD PATH's answer (the router, its auth middleware around it) to a POST on `path` carrying
/// `headers`, over `app`.
async fn old_path(app: Arc<App>, path: &str, headers: &[(&str, String)]) -> Read {
    crate::snapshot::init();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let serving = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let mut req = reqwest::Client::new()
        .post(format!("http://{addr}{path}"))
        .body("{}");
    for (n, v) in headers {
        req = req.header(*n, v);
    }
    let resp = req.send().await.unwrap();
    let field = |n: &str| resp.headers().get(n).map(|v| v.as_bytes().to_vec());
    let (status, challenge, content_type) = (
        resp.status().as_u16(),
        field("www-authenticate"),
        field("content-type"),
    );
    let body = resp.bytes().await.unwrap().to_vec();
    serving.abort();
    (status, challenge, content_type, body)
}

/// RED (/status row 192 C; THE DESIGN §6 l.962, every refusal the kernel's, byte for byte): on an
/// AUDIENCE-BOUND plane the inbound handle's refusals are the old auth middleware's own: an identity
/// that earns no grant is stopped at the hand-in and answered the RFC 6750 `insufficient_scope`
/// challenge, and a request the chain denies without a credential the bare challenge, each
/// compared against what the old path answers the same request on the same app.
#[tokio::test]
async fn red_an_audience_bound_planes_refusals_are_the_old_paths_challenges() {
    for verified in [ungranted("nobody"), Verified::Reject] {
        let a = Script::new(AuthPoints::HEAD, verified.clone(), Vec::new());
        let mut t = crate::test_support::TestApp::new().auth(Arc::new(
            crate::auth::AuthMiddleware::from_doors_for_test(vec![(
                "a".to_string(),
                Arc::clone(&a) as Arc<dyn AuthCalls>,
            )]),
        ));
        t.mount_plane("bound-plane", MESSAGES, "bound-wire");
        t.admit_plane(
            "bound-plane",
            crate::plane_driver::dispatch::PlaneAdmission {
                audience: "https://gw.example/v1/messages".to_string(),
                resource_metadata: "https://gw.example/.well-known/oauth-protected-resource"
                    .to_string(),
            },
        );
        let app = t.build();
        assert!(
            app.planes.admission_for(MESSAGES).is_some(),
            "audience-bound"
        );
        let want = old_path(Arc::clone(&app), MESSAGES, &[]).await;
        let k = kit_with(
            app,
            vec!["a".to_string()],
            AuthPoints::HEAD,
            &[("a", a)],
            kin_unsigned(),
            None,
            None,
        );
        let ans = k
            .call(
                MESSAGES,
                UnitRef::NONE,
                POINT_HEAD,
                post(MESSAGES, &[], None),
            )
            .unwrap();
        let (flow, unit) = if ans.flow == FLOW_CONTINUE {
            k.hand_in(MESSAGES, MESSAGES, ans.unit, post(MESSAGES, &[], None))
        } else {
            (ans.flow, ans.unit)
        };
        assert_eq!(flow, FLOW_STOP, "{verified:?}");
        let got = k.refuse(REFUSE_STOPPED, k.line(MESSAGES), unit, MESSAGES);
        assert!(
            want.1.is_some(),
            "the old path answered no challenge: {want:?}"
        );
        assert_eq!(read_refusal(&got), want, "{verified:?}");
    }
}

/// A door's own rendering of every kernel-shaped refusal: a 413 no kernel builder answers.
fn door_refuser() -> crate::plane_routes::PlaneRefuseByPathFn {
    Arc::new(|r: &crate::plane_routes::KernelRefusal<'_>| {
        let status = axum::http::StatusCode::from_u16(r.status).ok()?;
        Some(axum::response::IntoResponse::into_response((
            status,
            [("x-door", "own")],
            format!("door:{}:{}", r.status, r.target),
        )))
    })
}

/// RED (/status row 192 C; ARCHITECT ruling 2026-10-16, 3b B): a body past the size gate on a door's
/// path is answered by the door's own refusal hook, the same bytes the router's body-limit layer
/// renders through it (`router::oversized_refusal`), with a unit and without one.
#[test]
fn red_an_over_gate_refusal_renders_through_the_doors_own_hook() {
    let a = Script::new(AuthPoints::HEAD, identity("alice", "k"), Vec::new());
    let k = kit_with(
        crate::test_support::TestApp::new()
            .role_bindings(bound(&["a".to_string()]))
            .build(),
        vec!["a".to_string()],
        AuthPoints::HEAD,
        &[("a", a)],
        kin_unsigned(),
        None,
        Some(door_refuser()),
    );
    let handle = crate::state::AppHandle::new(Arc::clone(&k.app));
    handle.bind_door_refuser(door_refuser());
    let want = Refusal::of(crate::router::oversized_refusal(
        &handle, MESSAGES, MESSAGES,
    ));
    assert_eq!(
        want.body,
        b"door:413:/v1/messages".to_vec(),
        "the door rendered"
    );
    let unitless = k.refuse(REFUSE_OVER_GATE, k.line(MESSAGES), UnitRef::NONE, MESSAGES);
    assert_eq!(unitless, want);
    let ans = k
        .call(
            MESSAGES,
            UnitRef::NONE,
            POINT_HEAD,
            post(MESSAGES, &[], None),
        )
        .unwrap();
    let with_unit = k.refuse(REFUSE_OVER_GATE, k.line(MESSAGES), ans.unit, MESSAGES);
    assert_eq!(with_unit, want);
}

// ── the old path's judging before the chain, and the `keys` arm's audience ──────────────────

/// The audience the test plane mounted at `MESSAGES` is bound to.
const AUDIENCE: &str = "https://gw.example/v1/messages";

/// Mount a plane at `MESSAGES` and bind it to [`AUDIENCE`]: the path becomes an OAuth 2.1
/// protected resource.
fn bind_audience(t: &mut crate::test_support::TestApp) {
    t.mount_plane("bound-plane", MESSAGES, "bound-wire");
    t.admit_plane(
        "bound-plane",
        crate::plane_driver::dispatch::PlaneAdmission {
            audience: AUDIENCE.to_string(),
            resource_metadata: "https://gw.example/.well-known/oauth-protected-resource"
                .to_string(),
        },
    );
}

/// A JWS-shaped token over `claims`, never signature-checked by what reads it here.
fn jwt(claims: &serde_json::Value) -> String {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    format!(
        "{}.{}.c2ln",
        b64.encode(r#"{"alg":"ES256","typ":"at+jwt"}"#),
        b64.encode(claims.to_string())
    )
}

/// The app whose chain is the scripted `a` (its role bound) over `t`.
fn scripted(t: crate::test_support::TestApp, a: &Arc<Script>) -> crate::test_support::TestApp {
    t.auth(Arc::new(crate::auth::AuthMiddleware::from_doors_for_test(
        vec![("a".to_string(), Arc::clone(a) as Arc<dyn AuthCalls>)],
    )))
    .role_bindings(bound(&["a".to_string()]))
}

/// The inbound answer to a POST on `MESSAGES` carrying `fields`, on a kit over `app` whose line
/// chain is `names` (the opened `auths` among them): its first call, then (on a continue) its
/// hand-in, then the refusal of a stop, as a client reads it. `None` when it was handed on.
fn inbound_answer(
    app: Arc<App>,
    names: Vec<String>,
    auths: &[(&str, Arc<Script>)],
    fields: &[(&str, &str)],
) -> Option<Read> {
    let k = kit_with(
        app,
        names,
        AuthPoints::HEAD,
        auths,
        kin_unsigned(),
        None,
        None,
    );
    let ans = k
        .call(
            MESSAGES,
            UnitRef::NONE,
            POINT_HEAD,
            post(MESSAGES, fields, None),
        )
        .unwrap();
    let (flow, unit) = if ans.flow == FLOW_CONTINUE {
        // Handed in as the transport hands it: the named lines struck.
        let kept: Vec<(&str, &str)> = fields
            .iter()
            .copied()
            .filter(|(n, _)| {
                !ans.strips
                    .iter()
                    .any(|s| s.place == StripPlace::Field && s.name.eq_ignore_ascii_case(n))
            })
            .collect();
        k.hand_in(MESSAGES, MESSAGES, ans.unit, post(MESSAGES, &kept, None))
    } else {
        (ans.flow, ans.unit)
    };
    (flow == FLOW_STOP)
        .then(|| read_refusal(&k.refuse(REFUSE_STOPPED, k.line(MESSAGES), unit, MESSAGES)))
}

/// RED (/status row 192 C; RFC 9449, the old middleware's sender constraint): where this
/// deployment runs its own authorization server, a DPoP-bound token presented as a bearer is
/// refused BEFORE the chain, with the old path's bytes: the bare 401 on a residual path, the
/// `invalid_token` challenge on an audience-bound one. No auth is called for it.
#[tokio::test]
async fn red_a_dpop_bound_bearer_is_refused_with_the_old_paths_bytes() {
    let token = jwt(&serde_json::json!({ "sub": "a", "aud": AUDIENCE, "cnf": { "jkt": "abc" } }));
    let bearer = format!("Bearer {token}");
    for audience in [false, true] {
        let a = Script::new(AuthPoints::HEAD, identity("alice", "k"), Vec::new());
        let mut t = scripted(crate::test_support::TestApp::new(), &a).oauth_as_plane(Arc::new(()));
        if audience {
            bind_audience(&mut t);
        }
        let app = t.build();
        let want = old_path(
            Arc::clone(&app),
            MESSAGES,
            &[("authorization", bearer.clone())],
        )
        .await;
        let calls = a.calls();
        let got = inbound_answer(
            app,
            vec!["a".to_string()],
            &[("a", Arc::clone(&a))],
            &[("authorization", bearer.as_str())],
        );
        assert_eq!(got, Some(want), "audience-bound: {audience}");
        assert_eq!(a.calls(), calls, "an auth was called for a refused sender");
    }
}

/// RED (/status row 192 C; RFC 8707, the old middleware's audience pre-filter): on an
/// audience-bound plane a bearer busbar did not mint that is opaque, or a JWT minted for another
/// audience, is refused BEFORE the chain with the old path's `invalid_token` challenge; one bound
/// to this resource goes on to the chain, as it did there.
#[tokio::test]
async fn red_the_audience_pre_filter_refuses_with_the_old_paths_bytes() {
    let other = jwt(&serde_json::json!({ "sub": "a", "aud": "https://elsewhere.example" }));
    let ours = jwt(&serde_json::json!({ "sub": "a", "aud": AUDIENCE }));
    for (token, refused) in [
        ("opaque-token".to_string(), true),
        (other, true),
        (ours, false),
    ] {
        let bearer = format!("Bearer {token}");
        let a = Script::new(AuthPoints::HEAD, identity("alice", "k"), Vec::new());
        let mut t = scripted(crate::test_support::TestApp::new(), &a);
        bind_audience(&mut t);
        let app = t.build();
        let want = old_path(
            Arc::clone(&app),
            MESSAGES,
            &[("authorization", bearer.clone())],
        )
        .await;
        let calls = a.calls();
        let got = inbound_answer(
            app,
            vec!["a".to_string()],
            &[("a", Arc::clone(&a))],
            &[("authorization", bearer.as_str())],
        );
        if refused {
            assert!(
                want.1.is_some(),
                "the old path challenged {token}: {want:?}"
            );
            assert_eq!(got, Some(want), "{token}");
            assert_eq!(a.calls(), calls, "an auth was called for {token}");
        } else {
            assert_eq!(got, None, "a bound bearer was refused before the chain");
        }
    }
}

/// RED (/status row 192 C; the 1.6.0 plane boundary): on an audience-bound plane the `keys` arm
/// verifies against the plane's audience, as the old path's chain did: a busbar key minted with no
/// audience is refused there with the old path's `invalid_token` challenge, byte for byte.
#[tokio::test]
async fn red_the_keys_arm_verifies_against_the_planes_audience() {
    let gov = signing_gov();
    let now = crate::store::now();
    let (_, token) = minted(&gov, now + 3_600, now);
    let bearer = format!("Bearer {token}");
    let mut t = crate::test_support::TestApp::new()
        .keys_chain()
        .governance(Arc::clone(&gov));
    bind_audience(&mut t);
    let app = t.build();
    let want = old_path(
        Arc::clone(&app),
        MESSAGES,
        &[("authorization", bearer.clone())],
    )
    .await;
    assert_eq!(
        want.0, 401,
        "the old path refused an audience-less key: {want:?}"
    );
    let got = inbound_answer(
        app,
        vec![crate::config::KEYS_MODULE.to_string()],
        &[],
        &[("authorization", bearer.as_str())],
    );
    assert_eq!(got, Some(want));
}
