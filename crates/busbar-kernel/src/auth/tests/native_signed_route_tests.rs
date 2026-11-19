// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A signed route end to end, as the listener runs it: a real physical arrival on a route whose
//! record admits a signed sender, the route's own chain (one auth instance that covers the body,
//! states its bound and binds each signature to a replay claim), the replay book, and the
//! physical custody a served or refused request is answered under. The signature is core's
//! Standard Webhooks check (`ingress::signed_ingress::check`), so a wrong signature, a stale
//! timestamp and a changed body are refused by real arithmetic.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use busbar_contract::crypto;
use busbar_contract::kinds::codes::KindCode;
use busbar_contract::route::{METHOD_POST, PATH_EXACT};
use busbar_contract::secure::SecureVec;
use busbar_contract::services::Caller;
use busbar_plugin_abi::auth::{FB_NEEDS_BODY, FB_NEEDS_BODY_HASH};
use busbar_plugin_abi::host_side::caller::Caller as AbiCaller;
use busbar_plugin_abi::host_side::caller::{BoxFut, InstanceLimits};
use busbar_plugin_abi::plane::{AUTH_PRINCIPAL, AUTH_SIGNED_INGRESS};
use busbar_plugin_abi::records::{tag, Records, Reply, U64Rec, Writer};
use busbar_ports::auth::{
    decode_verify_ok, AuthIn, AuthPort, LoginAnswer, LoginIn, OutboundAnswer, ServeIn, ServeOut,
    UpstreamIn, Verify, VerifyAnswer, VerifyOk,
};
use busbar_ports::PortError;

use super::*;
use crate::auth::admission_table::{decide, Admission, Decision, NotMounted, Refusal, Target};
use crate::auth::native_chain::{AuthInstance, AuthOwners, OpenedAuth};
use crate::auth::native_data::withheld_carriers;
use crate::auth::native_signed::{ChainRefused, NotCovered};
use crate::auth::reference_plane;
use crate::auth::verdicts::{VerdictPolicy, Verdicts};
use crate::guest::{Claimant, GuestList, Line, LineAuth, Route};
use crate::inbound::native::tests::{accepted, app, Transport};
use crate::inbound::native::{
    ArrivalRefusal, CompletingPhysicalRequest, PhysicalConnection, PhysicalListener, PhysicalPlan,
    StreamOwner,
};
use crate::ingress::signed_ingress::{check, TOLERANCE_S};
use crate::issued::IssuedCredentials;
use crate::limits::process_admission::{AdmissionClass, ProcessAdmission};
use crate::plane_driver::port_intents::Namespace;
use crate::plane_grants::{KeyRefresh, ReplayGuard};
use crate::plugin_records::RecordsDenied;
use crate::router::PreparedListener;
use crate::state::AppHandle;

const SECRET: &[u8] = b"a-signing-secret-of-thirty-two-b";
const BOUND: u64 = 4096;
const BODY: &[u8] = br#"{"type":"response.completed","data":{"id":"resp_1"}}"#;
const SUBJECT: &str = "webhook-signature:standard-webhooks";
const SIGNATURE_HEADER: &str = "webhook-signature";

fn now() -> u64 {
    crate::store::now()
}

fn signature(id: &str, timestamp: u64, body: &[u8]) -> String {
    let timestamp = timestamp.to_string();
    let mac = crypto::HmacSha256Key::new(SECRET)
        .expect("a usable key")
        .sign_parts(&[id.as_bytes(), b".", timestamp.as_bytes(), b".", body]);
    format!("v1,{}", STANDARD.encode(mac))
}

/// The head fields of a webhook its sender signed over `signed` at `timestamp`.
fn signed_fields(id: &str, timestamp: u64, signed: &[u8]) -> Vec<(String, Vec<u8>)> {
    vec![
        ("webhook-id".into(), id.as_bytes().to_vec()),
        (
            "webhook-timestamp".into(),
            timestamp.to_string().into_bytes(),
        ),
        (
            SIGNATURE_HEADER.into(),
            signature(id, timestamp, signed).into_bytes(),
        ),
        ("content-type".into(), b"application/json".to_vec()),
    ]
}

/// The replay book and the issued-credential owner of the route's chain.
struct Book {
    seen: Mutex<HashSet<Vec<u8>>>,
    claims: AtomicUsize,
    down: AtomicBool,
}
impl IssuedCredentials for Book {
    fn lookup<'a>(&'a self, _: u64, _: &'a str, _: &'a str) -> BoxFut<'a, SecureVec> {
        panic!("a signature verifier looks up no issued credential");
    }
}
impl ReplayGuard for Book {
    fn claim_until<'a>(
        &'a self,
        _: &'a AbiCaller<'_>,
        key: &'a [u8],
        _: u64,
    ) -> BoxFut<'a, Result<bool, RecordsDenied>> {
        self.claims.fetch_add(1, Ordering::SeqCst);
        let answer = if self.down.load(Ordering::SeqCst) {
            Err(RecordsDenied::Unavailable)
        } else {
            Ok(self.seen.lock().unwrap().insert(key.to_vec()))
        };
        Box::pin(async move { answer })
    }
    fn claim<'a>(
        &'a self,
        who: &'a AbiCaller<'_>,
        key: &'a [u8],
        ttl_s: u64,
    ) -> BoxFut<'a, Result<bool, RecordsDenied>> {
        self.claim_until(who, key, ttl_s)
    }
}

/// The route's verifier: an auth instance that reads `webhook-signature`, covers the body up to
/// [`BOUND`] and binds each verified signature to a replay claim (unless `unbound`).
struct Hook {
    calls: AtomicUsize,
    /// The body of every request `verify` was handed.
    bodies: Mutex<Vec<Vec<u8>>>,
    down: AtomicBool,
    unbound: bool,
}
fn unsupported<'a, T: Send + 'a>() -> BoxFut<'a, Result<T, PortError>> {
    Box::pin(async {
        Err(PortError::Call(
            busbar_plugin_abi::fail::CallError::NotDeclared,
        ))
    })
}
impl AuthPort for Hook {
    fn facts(&self) -> u64 {
        FB_NEEDS_BODY
    }
    fn cred_headers(&self) -> &[Box<str>] {
        static HEADERS: std::sync::OnceLock<[Box<str>; 1]> = std::sync::OnceLock::new();
        HEADERS.get_or_init(|| [SIGNATURE_HEADER.into()])
    }
    fn body_max(&self) -> Option<u64> {
        Some(BOUND)
    }
    fn issued_kind(&self) -> Option<&str> {
        None
    }
    fn verify<'a>(&'a self, _: CallCx, req: &AuthIn<'_>, _: Option<&[u8]>) -> Verify<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.bodies.lock().unwrap().push(req.body.to_vec());
        if self.down.load(Ordering::SeqCst) {
            return Verify::Done(Err(PortError::Call(
                busbar_plugin_abi::fail::CallError::NotDeclared,
            )));
        }
        if !req
            .headers
            .iter()
            .any(|line| line.name.get().eq_ignore_ascii_case(SIGNATURE_HEADER))
        {
            return Verify::Done(Ok(VerifyAnswer::NotMine));
        }
        let Some(verified) = check(SECRET, req.headers, req.body, req.now_s) else {
            return Verify::Done(Ok(VerifyAnswer::Refused {
                code: busbar_plugin_abi::auth::BAD_CREDENTIAL,
                text: "signature".into(),
            }));
        };
        let mut records = Reply::new();
        records.put_text(tag::ID_SUBJECT, SUBJECT).unwrap();
        if !self.unbound {
            let key = format!("standard-webhooks/{}/{}", verified.timestamp, verified.id);
            records
                .put_pod_tail(
                    busbar_plugin_abi::auth::tag::REPLAY,
                    &U64Rec {
                        value: TOLERANCE_S + 1,
                    },
                    key.as_bytes(),
                )
                .unwrap();
        }
        let VerifyOk::Identity(identity) =
            decode_verify_ok(Records::new(records.as_bytes())).unwrap()
        else {
            panic!("identity")
        };
        Verify::Done(Ok(VerifyAnswer::Identity(identity)))
    }
    fn login<'a>(
        &'a self,
        _: CallCx,
        _: LoginIn<'a>,
    ) -> BoxFut<'a, Result<LoginAnswer, PortError>> {
        unsupported()
    }
    fn outbound<'a>(
        &'a self,
        _: CallCx,
        _: &'a UpstreamIn<'a>,
    ) -> BoxFut<'a, Result<OutboundAnswer, PortError>> {
        unsupported()
    }
    fn refresh<'a>(&'a self, _: CallCx) -> BoxFut<'a, Result<Option<u32>, PortError>> {
        unsupported()
    }
    fn serve<'a>(
        &'a self,
        _: CallCx,
        _: &'a ServeIn<'a>,
    ) -> BoxFut<'a, Result<ServeOut, PortError>> {
        unsupported()
    }
}

fn instance(port: Arc<Hook>) -> Arc<AuthInstance> {
    Arc::new(AuthInstance {
        opened: OpenedAuth {
            who: Namespace {
                plugin: "busbar-auth-webhook-signature".into(),
                name: "webhooks".into(),
                instance: 42,
                slot: 4,
            },
            port,
            methods: busbar_plugin_abi::auth::M_VERIFY,
            out_of_process: false,
            limits: InstanceLimits::default(),
        },
        keys: Arc::new(KeyRefresh::new(Duration::from_secs(30))),
        holds: Box::default(),
    })
}

fn signed_record() -> RouteRecord {
    reference_plane::route_of(Admission::SignedIngress)
        .expect("the reference plane has a signed route")
        .record
}

/// The route as its plane declares it. `auth`: the class it is mounted under.
fn mounted_as(auth: u32) -> Mounted {
    Mounted {
        record: signed_record(),
        route: 9,
        methods: METHOD_POST,
        flags: 0,
        auth,
        effective: auth,
        pattern: "/hooks/provider".into(),
        cred_header: Some(SIGNATURE_HEADER.into()),
        catalog: false,
        resource_kinds: Vec::<Box<str>>::new().into(),
    }
}

struct Fixture {
    route: Arc<NativeSignedRoute>,
    connection: PhysicalConnection,
    budget: Arc<ProcessAdmission>,
    book: Arc<Book>,
    hook: Arc<Hook>,
}

fn fixture() -> Fixture {
    fixture_of(AUTH_SIGNED_INGRESS, false)
}

/// `auth`: the class the route is mounted under. `unbound`: the verifier states no replay claim.
fn fixture_of(auth: u32, unbound: bool) -> Fixture {
    let caller = Caller::for_test(Arc::from("plane/test"), KindCode::Plane);
    let app = app();
    let mounted = mounted_as(auth);
    let line = Line {
        route: Route {
            methods: METHOD_POST,
            path_form: PATH_EXACT,
            path: "/hooks/provider".into(),
            fields: vec![],
            rung: 9,
        },
        claimant: Claimant::Plane("plane/test".into()),
        dialect: 0,
        auth: LineAuth::Chain(
            vec!["webhooks".into()],
            busbar_contract::route::AuthPoints::EMPTY,
        ),
        upgrade: None,
        offered: busbar_contract::route::AuthPoints::EMPTY,
    };
    let port: Arc<dyn busbar_ports::transport::TransportPort> = Arc::new(Transport);
    let plan = PhysicalPlan::new(
        "listen".into(),
        port.clone(),
        GuestList::seal(vec![line.clone()]).unwrap(),
        vec![RouteBinding::plane(line, caller, mounted, vec!["webhooks".into()]).unwrap()],
    )
    .unwrap();
    let binding = plan.routes()[0].clone();
    let prepared = Arc::new(
        PreparedListener::new(
            &app,
            &crate::plugin_routes::PluginRouteTable::empty(),
            vec![],
            vec![],
            None,
            false,
        )
        .unwrap()
        .with_physical(plan)
        .unwrap(),
    );
    let listener = PhysicalListener::new(
        Arc::new(AppHandle::new(app.clone())),
        "listen".into(),
        port,
        AdmissionClass::Data,
        Arc::new(move |_, slot| (slot == "listen").then(|| prepared.clone())),
    )
    .unwrap();
    let book = Arc::new(Book {
        seen: Mutex::new(HashSet::new()),
        claims: AtomicUsize::new(0),
        down: AtomicBool::new(false),
    });
    let hook = Arc::new(Hook {
        calls: AtomicUsize::new(0),
        bodies: Mutex::new(Vec::new()),
        down: AtomicBool::new(false),
        unbound,
    });
    let owners = Arc::new(AuthOwners {
        issued: book.clone(),
        replay: book.clone(),
        cache: Arc::new(Verdicts::new(VerdictPolicy::DEFAULT)),
    });
    let chain = Arc::new(NativeChain::data(7, vec![instance(hook.clone())], owners).unwrap());
    // Candidate configuration only: every request below is a real physical arrival judged by the
    // production chain, the production ingress and the production custody.
    let route = Arc::new(NativeSignedRoute {
        withheld: withheld_carriers(&chain, Some(SIGNATURE_HEADER)),
        ingress: NativeSignedIngress::new(
            ChainSignature::bind(chain).expect("a chain of one verifier"),
            BOUND,
        ),
        record: signed_record(),
        challenge: None,
        binding,
    });
    Fixture {
        route,
        connection: listener.connect(accepted()),
        budget: ProcessAdmission::with_limits(8, 1 << 20, 1 << 18),
        book,
        hook,
    }
}

fn arrival(
    f: &Fixture,
    stream: u64,
    fields: Vec<(String, Vec<u8>)>,
    body: &[u8],
) -> (CompletingPhysicalRequest, CallCx, StreamOwner) {
    let deadline = Instant::now() + Duration::from_secs(30);
    let (request, owner) = f
        .connection
        .head(
            stream,
            {
                let mut head = crate::inbound::Head::default();
                head.method = "POST".into();
                head.target = "/hooks/provider".into();
                head.fields = fields;
                head
            },
            f.budget.try_enter(AdmissionClass::Data).unwrap(),
            Some(deadline),
        )
        .unwrap();
    let credit = request.binding().request().try_reserve(body.len()).unwrap();
    let request = request
        .finish_input(SecureVec::from(body), credit)
        .unwrap()
        .begin_completion()
        .unwrap();
    let cx = CallCx {
        deadline,
        request_id: request.binding().invocation().request_id().get(),
        stack: Default::default(),
        mono_ns: 0,
    };
    (request, cx, owner)
}

/// What the admission table answers a refused sender.
fn answered(refused: SignedRefused) -> (Refusal, bool) {
    let record = signed_record();
    let Decision::Refuse { refusal, verified } = decide(
        Target::Route(&record),
        &SignedUnserved::Refused(refused).facts(),
    ) else {
        panic!("{refused:?} is refused by the table")
    };
    (refusal, verified)
}

/// Run one arrival that must be refused: nothing of it is served, nothing of its body is reachable,
/// and the answer is the table's.
async fn refused(
    f: &Fixture,
    stream: u64,
    fields: Vec<(String, Vec<u8>)>,
    body: &[u8],
) -> SignedRefused {
    let (request, cx, _owner) = arrival(f, stream, fields, body);
    let binding = request.binding().clone();
    let SignedAnswered::Refused { owner, refused } = f.route.admit(request, cx).await.unwrap()
    else {
        panic!("the request is refused")
    };
    assert!(Arc::ptr_eq(owner.binding(), &binding));
    assert!(
        owner.signed_request().is_none() && owner.signed_subject().is_none(),
        "a refused request has no verified body to parse"
    );
    assert!(
        owner.check_executing().is_err() && binding.check_executing().is_err(),
        "a refused request executes nothing"
    );
    assert!(!owner.verified() && owner.authorization().is_none());
    refused
}

/// The one answer to a sender that is not verified: 401, core's bytes, whatever was wrong.
fn the_one_401(refused: SignedRefused) {
    let (refusal, verified) = answered(refused);
    assert!(
        matches!(refusal, Refusal::Unverified { .. }),
        "{refused:?}: {refusal:?}"
    );
    assert!(!verified, "the sender was not verified");
    let row = refusal.row(false);
    let one = Refusal::Unverified { presented: false }.row(false);
    assert_eq!(
        (
            row.status,
            row.text,
            row.challenge,
            row.by,
            row.retry_after_s
        ),
        (401, one.text, one.challenge, one.by, one.retry_after_s),
        "{refused:?} is answered the same bytes as every other denial"
    );
}

#[tokio::test]
async fn a_valid_webhook_is_admitted_and_its_body_is_reachable_only_after_verification() {
    let f = fixture();
    let (request, cx, _owner) = arrival(&f, 1, signed_fields("msg_1", now(), BODY), BODY);
    let binding = request.binding().clone();

    let SignedAnswered::Admitted(owner) = f.route.admit(request, cx).await.unwrap() else {
        panic!("a signed webhook is admitted")
    };
    assert_eq!(f.hook.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        f.hook.bodies.lock().unwrap().as_slice(),
        &[BODY.to_vec()],
        "the verifier was handed the bytes as received"
    );
    assert_eq!(
        f.book.claims.load(Ordering::SeqCst),
        1,
        "its replay was claimed once"
    );

    // The body is parsed now, from the verified value, and it is the snapshot's own bytes.
    let verified = owner
        .signed_request()
        .expect("the verified request is the only way to the body");
    assert!(std::ptr::eq(
        verified.body(),
        binding.snapshot().unwrap().body()
    ));
    let event: serde_json::Value = serde_json::from_slice(verified.body()).unwrap();
    assert_eq!(event["type"], "response.completed");
    assert_eq!(owner.signed_subject(), Some(SUBJECT));
    // A signed sender earns no key: no principal's authorization stands behind the answer.
    assert!(!owner.verified() && owner.authorization().is_none());
    assert!(Arc::ptr_eq(owner.binding(), &binding));
    assert!(owner.check_executing().is_ok());
    drop(owner);
    assert!(
        binding.check_live().is_err(),
        "dropping the owner cancels the request"
    );
}

#[tokio::test]
async fn a_wrong_signature_is_refused_with_the_one_401() {
    let f = fixture();
    // Signed for another message id: a real signature of this sender, not this request's.
    let mut fields = signed_fields("msg_other", now(), BODY);
    fields[0].1 = b"msg_1".to_vec();
    let why = refused(&f, 1, fields, BODY).await;
    assert_eq!(why, SignedRefused::BadSignature);
    the_one_401(why);
    assert_eq!(
        f.book.claims.load(Ordering::SeqCst),
        0,
        "nothing unverified claims a replay key"
    );
}

#[tokio::test]
async fn a_stale_timestamp_is_refused_with_the_one_401() {
    let f = fixture();
    let stale = now() - TOLERANCE_S - 60;
    let why = refused(&f, 1, signed_fields("msg_1", stale, BODY), BODY).await;
    assert_eq!(why, SignedRefused::BadSignature);
    the_one_401(why);
    assert_eq!(f.book.claims.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_replay_is_refused_with_the_one_401() {
    let f = fixture();
    let fields = signed_fields("msg_1", now(), BODY);
    let (request, cx, _first) = arrival(&f, 1, fields.clone(), BODY);
    assert!(matches!(
        f.route.admit(request, cx).await.unwrap(),
        SignedAnswered::Admitted(_)
    ));
    // The same bytes again, on another stream: verified, and already seen.
    let why = refused(&f, 3, fields, BODY).await;
    assert_eq!(why, SignedRefused::Replayed);
    the_one_401(why);
    assert_eq!(f.hook.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_modified_body_is_refused_and_is_never_handed_on() {
    let f = fixture();
    let changed = br#"{"type":"response.completed","data":{"id":"resp_2"}}"#;
    let why = refused(&f, 1, signed_fields("msg_1", now(), BODY), changed).await;
    assert_eq!(why, SignedRefused::BadSignature);
    the_one_401(why);
    assert_eq!(f.book.claims.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_body_over_the_bound_is_refused_before_any_verifier_runs() {
    let f = fixture();
    let long = vec![b'a'; usize::try_from(BOUND).unwrap() + 1];
    // Its signature is right: the bound is what refuses it.
    let why = refused(&f, 1, signed_fields("msg_1", now(), &long), &long).await;
    assert_eq!(why, SignedRefused::TooLarge);
    assert_eq!(
        f.hook.calls.load(Ordering::SeqCst),
        0,
        "no verifier was handed a body longer than it said its signature covers"
    );
    assert_eq!(f.book.claims.load(Ordering::SeqCst), 0);
    let (refusal, verified) = answered(why);
    assert_eq!(refusal, Refusal::BodyTooLarge);
    assert!(!verified, "core answers it: nobody was verified");
    assert_eq!(refusal.row(false).status, 413);

    // Exactly the bound is read and judged.
    let at = vec![b'a'; usize::try_from(BOUND).unwrap()];
    let (request, cx, _owner) = arrival(&f, 3, signed_fields("msg_2", now(), &at), &at);
    assert!(matches!(
        f.route.admit(request, cx).await.unwrap(),
        SignedAnswered::Admitted(_)
    ));
}

#[tokio::test]
async fn a_signature_bound_to_no_replay_claim_is_refused() {
    let f = fixture_of(AUTH_SIGNED_INGRESS, true);
    // The verifier accepts the signature and states no claim for it: it could be sent twice.
    let why = refused(&f, 1, signed_fields("msg_1", now(), BODY), BODY).await;
    assert_eq!(why, SignedRefused::NoReplayBound);
    the_one_401(why);
    assert_eq!(f.hook.calls.load(Ordering::SeqCst), 1);
    assert_eq!(f.book.claims.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_request_with_no_signature_is_refused_with_the_one_401() {
    let f = fixture();
    let fields = vec![("content-type".to_string(), b"application/json".to_vec())];
    let why = refused(&f, 1, fields, BODY).await;
    assert_eq!(why, SignedRefused::NotSigned);
    the_one_401(why);
}

#[tokio::test]
async fn a_verifier_or_replay_store_that_cannot_answer_is_503_never_401() {
    let f = fixture();
    f.hook.down.store(true, Ordering::SeqCst);
    let why = refused(&f, 1, signed_fields("msg_1", now(), BODY), BODY).await;
    assert_eq!(why, SignedRefused::Unavailable);
    let (refusal, verified) = answered(why);
    assert_eq!(refusal, Refusal::VerifierUnavailable);
    assert!(!verified);
    assert_eq!(refusal.row(false).status, 503);

    f.hook.down.store(false, Ordering::SeqCst);
    f.book.down.store(true, Ordering::SeqCst);
    let why = refused(&f, 3, signed_fields("msg_2", now(), BODY), BODY).await;
    assert_eq!(
        why,
        SignedRefused::Unavailable,
        "a replay book that cannot answer admits nothing and denies nothing"
    );
    assert_eq!(answered(why).0.row(false).status, 503);
}

#[tokio::test]
async fn request_trailers_are_refused_by_core_before_any_verifier() {
    let f = fixture();
    let (request, _cx, _owner) = arrival(&f, 1, signed_fields("msg_1", now(), BODY), BODY);
    let binding = request.binding().clone();
    let record = signed_record();
    let Decision::Refuse { refusal, verified } =
        decide(Target::Route(&record), &SignedUnserved::Trailers.facts())
    else {
        panic!("trailers are refused")
    };
    assert_eq!(refusal, Refusal::Trailers);
    assert!(!verified);
    let owner = f.route.refuse_unread(request, SignedUnserved::Trailers).unwrap();
    assert!(owner.signed_request().is_none());
    assert!(binding.check_executing().is_err());
    assert_eq!(f.hook.calls.load(Ordering::SeqCst), 0);
    assert_eq!(f.book.claims.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_verified_value_of_another_request_completes_nothing() {
    let f = fixture();
    let (first, cx, _a) = arrival(&f, 1, signed_fields("msg_1", now(), BODY), BODY);
    let (second, _, _b) = arrival(&f, 3, signed_fields("msg_2", now(), BODY), BODY);
    let received = ChainRequest {
        cx,
        snapshot: first.binding().snapshot().unwrap(),
    };
    let verified = f.route.ingress.admit(&received).await.unwrap();
    let binding = second.binding().clone();
    assert!(matches!(
        second.complete_signed(&verified),
        Err(ArrivalRefusal::ForeignInput)
    ));
    assert!(
        binding.check_live().is_err(),
        "the request a foreign proof was offered for is cancelled, never served"
    );
    // Its own request completes.
    assert!(first.complete_signed(&verified).is_ok());
}

#[tokio::test]
async fn only_a_signed_route_is_completed_or_refused_as_signed() {
    // The same plane route mounted for principals: no signature admits anyone on it.
    let f = fixture_of(AUTH_PRINCIPAL, false);
    let (request, cx, _a) = arrival(&f, 1, signed_fields("msg_1", now(), BODY), BODY);
    let received = ChainRequest {
        cx,
        snapshot: request.binding().snapshot().unwrap(),
    };
    let verified = f.route.ingress.admit(&received).await.unwrap();
    assert!(matches!(
        request.complete_signed(&verified),
        Err(ArrivalRefusal::Class)
    ));
    let (request, _, _b) = arrival(&f, 3, Vec::new(), BODY);
    assert!(matches!(
        request.refuse_signed(SignedUnserved::Refused(SignedRefused::NotSigned)),
        Err(ArrivalRefusal::Class)
    ));
}

#[tokio::test]
async fn a_request_of_another_route_is_not_judged_by_this_one() {
    let f = fixture();
    let other = fixture();
    let (request, cx, _owner) = arrival(&other, 1, signed_fields("msg_1", now(), BODY), BODY);
    assert!(matches!(
        f.route.admit(request, cx).await,
        Err(ArrivalRefusal::ForeignInput)
    ));
    assert_eq!(f.hook.calls.load(Ordering::SeqCst), 0);
}

// ---- what mounts a signed route ----

const COVERS: (u64, Option<u64>) = (FB_NEEDS_BODY, Some(BOUND));

fn offer(members: Option<&[(u64, Option<u64>)]>) -> SignedOffer<'_> {
    SignedOffer {
        hooked: false,
        public_url: None,
        members,
        cap: 1 << 20,
    }
}

#[test]
fn a_signed_route_is_mounted_only_with_a_verifier_that_covers_and_bounds_its_body() {
    let mounted = mounted_as(AUTH_SIGNED_INGRESS);
    assert_eq!(
        NativeSignedRoute::offered(&mounted, offer(Some(&[COVERS]))),
        Ok(BOUND)
    );
    // The listener's own cap is never exceeded.
    assert_eq!(
        NativeSignedRoute::offered(
            &mounted,
            SignedOffer {
                cap: 1024,
                ..offer(Some(&[COVERS]))
            }
        ),
        Ok(1024)
    );
    // No instance reads its signature header: the data chain is never its verifier.
    assert_eq!(
        NativeSignedRoute::offered(&mounted, offer(None)),
        Err(SignedUnmounted::Coverage(NotCovered::NoVerifier))
    );
    assert_eq!(
        NativeSignedRoute::offered(&mounted, offer(Some(&[]))),
        Err(SignedUnmounted::Coverage(NotCovered::NoVerifier))
    );
    // A verifier that judges the head alone, or a digest of the body, says nothing of the bytes.
    for facts in [0, FB_NEEDS_BODY_HASH] {
        assert_eq!(
            NativeSignedRoute::offered(&mounted, offer(Some(&[(facts, Some(BOUND))]))),
            Err(SignedUnmounted::Coverage(NotCovered::HeadOnly))
        );
    }
    // One that states no bound: how much to read before verifying is unsaid, so nothing is.
    assert_eq!(
        NativeSignedRoute::offered(&mounted, offer(Some(&[COVERS, (FB_NEEDS_BODY, None)]))),
        Err(SignedUnmounted::Coverage(NotCovered::Unbounded))
    );
    assert_eq!(
        NativeSignedRoute::offered(&mounted, offer(Some(&[(FB_NEEDS_BODY, Some(0))]))),
        Err(SignedUnmounted::Coverage(NotCovered::Empty))
    );
    // Every reason is words the operator can act on.
    assert_eq!(
        SignedUnmounted::Coverage(NotCovered::Unbounded).reason(),
        NotCovered::Unbounded.reason()
    );
}

#[test]
fn a_signed_route_with_a_hook_or_another_class_is_not_mounted() {
    let mounted = mounted_as(AUTH_SIGNED_INGRESS);
    assert_eq!(
        NativeSignedRoute::offered(
            &mounted,
            SignedOffer {
                hooked: true,
                ..offer(Some(&[COVERS]))
            }
        ),
        Err(SignedUnmounted::Hooked),
        "a hook-bound route is never served unhooked"
    );
    // The operator chose another class for it: the route is not the signed class's.
    let mut chosen = mounted_as(AUTH_SIGNED_INGRESS);
    chosen.effective = AUTH_PRINCIPAL;
    assert_eq!(
        NativeSignedRoute::offered(&chosen, offer(Some(&[COVERS]))),
        Err(SignedUnmounted::OperatorChoice)
    );
    // A record that admits principals is not this class at all.
    let mut principal = mounted_as(AUTH_PRINCIPAL);
    principal.record = reference_plane::route_of(Admission::PrincipalOnly)
        .expect("the reference plane has a principal route")
        .record;
    assert_eq!(
        NativeSignedRoute::offered(&principal, offer(Some(&[COVERS]))),
        Err(SignedUnmounted::NotSigned)
    );
    // A challenge that names a public URL the operator did not configure cannot be written.
    let mut challenged = mounted_as(AUTH_SIGNED_INGRESS);
    challenged.record.challenge =
        Some("Signature realm=\"{public_url}/hooks\"".into());
    assert_eq!(
        NativeSignedRoute::offered(&challenged, offer(Some(&[COVERS]))),
        Err(SignedUnmounted::Table(
            NotMounted::NoPublicUrlForItsChallenge
        ))
    );
}

#[test]
fn a_chain_that_admits_a_caller_presenting_nothing_verifies_no_signed_route() {
    let book = Arc::new(Book {
        seen: Mutex::new(HashSet::new()),
        claims: AtomicUsize::new(0),
        down: AtomicBool::new(false),
    });
    let owners = Arc::new(AuthOwners {
        issued: book.clone(),
        replay: book,
        cache: Arc::new(Verdicts::new(VerdictPolicy::DEFAULT)),
    });
    let open = Arc::new(NativeChain::data_admitting_anonymous(7, Vec::new(), owners).unwrap());
    assert!(matches!(
        ChainSignature::bind(open),
        Err(ChainRefused::AdmitsAnonymous)
    ));
}
