// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! E9a: the auth step of a native ROUTE_UPGRADE request and the two custody transitions after it.
//! The route's own chain, key policy and replay claim run before core may answer the request
//! (`refuse_upgrade`, the 400 or 501 before any 101) or hand it over (`complete_upgrade`).

use super::*;
use crate::auth::native_chain::{AuthInstance, AuthOwners, OpenedAuth};
use crate::auth::verdicts::{VerdictPolicy, Verdicts};
use crate::guest::{Claimant, GuestList, Line, LineAuth, Route};
use crate::inbound::native::tests::{accepted, app, Transport};
use crate::inbound::native::{
    CompletingPhysicalRequest, PhysicalConnection, PhysicalListener, PhysicalPlan, StreamOwner,
};
use crate::issued::IssuedCredentials;
use crate::limits::process_admission::{AdmissionClass, ProcessAdmission};
use crate::plane_driver::port_intents::Namespace;
use crate::plane_driver::port_routes::Mounted;
use crate::plane_grants::{KeyRefresh, ReplayGuard};
use crate::plugin_records::RecordsDenied;
use crate::router::PreparedListener;
use crate::state::AppHandle;
use busbar_contract::kinds::codes::KindCode;
use busbar_contract::route::PATH_EXACT;
use busbar_contract::secure::SecureVec;
use busbar_plugin_abi::host_side::caller::Caller as AbiCaller;
use busbar_plugin_abi::host_side::caller::{BoxFut, InstanceLimits};
use busbar_plugin_abi::records::{tag, Records, Reply, U64Rec, Writer};
use busbar_ports::auth::{
    decode_verify_ok, AuthIn, AuthPort, LoginAnswer, LoginIn, OutboundAnswer, ServeIn, ServeOut,
    UpstreamIn, Verify, VerifyAnswer, VerifyOk,
};
use busbar_ports::PortError;
use std::collections::BTreeMap;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

const PATH: &str = "/v1/realtime";

/// Counts replay claims; the first claim of a key is its first sighting.
struct Owners(AtomicUsize);
impl IssuedCredentials for Owners {
    fn lookup<'a>(&'a self, _: u64, _: &'a str, _: &'a str) -> BoxFut<'a, SecureVec> {
        panic!("an identity answer must not perform issued lookup");
    }
}
impl ReplayGuard for Owners {
    fn claim_until<'a>(
        &'a self,
        _: &'a AbiCaller<'_>,
        _: &'a [u8],
        _: u64,
    ) -> BoxFut<'a, Result<bool, RecordsDenied>> {
        let first = self.0.fetch_add(1, Ordering::SeqCst) == 0;
        Box::pin(async move { Ok(first) })
    }
    fn claim<'a>(
        &'a self,
        _: &'a AbiCaller<'_>,
        _: &'a [u8],
        _: u64,
    ) -> BoxFut<'a, Result<bool, RecordsDenied>> {
        panic!("the native chain claims with its own cutoff");
    }
}

/// An auth instance that identifies `Bearer good`, refuses any other bearer and does not know a
/// request that carries none.
struct Port {
    calls: AtomicUsize,
}
fn unsupported<'a, T: Send + 'a>() -> BoxFut<'a, Result<T, PortError>> {
    Box::pin(async {
        Err(PortError::Call(
            busbar_plugin_abi::fail::CallError::NotDeclared,
        ))
    })
}
impl AuthPort for Port {
    fn facts(&self) -> u64 {
        0
    }
    fn cred_headers(&self) -> &[Box<str>] {
        &[]
    }
    fn issued_kind(&self) -> Option<&str> {
        None
    }
    fn verify<'a>(&'a self, _: CallCx, req: &AuthIn<'_>, _: Option<&[u8]>) -> Verify<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(req.path, PATH);
        let bearer = req
            .headers
            .iter()
            .find(|pair| pair.name.get().eq_ignore_ascii_case("authorization"))
            .map(|pair| pair.value.get().to_vec());
        match bearer.as_deref() {
            None => Verify::Done(Ok(VerifyAnswer::NotMine)),
            Some(b"Bearer good") => {
                let mut records = Reply::new();
                records.put_text(tag::ID_SUBJECT, "client").unwrap();
                records.put_text(tag::ID_GROUP, "reader").unwrap();
                records
                    .put_pod_tail(
                        busbar_plugin_abi::auth::tag::REPLAY,
                        &U64Rec { value: 60 },
                        b"nonce",
                    )
                    .unwrap();
                let VerifyOk::Identity(identity) =
                    decode_verify_ok(Records::new(records.as_bytes())).unwrap()
                else {
                    panic!("identity")
                };
                Verify::Done(Ok(VerifyAnswer::Identity(identity)))
            }
            Some(_) => Verify::Done(Ok(VerifyAnswer::Refused {
                code: busbar_plugin_abi::auth::BAD_CREDENTIAL,
                text: "bad".into(),
            })),
        }
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

struct Fixture {
    route: Arc<NativeUpgradeRoute>,
    connection: PhysicalConnection,
    budget: Arc<ProcessAdmission>,
    replay: Arc<Owners>,
    port: Arc<Port>,
}

fn fixture(bound: bool) -> Fixture {
    let caller = Caller::for_test(Arc::from("plane/test"), KindCode::Plane);
    let mut app = (*app()).clone();
    app.config_generation.store(7, Ordering::Release);
    if bound {
        app.role_bindings = BTreeMap::from([(
            "provider-42".into(),
            BTreeMap::from([(
                "reader".into(),
                crate::config::RoleBindingCfg {
                    allowed_pools: None,
                    group: Some("g".into()),
                    admin_scope: None,
                    verbs: None,
                    plane_grants: BTreeMap::new(),
                },
            )]),
        )]);
    }
    let app = Arc::new(app);
    let mounted = Mounted {
        route: 6,
        methods: METHOD_GET,
        flags: ROUTE_UPGRADE,
        auth: AUTH_PRINCIPAL,
        effective: AUTH_PRINCIPAL,
        pattern: PATH.into(),
        cred_header: None,
        catalog: false,
        resource_kinds: Arc::default(),
    };
    let line = Line {
        route: Route {
            methods: METHOD_GET,
            path_form: PATH_EXACT,
            path: PATH.into(),
            fields: vec![],
            rung: 6,
        },
        claimant: Claimant::Plane("plane/test".into()),
        dialect: 0,
        auth: LineAuth::Chain(
            vec!["provider-42".into()],
            busbar_contract::route::AuthPoints::EMPTY,
        ),
        upgrade: None,
        offered: busbar_contract::route::AuthPoints::EMPTY,
    };
    let transport: Arc<dyn busbar_ports::transport::TransportPort> = Arc::new(Transport);
    let plan = PhysicalPlan::new(
        "listen".into(),
        transport.clone(),
        GuestList::seal(vec![line.clone()]).unwrap(),
        vec![
            RouteBinding::plane(line, caller.clone(), mounted, vec!["provider-42".into()]).unwrap(),
        ],
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
        transport,
        AdmissionClass::Data,
        Arc::new(move |_, slot| (slot == "listen").then(|| prepared.clone())),
    )
    .unwrap();
    let replay = Arc::new(Owners(AtomicUsize::new(0)));
    let port = Arc::new(Port {
        calls: AtomicUsize::new(0),
    });
    let chain = Arc::new(
        NativeChain::data(
            7,
            vec![Arc::new(AuthInstance {
                opened: OpenedAuth {
                    who: Namespace {
                        plugin: "verified-image".into(),
                        name: "provider-42".into(),
                        instance: 42,
                        slot: 4,
                    },
                    port: port.clone(),
                    methods: busbar_plugin_abi::auth::M_VERIFY,
                    out_of_process: false,
                    limits: InstanceLimits::default(),
                },
                keys: Arc::new(KeyRefresh::new(Duration::from_secs(30))),
                holds: Box::default(),
            })],
            Arc::new(AuthOwners {
                issued: replay.clone(),
                replay: replay.clone(),
                cache: Arc::new(Verdicts::new(VerdictPolicy::DEFAULT)),
            }),
        )
        .unwrap(),
    );
    // Candidate assembly only; every request proof below runs the public physical factory,
    // the concrete verifier, the live generation and the replay claim.
    let route = Arc::new(NativeUpgradeRoute {
        binding,
        caller,
        chain,
    });
    Fixture {
        route,
        connection: listener.connect(accepted()),
        budget: ProcessAdmission::with_limits(8, 1 << 20, 1 << 18),
        replay,
        port,
    }
}

/// One upgrade GET on the route, its (empty) body finished, completion begun.
fn arrival(
    f: &Fixture,
    stream: u64,
    bearer: Option<&str>,
) -> (CompletingPhysicalRequest, CallCx, StreamOwner) {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut head = crate::inbound::Head::default();
    head.method = "GET".into();
    head.target = PATH.into();
    head.fields = vec![
        ("connection".into(), b"Upgrade".to_vec()),
        ("upgrade".into(), b"websocket".to_vec()),
    ];
    if let Some(bearer) = bearer {
        head.fields
            .push(("authorization".into(), bearer.as_bytes().to_vec()));
    }
    let (request, owner) = f
        .connection
        .head(
            stream,
            head,
            f.budget.try_enter(AdmissionClass::Data).unwrap(),
            Some(deadline),
        )
        .unwrap();
    let credit = request.binding().request().try_reserve(0).unwrap();
    let request = request
        .finish_input(SecureVec::new(), credit)
        .unwrap()
        .begin_completion()
        .unwrap();
    let cx = CallCx {
        deadline,
        request_id: request.binding().invocation().request_id().get(),
        stack: Default::default(),
    };
    (request, cx, owner)
}

#[tokio::test]
async fn an_authorized_upgrade_request_is_answered_by_core_only_after_auth_policy_and_replay() {
    let f = fixture(true);
    let (mut request, cx, _owner) = arrival(&f, 1, Some("Bearer good"));
    let binding = request.binding().clone();
    let preparation = request.begin_data_preparation().unwrap();
    let authorization = f.route.authorize(preparation, cx).await.unwrap();
    assert_eq!(f.port.calls.load(Ordering::SeqCst), 1, "the chain ran once");
    assert_eq!(
        f.replay.0.load(Ordering::SeqCst),
        1,
        "the replay key is spent"
    );
    assert_eq!(authorization.identity().subject(), "client");
    assert!(Arc::ptr_eq(authorization.binding(), &binding));
    let refusal = request.refuse_upgrade(authorization).unwrap();
    assert!(Arc::ptr_eq(refusal.binding(), &binding));
    assert!(
        refusal.unit().is_none(),
        "a refusal before any 101 opens no unit"
    );
    assert!(binding.check_executing().is_err(), "nothing executes");
}

#[tokio::test]
async fn an_unauthenticated_upgrade_request_is_denied_and_never_reaches_an_answer() {
    for bearer in [None, Some("Bearer stolen")] {
        let f = fixture(true);
        let (mut request, cx, _owner) = arrival(&f, 1, bearer);
        let binding = request.binding().clone();
        let preparation = request.begin_data_preparation().unwrap();
        let refused = f.route.authorize(preparation, cx).await.unwrap_err();
        assert!(
            matches!(
                refused,
                UpgradeRefused::Denied {
                    reason: DataRefused::Credential,
                    ..
                }
            ),
            "{bearer:?}: {refused:?}"
        );
        assert_eq!(f.replay.0.load(Ordering::SeqCst), 0, "no replay key spent");
        // The preparation was spent as denied: no second attempt can authorize this request.
        assert!(request.begin_data_preparation().is_err());
        assert!(binding.check_executing().is_err());
    }
}

#[tokio::test]
async fn a_credential_with_no_governed_key_is_a_policy_denial_and_spends_no_replay_key() {
    let f = fixture(false);
    let (mut request, cx, _owner) = arrival(&f, 1, Some("Bearer good"));
    let preparation = request.begin_data_preparation().unwrap();
    let refused = f.route.authorize(preparation, cx).await.unwrap_err();
    assert_eq!(refused.reason(), DataRefused::Policy);
    assert_eq!(f.replay.0.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn an_authorization_answers_only_its_own_request() {
    let f = fixture(true);
    let (mut first, cx, _first_owner) = arrival(&f, 1, Some("Bearer good"));
    let (second, _, _second_owner) = arrival(&f, 3, Some("Bearer good"));
    let authorization = f
        .route
        .authorize(first.begin_data_preparation().unwrap(), cx)
        .await
        .unwrap();
    assert!(matches!(
        second.refuse_upgrade(authorization),
        Err(crate::inbound::native::ArrivalRefusal::ForeignInput)
    ));
}

#[tokio::test]
async fn the_hand_over_consumes_the_authorized_request_once_and_carries_its_head_and_identity() {
    let f = fixture(true);
    let (mut request, cx, owner) = arrival(&f, 1, Some("Bearer good"));
    let binding = request.binding().clone();
    let authorization = f
        .route
        .authorize(request.begin_data_preparation().unwrap(), cx)
        .await
        .unwrap();
    let upgrade = request.complete_upgrade(authorization).unwrap();
    assert!(upgrade.check_executing().is_ok());
    assert!(binding.owns_stream(&owner));
    let head = upgrade.authorization().snapshot();
    assert_eq!((head.method(), head.path()), ("GET", PATH));
    assert!(head
        .headers()
        .any(|(name, value)| name == "upgrade" && value == b"websocket"));
    assert_eq!(upgrade.authorization().identity().subject(), "client");
    drop(upgrade);
    assert!(
        binding.check_live().is_err(),
        "dropping the hand-over cancels the request"
    );
}
