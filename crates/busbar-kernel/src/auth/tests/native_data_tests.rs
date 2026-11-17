// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::auth::native_chain::{AuthInstance, AuthOwners, OpenedAuth};
use crate::auth::verdicts::{VerdictPolicy, Verdicts};
use crate::config::groups::{ExhaustionMode, GroupCfg};
use crate::guest::{Claimant, GuestList, Line, LineAuth, Route};
use crate::host_services::{KernelServices, NativeInvocationAdmission, Nest, NestDone, NestRoute};
use crate::inbound::native::tests::{accepted, app, Transport};
use crate::inbound::native::{PhysicalConnection, PhysicalListener, PhysicalPlan, StreamOwner};
use crate::issued::IssuedCredentials;
use crate::limits::process_admission::{AdmissionClass, ProcessAdmission};
use crate::plane_driver::money::{EndPost, FeeRefund, PlaneMoney};
use crate::plane_driver::port_intents::Namespace;
use crate::plane_driver::port_routes::Mounted;
use crate::plane_grants::{KeyRefresh, ReplayGuard};
use crate::plugin_records::RecordsDenied;
use crate::resource_admission::{ForwardFact, FrozenRequest, ResourceFact};
use crate::router::PreparedListener;
use crate::state::AppHandle;
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::transport::route::{METHOD_POST, PATH_EXACT};
use busbar_contract::records::ScopeRef;
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
        Box::pin(async move {
            tokio::task::yield_now().await;
            Ok(first)
        })
    }
    fn claim<'a>(
        &'a self,
        _: &'a AbiCaller<'_>,
        _: &'a [u8],
        _: u64,
    ) -> BoxFut<'a, Result<bool, RecordsDenied>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(true) })
    }
}

struct Port {
    calls: AtomicUsize,
    not_mine: bool,
    native: bool,
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
        if self.native {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let accepted = req.body == b"admin-body";
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
            return Verify::Io(Box::pin(async move {
                tokio::task::yield_now().await;
                Ok(if accepted {
                    VerifyAnswer::Identity(identity)
                } else {
                    VerifyAnswer::Refused {
                        code: busbar_plugin_abi::auth::BAD_CREDENTIAL,
                        text: "body".into(),
                    }
                })
            }));
        }
        assert_eq!(req.path, "/resource");
        assert_eq!(req.body, b"body");
        assert_eq!(req.peer, "peer");
        assert_eq!(req.tls_peer_cert, b"certificate");
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.not_mine {
            return Verify::Done(Ok(VerifyAnswer::NotMine));
        }
        let mut records = Reply::new();
        records.put_text(tag::ID_SUBJECT, "client").unwrap();
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
            panic!("identity");
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

fn instance(id: u64, port: Arc<Port>) -> Arc<AuthInstance> {
    Arc::new(AuthInstance {
        opened: OpenedAuth {
            who: Namespace {
                plugin: "verified-image".into(),
                name: format!("provider-{id}").into(),
                instance: id,
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

struct NoChildren;
impl NestRoute for NoChildren {
    fn nest(&self, _: InvocationContext, _: Nest, _: NestDone) {
        panic!("unexpected child")
    }
}
struct Post;
impl EndPost for Post {
    fn post(&self, _: &crate::teller::UnitCtx, _: crate::teller::Ended) {}
}

struct Fixture {
    route: Arc<NativeDataRoute>,
    connection: PhysicalConnection,
    budget: Arc<ProcessAdmission>,
    replay: Arc<Owners>,
    calls: Arc<Port>,
    _native: NativeInvocationAdmission,
}
fn fixture(allowed: bool) -> Fixture {
    let caller = Caller::for_test(Arc::from("plane/test"), KindCode::Plane);
    let core = Arc::new(KernelServices::new());
    let native = core.admit_native_invocation(&caller).unwrap();
    let generation = Arc::new(ServingGeneration::new(core, Arc::new(NoChildren)));
    let mut app = (*app()).clone();
    app.config_generation.store(7, Ordering::Release);
    app.role_bindings = BTreeMap::from([(
        "provider-42".into(),
        BTreeMap::from([(
            "reader".into(),
            crate::config::RoleBindingCfg {
                allowed_pools: Some(vec![if allowed { "chat" } else { "other" }.into()]),
                group: Some("g".into()),
                admin_scope: None,
                verbs: None,
                plane_grants: BTreeMap::new(),
            },
        )]),
    )]);
    app.cost = Arc::new(crate::cost::CostModel::resolve_parts(
        None,
        1,
        &BTreeMap::from([(
            "g".into(),
            GroupCfg {
                enabled: true,
                ..Default::default()
            },
        )]),
    ));
    let app = Arc::new(app);
    let mounted = Mounted {
        route: 3,
        methods: METHOD_POST,
        flags: 0,
        auth: AUTH_PRINCIPAL,
        effective: AUTH_PRINCIPAL,
        pattern: "/resource".into(),
        cred_header: None,
        catalog: false,
        resource_kinds: vec!["pool".into()],
    };
    let line = Line {
        route: Route {
            methods: METHOD_POST,
            path_form: PATH_EXACT,
            path: "/resource".into(),
            fields: vec![],
            rung: 3,
        },
        claimant: Claimant::Plane("plane/test".into()),
        dialect: 0,
        auth: LineAuth::Chain(
            vec!["provider-42".into()],
            busbar_contract::abi::auth::AuthPoints::EMPTY,
        ),
        upgrade: None,
        offered: busbar_contract::abi::auth::AuthPoints::EMPTY,
    };
    let port: Arc<dyn busbar_ports::transport::TransportPort> = Arc::new(Transport);
    let plan = PhysicalPlan::new(
        "listen".into(),
        port.clone(),
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
    let upstream = Arc::new(crate::upstreams::UpstreamDef {
        resource: None,
        name: "shared".into(),
        allow_private: false,
        url: Some("https://example.invalid/".into()),
        command: None,
        tls: crate::upstreams::UpstreamTls {
            pin_spki: vec![],
            client_identity: None,
            trust: None,
        },
        auth: None,
    });
    let upstreams = Arc::new(crate::upstreams::ConfiguredUpstreams::from_definitions(
        BTreeMap::from([("shared".into(), upstream)]),
    ));
    let targets: crate::plane_driver::port_egress::Targets = Arc::new(|pool, member| {
        if pool != "chat" || member != "plane/test\u{1f}shared" {
            return None;
        }
        let mut target = crate::plane_driver::port_egress::MemberTarget::bare();
        target.registered_upstream = Some("shared".into());
        Some(target)
    });
    let inventory = ResourceInventory::build(
        &caller,
        7,
        vec!["pool".into()],
        vec![ResourceFact {
            scope: ScopeRef {
                kind: "pool".into(),
                value: "chat".into(),
            },
            forwards: vec![ForwardFact {
                descriptor: 1,
                pool: "chat".into(),
                member: "plane/test\u{1f}shared".into(),
                upstream: "shared".into(),
                dialect: "".into(),
                model: "".into(),
                method: "POST".into(),
                target: "/generate".into(),
            }],
        }],
        upstreams,
        targets,
        1 << 20,
    )
    .unwrap();
    let replay = Arc::new(Owners(AtomicUsize::new(0)));
    let calls = Arc::new(Port {
        calls: AtomicUsize::new(0),
        not_mine: false,
        native: true,
    });
    let chain = Arc::new(
        NativeChain::data(
            7,
            vec![instance(42, calls.clone())],
            Arc::new(AuthOwners {
                issued: replay.clone(),
                replay: replay.clone(),
                cache: Arc::new(Verdicts::new(VerdictPolicy::DEFAULT)),
            }),
        )
        .unwrap(),
    );
    // Assemble only candidate configuration here. Every request proof below uses the public
    // physical factory, real charged selection, concrete verifier, publication and replay.
    let route = Arc::new(NativeDataRoute {
        binding,
        caller,
        cost: app.cost.clone(),
        owners: DataRouteOwners {
            generation,
            inventory,
            chain,
            keys: Arc::default(),
            routes: Arc::new(RequestRoutes::new("plane/test", None, None, None).unwrap()),
        },
    });
    Fixture {
        route,
        connection: listener.connect(accepted()),
        budget: ProcessAdmission::with_limits(8, 1 << 20, 1 << 18),
        replay,
        calls,
        _native: native,
    }
}
fn arrival(
    f: &Fixture,
    stream: u64,
) -> (
    CompletingPhysicalRequest,
    SelectedResources,
    CallCx,
    StreamOwner,
) {
    arrival_with_fields(f, stream, Vec::new())
}

fn arrival_with_fields(
    f: &Fixture,
    stream: u64,
    fields: Vec<(String, Vec<u8>)>,
) -> (
    CompletingPhysicalRequest,
    SelectedResources,
    CallCx,
    StreamOwner,
) {
    let deadline = Instant::now() + Duration::from_secs(30);
    let (request, owner) = f
        .connection
        .head(
            stream,
            crate::inbound::Head {
                method: "POST".into(),
                target: "/resource".into(),
                fields,
                ..Default::default()
            },
            f.budget.try_enter(AdmissionClass::Data).unwrap(),
            Some(deadline),
        )
        .unwrap();
    let credit = request
        .binding()
        .request()
        .try_reserve(b"admin-body".len())
        .unwrap();
    let request = request
        .finish_input(SecureVec::from(b"admin-body".as_slice()), credit)
        .unwrap()
        .begin_completion()
        .unwrap();
    let binding = request.binding();
    let snapshot = binding.snapshot().unwrap();
    let frozen = FrozenRequest::from_snapshot(binding.invocation(), 3, snapshot);
    let RouteTarget::Plane(target) = binding.route().target() else {
        panic!("plane")
    };
    let mut wire = Reply::new();
    busbar_plugin_abi::resource_admission::write_selection(
        &mut wire,
        &[busbar_plugin_abi::resource_admission::Scope {
            kind: "pool",
            value: "chat",
        }],
    )
    .unwrap();
    let selected = f
        .route
        .owners
        .inventory
        .select_wire(frozen, target.mounted(), wire.as_bytes())
        .unwrap();
    let cx = CallCx {
        deadline,
        request_id: binding.invocation().request_id().get(),
        stack: Default::default(),
    };
    (request, selected, cx, owner)
}

#[tokio::test]
async fn native_data_selected_scope_denial_never_claims_replay() {
    let f = fixture(false);
    let (request, selected, cx, _owner) = arrival(&f, 1);
    let pending = f.route.prepare(request, selected, cx).await.unwrap();
    assert!(matches!(pending.complete().await, Err(DataRefused::Policy)));
    assert_eq!(f.calls.calls.load(Ordering::SeqCst), 1);
    assert_eq!(f.replay.0.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn native_data_keeps_gate_closed_until_actual_money_and_physical_join() {
    let f = fixture(true);
    let (request, selected, cx, owner) = arrival(&f, 1);
    let binding = request.binding().clone();
    let authorized = f
        .route
        .prepare(request, selected, cx)
        .await
        .unwrap()
        .complete()
        .await
        .unwrap();
    assert!(binding.check_executing().is_err());
    let allocation = NativeDataAllocation::register(authorized).unwrap();
    let context = allocation.context().clone();
    assert!(context.is_live());
    assert!(!context.effects_allowed());
    let gov = Arc::new(
        crate::governance::GovState::new_with_core(crate::real_store::core().await, None, None)
            .await
            .unwrap(),
    );
    let money = Arc::new(PlaneMoney::new(gov, Arc::new(Post)));
    let book = money.clone();
    assert!(context
        .generation()
        .core()
        .units()
        .ticketed(context.unit(), None));
    let observed = context.clone();
    let pending = allocation.into_pending(move |receipt| {
        let admitted = book
            .admit_existing(
                receipt.begin().unwrap(),
                Arc::from(Vec::<String>::new()),
                FeeRefund::CallerStatus,
                ExhaustionMode::FinishUnit,
            )
            .unwrap();
        assert!(observed.is_live());
        assert!(
            !observed.effects_allowed(),
            "money CAS alone must not open DATA effects"
        );
        assert!(!admitted.is_live());
        assert!(
            observed
                .generation()
                .core()
                .units()
                .take_ticket(observed.unit())
                .is_none(),
            "direct UnitRecords must enforce the same gate"
        );
        let ctx = crate::teller::UnitCtx {
            call: busbar_contract::caps::CallId::UNBOUND,
            key: admitted.unit(),
            origin: busbar_contract::caps::OriginKind::Client,
            session: None,
            generation: crate::registry::Generation::FIRST,
            admin_listener: false,
            kernel_verb_only: false,
        };
        Ok(AdmittedUnit {
            selected: None,
            request: admitted,
            unit: crate::plane_driver::port::Unit {
                ctx,
                money: crate::plane_driver::port_money::PortMoney::new(
                    book.clone(),
                    Arc::from(Vec::<String>::new()),
                    Arc::new(crate::plane_driver::CoreAudit),
                ),
                journal: None,
            },
        })
    });
    pending.pending().admit(None, None).unwrap();
    assert!(context.effects_allowed());
    assert!(binding.check_executing().is_ok());
    assert_eq!(
        context
            .generation()
            .core()
            .units()
            .take_ticket(context.unit()),
        Some(None)
    );
    assert!(pending.execution().unwrap().money().is_live());
    assert!(
        pending
            .execution()
            .unwrap()
            .physical
            .start_execution(pending.execution().unwrap())
            .is_err(),
        "start is one-shot"
    );
    assert_eq!(f.replay.0.load(Ordering::SeqCst), 1);
    assert_eq!(f.calls.calls.load(Ordering::SeqCst), 1);
    drop(pending);
    assert!(!context.is_live());
    assert!(!context.effects_allowed());
    assert!(binding.check_executing().is_err());
    money.settle_end(busbar_contract::UnitKey::new(context.unit()), 499);
    drop(owner);
}

#[tokio::test]
async fn native_data_cancellation_between_verification_and_replay_grants_nothing() {
    let f = fixture(true);
    let (request, selected, cx, owner) = arrival(&f, 1);
    let pending = f.route.prepare(request, selected, cx).await.unwrap();
    drop(owner);
    assert!(matches!(
        pending.complete().await,
        Err(DataRefused::Cancelled)
    ));
    assert_eq!(f.replay.0.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn native_data_selection_from_another_physical_request_is_refused() {
    let f = fixture(true);
    let (first, _selected, cx, _owner) = arrival(&f, 1);
    let (_second, foreign, _, _other_owner) = arrival(&f, 2);
    assert!(matches!(
        f.route.prepare(first, foreign, cx).await,
        Err(DataRefused::Binding)
    ));
    assert_eq!(f.calls.calls.load(Ordering::SeqCst), 0);
    assert_eq!(f.replay.0.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn native_data_publication_before_final_gate_prevents_replay() {
    let f = fixture(true);
    let (request, selected, cx, _owner) = arrival(&f, 1);
    let handle = request.binding().handle().clone();
    let pending = f.route.prepare(request, selected, cx).await.unwrap();
    handle.swap(app()).await;
    assert!(matches!(pending.complete().await, Err(DataRefused::Policy)));
    assert_eq!(f.replay.0.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn native_data_reset_after_authorization_cannot_register_effects() {
    let f = fixture(true);
    let (request, selected, cx, owner) = arrival(&f, 1);
    let binding = request.binding().clone();
    let authorized = f
        .route
        .prepare(request, selected, cx)
        .await
        .unwrap()
        .complete()
        .await
        .unwrap();
    assert!(f.connection.cancel(&owner));
    assert!(NativeDataAllocation::register(authorized).is_err());
    assert!(binding.check_executing().is_err());
    assert_eq!(f.replay.0.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn native_data_reset_after_registration_closes_the_exact_context() {
    let f = fixture(true);
    let (request, selected, cx, owner) = arrival(&f, 1);
    let binding = request.binding().clone();
    let authorized = f
        .route
        .prepare(request, selected, cx)
        .await
        .unwrap()
        .complete()
        .await
        .unwrap();
    let allocation = NativeDataAllocation::register(authorized).unwrap();
    let context = allocation.context().clone();
    assert!(f.connection.cancel(&owner));
    let pending = allocation.into_pending(|_| panic!("reset request must not acquire money"));
    assert!(pending.pending().admit(None, None).is_err());
    assert!(pending.execution().is_none());
    assert!(!context.effects_allowed());
    assert!(binding.check_executing().is_err());
    drop(pending);
    assert!(!context.is_live());
}

#[tokio::test]
async fn native_data_uncertain_replay_cancellation_never_opens_execution() {
    let f = fixture(true);
    let (request, selected, cx, owner) = arrival(&f, 1);
    let binding = request.binding().clone();
    let pending = f.route.prepare(request, selected, cx).await.unwrap();
    let mut completion = Box::pin(pending.complete());
    assert!(futures::poll!(completion.as_mut()).is_pending());
    assert_eq!(f.replay.0.load(Ordering::SeqCst), 1);
    drop(owner);
    assert!(matches!(completion.await, Err(DataRefused::Cancelled)));
    assert!(binding.check_executing().is_err());
    assert_eq!(
        f.replay.0.load(Ordering::SeqCst),
        1,
        "uncertain claim is never retried"
    );
}

#[tokio::test]
async fn native_data_publication_after_lease_retains_original_authority() {
    let f = fixture(true);
    let (request, selected, cx, _owner) = arrival(&f, 1);
    let binding = request.binding().clone();
    let pending = f.route.prepare(request, selected, cx).await.unwrap();
    let mut completion = Box::pin(pending.complete());
    assert!(futures::poll!(completion.as_mut()).is_pending());
    binding.handle().swap(app()).await;
    let authorized = completion.await.unwrap();
    let allocation = NativeDataAllocation::register(authorized).unwrap();
    assert!(allocation.context().is_live());
    assert!(!allocation.context().effects_allowed());
    drop(allocation);
    assert!(binding.check_live().is_err());
    assert_eq!(f.replay.0.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn native_data_final_physical_join_refuses_foreign_request() {
    let f = fixture(true);
    let (request, selected, cx, _owner) = arrival(&f, 1);
    let authorized = f
        .route
        .prepare(request, selected, cx)
        .await
        .unwrap()
        .complete()
        .await
        .unwrap();
    let (authorization, _original_owner) = authorized.into_parts();
    let (foreign, _selected, _, _foreign_owner) = arrival(&f, 2);
    let binding = foreign.binding().clone();
    assert!(matches!(
        foreign.complete(authorization),
        Err(crate::inbound::native::ArrivalRefusal::ForeignInput)
    ));
    assert!(binding.check_executing().is_err());
}

#[tokio::test]
async fn native_data_scans_later_duplicate_bound_carrier_before_verification() {
    for token in [
        "DPoP opaque",
        "Bearer eyJhbGciOiJub25lIn0.eyJjbmYiOnsiamt0IjoieCJ9fQ.x",
        "Bearer bbk_not_an_external_provider_credential",
    ] {
        let f = fixture(true);
        let (request, selected, cx, _owner) = arrival_with_fields(
            &f,
            1,
            vec![
                ("Authorization".into(), b"Bearer harmless-decoy".to_vec()),
                ("authorization".into(), token.as_bytes().to_vec()),
            ],
        );
        assert!(matches!(
            f.route.prepare(request, selected, cx).await,
            Err(DataRefused::Credential)
        ));
        assert_eq!(f.calls.calls.load(Ordering::SeqCst), 0);
        assert_eq!(f.replay.0.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn native_data_pending_liveness_tracks_physical_reset_before_task() {
    let f = fixture(true);
    let (request, selected, cx, owner) = arrival(&f, 1);
    let authorized = f
        .route
        .prepare(request, selected, cx)
        .await
        .unwrap()
        .complete()
        .await
        .unwrap();
    let allocation = NativeDataAllocation::register(authorized).unwrap();
    let pending = allocation.into_pending(|_| panic!("cancelled before request"));
    assert!(pending.is_live());
    assert!(f.connection.cancel(&owner));
    assert!(!pending.is_live());
}
