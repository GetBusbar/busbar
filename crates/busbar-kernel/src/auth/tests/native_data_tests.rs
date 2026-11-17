// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::auth::native_chain::{AuthInstance, AuthOwners, OpenedAuth};
use crate::auth::verdicts::{VerdictPolicy, Verdicts};
use crate::config::groups::{ExhaustionMode, GroupCfg};
use crate::guest::{Claimant, GuestList, Line, LineAuth, Route};
use crate::host_services::{KernelServices, NativeInvocationAdmission, Nest, NestDone, NestRoute};
use crate::inbound::native::tests::{accepted, app, Transport};
use crate::inbound::native::{
    CompletingPhysicalRequest, PhysicalConnection, PhysicalListener, PhysicalPlan, StreamOwner,
};
use crate::issued::IssuedCredentials;
use crate::limits::process_admission::{AdmissionClass, ProcessAdmission};
use crate::plane_driver::port_intents::Namespace;
use crate::plane_driver::port_routes::Mounted;
use crate::plane_driver::{EndPost, FeeRefund, PlaneMoney};
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

// Preserve the existing physical fixtures while using the production one-shot preparation.
trait PreparePhysicalFixture {
    async fn prepare_test(
        &self,
        physical: crate::inbound::native::CompletingPhysicalRequest,
        selected: SelectedResources,
        cx: CallCx,
    ) -> Result<PreparedPhysicalFixture, DataRefused>;
}
struct PreparedPhysicalFixture {
    physical: crate::inbound::native::CompletingPhysicalRequest,
    pending: PendingData,
}
impl PreparedPhysicalFixture {
    async fn complete(self) -> Result<AuthorizedPhysicalData, DataRefused> {
        let authorization = self
            .pending
            .complete()
            .await
            .map_err(|error| error.reason())?;
        self.physical
            .complete(authorization)
            .map_err(|_| DataRefused::Cancelled)
    }
}
impl PreparePhysicalFixture for Arc<NativeDataRoute> {
    async fn prepare_test(
        &self,
        mut physical: crate::inbound::native::CompletingPhysicalRequest,
        selected: SelectedResources,
        cx: CallCx,
    ) -> Result<PreparedPhysicalFixture, DataRefused> {
        let preparation = physical
            .begin_data_preparation()
            .map_err(|_| DataRefused::Cancelled)?;
        let pending = self
            .prepare(preparation, selected, cx)
            .await
            .map_err(|error| error.reason())?;
        Ok(PreparedPhysicalFixture { physical, pending })
    }
}

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
    let generation = Arc::new(ServingGeneration::try_new(core, Arc::new(NoChildren)).unwrap());
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
                authority: String::new(),
                query: None,
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
    let pending = f.route.prepare_test(request, selected, cx).await.unwrap();
    assert!(matches!(pending.complete().await, Err(DataRefused::Policy)));
    assert_eq!(f.calls.calls.load(Ordering::SeqCst), 1);
    assert_eq!(f.replay.0.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn native_data_preparation_latch_is_spent_before_verification() {
    let f = fixture(true);
    let (mut request, _selected, _cx, _owner) = arrival(&f, 1);
    let binding = request.binding().clone();
    let preparation = request.begin_data_preparation().unwrap();
    assert!(request.begin_data_preparation().is_err());
    assert_eq!(f.calls.calls.load(Ordering::SeqCst), 0);
    assert_eq!(f.replay.0.load(Ordering::SeqCst), 0);
    drop(preparation);
    assert!(binding.check_live().is_err());
    assert!(request.begin_data_preparation().is_err());
    assert_eq!(f.calls.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn native_data_policy_denial_retains_original_physical_completion() {
    let f = fixture(false);
    let (mut request, selected, cx, _owner) = arrival(&f, 1);
    let binding = request.binding().clone();
    let preparation = request.begin_data_preparation().unwrap();
    let pending = f.route.prepare(preparation, selected, cx).await.unwrap();
    let Err(DataPreparationFailed::Denied(denied)) = pending.complete().await else {
        panic!("expected actual policy denial");
    };
    assert_eq!(denied.decision(), DataRefused::Policy);
    assert!(Arc::ptr_eq(denied.binding(), &binding));
    assert!(request.begin_data_preparation().is_err());
    let refusal = request.refuse_data(denied).unwrap();
    assert!(Arc::ptr_eq(refusal.binding(), &binding));
    assert!(binding.check_live().is_err());
    assert!(binding.check_executing().is_err());
    assert_eq!(f.calls.calls.load(Ordering::SeqCst), 1);
    assert_eq!(f.replay.0.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn native_data_without_node_audit_custody_refuses_before_money_or_effects() {
    let f = fixture(true);
    let (request, selected, cx, _owner) = arrival(&f, 1);
    let binding = request.binding().clone();
    let authorized = f
        .route
        .prepare_test(request, selected, cx)
        .await
        .unwrap()
        .complete()
        .await
        .unwrap();
    let allocation = NativeDataAllocation::register(authorized).unwrap();
    let context = allocation.context().clone();
    let gov = Arc::new(
        crate::governance::GovState::new_with_core(crate::real_store::core().await, None, None)
            .await
            .unwrap(),
    );
    let money = Arc::new(PlaneMoney::new(gov, Arc::new(Post)));
    let book = money.clone();
    let commits = Arc::new(AtomicUsize::new(0));
    let observed = commits.clone();
    let pending = Arc::new(allocation.into_pending(move |receipt| {
        observed.fetch_add(1, Ordering::SeqCst);
        let admitted = book
            .admit_existing(
                receipt.begin().unwrap(),
                Arc::from(Vec::<String>::new()),
                FeeRefund::CallerStatus,
                ExhaustionMode::FinishUnit,
            )
            .unwrap();
        Ok(ordinary_unit(&book, admitted, None))
    }));
    let calls = PlaneCalls(AtomicUsize::new(0));
    let mut task = begin_task(&calls, &pending);
    let declaration = task.request_declaration().unwrap();
    assert!(
        pending.pending().admit(None, None, declaration).is_err(),
        "original physical and money owners cannot replace Node audit custody"
    );
    assert_eq!(commits.load(Ordering::SeqCst), 0);
    assert_eq!(money.open_units(), 0);
    assert!(!context.effects_allowed());
    assert!(binding.check_executing().is_err());
    assert!(pending.execution().is_none());
}

#[tokio::test]
async fn native_data_keeps_gate_closed_until_actual_money_and_physical_join() {
    let f = fixture(true);
    let (request, selected, cx, owner) = arrival(&f, 1);
    let binding = request.binding().clone();
    let authorized = f
        .route
        .prepare_test(request, selected, cx)
        .await
        .unwrap()
        .complete()
        .await
        .unwrap();
    assert!(binding.check_executing().is_err());
    let mut allocation = NativeDataAllocation::register(authorized).unwrap();
    let audit = audit_custody(&mut allocation);
    let audit_context = audit.owner.context().clone();
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
        Ok(ordinary_unit(&book, admitted, Some(&audit_context)))
    });
    let pending = Arc::new(pending);
    let calls = PlaneCalls(AtomicUsize::new(0));
    let mut task = begin_task(&calls, &pending);
    let declaration = task.request_declaration().unwrap();
    pending.pending().admit(None, None, declaration).unwrap();
    task.bind_admission(pending.pending()).unwrap();
    assert_eq!(calls.0.load(Ordering::SeqCst), 1);
    task.end(&DataEffects(&pending)).unwrap();
    drop(task);
    assert!(context.effects_allowed());
    assert!(binding.check_executing().is_ok());
    assert_eq!(
        context
            .generation()
            .core()
            .units()
            .take_ticket(context.unit()),
        None,
        "descriptor execution cannot authorize generic ticket access"
    );
    assert_generic_effects_refused(&f, &context);
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
    let receipt = pending.execution().unwrap().money().clone();
    drop(pending);
    assert!(!context.is_live());
    assert!(!context.effects_allowed());
    assert!(binding.check_executing().is_err());
    let ended = crate::plane_driver::UnitEnd {
        caller_status: 499,
        cut: false,
        refused_unspent: true,
    };
    assert!(money.settle_admitted(&receipt, ended).unwrap());
    assert!(!money.settle_admitted(&receipt, ended).unwrap());
    assert_eq!(money.open_units(), 0);
    drop(owner);
}

#[tokio::test]
async fn native_data_billing_books_keep_registered_key_and_generation_without_reminting() {
    let f = fixture(true);
    let (request, selected, cx, _owner) = arrival(&f, 1);
    let authorized = f
        .route
        .prepare_test(request, selected, cx)
        .await
        .unwrap()
        .complete()
        .await
        .unwrap();
    let allocation = NativeDataAllocation::register(authorized).unwrap();
    let gov = Arc::new(
        crate::governance::GovState::new_with_core(crate::real_store::core().await, None, None)
            .await
            .unwrap(),
    );
    let money = Arc::new(PlaneMoney::new(gov.clone(), Arc::new(Post)));
    let keys = Arc::new(crate::door::UnitKeyMint::default());
    let billing = crate::plane_driver::port_billing::PortBilling::new(
        money.clone(),
        gov,
        keys.clone(),
        Arc::new(crate::plane_driver::CoreAudit),
    );
    let unit = billing
        .allocated_data(&allocation, Arc::from(Vec::<String>::new()))
        .unwrap();
    assert_eq!(unit.ctx.key.get(), allocation.context().unit());
    assert_eq!(
        Some(unit.ctx.generation),
        allocation.context().generation().routing_generation()
    );
    assert_eq!(
        keys.mint().get(),
        1,
        "attaching books must not consume another unit identity"
    );
    assert_eq!(
        money.open_units(),
        0,
        "book attachment is not monetary admission"
    );
    assert!(!allocation.context().effects_allowed());
    allocation.context().retire();
    assert!(billing
        .allocated_data(&allocation, Arc::from(Vec::<String>::new()))
        .is_err());
}

#[tokio::test]
async fn native_data_cancellation_between_verification_and_replay_grants_nothing() {
    let f = fixture(true);
    let (request, selected, cx, owner) = arrival(&f, 1);
    let pending = f.route.prepare_test(request, selected, cx).await.unwrap();
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
        f.route.prepare_test(first, foreign, cx).await,
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
    let pending = f.route.prepare_test(request, selected, cx).await.unwrap();
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
        .prepare_test(request, selected, cx)
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
        .prepare_test(request, selected, cx)
        .await
        .unwrap()
        .complete()
        .await
        .unwrap();
    let allocation = NativeDataAllocation::register(authorized).unwrap();
    let context = allocation.context().clone();
    let pending =
        Arc::new(allocation.into_pending(|_| panic!("reset request must not acquire money")));
    let calls = PlaneCalls(AtomicUsize::new(0));
    let task = begin_task(&calls, &pending);
    let declaration = task.request_declaration().unwrap();
    assert!(f.connection.cancel(&owner));
    assert!(pending.pending().admit(None, None, declaration).is_err());
    drop(task);
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
    let pending = f.route.prepare_test(request, selected, cx).await.unwrap();
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
    let pending = f.route.prepare_test(request, selected, cx).await.unwrap();
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
        .prepare_test(request, selected, cx)
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
            f.route.prepare_test(request, selected, cx).await,
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
        .prepare_test(request, selected, cx)
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

struct PlaneCalls(AtomicUsize);
impl crate::plane_driver::port_session::Calls for PlaneCalls {
    type Session = ();
    fn resource_scoped(&self, _: u32) -> bool {
        true
    }
    fn request(
        &self,
        request: &busbar_ports::plane::PlaneIn<'_>,
        body: &[u8],
        _: &mut dyn FnMut(busbar_ports::plane::PlaneOut<'_>),
    ) -> Result<(), PortError> {
        assert_eq!(request.route, 3);
        assert_eq!(request.path, "/resource");
        assert_eq!(body, b"admin-body");
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn piece(
        &self,
        _: &mut (),
        _: u32,
        _: u32,
        _: u32,
        _: &[u8],
        _: &mut dyn FnMut(busbar_ports::plane::PlaneOut<'_>),
    ) -> Result<(), PortError> {
        Ok(())
    }
    fn rewrite(
        &self,
        _: &mut (),
        _: &[u8],
        _: &mut dyn FnMut(busbar_ports::plane::PlaneOut<'_>),
    ) -> Result<(), PortError> {
        panic!("no hooks")
    }
    fn end(
        &self,
        _: (),
        _: &mut dyn FnMut(busbar_ports::plane::PlaneOut<'_>),
    ) -> Result<(), PortError> {
        Ok(())
    }
    fn probe(
        &self,
        _: &busbar_ports::plane::TargetIn<'_>,
        _: &mut dyn FnMut(busbar_ports::plane::PlaneOut<'_>),
    ) -> Result<(), PortError> {
        panic!("no probe")
    }
    fn render(
        &self,
        _: &busbar_ports::plane::PlaneIn<'_>,
        _: u32,
        _: &[u8],
        _: &mut dyn FnMut(busbar_ports::plane::PlaneOut<'_>),
    ) -> Result<(), PortError> {
        panic!("no render")
    }
    fn upstream(
        &self,
        _: &mut (),
        _: &busbar_ports::plane::TargetIn<'_>,
        _: &mut dyn FnMut(busbar_ports::plane::PlaneOut<'_>),
    ) -> Result<(), PortError> {
        panic!("local fixture")
    }
}
struct DataEffects<'a>(&'a Arc<NativeDataPending>);
impl crate::plane_driver::port_session::Effects for DataEffects<'_> {
    fn data(&self) -> Option<&Arc<NativeDataPending>> {
        Some(self.0)
    }
    fn invocation(&self) -> Option<&InvocationContext> {
        Some(self.0.context())
    }
    fn admission(&self) -> Option<&Pending> {
        Some(self.0.pending())
    }
    fn emit(&self, _: u64, _: &[u8]) {
        panic!("no external effects in the preparatory phase")
    }
}
fn begin_task<'a>(
    calls: &'a PlaneCalls,
    data: &Arc<NativeDataPending>,
) -> crate::plane_driver::port_session::Task<'a, PlaneCalls> {
    let effects = DataEffects(data);
    let (task, _) = data
        .snapshot()
        .with_auth_input(|request| {
            crate::plane_driver::port_session::Task::begin(
                calls,
                &busbar_ports::plane::PlaneIn {
                    route: data.selected().request().route(),
                    flags: 0,
                    auth: AUTH_PRINCIPAL,
                    method: request.method,
                    path: request.path,
                    query: request.query,
                    headers: request.headers,
                    identity: data.identity().identity_records(),
                    request_id: data.binding().invocation().request_id().get(),
                    carrier: 0,
                    work: "",
                    ticket_record: &[],
                },
                request.body,
                &effects,
            )
        })
        .unwrap()
        .unwrap();
    task
}

fn assert_generic_effects_refused(f: &Fixture, context: &InvocationContext) {
    use busbar_contract::abi::host::service::{OUTBOUND_BIND, OUTBOUND_PUBLISH, OUTBOUND_REVOKE};
    use busbar_contract::abi::mechanism::call::Outcome;
    use busbar_contract::services::{HostServices, OutboundAuthorization, Ran};
    assert!(context
        .nest(
            &f.route.caller,
            busbar_contract::services::NestAsk {
                verb: "POST".into(),
                target: "/other".into(),
                body: vec![]
            },
            Box::new(|_| panic!("DATA cannot nest"))
        )
        .is_err());
    assert!(context
        .offload_hook(Box::new(|| panic!("DATA cannot run hooks")))
        .is_err());
    let core = context.generation().core();
    let call = |unit, action, revision| {
        let publish = action == OUTBOUND_PUBLISH;
        let result = core.outbound_authorize(
            &f.route.caller,
            Some(unit),
            OutboundAuthorization {
                action,
                need: 0,
                member: "m0",
                resource: "https://example.invalid/private",
                connection: "public-account",
                expected_revision: revision,
                expires_at_unix: if publish { u64::MAX } else { 0 },
                field_name: if publish { "authorization" } else { "" },
                credential: if publish { b"Bearer fixture" } else { b"" },
            },
            Box::new(|_| panic!("synchronous custody")),
        );
        match result {
            Ran::Now(result) => result,
            Ran::Later => panic!("synchronous custody"),
        }
    };
    assert_eq!(
        call(context.unit(), OUTBOUND_PUBLISH, 0).outcome,
        Outcome::Refused
    );
    // An independently admitted ordinary unit with the same owner can enroll revision 1.
    // This proves the refused DATA request created no custody row.
    let ordinary = 999;
    core.units().admitted_for(
        ordinary,
        &f.route.caller,
        crate::host_units::UnitRecord {
            principal: context.principal().cloned(),
            depth: 0,
        },
    );
    let published = call(ordinary, OUTBOUND_PUBLISH, 0);
    assert_eq!(published.outcome, Outcome::Ready);
    assert_eq!(published.value, 1);
    assert_eq!(
        call(context.unit(), OUTBOUND_REVOKE, 1).outcome,
        Outcome::Refused
    );
    assert_eq!(
        call(ordinary, OUTBOUND_BIND, 1).outcome,
        Outcome::Ready,
        "refused DATA revocation cannot alter the existing custody row"
    );
    core.units().ended(ordinary);
}

#[tokio::test]
async fn native_data_task_refuses_substituted_physical_request_id() {
    let f = fixture(true);
    let (request, selected, cx, _owner) = arrival(&f, 1);
    let authorized = f
        .route
        .prepare_test(request, selected, cx)
        .await
        .unwrap()
        .complete()
        .await
        .unwrap();
    let pending = Arc::new(
        NativeDataAllocation::register(authorized)
            .unwrap()
            .into_pending(|_| panic!("foreign request id cannot acquire money")),
    );
    let calls = PlaneCalls(AtomicUsize::new(0));
    let effects = DataEffects(&pending);
    let answer = pending
        .snapshot()
        .with_auth_input(|request| {
            crate::plane_driver::port_session::Task::begin(
                &calls,
                &busbar_ports::plane::PlaneIn {
                    route: pending.selected().request().route(),
                    flags: 0,
                    auth: AUTH_PRINCIPAL,
                    method: request.method,
                    path: request.path,
                    query: request.query,
                    headers: request.headers,
                    identity: pending.identity().identity_records(),
                    request_id: cx.request_id + 1,
                    carrier: 0,
                    work: "",
                    ticket_record: &[],
                },
                request.body,
                &effects,
            )
        })
        .unwrap();
    assert!(matches!(
        answer,
        Err(crate::plane_driver::port_session::SessionError::NotDriven)
    ));
    assert_eq!(calls.0.load(Ordering::SeqCst), 0);
    assert!(pending.execution().is_none());
}

struct AuditFixtureDoor;
impl crate::inflight::ArrivalDoor for AuditFixtureDoor {
    fn arrival_hold(
        &self,
        principal: busbar_contract::caps::PrincipalId,
        token: &busbar_contract::caps::Grant<busbar_contract::caps::Admittance>,
    ) -> busbar_contract::caps::Hold {
        busbar_contract::caps::Hold::open(token, principal)
    }
}
struct AuditFixtureCustody {
    owner: crate::teller::native_data_audit::NativeAuditOwner,
    inflight: crate::inflight::InFlight,
    _credit: busbar_contract::storage::StorageCredit,
}
fn audit_custody(allocation: &mut NativeDataAllocation) -> Box<AuditFixtureCustody> {
    let credit = allocation
        .authorization
        .binding
        .request()
        .storage()
        .try_reserve(std::mem::size_of::<AuditFixtureCustody>())
        .unwrap();
    let owner = allocation
        .take_audit_registration()
        .unwrap()
        .bind(Arc::new(crate::teller::Kernel::new()))
        .unwrap();
    let mut custody = Box::new(AuditFixtureCustody {
        owner,
        inflight: crate::inflight::InFlight::new(1),
        _credit: credit,
    });
    custody
        .owner
        .enter(&custody.inflight, &AuditFixtureDoor, 1)
        .unwrap();
    custody
}

fn ordinary_unit(
    book: &Arc<PlaneMoney>,
    admitted: AdmittedRequest,
    original: Option<&crate::teller::UnitCtx>,
) -> AdmittedUnit {
    let rollback = book.admission_rollback(&admitted).unwrap();
    let ctx = original.cloned().unwrap_or(crate::teller::UnitCtx {
        call: busbar_contract::caps::CallId::UNBOUND,
        key: admitted.unit(),
        origin: busbar_contract::caps::OriginKind::Client,
        session: None,
        generation: crate::registry::Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    });
    let unit = crate::plane_driver::port::Unit {
        ctx,
        money: crate::plane_driver::port_money::PortMoney::new(
            book.clone(),
            Arc::from(Vec::<String>::new()),
            Arc::new(crate::plane_driver::CoreAudit),
        ),
        journal: None,
    };
    AdmittedUnit::ordinary(admitted, unit, rollback).unwrap()
}

#[tokio::test]
async fn native_data_reset_after_money_rolls_back_exact_open_without_starting() {
    let f = fixture(true);
    let (request, selected, cx, owner) = arrival(&f, 1);
    let binding = request.binding().clone();
    let authorized = f
        .route
        .prepare_test(request, selected, cx)
        .await
        .unwrap()
        .complete()
        .await
        .unwrap();
    let mut allocation = NativeDataAllocation::register(authorized).unwrap();
    let audit = audit_custody(&mut allocation);
    let audit_context = audit.owner.context().clone();
    let context = allocation.context().clone();
    let gov = Arc::new(
        crate::governance::GovState::new_with_core(crate::real_store::core().await, None, None)
            .await
            .unwrap(),
    );
    let money = Arc::new(PlaneMoney::new(gov, Arc::new(Post)));
    let book = money.clone();
    let pending = Arc::new(allocation.into_pending(move |receipt| {
        let admitted = book
            .admit_existing(
                receipt.begin().unwrap(),
                Arc::from(Vec::<String>::new()),
                FeeRefund::CallerStatus,
                ExhaustionMode::FinishUnit,
            )
            .unwrap();
        let admitted = ordinary_unit(&book, admitted, Some(&audit_context));
        assert_eq!(book.open_units(), 1);
        drop(owner); // Actual physical reset wins after the grant and before DATA starts.
        Ok(admitted)
    }));
    let calls = PlaneCalls(AtomicUsize::new(0));
    let task = begin_task(&calls, &pending);
    let declaration = task.request_declaration().unwrap();
    assert!(pending.pending().admit(None, None, declaration).is_err());
    assert_eq!(calls.0.load(Ordering::SeqCst), 1);
    assert!(pending.execution().is_none());
    assert!(binding.check_executing().is_err());
    assert!(!context.effects_allowed());
    assert!(!context.is_live());
    assert_eq!(
        money.open_units(),
        0,
        "failed physical start cannot strand its monetary Open"
    );
    assert_eq!(f.replay.0.load(Ordering::SeqCst), 1);
    drop(task);
    drop(pending);
}
