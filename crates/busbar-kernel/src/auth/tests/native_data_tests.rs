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
use crate::plane_driver::port_session::SessionError;
use crate::plane_driver::{EndPost, FeeRefund, PlaneMoney};
use crate::plane_grants::{KeyRefresh, ReplayGuard};
use crate::plugin_records::RecordsDenied;
use crate::resource_admission::{ForwardFact, FrozenRequest, ResourceFact};
use crate::router::PreparedListener;
use crate::state::AppHandle;
use busbar_contract::kinds::codes::KindCode;
use busbar_contract::records::ScopeRef;
use busbar_contract::route::{METHOD_POST, PATH_EXACT};
use busbar_contract::secure::SecureVec;
use busbar_plugin_abi::host_side::caller::Caller as AbiCaller;
use busbar_plugin_abi::plane::AUTH_PRINCIPAL;
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
        selection: Vec<u8>,
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
        selection: Vec<u8>,
        cx: CallCx,
    ) -> Result<PreparedPhysicalFixture, DataRefused> {
        let preparation = physical
            .begin_data_preparation()
            .map_err(|_| DataRefused::Cancelled)?;
        let pending = self
            .prepare(preparation, cx)
            .await
            .map_err(|error| error.reason())?;
        let pending = if self.selects() {
            pending
                .select(|_, _| Ok(Ok(selection)))
                .map_err(|error| error.reason())?
        } else {
            pending
        };
        Ok(PreparedPhysicalFixture { physical, pending })
    }
}

struct Owners(AtomicUsize, AtomicBool);
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
        let unavailable = self.1.load(Ordering::SeqCst);
        Box::pin(async move {
            tokio::task::yield_now().await;
            if unavailable {
                return Err(RecordsDenied::Unavailable);
            }
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
    fixture_with(allowed, true, Vec::new())
}

fn fixture_with(
    allowed: bool,
    selects: bool,
    limits: Vec<crate::config::groups::LimitCfg>,
) -> Fixture {
    fixture_of(allowed, selects, limits, false)
}

/// `selects`: the route declares a resource kind (its plane selects); otherwise it selects none
/// and is admitted through the plane's `request`. `limits`: the key's group's limits. `open`: the
/// data chain is the operator's explicitly empty `auth.chain: []`.
fn fixture_of(
    allowed: bool,
    selects: bool,
    limits: Vec<crate::config::groups::LimitCfg>,
    open: bool,
) -> Fixture {
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
    // The open relay's principal earns its key like any other identity: from its binding
    // (decision 11). This one keeps 1.5.5's reach: every pool, no group.
    app.role_bindings.insert(
        crate::auth::native_chain::ANONYMOUS.into(),
        BTreeMap::from([(
            crate::config::auth::UNGOVERNED_ROLE.into(),
            crate::config::RoleBindingCfg {
                allowed_pools: None,
                group: None,
                admin_scope: None,
                verbs: None,
                plane_grants: BTreeMap::new(),
            },
        )]),
    );
    app.cost = Arc::new(crate::cost::CostModel::resolve_parts(
        None,
        1,
        &BTreeMap::from([(
            "g".into(),
            GroupCfg {
                enabled: true,
                limits,
                ..Default::default()
            },
        )]),
    ));
    let app = Arc::new(app);
    // The fixture's route as its plane states it: a principal data route that opens a unit, and
    // selects `pool` when the fixture has an inventory. The mounted route and the bound route
    // below carry this one record.
    let record = {
        use crate::auth::route_record::{Money, RouteClass, RouteRecord, Scope, Who};
        RouteRecord::stated(
            RouteClass::Data,
            Who::PRINCIPAL,
            if selects {
                Scope::selected(&["pool"])
            } else {
                Scope::none()
            },
            Money::Unit,
        )
    };
    let mounted = Mounted {
        record: record.clone(),
        route: 3,
        methods: METHOD_POST,
        flags: 0,
        auth: AUTH_PRINCIPAL,
        effective: AUTH_PRINCIPAL,
        pattern: "/resource".into(),
        cred_header: None,
        catalog: false,
        resource_kinds: if selects {
            vec![Box::<str>::from("pool")].into()
        } else {
            Vec::<Box<str>>::new().into()
        },
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
    let replay = Arc::new(Owners(AtomicUsize::new(0), AtomicBool::new(false)));
    let calls = Arc::new(Port {
        calls: AtomicUsize::new(0),
        not_mine: false,
        native: true,
    });
    let owners = Arc::new(AuthOwners {
        issued: replay.clone(),
        replay: replay.clone(),
        cache: Arc::new(Verdicts::new(VerdictPolicy::DEFAULT)),
    });
    let chain = Arc::new(if open {
        NativeChain::data_admitting_anonymous(7, Vec::new(), owners).unwrap()
    } else {
        NativeChain::data(7, vec![instance(42, calls.clone())], owners).unwrap()
    });
    // Assemble only candidate configuration here. Every request proof below uses the public
    // physical factory, real charged selection, concrete verifier, publication and replay.
    let admission = crate::auth::admission_table::admission_of(&record);
    let route = Arc::new(NativeDataRoute {
        ticket: None,
        withheld: withheld_carriers(&chain, None),
        audience: None,
        public_url: None,
        challenge: None,
        record,
        admission,
        binding,
        caller,
        cost: app.cost.clone(),
        owners: DataRouteOwners {
            generation,
            inventory: selects.then_some(inventory),
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
/// The plane's RESOURCE_SELECT answer a selecting route's test selector returns.
type Wire = Vec<u8>;

fn arrival(f: &Fixture, stream: u64) -> (CompletingPhysicalRequest, Wire, CallCx, StreamOwner) {
    arrival_with_fields(f, stream, Vec::new())
}

fn arrival_with_fields(
    f: &Fixture,
    stream: u64,
    fields: Vec<(String, Vec<u8>)>,
) -> (CompletingPhysicalRequest, Wire, CallCx, StreamOwner) {
    arrival_with(f, stream, fields, b"admin-body")
}

/// `body`: the fixture's verifier accepts exactly `admin-body`; any other body is unauthenticated.
fn arrival_with(
    f: &Fixture,
    stream: u64,
    fields: Vec<(String, Vec<u8>)>,
    body: &[u8],
) -> (CompletingPhysicalRequest, Wire, CallCx, StreamOwner) {
    let arrival =
        crate::inbound::native::Arrival::at(crate::store::monotonic_ns(), Duration::from_secs(30))
            .unwrap();
    let deadline = arrival.deadline();
    let (request, owner) = f
        .connection
        .head(
            stream,
            {
                let mut head = crate::inbound::Head::default();
                head.method = "POST".into();
                head.target = "/resource".into();
                head.fields = fields;
                head
            },
            f.budget.try_enter(AdmissionClass::Data).unwrap(),
            Some(arrival),
        )
        .unwrap();
    let credit = request.binding().request().try_reserve(body.len()).unwrap();
    let request = request
        .finish_input(SecureVec::from(body), credit)
        .unwrap()
        .begin_completion()
        .unwrap();
    let binding = request.binding();
    let mut wire = Reply::new();
    busbar_plugin_abi::resource_admission::write_selection(
        &mut wire,
        &[busbar_plugin_abi::resource_admission::Scope {
            kind: "pool",
            value: "chat",
        }],
    )
    .unwrap();
    let cx = CallCx {
        deadline,
        request_id: binding.invocation().request_id().get(),
        stack: Default::default(),
        mono_ns: 0,
    };
    (request, wire.as_bytes().to_vec(), cx, owner)
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
    let pending = f
        .route
        .prepare(preparation, cx)
        .await
        .unwrap()
        .select(|_, _| Ok(Ok(selected)))
        .unwrap();
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
    let calls = PlaneCalls(AtomicUsize::new(0), true);
    let task = begin_task(&calls, &pending);
    let declaration = task.request_declaration().unwrap();
    assert!(
        pending
            .pending()
            .admit::<crate::plane_driver::port_serve::NoWalk>(None, None, declaration)
            .is_err(),
        "original physical and money owners cannot replace Node audit custody"
    );
    assert_eq!(commits.load(Ordering::SeqCst), 0);
    assert_eq!(money.open_units(), 0);
    assert!(!context.effects_allowed());
    assert!(binding.check_executing().is_err());
    assert!(pending.execution().is_none());
}

#[tokio::test]
async fn native_data_replay_store_error_is_not_confirmed_duplicate() {
    let f = fixture(true);
    f.replay.1.store(true, Ordering::SeqCst);
    let (request, selected, cx, _owner) = arrival(&f, 1);
    let binding = request.binding().clone();
    let pending = f.route.prepare_test(request, selected, cx).await.unwrap();
    let result = pending.complete().await;
    assert!(result.is_err());
    assert!(
        !matches!(result, Err(DataRefused::Replay)),
        "an unavailable original Store claim is not a confirmed duplicate"
    );
    assert_eq!(f.replay.0.load(Ordering::SeqCst), 1);
    assert!(binding.check_executing().is_err());
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
    let calls = PlaneCalls(AtomicUsize::new(0), true);
    let mut task = begin_task(&calls, &pending);
    let declaration = task.request_declaration().unwrap();
    pending
        .pending()
        .admit::<crate::plane_driver::port_serve::NoWalk>(None, None, declaration)
        .unwrap();
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

/// What a selector double was lent: the request's path, body and header names.
#[derive(Default)]
struct Lent {
    calls: usize,
    path: String,
    body: Vec<u8>,
    headers: Vec<String>,
}

fn lend(
    lent: &Mutex<Lent>,
    frozen: &FrozenRequest,
    withheld: &[Box<str>],
    wire: Vec<u8>,
) -> crate::resource_admission::Selection {
    frozen.with_selection_input(withheld, |input, body| {
        let mut lent = lent.lock().unwrap();
        lent.calls += 1;
        lent.path = input.path.to_owned();
        lent.body = body.to_vec();
        lent.headers = input
            .headers
            .iter()
            .map(|field| field.name.get().to_ascii_lowercase())
            .collect();
        Ok(wire)
    })
}

#[tokio::test]
async fn native_data_unauthenticated_request_is_lent_nothing_and_a_verified_one_no_carrier() {
    let f = fixture(true);
    let fields = vec![
        ("authorization".to_owned(), b"Bearer secret".to_vec()),
        ("x-trace".to_owned(), b"1".to_vec()),
    ];
    // Unauthenticated: the credential is refused, and a refused request has no `PendingData`, so
    // its selector can never be reached; the double records nothing.
    let lent = Mutex::new(Lent::default());
    let (mut request, wire, cx, _owner) = arrival_with(&f, 1, fields.clone(), b"forged-body");
    let preparation = request.begin_data_preparation().unwrap();
    let refused = f.route.prepare(preparation, cx).await;
    let Err(failed) = refused else {
        panic!("an unauthenticated request verified")
    };
    assert_eq!(failed.reason(), DataRefused::Credential);
    assert_eq!(lent.lock().unwrap().calls, 0);
    drop(wire);
    // Verified: lent once, after verification, its path and body, never a carrier.
    let (mut request, wire, cx, _owner) = arrival_with(&f, 2, fields, b"admin-body");
    let preparation = request.begin_data_preparation().unwrap();
    let pending = f.route.prepare(preparation, cx).await.unwrap();
    assert_eq!(
        f.calls.calls.load(Ordering::SeqCst),
        2,
        "verified before any lending"
    );
    assert_eq!(lent.lock().unwrap().calls, 0);
    let pending = pending
        .select(|frozen, withheld| lend(&lent, frozen, withheld, wire))
        .unwrap();
    let lent = lent.into_inner().unwrap();
    assert_eq!(lent.calls, 1);
    assert_eq!(lent.path, "/resource");
    assert_eq!(lent.body, b"admin-body");
    assert_eq!(lent.headers, vec!["x-trace".to_owned()]);
    assert!(pending.complete().await.is_ok());
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
    let calls = PlaneCalls(AtomicUsize::new(0), true);
    let task = begin_task(&calls, &pending);
    let declaration = task.request_declaration().unwrap();
    assert!(f.connection.cancel(&owner));
    assert!(pending
        .pending()
        .admit::<crate::plane_driver::port_serve::NoWalk>(None, None, declaration)
        .is_err());
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

/// A plane double: its `request` calls, and whether its route declares resource kinds.
struct PlaneCalls(AtomicUsize, bool);
impl crate::plane_driver::port_session::Calls for PlaneCalls {
    type Session = ();
    fn resource_scoped(&self, _: u32) -> bool {
        self.1
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
    let withheld = data.withheld();
    let (task, _) = data
        .snapshot()
        .with_auth_input(|request| {
            // The plane is lent the request's fields minus the route's withheld carriers, as
            // `PortDriver::serve_admitted` lends them.
            let lent: Vec<_> = request
                .headers
                .iter()
                .filter(|field| {
                    !withheld
                        .iter()
                        .any(|carrier| carrier.eq_ignore_ascii_case(field.name.get()))
                })
                .copied()
                .collect();
            crate::plane_driver::port_session::Task::begin(
                calls,
                &busbar_ports::plane::PlaneIn {
                    route: data.route(),
                    flags: 0,
                    auth: AUTH_PRINCIPAL,
                    method: request.method,
                    path: request.path,
                    query: request.query,
                    headers: &lent,
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
    use busbar_contract::abi::mechanism::call::Outcome;
    use busbar_contract::services::codes::{OUTBOUND_BIND, OUTBOUND_PUBLISH, OUTBOUND_REVOKE};
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
    let calls = PlaneCalls(AtomicUsize::new(0), true);
    let effects = DataEffects(&pending);
    let answer = pending
        .snapshot()
        .with_auth_input(|request| {
            crate::plane_driver::port_session::Task::begin(
                &calls,
                &busbar_ports::plane::PlaneIn {
                    route: pending.route(),
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
    let calls = PlaneCalls(AtomicUsize::new(0), true);
    let task = begin_task(&calls, &pending);
    let declaration = task.request_declaration().unwrap();
    assert!(pending
        .pending()
        .admit::<crate::plane_driver::port_serve::NoWalk>(None, None, declaration)
        .is_err());
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

fn limit(metric: crate::config::groups::LimitMetric) -> crate::config::groups::LimitCfg {
    crate::config::groups::LimitCfg {
        selected: None,
        metric,
        amount: 0,
        per: Some(crate::config::groups::LimitWindow::Month),
        scope: None,
        on_exhaust: None,
        downgrade_to: None,
    }
}

/// What one request on a route that selects no resource came to: how often money was asked,
/// what it answered, and the books after it.
struct NoSelection {
    commits: usize,
    admitted: Result<(), SessionError>,
    open_units: usize,
    effects: bool,
    executing: bool,
    refusal: Option<ClientRefusal>,
    pending: Arc<NativeDataPending>,
}

/// One authenticated request on an llm-shaped route (no resource kinds) under the key's group
/// `limits`, through verification, its unit, the plane's `request` and core's money admission.
async fn no_selection_request(
    limits: Vec<crate::config::groups::LimitCfg>,
) -> (NoSelection, StreamOwner) {
    request_on(fixture_with(true, false, limits)).await
}

async fn request_on(f: Fixture) -> (NoSelection, StreamOwner) {
    let open = f.route.owners.chain.is_open();
    assert!(!f.route.selects());
    let (request, wire, cx, owner) = arrival(&f, 1);
    let binding = request.binding().clone();
    let authorized = f
        .route
        .prepare_test(request, wire, cx)
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
    let commits = Arc::new(AtomicUsize::new(0));
    let counted = commits.clone();
    let pending = Arc::new(allocation.into_pending(move |receipt| {
        counted.fetch_add(1, Ordering::SeqCst);
        let admitted = book
            .admit_existing(
                receipt.begin().unwrap(),
                Arc::from(Vec::<String>::new()),
                FeeRefund::CallerStatus,
                ExhaustionMode::FinishUnit,
            )
            .map_err(|_| ClientRefusal {
                status: 429,
                code: busbar_plugin_abi::fail::refused::R_RATE_LIMITED,
                text: "rate limit exceeded".into(),
            })?;
        Ok(ordinary_unit(&book, admitted, Some(&audit_context)))
    }));
    assert!(pending.selected().is_none());
    let calls = PlaneCalls(AtomicUsize::new(0), false);
    let mut task = begin_task(&calls, &pending);
    assert_eq!(
        calls.0.load(Ordering::SeqCst),
        1,
        "the plane's `request` ran"
    );
    let declaration = task.request_declaration().unwrap();
    let admitted = pending
        .pending()
        .admit::<crate::plane_driver::port_serve::NoWalk>(None, None, declaration)
        .map(|_| ());
    let refusal = match &admitted {
        Err(SessionError::AdmissionRefused(refusal)) => Some(refusal.clone()),
        _ => None,
    };
    if admitted.is_ok() {
        task.bind_admission(pending.pending()).unwrap();
        task.end(&DataEffects(&pending)).unwrap();
    }
    drop(task);
    let result = NoSelection {
        commits: commits.load(Ordering::SeqCst),
        admitted,
        open_units: money.open_units(),
        effects: context.effects_allowed(),
        executing: binding.check_executing().is_ok(),
        refusal,
        pending,
    };
    // An open chain verifies nothing and claims no replay key.
    let verified = usize::from(!open);
    assert_eq!(f.replay.0.load(Ordering::SeqCst), verified);
    assert_eq!(f.calls.calls.load(Ordering::SeqCst), verified);
    drop(audit);
    (result, owner)
}

#[tokio::test]
async fn native_data_route_that_selects_nothing_is_admitted_with_one_unit_and_its_money() {
    let (served, _owner) = no_selection_request(Vec::new()).await;
    assert!(served.admitted.is_ok());
    assert_eq!(served.commits, 1, "money is asked exactly once");
    assert_eq!(served.open_units, 1, "the unit's money is open");
    assert!(served.effects);
    assert!(served.executing);
    let execution = served.pending.execution().unwrap();
    assert!(execution.selected().is_none());
}

#[tokio::test]
async fn native_data_route_that_selects_nothing_is_refused_by_its_budget_and_its_rate_limit() {
    for metric in [
        crate::config::groups::LimitMetric::Budget,
        crate::config::groups::LimitMetric::Requests,
    ] {
        let (refused, _owner) = no_selection_request(vec![limit(metric)]).await;
        assert!(
            matches!(refused.admitted, Err(SessionError::AdmissionRefused(_))),
            "a zero {metric:?} limit refuses before any effect"
        );
        assert_eq!(refused.commits, 1);
        assert_eq!(refused.open_units, 0, "nothing is charged");
        assert!(!refused.effects);
        assert!(!refused.executing);
        assert!(refused.pending.execution().is_none());
        // The refusal keeps its custody: it is answered under the original physical request.
        let decision = refused.refusal.unwrap();
        assert!(refused.pending.take_refusal(&decision).is_ok());
    }
}

#[tokio::test]
async fn native_data_refusal_decided_before_money_keeps_its_custody_and_money_never_runs() {
    let f = fixture_with(true, false, Vec::new());
    let (request, wire, cx, _owner) = arrival(&f, 1);
    let authorized = f
        .route
        .prepare_test(request, wire, cx)
        .await
        .unwrap()
        .complete()
        .await
        .unwrap();
    let mut allocation = NativeDataAllocation::register(authorized).unwrap();
    let audit = audit_custody(&mut allocation);
    let commits = Arc::new(AtomicUsize::new(0));
    let counted = commits.clone();
    let pending = Arc::new(allocation.into_pending(move |_| {
        counted.fetch_add(1, Ordering::SeqCst);
        Err(ClientRefusal {
            status: 503,
            code: busbar_plugin_abi::fail::refused::R_NO_ROUTE,
            text: "unreachable".into(),
        })
    }));
    let calls = PlaneCalls(AtomicUsize::new(0), false);
    let task = begin_task(&calls, &pending);
    let declaration = task.request_declaration().unwrap();
    // The session refused before asking money (the key's grant, the plane's own refusal).
    let decision = crate::plane_driver::port_admission::scope_refusal();
    assert_eq!(decision.status, 403);
    assert!(pending.take_refusal(&decision).is_ok());
    assert!(
        pending.take_refusal(&decision).is_err(),
        "the custody leaves once"
    );
    // Money can no longer run for it.
    assert!(pending
        .pending()
        .admit::<crate::plane_driver::port_serve::NoWalk>(None, None, declaration)
        .is_err());
    assert_eq!(commits.load(Ordering::SeqCst), 0);
    assert!(pending.execution().is_none());
    drop(task);
    drop(audit);
}

/// A DATA request that carries its credential in `Authorization` reaches the plane's `request`:
/// the plane is lent the fields minus that carrier, and the session accepts exactly that lent set.
#[tokio::test]
async fn native_data_request_with_a_withheld_carrier_reaches_the_planes_request() {
    let f = fixture_with(true, false, Vec::new());
    let fields = vec![
        ("authorization".to_owned(), b"Bearer plain".to_vec()),
        ("x-trace".to_owned(), b"1".to_vec()),
    ];
    let (request, wire, cx, _owner) = arrival_with_fields(&f, 1, fields);
    let authorized = f
        .route
        .prepare_test(request, wire, cx)
        .await
        .unwrap()
        .complete()
        .await
        .unwrap();
    let mut allocation = NativeDataAllocation::register(authorized).unwrap();
    let audit = audit_custody(&mut allocation);
    let pending = Arc::new(allocation.into_pending(|_| {
        Err(ClientRefusal {
            status: 503,
            code: busbar_plugin_abi::fail::refused::R_NO_ROUTE,
            text: "unused".into(),
        })
    }));
    let calls = PlaneCalls(AtomicUsize::new(0), false);
    let task = begin_task(&calls, &pending);
    assert_eq!(
        calls.0.load(Ordering::SeqCst),
        1,
        "the plane's `request` ran"
    );
    drop(task);
    drop(audit);
}

#[tokio::test]
async fn native_data_open_chain_serves_the_anonymous_principal_through_admission() {
    // `auth.chain: []`: no credential is read and no verifier runs, as 1.5.5's open relay; the
    // request is still admitted with its unit and money, as the anonymous key.
    let (served, _owner) = request_on(fixture_of(true, false, Vec::new(), true)).await;
    assert!(served.admitted.is_ok());
    assert_eq!(served.commits, 1);
    assert_eq!(served.open_units, 1);
    assert!(served.effects);
    assert!(served.executing);
    let execution = served.pending.execution().unwrap();
    assert_eq!(
        execution.principal().id,
        crate::auth::native_chain::ANONYMOUS
    );
    assert!(execution.principal().allowed_scopes.is_none());
    assert_eq!(execution.principal().group, None);
    assert_eq!(
        execution.identity().subject(),
        crate::auth::native_chain::ANONYMOUS
    );
    assert_eq!(
        served
            .pending
            .context()
            .principal()
            .map(|key| key.id.as_str()),
        Some(crate::auth::native_chain::ANONYMOUS),
        "the unit is recorded under the anonymous key"
    );
}

#[tokio::test]
async fn native_data_open_chain_charges_no_group_as_v155_did() {
    // The anonymous key belongs to no group, so a group's limits do not apply to it (1.5.5 charged
    // no group for a keyless request); the process admission at the head still bounds it.
    let (refused, _owner) = request_on(fixture_of(
        true,
        false,
        vec![limit(crate::config::groups::LimitMetric::Requests)],
        true,
    ))
    .await;
    assert!(
        refused.admitted.is_ok(),
        "1.5.5 charged no group for a keyless request"
    );
}

#[test]
fn a_key_without_a_grant_of_the_named_pool_or_model_is_answered_v155s_403() {
    use crate::plane_driver::port_admission::forward_refused;
    use crate::plane_driver::request_admission::AdmissionError;
    let SessionError::AdmissionRefused(refusal) = forward_refused(AdmissionError::Scope) else {
        panic!("a scope refusal is answered")
    };
    assert_eq!(refusal.status, 403);
    assert_eq!(refusal.code, busbar_plugin_abi::fail::refused::R_DENIED);
    assert_eq!(
        refusal.text,
        "Your API key does not have permission to access this resource."
    );
    assert!(matches!(
        forward_refused(AdmissionError::Route),
        SessionError::NotDriven
    ));
}

#[tokio::test]
async fn native_data_selecting_route_is_never_completed_without_its_selection() {
    let f = fixture(true);
    let (mut request, _wire, cx, _owner) = arrival(&f, 1);
    let preparation = request.begin_data_preparation().unwrap();
    let pending = f.route.prepare(preparation, cx).await.unwrap();
    assert!(matches!(
        pending.complete().await.map_err(|failed| failed.reason()),
        Err(DataRefused::Binding)
    ));
    assert_eq!(
        f.replay.0.load(Ordering::SeqCst),
        0,
        "no replay key is spent"
    );
}

#[tokio::test]
async fn native_data_route_that_selects_nothing_lends_no_selection() {
    let f = fixture_with(true, false, Vec::new());
    let (mut request, wire, cx, _owner) = arrival(&f, 1);
    let preparation = request.begin_data_preparation().unwrap();
    let pending = f.route.prepare(preparation, cx).await.unwrap();
    let lent = Mutex::new(Lent::default());
    assert!(pending
        .select(|frozen, withheld| lend(&lent, frozen, withheld, wire))
        .is_err());
    assert_eq!(lent.into_inner().unwrap().calls, 0);
}

fn chain_owners() -> Arc<AuthOwners> {
    let replay = Arc::new(Owners(AtomicUsize::new(0), AtomicBool::new(false)));
    Arc::new(AuthOwners {
        issued: replay.clone(),
        replay,
        cache: Arc::new(Verdicts::new(VerdictPolicy::DEFAULT)),
    })
}

fn names(names: &[&str]) -> Vec<Box<str>> {
    names.iter().map(|name| Box::<str>::from(*name)).collect()
}

/// The built-in member `keys` (core's own token verifier) is a member only of a data chain that
/// names it: the operator chain never has it, so a core-minted token is never judged on the
/// admin listener.
#[test]
fn the_keys_member_exists_only_on_a_data_chain_that_names_it() {
    use crate::auth::native_chain::BuiltIn;
    let keys_only = NativeChain::data_with(
        7,
        Vec::new(),
        chain_owners(),
        BuiltIn {
            anonymous: false,
            keys: true,
        },
    )
    .expect("`chain: [keys]` is a closed chain, not an empty one");
    assert!(keys_only.admits_keys());
    assert!(!keys_only.admits_anonymous());
    assert!(
        !keys_only.is_open(),
        "a chain with a verifier reads its credential"
    );
    assert!(keys_only.matches_names(&names(&["keys"])));
    assert!(!keys_only.matches_names(&names(&[])));
    assert!(!keys_only.matches_names(&names(&["keys", "anonymous"])));

    let port = Arc::new(Port {
        calls: AtomicUsize::new(0),
        not_mine: false,
        native: true,
    });
    let plain = NativeChain::data(7, vec![instance(42, port.clone())], chain_owners()).unwrap();
    assert!(!plain.admits_keys());
    assert!(plain.matches_names(&names(&["provider-42"])));
    assert!(
        !plain.matches_names(&names(&["provider-42", "keys"])),
        "a route that names `keys` is never bound to a chain without the member"
    );

    let both = NativeChain::data_with(
        7,
        vec![instance(42, port.clone())],
        chain_owners(),
        BuiltIn {
            anonymous: true,
            keys: true,
        },
    )
    .unwrap();
    assert!(both.matches_names(&names(&["provider-42", "keys", "anonymous"])));
    assert!(!both.is_open());
    let relay = NativeChain::data_with(
        7,
        Vec::new(),
        chain_owners(),
        BuiltIn {
            anonymous: true,
            keys: true,
        },
    )
    .unwrap();
    assert!(
        !relay.is_open(),
        "`[keys, anonymous]` still reads a credential: a core token presented is judged"
    );
    assert!(
        NativeChain::data_with(7, Vec::new(), chain_owners(), BuiltIn::default()).is_err(),
        "an empty chain is still refused"
    );

    let operator = NativeChain::operator(
        vec![instance(42, port)],
        crate::auth::native_policy::ChainPolicy::new(7, Vec::new()),
        chain_owners(),
    );
    assert!(
        !operator.admits_keys(),
        "the admin listener's chain has no `keys` member"
    );
}

/// A ticket route at its own preparation, end to end.
#[path = "native_data_ticket_tests.rs"]
mod ticket;
