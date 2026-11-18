// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Signed original request -> actual Task/walk mint -> current App gate. Only the
//! plane callbacks and network peer are scripted; no receipt or rate token is fabricated.

use super::*;
use std::collections::BTreeMap;
use std::num::NonZeroU32;

use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::caps::{Pass, Route};
use busbar_contract::services::Caller;
use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_plugin_abi::plane::{AUTH_PRINCIPAL, FB_ATTEMPT_USAGE, UNIT_TOKENS};
use busbar_ports::plane::{PlanePort, PlaneSession, RouteInfo, UsageClass};
use busbar_ports::CallCx;

use crate::auth::ChainVerdict;
use crate::config::groups::{ExhaustionMode, GroupCfg};
use crate::cost::CostModel;
use crate::governance::current_credential::CurrentCredentialRefusal;
use crate::governance::selected_policy::{
    SelectedPolicy, SelectedPolicyRefusal, SelectedTargetConfig, SelectedTargetKind,
};
use crate::governance::selected_resource::RateRefusalKind;
use crate::governance::signing::{TokenSigner, DEFAULT_KID};
use crate::governance::{GovState, NewKeySpec};
use crate::host_services::{
    InvocationContext, KernelServices, Nest, NestDone, NestRoute, ServingGeneration,
};
use crate::plane_driver::money::{EndPost, FeeRefund, PlaneMoney};
use crate::plane_driver::port::{PortDriver, PortSeat};
use crate::plane_driver::port_admission::{AdmittedUnit, Pending};
use crate::plane_driver::port_billing::PortBilling;
use crate::plane_driver::port_egress::{
    prepare_fixture, upstream_targets, EgressWalk, MemberTarget, PortUpstream, SeatPool,
    SessionFacts, Targets,
};
use crate::plane_driver::port_intents::{IntentHost, Looked, Namespace};
use crate::plane_driver::port_upstream::{Members, UpSend, Wants};
use crate::plane_driver::request_admission::{
    RequestAllocation, RequestPoolReceipt, RequestRoutes,
};
use crate::plane_driver::route::{FarEnd, FarPiece, OutboundRequest, Pick};
use crate::plugin_records::{CommitOp, CommitOutcome, RecordsDenied, Scope};
use crate::state::{App, AppHandle, SelectedCommitRejected, SelectedRateRejected};
use crate::upstreams::{ConfiguredUpstreams, UpstreamDef};

struct NoChildren;
impl NestRoute for NoChildren {
    fn nest(&self, _: InvocationContext, _: Nest, _: NestDone) {
        panic!("this request must not create a child");
    }
}

struct Posted;
impl EndPost for Posted {
    fn post(&self, _: &crate::teller::UnitCtx, _: crate::teller::Ended) {}
    fn checkpoint_facts(&self, _: busbar_contract::UnitKey) -> Option<Vec<u8>> {
        Some(vec![1])
    }
}

struct NoIntents;
impl IntentHost for NoIntents {
    fn lookup(&self, _: Scope, _: u32, _: u32, _: &[u8]) -> Result<Looked, RecordsDenied> {
        Err(RecordsDenied::Unavailable)
    }
    fn store(&self, _: Scope, _: u32, _: u64, _: &[u8], _: &[u8]) -> Result<(), RecordsDenied> {
        Err(RecordsDenied::Unavailable)
    }
    fn delete(&self, _: Scope, _: &[u8]) -> Result<(), RecordsDenied> {
        Err(RecordsDenied::Unavailable)
    }
    fn commit(&self, _: Scope, _: &[CommitOp<'_>]) -> Result<CommitOutcome, RecordsDenied> {
        Err(RecordsDenied::Unavailable)
    }
    fn push(&self, _: u64, _: &[u8]) -> Result<(), RecordsDenied> {
        Err(RecordsDenied::Unavailable)
    }
    fn signal(&self, _: &[u8], _: Option<[u8; 32]>) {}
}

/// The driver's opened descriptor. Script supplies the corresponding callbacks to Task.
struct Descriptor {
    routes: Vec<RouteInfo>,
    classes: Vec<UsageClass>,
    attempt_classes: Vec<Box<str>>,
}
impl PlanePort for Descriptor {
    fn routes(&self) -> &[RouteInfo] {
        &self.routes
    }
    fn dialects(&self) -> &[Box<str>] {
        &[]
    }
    fn usage_classes(&self) -> &[UsageClass] {
        &self.classes
    }
    fn attempt_classes(&self) -> &[Box<str>] {
        &self.attempt_classes
    }
    fn facts(&self) -> u64 {
        FB_ATTEMPT_USAGE
    }
    fn tick_s(&self) -> Option<u64> {
        None
    }
    fn admin_openapi(&self) -> Option<&str> {
        None
    }
    fn charge(&self, _: busbar_plugin_abi::fail::FaultReason) {
        panic!("unexpected plane fault")
    }
    fn request(
        &self,
        _: &PlaneIn<'_>,
        _: &[u8],
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<PlaneSession, PortError> {
        unreachable!("Task uses Script")
    }
    fn upstream(
        &self,
        _: &mut PlaneSession,
        _: &TargetIn<'_>,
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        unreachable!("Task uses Script")
    }
    fn piece(
        &self,
        _: &mut PlaneSession,
        _: u32,
        _: u32,
        _: u32,
        _: &[u8],
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        unreachable!("Task uses Script")
    }
    fn rewrite(
        &self,
        _: &mut PlaneSession,
        _: &[u8],
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        unreachable!("Task uses Script")
    }
    fn end(&self, _: PlaneSession, _: &mut dyn FnMut(PlaneOut<'_>)) -> Result<(), PortError> {
        unreachable!("Task uses Script")
    }
    fn render(
        &self,
        _: &PlaneIn<'_>,
        _: u32,
        _: &[u8],
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        unreachable!("Task uses Script")
    }
    fn probe(
        &self,
        _: &TargetIn<'_>,
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<PlaneSession, PortError> {
        unreachable!("no probe")
    }
    fn demux(&self, _: &str, _: &[u8], _: &mut dyn FnMut(PlaneOut<'_>)) -> Result<(), PortError> {
        unreachable!("no channel")
    }
    fn admin<'a>(
        &'a self,
        _: CallCx,
        _: u32,
        _: &'a [u8],
    ) -> BoxFut<'a, Result<Vec<u8>, PortError>> {
        Box::pin(async { unreachable!("no admin") })
    }
}

struct CurrentTargets(Targets);
impl PortUpstream for CurrentTargets {
    fn target(&self, pool: &str, member: &str) -> Option<MemberTarget> {
        (self.0)(pool, member)
    }
    fn walk(&self, _: SessionFacts, _: &mut dyn FnMut(&mut dyn Members, &mut dyn UpSend)) {
        unreachable!("the fixture retains its actual EgressWalk")
    }
}

struct NoSend;
impl FarEnd for NoSend {
    // The far end a selected walk admits names its pool (64b918c418: a request is selected only
    // onto a far end scoped to the receipt's walk).
    fn scope(&self, _: &Pass<Route>) -> Option<crate::plane_driver::RoutedScope> {
        Some(crate::plane_driver::RoutedScope {
            pool: "seat".into(),
            container: String::new(),
        })
    }
    async fn send_selected(
        &self,
        _: &Pass<Route>,
        _: OutboundRequest,
        _: &mut crate::plane_driver::port_egress::SelectedHandoff,
    ) -> bool {
        panic!("refused preparation must not reach the connector")
    }
    async fn member(&self, _: &Pass<Route>, _: u32) -> Pick {
        Pick::Member {
            name: "seat\u{1f}up".into(),
            pool: "seat".into(),
            passthrough: false,
            provider: "up".into(),
        }
    }
    async fn send(&self, _: &Pass<Route>, _: OutboundRequest) -> bool {
        panic!("refused preparation must not send")
    }
    async fn next(&self, _: &Pass<Route>) -> Option<FarPiece> {
        panic!("no response exists")
    }
    async fn write(&self, _: &Pass<Route>, _: OutboundRequest) -> bool {
        panic!("refused preparation must not write")
    }
    fn judged_stating(&self, _: &Pass<Route>, _: u8, _: Option<&str>) {
        panic!("policy refusal must not affect a breaker")
    }
}

struct OriginalEffects {
    context: InvocationContext,
    pending: Arc<Pending>,
}
impl Effects for OriginalEffects {
    fn invocation(&self) -> Option<&InvocationContext> {
        Some(&self.context)
    }
    fn admission_owner(&self) -> Option<&Arc<Pending>> {
        Some(&self.pending)
    }
    fn admission(&self) -> Option<&Pending> {
        Some(&self.pending)
    }
    fn emit(&self, _: u64, _: &[u8]) {
        panic!("no external effect expected")
    }
}

fn classes() -> Vec<UsageClass> {
    vec![UsageClass {
        class: "tokens".into(),
        unit: UNIT_TOKENS,
        expected_units: None,
    }]
}

fn app(
    gov: &Arc<GovState>,
    seat: PortSeat,
    amount: u64,
    previous: Option<&SelectedPolicy>,
) -> Arc<App> {
    app_for(
        gov,
        seat,
        amount,
        previous,
        SelectedTargetConfig {
            instance: "seat",
            kind: SelectedTargetKind::Registration,
            pool: "seat",
            member: "seat\u{1f}up",
            resource: Some("configured"),
            attempt_accounting: true,
        },
    )
}

fn app_for(
    gov: &Arc<GovState>,
    seat: PortSeat,
    amount: u64,
    previous: Option<&SelectedPolicy>,
    target: SelectedTargetConfig<'_>,
) -> Arc<App> {
    let groups: BTreeMap<String, GroupCfg> = busbar_contract::yaml::from_str(&format!(
        "team:\n  limits:\n    - {{id: rpm, upstream_resource: seat/configured, requests: {amount}, per: minute, per_key: true, enforcement: process}}"
    )).unwrap();
    let mut app = crate::inbound::native::tests::app();
    let next = Arc::get_mut(&mut app).unwrap();
    next.cost = Arc::new(CostModel::resolve_parts(None, 0, &groups));
    next.governance = Some(gov.clone());
    next.port_seats = Arc::from([seat]);
    let pending = SelectedPolicy::compile(&groups, next.cost.clone(), &[target], previous).unwrap();
    if let Some(previous) = previous {
        next.selected_policy = Some(Arc::new(
            pending
                .activate(
                    Some(previous),
                    previous.revision() + 1,
                    gov.selected_rates().activation_minute().unwrap(),
                )
                .unwrap(),
        ));
    } else {
        pending.install_initial(next).unwrap();
    }
    app
}

#[test]
fn signed_selected_preparation_rechecks_current_policy_and_revocation_before_handoff() {
    // EgressWalk uses Handle::block_on, like production's blocking Task executor.
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _entered = rt.enter();
    let now = crate::store::now();
    let (gov, authority) = rt.block_on(async {
        let gov = Arc::new(
            GovState::new_with_core(
                crate::real_store::core().await,
                None,
                Some(TokenSigner::from_secret_bytes(&[17; 32], DEFAULT_KID)),
            )
            .await
            .unwrap(),
        );
        let (_, token) = gov
            .mint_signed_async(
                NewKeySpec {
                    name: "selected-original".into(),
                    group: Some("team".into()),
                    ..Default::default()
                },
                now + 3600,
                now,
            )
            .await
            .unwrap();
        let authority = match crate::auth::keys_arm_verdict(
            Some(&gov),
            Some(token.expose(&crate::seal::lend())),
            now,
            None,
        ) {
            ChainVerdict::Identified {
                signed_authority: Some(authority),
                ..
            } => authority,
            _ => panic!("actual signed verification must retain authority"),
        };
        (gov, authority)
    });
    let money = Arc::new(PlaneMoney::new(gov.clone(), Arc::new(Posted)));
    let billing = PortBilling::new(
        money.clone(),
        gov.clone(),
        Arc::new(crate::door::UnitKeyMint::default()),
        Arc::new(crate::plane_driver::CoreAudit),
    );
    let unit = billing.allocate(Arc::from(["tokens".to_owned()]));
    let core = Arc::new(KernelServices::new());
    let caller = Caller::for_test(Arc::from("seat"), KindCode::Plane);
    let _owner = core.admit_native_invocation(&caller).unwrap();
    assert!(core
        .units()
        .pre_admitted_signed_for(unit.ctx.key.get(), &caller, authority, 0));
    let context = InvocationContext::new(
        Arc::new(ServingGeneration::try_new(core.clone(), Arc::new(NoChildren)).unwrap()),
        caller.clone(),
        unit.ctx.key.get(),
    )
    .unwrap();
    let definition = Arc::new(
        UpstreamDef::from_config(
            "up",
            &busbar_contract::json::json!({"url":"https://example.com"}),
            &crate::config::min3::UpstreamCfg {
                resource: Some("configured".into()),
                ..Default::default()
            },
            &crate::plugin_config::upstream_anchor,
        )
        .unwrap(),
    );
    let upstreams = Arc::new(ConfiguredUpstreams::from_definitions(BTreeMap::from([(
        "up".into(),
        definition.clone(),
    )])));
    let routes = Arc::new(
        RequestRoutes::new(
            "seat",
            None,
            None,
            Some(Arc::new(SeatPool::of("seat", &upstreams).unwrap())),
        )
        .unwrap(),
    );
    let targets = upstream_targets("seat", upstreams);
    let driver = Arc::new(
        PortDriver::new(
            Arc::new(Descriptor {
                routes: vec![RouteInfo {
                    route: 1,
                    methods: 2,
                    flags: 0,
                    auth: AUTH_PRINCIPAL,
                    pattern: "/x".into(),
                    cred_header: None,
                    resource_kinds: Vec::new(),
                }],
                classes: classes(),
                attempt_classes: vec!["tokens".into()],
            }),
            core,
            caller,
            Arc::new(crate::refusal::CoreRefusals::new()),
            &|_| None,
        )
        .unwrap(),
    );
    let seat = PortSeat {
        image: Arc::new(
            crate::plane_driver::image_identity::PlaneImageIdentity::new("scripted".into(), None)
                .unwrap(),
        ),
        instance: "seat".into(),
        request_routes: routes.clone(),
        channel_budget: crate::channels::budget::ChannelBudget::new().instance(),
        driver,
        audience: None,
        intents: Arc::new(NoIntents),
        who: Namespace {
            plugin: Arc::from("scripted"),
            name: Arc::from("seat"),
            instance: 1,
            slot: 1,
        },
        upstream: Some(Arc::new(CurrentTargets(targets.clone()))),
        carrier: None,
    };
    let original = app(&gov, seat.clone(), 2, None);
    let original_cost = original.cost.clone();
    let original_key = context.principal().unwrap().clone();
    let handle = Arc::new(AppHandle::new(original.clone()));
    let admission = handle.selected_rate_admission();
    let origin = seat.retain_route(&context, 1).unwrap();
    let terminal = Arc::new(Mutex::new(None));
    let terminal_out = terminal.clone();
    let generation = context.generation().routing_generation().unwrap();
    let pending = Arc::new(
        Pending::new_selected(
            RequestAllocation::new(context.clone(), original_cost.clone(), now).unwrap(),
            routes,
            None,
            move |receipt, declaration| {
                let selected = billing
                    .admit_existing_selected(
                        receipt.begin().unwrap(),
                        declaration,
                        generation,
                        NonZeroU32::new(2).unwrap(),
                        FeeRefund::CallerStatus,
                        ExhaustionMode::FinishUnit,
                    )
                    .unwrap();
                *terminal_out.lock().unwrap() = Some(selected.terminal_receipt().unwrap());
                let rollback = billing.admission_rollback(selected.request()).unwrap();
                Ok(AdmittedUnit::selected(unit, selected, rollback).unwrap())
            },
        )
        .with_route(origin)
        .with_current_rates(admission.clone()),
    );
    let effects = OriginalEffects {
        context: context.clone(),
        pending: pending.clone(),
    };
    let script = Script {
        facts: FB_ATTEMPT_USAGE,
        classes: classes(),
        attempt_classes: vec!["tokens".into()],
        request: vec![It::Forward],
        upstream_items: Mutex::new(VecDeque::from([vec![
            It::SelectedResource,
            It::UpMethod,
            It::UpEnd,
        ]])),
        ..Default::default()
    };
    let mut request = req();
    request.request_id = context.unit();
    request.auth = AUTH_PRINCIPAL;
    let kernel = crate::teller::Kernel::new();
    let route = Pass::mint(kernel.seal());
    let make = |_: &Wants, _: Option<&RequestPoolReceipt>| NoSend;
    let runtime = rt.handle().clone();
    let walk = EgressWalk::new(&make, &route, &runtime, &*targets);
    let (mut task, prepared, _walk) =
        prepare_fixture(&script, &request, b"{}", &effects, pending.clone(), walk).unwrap();
    assert_eq!(money.open_units(), 1);
    assert!(Arc::ptr_eq(prepared.receipt().cost(), &original_cost));
    assert!(Arc::ptr_eq(prepared.receipt().key(), &original_key));
    let reservation = admission.reserve(prepared).unwrap();
    let prepared = reservation.cancel();

    let tightened = app(&gov, seat.clone(), 0, original.selected_policy.as_deref());
    rt.block_on(handle.swap(tightened.clone()));
    let prepared = match admission.reserve(prepared) {
        Err(SelectedRateRejected::Rate(rejected)) => {
            assert_eq!(rejected.reason.kind, RateRefusalKind::Rpm);
            assert_eq!(rejected.reason.snapshots[0].rule.threshold, 0);
            assert_eq!(rejected.reason.snapshots[0].rule.policy_revision, 2);
            rejected.prepared
        }
        _ => panic!("current threshold must refuse the original preparation"),
    };
    assert!(Arc::ptr_eq(prepared.receipt().cost(), &original_cost));
    assert!(Arc::ptr_eq(prepared.receipt().key(), &original_key));
    assert!(!Arc::ptr_eq(&tightened.cost, &original_cost));
    assert_eq!(money.open_units(), 1, "reload must not re-admit money");

    let mut changed_seat = seat.clone();
    changed_seat.image = Arc::new(
        crate::plane_driver::image_identity::PlaneImageIdentity::new(
            "scripted".into(),
            Some([3; 32]),
        )
        .unwrap(),
    );
    let changed = app(&gov, changed_seat, 3, tightened.selected_policy.as_deref());
    rt.block_on(handle.swap(changed.clone()));
    let prepared = match admission.reserve(prepared) {
        Err(SelectedRateRejected::Policy { reason, prepared }) => {
            assert_eq!(reason, SelectedPolicyRefusal::StalePolicyTarget);
            prepared
        }
        _ => panic!("same instance name cannot authorize a changed admitted image"),
    };
    let relaxed = app(&gov, seat, 3, changed.selected_policy.as_deref());
    rt.block_on(handle.swap(relaxed));
    let reservation = admission.reserve(prepared).unwrap();
    rt.block_on(gov.revoke_async(&original_key.id, "fixture revoke before handoff"))
        .unwrap();
    let selected = pending.admitted().unwrap().selected.as_ref().unwrap();
    let prepared = match admission.commit(selected, reservation) {
        Err(SelectedCommitRejected::Policy { reason, prepared }) => {
            assert_eq!(
                reason,
                SelectedPolicyRefusal::CurrentAuthority(CurrentCredentialRefusal::Revoked)
            );
            prepared
        }
        _ => panic!("handoff must preserve the actual current credential refusal"),
    };
    assert!(Arc::ptr_eq(prepared.receipt().cost(), &original_cost));
    assert!(Arc::ptr_eq(prepared.receipt().key(), &original_key));
    selected.no_send(prepared).unwrap();
    task.end(&effects).unwrap();
    selected
        .work_ended(crate::plane_driver::usage::Ending::End)
        .unwrap();
    let view = money.usage_view(selected.request().unit()).unwrap();
    let crate::plane_driver::money::UsageView::Partitioned(snapshot) = view.as_ref() else {
        panic!("actual selected checkpoint must remain retained");
    };
    let parts = snapshot.partitions.as_ref().unwrap();
    assert_eq!(parts.attempts.len(), 1);
    assert_eq!(
        parts.attempts[0].transport,
        crate::governance::unit_checkpoint::partitions::Transport::NoSend
    );
    assert!(parts.attempts[0].dispatch.is_none());
    assert!(!parts.far_end_answered);
    assert!(!parts.caller_bytes_committed);
    assert!(
        terminal.lock().unwrap().is_some(),
        "retain the original final reader"
    );
    assert_eq!(
        money.open_units(),
        1,
        "only terminal settlement releases the original Open"
    );
    // No client response was delivered. This bounded fixture ends with uncompleted terminal
    // custody; RegisteredDelivery owns settlement after an actual refusal response.
}

/// A provider-catalog plan for plane `seat`: model `m` (provider `provider`, wire model
/// `wire-m`) in authored pool `p`.
fn catalog_plan() -> crate::plane_driver::provider_catalog::CatalogPlan {
    use crate::config::{self, providers, Grammar};
    use crate::plane_driver::provider_catalog::ProviderPlane;
    let grammar = Grammar::empty();
    let definitions = providers::catalog_from_str(
        "provider:\n  protocol: wire\n  base_url: https://upstream.example\n",
        &grammar,
    )
    .unwrap();
    let deployment = config::deploy_from_yaml_str(
        "providers:\n  provider: {api_key: none}\nmodels:\n  m:\n    provider: provider\n    upstream_model: wire-m\npools:\n  p: {members: [m]}\n",
        &grammar,
    )
    .unwrap();
    let mut resolved = config::resolve_with_provider_planes(
        &deployment,
        &definitions,
        &[ProviderPlane {
            instance: "seat".into(),
            image: "image".into(),
            dialects: ["wire".into()].into(),
            schema: r#"{"type":"object","additionalProperties":false}"#.into(),
        }],
    )
    .unwrap();
    resolved.catalogs.remove("seat").unwrap()
}

/// The far end of a catalog walk: it picks the catalog member under the pool's walk key and is
/// scoped to that walk, as the connector-built far end is.
struct CatalogNoSend {
    walk: String,
}
impl FarEnd for CatalogNoSend {
    fn scope(&self, _: &Pass<Route>) -> Option<crate::plane_driver::RoutedScope> {
        Some(crate::plane_driver::RoutedScope {
            pool: self.walk.clone(),
            container: String::new(),
        })
    }
    async fn send_selected(
        &self,
        _: &Pass<Route>,
        _: OutboundRequest,
        _: &mut crate::plane_driver::port_egress::SelectedHandoff,
    ) -> bool {
        panic!("preparation must not reach the connector")
    }
    async fn member(&self, _: &Pass<Route>, _: u32) -> Pick {
        Pick::Member {
            name: "seat\u{1f}m".into(),
            pool: self.walk.clone(),
            passthrough: false,
            provider: "provider".into(),
        }
    }
    async fn send(&self, _: &Pass<Route>, _: OutboundRequest) -> bool {
        panic!("preparation must not send")
    }
    async fn next(&self, _: &Pass<Route>) -> Option<FarPiece> {
        panic!("no response exists")
    }
    async fn write(&self, _: &Pass<Route>, _: OutboundRequest) -> bool {
        panic!("preparation must not write")
    }
    fn judged_stating(&self, _: &Pass<Route>, _: u8, _: Option<&str>) {
        panic!("preparation must not affect a breaker")
    }
}

/// A selected attempt over a provider-catalog pool, end to end from the signed original request
/// through the actual Task/walk to the money boundary: the partition records the request's
/// instance-qualified pool (`seat\u{1f}p`), never the catalog's length-framed walk key, and the
/// partition rule (ddd61a377f) still refuses a pool of another instance or the walk key itself.
#[test]
fn a_selected_catalog_attempt_records_its_instance_qualified_pool() {
    use crate::governance::unit_checkpoint::partitions::ValidatedSelectedCheckpoint;
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _entered = rt.enter();
    let now = crate::store::now();
    let (gov, authority) = rt.block_on(async {
        let gov = Arc::new(
            GovState::new_with_core(
                crate::real_store::core().await,
                None,
                Some(TokenSigner::from_secret_bytes(&[17; 32], DEFAULT_KID)),
            )
            .await
            .unwrap(),
        );
        let (_, token) = gov
            .mint_signed_async(
                NewKeySpec {
                    name: "selected-catalog".into(),
                    group: Some("team".into()),
                    ..Default::default()
                },
                now + 3600,
                now,
            )
            .await
            .unwrap();
        let authority = match crate::auth::keys_arm_verdict(
            Some(&gov),
            Some(token.expose(&crate::seal::lend())),
            now,
            None,
        ) {
            ChainVerdict::Identified {
                signed_authority: Some(authority),
                ..
            } => authority,
            _ => panic!("actual signed verification must retain authority"),
        };
        (gov, authority)
    });
    let money = Arc::new(PlaneMoney::new(gov.clone(), Arc::new(Posted)));
    let billing = PortBilling::new(
        money.clone(),
        gov.clone(),
        Arc::new(crate::door::UnitKeyMint::default()),
        Arc::new(crate::plane_driver::CoreAudit),
    );
    let unit = billing.allocate(Arc::from(["tokens".to_owned()]));
    let core = Arc::new(KernelServices::new());
    let caller = Caller::for_test(Arc::from("seat"), KindCode::Plane);
    let _owner = core.admit_native_invocation(&caller).unwrap();
    assert!(core
        .units()
        .pre_admitted_signed_for(unit.ctx.key.get(), &caller, authority, 0));
    let context = InvocationContext::new(
        Arc::new(ServingGeneration::try_new(core.clone(), Arc::new(NoChildren)).unwrap()),
        caller.clone(),
        unit.ctx.key.get(),
    )
    .unwrap();
    let plan = catalog_plan();
    let walk_key = plan.select("p").unwrap().to_owned();
    assert!(
        !walk_key.contains('\u{1f}'),
        "a catalog walk key is an internal length-framed key"
    );
    let member = plan.target(&walk_key, "seat\u{1f}m").unwrap().clone();
    let definition = Arc::new(
        UpstreamDef::from_config(
            "up",
            &busbar_contract::json::json!({"url":"https://upstream.example"}),
            &crate::config::min3::UpstreamCfg {
                resource: Some("configured".into()),
                ..Default::default()
            },
            &crate::plugin_config::upstream_anchor,
        )
        .unwrap(),
    );
    // As root's catalog staging builds it (min3_provider_catalog): a model target under the
    // pool's walk key and the qualified member.
    let targets: Targets = {
        let (walk, definition) = (walk_key.clone(), definition.clone());
        Arc::new(move |pool: &str, qualified: &str| {
            (pool == walk && qualified == "seat\u{1f}m").then(|| MemberTarget {
                identity: crate::plane_driver::port_upstream::TargetIdentity::Model {
                    dialect: member.dialect.as_str().into(),
                    model: member.wire_model.as_str().into(),
                },
                definition: Some(crate::plane_driver::port_egress::TargetDefinition::new(
                    definition.clone(),
                )),
                resource: definition.resource.clone(),
                registered_upstream: Some(definition.name.clone()),
                provider: member.projection.as_ref().into(),
                base_path: member.base_path.as_str().into(),
                flags: 0,
                params: member.params.clone(),
            })
        })
    };
    let routes = Arc::new(
        RequestRoutes::new("seat", Some(Arc::from("pool")), Some(Arc::new(plan)), None).unwrap(),
    );
    let driver = Arc::new(
        PortDriver::new(
            Arc::new(Descriptor {
                routes: vec![RouteInfo {
                    route: 1,
                    methods: 2,
                    flags: 0,
                    auth: AUTH_PRINCIPAL,
                    pattern: "/x".into(),
                    cred_header: None,
                    resource_kinds: Vec::new(),
                }],
                classes: classes(),
                attempt_classes: vec!["tokens".into()],
            }),
            core,
            caller,
            Arc::new(crate::refusal::CoreRefusals::new()),
            &|_| None,
        )
        .unwrap(),
    );
    let seat = PortSeat {
        image: Arc::new(
            crate::plane_driver::image_identity::PlaneImageIdentity::new("scripted".into(), None)
                .unwrap(),
        ),
        instance: "seat".into(),
        request_routes: routes.clone(),
        channel_budget: crate::channels::budget::ChannelBudget::new().instance(),
        driver,
        audience: None,
        intents: Arc::new(NoIntents),
        who: Namespace {
            plugin: Arc::from("scripted"),
            name: Arc::from("seat"),
            instance: 1,
            slot: 1,
        },
        upstream: Some(Arc::new(CurrentTargets(targets.clone()))),
        carrier: None,
    };
    let original = app_for(
        &gov,
        seat.clone(),
        2,
        None,
        SelectedTargetConfig {
            instance: "seat",
            kind: SelectedTargetKind::Model,
            pool: &walk_key,
            member: "seat\u{1f}m",
            resource: Some("configured"),
            attempt_accounting: true,
        },
    );
    let original_cost = original.cost.clone();
    let handle = Arc::new(AppHandle::new(original));
    let admission = handle.selected_rate_admission();
    let origin = seat.retain_route(&context, 1).unwrap();
    let generation = context.generation().routing_generation().unwrap();
    let pending = Arc::new(
        Pending::new_selected(
            RequestAllocation::new(context.clone(), original_cost.clone(), now).unwrap(),
            routes,
            None,
            move |receipt, declaration| {
                let selected = billing
                    .admit_existing_selected(
                        receipt.begin().unwrap(),
                        declaration,
                        generation,
                        NonZeroU32::new(2).unwrap(),
                        FeeRefund::CallerStatus,
                        ExhaustionMode::FinishUnit,
                    )
                    .unwrap();
                let rollback = billing.admission_rollback(selected.request()).unwrap();
                Ok(AdmittedUnit::selected(unit, selected, rollback).unwrap())
            },
        )
        .with_route(origin)
        .with_current_rates(admission),
    );
    let effects = OriginalEffects {
        context: context.clone(),
        pending: pending.clone(),
    };
    let script = Script {
        facts: FB_ATTEMPT_USAGE,
        classes: classes(),
        attempt_classes: vec!["tokens".into()],
        request: vec![
            It::Forward,
            It::WantText(busbar_plugin_abi::plane::W_MODEL, "p"),
        ],
        upstream_items: Mutex::new(VecDeque::from([vec![
            It::SelectedResource,
            It::UpMethod,
            It::UpEnd,
        ]])),
        ..Default::default()
    };
    let mut request = req();
    request.request_id = context.unit();
    request.auth = AUTH_PRINCIPAL;
    let kernel = crate::teller::Kernel::new();
    let route = Pass::mint(kernel.seal());
    let make = {
        let walk = walk_key.clone();
        move |_: &Wants, _: Option<&RequestPoolReceipt>| CatalogNoSend { walk: walk.clone() }
    };
    let runtime = rt.handle().clone();
    let walk = EgressWalk::new(&make, &route, &runtime, &*targets);
    let (_task, prepared, _walk) =
        prepare_fixture(&script, &request, b"{}", &effects, pending.clone(), walk)
            .expect("a selected attempt over a catalog pool is prepared");
    let unit_key = prepared.receipt().unit();
    let view = money.usage_view(unit_key).unwrap();
    let crate::plane_driver::money::UsageView::Partitioned(snapshot) = view.as_ref() else {
        panic!("the selected checkpoint is retained");
    };
    let parts = snapshot.partitions.as_ref().unwrap();
    assert_eq!(parts.attempts.len(), 1);
    assert_eq!(parts.attempts[0].instance, "seat");
    assert_eq!(parts.attempts[0].selected_pool, "seat\u{1f}p");
    assert_eq!(parts.attempts[0].usage.lane, "seat\u{1f}m");
    assert!(ValidatedSelectedCheckpoint::try_from(&**snapshot).is_ok());
    // The partition rule is unchanged: a pool of another instance, or the bare walk key, is refused.
    for refused in ["other\u{1f}p".to_owned(), walk_key] {
        let mut changed = (**snapshot).clone();
        changed.partitions.as_mut().unwrap().attempts[0].selected_pool = refused.clone();
        assert!(
            ValidatedSelectedCheckpoint::try_from(&changed).is_err(),
            "selected_pool {refused:?} must be refused"
        );
    }
}
