// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::route::{METHOD_GET, METHOD_HEAD, METHOD_POST, PATH_EXACT};
use busbar_kernel::guest::{Line, LineAuth, Route};
use busbar_kernel::plane_driver::port_routes::Mounted;
use busbar_kernel::plane_driver::port_routes::PortRoutes;
use busbar_plugin_abi::plane::AUTH_PRINCIPAL;

fn routes(entries: &[(u32, &str, u32)]) -> PortRoutes {
    PortRoutes {
        data: entries
            .iter()
            .map(|(route, pattern, methods)| Mounted {
                record: busbar_kernel::auth::route_record::RouteRecord::stated(
                    busbar_kernel::auth::route_record::RouteClass::Data,
                    busbar_kernel::auth::route_record::Who::PRINCIPAL,
                    busbar_kernel::auth::route_record::Scope::walk("pool"),
                    busbar_kernel::auth::route_record::Money::Unit,
                ),
                route: *route,
                methods: *methods,
                flags: 0,
                auth: AUTH_PRINCIPAL,
                effective: AUTH_PRINCIPAL,
                pattern: (*pattern).into(),
                cred_header: None,
                resource_kinds: Default::default(),
                catalog: false,
            })
            .collect(),
        ..Default::default()
    }
}

#[test]
fn native_selection_uses_guest_precedence_and_the_data_mounts_verbs() {
    let generic = routes(&[(9, "/jobs/{id}", METHOD_GET)]);
    let exact = routes(&[(4, "/jobs/current", METHOD_GET), (5, "/head", METHOD_HEAD)]);
    let selected = NativeNests::seal(
        Vec::new(),
        &[("generic", &generic), ("exact", &exact)],
        |_, _| true,
    )
    .unwrap();
    assert_eq!(
        selected.selected("GET", "/jobs/current?cursor=2"),
        Some((1, 4))
    );
    assert_eq!(selected.selected("GET", "/jobs/other"), Some((0, 9)));
    assert_eq!(selected.selected("POST", "/jobs/current"), None);
    assert_eq!(selected.selected("HEAD", "/head"), None);
}

#[test]
fn equal_precedence_native_destinations_refuse_before_publication() {
    let one = routes(&[(1, "/jobs/{id}", METHOD_GET)]);
    let other = routes(&[(7, "/jobs/{name}", METHOD_GET)]);
    assert!(NativeNests::seal(Vec::new(), &[("one", &one), ("two", &other)], |_, _| true).is_err());
}

/// A port's own data line, as the native listener seals it into the generation's guest list.
fn port_line(instance: &str, rung: u32, path: &str) -> Line {
    Line {
        route: Route {
            methods: METHOD_POST,
            path_form: PATH_EXACT,
            path: path.into(),
            fields: Vec::new(),
            rung,
        },
        claimant: Claimant::Plane(instance.into()),
        dialect: 0,
        auth: LineAuth::None,
        upgrade: None,
        offered: busbar_contract::route::AuthPoints::EMPTY,
    }
}

/// The native listener's guest list holds each served port route's own line; the generation's nest
/// table is built from that same list, so a port line is not a repeat of the nest's line for the same
/// route, and a port route the listener left unmounted (no line) is no nest destination.
#[test]
fn the_nest_table_is_built_over_a_guest_list_holding_the_ports_own_lines() {
    let llm = routes(&[
        (2, "/v1/chat/completions", METHOD_POST),
        (7, "/model/x", METHOD_POST),
    ]);
    let guests = vec![port_line("llm", 2, "/v1/chat/completions")];
    let nests = NativeNests::from_guests(&guests, &[("llm", &llm)]).unwrap();
    assert_eq!(nests.selected("POST", "/v1/chat/completions"), Some((0, 2)));
    assert_eq!(nests.selected("POST", "/model/x"), None);
    assert!(!nests.destinations.contains_key(&("llm".to_owned(), 7)));
}

#[test]
fn a_core_claim_cannot_fall_through_to_a_broader_native_destination() {
    let core = Line {
        route: Route {
            methods: METHOD_GET,
            path_form: PATH_EXACT,
            path: "/jobs/core".into(),
            fields: Vec::new(),
            rung: 0,
        },
        claimant: Claimant::Clean("core".into()),
        dialect: 0,
        auth: LineAuth::None,
        upgrade: None,
        offered: busbar_contract::route::AuthPoints::EMPTY,
    };
    let native = routes(&[(1, "/jobs/{id}", METHOD_GET | METHOD_POST)]);
    let selected = NativeNests::seal(vec![core], &[("native", &native)], |_, _| true).unwrap();
    assert_eq!(selected.selected("GET", "/jobs/core"), None);
    assert_eq!(selected.selected("POST", "/jobs/core"), Some((0, 1)));
}

fn reply(bound: usize) -> Reply {
    Reply {
        state: Mutex::default(),
        bound,
        owner: None,
    }
}

#[test]
fn bounded_reply_preserves_status_fields_and_body_order() {
    let reply = reply(8);
    assert!(reply.items(vec![
        ToClient::Head {
            status: 201,
            fields: vec![(b"x".to_vec(), b"y".to_vec())]
        },
        ToClient::Body(b"ab".to_vec())
    ]));
    assert!(reply.items(vec![
        ToClient::Msg {
            flags: 0,
            bytes: b"cd".to_vec()
        },
        ToClient::End
    ]));
    assert_eq!(
        reply.answer(),
        NestReply::Answered {
            status: 201,
            fields: vec![(b"x".to_vec(), b"y".to_vec())],
            body: b"abcd".to_vec()
        }
    );
}

#[test]
fn reply_bound_covers_headers_and_body_and_cannot_recover_after_overflow() {
    let reply = reply(4);
    assert!(reply.items(vec![ToClient::Head {
        status: 200,
        fields: vec![(b"x".to_vec(), b"y".to_vec())]
    }]));
    assert!(!reply.items(vec![ToClient::Body(b"abc".to_vec())]));
    assert!(!reply.items(vec![ToClient::End]));
    assert_eq!(reply.answer(), NestReply::Failed(NEST_UNREAD));
}

fn parent_key() -> Arc<VirtualKey> {
    Arc::new(VirtualKey {
        id: "nested-parent".into(),
        enabled: true,
        ..Default::default()
    })
}

fn nest_of(parent: &UnitRecord, principal: Option<Arc<VirtualKey>>) -> Nest {
    Nest {
        parent: 1,
        depth: parent.depth + 1,
        principal,
        ask: busbar_contract::services::NestAsk {
            verb: "POST".into(),
            target: "/call/local".into(),
            body: b"ping".to_vec(),
        },
        ancestry: Vec::new(),
        constraints: None,
    }
}

/// SECURITY (#105, Aikido 1074607025; v1.5.5 `nested_ordinary_child_never_spends_the_parent_key_on_a_protected_claim`):
/// an ordinary nested child presents no credential and is never authenticated as its keyed parent.
/// On a route that requires a principal it is refused 401 before the plane runs (so nothing is
/// charged); on an optional or public route it is served with no identity. No explicit delegation
/// exists for an ordinary child: the parent's key is only the money admission it spends.
#[tokio::test]
async fn nested_child_of_a_keyed_parent_is_refused_on_a_principal_route() {
    use busbar_kernel::plane_driver::port_auth::{admit, NoTickets};
    use busbar_kernel::refusal::CoreRefusals;
    use busbar_plugin_abi::fail::refused::R_AUTH_REQUIRED;
    use busbar_plugin_abi::plane::{AUTH_OPTIONAL, AUTH_PUBLIC};
    let key = parent_key();
    let parent = UnitRecord {
        principal: Some(Arc::clone(&key)),
        depth: 0,
    };
    let (money, creds) =
        child_admission(&parent, &nest_of(&parent, Some(Arc::clone(&key)))).expect("admitted");
    assert!(
        Arc::ptr_eq(&money, &key),
        "the child spends its parent's admission"
    );
    assert!(creds.bearer.is_none(), "no credential is copied to a child");
    let refusals = CoreRefusals::new();
    let refused = admit(9, AUTH_PRINCIPAL, &creds, &NoTickets, &refusals, "", 1)
        .await
        .err()
        .expect("a principal route refuses a nested child on its parent's key");
    assert_eq!(refused.status, 401);
    assert_eq!(refused.code, R_AUTH_REQUIRED);
    for open in [AUTH_OPTIONAL, AUTH_PUBLIC] {
        let admitted = admit(9, open, &creds, &NoTickets, &refusals, "", 1)
            .await
            .ok()
            .expect("an open route serves the child");
        assert!(
            admitted.identity.is_none(),
            "the child is handed no identity of its parent"
        );
    }
}

/// SECURITY (#105): a nest claiming a principal other than the very key its parent was admitted
/// under (a forged principal, even one naming the same id) is refused, as is one with none.
#[test]
fn nested_child_with_a_forged_principal_is_refused() {
    let key = parent_key();
    let parent = UnitRecord {
        principal: Some(Arc::clone(&key)),
        depth: 0,
    };
    for claimed in [Some(parent_key()), None] {
        assert_eq!(
            child_admission(&parent, &nest_of(&parent, claimed)).err(),
            Some(NEST_PARENT_GONE)
        );
    }
    let anonymous = UnitRecord {
        principal: None,
        depth: 0,
    };
    assert_eq!(
        child_admission(&anonymous, &nest_of(&anonymous, None)).err(),
        Some(PARENT_ADMISSION)
    );
}

#[test]
fn a_body_without_a_head_is_not_a_successful_reply() {
    let reply = reply(4);
    assert!(reply.items(vec![ToClient::Body(b"abc".to_vec())]));
    assert_eq!(reply.answer(), NestReply::Failed(NEST_UNREAD));
}

/// The nest's own run ([`NativeNests::run`]) over one served seat whose plane notes, from inside
/// its `request` crossing, what the child's admitted request holds then (PROOF-093-F rows 397,
/// 398, 409, 410, 412). The seat's route is public, so the child reaches the plane whatever
/// identity it is served with; the money is a real governor's, read through `open_units`.
mod nest_custody {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use busbar_contract::kinds::codes::KindCode;
    use busbar_contract::services::Caller;
    use busbar_kernel::config::groups::ExhaustionMode;
    use busbar_kernel::cost::CostModel;
    use busbar_kernel::host_services::{
        NativeInvocationAdmission, NestDone, NestRoute, ServingGeneration,
    };
    use busbar_kernel::limits::process_admission::{AdmissionClass, ProcessAdmission, RequestLease};
    use busbar_kernel::plane_driver::port::{PortDriver, PortSeat, Unit};
    use busbar_kernel::plane_driver::port_billing::Admit;
    use busbar_kernel::plane_driver::port_intents::{IntentHost, Looked, Namespace};
    use busbar_kernel::plane_driver::{CoreAudit, EndPost, PlaneMoney};
    use busbar_kernel::plugin_records::{CommitOp, CommitOutcome, RecordsDenied, Scope};
    use busbar_plugin_abi::fail::FaultReason;
    use busbar_plugin_abi::host_side::caller::BoxFut;
    use busbar_plugin_abi::plane::AUTH_PUBLIC;
    use busbar_ports::plane::{
        PlaneIn, PlaneOut, PlanePort, PlaneSession, RouteInfo, TargetIn, UsageClass,
    };
    use busbar_ports::{CallCx, PortError};

    use crate::root::serve::{DispatchFrame, Served};

    const ROUTE: u32 = 1;
    const ASK: &[u8] = b"ping";

    fn refused() -> PortError {
        PortError::Refused {
            code: 1,
            text: "refused".into(),
            error: None,
        }
    }

    type OnEnter = Box<dyn FnOnce(&Arc<DispatchSnapshot>) + Send>;

    /// What the plane saw inside its `request` crossing: the body, the request's bytes in use,
    /// whether another Data request was refused then, and the frames retained then.
    type Entered = (Vec<u8>, (usize, usize), bool, usize);

    struct NestPlane {
        routes: [RouteInfo; 1],
        budget: Arc<ProcessAdmission>,
        /// Run first inside the crossing (the parent retiring while its child runs).
        on_enter: Mutex<Option<OnEnter>>,
        snapshot: Mutex<Option<std::sync::Weak<DispatchSnapshot>>>,
        entered: Mutex<Option<Entered>>,
        calls: AtomicUsize,
    }

    impl PlanePort for NestPlane {
        fn route_admission(&self, _: u32) -> Option<(u32, u32, u32, &str)> {
            use busbar_plugin_abi::plane::{CALLERS_SHARED, MONEY_NONE, SCOPE_NONE};
            Some((SCOPE_NONE, MONEY_NONE, CALLERS_SHARED, ""))
        }
        fn routes(&self) -> &[RouteInfo] {
            &self.routes
        }
        fn dialects(&self) -> &[Box<str>] {
            &[]
        }
        fn usage_classes(&self) -> &[UsageClass] {
            &[]
        }
        fn usage_shared(&self) -> (Arc<[UsageClass]>, Arc<[Box<str>]>) {
            Default::default()
        }
        fn facts(&self) -> u64 {
            0
        }
        fn tick_s(&self) -> Option<u64> {
            None
        }
        fn admin_openapi(&self) -> Option<&str> {
            None
        }
        fn charge(&self, _: FaultReason) {}
        fn request(
            &self,
            _: &PlaneIn<'_>,
            body: &[u8],
            _: &mut dyn FnMut(PlaneOut<'_>),
        ) -> Result<PlaneSession, PortError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let snapshot = self
                .snapshot
                .lock()
                .unwrap()
                .as_ref()
                .and_then(std::sync::Weak::upgrade)
                .expect("the seat's snapshot is live while it serves");
            let on_enter = self.on_enter.lock().unwrap().take();
            if let Some(on_enter) = on_enter {
                on_enter(&snapshot);
            }
            let refused_more = self.budget.try_enter(AdmissionClass::Data).is_err();
            let frames = snapshot.frames.lock().unwrap().len();
            *self.entered.lock().unwrap() =
                Some((body.to_vec(), self.budget.used(), refused_more, frames));
            Err(refused())
        }
        fn upstream(
            &self,
            _: &mut PlaneSession,
            _: &TargetIn<'_>,
            _: &mut dyn FnMut(PlaneOut<'_>),
        ) -> Result<(), PortError> {
            Err(refused())
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
            Err(refused())
        }
        fn rewrite(
            &self,
            _: &mut PlaneSession,
            _: &[u8],
            _: &mut dyn FnMut(PlaneOut<'_>),
        ) -> Result<(), PortError> {
            Err(refused())
        }
        fn end(&self, _: PlaneSession, _: &mut dyn FnMut(PlaneOut<'_>)) -> Result<(), PortError> {
            Err(refused())
        }
        fn render(
            &self,
            _: &PlaneIn<'_>,
            _: u32,
            _: &[u8],
            sink: &mut dyn FnMut(PlaneOut<'_>),
        ) -> Result<(), PortError> {
            sink(PlaneOut::Respond { status: 503 });
            sink(PlaneOut::End);
            Ok(())
        }
        fn probe(
            &self,
            _: &TargetIn<'_>,
            _: &mut dyn FnMut(PlaneOut<'_>),
        ) -> Result<PlaneSession, PortError> {
            Err(refused())
        }
        fn demux(
            &self,
            _: &str,
            _: &[u8],
            _: &mut dyn FnMut(PlaneOut<'_>),
        ) -> Result<(), PortError> {
            Err(refused())
        }
        fn admin<'a>(
            &'a self,
            _: CallCx,
            _: u32,
            _: &'a [u8],
        ) -> BoxFut<'a, Result<Vec<u8>, PortError>> {
            Box::pin(async { Err(refused()) })
        }
    }

    struct NoIntents;

    impl IntentHost for NoIntents {
        fn lookup<'a>(
            &'a self,
            _: Scope,
            _: u32,
            _: u32,
            _: &'a [u8],
            _: &'a mut Looked,
        ) -> BoxFut<'a, Result<(), RecordsDenied>> {
            Box::pin(std::future::ready(Err(RecordsDenied::Unavailable)))
        }
        fn store<'a>(
            &'a self,
            _: Scope,
            _: u32,
            _: u64,
            _: &'a [u8],
            _: &'a [u8],
        ) -> BoxFut<'a, Result<(), RecordsDenied>> {
            Box::pin(std::future::ready(Err(RecordsDenied::Unavailable)))
        }
        fn delete<'a>(&'a self, _: Scope, _: &'a [u8]) -> BoxFut<'a, Result<(), RecordsDenied>> {
            Box::pin(std::future::ready(Err(RecordsDenied::Unavailable)))
        }
        fn commit<'a>(
            &'a self,
            _: Scope,
            _: &'a [CommitOp<'a>],
        ) -> BoxFut<'a, Result<CommitOutcome, RecordsDenied>> {
            Box::pin(std::future::ready(Err(RecordsDenied::Unavailable)))
        }
        fn push<'a>(&'a self, _: u64, _: &'a [u8]) -> BoxFut<'a, Result<(), RecordsDenied>> {
            Box::pin(std::future::ready(Err(RecordsDenied::Unavailable)))
        }
        fn signal(&self, _: &[u8], _: Option<[u8; 32]>) {}
    }

    struct Posted;

    impl EndPost for Posted {
        fn post(&self, _: &busbar_kernel::teller::UnitCtx, _: busbar_kernel::teller::Ended) {}
    }

    struct NoChildren;

    impl NestRoute for NoChildren {
        fn nest(&self, _: InvocationContext, _: Nest, _: NestDone) {
            panic!("the nest under test is run directly");
        }
    }

    struct Rig {
        budget: Arc<ProcessAdmission>,
        plane: Arc<NestPlane>,
        snapshot: Arc<DispatchSnapshot>,
        core: Arc<KernelServices>,
        caller: Caller,
        generation: Arc<ServingGeneration>,
        billing: PortBilling,
        money: Arc<PlaneMoney>,
        _admission: NativeInvocationAdmission,
    }

    /// A parent in flight on the rig's seat: its unit record, its retained frame (the admitted
    /// request) and, when keyed, its open money unit.
    struct Parent {
        id: u64,
        context: InvocationContext,
        lease: RequestLease,
        _unit: Option<Unit>,
    }

    fn payer() -> Arc<VirtualKey> {
        Arc::new(VirtualKey {
            id: "nest-payer".into(),
            enabled: true,
            ..Default::default()
        })
    }

    fn nest(parent: u64, principal: Option<Arc<VirtualKey>>) -> Nest {
        Nest {
            parent,
            depth: 1,
            principal,
            ask: busbar_contract::services::NestAsk {
                verb: "POST".into(),
                target: "/call/local".into(),
                body: ASK.to_vec(),
            },
            ancestry: Vec::new(),
            constraints: None,
        }
    }

    async fn seat_rig() -> Rig {
        // Two requests at most, one of them Data: a second Data request is refused while one
        // admitted request is held by anything.
        let budget = ProcessAdmission::with_limits(2, 32, 8);
        let plane = Arc::new(NestPlane {
            routes: [RouteInfo {
                route: ROUTE,
                methods: METHOD_POST,
                flags: 0,
                auth: AUTH_PUBLIC,
                pattern: "/call/local".into(),
                cred_header: None,
                resource_kinds: Default::default(),
            }],
            budget: Arc::clone(&budget),
            on_enter: Mutex::new(None),
            snapshot: Mutex::new(None),
            entered: Mutex::new(None),
            calls: AtomicUsize::new(0),
        });
        let core = Arc::new(KernelServices::new());
        let caller = Caller::issue(
            &busbar_kernel::seal::acquire(),
            Arc::from("nest-seat"),
            KindCode::Plane,
        );
        let admission = core.admit_native_invocation(&caller).unwrap();
        let driver = Arc::new(
            PortDriver::new(
                Arc::clone(&plane) as Arc<dyn PlanePort>,
                Arc::clone(&core),
                caller.clone(),
                Arc::new(busbar_kernel::refusal::CoreRefusals::new()),
                &|_| None,
            )
            .unwrap(),
        );
        let seat = PortSeat {
            public_url: None,
            image: Arc::new(
                busbar_kernel::plane_driver::image_identity::PlaneImageIdentity::new(
                    "nest-seat".into(),
                    None,
                )
                .unwrap(),
            ),
            instance: "seat".into(),
            request_routes: Arc::new(
                busbar_kernel::plane_driver::request_admission::RequestRoutes::new(
                    "seat", None, None, None,
                )
                .unwrap(),
            ),
            channel_budget: busbar_kernel::channels::budget::ChannelBudget::new().instance(),
            driver,
            audience: None,
            intents: Arc::new(NoIntents),
            who: Namespace {
                plugin: Arc::from("nest-seat"),
                name: Arc::from("seat"),
                instance: 1,
                slot: 1,
            },
            upstream: None,
            carrier: None,
        };
        let gov = Arc::new(
            busbar_kernel::governance::GovState::new_with_core(
                crate::root::real_store::core().await,
                None,
                None,
            )
            .await
            .expect("governance builds"),
        );
        let money = Arc::new(PlaneMoney::new(Arc::clone(&gov), Arc::new(Posted)));
        let billing = PortBilling::new(
            Arc::clone(&money),
            gov,
            Arc::new(busbar_kernel::door::UnitKeyMint::default()),
            Arc::new(CoreAudit),
        );
        let snapshot = Arc::new(DispatchSnapshot {
            served: Served {
                ports: vec![seat],
                billing: Some(billing.clone()),
                ..Default::default()
            },
            post: Arc::new(crate::root::plane_node::NodeEndPost::new(
                crate::root::plane_node::node(),
            )),
            guests: Default::default(),
            frames: Mutex::default(),
        });
        *plane.snapshot.lock().unwrap() = Some(Arc::downgrade(&snapshot));
        let generation =
            Arc::new(ServingGeneration::try_new(Arc::clone(&core), Arc::new(NoChildren)).unwrap());
        Rig {
            budget,
            plane,
            snapshot,
            core,
            caller,
            generation,
            billing,
            money,
            _admission: admission,
        }
    }

    impl Rig {
        /// A parent admitted on `key` (`None`: anonymous, with no money unit), registered under
        /// the seat's own owner, its frame retaining its admitted request.
        fn parent(&self, key: Option<&Arc<VirtualKey>>) -> Parent {
            let unit = key.map(|key| {
                self.billing
                    .open(Admit {
                        instance: "seat",
                        classes: Arc::from(Vec::<String>::new()),
                        key: Arc::clone(key),
                        cost: Arc::new(CostModel::resolve_parts(None, 0, &Default::default())),
                        mode: ExhaustionMode::FinishUnit,
                        arrived: 1_700_000_000,
                    })
                    .ok()
                    .expect("the keyed parent opens its unit")
            });
            let id = unit.as_ref().map_or(1, |unit| unit.ctx.key.get());
            self.core.units().admitted_for(
                id,
                &self.caller,
                UnitRecord {
                    principal: key.cloned(),
                    depth: 0,
                },
            );
            let lease = self.budget.try_enter(AdmissionClass::Data).unwrap();
            self.snapshot.frames.lock().unwrap().insert(
                id,
                DispatchFrame {
                    request: lease.clone(),
                },
            );
            let context =
                InvocationContext::new(Arc::clone(&self.generation), self.caller.clone(), id)
                    .unwrap();
            Parent {
                id,
                context,
                lease,
                _unit: unit,
            }
        }

        async fn run(&self, parent: &Parent, principal: Option<Arc<VirtualKey>>) -> NestReply {
            NativeNests::run(
                Arc::clone(&self.snapshot),
                &parent.context,
                &nest(parent.id, principal),
                0,
                ROUTE,
            )
            .await
        }

        fn frames(&self) -> Vec<u64> {
            let mut ids: Vec<u64> = self.snapshot.frames.lock().unwrap().keys().copied().collect();
            ids.sort_unstable();
            ids
        }

        /// The refused nest ran nothing, opened no money, reserved no input and retained no frame.
        fn nothing_ran_or_charged(&self, open: usize, frames: &[u64], case: &str) {
            assert_eq!(self.plane.calls.load(Ordering::SeqCst), 0, "{case}: the plane ran");
            assert_eq!(self.money.open_units(), open, "{case}: the child opened money");
            assert_eq!(self.budget.used(), (0, 0), "{case}: the child reserved input");
            assert_eq!(self.frames(), frames, "{case}: the child retained a frame");
        }
    }

    /// v1.6 `an_admitted_session_exposes_its_parent_frame_until_cleanup` (PROOF-093-F row 397,
    /// flipped to owed by P094): a child is served from its parent's retained frame only while the
    /// parent is in flight. A nest whose parent has no unit record, or no retained frame, answers
    /// NEST_PARENT_GONE, runs nothing and charges nothing; with both, the child is served on the
    /// parent's admitted request.
    #[tokio::test]
    async fn an_admitted_session_exposes_its_parent_frame_until_cleanup() {
        let key = payer();

        let rig = seat_rig().await;
        let parent = rig.parent(Some(&key));
        rig.core.units().ended(parent.id);
        assert_eq!(
            rig.run(&parent, Some(Arc::clone(&key))).await,
            NestReply::Unserved(NEST_PARENT_GONE)
        );
        rig.nothing_ran_or_charged(1, &[parent.id], "no unit record");

        let rig = seat_rig().await;
        let parent = rig.parent(Some(&key));
        rig.snapshot.frames.lock().unwrap().remove(&parent.id);
        assert_eq!(
            rig.run(&parent, Some(Arc::clone(&key))).await,
            NestReply::Unserved(NEST_PARENT_GONE)
        );
        rig.nothing_ran_or_charged(1, &[], "no retained frame");

        let rig = seat_rig().await;
        let parent = rig.parent(Some(&key));
        let served = rig.run(&parent, Some(Arc::clone(&key))).await;
        assert_ne!(served, NestReply::Unserved(NEST_PARENT_GONE));
        assert_eq!(rig.plane.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            *rig.plane.entered.lock().unwrap(),
            Some((ASK.to_vec(), (ASK.len(), ASK.len()), true, 2)),
            "the child ran on its parent's admitted request, its frame beside the parent's"
        );
        assert_eq!(rig.frames(), [parent.id], "the ended child's frame is cleaned up");
        assert_eq!(rig.money.open_units(), 1, "the ended child's unit is settled");
        assert_eq!(rig.budget.used(), (0, 0));
    }

    /// SECURITY (v1.6 `nested_anonymous_admission_matches_the_arrival_rule`, PROOF-093-F row
    /// 398): a parent admitted with no principal can never nest. Its nest is refused
    /// PARENT_ADMISSION before anything runs, and nothing is charged.
    #[tokio::test]
    async fn nested_anonymous_admission_matches_the_arrival_rule() {
        let rig = seat_rig().await;
        let parent = rig.parent(None);
        assert_eq!(
            rig.run(&parent, None).await,
            NestReply::Unserved(PARENT_ADMISSION)
        );
        rig.nothing_ran_or_charged(0, &[parent.id], "anonymous parent");
    }

    /// Retire the parent while its child runs, as its unit's cleanup does: its frame goes, its
    /// own share of the admitted request is dropped, its money settles and its record ends.
    /// `child_frame_too`: the child's own nested frame is cancelled as well.
    fn retire_parent(rig: &Rig, parent: Parent, child_frame_too: bool) {
        let Parent {
            id,
            context,
            lease,
            _unit: unit,
        } = parent;
        let core = Arc::clone(&rig.core);
        let billing = rig.billing.clone();
        *rig.plane.on_enter.lock().unwrap() = Some(Box::new(move |snapshot: &Arc<DispatchSnapshot>| {
            let mut frames = snapshot.frames.lock().unwrap();
            frames.remove(&id);
            if child_frame_too {
                frames.clear();
            }
            drop(frames);
            drop(lease);
            billing.settle(UnitKey::new(id), end_of(200, true));
            drop(unit);
            core.units().ended(id);
        }));
        drop(context);
    }

    /// The nest's run, after `retire_parent` armed the plane: what the plane saw inside the
    /// crossing, and that the child's end released everything.
    async fn run_after_parent_retirement(child_frame_too: bool) -> Entered {
        let key = payer();
        let rig = seat_rig().await;
        let parent = rig.parent(Some(&key));
        let context = parent.context.clone();
        let id = parent.id;
        retire_parent(&rig, parent, child_frame_too);
        let served = NativeNests::run(
            Arc::clone(&rig.snapshot),
            &context,
            &nest(id, Some(Arc::clone(&key))),
            0,
            ROUTE,
        )
        .await;
        assert_ne!(served, NestReply::Unserved(NEST_PARENT_GONE));
        let entered = rig
            .plane
            .entered
            .lock()
            .unwrap()
            .take()
            .expect("the child reached its plane");
        assert_eq!(rig.budget.used(), (0, 0), "the child's end released its input");
        assert!(
            rig.budget.try_enter(AdmissionClass::Data).is_ok(),
            "the child's end released the one Data admission"
        );
        assert!(rig.frames().is_empty());
        assert_eq!(rig.money.open_units(), 0, "the child settled its own unit");
        entered
    }

    /// SECURITY (v1.6 `nested_frame_carries_the_same_admitted_request_after_parent_retirement`,
    /// PROOF-093-F row 409): a native child's input is a copy reserved from its parent's admitted
    /// request, and the child keeps that one Data admission after the parent retires, until the
    /// child itself ends.
    #[tokio::test]
    async fn nested_frame_carries_the_same_admitted_request_after_parent_retirement() {
        assert_eq!(
            run_after_parent_retirement(false).await,
            (ASK.to_vec(), (ASK.len(), ASK.len()), true, 1),
            "after the parent retired: the child's input copy is charged to the parent's request, \
             which still holds the single Data admission, and only the child's frame remains"
        );
    }

    /// SECURITY (v1.6 `cancelled_nested_frame_does_not_retire_its_retained_input_lease`,
    /// PROOF-093-F row 410): with the parent retired and the child's nested frame cancelled too,
    /// the input the child retains still owns the admitted request until the child ends.
    #[tokio::test]
    async fn cancelled_nested_frame_does_not_retire_its_retained_input_lease() {
        assert_eq!(
            run_after_parent_retirement(true).await,
            (ASK.to_vec(), (ASK.len(), ASK.len()), true, 0),
            "with no frame left the retained input alone still owns the Data admission"
        );
    }

    /// v1.6 `cancelling_a_nested_collector_drops_its_live_producer` (PROOF-093-F row 412): a
    /// native nest's collector (its reply sink) owns the child's registration and money. Dropping
    /// it while the child is live and has produced part of an answer (its parent cancelled)
    /// settles the child's unit, ends its record and drops its frame; the parent is untouched.
    #[tokio::test]
    async fn cancelling_a_nested_collector_drops_its_live_producer() {
        let key = payer();
        let rig = seat_rig().await;
        let parent = rig.parent(Some(&key));
        let child = rig
            .billing
            .child(
                UnitKey::new(parent.id),
                &key,
                "seat",
                Arc::from(Vec::<String>::new()),
            )
            .ok()
            .expect("the child opens on its parent's admission");
        let id = child.ctx.key;
        rig.core.units().admitted_for(
            id.get(),
            &rig.caller,
            UnitRecord {
                principal: Some(Arc::clone(&key)),
                depth: 1,
            },
        );
        rig.snapshot.frames.lock().unwrap().insert(
            id.get(),
            DispatchFrame {
                request: parent.lease.clone(),
            },
        );
        let collector = Reply {
            state: Mutex::default(),
            bound: NEST_REPLY_MAX,
            owner: Some(Child {
                snapshot: Arc::clone(&rig.snapshot),
                core: Arc::clone(&rig.core),
                billing: rig.billing.clone(),
                id,
            }),
        };
        assert!(collector.items(vec![
            ToClient::Head {
                status: 200,
                fields: vec![(b"opaque field".to_vec(), b"\0value".to_vec())],
            },
            ToClient::Body(b"one piece".to_vec()),
        ]));
        assert_eq!(rig.money.open_units(), 2, "parent and live child");
        drop(collector);
        assert_eq!(
            rig.money.open_units(),
            1,
            "the child's unit is settled with its collector"
        );
        assert!(
            rig.core.units().get(id.get()).is_none(),
            "the child's record ends with its collector"
        );
        assert_eq!(rig.frames(), [parent.id], "the child's frame is dropped");
        assert!(rig.core.units().get(parent.id).is_some(), "the parent is untouched");
        drop(child);
    }
}
