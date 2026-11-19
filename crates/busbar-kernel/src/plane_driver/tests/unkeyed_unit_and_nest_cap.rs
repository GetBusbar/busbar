// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Owed security proof (SECURITY-OWED `an_unkeyed_unit_on_a_credential_claim_is_refused` and
//! `a_nest_past_the_depth_cap_is_refused`, deleted with the door pipeline's `serve_money.rs`), on
//! the native path end to end:
//!
//! - a request with no key on a route that claims a credential (IF §12.11 `AUTH_PRINCIPAL`, alone or
//!   beside `AUTH_TICKET`) is refused 401 `R_AUTH_REQUIRED` through [`PortDriver::serve`], and the
//!   plane's request crossing never runs, so nothing is served, forwarded or charged;
//! - a unit that nests through the serving generation, each child nesting again, is refused
//!   `NEST_TOO_DEEP` one level past `NEST_DEPTH_MAX` before the root sees it, every level below the
//!   cap is handed on under the parent's principal one level deeper, and every nest permit is given
//!   back.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::records::VirtualKey;
use busbar_contract::services::{Caller, NestAsk};
use busbar_plugin_abi::fail::refused::R_AUTH_REQUIRED;
use busbar_plugin_abi::fail::FaultReason;
use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_plugin_abi::plane::{AUTH_PRINCIPAL, AUTH_TICKET};
use busbar_ports::plane::{
    PlaneIn, PlaneOut, PlanePort, PlaneSession, RouteInfo, TargetIn, UsageClass,
};
use busbar_ports::{CallCx, PortError};

use super::input_custody_tests::NoIntents;
use super::{HttpHead, HttpIn, PortDriver, ServeIn, Served};
use crate::host_services::{
    InstanceFacts, InvocationContext, KernelServices, Nest, NestDone, NestReply, NestRoute,
    ServingGeneration, NEST_CONCURRENCY, NEST_DEPTH_MAX, NEST_TOO_DEEP,
};
use crate::host_units::UnitRecord;
use crate::limits::process_admission::{AdmissionClass, ProcessAdmission};
use crate::plane_driver::port_auth::{Credentials, Principal};
use crate::plane_driver::port_session::ToClient;
use crate::refusal::CoreRefusals;

const CLAIM: u32 = 1;

fn refused() -> PortError {
    PortError::Refused {
        code: 1,
        text: "refused".into(),
        error: None,
    }
}

/// A plane with one data route under `auth`; it counts the request crossings it is asked to run
/// and serves none of them, and renders no refusal (core's own text is served).
struct CredentialClaim {
    routes: [RouteInfo; 1],
    requests: AtomicUsize,
}

impl CredentialClaim {
    fn new(auth: u32) -> Arc<Self> {
        Arc::new(Self {
            routes: [RouteInfo {
                route: CLAIM,
                methods: 1,
                flags: 0,
                auth,
                pattern: "/claim".into(),
                cred_header: None,
                resource_kinds: Default::default(),
            }],
            requests: AtomicUsize::new(0),
        })
    }
}

impl PlanePort for CredentialClaim {
    fn route_admission(&self, _: u32) -> Option<(u32, u32, u32, &str)> {
        use busbar_plugin_abi::plane::{CALLERS_SHARED, MONEY_NONE, SCOPE_NONE};
        Some((SCOPE_NONE, MONEY_NONE, CALLERS_SHARED, ""))
    }
    fn routes(&self) -> &[RouteInfo] {
        &self.routes
    }
    fn resource_facts(
        &self,
        _: u32,
        _: &PlaneIn<'_>,
        _: &[u8],
        _: usize,
    ) -> Result<Vec<u8>, PortError> {
        Err(refused())
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
        _: &[u8],
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<PlaneSession, PortError> {
        self.requests.fetch_add(1, Ordering::Relaxed);
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
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        Err(refused())
    }
    fn probe(
        &self,
        _: &TargetIn<'_>,
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<PlaneSession, PortError> {
        Err(refused())
    }
    fn demux(&self, _: &str, _: &[u8], _: &mut dyn FnMut(PlaneOut<'_>)) -> Result<(), PortError> {
        Err(refused())
    }
    fn admin<'a>(
        &'a self,
        _: CallCx,
        _: u32,
        _: &'a [u8],
    ) -> BoxFut<'a, Result<Vec<u8>, PortError>> {
        Box::pin(async move { Err(refused()) })
    }
}

/// One request with no key at all: no bearer, no verified principal, no operator credential, no
/// signature.
fn unkeyed(budget: &Arc<ProcessAdmission>) -> ServeIn<'static> {
    ServeIn {
        invocation: None,
        request: budget.try_enter(AdmissionClass::Data).unwrap(),
        admission: None,
        route: CLAIM,
        http: HttpIn::new(
            HttpHead::Text {
                method: "GET".into(),
                path: "/claim".into(),
                query: String::new(),
                headers: Vec::new(),
            },
            bytes::Bytes::new(),
            1,
        ),
        creds: Credentials {
            bearer: None,
            principal: Principal::Anonymous,
            operator: false,
            signed: None,
        },
        audience: "",
        now_s: 0,
        unit: None,
        upstream: None,
        client: None,
        carrier: None,
        intents: Arc::new(NoIntents),
        models: Vec::new(),
    }
}

#[test]
fn an_unkeyed_unit_on_a_credential_claim_is_refused() {
    for auth in [AUTH_PRINCIPAL, AUTH_PRINCIPAL | AUTH_TICKET] {
        let plane = CredentialClaim::new(auth);
        let driver = PortDriver::new(
            plane.clone(),
            Arc::new(KernelServices::new()),
            Caller::for_test(Arc::from("unkeyed"), KindCode::Plane),
            Arc::new(CoreRefusals::new()),
            &|_| None,
        )
        .unwrap();
        let budget = ProcessAdmission::with_limits(1, 64, 8);
        let served = crate::rt::current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(driver.serve(unkeyed(&budget)));
        let Ok(Served::Refused(refused)) = served else {
            panic!("auth={auth:#x}: an unkeyed request on a credential claim was not refused");
        };
        assert_eq!(
            (refused.decision.status, refused.decision.code),
            (401, R_AUTH_REQUIRED),
            "auth={auth:#x}: refused as unauthenticated"
        );
        assert!(
            matches!(
                refused.items.first(),
                Some(ToClient::Head { status: 401, .. })
            ),
            "auth={auth:#x}: the client is answered 401"
        );
        assert!(
            matches!(refused.items.last(), Some(ToClient::End)),
            "auth={auth:#x}: the refusal is the whole answer"
        );
        assert_eq!(
            plane.requests.load(Ordering::Relaxed),
            0,
            "auth={auth:#x}: the plane never ran the unkeyed request, so nothing was charged"
        );
    }
}

/// The root: every nested claim is served as a child unit admitted one level deeper under the
/// parent's principal, and that child nests once more. A child answers 200 with
/// `nested:<status>:` and its own child's body, or `nest-refused:<why>` when its nest was refused.
struct NestsAgain {
    caller: Caller,
    next_unit: AtomicU64,
    /// (parent, depth, principal) of every nest the root was handed.
    seen: Mutex<Vec<(u64, u32, Option<String>)>>,
}

fn ask() -> NestAsk {
    NestAsk {
        verb: "POST".into(),
        target: "/call/nest".into(),
        body: Vec::new(),
    }
}

impl NestRoute for NestsAgain {
    fn nest(&self, context: InvocationContext, nest: Nest, done: NestDone) {
        self.seen.lock().unwrap().push((
            nest.parent,
            nest.depth,
            nest.principal.as_ref().map(|key| key.id.clone()),
        ));
        let child = self.next_unit.fetch_add(1, Ordering::Relaxed);
        context.generation().core().units().admitted_for(
            child,
            &self.caller,
            UnitRecord {
                principal: nest.principal,
                depth: nest.depth,
            },
        );
        let child = InvocationContext::new(Arc::clone(context.generation()), self.caller.clone(), child)
            .expect("the admitted child unit is in flight");
        child
            .nest(
                &self.caller,
                ask(),
                Box::new(move |reply| {
                    let body = match reply {
                        NestReply::Answered { status, body, .. } => {
                            [format!("nested:{status}:").into_bytes(), body].concat()
                        }
                        NestReply::Unserved(why) => format!("nest-refused:{why}").into_bytes(),
                        NestReply::Failed(why) => format!("nest-failed:{why}").into_bytes(),
                    };
                    done(NestReply::Answered {
                        status: 200,
                        fields: Vec::new(),
                        body,
                    });
                }),
            )
            .expect("the child unit may nest");
    }
}

#[test]
fn a_nest_past_the_depth_cap_is_refused() {
    let caller = Caller::for_test(Arc::from("inst"), KindCode::Plane);
    let core = Arc::new(KernelServices::new());
    futures::FutureExt::now_or_never(core.admit(&Arc::from("inst"), InstanceFacts::default()))
        .expect("in-memory fixture admission finishes in one poll")
        .unwrap();
    let root = Arc::new(NestsAgain {
        caller: caller.clone(),
        next_unit: AtomicU64::new(2),
        seen: Mutex::new(Vec::new()),
    });
    let generation = Arc::new(ServingGeneration::new(core.clone(), root.clone()));
    let alice = Arc::new(VirtualKey {
        id: "alice".into(),
        ..VirtualKey::default()
    });
    core.units().admitted_for(
        1,
        &caller,
        UnitRecord {
            principal: Some(alice),
            depth: 0,
        },
    );

    let answer: Arc<Mutex<Option<NestReply>>> = Arc::default();
    let slot = Arc::clone(&answer);
    InvocationContext::new(generation, caller.clone(), 1)
        .expect("the caller's unit is in flight")
        .nest(
            &caller,
            ask(),
            Box::new(move |reply| *slot.lock().unwrap() = Some(reply)),
        )
        .expect("the caller's unit may nest");

    let deep = NEST_DEPTH_MAX as usize;
    let answered = answer.lock().unwrap().take().expect("answered");
    assert_eq!(
        answered,
        NestReply::Answered {
            status: 200,
            fields: Vec::new(),
            body: format!("{}nest-refused:{NEST_TOO_DEEP}", "nested:200:".repeat(deep - 1))
                .into_bytes(),
        },
        "every level up to the cap ran; the one past it was refused"
    );
    let seen = root.seen.lock().unwrap().clone();
    let expected: Vec<(u64, u32, Option<String>)> = (1..=NEST_DEPTH_MAX)
        .map(|depth| (u64::from(depth), depth, Some("alice".to_owned())))
        .collect();
    assert_eq!(
        seen, expected,
        "the root was handed each level up to the cap under the caller's principal, never past it"
    );
    assert_eq!(
        core.nested().available(),
        NEST_CONCURRENCY,
        "every nest permit went back"
    );
}
