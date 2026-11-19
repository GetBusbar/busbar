// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A plane session runs on the request's own task: the inbound backing and the original count admission are held
//! for every crossing, and released when the session ends or its future is dropped (no thread is left holding them).

use std::sync::{Arc, Mutex};

use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::services::Caller;
use busbar_plugin_abi::fail::FaultReason;
use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_plugin_abi::plane::AUTH_PUBLIC;
use busbar_ports::plane::{
    PlaneIn, PlaneOut, PlanePort, PlaneSession, RouteInfo, TargetIn, UsageClass,
};
use busbar_ports::{CallCx, PortError};

use super::{HttpHead, HttpIn, PortDriver, ServeIn};
use crate::host_services::KernelServices;
use crate::limits::process_admission::{AdmissionClass, ProcessAdmission};
use crate::plane_driver::port_auth::{Credentials, Principal};
use crate::plane_driver::port_intents::{IntentHost, Looked};
use crate::plugin_records::{CommitOp, CommitOutcome, RecordsDenied, Scope};
use crate::refusal::CoreRefusals;

fn refused() -> PortError {
    PortError::Refused {
        code: 1,
        text: "refused".into(),
        error: None,
    }
}

/// A plane that notes, from inside its `request` crossing, what the request's admission holds then: the bytes and
/// count in use, and whether another request is refused.
struct CustodyPlane {
    routes: [RouteInfo; 1],
    budget: Arc<ProcessAdmission>,
    entered: Mutex<Option<(Vec<u8>, (usize, usize), bool)>>,
}

impl PlanePort for CustodyPlane {
    fn routes(&self) -> &[RouteInfo] {
        &self.routes
    }
    fn dialects(&self) -> &[Box<str>] {
        &[]
    }
    fn usage_classes(&self) -> &[UsageClass] {
        &[]
    }
    fn usage_shared(&self) -> (std::sync::Arc<[UsageClass]>, std::sync::Arc<[Box<str>]>) {
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
        let refused_more = self.budget.try_enter(AdmissionClass::Data).is_err();
        *self.entered.lock().unwrap() = Some((body.to_vec(), self.budget.used(), refused_more));
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
    fn demux(&self, _: &str, _: &[u8], _: &mut dyn FnMut(PlaneOut<'_>)) -> Result<(), PortError> {
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

/// A host with no store (the thread hand-off tests share it).
pub(super) struct NoIntents;

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

/// One admitted request of `payload` against a fresh budget: the budget, the plane and its driver, and the
/// request's serve input.
fn custody(
    payload: &[u8],
) -> (
    Arc<ProcessAdmission>,
    Arc<CustodyPlane>,
    PortDriver,
    ServeIn<'static>,
) {
    let budget = ProcessAdmission::with_limits(2, 64, 8);
    let request = budget.try_enter(AdmissionClass::Data).unwrap();
    let body = request.copy_input(payload).unwrap().into_bytes();
    let port = Arc::new(CustodyPlane {
        routes: [RouteInfo {
            route: 1,
            methods: 1,
            flags: 0,
            auth: AUTH_PUBLIC,
            pattern: "/input".into(),
            cred_header: None,
            resource_kinds: Default::default(),
        }],
        budget: Arc::clone(&budget),
        entered: Mutex::new(None),
    });
    let driver = PortDriver::new(
        Arc::clone(&port) as Arc<dyn PlanePort>,
        Arc::new(KernelServices::new()),
        Caller::for_test(Arc::from("input-custody"), KindCode::Plane),
        Arc::new(CoreRefusals::new()),
        &|_| None,
    )
    .unwrap();
    let input = ServeIn {
        invocation: None,
        request,
        admission: None,
        route: 1,
        http: HttpIn::new(
            HttpHead::Text {
                method: "GET".into(),
                path: "/input".into(),
                query: String::new(),
                headers: Vec::new(),
            },
            body,
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
    };
    (budget, port, driver, input)
}

/// The session is spawned as the listener spawns it (so its future is `Send`), the plane's crossing sees the
/// whole input and the count still held, and both are released when the session ends.
async fn input_held_through_the_crossing(payload: &[u8]) {
    let (budget, port, driver, input) = custody(payload);
    let served = tokio::spawn(async move { driver.serve(input).await })
        .await
        .unwrap();
    assert!(served.is_ok());
    assert_eq!(
        *port.entered.lock().unwrap(),
        Some((payload.to_vec(), (payload.len(), payload.len()), true)),
        "inside the crossing: the body, its bytes and the count are held"
    );
    assert_eq!(budget.used(), (0, 0));
    assert!(budget.try_enter(AdmissionClass::Data).is_ok());
}

#[tokio::test]
async fn native_input_is_held_for_the_crossing_and_retired_with_the_session() {
    input_held_through_the_crossing(b"payload").await;
}

#[tokio::test]
async fn an_empty_native_request_keeps_its_count_for_the_crossing() {
    input_held_through_the_crossing(b"").await;
}

/// Dropping a session's future releases its input at once: no thread is left running with it.
#[tokio::test]
async fn a_dropped_serve_future_releases_its_input_at_once() {
    let (budget, port, driver, input) = custody(b"payload");
    let serving = driver.serve(input);
    assert_eq!(budget.used(), (7, 7), "the future owns the input");
    drop(serving);
    assert_eq!(budget.used(), (0, 0));
    assert!(budget.try_enter(AdmissionClass::Data).is_ok());
    assert!(
        port.entered.lock().unwrap().is_none(),
        "the plane was never entered"
    );
}

#[test]
fn partial_native_body_backing_survives_http_owner_drop() {
    let budget = ProcessAdmission::with_limits(2, 64, 8);
    let request = budget.try_enter(AdmissionClass::Data).unwrap();
    let http = HttpIn::new(
        HttpHead::Text {
            method: "POST".into(),
            path: "/input".into(),
            query: String::new(),
            headers: Vec::new(),
        },
        request.copy_input(b"payload").unwrap().into_bytes(),
        1,
    );
    let tail = http.body.slice(3..);
    drop(request);
    drop(http);
    assert_eq!(tail.as_ref(), b"load");
    assert_eq!(budget.used(), (7, 7));
    assert!(budget.try_enter(AdmissionClass::Data).is_err());
    drop(tail);
    assert_eq!(budget.used(), (0, 0));
    assert!(budget.try_enter(AdmissionClass::Data).is_ok());
}
