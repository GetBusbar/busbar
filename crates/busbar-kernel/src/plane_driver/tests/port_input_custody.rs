// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Real blocking plane calls retain inbound backing and the original count admission.

use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::services::Caller;
use busbar_plugin_abi::fail::FaultReason;
use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_plugin_abi::plane::AUTH_PUBLIC;
use busbar_ports::plane::{
    PlaneIn, PlaneOut, PlanePort, PlaneSession, RouteInfo, TargetIn, UsageClass,
};
use busbar_ports::{CallCx, PortError};

use super::{HttpIn, PortDriver, ServeIn};
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

struct BlockingPlane {
    routes: [RouteInfo; 1],
    entered: Mutex<Option<tokio::sync::oneshot::Sender<Vec<u8>>>>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl PlanePort for BlockingPlane {
    fn routes(&self) -> &[RouteInfo] {
        &self.routes
    }
    fn dialects(&self) -> &[Box<str>] {
        &[]
    }
    fn usage_classes(&self) -> &[UsageClass] {
        &[]
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
        self.entered
            .lock()
            .unwrap()
            .take()
            .unwrap()
            .send(body.to_vec())
            .unwrap();
        self.release
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
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

async fn blocking_input_lifetime(payload: &[u8], cancel: bool) {
    let budget = ProcessAdmission::with_limits(2, 64, 8);
    let request = budget.try_enter(AdmissionClass::Data).unwrap();
    let body = request.copy_input(payload).unwrap().into_bytes();
    let (entered, started) = tokio::sync::oneshot::channel();
    let (release, blocked) = mpsc::channel();
    let port = Arc::new(BlockingPlane {
        routes: [RouteInfo {
            route: 1,
            methods: 1,
            flags: 0,
            auth: AUTH_PUBLIC,
            pattern: "/input".into(),
            cred_header: None,
            resource_kinds: Vec::new(),
        }],
        entered: Mutex::new(Some(entered)),
        release: Mutex::new(blocked),
    });
    let driver = PortDriver::new(
        port,
        Arc::new(KernelServices::new()),
        Caller::for_test(Arc::from("input-custody"), KindCode::Plane),
        Arc::new(CoreRefusals::new()),
        &|_| None,
    )
    .unwrap();
    let caller = tokio::spawn(async move {
        driver
            .serve(ServeIn {
                invocation: None,
                request,
                route: 1,
                http: HttpIn {
                    method: "GET".into(),
                    path: "/input".into(),
                    query: String::new(),
                    headers: Vec::new(),
                    body,
                    request_id: 1,
                },
                creds: Credentials {
                    bearer: None,
                    principal: Principal::Anonymous,
                    operator: false,
                    signed: None,
                },
                audience: "",
                now_s: 0,
                principal: None,
                unit: None,
                upstream: None,
                client: None,
                carrier: None,
                intents: Arc::new(NoIntents),
                models: Vec::new(),
            })
            .await
    });
    let mut caller = Some(caller);
    assert_eq!(started.await.unwrap(), payload);
    if cancel {
        let caller = caller.take().unwrap();
        caller.abort();
        assert!(matches!(caller.await, Err(error) if error.is_cancelled()));
    }
    assert_eq!(budget.used(), (payload.len(), payload.len()));
    assert!(budget.try_enter(AdmissionClass::Data).is_err());
    release.send(()).unwrap();
    if !cancel {
        assert!(caller.take().unwrap().await.unwrap().is_ok());
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if budget.used() == (0, 0) && budget.try_enter(AdmissionClass::Data).is_ok() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn blocked_native_input_outlives_cancelled_serve_future() {
    blocking_input_lifetime(b"payload", true).await;
}

#[tokio::test]
async fn empty_native_request_keeps_count_after_caller_cancellation() {
    blocking_input_lifetime(b"", true).await;
}

#[tokio::test]
async fn native_input_retires_after_normal_blocking_completion() {
    blocking_input_lifetime(b"payload", false).await;
}

#[test]
fn partial_native_body_backing_survives_http_owner_drop() {
    let budget = ProcessAdmission::with_limits(2, 64, 8);
    let request = budget.try_enter(AdmissionClass::Data).unwrap();
    let http = HttpIn {
        method: "POST".into(),
        path: "/input".into(),
        query: String::new(),
        headers: Vec::new(),
        body: request.copy_input(b"payload").unwrap().into_bytes(),
        request_id: 1,
    };
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
