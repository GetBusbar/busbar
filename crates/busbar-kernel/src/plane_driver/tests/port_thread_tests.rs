// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A plane crossing is a direct call on the request's thread: each test counts the crossings a
//! recording plane saw run on a thread other than the caller's (a thread hand-off). The plane's
//! containment (a FAULT answer, the watchdog word, quarantine) is the adapter's and busbar-ffi's,
//! on whichever thread calls; a hand-off adds nothing to it.

use std::num::NonZeroU64;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::ThreadId;

use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::services::Caller;
use busbar_plugin_abi::fail::FaultReason;
use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_plugin_abi::plane::AUTH_PUBLIC;
use busbar_ports::plane::{
    PlaneIn, PlaneOut, PlanePort, PlaneSession, RouteInfo, TargetIn, UsageClass,
};
use busbar_ports::{CallCx, PortError};

use super::input_custody_tests::NoIntents;
use super::{HttpHead, HttpIn, PortDriver, ServeError, ServeIn};
use crate::host_services::KernelServices;
use crate::limits::process_admission::{AdmissionClass, ProcessAdmission};
use crate::plane_driver::port_auth::{Credentials, Principal};
use crate::refusal::{ClientRefusal, CoreRefusals};
use crate::resource_admission::{select_resources, FrozenRequest};
use crate::state::InvocationId;

fn refused() -> PortError {
    PortError::Refused {
        code: 1,
        text: "refused".into(),
        error: None,
    }
}

/// A plane that records the thread of every crossing it answers; its `request` panics while `panics` is set (the
/// flag is cleared by the panic, so the next request is served).
struct Recording {
    routes: [RouteInfo; 1],
    threads: Mutex<Vec<ThreadId>>,
    panics: AtomicBool,
}

impl Recording {
    fn panicking() -> Arc<Self> {
        let plane = Self::new();
        plane.panics.store(true, Ordering::Relaxed);
        plane
    }

    fn new() -> Arc<Self> {
        Arc::new(Self {
            routes: [RouteInfo {
                route: 1,
                methods: 1,
                flags: 0,
                auth: AUTH_PUBLIC,
                pattern: "/threads".into(),
                cred_header: None,
                resource_kinds: Default::default(),
            }],
            threads: Mutex::new(Vec::new()),
            panics: AtomicBool::new(false),
        })
    }

    fn crossed(&self) {
        self.threads
            .lock()
            .unwrap()
            .push(std::thread::current().id());
    }

    /// (crossings, hand-offs): how many crossings ran, and how many of them ran on a thread other
    /// than `caller`.
    fn counts(&self, caller: ThreadId) -> (usize, usize) {
        let threads = self.threads.lock().unwrap();
        let handed = threads.iter().filter(|ran| **ran != caller).count();
        (threads.len(), handed)
    }
}

impl PlanePort for Recording {
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
        self.crossed();
        Ok(Vec::new())
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
        self.crossed();
        if self.panics.swap(false, Ordering::Relaxed) {
            panic!("a crossing that panics");
        }
        Err(refused())
    }
    fn upstream(
        &self,
        _: &mut PlaneSession,
        _: &TargetIn<'_>,
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        self.crossed();
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
        self.crossed();
        Err(refused())
    }
    fn rewrite(
        &self,
        _: &mut PlaneSession,
        _: &[u8],
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        self.crossed();
        Err(refused())
    }
    fn end(&self, _: PlaneSession, _: &mut dyn FnMut(PlaneOut<'_>)) -> Result<(), PortError> {
        self.crossed();
        Err(refused())
    }
    fn render(
        &self,
        _: &PlaneIn<'_>,
        _: u32,
        _: &[u8],
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        self.crossed();
        Err(refused())
    }
    fn probe(
        &self,
        _: &TargetIn<'_>,
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<PlaneSession, PortError> {
        self.crossed();
        Err(refused())
    }
    fn demux(&self, _: &str, _: &[u8], _: &mut dyn FnMut(PlaneOut<'_>)) -> Result<(), PortError> {
        self.crossed();
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

fn http() -> HttpIn {
    HttpIn::new(
        HttpHead::Text {
            method: "GET".into(),
            path: "/threads".into(),
            query: String::new(),
            headers: Vec::new(),
        },
        bytes::Bytes::new(),
        1,
    )
}

/// The DATA listener's RESOURCE_SELECT crossing runs on the request's own thread.
#[test]
fn the_resource_select_crossing_is_not_handed_to_another_thread() {
    let plane = Recording::new();
    let frozen = FrozenRequest::new(
        InvocationId::from_request_id(NonZeroU64::new(1).unwrap()),
        1,
        "POST".into(),
        "/threads".into(),
        "".into(),
        Vec::new(),
        b"body".to_vec(),
    );
    let selection = select_resources(&*plane, &frozen, &[]);
    assert_eq!(selection.unwrap().unwrap(), Vec::<u8>::new());
    assert_eq!(
        plane.counts(std::thread::current().id()),
        (1, 0),
        "one crossing, no thread hand-off"
    );
}

/// An upgrade refusal rendered by the plane runs on the request's own thread.
#[test]
fn the_refusal_render_crossing_is_not_handed_to_another_thread() {
    let plane = Recording::new();
    let driver = PortDriver::new(
        plane.clone(),
        Arc::new(KernelServices::new()),
        Caller::for_test(Arc::from("thread-count"), KindCode::Plane),
        Arc::new(CoreRefusals::new()),
        &|_| None,
    )
    .unwrap();
    let refusal = ClientRefusal {
        status: 400,
        code: 1,
        text: "no".into(),
    };
    let rendered = driver.render_refusal_now(1, &http(), &refusal);
    assert!(rendered.is_ok());
    assert_eq!(
        plane.counts(std::thread::current().id()),
        (1, 0),
        "one crossing, no thread hand-off"
    );
}

fn driver(plane: &Arc<Recording>) -> PortDriver {
    PortDriver::new(
        plane.clone(),
        Arc::new(KernelServices::new()),
        Caller::for_test(Arc::from("thread-count"), KindCode::Plane),
        Arc::new(CoreRefusals::new()),
        &|_| None,
    )
    .unwrap()
}

/// One public request on route 1, admitted against `budget`.
fn serve_in(budget: &Arc<ProcessAdmission>) -> ServeIn<'static> {
    ServeIn {
        invocation: None,
        request: budget.try_enter(AdmissionClass::Data).unwrap(),
        admission: None,
        route: 1,
        http: http(),
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

/// The request's own core: one current-thread runtime, as the data listener runs per core.
fn core() -> tokio::runtime::Runtime {
    crate::rt::current_thread().enable_all().build().unwrap()
}

/// A whole served request makes every one of its plane crossings on the thread that awaits it.
#[test]
fn every_crossing_of_a_served_request_is_on_the_caller_thread() {
    let plane = Recording::new();
    let driver = driver(&plane);
    let budget = ProcessAdmission::with_limits(2, 64, 8);
    let served = core().block_on(driver.serve(serve_in(&budget)));
    assert!(!matches!(served, Err(ServeError::Cancelled)));
    let (crossings, handed) = plane.counts(std::thread::current().id());
    assert!(crossings >= 1, "the request crossed into the plane");
    assert_eq!(handed, 0, "{crossings} crossings, no thread hand-off");
}

/// Containment as before: a crossing that panics ends its one request as `Cancelled` and releases its input; the
/// same core serves the next request.
#[test]
fn a_panicking_crossing_ends_only_its_own_request() {
    let plane = Recording::panicking();
    let driver = driver(&plane);
    // One request at a time: the next is admitted only if the panicked one released its count.
    let budget = ProcessAdmission::with_limits(1, 64, 8);
    let core = core();
    let first = core.block_on(driver.serve(serve_in(&budget)));
    assert!(matches!(first, Err(ServeError::Cancelled)));
    let next = core.block_on(driver.serve(serve_in(&budget)));
    assert!(!matches!(next, Err(ServeError::Cancelled)));
    assert!(
        plane.counts(std::thread::current().id()).0 >= 2,
        "the next request crossed into the same plane"
    );
}
