// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A plane crossing is a direct call on the request's thread: each test counts the crossings a
//! recording plane saw run on a thread other than the caller's (a thread hand-off). The plane's
//! containment (a FAULT answer, the watchdog word, quarantine) is the adapter's and busbar-ffi's,
//! on whichever thread calls; a hand-off adds nothing to it.

use std::num::NonZeroU64;
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

use super::{HttpHead, HttpIn, PortDriver};
use crate::host_services::KernelServices;
use crate::limits::process_admission::{AdmissionClass, ProcessAdmission};
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

/// A plane that records the thread of every crossing it answers.
struct Recording {
    routes: [RouteInfo; 1],
    threads: Mutex<Vec<ThreadId>>,
}

impl Recording {
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
#[tokio::test(flavor = "current_thread")]
async fn the_resource_select_crossing_is_not_handed_to_another_thread() {
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
    let (_frozen, selection) = select_resources(plane.clone(), frozen).await.unwrap();
    assert_eq!(selection.unwrap().unwrap(), Vec::<u8>::new());
    assert_eq!(
        plane.counts(std::thread::current().id()),
        (1, 0),
        "one crossing, no thread hand-off"
    );
}

/// An upgrade refusal rendered by the plane runs on the request's own thread.
#[tokio::test(flavor = "current_thread")]
async fn the_refusal_render_crossing_is_not_handed_to_another_thread() {
    let plane = Recording::new();
    let driver = PortDriver::new(
        plane.clone(),
        Arc::new(KernelServices::new()),
        Caller::for_test(Arc::from("thread-count"), KindCode::Plane),
        Arc::new(CoreRefusals::new()),
        &|_| None,
    )
    .unwrap();
    let budget = ProcessAdmission::with_limits(2, 64, 8);
    let request = budget.try_enter(AdmissionClass::Data).unwrap();
    let refusal = ClientRefusal {
        status: 400,
        code: 1,
        text: "no".into(),
    };
    let rendered = driver.render_refusal(1, request, http(), refusal).await;
    assert!(rendered.is_ok());
    assert_eq!(
        plane.counts(std::thread::current().id()),
        (1, 0),
        "one crossing, no thread hand-off"
    );
}
