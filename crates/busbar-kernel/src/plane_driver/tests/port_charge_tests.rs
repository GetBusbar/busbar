// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IF §8.6: a once rule core finds itself (a second FORWARD, a late one, an item out of place) is handled exactly
//! as an adapter FAULT: the session ends and the image is charged (the instance quarantined, `plugin_fault`
//! audited). The charge is the port's one `charge` entry; what core finds that is its own doing (a record that did
//! not read back) or that the port already handled charges nothing.

use std::sync::Mutex;

use busbar_plugin_abi::fail::FaultReason;
use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_ports::plane::{
    PlaneIn, PlaneOut, PlanePort, PlaneSession, RouteInfo, TargetIn, UsageClass,
};
use busbar_ports::{CallCx, PortError};

use super::{charge, fault_of};
use crate::plane_driver::port_session::{Origin, SessionError, Violation};
use crate::plane_driver::usage::UsageInvalid;

fn refused() -> PortError {
    PortError::Refused {
        code: 1,
        text: "no".into(),
        error: None,
    }
}

/// A plane that only remembers what it was charged.
#[derive(Default)]
struct Charged(Mutex<Vec<FaultReason>>);

impl PlanePort for Charged {
    fn routes(&self) -> &[RouteInfo] {
        &[]
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
    fn charge(&self, reason: FaultReason) {
        self.0.lock().unwrap().push(reason);
    }
    fn request(
        &self,
        _: &PlaneIn<'_>,
        _: &[u8],
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<PlaneSession, PortError> {
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

#[test]
fn every_once_rule_core_finds_charges_the_image_once_as_a_fault() {
    for violation in [
        Violation::SecondForward,
        Violation::LateForward,
        Violation::ForwardOutOfPlace(Origin::Rewrite),
        Violation::AfterEnd,
        Violation::Usage(UsageInvalid::Scale),
        Violation::AttemptOutOfPlace(Origin::Request),
        Violation::AttemptWithResponse,
        Violation::BadAttempt,
        Violation::BadAudit,
        Violation::UpstreamOutOfPlace(Origin::Request),
        Violation::BadExchange,
        Violation::MissingExchange,
        Violation::IntentStorm,
        Violation::BadJudge,
    ] {
        let port = Charged::default();
        assert!(
            charge(&port, &SessionError::Violation(violation)),
            "{violation:?} charges the image"
        );
        assert_eq!(*port.0.lock().unwrap(), vec![FaultReason::OnceRule]);
        assert_eq!(fault_of(&violation), Some(FaultReason::OnceRule));
    }
}

#[test]
fn what_is_core_s_own_or_already_handled_by_the_port_charges_nothing() {
    for error in [
        SessionError::Violation(Violation::BadRecords),
        SessionError::Port(refused()),
        SessionError::Over,
        SessionError::NotDriven,
        SessionError::Encode,
    ] {
        let port = Charged::default();
        assert!(!charge(&port, &error), "{error:?} charges nothing");
        assert!(port.0.lock().unwrap().is_empty());
    }
}
