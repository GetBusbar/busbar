// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! OWNER DECISION (ENGINE-OPEN-3 rows 1 and 5): an upgraded session's time limit is its PLANE's
//! stated ceiling, stated in the plane's own describe (D_SESSION_CEILING_S) from its protocol's
//! specification or its own documented default. The engine enforces what the plane states and
//! borrows no number of its own: a plane that states none has no engine ceiling put on it.
//!
//! The item is additive: a describe written before it (no D_SESSION_CEILING_S) still loads.

use std::time::{Duration, Instant};

use busbar_plugin_abi::fail::FaultReason;
use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_plugin_abi::plane::{self as p, tag as t};
use busbar_plugin_abi::records::{Records, Reply, U64Rec, Writer};
use busbar_plugin_loader::adapters::plane::{decode_describe, DescribeInvalid};
use busbar_ports::plane::{
    PlaneIn, PlaneOut, PlanePort, PlaneSession, RouteInfo, TargetIn, UsageClass,
};
use busbar_ports::{CallCx, PortError};

use super::{session_ceiling_secs, session_ends};

/// One upgrade route with its admission, as every plane 2.0 describe states it.
fn upgrade_route(r: &mut Reply) {
    let route = p::RouteRec {
        route: 1,
        methods: 1,
        flags: p::ROUTE_UPGRADE,
        auth: p::AUTH_PRINCIPAL,
    };
    r.put_pod_tail(t::D_ROUTE, &route, b"/v1/realtime").unwrap();
    let admission = p::RouteAdmissionRec {
        route: 1,
        scope: p::SCOPE_NONE,
        money: p::MONEY_NONE,
        callers: p::CALLERS_SHARED,
    };
    r.put_pod_tail(t::D_ROUTE_ADMISSION, &admission, b"").unwrap();
}

fn describe(stated: &[u64]) -> Result<Option<u64>, DescribeInvalid> {
    let mut r = Reply::new();
    upgrade_route(&mut r);
    for value in stated {
        r.put_pod(t::D_SESSION_CEILING_S, &U64Rec { value: *value })
            .unwrap();
    }
    decode_describe(Records::new(r.as_bytes()), p::ALL, 0).map(|d| d.session_ceiling_s)
}

/// A plane whose port reports the ceiling its describe stated, and nothing else.
struct Stated(Option<u64>);

fn refused() -> PortError {
    PortError::Refused {
        code: 1,
        text: "no".into(),
        error: None,
    }
}

impl PlanePort for Stated {
    fn routes(&self) -> &[RouteInfo] {
        &[]
    }
    fn session_ceiling_s(&self) -> Option<u64> {
        self.0
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
fn session_ceiling_a_plane_states_ends_its_sessions_at_that_ceiling() {
    // plane-llm states 300 s in its describe: the loader reads it, the port reports it, the seat's
    // sessions end 300 s after their request was taken up.
    let stated = describe(&[300]).unwrap();
    assert_eq!(stated, Some(300));
    let port = Stated(stated);
    assert_eq!(session_ceiling_secs(&port), 300);
    let now = Instant::now();
    assert_eq!(
        session_ends(now, session_ceiling_secs(&port)),
        Some(now + Duration::from_secs(300))
    );
}

#[test]
fn session_ceiling_a_plane_that_states_none_gets_no_engine_number() {
    // A describe written before the item (or a plane whose specification states no limit): it
    // still loads, and the engine puts no ceiling of its own on its sessions.
    let stated = describe(&[]).unwrap();
    assert_eq!(stated, None);
    let port = Stated(stated);
    assert_eq!(session_ceiling_secs(&port), 0);
    assert_eq!(session_ends(Instant::now(), session_ceiling_secs(&port)), None);
}

#[test]
fn session_ceiling_the_loader_refuses_a_ceiling_it_cannot_enforce() {
    let bad = Err(DescribeInvalid("describe.session_ceiling_s"));
    // 0 is not a ceiling: a plane that has none states nothing.
    assert_eq!(describe(&[0]), bad);
    // At most once.
    assert_eq!(describe(&[300, 300]), bad);
    // Beyond what the engine's nanosecond clock can hold.
    assert_eq!(describe(&[u64::MAX / 1_000_000_000 + 1]), bad);
    assert_eq!(
        describe(&[u64::MAX / 1_000_000_000]),
        Ok(Some(u64::MAX / 1_000_000_000))
    );
}
