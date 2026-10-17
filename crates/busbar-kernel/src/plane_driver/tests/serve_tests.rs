// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A DOOR PLANE'S ADMIN ROUTE, served (`served_at`), over a plane double that echoes what crossed:
//! the head it was handed holds none of the credentials the auth gate consumed, its target carries
//! the query, and the audit row it asks for is written under the admitted principal.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::task::{Context, Poll};

use busbar_contract::abi::mechanism::call::{AbiStr, Field, Outcome as AbiOutcome, Span};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::plane::{
    ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, ProjectIn, ProjectOut, RecordWrite, RefusalIn,
    RefusalOut, ServeIn, ServeOut, AUDIT_APPLIED, RECORD_AUDIT,
};
use busbar_contract::plane_calls::{
    Answered, Grow, InstanceDecl, Lent, PieceInFlight, PlaneCalls, ServeInFlight,
};

use super::*;
use crate::plane_driver::AuditSink;

/// What one `serve` crossing was handed: its target and its head field names.
type Crossed = (String, Vec<String>);

/// A plane whose `serve` keeps the target and head field names it was handed, answers `200`, and
/// asks for one audit row.
#[derive(Default)]
struct Echo {
    crossed: Mutex<Vec<Crossed>>,
    next: AtomicU32,
}

const READY: Answered = Answered {
    outcome: AbiOutcome::Ready,
    short: false,
    disposition: None,
};

/// A `serve` answered at once.
struct Now(ServeOut);
// SAFETY: plain data the double wrote; its pointers are never dereferenced.
unsafe impl Send for Now {}

impl Future for Now {
    type Output = Answered;
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Answered> {
        Poll::Ready(READY)
    }
}

impl ServeInFlight for Now {
    fn out(&self) -> Option<ServeOut> {
        Some(self.0)
    }
}

/// No piece is ever driven here.
struct NoPiece;

impl Future for NoPiece {
    type Output = Answered;
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Answered> {
        Poll::Ready(Answered {
            outcome: AbiOutcome::Fault,
            short: false,
            disposition: None,
        })
    }
}

impl PieceInFlight for NoPiece {
    fn settled(&mut self) -> Option<Answered> {
        None
    }
    fn out(&self) -> Option<OnPieceOut> {
        None
    }
}

/// The bytes `s` points at.
///
/// # Safety
/// `s` points at `s.len` live bytes (the host's buffers, for the crossing).
unsafe fn text(s: AbiStr) -> String {
    let bytes = unsafe { std::slice::from_raw_parts(s.ptr, s.len) };
    String::from_utf8_lossy(bytes).into_owned()
}

/// The audit row the double asks for: its action (`key`) and resource (`value`).
const ROW: (&[u8], &[u8]) = (b"door.check", b"door:a");

impl PlaneCalls for Echo {
    fn now_ns(&self) -> u64 {
        0
    }
    fn arrive(
        &self,
        _: &mut ArriveIn,
        _: &mut ArriveOut,
        _: Grow<'_, ArriveIn, ArriveOut>,
    ) -> AbiOutcome {
        AbiOutcome::Fault
    }
    fn arrived_pool(&self, _: &ArriveOut) -> Option<Vec<u8>> {
        None
    }
    fn refusal(
        &self,
        _: &mut RefusalIn,
        _: &mut RefusalOut,
        _: Grow<'_, RefusalIn, RefusalOut>,
    ) -> AbiOutcome {
        AbiOutcome::Fault
    }
    fn project(
        &self,
        _: &mut ProjectIn,
        _: &mut ProjectOut,
        _: Grow<'_, ProjectIn, ProjectOut>,
    ) -> AbiOutcome {
        AbiOutcome::Ready
    }
    fn cancel(&self, _: Ticket) -> Option<busbar_contract::plane_calls::Cancelled> {
        None
    }
    fn declared(&self) -> InstanceDecl {
        InstanceDecl {
            label: "echo".into(),
            ..InstanceDecl::default()
        }
    }
    fn driver(&self) -> Option<Ticket> {
        self.mint()
    }
    fn tick(&self, _: Ticket, _: u64) -> Pin<Box<dyn Future<Output = Option<u64>> + Send>> {
        Box::pin(std::future::ready(Some(0)))
    }
    fn ready(&self) -> Pin<Box<dyn Future<Output = Vec<u64>> + Send>> {
        Box::pin(std::future::ready(Vec::new()))
    }
    fn mint(&self) -> Option<Ticket> {
        Some(Ticket {
            slot: self.next.fetch_add(1, Ordering::SeqCst),
            generation: 1,
        })
    }
    fn recycle(&self, _: Ticket) {}
    fn drop_client(&self, _: Ticket) {}
    fn serve(&self, _: Ticket, i: ServeIn, mut o: ServeOut, _: Lent) -> Box<dyn ServeInFlight> {
        // SAFETY: the driver's target and `fields_len` head fields, live for the crossing.
        let target = unsafe { text(i.target) };
        let fields: &[Field] = unsafe { std::slice::from_raw_parts(i.fields, i.fields_len) };
        let names = fields.iter().map(|f| unsafe { text(f.name) }).collect();
        self.crossed.lock().unwrap().push((target, names));
        let (key, value) = ROW;
        let words = [key, value].concat();
        assert!(words.len() <= i.arena_cap && i.records_cap > 0);
        // SAFETY: the driver's arena of `arena_cap` bytes and records buffer of `records_cap`.
        unsafe {
            std::ptr::copy_nonoverlapping(words.as_ptr(), i.arena_buf, words.len());
            *i.records_buf = RecordWrite {
                kind: AUDIT_APPLIED,
                op: RECORD_AUDIT,
                key: Span {
                    offset: 0,
                    len: key.len() as u32,
                },
                value: Span {
                    offset: key.len() as u32,
                    len: value.len() as u32,
                },
            };
        }
        o.arena_written = words.len() as u64;
        o.records_written = 1;
        o.status = 200;
        Box::new(Now(o))
    }
    fn on_piece(&self, _: Ticket, _: OnPieceIn, _: OnPieceOut, _: Lent) -> Box<dyn PieceInFlight> {
        Box::new(NoPiece)
    }
}

/// An audit sink that keeps every row's action and principal.
#[derive(Default)]
struct Rows(Mutex<Vec<(String, String)>>);

impl AuditSink for Rows {
    fn record(&self, action: &str, _: &str, _: &'static str, principal: &str) {
        self.0
            .lock()
            .unwrap()
            .push((action.to_string(), principal.to_string()));
    }
}

/// RED (K2 #4): a door plane's admin route is handed the request as the auth gate admitted it.
/// - The credential lines the gate consumed on the admin plane (`gate_consumed`: the client and
///   admin carriers and the DPoP proof) never cross: not `x-admin-token`, which the contract's
///   never-kept list does not name, nor `x-api-key`, `x-goog-api-key`, `authorization` or `dpop`.
///   A line the gate did not read (`x-trace`) does.
/// - The target is `path?query`.
/// - The plane's audit row names the admitted principal, not `anonymous`.
///
/// RED before: `served_at` struck only the never-kept list (so `x-admin-token` and `dpop`
/// crossed), passed the path alone, and wrote the row under `AuthPrincipal(None)`.
#[tokio::test]
async fn a_door_plane_admin_route_sees_no_consumed_credential_and_its_row_names_the_actor() {
    let echo = std::sync::Arc::new(Echo::default());
    publish(
        ServeTable {
            instance: "served-at-red".to_string(),
            audit_kind: "door".to_string(),
            calls: echo.clone(),
            caps: BufferCaps::default(),
            routes: vec![ServeRoute {
                verb: "GET".to_string(),
                target: "/served-at-red/{name}/health".to_string(),
                flags: 0,
                audit_verb: String::new(),
            }],
            records: None,
        },
        &[],
    )
    .expect("publishes");
    let app = crate::test_support::TestApp::new()
        .admin_chain(vec![crate::config::operator_provider().to_string()])
        .build();
    let consumed = crate::auth::gate_consumed(&app, true, false);
    let mut headers = axum::http::HeaderMap::new();
    for (name, value) in [
        ("x-admin-token", "operator-secret"),
        ("authorization", "Bearer operator-secret"),
        ("x-api-key", "k"),
        ("x-goog-api-key", "g"),
        ("dpop", "proof"),
        ("x-trace", "t-1"),
    ] {
        headers.insert(name, axum::http::HeaderValue::from_static(value));
    }
    let principal = AuthPrincipal(Some(busbar_contract::auth::Principal::from_id("op")));
    let rows = Rows::default();
    let served = served_at_to(
        &rows,
        AdminServe {
            method: "GET",
            path: "/served-at-red/a/health",
            query: Some("x=1"),
            headers: &headers,
            consumed: Some(&consumed),
            principal: Some(&principal),
        },
        Bytes::new(),
    )
    .await;
    withdraw("served-at-red");
    assert_eq!(
        served
            .expect("an instance names it")
            .expect("served")
            .status,
        200
    );
    let crossed = echo.crossed.lock().unwrap().clone();
    let [(target, names)] = crossed.as_slice() else {
        panic!("one crossing: {crossed:?}");
    };
    for credential in [
        "x-admin-token",
        "authorization",
        "x-api-key",
        "x-goog-api-key",
        "dpop",
    ] {
        assert!(
            !names.iter().any(|n| n == credential),
            "`{credential}` crossed to the plane: {names:?}"
        );
    }
    assert!(names.iter().any(|n| n == "x-trace"), "{names:?}");
    assert_eq!(target, "/served-at-red/a/health?x=1");
    assert_eq!(
        rows.0.lock().unwrap().as_slice(),
        [("door.check".to_string(), "op".to_string())]
    );
}
