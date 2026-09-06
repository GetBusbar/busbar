// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE BINDING CELLS: a served session and a governed session are the same session.
//!
//! The port and its implementor were both in the tree and no served session had ever been handed one.
//! `SessionCore::with_governed` existed, the composition root's table existed, and between them sat a
//! door that opened every one of its sessions ungoverned — so a client-served tool call's wait was
//! entered by the root and there was nothing on any socket that could wake it or sweep it. These
//! cells judge the join: the composition writes a table, every served open reads it, and what the
//! sweep ends is ended at the deadline the plane itself declares rather than at a second spelling of
//! thirty seconds kept here.
//!
//! The table under test is a stand-in that answers the two questions the port declares, and it
//! answers them with the SAME arithmetic the kernel's own wait table uses — a deadline of
//! `now + TOOL_REPLY_DEADLINE_SECS`, swept when the wall is reached and not one millisecond earlier.
//! The root's own cells judge what the ending then does to a unit; what these judge is that a socket
//! can reach the ending at all, and reach it on time.

use crate::ir::codec::OpenAiRealtimeCodec;
use crate::runtime::carrier::Carrier;
use crate::runtime::metering::{HostMeteringPort, MockMeteringHost};
use crate::runtime::{GovernedCalls, ReplyRefusal, VoiceRuntime};
use crate::topology::{open_admitted_session, SessionBudget};
use busbar_substrate::plane::handle_engine::DurableHandleEngine;
use busbar_substrate::plane_host::MeteringHost;
use std::sync::{Arc, Mutex};

/// The deadline the plane declares for a tool call the node does not serve, in milliseconds. Read
/// from the plane crate the composition root builds its own reply leg from — one declaration, two
/// readers, so a change to it cannot leave this cell asserting the old number.
fn deadline_ms() -> u64 {
    u64::from(busbar_plane_voice::plane::TOOL_REPLY_DEADLINE_SECS) * 1_000
}

/// One open call, as the node's table holds it.
#[derive(Debug)]
struct OpenCall {
    session: u64,
    call_id: String,
    /// The wall this call stops waiting at — entered as `now + the plane's declared seconds`, which
    /// is the kernel wait table's own arithmetic rather than a second one written here.
    deadline: u64,
}

/// A stand-in for the composition root's open-call table, answering the two questions the port
/// declares and recording what it was asked.
#[derive(Debug, Default)]
struct TableStandIn {
    open: Mutex<Vec<OpenCall>>,
    woken: Mutex<Vec<(u64, String)>>,
    swept: Mutex<Vec<(u64, String)>>,
}

impl TableStandIn {
    fn enter(&self, session: u64, call_id: &str, now_ms: u64) {
        self.open.lock().unwrap().push(OpenCall {
            session,
            call_id: call_id.to_string(),
            deadline: now_ms + deadline_ms(),
        });
    }
}

impl GovernedCalls for TableStandIn {
    fn replied(&self, session: u64, call_id: &str) -> Result<(), ReplyRefusal> {
        let mut open = self.open.lock().unwrap();
        if !open.iter().any(|c| c.session == session) {
            return Err(ReplyRefusal::NoSuchSession);
        }
        let at = open
            .iter()
            .position(|c| c.session == session && c.call_id == call_id)
            .ok_or(ReplyRefusal::UnknownCall)?;
        let call = open.remove(at);
        self.woken.lock().unwrap().push((session, call.call_id));
        Ok(())
    }

    fn expired(&self, now_ms: u64) -> usize {
        let mut open = self.open.lock().unwrap();
        let (done, still): (Vec<OpenCall>, Vec<OpenCall>) = std::mem::take(&mut *open)
            .into_iter()
            .partition(|c| c.deadline <= now_ms);
        *open = still;
        let mut swept = self.swept.lock().unwrap();
        for c in &done {
            swept.push((c.session, c.call_id.clone()));
        }
        done.len()
    }
}

fn runtime() -> VoiceRuntime {
    let host = Arc::new(MockMeteringHost::default()) as Arc<dyn MeteringHost>;
    VoiceRuntime::new(
        Arc::new(DurableHandleEngine::new()),
        Arc::new(HostMeteringPort::new(host)),
        Arc::new(crate::runtime::tools::EchoToolExecutor),
    )
}

fn budget() -> SessionBudget {
    SessionBudget {
        estimate_nanos: 1_000,
        fee_nanos: 0,
        cap_nanos: None,
    }
}

/// **A served open takes the binding it is handed, and the sweep on that session reaches the table.**
///
/// The post-admit open is the one door every served topology goes through — the dialed proxy, the
/// uplink-only fallback and the WebRTC sideband all reach a socket through it — so a binding it
/// carries is a binding all three carry. What is proved here is that the binding survives the open
/// and that the session's own tick lands on the composed table rather than on nothing.
#[test]
fn a_served_open_carries_its_binding_into_the_session_it_opens() {
    let rt = runtime();
    let table = Arc::new(TableStandIn::default());
    let governed = crate::runtime::GovernedSession {
        session: 4_242,
        calls: Arc::clone(&table) as Arc<dyn GovernedCalls>,
    };
    table.enter(4_242, "call_x", 0);

    let (core, _handle, _guard) = open_admitted_session(
        &rt,
        OpenAiRealtimeCodec,
        "acct-1",
        "call-9",
        None,
        Carrier::sideband(),
        budget(),
        None,
        1,
        Some(governed),
    )
    .expect("an uncapped budget opens");

    assert_eq!(
        core.governed_session(),
        Some(4_242),
        "the session the node knows this pump as is the one the open was handed"
    );
    assert_eq!(
        core.sweep_expired(deadline_ms()),
        1,
        "and the pump's own tick reaches that node's table"
    );
    assert_eq!(
        table.swept.lock().unwrap().as_slice(),
        [(4_242, "call_x".to_string())],
        "which is the call this session had open, ended by identifier"
    );
}

/// **An unanswered call ends at exactly the deadline the plane declares, through the served path.**
///
/// Not one millisecond early and not on the next tick that happens along. The figure is the plane's
/// own `TOOL_REPLY_DEADLINE_SECS` — the same declaration the composition root builds its reply leg
/// from — and it is read here rather than restated, so the two cannot drift.
#[test]
fn an_unanswered_call_is_swept_at_the_declared_deadline_and_not_before() {
    let rt = runtime();
    let table = Arc::new(TableStandIn::default());
    let (core, _handle, _guard) = open_admitted_session(
        &rt,
        OpenAiRealtimeCodec,
        "acct-1",
        "call-9",
        None,
        Carrier::sideband(),
        budget(),
        None,
        1,
        Some(crate::runtime::GovernedSession {
            session: 7,
            calls: Arc::clone(&table) as Arc<dyn GovernedCalls>,
        }),
    )
    .expect("an uncapped budget opens");

    table.enter(7, "call_late", 0);
    assert_eq!(
        core.sweep_expired(deadline_ms() - 1),
        0,
        "a call is not ended one millisecond before the deadline its leg declared"
    );
    assert_eq!(
        core.sweep_expired(deadline_ms()),
        1,
        "and it is ended at that deadline, on the tick that reaches it"
    );
    assert!(
        table.woken.lock().unwrap().is_empty(),
        "an ending is not a settlement: nobody answered this call"
    );
}

/// **Nothing is composed until a composition root composes it.**
///
/// The plane mounted without the root's own switch keeps what it had: no table, and every session it
/// serves is the ungoverned kind the runtime served before the wait existed.
#[test]
fn a_node_with_no_table_composed_serves_what_it_served_before() {
    let rt = runtime();
    let (core, _handle, _guard) = open_admitted_session(
        &rt,
        OpenAiRealtimeCodec,
        "acct-1",
        "call-9",
        None,
        Carrier::sideband(),
        budget(),
        None,
        1,
        None,
    )
    .expect("an uncapped budget opens");
    assert_eq!(core.governed_session(), None);
    assert_eq!(core.sweep_expired(u64::MAX), 0, "and it sweeps nothing");
}

/// **The composed table is what a served session-open reads, and each open reads a session of its
/// own.**
///
/// Two conversations may carry identical call identifiers — a provider mints them per conversation —
/// so the number the root keys its table by has to be unique per session on this node. It is minted
/// here, once per open.
#[test]
fn the_composition_hands_each_served_open_its_own_session() {
    assert!(
        crate::mount::install_governed_calls(
            Arc::new(TableStandIn::default()) as Arc<dyn GovernedCalls>
        ),
        "the first composition stands"
    );
    assert!(
        crate::mount::governed_calls_composed(),
        "and the door now serves governed sessions"
    );
    assert!(
        !crate::mount::install_governed_calls(
            Arc::new(TableStandIn::default()) as Arc<dyn GovernedCalls>
        ),
        "a second compose is a no-op, never a silent swap of the table live sessions are keyed into"
    );

    let first =
        crate::mount::served_governed_session().expect("a composed node binds every session");
    let second =
        crate::mount::served_governed_session().expect("a composed node binds every session");
    assert_ne!(
        first.session, second.session,
        "two sessions on one node are told apart before either has a call open"
    );
}

/// **THE ROOT IDENTITY, from this side: no served session-open reaches the ungoverned path.**
///
/// The cells above prove a binding works when one is handed over. This one proves there is no served
/// call site that declines to hand one — the property that makes "served" and "governed" the same set
/// rather than two sets that happen to overlap. It reads the door's own source because that is where
/// the property lives: the three legs are three call sites in one function, and a fourth added
/// without the binding would be a session nobody could sweep, discovered by a customer.
#[test]
fn every_served_session_open_asks_the_composition_for_its_binding() {
    let door = include_str!("../mount.rs");
    let accept = door
        .split_once("pub(crate) async fn ws_accept")
        .expect("the door is where the served legs are")
        .1;

    let opens = accept.matches("open_admitted_session(").count()
        + accept.matches("open_admitted_telephony(").count();
    assert_eq!(
        opens, 3,
        "the served legs are the dialed proxy, the uplink-only fallback and the WebRTC sideband; \
         a fourth needs its own binding and this cell counted {opens}"
    );
    let bound = accept.matches("served_governed_session()").count();
    assert_eq!(
        bound, opens,
        "every served session-open asks the composition for its binding: {bound} of {opens} do"
    );
}
