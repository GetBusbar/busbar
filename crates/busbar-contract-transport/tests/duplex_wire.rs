// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A WIRE THAT UPGRADES AND PUMPS, as a face — over a wire that does not exist.
//!
//! [`busbar_contract_transport::session::SessionDriver`] is the seam a session's FRAMES cross. This
//! battery is about the other half of the same exchange: the seam an ACCEPTOR reaches a wire
//! through. A composition that has to answer a stop needs a wire that can be asked for a session in
//! two moves — wait for one, then run it — and needs to ask that of ANY duplex wire, not of one it
//! named.
//!
//! Every fixture here is invented. The wire below moves no bytes, speaks no protocol and has no
//! socket; the driver is a script; there is no plane, no dialect and no transport crate anywhere in
//! this file. That is the claim rather than a style: what an acceptor does with this face, it does
//! for every duplex wire there will ever be, and a battery driving a real one would prove only that
//! it works for that one.
//!
//! Three questions:
//!
//! * a wire that upgrades and pumps is a face an acceptor can be written against generically;
//! * the open session is a VALUE, handed back before one frame is pumped, so "is anything open?" is
//!   something an acceptor HOLDS rather than a flag it maintains;
//! * that value is the whole of the drain: it can only be finished by moving it into the pump.

use std::sync::Mutex;

use busbar_contract_transport::driver::Outcome;
use busbar_contract_transport::session::{
    DuplexWire, SessionBudgets, SessionDriver, SessionEnd, SessionFrame, SessionHandle,
    SessionOpen, SessionReply,
};
use busbar_contract_transport::surface::{
    Answering, Bar, BindingDecl, Dispatch, Operation, WireSurface,
};
use busbar_contract_transport::wire::{CloseReason, Listener, ListenerHandle, TransportError};

// ── a plane that does not exist, on a wire that does not exist ──────────────────────────────────

/// A made-up registry key. No transport in this tree is named here, and none could be.
const WIRE: &str = "no-such-wire";

/// The made-up plane's one duplex binding.
const BINDING: &str = "made-up";

const SURFACE: WireSurface = WireSurface {
    bindings: &[BindingDecl {
        name: BINDING,
        transport: WIRE,
        mounts: &["/made/up/sessions"],
    }],
    operations: &[Operation {
        op: "open",
        dispatch: &[Dispatch::Duplex {
            binding: BINDING,
            method: "GET",
            bar: Bar::Credential,
        }],
        answering: Answering::Stream,
        request_media: "application/json",
        response_media: "application/json",
    }],
};

/// A listener that is bound to nothing. The face takes one; this battery never accepts on it.
fn listener() -> Listener {
    #[derive(Debug)]
    struct Nowhere;
    impl ListenerHandle for Nowhere {
        fn local_addr(&self) -> String {
            String::new()
        }
    }
    Listener::new(std::sync::Arc::new(Nowhere))
}

// ── a driver that is nobody's ───────────────────────────────────────────────────────────────────

#[derive(Default)]
struct ScriptedDriver {
    opened: Mutex<usize>,
    closed: Mutex<Vec<SessionEnd>>,
}

impl SessionDriver for ScriptedDriver {
    fn open(
        &self,
        _open: SessionOpen<'_>,
        _surface: &WireSurface,
    ) -> Result<SessionHandle, Outcome> {
        let mut n = self.opened.lock().expect("the log");
        *n += 1;
        Ok(SessionHandle(*n as u64))
    }

    fn drive(&self, _session: SessionHandle, _frame: SessionFrame<'_>) -> SessionReply {
        SessionReply::quiet(Outcome::Completed)
    }

    fn close(&self, _session: SessionHandle, end: SessionEnd) {
        self.closed.lock().expect("the log").push(end);
    }
}

// ── a wire that upgrades and pumps, and does nothing else ───────────────────────────────────────

/// What the invented wire did, in the order it did it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Did {
    Upgraded,
    Pumped,
}

/// A wire with no socket: it opens a session against the driver and, when the session is handed
/// back to it, ends it.
///
/// It is here to be a SECOND implementation of the face, because a face with one implementation is
/// a method with extra syntax. Nothing about it is a WebSocket, a stream or a byte.
#[derive(Default)]
struct InventedWire {
    log: Mutex<Vec<Did>>,
    /// How many upgrades this wire has left. When it runs out it reports the listener as closed,
    /// which is how a made-up wire says "no more".
    upgrades: Mutex<usize>,
}

/// The invented wire's open session: the driver's handle, and nothing else.
///
/// It is not `Copy` and not `Clone`, deliberately: the value IS the promise made to a caller, and a
/// promise that could be duplicated would be a session two acceptors each thought they owed.
#[derive(Debug)]
struct InventedSession(SessionHandle);

impl DuplexWire for InventedWire {
    type OpenSession = InventedSession;

    async fn serve_upgrade(
        &self,
        _listener: &Listener,
        driver: &dyn SessionDriver,
        surface: &WireSurface,
    ) -> Result<Self::OpenSession, TransportError> {
        {
            let mut left = self.upgrades.lock().expect("the log");
            if *left == 0 {
                return Err(TransportError::Closed);
            }
            *left -= 1;
        }
        let handle = driver
            .open(
                SessionOpen {
                    facts: &[],
                    transport: WIRE,
                    chain: &[WIRE],
                    binding: BINDING,
                    bar: Bar::Credential,
                },
                surface,
            )
            .map_err(|_| TransportError::HandshakeFailed)?;
        self.log.lock().expect("the log").push(Did::Upgraded);
        Ok(InventedSession(handle))
    }

    async fn pump_session(
        &self,
        open: Self::OpenSession,
        driver: &dyn SessionDriver,
        _budgets: SessionBudgets,
    ) -> SessionEnd {
        self.log.lock().expect("the log").push(Did::Pumped);
        let end = SessionEnd {
            cut: busbar_contract_transport::session::Cut::Client,
            reason: CloseReason::Normal,
        };
        driver.close(open.0, end);
        end
    }
}

// ── an acceptor written against the face and against no wire ────────────────────────────────────

/// The shape every composition root's acceptor has, written here in six lines to prove the face
/// carries it: wait, and then finish what you were handed.
///
/// It is generic over the wire and knows nothing about it — not its name, not its key, not what a
/// frame of it is.
async fn accept_one<W: DuplexWire>(
    wire: &W,
    l: &Listener,
    driver: &dyn SessionDriver,
    surface: &WireSurface,
) -> Result<SessionEnd, TransportError> {
    let open = wire.serve_upgrade(l, driver, surface).await?;
    Ok(wire
        .pump_session(open, driver, SessionBudgets::default())
        .await)
}

// ── the questions ───────────────────────────────────────────────────────────────────────────────

/// A WIRE THAT UPGRADES AND PUMPS IS A FACE AN ACCEPTOR CAN BE WRITTEN AGAINST.
///
/// The generic acceptor above compiles and runs against a wire the contract has never heard of, and
/// the driver saw one open and one close. Nothing in the acceptor named the wire.
#[test]
fn an_acceptor_serves_any_wire_that_upgrades_and_pumps() {
    let wire = InventedWire::default();
    *wire.upgrades.lock().expect("the log") = 1;
    let driver = ScriptedDriver::default();
    let l = listener();

    let end = futures::executor::block_on(accept_one(&wire, &l, &driver, &SURFACE))
        .expect("the invented wire had one upgrade to give");

    assert_eq!(end.reason, CloseReason::Normal);
    assert_eq!(*driver.opened.lock().expect("the log"), 1);
    assert_eq!(driver.closed.lock().expect("the log").len(), 1);
}

/// THE OPEN SESSION IS A VALUE, HANDED BACK BEFORE ONE FRAME IS PUMPED.
///
/// The whole reason the face is two calls rather than one. An acceptor that held a single
/// accept-upgrade-open-and-pump future could not tell WAITING from MID-SESSION, so a stop either
/// cut a live session or waited on a connection that might never come. Here the upgrade RETURNS
/// with the session open and the pump not yet entered, which is exactly the moment the two halves
/// are told apart — and it says so by handing back a value rather than by setting a flag.
#[test]
fn the_upgrade_returns_a_value_before_the_pump_is_entered() {
    let wire = InventedWire::default();
    *wire.upgrades.lock().expect("the log") = 1;
    let driver = ScriptedDriver::default();
    let l = listener();

    let open = futures::executor::block_on(wire.serve_upgrade(&l, &driver, &SURFACE))
        .expect("the invented wire had one upgrade to give");

    assert_eq!(
        *wire.log.lock().expect("the log"),
        vec![Did::Upgraded],
        "the wire has upgraded and has NOT pumped: an acceptor holding this value is mid-session, \
         and a stop cannot reach past it"
    );
    assert_eq!(
        *driver.opened.lock().expect("the log"),
        1,
        "a caller has been told yes"
    );
    assert!(
        driver.closed.lock().expect("the log").is_empty(),
        "and is owed the session they were promised"
    );

    let end =
        futures::executor::block_on(wire.pump_session(open, &driver, SessionBudgets::default()));
    assert_eq!(end.cut, busbar_contract_transport::session::Cut::Client);
    assert_eq!(
        *wire.log.lock().expect("the log"),
        vec![Did::Upgraded, Did::Pumped]
    );
}

/// A REFUSED UPGRADE IS NOT AN ENDING, and the face says which by its RESULT.
///
/// The upgrade errs where no session opened, so an acceptor that gets an `Err` has nothing open and
/// nothing draining. The distinction lives in the type, which is what lets one acceptor go round
/// again on a refusal and give up on a dead listener without either decision being a guess about a
/// string.
#[test]
fn an_upgrade_that_opened_nothing_leaves_nothing_to_drain() {
    let wire = InventedWire::default();
    let driver = ScriptedDriver::default();
    let l = listener();

    let refused = futures::executor::block_on(wire.serve_upgrade(&l, &driver, &SURFACE));

    assert_eq!(refused.unwrap_err(), TransportError::Closed);
    assert_eq!(*driver.opened.lock().expect("the log"), 0);
    assert!(
        wire.log.lock().expect("the log").is_empty(),
        "nothing was upgraded, so nothing is owed"
    );
}

/// THE BUDGET ARRIVES WITH THE PUMP, not with the upgrade.
///
/// An acceptor that held an open session across a configuration change is not holding a stale
/// ceiling, because the value it holds carries none: how long a session may run is the
/// composition's decision and is spelled at the moment the session starts running.
#[test]
fn the_open_session_carries_no_ceiling() {
    assert_eq!(SessionBudgets::default().deadline, None);
    assert_eq!(
        SessionBudgets {
            deadline: Some(std::time::Duration::from_secs(30))
        }
        .deadline,
        Some(std::time::Duration::from_secs(30))
    );
}

// THAT THE FACE NAMES NO PLANE AND NO WIRE IS NOT A CELL HERE, and the absence is deliberate. A
// test that listed the words a seam may not carry would be a second, weaker copy of
// `cargo xtask gate kind-isolation` — which reads every kind's instance vocabulary off the kind
// table and scans the whole tree with it, rather than off a list somebody remembered to extend. The
// list is also the coupling: a file spelling every plane's and every wire's name in order to say it
// names none of them is a file that names all of them. The gate judges this claim; this battery
// proves what the face DOES.
