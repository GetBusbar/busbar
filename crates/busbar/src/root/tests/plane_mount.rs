// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE GENERIC DUPLEX MOUNT, PROVED AGAINST A PLANE THAT DOES NOT EXIST.
//!
//! Every fixture here is invented. The surface below is a made-up plane's, declared in the ordinary
//! vocabulary with the ordinary duplex kind; the driver is a script. There is no dialect, no
//! protocol and no plane name anywhere in this file, and that is the claim under test rather than a
//! stylistic preference: what the mount does, it does for ANY plane, and a battery driving a real
//! one through it would prove only that it works for that one.
//!
//! Four questions:
//!
//! * the wire the acceptor mounts is the one the boot seal REGISTERED — the same allocation, not a
//!   second composition of a key the registry seals exactly one of;
//! * a plane that declares a duplex route gets its sessions served on the node's existing listener,
//!   with no second address and no configuration key;
//! * a stop that arrives while the acceptor is WAITING opens nothing and cuts nothing;
//! * a stop that arrives with a session OPEN finishes that session and refuses the next one.

use std::sync::{Arc, Mutex};

use busbar_contract::transport::facts as tfacts;
use busbar_contract::transport::session::{
    SessionBudgets, SessionDriver, SessionEnd, SessionFrame, SessionHandle, SessionOpen,
    SessionReply,
};
use busbar_contract::transport::surface::{
    check_surface, Answering, Bar, BindingDecl, Dispatch, Operation, WireSurface,
};
use busbar_contract::transport::Outcome;
use busbar_contract::Transport;
use busbar_kernel::registry::{Plugin, PluginKind};

use crate::root::registry::{seal, BootRegistry};

use super::{serve_until, Accepted, Mounted, NeverStops, Stop};

// ── a plane that does not exist ─────────────────────────────────────────────────────────────────

/// The made-up plane's one duplex binding, carried on the `ws` registry key.
///
/// The key is the only string here that is not invented, and it is not a plane's: it is the wire's
/// own registry entry, and the declaration names it as DATA exactly as a real plane's does.
const BINDING: &str = "made-up";

const SURFACE: WireSurface = WireSurface {
    bindings: &[BindingDecl {
        name: BINDING,
        transport: "ws",
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

/// The declaration this whole battery stands on is one the boot check admits.
///
/// A fixture the tree would refuse at startup would make every green cell below a statement about a
/// surface that could never be mounted.
#[test]
fn the_fixture_plane_declares_a_surface_the_boot_check_admits() {
    assert_eq!(check_surface(&SURFACE), Ok(()));
}

// ── a driver that is nobody's ───────────────────────────────────────────────────────────────────

#[derive(Default)]
struct ScriptedDriver {
    opened: Mutex<Vec<String>>,
    seen: Mutex<Vec<Vec<u8>>>,
    closed: Mutex<Vec<SessionEnd>>,
}

impl SessionDriver for ScriptedDriver {
    fn open(
        &self,
        open: SessionOpen<'_>,
        _surface: &WireSurface,
    ) -> Result<SessionHandle, Outcome> {
        let mut log = self.opened.lock().expect("the log");
        log.push(open.fact(tfacts::PATH).unwrap_or_default().to_string());
        Ok(SessionHandle(log.len() as u64))
    }

    fn drive(&self, _session: SessionHandle, frame: SessionFrame<'_>) -> SessionReply {
        self.seen
            .lock()
            .expect("the log")
            .push(frame.payload.to_vec());
        SessionReply::frames(
            vec![b"{\"answered\":true}".to_vec()],
            "application/json",
            Outcome::Completed,
        )
    }

    fn close(&self, _session: SessionHandle, end: SessionEnd) {
        self.closed.lock().expect("the log").push(end);
    }
}

// ── a stop the composition owns ─────────────────────────────────────────────────────────────────

/// A stop a test can pull, and a stop that is safe to poll more than once.
///
/// A latch rather than a channel, for the reason the trait's own doc gives: the acceptor polls it as
/// one arm of a race, and an implementation that consumed a permit merely by being polled would
/// swallow a stop that had genuinely arrived.
#[derive(Default)]
struct Latch {
    pulled: std::sync::atomic::AtomicBool,
    ring: tokio::sync::Notify,
}

impl Latch {
    fn pull(&self) {
        self.pulled.store(true, std::sync::atomic::Ordering::SeqCst);
        self.ring.notify_waiters();
    }
}

impl Stop for Latch {
    async fn stopped(&self) {
        loop {
            if self.pulled.load(std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            self.ring.notified().await;
        }
    }
}

// ── the node's one listener ─────────────────────────────────────────────────────────────────────

/// THE NODE'S OWN BOOT SEAL, and a listener bound on the wire that seal REGISTERED.
///
/// Nothing here is constructed for the test. The composition root seals its transports once, and
/// what this returns is that seal and a listener taken off the instance inside it — because a
/// battery that built its own wire would prove the acceptor works against a transport this node
/// never registered, which is the one thing an acceptor must not be doing. There is exactly one
/// registration of the duplex key in this process, and the cell below says so directly.
///
/// One address, too. There is no second bind anywhere in this file and no key naming one: the
/// duplex sessions below arrive on the very listener a request/answer path would be served on,
/// because an upgrade is an HTTP request.
async fn listening() -> (BootRegistry, busbar_contract::wire::Listener) {
    struct Seal;
    impl busbar_contract::plugin::KernelSeal for Seal {
        fn seal_origin(&self) -> &'static str {
            "test"
        }
    }
    let sealed = seal(busbar_transport_http::ClientSettings::default()).expect("the node boots");
    let listener = sealed
        .transports
        .ws
        .listen(
            &busbar_transport_ws::StaticConfig::bind_to("127.0.0.1:0"),
            &busbar_contract::TransportKeyHandle::issue(&Seal, 0, "test"),
        )
        .await
        .expect("the listener binds");
    (sealed, listener)
}

// ── the questions ───────────────────────────────────────────────────────────────────────────────
//
// The real-socket half of these claims — a client that is a WebSocket library, an upgrade, frames
// answered after a stop — lives in `busbar-transport-ws`'s own session battery and not here, and
// the reason is a dependency edge rather than a preference: `cargo xtask gate
// duplex-ws-default-edge` reads a `--no-default-features` build's graph INCLUDING dev-dependencies,
// so a WebSocket client borrowed for this file would red the gate that keeps this binary
// strong-form deletable. What is proved here is what is decided here.

/// ANY PLANE THAT DECLARED A DUPLEX ROUTE IS ADDRESSABLE ON THE NODE'S EXISTING WIRE.
///
/// The made-up plane's declaration is reached by the very walk the transport addresses an upgrade
/// with, given the wire's own registry key — so the route this acceptor will serve is a route this
/// acceptor's wire can find, and finding it needed no second address, no second bind and no
/// configuration key naming either.
/// THE WIRE THE ACCEPTOR MOUNTS IS THE ONE REGISTRATION, NOT A SECOND COMPOSITION OF THE SAME KEY.
///
/// The cell that makes the generic signature worth having. The registry seals by key, so exactly one
/// duplex transport may register; an acceptor that constructed its own would be a second live
/// instance of a key the root promised there was one of — same allocation or the promise is
/// rhetorical. Asked by identity rather than by count, because two instances of one type answer a
/// count identically and differ in the only way that matters here.
#[tokio::test]
async fn the_acceptor_mounts_the_registered_wire_and_not_a_second_one() {
    let (sealed, _listener) = listening().await;
    let registered = sealed
        .registry
        .resolve(PluginKind::Transport, "ws")
        .expect("the root registered the duplex key exactly once");
    let mounted = Arc::clone(&sealed.transports.ws) as Arc<dyn Plugin>;
    assert!(
        Arc::ptr_eq(&registered, &mounted),
        "the acceptor's wire and the registry's entry are the same allocation, or the seal's \
         one-registration promise is a word rather than a fact"
    );
}

#[tokio::test]
async fn any_declared_duplex_surface_is_mountable_on_the_one_listener() {
    let (_sealed, listener) = listening().await;
    assert!(
        !listener.local_addr().is_empty(),
        "the node has ONE bound address, and the sessions below arrive on it"
    );
    for mount in SURFACE.bindings[0].mounts {
        let (binding, bar, captures) =
            busbar_contract::transport::surface::duplex_binding_at(&SURFACE, "ws", mount)
                .expect("the wire addresses the route the plane declared");
        assert_eq!(binding.name, BINDING);
        assert_eq!(bar, Bar::Credential);
        // THE THIRD VALUE IS THE MOUNT'S OWN CAPTURES, and this plane's mount is a literal path
        // with no `{capture}` in it — so the honest answer is none. Asserted rather than dropped
        // because a mount that silently grew a capture would change what facts a session publishes.
        assert!(
            captures.is_empty(),
            "a literal mount declares no capture, got {captures:?}"
        );
    }
}

/// A STOP WHILE WAITING OPENS NOTHING AND CUTS NOTHING.
///
/// The first half of the drain. No client ever connects; the stop arrives; the acceptor reports the
/// arm that says so. New sessions are refused by the only mechanism that cannot be got wrong —
/// nobody is listening for them any more.
#[tokio::test]
async fn a_stop_while_waiting_ends_the_acceptor_with_nothing_open() {
    let (sealed, listener) = listening().await;
    let driver = Arc::new(ScriptedDriver::default());
    let stop = Arc::new(Latch::default());
    stop.pull();

    let ended = serve_until(
        Mounted {
            wire: sealed.transports.ws.as_ref(),
            listener: &listener,
            surface: &SURFACE,
            driver: driver.as_ref(),
        },
        SessionBudgets::default(),
        stop.as_ref(),
    )
    .await;

    assert_eq!(ended, Accepted::StoppedWaiting { served: 0 });
    assert!(
        driver.opened.lock().expect("the log").is_empty(),
        "no caller was answered, so nothing is draining"
    );
    assert!(driver.closed.lock().expect("the log").is_empty());
}

/// A STOP THAT IS PULLED AND THEN ASKED AGAIN IS STILL STANDING.
///
/// The property the drain's second half rests on, checked directly. The acceptor asks the stop TWICE
/// per turn — once as an arm of the accept race, once after a session has finished — and a stop that
/// answered only the first would leave a node that drained one session and then went round for
/// another it had already been told not to take. A latch answers both; a one-shot channel would not,
/// which is why [`super::Stop`] is a trait with a re-askable question rather than a receiver.
#[tokio::test]
async fn a_stop_answers_every_time_it_is_asked() {
    let stop = Latch::default();
    stop.pull();
    for _ in 0..3 {
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), stop.stopped())
                .await
                .is_ok(),
            "a stop that has arrived is still standing the next time the loop asks"
        );
    }
}

/// A STOP THAT HAS NOT ARRIVED DOES NOT RESOLVE, so the accept race is a race and not a fall-through.
///
/// The other direction of the same property. A `stopped()` that resolved before the stop was pulled
/// would make the acceptor return `StoppedWaiting` on its first turn without ever taking a session —
/// a node that binds a listener and serves nobody, with nothing in its ending to say so.
#[tokio::test]
async fn an_unpulled_stop_never_resolves() {
    let stop = Latch::default();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), stop.stopped())
            .await
            .is_err(),
        "the acceptor would have stopped before serving anybody"
    );
}

/// The declared no-shutdown posture is a stop that never comes, and is stated rather than inferred.
#[tokio::test]
async fn the_never_stopping_posture_is_a_declaration() {
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), NeverStops.stopped())
            .await
            .is_err(),
        "a stop that never comes never resolves"
    );
}
