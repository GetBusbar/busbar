// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

// THE SERVING SWITCH, ON THE WHOLE FILE. Off, this module is not compiled and no call site names
// it, which is what makes the feature-off binary byte-identical by construction rather than by
// measurement. The switch is `root-duplex-serve` and NOT a plane's, because nothing below is any
// plane's: it is declared in `root/mod.rs` under that neutral name, and a plane's serving feature
// turns it on by implying it rather than by being it.
#![cfg(feature = "root-duplex-serve")]

//! MOUNTING ANY PLANE'S DECLARED DUPLEX SURFACE, AND DRAINING IT: one acceptor, no plane's name.
//!
//! ## What this module is
//!
//! The composition root's side of the duplex seam. A plane declares, as data, WHERE a session may be
//! opened — a duplex binding, its mounts, its credential bar
//! ([`busbar_contract::transport::surface::Dispatch::Duplex`]). A transport knows how to take an
//! upgrade off a listener, address it against a declaration and run the session it opens. Neither
//! knows how many sessions this node will run at once, or what happens when the node is asked to
//! stop. That is a composition decision, and this is where it is made — once, for every plane.
//!
//! There is no plane, protocol or dialect named in this file. What it is handed is a listener, a
//! declared surface, a session driver and a stop; what it hands back is how the acceptor ended. It
//! could not tell you which plane it just served, and it has no way to ask.
//!
//! ## THE WIRE IS A PARAMETER, and that is what keeps it to one registration
//!
//! [`serve_until`] is generic over [`DuplexWire`], so nothing below holds a wire's own type or names
//! a wire's own crate. That is a coupling statement rather than a generality for its own sake: a
//! second place in the tree that spells one transport's concrete receiver is a second registration
//! of that transport in everything but the word, and the composition that calls this hands it the
//! instance it already registered — the one off [`crate::root::registry::seal`]'s
//! `transports` — rather than building itself another.
//!
//! ## ONE LISTENER, and no second address
//!
//! The listener is the caller's, and the caller's is the node's existing HTTP one. A duplex session
//! on this wire IS an upgrade of an HTTP request — same port, same address, same accept — so a
//! second bind would be a second address for the same protocol, and a configuration key naming it
//! would be an operator being asked to choose something the wire already decided. There is no key
//! here, no address here and no bind here: [`serve_until`] takes a listener that is already bound.
//!
//! ## DRAIN, and why it is stated in ownership
//!
//! Stopping a node that is serving sessions has two halves, and they are not the same half:
//!
//! * **A session that is not yet open** — the acceptor is WAITING. Nothing has been accepted, no
//!   caller has been told yes, and the honest answer to a stop is to stop waiting. New sessions are
//!   refused by the simplest possible mechanism: nobody is left listening for them.
//! * **A session that IS open** — a caller has been told yes and is being served. Cutting it is this
//!   node ending an exchange for a reason the caller cannot see, one frame after having promised to
//!   carry it. So it is finished: the peer's frames are answered until the session reaches its own
//!   ending.
//!
//! An acceptor holding a single accept-upgrade-open-and-pump future cannot tell those apart, which
//! is why [`DuplexWire::serve_upgrade`] and [`DuplexWire::pump_session`] are two calls. The loop
//! below races the stop against the WAITING half only. Losing that race drops a pending accept,
//! which tells nobody anything; winning it yields a [`DuplexWire::OpenSession`], and once this loop
//! is holding one the stop cannot take it back, because finishing it is the only thing that can be
//! done with a value that must be moved into the pump.
//!
//! That is the whole of the drain, and it is generic for the reason it is short: nothing about it
//! reads the surface, the driver or the frames. What drains is a SESSION, and every plane's sessions
//! drain the same way.
//!
//! ## What this module deliberately does NOT do
//!
//! It runs one session at a time. That is a statement and not a limitation to be quietly fixed: how
//! many sessions may be in flight is a capacity decision with a name — the node's own concurrency
//! gauge — and an acceptor that spawned freely would be making it silently, in the one place that
//! cannot see what a session costs. A composition that wants more runs more acceptors.
//!
//! It also refuses nothing on its own account. Whether a session may be opened at all is the
//! driver's answer, given while the upgrade still has a status line to carry a refusal; whether a
//! target is a session mount is the DECLARATION's answer, read by the transport. This loop makes
//! neither decision and cannot: it never sees the target.

use busbar_contract::transport::session::{DuplexWire, SessionBudgets, SessionDriver, SessionEnd};
use busbar_contract::transport::surface::WireSurface;
use busbar_contract::wire::{Listener, TransportError};

/// How an acceptor stopped, and what it was doing when it did.
///
/// Three arms, because a caller that logged "the acceptor ended" and nothing else could not tell an
/// orderly shutdown from a listener that died — and those want different answers from whoever is
/// reading. Every arm carries the count of sessions this acceptor served to completion, because the
/// one question asked of a drain afterwards is whether anything was cut, and a number nobody
/// recorded cannot answer it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Accepted {
    /// The stop arrived while the acceptor was WAITING, so nothing was open and nothing was cut.
    ///
    /// The clean shutdown. A pending accept was dropped, which no caller can observe: a connection
    /// that was never taken was never answered.
    StoppedWaiting {
        /// Sessions served to their own ending before the stop.
        served: usize,
    },
    /// The stop arrived while a session was open; that session was finished, and then the acceptor
    /// ended.
    ///
    /// The draining shutdown, and the count includes the session that was drained. Distinct from
    /// [`Accepted::StoppedWaiting`] because it is the arm that says the promise was kept.
    Drained {
        /// Sessions served to their own ending, the drained one included.
        served: usize,
    },
    /// The listener itself would not yield another session.
    ///
    /// Not a stop and not a drain: the wire under this acceptor gave out. The error is the
    /// transport's own word, carried rather than flattened, because "the listener closed" and "an
    /// upgrade failed" are the same shape here and are not the same operational event.
    ListenerEnded {
        /// Sessions served to their own ending before it ended.
        served: usize,
        /// What the wire said.
        error: TransportError,
    },
}

impl Accepted {
    /// How many sessions ran to their own ending under this acceptor.
    #[must_use]
    pub fn served(&self) -> usize {
        match self {
            Accepted::StoppedWaiting { served }
            | Accepted::Drained { served }
            | Accepted::ListenerEnded { served, .. } => *served,
        }
    }
}

/// What one acceptor is composed of, named rather than ordered.
///
/// Four references, three of which would swap silently in a positional call. Naming them is what
/// makes it impossible to hand the surface where the listener goes — and all four are things the
/// composition owns for the whole life of the node, so nothing here is per-session.
pub struct Mounted<'m, W: DuplexWire> {
    /// The wire that takes the upgrades, reached through the face and never by its own type.
    ///
    /// Already composed, already over its lower layer, and already REGISTERED: the composition
    /// hands over the instance its boot seal produced, because a wire this module constructed would
    /// be a second one of a key the registry seals exactly one of.
    pub wire: &'m W,
    /// The listener sessions arrive on — the node's own, already bound.
    ///
    /// The SAME one the request/answer path is served on. See this module's header: an upgrade is an
    /// HTTP request, so a second listener would be a second address for one protocol.
    pub listener: &'m Listener,
    /// The plane's own declaration of where a session may be opened.
    ///
    /// Read only by the transport, which addresses upgrades against it. This module never looks
    /// inside, which is why it cannot know whose surface it is.
    pub surface: &'m WireSurface,
    /// The seam a session's frames are driven through.
    pub driver: &'m dyn SessionDriver,
}

impl<W: DuplexWire> std::fmt::Debug for Mounted<'_, W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mounted").finish_non_exhaustive()
    }
}

/// The stop one acceptor answers.
///
/// A trait with one question rather than a channel, because the acceptor's whole requirement is
/// "tell me when to stop taking new work", and the thing that decides that differs by composition:
/// a signal handler, an administrative verb, a supervisor's channel, a test. A concrete channel here
/// would force every one of those through a shape it did not choose.
///
/// The future is polled as one arm of a race against a pending accept, so an implementation must be
/// safe to DROP: losing the race means the acceptor took a session instead, and the same stop will
/// be asked again on the next turn of the loop. An implementation that consumed a permit merely by
/// being polled would swallow a stop that had genuinely arrived.
pub trait Stop {
    /// Resolves when this acceptor should stop taking NEW sessions.
    ///
    /// It says nothing about the session already open, and it cannot: a stop is a decision about
    /// what this node accepts next, and what it does about what it already accepted is the drain's
    /// answer rather than the signal's.
    fn stopped(&self) -> impl std::future::Future<Output = ()> + Send;
}

/// A stop that never comes: serve until the listener ends.
///
/// The honest spelling of an acceptor with no shutdown wired to it yet, and better than an
/// `Option<impl Stop>` for the reason a declared `Bar::Open` is better than an absent one — the
/// posture is stated rather than inferred from a missing value.
#[derive(Clone, Copy, Debug, Default)]
pub struct NeverStops;

impl Stop for NeverStops {
    async fn stopped(&self) {
        std::future::pending::<()>().await
    }
}

/// ACCEPT SESSIONS ON A DECLARED SURFACE UNTIL THE STOP ARRIVES, THEN DRAIN.
///
/// One session at a time, to its own ending, until one of three things happens: the stop arrives
/// while waiting (nothing open, nothing cut), the stop arrives with a session open (that session is
/// finished first), or the listener gives out.
///
/// The race is against the WAITING half alone. That is the whole mechanism and it is why this
/// function is short: the transport reports an open session by RETURNING one, so "is anything
/// open?" is not a flag this loop maintains but a value it either holds or does not. A stop cannot
/// reach past the point where one is held, because there is nothing to do with a
/// [`DuplexWire::OpenSession`] except move it into the pump.
///
/// `budgets` is the composition's ceiling on a single session and is applied per session rather than
/// to the acceptor: an acceptor bounded as a whole would cut whichever session happened to be open
/// when the node's total ran out, which is a caller punished for the traffic before them.
pub async fn serve_until<W: DuplexWire, S: Stop>(
    mounted: Mounted<'_, W>,
    budgets: SessionBudgets,
    stop: &S,
) -> Accepted {
    let mut served = 0usize;
    loop {
        // THE RACE, and the only one. Both arms are droppable and neither has answered a caller:
        // the stop is asked again next turn if it loses, and a dropped upgrade is a connection not
        // taken. Nothing that has been promised to anybody is in flight here.
        let opened = tokio::select! {
            () = stop.stopped() => return Accepted::StoppedWaiting { served },
            opened = mounted.wire.serve_upgrade(mounted.listener, mounted.driver, mounted.surface) => opened,
        };
        let open = match opened {
            Ok(open) => open,
            // A REFUSAL IS NOT AN ENDING. An upgrade this node would not open — an undeclared
            // target, a driver that said no — was answered with a status on the leg underneath
            // while it still had one, and the caller has been told. Nothing is open, so nothing is
            // draining, and the acceptor goes round again.
            //
            // A listener that has genuinely given out reports the same shape, and the two are told
            // apart by the one question that separates them: can this listener still be waited on?
            Err(error) if is_fatal(error) => return Accepted::ListenerEnded { served, error },
            Err(_) => continue,
        };
        // FROM HERE THE STOP CANNOT CUT IT. A caller has been told yes, and the value that says so
        // has to be moved into the pump. The stop is not raced against this: draining means the
        // session reaches its OWN ending.
        let _end: SessionEnd = mounted
            .wire
            .pump_session(open, mounted.driver, budgets)
            .await;
        served += 1;
        // And now — with nothing open and nobody owed anything — a stop that arrived mid-session is
        // answered. Asking here rather than only at the top of the loop is what makes the drain
        // observable as its own arm: a node that reported `StoppedWaiting` after finishing a session
        // would be indistinguishable from one that had never had one open.
        if is_ready(stop.stopped()).await {
            return Accepted::Drained { served };
        }
    }
}

/// Whether a stop has ALREADY arrived, without waiting for one that has not.
///
/// ONE poll and an answer either way, rather than a timeout with a small number in it. The question
/// is "is this standing right now", and any duration at all would be this loop waiting on a stop
/// that may never come while a client sits on a connection nobody has accepted.
async fn is_ready(f: impl std::future::Future<Output = ()>) -> bool {
    let mut f = std::pin::pin!(f);
    std::future::poll_fn(move |cx| std::task::Poll::Ready(f.as_mut().poll(cx).is_ready())).await
}

/// Whether one transport failure means this listener will never yield another session.
///
/// The distinction the acceptor cannot survive getting wrong in either direction. Treating a refused
/// upgrade as fatal takes the node's whole duplex surface down the first time a stranger asks for a
/// path nobody declared. Treating a dead listener as a refusal spins this loop against a socket that
/// will never accept again, as fast as it can ask.
///
/// Only [`TransportError::Closed`] is the first kind. Everything else — a handshake that failed, a
/// budget that expired, a caller refused before the protocol changed — is about ONE upgrade, and the
/// listener is still there for the next one.
fn is_fatal(error: TransportError) -> bool {
    matches!(error, TransportError::Closed)
}

#[cfg(test)]
#[path = "tests/plane_mount.rs"]
mod tests;
