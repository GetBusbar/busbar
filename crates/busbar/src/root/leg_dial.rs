// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHERE A RELAYED SESSION'S UPSTREAM LEG IS DIALLED, and why it is dialled HERE and nowhere else.
//!
//! [`crate::root::session_driver::SessionLoopDriver::drive`] is synchronous, and it is synchronous on
//! purpose: the arena, the plane call and the ledger all run under it, and a seam that could await
//! would be a seam a session's state could be held across. So the driver cannot dial. What it does
//! instead is RECORD the decision — the moment its units seal a destination, the leg is parked on the
//! slot — and something on the other side of the seam, which can await, turns that into a socket.
//!
//! This is that something, and its shape is the whole of the argument.
//!
//! ## Why a FrameSource decorator, and why "between frames" is exact
//!
//! The pump is a strict alternation: read one frame, drive it, write what came back, read again.
//! Wrapping the READ means the dial runs in the gap between two frames of the session and nowhere
//! else — never while a unit is running, never while a frame is in flight, and never on a task of its
//! own that could outlive the session or race the close. And the alternation is what makes the
//! ordering right rather than lucky: the frame whose unit SEALS the leg has already been driven and
//! answered by the time the next read begins, so the dial completes strictly before any frame that
//! could need the leg is read. Zero frames in flight across it, by the shape of the loop and not by
//! a lock.
//!
//! ## Why the dialler is a seam and not a call
//!
//! What dials is a WIRE, and this module names none. A composition hands in something that can turn a
//! sealed destination into the offering end of a leg plus the drain that empties it; which wire that
//! is, and what it does about `wss://` over a cleartext layer, is that wire's own business and
//! already settled in its own crate. So this file is testable against a lease that is nobody's, which
//! is what the cells beside it drive.
//!
//! ## A dial that fails ENDS THE SESSION
//!
//! `Err(Closed)` back to the pump, which is the client's cut with no courtesy frame. That is the
//! honest answer and the alternative is worse: a session whose leg never opened would read the next
//! frame, find no leg, relay nothing and carry on — a relayed session that silently stopped relaying,
//! for as long as the client kept talking.

use std::future::Future;
use std::pin::Pin;

use busbar_contract::dest::VerifiedDestination as PlaneDestination;
use busbar_contract::transport::session::{EgressLease, LegCredential, SessionHandle};
use busbar_contract::TransportError;
use busbar_transport_ws::mount::FrameSource;

use crate::root::session_driver::{SessionLoopDriver, SessionUnits};

/// The offering end of one dialled leg and the future that empties it.
///
/// Two values because they are owned in two places: the lease goes to the driver, where a
/// synchronous `drive` can reach it, and the drain is spawned by whoever is running the session. A
/// dialler that spawned the drain itself would be choosing the composition's runtime.
///
/// The leg's INBOUND half is deliberately not here, and that is the one asymmetry in this face. It
/// has to be READ in a loop for as long as the session lives, which means a task, which means
/// something that outlives this call and holds the driver — and this module's driver is a BORROW.
/// The composition's is not: it composed the driver and can keep it for the process. So the
/// inbound half is the dialler's to pump, which is why the dial is handed the session it is for.
pub type DialledLeg = (
    Box<dyn EgressLease>,
    Pin<Box<dyn Future<Output = ()> + Send>>,
);

/// WHAT CAN TURN A SEALED DESTINATION INTO A LEG. The one thing this module does not do itself.
///
/// A trait rather than a call to a wire, because this file must not name one: the composition
/// registers its wire in exactly one place, and a second place that named it by its concrete type
/// would be a second registration in everything but the word. It is also what makes the decorator
/// exercisable — the cells beside this file drive it with a lease that is nobody's.
pub trait LegDialer: Send + Sync {
    /// Dial the leg this destination names, and hand back the two halves this side owns.
    ///
    /// The SESSION comes with it, and for one reason: the leg's inbound half has to be read in a
    /// loop for as long as the session lives, and the thing that reads it must be told which
    /// session's driver the replies go through. It is the dialler that starts that read, because it
    /// is the composition — the one party here whose driver outlives a session.
    ///
    /// THE CREDENTIAL COMES WITH IT TOO, and for the same shape of reason: the units that sealed
    /// this address settled what is presented at it, in one step, at one moment. A dialler that
    /// looked the credential up for itself would be a second opinion about which row a session's
    /// leg came off, and the two could disagree for exactly the sessions that matter — the ones
    /// whose own wire has no configured row and seal against another. It is BORROWED, for the one
    /// call: nothing here owns a secret and nothing here may keep one.
    ///
    /// # Errors
    ///
    /// The leg could not be opened. Nothing is half-open on the error path: on it, there is nothing
    /// to own.
    fn dial<'a>(
        &'a self,
        session: SessionHandle,
        dest: &'a PlaneDestination,
        credential: Option<LegCredential<'a>>,
    ) -> Pin<Box<dyn Future<Output = Result<DialledLeg, TransportError>> + Send + 'a>>;
}

/// A [`FrameSource`] that dials the session's upstream leg in the gap before each read.
///
/// It reads no frame, decides nothing about one and cannot say what protocol is under it. What it
/// adds to the source it wraps is one question asked at one moment: has this session's driver parked
/// a leg that nothing has dialled?
pub struct LegDialing<'d, S, U: SessionUnits + ?Sized> {
    source: S,
    driver: &'d SessionLoopDriver<'d, U>,
    session: SessionHandle,
    dialler: &'d dyn LegDialer,
}

impl<S, U: SessionUnits + ?Sized> std::fmt::Debug for LegDialing<'_, S, U> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LegDialing")
    }
}

impl<'d, S, U: SessionUnits + ?Sized> LegDialing<'d, S, U> {
    /// Wrap one session's inbound half.
    pub fn new(
        source: S,
        driver: &'d SessionLoopDriver<'d, U>,
        session: SessionHandle,
        dialler: &'d dyn LegDialer,
    ) -> Self {
        Self {
            source,
            driver,
            session,
            dialler,
        }
    }
}

/// Dial and attach whatever the driver has parked, if anything.
///
/// A free function taking the three pieces it needs rather than a method on the decorator, and the
/// reason is the seam it has to satisfy: [`FrameSource::next_frame`] returns a `Send` future, and a
/// method would hold a shared borrow of the whole decorator — including the source it wraps —
/// across the dial. The three things the dial actually needs are all already shared references.
///
/// `Ok(())` covers the ordinary case where there is nothing parked, which is every read of every
/// session that never relays. The drain is spawned HERE, beside the session it belongs to, and the
/// handle is dropped rather than joined: it ends when the lease is finished or the leg fails, and
/// both of those are the session's own endings.
async fn dial_pending<U: SessionUnits + ?Sized + Sync>(
    driver: &SessionLoopDriver<'_, U>,
    session: SessionHandle,
    dialler: &dyn LegDialer,
) -> Result<(), TransportError> {
    let Some(pending) = driver.pending_leg(session) else {
        return Ok(());
    };
    // THE BORROWED FACE, built here and nowhere earlier: what crossed the driver seam is owned
    // (it was read out from under the session's own lock), and what the wire takes is a borrow for
    // the length of one dial. Neither end of that is a copy of the secret that outlives the call.
    let credential = pending
        .credential
        .as_ref()
        .map(|(at, secret)| LegCredential { at: *at, secret });
    let (lease, drain) = dialler.dial(session, &pending.dest, credential).await?;
    // A driver that will not take the leg is one whose session has gone, or one somebody else
    // attached to first. Either way this lease is nobody's, and dropping it here is what closes the
    // socket rather than leaving it open with no owner.
    if !driver.attach_leg(session, lease) {
        return Ok(());
    }
    drop(tokio::spawn(drain));
    Ok(())
}

impl<S: FrameSource + Send, U: SessionUnits + ?Sized + Sync> FrameSource for LegDialing<'_, S, U> {
    async fn next_frame(&mut self) -> Option<Result<Vec<u8>, TransportError>> {
        // BEFORE the read, which is what "between frames" means: the frame whose unit sealed the leg
        // has already been driven and answered, and the frame that may need the leg has not been
        // read yet.
        if let Err(error) = dial_pending(self.driver, self.session, self.dialler).await {
            // The pump reads this as the session's end. A session whose leg never opened would relay
            // nothing and say nothing, which is the one outcome worse than ending.
            return Some(Err(error));
        }
        self.source.next_frame().await
    }
}

// THE CELLS FOR THIS FILE LIVE BESIDE THE DRIVER'S, in `tests/session_driver.rs`, and deliberately.
// What this decorator does is only observable through a driver with a leg parked on it, so a battery
// of its own would have to build a second copy of that driver's whole harness — the made-up plane,
// the recording units, the node — and two harnesses for one seam are two things to keep in step.
