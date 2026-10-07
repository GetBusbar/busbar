// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! DUPLEX SESSIONS (K6; `BUSBAR-1.6.0.md` Part 3, the driver's contract "Duplex sessions";
//! ARCHITECT R-B and the K6 ruling). A session is ONE unit: `open_unit` ran its steps to the door
//! and admitted it once, and [`PlaneUnits::session`] pumps it from there until it ends.
//!
//! - TWO PLANE TICKETS, one per side. The caller side carries the caller's pieces (`FROM_CALLER`)
//!   and the collection of the plane's unsolicited output (`FROM_KERNEL`, no bytes); the far side
//!   carries the turn legs. Each holds at most one op in flight, and neither waits on the other.
//! - THE INSTANCE'S ONE DRIVER TICKET names the sessions with output ready
//!   ([`PlaneDriver::drives`]); each one named is woken and collects on its caller side. There is
//!   no per-session driver ticket.
//! - ONE [`SessionCaller`], whatever carrier holds the session open (an inbound listener's
//!   connection, a piped session).
//! - EVERY TURN LEG IS UNDER THE SESSION'S ONE ADMISSION, INSIDE THE DESTINATION SET SEALED AT THE
//!   OPEN (THE DESIGN; ARCHITECT Q-L5-FAR (A)). A caller-side answer bound for the far end is a
//!   turn's request. The first turn is the session's ONE route walk (the unit's own `attempts`):
//!   it dials the far end inside the sealed set, and the far end it answers from is HELD for the
//!   session. Every later turn writes its frame into that held far end ([`FarEnd::write`]), never
//!   a walk of its own, and the far end's pieces reach the far side's ticket as they arrive: there
//!   is no per-turn end. A dial or a write that fails ends the session, and so does a cancel on
//!   either side; each side tells the other.
//! - EITHER SIDE ENDING ON ITS OWN ENDS THE SESSION: the caller's side ending (its last piece, or the
//!   plane's done) stops the far side reading the held far end; the far end's answer ending (it
//!   hung up) ends the caller's side with the caller's last piece, so the plane settles once.
//! - CLEANUP RUNS EXACTLY ONCE, however the session ends (its own end, a cancel, or its caller
//!   dropping the future): the stream leaves the instance's table and the money seam is told, in
//!   the session's one guard; each side's ticket goes back through its own pump (finished, or
//!   buried for the sweep).
//! - Money per THE DESIGN §7 (`MoneySeam::session_opened`, `MoneySeam::session_ended`): one unit, one line.

use std::future::Future;
use std::pin::pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use busbar_contract::abi::plane::{FROM_CALLER, FROM_KERNEL, PIECE_LAST};
use busbar_contract::caps::{Pass, ReasonCode, Route, VerifiedDestination};
use tokio::sync::{mpsc, watch, Notify};

use super::{
    guarded_run, CallerEnd, End, FarEnd, OutboundRequest, Piece, Pumping, Src, Step, Toward,
};
use crate::plane_driver::cancel::Facts;
use crate::plane_driver::{PlaneDriver, PlaneUnits, UnitState};
use crate::teller::UnitCtx;

/// THE CALLER'S SIDE OF A DUPLEX SESSION, one trait for every carrier that holds a session open:
/// its pieces go to the plane, and what the plane emits toward the caller is written to it (the
/// [`CallerEnd`] it also is).
pub trait SessionCaller: CallerEnd {
    /// The caller's next piece; `None` once the caller's side has ended. Cancel-safe: a read
    /// dropped before it resolved loses no piece.
    fn read(&self) -> impl Future<Output = Option<Vec<u8>>> + Send + '_;
}

/// Why a side stops before its own end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Halt {
    /// The session ended for this cause.
    Cause(ReasonCode),
    /// The other side ended on its own: the session is over.
    Over,
}

impl Halt {
    /// How a walk the halt stopped ends.
    pub(crate) fn end(self) -> End {
        match self {
            Halt::Cause(cause) => End::Cancel(cause, None),
            Halt::Over => End::Done,
        }
    }
}

/// The session's end, once a side names it; the first to name it wins.
type EndCell = watch::Sender<Option<Halt>>;

/// Name the session's end, unless a side already did.
fn end_session(ended: &EndCell, halt: Halt) {
    ended.send_if_modified(|e| {
        let first = e.is_none();
        if first {
            *e = Some(halt);
        }
        first
    });
}

/// The session's one dial: the first turn's request, the destination set sealed at the session's
/// open, the session's end (the walk stops at its next wait once it is named), and whether the far
/// end the walk dialled has answered (the later turns are written into it from then on).
pub(crate) struct Turn<'t> {
    pub(crate) request: OutboundRequest,
    sealed: &'t [VerifiedDestination],
    halt: watch::Receiver<Option<Halt>>,
    pub(crate) held: &'t watch::Sender<bool>,
}

impl Turn<'_> {
    /// Whether `member` is inside the set sealed at the open.
    pub(crate) fn within(&self, member: &str) -> bool {
        self.sealed.iter().any(|d| d.lane().as_str() == member)
    }

    /// Resolves once the session's end is named.
    pub(crate) fn halted(&self) -> impl Future<Output = Halt> + Send + 'static {
        let mut halt = self.halt.clone();
        async move {
            match halt.wait_for(Option::is_some).await {
                Ok(h) => h.unwrap_or(Halt::Over),
                Err(_) => Halt::Over,
            }
        }
    }
}

/// The session's ONE cleanup, run by its drop whichever way the session ends.
struct Open<'d> {
    driver: &'d PlaneDriver,
    stream: u64,
    ctx: &'d UnitCtx,
    /// The money seam was told the session opened, so it is told it ended.
    priced: bool,
}

impl Drop for Open<'_> {
    fn drop(&mut self) {
        self.driver.lock_sessions().remove(&self.stream);
        if self.priced {
            self.driver.money.session_ended(self.ctx);
        }
    }
}

/// What the caller side waits for next.
enum Next {
    /// The other side ended the session.
    Halt(Halt),
    /// `drive` named the session: collect its output.
    Collect,
    /// The caller's piece; `None` once its side ended.
    Caller(Option<Vec<u8>>),
}

impl PlaneDriver {
    fn lock_sessions(&self) -> MutexGuard<'_, std::collections::HashMap<u64, Arc<Notify>>> {
        self.sessions.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// THE READY-SESSION FAN-OUT (R-B), on the instance's one driver ticket: each stream its
    /// `drive` names wakes that open session, which collects its output on its caller side. A
    /// stream no open session holds is ignored. It ends when the instance names no more, or
    /// holds no driver ticket.
    pub async fn drives(&self) {
        if self.driver.is_none() {
            return;
        }
        loop {
            let ready = self.calls.ready().await;
            if ready.is_empty() {
                return;
            }
            let open = self.lock_sessions();
            for told in ready.iter().filter_map(|stream| open.get(stream)) {
                told.notify_one();
            }
        }
    }
}

/// Why `end` ended a side; `None` for a side that simply finished.
fn cause(end: &End) -> Option<ReasonCode> {
    match end {
        End::Done => None,
        End::Failed(reason) | End::Cancel(reason, _) => Some(*reason),
        End::Exhausted(..) => Some(ReasonCode::BreakerOpen),
        End::Vetoed(..) => Some(ReasonCode::HookVeto),
    }
}

impl<S: crate::plane_driver::DriverSteps + Sync, F: FarEnd, C: SessionCaller>
    PlaneUnits<'_, S, F, C>
{
    /// THE SESSION, after `open_unit` admitted its unit: `token` and `sealed` are what the
    /// admission handed back. Both sides run until the session ends; `Ok` when it ended on its
    /// own (the caller's side ended, or the plane said its reply was done), else why it ended.
    ///
    /// # Errors
    ///
    /// The money seam refused the session, no ticket could be minted, a turn failed, or a side
    /// was cancelled (deadline, reload, cut, the caller gone).
    pub async fn session(
        &self,
        token: &Pass<Route>,
        ctx: &UnitCtx,
        sealed: &[VerifiedDestination],
    ) -> Result<(), ReasonCode> {
        self.session_priced(token, ctx, sealed, true).await
    }

    /// [`Self::session`]; `priced` = false for a session its plane answers ITSELF (`ROUTE_LOCAL`,
    /// ARCHITECT Q-L3B-LOCAL: it names no entry, so it dials nothing, and only far-end-reported
    /// units bill): it runs under the admission that charged nothing, and the money seam is told
    /// nothing of it, as of a local request unit.
    pub(crate) async fn session_priced(
        &self,
        token: &Pass<Route>,
        ctx: &UnitCtx,
        sealed: &[VerifiedDestination],
        priced: bool,
    ) -> Result<(), ReasonCode> {
        let d = self.driver;
        if priced {
            d.money.session_opened(ctx)?;
        }
        // The session's in-session hook stage (`hook.call`, `content.scan`), from the open.
        self.state_stage(token);
        let stream = ctx.key.get();
        let told = Arc::new(Notify::new());
        d.lock_sessions().insert(stream, told.clone());
        let _open = Open {
            driver: d,
            stream,
            ctx,
            priced,
        };
        d.sweep();
        let (near, far) = (d.calls.mint(), d.calls.mint());
        let (Some(near), Some(far)) = (near, far) else {
            for t in [near, far].into_iter().flatten() {
                d.calls.recycle(t);
            }
            return Err(ReasonCode::InFlightCap);
        };
        let (dialect, caller_ref) = {
            let st = self.lock();
            let dialect = st.decoded.as_ref().map_or(0, |x| x.dialect);
            (dialect, st.caller_ref.clone())
        };
        let far_state = Mutex::new(UnitState::default());
        let none: Arc<[u8]> = Arc::from(&[][..]);
        let mut near_run = Pumping::new(
            d,
            token,
            &self.state,
            ctx,
            near,
            self.deadline_ns,
            none.clone(),
        );
        let mut far_run = Pumping::new(d, token, &far_state, ctx, far, self.deadline_ns, none);
        for run in [&mut near_run, &mut far_run] {
            run.lend_unit(self.arrival.claim, dialect, &caller_ref, stream);
        }
        let ended: EndCell = watch::Sender::new(None);
        let (turns, queued) = mpsc::channel(1);
        let near_side = async {
            let end = self
                .near_side(&mut near_run, &told, ended.subscribe(), turns)
                .await;
            self.close(&mut near_run, end, &ended).await
        };
        let far_side = async {
            let end = self.far_side(&mut far_run, &ended, queued, sealed).await;
            self.close(&mut far_run, end, &ended).await
        };
        let (near, far) = tokio::join!(near_side, far_side);
        near.and(far)
    }

    /// The caller side, on its own ticket: the caller's pieces, and the collection of what the
    /// plane has ready whenever `drive` named the session. An answer bound for the far end is
    /// queued as a turn. It ends when the caller's side ends, the plane says its reply is done,
    /// the other side ended the session, or the driver cancels. When the far side ended on its own
    /// (the far end hung up), the caller's side ends with the caller's last piece, so the plane
    /// settles the session once.
    async fn near_side(
        &self,
        run: &mut Pumping<'_>,
        told: &Notify,
        mut ended: watch::Receiver<Option<Halt>>,
        turns: mpsc::Sender<OutboundRequest>,
    ) -> End {
        loop {
            let next = guarded_run(run, async {
                tokio::select! {
                    biased;
                    halt = ended.wait_for(Option::is_some) => {
                        Next::Halt(halt.ok().and_then(|h| *h).unwrap_or(Halt::Cause(ReasonCode::ClientGone)))
                    }
                    () = told.notified() => Next::Collect,
                    read = self.caller.read() => Next::Caller(read),
                }
            })
            .await;
            let quiet = Piece {
                from: FROM_CALLER,
                flags: 0,
                status: (0, 0),
                attempt_no: 0,
                src: Src::None,
                head: false,
            };
            let piece = match next {
                Err(cause) | Ok(Next::Halt(Halt::Cause(cause))) => return End::Cancel(cause, None),
                Ok(Next::Halt(Halt::Over) | Next::Caller(None)) => Piece {
                    flags: PIECE_LAST,
                    ..quiet
                },
                Ok(Next::Collect) => Piece {
                    from: FROM_KERNEL,
                    ..quiet
                },
                Ok(Next::Caller(Some(bytes))) => {
                    run.bufs.input = bytes;
                    Piece {
                        src: Src::Input,
                        ..quiet
                    }
                }
            };
            let mut request = OutboundRequest::default();
            match self
                .push(run, piece, &mut Toward::Session(&mut request))
                .await
            {
                Step::End(end) => return end,
                Step::Answered(done) => {
                    if done || piece.flags & PIECE_LAST != 0 {
                        return End::Done;
                    }
                    // A far side that has ended takes no more turns: its end is named, and the
                    // next wait sees it.
                    if request != OutboundRequest::default() {
                        let _ = turns.send(request).await;
                    }
                }
                // A verdict means nothing on the caller's side: there is nothing to fail over.
                Step::Retry => {}
            }
        }
    }

    /// The far side, on its own ticket. It waits for the session's first turn, whose walk is the
    /// session's ONE dial inside the sealed set; the far end that answers it is held, and its pieces
    /// reach this ticket as they arrive. Beside the walk, every later turn is written into the held
    /// far end once it has answered, in the order the caller side queued them. It ends when the
    /// far end's answer ends, the session's end is named (the caller's side ended, or a side ended
    /// it for a cause), a dial or a write fails, or the driver cancels. Its end drops the turn
    /// queue, so a caller side waiting to queue a turn is never left waiting on it.
    async fn far_side(
        &self,
        run: &mut Pumping<'_>,
        ended: &EndCell,
        mut queued: mpsc::Receiver<OutboundRequest>,
        sealed: &[VerifiedDestination],
    ) -> End {
        let mut halt = ended.subscribe();
        let first = guarded_run(run, async {
            tokio::select! {
                biased;
                h = halt.wait_for(Option::is_some) => Err(h.ok().and_then(|h| *h).unwrap_or(Halt::Over)),
                turn = queued.recv() => Ok(turn),
            }
        })
        .await;
        let request = match first {
            Err(cause) => return End::Cancel(cause, None),
            Ok(Err(halt)) => return halt.end(),
            // The caller's side ended before any turn: nothing was dialled.
            Ok(Ok(None)) => return End::Done,
            Ok(Ok(Some(request))) => request,
        };
        run.lock().facts = Facts::default();
        let held = watch::Sender::new(false);
        let token = run.token;
        let turn = Turn {
            request,
            sealed,
            halt: ended.subscribe(),
            held: &held,
        };
        let mut walk = pin!(self.attempts(run, Some(&turn)));
        let mut writes = pin!(self.write_turns(token, &mut queued, held.subscribe(), ended));
        let mut writing = true;
        loop {
            tokio::select! {
                biased;
                end = &mut walk => return end,
                () = &mut writes, if writing => writing = false,
            }
        }
    }

    /// The session's later turns, each written into the held far end once it has answered, in
    /// order. A write the far end does not take ends the session. It returns once the caller's side
    /// has queued its last turn.
    async fn write_turns(
        &self,
        token: &Pass<Route>,
        queued: &mut mpsc::Receiver<OutboundRequest>,
        mut held: watch::Receiver<bool>,
        ended: &EndCell,
    ) {
        while let Some(request) = queued.recv().await {
            // The attempt that answered holds the session's far end: a frame never goes to an
            // attempt the walk is still dialling, or one it failed over from.
            if held.wait_for(|h| *h).await.is_err() {
                return;
            }
            if !self.far.write(token, request).await {
                end_session(ended, Halt::Cause(ReasonCode::DestinationUnreachable));
                return;
            }
        }
    }

    /// One side's end: a cancel is billed (and a cut renders its frame to the caller), its ticket
    /// goes back, and a side that did not simply finish ends the session for the other side.
    async fn close(
        &self,
        run: &mut Pumping<'_>,
        end: End,
        ended: &EndCell,
    ) -> Result<(), ReasonCode> {
        let why = cause(&end);
        if let End::Cancel(reason, done) = end {
            let _bill = run.cancel(reason, done);
            if reason == ReasonCode::OverBudget {
                self.cut_frame().await;
            }
        }
        run.finish();
        // The first side to end the session names why; the other side's end follows it. A side
        // that simply finished ends the session for the other side too.
        match why {
            Some(reason) => {
                end_session(ended, Halt::Cause(reason));
                Err(reason)
            }
            None => {
                end_session(ended, Halt::Over);
                Ok(())
            }
        }
    }
}
