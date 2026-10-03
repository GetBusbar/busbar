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
//! - EVERY TURN LEG IS A ROUTE WALK (the unit's own `attempts`) under the session's one admission
//!   and its Route pass, inside the destination set sealed at the open: a caller-side answer bound
//!   for the far end is a turn's request, and the far side walks it. A turn that fails ends the
//!   session, and so does a cancel on either side; each side tells the other.
//! - CLEANUP RUNS EXACTLY ONCE, however the session ends (its own end, a cancel, or its caller
//!   dropping the future): the stream leaves the instance's table and the money seam is told, in
//!   the session's one guard; each side's ticket goes back through its own pump (finished, or
//!   buried for the sweep).
//! - Money per THE DESIGN §7 (`MoneySeam::session_opened`), which refuses until K6-4 states it.

use std::future::Future;
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

/// One turn leg: the request a caller-side answer bound for the far end, and the destination set
/// sealed at the session's open.
pub(crate) struct Turn<'t> {
    pub(crate) request: OutboundRequest,
    sealed: &'t [VerifiedDestination],
}

impl Turn<'_> {
    /// Whether `member` is inside the set sealed at the open.
    pub(crate) fn within(&self, member: &str) -> bool {
        self.sealed.iter().any(|d| d.lane().as_str() == member)
    }
}

/// The session's ONE cleanup, run by its drop whichever way the session ends.
struct Open<'d> {
    driver: &'d PlaneDriver,
    stream: u64,
    ctx: &'d UnitCtx,
}

impl Drop for Open<'_> {
    fn drop(&mut self) {
        self.driver.lock_sessions().remove(&self.stream);
        self.driver.money.session_ended(self.ctx);
    }
}

/// What the caller side waits for next.
enum Next {
    /// The other side ended the session.
    Halt(ReasonCode),
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
    }
}

impl<S: crate::plane_driver::DriverSteps + Sync, F: FarEnd, C: SessionCaller> PlaneUnits<'_, S, F, C> {
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
        let d = self.driver;
        d.money.session_opened(ctx)?;
        let stream = ctx.key.get();
        let told = Arc::new(Notify::new());
        d.lock_sessions().insert(stream, told.clone());
        let _open = Open {
            driver: d,
            stream,
            ctx,
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
        let ended = watch::Sender::new(None);
        let (turns, mut queued) = mpsc::channel(1);
        let near_side = async {
            let end = self
                .near_side(&mut near_run, &told, ended.subscribe(), turns)
                .await;
            self.close(&mut near_run, end, &ended).await
        };
        let far_side = async {
            let end = self
                .far_side(&mut far_run, ended.subscribe(), &mut queued, sealed)
                .await;
            self.close(&mut far_run, end, &ended).await
        };
        let (near, far) = tokio::join!(near_side, far_side);
        near.and(far)
    }

    /// The caller side, on its own ticket: the caller's pieces, and the collection of what the
    /// plane has ready whenever `drive` named the session. An answer bound for the far end is
    /// queued as a turn. It ends when the caller's side ends, the plane says its reply is done,
    /// the other side ended the session, or the driver cancels.
    async fn near_side(
        &self,
        run: &mut Pumping<'_>,
        told: &Notify,
        mut ended: watch::Receiver<Option<ReasonCode>>,
        turns: mpsc::Sender<OutboundRequest>,
    ) -> End {
        loop {
            let next = guarded_run(run, async {
                tokio::select! {
                    biased;
                    halt = ended.wait_for(Option::is_some) => {
                        Next::Halt(halt.ok().and_then(|h| *h).unwrap_or(ReasonCode::ClientGone))
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
                Err(cause) | Ok(Next::Halt(cause)) => return End::Cancel(cause, None),
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
                Ok(Next::Caller(None)) => Piece {
                    flags: PIECE_LAST,
                    ..quiet
                },
            };
            let mut request = OutboundRequest::default();
            match self
                .push(run, piece, &mut Toward::Session(&mut request))
                .await
            {
                Step::End(end) => return end,
                Step::Answered(done) => {
                    if request != OutboundRequest::default() && turns.send(request).await.is_err() {
                        return End::Done;
                    }
                    if done || piece.flags & PIECE_LAST != 0 {
                        return End::Done;
                    }
                }
                // A verdict means nothing on the caller's side: there is nothing to fail over.
                Step::Retry => {}
            }
        }
    }

    /// The far side, on its own ticket: each queued turn, one at a time, as a route walk inside
    /// the sealed set. Each turn starts with its own facts, so its failover window is its own.
    /// It ends once the caller side has ended and every queued turn is walked, or when a turn
    /// fails, the other side ended the session, or the driver cancels.
    async fn far_side(
        &self,
        run: &mut Pumping<'_>,
        mut ended: watch::Receiver<Option<ReasonCode>>,
        queued: &mut mpsc::Receiver<OutboundRequest>,
        sealed: &[VerifiedDestination],
    ) -> End {
        loop {
            let next = guarded_run(run, async {
                tokio::select! {
                    biased;
                    halt = ended.wait_for(Option::is_some) => {
                        Err(halt.ok().and_then(|h| *h).unwrap_or(ReasonCode::ClientGone))
                    }
                    turn = queued.recv() => Ok(turn),
                }
            })
            .await;
            let request = match next {
                Err(cause) | Ok(Err(cause)) => return End::Cancel(cause, None),
                Ok(Ok(None)) => return End::Done,
                Ok(Ok(Some(request))) => request,
            };
            run.lock().facts = Facts::default();
            match self.attempts(run, Some(&Turn { request, sealed })).await {
                End::Done => {}
                end => return end,
            }
        }
    }

    /// One side's end: a cancel is billed (and a cut renders its frame to the caller), its ticket
    /// goes back, and a side that did not simply finish ends the session for the other side.
    async fn close(
        &self,
        run: &mut Pumping<'_>,
        end: End,
        ended: &watch::Sender<Option<ReasonCode>>,
    ) -> Result<(), ReasonCode> {
        let why = cause(&end);
        if let End::Cancel(reason, done) = end {
            let _bill = run.cancel(reason, done);
            if reason == ReasonCode::OverBudget {
                self.cut_frame().await;
            }
        }
        run.finish();
        match why {
            Some(reason) => {
                // The first side to end the session names why; the other side's end follows it.
                ended.send_if_modified(|e| {
                    let first = e.is_none();
                    if first {
                        *e = Some(reason);
                    }
                    first
                });
                Err(reason)
            }
            None => Ok(()),
        }
    }
}
