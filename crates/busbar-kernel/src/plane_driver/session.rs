// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::future::Future;
use std::pin::pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use busbar_contract::abi::plane::{FROM_CALLER, FROM_KERNEL, PIECE_LAST};
use busbar_contract::caps::{Pass, ReasonCode, Route, VerifiedDestination};
use tokio::sync::{mpsc, watch, Notify};

use super::{
    guarded_run, CallerEnd, End, FarEnd, OutboundRequest, Piece, Pumping, Src, Step, Toward,
};
use crate::plane_driver::{PlaneDriver, PlaneUnits};
use crate::teller::UnitCtx;

pub trait SessionCaller: CallerEnd {
    fn read(&self) -> impl Future<Output = Option<Vec<u8>>> + Send + '_;

    fn read_owned(&self) -> impl Future<Output = Option<SessionInput>> + Send + '_ {
        async move {
            self.read().await.map(|bytes| SessionInput {
                bytes,
                custody: None,
            })
        }
    }
}

/// A caller piece and opaque ownership that follows its allocation through the session pump.
/// A successful crossing retires the consumed allocation before any record/output waits or the
/// next read. A crossing that still borrows it after the session ends retains its custody.
#[derive(Default)]
pub struct SessionInput {
    /// The piece's allocation. Declared first so it is dropped before its custody owner.
    pub bytes: Vec<u8>,
    /// Optional allocation custody; the kernel neither inspects nor clones it.
    pub custody: Option<Arc<dyn Send + Sync>>,
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
    pub(crate) fn end(self) -> End {
        match self {
            Halt::Cause(cause) => End::Cancel(cause, None),
            Halt::Over => End::Done,
        }
    }
}

type EndCell = watch::Sender<Option<Halt>>;

fn end_session(ended: &EndCell, halt: Halt) {
    ended.send_if_modified(|e| {
        let first = e.is_none();
        if first {
            *e = Some(halt);
        }
        first
    });
}

pub(crate) struct Turn<'t> {
    pub(crate) request: OutboundRequest,
    sealed: &'t [VerifiedDestination],
    halt: watch::Receiver<Option<Halt>>,
    pub(crate) held: &'t watch::Sender<bool>,
}

impl Turn<'_> {
    pub(crate) fn within(&self, member: &str) -> bool {
        self.sealed.iter().any(|d| d.lane().as_str() == member)
    }

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

struct Open<'d> {
    driver: &'d PlaneDriver,
    stream: u64,
    ctx: &'d UnitCtx,

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

enum Next {
    Open,

    Halt(Halt),

    Collect,

    Caller(Option<SessionInput>),
}

fn wake_ready(sessions: &Mutex<std::collections::HashMap<u64, Arc<Notify>>>, ready: &[u64]) {
    let told: Vec<_> = {
        let open = sessions.lock().unwrap_or_else(PoisonError::into_inner);
        ready
            .iter()
            .filter_map(|stream| open.get(stream).cloned())
            .collect()
    };
    for told in told {
        told.notify_one();
    }
}

impl PlaneDriver {
    fn lock_sessions(&self) -> MutexGuard<'_, std::collections::HashMap<u64, Arc<Notify>>> {
        self.sessions.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub async fn drives(&self) {
        if self.driver.is_none() {
            return;
        }
        loop {
            let ready = self.calls.ready().await;
            if ready.is_empty() {
                return;
            }
            wake_ready(&self.sessions, &ready);
        }
    }
}

#[cfg(test)]
#[path = "tests/session_wake_tests.rs"]
mod session_wake_tests;

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
    pub async fn session(
        &self,
        token: &Pass<Route>,
        ctx: &UnitCtx,
        sealed: &[VerifiedDestination],
    ) -> Result<(), ReasonCode> {
        self.session_priced(token, ctx, sealed, true).await
    }

    pub(crate) async fn session_priced(
        &self,
        token: &Pass<Route>,
        ctx: &UnitCtx,
        sealed: &[VerifiedDestination],
        priced: bool,
    ) -> Result<(), ReasonCode> {
        let d = self.driver;
        self.open_hooks(token, ctx).await?;
        if priced {
            d.money.session_opened(ctx)?;
        }

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

        let near = d.calls.mint();
        let far = near.and_then(|n| d.calls.mint_beside(n));
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
        let none = bytes::Bytes::new();
        let mut near_run = Pumping::new(
            d,
            token,
            &self.state,
            ctx,
            near,
            self.deadline_ns,
            none.clone(),
        );
        let mut far_run = Pumping::new(d, token, &self.state, ctx, far, self.deadline_ns, none);
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

    async fn near_side(
        &self,
        run: &mut Pumping<'_>,
        told: &Notify,
        mut ended: watch::Receiver<Option<Halt>>,
        turns: mpsc::Sender<OutboundRequest>,
    ) -> End {
        let mut opening = true;
        loop {
            let next = if std::mem::take(&mut opening) {
                Ok(Next::Open)
            } else {
                guarded_run(run, async {
                tokio::select! {
                    biased;
                    halt = ended.wait_for(Option::is_some) => {
                        Next::Halt(halt.ok().and_then(|h| *h).unwrap_or(Halt::Cause(ReasonCode::ClientGone)))
                    }
                    () = told.notified() => Next::Collect,
                    read = self.caller.read_owned() => Next::Caller(read),
                }
                })
                .await
            };
            let quiet = Piece {
                from: FROM_CALLER,
                flags: 0,
                status: (0, 0),
                attempt_no: 0,
                src: Src::None,
                head: false,
                reason: 0,
            };
            let piece = match next {
                Ok(Next::Open) => quiet,
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

                    if request != OutboundRequest::default() {
                        let _ = turns.send(request).await;
                    }
                }

                Step::Retry => {}
            }
        }
    }

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

            Ok(Ok(None)) => return End::Done,
            Ok(Ok(Some(request))) => request,
        };
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

    async fn write_turns(
        &self,
        token: &Pass<Route>,
        queued: &mut mpsc::Receiver<OutboundRequest>,
        mut held: watch::Receiver<bool>,
        ended: &EndCell,
    ) {
        while let Some(request) = queued.recv().await {
            if held.wait_for(|h| *h).await.is_err() {
                return;
            }
            if !self.far.write(token, request).await {
                end_session(ended, Halt::Cause(ReasonCode::DestinationUnreachable));
                return;
            }
        }
    }

    async fn close(
        &self,
        run: &mut Pumping<'_>,
        end: End,
        ended: &EndCell,
    ) -> Result<(), ReasonCode> {
        let why = match *ended.borrow() {
            Some(Halt::Over) => None,
            Some(Halt::Cause(reason)) => Some(reason),
            None => cause(&end),
        };

        end_session(ended, why.map_or(Halt::Over, Halt::Cause));
        if let (Some(reason), End::Cancel(_, done)) = (why, end) {
            let _bill = run.cancel(reason, done).await;
            if reason == ReasonCode::OverBudget {
                self.cut_frame().await;
            }
        }
        run.finish();

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
