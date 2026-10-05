// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE LOADED PLANE INSTANCE AS THE KERNEL CALLS IT: [`PlaneInstance`] implements the contract's
//! `PlaneCalls` over the one dispatcher's plane handle, so the kernel's plane driver reaches a
//! compiled-in and a dropped-in plane through the same table without naming this crate. The
//! composition root builds it and hands it to the driver.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use busbar_contract::abi::mechanism::call::{DeadlineClass, Outcome};
use busbar_contract::abi::mechanism::lifecycle::slot as life;
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::plane::{
    slot, ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, ProjectIn, ProjectOut, RefusalIn, RefusalOut,
    RefusalStatus, ServeIn, ServeOut,
};
use busbar_contract::plane_calls::{
    Answered, CancelWrite, Cancelled, Grow, InstanceDecl, Lent, PieceInFlight, PlaneCalls,
    ServeInFlight,
};

use super::kinds::plane::Plane;
use super::{in_head, now_ns, Dispatcher, Done, Frame, InFrame, OutFrame, Plugin, Reply};

/// One open plane instance, the dispatcher that adopted it, and the worker its unit tickets are
/// minted on.
#[derive(Debug, Clone)]
pub struct PlaneInstance {
    plugin: Plugin<Plane>,
    dispatcher: Arc<Dispatcher>,
    worker: u32,
}

impl PlaneInstance {
    /// `plugin`, adopted by `dispatcher`, its unit tickets minted on `worker`.
    pub fn new(plugin: Plugin<Plane>, dispatcher: Arc<Dispatcher>, worker: u32) -> Self {
        PlaneInstance {
            plugin,
            dispatcher,
            worker,
        }
    }

    /// The refusal statuses the plane's tail states, for the driver's config.
    pub fn refusal_statuses(&self) -> Vec<RefusalStatus> {
        self.plugin.refusal_statuses().to_vec()
    }

    /// A ticketless call of `s` with the one re-call a short answer earns. It crosses on the
    /// caller's own thread ([`Plugin::call`]), which the watchdog can fault but never abandon: the
    /// caller is inside the crossing until it returns, so the buffers it lends need no owner.
    fn pure<I: InFrame, O: OutFrame>(
        &self,
        s: u32,
        input: &mut I,
        out: &mut O,
        grow: Grow<'_, I, O>,
    ) -> Outcome {
        let mut frame = Frame::new(*input, *out);
        let mut called = self.plugin.call(s, &mut frame);
        if let Some(token) = called.recall.take() {
            grow(&frame.out, &mut frame.input);
            called = self.plugin.recall(token, s, &mut frame);
        }
        (*input, *out) = (frame.input, frame.out);
        called.outcome
    }
}

impl PlaneCalls for PlaneInstance {
    fn now_ns(&self) -> u64 {
        now_ns()
    }

    fn arrive(
        &self,
        input: &mut ArriveIn,
        out: &mut ArriveOut,
        grow: Grow<'_, ArriveIn, ArriveOut>,
    ) -> Outcome {
        self.pure(slot::ARRIVE, input, out, grow)
    }

    fn arrived_pool(&self, out: &ArriveOut) -> Option<Vec<u8>> {
        crate::dispatch::plugin::copy_str(out.pool)
    }

    fn arrived_refusal(&self, out: &ArriveOut) -> Option<Vec<u8>> {
        crate::dispatch::plugin::copy_str(out.head.error)
    }

    fn refusal(
        &self,
        input: &mut RefusalIn,
        out: &mut RefusalOut,
        grow: Grow<'_, RefusalIn, RefusalOut>,
    ) -> Outcome {
        self.pure(slot::REFUSAL, input, out, grow)
    }

    fn project(
        &self,
        input: &mut ProjectIn,
        out: &mut ProjectOut,
        grow: Grow<'_, ProjectIn, ProjectOut>,
    ) -> Outcome {
        self.pure(slot::PROJECT, input, out, grow)
    }

    fn cancel(&self, ticket: Ticket) -> Option<Cancelled> {
        use super::CancelFrame as _;
        // The plane's own `cancel` frame, its record buffers lent (SEAM-L(r)).
        let mut cancel = super::PlaneCancel::new();
        let _ = cancel.prepare(ticket, 0);
        let called = self.plugin.call(life::CANCEL, cancel.frame());
        (called.outcome == Outcome::Ready).then(|| Cancelled {
            disposition: cancel.disposition(),
            writes: cancel.writes(),
        })
    }

    fn mint(&self) -> Option<Ticket> {
        self.dispatcher.mint(self.worker)
    }

    fn recycle(&self, ticket: Ticket) {
        self.dispatcher.recycle(ticket);
    }

    fn drop_client(&self, ticket: Ticket) {
        self.dispatcher.drop_client(ticket);
    }

    fn declared(&self) -> InstanceDecl {
        self.plugin.declared()
    }

    fn driver(&self) -> Option<Ticket> {
        self.dispatcher.driver(&self.plugin, self.worker)
    }

    fn ready(&self) -> Pin<Box<dyn Future<Output = Vec<u64>> + Send>> {
        let inst = self.plugin.inner.clone();
        Box::pin(async move {
            if inst.is_open() {
                inst.driven.take().await
            } else {
                Vec::new()
            }
        })
    }

    fn tick(
        &self,
        driver: Ticket,
        now_ns: u64,
    ) -> Pin<Box<dyn Future<Output = Option<u64>> + Send>> {
        let reply = self.dispatcher.tick(&self.plugin, driver, now_ns);
        Box::pin(async move {
            let done = reply.await;
            matches!(done.outcome, Outcome::Ready | Outcome::Pending)
                .then(|| done.frame.map(|f| f.out.next_tick_ns))
                .flatten()
        })
    }

    fn on_piece(
        &self,
        ticket: Ticket,
        mut input: OnPieceIn,
        out: OnPieceOut,
        lent: Lent,
    ) -> Box<dyn PieceInFlight> {
        input.head = in_head();
        // The unit's buffers ride with the job: a crossing the watchdog answered FAULT still owns
        // them until it returns.
        let reply = self.dispatcher.submit_lent(
            &self.plugin,
            ticket,
            slot::ON_PIECE,
            Frame::new(input, out),
            DeadlineClass::Stream,
            0,
            lent,
        );
        Box::new(InFlight { reply, done: None })
    }

    fn serve(
        &self,
        ticket: Ticket,
        mut input: ServeIn,
        out: ServeOut,
        lent: Lent,
    ) -> Box<dyn ServeInFlight> {
        input.head = in_head();
        // As `on_piece`'s: the request's buffers ride with the job.
        let reply = self.dispatcher.submit_lent(
            &self.plugin,
            ticket,
            slot::SERVE,
            Frame::new(input, out),
            DeadlineClass::Call,
            0,
            lent,
        );
        Box::new(InFlight { reply, done: None })
    }
}

/// A ticketed op in flight (`on_piece`, `serve`): its reply, then its answer.
struct InFlight<I, O> {
    reply: Reply<I, O>,
    done: Option<Done<I, O>>,
}

fn answered<I, O>(d: &Done<I, O>) -> Answered {
    Answered {
        outcome: d.outcome,
        short: d.short,
        disposition: d.disposition,
    }
}

impl<I: InFrame, O: OutFrame> Future for InFlight<I, O> {
    type Output = Answered;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Answered> {
        if let Some(d) = &self.done {
            return Poll::Ready(answered(d));
        }
        match Pin::new(&mut self.reply).poll(cx) {
            Poll::Ready(d) => {
                let a = answered(&d);
                self.done = Some(d);
                Poll::Ready(a)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<I: InFrame, O: OutFrame> InFlight<I, O> {
    fn answer_out(&self) -> Option<O> {
        self.done
            .as_ref()
            .and_then(|d| d.frame.as_deref())
            .map(|f| f.out)
    }
}

impl ServeInFlight for InFlight<ServeIn, ServeOut> {
    fn out(&self) -> Option<ServeOut> {
        self.answer_out()
    }
}

impl PieceInFlight for InFlight<OnPieceIn, OnPieceOut> {
    fn settled(&mut self) -> Option<Answered> {
        if self.done.is_none() {
            self.done = self.reply.wait(Duration::ZERO);
        }
        self.done.as_ref().map(answered)
    }

    fn out(&self) -> Option<OnPieceOut> {
        self.answer_out()
    }

    fn cancel_writes(&self) -> Vec<CancelWrite> {
        self.done
            .as_ref()
            .map(|d| d.cancel_writes.clone())
            .unwrap_or_default()
    }
}
