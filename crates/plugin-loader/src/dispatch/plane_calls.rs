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
    slot, ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, RefusalIn, RefusalOut, RefusalStatus,
};
use busbar_contract::plane_calls::{Answered, Grow, Lent, PieceInFlight, PlaneCalls};

use super::kinds::plane::Plane;
use super::{
    cancel_frame, in_head, now_ns, Dispatcher, Done, Frame, InFrame, OutFrame, Plugin, Reply,
};

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

    fn refusal(
        &self,
        input: &mut RefusalIn,
        out: &mut RefusalOut,
        grow: Grow<'_, RefusalIn, RefusalOut>,
    ) -> Outcome {
        self.pure(slot::REFUSAL, input, out, grow)
    }

    fn cancel(&self, ticket: Ticket) -> Option<u32> {
        let mut frame = cancel_frame(ticket);
        let called = self.plugin.call(life::CANCEL, &mut frame);
        (called.outcome == Outcome::Ready).then_some(frame.out.disposition)
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
        Box::new(Piece { reply, done: None })
    }
}

/// An `on_piece` in flight: its reply, then its answer.
struct Piece {
    reply: Reply<OnPieceIn, OnPieceOut>,
    done: Option<Done<OnPieceIn, OnPieceOut>>,
}

fn answered(d: &Done<OnPieceIn, OnPieceOut>) -> Answered {
    Answered {
        outcome: d.outcome,
        short: d.short,
        disposition: d.disposition,
    }
}

impl Future for Piece {
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

impl PieceInFlight for Piece {
    fn settled(&mut self) -> Option<Answered> {
        if self.done.is_none() {
            self.done = self.reply.wait(Duration::ZERO);
        }
        self.done.as_ref().map(answered)
    }

    fn out(&self) -> Option<OnPieceOut> {
        self.done
            .as_ref()
            .and_then(|d| d.frame.as_deref())
            .map(|f| f.out)
    }
}
