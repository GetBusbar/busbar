// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE LOADED PLANE INSTANCE AS THE KERNEL CALLS IT: [`PlaneInstance`] implements the contract's
//! `PlaneCalls` over the one dispatcher's plane handle, so the kernel's plane driver reaches a
//! compiled-in and a dropped-in plane through the same table without naming this crate. The
//! composition root builds it and hands it to the driver.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
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
    Answered, ArrivedTrust, CancelWrite, Cancelled, Grow, InstanceDecl, Lent, PieceInFlight,
    PlaneCalls, ServeInFlight,
};

use super::kinds::plane::Plane;
use super::{in_head, now_ns, Dispatcher, Done, Frame, InFrame, OutFrame, Plugin, Reply};

/// One open plane instance, the dispatcher that adopted it, and the worker its driver ticket is
/// minted on. Its unit tickets are spread over every worker of the dispatcher, from that one on
/// (the slab is per instance and worker, `BUSBAR-1.6.0.md` A.4.1): one worker would cross every
/// piece of every unit of the plane in turn. The instance is shared, never copied: a [`Plugin`] is
/// `!Clone`, so a holder that keeps the plugin beside this one shares the same `Arc`.
#[derive(Debug, Clone)]
pub struct PlaneInstance {
    plugin: Arc<Plugin<Plane>>,
    dispatcher: Arc<Dispatcher>,
    worker: u32,
    /// How many unit tickets were minted: the next one's worker, counted on from `worker`.
    minted: Arc<AtomicU32>,
}

impl PlaneInstance {
    /// `plugin` (owned, or shared through its `Arc`), adopted by `dispatcher`, its driver ticket
    /// minted on `worker` and its unit tickets on every worker in turn from `worker` on.
    pub fn new(
        plugin: impl Into<Arc<Plugin<Plane>>>,
        dispatcher: Arc<Dispatcher>,
        worker: u32,
    ) -> Self {
        PlaneInstance {
            plugin: plugin.into(),
            dispatcher,
            worker,
            minted: Arc::new(AtomicU32::new(0)),
        }
    }

    /// The worker the next unit ticket is minted on: every worker of the dispatcher in turn.
    fn next_worker(&self) -> u32 {
        let workers = self.dispatcher.workers().max(1);
        let turn = self.minted.fetch_add(1, Ordering::Relaxed) % workers;
        (self.worker % workers + turn) % workers
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

    fn arrived_affinity(&self, out: &ArriveOut) -> Option<Vec<u8>> {
        crate::dispatch::plugin::copy_str(out.affinity)
    }

    fn arrived_trust(&self, out: &ArriveOut) -> Option<ArrivedTrust> {
        use crate::dispatch::plugin::copy_str;
        let counterparty = copy_str(out.trust_counterparty).filter(|c| !c.is_empty())?;
        Some(ArrivedTrust {
            counterparty,
            item: copy_str(out.trust_item).filter(|c| !c.is_empty()),
            digest: copy_str(out.trust_digest).filter(|c| !c.is_empty()),
        })
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

    fn catalog(
        &self,
        input: &mut busbar_contract::abi::plane::CatalogIn,
        out: &mut busbar_contract::abi::plane::CatalogOut,
        grow: Grow<
            '_,
            busbar_contract::abi::plane::CatalogIn,
            busbar_contract::abi::plane::CatalogOut,
        >,
    ) -> Outcome {
        self.pure(slot::CATALOG, input, out, grow)
    }

    fn project(
        &self,
        input: &mut ProjectIn,
        out: &mut ProjectOut,
        grow: Grow<'_, ProjectIn, ProjectOut>,
    ) -> Outcome {
        self.pure(slot::PROJECT, input, out, grow)
    }

    fn cancel(&self, ticket: Ticket, unit: u64) -> Option<Cancelled> {
        use super::CancelFrame as _;
        // The plane's own `cancel` frame, its record buffers lent (SEAM-L(r)), naming the unit.
        let mut cancel = super::PlaneCancel::new();
        let _ = cancel.prepare(ticket, 0);
        cancel.frame().input.unit = unit;
        let called = self.plugin.call(life::CANCEL, cancel.frame());
        (called.outcome == Outcome::Ready).then(|| Cancelled {
            disposition: cancel.disposition(),
            writes: cancel.writes(),
        })
    }

    fn mint(&self) -> Option<Ticket> {
        self.dispatcher.mint(self.next_worker())
    }

    /// On the worker `beside` was minted on: one unit's tickets cross on one worker.
    fn mint_beside(&self, beside: Ticket) -> Option<Ticket> {
        let (worker, _) = super::ticket::decode(beside.slot);
        self.dispatcher.mint(worker)
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
        self.dispatcher.driver(&*self.plugin, self.worker)
    }

    fn woke(&self) -> Pin<Box<dyn Future<Output = bool> + Send>> {
        let inst = self.plugin.inner.clone();
        Box::pin(async move {
            if !inst.is_open() {
                return false;
            }
            inst.driven.woken().await;
            true
        })
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
        let reply = self.dispatcher.tick(&*self.plugin, driver, now_ns);
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
        // them until it returns. A piece of an admitted unit is never refused for the instance's
        // `max_inflight` ([`Dispatcher::submit_unit`]): refused mid-answer, it would end a stream
        // its caller was already answered on.
        let reply = self.dispatcher.submit_unit(
            &*self.plugin,
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
        // As `on_piece`'s: the request's buffers ride with the job, on its admitted unit's ticket.
        let reply = self.dispatcher.submit_unit(
            &*self.plugin,
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
