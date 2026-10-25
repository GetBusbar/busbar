// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE LOADED PLANE INSTANCE AS THE KERNEL CALLS IT: [`PlaneInstance`] implements the contract's
//! `PlaneCalls` over the one dispatcher's plane handle, so the kernel's plane driver reaches a
//! compiled-in and a dropped-in plane through the same table without naming this crate. The
//! composition root builds it and hands it to the driver.

use std::future::Future;
use std::pin::Pin;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};

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
use super::call::{self, CancelRequest, Opts, Ran};
use super::inline::InlineTicket;
use super::plugin::Admission;
use super::{in_head, now_ns, Dispatcher, Frame, InFrame, OutFrame, Plugin};

/// One open plane instance, the dispatcher that adopted it, and the worker its driver ticket is
/// minted on. Its units' tickets are inline tickets the instance holds until the kernel recycles
/// them; their ops run on the one call path, on the caller's thread. The instance is shared,
/// never copied: a [`Plugin`] is `!Clone`, so a holder that keeps the plugin beside this one shares
/// the same `Arc`.
#[derive(Debug, Clone)]
pub struct PlaneInstance {
    plugin: Arc<Plugin<Plane>>,
    dispatcher: Arc<Dispatcher>,
    worker: u32,
    /// The units' tickets, held until the kernel recycles them.
    tickets: Arc<Mutex<HashMap<Ticket, Held>>>,
}

/// One unit ticket the instance holds for the kernel.
#[derive(Debug)]
struct Held {
    _ticket: InlineTicket,
    /// The op in flight on it: what a client drop asks to cancel.
    flight: Option<Arc<CancelRequest>>,
    /// Its client dropped: every later op on it is REFUSED until it is recycled.
    dropped: bool,
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
            tickets: Arc::default(),
        }
    }

    fn tickets(&self) -> std::sync::MutexGuard<'_, HashMap<Ticket, Held>> {
        self.tickets.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Op `s` of a unit on its `ticket`, on the one call path: crossed on the caller's thread,
    /// never refused for the instance's cap, cancelled at the kernel's client drop. A ticket whose
    /// client dropped answers every later op REFUSED, with no crossing, until it is recycled.
    fn unit_op<I: InFrame, O: OutFrame>(
        &self,
        ticket: Ticket,
        s: u32,
        class: DeadlineClass,
        frame: Frame<I, O>,
        lent: Lent,
    ) -> InFlight<I, O> {
        let cancel = Arc::new(CancelRequest::default());
        let dropped = match self.tickets().get_mut(&ticket) {
            Some(held) => {
                held.flight = Some(Arc::clone(&cancel));
                held.dropped
            }
            None => false,
        };
        if dropped {
            return InFlight::settled(Answered {
                outcome: Outcome::Refused,
                short: false,
                disposition: None,
            });
        }
        let plugin = Arc::clone(&self.plugin);
        let op = async move {
            call::call(
                &plugin,
                s,
                frame,
                lent,
                Opts {
                    class,
                    deadline: None,
                    watch: std::time::Duration::ZERO,
                    leave: false,
                    lane: None,
                    admission: Admission::Unit,
                    ticket: Some(ticket),
                    inline: true,
                    cancel: Some(cancel),
                },
                &mut |_| None,
            )
            .await
        };
        let mut flight = InFlight {
            op: Some(Box::pin(op)),
            done: None,
        };
        // Started at once: its first crossing runs now, as a submitted op's was queued now.
        let _ = flight.settled_now();
        flight
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
        let it = self.plugin.inline_ticket()?;
        let t = it.ticket();
        self.tickets().insert(
            t,
            Held {
                _ticket: it,
                flight: None,
                dropped: false,
            },
        );
        Some(t)
    }

    /// One unit's two tickets are independent: beside one is any other.
    fn mint_beside(&self, _beside: Ticket) -> Option<Ticket> {
        self.mint()
    }

    fn recycle(&self, ticket: Ticket) {
        let gone = self.tickets().remove(&ticket);
        drop(gone);
    }

    fn drop_client(&self, ticket: Ticket) {
        let flight = self.tickets().get_mut(&ticket).and_then(|h| {
            h.dropped = true;
            h.flight.clone()
        });
        if let Some(c) = flight {
            c.request();
        }
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
        // The unit's buffers ride with the op: a crossing the watchdog answered FAULT still owns
        // them until it returns. A piece of an admitted unit is never refused for the instance's
        // `max_inflight`: refused mid-answer, it would end a stream its caller was already
        // answered on.
        Box::new(self.unit_op(
            ticket,
            slot::ON_PIECE,
            DeadlineClass::Stream,
            Frame::new(input, out),
            lent,
        ))
    }

    fn serve(
        &self,
        ticket: Ticket,
        mut input: ServeIn,
        out: ServeOut,
        lent: Lent,
    ) -> Box<dyn ServeInFlight> {
        input.head = in_head();
        // As `on_piece`'s: the request's buffers ride with the op, on its admitted unit's ticket.
        Box::new(self.unit_op(
            ticket,
            slot::SERVE,
            DeadlineClass::Call,
            Frame::new(input, out),
            lent,
        ))
    }
}

/// A unit op in flight (`on_piece`, `serve`) on the one call path: its answer once it has one.
struct InFlight<I, O> {
    op: Option<Pin<Box<dyn Future<Output = Ran<I, O>> + Send>>>,
    done: Option<Done<O>>,
}

// SAFETY: as `Frame`'s (`InFrame`/`OutFrame` promise a frame may move between threads): the
// answer's `out` points only into the host buffers and lent memory of the op, and one thread
// touches the flight at a time.
unsafe impl<I: InFrame, O: OutFrame> Send for InFlight<I, O> {}

// Nothing in a flight is pinned in place: its op is boxed.
impl<I, O> Unpin for InFlight<I, O> {}

/// A unit op's settled answer.
struct Done<O> {
    answered: Answered,
    out: Option<O>,
    writes: Vec<CancelWrite>,
}

impl<I: InFrame, O: OutFrame> InFlight<I, O> {
    /// An op answered with no crossing (a frame-less settle).
    fn settled(answered: Answered) -> Self {
        Self {
            op: None,
            done: Some(Done {
                answered,
                out: None,
                writes: Vec::new(),
            }),
        }
    }

    /// Poll once with no waker: the answer if it has arrived; never waits.
    fn settled_now(&mut self) -> Option<Answered> {
        let mut cx = Context::from_waker(std::task::Waker::noop());
        match Pin::new(self).poll(&mut cx) {
            Poll::Ready(a) => Some(a),
            Poll::Pending => None,
        }
    }

    fn answer_out(&self) -> Option<O> {
        self.done.as_ref().and_then(|d| d.out)
    }
}

impl<I: InFrame, O: OutFrame> Future for InFlight<I, O> {
    type Output = Answered;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Answered> {
        if let Some(d) = &self.done {
            return Poll::Ready(d.answered.clone());
        }
        let Some(op) = self.op.as_mut() else {
            return Poll::Ready(Answered {
                outcome: Outcome::Fault,
                short: false,
                disposition: None,
            });
        };
        let ran = std::task::ready!(op.as_mut().poll(cx));
        self.op = None;
        let done = match ran {
            Ran::Answered { called, frame, .. } => Done {
                answered: Answered {
                    outcome: called.outcome,
                    short: called.recall.is_some(),
                    disposition: None,
                },
                out: Some(frame.out),
                writes: Vec::new(),
            },
            // Ended by its client drop's `cancel`: the plane's timeout with what the cancel said;
            // a cancel that FAULTed makes the op FAULT, with no disposition.
            Ran::TimedOut { cancelled } => match cancelled {
                Some(c) if c.outcome == Outcome::Ready => Done {
                    answered: Answered {
                        outcome: <Plane as super::Kind>::TIMEOUT,
                        short: false,
                        disposition: c.disposition,
                    },
                    out: None,
                    writes: c.writes,
                },
                Some(c) if c.outcome == Outcome::Fault => Done {
                    answered: Answered {
                        outcome: Outcome::Fault,
                        short: false,
                        disposition: None,
                    },
                    out: None,
                    writes: Vec::new(),
                },
                _ => Done {
                    answered: Answered {
                        outcome: <Plane as super::Kind>::TIMEOUT,
                        short: false,
                        disposition: None,
                    },
                    out: None,
                    writes: Vec::new(),
                },
            },
            Ran::NoTicket => Done {
                answered: Answered {
                    outcome: Outcome::Fault,
                    short: false,
                    disposition: None,
                },
                out: None,
                writes: Vec::new(),
            },
        };
        let a = done.answered.clone();
        self.done = Some(done);
        Poll::Ready(a)
    }
}

impl ServeInFlight for InFlight<ServeIn, ServeOut> {
    fn out(&self) -> Option<ServeOut> {
        self.answer_out()
    }
}

impl PieceInFlight for InFlight<OnPieceIn, OnPieceOut> {
    fn settled(&mut self) -> Option<Answered> {
        self.settled_now()
    }

    fn out(&self) -> Option<OnPieceOut> {
        self.answer_out()
    }

    fn cancel_writes(&self) -> Vec<CancelWrite> {
        self.done
            .as_ref()
            .map(|d| d.writes.clone())
            .unwrap_or_default()
    }
}
