// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use busbar_contract::abi::mechanism::call::{DeadlineClass, Outcome};
use busbar_contract::abi::mechanism::ticket::Ticket;

use super::{Dispatcher, Done, Frame, InFrame, Kind, Lent, OutFrame, Plugin, Reply};

pub(crate) struct Ticketed<I, O> {
    dispatcher: Arc<Dispatcher>,
    ticket: Ticket,
    reply: Option<Reply<I, O>>,

    watch: Duration,
}

impl<I: InFrame, O: OutFrame> Ticketed<I, O> {
    pub(crate) fn mint(dispatcher: &Arc<Dispatcher>, worker: u32) -> Option<Self> {
        Some(Self {
            ticket: dispatcher.mint(worker)?,
            dispatcher: Arc::clone(dispatcher),
            reply: None,
            watch: Duration::ZERO,
        })
    }

    pub(crate) fn watched(mut self, watch: Duration) -> Self {
        self.watch = watch;
        self
    }

    pub(crate) fn submit<K: Kind>(
        &mut self,
        plugin: &Plugin<K>,
        s: u32,
        frame: Frame<I, O>,
        class: DeadlineClass,
        deadline_ns: u64,
        lent: Lent,
    ) {
        self.reply = Some(self.dispatcher.submit_watched(
            plugin,
            self.ticket,
            s,
            frame,
            class,
            deadline_ns,
            lent,
            self.watch,
        ));
    }
}

impl<I: InFrame, O: OutFrame> Future for Ticketed<I, O> {
    type Output = Done<I, O>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Done<I, O>> {
        let Some(reply) = self.reply.as_mut() else {
            return Poll::Ready(Done {
                outcome: Outcome::Fault,
                error: None,
                lease: 0,
                frame: None,
                detached: false,
                short: false,
                disposition: None,
                cancel_writes: Vec::new(),
            });
        };
        let done = std::task::ready!(Pin::new(reply).poll(cx));
        self.reply = None;
        Poll::Ready(done)
    }
}

impl<I, O> Drop for Ticketed<I, O> {
    fn drop(&mut self) {
        drop(self.reply.take());
        self.dispatcher.recycle(self.ticket);
    }
}

pub(crate) trait Answering<I, O> {
    type Out: Clone;
    fn answer(&mut self, done: Done<I, O>, call: &mut Ticketed<I, O>) -> Option<Self::Out>;

    fn start(&mut self, _call: &mut Ticketed<I, O>) {}
}

pub(crate) struct Pending<I, O, A: Answering<I, O>> {
    call: Ticketed<I, O>,
    door: A,
    answer: Option<A::Out>,
    faulted: bool,
}

impl<I, O, A: Answering<I, O>> Unpin for Pending<I, O, A> {}

impl<I: InFrame, O: OutFrame, A: Answering<I, O>> Pending<I, O, A> {
    pub(crate) fn new(call: Ticketed<I, O>, door: A) -> Self {
        Self {
            call,
            door,
            answer: None,
            faulted: false,
        }
    }

    pub(crate) fn now(&mut self) -> Option<A::Out> {
        match self.step(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(a) => Some(a),
            Poll::Pending => None,
        }
    }

    pub(crate) fn any_fault(&self) -> bool {
        self.faulted
    }

    fn step(&mut self, cx: &mut Context<'_>) -> Poll<A::Out> {
        loop {
            if let Some(a) = &self.answer {
                return Poll::Ready(a.clone());
            }
            if self.call.reply.is_none() {
                self.door.start(&mut self.call);
            }
            let done = std::task::ready!(Pin::new(&mut self.call).poll(cx));
            self.faulted |= done.outcome == Outcome::Fault;
            self.answer = self.door.answer(done, &mut self.call);
        }
    }
}

impl<I: InFrame, O: OutFrame, A: Answering<I, O>> Future for Pending<I, O, A> {
    type Output = A::Out;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<A::Out> {
        self.get_mut().step(cx)
    }
}
