// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE CALL ON A TICKET OF ITS OWN, the submit-and-await every door shares: the ticket is minted
//! for the call and recycled when the call is dropped, however it ended; awaiting it answers the
//! op's [`Done`].

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use busbar_contract::abi::mechanism::call::{DeadlineClass, Outcome};
use busbar_contract::abi::mechanism::ticket::Ticket;

use super::{Dispatcher, Done, Frame, InFrame, Kind, Lent, OutFrame, Plugin, Reply};

/// One call's ticket and the reply of the op it submitted last (a REFUSED or SHORT op is
/// re-submitted on the same ticket).
///
/// DROPPED BEFORE ITS ANSWER, the reply's drop is a client drop ([`Reply`]): the op is cancelled
/// (a WriteBehind op runs on), and the memory lent to it stays with the op until its last crossing
/// returns ([`Lent`]). The ticket is recycled after that client drop, and the dispatcher bumps its
/// generation once the op ends.
pub(crate) struct Ticketed<I, O> {
    dispatcher: Arc<Dispatcher>,
    ticket: Ticket,
    reply: Option<Reply<I, O>>,
    /// The ops' watch budget ([`Dispatcher::submit_watched`]); zero: their class budget.
    watch: Duration,
}

impl<I: InFrame, O: OutFrame> Ticketed<I, O> {
    /// A ticket minted on `worker` for one call; `None` when none can be minted.
    pub(crate) fn mint(dispatcher: &Arc<Dispatcher>, worker: u32) -> Option<Self> {
        Some(Self {
            ticket: dispatcher.mint(worker)?,
            dispatcher: Arc::clone(dispatcher),
            reply: None,
            watch: Duration::ZERO,
        })
    }

    /// Every op of the call is submitted with `watch` as its watch budget.
    pub(crate) fn watched(mut self, watch: Duration) -> Self {
        self.watch = watch;
        self
    }

    /// Submit op `s` over `frame` on the call's ticket, lending `lent` until the op completes.
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

    /// The submitted op's answer; with none submitted, a FAULT with no frame.
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
