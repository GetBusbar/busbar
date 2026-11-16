// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The state one channel generation shares with its attachments (IF §12.19): the ask line, the writer
//! queue (frames in arrival order, drained by the carrier's writer task), the CH_READY tail and the greet
//! hand-off. The carrier driver builds one `Link` per generation and hands each attach an `Attachment`.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, watch, Notify};

use super::ask_line::{AskLine, Write};

/// Who holds the greeting of a generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Greet {
    /// Nobody greets yet: the next attach to ask does.
    Open,
    /// The attachment in this slot runs the greeting.
    Held(u64),
    /// The greeting session answered CH_READY.
    Done,
}

/// What an attach finds of the greeting.
#[derive(Debug, PartialEq, Eq)]
pub enum Claim {
    /// This attach runs the greeting (its `ChanAttach.greet` is 1).
    Greeter,
    /// The greeting is done: the CH_READY tail the greeting session published.
    Ready(Box<[u8]>),
    /// Another attach is greeting: wait for [`Link::greet_released`].
    Wait,
}

pub struct Link {
    line: Mutex<AskLine>,
    writer: mpsc::UnboundedSender<Box<[u8]>>,
    ready: watch::Sender<Option<Box<[u8]>>>,
    greet_free: Notify,
    greet: Mutex<Greet>,
    attached: AtomicUsize,
    born: Instant,
    /// Nanoseconds after `born` of the last attach, detach or send.
    last_ns: AtomicU64,
}

impl Link {
    /// A fresh generation; `serial` = CH_SERIAL. The receiver is the writer task's queue.
    #[must_use]
    pub fn new(serial: bool) -> (Arc<Self>, mpsc::UnboundedReceiver<Box<[u8]>>) {
        let (writer, queue) = mpsc::unbounded_channel();
        let (ready, _) = watch::channel(None);
        let link = Self {
            line: Mutex::new(AskLine::new(serial)),
            writer,
            ready,
            greet_free: Notify::new(),
            greet: Mutex::new(Greet::Open),
            attached: AtomicUsize::new(0),
            born: Instant::now(),
            last_ns: AtomicU64::new(0),
        };
        (Arc::new(link), queue)
    }

    /// One EX_MSG of `slot`. Err = the generation's writer is gone (the generation ended).
    pub(super) fn send(&self, slot: u64, message: &[u8], ask: bool) -> Result<(), ()> {
        self.touch();
        let write = self.lock().send(slot, message, ask);
        match write {
            Write::Now(bytes) => self.writer.send(bytes).map_err(|_| ()),
            Write::Queued => Ok(()),
        }
    }

    /// CH_READY from the greeting session: published once.
    pub(super) fn ready(&self, tail: &[u8]) {
        self.ready.send_if_modified(|cur| {
            if cur.is_some() {
                return false;
            }
            *cur = Some(tail.into());
            true
        });
        *self.greeting() = Greet::Done;
        self.greet_free.notify_one();
    }

    /// The published CH_READY tail, if the greeting session has sent it.
    #[must_use]
    pub fn ready_tail(&self) -> Option<Box<[u8]>> {
        self.ready.borrow().clone()
    }

    /// Resolves once the greeting session handed the greet on (it readied or detached).
    pub async fn greet_released(&self) {
        self.greet_free.notified().await;
    }

    /// An attach in `slot` asks for the greeting: it greets when nobody does and no CH_READY was published.
    pub fn claim_greet(&self, slot: u64) -> Claim {
        let mut greet = self.greeting();
        match *greet {
            Greet::Done => Claim::Ready(self.ready_tail().unwrap_or_default()),
            Greet::Open => {
                *greet = Greet::Held(slot);
                Claim::Greeter
            }
            Greet::Held(_) => Claim::Wait,
        }
    }

    /// A waiter that stopped waiting (it greeted, found the greeting done, or the generation ended) wakes the next.
    pub fn pass_on(&self) {
        self.greet_free.notify_one();
    }

    /// `slot` detached: its asks leave the line, what that frees is written, a pending greet moves on.
    pub(super) fn detach(&self, slot: u64, greet: bool) {
        self.touch();
        self.attached.fetch_sub(1, Ordering::AcqRel);
        let freed = self.lock().detached(slot);
        for bytes in freed {
            let _ = self.writer.send(bytes);
        }
        if greet {
            let mut held = self.greeting();
            if *held == Greet::Held(slot) {
                *held = Greet::Open;
            }
            drop(held);
            self.greet_free.notify_one();
        }
    }

    /// An attachment was built on this generation.
    pub(super) fn attach(&self) {
        self.touch();
        self.attached.fetch_add(1, Ordering::AcqRel);
    }

    /// How many attachments hold this generation.
    #[must_use]
    pub fn attached(&self) -> usize {
        self.attached.load(Ordering::Acquire)
    }

    /// How long nothing is attached and nothing was sent; zero while anything is attached.
    #[must_use]
    pub fn idle(&self) -> Duration {
        if self.attached() > 0 {
            return Duration::ZERO;
        }
        self.born
            .elapsed()
            .saturating_sub(Duration::from_nanos(self.last_ns.load(Ordering::Acquire)))
    }

    /// The slot DX_OUTSTANDING delivers to: the head of the ask line.
    #[must_use]
    pub fn head(&self) -> Option<u64> {
        self.lock().head()
    }

    /// Writes `bytes` to the channel now, outside the ask line (the plane's DX_OUTSTANDING fallback).
    pub fn write(&self, bytes: Box<[u8]>) -> Result<(), ()> {
        self.touch();
        self.writer.send(bytes).map_err(|_| ())
    }

    /// DX_FINAL to `slot`: its oldest ask leaves the line and the next serial ask is written.
    pub fn finished(&self, slot: u64) {
        let freed = self.lock().finished(slot);
        for bytes in freed {
            let _ = self.writer.send(bytes);
        }
    }

    /// The generation ended: the slots whose asks were open (each gets P_ERROR).
    pub fn ended(&self) -> Vec<u64> {
        self.lock().ended()
    }

    fn touch(&self) {
        let ns = u64::try_from(self.born.elapsed().as_nanos()).unwrap_or(u64::MAX);
        self.last_ns.store(ns, Ordering::Release);
    }

    fn greeting(&self) -> MutexGuard<'_, Greet> {
        self.greet.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn lock(&self) -> MutexGuard<'_, AskLine> {
        self.line.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
