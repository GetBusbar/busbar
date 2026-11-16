// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The state one channel generation shares with its attachments (IF §12.19): the ask line, the writer
//! queue (frames in arrival order, drained by the carrier's writer task), the CH_READY tail and the greet
//! hand-off. The carrier driver builds one `Link` per generation and hands each attach an `Attachment`.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tokio::sync::{mpsc, watch, Notify};

use super::ask_line::{AskLine, Write};

pub struct Link {
    line: Mutex<AskLine>,
    writer: mpsc::UnboundedSender<Box<[u8]>>,
    ready: watch::Sender<Option<Box<[u8]>>>,
    greet_free: Notify,
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
        };
        (Arc::new(link), queue)
    }

    /// One EX_MSG of `slot`. Err = the generation's writer is gone (the generation ended).
    pub(super) fn send(&self, slot: u64, message: &[u8], ask: bool) -> Result<(), ()> {
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

    /// `slot` detached: its asks leave the line, what that frees is written, a pending greet moves on.
    pub(super) fn detach(&self, slot: u64, greet: bool) {
        let freed = self.lock().detached(slot);
        for bytes in freed {
            let _ = self.writer.send(bytes);
        }
        if greet {
            self.greet_free.notify_one();
        }
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

    fn lock(&self) -> MutexGuard<'_, AskLine> {
        self.line.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
