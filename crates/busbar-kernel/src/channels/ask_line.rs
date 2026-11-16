// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The ask line of one channel generation (IF §12.19 round 18, §8.6 DemuxRec, MSG_ASK).
//!
//! An attachment enters the line (in write order) with each EX_MSG carrying MSG_ASK and leaves on the
//! DEMUX with DX_FINAL to its slot, its detach, or the generation's end. Under CH_SERIAL only the line's
//! head is written and the rest wait; an EX_MSG without MSG_ASK is written at once. DX_OUTSTANDING
//! delivers to the line's head, leaving its ask open.

use std::collections::VecDeque;

/// One queued ask: the slot that sent it and its message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ask {
    pub slot: u64,
    pub message: Box<[u8]>,
}

/// What core does with one EX_MSG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Write {
    /// Write it to the channel now.
    Now(Box<[u8]>),
    /// Under CH_SERIAL another ask is outstanding: it waits its turn.
    Queued,
}

#[derive(Debug, Clone, Default)]
pub struct AskLine {
    serial: bool,
    /// Every open ask, in write order; under CH_SERIAL only the head has been written.
    line: VecDeque<Ask>,
}

impl AskLine {
    #[must_use]
    pub fn new(serial: bool) -> Self {
        Self {
            serial,
            line: VecDeque::new(),
        }
    }

    /// One EX_MSG of `slot`; `ask` = it carried MSG_ASK.
    pub fn send(&mut self, slot: u64, message: &[u8], ask: bool) -> Write {
        let _ = (slot, message, ask, self.serial, &mut self.line);
        todo!()
    }

    /// The slot DX_OUTSTANDING delivers to (the line's head); `None` on an empty line.
    #[must_use]
    pub fn head(&self) -> Option<u64> {
        todo!()
    }

    /// DX_FINAL to `slot`: its oldest ask leaves the line. Returns the messages that may now be written
    /// (under CH_SERIAL the next head's, if it was waiting).
    pub fn finished(&mut self, slot: u64) -> Vec<Box<[u8]>> {
        let _ = slot;
        todo!()
    }

    /// `slot` detached: every ask of it leaves the line. Returns what may now be written.
    pub fn detached(&mut self, slot: u64) -> Vec<Box<[u8]>> {
        let _ = slot;
        todo!()
    }

    /// The generation ended: the slots whose asks were open (each gets P_ERROR), in line order, once each.
    pub fn ended(&mut self) -> Vec<u64> {
        todo!()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.line.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.line.is_empty()
    }
}
