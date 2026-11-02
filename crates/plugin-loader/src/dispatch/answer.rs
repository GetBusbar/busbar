// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::any::Any;
use std::mem::size_of;

use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome};
use busbar_contract::abi::mechanism::check::{fault, Fault, Rule};

use super::{InFrame, OutFrame};

pub type Context = dyn Any + Send + Sync;

/// One answer of op `slot`, validated after the mechanism's own checks passed.
#[derive(Clone, Copy)]
pub struct Answer<'a> {
    /// The op.
    pub slot: u32,
    /// The authoritative outcome (READY or FAILED when a validator runs).
    pub outcome: Outcome,
    input: *const InHead,
    in_size: usize,
    out: *const OutHead,
    out_size: usize,
    context: Option<&'a Context>,
}

impl std::fmt::Debug for Answer<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Answer")
            .field("slot", &self.slot)
            .field("outcome", &self.outcome)
            .finish_non_exhaustive()
    }
}

impl<'a> Answer<'a> {
    /// # Safety
    /// `input`/`out` are the op's live host-owned `in`/`out`, `in_size`/`out_size` bytes, not
    /// written by anyone while the answer lives.
    pub(crate) unsafe fn new(
        slot: u32,
        outcome: Outcome,
        input: *const InHead,
        in_size: usize,
        out: *const OutHead,
        out_size: usize,
    ) -> Self {
        Self {
            slot,
            outcome,
            input,
            in_size,
            out,
            out_size,
            context: None,
        }
    }

    #[must_use]
    pub fn with_context(self, context: Option<&'a Context>) -> Self {
        Self { context, ..self }
    }

    pub fn context<T: 'static>(&self) -> Option<&'a T> {
        self.context.and_then(|c| c.downcast_ref::<T>())
    }

    pub(crate) fn frames(&self) -> (*const InHead, usize, *const OutHead, usize) {
        (self.input, self.in_size, self.out, self.out_size)
    }

    pub fn input<T: InFrame>(&self) -> Result<&T, Fault> {
        if self.in_size < size_of::<T>() {
            return Err(fault(Rule::Foreign, "in"));
        }
        // SAFETY: `new`'s contract; `T` leads with an `InHead` and fits the host's buffer.
        Ok(unsafe { &*self.input.cast::<T>() })
    }

    pub fn out<T: OutFrame>(&self) -> Result<&T, Fault> {
        if self.out_size < size_of::<T>() {
            return Err(fault(Rule::Foreign, "out"));
        }
        // SAFETY: as `input`.
        Ok(unsafe { &*self.out.cast::<T>() })
    }
}
