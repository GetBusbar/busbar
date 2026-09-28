// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE ANSWER, as a kind's validator sees it: the op, its authoritative outcome, and the op's
//! host-owned `in` and `out`. A kind's [`super::Kind::check`] reads its own structs through
//! [`Answer::input`] and [`Answer::out`], which refuse a struct larger than the host's buffer (a
//! foreign size is FAULT, never a read past the end), and builds every slice a plugin-reported
//! count names through `abi::mechanism::check::reported`, which checks the count against the cap
//! the host passed BEFORE any slice exists.

use std::any::Any;
use std::mem::size_of;

use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome};
use busbar_contract::abi::mechanism::check::{fault, Fault, Rule};

use super::{InFrame, OutFrame};

/// A kind's per-instance context: what its checks judge an answer against beyond the op's own
/// `in`/`out` (the plane's tail bounds), built once from the Statement at bind.
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

    /// The same answer, judged in the instance's `context` ([`super::Kind::context`]).
    #[must_use]
    pub fn with_context(self, context: Option<&'a Context>) -> Self {
        Self { context, ..self }
    }

    /// The instance's context as the kind's type `T`, if it has one.
    pub fn context<T: 'static>(&self) -> Option<&'a T> {
        self.context.and_then(|c| c.downcast_ref::<T>())
    }

    /// The op's `in` as the kind's struct `T`.
    ///
    /// # Errors
    /// [`Rule::Foreign`] when the host's `in` is smaller than `T` (the op was submitted with another
    /// struct than its kind names).
    pub fn input<T: InFrame>(&self) -> Result<&T, Fault> {
        if self.in_size < size_of::<T>() {
            return Err(fault(Rule::Foreign, "in"));
        }
        // SAFETY: `new`'s contract; `T` leads with an `InHead` and fits the host's buffer.
        Ok(unsafe { &*self.input.cast::<T>() })
    }

    /// The op's `out` as the kind's struct `T`.
    ///
    /// # Errors
    /// [`Rule::Foreign`] when the host's `out` is smaller than `T`.
    pub fn out<T: OutFrame>(&self) -> Result<&T, Fault> {
        if self.out_size < size_of::<T>() {
            return Err(fault(Rule::Foreign, "out"));
        }
        // SAFETY: as `input`.
        Ok(unsafe { &*self.out.cast::<T>() })
    }
}
