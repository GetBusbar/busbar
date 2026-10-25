// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What one kind declaration (`busbar_abi_macros::kind!`) states about its ops, for the host's one
//! call path: names, contracts, the answer check and the short-buffer rule of each kind op.

use std::mem::size_of;

use super::call::{InHead, OutHead, Outcome};
use super::check::{fault, Fault, OpContract, Rule};
use crate::abi::sdk::door::{AbiIn, AbiOut, KindOps};

/// The `in` and `out` of one crossing, as the host laid them out.
#[derive(Debug, Clone, Copy)]
pub struct Frames {
    /// The `in`, leading with its head.
    pub input: *const InHead,
    /// Its size in bytes.
    pub in_size: usize,
    /// The `out`, leading with its head.
    pub out: *const OutHead,
    /// Its size in bytes.
    pub out_size: usize,
}

impl Frames {
    /// The frames read as `I`/`O`: FAULT (`Rule::Foreign`) when either is smaller than the struct.
    ///
    /// # Safety
    /// `input`/`out` point at live frames of `in_size`/`out_size` bytes for `'a`.
    pub unsafe fn get<'a, I: AbiIn, O: AbiOut>(self) -> Result<(&'a I, &'a O), Fault> {
        if self.in_size < size_of::<I>() {
            return Err(fault(Rule::Foreign, "in"));
        }
        if self.out_size < size_of::<O>() {
            return Err(fault(Rule::Foreign, "out"));
        }
        // SAFETY: sizes checked above; liveness is the caller's.
        Ok(unsafe { (&*self.input.cast::<I>(), &*self.out.cast::<O>()) })
    }

    /// The `out` alone, read as `O` (an op whose check never reads its `in`).
    ///
    /// # Errors
    /// FAULT (`Rule::Foreign`) when the `out` is smaller than `O`.
    ///
    /// # Safety
    /// As [`Frames::get`].
    pub unsafe fn out<'a, O: AbiOut>(self) -> Result<&'a O, Fault> {
        if self.out_size < size_of::<O>() {
            return Err(fault(Rule::Foreign, "out"));
        }
        // SAFETY: size checked above; liveness is the caller's.
        Ok(unsafe { &*self.out.cast::<O>() })
    }
}

/// One kind's ops as its declaration states them. Implemented only by `kind!`.
///
/// # Safety
/// `check` and `short` read the frames only as the structs the declaration states for the slot.
pub unsafe trait KindDecl: KindOps {
    /// Each kind op's name, in table order.
    const NAMES: &'static [&'static str];
    /// Each kind op's contract, in table order.
    const OPS: &'static [OpContract];
    /// The kind slots no host code calls.
    const UNUSED: &'static [u32];

    /// The kind's own check of an answer to kind slot `slot` (beyond the mechanism's).
    ///
    /// # Errors
    /// The rule the answer breaks.
    ///
    /// # Safety
    /// `frames` are the live frames of a crossing of `slot`.
    unsafe fn check(slot: u32, outcome: Outcome, frames: Frames) -> Result<(), Fault>;

    /// A FAILED answer to `slot` that names a larger host buffer (the short-buffer rule).
    ///
    /// # Safety
    /// As [`KindDecl::check`].
    unsafe fn short(slot: u32, outcome: Outcome, frames: Frames) -> bool;

    /// Kind slot `slot`'s name, or `None` for a lifecycle or unknown slot.
    #[must_use]
    fn op_name(slot: u32) -> Option<&'static str> {
        let k = slot.checked_sub(super::lifecycle::LIFECYCLE_SLOTS)?;
        Self::NAMES.get(k as usize).copied()
    }
}
