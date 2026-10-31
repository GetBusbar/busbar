// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SECRET KIND: `abi/secret/`. `resolve` is checked by the contract's `secret::check_answer`
//! (`check_resolve` against the host buffer it was lent), and its short answer is the one
//! re-call's; `check` answers an
//! `OutHead` alone and states no rule beyond the mechanism's (its refusal text is judged where the
//! host renders it, `check_validate_refusal`).

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::check::Fault;
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::secret::{self, slot, CheckIn, ResolveIn, ResolveOut};

use crate::dispatch::{lifecycle_name, Answer, InFrame, Kind, OutFrame};

/// The secret kind.
#[derive(Debug, Clone, Copy)]
pub struct Secret;

// SAFETY: `#[repr(C)]` in `abi/secret/`, each leading with its head; host buffers only.
unsafe impl InFrame for ResolveIn {}
unsafe impl InFrame for CheckIn {}
unsafe impl OutFrame for ResolveOut {}

impl Kind for Secret {
    const CODE: KindCode = KindCode::Secret;
    type Ops = secret::Ops;
    const TIMEOUT: Outcome = Outcome::Failed;

    fn op_name(s: u32) -> &'static str {
        match s {
            slot::RESOLVE => "resolve",
            slot::CHECK => "check",
            _ => lifecycle_name(s),
        }
    }

    /// `check` is optional: a source that states none passes every reference it is handed.
    fn optional_slot(s: u32) -> bool {
        s == slot::CHECK
    }

    fn check(a: &Answer) -> Result<(), Fault> {
        let (input, in_size, out, out_size) = a.frames();
        // SAFETY: `Answer::new`'s contract: the op's live host-owned frames, unwritten while the
        // answer lives; `resolve`'s buffer is the host's own, of its stated capacity.
        unsafe { secret::check_answer(a.slot, a.outcome, input, in_size, out, out_size, &()) }
    }

    /// A `resolve` whose value does not fit the host's buffer: FAILED with `needed` (M-SB).
    fn short(a: &Answer) -> bool {
        a.outcome == Outcome::Failed
            && a.slot == slot::RESOLVE
            && a.out::<ResolveOut>().is_ok_and(|o| o.needed != 0)
    }
}
