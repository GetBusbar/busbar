// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::hook::{
    self, slot, validate, ConfigureIn, ConfigureOut, DecideIn, DecideOut, DescribeOut, NotifyIn,
    ServeIn, ServeOut, StatusOut, Tail, TransformOut,
};
use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome};
use busbar_contract::abi::mechanism::check::Fault;
use busbar_contract::abi::mechanism::door::{MarkWord, Statement};
#[cfg(test)]
use busbar_contract::abi::mechanism::route::Route;
use busbar_contract::abi::mechanism::KindCode;
pub use busbar_contract::hook_calls::HookFacts;

use crate::dispatch::{lifecycle_name, Answer, Context, InFrame, Kind, OutFrame};
// The hook's Statement read (once per load and bind) lives in `off_path::kinds_hook`.
#[cfg(test)]
use crate::off_path::kinds_hook::owned;
use crate::off_path::kinds_hook::read;
pub(crate) use crate::off_path::kinds_hook::route;

pub const NO_TAIL: &str = "a hook Statement states no hook tail: a hook states its class and grants (abi::sdk::hook::tail)";

pub const SIGNALS_REFUSED: &str = "the hook tail states requested_signals: the signals a hook is \
     lent are the operator's `hooks:` configuration, never its tail; a hook states none";

const HOOK_TAIL_FROZEN: usize = std::mem::size_of::<Tail>();

// THE PLUGIN MEMORY THE HOOK'S STATEMENT READ (`off_path::kinds_hook`, once per load and bind)
// READS, read here beside the kind's other unsafe code.

/// The hook tail `st` states (THE KIND TAIL GROWTH RULE, `dispatch::plugin::kind_tail`).
pub(crate) fn hook_tail(st: &Statement) -> Result<Tail, String> {
    // SAFETY: `Tail` is a `#[repr(C)]` kind tail of integers and pointers (all-zero valid: NULL
    // lists of length 0); a non-NULL kind tail is `'static` plugin data of its stated size.
    unsafe { crate::dispatch::plugin::kind_tail(st, "a hook", HOOK_TAIL_FROZEN) }
}

/// The bound tail's route list, or `None` when [`lent`] refuses it (misaligned or over the byte
/// bound). The caller refuses a NULL list with a count and a count over the route bound first.
///
/// [`lent`]: crate::dispatch::validate::lent
pub(crate) fn tail_routes(t: &Tail) -> Option<&'static [hook::Route]> {
    // SAFETY: a nonempty route list is static plugin data. `lent` checks alignment and the byte
    // bound before forming a slice; the route count and NULL checks come first (the caller's).
    unsafe { crate::dispatch::validate::lent(t.routes, t.routes_len) }
}

/// The bound Statement's mark words.
pub(crate) fn mark_words(st: &Statement) -> &'static [MarkWord] {
    if st.mark_words_len == 0 || st.mark_words.is_null() {
        &[]
    } else {
        // SAFETY: the loader's Statement check bounded `mark_words` and refused it behind NULL; it
        // is `'static` plugin data.
        unsafe { std::slice::from_raw_parts(st.mark_words, st.mark_words_len) }
    }
}

#[cfg(test)]
pub(crate) fn facts(st: &Statement) -> Result<HookFacts, String> {
    read(st).map(|(facts, _)| facts)
}

#[cfg(test)]
pub(crate) fn routes(st: &Statement) -> Result<Vec<Route>, String> {
    read(st).map(|(_, routes)| routes)
}

/// The hook kind.
#[derive(Debug, Clone, Copy)]
pub struct Hook;

// SAFETY: `#[repr(C)]` in `abi/hook/`, each leading with its head; host buffers only.
unsafe impl InFrame for DecideIn {}
unsafe impl InFrame for NotifyIn {}
unsafe impl InFrame for ConfigureIn {}
unsafe impl InFrame for ServeIn {}
unsafe impl OutFrame for DecideOut {}
unsafe impl OutFrame for TransformOut {}
unsafe impl OutFrame for ConfigureOut {}
unsafe impl OutFrame for StatusOut {}
unsafe impl OutFrame for DescribeOut {}
unsafe impl OutFrame for ServeOut {}

impl crate::dispatch::kind_seal::Validated for Hook {}

impl Kind for Hook {
    const CODE: KindCode = KindCode::Hook;
    type Ops = hook::Ops;
    const TIMEOUT: Outcome = Outcome::Failed;

    fn context(st: &Statement) -> Result<Option<Box<Context>>, String> {
        read(st)?;
        Ok(None)
    }

    fn optional_by_statement(s: u32, st: &Statement) -> bool {
        s == slot::SERVE && read(st).is_ok_and(|(_, routes)| routes.is_empty())
    }

    fn op_name(s: u32) -> &'static str {
        match s {
            slot::DECIDE => "decide",
            slot::TRANSFORM => "transform",
            slot::NOTIFY => "notify",
            slot::CONFIGURE => "configure",
            slot::STATUS => "status",
            slot::DESCRIBE => "describe",
            slot::SERVE => "serve",
            _ => lifecycle_name(s),
        }
    }

    fn check(a: &Answer) -> Result<(), Fault> {
        match a.slot {
            slot::DECIDE => {
                let i = a.input::<DecideIn>()?;
                validate::check_decide(
                    a.out::<DecideOut>()?,
                    i.reject_message_cap,
                    i.restrict_tags_cap,
                    i.order_cap,
                )
            }
            slot::TRANSFORM => {
                let i = a.input::<DecideIn>()?;
                validate::check_transform(
                    a.out::<TransformOut>()?,
                    i.reject_message_cap,
                    i.rewrite_cap,
                )
            }
            slot::NOTIFY => {
                a.input::<NotifyIn>()?;
                validate::check_notify(a.out::<OutHead>()?)
            }
            slot::CONFIGURE => validate::check_configure(
                a.out::<ConfigureOut>()?,
                a.input::<ConfigureIn>()?.version,
            ),
            slot::STATUS => {
                a.input::<InHead>()?;
                validate::check_status(a.out::<StatusOut>()?)
            }
            slot::DESCRIBE => {
                a.input::<InHead>()?;
                validate::check_describe(a.out::<DescribeOut>()?)
            }
            slot::SERVE => {
                a.input::<ServeIn>()?;
                validate::check_serve(a.out::<ServeOut>()?)
            }
            _ => Ok(()),
        }
    }

    fn short(a: &Answer) -> bool {
        if a.outcome != Outcome::Failed {
            return false;
        }
        match a.slot {
            slot::DECIDE => a.out::<DecideOut>().is_ok_and(|o| {
                o.reject_message_needed != 0 || o.restrict_tags_needed != 0 || o.order_needed != 0
            }),
            slot::TRANSFORM => a
                .out::<TransformOut>()
                .is_ok_and(|o| o.reject_message_needed != 0 || o.rewrite_needed != 0),
            _ => false,
        }
    }
}

#[cfg(test)]
mod owned_tests {
    use super::*;

    #[test]
    fn a_declared_text_that_is_not_utf8_is_refused_not_repaired() {
        let bad: &'static [u8] = b"/\xff";
        let s = busbar_contract::abi::mechanism::call::AbiStr {
            ptr: bad.as_ptr(),
            len: bad.len(),
        };
        assert_eq!(owned(s), None, "a lossy U+FFFD text must not load");
    }
}
