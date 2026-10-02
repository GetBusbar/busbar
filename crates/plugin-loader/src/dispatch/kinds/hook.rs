// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOOK KIND: `abi/hook/`. Every kind op is checked by its `check_<op>`. `decide` and
//! `transform` write into host buffers [`DecideIn`] names, so their checks take the caps from that
//! `in`, and they are the two ops with a short-buffer path (a `*_needed` above its cap);
//! `configure` is checked against the version [`ConfigureIn`] pushed. No hook check reads a slice
//! a plugin-reported count names, so none is built here. The Statement's hook facts (its tail's
//! class and grants, its `MARK_WORD_HOOK` words) are read once at bind into [`HookFacts`].

use busbar_contract::abi::hook::{
    self, slot, validate, ConfigureIn, ConfigureOut, DecideIn, DecideOut, DescribeOut, NotifyIn,
    ServeIn, ServeOut, StatusOut, Tail, TransformOut, CLASS_GATE, CLASS_TAP, PROMPT_NO, PROMPT_RW,
    USER_NO, USER_RO,
};
use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome};
use busbar_contract::abi::mechanism::check::Fault;
use busbar_contract::abi::mechanism::door::{MarkWord, Statement, MARK_WORD_HOOK};
use busbar_contract::abi::mechanism::KindCode;
pub use busbar_contract::hook_calls::HookFacts;

use crate::dispatch::{lifecycle_name, Answer, Context, InFrame, Kind, OutFrame};

/// A `'static` Statement string, copied; `None` when malformed.
fn owned(s: busbar_contract::abi::mechanism::call::AbiStr) -> Option<String> {
    crate::dispatch::plugin::str_bytes(s).map(|b| String::from_utf8_lossy(b).into_owned())
}

/// WHAT A HOOK STATES ABOUT ITSELF, read once at bind: its name, its tail's class and grants (a
/// Statement with no hook tail states the defaults: a gate that asks for neither view) and the
/// hook words its `MARK_WORD_HOOK` marks claim. Read back through
/// [`crate::dispatch::Plugin::context`].
fn facts(st: &Statement) -> Result<HookFacts, String> {
    let name = owned(st.name).ok_or("a hook's name is over-long")?;
    let mut facts = HookFacts {
        name,
        class: CLASS_GATE,
        prompt: PROMPT_NO,
        user: USER_NO,
        infallible: false,
        words: Vec::new(),
    };
    let p = st.kind_tail;
    if !p.is_null() {
        // SAFETY: a non-NULL kind tail is `'static` plugin data leading with a `KindTailHead`; the
        // whole tail is read only once its size covers this host's `Tail`.
        let size = unsafe { (*p).size };
        if (size as usize) < std::mem::size_of::<Tail>() {
            return Err(format!(
                "the hook tail is {size} bytes, smaller than this host's"
            ));
        }
        // SAFETY: as above.
        let t = unsafe { p.cast::<Tail>().read_unaligned() };
        if t.kind_class != CLASS_GATE && t.kind_class != CLASS_TAP {
            return Err(format!("the hook tail states class {}", t.kind_class));
        }
        if t.prompt_access > PROMPT_RW {
            return Err(format!(
                "the hook tail states prompt access {}",
                t.prompt_access
            ));
        }
        if t.user_access > USER_RO {
            return Err(format!(
                "the hook tail states user access {}",
                t.user_access
            ));
        }
        facts.class = t.kind_class;
        facts.prompt = t.prompt_access;
        facts.user = t.user_access;
        facts.infallible = t.infallible != 0;
    }
    let marks: &[MarkWord] = if st.mark_words_len == 0 || st.mark_words.is_null() {
        &[]
    } else {
        // SAFETY: the loader's Statement check bounded `mark_words` and refused it behind NULL; it
        // is `'static` plugin data.
        unsafe { std::slice::from_raw_parts(st.mark_words, st.mark_words_len) }
    };
    for m in marks.iter().filter(|m| m.class == MARK_WORD_HOOK) {
        facts
            .words
            .push(owned(m.word).ok_or("a hook word is over-long")?);
    }
    Ok(facts)
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

impl Kind for Hook {
    const CODE: KindCode = KindCode::Hook;
    type Ops = hook::Ops;
    const TIMEOUT: Outcome = Outcome::Failed;

    fn context(st: &Statement) -> Result<Option<Box<Context>>, String> {
        Ok(Some(Box::new(facts(st)?)))
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
