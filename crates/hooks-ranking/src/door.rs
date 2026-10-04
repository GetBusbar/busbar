// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR: the ranking hook on the hook kind's memory ABI (`hook_door!`), on the SDK's safe
//! surface. No `unsafe` here.
//!
//! * `open` reads the strategy from the settings document, `{"policy": "<word>"}`, one of
//!   [`crate::WORDS`]; anything else refuses in words.
//! * `decide` ranks the view's candidates ([`crate::rank`]). It reads no prompt and no caller (the
//!   Statement's tail asks for none) and never pends: no need is declared.
//! * `transform` / `notify` / `configure` / `status` / `describe` are the SDK's defaults.
//!
//! The Statement claims the four strategy words as hook word marks.

use std::task::Poll;

use busbar_contract::abi::hook::{Tail, CLASS_GATE, PROMPT_NO, USER_NO};
use busbar_contract::abi::mechanism::door::{MarkWord, Statement, MARK_WORD_HOOK};
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::abi::sdk::exchange::Op;
use busbar_contract::abi::sdk::hook::{
    statement_with_tail, tail, Decoded, Hook, HookOpen, Verdict,
};

use crate::{rank, NAME, WORDS};

/// How many ops one instance holds in flight; the host clamps. Ranking is CPU-only.
pub const MAX_INFLIGHT: u32 = 64;

/// An order gate that reads neither the prompt nor the caller.
const TAIL: &Tail = &tail(CLASS_GATE, PROMPT_NO, USER_NO);

const fn word(w: &'static str) -> MarkWord {
    MarkWord {
        class: MARK_WORD_HOOK,
        _reserved: 0,
        word: abi_str(w),
    }
}

/// The hook words, one mark each.
const MARKS: &[MarkWord] = &[
    word(WORDS[0]),
    word(WORDS[1]),
    word(WORDS[2]),
    word(WORDS[3]),
];

/// THE STATEMENT: name, version, the hook tail and the four claimed words.
pub const STATEMENT: Statement = Statement {
    mark_words: MARKS.as_ptr(),
    mark_words_len: MARKS.len(),
    ..statement_with_tail(
        statement(NAME, env!("CARGO_PKG_VERSION"), MAX_INFLIGHT),
        TAIL,
    )
};

/// One opened ranking: the strategy its settings named.
#[derive(Debug)]
pub struct Ranking(&'static str);

impl Hook for Ranking {
    fn decide(&self, view: &Decoded<'_>, _: &Op<'_>) -> Poll<Verdict> {
        Poll::Ready(rank(self.0, &view.candidates).unwrap_or(Verdict::Abstain))
    }
}

/// Opens a [`Ranking`] from `{"policy": "<word>"}`.
#[derive(Debug)]
pub struct Open;

impl HookOpen for Open {
    fn open(settings: &str) -> Result<Box<dyn Hook>, String> {
        let doc: serde_json::Value = serde_json::from_str(settings)
            .map_err(|e| format!("hook-ranking: the settings are not JSON: {e}"))?;
        let word = doc
            .get("policy")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "hook-ranking: settings.policy is required".to_string())?;
        let word = WORDS
            .iter()
            .find(|w| **w == word)
            .ok_or_else(|| format!("hook-ranking: no strategy '{word}' (one of {WORDS:?})"))?;
        Ok(Box::new(Ranking(word)))
    }
}

busbar_contract::hook_door! {
    open: Open,
    statement: STATEMENT,
}
