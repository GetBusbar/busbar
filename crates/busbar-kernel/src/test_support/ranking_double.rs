// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RANKING HOOK DOUBLE (R-FIX3): the door that stands in for the root's linked ranking row in a
//! test build. Linked only.
//!
//! ## Why a double, and why this one (ARCHITECT R-FIX3)
//!
//! A test build has no composition root, so the kernel's own tests that resolve a pool strategy
//! word through the hook axis (`preflight::builtin_ranking`) need a linked `kind: hook` row that
//! claims the words. A behaviour double the kernel's own tests need lives HERE, as a test-support
//! module of the crate under test, LINKED only — not a workspace crate, not an example plugin, and
//! not the shipped plugin taken under another name: the kernel names no plugin crate.
//!
//! What it copies is the shipped ranking door at the rev the root pins (`7e1285e2e3`):
//! the same four `MARK_WORD_HOOK` words, the same tail and `max_inflight`, the same `open` refusals
//! (in its own name), and the same ranking rules. Each copied literal and rule names its source
//! below. Its Statement name is its OWN, never the plugin's: the kernel spells no plugin name, not
//! even in a double (C1, `qa/c1-literals.toml`). That the copy holds is proven where the real door
//! is linked: the root's `the_kernel_ranking_double_states_what_the_linked_ranking_door_states`
//! renders both and runs the 1.5.5 parity cases through both. The plugin's own behaviour is proven
//! in its own repo.

use std::task::Poll;

use busbar_contract::abi::hook::{Tail, CLASS_GATE, PROMPT_NO, USER_NO};
use busbar_contract::abi::mechanism::door::{MarkWord, Statement, MARK_WORD_HOOK};
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::abi::sdk::exchange::Op;
use busbar_contract::abi::sdk::hook::{
    statement_with_tail, tail, Decoded, DecodedCandidate, Hook, HookOpen, Verdict,
};

/// The double's own Statement name, and the prefix of its refusals: not the plugin's (C1).
pub const NAME: &str = "strategy-double";

/// The strategy words, in order (`hook-ranking/src/lib.rs`, `WORDS`).
pub const WORDS: [&str; 4] = ["cheapest", "fastest", "least_busy", "usage"];

/// The most calls one instance holds in flight (`hook-ranking/src/door.rs`, `MAX_INFLIGHT`).
pub const MAX_INFLIGHT: u32 = 64;

/// The hook tail: a gate that asks for neither the prompt nor the user view
/// (`hook-ranking/src/door.rs`, `tail(CLASS_GATE, PROMPT_NO, USER_NO)`).
const TAIL: &Tail = &tail(CLASS_GATE, PROMPT_NO, USER_NO);

/// One `MARK_WORD_HOOK` mark.
const fn word(w: &'static str) -> MarkWord {
    MarkWord {
        class: MARK_WORD_HOOK,
        _reserved: 0,
        word: abi_str(w),
    }
}

/// One `MARK_WORD_HOOK` mark per word of [`WORDS`], in order (`hook-ranking/src/door.rs`, the
/// Statement's `mark_words`).
const MARKS: &[MarkWord] = &[
    word(WORDS[0]),
    word(WORDS[1]),
    word(WORDS[2]),
    word(WORDS[3]),
];

/// The Statement: [`NAME`], [`MAX_INFLIGHT`], [`TAIL`] and [`MARKS`].
const STATEMENT: Statement = statement_with_tail(
    Statement {
        mark_words: MARKS.as_ptr(),
        mark_words_len: MARKS.len(),
        ..statement(NAME, "1.6.0", MAX_INFLIGHT)
    },
    TAIL,
);

/// One ranking order (`hook-ranking/src/lib.rs`, the strategies [`rank`] answers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// Ascending `cost_per_mtok`.
    Cheapest,
    /// Ascending `latency_ms`.
    Fastest,
    /// Descending `available_concurrency`.
    LeastBusy,
    /// Descending `rate_headroom`.
    Usage,
    /// No order: abstains.
    Weighted,
}

impl Strategy {
    /// The strategy a word of [`WORDS`] spells; `None` for any other word.
    #[must_use]
    pub fn of(word: &str) -> Option<Self> {
        match word {
            "cheapest" => Some(Self::Cheapest),
            "fastest" => Some(Self::Fastest),
            "least_busy" => Some(Self::LeastBusy),
            "usage" => Some(Self::Usage),
            _ => None,
        }
    }
}

/// The sort key a strategy reads off a candidate, lower first; `None` = absent.
fn key(strategy: Strategy, c: &DecodedCandidate<'_>) -> Option<f64> {
    let k = match strategy {
        // `cheapest` = ascending `cost_per_mtok` (`hook-ranking/src/lib.rs`, `rank`).
        Strategy::Cheapest => c.cost_per_mtok,
        // `fastest` = ascending `latency_ms` (`hook-ranking/src/lib.rs`, `rank`).
        Strategy::Fastest => c.latency_ms,
        // `least_busy` = descending `available_concurrency` (`hook-ranking/src/lib.rs`, `rank`).
        Strategy::LeastBusy => Some(-(c.available_concurrency as f64)),
        // `usage` = descending `rate_headroom` (`hook-ranking/src/lib.rs`, `rank`).
        Strategy::Usage => c.rate_headroom.map(|h| -h),
        Strategy::Weighted => None,
    };
    // A non-finite key sorts as an absent one (`hook-ranking/src/lib.rs`, `rank`).
    k.filter(|k| k.is_finite())
}

/// RANK `candidates` by `strategy` (`hook-ranking/src/lib.rs`, `rank`): a present key before an
/// absent one, keys in the strategy's order, ties by `idx`; every key absent (or no candidate) is
/// [`Verdict::Abstain`], and `weighted` abstains.
#[must_use]
pub fn rank(strategy: Strategy, candidates: &[DecodedCandidate<'_>]) -> Verdict {
    if strategy == Strategy::Weighted {
        return Verdict::Abstain;
    }
    let mut keyed: Vec<(Option<f64>, usize)> = candidates
        .iter()
        .map(|c| (key(strategy, c), c.idx))
        .collect();
    // Every key absent abstains (`hook-ranking/src/lib.rs`, `rank`).
    if keyed.iter().all(|(k, _)| k.is_none()) {
        return Verdict::Abstain;
    }
    // Absent last; ties break by `idx` (`hook-ranking/src/lib.rs`, `rank`).
    keyed.sort_by(|(ka, ia), (kb, ib)| match (ka, kb) {
        (Some(a), Some(b)) => a.total_cmp(b).then(ia.cmp(ib)),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => ia.cmp(ib),
    });
    Verdict::Prefer(keyed.into_iter().map(|(_, idx)| idx).collect())
}

/// One opened instance: the strategy its `policy` setting names.
#[derive(Debug)]
pub struct Ranking(Strategy);

impl Hook for Ranking {
    fn decide(&self, view: &Decoded<'_>, _: &Op<'_>) -> Poll<Verdict> {
        Poll::Ready(rank(self.0, &view.candidates))
    }
}

/// How the double opens (`hook-ranking/src/door.rs`, `HookOpen::open`): settings must carry
/// `policy`, one of [`WORDS`]. Each refusal is the door's, prefixed with [`NAME`] where the door
/// prefixes its own.
#[derive(Debug)]
pub struct Open;

impl HookOpen for Open {
    fn open(settings: &str) -> Result<Box<dyn Hook>, String> {
        // `hook-ranking/src/door.rs`, `open`: "<door>: the settings are not JSON: {e}".
        let v: serde_json::Value = serde_json::from_str(settings)
            .map_err(|e| format!("{NAME}: the settings are not JSON: {e}"))?;
        // `hook-ranking/src/door.rs`, `open`: "<door>: settings.policy is required".
        let word = v
            .get("policy")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("{NAME}: settings.policy is required"))?;
        // `hook-ranking/src/door.rs`, `open`: "<door>: no strategy '{word}' (one of {WORDS:?})".
        let strategy = Strategy::of(word)
            .ok_or_else(|| format!("{NAME}: no strategy '{word}' (one of {WORDS:?})"))?;
        Ok(Box::new(Ranking(strategy)))
    }
}

busbar_contract::hook_door! {
    open: Open,
    statement: STATEMENT,
}
