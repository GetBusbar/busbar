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
//! What it copies is the shipped ranking door (the ranking hook row the root's `Cargo.toml`
//! pins): the same four `MARK_WORD_HOOK` words, the same tail and `max_inflight`, the same `open`
//! refusals (bare: the host names the plugin in front of them). Its ranking rules are 1.5.5's (hook behaviour is frozen at 1.5.5):
//! each rule cites the v1.5.5 line it copies; its `NaN` rule is the door's (the coordinator's
//! ruling of 2026-10-18, a total order: a `NaN` sorts after every number); and each literal names
//! the door item it copies. Its Statement name is its OWN, never the plugin's: the kernel spells no
//! plugin name, not even in a double (C1, `qa/c1-literals.toml`). That the copy holds is proven where the real door
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

/// The double's own Statement name: not the plugin's (C1).
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

/// The sort key a strategy reads off a candidate; `None` = absent. Every present key is kept, an
/// infinity included: 1.5.5 filtered nothing (the v1.5.5 ranking natives' `lib.rs:64-106`; hook
/// behaviour is frozen at 1.5.5).
fn key(strategy: Strategy, c: &DecodedCandidate<'_>) -> Option<f64> {
    match strategy {
        // `cheapest` = ascending `cost_per_mtok` (the v1.5.5 ranking natives' `lib.rs:123`).
        Strategy::Cheapest => c.cost_per_mtok,
        // `fastest` = ascending `latency_ms` (the v1.5.5 ranking natives' `lib.rs:143`).
        Strategy::Fastest => c.latency_ms,
        // `least_busy` = descending `available_concurrency` (the v1.5.5 ranking natives'
        // `lib.rs:164`).
        // A `usize` count is exact in an `f64` up to 2^53, so the order is the integer order.
        Strategy::LeastBusy => Some(c.available_concurrency as f64),
        // `usage` = descending `rate_headroom` (the v1.5.5 ranking natives' `lib.rs:190`).
        Strategy::Usage => c.rate_headroom,
        Strategy::Weighted => None,
    }
}

/// Whether a strategy prefers the LARGEST key (`least_busy`, `usage`): 1.5.5's
/// `rank_descending_by` (the v1.5.5 ranking natives' `lib.rs:88-106`).
fn descending(strategy: Strategy) -> bool {
    matches!(strategy, Strategy::LeastBusy | Strategy::Usage)
}

/// THE KEY ORDER the shipped ranking door states (its `key_order`, the coordinator's ruling of
/// 2026-10-18): present keys by `partial_cmp`, so `-0.0` ties `+0.0` and an
/// infinity is ordered, exactly as 1.5.5 compared them (the v1.5.5 ranking natives' `lib.rs:77-80`,
/// `:99-102`); a `NaN` sorts after every number, as an absent key does, and ties every other `NaN`
/// and every absent key, so the comparator is a total order and no sort can panic on it; then the
/// index.
fn key_order(
    (ia, ka): &(usize, Option<f64>),
    (ib, kb): &(usize, Option<f64>),
    desc: bool,
) -> std::cmp::Ordering {
    use std::cmp::Ordering::{Equal, Greater, Less};
    let orderable = |k: &Option<f64>| k.filter(|v| !v.is_nan());
    let by_key = match (orderable(ka), orderable(kb)) {
        (Some(a), Some(b)) => {
            let (x, y) = if desc { (b, a) } else { (a, b) };
            x.partial_cmp(&y).unwrap_or(Equal)
        }
        (Some(_), None) => Less,
        (None, Some(_)) => Greater,
        (None, None) => Equal,
    };
    by_key.then(ia.cmp(ib))
}

/// RANK `candidates` by `strategy` as the shipped ranking door ranks them (1.5.5's
/// `rank_ascending_by` / `rank_descending_by`, the v1.5.5 ranking natives' `lib.rs:64-106`,
/// under [`key_order`]): present keys in the strategy's order, then every absent or `NaN` key, ties
/// by `idx`. Only a signal ABSENT on every candidate (or no candidate) is [`Verdict::Abstain`]
/// (`:70-72`): an all-`NaN` pool states the signal and ranks by index. `weighted` abstains.
#[must_use]
pub fn rank(strategy: Strategy, candidates: &[DecodedCandidate<'_>]) -> Verdict {
    if strategy == Strategy::Weighted {
        return Verdict::Abstain;
    }
    let mut keyed: Vec<(usize, Option<f64>)> = candidates
        .iter()
        .map(|c| (c.idx, key(strategy, c)))
        .collect();
    // Every key absent abstains (the v1.5.5 ranking natives' `lib.rs:70-72`).
    if keyed.iter().all(|(_, k)| k.is_none()) {
        return Verdict::Abstain;
    }
    let desc = descending(strategy);
    keyed.sort_by(|a, b| key_order(a, b, desc));
    Verdict::Prefer(keyed.into_iter().map(|(idx, _)| idx).collect())
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
/// `policy`, one of [`WORDS`]. Each refusal is the door's bare words: the host names the plugin in
/// front of them (`plugin '<name>' open failed: ...`), so neither spells its own name.
#[derive(Debug)]
pub struct Open;

impl HookOpen for Open {
    fn open(settings: &str) -> Result<Box<dyn Hook>, String> {
        Ok(Box::new(Ranking(strategy_of(settings)?)))
    }
}

/// The strategy `settings` names, parsed as the door parses it.
fn strategy_of(settings: &str) -> Result<Strategy, String> {
    // `hook-ranking/src/door.rs`, `open`: "the settings are not JSON: {e}".
    let v: serde_json::Value =
        serde_json::from_str(settings).map_err(|e| format!("the settings are not JSON: {e}"))?;
    // `hook-ranking/src/door.rs`, `open`: "settings.policy is required".
    let word = v
        .get("policy")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "settings.policy is required".to_string())?;
    // `hook-ranking/src/door.rs`, `open`: "no strategy '{word}' (one of {WORDS:?})".
    Strategy::of(word).ok_or_else(|| format!("no strategy '{word}' (one of {WORDS:?})"))
}

busbar_contract::export_plugin! {
    hook: Open,
    statement: STATEMENT,
}

#[cfg(test)]
#[path = "tests/ranking_double_tests.rs"]
mod ranking_double_tests;

// ── THE DOUBLE ON THE HOOK AXIS, IN PROCESS ──────────────────────────────────────────────────────
//
// A test build has no composition root and so no loader to cross the door above (THE DESIGN
// l.322: the kernel never names the loader). The kernel's hook port — the contract's [`HookAxis`] /
// [`HookCalls`] — answers the double's words here, in process: the same strategies, ranked by
// [`rank`] itself over the frame's view as the SDK decodes it for the door
// ([`DecideFrame::decoded`], every key as the `in` carries it), answered through the frame exactly
// as an in-process hook answers ([`DecideFrame::answer_decide`]). That the door states and ranks the
// same is the root's proof, which crosses it (`the_kernel_ranking_double_states_what_the_linked_
// ranking_door_states`).

use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::host::hook::{DecideFrame, NotifyFrame};
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::hook_calls::{Answered, HookAxis, HookCalls, HookFacts, Pending, Probed};

/// The call budget the double's calls are bounded by: the root's dispatcher's `Call` class budget
/// at its defaults (`busbar-plugin-loader`, `dispatch::worker::Budgets::default`).
pub const CALL_BUDGET: Duration = Duration::from_secs(1);

/// Whether `module` names the double on the hook axis: its Statement name or one of its words, in
/// every test build (THE DESIGN l.1443: the kernel has no hook feature to switch it on).
fn answers(module: &str) -> bool {
    module == NAME || WORDS.contains(&module)
}

/// One opened instance, on the hook port.
struct RankingCalls(Strategy);

impl HookCalls for RankingCalls {
    fn name(&self) -> &str {
        NAME
    }

    fn decide(
        &self,
        frame: Arc<DecideFrame>,
        budget: Duration,
    ) -> Pending<Answered<busbar_contract::abi::hook::DecideOut>> {
        let strategy = self.0;
        Box::pin(super::hook_double::verdict(
            frame,
            budget,
            move |f| f.decoded(|view| rank(strategy, &view.candidates)),
            |f, v| {
                let (outcome, out) = f.answer_decide(v);
                (outcome, out, None, outcome == Outcome::Failed)
            },
            |f, out| f.regrown_decide(out),
        ))
    }

    fn transform(
        &self,
        frame: Arc<DecideFrame>,
        budget: Duration,
    ) -> Pending<Answered<busbar_contract::abi::hook::TransformOut>> {
        // The SDK's default `transform`: no change.
        Box::pin(super::hook_double::verdict(
            frame,
            budget,
            |_| busbar_contract::abi::sdk::hook::RewriteVerdict::Abstain,
            |f, v| {
                let (outcome, out) = f.answer_transform(v);
                (outcome, out, None, outcome == Outcome::Failed)
            },
            |f, out| f.regrown_transform(out),
        ))
    }

    fn notify(&self, _frame: Arc<NotifyFrame>, _budget: Duration) -> Pending<()> {
        Box::pin(async {})
    }

    fn configure(
        &self,
        _name: &str,
        _settings: &str,
        _version: u64,
        _budget: Duration,
    ) -> Pending<Result<(), String>> {
        Box::pin(async { Ok(()) })
    }

    fn status(&self, _budget: Duration) -> Pending<Option<Vec<u8>>> {
        Box::pin(async { None })
    }

    fn describe(&self, _budget: Duration) -> Pending<Option<Vec<u8>>> {
        Box::pin(async { None })
    }
}

/// THE STAND-IN HOOK AXIS's linked half: the double's words, opened in process.
#[derive(Debug)]
pub struct RankingAxis;

impl RankingAxis {
    /// What the double states: a gate asking for neither view, claiming [`WORDS`].
    fn facts() -> HookFacts {
        HookFacts {
            name: NAME.to_string(),
            class: CLASS_GATE,
            prompt: PROMPT_NO,
            user: USER_NO,
            infallible: false,
            words: WORDS.iter().map(|w| (*w).to_string()).collect(),
        }
    }
}

impl HookAxis for RankingAxis {
    fn probe(&self, module: &str, _instance: &str, settings: &serde_json::Value) -> Option<Probed> {
        if !answers(module) {
            return None;
        }
        let text = serde_json::to_string(settings).unwrap_or_default();
        let problems = match <Open as HookOpen>::open(&text) {
            Ok(_) => Vec::new(),
            Err(e) => vec![e],
        };
        Some((Some(Self::facts()), problems))
    }

    fn open(
        &self,
        module: &str,
        _label: &str,
        settings: &serde_json::Value,
        _budget: Duration,
    ) -> Result<Arc<dyn HookCalls>, String> {
        if !answers(module) {
            return Err(format!("no `kind: hook` plugin answers to '{module}'"));
        }
        let text = serde_json::to_string(settings).map_err(|e| e.to_string())?;
        Ok(Arc::new(RankingCalls(strategy_of(&text)?)))
    }

    fn linked(&self, module: &str) -> bool {
        answers(module)
    }

    fn call_budget(&self) -> Duration {
        CALL_BUDGET
    }

    fn first_party(&self, module: &str) -> bool {
        answers(module)
    }
}
