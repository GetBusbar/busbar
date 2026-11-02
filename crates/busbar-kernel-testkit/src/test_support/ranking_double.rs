// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::task::Poll;

use busbar_contract::abi::hook::{Tail, CLASS_GATE, PROMPT_NO, USER_NO};
use busbar_contract::abi::mechanism::door::{MarkWord, Statement, MARK_WORD_HOOK};
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::abi::sdk::exchange::Op;
use busbar_contract::abi::sdk::hook::{
    statement_with_tail, tail, Decoded, DecodedCandidate, Hook, HookOpen, Verdict,
};

pub const NAME: &str = "strategy-double";

pub const WORDS: [&str; 4] = ["cheapest", "fastest", "least_busy", "usage"];

pub const MAX_INFLIGHT: u32 = 64;

const TAIL: &Tail = &tail(CLASS_GATE, PROMPT_NO, USER_NO);

const fn word(w: &'static str) -> MarkWord {
    MarkWord {
        class: MARK_WORD_HOOK,
        _reserved: 0,
        word: abi_str(w),
    }
}

const MARKS: &[MarkWord] = &[
    word(WORDS[0]),
    word(WORDS[1]),
    word(WORDS[2]),
    word(WORDS[3]),
];

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

fn key(strategy: Strategy, c: &DecodedCandidate<'_>) -> Option<f64> {
    match strategy {
        Strategy::Cheapest => c.cost_per_mtok,

        Strategy::Fastest => c.latency_ms,

        Strategy::LeastBusy => Some(c.available_concurrency as f64),

        Strategy::Usage => c.rate_headroom,
        Strategy::Weighted => None,
    }
}

fn descending(strategy: Strategy) -> bool {
    matches!(strategy, Strategy::LeastBusy | Strategy::Usage)
}

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

#[must_use]
pub fn rank(strategy: Strategy, candidates: &[DecodedCandidate<'_>]) -> Verdict {
    if strategy == Strategy::Weighted {
        return Verdict::Abstain;
    }
    let mut keyed: Vec<(usize, Option<f64>)> = candidates
        .iter()
        .map(|c| (c.idx, key(strategy, c)))
        .collect();

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

fn strategy_of(settings: &str) -> Result<Strategy, String> {
    let v: serde_json::Value =
        serde_json::from_str(settings).map_err(|e| format!("the settings are not JSON: {e}"))?;

    let word = v
        .get("policy")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "settings.policy is required".to_string())?;

    Strategy::of(word).ok_or_else(|| format!("no strategy '{word}' (one of {WORDS:?})"))
}

busbar_contract::export_plugin! {
    hook: Open,
    statement: STATEMENT,
}

#[cfg(test)]
#[path = "tests/ranking_double_tests.rs"]
mod ranking_double_tests;

use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::host::hook::{DecideFrame, NotifyFrame};
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::hook_calls::{Answered, HookAxis, HookCalls, HookFacts, Pending, Probed};

pub const CALL_BUDGET: Duration = Duration::from_secs(1);

fn answers(module: &str) -> bool {
    module == NAME || WORDS.contains(&module)
}

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
