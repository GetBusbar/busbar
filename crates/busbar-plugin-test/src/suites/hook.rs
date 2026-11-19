// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The hook suite body (IF §14). Owned by the hook agent: this is the only file it edits (plus the `tests/`
//! cases that call it). Drive the plugin with [`super::harness::Harness`].
//!
//! The cases, in order:
//! - admit and describe: the stamp names the hook kind, exactly one of `on` / `on_io` is declared, D_POINTS names
//!   only the three decision points and every D_WORD word is well formed, at most 8, and needs POINT_ROUTE;
//! - open: a malformed config is refused (never a panic), a good one opens, two instances of one image are
//!   independent, and `points` / `facts` agree with describe;
//! - on: for every served point, over request-stage views, a candidate view (presence bits clear and set, tier,
//!   tags, priced and unpriced cost terms, budgets), the S_ROUTING_POLICY word of every D_WORD, every stage tap
//!   (S_STAGE, S_STAGE_MODEL) and the prompt/body/identity parts the hook asked for (FB_*): the answer is a
//!   legal verdict (C-REFUSAL-MAP: a failure is a Refused or Failed, never a fault; reject status in range;
//!   ORDER indices in range and distinct; RESTRICT and REWRITE only with their verb);
//! - C-COST-TERMS / C_HAS_*: a view with an unpriced class and a candidate with no latency sample never makes the
//!   hook fault, and a `fastest` hook never ranks the no-sample member first.

use busbar_plugin_abi::hook::{
    self, C_HAS_BUDGET, C_HAS_CONTEXT_MAX, C_HAS_COST, C_HAS_LATENCY, C_HAS_RATE_HEADROOM,
    FB_WANTS_PROMPT, M_ON, M_ON_IO, POINT_NOTIFY, POINT_REWRITE, POINT_ROUTE, STAGE_CANDIDATE,
    STAGE_RESPONSE, STAGE_ROUTING, S_ATTEMPT, S_INGRESS_PROTOCOL, S_KEY_ID, S_KEY_NAME, S_POOL,
    S_REMAINING_CANDIDATES, S_ROUTING_POLICY, S_STAGE, S_STAGE_MODEL, S_USER_SUBJECT, VERB_ABSTAIN,
    VERB_PREFER, VERB_PRIORITIZE, VERB_REJECT, VERB_RESTRICT, VERB_REWRITE,
};
use busbar_plugin_abi::host_side::caller::CallStack;
use busbar_plugin_abi::plugin::Plugin;
use busbar_plugin_abi::types::KindCode;
use busbar_ports::hook::{
    BudgetIn, CandidateIn, CostTermIn, HookAnswer, HookCall, HookPort, HookView,
};
use busbar_ports::{CallCx, FactRef, PortError};

use super::harness::Harness;
use crate::fake_needs::FakeNeeds;

type Candidate = hook::CandidateRec;

pub(super) fn run(plugin: &'static Plugin, config: &[u8], needs: FakeNeeds) {
    let h = Harness::admit(plugin, needs)
        .unwrap_or_else(|r| panic!("hook suite: admission refused the image: {r:?}"));
    assert_eq!(
        h.kind(),
        KindCode::Hook,
        "hook suite: the stamp is not a hook"
    );

    let words = describe_cases(&h);
    open_cases(&h, config);

    let port = h
        .open_hook("hook-a", config)
        .unwrap_or_else(|e| panic!("hook suite: open failed: {e:?}"));
    let other = h
        .open_hook("hook-b", config)
        .unwrap_or_else(|e| panic!("hook suite: a second instance failed to open: {e:?}"));
    assert_eq!(
        port.points(),
        other.points(),
        "two instances differ in points"
    );
    assert_eq!(port.facts(), other.facts(), "two instances differ in facts");
    let points = port.points();
    assert_ne!(points, 0, "a hook serves at least one point");
    assert_eq!(
        points & !(bit(POINT_ROUTE) | bit(POINT_REWRITE) | bit(POINT_NOTIFY)),
        0,
        "D_POINTS names a point that is not ROUTE, REWRITE or NOTIFY: {points:#b}"
    );
    assert_eq!(
        port.facts() & !FB_WANTS_PROMPT,
        0,
        "facts carry a bit that is not an FB_*"
    );

    for point in [POINT_ROUTE, POINT_REWRITE, POINT_NOTIFY] {
        if points & bit(point) == 0 {
            continue;
        }
        for view in views(&words, point, port.facts()) {
            for instance in [&port, &other] {
                let answer = call(&h, instance.as_ref(), point, &view);
                check_answer(point, &view, &answer);
            }
        }
    }

    if points & bit(POINT_ROUTE) != 0 {
        no_sample_member_cases(&h, port.as_ref(), &words);
    }

    // A hook never faults, so every line it logged names an instance this suite opened.
    for line in h.logs() {
        assert!(
            ["hook-a", "hook-b", "hook-bad"].contains(&line.instance.as_str()),
            "a log line names an instance the suite never opened: {line:?}"
        );
    }
}

const fn bit(point: u32) -> u32 {
    1 << point
}

/// Describe: the shape rules of §8.4. Returns the D_WORD words.
fn describe_cases(h: &Harness) -> Vec<String> {
    let d = h
        .registry()
        .described(h.identity())
        .expect("the admitted image has a describe");
    assert_eq!(d.kind, KindCode::Hook);
    let on = d.methods & M_ON != 0;
    let on_io = d.methods & M_ON_IO != 0;
    assert!(
        on ^ on_io,
        "declare exactly one of on / on_io (methods {:#b})",
        d.methods
    );

    let words: Vec<String> = d
        .items
        .iter()
        .filter(|(t, _)| *t == hook::tag::D_WORD)
        .map(|(_, b)| String::from_utf8(b.clone()).expect("a D_WORD word is UTF-8 text"))
        .collect();
    assert!(
        words.len() <= 8,
        "at most 8 D_WORD words, got {}",
        words.len()
    );
    for w in &words {
        let mut chars = w.chars();
        let first = chars.next().expect("a D_WORD word is not empty");
        assert!(first.is_ascii_lowercase(), "D_WORD `{w}` must start [a-z]");
        assert!(
            w.len() <= 32
                && chars
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_'),
            "D_WORD `{w}` is not [a-z][a-z0-9_-]{{0,31}}"
        );
    }
    let mut sorted = words.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), words.len(), "a D_WORD word is declared twice");
    if !words.is_empty() {
        let points = d
            .items
            .iter()
            .find(|(t, _)| *t == hook::tag::D_POINTS)
            .and_then(|(_, b)| b.get(..4))
            .map_or(0, |m| u32::from_le_bytes([m[0], m[1], m[2], m[3]]));
        assert_ne!(
            points & bit(POINT_ROUTE),
            0,
            "D_WORD requires POINT_ROUTE in D_POINTS"
        );
    }
    words
}

/// Open: bad config refused, good config opens.
fn open_cases(h: &Harness, config: &[u8]) {
    let bad = h.open_hook("hook-bad", b"\xff\xfe not json");
    assert!(bad.is_err(), "a config that is not JSON must be refused");
    assert!(h.check("hook-bad", b"\xff\xfe not json").is_err());
    h.check("hook-check", config)
        .unwrap_or_else(|e| panic!("hook suite: check refused the suite's own config: {e:?}"));
}

// ---------------------------------------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------------------------------------

struct OwnedCost {
    class: &'static str,
    price: Option<f64>,
    units: f64,
}

struct OwnedCandidate {
    rec: Candidate,
    model: &'static str,
    provider: &'static str,
    tier: Option<&'static str>,
    tags: Vec<&'static str>,
    cost: Vec<OwnedCost>,
}

struct OwnedBudget {
    id: &'static str,
    period: &'static str,
    group: Option<&'static str>,
    pool: Option<&'static str>,
    remaining: i64,
    spend: Option<i64>,
}

/// A view the suite owns, so it can lend a `HookView` and later check the answer against it.
struct Case {
    signals: Vec<(u32, OwnedFact)>,
    candidates: Vec<OwnedCandidate>,
    budgets: Vec<OwnedBudget>,
    conversation: Option<Vec<u8>>,
    body: Option<Vec<u8>>,
    identity: Option<Vec<u8>>,
}

enum OwnedFact {
    U(u64),
    Text(&'static str),
}

/// Lend `case` as a `HookView` for the duration of `f`.
fn with_view<R>(case: &Case, f: impl FnOnce(&HookView<'_>) -> R) -> R {
    let signals: Vec<(u32, FactRef<'_>)> = case
        .signals
        .iter()
        .map(|(k, v)| {
            (
                *k,
                match v {
                    OwnedFact::U(n) => FactRef::U(*n),
                    OwnedFact::Text(t) => FactRef::Text(t),
                },
            )
        })
        .collect();
    let terms: Vec<Vec<CostTermIn<'_>>> = case
        .candidates
        .iter()
        .map(|c| {
            c.cost
                .iter()
                .map(|t| CostTermIn {
                    class: t.class,
                    price_per_unit: t.price,
                    expected_units: t.units,
                })
                .collect()
        })
        .collect();
    let cands: Vec<CandidateIn<'_>> = case
        .candidates
        .iter()
        .zip(&terms)
        .map(|(c, t)| CandidateIn {
            rec: c.rec,
            model: c.model,
            provider: c.provider,
            tier: c.tier,
            tags: &c.tags,
            cost_terms: t,
        })
        .collect();
    let budgets: Vec<BudgetIn<'_>> = case
        .budgets
        .iter()
        .map(|b| BudgetIn {
            id: b.id,
            period: b.period,
            group: b.group,
            pool: b.pool,
            remaining_micros: b.remaining,
            spend_micros_at_current_rate: b.spend,
            window_start_s: 1_700_000_000,
        })
        .collect();
    let view = HookView {
        signals: &signals,
        candidates: &cands,
        budgets: &budgets,
        conversation: case.conversation.as_deref(),
        body: case.body.as_deref(),
        identity: case.identity.as_deref(),
    };
    f(&view)
}

fn rec(index: u32, flags: u32) -> Candidate {
    Candidate {
        index,
        flags,
        context_max: if flags & C_HAS_CONTEXT_MAX != 0 {
            128_000
        } else {
            0
        },
        cost_per_mtok_micros: if flags & C_HAS_COST != 0 {
            3_000_000 + u64::from(index)
        } else {
            0
        },
        latency_ms: if flags & C_HAS_LATENCY != 0 {
            120 + 40 * u64::from(index)
        } else {
            0
        },
        budget_remaining_micros: if flags & C_HAS_BUDGET != 0 {
            5_000_000
        } else {
            0
        },
        // Hook 3.0: the error-rate presence bit is retired; the field is always absent (zero).
        error_rate_ppm: 0,
        breaker: 0,
        rate_headroom_ppm: if flags & C_HAS_RATE_HEADROOM != 0 {
            750_000
        } else {
            0
        },
        _r: 0,
        weight: 1 + index,
        available_concurrency: 4,
    }
}

fn candidate(index: u32, flags: u32, priced: bool) -> OwnedCandidate {
    OwnedCandidate {
        rec: rec(index, flags),
        model: ["model-a", "model-b", "model-c", "model-d"][index as usize % 4],
        provider: ["prov-a", "prov-b", "prov-c", "prov-d"][index as usize % 4],
        tier: (index.is_multiple_of(2)).then_some("premium"),
        tags: if index.is_multiple_of(2) {
            vec!["fast", "eu"]
        } else {
            Vec::new()
        },
        cost: vec![
            OwnedCost {
                class: "input",
                price: Some(2.5),
                units: 1000.0,
            },
            OwnedCost {
                class: "output",
                price: if priced { Some(10.0) } else { None },
                units: 400.0,
            },
        ],
    }
}

fn all_flags() -> u32 {
    C_HAS_LATENCY | C_HAS_BUDGET | C_HAS_RATE_HEADROOM | C_HAS_CONTEXT_MAX | C_HAS_COST
}

fn base(_point: u32, facts: u64) -> Case {
    Case {
        signals: vec![
            (S_POOL, OwnedFact::Text("default")),
            (S_INGRESS_PROTOCOL, OwnedFact::Text("openai-chat")),
            (S_ATTEMPT, OwnedFact::U(1)),
            (S_REMAINING_CANDIDATES, OwnedFact::U(2)),
            (S_USER_SUBJECT, OwnedFact::Text("subject-1")),
            (S_KEY_ID, OwnedFact::Text("key-1")),
            (S_KEY_NAME, OwnedFact::Text("ci key")),
        ],
        candidates: Vec::new(),
        budgets: Vec::new(),
        conversation: (facts & FB_WANTS_PROMPT != 0)
            .then(|| br#"{"messages":[{"role":"user","content":"hello"}]}"#.to_vec()),
        // Hook 3.0: the raw body and the identity are not part of the view (their fact bits are retired).
        body: None,
        identity: None,
    }
}

/// Every view the suite sends at `point`.
fn views(words: &[String], point: u32, facts: u64) -> Vec<Case> {
    let mut out = Vec::new();

    // Request stage, nothing known yet.
    out.push(base(point, facts));

    // Candidates: full presence bits, priced; no bits, unpriced; a mix; budgets with and without spend.
    let mut full = base(point, facts);
    full.candidates = vec![
        candidate(0, all_flags(), true),
        candidate(1, all_flags(), true),
        candidate(2, all_flags(), true),
    ];
    full.budgets = vec![
        OwnedBudget {
            id: "b1",
            period: "month",
            group: Some("team"),
            pool: Some("default"),
            remaining: 9_000_000,
            spend: Some(1_000),
        },
        OwnedBudget {
            id: "b2",
            period: "day",
            group: None,
            pool: None,
            remaining: -5,
            spend: None,
        },
    ];
    out.push(full);

    let mut bare = base(point, facts);
    bare.candidates = vec![candidate(0, 0, false), candidate(1, 0, false)];
    out.push(bare);

    let mut mixed = base(point, facts);
    mixed.candidates = vec![
        candidate(0, C_HAS_LATENCY | C_HAS_COST, true),
        candidate(1, C_HAS_BUDGET, false),
        candidate(2, C_HAS_RATE_HEADROOM | C_HAS_CONTEXT_MAX, true),
        candidate(3, 0, false),
    ];
    out.push(mixed);

    // A single candidate and a failed previous attempt.
    let mut one = base(point, facts);
    one.candidates = vec![candidate(0, all_flags(), true)];
    one.signals
        .push((hook::S_PREVIOUS_FAILURE, OwnedFact::U(1)));
    out.push(one);

    // Every strategy word the hook declared, at the point that carries it.
    if point == POINT_ROUTE {
        for w in words {
            let mut c = base(point, facts);
            c.candidates = vec![
                candidate(0, all_flags(), true),
                candidate(1, all_flags(), true),
                candidate(2, C_HAS_COST, true),
            ];
            c.signals.push((S_ROUTING_POLICY, OwnedFact::Text(leak(w))));
            out.push(c);
        }
    }

    // Stage taps (POINT_NOTIFY): S_STAGE present exactly there, S_STAGE_MODEL only when the attempt has a model.
    if point == POINT_NOTIFY {
        for (stage, model) in [
            (STAGE_CANDIDATE, None),
            (STAGE_ROUTING, Some("model-a")),
            (STAGE_RESPONSE, Some("model-b")),
        ] {
            let mut c = base(point, facts);
            c.candidates = vec![candidate(0, all_flags(), true)];
            c.signals.push((S_STAGE, OwnedFact::U(stage)));
            if let Some(m) = model {
                c.signals.push((S_STAGE_MODEL, OwnedFact::Text(m)));
            }
            c.signals.push((hook::S_OUTCOME, OwnedFact::U(0)));
            c.signals.push((hook::S_STATUS, OwnedFact::U(200)));

            out.push(c);
        }
    }
    out
}

fn leak(s: &str) -> &'static str {
    Box::leak(s.to_owned().into_boxed_str())
}

// ---------------------------------------------------------------------------------------------------------
// Calls and answers
// ---------------------------------------------------------------------------------------------------------

fn cx() -> CallCx {
    CallCx {
        deadline: std::time::Instant::now() + std::time::Duration::from_secs(10),
        request_id: 1,
        stack: CallStack::default(),
    }
}

fn call(
    h: &Harness,
    port: &dyn HookPort,
    point: u32,
    case: &Case,
) -> Result<HookAnswer, PortError> {
    with_view(case, |v| match port.on(cx(), point, v) {
        HookCall::Done(r) => r,
        HookCall::Io(fut) => h.block_on(fut),
    })
}

fn check_answer(point: u32, case: &Case, answer: &Result<HookAnswer, PortError>) {
    let n = case.candidates.len() as u32;
    let a = match answer {
        Ok(a) => a,
        Err(PortError::Refused { .. } | PortError::Failed { .. }) => return,
        Err(PortError::Call(e)) => panic!("a hook call faulted at point {point}: {e:?}"),
    };
    if point == POINT_NOTIFY {
        // Only METRIC is read at a tap; the verdict is ignored by core but must still be a known verb.
        assert!(a.verb <= VERB_REWRITE, "unknown verb {}", a.verb);
        return;
    }
    assert!(a.verb <= VERB_REWRITE, "unknown verb {}", a.verb);
    let mut seen = std::collections::BTreeSet::new();
    for &i in &a.order {
        assert!(i < n, "ORDER index {i} out of range for {n} candidates");
        assert!(seen.insert(i), "ORDER names candidate {i} twice");
    }
    if let Some(s) = a.reject_status {
        assert_eq!(a.verb, VERB_REJECT, "reject_status without the REJECT verb");
        assert!(
            (400..=499).contains(&s),
            "reject status {s} outside 400..=499"
        );
    }
    match a.verb {
        VERB_ABSTAIN => {
            assert!(a.order.is_empty() && a.restrict.is_empty() && a.rewrite.is_none());
        }
        VERB_PREFER | VERB_PRIORITIZE => {
            assert!(a.restrict.is_empty() && a.rewrite.is_none());
            assert!(point == POINT_ROUTE, "a ranking verb at point {point}");
            if n > 0 {
                assert!(!a.order.is_empty(), "a ranking verb with an empty ORDER");
            }
        }
        VERB_RESTRICT => {
            assert!(point == POINT_ROUTE, "RESTRICT at point {point}");
            assert!(!a.restrict.is_empty(), "RESTRICT with nothing named");
            assert!(a.restrict.iter().all(|r| !r.is_empty()));
        }
        VERB_REJECT => {
            assert!(a.order.is_empty() && a.rewrite.is_none());
        }
        VERB_REWRITE => {
            assert_eq!(point, POINT_REWRITE, "REWRITE at point {point}");
            let body = a.rewrite.as_deref().expect("REWRITE without a body");
            busbar_contract::json::parse_value(body)
                .expect("REWRITE body is the generic CONVERSATION JSON");
        }
        _ => unreachable!(),
    }
    if a.verb != VERB_REWRITE {
        assert!(
            a.rewrite.is_none(),
            "a REWRITE body without the REWRITE verb"
        );
    }
    if let Some(m) = &a.message {
        assert!(
            !m.contains("BUSBAR-"),
            "MESSAGE carries a plugin error code: {m}"
        );
    }
}

/// C-COST-TERMS and the C_HAS_* rule: the member with no latency sample is never ranked first by `fastest`.
fn no_sample_member_cases(h: &Harness, port: &dyn HookPort, words: &[String]) {
    let mut c = base(POINT_ROUTE, port.facts());
    let mut no_sample = candidate(0, C_HAS_COST, false);
    no_sample.cost[1].price = None;
    let mut sampled = candidate(1, C_HAS_COST | C_HAS_LATENCY, true);
    sampled.rec.latency_ms = 900;
    c.candidates = vec![no_sample, sampled];
    c.signals
        .push((S_ROUTING_POLICY, OwnedFact::Text("fastest")));
    let answer = call(h, port, POINT_ROUTE, &c);
    check_answer(POINT_ROUTE, &c, &answer);
    if words.iter().any(|w| w == "fastest") {
        if let Ok(a) = &answer {
            if matches!(a.verb, VERB_PREFER | VERB_PRIORITIZE) {
                assert_eq!(
                    a.order.first(),
                    Some(&1),
                    "`fastest` ranked the member with no latency sample first"
                );
            }
        }
    }
}
