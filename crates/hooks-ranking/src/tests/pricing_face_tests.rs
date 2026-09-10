// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Two questions about the candidate's COST, asked from the crate that ranks on it.
//!
//! **What is it called.** A candidate's cost is the only member of the routable-member face that
//! is spelled in one dialect's unit of quantity: a price per MILLION TOKENS. Tokens are what one
//! kind of traffic is counted in; a duplex leg is counted in seconds and a relay in frames, and
//! each of them has a rate off the same card. A neutral face that can only say what a token costs
//! is a face the other kinds cannot answer at all, and the shipped ranking hook here reads that
//! member by that name, so the noun is not merely declared in the contract — it is in the
//! comparison. The scan below holds the FACE to a kind-neutral vocabulary. It deliberately does
//! not scan the hook WIRE: the JSON key an operator's hook receives is frozen bytes and stays
//! exactly as it is; what a member is CALLED where the engine decides is a different question from
//! what it is called on a wire nobody may move.
//!
//! **Does it decide the same thing.** Every rate vector below is RECORDED — read off a rate card
//! that exists in this repository as a fixture, a corpus entry, a shipped example or a pinned
//! oracle body — and the order beside it is the order `cheapest` ranks it in. The table is written
//! before the cost member changes shape and is not touched when it does, so "the same candidate is
//! picked" is a comparison against something recorded rather than against something re-derived.

use super::*;
use busbar_api::{ClassRate, MeterClassId, UNIT_INPUT, UNIT_OUTPUT};

/// The recorded rate cards, and what `cheapest` makes of each.
///
/// `members` is one entry per routable member, in the pool's declaration order, carrying the
/// member's `(input, output)` rates in micro-units per unit of quantity — `None` for a member the
/// card does not price. `order` is the ranking `cheapest` returns, or `None` where it abstains.
struct RecordedDecision {
    /// Where the rates were recorded, so a reader can go and check them.
    recorded_at: &'static str,
    /// The card's rates for each member, in declaration order.
    members: &'static [Option<(f64, f64)>],
    /// The ranking `cheapest` answers with; `None` is an abstention.
    order: Option<&'static [usize]>,
}

/// Nine lanes at one price is what the oracle's own card records, so the whole table ties and the
/// tiebreak is the only thing deciding.
const ORACLE_CARD: &[Option<(f64, f64)>] = &[Some((10_000_000.0, 20_000_000.0)); 9];
/// The same nine lanes on the oracle's penny card.
const ORACLE_PENNY_CARD: &[Option<(f64, f64)>] = &[Some((1.0, 1.0)); 9];
/// Nine ties rank by the candidate's own slot.
const NINE_TIED: &[usize] = &[0, 1, 2, 3, 4, 5, 6, 7, 8];

const RECORDED: &[RecordedDecision] = &[
    RecordedDecision {
        recorded_at: "the oracle's rate card (testing/shadow-oracle/cells.json): nine lanes, each \
                      priced 10.0/20.0 micro-units per unit",
        members: ORACLE_CARD,
        order: Some(NINE_TIED),
    },
    RecordedDecision {
        recorded_at: "the oracle's penny card (testing/shadow-oracle/cells.json): the same nine \
                      lanes at 1.0/1.0",
        members: ORACLE_PENNY_CARD,
        order: Some(NINE_TIED),
    },
    RecordedDecision {
        recorded_at: "the mid-window repricing's FIRST card \
                      (testing/shadow-oracle/golden/1.5.5/cells/billing__rate-card__\
                      history-mid-window.json): one lane at 1000000.0/2000000.0",
        members: &[Some((1_000_000.0, 2_000_000.0))],
        order: Some(&[0]),
    },
    RecordedDecision {
        recorded_at: "the mid-window repricing's SECOND card (the same golden cell): the one lane \
                      repriced to 10000000.0/20000000.0",
        members: &[Some((10_000_000.0, 20_000_000.0))],
        order: Some(&[0]),
    },
    RecordedDecision {
        recorded_at: "the backcompat corpus's tiered card (02_rate_card_tiers.yaml): 3.0/15.0 \
                      then 2.5/10.0",
        members: &[Some((3.0, 15.0)), Some((2.5, 10.0))],
        order: Some(&[1, 0]),
    },
    RecordedDecision {
        recorded_at: "the backcompat corpus's full billing surface \
                      (05_full_billing_surface.yaml): four priced members",
        members: &[
            Some((0.8, 4.0)),
            Some((3.0, 15.0)),
            Some((0.075, 0.3)),
            Some((2.5, 10.0)),
        ],
        order: Some(&[2, 0, 3, 1]),
    },
    RecordedDecision {
        recorded_at: "the shipped config.yaml's documented card: 3.0/15.0 and 2.5/10.0",
        members: &[Some((3.0, 15.0)), Some((2.5, 10.0))],
        order: Some(&[1, 0]),
    },
    RecordedDecision {
        recorded_at: "the deployment card the engine's own config battery records: one entry at \
                      3.0/15.0, whose comparable price that battery pins at 9.0",
        members: &[Some((3.0, 15.0))],
        order: Some(&[0]),
    },
    RecordedDecision {
        recorded_at: "the card the engine's own cost battery records: one entry at 2.5/10.0, \
                      whose comparable price that battery pins at 6.25",
        members: &[Some((2.5, 10.0))],
        order: Some(&[0]),
    },
    RecordedDecision {
        recorded_at: "an unpriced deployment — the shape the dlopen hook battery and the engine's \
                      own hook tests record, where no member carries a rate at all",
        members: &[None, None],
        order: None,
    },
    RecordedDecision {
        recorded_at: "a card that prices some members and not others (the corpus's four-member \
                      pool with two entries removed): the priced rank first, the unpriced are \
                      demoted and still reachable",
        members: &[None, Some((2.5, 10.0)), None, Some((0.8, 4.0))],
        order: Some(&[3, 1, 0, 2]),
    },
];

/// The recorded rates of one member, as the metering step's rate face states them.
fn rate_lines(rates: Option<(f64, f64)>) -> Vec<ClassRate> {
    rates
        .map(|(input, output)| {
            vec![
                ClassRate {
                    class: MeterClassId::new(UNIT_INPUT),
                    micros_per_unit: input,
                },
                ClassRate {
                    class: MeterClassId::new(UNIT_OUTPUT),
                    micros_per_unit: output,
                },
            ]
        })
        .unwrap_or_default()
}

/// One candidate carrying a recorded member's rates and nothing else that `cheapest` reads.
fn cand_priced(idx: usize, price: &[ClassRate]) -> Candidate<'_> {
    Candidate {
        idx,
        model: "m",
        provider: "p",
        weight: 1,
        context_max: None,
        tier: None,
        price,
        tags: &[],
        latency_ms: None,
        available_concurrency: 1,
        budget_remaining: None,
        rate_headroom: None,
        signals: Default::default(),
    }
}

/// The request every recorded decision is ranked for: `cheapest` reads nothing off it.
fn req() -> RoutingRequest<'static> {
    RoutingRequest {
        request_id: 1,
        pool: "p",
        ingress_protocol: "anthropic",
        message_count: 1,
        has_tools: false,
        total_chars: 10,
        max_tokens: None,
        stream: false,
        argument: None,
        identity: None,
        signals: Default::default(),
    }
}

/// The pool context, which `cheapest` likewise never reads.
fn ctx() -> RoutingContext<'static> {
    RoutingContext {
        pool: "p",
        budget_remaining: None,
        budget: &[],
    }
}

/// THE SAME CANDIDATE, for every recorded routing decision.
///
/// Not "the ranking still works": the ordering each recorded card produces, written down, one row
/// per card. A row that moves is a deployment whose traffic changed destination because a member
/// was renamed, which is the one outcome this line is not allowed to have.
#[tokio::test]
async fn every_recorded_routing_decision_picks_the_same_candidate() {
    let policy = native_policy("cheapest").expect("the shipped cheapest ranking hook");
    for row in RECORDED {
        let priced: Vec<Vec<ClassRate>> = row.members.iter().map(|m| rate_lines(*m)).collect();
        let cands: Vec<Candidate<'_>> = priced
            .iter()
            .enumerate()
            .map(|(idx, price)| cand_priced(idx, price))
            .collect();
        let decided = policy
            .decide(&req(), &cands, &ctx(), Duration::from_secs(1))
            .await
            .expect("a native ranking never errors");
        match (row.order, decided) {
            (Some(expected), RoutingDecision::Prefer(got)) => {
                assert_eq!(got, expected, "the pick moved for {}", row.recorded_at)
            }
            (None, RoutingDecision::Abstain) => {}
            (_, other) => panic!(
                "the decision changed shape for {}: {other:?}",
                row.recorded_at
            ),
        }
    }
}

/// The routable-member face, and this plugin's reading of it, in a vocabulary every kind of
/// traffic can answer.
///
/// A price per million TOKENS is a fact about one kind of unit. The card behind it prices a CLASS
/// per unit of that class's own quantity, which is the vocabulary the metering step already uses,
/// and which a duplex leg priced by the second can answer without pretending to have tokens.
#[test]
fn the_candidates_cost_is_not_named_in_one_kinds_quantity() {
    let faces = [
        (
            "the routable-member face",
            "../busbar-contract/src/hooks.rs",
        ),
        ("this ranking hook's own reading", "src/lib.rs"),
    ];
    let mut offenders: Vec<String> = Vec::new();
    for (what, rel) in faces {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
        let src = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        for (n, line) in src.lines().enumerate() {
            if line.contains("mtok") {
                offenders.push(format!("{what} ({rel}:{}): {}", n + 1, line.trim()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "a candidate's cost is stated in one kind's unit of quantity:\n  {}",
        offenders.join("\n  ")
    );
}
