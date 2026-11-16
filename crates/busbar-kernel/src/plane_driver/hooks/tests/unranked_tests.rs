// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The ordering-slot "no choice, no known cost" warning: once per `policy@pool`, only where the
//! walk really falls back to weighted round-robin, never from a gate.

use super::*;
use busbar_contract::abi::hook::{DecideOut, TransformOut};
use busbar_contract::abi::host::hook::{DecideFrame, NotifyFrame};
use busbar_contract::abi::sdk::hook::Verdict;
use busbar_contract::hook_calls::{Answered, HookCalls, Pending};
use busbar_contract::signal::route_cost::{self, Term};
use tracing_subscriber::layer::SubscriberExt as _;

/// The catalogued code of `ROUTING_POLICY_ABSTAINED_UNPRICED`.
const CODE: &str = "BUSBAR-5050";

/// Every WARN line, its fields rendered ` name=value`.
#[derive(Clone, Default)]
struct Warns(Arc<Mutex<Vec<String>>>);

impl Warns {
    fn with(&self, code: &str) -> Vec<String> {
        let needle = format!("diag={code}");
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|line| line.split(' ').any(|field| field == needle))
            .cloned()
            .collect()
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Warns {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        if *event.metadata().level() != tracing::Level::WARN {
            return;
        }
        struct Fields(String);
        impl tracing::field::Visit for Fields {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                self.0.push(' ');
                self.0.push_str(field.name());
                self.0.push('=');
                self.0.push_str(value);
            }
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.push(' ');
                self.0.push_str(field.name());
                self.0.push('=');
                self.0.push_str(&format!("{value:?}"));
            }
        }
        let mut line = Fields(String::new());
        event.record(&mut line);
        self.0.lock().unwrap().push(line.0);
    }
}

fn member(idx: usize, signals: SignalBag) -> Candidate<'static> {
    Candidate {
        idx,
        model: "m",
        provider: "prov",
        weight: 1,
        context_max: None,
        tier: None,
        cost_per_mtok: None,
        tags: &[],
        latency_ms: None,
        available_concurrency: 1,
        budget_remaining: None,
        rate_headroom: None,
        signals,
    }
}

fn recipe(input: Option<f64>, output: Option<f64>) -> SignalBag {
    let mut bag = SignalBag::new();
    route_cost::append(
        &mut bag,
        [
            Term {
                class: "input",
                price_per_unit: input,
                expected_units: 0.5,
            },
            Term {
                class: "output",
                price_per_unit: output,
                expected_units: 0.5,
            },
        ],
    );
    bag
}

fn priced() -> SignalBag {
    recipe(Some(1000.0), Some(2000.0))
}

fn unpriced() -> SignalBag {
    recipe(None, None)
}

#[test]
fn an_ordering_fallback_with_no_known_cost_warns_once_per_policy_and_pool() {
    let warns = Warns::default();
    let capture = || tracing_subscriber::registry().with(warns.clone());
    let shown = [member(0, unpriced()), member(1, SignalBag::new())];

    let logged: usize = std::thread::scope(|s| {
        let racers: Vec<_> = (0..8)
            .map(|_| {
                s.spawn(|| {
                    tracing::subscriber::with_default(capture(), || {
                        note_unranked("cheapest", "p-unpriced", &shown)
                    })
                })
            })
            .collect();
        racers
            .into_iter()
            .map(|racer| usize::from(racer.join().expect("no racer panics")))
            .sum()
    });
    assert_eq!(logged, 1, "exactly one of 8 concurrent first calls logs");
    tracing::subscriber::with_default(capture(), || {
        for _ in 0..3 {
            assert!(
                !note_unranked("cheapest", "p-unpriced", &shown),
                "a warned policy@pool stays quiet"
            );
        }
    });
    let lines = warns.with(CODE);
    assert_eq!(lines.len(), 1, "one WARN for policy@pool: {lines:?}");
    let fields: Vec<&str> = lines[0].split(' ').collect();
    assert!(fields.contains(&"policy=cheapest"), "{lines:?}");
    assert!(fields.contains(&"pool=p-unpriced"), "{lines:?}");

    let known = [member(0, priced()), member(1, recipe(Some(1.0), Some(2.0)))];
    tracing::subscriber::with_default(capture(), || {
        assert!(
            !note_unranked("cheapest", "p-priced", &known),
            "a member with a known cost means the policy chose to abstain over real prices"
        );
    });
    assert!(
        warns
            .with(CODE)
            .iter()
            .all(|line| !line.split(' ').any(|field| field == "pool=p-priced")),
        "nothing logged for a priced pool"
    );

    unranked_clear("cheapest", "p-unpriced");
    tracing::subscriber::with_default(capture(), || {
        assert!(
            note_unranked("cheapest", "p-unpriced", &shown),
            "once the policy ranked again, the next fallback warns again"
        );
    });
    assert_eq!(warns.with(CODE).len(), 2);
}

#[test]
fn has_known_cost_needs_a_fully_priced_recipe() {
    assert!(!has_known_cost(&member(0, SignalBag::new())), "no recipe");

    let mut marker = SignalBag::new();
    route_cost::append(&mut marker, std::iter::empty());
    assert!(
        !has_known_cost(&member(0, marker)),
        "a marker with no terms"
    );

    assert!(
        !has_known_cost(&member(0, recipe(Some(1000.0), None))),
        "one unpriced term"
    );
    assert!(has_known_cost(&member(0, priced())), "every term priced");

    let mut malformed = SignalBag::new();
    malformed.push(Signal::CandidateRouteCost, SignalValue::U64(7));
    assert!(!has_known_cost(&member(0, malformed)), "a malformed bag");
}

/// A hook that answers every `decide` with one fixed verdict.
struct Answers(Verdict, &'static str);

impl HookCalls for Answers {
    fn name(&self) -> &str {
        self.1
    }
    fn decide(&self, frame: Arc<DecideFrame>, _: Duration) -> Pending<Answered<DecideOut>> {
        let verdict = self.0.clone();
        Box::pin(async move {
            // `DecideOut` carries raw pointers (not `Send`), so it is built inside the future.
            let (outcome, out) = frame.answer_decide(&verdict);
            Answered::Answer {
                outcome,
                out,
                error: None,
                frame,
            }
        })
    }
    fn transform(&self, _: Arc<DecideFrame>, _: Duration) -> Pending<Answered<TransformOut>> {
        Box::pin(async { Answered::TimedOut })
    }
    fn notify(&self, _: Arc<NotifyFrame>, _: Duration) -> Pending<()> {
        Box::pin(std::future::ready(()))
    }
    fn configure(
        &self,
        _: &str,
        _: &busbar_contract::plugin_settings::ResolvedSettings,
        _: u64,
        _: Duration,
    ) -> Pending<Result<(), String>> {
        Box::pin(std::future::ready(Ok(())))
    }
    fn status(&self, _: Duration) -> Pending<Option<Vec<u8>>> {
        Box::pin(std::future::ready(None))
    }
    fn describe(&self, _: Duration) -> Pending<Option<Vec<u8>>> {
        Box::pin(std::future::ready(None))
    }
}

fn resolved(policy: Arc<dyn RoutingPolicy>) -> ResolvedPolicy {
    ResolvedPolicy::Policy {
        policy,
        on_error: PolicyOnError::Weighted,
        on_error_chain: Vec::new(),
        timeout: Duration::from_secs(5),
        send_prompt: false,
        send_user: false,
        on_empty: PolicyOnError::Reject,
    }
}

fn no_read<'a>(
    _: &'a [&'a str],
    _: Option<&'a str>,
    _: &'a str,
    _: bool,
) -> crate::audit::amend::ReadConfirmation<'a> {
    Box::pin(async { Ok(()) })
}

fn unit_hooks(gates: Vec<(u16, ResolvedPolicy)>) -> UnitHooks {
    UnitHooks {
        request_id: 1,
        rewrites: Vec::new(),
        gates,
        policy: None,
        taps: StageTaps::default(),
        key: None,
        rate_headroom: None,
        budget: Vec::new(),
        requested: RequestedSignals::default(),
        groups: Arc::new(|_: &[String]| true),
        reads: Arc::new(no_read),
        dialect: String::new(),
    }
}

/// The r1 placement guard: a gate is the same `HookPolicy` type as an ordering policy, and its
/// abstain over unpriced members must never claim the pool fell back to weighted round-robin.
#[tokio::test]
async fn a_gate_that_abstains_over_unpriced_members_logs_nothing() {
    let warns = Warns::default();
    let _capture =
        tracing::subscriber::set_default(tracing_subscriber::registry().with(warns.clone()));
    let gate = resolved(super::policy::HookPolicy::policy(
        Arc::new(Answers(Verdict::Abstain, "screen")),
        "screen",
        &[Signal::RequestTotalChars],
    ));
    let hooks = unit_hooks(vec![(0, gate.clone())]);
    let view = Projection::empty("", "");
    let shown = [member(0, unpriced()), member(1, SignalBag::new())];
    let asked = Asked {
        view: &view,
        hooks: &hooks,
        pool: "p-gate",
        candidates: &shown,
        named: false,
    };

    let judged = futures::future::join_all((0..8).map(|_| asked.decide(&gate))).await;
    for (decided, ran) in &judged {
        assert_eq!(*decided, Decided::Weighted, "the gate abstained");
        assert!(
            ran.as_ref().is_some_and(|ran| !ran.failed),
            "a clean answer"
        );
    }

    let ordering = resolved(super::policy::HookPolicy::policy(
        Arc::new(Answers(Verdict::Prefer(vec![1, 0]), "least_busy")),
        "least_busy",
        &[],
    ));
    match asked.decide(&ordering).await {
        (Decided::Order { order, name }, _) => {
            assert_eq!(order, vec![1, 0]);
            unranked_clear(&name, "p-gate");
        }
        (other, _) => panic!("the ordering policy ranked: {other:?}"),
    }

    assert!(
        warns.with(CODE).is_empty(),
        "neither an abstaining gate nor a ranking ordering policy logs {CODE}"
    );
}
