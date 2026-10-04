// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RANKING HOOK'S CONFORMANCE: its door, BOTH WAYS (#2 rule (1): compiled in or dropped in,
//! one contract, one loading path), and RANKING NEVER PENDS (ARCHITECT Q-SO9).
//!
//! * [`the_linked_and_the_dropped_in_door_rank_every_shape_the_same`]: the linked door
//!   (`linked::door`) and this crate's dropped-in image (the `ranking_door` example, the same door
//!   behind `export_door!`), each admitted through the one loader, run ONE script — a refused open,
//!   then every strategy word opened and asked to `decide` over every candidate shape the ranking
//!   parity cases use. The two transcripts (outcome, verbs, the order written) must be identical.
//! * RED ARM, kept: [`red_a_door_that_ranks_the_other_way_answers_differently`] runs the same script
//!   over the same door with its verdict reversed. Its transcript differs at the orders, so a door
//!   that ranked differently cannot pass for this one.
//! * [`every_strategy_word_answers_decide_ready_on_the_first_poll_never_pending`]: through both
//!   doors, `decide` answers READY on the FIRST poll for every word and shape. Ranking is pure
//!   compute: an answer of PENDING would hand the call to the dispatcher's deadline, where 1.5.5's
//!   in-process ranking could never time out. RED by making the door's `decide` answer
//!   `Poll::Pending`: this test fails on the first word.

use std::sync::Arc;
use std::task::Poll;

use busbar_contract::abi::hook::{slot, DecideOut};
use busbar_contract::abi::host::hook::{DecideFrame, DecideView};
use busbar_contract::abi::mechanism::call::{Blob, Outcome, BLOB_JSON};
use busbar_contract::abi::mechanism::door::DoorFn;
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_contract::abi::sdk::door::blank_out;
use busbar_contract::abi::sdk::exchange::Op;
use busbar_contract::abi::sdk::hook::{Decoded, Hook as HookImpl, HookOpen, Verdict};
use busbar_contract::hooks::{Candidate, RoutingContext, RoutingRequest};
use busbar_contract::SignalBag;
use busbar_hooks_ranking::WORDS;
use busbar_plugin_loader::dispatch::kinds::hook::Hook;
use busbar_plugin_loader::dispatch::{
    in_head, load_dropped, load_linked, out_head, rendering_of, Bind, DispatchConfig, Dispatcher,
    Frame, LinkedRow, NoSink, Plugin,
};

fn bind(d: &Dispatcher) -> Bind {
    Bind {
        instance: Arc::from("ranking"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: None,
    }
}

/// `door`, linked and bound on `d`.
fn linked_row(door: DoorFn, d: &Dispatcher) -> Plugin<Hook> {
    let row = LinkedRow::of(door).expect("the door states itself");
    load_linked::<Hook>(&row, bind(d)).expect("the door loads")
}

/// The linked door, bound on `d`.
fn linked(d: &Dispatcher) -> Plugin<Hook> {
    linked_row(busbar_hooks_ranking::linked::door, d)
}

/// This crate's dropped-in image, the `ranking_door` example `cargo test` builds, admitted against
/// the Statement the linked door renders. A missing artifact is a failure, never a skip: this test
/// IS the dropped-in door's proof.
fn dropped(d: &Dispatcher) -> Plugin<Hook> {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let examples = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/<profile>")
        .join("examples");
    let file = busbar_plugin_loader::plugin_library_filename("ranking_door");
    let path = [examples.join(&file), examples.join("deps").join(&file)]
        .into_iter()
        .find(|p| p.exists())
        .unwrap_or_else(|| panic!("the ranking_door example ({file}) is not built"));
    let stated =
        rendering_of(busbar_hooks_ranking::linked::door).expect("the door renders its Statement");
    load_dropped::<Hook>(&path, &stated, bind(d)).expect("the dropped door loads")
}

/// `open` over `settings`: its outcome.
fn open(p: &Plugin<Hook>, settings: &str) -> Outcome {
    let mut f = Frame::new(
        OpenIn {
            head: in_head(),
            host: std::ptr::null(),
            settings: Blob {
                ptr: settings.as_ptr(),
                len: settings.len(),
                fmt: BLOB_JSON,
                flags: 0,
            },
            secrets: std::ptr::null(),
            secrets_len: 0,
            generation: 1,
            err_buf: std::ptr::null_mut(),
            err_cap: 0,
        },
        OpenOut {
            head: out_head(),
            instance: std::ptr::null_mut(),
            err_len: 0,
        },
    );
    p.call(life::OPEN, &mut f).outcome
}

fn request() -> RoutingRequest<'static> {
    RoutingRequest {
        request_id: 1,
        pool: "p",
        ingress_protocol: "wire-a",
        requested_model: None,
        message_count: 1,
        tool_count: 0,
        has_tools: false,
        total_chars: 10,
        system_chars: 0,
        max_tokens: None,
        stream: false,
        prompt: None,
        identity: None,
        signals: SignalBag::new(),
    }
}

/// `(idx, cost, latency, concurrency, rate headroom)`.
type Row = (usize, Option<f64>, Option<f64>, usize, Option<f64>);

/// The candidate shapes the ranking parity cases rank: signals present, partly absent, all absent,
/// a non-finite key, all saturated, one member, none.
const SHAPES: &[&[Row]] = &[
    &[
        (0, Some(15.0), Some(120.0), 2, Some(0.10)),
        (1, Some(3.0), Some(40.0), 9, Some(0.90)),
        (2, None, None, 5, None),
    ],
    &[(0, None, None, 1, None), (1, None, None, 1, None)],
    &[
        (0, Some(f64::NAN), Some(f64::INFINITY), 0, Some(f64::NAN)),
        (1, Some(1.0), None, 0, None),
    ],
    &[(0, Some(5.0), Some(30.0), 3, Some(0.5))],
    &[],
];

fn candidates(rows: &[Row]) -> Vec<Candidate<'static>> {
    rows.iter()
        .map(|&(idx, cost, lat, conc, rate)| Candidate {
            idx,
            model: "m",
            provider: "p",
            weight: 1,
            context_max: None,
            tier: None,
            cost_per_mtok: cost,
            tags: &[],
            latency_ms: lat,
            available_concurrency: conc,
            budget_remaining: None,
            rate_headroom: rate,
            signals: SignalBag::new(),
        })
        .collect()
}

fn ctx() -> RoutingContext<'static> {
    RoutingContext {
        pool: "p",
        budget_remaining: None,
        budget: &[],
    }
}

/// One `decide` over `rows`: its outcome, verbs and the order it wrote.
fn decide(p: &Plugin<Hook>, rows: &[Row]) -> (Outcome, u32, Vec<usize>) {
    let frame = DecideFrame::first(DecideView::build(&request(), &candidates(rows), &ctx()));
    let mut f = Frame::new(frame.input(), blank_out::<DecideOut>());
    let outcome = p.call(slot::DECIDE, &mut f).outcome;
    (outcome, f.out.verbs, frame.order(f.out.order_written))
}

/// THE SCRIPT over the door `load` binds, one line per answer: an open that names no strategy,
/// then every strategy word opened and asked to rank every shape.
fn script(load: impl Fn(&Dispatcher) -> Plugin<Hook>) -> Vec<String> {
    let d = Dispatcher::new(DispatchConfig::default());
    let mut lines = vec![format!(
        "open nope: {:?}",
        open(&load(&d), r#"{"policy": "nope"}"#)
    )];
    for word in WORDS {
        let p = load(&d);
        lines.push(format!(
            "open {word}: {:?}",
            open(&p, &format!(r#"{{"policy": "{word}"}}"#))
        ));
        for (n, rows) in SHAPES.iter().enumerate() {
            let (outcome, verbs, order) = decide(&p, rows);
            lines.push(format!(
                "{word} shape {n}: {outcome:?} verbs={verbs:#x} order={order:?}"
            ));
        }
    }
    lines
}

#[test]
fn the_linked_and_the_dropped_in_door_rank_every_shape_the_same() {
    let linked = script(linked);
    assert_ne!(
        linked[0], "open nope: Ready",
        "a word no strategy spells opens nothing"
    );
    // The script reached real rankings: equal transcripts of abstains would prove nothing.
    assert!(
        linked
            .iter()
            .any(|l| l.contains("order=[1, 0") || l.contains("order=[0, 1")),
        "{linked:#?}"
    );
    assert_eq!(script(dropped), linked, "the dropped-in door");
}

/// The ranking door with its verdict REVERSED: the same Statement, the same strategies, every
/// preferred order read back to front. The red arm's door.
mod reversed {
    use super::{Decoded, HookImpl, HookOpen, Op, Poll, Verdict};

    struct Reversed(Box<dyn HookImpl>);

    impl HookImpl for Reversed {
        fn decide(&self, view: &Decoded<'_>, op: &Op<'_>) -> Poll<Verdict> {
            self.0.decide(view, op).map(|v| match v {
                Verdict::Prefer(mut order) => {
                    order.reverse();
                    Verdict::Prefer(order)
                }
                other => other,
            })
        }
    }

    pub struct Open;

    impl HookOpen for Open {
        fn open(settings: &str) -> Result<Box<dyn HookImpl>, String> {
            busbar_hooks_ranking::door::Open::open(settings)
                .map(|h| Box::new(Reversed(h)) as Box<dyn HookImpl>)
        }
    }

    busbar_contract::hook_door! {
        open: Open,
        statement: busbar_hooks_ranking::door::STATEMENT,
    }
}

#[test]
fn red_a_door_that_ranks_the_other_way_answers_differently() {
    let honest = script(linked);
    let red = script(|d| linked_row(reversed::door, d));
    assert_eq!(red.len(), honest.len());
    let differ: Vec<(&String, &String)> = honest.iter().zip(&red).filter(|(a, b)| a != b).collect();
    assert!(
        !differ.is_empty(),
        "a reversed ranking must answer differently"
    );
    assert!(
        differ.iter().all(|(a, _)| a.contains(" shape ")),
        "the two differ at the orders, nowhere else: {differ:#?}"
    );
}

#[test]
fn every_strategy_word_answers_decide_ready_on_the_first_poll_never_pending() {
    for load in [linked as fn(&Dispatcher) -> Plugin<Hook>, dropped] {
        let d = Dispatcher::new(DispatchConfig::default());
        for word in WORDS {
            let p = load(&d);
            assert_eq!(
                open(&p, &format!(r#"{{"policy": "{word}"}}"#)),
                Outcome::Ready,
                "{word}"
            );
            for rows in SHAPES {
                let (outcome, ..) = decide(&p, rows);
                assert_eq!(
                    outcome,
                    Outcome::Ready,
                    "`{word}` must answer READY on its first poll (pure compute), never \
                     {outcome:?}, over {} candidates",
                    rows.len()
                );
            }
        }
    }
}
