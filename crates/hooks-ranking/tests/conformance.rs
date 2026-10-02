// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **RANKING NEVER PENDS** (ARCHITECT Q-SO9): the ranking door, admitted through the loader's one
//! door validation and driven through its real dispatch, answers `decide` READY on the FIRST poll
//! for every strategy word, over every candidate shape the ranking parity cases use. Ranking is pure
//! compute: an answer of PENDING would hand the call to the dispatcher's deadline, where 1.5.5's
//! in-process ranking could never time out. RED by making the door's `decide` answer
//! `Poll::Pending`: this test fails on the first word.

use std::sync::Arc;

use busbar_contract::abi::hook::{slot, DecideOut};
use busbar_contract::abi::host::hook::{DecideFrame, DecideView};
use busbar_contract::abi::mechanism::call::{Blob, Outcome, BLOB_JSON};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_contract::abi::sdk::door::blank_out;
use busbar_contract::hooks::{Candidate, RoutingContext, RoutingRequest};
use busbar_contract::SignalBag;
use busbar_hooks_ranking::WORDS;
use busbar_plugin_loader::dispatch::kinds::hook::Hook;
use busbar_plugin_loader::dispatch::{
    in_head, load_linked, out_head, Bind, DispatchConfig, Dispatcher, Frame, LinkedRow, NoSink,
    Plugin,
};

/// The linked door, bound on `d`.
fn load(d: &Dispatcher) -> Plugin<Hook> {
    let row = LinkedRow::of(busbar_hooks_ranking::linked::door).expect("the door states itself");
    let bind = Bind {
        instance: Arc::from("ranking"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: None,
    };
    load_linked::<Hook>(&row, bind).expect("the door loads")
}

/// `open` over `settings`, READY.
fn open(p: &Plugin<Hook>, settings: &str) {
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
    assert_eq!(
        p.call(life::OPEN, &mut f).outcome,
        Outcome::Ready,
        "{settings}"
    );
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

#[test]
fn every_strategy_word_answers_decide_ready_on_the_first_poll_never_pending() {
    let d = Dispatcher::new(DispatchConfig::default());
    let ctx = RoutingContext {
        pool: "p",
        budget_remaining: None,
        budget: &[],
    };
    for word in WORDS {
        let p = load(&d);
        open(&p, &format!(r#"{{"policy": "{word}"}}"#));
        for rows in SHAPES {
            let frame = DecideFrame::first(DecideView::build(&request(), &candidates(rows), &ctx));
            let mut f = Frame::new(frame.input(), blank_out::<DecideOut>());
            let outcome = p.call(slot::DECIDE, &mut f).outcome;
            assert_eq!(
                outcome,
                Outcome::Ready,
                "`{word}` must answer READY on its first poll (pure compute), never {outcome:?}, \
                 over {} candidates",
                rows.len()
            );
        }
    }
}
