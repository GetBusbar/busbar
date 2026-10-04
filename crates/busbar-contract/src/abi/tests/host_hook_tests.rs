// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The hook views, host side: every view the host builds passes the kind's own `in` checks, the
//! frames point at their own buffers, and a re-call's frame grows exactly the short dimensions.

use super::*;
use crate::abi::hook::validate::{check_notify_in, check_prompt_view};
use crate::hooks::{BudgetBucketState as K, CallerIdentity, PromptProjection};
use crate::signal::Signal;

fn req(prompt: bool) -> RoutingRequest<'static> {
    let mut signals = SignalBag::new();
    signals.push(Signal::RoutingPolicy, Value::Str("cheapest".into()));
    RoutingRequest {
        request_id: 7,
        pool: "p",
        ingress_protocol: "acme",
        requested_model: None,
        message_count: 2,
        tool_count: 0,
        has_tools: true,
        total_chars: 11,
        system_chars: 0,
        max_tokens: Some(9),
        stream: true,
        prompt: prompt.then(|| PromptProjection {
            system: Some("sys".into()),
            messages: vec![
                ("user".into(), "hi".into()),
                ("assistant".into(), "".into()),
            ],
        }),
        identity: Some(CallerIdentity {
            key_id: Some("k".into()),
            key_name: None,
            user: Some("u".into()),
        }),
        signals,
        session: None,
    }
}

#[test]
fn a_decide_view_passes_the_prompt_check_and_carries_every_message() {
    let tags = vec!["a".to_string()];
    let cands = [Candidate {
        idx: 4,
        model: "m",
        provider: "prov",
        weight: 1,
        context_max: Some(8),
        tier: None,
        cost_per_mtok: Some(1.5),
        tags: &tags,
        latency_ms: None,
        available_concurrency: 3,
        budget_remaining: None,
        rate_headroom: Some(0.5),
        signals: SignalBag::new(),
    }];
    let budget = [K {
        bucket_id: "b".into(),
        budget_group: None,
        pool: None,
        spend_micros_at_current_rate: 1,
        remaining_micros: Some(2),
        window_start: 3,
        budget_period: "day".into(),
    }];
    let ctx = RoutingContext {
        pool: "p",
        budget_remaining: Some(5),
        budget: &budget,
    };
    let view = DecideView::build(&req(true), &cands, &ctx);
    let frame = DecideFrame::first(view);
    let i = frame.input();
    assert_eq!(
        i.present,
        VIEW_HAS_PROMPT | VIEW_HAS_USER | VIEW_HAS_BUDGET_REMAINING
    );
    assert_eq!(check_prompt_view(&i.prompt), Ok(()));
    assert_eq!(i.prompt.messages_len, 2);
    assert_eq!(i.candidates_len, 1);
    assert_eq!(i.order_cap, 1);
    assert!(!i.order_buf.is_null() && !i.rewrite_buf.is_null());
    assert_eq!(frame.view().candidate_idx(), &[4]);
}

#[test]
fn no_prompt_projection_no_prompt_view() {
    let ctx = RoutingContext {
        pool: "p",
        budget_remaining: None,
        budget: &[],
    };
    let i = DecideFrame::first(DecideView::build(&req(false), &[], &ctx)).input();
    assert_eq!(i.present & VIEW_HAS_PROMPT, 0);
    assert!(i.prompt.messages.is_null() && i.prompt.system.ptr.is_null());
    assert_eq!(check_prompt_view(&i.prompt), Ok(()));
}

#[test]
fn a_regrown_frame_grows_only_what_the_short_answer_needed() {
    let ctx = RoutingContext {
        pool: "p",
        budget_remaining: None,
        budget: &[],
    };
    let first = DecideFrame::first(DecideView::build(&req(false), &[], &ctx));
    // SAFETY: plain data.
    let mut out: DecideOut = unsafe { std::mem::zeroed() };
    out.order_needed = 40;
    let again = first.regrown_decide(&out).input();
    assert_eq!(again.order_cap, 40);
    assert_eq!(again.reject_message_cap, first.input().reject_message_cap);
}

#[test]
fn a_tap_view_carries_signals_and_the_prompt_only_when_projected() {
    let with = NotifyFrame::build(&req(true), None, true).input();
    assert_eq!(check_notify_in(&with), Ok(()));
    assert_eq!(with.present, VIEW_HAS_PROMPT);
    assert_eq!(with.signals_len, 1);
    assert_eq!(with.stage.stage_present, 0);
    // A granted tap over a request that projects no prompt sees none.
    let without = NotifyFrame::build(&req(false), None, true).input();
    assert_eq!(check_notify_in(&without), Ok(()));
    assert_eq!(without.present, 0);
    assert!(without.prompt.messages.is_null());
    let stage = HookStageProjection {
        at: "routing",
        model: Some("m"),
        attempt_number: Some(2),
        remaining_candidates: None,
        previous_failure: Some("x"),
        outcome: None,
        status: None,
    };
    let s = NotifyFrame::build(&req(false), Some(&stage), false)
        .input()
        .stage;
    assert_eq!(s.at, STAGE_AT_ROUTING);
    assert_eq!(
        s.stage_present,
        STAGE_HAS_PROJECTION
            | STAGE_HAS_MODEL
            | STAGE_HAS_ATTEMPT_NUMBER
            | STAGE_HAS_PREVIOUS_FAILURE
    );
}

/// RED (ARCHITECT ruling 2026-09-29, WIRE-HOOK Q5): the prompt rides `notify` ONLY under the tap's
/// `prompt: ro` grant. An ungranted tap is handed no prompt even when the request it observes
/// carries one: no presence bit, no system text, no messages, no body.
#[test]
fn red_an_ungranted_tap_never_sees_the_prompt_the_request_carries() {
    let tap = NotifyFrame::build(&req(true), None, false).input();
    assert_eq!(check_notify_in(&tap), Ok(()));
    assert_eq!(
        tap.present & VIEW_HAS_PROMPT,
        0,
        "an ungranted tap saw the prompt"
    );
    assert!(tap.prompt.system.ptr.is_null());
    assert!(tap.prompt.messages.is_null());
    assert_eq!(tap.prompt.messages_len, 0);
    assert_eq!(tap.prompt.message_count, 0);
    assert!(tap.prompt.body.ptr.is_null());
    // The signals are not grant-gated: they still ride.
    assert_eq!(tap.signals_len, 1);
}

/// THE SESSION CROSSES (ARCHITECT RULING 2026-10-03, Q-FOLD-A2A-2-PROJECT-POOL session half): the
/// request's opaque session reaches the hook's request view as octets, byte for byte; a request
/// that names none crosses an absent blob.
#[test]
fn a_decide_view_carries_the_request_session_as_octets() {
    let ctx = RoutingContext {
        pool: "p",
        budget_remaining: None,
        budget: &[],
    };
    let mut with = req(false);
    with.session = Some(b"ctx-\xff-1");
    let frame = DecideFrame::first(DecideView::build(&with, &[], &ctx));
    let s = frame.input().request.session;
    assert_eq!(s.fmt, crate::abi::mechanism::call::BLOB_OCTETS);
    assert_eq!(s.flags, 0);
    // SAFETY: the frame owns the bytes the view names for its life.
    let bytes = unsafe { std::slice::from_raw_parts(s.ptr, s.len) };
    assert_eq!(bytes, b"ctx-\xff-1");

    let none = DecideFrame::first(DecideView::build(&req(false), &[], &ctx)).input();
    assert_eq!(none.request.session.fmt, BLOB_ABSENT);
    assert!(none.request.session.ptr.is_null());
    assert_eq!(none.request.session.len, 0);
}
