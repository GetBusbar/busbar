// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The hook SDK: the 1.5.5 JSON a hook is handed is rebuilt byte for byte from the fixed views the

use super::*;
use crate::abi::hook::slot;
use crate::abi::hook::validate::{check_decide, check_transform};
use crate::abi::host::hook::{DecideFrame, DecideView, NotifyFrame};
use crate::hook_wire::{OP_DECIDE, OP_TRANSFORM};
use std::ffi::c_void;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::abi::host::conn::connector::{service, ConnectorSlots, SERVICES};
use crate::abi::host::service::{ServiceHead, ServiceOut};
use crate::abi::mechanism::call::{Blob, RawOutcome, FLAG_RESUME};
use crate::abi::mechanism::lifecycle::slot::{CANCEL, CLOSE, OPEN, VALIDATE};
use crate::abi::mechanism::lifecycle::{CancelIn, CancelOut, OpenIn, OpenOut, ValidateIn};
use crate::abi::mechanism::ticket::{HostCtx, HostTables, Ticket};
use crate::abi::sdk::conn::ConnFailure;
use crate::abi::sdk::door::Entry;
use crate::abi::sdk::exchange::{OpFailure, Request};
use crate::abi::sdk::{life, Safe};
use crate::hooks::BudgetBucketState as K;
use crate::signal::Signal;
use serde_json::json;

/// The host's `in`, lent to a reader as the trampoline lends it.
fn lend<T>(input: &T) -> Lent<'_, T> {
    // SAFETY: every `in` here is a frame's, which owns what it points at for the test's scope.
    unsafe { Lent::new(input) }
}

/// One slot, entered as the trampoline enters it.
fn call<S: SafeSlot>(
    instance: *mut std::ffi::c_void,
    index: u32,
    input: &S::In,
    out: &mut S::Out,
) -> Outcome {
    // SAFETY: the call contract: `instance` is NULL or what this SDK's `open` minted, and `input`
    // owns what it points at for the call.
    unsafe { <Safe<S> as Entry>::enter(instance, index, input, out) }
}

fn signals() -> SignalBag {
    let mut b = SignalBag::new();
    b.push(Signal::RequestedModel, SignalValue::Str("gpt".into()));
    b.push(Signal::RequestTotalChars, SignalValue::U64(11));
    b.push(Signal::CandidateErrorRate, SignalValue::F64(0.25));
    b.push(Signal::RequestSystemChars, SignalValue::I64(-3));
    b.push(Signal::RoutingPolicy, SignalValue::Bool(true));
    b
}

fn request(prompt: bool, user: bool) -> RoutingRequest<'static> {
    RoutingRequest {
        request_id: 42,
        pool: "pool-a",
        ingress_protocol: "acme",
        requested_model: None,
        message_count: 2,
        tool_count: 0,
        has_tools: true,
        total_chars: 17,
        system_chars: 0,
        max_tokens: Some(128),
        stream: false,
        prompt: prompt.then(|| PromptProjection {
            system: Some("be brief".into()),
            messages: vec![
                ("user".into(), "héllo \"q\"".into()),
                ("assistant".into(), "".into()),
            ],
        }),
        identity: user.then(|| CallerIdentity {
            key_id: Some("key-1".into()),
            key_name: None,
            user: Some("u@x".into()),
        }),
        signals: signals(),
        session: None,
    }
}

fn tags() -> Vec<String> {
    vec!["eu".into(), "baa".into()]
}

fn candidates(tags: &[String]) -> Vec<Candidate<'_>> {
    vec![
        Candidate {
            idx: 3,
            model: "m1",
            provider: "p1",
            weight: 2,
            context_max: Some(200_000),
            tier: Some("gold"),
            cost_per_mtok: Some(0.1 + 0.2),
            tags,
            latency_ms: Some(12.5),
            available_concurrency: 4,
            budget_remaining: Some(-1),
            rate_headroom: Some(0.75),
            signals: signals(),
        },
        Candidate {
            idx: 9,
            model: "m2",
            provider: "p2",
            weight: 1,
            context_max: None,
            tier: None,
            cost_per_mtok: None,
            tags: &[],
            latency_ms: None,
            available_concurrency: 0,
            budget_remaining: None,
            rate_headroom: None,
            signals: SignalBag::new(),
        },
    ]
}

fn budget() -> Vec<K> {
    vec![
        K {
            bucket_id: "key-1".into(),
            budget_group: None,
            pool: None,
            spend_micros_at_current_rate: 15_000_000,
            remaining_micros: None,
            window_start: 1_700_000_000,
            budget_period: "day".into(),
        },
        K {
            bucket_id: "group:g@m#pool-a".into(),
            budget_group: Some("g".into()),
            pool: Some("pool-a".into()),
            spend_micros_at_current_rate: 1,
            remaining_micros: Some(99),
            window_start: 5,
            budget_period: "month".into(),
        },
    ]
}

#[test]
fn routing_cost_terms_survive_the_hook_memory_view() {
    use crate::abi::hook::{
        SignalEntry, SignalValue as RawValue, SIGNAL_TAG_BOOL, SIGNAL_TAG_F64, SIGNAL_TAG_STR,
        SIGNAL_TAG_U64,
    };
    let class = "relay_frames";
    let entries = [
        SignalEntry {
            id: 10,
            tag: SIGNAL_TAG_BOOL,
            value: RawValue { boolean: 1 },
        },
        SignalEntry {
            id: 10,
            tag: SIGNAL_TAG_STR,
            value: RawValue {
                str_: AbiStr {
                    ptr: class.as_ptr(),
                    len: class.len(),
                },
            },
        },
        SignalEntry {
            id: 10,
            tag: SIGNAL_TAG_U64,
            value: RawValue { u64_: 17 },
        },
        SignalEntry {
            id: 10,
            tag: SIGNAL_TAG_F64,
            value: RawValue { f64_: 2.5 },
        },
    ];
    let req = request(false, false);
    let candidates = candidates(&[]);
    let ctx = RoutingContext {
        pool: "p",
        budget_remaining: None,
        budget: &[],
    };
    let frame = DecideFrame::first(DecideView::build(&req, &candidates, &ctx));
    let mut input = frame.input();
    // SAFETY: the frame owns both candidate rows for this test's scope.
    let mut dynamics =
        unsafe { std::slice::from_raw_parts(input.candidate_dynamics, input.candidates_len) }
            .to_vec();
    dynamics[0].signals = entries.as_ptr();
    dynamics[0].signals_len = entries.len();
    input.candidate_dynamics = dynamics.as_ptr();
    let decoded = Decoded::of(lend(&input));
    let values: Vec<_> = decoded.candidates[0]
        .signals
        .iter()
        .filter(|(signal, _)| signal.name() == "candidate_route_cost")
        .map(|(_, value)| value.clone())
        .collect();
    assert_eq!(
        values,
        vec![
            SignalValue::Bool(true),
            SignalValue::Str(class.into()),
            SignalValue::U64(17),
            SignalValue::F64(2.5)
        ]
    );
    assert_eq!(
        decoded.candidates[0].cost_per_mtok,
        candidates[0].cost_per_mtok
    );
}

/// The bytes 1.5.5's host sent, and the bytes the SDK rebuilds from the fixed view.
fn both(op: &'static str, prompt: bool, user: bool, with_cands: bool) -> (String, String) {
    let t = tags();
    let cands = if with_cands {
        candidates(&t)
    } else {
        Vec::new()
    };
    let b = budget();
    let ctx = RoutingContext {
        pool: "pool-a",
        budget_remaining: with_cands.then_some(7),
        budget: if with_cands { &b } else { &[] },
    };
    let req = request(prompt, user);

    let old = serde_json::to_value(crate::hook_wire::build(op, &req, &cands, &ctx)).unwrap();
    let old = serde_json::to_string(&old).unwrap();
    let frame = DecideFrame::first(DecideView::build(&req, &cands, &ctx));
    let new =
        serde_json::to_string(&Decoded::of(lend(&frame.input())).projection_json(op)).unwrap();
    (old, new)
}

#[test]
fn the_decide_projection_is_byte_identical_to_1_5_5() {
    for (prompt, user) in [(false, false), (true, false), (false, true), (true, true)] {
        let (old, new) = both(OP_DECIDE, prompt, user, true);
        assert_eq!(new, old, "prompt={prompt} user={user}");
    }
}

#[test]
fn the_transform_projection_is_byte_identical_to_1_5_5() {
    let (old, new) = both(OP_TRANSFORM, true, false, false);
    assert_eq!(new, old);
}

#[test]
fn the_notify_projection_is_byte_identical_to_1_5_5_for_request_and_stage_taps() {
    let ctx = RoutingContext {
        pool: "pool-a",
        budget_remaining: None,
        budget: &[],
    };
    for prompt in [false, true] {
        let mut req = request(prompt, false);
        req.identity = None;
        for stage in [
            None,
            Some(HookStageProjection {
                at: "response",
                model: Some("m1"),
                attempt_number: Some(2),
                remaining_candidates: Some(1),
                previous_failure: Some("upstream 503"),
                outcome: Some("rejected_by_gate"),
                status: Some(403),
            }),
            Some(HookStageProjection {
                at: "candidate",
                model: None,
                attempt_number: None,
                remaining_candidates: Some(0),
                previous_failure: None,
                outcome: None,
                status: None,
            }),
        ] {
            let mut wire = crate::hook_wire::build(OP_NOTIFY, &req, &[], &ctx);
            let frame = NotifyFrame::build(&req, stage.as_ref(), prompt);
            wire.stage = stage;
            let old = serde_json::to_string(&serde_json::to_value(wire).unwrap()).unwrap();
            let new =
                serde_json::to_string(&DecodedTap::of(lend(&frame.input())).projection_json())
                    .unwrap();
            assert_eq!(new, old, "prompt={prompt}");
        }
    }
}

#[test]
fn reject_beats_restrict_beats_abstain_beats_order() {
    let all = json!({"order": [1], "abstain": true, "restrict": {"tags_any": ["a"]},
                     "reject": {"status": 451, "message": "no"}});
    assert_eq!(
        lower_decide_reply(Ok(all)),
        Verdict::Reject {
            status: Some(451),
            message: "no".into()
        }
    );
    assert_eq!(
        lower_decide_reply(Ok(
            json!({"order": [1], "abstain": true, "restrict": {"tags_any": [" a "]}})
        )),
        Verdict::Restrict(vec!["a".into()])
    );
    assert_eq!(
        lower_decide_reply(Ok(json!({"order": [1], "abstain": true}))),
        Verdict::Abstain
    );
    assert_eq!(
        lower_decide_reply(Ok(json!({"order": [1, 0]}))),
        Verdict::Prefer(vec![1, 0])
    );
    assert_eq!(lower_decide_reply(Ok(json!({}))), Verdict::Abstain);
}

#[test]
fn an_explicit_false_or_null_verb_is_absent_and_a_bad_detail_still_rejects() {
    assert_eq!(
        lower_decide_reply(Ok(json!({"reject": false, "restrict": null, "order": [2]}))),
        Verdict::Prefer(vec![2])
    );

    assert_eq!(
        lower_decide_reply(Ok(json!({"reject": {"status": 70000, "message": 5}}))),
        Verdict::Reject {
            status: None,
            message: String::new()
        }
    );
    assert_eq!(
        lower_decide_reply(Ok(json!({"reject": true}))),
        Verdict::Reject {
            status: None,
            message: String::new()
        }
    );

    assert_eq!(
        lower_decide_reply(Ok(json!({"restrict": {"tags_any": []}}))),
        Verdict::Restrict(Vec::new())
    );
}

/// `decide`: each reply shape → 1.5.5's verdict.
#[test]
fn a_decide_reply_lowers_to_the_verdict_1_5_5s_host_read() {
    let reject = |status: Option<u16>, message: &str| Verdict::Reject {
        status,
        message: message.into(),
    };
    let rows = [
        (json!({}), Verdict::Abstain),
        (json!({"order": [1, 0]}), Verdict::Prefer(vec![1, 0])),
        (json!({"order": [1], "note": "x"}), Verdict::Prefer(vec![1])),
        (json!({"order": null}), Verdict::Abstain),
        (json!({"order": "x"}), Verdict::Abstain),
        (json!({"order": [-1]}), Verdict::Abstain),
        (json!({"order": [1.5]}), Verdict::Abstain),
        (json!({"abstain": "yes"}), Verdict::Abstain),
        (json!({"abstain": 1}), Verdict::Abstain),
        (json!({"abstain": true, "order": [1]}), Verdict::Abstain),
        (
            json!({"abstain": false, "order": [1]}),
            Verdict::Prefer(vec![1]),
        ),
        (json!(null), Verdict::Abstain),
        (json!([1]), Verdict::Abstain),
        (json!("garbage"), Verdict::Abstain),
        (json!(42), Verdict::Abstain),
        (json!(true), Verdict::Abstain),
        (
            json!({"reject": {"status": 403, "message": "no"}, "order": "x"}),
            Verdict::Abstain,
        ),
        (
            json!({"reject": {"status": 403}, "abstain": "yes"}),
            Verdict::Abstain,
        ),
        (
            json!({"restrict": {"tags_any": ["a"]}, "abstain": "yes"}),
            Verdict::Abstain,
        ),
        (
            json!({"reject": {"status": 451, "message": "no"}, "order": [1]}),
            reject(Some(451), "no"),
        ),
        (json!({"reject": true}), reject(None, "")),
        (json!({"reject": {"status": "451"}}), reject(None, "")),
        (
            json!({"reject": false, "order": [1]}),
            Verdict::Prefer(vec![1]),
        ),
        (
            json!({"reject": null, "order": [1]}),
            Verdict::Prefer(vec![1]),
        ),
        (
            json!({"restrict": {"tags_any": [" a ", ""]}, "order": [0]}),
            Verdict::Restrict(vec!["a".into()]),
        ),
        (json!({"restrict": {}}), Verdict::Restrict(Vec::new())),
        (json!({"restrict": "a"}), Verdict::Restrict(Vec::new())),
        (
            json!({"restrict": false, "order": [0]}),
            Verdict::Prefer(vec![0]),
        ),
        (
            json!({"rewrite": {"messages": [{"role": "user"}]}}),
            Verdict::Abstain,
        ),
    ];
    for (reply, want) in rows {
        assert_eq!(
            lower_decide_reply(Ok(reply.clone())),
            want,
            "1.5.5's host read the decide reply {reply} as {want:?}"
        );
    }

    assert_eq!(
        lower_decide_reply(Err("down".into())),
        Verdict::Failed("down".into())
    );
}

/// `transform`: each reply shape → 1.5.5's verdict.
#[test]
fn a_transform_reply_lowers_to_the_verdict_1_5_5s_host_read() {
    let rw = json!({"messages": [{"role": "user", "content": "x"}]});
    let rewrite = |v: &serde_json::Value| RewriteVerdict::Rewrite(serde_json::to_vec(v).unwrap());
    let reject = |status: Option<u16>, message: &str| RewriteVerdict::Reject {
        status,
        message: message.into(),
    };
    let rows = [
        (json!({}), RewriteVerdict::Abstain),
        (json!({"rewrite": rw}), rewrite(&rw)),
        (json!({"rewrite": rw, "note": 1}), rewrite(&rw)),
        (
            json!({"order": [1], "restrict": {"tags_any": ["a"]}}),
            RewriteVerdict::Abstain,
        ),
        (json!({"rewrite": null}), RewriteVerdict::Abstain),
        (json!({"rewrite": false}), RewriteVerdict::Abstain),
        (json!({"rewrite": {}}), RewriteVerdict::Abstain),
        (
            json!({"rewrite": {"messages": []}}),
            RewriteVerdict::Abstain,
        ),
        (
            json!({"rewrite": {"messages": "hi"}}),
            RewriteVerdict::Abstain,
        ),
        (json!({"abstain": 1}), RewriteVerdict::Abstain),
        (
            json!({"rewrite": rw, "order": "x"}),
            RewriteVerdict::Abstain,
        ),
        (
            json!({"reject": {"status": 451}, "abstain": "yes"}),
            RewriteVerdict::Abstain,
        ),
        (json!(null), RewriteVerdict::Abstain),
        (json!([1]), RewriteVerdict::Abstain),
        (json!("garbage"), RewriteVerdict::Abstain),
        (
            json!({"reject": {"status": 451, "message": "s"}, "rewrite": rw}),
            reject(Some(451), "s"),
        ),
        (json!({"reject": true}), reject(None, "")),
        (json!({"reject": false, "rewrite": rw}), rewrite(&rw)),
    ];
    for (reply, want) in rows {
        assert_eq!(
            lower_transform_reply(Ok(reply.clone())),
            want,
            "1.5.5's host read the transform reply {reply} as {want:?}"
        );
    }

    assert_eq!(
        lower_transform_reply(Err("down".into())),
        RewriteVerdict::Failed("down".into())
    );
}

#[test]
fn transform_reject_beats_rewrite_and_the_rewrite_crosses_as_its_json() {
    assert_eq!(
        lower_transform_reply(Ok(
            json!({"reject": {"status": 451, "message": "s"}, "rewrite": {}})
        )),
        RewriteVerdict::Reject {
            status: Some(451),
            message: "s".into()
        }
    );
    let rw = json!({"messages": [{"role": "user", "content": "x"}]});
    assert_eq!(
        lower_transform_reply(Ok(json!({"rewrite": rw.clone()}))),
        RewriteVerdict::Rewrite(serde_json::to_vec(&rw).unwrap())
    );
    assert_eq!(
        lower_transform_reply(Ok(json!({"rewrite": null}))),
        RewriteVerdict::Abstain
    );
}

fn frame_with(caps: crate::abi::host::hook::Caps) -> std::sync::Arc<DecideFrame> {
    let t = tags();
    let ctx = RoutingContext {
        pool: "pool-a",
        budget_remaining: None,
        budget: &[],
    };
    DecideFrame::new(
        DecideView::build(&request(false, false), &candidates(&t), &ctx),
        caps,
    )
}

fn zeroed<T>() -> T {
    // SAFETY: every `out` here is plain integers, raw pointers and plain structs of those.
    unsafe { std::mem::zeroed() }
}

fn caps(order: usize, text: usize) -> crate::abi::host::hook::Caps {
    crate::abi::host::hook::Caps {
        order,
        reject_message: text,
        restrict_tags: text,
        rewrite: text,
    }
}

#[test]
fn every_verdict_writes_an_answer_the_validator_accepts_and_the_host_reads_back() {
    let frame = frame_with(caps(2, 64));
    let i = frame.input();
    for v in [
        Verdict::Prefer(vec![9, 3]),
        Verdict::Prefer(Vec::new()),
        Verdict::Abstain,
        Verdict::Reject {
            status: Some(451),
            message: "nope".into(),
        },
        Verdict::Reject {
            status: None,
            message: String::new(),
        },
        Verdict::Restrict(vec!["eu".into(), "baa".into()]),
        Verdict::Restrict(Vec::new()),
        Verdict::Failed("down".into()),
    ] {
        let mut out: DecideOut = zeroed();
        let o = write_verdict(&v, lend(&i), &mut out);
        out.head.outcome = crate::abi::mechanism::call::RawOutcome::of(o);
        assert_eq!(
            check_decide(&out, i.reject_message_cap, i.restrict_tags_cap, i.order_cap),
            Ok(()),
            "{v:?}"
        );
        match &v {
            Verdict::Prefer(o) if !o.is_empty() => {
                assert_eq!(frame.order(out.order_written), *o)
            }
            Verdict::Reject { message, .. } => {
                assert_eq!(frame.reject_message(out.reject_message_written), *message)
            }
            Verdict::Restrict(t) => {
                assert_eq!(frame.restrict_tags(out.restrict_tags_written), *t)
            }
            _ => {}
        }
    }
}

#[test]
fn a_buffer_too_small_is_the_one_short_answer_with_nothing_written() {
    let frame = frame_with(caps(1, 3));
    let i = frame.input();
    let mut out: DecideOut = zeroed();
    let v = Verdict::Prefer(vec![9, 3]);
    let o = write_verdict(&v, lend(&i), &mut out);
    assert_eq!(o, Outcome::Failed);
    assert_eq!((out.order_needed, out.order_written), (2, 0));
    out.head.outcome = crate::abi::mechanism::call::RawOutcome::of(o);
    assert_eq!(
        check_decide(&out, i.reject_message_cap, i.restrict_tags_cap, i.order_cap),
        Ok(())
    );

    let again = frame.regrown_decide(&out);
    let mut out2: DecideOut = zeroed();
    assert_eq!(
        write_verdict(&v, lend(&again.input()), &mut out2),
        Outcome::Ready
    );
    assert_eq!(again.order(out2.order_written), vec![9, 3]);

    let mut t: TransformOut = zeroed();
    let o = write_rewrite(
        &RewriteVerdict::Rewrite(b"{\"messages\":[1]}".to_vec()),
        lend(&i),
        &mut t,
    );
    assert_eq!(
        (o, t.rewrite_needed, t.rewrite_written),
        (Outcome::Failed, 16, 0)
    );
    t.head.outcome = crate::abi::mechanism::call::RawOutcome::of(o);
    assert_eq!(
        check_transform(&t, i.reject_message_cap, i.rewrite_cap),
        Ok(())
    );
}

/// A typed hook: prefers the candidates in reverse, and records what its tap saw.
struct Reverse(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

impl Hook for Reverse {
    fn decide(&self, view: &Decoded<'_>, _: &Op<'_>) -> Poll<Verdict> {
        Poll::Ready(Verdict::Prefer(
            view.candidates.iter().rev().map(|c| c.idx).collect(),
        ))
    }
    fn notify(&self, tap: &DecodedTap<'_>, _: &Op<'_>) -> Poll<()> {
        self.0
            .lock()
            .unwrap()
            .push(tap.projection_json().to_string());
        Poll::Ready(())
    }
}

static SEEN: std::sync::OnceLock<std::sync::Arc<std::sync::Mutex<Vec<String>>>> =
    std::sync::OnceLock::new();

struct OpenReverse;
impl HookOpen for OpenReverse {
    fn open(_: &str) -> Result<Box<dyn Hook>, String> {
        Ok(Box::new(Reverse(
            SEEN.get_or_init(Default::default).clone(),
        )))
    }
}

/// An instance of `P`'s hook, opened through the generic lifecycle over `input`.
fn opened_with<P: HookOpen>(input: &OpenIn) -> *mut std::ffi::c_void {
    let mut out: OpenOut = zeroed();
    assert_eq!(
        call::<life::Open<HookLife<P>>>(std::ptr::null_mut(), OPEN, input, &mut out),
        Outcome::Ready
    );
    out.instance
}

fn opened() -> *mut std::ffi::c_void {
    opened_with::<OpenReverse>(&zeroed())
}

fn closed<P: HookOpen>(p: *mut std::ffi::c_void) {
    let mut out: OutHead = zeroed();
    let _ = call::<life::Close<HookLife<P>>>(p, CLOSE, &zeroed(), &mut out);
}

/// The text a FAILED answer's head names, while its instance keeps it.
fn error_text(head: &OutHead) -> String {
    // SAFETY: the answering instance (or a `'static` text) holds it for the scope.
    let bytes = unsafe { std::slice::from_raw_parts(head.error.ptr, head.error.len) };
    String::from_utf8_lossy(bytes).into_owned()
}

/// A typed [`Hook`] reads the host's view as owned values through the slot, and answers into the
#[test]
fn the_decide_slot_hands_a_typed_hook_the_decoded_view() {
    let p = opened();
    let frame = frame_with(caps(4, 64));
    let mut out: DecideOut = zeroed();
    assert_eq!(
        call::<Decide<OpenReverse>>(p, slot::DECIDE, &frame.input(), &mut out),
        Outcome::Ready
    );
    let mut want: Vec<usize> = frame.view().candidate_idx().to_vec();
    want.reverse();
    assert_eq!(frame.order(out.order_written), want);
    closed::<OpenReverse>(p);
}

/// RED: a host view whose prompt lists do not hold (a present prompt claiming messages behind a
#[test]
fn red_a_broken_host_view_is_a_fault_not_a_read() {
    let p = opened();
    let frame = frame_with(caps(4, 64));
    let mut bad = frame.input();
    bad.present |= VIEW_HAS_PROMPT;
    bad.prompt.messages = std::ptr::null();
    bad.prompt.messages_len = 3;
    bad.prompt.message_count = 3;
    let mut d: DecideOut = zeroed();
    assert_eq!(
        call::<Decide<OpenReverse>>(p, slot::DECIDE, &bad, &mut d),
        Outcome::Fault
    );
    let mut t: TransformOut = zeroed();
    assert_eq!(
        call::<Transform<OpenReverse>>(p, slot::TRANSFORM, &bad, &mut t),
        Outcome::Fault
    );

    let tap = NotifyFrame::build(&request(true, false), None, true);
    let mut bad_tap = tap.input();
    bad_tap.signals = std::ptr::null();
    bad_tap.signals_len = 2;
    let mut o: OutHead = zeroed();
    assert_eq!(
        call::<Notify<OpenReverse>>(p, slot::NOTIFY, &bad_tap, &mut o),
        Outcome::Fault
    );

    let before = SEEN.get().unwrap().lock().unwrap().len();
    assert_eq!(
        call::<Notify<OpenReverse>>(p, slot::NOTIFY, &tap.input(), &mut o),
        Outcome::Ready
    );
    let seen = SEEN.get().unwrap().lock().unwrap();
    assert_eq!(seen.len(), before + 1);
    assert!(seen[before].contains("\"op\":\"notify\""));
    drop(seen);
    closed::<OpenReverse>(p);
}

/// An instance-less failure (`validate` over settings that are not an object) answers FAILED with
#[test]
fn a_validate_failure_states_its_text() {
    let raw = b"[1]";
    let mut input: ValidateIn = zeroed();
    input.settings = Blob {
        ptr: raw.as_ptr(),
        len: raw.len(),
        fmt: BLOB_JSON,
        flags: 0,
    };
    let mut out: OutHead = zeroed();
    assert_eq!(
        call::<life::Validate<HookLife<OpenReverse>>>(
            std::ptr::null_mut(),
            VALIDATE,
            &input,
            &mut out
        ),
        Outcome::Failed
    );
    assert_eq!(error_text(&out), "settings: must be a JSON object");
}

/// A hook whose `open` refuses any settings naming `"refuse"`.
struct OpenPicky;
impl HookOpen for OpenPicky {
    fn open(settings: &str) -> Result<Box<dyn Hook>, String> {
        if settings.contains("refuse") {
            return Err("settings: `refuse` is not a setting this hook reads".to_owned());
        }
        Ok(Box::new(Forward))
    }
}

/// `validate` over `raw` for `P`'s hook, lent a reason buffer as the host's dispatcher lends every
fn validated<P: HookOpen>(raw: &[u8]) -> (Outcome, String) {
    let mut reason = vec![0_u8; 1024];
    let mut input: ValidateIn = zeroed();
    input.settings = Blob {
        ptr: raw.as_ptr(),
        len: raw.len(),
        fmt: BLOB_JSON,
        flags: 0,
    };
    input.err_buf = reason.as_mut_ptr();
    input.err_cap = reason.len();
    let mut out: OutHead = zeroed();
    let o = call::<life::Validate<HookLife<P>>>(std::ptr::null_mut(), VALIDATE, &input, &mut out);
    let text = if o == Outcome::Ready {
        String::new()
    } else {
        error_text(&out)
    };
    (o, text)
}

/// Validate refuses what open refuses.
#[test]
fn validate_refuses_what_open_refuses() {
    assert_eq!(
        validated::<OpenPicky>(br#"{"refuse": true}"#),
        (
            Outcome::Failed,
            "settings: `refuse` is not a setting this hook reads".to_owned()
        )
    );
    assert_eq!(
        validated::<OpenPicky>(br#"{"fine": true}"#),
        (Outcome::Ready, String::new())
    );
    assert_eq!(validated::<OpenPicky>(b""), (Outcome::Ready, String::new()));
}

#[test]
fn red_the_content_body_a_hook_sees_is_the_hosts_own_bytes() {
    std::thread_local! {
        static SAW: std::cell::Cell<(usize, usize, usize)> = const { std::cell::Cell::new((0, 0, 0)) };
    }
    struct Peek;
    impl Hook for Peek {
        fn decide(&self, view: &Decoded<'_>, _: &Op<'_>) -> Poll<Verdict> {
            let p = view.prompt.as_ref().expect("granted");
            let body = p.body.expect("a body");
            let text = match &p.messages[0].1 {
                Cow::Borrowed(t) => t.as_ptr() as usize,
                Cow::Owned(_) => 0,
            };
            SAW.with(|s| s.set((body.as_ptr() as usize, body.len(), text)));
            Poll::Ready(Verdict::Abstain)
        }
    }
    struct OpenPeek;
    impl HookOpen for OpenPeek {
        fn open(_: &str) -> Result<Box<dyn Hook>, String> {
            Ok(Box::new(Peek))
        }
    }
    let t = tags();
    let ctx = RoutingContext {
        pool: "pool-a",
        budget_remaining: None,
        budget: &[],
    };
    let frame = DecideFrame::first(DecideView::build(
        &request(true, false),
        &candidates(&t),
        &ctx,
    ));
    let raw = br#"{"messages":[{"role":"user","content":"hi"}]}"#.to_vec();
    let mut input = frame.input();
    input.prompt.body = Blob {
        ptr: raw.as_ptr(),
        len: raw.len(),
        fmt: crate::abi::mechanism::call::BLOB_OCTETS,
        flags: 0,
    };
    let host_text = input.prompt.messages;
    let p = opened_with::<OpenPeek>(&zeroed());
    let mut out: DecideOut = zeroed();
    assert_eq!(
        call::<Decide<OpenPeek>>(p, slot::DECIDE, &input, &mut out),
        Outcome::Ready
    );
    let (ptr, len, text) = SAW.with(std::cell::Cell::get);
    assert_eq!(ptr, raw.as_ptr() as usize, "the body was copied");
    assert_eq!(len, raw.len());
    // SAFETY: the frame's message list, alive for the scope.
    let host_text_ptr = unsafe { (*host_text).text.ptr } as usize;
    assert_eq!(text, host_text_ptr, "the message text was copied");
    closed::<OpenPeek>(p);
}

thread_local! {
    /// Calls on this test thread: the fixture invokes ESTABLISH synchronously.
    static ESTABLISHED: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}
/// What the scripted far end answers once the established stream completes.
const DOWN: &str = "the far end is down";

/// A scripted connector ESTABLISH: every even entry pends (the host finishes it off the op); the
extern "C" fn establish_pends(
    _: HostCtx,
    input: *const c_void,
    out: *mut ServiceOut,
) -> RawOutcome {
    // SAFETY: every service `in` leads with a `ServiceHead`; `out` is the SDK's, live for the call.
    let (head, out) = unsafe { (*input.cast::<ServiceHead>(), &mut *out) };
    assert_eq!((head.op, head.handle.seq), (service::ESTABLISH, 0));
    let entered = ESTABLISHED.with(|calls| {
        let entered = calls.get();
        calls.set(entered + 1);
        entered
    });
    let o = if entered.is_multiple_of(2) {
        Outcome::Pending
    } else {
        out.error = AbiStr {
            ptr: DOWN.as_ptr(),
            len: DOWN.len(),
        };
        Outcome::Failed
    };
    out.outcome = RawOutcome::of(o);
    RawOutcome::of(o)
}

static PENDING_SLOTS: ConnectorSlots = ConnectorSlots {
    size: std::mem::size_of::<ConnectorSlots>() as u32,
    slots: SERVICES,
    establish: Some(establish_pends),
    reject_endpoint: None,
    side_stream: None,
    read: None,
    write: None,
    upgrade_secure: None,
    facts: None,
    checkout: None,
    checkin: None,
    close: None,
    random: None,
    identity: None,
    read_reply: None,
    write_request: None,
};

/// A hook that asks the far end on every `decide`: its one exchange's answer is its verdict.
struct Forward;
impl Hook for Forward {
    fn decide(&self, _: &Decoded<'_>, op: &Op<'_>) -> Poll<Verdict> {
        op.exchange(0, Some("http://far.example"), || {
            Ok({
                let mut request = Request::default();
                request.method = b"POST".to_vec();
                request.target = b"/".to_vec();
                request
            })
        })
        .map(|r| match r {
            Ok(reply) => Verdict::Prefer(vec![usize::from(reply.status)]),
            Err(e) => Verdict::Failed(e.to_string()),
        })
    }
}
struct OpenForward;
impl HookOpen for OpenForward {
    fn open(_: &str) -> Result<Box<dyn Hook>, String> {
        Ok(Box::new(Forward))
    }
}

const TICKET: Ticket = Ticket {
    slot: 5,
    generation: 1,
};

#[test]
fn red_a_hook_waiting_on_its_exchange_pends_and_resumes_on_the_wake() {
    ESTABLISHED.set(0);
    let tables = HostTables {
        size: std::mem::size_of::<HostTables>() as u32,
        _reserved: 0,
        ctx: HostCtx::NONE,
        wake: None,
        conns: &PENDING_SLOTS,
        services: std::ptr::null(),
        io: std::ptr::null(),
    };
    let mut open: OpenIn = zeroed();
    open.host = &tables;
    let p = opened_with::<OpenForward>(&open);
    let frame = frame_with(caps(4, 64));
    let mut input = frame.input();
    input.head.ticket = TICKET;

    let mut out: DecideOut = zeroed();
    assert_eq!(
        call::<Decide<OpenForward>>(p, slot::DECIDE, &input, &mut out),
        Outcome::Pending
    );
    assert_eq!(
        (out.verbs, out.order_written),
        (0, 0),
        "PENDING writes nothing"
    );
    assert_eq!(ESTABLISHED.get(), 1);

    input.head.flags = FLAG_RESUME;
    let mut out: DecideOut = zeroed();
    assert_eq!(
        call::<Decide<OpenForward>>(p, slot::DECIDE, &input, &mut out),
        Outcome::Failed
    );
    assert_eq!(error_text(&out.head), DOWN);
    assert_eq!(ESTABLISHED.get(), 2);

    let mut none = frame.input();
    none.head.ticket = Ticket::NONE;
    let mut out: DecideOut = zeroed();
    assert_eq!(
        call::<Decide<OpenForward>>(p, slot::DECIDE, &none, &mut out),
        Outcome::Failed
    );
    assert_eq!(error_text(&out.head), ConnFailure::NoTicket.to_string());

    input.head.flags = 0;
    let mut out: DecideOut = zeroed();
    assert_eq!(
        call::<Decide<OpenForward>>(p, slot::DECIDE, &input, &mut out),
        Outcome::Pending
    );
    let mut c: CancelIn = zeroed();
    c.ticket = TICKET;
    let mut co: CancelOut = zeroed();
    assert_eq!(
        call::<life::Cancel<HookLife<OpenForward>>>(p, CANCEL, &c, &mut co),
        Outcome::Ready
    );
    assert_eq!(co.disposition, cancel::ABORTED);
    closed::<OpenForward>(p);
}

/// The stream the closing connector's ESTABLISH answers.
const HELD_STREAM: u64 = 9;
/// What the closing connector's CLOSE was handed: the stream and the ticket it came on.
static CLOSED: std::sync::Mutex<Vec<(u64, Ticket)>> = std::sync::Mutex::new(Vec::new());
/// The same, for the connector whose ESTABLISH never completes.
static DIALLING_CLOSED: std::sync::Mutex<Vec<(u64, Ticket)>> = std::sync::Mutex::new(Vec::new());

/// Answer `o` in the SDK's `out`, with `value`.
fn answered(out: *mut ServiceOut, o: Outcome, value: u64) -> RawOutcome {
    // SAFETY: the SDK's `out`, live for the call.
    let out = unsafe { &mut *out };
    out.value = value;
    out.outcome = RawOutcome::of(o);
    RawOutcome::of(o)
}

/// An ESTABLISH that answers [`HELD_STREAM`] at once.
extern "C" fn establish_at_once(_: HostCtx, i: *const c_void, o: *mut ServiceOut) -> RawOutcome {
    // SAFETY: every service `in` leads with a `ServiceHead`.
    assert_eq!(unsafe { *i.cast::<ServiceHead>() }.op, service::ESTABLISH);
    answered(o, Outcome::Ready, HELD_STREAM)
}

/// An ESTABLISH (or a request piece) that never completes: the op pends on it.
extern "C" fn never_completes(_: HostCtx, _: *const c_void, o: *mut ServiceOut) -> RawOutcome {
    answered(o, Outcome::Pending, 0)
}

/// Log the CLOSE `i` names into `log`.
fn log_close(log: &std::sync::Mutex<Vec<(u64, Ticket)>>, i: *const c_void) {
    // SAFETY: a CLOSE's `in` is a `StreamIn`.
    let i = unsafe {
        i.cast::<crate::abi::host::conn::connector::StreamIn>()
            .read()
    };
    let mut log = log
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    log.push((i.stream, i.head.handle.ticket));
}

extern "C" fn close_logged(_: HostCtx, i: *const c_void, o: *mut ServiceOut) -> RawOutcome {
    log_close(&CLOSED, i);
    answered(o, Outcome::Ready, 0)
}

extern "C" fn close_logged_dialling(
    _: HostCtx,
    i: *const c_void,
    o: *mut ServiceOut,
) -> RawOutcome {
    log_close(&DIALLING_CLOSED, i);
    answered(o, Outcome::Ready, 0)
}

/// A connector whose ESTABLISH answers a stream at once and whose request never completes.
static CLOSING_SLOTS: ConnectorSlots = ConnectorSlots {
    size: std::mem::size_of::<ConnectorSlots>() as u32,
    slots: SERVICES,
    establish: Some(establish_at_once),
    reject_endpoint: None,
    side_stream: None,
    read: None,
    write: None,
    upgrade_secure: None,
    facts: None,
    checkout: None,
    checkin: None,
    close: Some(close_logged),
    random: None,
    identity: None,
    read_reply: None,
    write_request: Some(never_completes),
};

/// A connector whose ESTABLISH never completes.
static DIALLING_SLOTS: ConnectorSlots = ConnectorSlots {
    size: std::mem::size_of::<ConnectorSlots>() as u32,
    slots: SERVICES,
    establish: Some(never_completes),
    reject_endpoint: None,
    side_stream: None,
    read: None,
    write: None,
    upgrade_secure: None,
    facts: None,
    checkout: None,
    checkin: None,
    close: Some(close_logged_dialling),
    random: None,
    identity: None,
    read_reply: None,
    write_request: None,
};

/// Open a [`Forward`] hook over `conns`, run one `decide` to PENDING on [`TICKET`], cancel that
fn cancel_a_pending_decide(conns: &'static ConnectorSlots) {
    let tables = HostTables {
        size: std::mem::size_of::<HostTables>() as u32,
        _reserved: 0,
        ctx: HostCtx::NONE,
        wake: None,
        conns,
        services: std::ptr::null(),
        io: std::ptr::null(),
    };
    let mut open: OpenIn = zeroed();
    open.host = &tables;
    let p = opened_with::<OpenForward>(&open);
    let frame = frame_with(caps(4, 64));
    let mut input = frame.input();
    input.head.ticket = TICKET;
    let mut out: DecideOut = zeroed();
    assert_eq!(
        call::<Decide<OpenForward>>(p, slot::DECIDE, &input, &mut out),
        Outcome::Pending
    );
    let mut c: CancelIn = zeroed();
    c.ticket = TICKET;
    let mut co: CancelOut = zeroed();
    assert_eq!(
        call::<life::Cancel<HookLife<OpenForward>>>(p, CANCEL, &c, &mut co),
        Outcome::Ready
    );
    assert_eq!(co.disposition, cancel::ABORTED);
    closed::<OpenForward>(p);
}

#[test]
fn a_cancelled_exchange_closes_the_stream_it_established() {
    cancel_a_pending_decide(&CLOSING_SLOTS);
    let seen = CLOSED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert_eq!(seen, vec![(HELD_STREAM, Ticket::NONE)]);
}

/// GREEN twin: an exchange cancelled before its stream was established closes nothing: the
#[test]
fn a_cancelled_exchange_with_no_stream_closes_nothing() {
    cancel_a_pending_decide(&DIALLING_SLOTS);
    let seen = DIALLING_CLOSED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert!(seen.is_empty(), "{seen:?}");
}

/// A hook handed no connector answers its exchange unarmed, at once.
#[test]
fn a_hook_with_no_connector_answers_unarmed() {
    let p = opened_with::<OpenForward>(&zeroed());
    let frame = frame_with(caps(4, 64));
    let mut input = frame.input();
    input.head.ticket = TICKET;
    let mut out: DecideOut = zeroed();
    assert_eq!(
        call::<Decide<OpenForward>>(p, slot::DECIDE, &input, &mut out),
        Outcome::Failed
    );
    assert_eq!(error_text(&out.head), ConnFailure::Unarmed.to_string());
    closed::<OpenForward>(p);
}

/// What [`OpenRecording`] was handed, in order.
static OPENED_WITH: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

struct OpenRecording;
impl HookOpen for OpenRecording {
    fn open(settings: &str) -> Result<Box<dyn Hook>, String> {
        OPENED_WITH.lock().unwrap().push(settings.to_owned());
        Ok(Box::new(Forward))
    }
}

#[test]
fn red_open_hands_the_plugin_its_settings_verbatim_an_empty_blob_stays_empty() {
    let empty = opened_with::<OpenRecording>(&zeroed());
    let raw = br#"{"url": "https://x"}"#;
    let mut input: OpenIn = zeroed();
    input.settings = Blob {
        ptr: raw.as_ptr(),
        len: raw.len(),
        fmt: BLOB_JSON,
        flags: 0,
    };
    let present = opened_with::<OpenRecording>(&input);
    assert_eq!(
        *OPENED_WITH.lock().unwrap(),
        vec![String::new(), r#"{"url": "https://x"}"#.to_owned()]
    );
    closed::<OpenRecording>(empty);
    closed::<OpenRecording>(present);
}

#[test]
fn a_hook_reads_the_session_and_the_1_5_5_projection_does_not_carry_it() {
    let ctx = RoutingContext {
        pool: "pool-a",
        budget_remaining: None,
        budget: &[],
    };
    let mut req = request(true, true);
    let old = serde_json::to_string(
        &serde_json::to_value(crate::hook_wire::build(OP_DECIDE, &req, &[], &ctx)).unwrap(),
    )
    .unwrap();
    req.session = Some(b"ctx-1");
    let frame = DecideFrame::first(DecideView::build(&req, &[], &ctx));
    let input = frame.input();
    let decoded = Decoded::of(lend(&input));
    assert_eq!(decoded.session, Some(&b"ctx-1"[..]));
    assert_eq!(
        serde_json::to_string(&decoded.projection_json(OP_DECIDE)).unwrap(),
        old
    );

    let frame = DecideFrame::first(DecideView::build(&request(true, true), &[], &ctx));
    let input = frame.input();
    assert_eq!(Decoded::of(lend(&input)).session, None);
}

/// How often [`Asks`] ran its `decide` / `transform`: each run is one POST to the far end.
static ASKED: AtomicU32 = AtomicU32::new(0);

/// A hook that asks the far end on every run (counted in [`ASKED`]) and answers more than the
struct Asks;
impl Hook for Asks {
    fn decide(&self, _: &Decoded<'_>, _: &Op<'_>) -> Poll<Verdict> {
        ASKED.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(Verdict::Prefer(vec![3, 2, 1, 0]))
    }
    fn transform(&self, _: &Decoded<'_>, _: &Op<'_>) -> Poll<RewriteVerdict> {
        ASKED.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(RewriteVerdict::Rewrite(
            br#"{"messages":[{"role":"user","content":"a longer rewrite"}]}"#.to_vec(),
        ))
    }
}
struct OpenAsks;
impl HookOpen for OpenAsks {
    fn open(_: &str) -> Result<Box<dyn Hook>, String> {
        Ok(Box::new(Asks))
    }
}

/// A short-buffer retry returns the first verdict without rerunning the hook.
#[test]
fn red_the_short_buffer_re_call_answers_the_first_verdict_without_running_the_hook_again() {
    let p = opened_with::<OpenAsks>(&zeroed());
    let frame = frame_with(caps(1, 4));
    let mut input = frame.input();
    input.head.ticket = TICKET;
    let mut out: DecideOut = zeroed();
    assert_eq!(
        call::<Decide<OpenAsks>>(p, slot::DECIDE, &input, &mut out),
        Outcome::Failed
    );
    assert_eq!((out.order_needed, out.order_written), (4, 0));
    let grown = frame.regrown_decide(&out);
    let mut again = grown.input();
    again.head.ticket = TICKET;
    let mut out2: DecideOut = zeroed();
    assert_eq!(
        call::<Decide<OpenAsks>>(p, slot::DECIDE, &again, &mut out2),
        Outcome::Ready
    );
    assert_eq!(grown.order(out2.order_written), vec![3, 2, 1, 0]);
    assert_eq!(
        ASKED.load(Ordering::SeqCst),
        1,
        "decide ran again on the re-call"
    );

    let mut t: TransformOut = zeroed();
    assert_eq!(
        call::<Transform<OpenAsks>>(p, slot::TRANSFORM, &input, &mut t),
        Outcome::Failed
    );
    let grown = frame.regrown_transform(&t);
    let mut again = grown.input();
    again.head.ticket = TICKET;
    let mut t2: TransformOut = zeroed();
    assert_eq!(
        call::<Transform<OpenAsks>>(p, slot::TRANSFORM, &again, &mut t2),
        Outcome::Ready
    );
    assert_eq!(
        ASKED.load(Ordering::SeqCst),
        2,
        "transform ran again on the re-call"
    );

    let mut out: DecideOut = zeroed();
    assert_eq!(
        call::<Decide<OpenAsks>>(p, slot::DECIDE, &input, &mut out),
        Outcome::Failed
    );
    let regrown = frame.regrown_decide(&out);
    let mut later = regrown.input();
    later.head.ticket = Ticket {
        generation: TICKET.generation + 1,
        ..TICKET
    };
    let mut out2: DecideOut = zeroed();
    assert_eq!(
        call::<Decide<OpenAsks>>(p, slot::DECIDE, &later, &mut out2),
        Outcome::Ready
    );
    assert_eq!(ASKED.load(Ordering::SeqCst), 4);
    closed::<OpenAsks>(p);
}

/// A hook that refuses any pushed settings naming `"bad"`, saying why.
struct Picky;
impl Hook for Picky {
    fn configure(
        &self,
        settings: &serde_json::Map<String, serde_json::Value>,
        _: u64,
    ) -> Result<(), String> {
        if settings.contains_key("bad") {
            return Err("settings.bad is not a setting this hook reads".to_owned());
        }
        Ok(())
    }
}
struct OpenPickyConfigure;
impl HookOpen for OpenPickyConfigure {
    fn open(_: &str) -> Result<Box<dyn Hook>, String> {
        Ok(Box::new(Picky))
    }
}

/// `configure` over `raw` at `version` on `p`: its outcome, the version it acked and its text.
fn configured<P: HookOpen>(p: *mut c_void, raw: &[u8], version: u64) -> (Outcome, u64, String) {
    let mut input: crate::abi::hook::ConfigureIn = zeroed();
    input.version = version;
    input.settings = Blob {
        ptr: raw.as_ptr(),
        len: raw.len(),
        fmt: BLOB_JSON,
        flags: 0,
    };
    let mut out: crate::abi::hook::ConfigureOut = zeroed();
    let o = call::<Configure<P>>(p, slot::CONFIGURE, &input, &mut out);
    let text = if o == Outcome::Ready {
        String::new()
    } else {
        error_text(&out.head)
    };
    (o, out.acked_version, text)
}

#[test]
fn configure_sdk_leases_the_atomic_checkpoint_and_preserves_the_pushed_ack_version() {
    struct Checkpoint;
    impl Hook for Checkpoint {
        fn configure(
            &self,
            _: &serde_json::Map<String, serde_json::Value>,
            _: u64,
        ) -> Result<(), String> {
            panic!("the checkpoint adapter must make one atomic call, not configure then snapshot")
        }
        fn configure_checkpoint(
            &self,
            _: &serde_json::Map<String, serde_json::Value>,
            _: u64,
        ) -> Result<Option<ConfigureCheckpoint>, String> {
            ConfigureCheckpoint::new(9, 12, br#"{"credential":"fixture-secret"}"#.to_vec())
                .map(Some)
        }
    }
    struct OpenCheckpoint;
    impl HookOpen for OpenCheckpoint {
        fn open(_: &str) -> Result<Box<dyn Hook>, String> {
            Ok(Box::new(Checkpoint))
        }
    }
    let instance = opened_with::<OpenCheckpoint>(&zeroed());
    let raw = b"{}";
    let mut input: ConfigureIn = zeroed();
    input.version = 7;
    input.settings = Blob {
        ptr: raw.as_ptr(),
        len: raw.len(),
        fmt: BLOB_JSON,
        flags: 0,
    };
    let mut out: ConfigureOut = zeroed();
    assert_eq!(
        call::<Configure<OpenCheckpoint>>(instance, slot::CONFIGURE, &input, &mut out),
        Outcome::Ready
    );
    assert_eq!(
        out.acked_version, 7,
        "the pushed version is still acknowledged exactly"
    );
    assert_ne!(out.head.lease, 0);
    assert_ne!(
        out.head.extensions.flags & crate::abi::mechanism::call::BLOB_SECRET,
        0
    );
    // SAFETY: the SDK's returned extension remains alive under this unreleased lease.
    let bytes =
        unsafe { std::slice::from_raw_parts(out.head.extensions.ptr, out.head.extensions.len) };
    let checkpoint = ConfigureCheckpoint::decode(bytes).unwrap().unwrap();
    assert_eq!((checkpoint.revision, checkpoint.settings_version), (9, 12));
    assert_eq!(checkpoint.settings(), br#"{"credential":"fixture-secret"}"#);
    let mut release: crate::abi::mechanism::lifecycle::ReleaseIn = zeroed();
    release.lease = out.head.lease;
    assert_eq!(
        call::<life::Release<HookLife<OpenCheckpoint>>>(
            instance,
            crate::abi::mechanism::lifecycle::slot::RELEASE,
            &release,
            &mut zeroed()
        ),
        Outcome::Ready
    );
    closed::<OpenCheckpoint>(instance);
}

/// A configure refusal states the hook's reason.
#[test]
fn red_a_configure_refusal_states_the_hooks_reason() {
    let p = opened_with::<OpenPickyConfigure>(&zeroed());
    assert_eq!(
        configured::<OpenPickyConfigure>(p, br#"{"bad": 1}"#, 7),
        (
            Outcome::Failed,
            0,
            "settings.bad is not a setting this hook reads".to_owned()
        )
    );
    assert_eq!(
        configured::<OpenPickyConfigure>(p, br#"{"good": 1}"#, 8),
        (Outcome::Ready, 8, String::new())
    );
    closed::<OpenPickyConfigure>(p);
}

/// One opening [`OpenSecrets`] was handed: its settings, secrets and generation.
type Handed = (String, Vec<Vec<u8>>, u64);

/// What [`OpenSecrets`] was handed, in order.
static OPENED_SECRETS: std::sync::Mutex<Vec<Handed>> = std::sync::Mutex::new(Vec::new());

struct OpenSecrets;
impl HookOpen for OpenSecrets {
    fn open(_: &str) -> Result<Box<dyn Hook>, String> {
        Err("opens through open_with".to_owned())
    }
    fn open_with(opening: &Opening<'_>) -> Result<Box<dyn Hook>, String> {
        OPENED_SECRETS.lock().unwrap().push((
            opening.settings.to_owned(),
            opening.secrets.iter().map(|s| s.to_vec()).collect(),
            opening.generation,
        ));
        Ok(Box::new(Forward))
    }
}

/// Open and refresh hand the hook its secrets and generation.
#[test]
fn red_open_and_refresh_hand_the_hook_its_secrets_and_generation() {
    use crate::abi::mechanism::lifecycle::slot::REFRESH;
    use crate::abi::mechanism::lifecycle::RefreshIn;
    let (one, two) = (b"s3cret".as_slice(), b"t0ken".as_slice());
    let lent = [
        Blob {
            ptr: one.as_ptr(),
            len: one.len(),
            fmt: crate::abi::mechanism::call::BLOB_SECRET,
            flags: 0,
        },
        Blob {
            ptr: two.as_ptr(),
            len: two.len(),
            fmt: crate::abi::mechanism::call::BLOB_SECRET,
            flags: 0,
        },
    ];
    let raw = br#"{"k": 1}"#;
    let mut input: OpenIn = zeroed();
    input.settings = Blob {
        ptr: raw.as_ptr(),
        len: raw.len(),
        fmt: BLOB_JSON,
        flags: 0,
    };
    input.secrets = lent.as_ptr();
    input.secrets_len = lent.len();
    input.generation = 3;
    let p = opened_with::<OpenSecrets>(&input);

    let mut r: RefreshIn = zeroed();
    r.settings = input.settings;
    r.secrets = lent[1..].as_ptr();
    r.secrets_len = 1;
    r.generation = 4;
    let mut out: OutHead = zeroed();
    assert_eq!(
        call::<life::Refresh<HookLife<OpenSecrets>>>(p, REFRESH, &r, &mut out),
        Outcome::Ready
    );
    assert_eq!(
        *OPENED_SECRETS.lock().unwrap(),
        vec![
            (
                r#"{"k": 1}"#.to_owned(),
                vec![one.to_vec(), two.to_vec()],
                3
            ),
            (r#"{"k": 1}"#.to_owned(), vec![two.to_vec()], 4),
        ]
    );
    closed::<OpenSecrets>(p);
}

/// A hook whose request cannot be built: the builder's text is its failure, told apart from the
struct Unsendable;
impl Hook for Unsendable {
    fn decide(&self, _: &Decoded<'_>, op: &Op<'_>) -> Poll<Verdict> {
        op.exchange(0, Some("http://far.example"), || {
            Err("the projection does not serialise".to_owned())
        })
        .map(|r| match r {
            Ok(_) => Verdict::Abstain,
            Err(OpFailure::Unbuilt(why)) => Verdict::Failed(format!("unbuilt: {why}")),
            Err(OpFailure::Conn(e)) => Verdict::Failed(format!("exchange: {e}")),
        })
    }
}
struct OpenUnsendable;
impl HookOpen for OpenUnsendable {
    fn open(_: &str) -> Result<Box<dyn Hook>, String> {
        Ok(Box::new(Unsendable))
    }
}

/// A request the builder refuses answers the builder's text.
#[test]
fn red_a_request_the_builder_refuses_answers_the_builders_text() {
    ESTABLISHED.set(0);
    let tables = HostTables {
        size: std::mem::size_of::<HostTables>() as u32,
        _reserved: 0,
        ctx: HostCtx::NONE,
        wake: None,
        conns: &PENDING_SLOTS,
        services: std::ptr::null(),
        io: std::ptr::null(),
    };
    let mut open: OpenIn = zeroed();
    open.host = &tables;
    let p = opened_with::<OpenUnsendable>(&open);
    let frame = frame_with(caps(4, 64));
    let mut input = frame.input();
    input.head.ticket = TICKET;
    let mut out: DecideOut = zeroed();
    assert_eq!(
        call::<Decide<OpenUnsendable>>(p, slot::DECIDE, &input, &mut out),
        Outcome::Failed
    );
    assert_eq!(
        error_text(&out.head),
        "unbuilt: the projection does not serialise"
    );
    assert_eq!(ESTABLISHED.get(), 0, "nothing was sent");
    closed::<OpenUnsendable>(p);
}

/// A scripted far end drives a pending decide to its answer.
#[test]
fn a_scripted_far_end_drives_a_pending_decide_to_its_answer() {
    use crate::abi::sdk::test_support::fake::FakeHost;
    use crate::abi::sdk::test_support::far::Far;
    let far = Far::answering(2, b"{}");
    let host = FakeHost::new().far();
    let mut open: OpenIn = zeroed();
    open.host = host.tables_for_tests();
    let p = opened_with::<OpenForward>(&open);
    let frame = frame_with(caps(4, 64));
    let mut input = frame.input();
    input.head.ticket = TICKET;
    let mut entries = 0;
    let (outcome, out) = loop {
        entries += 1;
        assert!(entries < 40, "the decide never answered");
        let mut out: DecideOut = zeroed();
        let o = call::<Decide<OpenForward>>(p, slot::DECIDE, &input, &mut out);
        if o != Outcome::Pending {
            break (o, out);
        }
        input.head.flags = FLAG_RESUME;
    };
    assert_eq!(outcome, Outcome::Ready);
    assert!(entries > 1, "the far end pends: the decide was resumed");
    assert_eq!(frame.order(out.order_written), vec![2]);
    assert_eq!(far.posts(), 1, "one POST per decide");
    assert_eq!(far.sent()[0].method, b"POST");
    assert!(far.sent()[0].ended);
    assert_eq!(far.held(), 0, "the exchange closed its stream");
    closed::<OpenForward>(p);
}
#[test]
fn operation_context_follows_pending_custody_and_retires_without_slot_reuse() {
    struct Unsupported;
    impl Parks for Unsupported {
        fn ticket(&self) -> Ticket {
            Ticket::NONE
        }
        fn park(&self, _: Exchange) {
            panic!("no exchange")
        }
        fn resume(&self) -> Option<Box<Exchange>> {
            None
        }
    }
    assert_eq!(
        Op::over(&Unsupported, None)
            .context::<u32>(|| panic!("unsupported initializer"))
            .unwrap_err(),
        "operation context is unavailable"
    );
    struct Contextual(RefCell<Option<Context>>);
    impl Parks for Contextual {
        fn context(&self) -> Option<&RefCell<Option<Context>>> {
            Some(&self.0)
        }
        fn ticket(&self) -> Ticket {
            Ticket::NONE
        }
        fn park(&self, _: Exchange) {
            panic!("no exchange")
        }
        fn resume(&self) -> Option<Box<Exchange>> {
            None
        }
    }
    let local = Contextual(RefCell::new(None));
    let op = Op::over(&local, None);
    let outer = Arc::new(7_u32);
    let unused = Arc::downgrade(&outer);
    let selected = op
        .context(|| {
            assert_eq!(*op.context(|| Arc::new(8_u32)).unwrap(), 8);
            outer
        })
        .unwrap();
    assert_eq!(*selected, 8, "nested initialization is never overwritten");
    assert!(unused.upgrade().is_none(), "unused initializer is released");
    struct State(u32);
    thread_local! {
        static CURRENT: std::cell::Cell<u32> = const { std::cell::Cell::new(1) };
        static READY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        static CREATED: RefCell<Vec<std::sync::Weak<State>>> = const { RefCell::new(Vec::new()) };
        static SEEN: RefCell<Vec<u32>> = const { RefCell::new(Vec::new()) };
    }
    fn enter(op: &Op<'_>) -> bool {
        let state = op
            .context(|| {
                let state = Arc::new(State(CURRENT.get()));
                CREATED.with(|created| created.borrow_mut().push(Arc::downgrade(&state)));
                state
            })
            .unwrap();
        let again = op
            .context::<State>(|| panic!("context initialized twice"))
            .unwrap();
        assert!(Arc::ptr_eq(&state, &again));
        assert_eq!(
            op.context::<u32>(|| panic!("wrong type initialized"))
                .unwrap_err(),
            "operation context type changed"
        );
        SEEN.with(|seen| seen.borrow_mut().push(state.0));
        READY.get()
    }
    struct Waiting;
    impl Hook for Waiting {
        fn decide(&self, _: &Decoded<'_>, op: &Op<'_>) -> Poll<Verdict> {
            if enter(op) {
                Poll::Ready(Verdict::Abstain)
            } else {
                Poll::Pending
            }
        }
        fn transform(&self, _: &Decoded<'_>, op: &Op<'_>) -> Poll<RewriteVerdict> {
            if enter(op) {
                Poll::Ready(RewriteVerdict::Abstain)
            } else {
                Poll::Pending
            }
        }
        fn notify(&self, _: &DecodedTap<'_>, op: &Op<'_>) -> Poll<()> {
            if enter(op) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }
    }
    struct OpenWaiting;
    impl HookOpen for OpenWaiting {
        fn open(_: &str) -> Result<Box<dyn Hook>, String> {
            Ok(Box::new(Waiting))
        }
    }
    for kind in 0..3 {
        let instance = opened_with::<OpenWaiting>(&zeroed());
        let decide = frame_with(caps(4, 64));
        let request = request(false, false);
        let notify = NotifyFrame::build(&request, None, false);
        let run = |ticket, flags| {
            if kind == 2 {
                let mut input = notify.input();
                input.head.ticket = ticket;
                input.head.flags = flags;
                call::<Notify<OpenWaiting>>(instance, slot::NOTIFY, &input, &mut zeroed())
            } else {
                let mut input = decide.input();
                input.head.ticket = ticket;
                input.head.flags = flags;
                if kind == 0 {
                    call::<Decide<OpenWaiting>>(instance, slot::DECIDE, &input, &mut zeroed())
                } else {
                    call::<Transform<OpenWaiting>>(instance, slot::TRANSFORM, &input, &mut zeroed())
                }
            }
        };
        let cancel = |ticket| {
            let mut input: CancelIn = zeroed();
            input.ticket = ticket;
            let mut out: CancelOut = zeroed();
            assert_eq!(
                call::<life::Cancel<HookLife<OpenWaiting>>>(instance, CANCEL, &input, &mut out),
                Outcome::Ready
            );
            assert_eq!(out.disposition, cancel::ABORTED);
        };
        let last = || CREATED.with(|created| created.borrow().last().unwrap().clone());

        for slot in 40..64 {
            let ticket = Ticket {
                slot,
                generation: 1,
            };
            CURRENT.set(1);
            READY.set(false);
            assert_eq!(run(ticket, 0), Outcome::Pending);
            let first = last();
            CURRENT.set(2);
            if slot == 40 {
                let mut refresh: crate::abi::mechanism::lifecycle::RefreshIn = zeroed();
                refresh.generation = 2;
                assert_eq!(
                    call::<life::Refresh<HookLife<OpenWaiting>>>(
                        instance,
                        crate::abi::mechanism::lifecycle::slot::REFRESH,
                        &refresh,
                        &mut zeroed()
                    ),
                    Outcome::Ready
                );
            }
            assert_eq!(run(ticket, FLAG_RESUME), Outcome::Pending);
            assert!(first.upgrade().is_some());
            assert_eq!(SEEN.with(|seen| seen.borrow().last().copied()), Some(1));
            cancel(ticket);
            assert!(
                first.upgrade().is_none(),
                "cancel retained context on slot {slot}"
            );
        }
        let old = Ticket {
            slot: 8,
            generation: 1,
        };
        let new = Ticket {
            slot: 8,
            generation: 2,
        };
        assert_eq!(run(old, 0), Outcome::Pending);
        let replaced = last();
        assert_eq!(run(old, 0), Outcome::Pending);
        assert!(
            replaced.upgrade().is_none(),
            "fresh replacement retires the old operation"
        );
        cancel(old);
        assert_eq!(run(new, 0), Outcome::Pending);
        let current = last();
        cancel(old);
        assert!(
            current.upgrade().is_some(),
            "stale cancel preserves current generation"
        );
        READY.set(true);
        assert_eq!(run(new, FLAG_RESUME), Outcome::Ready);
        assert!(
            current.upgrade().is_none(),
            "terminal answer retires context"
        );
        READY.set(false);
        assert_eq!(run(new, 0), Outcome::Pending);
        let closing = last();
        closed::<OpenWaiting>(instance);
        assert!(
            closing.upgrade().is_none(),
            "instance close retires context"
        );
        CREATED.with(|created| created.borrow_mut().clear());
        SEEN.with(|seen| seen.borrow_mut().clear());
    }
}

fn canonical_envelope(
    mut projection: serde_json::Value,
    op: &str,
    extra: Option<&serde_json::Map<String, serde_json::Value>>,
) -> Vec<u8> {
    let object = projection
        .as_object_mut()
        .expect("a hook projection is an object");
    if let Some(extra) = extra {
        object.extend(extra.clone());
    }
    object.remove("op");
    let mut out = Vec::new();
    out.push(b'{');
    for (index, (name, value)) in object.iter().enumerate() {
        if index != 0 {
            out.push(b',');
        }
        serde_json::to_writer(&mut out, name).unwrap();
        out.push(b':');
        serde_json::to_writer(&mut out, value).unwrap();
    }
    if !object.is_empty() {
        out.push(b',');
    }
    out.extend_from_slice(b"\"op\":");
    serde_json::to_writer(&mut out, op).unwrap();
    out.push(b'}');
    out
}

#[test]
fn direct_decide_and_transform_envelopes_keep_the_canonical_wire_bytes() {
    for (prompt, user) in [(false, false), (true, false), (false, true), (true, true)] {
        for op in [OP_DECIDE, OP_TRANSFORM] {
            let tags = tags();
            let mut candidates = candidates(&tags);
            candidates[0]
                .signals
                .push(Signal::CandidateErrorRate, SignalValue::F64(0.75));
            let budget = budget();
            let context = RoutingContext {
                pool: "pool-a",
                budget_remaining: Some(7),
                budget: &budget,
            };
            let mut request = request(prompt, user);
            request
                .signals
                .push(Signal::RequestTotalChars, SignalValue::U64(33));
            let frame = DecideFrame::first(DecideView::build(&request, &candidates, &context));
            let input = frame.input();
            let decoded = Decoded::of(lend(&input));
            let mut out = b"caller prefix:".to_vec();
            decoded.write_projection(op, None, &mut out).unwrap();
            let expected = canonical_envelope(decoded.projection_json(op), op, None);
            assert_eq!(
                &out[b"caller prefix:".len()..],
                expected,
                "prompt={prompt} user={user}"
            );
            let extra = json!({
                "z": {"z": 2, "a": 1},
                "a": ["é", "escaped \" quote"],
                "op": "must not win",
                "context": {"replacement": true}
            });
            let extra = extra.as_object().unwrap();
            let mut overlaid = Vec::new();
            decoded
                .write_projection(op, Some(extra), &mut overlaid)
                .unwrap();
            assert_eq!(
                overlaid,
                canonical_envelope(decoded.projection_json(op), op, Some(extra))
            );
        }
    }
}

#[test]
fn direct_budget_projection_preserves_nullable_fields_and_absent_pool() {
    for present in [false, true] {
        let tags = tags();
        let candidates = candidates(&tags);
        let mut budget = budget();
        budget.truncate(1);
        if present {
            budget[0].budget_group = Some("group".into());
            budget[0].remaining_micros = Some(9);
        }
        let context = RoutingContext {
            pool: "pool-a",
            budget_remaining: None,
            budget: &budget,
        };
        let request = request(false, false);
        let frame = DecideFrame::first(DecideView::build(&request, &candidates, &context));
        let input = frame.input();
        let decoded = Decoded::of(lend(&input));
        for op in [OP_DECIDE, OP_TRANSFORM] {
            let mut bytes = Vec::new();
            decoded.write_projection(op, None, &mut bytes).unwrap();
            let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let bucket = &value["context"]["budget"][0];
            assert_eq!(
                bucket["budget_group"],
                if present { json!("group") } else { json!(null) }
            );
            assert_eq!(
                bucket["remaining_micros"],
                if present { json!(9) } else { json!(null) }
            );
            assert!(bucket.as_object().unwrap().contains_key("budget_group"));
            assert!(bucket.as_object().unwrap().contains_key("remaining_micros"));
            assert!(!bucket.as_object().unwrap().contains_key("pool"));
            assert_eq!(
                bytes,
                canonical_envelope(decoded.projection_json(op), op, None)
            );
        }
    }
}

#[test]
fn direct_notify_envelopes_keep_request_candidate_routing_and_response_stage_bytes() {
    for prompt in [false, true] {
        let request = request(prompt, false);
        for stage in [
            None,
            Some(HookStageProjection {
                at: "candidate",
                model: None,
                attempt_number: None,
                remaining_candidates: Some(0),
                previous_failure: None,
                outcome: None,
                status: None,
            }),
            Some(HookStageProjection {
                at: "routing",
                model: Some("m1"),
                attempt_number: Some(2),
                remaining_candidates: Some(1),
                previous_failure: Some("upstream 503"),
                outcome: None,
                status: None,
            }),
            Some(HookStageProjection {
                at: "response",
                model: Some("m1"),
                attempt_number: None,
                remaining_candidates: None,
                previous_failure: None,
                outcome: Some("rejected_by_gate"),
                status: Some(403),
            }),
        ] {
            let frame = NotifyFrame::build(&request, stage.as_ref(), prompt);
            let input = frame.input();
            let tap = DecodedTap::of(lend(&input));
            let mut out = Vec::new();
            tap.write_projection(OP_NOTIFY, None, &mut out).unwrap();
            assert_eq!(
                out,
                canonical_envelope(tap.projection_json(), OP_NOTIFY, None)
            );
        }
    }
}

#[test]
fn hook_resuming_requires_the_actual_parked_continuation_even_on_the_same_cancelled_ticket() {
    thread_local! {
        static ENTRIES: RefCell<Vec<(u8, bool)>> = const { RefCell::new(Vec::new()) };
    }
    fn entry(kind: u8, op: &Op<'_>) -> bool {
        let resuming = op.resuming();
        ENTRIES.with(|entries| entries.borrow_mut().push((kind, resuming)));
        resuming
    }
    struct Waiting;
    impl Hook for Waiting {
        fn decide(&self, _: &Decoded<'_>, op: &Op<'_>) -> Poll<Verdict> {
            if entry(0, op) {
                Poll::Ready(Verdict::Abstain)
            } else {
                Poll::Pending
            }
        }
        fn transform(&self, _: &Decoded<'_>, op: &Op<'_>) -> Poll<RewriteVerdict> {
            if entry(1, op) {
                Poll::Ready(RewriteVerdict::Abstain)
            } else {
                Poll::Pending
            }
        }
        fn notify(&self, _: &DecodedTap<'_>, op: &Op<'_>) -> Poll<()> {
            if entry(2, op) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }
    }
    struct OpenWaiting;
    impl HookOpen for OpenWaiting {
        fn open(_: &str) -> Result<Box<dyn Hook>, String> {
            Ok(Box::new(Waiting))
        }
    }
    let instance = opened_with::<OpenWaiting>(&zeroed());
    let decide_frame = frame_with(caps(4, 64));
    let request = request(false, false);
    let notify_frame = NotifyFrame::build(&request, None, false);
    for kind in 0..3 {
        let run = |flags| {
            if kind == 2 {
                let mut input = notify_frame.input();
                input.head.ticket = TICKET;
                input.head.flags = flags;
                call::<Notify<OpenWaiting>>(instance, slot::NOTIFY, &input, &mut zeroed())
            } else {
                let mut input = decide_frame.input();
                input.head.ticket = TICKET;
                input.head.flags = flags;
                if kind == 0 {
                    call::<Decide<OpenWaiting>>(instance, slot::DECIDE, &input, &mut zeroed())
                } else {
                    call::<Transform<OpenWaiting>>(instance, slot::TRANSFORM, &input, &mut zeroed())
                }
            }
        };
        assert_eq!(run(0), Outcome::Pending, "fresh entry");
        assert_eq!(run(FLAG_RESUME), Outcome::Ready, "restored pending entry");
        assert_eq!(run(0), Outcome::Pending, "another fresh entry");
        let mut cancel: CancelIn = zeroed();
        cancel.ticket = TICKET;
        let mut out: CancelOut = zeroed();
        assert_eq!(
            call::<life::Cancel<HookLife<OpenWaiting>>>(instance, CANCEL, &cancel, &mut out),
            Outcome::Ready
        );
        assert_eq!(out.disposition, cancel::ABORTED);
        assert_eq!(
            run(FLAG_RESUME),
            Outcome::Pending,
            "cancel removed the continuation despite the stale flag"
        );
        assert_eq!(
            run(0),
            Outcome::Pending,
            "fresh entry discards a same-ticket continuation"
        );
        assert_eq!(
            run(FLAG_RESUME),
            Outcome::Ready,
            "only the new continuation resumes"
        );
        let seen = ENTRIES.with(|entries| std::mem::take(&mut *entries.borrow_mut()));
        assert_eq!(
            seen,
            [
                (kind, false),
                (kind, true),
                (kind, false),
                (kind, false),
                (kind, false),
                (kind, true)
            ]
        );
    }
    closed::<OpenWaiting>(instance);
}

#[test]
fn bounded_op_failures_keep_the_earlier_head_and_head_only_ops_never_read_a_body() {
    use crate::abi::host::conn::connector::{
        ReplyIn, ReplyPiece, REPLY_BODY, REPLY_END, REPLY_HEAD,
    };
    use crate::abi::sdk::exchange::{ExchangeFailure, ExchangeResponse, REPLY_OVER_BOUND};
    use crate::abi::sdk::test_support::fake::{self, FakeHost, FakeService, ServiceCall};
    use crate::abi::sdk::test_support::far::Far;
    use crate::abi::transport::FrameSpan;

    struct Probe {
        status: u16,
        limit: usize,
        head_only: bool,
        fail_before_head: bool,
        fail_body: bool,
        reads: HashMap<u32, usize>,
        built: u32,
        answer: Option<Result<ExchangeResponse, ExchangeFailure>>,
    }
    thread_local! {
        static PROBE: RefCell<Option<Probe>> = const { RefCell::new(None) };
    }
    const REASON: &[u8] = b"nonstandard secret-reason";
    const FIELDS: &[u8] = b"x-proof: sensitive-head\r\n";
    struct ReadReply;
    impl FakeService for ReadReply {
        type In = ReplyIn;
        fn serve(call: &mut ServiceCall<ReplyIn>) -> Outcome {
            PROBE.with(|probe| {
                let mut probe = probe.borrow_mut();
                let probe = probe.as_mut().unwrap();
                let next = probe.reads.len();
                let index = *probe
                    .reads
                    .entry(call.input().head.handle.seq)
                    .or_insert(next);
                if (probe.fail_before_head && index == 0) || (probe.fail_body && index == 1) {
                    call.set_error("the scripted reply read failed");
                    return Outcome::Failed;
                }
                let mut piece = ReplyPiece::default();
                let head;
                let bytes: &[u8] = match index {
                    0 => {
                        piece.kind = REPLY_HEAD;
                        piece.code = u32::from(probe.status);
                        piece.reason = FrameSpan {
                            offset: 0,
                            len: REASON.len() as u64,
                        };
                        piece.fields = FrameSpan {
                            offset: REASON.len() as u64,
                            len: FIELDS.len() as u64,
                        };
                        head = [REASON, FIELDS].concat();
                        &head
                    }
                    1 => {
                        piece.kind = REPLY_BODY;
                        &[b'a'; 60]
                    }
                    2 => {
                        piece.kind = REPLY_BODY;
                        &[b'b'; 41]
                    }
                    _ => {
                        piece.kind = REPLY_END;
                        &[]
                    }
                };
                assert!(call.fill_lent(|i| &i.buf, bytes));
                call.put(|i| &i.piece, piece);
                Outcome::Ready
            })
        }
    }
    struct Bounded;
    impl Hook for Bounded {
        fn decide(&self, _: &Decoded<'_>, op: &Op<'_>) -> Poll<Verdict> {
            let (limit, head_only) = PROBE.with(|probe| {
                let probe = probe.borrow();
                let probe = probe.as_ref().unwrap();
                (probe.limit, probe.head_only)
            });
            match op.exchange_sealed_bounded_with_head(
                0,
                Some("http://far.example"),
                limit,
                head_only,
                || {
                    PROBE.with(|probe| probe.borrow_mut().as_mut().unwrap().built += 1);
                    Ok((
                        {
                            let mut request = Request::default();
                            request.method = b"POST".to_vec();
                            request.target = b"/".to_vec();
                            request
                        },
                        Vec::new(),
                    ))
                },
            ) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(answer) => {
                    PROBE.with(|probe| probe.borrow_mut().as_mut().unwrap().answer = Some(answer));
                    Poll::Ready(Verdict::Abstain)
                }
            }
        }
    }
    struct OpenBounded;
    impl HookOpen for OpenBounded {
        fn open(_: &str) -> Result<Box<dyn Hook>, String> {
            Ok(Box::new(Bounded))
        }
    }
    for (status, limit, head_only, fail_before_head, fail_body) in [
        (503, 100, false, false, false),
        (302, 100, false, false, false),
        (200, 100, false, false, false),
        (200, 0, true, false, false),
        (503, 0, true, false, false),
        (200, 100, false, true, false),
        (503, 100, false, false, true),
        (200, 101, false, false, false),
    ] {
        let far = Far::answering(status, b"unused by the scripted read override");
        let host = FakeHost::new()
            .far()
            .serve(fake::conn::READ_REPLY, ReadReply);
        PROBE.with(|probe| {
            *probe.borrow_mut() = Some(Probe {
                status,
                limit,
                head_only,
                fail_before_head,
                fail_body,
                reads: HashMap::new(),
                built: 0,
                answer: None,
            })
        });
        let mut open: OpenIn = zeroed();
        open.host = host.tables_for_tests();
        let instance = opened_with::<OpenBounded>(&open);
        let frame = frame_with(caps(4, 64));
        let mut input = frame.input();
        input.head.ticket = TICKET;
        let mut entries = 0;
        loop {
            entries += 1;
            assert!(entries < 40, "the bounded operation never completed");
            let outcome =
                call::<Decide<OpenBounded>>(instance, slot::DECIDE, &input, &mut zeroed());
            if outcome != Outcome::Pending {
                assert_eq!(outcome, Outcome::Ready);
                break;
            }
            input.head.flags = FLAG_RESUME;

            PROBE.with(|probe| {
                let mut probe = probe.borrow_mut();
                let probe = probe.as_mut().unwrap();
                probe.limit = usize::MAX;
                probe.head_only = !head_only;
            });
        }
        let probe = PROBE.with(|probe| probe.borrow_mut().take().unwrap());
        assert!(entries > 1, "connector operations actually pended");
        assert_eq!(probe.built, 1, "one builder across all resumed entries");
        let answer = probe.answer.expect("the hook retained the typed result");
        if head_only {
            let reply = answer.expect("the head completes the operation");
            assert_eq!(reply.status, status);
            assert_eq!(reply.reason.as_deref(), Some(REASON));
            assert!(reply.body.is_empty());
            assert_eq!(probe.reads.len(), 1, "the body was never requested");
        } else if limit == 101 {
            let reply = answer.expect("the body exactly meets the limit");
            assert_eq!(reply.body.len(), 101);
        } else {
            let failure = answer.expect_err("the bounded reply fails");
            if fail_before_head {
                assert!(
                    failure.head().is_none(),
                    "no invented reply head before one arrives"
                );
            } else {
                let head = failure
                    .head()
                    .expect("the earlier head survives the failure");
                assert_eq!(head.status, status);
                assert_eq!(head.reason.as_deref(), Some(REASON));
                assert_eq!(
                    head.fields,
                    [(b"x-proof".to_vec(), b"sensitive-head".to_vec())]
                );
                assert!(
                    head.body.is_empty(),
                    "partial body is not exposed through the head"
                );
                let debug = format!("{failure:?}");
                assert!(!debug.contains("secret-reason"));
                assert!(!debug.contains("sensitive-head"));
            }
            let expected = if fail_before_head || fail_body {
                "the scripted reply read failed"
            } else {
                REPLY_OVER_BOUND
            };
            assert_eq!(
                failure.cause(),
                &OpFailure::Conn(ConnFailure::Failed(expected.to_owned()))
            );
            assert_eq!(
                failure.into_cause(),
                OpFailure::Conn(ConnFailure::Failed(expected.to_owned()))
            );
        }
        assert_eq!(far.posts(), 1);
        assert_eq!(
            far.held(),
            0,
            "failure and head-only paths close the stream"
        );
        closed::<OpenBounded>(instance);
    }
}

#[path = "hook_deadline_tests.rs"]
mod whole_timeout;
