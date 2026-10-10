// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The hook SDK: the 1.5.5 JSON a hook is handed is rebuilt byte for byte from the fixed views the
//! host builds, and a 1.5.5 reply lowers into exactly the answer 1.5.5's host normalized it to,
//! every answer passing the kind's own validator.

use super::*;
use crate::abi::hook::slot;
use crate::abi::hook::validate::{check_decide, check_transform};
use crate::abi::host::hook::{DecideFrame, DecideView, NotifyFrame};
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
use crate::abi::sdk::exchange::Request;
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
    // What 1.5.5's host handed the plugin: the projection as a JSON value (the plugin's handler
    // reads a `serde_json::Value`, however the bytes were ordered on the way).
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

// ── lowering ─────────────────────────────────────────────────────────────────────────────────────

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
    // Out-of-shape details keep the verb: the host defaults them (403, the canned message).
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
    // A malformed restrict restricts to nothing (the gate's `on_empty`), never allow-all.
    assert_eq!(
        lower_decide_reply(Ok(json!({"restrict": {"tags_any": []}}))),
        Verdict::Restrict(Vec::new())
    );
}

#[test]
fn a_typed_field_mismatch_is_failed_not_an_abstain() {
    // A valid reject beside a wrong-typed sibling: 1.5.5's host failed the whole parse (on_error).
    let v = lower_decide_reply(Ok(json!({"reject": {"status": 403}, "order": "x"})));
    assert!(matches!(v, Verdict::Failed(m) if m.starts_with("hook decide reply failed to parse")));
    assert_eq!(
        lower_decide_reply(Err("down".into())),
        Verdict::Failed("down".into())
    );
    let t = lower_transform_reply(Ok(json!({"abstain": 1})));
    assert!(
        matches!(t, RewriteVerdict::Failed(m) if m.starts_with("hook transform reply failed to parse"))
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

// ── writing, judged by the kind's own validator ──────────────────────────────────────────────────

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
    // The re-call's frame fits it.
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

// ── the slots ────────────────────────────────────────────────────────────────────────────────────

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
/// host's buffers.
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
/// NULL pointer) is never read: the slot answers FAULT, for `decide`, `transform` and `notify`.
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
    // The well-formed tap reaches the hook, as its 1.5.5 JSON.
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
/// its text readable by the host after the crossing returned.
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

/// RED (ARCHITECT ruling 2026-09-29, the hooks law: memory ABI, body zero-copy): a typed hook's
/// view BORROWS the host's `in`. The prompt body the plugin sees through the `decide` slot is the
/// host's own slice (same pointer, same length), and the message text is the host's bytes, not a
/// copy.
#[test]
fn red_the_prompt_body_a_hook_sees_is_the_hosts_own_bytes() {
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

// ── pending on the far end (THE DESIGN, the plugin ABI: Ready|Pending(wake)) ─────────────────────

/// How often the scripted connector's ESTABLISH was entered.
static ESTABLISHED: AtomicU32 = AtomicU32::new(0);
/// What the scripted far end answers once the established stream completes.
const DOWN: &str = "the far end is down";

/// A scripted connector ESTABLISH: every even entry pends (the host finishes it off the op); the
/// re-issue of the same handle answers the stored result, FAILED with [`DOWN`].
extern "C" fn establish_pends(
    _: HostCtx,
    input: *const c_void,
    out: *mut ServiceOut,
) -> RawOutcome {
    // SAFETY: every service `in` leads with a `ServiceHead`; `out` is the SDK's, live for the call.
    let (head, out) = unsafe { (*input.cast::<ServiceHead>(), &mut *out) };
    assert_eq!((head.op, head.handle.seq), (service::ESTABLISH, 0));
    let o = if ESTABLISHED.fetch_add(1, Ordering::SeqCst).is_multiple_of(2) {
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
            Ok(Request {
                method: b"POST".to_vec(),
                target: b"/".to_vec(),
                ..Request::default()
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

/// RED (ARCHITECT ruling 2026-10-02, the ORPHANS seam): a hook waiting on its exchange answers
/// PENDING, writing nothing; the host's RESUME re-enters it and the exchange resumes on its
/// parked state (the same handle re-issued, the stored result read); a fresh entry on the ticket
/// starts over, and a ticket-less call cannot pend at all.
#[test]
fn red_a_hook_waiting_on_its_exchange_pends_and_resumes_on_the_wake() {
    let tables = HostTables {
        size: std::mem::size_of::<HostTables>() as u32,
        _reserved: 0,
        ctx: HostCtx {
            ptr: std::ptr::null_mut(),
        },
        wake: None,
        conns: &PENDING_SLOTS,
        services: std::ptr::null(),
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
    assert_eq!(ESTABLISHED.load(Ordering::SeqCst), 1);

    input.head.flags = FLAG_RESUME;
    let mut out: DecideOut = zeroed();
    assert_eq!(
        call::<Decide<OpenForward>>(p, slot::DECIDE, &input, &mut out),
        Outcome::Failed
    );
    assert_eq!(error_text(&out.head), DOWN);
    assert_eq!(ESTABLISHED.load(Ordering::SeqCst), 2);

    // A ticket-less `decide` is answered at once: its exchange cannot pend.
    let mut none = frame.input();
    none.head.ticket = Ticket::NONE;
    let mut out: DecideOut = zeroed();
    assert_eq!(
        call::<Decide<OpenForward>>(p, slot::DECIDE, &none, &mut out),
        Outcome::Failed
    );
    assert_eq!(error_text(&out.head), ConnFailure::NoTicket.to_string());

    // A fresh entry pends again, and a cancel of it aborts the op.
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

/// RED (ARCHITECT ruling 2026-10-02: operator-visible text equals 1.5.5): `open` hands the plugin
/// its settings verbatim. An empty blob stays empty (1.5.5's hooks were handed exactly that, and
/// answer it in their own words), never rewritten to `{}`; a present one crosses byte for byte.
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

/// THE SESSION CROSSES TO THE SDK (ARCHITECT RULING 2026-10-03, Q-FOLD-A2A-2-PROJECT-POOL session
/// half): a hook reads the request's opaque session off its view, byte for byte, and the 1.5.5
/// JSON projection a JSON hook is handed stays byte-identical (the session is never on that wire).
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
