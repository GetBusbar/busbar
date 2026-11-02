// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Complete-exchange bounds through the actual hook Safe entry, with a manually advanced host
//! clock. The far end sends a head and then remains Pending without waking the operation.

use super::*;
use crate::abi::host::conn::connector::{ReplyIn, StreamIn, REPLY_BODY, REPLY_END, REPLY_HEAD};
use crate::abi::host::service::{ClockNowIn, ClockReading, HostSlots};
use std::cell::RefCell;
use std::sync::atomic::AtomicU64;

const START: u64 = 7_000_000_000;
const BOUND_MS: u64 = 100;
const EXPIRY: u64 = START + BOUND_MS * 1_000_000;
const STREAM: u64 = 81;

#[derive(Default)]
struct Far {
    now: u64,
    dial_pending: bool,
    body_ready: bool,
    facts_pending: bool,
    advance_in_facts: bool,
    established: bool,
    closes: Vec<Ticket>,
    pieces: std::collections::HashMap<u32, u32>,
}
thread_local! {
    static FAR: RefCell<Far> = RefCell::new(Far::default());
}

extern "C" fn clock(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK calls this slot with a ClockNowIn and its writable reading.
    let input = unsafe { &*input.cast::<ClockNowIn>() };
    let now = FAR.with(|far| far.borrow().now);
    // SAFETY: reading is initialized and writable for this synchronous service call.
    unsafe {
        input.reading.write(ClockReading {
            size: std::mem::size_of::<ClockReading>() as u32,
            _reserved: 0,
            wall_ns: 0,
            mono_ns: now,
        })
    };
    answered(out, Outcome::Ready, 0)
}
extern "C" fn establish(_: HostCtx, _: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    FAR.with(|far| {
        let mut far = far.borrow_mut();
        if far.dial_pending {
            return answered(out, Outcome::Pending, 0);
        }
        far.established = true;
        answered(out, Outcome::Ready, STREAM)
    })
}
extern "C" fn write(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: this connector slot's input is the SDK's RequestIn for this call.
    let input = unsafe { &*input.cast::<crate::abi::host::conn::connector::RequestIn>() };
    // SAFETY: out is the SDK's writable service result.
    unsafe {
        (*out).len = input.len as u64;
    }
    answered(out, Outcome::Ready, 0)
}
extern "C" fn read(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: this slot receives the SDK's ReplyIn and initialized writable buffer/descriptor.
    let input = unsafe { &*input.cast::<ReplyIn>() };
    let result = FAR.with(|far| {
        let mut far = far.borrow_mut();
        let seq = input.head.handle.seq;
        let kind = if let Some(kind) = far.pieces.get(&seq) {
            *kind
        } else {
            let kind = match far.pieces.len() {
                0 => REPLY_HEAD,
                1 => REPLY_BODY,
                _ => REPLY_END,
            };
            if kind != REPLY_HEAD && !far.body_ready {
                return Outcome::Pending;
            }
            far.pieces.insert(seq, kind);
            kind
        };
        let body = if kind == REPLY_BODY {
            &b"{}"[..]
        } else {
            &b""[..]
        };
        // SAFETY: body fits the SDK's reply buffer; piece names exactly those initialized bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(body.as_ptr(), input.buf, body.len());
            input
                .piece
                .write(crate::abi::host::conn::connector::ReplyPiece {
                    kind,
                    code: 200,
                    ..Default::default()
                });
            (*out).len = body.len() as u64;
        }
        Outcome::Ready
    });
    answered(out, result, 0)
}
extern "C" fn facts(_: HostCtx, _: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    FAR.with(|far| {
        let mut far = far.borrow_mut();
        if far.advance_in_facts {
            far.now = EXPIRY;
        }
        answered(
            out,
            if far.facts_pending {
                Outcome::Pending
            } else {
                Outcome::Refused
            },
            0,
        )
    })
}
extern "C" fn close(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: CLOSE receives the SDK's StreamIn for this call.
    let input = unsafe { &*input.cast::<StreamIn>() };
    assert_eq!(input.stream, STREAM);
    FAR.with(|far| far.borrow_mut().closes.push(input.head.handle.ticket));
    answered(out, Outcome::Ready, 0)
}

struct Bounded(AtomicU64);
impl Bounded {
    fn post(&self, op: &Op<'_>) -> Poll<Result<serde_json::Value, String>> {
        op.set_timeout_ms(self.0.load(Ordering::SeqCst));
        op.exchange_sealed_bounded_with_head(
            0,
            Some("https://receiver.example"),
            1024,
            false,
            || Ok((Request::default(), Vec::new())),
        )
        .map(|result| result.map(|_| json!({})).map_err(|e| e.to_string()))
    }
}
impl Hook for Bounded {
    fn decide(&self, _: &Decoded<'_>, op: &Op<'_>) -> Poll<Verdict> {
        self.post(op).map(lower_decide_reply)
    }
    fn transform(&self, _: &Decoded<'_>, op: &Op<'_>) -> Poll<RewriteVerdict> {
        self.post(op).map(lower_transform_reply)
    }
    fn notify(&self, _: &DecodedTap<'_>, op: &Op<'_>) -> Poll<()> {
        self.post(op).map(|_| ())
    }
    fn configure(
        &self,
        _: &serde_json::Map<String, serde_json::Value>,
        version: u64,
    ) -> Result<(), String> {
        self.0.store(version, Ordering::SeqCst);
        Ok(())
    }
}
struct OpenBounded;
impl HookOpen for OpenBounded {
    fn open(_: &str) -> Result<Box<dyn Hook>, String> {
        Ok(Box::new(Bounded(AtomicU64::new(BOUND_MS))))
    }
}

fn with_tables(far: Far, body: impl FnOnce(&HostTables)) {
    FAR.with(|state| *state.borrow_mut() = far);
    let mut conns: ConnectorSlots = zeroed();
    conns.size = std::mem::size_of::<ConnectorSlots>() as u32;
    conns.slots = SERVICES;
    conns.establish = Some(establish);
    conns.write_request = Some(write);
    conns.read_reply = Some(read);
    conns.close = Some(close);
    conns.facts = Some(facts);
    let mut services: HostSlots = zeroed();
    services.size = std::mem::size_of::<HostSlots>() as u32;
    services.slots = crate::abi::host::service::SERVICES;
    services.clock_now = Some(clock);
    let tables = HostTables {
        size: std::mem::size_of::<HostTables>() as u32,
        _reserved: 0,
        ctx: HostCtx::NONE,
        wake: None,
        conns: &conns,
        services: &services,
        io: std::ptr::null(),
    };
    body(&tables);
}

fn run(far: Far, body: impl FnOnce(*mut c_void)) {
    with_tables(far, |tables| {
        let mut opening: OpenIn = zeroed();
        opening.host = tables;
        let instance = opened_with::<OpenBounded>(&opening);
        body(instance);
        closed::<OpenBounded>(instance);
    });
}

#[test]
fn a_head_then_silent_body_keeps_the_original_deadline_across_configuration() {
    run(
        Far {
            now: START,
            ..Default::default()
        },
        |instance| {
            let frame = frame_with(caps(4, 64));
            let mut input = frame.input();
            input.head.ticket = TICKET;
            let mut out: DecideOut = zeroed();
            assert_eq!(
                call::<Decide<OpenBounded>>(instance, slot::DECIDE, &input, &mut out),
                Outcome::Pending
            );
            assert_eq!(
                out.head.wake_at_ns, EXPIRY,
                "the real hook door publishes a timer for a silent body"
            );
            assert_eq!(
                configured::<OpenBounded>(instance, b"{}", 2000).0,
                Outcome::Ready
            );
            input.head.flags = FLAG_RESUME;
            FAR.with(|far| far.borrow_mut().now = EXPIRY - 1);
            let mut out: DecideOut = zeroed();
            assert_eq!(
                call::<Decide<OpenBounded>>(instance, slot::DECIDE, &input, &mut out),
                Outcome::Pending
            );
            assert_eq!(
                out.head.wake_at_ns, EXPIRY,
                "neither re-entry nor configure renews the timer"
            );
            FAR.with(|far| far.borrow_mut().now = EXPIRY);
            let mut out: DecideOut = zeroed();
            assert_eq!(
                call::<Decide<OpenBounded>>(instance, slot::DECIDE, &input, &mut out),
                Outcome::Failed
            );
            assert!(error_text(&out.head).contains("deadline passed"));
            FAR.with(|far| assert_eq!(far.borrow().closes, [Ticket::NONE]));
        },
    );
}

#[test]
fn transform_and_notify_publish_the_timer_and_cancellation_closes_once() {
    for notify in [false, true] {
        run(
            Far {
                now: START,
                ..Default::default()
            },
            |instance| {
                let wake = if notify {
                    let frame = NotifyFrame::build(&request(false, false), None, true);
                    let mut input = frame.input();
                    input.head.ticket = TICKET;
                    let mut out: OutHead = zeroed();
                    assert_eq!(
                        call::<Notify<OpenBounded>>(instance, slot::NOTIFY, &input, &mut out),
                        Outcome::Pending
                    );
                    out.wake_at_ns
                } else {
                    let frame = frame_with(caps(4, 64));
                    let mut input = frame.input();
                    input.head.ticket = TICKET;
                    let mut out: TransformOut = zeroed();
                    assert_eq!(
                        call::<Transform<OpenBounded>>(instance, slot::TRANSFORM, &input, &mut out),
                        Outcome::Pending
                    );
                    out.head.wake_at_ns
                };
                assert_eq!(wake, EXPIRY);
                let mut input: CancelIn = zeroed();
                input.ticket = TICKET;
                assert_eq!(
                    call::<life::Cancel<HookLife<OpenBounded>>>(
                        instance,
                        CANCEL,
                        &input,
                        &mut zeroed()
                    ),
                    Outcome::Ready
                );
                FAR.with(|far| assert_eq!(far.borrow().closes, [Ticket::NONE]));
            },
        );
    }
}

#[test]
fn a_pending_connect_expires_without_renewal_and_a_timely_whole_body_succeeds() {
    run(
        Far {
            now: START,
            dial_pending: true,
            ..Default::default()
        },
        |instance| {
            let frame = frame_with(caps(4, 64));
            let mut input = frame.input();
            input.head.ticket = TICKET;
            let mut out: DecideOut = zeroed();
            assert_eq!(
                call::<Decide<OpenBounded>>(instance, slot::DECIDE, &input, &mut out),
                Outcome::Pending
            );
            assert_eq!(out.head.wake_at_ns, EXPIRY);
            FAR.with(|far| far.borrow_mut().now = EXPIRY);
            input.head.flags = FLAG_RESUME;
            assert_eq!(
                call::<Decide<OpenBounded>>(instance, slot::DECIDE, &input, &mut zeroed()),
                Outcome::Failed
            );
            FAR.with(|far| assert!(!far.borrow().established && far.borrow().closes.is_empty()));
        },
    );
    run(
        Far {
            now: START,
            body_ready: true,
            ..Default::default()
        },
        |instance| {
            let frame = frame_with(caps(4, 64));
            let mut input = frame.input();
            input.head.ticket = TICKET;
            let mut out: DecideOut = zeroed();
            assert_eq!(
                call::<Decide<OpenBounded>>(instance, slot::DECIDE, &input, &mut out),
                Outcome::Ready
            );
            assert_eq!(out.verbs, VERB_ABSTAIN);
            FAR.with(|far| assert_eq!(far.borrow().closes, [TICKET]));
        },
    );
}

#[cfg(target_os = "linux")]
fn watch_json(value: &serde_json::Value) {
    match value {
        serde_json::Value::String(text) => {
            // SAFETY: each caller keeps this complete initialized owned tree on this thread
            // through the synchronous production call and its deallocation.
            unsafe { crate::alloc_counter::watch_initialized_payload(text.as_bytes()) };
        }
        serde_json::Value::Array(items) => items.iter().for_each(watch_json),
        serde_json::Value::Object(items) => watch_settings(items),
        _ => {}
    }
}

#[cfg(target_os = "linux")]
fn watch_settings(settings: &serde_json::Map<String, serde_json::Value>) {
    for (key, value) in settings {
        // SAFETY: this borrowed key belongs to the actual live SDK-owned configure/reply tree;
        // only the initialized allocation prefix at its base is registered, never parser scratch.
        unsafe { crate::alloc_counter::watch_initialized_payload(key.as_bytes()) };
        watch_json(value);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn configure_owned_dom_is_wiped_on_ack_and_nack_from_the_actual_hook_callback() {
    use crate::alloc_counter::InitializedPayloadProbe;
    struct WatchConfigure;
    impl Hook for WatchConfigure {
        fn configure(
            &self,
            settings: &serde_json::Map<String, serde_json::Value>,
            _: u64,
        ) -> Result<(), String> {
            // Registration is in the consumer of the actual adapter-owned map, so the same test
            // observes the old unguarded adapter as well as its fixed owner.
            watch_settings(settings);
            if settings.contains_key("bad") {
                Err("refused settings.bad".into())
            } else {
                Ok(())
            }
        }
    }
    struct OpenWatchConfigure;
    impl HookOpen for OpenWatchConfigure {
        fn open(_: &str) -> Result<Box<dyn Hook>, String> {
            Ok(Box::new(WatchConfigure))
        }
    }
    for (raw, expected) in [
        (&br#"{"url":"https://u:URLCANARY@receiver.example/key","unknown":{"NESTEDKEYCANARY":["ARRAYCANARY",{"inner":"INNERCANARY"}]}}"#[..], Outcome::Ready),
        (&br#"{"bad":true,"url":"https://u:NACKCANARY@receiver.example/key","unknown":["NESTEDNACKCANARY"]}"#[..], Outcome::Failed),
    ] {
        let instance = opened_with::<OpenWatchConfigure>(&zeroed());
        // SAFETY: the actual CONFIGURE adapter owns all registered strings/keys; the callback
        // only borrows them and their owners return/drop on this thread before observation ends.
        let probe = unsafe { InitializedPayloadProbe::start().expect("Linux memory observer") };
        let result = configured::<OpenWatchConfigure>(instance, raw, 2);
        let seen = probe.finish();
        assert_eq!(result.0, expected);
        assert!(!seen.reentered);
        assert!(!seen.payloads.is_empty(), "the actual configure callback received no observed tree");
        for payload in seen.payloads {
            assert!(payload.freed && payload.complete_read && payload.wiped, "{payload:?}");
            assert!(!payload.reallocated && payload.read_error.is_none(), "{payload:?}");
        }
        closed::<OpenWatchConfigure>(instance);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn reply_trees_wipe_unknown_and_typed_refusal_fields_with_an_unwiped_control() {
    use crate::alloc_counter::{watch_initialized_payload, InitializedPayloadProbe};
    // Register the complete caller-owned input before handing it to the actual production
    // lowerer. The old consuming decoder frees unknown strings/keys without wiping them.
    for raw in [
        r#"{"unknown":{"KEYCANARY":["VALUECANARY"]},"abstain":true}"#,
        r#"{"reject":{"message":"MESSAGECANARY"},"restrict":{"FIELDKEYCANARY":"FIELDCANARY"},"rewrite":1,"abstain":"WRONGTYPECANARY"}"#,
    ] {
        let reply = serde_json::from_str(raw).unwrap();
        // SAFETY: production lowering owns, wipes and drops these initialized trees on this thread.
        let probe = unsafe { InitializedPayloadProbe::start().expect("Linux memory observer") };
        watch_json(&reply);
        assert_eq!(lower_decide_reply(Ok(reply)), Verdict::Abstain);
        let seen = probe.finish();
        assert!(!seen.reentered && !seen.payloads.is_empty());
        for payload in seen.payloads {
            assert!(
                payload.freed && payload.complete_read && payload.wiped,
                "{payload:?}"
            );
            assert!(
                !payload.reallocated && payload.read_error.is_none(),
                "{payload:?}"
            );
        }
    }
    // SAFETY: exclusively owned initialized String, dropped before observation ends.
    let probe = unsafe { InitializedPayloadProbe::start().expect("Linux memory observer") };
    let control = String::from("UNWIPED-CONTROL-CANARY");
    // SAFETY: the String's whole initialized payload starts at its allocation base.
    unsafe { watch_initialized_payload(control.as_bytes()) };
    drop(control);
    let seen = probe.finish();
    assert!(!seen.reentered && !seen.payloads.is_empty());
    assert!(seen
        .payloads
        .iter()
        .all(|p| p.freed && p.complete_read && !p.wiped));
}

#[test]
fn whole_deadline_overflow_fails_before_establishing() {
    run(
        Far {
            now: u64::MAX - 1,
            ..Default::default()
        },
        |instance| {
            let frame = frame_with(caps(4, 64));
            let mut input = frame.input();
            input.head.ticket = TICKET;
            let mut out: DecideOut = zeroed();
            assert_eq!(
                call::<Decide<OpenBounded>>(instance, slot::DECIDE, &input, &mut out),
                Outcome::Failed
            );
            assert!(error_text(&out.head).contains("clock range"));
            FAR.with(|far| assert!(!far.borrow().established));
        },
    );
}

#[test]
fn expiry_while_facts_is_pending_closes_without_reusing_its_replay_handle() {
    with_tables(
        Far {
            now: START,
            body_ready: true,
            facts_pending: true,
            ..Default::default()
        },
        |tables| {
            // SAFETY: with_tables owns the complete outer, connector and service tables for
            // this closure; their immutable callbacks and thread-local state stay live here.
            let host = crate::abi::sdk::conn::Host::of(unsafe { Lent::new(tables) });
            let mut exchange = crate::abi::sdk::exchange::Exchange::request(Request::default())
                .unwrap()
                .observing()
                .with_timeout_ms(BOUND_MS);
            assert!(crate::abi::sdk::exchange::exchange(
                &mut host.connector(TICKET),
                &mut exchange,
                0,
                None
            )
            .is_pending());
            assert_eq!(exchange.wake_at_ns(), Some(EXPIRY));
            FAR.with(|far| far.borrow_mut().now = EXPIRY);
            let result = crate::abi::sdk::exchange::exchange(
                &mut host.connector(TICKET),
                &mut exchange,
                0,
                None,
            );
            assert!(
                matches!(result, Poll::Ready(Err(ConnFailure::Failed(ref text))) if text.contains("deadline passed"))
            );
            assert_eq!(exchange.stream(), None);
            FAR.with(|far| assert_eq!(far.borrow().closes, [Ticket::NONE]));
        },
    );
}

#[test]
fn an_oversized_configured_span_is_clamped_by_the_known_absolute_caller_deadline() {
    const CAP: u64 = START + 50_000_000;
    run(
        Far {
            now: START,
            ..Default::default()
        },
        |instance| {
            assert_eq!(
                configured::<OpenBounded>(instance, b"{}", u64::MAX).0,
                Outcome::Ready
            );
            let frame = frame_with(caps(4, 64));
            let mut input = frame.input();
            input.head.ticket = TICKET;
            input.head.deadline_ns = CAP;
            let mut out: DecideOut = zeroed();
            assert_eq!(
                call::<Decide<OpenBounded>>(instance, slot::DECIDE, &input, &mut out),
                Outcome::Pending
            );
            assert_eq!(out.head.wake_at_ns, CAP);
            FAR.with(|far| far.borrow_mut().now = CAP);
            input.head.flags = FLAG_RESUME;
            assert_eq!(
                call::<Decide<OpenBounded>>(instance, slot::DECIDE, &input, &mut zeroed()),
                Outcome::Failed
            );
            FAR.with(|far| assert_eq!(far.borrow().closes, [Ticket::NONE]));
        },
    );
}

#[test]
fn an_existing_untimed_hook_exchange_needs_no_clock_with_an_outer_deadline() {
    let tables = HostTables {
        size: std::mem::size_of::<HostTables>() as u32,
        _reserved: 0,
        ctx: HostCtx::NONE,
        wake: None,
        conns: &DIALLING_SLOTS,
        services: std::ptr::null(),
        io: std::ptr::null(),
    };
    let mut opening: OpenIn = zeroed();
    opening.host = &tables;
    let instance = opened_with::<OpenForward>(&opening);
    let frame = frame_with(caps(4, 64));
    let mut input = frame.input();
    input.head.ticket = TICKET;
    input.head.deadline_ns = EXPIRY;
    let mut out: DecideOut = zeroed();
    assert_eq!(
        call::<Decide<OpenForward>>(instance, slot::DECIDE, &input, &mut out),
        Outcome::Pending
    );
    assert_eq!(out.head.wake_at_ns, 0);
    let mut cancel: CancelIn = zeroed();
    cancel.ticket = TICKET;
    assert_eq!(
        call::<life::Cancel<HookLife<OpenForward>>>(instance, CANCEL, &cancel, &mut zeroed()),
        Outcome::Ready
    );
    closed::<OpenForward>(instance);
}

#[test]
fn explicit_whole_timeout_without_a_host_clock_refuses_before_connecting() {
    FAR.with(|far| {
        *far.borrow_mut() = Far {
            now: START,
            ..Default::default()
        }
    });
    let mut conns: ConnectorSlots = zeroed();
    conns.size = std::mem::size_of::<ConnectorSlots>() as u32;
    conns.slots = SERVICES;
    conns.establish = Some(establish);
    conns.close = Some(close);
    let tables = HostTables {
        size: std::mem::size_of::<HostTables>() as u32,
        _reserved: 0,
        ctx: HostCtx::NONE,
        wake: None,
        conns: &conns,
        services: std::ptr::null(),
        io: std::ptr::null(),
    };
    let mut opening: OpenIn = zeroed();
    opening.host = &tables;
    let instance = opened_with::<OpenBounded>(&opening);
    let frame = frame_with(caps(4, 64));
    let mut input = frame.input();
    input.head.ticket = TICKET;
    let mut out: DecideOut = zeroed();
    assert_eq!(
        call::<Decide<OpenBounded>>(instance, slot::DECIDE, &input, &mut out),
        Outcome::Failed
    );
    FAR.with(|far| assert!(!far.borrow().established && far.borrow().closes.is_empty()));
    closed::<OpenBounded>(instance);
}

#[test]
fn facts_that_reaches_expiry_in_its_service_step_cannot_lend_its_handle_to_close() {
    with_tables(
        Far {
            now: START,
            body_ready: true,
            facts_pending: true,
            advance_in_facts: true,
            ..Default::default()
        },
        |tables| {
            // SAFETY: with_tables owns the complete outer, connector and service tables for
            // this closure; their immutable callbacks and thread-local state stay live here.
            let host = crate::abi::sdk::conn::Host::of(unsafe { Lent::new(tables) });
            let mut exchange = crate::abi::sdk::exchange::Exchange::request(Request::default())
                .unwrap()
                .observing()
                .with_timeout_ms(BOUND_MS);
            // The host advances time inside FACTS and answers Pending. Observe's optional-facts
            // handling must not convert that expiry into a normal ticketed CLOSE on its handle.
            let result = crate::abi::sdk::exchange::exchange(
                &mut host.connector(TICKET),
                &mut exchange,
                0,
                None,
            );
            assert!(
                matches!(result, Poll::Ready(Err(ConnFailure::Failed(ref text))) if text.contains("deadline passed"))
            );
            assert_eq!(exchange.stream(), None);
            FAR.with(|far| assert_eq!(far.borrow().closes, [Ticket::NONE]));
        },
    );
}

#[test]
fn configure_refuses_invalid_utf8_instead_of_allocating_a_lossy_credential_copy() {
    let instance = opened_with::<OpenPickyConfigure>(&zeroed());
    let (outcome, _, why) =
        configured::<OpenPickyConfigure>(instance, b"{\"url\":\"CANARY\xff\"}", 2);
    assert_eq!(outcome, Outcome::Failed);
    assert_eq!(why, "settings: must be a JSON object");
    assert!(!why.contains("CANARY"));
    closed::<OpenPickyConfigure>(instance);
}

#[test]
fn configure_refuses_nonobject_shapes_without_calling_the_hook() {
    let instance = opened_with::<OpenPickyConfigure>(&zeroed());
    for raw in [
        &br#"[{"ARRAYKEYCANARY":"NONOBJECTCANARY"}]"#[..],
        &br#""SCALARCANARY""#[..],
    ] {
        let (outcome, _, why) = configured::<OpenPickyConfigure>(instance, raw, 2);
        assert_eq!(outcome, Outcome::Failed);
        assert_eq!(why, "settings: must be a JSON object");
        assert!(!why.contains("CANARY"));
    }
    closed::<OpenPickyConfigure>(instance);
}
