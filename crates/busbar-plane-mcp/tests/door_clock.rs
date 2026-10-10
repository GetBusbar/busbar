// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A sealed state's window is judged at a time the host's clock gave: a host whose `clock.now`
//! fails refuses the state (busbar's own and a relayed one) and mints none, and never reads the
//! failure as the epoch (BUSBAR-1.6.0 spec line 1576: the clock is the kernel's one clock; line
//! 3295-3370: fail closed).

#![allow(unsafe_code)]

use std::ffi::c_void;

use busbar_contract::abi::host::service::{
    ClockNowIn, HostSlots, ItemSpan, RandomFillIn, ServiceFn, ServiceOut, SignIn, SERVICES,
};
use busbar_contract::abi::mechanism::call::{RawOutcome, Span};
use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables};
use serde_json::json;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::publish::Keyed;
use busbar_contract::abi::sdk::Services;
use busbar_plane_mcp::ask::{self as ask, AskDecision, AskRefusal, Rejected, UpstreamLeg};
use busbar_plane_mcp::tool_door::{decide_ask, DoorSeal, Held, Site};
use busbar_plane_mcp::{codec, door, tools_config};
use serde_json::Value;

fn answered(out: *mut ServiceOut, len: u64, items: u64) -> RawOutcome {
    // SAFETY: the wrapper's live `out`.
    unsafe {
        (*out).len = len;
        (*out).items = items;
        (*out).outcome = RawOutcome::of(Outcome::Ready);
    }
    RawOutcome::of(Outcome::Ready)
}

/// A signer: key id `k`, the signature the data's digest (64 bytes), so a state opens only as
/// minted.
extern "C" fn signs(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the wrapper hands a `SignIn` naming its live data and buffers, and a live `out`.
    unsafe {
        let i = input.cast::<SignIn>().read_unaligned();
        let data = std::slice::from_raw_parts(i.data.ptr, i.data.len);
        let digest = busbar_contract::redacted::sha256_hex(data);
        let sig = &digest.as_bytes()[..64];
        *i.into.buf = b'k';
        std::ptr::copy_nonoverlapping(sig.as_ptr(), i.into.buf.add(1), sig.len());
        *i.into.spans = ItemSpan {
            key: Span { offset: 0, len: 1 },
            value: Span { offset: 1, len: 64 },
        };
        answered(out, 65, 1)
    }
}

extern "C" fn fills(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the wrapper hands a `RandomFillIn` naming its live buffer, and a live `out`.
    unsafe {
        let i = input.cast::<RandomFillIn>().read_unaligned();
        std::ptr::write_bytes(i.into.buf, 7, i.len as usize);
        answered(out, i.len, 0)
    }
}

fn clock(input: *const c_void, out: *mut ServiceOut, secs: u64) -> RawOutcome {
    // SAFETY: the wrapper hands a `ClockNowIn` naming its live reading, and a live `out`.
    unsafe {
        let i = input.cast::<ClockNowIn>().read_unaligned();
        (*i.reading).wall_ns = secs * 1_000_000_000;
        (*i.reading).mono_ns = 1;
        answered(out, 0, 0)
    }
}

extern "C" fn at_1000(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    clock(input, out, 1000)
}

extern "C" fn at_9000(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    clock(input, out, 9000)
}

/// A host whose clock call fails.
extern "C" fn broken(_: HostCtx, _: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the wrapper's live `out`.
    unsafe { (*out).outcome = RawOutcome::of(Outcome::Failed) };
    RawOutcome::of(Outcome::Failed)
}

const fn host(clock: Option<ServiceFn>) -> HostSlots {
    HostSlots {
        size: std::mem::size_of::<HostSlots>() as u32,
        slots: SERVICES,
        clock_now: clock,
        records_get: None,
        records_list: None,
        records_claim: None,
        dest_judge: None,
        sign: Some(signs),
        unit_nest: None,
        work_open: None,
        work_find: None,
        work_settle: None,
        work_resume: None,
        trust_sight: None,
        trust_due: None,
        verify_lookup: None,
        verify_store: None,
        entitlement_check: None,
        content_scan: None,
        hook_call: None,
        random_fill: Some(fills),
        need_admit: None,
        trust_verify: None,
        records_secret: None,
        disk_append: None,
        snapshot_read: None,
        trust_sight_item: None,
        trust_serves: None,
        trust_decide: None,
        trust_state: None,
        session_emit: None,
    }
}

static MINTS: HostSlots = host(Some(at_1000));
static LAPSED: HostSlots = host(Some(at_9000));
static UNSERVED: HostSlots = host(None);
static FAILS: HostSlots = host(Some(broken));

fn with_seal<R>(
    table: &'static HostSlots,
    spent: &Keyed<String, u64>,
    f: impl FnOnce(&mut DoorSeal<'_>) -> R,
) -> R {
    let tables = HostTables {
        size: std::mem::size_of::<HostTables>() as u32,
        _reserved: 0,
        ctx: HostCtx {
            ptr: std::ptr::null_mut(),
        },
        wake: None,
        conns: std::ptr::null(),
        io: std::ptr::null(),
        services: table,
    };
    let (mut issued, mut claim) = (0u32, None);
    let mut seal = DoorSeal {
        services: Services::of(&tables).expect("a table was handed"),
        ticket: Ticket::NONE,
        issued: &mut issued,
        claim: &mut claim,
        spent,
        pending: false,
    };
    f(&mut seal)
}

fn held() -> Held {
    let section = door::read_tools_section(
        br#"{"fs": {"url": "https://mcp.example/fs", "pin": {"mechanism": "unpinned"}}}"#,
    )
    .expect("the section reads");
    Held::of(1, section)
}

fn confirm() -> Vec<tools_config::AskRoundCfg> {
    serde_json::from_value(json!([{
        "ok": { "method": "elicitation/create", "params": { "message": "sure?" } }
    }]))
    .expect("the operator's rounds read")
}

fn site(rounds: &[tools_config::AskRoundCfg]) -> Site<'_> {
    Site {
        principal: "k",
        roots_epoch: 0,
        method: codec::METHOD_TOOLS_CALL,
        server: "fs",
        capability: "fs_confirm",
        rounds,
    }
}

fn caps() -> Value {
    let mut params = json!({ "_meta": {} });
    params["_meta"][codec::META_CLIENT_CAPABILITIES] = json!({ "elicitation": {} });
    params
}

fn decide_on(
    table: &'static HostSlots,
    spent: &Keyed<String, u64>,
    rounds: &[tools_config::AskRoundCfg],
    params: &Value,
) -> AskDecision {
    with_seal(table, spent, |seal| {
        decide_ask(&held(), site(rounds), Some(params), &json!({}), Some(seal))
    })
}

#[test]
fn busbars_own_state_is_refused_when_the_clock_fails() {
    let (spent, rounds) = (Keyed::new(), confirm());
    let AskDecision::Ask { request_state, .. } = decide_on(&MINTS, &spent, &rounds, &caps()) else {
        panic!("the first round asks");
    };
    let mut retry = caps();
    retry["requestState"] = json!(request_state);
    retry["inputResponses"] = json!({ "ok": true });
    // A clock that reads past the window refuses the state as expired: the harness's control.
    assert!(
        matches!(
            decide_on(&LAPSED, &spent, &rounds, &retry),
            AskDecision::Refuse(AskRefusal::StateRejected(Rejected::Expired))
        ),
        "a lapsed state is expired"
    );
    // A clock that fails (whether served and failing, or not served) judges nothing: refused.
    for table in [&FAILS, &UNSERVED] {
        let d = decide_on(table, &spent, &rounds, &retry);
        assert!(
            matches!(d, AskDecision::Refuse(AskRefusal::ClockUnavailable { .. })),
            "refused for the clock, got {d:?}"
        );
        // And no state is minted at the epoch.
        let d = decide_on(table, &spent, &rounds, &caps());
        assert!(
            matches!(d, AskDecision::Refuse(AskRefusal::ClockUnavailable { .. })),
            "no mint, got {d:?}"
        );
    }
}

#[test]
fn a_relayed_state_is_refused_when_the_clock_fails() {
    let (spent, none) = (Keyed::new(), Vec::new());
    let held = held();
    let leg = UpstreamLeg {
        member: "fs".into(),
        state: None,
        round: 1,
        child: None,
    };
    let state = with_seal(&MINTS, &spent, |seal| {
        let bind = ask::Bind {
            principal: "k",
            method: codec::METHOD_TOOLS_CALL,
            capability: "fs_confirm",
            generation: held.catalogue.generation(),
            now: 1000,
            roots_epoch: 0,
        };
        ask::relay_state(bind, &ask::digest_arguments(&json!({})), leg, seal)
    })
    .expect("a relayed state is sealed");
    let mut retry = caps();
    retry["requestState"] = json!(state);
    assert!(
        matches!(
            decide_on(&LAPSED, &spent, &none, &retry),
            AskDecision::Refuse(AskRefusal::StateRejected(Rejected::Expired))
        ),
        "a lapsed relayed state is expired"
    );
    for table in [&FAILS, &UNSERVED] {
        let d = decide_on(table, &spent, &none, &retry);
        assert!(
            matches!(d, AskDecision::Refuse(AskRefusal::ClockUnavailable { .. })),
            "refused for the clock, got {d:?}"
        );
    }
}

/// A relayed state's seal under the failing clock: the refusal and the words the caller reads.
fn relayed_under_failed_clock(ttl_secs: u64) -> busbar_plane_mcp::call::AskRefusal {
    let spent = Keyed::new();
    let leg = UpstreamLeg {
        member: "fs".into(),
        state: None,
        round: 1,
        child: None,
    };
    let bind = |now| ask::Bind {
        principal: "k",
        method: codec::METHOD_TOOLS_CALL,
        capability: "fs_read_file",
        generation: 1,
        now,
        roots_epoch: 0,
    };
    with_seal(&FAILS, &spent, |seal| {
        busbar_plane_mcp::tool_door::seal_relayed(seal, "fs", bind, "d", leg, ttl_secs)
    })
    .expect_err("a state is never sealed at a time that was not read")
}

/// A relayed ask (the request's window) whose host clock fails is refused as `ask_unavailable`, in
/// words naming the clock.
#[test]
fn a_relayed_ask_under_a_failed_clock_is_refused_naming_the_clock() {
    let refusal = relayed_under_failed_clock(ask::DEFAULT_TTL_SECS);
    assert_eq!(refusal.audit_reason(), "ask_unavailable");
    assert!(
        refusal
            .to_string()
            .contains(busbar_plane_mcp::tool_door::CLOCK_UNAVAILABLE),
        "{refusal}"
    );
}

/// A task parked on its caller's answer (the task relay's window) refuses the same way.
#[test]
fn a_task_relay_under_a_failed_clock_is_refused_naming_the_clock() {
    let refusal = relayed_under_failed_clock(busbar_plane_mcp::tool_tasks::TASK_RELAY_TTL_SECS);
    assert_eq!(refusal.audit_reason(), "ask_unavailable");
    assert!(
        refusal
            .to_string()
            .contains(busbar_plane_mcp::tool_door::CLOCK_UNAVAILABLE),
        "{refusal}"
    );
}
