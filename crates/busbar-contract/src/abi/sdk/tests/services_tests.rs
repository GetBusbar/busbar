// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plugin side's host-service wrappers (`services.rs`), over a hand-built table.

use std::sync::atomic::{AtomicU8, Ordering};

use super::*;
use crate::abi::host::service::{
    DEST_ALLOWED, DEST_INTERNAL, DEST_METADATA, MAX_RANDOM_FILL, NOT_ENTITLED, SERVICES, TRUST_NEW,
    TRUST_SAME,
};
use crate::abi::mechanism::call::Span;
use crate::abi::mechanism::ticket::Ticket;

/// A host that entitles exactly `item:one`.
extern "C" fn entitles_one(
    _ctx: HostCtx,
    input: *const c_void,
    out: *mut ServiceOut,
) -> RawOutcome {
    // SAFETY: the wrapper hands an `EntitlementCheckIn` and a live `out`.
    unsafe {
        let i = input.cast::<EntitlementCheckIn>().read_unaligned();
        let target = std::slice::from_raw_parts(i.target.ptr, i.target.len);
        (*out).value = if target == b"item:one" {
            ENTITLED
        } else {
            NOT_ENTITLED
        };
        (*out).outcome = RawOutcome::of(Outcome::Ready);
    }
    RawOutcome::of(Outcome::Ready)
}

/// A host that answers FAILED.
extern "C" fn fails(_ctx: HostCtx, _input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: a live `out`.
    unsafe { (*out).outcome = RawOutcome::of(Outcome::Failed) };
    RawOutcome::of(Outcome::Failed)
}

/// A host that answers a verdict the service does not have.
extern "C" fn breaks(_ctx: HostCtx, _input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: a live `out`.
    unsafe {
        (*out).value = 7;
        (*out).outcome = RawOutcome::of(Outcome::Ready);
    }
    RawOutcome::of(Outcome::Ready)
}

fn table(slot: Option<ServiceFn>) -> HostSlots {
    HostSlots {
        size: size_of::<HostSlots>() as u32,
        slots: SERVICES,
        clock_now: None,
        records_get: None,
        records_list: None,
        records_claim: None,
        dest_judge: None,
        sign: None,
        unit_nest: None,
        work_open: None,
        work_find: None,
        work_settle: None,
        work_resume: None,
        trust_sight: None,
        trust_due: None,
        verify_lookup: None,
        verify_store: None,
        entitlement_check: slot,
        content_scan: None,
        hook_call: None,
        random_fill: None,
        need_admit: None,
    }
}

/// How many fills [`fills_with_its_count`] answered.
static FILLS: AtomicU8 = AtomicU8::new(0);

/// A host that fills every byte asked with the fill's ordinal, `short` bytes fewer than asked.
fn fill_with_count(input: *const c_void, out: *mut ServiceOut, short: u64) -> RawOutcome {
    // SAFETY: the wrapper hands a `RandomFillIn` naming its live buffer, and a live `out`.
    unsafe {
        let i = input.cast::<RandomFillIn>().read_unaligned();
        let n = FILLS.fetch_add(1, Ordering::SeqCst) + 1;
        std::ptr::write_bytes(i.into.buf, n, i.len as usize);
        (*out).len = i.len - short;
        (*out).outcome = RawOutcome::of(Outcome::Ready);
    }
    RawOutcome::of(Outcome::Ready)
}

extern "C" fn fills_with_its_count(
    _ctx: HostCtx,
    input: *const c_void,
    out: *mut ServiceOut,
) -> RawOutcome {
    fill_with_count(input, out, 0)
}

/// A host that answers one byte fewer than asked.
extern "C" fn fills_short(_ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    fill_with_count(input, out, 1)
}

fn fill_table(slot: Option<ServiceFn>) -> HostSlots {
    HostSlots {
        random_fill: slot,
        ..table(None)
    }
}

fn services(t: &HostSlots) -> Services {
    let tables = HostTables {
        size: size_of::<HostTables>() as u32,
        _reserved: 0,
        ctx: HostCtx {
            ptr: std::ptr::null_mut(),
        },
        wake: None,
        conns: std::ptr::null(),
        services: t,
    };
    Services::of(&tables).expect("a table was handed")
}

fn handle() -> CompletionHandle {
    CompletionHandle {
        ticket: Ticket::NONE,
        seq: 0,
        _reserved: 0,
    }
}

#[test]
fn entitled_answers_the_hosts_verdict_and_every_failure_is_an_error() {
    let t = table(Some(entitles_one));
    let s = services(&t);
    assert_eq!(s.entitled(handle(), "item:one"), Ok(true));
    assert_eq!(s.entitled(handle(), "item:two"), Ok(false));
    let none = table(None);
    assert_eq!(
        services(&none).entitled(handle(), "item:one"),
        Err(ServiceError::Unserved)
    );
    let failing = table(Some(fails));
    let refused = services(&failing).entitled(handle(), "item:one");
    assert_eq!(refused, Err(ServiceError::Declined(Outcome::Failed)));
    let broken = table(Some(breaks));
    assert_eq!(
        services(&broken).entitled(handle(), "item:one"),
        Err(ServiceError::Broken)
    );
}

#[test]
fn no_table_is_no_services() {
    let tables = HostTables {
        size: size_of::<HostTables>() as u32,
        _reserved: 0,
        ctx: HostCtx {
            ptr: std::ptr::null_mut(),
        },
        wake: None,
        conns: std::ptr::null(),
        services: std::ptr::null(),
    };
    assert!(Services::of(&tables).is_none());
}

#[test]
fn random_fill_fills_the_buffer_fresh_each_call_and_refuses_outside_its_cap_before_the_host() {
    let t = fill_table(Some(fills_with_its_count));
    let s = services(&t);
    let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
    assert_eq!(s.random_fill(handle(), &mut a), Ok(()));
    assert_eq!(s.random_fill(handle(), &mut b), Ok(()));
    assert_ne!(a, b, "two fills are never equal");
    assert!(a.iter().all(|x| *x == a[0]));
    let mut top = vec![0u8; MAX_RANDOM_FILL as usize];
    assert_eq!(s.random_fill(handle(), &mut top), Ok(()));
    let called = FILLS.load(Ordering::SeqCst);
    let mut over = vec![0u8; MAX_RANDOM_FILL as usize + 1];
    assert_eq!(
        s.random_fill(handle(), &mut over),
        Err(ServiceError::Declined(Outcome::Refused))
    );
    assert_eq!(
        s.random_fill(handle(), &mut []),
        Err(ServiceError::Declined(Outcome::Refused))
    );
    // A refused fill never calls the host.
    assert_eq!(FILLS.load(Ordering::SeqCst), called);
    assert!(over.iter().all(|x| *x == 0));
    assert_eq!(
        services(&fill_table(Some(fills_short))).random_fill(handle(), &mut a),
        Err(ServiceError::Broken)
    );
    assert_eq!(
        services(&fill_table(None)).random_fill(handle(), &mut a),
        Err(ServiceError::Unserved)
    );
    // A host whose table ends before `random.fill` serves none, and its slot is never read.
    let old = HostSlots {
        slots: op::RANDOM_FILL,
        ..fill_table(Some(fills_with_its_count))
    };
    assert_eq!(
        services(&old).random_fill(handle(), &mut a),
        Err(ServiceError::Unserved)
    );
}

// ── dest.judge, trust.sight, trust.due ────────────────────────────────────────────────────────

/// Answer `outcome` with `value`, `len` bytes and `items` spans into the live `out`.
fn answer(out: *mut ServiceOut, outcome: Outcome, value: u64, len: u64, items: u64) -> RawOutcome {
    // SAFETY: the caller's live `out`.
    unsafe {
        (*out).value = value;
        (*out).len = len;
        (*out).items = items;
        (*out).outcome = RawOutcome::of(outcome);
    }
    RawOutcome::of(outcome)
}

/// A judge that pends a resolving call on a ticket, refuses the metadata address by name, answers
/// INTERNAL for class 9 and admits the rest.
extern "C" fn judges(_ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the wrapper hands a `DestJudgeIn` naming its live text, and a live `out`.
    unsafe {
        let i = input.cast::<DestJudgeIn>().read_unaligned();
        let dest = std::slice::from_raw_parts(i.dest.ptr, i.dest.len);
        let verdict = if dest.starts_with(b"http://169.254.169.254") {
            DEST_METADATA
        } else if i.flags & DEST_RESOLVE != 0 && !i.head.handle.ticket.is_none() {
            return answer(out, Outcome::Pending, 0, 0, 0);
        } else if i.egress_class == 9 {
            DEST_INTERNAL
        } else {
            DEST_ALLOWED
        };
        answer(out, Outcome::Ready, verdict, 0, 0)
    }
}

/// A host that answers PENDING whatever the call.
extern "C" fn pends(_ctx: HostCtx, _input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    answer(out, Outcome::Pending, 0, 0, 0)
}

/// A kernel that pins the hash `h1`: SAME for it, NEW for any other; `slow` pends.
extern "C" fn sights(_ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the wrapper hands a `TrustSightIn` naming its live texts, and a live `out`.
    unsafe {
        let i = input.cast::<TrustSightIn>().read_unaligned();
        let who = std::slice::from_raw_parts(i.counterparty.ptr, i.counterparty.len);
        let hash = std::slice::from_raw_parts(i.catalogue_hash.ptr, i.catalogue_hash.len);
        if who == b"slow" {
            return answer(out, Outcome::Pending, 0, 0, 0);
        }
        answer(
            out,
            Outcome::Ready,
            if hash == b"h1" { TRUST_SAME } else { TRUST_NEW },
            0,
            0,
        )
    }
}

/// The names [`dues`] answers, in the kernel's layout: key = the name, value absent.
const DUE: [&str; 2] = ["alpha", "beta"];

/// Write `DUE` into the caller's buffers, or answer FAILED with what it needs when they are short.
fn write_due(
    input: *const c_void,
    out: *mut ServiceOut,
    key: impl Fn(u32, u32) -> Span,
) -> RawOutcome {
    let need = DUE.iter().map(|n| n.len()).sum::<usize>();
    // SAFETY: the wrapper hands a `TrustDueIn` naming its live buffers, and a live `out`.
    unsafe {
        let i = input.cast::<TrustDueIn>().read_unaligned();
        if i.into.cap < need || i.into.spans_cap < DUE.len() {
            (*out).needed_bytes = need as u64;
            (*out).needed_items = DUE.len() as u64;
            return answer(out, Outcome::Failed, 0, 0, 0);
        }
        let mut at = 0;
        for (n, name) in DUE.iter().enumerate() {
            std::ptr::copy_nonoverlapping(name.as_ptr(), i.into.buf.add(at), name.len());
            *i.into.spans.add(n) = ItemSpan {
                key: key(at as u32, name.len() as u32),
                value: Span {
                    offset: SPAN_ABSENT,
                    len: 0,
                },
            };
            at += name.len();
        }
        answer(out, Outcome::Ready, 0, at as u64, DUE.len() as u64)
    }
}

extern "C" fn dues(_ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    write_due(input, out, |offset, len| Span { offset, len })
}

/// A host whose names are absent spans.
extern "C" fn dues_nameless(
    _ctx: HostCtx,
    input: *const c_void,
    out: *mut ServiceOut,
) -> RawOutcome {
    write_due(input, out, |_, _| Span {
        offset: SPAN_ABSENT,
        len: 0,
    })
}

fn ticketed(seq: u32) -> CompletionHandle {
    CompletionHandle {
        ticket: Ticket {
            slot: 1,
            generation: 1,
        },
        seq,
        _reserved: 0,
    }
}

const NO_SPAN: ItemSpan = ItemSpan {
    key: Span { offset: 0, len: 0 },
    value: Span { offset: 0, len: 0 },
};

#[test]
fn dest_judge_answers_the_hosts_verdict_and_pends_only_on_a_ticket() {
    let t = HostSlots {
        dest_judge: Some(judges),
        ..table(None)
    };
    let s = services(&t);
    let meta = "http://169.254.169.254/latest";
    assert_eq!(
        s.dest_judge(handle(), meta, 0, true),
        Poll::Ready(Ok(DEST_METADATA))
    );
    assert_eq!(
        s.dest_judge(handle(), "https://a.example/", 0, false),
        Poll::Ready(Ok(DEST_ALLOWED))
    );
    assert_eq!(
        s.dest_judge(handle(), "https://a.example/", 9, false),
        Poll::Ready(Ok(DEST_INTERNAL))
    );
    assert_eq!(
        s.dest_judge(ticketed(0), "https://a.example/", 0, true),
        Poll::Pending
    );
    // PENDING on no ticket breaks the service's rule; a verdict in range passes as answered.
    let p = HostSlots {
        dest_judge: Some(pends),
        ..table(None)
    };
    assert_eq!(
        services(&p).dest_judge(handle(), "x", 0, true),
        Poll::Ready(Err(ServiceError::Broken))
    );
    let b = HostSlots {
        dest_judge: Some(breaks),
        ..table(None)
    };
    assert_eq!(
        services(&b).dest_judge(handle(), "x", 0, false),
        Poll::Ready(Ok(7))
    );
    let f = HostSlots {
        dest_judge: Some(fails),
        ..table(None)
    };
    assert_eq!(
        services(&f).dest_judge(handle(), "x", 0, false),
        Poll::Ready(Err(ServiceError::Declined(Outcome::Failed)))
    );
    assert_eq!(
        services(&table(None)).dest_judge(handle(), "x", 0, false),
        Poll::Ready(Err(ServiceError::Unserved))
    );
}

#[test]
fn trust_sight_answers_the_kernels_judgement_and_pends_on_a_ticket() {
    let t = HostSlots {
        trust_sight: Some(sights),
        ..table(None)
    };
    let s = services(&t);
    assert_eq!(
        s.trust_sight(ticketed(0), "srv", "h1"),
        Poll::Ready(Ok(TRUST_SAME))
    );
    assert_eq!(
        s.trust_sight(ticketed(1), "srv", "h2"),
        Poll::Ready(Ok(TRUST_NEW))
    );
    assert_eq!(s.trust_sight(ticketed(2), "slow", "h1"), Poll::Pending);
    assert_eq!(
        s.trust_sight(handle(), "slow", "h1"),
        Poll::Ready(Err(ServiceError::Broken))
    );
    // `7` is no `TRUST_*` verdict.
    let b = HostSlots {
        trust_sight: Some(breaks),
        ..table(None)
    };
    assert_eq!(
        services(&b).trust_sight(ticketed(0), "srv", "h1"),
        Poll::Ready(Err(ServiceError::Broken))
    );
    assert_eq!(
        services(&table(None)).trust_sight(ticketed(0), "srv", "h1"),
        Poll::Ready(Err(ServiceError::Unserved))
    );
}

#[test]
fn trust_due_views_the_names_in_the_callers_buffers_and_reports_a_short_one() {
    let t = HostSlots {
        trust_due: Some(dues),
        ..table(None)
    };
    let s = services(&t);
    let (mut buf, mut spans) = ([0u8; 4], [NO_SPAN; 1]);
    assert_eq!(
        s.trust_due(handle(), &mut buf, &mut spans).map(|d| d.len()),
        Err(ServiceError::Short { bytes: 9, items: 2 })
    );
    let (mut buf, mut spans) = ([0u8; 9], [NO_SPAN; 2]);
    let due = s
        .trust_due(handle(), &mut buf, &mut spans)
        .expect("two are due");
    assert_eq!(due.len(), 2);
    assert!(due.names().eq(DUE));
    let n = HostSlots {
        trust_due: Some(dues_nameless),
        ..table(None)
    };
    let (mut buf, mut spans) = ([0u8; 9], [NO_SPAN; 2]);
    assert_eq!(
        services(&n)
            .trust_due(handle(), &mut buf, &mut spans)
            .map(|d| d.len()),
        Err(ServiceError::Broken)
    );
    // It never pends: a host that does broke its rule.
    let p = HostSlots {
        trust_due: Some(pends),
        ..table(None)
    };
    assert_eq!(
        services(&p)
            .trust_due(ticketed(0), &mut buf, &mut spans)
            .map(|d| d.len()),
        Err(ServiceError::Broken)
    );
    assert_eq!(
        services(&table(None))
            .trust_due(handle(), &mut buf, &mut spans)
            .map(|d| d.len()),
        Err(ServiceError::Unserved)
    );
}
