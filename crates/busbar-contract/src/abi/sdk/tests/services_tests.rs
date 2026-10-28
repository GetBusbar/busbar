// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plugin side's host-service wrappers (`services.rs`), over a hand-built table.

use std::sync::atomic::{AtomicU8, Ordering};

use super::*;
use crate::abi::host::service::{
    ABSENT, CLAIM_TAKEN, DEST_ALLOWED, DEST_INTERNAL, DEST_METADATA, HOOK_GATE, HOOK_REWRITE,
    MAX_RANDOM_FILL, NOT_ENTITLED, SCHEME_PLAIN, SCHEME_SECURE, SCHEME_UNDECLARED, SERVICES,
    TRUST_NEW, TRUST_SAME,
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
        trust_verify: None,
        records_secret: None,
        disk_append: None,
        snapshot_read: None,
        trust_sight_item: None,
        trust_serves: None,
        trust_decide: None,
        trust_state: None,
        session_emit: None,
        auth_call: None,
        unit_hand_in: None,
        unit_refuse: None,
        ticket_mint: None,
        ticket_take: None,
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
        ctx: HostCtx::NONE,
        wake: None,
        conns: std::ptr::null(),
        services: t,
        io: std::ptr::null(),
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
        ctx: HostCtx::NONE,
        wake: None,
        conns: std::ptr::null(),
        services: std::ptr::null(),
        io: std::ptr::null(),
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

/// The addresses [`resolves`] answers as judged, in the kernel's layout.
const JUDGED: [&str; 2] = ["203.0.113.5", "2001:db8::1"];

/// Write `DUE` into the buffers of the `TrustDueIn` at `input`.
fn write_due(
    input: *const c_void,
    out: *mut ServiceOut,
    key: impl Fn(u32, u32) -> Span,
) -> RawOutcome {
    // SAFETY: the wrapper hands a `TrustDueIn`.
    let into = unsafe { input.cast::<TrustDueIn>().read_unaligned() }.into;
    write_names(into, &DUE, out, key)
}

/// Write `names` into the caller's buffers `into`, READY with value `0`, or answer FAILED with what
/// it needs when they are short.
fn write_names(
    into: ServiceBufs,
    names: &[&str],
    out: *mut ServiceOut,
    key: impl Fn(u32, u32) -> Span,
) -> RawOutcome {
    let need = names.iter().map(|n| n.len()).sum::<usize>();
    // SAFETY: the wrapper's live buffers and a live `out`.
    unsafe {
        if into.cap < need || into.spans_cap < names.len() {
            (*out).needed_bytes = need as u64;
            (*out).needed_items = names.len() as u64;
            return answer(out, Outcome::Failed, 0, 0, 0);
        }
        let mut at = 0;
        for (n, name) in names.iter().enumerate() {
            std::ptr::copy_nonoverlapping(name.as_ptr(), into.buf.add(at), name.len());
            *into.spans.add(n) = ItemSpan {
                key: key(at as u32, name.len() as u32),
                value: Span {
                    offset: SPAN_ABSENT,
                    len: 0,
                },
            };
            at += name.len();
        }
        answer(out, Outcome::Ready, 0, at as u64, names.len() as u64)
    }
}

/// A judge that, asked to resolve, admits and writes [`JUDGED`]; not asked, admits and writes none.
extern "C" fn resolves(_ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the wrapper hands a `DestJudgeIn`.
    let i = unsafe { input.cast::<DestJudgeIn>().read_unaligned() };
    if i.flags & DEST_RESOLVE == 0 {
        return answer(out, Outcome::Ready, DEST_ALLOWED, 0, 0);
    }
    write_names(i.into, &JUDGED, out, |offset, len| Span { offset, len })
}

/// Resolve, with no room for an address.
fn no_room<'a>() -> Option<(&'a mut [u8], &'a mut [ItemSpan])> {
    Some(Default::default())
}

/// The verdict of a `dest.judge` answer.
fn verdict_of(p: Pend<Judged<'_>>) -> Pend<u64> {
    p.map(|r| r.map(|j| j.verdict))
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
        verdict_of(s.dest_judge(handle(), meta, 0, no_room())),
        Poll::Ready(Ok(DEST_METADATA))
    );
    assert_eq!(
        verdict_of(s.dest_judge(handle(), "https://a.example/", 0, None)),
        Poll::Ready(Ok(DEST_ALLOWED))
    );
    assert_eq!(
        verdict_of(s.dest_judge(handle(), "https://a.example/", 9, None)),
        Poll::Ready(Ok(DEST_INTERNAL))
    );
    assert_eq!(
        verdict_of(s.dest_judge(ticketed(0), "https://a.example/", 0, no_room())),
        Poll::Pending
    );
    // PENDING on no ticket breaks the service's rule; a verdict in range passes as answered.
    let p = HostSlots {
        dest_judge: Some(pends),
        ..table(None)
    };
    assert_eq!(
        verdict_of(services(&p).dest_judge(handle(), "x", 0, no_room())),
        Poll::Ready(Err(ServiceError::Broken))
    );
    let b = HostSlots {
        dest_judge: Some(breaks),
        ..table(None)
    };
    assert_eq!(
        verdict_of(services(&b).dest_judge(handle(), "x", 0, None)),
        Poll::Ready(Ok(7))
    );
    let f = HostSlots {
        dest_judge: Some(fails),
        ..table(None)
    };
    assert_eq!(
        verdict_of(services(&f).dest_judge(handle(), "x", 0, None)),
        Poll::Ready(Err(ServiceError::Declined(Outcome::Failed)))
    );
    assert_eq!(
        verdict_of(services(&table(None)).dest_judge(handle(), "x", 0, None)),
        Poll::Ready(Err(ServiceError::Unserved))
    );
}

/// THE JUDGED ADDRESSES (ARCHITECT DEST-PIN 2026-10-01): asked to resolve, the wrapper answers the
/// verdict with the addresses the host wrote, views into the caller's buffers, and their joined
/// form is the set an ESTABLISH's dial lands within; short buffers are a short answer naming what
/// it needs; not asked, no address and an empty set. RED on the wrapper that answered the verdict
/// alone.
#[test]
fn dest_judge_answers_the_judged_addresses_as_the_set_a_dial_lands_within() {
    let t = HostSlots {
        dest_judge: Some(resolves),
        ..table(None)
    };
    let s = services(&t);
    let dest = "https://push.example/hook";
    let (mut buf, mut spans) = ([0u8; 4], [NO_SPAN; 1]);
    assert_eq!(
        s.dest_judge(handle(), dest, 0, Some((&mut buf[..], &mut spans[..]))),
        Poll::Ready(Err(ServiceError::Short {
            bytes: 22,
            items: 2
        }))
    );
    let (mut buf, mut spans) = ([0u8; 22], [NO_SPAN; 2]);
    let Poll::Ready(Ok(j)) = s.dest_judge(handle(), dest, 0, Some((&mut buf[..], &mut spans[..])))
    else {
        panic!("admitted, with its addresses");
    };
    assert_eq!(j.verdict, DEST_ALLOWED);
    assert!(j.addresses.names().eq(JUDGED));
    assert_eq!(j.within(), "203.0.113.5,2001:db8::1");
    let Poll::Ready(Ok(j)) = s.dest_judge(handle(), dest, 0, None) else {
        panic!("admitted");
    };
    assert!(j.addresses.is_empty());
    assert_eq!(j.within(), "");
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

/// A host whose clock reads wall 7 s and monotonic 9 ms.
extern "C" fn reads_the_clock(
    _ctx: HostCtx,
    input: *const c_void,
    out: *mut ServiceOut,
) -> RawOutcome {
    // SAFETY: the wrapper hands a `ClockNowIn` naming its live reading, and a live `out`.
    unsafe {
        let i = input.cast::<ClockNowIn>().read_unaligned();
        (*i.reading).wall_ns = 7_000_000_000;
        (*i.reading).mono_ns = 9_000_000;
        (*out).outcome = RawOutcome::of(Outcome::Ready);
    }
    RawOutcome::of(Outcome::Ready)
}

#[test]
fn clock_now_answers_the_hosts_reading_and_every_failure_is_an_error() {
    let t = HostSlots {
        clock_now: Some(reads_the_clock),
        ..table(None)
    };
    let reading = services(&t)
        .clock_now(handle())
        .expect("the host reads its clock");
    assert_eq!(
        (reading.wall_ns, reading.mono_ns),
        (7_000_000_000, 9_000_000)
    );
    assert_eq!(reading.size as usize, size_of::<ClockReading>());
    let none = table(None);
    assert!(matches!(
        services(&none).clock_now(handle()),
        Err(ServiceError::Unserved)
    ));
    let failing = HostSlots {
        clock_now: Some(fails),
        ..table(None)
    };
    assert!(matches!(
        services(&failing).clock_now(handle()),
        Err(ServiceError::Declined(Outcome::Failed))
    ));
}

/// A host that verifies payload `ok`, refuses any other algorithm by name (`long`: a name longer
/// than the caller's buffer is answered short), and checks the blobs' formats.
extern "C" fn verifies(_ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    use crate::abi::host::service::{SIGNED_ALGORITHM, SIGNED_VERIFIED};
    // SAFETY: the wrapper hands a `TrustVerifyIn` naming live blobs and buffer, and a live `out`.
    unsafe {
        let i = input.cast::<TrustVerifyIn>().read_unaligned();
        assert_eq!((i.payload.fmt, i.signatures.fmt), (BLOB_OCTETS, BLOB_JSON));
        let payload = std::slice::from_raw_parts(i.payload.ptr, i.payload.len);
        let named: Vec<u8> = match payload {
            b"ok" => Vec::new(),
            b"long" => vec![b'x'; 100],
            _ => b"none".to_vec(),
        };
        if named.len() > i.into.cap {
            (*out).needed_bytes = named.len() as u64;
            (*out).outcome = RawOutcome::of(Outcome::Failed);
            return RawOutcome::of(Outcome::Failed);
        }
        std::ptr::copy_nonoverlapping(named.as_ptr(), i.into.buf, named.len());
        (*out).len = named.len() as u64;
        (*out).value = if named.is_empty() {
            SIGNED_VERIFIED
        } else {
            SIGNED_ALGORITHM
        };
        (*out).outcome = RawOutcome::of(Outcome::Ready);
    }
    RawOutcome::of(Outcome::Ready)
}

/// A host that answers a `trust.verify` verdict past the last.
extern "C" fn past_the_last_verdict(
    _ctx: HostCtx,
    _input: *const c_void,
    out: *mut ServiceOut,
) -> RawOutcome {
    // SAFETY: a live `out`.
    unsafe {
        (*out).value = crate::abi::host::service::SIGNED_MALFORMED_ROOT + 1;
        (*out).outcome = RawOutcome::of(Outcome::Ready);
    }
    RawOutcome::of(Outcome::Ready)
}

fn verify_table(slot: Option<ServiceFn>) -> HostSlots {
    HostSlots {
        trust_verify: slot,
        ..table(None)
    }
}

#[test]
fn trust_verify_views_the_verdict_and_the_refused_name_and_reports_a_short_buffer() {
    use crate::abi::host::service::{SIGNED_ALGORITHM, SIGNED_VERIFIED};
    let t = verify_table(Some(verifies));
    let s = services(&t);
    let mut buf = [0u8; 8];
    assert_eq!(
        s.trust_verify(handle(), "peer", b"ok", b"[]", &mut buf),
        Ok(Signed {
            verdict: SIGNED_VERIFIED,
            named: ""
        })
    );
    assert_eq!(
        s.trust_verify(handle(), "peer", b"alg", b"[]", &mut buf),
        Ok(Signed {
            verdict: SIGNED_ALGORITHM,
            named: "none"
        })
    );
    assert_eq!(
        s.trust_verify(handle(), "peer", b"long", b"[]", &mut buf),
        Err(ServiceError::Short {
            bytes: 100,
            items: 0
        })
    );
    let mut big = [0u8; 100];
    let long = "x".repeat(100);
    assert_eq!(
        s.trust_verify(handle(), "peer", b"long", b"[]", &mut big),
        Ok(Signed {
            verdict: SIGNED_ALGORITHM,
            named: &long
        })
    );
}

#[test]
fn trust_verify_failures_are_errors() {
    let mut buf = [0u8; 8];
    let none = verify_table(None);
    assert_eq!(
        services(&none).trust_verify(handle(), "peer", b"ok", b"", &mut buf),
        Err(ServiceError::Unserved)
    );
    let failing = verify_table(Some(fails));
    assert_eq!(
        services(&failing).trust_verify(handle(), "peer", b"ok", b"", &mut buf),
        Err(ServiceError::Declined(Outcome::Failed))
    );
    // A verdict past the last one is a host that broke the rules.
    let broken = verify_table(Some(past_the_last_verdict));
    assert_eq!(
        services(&broken).trust_verify(handle(), "peer", b"ok", b"", &mut buf),
        Err(ServiceError::Broken)
    );
    let old = HostSlots {
        slots: op::TRUST_VERIFY,
        ..verify_table(Some(verifies))
    };
    assert_eq!(
        services(&old).trust_verify(handle(), "peer", b"ok", b"", &mut buf),
        Err(ServiceError::Unserved)
    );
}

// ── records.get, records.list, records.claim ──────────────────────────────────────────────────

/// The record [`keeps`] holds, under key `k1`.
const KEPT: &[u8] = b"approved";

/// The records [`lists`] holds, in key order.
const LISTED: [(&[u8], &[u8]); 3] = [(b"t/1", b"one"), (b"t/2", b""), (b"t/3", b"three")];

/// Write `rows` (key then value per record, one span each, `key` absent when `keyless`) into the
/// caller's `into`, READY with `value`, or answer FAILED with what it needs when they are short.
fn write_rows(
    into: ServiceBufs,
    rows: &[(&[u8], &[u8])],
    value: u64,
    keyless: bool,
    out: *mut ServiceOut,
) -> RawOutcome {
    let need = rows.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>();
    // SAFETY: the wrapper's live buffers and a live `out`.
    unsafe {
        if into.cap < need || into.spans_cap < rows.len() {
            (*out).needed_bytes = need as u64;
            (*out).needed_items = rows.len() as u64;
            return answer(out, Outcome::Failed, 0, 0, 0);
        }
        let mut at = 0;
        for (n, (k, v)) in rows.iter().enumerate() {
            std::ptr::copy_nonoverlapping(k.as_ptr(), into.buf.add(at), k.len());
            std::ptr::copy_nonoverlapping(v.as_ptr(), into.buf.add(at + k.len()), v.len());
            let key = if keyless {
                Span {
                    offset: SPAN_ABSENT,
                    len: 0,
                }
            } else {
                Span {
                    offset: at as u32,
                    len: k.len() as u32,
                }
            };
            *into.spans.add(n) = ItemSpan {
                key,
                value: Span {
                    offset: (at + k.len()) as u32,
                    len: v.len() as u32,
                },
            };
            at += k.len() + v.len();
        }
        answer(out, Outcome::Ready, value, at as u64, rows.len() as u64)
    }
}

/// A store holding [`KEPT`] under `k1` of kind `approval`; `slow` pends; any other key is absent.
extern "C" fn keeps(_ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the wrapper hands a `RecordsGetIn` naming its live texts.
    let i = unsafe { input.cast::<RecordsGetIn>().read_unaligned() };
    // SAFETY: as above.
    let (kind, key) = unsafe {
        (
            std::slice::from_raw_parts(i.kind.ptr, i.kind.len),
            std::slice::from_raw_parts(i.key.ptr, i.key.len),
        )
    };
    match (kind, key) {
        (b"approval", b"k1") => write_rows(i.into, &[(&b""[..], KEPT)], FOUND, true, out),
        (_, b"slow") => answer(out, Outcome::Pending, 0, 0, 0),
        _ => answer(out, Outcome::Ready, ABSENT, 0, 0),
    }
}

/// A store that answers FOUND but writes no record.
extern "C" fn finds_nothing(
    _ctx: HostCtx,
    _input: *const c_void,
    out: *mut ServiceOut,
) -> RawOutcome {
    answer(out, Outcome::Ready, FOUND, 0, 0)
}

/// A store listing [`LISTED`] (tombstones dropped) after the `in`'s `after`, at most its `limit`;
/// an `after` sent absent (NULL) lists from the first, one sent present lists after it. Kind
/// `keyless` answers its records without keys.
extern "C" fn lists(_ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the wrapper hands a `RecordsListIn` naming its live texts.
    let i = unsafe { input.cast::<RecordsListIn>().read_unaligned() };
    // SAFETY: as above; `after` is read only when present.
    let (kind, prefix, after) = unsafe {
        (
            std::slice::from_raw_parts(i.kind.ptr, i.kind.len),
            std::slice::from_raw_parts(i.prefix.ptr, i.prefix.len),
            (!i.after.ptr.is_null()).then(|| std::slice::from_raw_parts(i.after.ptr, i.after.len)),
        )
    };
    let limit = if i.limit == 0 {
        usize::MAX
    } else {
        i.limit as usize
    };
    let rows: Vec<_> = LISTED
        .iter()
        .copied()
        .filter(|(k, v)| !v.is_empty() && k.starts_with(prefix))
        .filter(|(k, _)| after.is_none_or(|a| *k > a))
        .take(limit)
        .collect();
    write_rows(i.into, &rows, 0, kind == b"keyless", out)
}

/// How many claims [`claims`] ran, and whether `k1` is claimed.
static CLAIMS_RUN: AtomicU8 = AtomicU8::new(0);
static K1_CLAIMED: AtomicU8 = AtomicU8::new(0);

/// A claim store: `k1` is won by the first claim and taken after; `slow` pends.
extern "C" fn claims(_ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    CLAIMS_RUN.fetch_add(1, Ordering::SeqCst);
    // SAFETY: the wrapper hands a `RecordsClaimIn` naming its live key.
    let i = unsafe { input.cast::<RecordsClaimIn>().read_unaligned() };
    // SAFETY: as above.
    let key = unsafe { std::slice::from_raw_parts(i.key.ptr, i.key.len) };
    if key == b"slow" {
        return answer(out, Outcome::Pending, 0, 0, 0);
    }
    let won = K1_CLAIMED.swap(1, Ordering::SeqCst) == 0;
    answer(
        out,
        Outcome::Ready,
        if won { CLAIM_WON } else { CLAIM_TAKEN },
        0,
        0,
    )
}

/// THE RECORDS WRAPPERS (K-RECORDS): `records.get` answers the record as
/// a view into the caller's buffer, absent as `None`, a short buffer as the size to re-call with,
/// and pends only on a ticket; a FOUND without its record broke the rule.
#[test]
fn records_get_views_the_record_and_answers_absent_as_none() {
    let t = HostSlots {
        records_get: Some(keeps),
        ..table(None)
    };
    let s = services(&t);
    let mut short = [0u8; 3];
    assert_eq!(
        s.records_get(ticketed(0), "approval", b"k1", &mut short),
        Poll::Ready(Err(ServiceError::Short {
            bytes: KEPT.len() as u64,
            items: 1
        }))
    );
    let mut buf = [0u8; 16];
    assert_eq!(
        s.records_get(ticketed(0), "approval", b"k1", &mut buf),
        Poll::Ready(Ok(Some(KEPT)))
    );
    assert_eq!(
        s.records_get(ticketed(1), "approval", b"k2", &mut buf),
        Poll::Ready(Ok(None))
    );
    assert_eq!(
        s.records_get(ticketed(2), "approval", b"slow", &mut buf),
        Poll::Pending
    );
    // PENDING on no ticket breaks the service's rule.
    assert_eq!(
        s.records_get(handle(), "approval", b"slow", &mut buf),
        Poll::Ready(Err(ServiceError::Broken))
    );
    let empty = HostSlots {
        records_get: Some(finds_nothing),
        ..table(None)
    };
    assert_eq!(
        services(&empty).records_get(ticketed(0), "approval", b"k1", &mut buf),
        Poll::Ready(Err(ServiceError::Broken))
    );
    let f = HostSlots {
        records_get: Some(fails),
        ..table(None)
    };
    assert_eq!(
        services(&f).records_get(ticketed(0), "approval", b"k1", &mut buf),
        Poll::Ready(Err(ServiceError::Declined(Outcome::Failed)))
    );
    assert_eq!(
        services(&table(None)).records_get(ticketed(0), "approval", b"k1", &mut buf),
        Poll::Ready(Err(ServiceError::Unserved))
    );
}

/// `records.list` answers the records as `(key, value)` views in key order; `after` absent lists
/// from the first, and a page's last key is the next page's `after`; a record without its key broke
/// the rule.
#[test]
fn records_list_pages_by_the_last_key_and_reports_a_short_one() {
    let t = HostSlots {
        records_list: Some(lists),
        ..table(None)
    };
    let s = services(&t);
    let (mut buf, mut spans) = ([0u8; 4], [NO_SPAN; 1]);
    assert_eq!(
        s.records_list(
            ticketed(0),
            "task",
            b"t/",
            None,
            0,
            (&mut buf[..], &mut spans[..])
        )
        .map(|r| r.map(|r| r.records().count())),
        Poll::Ready(Err(ServiceError::Short {
            bytes: 14,
            items: 2
        }))
    );
    let (mut buf, mut spans) = ([0u8; 32], [NO_SPAN; 4]);
    let Poll::Ready(Ok(page)) = s.records_list(
        ticketed(0),
        "task",
        b"t/",
        None,
        1,
        (&mut buf[..], &mut spans[..]),
    ) else {
        panic!("the first page");
    };
    assert!(page.records().eq([(&b"t/1"[..], &b"one"[..])]));
    let after = page.last_key().expect("a key").to_vec();
    let (mut buf, mut spans) = ([0u8; 32], [NO_SPAN; 4]);
    let Poll::Ready(Ok(rest)) = s.records_list(
        ticketed(1),
        "task",
        b"",
        Some(after.as_slice()),
        0,
        (&mut buf[..], &mut spans[..]),
    ) else {
        panic!("the next page");
    };
    assert!(rest.records().eq([(&b"t/3"[..], &b"three"[..])]));
    let (mut buf, mut spans) = ([0u8; 32], [NO_SPAN; 4]);
    let Poll::Ready(Ok(none)) = s.records_list(
        ticketed(2),
        "task",
        b"u/",
        None,
        0,
        (&mut buf[..], &mut spans[..]),
    ) else {
        panic!("an empty page");
    };
    assert_eq!(none.records().next(), None);
    assert_eq!(none.last_key(), None);
    assert_eq!(
        s.records_list(
            ticketed(3),
            "keyless",
            b"",
            None,
            0,
            (&mut buf[..], &mut spans[..])
        )
        .map(|r| r.map(|r| r.records().count())),
        Poll::Ready(Err(ServiceError::Broken))
    );
    let p = HostSlots {
        records_list: Some(pends),
        ..table(None)
    };
    assert_eq!(
        services(&p)
            .records_list(
                ticketed(0),
                "task",
                b"",
                None,
                0,
                (&mut buf[..], &mut spans[..])
            )
            .map(|r| r.map(|r| r.records().count())),
        Poll::Pending
    );
    assert_eq!(
        services(&table(None))
            .records_list(
                ticketed(0),
                "task",
                b"",
                None,
                0,
                (&mut buf[..], &mut spans[..])
            )
            .map(|r| r.map(|r| r.records().count())),
        Poll::Ready(Err(ServiceError::Unserved))
    );
}

/// `records.claim` is won once and taken after; a claim with no time to live is REFUSED before the
/// host is called; it pends only on a ticket.
#[test]
fn records_claim_is_won_once_and_a_claim_without_a_ttl_never_reaches_the_host() {
    let t = HostSlots {
        records_claim: Some(claims),
        ..table(None)
    };
    let s = services(&t);
    let ran = CLAIMS_RUN.load(Ordering::SeqCst);
    assert_eq!(
        s.records_claim(ticketed(0), "approval", b"k1", 0),
        Poll::Ready(Err(ServiceError::Declined(Outcome::Refused)))
    );
    assert_eq!(
        CLAIMS_RUN.load(Ordering::SeqCst),
        ran,
        "never reached the host"
    );
    assert_eq!(
        s.records_claim(ticketed(0), "approval", b"k1", 60_000),
        Poll::Ready(Ok(true))
    );
    assert_eq!(
        s.records_claim(ticketed(1), "approval", b"k1", 60_000),
        Poll::Ready(Ok(false))
    );
    assert_eq!(
        s.records_claim(ticketed(2), "approval", b"slow", 60_000),
        Poll::Pending
    );
    assert_eq!(
        s.records_claim(handle(), "approval", b"slow", 60_000),
        Poll::Ready(Err(ServiceError::Broken))
    );
    // `7` is neither `CLAIM_WON` nor `CLAIM_TAKEN`.
    let b = HostSlots {
        records_claim: Some(breaks),
        ..table(None)
    };
    assert_eq!(
        services(&b).records_claim(ticketed(0), "approval", b"k1", 1),
        Poll::Ready(Err(ServiceError::Broken))
    );
    assert_eq!(
        services(&table(None)).records_claim(ticketed(0), "approval", b"k1", 1),
        Poll::Ready(Err(ServiceError::Unserved))
    );
}

/// A host whose work handle 9 has reference `ab` and record `rec`, live: `work.open` answers it;
/// `work.find` finds `ab` and answers absent for anything else.
extern "C" fn works(_ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the wrapper hands a service `in` naming its live buffers, and a live `out`.
    unsafe {
        let h = input.cast::<ServiceHead>().read_unaligned();
        let span = |key: (u32, u32), value: (u32, u32)| ItemSpan {
            key: Span {
                offset: key.0,
                len: key.1,
            },
            value: Span {
                offset: value.0,
                len: value.1,
            },
        };
        let (into, bytes, s, value): (ServiceBufs, &[u8], ItemSpan, u64) = match h.op {
            op::WORK_OPEN => {
                let i = input.cast::<WorkOpenIn>().read_unaligned();
                (i.into, b"ab", span((0, 2), (SPAN_ABSENT, 0)), 9)
            }
            _ => {
                let i = input.cast::<WorkFindIn>().read_unaligned();
                if std::slice::from_raw_parts(i.reference.ptr, i.reference.len) != b"ab" {
                    (*out).value = ABSENT;
                    (*out).outcome = RawOutcome::of(Outcome::Ready);
                    return RawOutcome::of(Outcome::Ready);
                }
                (i.into, b"\x01rec", span((0, 1), (1, 3)), 9)
            }
        };
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), into.buf, bytes.len());
        into.spans.write_unaligned(s);
        (*out).value = value;
        (*out).len = bytes.len() as u64;
        (*out).items = 1;
        (*out).outcome = RawOutcome::of(Outcome::Ready);
    }
    RawOutcome::of(Outcome::Ready)
}

#[test]
fn the_work_wrappers_read_the_reference_and_the_found_record() {
    let t = HostSlots {
        work_open: Some(works),
        work_find: Some(works),
        ..table(None)
    };
    let s = services(&t);
    let handle = CompletionHandle {
        ticket: Ticket {
            slot: 1,
            generation: 1,
        },
        seq: 0,
        _reserved: 0,
    };
    let empty = ItemSpan {
        key: Span { offset: 0, len: 0 },
        value: Span { offset: 0, len: 0 },
    };
    let (mut buf, mut spans) = ([0u8; 8], [empty; 1]);
    let opened = s.work_open(handle, "job", b"r", &mut buf, &mut spans);
    assert_eq!(
        opened,
        Poll::Ready(Ok(Opened {
            handle: 9,
            reference: "ab"
        }))
    );
    let (mut buf, mut spans) = ([0u8; 8], [empty; 1]);
    let found = s.work_find(handle, "ab", &mut buf, &mut spans);
    assert_eq!(
        found,
        Poll::Ready(Ok(Some(Found {
            handle: 9,
            state: crate::abi::host::service::WORK_LIVE,
            record: b"rec",
        })))
    );
    let (mut buf, mut spans) = ([0u8; 8], [empty; 1]);
    assert_eq!(
        s.work_find(handle, "zz", &mut buf, &mut spans),
        Poll::Ready(Ok(None))
    );
    // A host that serves no work answers unserved.
    let none = table(None);
    let (mut buf, mut spans) = ([0u8; 8], [empty; 1]);
    assert_eq!(
        services(&none).work_open(handle, "job", b"r", &mut buf, &mut spans),
        Poll::Ready(Err(ServiceError::Unserved))
    );
}

/// A host whose nested unit answers 201, body `ok`, one field `a: b`.
extern "C" fn nests(_ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the wrapper hands a `UnitNestIn` naming its live buffers, and a live `out`.
    unsafe {
        let i = input.cast::<UnitNestIn>().read_unaligned();
        let bytes = b"okab";
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), i.into.buf, bytes.len());
        let span = |k: (u32, u32), v: (u32, u32)| ItemSpan {
            key: Span {
                offset: k.0,
                len: k.1,
            },
            value: Span {
                offset: v.0,
                len: v.1,
            },
        };
        i.into.spans.write_unaligned(span((SPAN_ABSENT, 0), (0, 2)));
        i.into.spans.add(1).write_unaligned(span((2, 1), (3, 1)));
        (*out).value = 201;
        (*out).len = bytes.len() as u64;
        (*out).items = 2;
        (*out).outcome = RawOutcome::of(Outcome::Ready);
    }
    RawOutcome::of(Outcome::Ready)
}

#[test]
fn the_nest_wrapper_reads_the_childs_status_body_and_fields() {
    let t = HostSlots {
        unit_nest: Some(nests),
        ..table(None)
    };
    let handle = CompletionHandle {
        ticket: Ticket {
            slot: 1,
            generation: 1,
        },
        seq: 0,
        _reserved: 0,
    };
    let empty = ItemSpan {
        key: Span { offset: 0, len: 0 },
        value: Span { offset: 0, len: 0 },
    };
    let (mut buf, mut spans) = ([0u8; 8], [empty; 2]);
    let Poll::Ready(Ok(nested)) =
        services(&t).unit_nest(handle, "POST", "/child", b"x", &mut buf, &mut spans)
    else {
        panic!("the nest answered");
    };
    assert_eq!((nested.status, nested.body), (201, b"ok".as_slice()));
    assert_eq!(
        nested.fields().collect::<Vec<_>>(),
        vec![(b"a".as_slice(), b"b".as_slice())]
    );
}

// ── verify, content, hook ─────────────────────────────────────────────────────────────────────

/// A verify cache: key `hit` is cached (`cached`), key `follow` follows (`led`), any other leads.
extern "C" fn caches(_ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the wrapper hands a `VerifyLookupIn` naming its live key and buffers, and a live `out`.
    unsafe {
        let i = input.cast::<VerifyLookupIn>().read_unaligned();
        let key = std::slice::from_raw_parts(i.key.ptr, i.key.len);
        let (value, entry): (u64, &[u8]) = match key {
            b"hit" => (VERIFY_HIT, b"cached"),
            b"follow" => (VERIFY_FOLLOW, b"led"),
            _ => (VERIFY_LEAD, b""),
        };
        if !entry.is_empty() {
            std::ptr::copy_nonoverlapping(entry.as_ptr(), i.into.buf, entry.len());
            i.into.spans.write(ItemSpan {
                key: Span {
                    offset: SPAN_ABSENT,
                    len: 0,
                },
                value: Span {
                    offset: 0,
                    len: entry.len() as u32,
                },
            });
        }
        answer(
            out,
            Outcome::Ready,
            value,
            entry.len() as u64,
            u64::from(!entry.is_empty()),
        )
    }
}

extern "C" fn stores(_ctx: HostCtx, _input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    answer(out, Outcome::Ready, 0, 0, 0)
}

#[test]
fn verify_lookup_reads_a_hit_a_follow_or_the_lead_and_store_is_answered() {
    let t = HostSlots {
        verify_lookup: Some(caches),
        verify_store: Some(stores),
        ..table(None)
    };
    let s = services(&t);
    let mut buf = [0u8; 8];
    assert_eq!(
        s.verify_lookup(ticketed(0), b"hit", &mut buf),
        Poll::Ready(Ok(Verified::Hit(b"cached")))
    );
    let mut buf = [0u8; 8];
    assert_eq!(
        s.verify_lookup(ticketed(1), b"follow", &mut buf),
        Poll::Ready(Ok(Verified::Follow(b"led")))
    );
    let mut buf = [0u8; 8];
    assert_eq!(
        s.verify_lookup(ticketed(2), b"other", &mut buf),
        Poll::Ready(Ok(Verified::Lead))
    );
    assert_eq!(s.verify_store(handle(), b"other", b"v", 0), Ok(()));
    // RED: a host serving neither.
    let none = table(None);
    let mut buf = [0u8; 8];
    assert_eq!(
        services(&none).verify_lookup(ticketed(3), b"hit", &mut buf),
        Poll::Ready(Err(ServiceError::Unserved))
    );
    assert_eq!(
        services(&none).verify_store(handle(), b"k", b"v", 0),
        Err(ServiceError::Unserved)
    );
}

/// A gate that blocks content starting `bad` and passes the rest.
extern "C" fn scans(_ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the wrapper hands a `ContentScanIn` naming its live content, and a live `out`.
    unsafe {
        let i = input.cast::<ContentScanIn>().read_unaligned();
        let content = std::slice::from_raw_parts(i.content.ptr, i.content.len);
        let block = u64::from(content.starts_with(b"bad"));
        answer(out, Outcome::Ready, block, 0, 0)
    }
}

#[test]
fn content_scan_answers_pass_or_block_and_pends_on_a_ticket() {
    let t = HostSlots {
        content_scan: Some(scans),
        ..table(None)
    };
    let s = services(&t);
    let mut buf = [0u8; 4];
    assert_eq!(
        s.content_scan(ticketed(0), b"fine", &mut buf),
        Poll::Ready(Ok(Scanned {
            passed: true,
            rewritten: None
        }))
    );
    let mut buf = [0u8; 4];
    assert_eq!(
        s.content_scan(ticketed(1), b"bad", &mut buf),
        Poll::Ready(Ok(Scanned {
            passed: false,
            rewritten: None
        }))
    );
    let p = HostSlots {
        content_scan: Some(pends),
        ..table(None)
    };
    let mut buf = [0u8; 4];
    assert_eq!(
        services(&p).content_scan(ticketed(2), b"x", &mut buf),
        Poll::Pending
    );
}

/// A hook stage: a gate stops `stop` with 451 `no`; a rewrite from `0` rewrites to `rw` (resume 1),
/// from `1` passes.
extern "C" fn hooks(_ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the wrapper hands a `HookCallIn` naming its live prompt and buffer, and a live `out`.
    unsafe {
        let i = input.cast::<HookCallIn>().read_unaligned();
        let p = i.prompt.read_unaligned();
        let first = p.messages.read_unaligned();
        let text = std::slice::from_raw_parts(first.text.ptr, first.text.len);
        let (value, bytes): (u64, &[u8]) = match (i.stage, i.from, text) {
            (HOOK_GATE, _, b"stop") => (451, b"no"),
            (HOOK_REWRITE, 0, _) => (1, b"rw"),
            _ => (0, b""),
        };
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), i.into.buf, bytes.len());
        answer(out, Outcome::Ready, value, bytes.len() as u64, 0)
    }
}

#[test]
fn hook_call_reads_pass_rewrite_or_stop_and_refuses_a_bad_in_before_the_host() {
    use crate::abi::host::service::HOOK_FROM_MAX;
    let t = HostSlots {
        hook_call: Some(hooks),
        ..table(None)
    };
    let s = services(&t);
    let msg = |text: &'static str| {
        [MessageView {
            role: raw(b"user"),
            text: raw(text.as_bytes()),
        }]
    };
    let mut buf = [0u8; 8];
    assert_eq!(
        s.hook_call(ticketed(0), (HOOK_GATE, 0), None, &msg("stop"), &mut buf),
        Poll::Ready(Ok(Hooked::Stop {
            status: 451,
            words: b"no"
        }))
    );
    let mut buf = [0u8; 8];
    assert_eq!(
        s.hook_call(
            ticketed(1),
            (HOOK_GATE, 0),
            Some("sys"),
            &msg("ok"),
            &mut buf
        ),
        Poll::Ready(Ok(Hooked::Pass))
    );
    let mut buf = [0u8; 8];
    assert_eq!(
        s.hook_call(ticketed(2), (HOOK_REWRITE, 0), None, &msg("x"), &mut buf),
        Poll::Ready(Ok(Hooked::Rewrote {
            resume: 1,
            rewrite: b"rw"
        }))
    );
    let mut buf = [0u8; 8];
    assert_eq!(
        s.hook_call(ticketed(3), (HOOK_REWRITE, 1), None, &msg("rw"), &mut buf),
        Poll::Ready(Ok(Hooked::Pass))
    );
    // RED: a resumed gate and a chain past the cap never reach the host.
    let none = table(None);
    for stage_from in [(HOOK_GATE, 1), (HOOK_REWRITE, HOOK_FROM_MAX + 1), (9, 0)] {
        let mut buf = [0u8; 8];
        assert_eq!(
            services(&none).hook_call(ticketed(4), stage_from, None, &msg("x"), &mut buf),
            Poll::Ready(Err(ServiceError::Declined(Outcome::Refused)))
        );
    }
}

// ── sign ─────────────────────────────────────────────────────────────────────────────────────────

/// The key id and signature [`signs`] answers.
const KID: &str = "door-1";
const SIG: &[u8] = b"\x01\x02\x03";

/// A signer in the kernel's layout: span `0`, key = the key id, value = the signature (here the
/// data reversed after a fixed prefix, so the answer depends on the call); short when the buffers
/// are.
extern "C" fn signs(_ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the wrapper hands a `SignIn` naming its live data and buffers, and a live `out`.
    unsafe {
        let i = input.cast::<SignIn>().read_unaligned();
        let data = std::slice::from_raw_parts(i.data.ptr, i.data.len);
        let mut sig = SIG.to_vec();
        sig.extend(data.iter().rev());
        let need = KID.len() + sig.len();
        if i.into.cap < need || i.into.spans_cap < 1 {
            (*out).needed_bytes = need as u64;
            (*out).needed_items = 1;
            return answer(out, Outcome::Failed, 0, 0, 0);
        }
        std::ptr::copy_nonoverlapping(KID.as_ptr(), i.into.buf, KID.len());
        std::ptr::copy_nonoverlapping(sig.as_ptr(), i.into.buf.add(KID.len()), sig.len());
        *i.into.spans = ItemSpan {
            key: Span {
                offset: 0,
                len: KID.len() as u32,
            },
            value: Span {
                offset: KID.len() as u32,
                len: sig.len() as u32,
            },
        };
        answer(out, Outcome::Ready, 0, need as u64, 1)
    }
}

/// A signer that answers READY with no span.
extern "C" fn signs_nothing(
    _ctx: HostCtx,
    _input: *const c_void,
    out: *mut ServiceOut,
) -> RawOutcome {
    answer(out, Outcome::Ready, 0, 0, 0)
}

fn sign_table(slot: Option<ServiceFn>) -> HostSlots {
    HostSlots {
        sign: slot,
        ..table(None)
    }
}

#[test]
fn sign_answers_the_key_id_and_the_signature_from_the_callers_buffers() {
    let t = sign_table(Some(signs));
    let s = services(&t);
    let (mut buf, mut spans) = ([0u8; 32], [NO_SPAN; 1]);
    let signed = s
        .sign(handle(), b"ab", &mut buf, &mut spans)
        .expect("signed");
    assert_eq!(signed.key_id, KID);
    assert_eq!(signed.signature, b"\x01\x02\x03ba");
    let (mut small, mut spans) = ([0u8; 4], [NO_SPAN; 1]);
    assert_eq!(
        s.sign(handle(), b"ab", &mut small, &mut spans),
        Err(ServiceError::Short {
            bytes: 11,
            items: 1
        })
    );
}

#[test]
fn sign_failures_are_errors() {
    let (mut buf, mut spans) = ([0u8; 32], [NO_SPAN; 1]);
    assert_eq!(
        services(&sign_table(None)).sign(handle(), b"x", &mut buf, &mut spans),
        Err(ServiceError::Unserved)
    );
    assert_eq!(
        services(&sign_table(Some(fails))).sign(handle(), b"x", &mut buf, &mut spans),
        Err(ServiceError::Declined(Outcome::Failed))
    );
    assert_eq!(
        services(&sign_table(Some(signs_nothing))).sign(handle(), b"x", &mut buf, &mut spans),
        Err(ServiceError::Broken),
        "a READY sign with no key id and no signature is a broken host"
    );
}

// ── the host auth handle ──────────────────────────────────────────────────────────────────────

crate::own_seal!(Own);

use crate::abi::auth::{FIELD_QUERY, FIELD_SENSITIVE, POINT_HEAD};
use crate::abi::host::service::{FLOW_CONTINUE, FLOW_STOP, LINE_NONE, REFUSE_NO_ROUTE};

/// How many `auth.call`s the scripted hosts answered.
static AUTH_CALLS: AtomicU8 = AtomicU8::new(0);

const MINTED: UnitRef = UnitRef { id: 5, mac: 6 };
const LINE_REF: AuthRef = AuthRef { id: 2, mac: 3 };

/// One name an auth answers: the name, its value (outbound) or none (inbound), and its flags.
type AnsweredName<'a> = (&'a [u8], Option<&'a [u8]>, u32);

/// A scripted `auth.call` host: answers `spans` (name, value, flags) over one byte run, under the
/// short-buffer rule, and the minted unit with `flow`.
///
/// # Safety
/// `input` is a live `AuthCallIn` and `out` a live `out`.
unsafe fn answer_auth(
    input: *const c_void,
    out: *mut ServiceOut,
    flow: u32,
    spans: &[AnsweredName<'_>],
) -> RawOutcome {
    AUTH_CALLS.fetch_add(1, Ordering::SeqCst);
    // SAFETY: the caller's contract.
    unsafe {
        let i = input.cast::<AuthCallIn>().read_unaligned();
        let mut bytes = Vec::new();
        let mut laid = Vec::new();
        for (n, v, flags) in spans {
            let name = Span {
                offset: bytes.len() as u32,
                len: n.len() as u32,
            };
            bytes.extend_from_slice(n);
            let value = match v {
                Some(v) => {
                    let s = Span {
                        offset: bytes.len() as u32,
                        len: v.len() as u32,
                    };
                    bytes.extend_from_slice(v);
                    s
                }
                None => Span {
                    offset: SPAN_ABSENT,
                    len: 0,
                },
            };
            laid.push(FieldSpan {
                name,
                value,
                flags: *flags,
                _reserved: 0,
            });
        }
        if bytes.len() > i.cap || laid.len() > i.spans_cap {
            (*out).needed_bytes = bytes.len() as u64;
            (*out).needed_items = laid.len() as u64;
            (*out).outcome = RawOutcome::of(Outcome::Failed);
            return RawOutcome::of(Outcome::Failed);
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), i.buf, bytes.len());
        std::ptr::copy_nonoverlapping(laid.as_ptr(), i.spans, laid.len());
        i.answer.write_unaligned(AuthAnswer {
            size: size_of::<AuthAnswer>() as u32,
            flow,
            unit: MINTED,
        });
        (*out).len = bytes.len() as u64;
        (*out).items = laid.len() as u64;
        (*out).outcome = RawOutcome::of(Outcome::Ready);
    }
    RawOutcome::of(Outcome::Ready)
}

/// An inbound line's call: continue, and strip one field line and one query key.
extern "C" fn strips(_ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the wrapper hands a live `AuthCallIn` and `out`.
    unsafe {
        answer_auth(
            input,
            out,
            FLOW_CONTINUE,
            &[
                (b"x-credential", None, FIELD_SENSITIVE),
                (b"key", None, FIELD_QUERY),
            ],
        )
    }
}

/// An outbound binding's call: one field whose value outgrows the wrapper's first buffer.
extern "C" fn signs_long(_ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    static LONG: [u8; 3000] = [b's'; 3000];
    // SAFETY: as `strips`.
    unsafe { answer_auth(input, out, FLOW_CONTINUE, &[(b"x-sig", Some(&LONG), 0)]) }
}

/// A host whose every answer is short.
extern "C" fn always_short(
    _ctx: HostCtx,
    _input: *const c_void,
    out: *mut ServiceOut,
) -> RawOutcome {
    AUTH_CALLS.fetch_add(1, Ordering::SeqCst);
    // SAFETY: a live `out`.
    unsafe {
        (*out).needed_bytes = 4096;
        (*out).outcome = RawOutcome::of(Outcome::Failed);
    }
    RawOutcome::of(Outcome::Failed)
}

/// A name-only span flagged as neither a field line nor a query key.
extern "C" fn names_nowhere(
    _ctx: HostCtx,
    input: *const c_void,
    out: *mut ServiceOut,
) -> RawOutcome {
    // SAFETY: as `strips`.
    unsafe { answer_auth(input, out, FLOW_STOP, &[(b"x-credential", None, 0)]) }
}

fn auth_table(slot: Option<ServiceFn>) -> HostSlots {
    HostSlots {
        auth_call: slot,
        ..table(None)
    }
}

fn request() -> HeadViewArgs<'static> {
    HeadViewArgs {
        method: "POST",
        target: "/v1",
        authority: "a.example",
        query: Some("key=k"),
        fields: &[("x-credential", b"c")],
        scheme: SCHEME_SECURE,
    }
}

/// The scheme code the last `sees_scheme` call's view carried.
static SEEN_SCHEME: std::sync::Mutex<Option<u8>> = std::sync::Mutex::new(None);

/// An `auth.call` host that records the scheme code its request view carries, then continues.
extern "C" fn sees_scheme(_ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the wrapper hands a live `AuthCallIn` and `out`.
    unsafe {
        let i = input.cast::<AuthCallIn>().read_unaligned();
        *SEEN_SCHEME.lock().unwrap() = Some(i.request.scheme);
        answer_auth(input, out, FLOW_CONTINUE, &[])
    }
}

/// RED (the upstream's scheme): the code the host declared for the stream reaches the auth in the
/// view, as is; a request view that declares none hands `SCHEME_UNDECLARED`, never plain.
#[test]
fn auth_call_hands_the_auth_the_scheme_the_request_carries() {
    let t = auth_table(Some(sees_scheme));
    let call = |request: &HeadViewArgs<'_>| {
        match services(&t).auth_call::<Own>(
            ticketed(0),
            LINE_REF,
            UnitRef::NONE,
            POINT_HEAD,
            1,
            1,
            request,
            None,
        ) {
            Poll::Ready(r) => assert_eq!(r.expect("answered").flow, FLOW_CONTINUE),
            Poll::Pending => panic!("did not pend"),
        }
        SEEN_SCHEME.lock().unwrap().take()
    };
    assert_eq!(call(&request()), Some(SCHEME_SECURE));
    let plain = HeadViewArgs {
        scheme: SCHEME_PLAIN,
        ..request()
    };
    assert_eq!(call(&plain), Some(SCHEME_PLAIN));
    let undeclared = HeadViewArgs {
        scheme: SCHEME_UNDECLARED,
        ..request()
    };
    assert_eq!(
        call(&undeclared),
        Some(SCHEME_UNDECLARED),
        "the default declares nothing"
    );
    assert_eq!(HeadViewArgs::default().scheme, SCHEME_UNDECLARED);
}

#[test]
fn auth_call_answers_the_names_to_strip_for_an_inbound_line() {
    let t = auth_table(Some(strips));
    let called: AuthCalled<Own> = match services(&t).auth_call(
        ticketed(0),
        LINE_REF,
        UnitRef::NONE,
        POINT_HEAD,
        1,
        1,
        &request(),
        None,
    ) {
        Poll::Ready(r) => r.expect("answered"),
        Poll::Pending => panic!("did not pend"),
    };
    assert_eq!(called.flow, FLOW_CONTINUE);
    assert_eq!(called.unit, MINTED);
    assert_eq!(
        called.names,
        vec![
            ("x-credential".to_string(), Place::Field),
            ("key".to_string(), Place::Query)
        ]
    );
    assert!(called.fields.is_empty());
}

#[test]
fn auth_call_owns_the_one_short_recall_and_holds_outbound_values_as_the_callers_secret() {
    let t = auth_table(Some(signs_long));
    let before = AUTH_CALLS.load(Ordering::SeqCst);
    let Poll::Ready(Ok(called)) = services(&t).auth_call::<Own>(
        ticketed(0),
        LINE_REF,
        MINTED,
        POINT_HEAD,
        1,
        1,
        &request(),
        None,
    ) else {
        panic!("answered on the re-call");
    };
    assert!(
        AUTH_CALLS.load(Ordering::SeqCst) >= before + 2,
        "short, then re-called"
    );
    assert!(called.names.is_empty());
    assert_eq!(called.fields.len(), 1);
    assert_eq!(called.fields[0].name, "x-sig");
    assert_eq!(called.fields[0].value.expose_own(&Own::here()).len(), 3000);
    assert_eq!(format!("{:?}", called.fields[0].value), "[REDACTED]");

    let t = auth_table(Some(always_short));
    assert!(matches!(
        services(&t).auth_call::<Own>(
            ticketed(0),
            LINE_REF,
            MINTED,
            POINT_HEAD,
            1,
            1,
            &request(),
            None
        ),
        Poll::Ready(Err(ServiceError::Broken))
    ));
}

#[test]
fn auth_call_pends_on_a_ticket_and_refuses_what_breaks_the_rules() {
    let t = auth_table(Some(pends));
    assert!(services(&t)
        .auth_call::<Own>(
            ticketed(0),
            LINE_REF,
            UnitRef::NONE,
            POINT_HEAD,
            1,
            1,
            &request(),
            None
        )
        .is_pending());
    // A pending answer to a ticketless call breaks the rule.
    assert!(matches!(
        services(&t).auth_call::<Own>(
            handle(),
            LINE_REF,
            UnitRef::NONE,
            POINT_HEAD,
            1,
            1,
            &request(),
            None
        ),
        Poll::Ready(Err(ServiceError::Broken))
    ));
    let t = auth_table(Some(names_nowhere));
    assert!(matches!(
        services(&t).auth_call::<Own>(
            ticketed(0),
            LINE_REF,
            UnitRef::NONE,
            POINT_HEAD,
            1,
            1,
            &request(),
            None
        ),
        Poll::Ready(Err(ServiceError::Broken))
    ));
    assert!(matches!(
        services(&auth_table(None)).auth_call::<Own>(
            ticketed(0),
            LINE_REF,
            UnitRef::NONE,
            POINT_HEAD,
            1,
            1,
            &request(),
            None
        ),
        Poll::Ready(Err(ServiceError::Unserved))
    ));
}

/// A hand-in that answers STOP with the unit it minted.
extern "C" fn stops(_ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the wrapper hands a live `UnitHandInIn` and `out`.
    unsafe {
        let i = input.cast::<UnitHandInIn>().read_unaligned();
        i.answer.write_unaligned(AuthAnswer {
            size: size_of::<AuthAnswer>() as u32,
            flow: FLOW_STOP,
            unit: MINTED,
        });
        (*out).outcome = RawOutcome::of(Outcome::Ready);
    }
    RawOutcome::of(Outcome::Ready)
}

#[test]
fn unit_hand_in_answers_the_flow_and_the_unit() {
    let t = HostSlots {
        unit_hand_in: Some(stops),
        ..table(None)
    };
    assert_eq!(
        services(&t).unit_hand_in(handle(), LINE_REF, UnitRef::NONE, 4, 1, 1, &request()),
        Ok((FLOW_STOP, MINTED))
    );
    let failing = HostSlots {
        unit_hand_in: Some(fails),
        ..table(None)
    };
    assert_eq!(
        services(&failing).unit_hand_in(handle(), LINE_REF, UnitRef::NONE, 4, 1, 1, &request()),
        Err(ServiceError::Declined(Outcome::Failed))
    );
}

/// A refusal held in the host's own memory, as the kernel holds it until the next call.
extern "C" fn refuses(_ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    let fields: &'static [Field] = Box::leak(Box::new([Field {
        name: raw(b"x-reason"),
        value: raw(b"no route"),
    }]));
    // SAFETY: the wrapper hands a live `UnitRefuseIn` and `out`.
    unsafe {
        let i = input.cast::<UnitRefuseIn>().read_unaligned();
        i.answer.write_unaligned(RefusalAnswer {
            size: size_of::<RefusalAnswer>() as u32,
            status: 404,
            _reserved: 0,
            fields: fields.as_ptr(),
            fields_len: fields.len(),
            body: blob(b"refused", BLOB_OCTETS),
        });
        (*out).outcome = RawOutcome::of(Outcome::Ready);
    }
    RawOutcome::of(Outcome::Ready)
}

#[test]
fn unit_refuse_copies_the_kernels_answer_out() {
    let t = HostSlots {
        unit_refuse: Some(refuses),
        ..table(None)
    };
    assert_eq!(
        services(&t).unit_refuse(
            handle(),
            UnitRef::NONE,
            REFUSE_NO_ROUTE,
            LINE_NONE,
            1,
            1,
            &request()
        ),
        Ok(RefusalCopy {
            status: 404,
            fields: vec![("x-reason".to_string(), b"no route".to_vec())],
            body: b"refused".to_vec(),
        })
    );
    let broken = HostSlots {
        unit_refuse: Some(breaks),
        ..table(None)
    };
    assert_eq!(
        services(&broken).unit_refuse(
            handle(),
            UnitRef::NONE,
            REFUSE_NO_ROUTE,
            LINE_NONE,
            1,
            1,
            &request()
        ),
        Err(ServiceError::Broken),
        "a READY with no answer written"
    );
}

/// The secret [`holds_secrets`] keeps for its one live credential.
const LIVE_SECRET: &[u8] = b"s3cr3t";

/// The fixed dummy [`holds_secrets`] answers for an id it does not hold.
const DUMMY_SECRET: &[u8] = b"dummy-secret-0000";

/// The bytes of [`holds_secrets`]'s long credential: past the wrapper's first buffer.
const LONG_SECRET: [u8; 300] = [0x5a; 300];

/// How many crossings [`holds_secrets`] answered for the id `long` (each test reads its own id's
/// count: the tests run at once).
static LONG_CROSSINGS: AtomicU8 = AtomicU8::new(0);

/// How many crossings [`holds_secrets`] answered for the id `probe`.
static PROBE_CROSSINGS: AtomicU8 = AtomicU8::new(0);

/// A credential source for the kind `signing-key`: `AKID` live with [`LIVE_SECRET`]; `long` live
/// with [`LONG_SECRET`] (the short answer first); `slow` pends (on no ticket too: the wrapper's
/// check must catch it); any other id the fixed [`DUMMY_SECRET`], not live. Any other kind is
/// REFUSED.
extern "C" fn holds_secrets(
    _ctx: HostCtx,
    input: *const c_void,
    out: *mut ServiceOut,
) -> RawOutcome {
    // SAFETY: the wrapper hands a `RecordsSecretIn` naming its live texts and buffers.
    let i = unsafe { input.cast::<RecordsSecretIn>().read_unaligned() };
    // SAFETY: as above.
    let (kind, id) = unsafe {
        (
            std::slice::from_raw_parts(i.kind.ptr, i.kind.len),
            std::slice::from_raw_parts(i.id.ptr, i.id.len),
        )
    };
    match id {
        b"long" => LONG_CROSSINGS.fetch_add(1, Ordering::SeqCst),
        b"probe" => PROBE_CROSSINGS.fetch_add(1, Ordering::SeqCst),
        _ => 0,
    };
    if kind != b"signing-key" {
        return answer(out, Outcome::Refused, 0, 0, 0);
    }
    let not_live = crate::abi::host::service::SECRET_NOT_LIVE;
    match id {
        b"AKID" => write_rows(i.into, &[(&b""[..], LIVE_SECRET)], SECRET_LIVE, false, out),
        b"long" => write_rows(
            i.into,
            &[(&b""[..], &LONG_SECRET[..])],
            SECRET_LIVE,
            false,
            out,
        ),
        b"slow" => answer(out, Outcome::Pending, 0, 0, 0),
        _ => write_rows(i.into, &[(&b""[..], DUMMY_SECRET)], not_live, false, out),
    }
}

/// A credential source that answers READY, live, with no secret written.
extern "C" fn holds_no_secret(
    _ctx: HostCtx,
    _input: *const c_void,
    out: *mut ServiceOut,
) -> RawOutcome {
    answer(out, Outcome::Ready, SECRET_LIVE, 0, 0)
}

fn secret_table(slot: Option<ServiceFn>) -> HostSlots {
    HostSlots {
        records_secret: slot,
        ..table(None)
    }
}

/// THE SAFE `records.secret` (ARCHITECT ruling on the auth kit's credential read): READY hands the
/// secret's bytes and the live verdict in a holder the plugin owns; an id the host does not hold is
/// READY too, with the host's dummy and NOT live (absent is `live == false`, never an error, so the
/// plugin's check runs over the dummy in equal time); PENDING surfaces as `Poll::Pending`, for the
/// op to answer PENDING and the host's wake to re-enter it; a secret past the first buffer is
/// re-called once inside the call. RED before the wrapper: the SDK had no safe call, and an auth
/// plugin crossed the raw slot in an `unsafe` module of its own.
#[test]
fn records_secret_answers_the_secret_and_its_liveness_and_pends_on_a_ticket() {
    let t = secret_table(Some(holds_secrets));
    let s = services(&t);
    let Poll::Ready(Ok(live)) = s.records_secret(ticketed(0), "signing-key", "AKID") else {
        panic!("a held credential is READY");
    };
    assert_eq!(live.secret(), LIVE_SECRET);
    assert!(live.live());
    let Poll::Ready(Ok(unknown)) = s.records_secret(ticketed(1), "signing-key", "nobody") else {
        panic!("an unknown id is READY, as a held one is");
    };
    assert_eq!(
        unknown.secret(),
        DUMMY_SECRET,
        "the host's dummy, not nothing"
    );
    assert!(!unknown.live(), "an unknown id is absent: not live");
    assert!(s
        .records_secret(ticketed(2), "signing-key", "slow")
        .is_pending());
    let Poll::Ready(Ok(long)) = s.records_secret(ticketed(3), "signing-key", "long") else {
        panic!("a long secret is re-called once and READY");
    };
    assert_eq!(long.secret(), &LONG_SECRET[..]);
    assert_eq!(
        LONG_CROSSINGS.load(Ordering::SeqCst),
        2,
        "the short answer and its one re-call"
    );
    assert!(
        !format!("{live:?}").contains("s3cr3t"),
        "the holder's Debug never shows the secret"
    );
}

#[test]
fn records_secret_failures_are_errors() {
    assert_eq!(
        services(&secret_table(None))
            .records_secret(ticketed(0), "signing-key", "AKID")
            .map(|r| r.map(|s| s.live())),
        Poll::Ready(Err(ServiceError::Unserved))
    );
    assert_eq!(
        services(&secret_table(Some(holds_secrets)))
            .records_secret(ticketed(0), "undeclared", "AKID")
            .map(|r| r.map(|s| s.live())),
        Poll::Ready(Err(ServiceError::Declined(Outcome::Refused)))
    );
    // PENDING on no ticket breaks the service's rule.
    assert_eq!(
        services(&secret_table(Some(holds_secrets)))
            .records_secret(handle(), "signing-key", "slow")
            .map(|r| r.map(|s| s.live())),
        Poll::Ready(Err(ServiceError::Broken))
    );
    assert_eq!(
        services(&secret_table(Some(holds_no_secret)))
            .records_secret(ticketed(0), "signing-key", "AKID")
            .map(|r| r.map(|s| s.live())),
        Poll::Ready(Err(ServiceError::Broken)),
        "a READY with no secret in span 0 is a broken host"
    );
}

/// THE HOLDER ZEROIZES: wiping a [`CredentialSecret`] zeroes every byte its buffer held, and the
/// holder is `ZeroizeOnDrop` (its one secret field is a `Zeroizing`, whose drop runs the same
/// wipe). RED against a holder over a plain `Vec`: the bytes outlive the wipe.
#[test]
fn the_secret_holder_zeroizes() {
    fn wipes_on_drop<T: ZeroizeOnDrop>() {}
    wipes_on_drop::<CredentialSecret>();
    let t = secret_table(Some(holds_secrets));
    let Poll::Ready(Ok(mut held)) = services(&t).records_secret(ticketed(0), "signing-key", "AKID")
    else {
        panic!("a held credential is READY");
    };
    let at = held.secret.as_ptr();
    let cap = held.secret.capacity();
    assert!(cap >= LIVE_SECRET.len());
    held.zeroize();
    // SAFETY: a wiped `Vec` keeps its allocation (`Vec::zeroize` zeroes the whole capacity and
    // clears the length); `held` is alive, so `cap` bytes at `at` are still its own.
    let after = unsafe { std::slice::from_raw_parts(at, cap) };
    assert!(after.iter().all(|b| *b == 0), "every byte is zeroed");
    assert!(held.secret().is_empty());
    assert!(!held.live());
}

/// ONE VERIFY'S HANDLES: [`VerifyOp`] issues the call's handles in order from `0`, so a body that
/// runs again from the top re-issues the same ones; on no ticket its `records.secret` is PENDING at
/// once with no crossing (the kit answers that `verify` REFUSED).
#[test]
fn a_verify_op_issues_its_handles_in_order_and_never_crosses_ticketless() {
    use crate::abi::sdk::auth_door::VerifyOp;
    let t = secret_table(Some(holds_secrets));
    let ticket = ticketed(0).ticket;
    let op = VerifyOp::new(Some(services(&t)), ticket);
    assert_eq!(op.handle(), ticketed(0));
    assert_eq!(op.handle(), ticketed(1));
    let Poll::Ready(Ok(live)) = op.records_secret("signing-key", "AKID") else {
        panic!("READY on a ticket");
    };
    assert_eq!(live.secret(), LIVE_SECRET);
    let none = VerifyOp::new(Some(services(&t)), Ticket::NONE);
    assert!(none.records_secret("signing-key", "probe").is_pending());
    assert_eq!(
        PROBE_CROSSINGS.load(Ordering::SeqCst),
        0,
        "no crossing on no ticket"
    );
    assert_eq!(
        VerifyOp::new(None, ticket)
            .records_secret("signing-key", "AKID")
            .map(|r| r.map(|s| s.live())),
        Poll::Ready(Err(ServiceError::Unserved))
    );
}

// ── TICKET.MINT: THE TICKET IS SEALED FROM THE PLANE (R7) ───────────────────────────────────────

/// The ticket the minting host writes: longer than the SDK's first buffer, so the first crossing is
/// the short answer.
fn minted_ticket() -> Vec<u8> {
    let mut t = b"bt_".to_vec();
    t.resize(600, b'k');
    t
}

/// When [`minted_ticket`] expires.
const MINTED_EXPIRES: u64 = 1_767_225_600;

/// How many `ticket.mint` crossings [`mints`] answered.
static MINTS: AtomicU8 = AtomicU8::new(0);

/// A host that mints [`minted_ticket`]: into the caller's buffer READY with its expiry, or FAILED
/// naming its length when the buffer is short.
extern "C" fn mints(_ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    MINTS.fetch_add(1, Ordering::SeqCst);
    // SAFETY: the wrapper hands a `TicketMintIn` naming its live buffer.
    let i = unsafe { input.cast::<TicketMintIn>().read_unaligned() };
    let ticket = minted_ticket();
    if i.into.cap < ticket.len() {
        // SAFETY: a live `out`.
        unsafe { (*out).needed_bytes = ticket.len() as u64 };
        return answer(out, Outcome::Failed, 0, 0, 0);
    }
    // SAFETY: `into.buf` holds `into.cap` writable bytes, at least the ticket's length.
    unsafe { std::ptr::copy_nonoverlapping(ticket.as_ptr(), i.into.buf, ticket.len()) };
    answer(out, Outcome::Ready, MINTED_EXPIRES, ticket.len() as u64, 0)
}

/// What a sealed answer puts on the wire, through the SDK's test-only driver.
fn sealed_wire(w: &mut crate::abi::sdk::cred::SealedWrite) -> Vec<u8> {
    let mut wire = Vec::new();
    let done = crate::abi::sdk::test_support::chip::drive_sealed::<()>(w, |b: &[u8]| {
        wire.extend_from_slice(b);
        Poll::Ready(Ok(b.len()))
    });
    assert!(done.is_ready(), "the sealed answer is taken whole");
    wire
}

/// RED-BEFORE-GREEN (R7: a plane never holds credential bytes; the chip precedent of the `ek_`
/// answer): `ticket.mint` hands the plane its bearer ticket SEALED. Nothing the plane can print
/// shows it, and the plane's only way to answer it on is the SDK's sealed JSON, which carries it
/// byte for byte to the host's buffer. A ticket longer than the first buffer is the short answer,
/// re-called once inside the call. RED before: the plane got the ticket as a `&str` view into a
/// buffer of its own.
#[test]
fn a_minted_ticket_reaches_the_plane_sealed() {
    let t = HostSlots {
        ticket_mint: Some(mints),
        ..table(None)
    };
    let before = MINTS.load(Ordering::SeqCst);
    let minted = services(&t)
        .ticket_mint(handle(), 600, br#"{"locked":true}"#)
        .expect("minted");
    assert_eq!(
        MINTS.load(Ordering::SeqCst) - before,
        2,
        "the short answer, then its one re-call"
    );
    assert_eq!(minted.expires_at_unix, MINTED_EXPIRES);
    assert_eq!(minted.ticket.len(), minted_ticket().len());
    assert!(minted.ticket.starts_with(b"bt_"));
    let shown = format!("{minted:?}");
    assert!(!shown.contains("bt_k"), "Debug shows the ticket: {shown}");
    assert!(shown.contains("<600 bytes>"), "{shown}");

    let mut answer = crate::abi::sdk::cred::SealedJson::new()
        .sealed("value", &minted.ticket)
        .public("expires_at_unix", minted.expires_at_unix)
        .encoded()
        .expect("the ticket is text");
    let ticket = String::from_utf8(minted_ticket()).expect("text");
    assert_eq!(
        sealed_wire(&mut answer),
        serde_json::to_vec(&serde_json::json!({
            "value": ticket,
            "expires_at_unix": MINTED_EXPIRES,
        }))
        .expect("json"),
        "the host's buffer receives the ticket byte for byte"
    );
}

/// A host that answers a ticket that is not UTF-8: broken, never handed on.
extern "C" fn mints_bytes(_ctx: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the wrapper hands a `TicketMintIn` naming its live buffer.
    let i = unsafe { input.cast::<TicketMintIn>().read_unaligned() };
    // SAFETY: the SDK's first buffer holds far more than two bytes.
    unsafe { std::ptr::copy_nonoverlapping([0xff_u8, 0xfe].as_ptr(), i.into.buf, 2) };
    answer(out, Outcome::Ready, MINTED_EXPIRES, 2, 0)
}

#[test]
fn a_minted_ticket_that_is_not_text_is_broken() {
    let t = HostSlots {
        ticket_mint: Some(mints_bytes),
        ..table(None)
    };
    assert_eq!(
        services(&t)
            .ticket_mint(handle(), 600, b"{}")
            .map(|m| m.expires_at_unix),
        Err(ServiceError::Broken)
    );
}
