// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host services' validators (`abi/host/service.rs`): one test per arm, each answer built to
//! break exactly one rule.

use super::*;
use crate::abi::mechanism::check::SPAN_ABSENT;
use crate::abi::mechanism::ticket::Ticket;

const TICKET: Ticket = Ticket {
    slot: 7,
    generation: 1,
};

fn head(service: u32, ticket: Ticket, size: usize) -> ServiceHead {
    ServiceHead {
        size: size as u32,
        op: service,
        handle: CompletionHandle {
            ticket,
            seq: 0,
            _reserved: 0,
        },
    }
}

fn out(o: Outcome) -> ServiceOut {
    ServiceOut {
        size: core::mem::size_of::<ServiceOut>() as u32,
        outcome: RawOutcome::of(o),
        _reserved: [0; 3],
        value: 0,
        len: 0,
        items: 0,
        needed_bytes: 0,
        needed_items: 0,
        error: AbiStr {
            ptr: core::ptr::null(),
            len: 0,
        },
    }
}

fn none() -> AbiStr {
    AbiStr {
        ptr: core::ptr::null(),
        len: 0,
    }
}

fn empty_blob() -> Blob {
    Blob {
        ptr: core::ptr::null(),
        len: 0,
        fmt: 0,
        flags: 0,
    }
}

fn bufs(buf: &mut [u8], spans: &mut [ItemSpan]) -> ServiceBufs {
    ServiceBufs {
        buf: buf.as_mut_ptr(),
        cap: buf.len(),
        spans: spans.as_mut_ptr(),
        spans_cap: spans.len(),
    }
}

fn get_in(ticket: Ticket, into: ServiceBufs) -> RecordsGetIn {
    RecordsGetIn {
        head: head(
            op::RECORDS_GET,
            ticket,
            core::mem::size_of::<RecordsGetIn>(),
        ),
        kind: none(),
        key: none(),
        into,
    }
}

fn judge_in(ticket: Ticket) -> DestJudgeIn {
    DestJudgeIn {
        head: head(op::DEST_JUDGE, ticket, core::mem::size_of::<DestJudgeIn>()),
        dest: none(),
        egress_class: 0,
        flags: 0,
    }
}

fn ready(o: &ServiceOut) -> RawOutcome {
    o.outcome
}

fn rule(r: Result<Filled, Fault>) -> Rule {
    r.expect_err("the answer must be FAULT").rule
}

#[test]
fn a_mirrored_outcome_that_differs_from_the_return_value_is_fault() {
    let i = judge_in(TICKET);
    let o = out(Outcome::Ready);
    let r = check_dest_judge(&i, RawOutcome::of(Outcome::Failed), &o);
    assert_eq!(
        r.unwrap_err(),
        fault(Rule::Contradiction, "service.out.outcome")
    );
}

#[test]
fn an_out_of_a_foreign_size_is_fault() {
    let i = judge_in(TICKET);
    let mut o = out(Outcome::Ready);
    o.size -= 8;
    assert_eq!(rule(check_dest_judge(&i, ready(&o), &o)), Rule::Foreign);
}

#[test]
fn pending_from_a_service_that_never_pends_is_fault() {
    let mut reading = ClockReading {
        size: 0,
        _reserved: 0,
        wall_ns: 0,
        mono_ns: 0,
    };
    let i = ClockNowIn {
        head: head(op::CLOCK_NOW, TICKET, core::mem::size_of::<ClockNowIn>()),
        reading: &mut reading,
    };
    let o = out(Outcome::Pending);
    assert_eq!(
        check_clock_now(&i, ready(&o), &o).unwrap_err(),
        fault(Rule::Contradiction, "service.out.pending")
    );
}

#[test]
fn pending_without_a_ticket_is_fault_and_with_one_is_legal() {
    let o = out(Outcome::Pending);
    assert_eq!(
        rule(check_dest_judge(&judge_in(Ticket::NONE), ready(&o), &o)),
        Rule::Contradiction
    );
    assert_eq!(
        check_dest_judge(&judge_in(TICKET), ready(&o), &o),
        Ok(Filled::Written)
    );
}

#[test]
fn a_needed_size_above_the_maximum_is_fault() {
    let (mut b, mut s) = ([0u8; 4], [ItemSpan::default_absent(); 1]);
    let i = get_in(TICKET, bufs(&mut b, &mut s));
    let mut o = out(Outcome::Failed);
    o.needed_items = MAX_SPANS + 1;
    assert_eq!(rule(check_records_get(&i, ready(&o), &o)), Rule::OverMax);
}

#[test]
fn refused_never_carries_a_needed_size() {
    let (mut b, mut s) = ([0u8; 4], [ItemSpan::default_absent(); 1]);
    let i = get_in(TICKET, bufs(&mut b, &mut s));
    let mut o = out(Outcome::Refused);
    o.needed_bytes = 64;
    assert_eq!(
        rule(check_records_get(&i, ready(&o), &o)),
        Rule::NeededNotFailed
    );
}

#[test]
fn a_short_answer_where_every_dimension_fits_is_fault() {
    let (mut b, mut s) = ([0u8; 4], [ItemSpan::default_absent(); 1]);
    let i = get_in(TICKET, bufs(&mut b, &mut s));
    let mut o = out(Outcome::Failed);
    o.needed_bytes = 4;
    o.needed_items = 1;
    assert_eq!(
        rule(check_records_get(&i, ready(&o), &o)),
        Rule::WastedRecall
    );
}

#[test]
fn one_dimension_short_with_the_other_fitting_is_a_legal_short_answer() {
    let (mut b, mut s) = ([0u8; 4], [ItemSpan::default_absent(); 1]);
    let i = get_in(TICKET, bufs(&mut b, &mut s));
    let mut o = out(Outcome::Failed);
    o.needed_bytes = 5;
    o.needed_items = 1;
    assert_eq!(check_records_get(&i, ready(&o), &o), Ok(Filled::Short));
}

#[test]
fn a_short_answer_that_wrote_something_is_fault() {
    let (mut b, mut s) = ([0u8; 4], [ItemSpan::default_absent(); 1]);
    let i = get_in(TICKET, bufs(&mut b, &mut s));
    let mut o = out(Outcome::Failed);
    o.needed_bytes = 5;
    o.len = 1;
    assert_eq!(
        rule(check_records_get(&i, ready(&o), &o)),
        Rule::WrittenOnShort
    );
}

#[test]
fn a_service_with_no_buffer_that_wrote_bytes_is_fault() {
    let i = judge_in(TICKET);
    let mut o = out(Outcome::Ready);
    o.len = 1;
    assert_eq!(rule(check_dest_judge(&i, ready(&o), &o)), Rule::OverCap);
}

#[test]
fn a_span_outside_the_bytes_written_is_fault() {
    let (mut b, mut s) = ([0u8; 4], [ItemSpan::default_absent(); 1]);
    s[0] = ItemSpan {
        key_off: SPAN_ABSENT,
        key_len: 0,
        value_off: 2,
        value_len: 3,
    };
    let i = get_in(TICKET, bufs(&mut b, &mut s));
    let mut o = out(Outcome::Ready);
    o.value = FOUND;
    o.len = 4;
    o.items = 1;
    assert_eq!(
        check_records_get(&i, ready(&o), &o).unwrap_err(),
        fault(Rule::SpanOutOfBounds, "service.out.span.value")
    );
}

#[test]
fn an_absent_span_with_a_length_is_fault() {
    let (mut b, mut s) = ([0u8; 4], [ItemSpan::default_absent(); 1]);
    s[0].key_len = 1;
    let i = get_in(TICKET, bufs(&mut b, &mut s));
    let mut o = out(Outcome::Ready);
    o.value = FOUND;
    o.len = 4;
    o.items = 1;
    assert_eq!(
        rule(check_records_get(&i, ready(&o), &o)),
        Rule::SpanNotAbsent
    );
}

#[test]
fn a_well_formed_found_record_is_legal() {
    let (mut b, mut s) = ([0u8; 4], [ItemSpan::default_absent(); 1]);
    s[0].value_off = 0;
    s[0].value_len = 4;
    let i = get_in(TICKET, bufs(&mut b, &mut s));
    let mut o = out(Outcome::Ready);
    o.value = FOUND;
    o.len = 4;
    o.items = 1;
    assert_eq!(check_records_get(&i, ready(&o), &o), Ok(Filled::Written));
}

#[test]
fn a_ready_value_outside_the_service_range_is_fault() {
    let mut o = out(Outcome::Ready);
    o.value = DEST_NO_ADDRESSES + 1;
    assert_eq!(
        check_dest_judge(&judge_in(TICKET), ready(&o), &o).unwrap_err(),
        fault(Rule::UnknownCode, "service.out.value")
    );
    o.value = DEST_NO_ADDRESSES;
    assert!(check_dest_judge(&judge_in(TICKET), ready(&o), &o).is_ok());

    let claim = RecordsClaimIn {
        head: head(op::RECORDS_CLAIM, TICKET, 0),
        kind: none(),
        key: none(),
        ttl_ms: 0,
    };
    o.value = 0;
    assert_eq!(
        rule(check_records_claim(&claim, ready(&o), &o)),
        Rule::UnknownCode
    );
    let sight = TrustSightIn {
        head: head(op::TRUST_SIGHT, TICKET, 0),
        counterparty: none(),
        catalogue_hash: none(),
    };
    o.value = TRUST_QUARANTINED + 1;
    assert_eq!(
        rule(check_trust_sight(&sight, ready(&o), &o)),
        Rule::UnknownCode
    );
    let ent = EntitlementCheckIn {
        head: head(op::ENTITLEMENT_CHECK, TICKET, 0),
        target: none(),
    };
    o.value = ENTITLED + 1;
    assert_eq!(
        rule(check_entitlement_check(&ent, ready(&o), &o)),
        Rule::UnknownCode
    );
    let open = WorkOpenIn {
        head: head(op::WORK_OPEN, TICKET, 0),
        kind: none(),
        record: empty_blob(),
    };
    o.value = 0;
    assert_eq!(
        rule(check_work_open(&open, ready(&o), &o)),
        Rule::UnknownCode
    );
}

#[test]
fn a_claim_with_no_time_to_live_is_refused() {
    let mut claim = RecordsClaimIn {
        head: head(
            op::RECORDS_CLAIM,
            TICKET,
            core::mem::size_of::<RecordsClaimIn>(),
        ),
        kind: none(),
        key: none(),
        ttl_ms: 0,
    };
    assert_eq!(
        check_records_claim_in(&claim).unwrap_err(),
        fault(Rule::Missing, "records_claim.ttl_ms")
    );
    claim.ttl_ms = 1;
    assert!(check_records_claim_in(&claim).is_ok());
}

#[test]
fn a_clock_reading_must_be_there_and_of_this_layout() {
    let o = out(Outcome::Ready);
    let null = ClockNowIn {
        head: head(op::CLOCK_NOW, Ticket::NONE, 0),
        reading: core::ptr::null_mut(),
    };
    assert_eq!(
        rule(check_clock_now(&null, ready(&o), &o)),
        Rule::NullWithCount
    );
    let mut reading = ClockReading {
        size: 8,
        _reserved: 0,
        wall_ns: 1,
        mono_ns: 1,
    };
    let i = ClockNowIn {
        head: head(op::CLOCK_NOW, Ticket::NONE, 0),
        reading: &mut reading,
    };
    assert_eq!(rule(check_clock_now(&i, ready(&o), &o)), Rule::Foreign);
    reading.size = core::mem::size_of::<ClockReading>() as u32;
    let i = ClockNowIn {
        head: head(op::CLOCK_NOW, Ticket::NONE, 0),
        reading: &mut reading,
    };
    assert_eq!(check_clock_now(&i, ready(&o), &o), Ok(Filled::Written));
}

#[test]
fn the_host_refuses_an_in_for_another_service_or_of_a_short_size() {
    let h = head(op::DEST_JUDGE, TICKET, core::mem::size_of::<DestJudgeIn>());
    assert!(check_head(&h, op::DEST_JUDGE, core::mem::size_of::<DestJudgeIn>()).is_ok());
    assert_eq!(
        check_head(&h, op::CLOCK_NOW, core::mem::size_of::<DestJudgeIn>()).unwrap_err(),
        fault(Rule::Contradiction, "service.head.op")
    );
    let short = head(
        op::DEST_JUDGE,
        TICKET,
        core::mem::size_of::<DestJudgeIn>() - 1,
    );
    assert_eq!(
        check_head(&short, op::DEST_JUDGE, core::mem::size_of::<DestJudgeIn>()).unwrap_err(),
        fault(Rule::Foreign, "service.head.size")
    );
}

#[test]
fn the_host_refuses_a_capacity_with_a_null_buffer() {
    let mut b = bufs(&mut [], &mut []);
    b.buf = core::ptr::null_mut();
    b.cap = 1;
    assert_eq!(
        check_bufs(&b).unwrap_err(),
        fault(Rule::NullWithCount, "service.into.buf")
    );
    let mut b = bufs(&mut [], &mut []);
    b.spans = core::ptr::null_mut();
    b.spans_cap = 1;
    assert_eq!(
        check_bufs(&b).unwrap_err(),
        fault(Rule::NullWithCount, "service.into.spans")
    );
}

#[test]
fn the_services_that_never_pend_are_exactly_the_stated_six() {
    let never: Vec<u32> = (0..SERVICES).filter(|s| !may_pend(*s)).collect();
    assert_eq!(
        never,
        [
            op::CLOCK_NOW,
            op::SIGN,
            op::TRUST_DUE,
            op::VERIFY_STORE,
            op::ENTITLEMENT_CHECK,
            op::RANDOM_FILL
        ]
    );
    assert!(!may_pend(SERVICES), "an index past the table never pends");
}

#[test]
fn the_table_holds_one_slot_per_service() {
    let slots = (core::mem::size_of::<HostSlots>() - 8) / core::mem::size_of::<usize>();
    assert_eq!(slots, SERVICES as usize);
}

impl ItemSpan {
    fn default_absent() -> Self {
        ItemSpan {
            key_off: SPAN_ABSENT,
            key_len: 0,
            value_off: SPAN_ABSENT,
            value_len: 0,
        }
    }
}

/// THE SLOT ORDER, pinned: each service's field sits at the table index its `op` constant names,
/// one function pointer apart after the two `u32` heads. Services are appended in landing order;
/// a later append that reorders an earlier one fails here, and the loader's table (built field by
/// field) follows the same order.
#[test]
fn every_service_field_sits_at_its_op_index() {
    use core::mem::{offset_of, size_of};
    let slot = |op: u32| 8 + op as usize * size_of::<Option<ServiceFn>>();
    let table = [
        (offset_of!(HostSlots, clock_now), op::CLOCK_NOW),
        (offset_of!(HostSlots, records_get), op::RECORDS_GET),
        (offset_of!(HostSlots, records_list), op::RECORDS_LIST),
        (offset_of!(HostSlots, records_claim), op::RECORDS_CLAIM),
        (offset_of!(HostSlots, dest_judge), op::DEST_JUDGE),
        (offset_of!(HostSlots, sign), op::SIGN),
        (offset_of!(HostSlots, unit_nest), op::UNIT_NEST),
        (offset_of!(HostSlots, work_open), op::WORK_OPEN),
        (offset_of!(HostSlots, work_find), op::WORK_FIND),
        (offset_of!(HostSlots, work_settle), op::WORK_SETTLE),
        (offset_of!(HostSlots, work_resume), op::WORK_RESUME),
        (offset_of!(HostSlots, trust_sight), op::TRUST_SIGHT),
        (offset_of!(HostSlots, trust_due), op::TRUST_DUE),
        (offset_of!(HostSlots, verify_lookup), op::VERIFY_LOOKUP),
        (offset_of!(HostSlots, verify_store), op::VERIFY_STORE),
        (
            offset_of!(HostSlots, entitlement_check),
            op::ENTITLEMENT_CHECK,
        ),
        (offset_of!(HostSlots, content_scan), op::CONTENT_SCAN),
        (offset_of!(HostSlots, hook_call), op::HOOK_CALL),
        (offset_of!(HostSlots, random_fill), op::RANDOM_FILL),
    ];
    for (i, (offset, op)) in table.iter().enumerate() {
        assert_eq!(*op as usize, i, "op constants run 0.. in table order");
        assert_eq!(*offset, slot(*op), "field of op {op} sits at its index");
    }
    assert_eq!(table.len(), SERVICES as usize);
    assert_eq!(size_of::<HostSlots>(), slot(SERVICES));
}
