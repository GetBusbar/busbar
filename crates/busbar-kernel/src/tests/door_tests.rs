// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The door's kernel-side acts: the facts an admitted or refused unit ends with, and the zero hold
//! an exact admission carries.

use super::*;

#[test]
fn an_admitted_unit_ends_as_its_plane_reported() {
    let op = OpClassId::new("chat");
    for reported in [
        FinishClass::Complete,
        FinishClass::Partial,
        FinishClass::Error,
    ] {
        assert_eq!(admitted_facts(op, Some(reported), true).finish, reported);
        assert_eq!(admitted_facts(op, Some(reported), false).finish, reported);
    }
}

#[test]
fn an_admitted_unit_with_no_reported_end_reads_its_status() {
    let op = OpClassId::new("chat");
    assert_eq!(admitted_facts(op, None, true).finish, FinishClass::Complete);
    assert_eq!(admitted_facts(op, None, false).finish, FinishClass::Error);
    assert_eq!(admitted_facts(op, None, true).op_class, op);
}

#[test]
fn a_refused_unit_is_never_a_completion() {
    let op = OpClassId::new("chat");
    let f = refused_facts(op);
    assert_eq!((f.op_class, f.finish), (op, FinishClass::Error));
}

/// Under `admission: exact` (the default) the admission carries a ZERO hold. The design's budget
/// modes: "the 'hold sized at admit from estimate' idea ... becomes the estimate mode only"; exact
/// refuses at admit only a budget already exhausted and reserves nothing. RED: any admission that
/// reserves (an estimate-sized hold) fails this pin.
#[test]
fn an_exact_admission_carries_a_zero_hold() {
    use busbar_contract::caps::KernelSeal;
    let seal = KernelSeal::acquire_for_kernel();
    let admit: Grant<Admittance> = Grant::<Admittance>::mint(&seal);
    match admitted_at_zero(&admit, PrincipalId::new("vk_exact")) {
        Admission::Own(hold) => {
            assert_eq!(hold.principal().as_str(), "vk_exact");
        }
        _ => panic!("an exact admission opens the unit's own hold"),
    }
}

fn usage(
    input: u64,
    output: u64,
    read: Option<u64>,
    write: Option<u64>,
) -> busbar_contract::billing::TokenUsage {
    busbar_contract::billing::TokenUsage {
        input,
        output,
        cache_read: read,
        cache_creation: write,
        ..Default::default()
    }
}

#[test]
fn the_metering_row_counts_its_request_and_carries_no_card_instant() {
    let u = usage(7, 2, Some(1), None);
    let row = metering_row("k1", "lane-a", "prov", Some(&u));
    assert_eq!(
        (
            row.key_id.as_str(),
            row.model.as_str(),
            row.provider.as_str()
        ),
        ("k1", "lane-a", "prov")
    );
    assert_eq!((row.tokens_input, row.tokens_output), (7, 2));
    assert_eq!((row.tokens_cache_read, row.tokens_cache_write), (1, 0));
    assert_eq!((row.requests, row.billable_requests), (1, 1));
    assert_eq!(row.priced_from_ms, 0);
    let empty = metering_row("k1", "lane-a", "prov", None);
    assert_eq!((empty.tokens_input, empty.requests), (0, 1));
}
