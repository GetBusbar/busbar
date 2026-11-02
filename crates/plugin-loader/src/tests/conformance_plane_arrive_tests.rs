// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::{arrival_line, output, ArriveOut, Called, PRINCIPAL_REQUIRED};
use busbar_contract::abi::mechanism::call::{AbiStr, Outcome};

fn called(outcome: Outcome) -> Called {
    Called {
        outcome,
        error: None,
        lease: 0,
        recall: None,
    }
}

fn poisoned() -> ArriveOut {
    let unread = AbiStr {
        ptr: std::ptr::dangling::<u8>(),
        len: usize::MAX,
    };
    let mut out: ArriveOut = output();
    out.head.lease = u64::MAX;
    out.head.error = unread;
    out.op_class = u32::MAX;
    out.principal_need = u32::MAX;
    out.dialect = u32::MAX;
    out.units_written = u32::MAX;
    out.units_needed = u32::MAX;
    out.refusal = u32::MAX;
    out.refusal_status = u32::MAX;
    out.refusal_flags = u32::MAX;
    out.correlation = u64::MAX;
    out.cancels = u64::MAX;
    out.pool = unread;
    out.route = u8::MAX;
    out.route_flags = u8::MAX;
    out.affinity = unread;
    out.trust_counterparty = unread;
    out.trust_item = unread;
    out.trust_digest = unread;
    out
}

#[test]
fn refused_arrival_renders_only_its_documented_scalars_and_copied_error() {
    let mut out = poisoned();
    out.refusal = 7;
    out.refusal_status = 405;
    let mut refused = called(Outcome::Refused);
    refused.error = Some(b"unclaimed".to_vec());
    for route in [false, true] {
        assert_eq!(
            arrival_line(&refused, &out, route),
            "Refused lease=false unclaimed refusal=7 status=405"
        );
    }
}

#[test]
fn fault_failed_and_pending_arrivals_never_read_poisoned_payload_fields() {
    let out = poisoned();
    for outcome in [Outcome::Fault, Outcome::Failed, Outcome::Pending] {
        for route in [false, true] {
            assert_eq!(
                arrival_line(&called(outcome), &out, route),
                format!("{outcome:?} lease=false  UNREAD")
            );
        }
    }
}

#[test]
fn ready_arrival_keeps_its_existing_scalar_format() {
    let mut out: ArriveOut = output();
    out.op_class = 2;
    out.principal_need = PRINCIPAL_REQUIRED;
    out.dialect = 1;
    out.units_written = 3;
    assert_eq!(
        arrival_line(&called(Outcome::Ready), &out, false),
        "Ready lease=false  op_class=2 principal_required=true dialect=1 units=3 refusal=0 status=0"
    );
}
