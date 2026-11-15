// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SHUTDOWN-HANG §5: the process-wide record ledger. Each test owns fresh random writer ids, so
//! tests sharing the static see only their own targets.

use super::*;

fn writer(observed_by: ObservedBy) -> UndrainedWriter {
    let mut id = [0; 16];
    busbar_contract::crypto::fill(&mut id).unwrap();
    UndrainedWriter {
        node: Some(7),
        other_nodes: vec![9],
        epoch: 3,
        writer: id,
        host: Some("host-a".into()),
        observed_by,
    }
}

fn listed(report: &[UndrainedWriter], seen: &UndrainedWriter) -> bool {
    report.iter().any(|s| s == seen)
}

#[test]
fn a_record_is_confirmed_only_by_a_mark_taken_after_it() {
    let ledger = undrained_records();
    let early = writer(ObservedBy::Successor);
    ledger.retain(&early);
    assert!(
        listed(&ledger.exit_report().unconfirmed, &early),
        "retained is listed"
    );
    assert_eq!(ledger.decided(&early, true), None);
    let mark = ledger.mark();
    let late = writer(ObservedBy::Adopter);
    ledger.retain(&late);
    assert_eq!(ledger.decided(&late, true), None);
    ledger.confirm_before(mark);
    let report = ledger.exit_report();
    assert!(
        !listed(&report.unconfirmed, &early),
        "recorded before the mark: confirmed"
    );
    assert!(
        listed(&report.unconfirmed, &late),
        "recorded at or after the mark: printed"
    );
    ledger.confirm_before(ledger.mark());
    assert!(!listed(&ledger.exit_report().unconfirmed, &late));
}

#[test]
fn a_close_that_did_not_apply_records_nothing() {
    let ledger = undrained_records();
    let seen = writer(ObservedBy::ExpiredLeasePass);
    ledger.retain(&seen);
    let before = ledger.mark();
    assert_eq!(ledger.decided(&seen, false), None);
    assert_eq!(ledger.mark(), before, "no generation was taken");
    let report = ledger.exit_report();
    assert!(!listed(&report.unconfirmed, &seen));
    assert!(!listed(&report.unrecorded, &seen));
}

#[test]
fn a_lost_decision_is_listed_unconfirmed() {
    let ledger = undrained_records();
    let seen = writer(ObservedBy::Successor);
    ledger.retain(&seen);
    ledger.lost(&seen);
    assert!(listed(&ledger.exit_report().unconfirmed, &seen));
}

#[test]
fn a_record_the_full_queue_refuses_is_held_and_named() {
    let ledger = undrained_records();
    // Fill the admin audit queue to its bound; nothing drains it (no native owner here).
    let mut filled = 0;
    while crate::audit::auditlog::try_emit_admin_hostless_now("test.fill", "x", "ok", "system")
        .is_ok()
    {
        filled += 1;
        assert!(filled <= 4096, "the admin audit queue is bounded");
    }
    let seen = writer(ObservedBy::ExpiredLeasePass);
    ledger.retain(&seen);
    assert!(
        ledger.decided(&seen, true).is_some(),
        "the refusal is returned"
    );
    assert!(ledger.has_unrecorded());
    let report = ledger.exit_report();
    assert!(listed(&report.unrecorded, &seen));
    assert!(
        !listed(&report.unconfirmed, &seen),
        "never counted as recorded"
    );
    assert_eq!(
        ledger.retry_unrecorded(),
        0,
        "still refused while the queue is full"
    );
    assert!(listed(&ledger.exit_report().unrecorded, &seen));
}

#[test]
fn the_record_names_the_writer() {
    let seen = writer(ObservedBy::ExpiredLeasePass);
    let resource = seen.resource();
    assert!(resource.contains(&format!("writer={}", hex::encode(seen.writer))));
    assert!(resource.contains("epoch=3 node=7 other_nodes=[9] host=host-a"));
    assert!(resource.ends_with("observed_by=expired_lease_pass"));
}
