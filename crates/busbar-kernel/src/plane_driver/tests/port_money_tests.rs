// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IF §12.4 over the plane port: a session's cumulative USAGE becomes the unit's counts, a checkpoint asks the
//! budget, and the session's end posts what the cancel table says (never more), through the existing money seam.

use std::sync::{Arc, Mutex};

use busbar_contract::abi::measurement::{UNITS_ESTIMATED, UNITS_FLOOR, UNITS_REPORTED};
use busbar_contract::abi::plane::{UnitCount, CANCEL_ABORTED, CANCEL_FAILED, CANCEL_OK_PARTIAL};
use busbar_contract::caps::{OriginKind, ReasonCode};
use busbar_contract::UnitKey;
use busbar_plugin_abi::plane::{
    UsageRec, AUDIT_APPLIED, AUDIT_REJECTED, SRC_ESTIMATED, SRC_FLOOR, SRC_REPORTED,
};

use super::{unit_counts, AuditRow, PortMoney};
use crate::plane_driver::cancel::{CancelBill, Checkpoint, MoneySeam};
use crate::plane_driver::usage::{Ending, SessionUsage};
use crate::plane_driver::AuditSink;
use crate::registry::Generation;
use crate::teller::{Ended, UnitCtx};

fn ctx() -> UnitCtx {
    UnitCtx {
        call: busbar_contract::caps::CallId::UNBOUND,
        key: UnitKey::new(9),
        origin: OriginKind::Client,
        session: None,
        generation: Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    }
}

fn classes() -> Arc<[String]> {
    Arc::from(vec!["requests".to_string(), "tokens".to_string()])
}

fn usage(rows: &[(&str, u64, u32, u32)]) -> SessionUsage {
    let mut u = SessionUsage::new();
    for &(class, amount, scale, source) in rows {
        u.answer(
            class,
            UsageRec {
                amount,
                scale,
                source,
            },
        )
        .unwrap();
    }
    u
}

#[derive(Default)]
struct Seam {
    log: Mutex<Vec<String>>,
    counts: Mutex<Vec<Vec<(u32, u32, u64)>>>,
    bills: Mutex<Vec<CancelBill>>,
    answer: Option<Checkpoint>,
}

impl MoneySeam for Seam {
    fn checkpoint(&self, _: &UnitCtx, units: &[UnitCount]) -> Checkpoint {
        self.log.lock().unwrap().push("checkpoint".into());
        self.counts.lock().unwrap().push(
            units
                .iter()
                .map(|u| (u.class, u.source, u.amount))
                .collect(),
        );
        self.answer.unwrap_or(Checkpoint::Continue)
    }

    fn cancelled(&self, _: &UnitCtx, bill: &CancelBill) {
        self.log.lock().unwrap().push("cancelled".into());
        self.bills.lock().unwrap().push(bill.clone());
    }

    fn finished(&self, _: &UnitCtx) {
        self.log.lock().unwrap().push("finished".into());
    }

    fn abandoned(&self, _: &UnitCtx, _: Ended) {
        self.log.lock().unwrap().push("abandoned".into());
    }
}

#[derive(Default)]
struct Audits(Mutex<Vec<(String, String, &'static str, String)>>);

impl AuditSink for Audits {
    fn record(&self, action: &str, resource: &str, outcome: &'static str, principal: &str) {
        self.0
            .lock()
            .unwrap()
            .push((action.into(), resource.into(), outcome, principal.into()));
    }
}

fn money(seam: Arc<Seam>, audits: Arc<Audits>) -> PortMoney {
    PortMoney::new(seam, classes(), audits)
}

#[test]
fn a_usage_becomes_a_count_at_its_class_index_and_source() {
    let counted = unit_counts(
        &usage(&[
            ("tokens", 120, 0, SRC_REPORTED),
            ("requests", 1, 0, SRC_ESTIMATED),
            ("tokens", 3, 0, SRC_FLOOR),
        ]),
        &classes(),
    );
    let got: Vec<(u32, u32, u64)> = counted
        .counts
        .iter()
        .map(|u| (u.class, u.source, u.amount))
        .collect();
    assert_eq!(
        got,
        vec![
            (1, UNITS_REPORTED, 120),
            (0, UNITS_ESTIMATED, 1),
            (1, UNITS_FLOOR, 3)
        ]
    );
    assert!(counted.dropped.is_empty());
}

#[test]
fn a_fractional_usage_is_stated_in_micro_units_and_a_deep_scale_is_rounded_and_named() {
    let counted = unit_counts(
        &usage(&[("tokens", 1_500_000, 6, SRC_REPORTED)]),
        &classes(),
    );
    assert_eq!(counted.counts[0].amount, 1_500_000);
    assert_eq!(counted.counts[0].source, UNITS_REPORTED + 3);
    let counted = unit_counts(
        &usage(&[("tokens", 1_500_000_001, 9, SRC_REPORTED)]),
        &classes(),
    );
    assert_eq!(counted.rounded.len(), 1);
    assert_eq!(&*counted.rounded[0], "tokens");
}

#[test]
fn a_class_the_plane_never_declared_is_dropped_and_named() {
    let counted = unit_counts(&usage(&[("images", 2, 0, SRC_REPORTED)]), &classes());
    assert!(counted.counts.is_empty());
    assert_eq!(&*counted.dropped[0], "images");
}

#[test]
fn a_checkpoint_hands_the_budget_the_cumulative_counts_and_returns_its_verdict() {
    let seam = Arc::new(Seam {
        answer: Some(Checkpoint::Cut),
        ..Seam::default()
    });
    let m = money(Arc::clone(&seam), Arc::default());
    let verdict = m.checkpoint(&ctx(), &usage(&[("tokens", 10, 0, SRC_REPORTED)]), None);
    assert_eq!(verdict, Checkpoint::Cut);
    assert_eq!(
        seam.counts.lock().unwrap()[0],
        vec![(1, UNITS_REPORTED, 10)]
    );
}

#[test]
fn a_dropped_class_is_audited_degraded_under_the_principal_once_per_checkpoint() {
    let audits = Arc::new(Audits::default());
    let m = money(Arc::new(Seam::default()), Arc::clone(&audits));
    m.checkpoint(&ctx(), &usage(&[("images", 2, 0, SRC_REPORTED)]), None);
    let rows = audits.0.lock().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, "plane_usage_class_undeclared");
    assert!(rows[0].1.contains("images"));
    assert_eq!(rows[0].2, busbar_contract::vocab::OUTCOME_DEGRADED);
}

#[test]
fn an_end_posts_the_final_counts_then_finishes_and_an_end_with_no_usage_only_finishes() {
    let seam = Arc::new(Seam::default());
    let m = money(Arc::clone(&seam), Arc::default());
    m.ended(
        &ctx(),
        Ending::End,
        &usage(&[("tokens", 5, 0, SRC_REPORTED)]),
        None,
    );
    assert_eq!(*seam.log.lock().unwrap(), vec!["checkpoint", "finished"]);
    let seam = Arc::new(Seam::default());
    let m = money(Arc::clone(&seam), Arc::default());
    m.ended(&ctx(), Ending::End, &SessionUsage::new(), None);
    assert_eq!(*seam.log.lock().unwrap(), vec!["finished"]);
}

#[test]
fn a_cancel_bills_reported_units_only_when_the_far_end_answered_and_a_byte_streamed() {
    let cancel = |answered, streamed| Ending::Cancel {
        cause: ReasonCode::ClientGone,
        far_end_answered: answered,
        streamed,
    };
    let held = usage(&[
        ("tokens", 5, 0, SRC_REPORTED),
        ("requests", 1, 0, SRC_ESTIMATED),
    ]);
    for (answered, streamed, billed) in [
        (true, true, 1),
        (true, false, 0),
        (false, true, 0),
        (false, false, 0),
    ] {
        let seam = Arc::new(Seam::default());
        money(Arc::clone(&seam), Arc::default()).ended(
            &ctx(),
            cancel(answered, streamed),
            &held,
            None,
        );
        let bills = seam.bills.lock().unwrap();
        assert_eq!(bills.len(), 1, "{answered} {streamed}");
        assert_eq!(bills[0].billed.len(), billed, "{answered} {streamed}");
        assert_eq!(bills[0].cause, ReasonCode::ClientGone);
        assert_eq!(bills[0].far_end_answered, answered);
        assert_eq!(bills[0].streamed, streamed);
        let disposition = if billed == 1 {
            CANCEL_OK_PARTIAL
        } else {
            CANCEL_ABORTED
        };
        assert_eq!(bills[0].disposition, disposition);
    }
}

#[test]
fn a_failed_session_bills_nothing_and_is_a_failed_cancel() {
    let seam = Arc::new(Seam::default());
    let held = usage(&[("tokens", 5, 0, SRC_REPORTED)]);
    money(Arc::clone(&seam), Arc::default()).ended(&ctx(), Ending::Failed, &held, None);
    let bills = seam.bills.lock().unwrap();
    assert!(bills[0].billed.is_empty());
    assert_eq!(bills[0].disposition, CANCEL_FAILED);
}

#[test]
fn an_audit_row_goes_to_the_chain_under_the_principal_and_an_unknown_verdict_is_refused() {
    let audits = Arc::new(Audits::default());
    let m = money(Arc::new(Seam::default()), Arc::clone(&audits));
    let applied = AuditRow {
        verdict: AUDIT_APPLIED,
        action: "plane.thing".into(),
        resource: "r1".into(),
    };
    let rejected = AuditRow {
        verdict: AUDIT_REJECTED,
        action: "plane.thing".into(),
        resource: String::new().into(),
    };
    assert!(m.audit(&applied, Some("ada")).is_ok());
    assert!(m.audit(&rejected, None).is_ok());
    let rows = audits.0.lock().unwrap();
    assert_eq!(
        rows[0],
        (
            "plane.thing".into(),
            "r1".into(),
            busbar_contract::vocab::OUTCOME_APPLIED,
            "ada".into()
        )
    );
    assert_eq!(rows[1].2, busbar_contract::vocab::OUTCOME_REJECTED);
    let unknown = AuditRow {
        verdict: 77,
        action: "a".into(),
        resource: "b".into(),
    };
    assert!(m.audit(&unknown, None).is_err());
}
