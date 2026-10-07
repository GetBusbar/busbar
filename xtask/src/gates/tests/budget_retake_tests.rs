//! AN OVER-BUDGET BATTERY IS RE-TAKEN SERIALLY BEFORE IT COUNTS (ARCHITECT 2026-10-07): the budget
//! is measured at `--jobs 1`, so a contended reading over it is taken once more at `--jobs 1` and
//! the serial reading is the verdict. RED: a battery twice its budget serially stays red. GREEN: a
//! battery over only under contention comes out green. No third try.

use super::*;

#[test]
fn a_battery_twice_its_budget_stays_red_after_the_serial_retake() {
    let r = budget_verdict(1_000.0, 2_600.0, 8, || 2_000.0);
    assert_eq!(
        r.serial,
        Some(2_000.0),
        "an over-budget contended reading is re-taken"
    );
    assert!(r.over(), "twice the budget serially is red");
    assert_eq!(r.spent(), 2_000.0, "the serial reading is the verdict");
    let line = r.retake_line().expect("both readings are printed");
    assert!(line.contains("contended 2600 → serial 2000"), "{line}");
}

#[test]
fn a_battery_over_only_under_contention_is_green_after_the_serial_retake() {
    let r = budget_verdict(1_000.0, 2_600.0, 8, || 900.0);
    assert_eq!(r.serial, Some(900.0));
    assert!(!r.over(), "within budget serially is green");
    assert!(r.retake_line().is_some_and(|l| l.contains("serial 900")));
}

#[test]
fn within_budget_or_already_serial_is_never_retaken() {
    let within = budget_verdict(1_000.0, 999.0, 8, || {
        panic!("a battery within budget is not re-taken")
    });
    assert_eq!(within.serial, None);
    assert!(!within.over());
    let serial = budget_verdict(1_000.0, 2_000.0, 1, || {
        panic!("a serial reading is not re-taken")
    });
    assert_eq!(serial.serial, None);
    assert!(
        serial.over(),
        "over at --jobs 1 is red at once: no second try"
    );
}

/// The verdict a real battery's report gets from each reading: red with both readings named when
/// the serial re-take is still over, green when it is not.
#[test]
fn the_report_is_judged_on_the_serial_reading() {
    let cx = crate::ctx::Ctx::workspace().expect("the workspace opens");
    let gate = (find("design-docs-allowlist").expect("registered").build)();
    let report = gate.selftest(&cx);
    let _ = report.cases();
    let red = BudgetVerdict {
        budget: 1.0,
        contended: 5.0,
        jobs: 8,
        serial: Some(2.0),
    };
    let errs = verify_report_with(gate.as_ref(), &report, &red).expect_err("over serially is red");
    assert!(
        errs.iter().any(|e| e.contains("contended 5 → serial 2")),
        "{errs:?}"
    );
    let green = BudgetVerdict {
        serial: Some(0.5),
        ..red
    };
    verify_report_with(gate.as_ref(), &report, &green).expect("within budget serially is green");
}
