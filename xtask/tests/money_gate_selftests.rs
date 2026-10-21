// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MONEY GATES' SELF-TESTS, RUN BY THE TEST CHECK. Every case of each battery — each RED plant
//! and each GREEN control — is judged here, so a plant the gate cannot see fails the suite rather
//! than waiting for somebody to run `cargo xtask selftest <gate>` by hand (audit row 159, XE HIGH
//! 1-4 and XG HIGH 1).

use xtask::ctx::Ctx;
use xtask::gates::Gate;

fn assert_battery_holds(gate: &dyn Gate) {
    let cx = Ctx::workspace().expect("the workspace opens");
    let report = gate.selftest(&cx);
    let failures = report.failures();
    assert!(
        failures.is_empty(),
        "{}: {} selftest case(s) failed:\n{}",
        gate.name(),
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn the_no_float_money_battery_holds_on_the_tree() {
    assert_battery_holds(&xtask::gates::no_float_money::NoFloatMoneyGate);
}

#[test]
fn the_money_invariants_battery_holds_on_the_tree() {
    assert_battery_holds(&xtask::gates::money_invariants::MoneyInvariantsGate);
}
