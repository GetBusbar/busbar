//! THE NEVER-CONSTRUCTED GATE'S SELF-TEST, RUN UNDER `cargo test`.
//!
//! No CI check ran `gate unconstructed --selftest`, so its battery proved nothing on any move. This
//! runs it and judges it with the one judge every gate's battery answers to: every case did what
//! it expected, and every owed row has a RED case. Control 14 is the release posture (XH2#1): for a
//! `qa` or `main` target, or one nobody could read, every row on the KNOWN_UNSHIPPED register is
//! RED, because "a built type or verb with no production construction site is either wired or
//! deleted before the cut" (BUSBAR-1.6.0.md, What this means for the gates).

use xtask::ctx::Ctx;
use xtask::gates::unconstructed::UnconstructedGate;
use xtask::gates::{verify_report, Gate};

#[test]
fn the_unconstructed_gate_proves_its_battery_release_posture_included() {
    let cx = Ctx::workspace().expect("workspace context");
    let report = UnconstructedGate.selftest(&cx);
    verify_report(&UnconstructedGate, &report)
        .unwrap_or_else(|errs| panic!("unconstructed selftest: {errs:#?}"));
}
