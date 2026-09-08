//! THE GATE'S OWN RED PROOFS. Expanded below; this is the compiling skeleton.

use crate::ctx::{Ctx, Overlay};
use crate::gates::{prove_green, prove_rows_red, Gate, Report};

use super::{
    ROW_ADDITIVE_ONLY, ROW_BASELINE, ROW_SNAPSHOT_DRIFT, ROW_TRACKED_SOURCES, ROW_WAIVERS,
};

pub fn run(gate: &dyn Gate, cx: &Ctx) -> Report {
    let mut report = Report::new();
    let owed = gate.owed();
    let all: Vec<&str> = owed.iter().map(String::as_str).collect();

    report.push(prove_green(
        cx,
        gate,
        "the real tracked source set renders the committed snapshot, additively, with no stale waiver",
        &all,
    ));

    let mut ov = Overlay::new();
    ov.set(
        super::schema::SNAPSHOT,
        cx.read(super::schema::SNAPSHOT).unwrap_or_default() + " ",
    );
    report.push(prove_rows_red(
        cx,
        gate,
        "a committed snapshot that is not the fresh render is STALE",
        &[ROW_SNAPSHOT_DRIFT],
        ov,
        &["is STALE"],
    ));

    // The baseline ref is read through `Env`, so a plant drives the DEFAULT ref rather than naming
    // a second one: `git-ref:HEAD` = "0" is "HEAD does not resolve", which is what a shallow
    // checkout looks like to this gate.
    let mut ov = Overlay::new();
    ov.set_command("git-ref:HEAD", "0");
    report.push(prove_rows_red(
        cx,
        gate,
        "a baseline ref that does not resolve is refused",
        &[ROW_BASELINE, ROW_ADDITIVE_ONLY, ROW_WAIVERS],
        ov,
        &["does not resolve"],
    ));

    let _ = (ROW_TRACKED_SOURCES,);
    report
}
