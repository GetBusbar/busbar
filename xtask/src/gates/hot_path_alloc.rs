//! `cargo xtask gate hot-path-alloc` — THE HOT-PATH ALLOC WITNESS, ENFORCED.
//!
//! `docs/design/BUSBAR-1.6.0.md` Part 3 §8 owes an alloc gate: "`#[global_allocator]`
//! counter = 0 across the ISOLATED POD host-call batch", the second of the two criterion benches
//! that count toward the core-engine tests/benches 8→9 rise. The MEASUREMENT lives in
//! `crates/busbar-kernel/benches/plane_host_vtable_alloc.rs`; this gate keeps that instrument making
//! that claim, so it cannot be dropped from the bench without an owed row going missing.
//!
//! Three claims, three rows:
//!
//! | row | the claim it holds |
//! | --- | --- |
//! | `:instrument-present` | the criterion bench exists AND its OWN `[[bench]]` block says `harness = false` |
//! | `:global-allocator` | it installs a counting `#[global_allocator]` |
//! | `:pod-batch-zero` | it asserts `allocations == 0` across the isolated `PlaneHostVtable` POD batch |
//!
//! Each row holds its own comparison as lexed CODE clauses, and the registration is read from this
//! bench's own `[[bench]]` block — the matchers are `hot-path-perf`'s (see its header for why a
//! whole-file `contains` per token held neither).
//!
//! WHY A SOURCE GATE. Same reason as `hot-path-perf`: `xtask` depends on no product crate
//! (`segregation`) and a Tier::Fast gate builds nothing, so the allocation count is the bench's
//! measurement, run in the perf lane, and its `BUSBAR_ALLOC_INJECT` knob is what proves the `== 0`
//! assertion can still fire. This gate owns the CONTRACT that the instrument keeps arming the counter
//! around the isolated POD batch and asserting zero.
//!
//! THE PENDING-RIDER DEPENDENCY. As with the perf instrument, `PlaneHostVtable`
//! (`crates/busbar-plugin/src/hot/host.rs`) has no production caller yet — the keystone
//! loop-unification (`crates/busbar/src/root/kernel.rs` + `main.rs`, reserved for the keystone wave)
//! has not landed — so the instrument is ARMED against the vtable's own construction (the subject
//! `crates/busbar-plugin/tests/layout_golden.rs` pins) and binds to the production crossing
//! unchanged when the rider lands: an allocation-free POD call is allocation-free wherever it is
//! made. This gate is GREEN now and stays green across that transition.

use crate::ctx::{Ctx, Overlay};
use crate::gates::hot_path_perf::{
    bench_block_is_harness_false, claim_row_over, code_tokens, strike_clause, Claim,
};
use crate::gates::{prove_green, prove_red, Gate, Report};
use crate::ledger::{Row, Verdict};

pub const ROW_INSTRUMENT: &str = "hot-path-alloc:instrument-present";
pub const ROW_GLOBAL_ALLOCATOR: &str = "hot-path-alloc:global-allocator";
pub const ROW_POD_BATCH: &str = "hot-path-alloc:pod-batch-zero";

const BENCH_REL: &str = "crates/busbar-kernel/benches/plane_host_vtable_alloc.rs";
const MANIFEST_REL: &str = "crates/busbar-kernel/Cargo.toml";
const BENCH_NAME: &str = "plane_host_vtable_alloc";

const CLAIMS: &[Claim] = &[
    Claim {
        row: ROW_GLOBAL_ALLOCATOR,
        clauses: &[
            "#[global_allocator]",
            "impl GlobalAlloc for",
            "ALLOC_COUNT.fetch_add(1,",
        ],
        ok: "the instrument installs a counting #[global_allocator]",
        bad: "the instrument no longer installs a counting global allocator",
    },
    Claim {
        row: ROW_POD_BATCH,
        clauses: &[
            "use busbar_plugin::hot::host::{",
            "PlaneHostVtable",
            "bench_function(\"POD_HOST_CALL_BATCH\"",
            "ALLOC_COUNT.store(0,",
            "let allocations = ALLOC_COUNT.load(",
            "assert_eq!(allocations, 0,",
        ],
        ok: "the instrument asserts zero allocations across the isolated PlaneHostVtable POD batch",
        bad: "the instrument no longer asserts zero allocations across the isolated POD batch",
    },
];

fn instrument_row(cx: &Ctx) -> Row {
    if !cx.exists(BENCH_REL) {
        return Row::fail(
            ROW_INSTRUMENT,
            "the alloc instrument is missing",
            format!("{BENCH_REL} does not exist — the alloc gate has nothing to enforce"),
        );
    }
    let manifest = cx.read(MANIFEST_REL).unwrap_or_default();
    if let Err(why) = bench_block_is_harness_false(&manifest, BENCH_NAME) {
        return Row::fail(
            ROW_INSTRUMENT,
            "the alloc instrument is not a registered criterion bench",
            format!(
                "{MANIFEST_REL}: {why} — an unregistered criterion bench is built as a libtest \
                 harness and never runs the budget measurement"
            ),
        );
    }
    Row::pass(
        ROW_INSTRUMENT,
        "the alloc instrument exists and is a registered criterion bench",
        format!("{BENCH_REL}, its own [[bench]] block sets harness = false in {MANIFEST_REL}"),
    )
}

pub struct HotPathAllocGate;

impl Gate for HotPathAllocGate {
    fn name(&self) -> &'static str {
        "hot-path-alloc"
    }

    fn owed(&self) -> Vec<String> {
        std::iter::once(ROW_INSTRUMENT.to_string())
            .chain(CLAIMS.iter().map(|c| c.row.to_string()))
            .collect()
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let mut rows = vec![instrument_row(cx)];
        let bench = cx.read(BENCH_REL).and_then(|t| code_tokens(&t));
        for claim in CLAIMS {
            match &bench {
                Ok(code) => rows.push(claim_row_over(claim, BENCH_REL, code, "alloc")),
                Err(e) => rows.push(Row::fail(
                    claim.row,
                    claim.bad,
                    format!("{BENCH_REL}: {e} — the alloc instrument could not be read"),
                )),
            }
        }
        Verdict::of(rows)
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        report.push(prove_green(
            cx,
            self,
            "the committed alloc instrument makes every budget claim",
            &self.owed().iter().map(String::as_str).collect::<Vec<_>>(),
        ));

        let manifest = cx.read(MANIFEST_REL).unwrap_or_default();
        let mut ov = Overlay::new();
        ov.set(
            MANIFEST_REL,
            manifest.replace(&format!("name = \"{BENCH_NAME}\""), "name = \"struck\""),
        );
        report.push(prove_red(
            cx,
            self,
            "an unregistered instrument is RED, not read as present",
            &[ROW_INSTRUMENT],
            ov,
            &["not a registered criterion bench"],
        ));

        // HARNESS HALF: strike `harness = false` from THIS bench's block only; the sibling
        // `[[bench]]` blocks keep theirs.
        let mut ov = Overlay::new();
        ov.set(
            MANIFEST_REL,
            manifest.replace(
                &format!("name = \"{BENCH_NAME}\"\nharness = false"),
                &format!("name = \"{BENCH_NAME}\""),
            ),
        );
        report.push(prove_red(
            cx,
            self,
            "an instrument whose own block drops `harness = false` is RED while siblings keep theirs",
            &[ROW_INSTRUMENT],
            ov,
            &["does not itself set `harness = false`"],
        ));

        // One RED plant per CLAUSE of every claim, not per claim's first token.
        let bench = cx.read(BENCH_REL).unwrap_or_default();
        for claim in CLAIMS {
            for clause in claim.clauses {
                let mut ov = Overlay::new();
                ov.set(BENCH_REL, strike_clause(&bench, clause));
                report.push(prove_red(
                    cx,
                    self,
                    format!("an alloc instrument that drops `{clause}` is RED"),
                    &[claim.row],
                    ov,
                    &[*clause],
                ));
            }
        }

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::Status;

    fn cx() -> Ctx {
        Ctx::workspace().expect("the workspace opens")
    }

    fn status_with(rel: &str, from: &str, to: &str, row: &str) -> Status {
        let cx = cx();
        let text = cx.read(rel).expect("the subject file reads");
        let planted = text.replacen(from, to, 1);
        assert_ne!(
            planted, text,
            "the rewrite of {rel} must bite: `{from}` not found"
        );
        let mut ov = Overlay::new();
        ov.set(rel, planted);
        let verdict = HotPathAllocGate.run(&cx.with_overlay(ov));
        verdict
            .rows
            .iter()
            .find(|r| r.id == row)
            .map(|r| r.status)
            .expect("the gate emits the row")
    }

    /// Item 170: `harness = false` struck from THIS bench's own block is an unregistered instrument,
    /// whatever the sibling blocks carry.
    #[test]
    fn harness_false_is_read_from_this_benchs_own_block() {
        let st = status_with(
            MANIFEST_REL,
            "name = \"plane_host_vtable_alloc\"\nharness = false",
            "name = \"plane_host_vtable_alloc\"",
            ROW_INSTRUMENT,
        );
        assert_eq!(st, Status::Fail);
    }

    /// Item 169: `assert_eq!(allocations, allocations)` keeps every token and asserts nothing.
    #[test]
    fn a_self_compared_allocation_count_is_red() {
        let st = status_with(
            BENCH_REL,
            "allocations, 0,",
            "allocations, allocations,",
            ROW_POD_BATCH,
        );
        assert_eq!(st, Status::Fail);
    }
}
