//! `cargo xtask gate hot-path-alloc` — THE HOT-PATH ALLOC WITNESS, ENFORCED.
//!
//! `docs/design/1.6.0-plane-extraction-LOCKED.md` §8 owes an alloc gate: "`#[global_allocator]`
//! counter = 0 across the ISOLATED POD host-call batch", the second of the two criterion benches.
//! The MEASUREMENT lives in
//! `crates/busbar-core/benches/plane_host_vtable_alloc.rs`; this gate keeps that instrument making
//! the alloc claim, so it cannot be dropped from the bench without an owed row going missing.
//!
//! Three claims, three rows:
//!
//! | row | the claim it holds |
//! | --- | --- |
//! | `:instrument-present` | the criterion bench exists AND is registered `harness = false` |
//! | `:global-allocator` | it installs a counting `#[global_allocator]` |
//! | `:pod-batch-zero` | it asserts that counter is `== 0` across the isolated `PlaneHostVtable` POD batch |
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
use crate::gates::{prove_green, prove_red, Gate, Report};
use crate::ledger::{Row, Verdict};

pub const ROW_INSTRUMENT: &str = "hot-path-alloc:instrument-present";
pub const ROW_GLOBAL_ALLOCATOR: &str = "hot-path-alloc:global-allocator";
pub const ROW_POD_BATCH: &str = "hot-path-alloc:pod-batch-zero";

const BENCH_REL: &str = "crates/busbar-core/benches/plane_host_vtable_alloc.rs";
const MANIFEST_REL: &str = "crates/busbar-core/Cargo.toml";
const BENCH_NAME: &str = "plane_host_vtable_alloc";

struct Claim {
    row: &'static str,
    markers: &'static [&'static str],
    ok: &'static str,
    bad: &'static str,
}

const CLAIMS: &[Claim] = &[
    Claim {
        row: ROW_GLOBAL_ALLOCATOR,
        markers: &["#[global_allocator]", "GlobalAlloc", "ALLOC_COUNT"],
        ok: "the instrument installs a counting #[global_allocator]",
        bad: "the instrument no longer installs a counting global allocator",
    },
    Claim {
        row: ROW_POD_BATCH,
        markers: &[
            "PlaneHostVtable",
            "busbar_plugin::hot::host",
            "POD_HOST_CALL_BATCH",
            "ALLOC_COUNT",
            "assert_eq!",
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
    let registered = manifest.contains(&format!("name = \"{BENCH_NAME}\""))
        && manifest.contains("harness = false");
    if registered {
        Row::pass(
            ROW_INSTRUMENT,
            "the alloc instrument exists and is a registered criterion bench",
            format!("{BENCH_REL}, registered harness = false in {MANIFEST_REL}"),
        )
    } else {
        Row::fail(
            ROW_INSTRUMENT,
            "the alloc instrument is not a registered criterion bench",
            format!(
                "{MANIFEST_REL} does not register `name = \"{BENCH_NAME}\"` with `harness = false` \
                 — an unregistered criterion bench is built as a libtest harness and never runs the \
                 alloc measurement"
            ),
        )
    }
}

fn claim_row(claim: &Claim, bench: &str) -> Row {
    let missing: Vec<&str> = claim
        .markers
        .iter()
        .copied()
        .filter(|m| !bench.contains(m))
        .collect();
    if missing.is_empty() {
        Row::pass(claim.row, claim.ok, format!("{BENCH_REL}: all markers present"))
    } else {
        Row::fail(
            claim.row,
            claim.bad,
            format!(
                "{BENCH_REL} is missing {missing:?} — a claim was dropped from the alloc \
                 instrument"
            ),
        )
    }
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
        let bench = cx.read(BENCH_REL);
        for claim in CLAIMS {
            match &bench {
                Ok(text) => rows.push(claim_row(claim, text)),
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
            "the committed alloc instrument makes every claim",
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

        let bench = cx.read(BENCH_REL).unwrap_or_default();
        for claim in CLAIMS {
            let marker = claim.markers[0];
            let mut ov = Overlay::new();
            ov.set(BENCH_REL, bench.replace(marker, "__struck__"));
            report.push(prove_red(
                cx,
                self,
                format!("an alloc instrument that drops `{marker}` is RED"),
                &[claim.row],
                ov,
                &[marker],
            ));
        }

        report
    }
}
