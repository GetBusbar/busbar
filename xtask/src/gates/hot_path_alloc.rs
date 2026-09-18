//! `cargo xtask gate hot-path-alloc` — THE §8 HOT-PATH ALLOC INSTRUMENT'S SOURCE CONTRACT.
//!
//! `docs/design/1.6.0-plane-extraction-LOCKED.md` §8 owes an alloc gate: "`#[global_allocator]`
//! counter = 0 across the ISOLATED POD host-call batch", the second of the two criterion benches
//! §11b counts toward the core-engine tests/benches 8→9 rise. The MEASUREMENT lives in
//! `crates/busbar-core/benches/plane_host_vtable_alloc.rs`; this gate keeps that instrument making
//! §8's claim, so it cannot be dropped from the bench without an owed row going missing.
//!
//! # WHAT GREEN MEANS HERE — READ THIS BEFORE TRUSTING THE COLOR
//!
//! This gate is a SOURCE gate: it proves the alloc instrument's SOURCE still MAKES §8's claim (the
//! load-bearing markers are present), NOT that zero allocations were MEASURED. A green row here says
//! "the assertion is still written into the bench," never "the allocator counted zero." The rows are
//! named `…-markers-present` / `…-assertion-present` for exactly that reason — an earlier draft named
//! one `pod-batch-zero`, which read as a MEASURED result and was theatre.
//!
//! The measurement is produced by RUNNING the bench (`cargo bench -p busbar-core --bench
//! plane_host_vtable_alloc`), whose counting `#[global_allocator]` asserts `== 0` and EXITS NON-ZERO
//! otherwise (its `BUSBAR_ALLOC_INJECT` knob proves that assertion can still fire). That run is the
//! bench's job in the perf lane; this gate is deliberately not it, because `xtask` depends on no
//! product crate (`segregation:xtask-src-imports` — xtask reads sources as TEXT) and a Tier::Fast
//! gate builds nothing, so a text gate cannot honestly report a measured allocation count.
//!
//! Three rows:
//!
//! | row | what a GREEN proves (source only) |
//! | --- | --- |
//! | `:instrument-present` | the criterion bench exists AND is registered `harness = false` |
//! | `:global-allocator-markers-present` | the source still installs a counting `#[global_allocator]` (markers present) |
//! | `:pod-batch-assertion-present` | the source still asserts the counter is `== 0` across the isolated `PlaneHostVtable` POD batch (marker present) |
//!
//! THE PENDING-RIDER DEPENDENCY — WHY THE MEASURED GATE IS NOT WIRED YET. As with the perf
//! instrument, `PlaneHostVtable` (`crates/busbar-plugin/src/hot/host.rs`) has no production caller
//! yet — the keystone loop-unification (`crates/busbar/src/root/kernel.rs` + `main.rs`, reserved for
//! the keystone wave) has not landed — so the instrument is ARMED against the vtable's own
//! construction (the subject `crates/busbar-plugin/tests/layout_golden.rs` pins) and binds to the
//! production crossing unchanged when the rider lands: an allocation-free POD call is allocation-free
//! wherever it is made. That is when the measured `cargo bench` step earns a place in `ci.yml`; until
//! then this source contract is the honest witness.

use crate::ctx::{Ctx, Overlay};
use crate::gates::{prove_green, prove_red, Gate, Report};
use crate::ledger::{Row, Verdict};

pub const ROW_INSTRUMENT: &str = "hot-path-alloc:instrument-present";
pub const ROW_GLOBAL_ALLOCATOR: &str = "hot-path-alloc:global-allocator-markers-present";
pub const ROW_POD_BATCH: &str = "hot-path-alloc:pod-batch-assertion-present";

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
        ok: "the instrument source still installs a counting #[global_allocator] (markers present)",
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
        ok: "the instrument source still asserts zero allocations across the isolated PlaneHostVtable \
             POD batch (marker present)",
        bad: "the instrument no longer asserts zero allocations across the isolated POD batch",
    },
];

fn instrument_row(cx: &Ctx) -> Row {
    if !cx.exists(BENCH_REL) {
        return Row::fail(
            ROW_INSTRUMENT,
            "the §8 alloc instrument is missing",
            format!("{BENCH_REL} does not exist — the alloc gate has nothing to enforce"),
        );
    }
    let manifest = cx.read(MANIFEST_REL).unwrap_or_default();
    let registered = manifest.contains(&format!("name = \"{BENCH_NAME}\""))
        && manifest.contains("harness = false");
    if registered {
        Row::pass(
            ROW_INSTRUMENT,
            "the §8 alloc instrument exists and is a registered criterion bench",
            format!("{BENCH_REL}, registered harness = false in {MANIFEST_REL}"),
        )
    } else {
        Row::fail(
            ROW_INSTRUMENT,
            "the §8 alloc instrument is not a registered criterion bench",
            format!(
                "{MANIFEST_REL} does not register `name = \"{BENCH_NAME}\"` with `harness = false` \
                 — an unregistered criterion bench is built as a libtest harness and never runs the \
                 §8 measurement"
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
        Row::pass(
            claim.row,
            claim.ok,
            format!("{BENCH_REL}: all markers present"),
        )
    } else {
        Row::fail(
            claim.row,
            claim.bad,
            format!(
                "{BENCH_REL} is missing {missing:?} — a §8 claim was dropped from the alloc \
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
            "the committed alloc instrument makes every §8 claim",
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
