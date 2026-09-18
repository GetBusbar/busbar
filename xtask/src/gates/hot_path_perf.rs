//! `cargo xtask gate hot-path-perf` — THE §8 HOT-PATH PERF INSTRUMENT'S SOURCE CONTRACT.
//!
//! `docs/design/1.6.0-plane-extraction-LOCKED.md` §8 owes a perf gate: "criterion,
//! plugin-host-vtable vs direct-call baseline, delta<1µs p50 AND p99; a per-token host-call counter
//! on the streaming path asserted == 0", and §11b counts it as one of the two criterion benches that
//! raise the core-engine tests/benches dimension 8→9. The MEASUREMENT lives in the criterion
//! instrument `crates/busbar-core/benches/plane_host_vtable_perf.rs`; this gate is what keeps that
//! instrument making every one of §8's claims, so a claim cannot be quietly dropped from the bench
//! without an owed row going missing.
//!
//! # WHAT GREEN MEANS HERE — READ THIS BEFORE TRUSTING THE COLOR
//!
//! This gate is a SOURCE gate: it proves that the perf instrument's SOURCE still MAKES each §8 claim
//! (the load-bearing markers are present), NOT that the number was MEASURED. A green row here says
//! "the assertion is still written into the bench," never "the p50 delta was measured under 1µs."
//! The rows are named `…-markers-present` / `…-assertion-present` for exactly this reason: an earlier
//! draft named them `delta-p50-under-1us` / `per-token-host-calls-zero`, which read as a MEASURED
//! result and was theatre — green there meant a grep matched, not that a microsecond was clocked.
//!
//! The measurement is produced by RUNNING the bench (`cargo bench -p busbar-core --bench
//! plane_host_vtable_perf`), which computes the percentiles itself and EXITS NON-ZERO on a blown
//! budget or a per-token crossing (its `BUSBAR_PERF_STREAM_CROSS` knob proves those assertions can
//! still fire). That run is the bench's job in the perf lane — it is NOT wired into `ci.yml` yet (see
//! the pending-rider note below) — and this gate is deliberately not it: `xtask` depends on no
//! product crate (`segregation:xtask-src-imports` — xtask reads sources as TEXT) and a Tier::Fast
//! gate builds nothing, so a text gate cannot honestly report a measured microsecond.
//!
//! Five rows — the same shape as `duplex-ws-default-edge`:
//!
//! | row | what a GREEN proves (source only) |
//! | --- | --- |
//! | `:instrument-present` | the criterion bench exists AND is registered `harness = false` |
//! | `:vtable-vs-direct-markers-present` | the source still names the REAL `PlaneHostVtable` slot and the direct-call baseline it compares (markers present — NOT a measured delta) |
//! | `:delta-p50-assertion-present` | the source still carries the p50 `< HOT_PATH_BUDGET_NANOS` assertion (marker present) |
//! | `:delta-p99-assertion-present` | …and the p99 assertion |
//! | `:per-token-assertion-present` | the source still carries the per-token host-call counter `== 0` assertion (marker present) |
//!
//! THE PENDING-RIDER DEPENDENCY — WHY THE MEASURED GATE IS NOT WIRED YET. `PlaneHostVtable`
//! (`crates/busbar-plugin/src/hot/host.rs`) has NO production caller yet — the keystone
//! loop-unification (`crates/busbar/src/root/kernel.rs` + `main.rs`, reserved for the keystone wave)
//! has not landed. So the instrument is ARMED against the vtable's own construction (the `#[repr(C)]`
//! subject `crates/busbar-plugin/tests/layout_golden.rs` pins) rather than the production streaming
//! path: what it clocks today is an ISOLATED vtable-vs-direct crossing, not a real rider streaming N
//! tokens. That isolated bench binds to the production crossing unchanged when the rider lands (the
//! slot is the same fn pointer either way), and THAT is when the measured `cargo bench` step earns a
//! place in `ci.yml`. Until then this source contract is the honest witness: it holds the shape of
//! the claim, and says plainly that it does not hold the number.

use crate::ctx::{Ctx, Overlay};
use crate::gates::{prove_green, prove_red, Gate, Report};
use crate::ledger::{Row, Verdict};

pub const ROW_INSTRUMENT: &str = "hot-path-perf:instrument-present";
pub const ROW_SUBJECT: &str = "hot-path-perf:vtable-vs-direct-markers-present";
pub const ROW_P50: &str = "hot-path-perf:delta-p50-assertion-present";
pub const ROW_P99: &str = "hot-path-perf:delta-p99-assertion-present";
pub const ROW_PER_TOKEN: &str = "hot-path-perf:per-token-assertion-present";

const BENCH_REL: &str = "crates/busbar-core/benches/plane_host_vtable_perf.rs";
const MANIFEST_REL: &str = "crates/busbar-core/Cargo.toml";
const BENCH_NAME: &str = "plane_host_vtable_perf";

/// One text claim: the row it answers, and the source markers the instrument must ALL carry for it.
/// Each marker is a load-bearing token of the claim's code, not a comment — removing it from the
/// bench is removing the claim.
struct Claim {
    row: &'static str,
    markers: &'static [&'static str],
    ok: &'static str,
    bad: &'static str,
}

const CLAIMS: &[Claim] = &[
    Claim {
        row: ROW_SUBJECT,
        markers: &[
            "PlaneHostVtable",
            "busbar_plugin::hot::host",
            "HOT_PATH_DIRECT_CALL",
            "HOT_PATH_VTABLE_CALL",
        ],
        ok: "the instrument source still names the real PlaneHostVtable slot and its direct-call \
             baseline (markers present — not a measured delta)",
        bad: "the instrument no longer compares the vtable crossing to a direct call",
    },
    Claim {
        row: ROW_P50,
        markers: &["p50_delta_nanos", "HOT_PATH_BUDGET_NANOS", "assert!"],
        ok: "the instrument source still carries the p50-under-budget assertion (marker present)",
        bad: "the instrument no longer asserts the p50 delta under budget",
    },
    Claim {
        row: ROW_P99,
        markers: &["p99_delta_nanos", "HOT_PATH_BUDGET_NANOS", "assert!"],
        ok: "the instrument source still carries the p99-under-budget assertion (marker present)",
        bad: "the instrument no longer asserts the p99 delta under budget",
    },
    Claim {
        row: ROW_PER_TOKEN,
        markers: &["PER_TOKEN_HOST_CALLS", "per_token_crossings", "assert_eq!"],
        ok: "the instrument source still carries the zero-per-token-crossing assertion (marker \
             present)",
        bad: "the instrument no longer asserts the per-token host-call counter is zero",
    },
];

/// The registration row: the bench file is present AND the manifest registers it `harness = false`
/// (so cargo builds the criterion binary, not a default libtest harness that would never compile).
fn instrument_row(cx: &Ctx) -> Row {
    if !cx.exists(BENCH_REL) {
        return Row::fail(
            ROW_INSTRUMENT,
            "the §8 perf instrument is missing",
            format!("{BENCH_REL} does not exist — the perf gate has nothing to enforce"),
        );
    }
    let manifest = cx.read(MANIFEST_REL).unwrap_or_default();
    let registered = manifest.contains(&format!("name = \"{BENCH_NAME}\""))
        && manifest.contains("harness = false");
    if registered {
        Row::pass(
            ROW_INSTRUMENT,
            "the §8 perf instrument exists and is a registered criterion bench",
            format!("{BENCH_REL}, registered harness = false in {MANIFEST_REL}"),
        )
    } else {
        Row::fail(
            ROW_INSTRUMENT,
            "the §8 perf instrument is not a registered criterion bench",
            format!(
                "{MANIFEST_REL} does not register `name = \"{BENCH_NAME}\"` with `harness = false` \
                 — an unregistered criterion bench is built as a libtest harness and never runs the \
                 §8 measurement"
            ),
        )
    }
}

/// One text claim's row: PASS iff every marker is present in the instrument source.
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
                "{BENCH_REL} is missing {missing:?} — a §8 claim was dropped from the perf \
                 instrument"
            ),
        )
    }
}

pub struct HotPathPerfGate;

impl Gate for HotPathPerfGate {
    fn name(&self) -> &'static str {
        "hot-path-perf"
    }

    fn owed(&self) -> Vec<String> {
        std::iter::once(ROW_INSTRUMENT.to_string())
            .chain(CLAIMS.iter().map(|c| c.row.to_string()))
            .collect()
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let mut rows = vec![instrument_row(cx)];
        // A missing instrument makes every text claim fail too — a rule that could not read its
        // subject is not a rule that passed.
        let bench = cx.read(BENCH_REL);
        for claim in CLAIMS {
            match &bench {
                Ok(text) => rows.push(claim_row(claim, text)),
                Err(e) => rows.push(Row::fail(
                    claim.row,
                    claim.bad,
                    format!("{BENCH_REL}: {e} — the perf instrument could not be read"),
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
            "the committed perf instrument makes every §8 claim",
            &self.owed().iter().map(String::as_str).collect::<Vec<_>>(),
        ));

        // INSTRUMENT: strike the registration from the manifest. The bench source is untouched, so
        // only this row goes red.
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

        // One RED plant per text claim: strike its FIRST marker out of the real committed bench, so
        // exactly that row goes red and names the token it lost.
        let bench = cx.read(BENCH_REL).unwrap_or_default();
        for claim in CLAIMS {
            let marker = claim.markers[0];
            let mut ov = Overlay::new();
            ov.set(BENCH_REL, bench.replace(marker, "__struck__"));
            report.push(prove_red(
                cx,
                self,
                format!("a perf instrument that drops `{marker}` is RED"),
                &[claim.row],
                ov,
                &[marker],
            ));
        }

        report
    }
}
