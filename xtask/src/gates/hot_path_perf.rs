//! `cargo xtask gate hot-path-perf` — THE HOT-PATH PERF WITNESS, ENFORCED.
//!
//! `docs/design/1.6.0-plane-extraction-LOCKED.md` §8 owes a perf gate: "criterion,
//! plugin-host-vtable vs direct-call baseline, delta<1µs p50 AND p99; a per-token host-call counter
//! on the streaming path asserted == 0". It is one of the two criterion benches. The MEASUREMENT
//! lives in the criterion
//! instrument `crates/busbar-core/benches/plane_host_vtable_perf.rs`; this gate is what keeps that
//! instrument making every one of the perf claims, so a claim cannot be quietly dropped from the bench
//! without an owed row going missing.
//!
//! Five claims, five rows — the same shape as `duplex-ws-default-edge`:
//!
//! | row | the claim it holds |
//! | --- | --- |
//! | `:instrument-present` | the criterion bench exists AND is registered `harness = false` |
//! | `:vtable-vs-direct` | it measures the REAL `PlaneHostVtable` slot against a direct-call baseline |
//! | `:delta-p50-under-1us` | it asserts the crossing delta `< HOT_PATH_BUDGET_NANOS` at p50 |
//! | `:delta-p99-under-1us` | …and at p99 |
//! | `:per-token-host-calls-zero` | it asserts the per-token host-call counter `== 0` on the stream |
//!
//! WHY A SOURCE GATE AND NOT A `cargo bench` RUNNER. `xtask` depends on no product crate (the
//! `segregation` gate), and a Tier::Fast gate builds nothing; the microsecond measurement is the
//! bench's job and runs in the perf lane. What this gate owns is the CONTRACT — that the instrument
//! still constructs the vtable, still compares it to a direct call, and still asserts the exact
//! budget at both percentiles and a zero per-token crossing. Deleting an assertion from the bench is
//! the drift this catches, and the bench's own `BUSBAR_PERF_STREAM_CROSS` knob is what proves those
//! assertions can still fire.
//!
//! THE PENDING-RIDER DEPENDENCY. `PlaneHostVtable`
//! (`crates/busbar-plugin/src/hot/host.rs`) has NO production caller yet — the keystone
//! loop-unification (`crates/busbar/src/root/kernel.rs` + `main.rs`, reserved for the keystone wave)
//! has not landed. So the instrument this gate guards is ARMED against the vtable's own construction
//! (the `#[repr(C)]` subject `crates/busbar-plugin/tests/layout_golden.rs` pins), and binds to the
//! production crossing unchanged when the rider lands: the measured slot is the same fn pointer
//! either way. This gate is GREEN now and stays green across that transition.

use crate::ctx::{Ctx, Overlay};
use crate::gates::{prove_green, prove_red, Gate, Report};
use crate::ledger::{Row, Verdict};

pub const ROW_INSTRUMENT: &str = "hot-path-perf:instrument-present";
pub const ROW_SUBJECT: &str = "hot-path-perf:vtable-vs-direct";
pub const ROW_P50: &str = "hot-path-perf:delta-p50-under-1us";
pub const ROW_P99: &str = "hot-path-perf:delta-p99-under-1us";
pub const ROW_PER_TOKEN: &str = "hot-path-perf:per-token-host-calls-zero";

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
        ok: "the instrument measures the real PlaneHostVtable slot against a direct-call baseline",
        bad: "the instrument no longer compares the vtable crossing to a direct call",
    },
    Claim {
        row: ROW_P50,
        markers: &["p50_delta_nanos", "HOT_PATH_BUDGET_NANOS", "assert!"],
        ok: "the instrument asserts the crossing delta is under 1µs at p50",
        bad: "the instrument no longer asserts the p50 delta under budget",
    },
    Claim {
        row: ROW_P99,
        markers: &["p99_delta_nanos", "HOT_PATH_BUDGET_NANOS", "assert!"],
        ok: "the instrument asserts the crossing delta is under 1µs at p99",
        bad: "the instrument no longer asserts the p99 delta under budget",
    },
    Claim {
        row: ROW_PER_TOKEN,
        markers: &["PER_TOKEN_HOST_CALLS", "per_token_crossings", "assert_eq!"],
        ok: "the instrument asserts zero per-token host-vtable crossings on the streaming path",
        bad: "the instrument no longer asserts the per-token host-call counter is zero",
    },
];

/// The registration row: the bench file is present AND the manifest registers it `harness = false`
/// (so cargo builds the criterion binary, not a default libtest harness that would never compile).
fn instrument_row(cx: &Ctx) -> Row {
    if !cx.exists(BENCH_REL) {
        return Row::fail(
            ROW_INSTRUMENT,
            "the perf instrument is missing",
            format!("{BENCH_REL} does not exist — the perf gate has nothing to enforce"),
        );
    }
    let manifest = cx.read(MANIFEST_REL).unwrap_or_default();
    let registered = manifest.contains(&format!("name = \"{BENCH_NAME}\""))
        && manifest.contains("harness = false");
    if registered {
        Row::pass(
            ROW_INSTRUMENT,
            "the perf instrument exists and is a registered criterion bench",
            format!("{BENCH_REL}, registered harness = false in {MANIFEST_REL}"),
        )
    } else {
        Row::fail(
            ROW_INSTRUMENT,
            "the perf instrument is not a registered criterion bench",
            format!(
                "{MANIFEST_REL} does not register `name = \"{BENCH_NAME}\"` with `harness = false` \
                 — an unregistered criterion bench is built as a libtest harness and never runs the \
                 perf measurement"
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
        Row::pass(claim.row, claim.ok, format!("{BENCH_REL}: all markers present"))
    } else {
        Row::fail(
            claim.row,
            claim.bad,
            format!(
                "{BENCH_REL} is missing {missing:?} — a claim was dropped from the perf \
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
            "the committed perf instrument makes every claim",
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
