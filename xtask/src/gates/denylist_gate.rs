//! `denylist`, re-registered under `gate`.
//!
//! The gate's LOGIC is untouched: [`crate::denylist::run`] and [`crate::selftest::run`] are the
//! same functions `cargo xtask denylist` has always called, and that subcommand still prints the
//! same bytes. What this file adds is the registry shape around them — declared owed row ids
//! reconciled by the runner, and a [`Report`] whose RED cases are driven THROUGH [`Gate::run`]
//! over the two fixture trees that must refuse a vacuous pass.

use crate::ctx::{Ctx, Overlay};
use crate::denylist;
use crate::gates::{prove_green, prove_red, Case, Expect, Gate, Report};
use crate::ledger::{Row, Verdict};
use crate::selftest;

pub const ROW_SCAN: &str = "denylist:scan";
pub const ROW_HITS: &str = "denylist:hits";
pub const ROW_WAIVERS: &str = "denylist:stale-waivers";

pub struct DenylistGate;

impl Gate for DenylistGate {
    fn name(&self) -> &'static str {
        "denylist"
    }

    fn owed(&self) -> Vec<String> {
        vec![
            ROW_SCAN.to_string(),
            ROW_HITS.to_string(),
            ROW_WAIVERS.to_string(),
        ]
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let report = denylist::run(cx);
        let mut rows = Vec::new();

        // A GATE WHOSE OWN INPUT VANISHED MUST NOT ANSWER GREEN: zero crates scanned, or any
        // defect reading the tree, is RED before the hit list is even consulted.
        if report.crates_scanned == 0 || !report.defects.is_empty() {
            rows.push(Row::fail(
                ROW_SCAN,
                "the denylist scanned nothing, or could not read its own input",
                format!(
                    "{} crate(s) scanned; defects: {}",
                    report.crates_scanned,
                    if report.defects.is_empty() {
                        "none".to_string()
                    } else {
                        report.defects.join("; ")
                    }
                ),
            ));
        } else {
            rows.push(Row::pass(
                ROW_SCAN,
                "the pure-kind crate list resolved and was scanned",
                format!("{} crate(s) scanned", report.crates_scanned),
            ));
        }

        if report.hits.is_empty() {
            rows.push(Row::pass(
                ROW_HITS,
                "no banned transitive source in any pure plugin kind",
                "0 hits".to_string(),
            ));
        } else {
            rows.push(Row::fail(
                ROW_HITS,
                "a pure plugin kind reaches banned source",
                report
                    .hits
                    .iter()
                    .map(|h| format!("{}: {} via {}", h.crate_name, h.offender, h.via))
                    .collect::<Vec<_>>()
                    .join(" | "),
            ));
        }

        if report.stale_waivers.is_empty() {
            rows.push(Row::pass(
                ROW_WAIVERS,
                "every allow-list waiver still covers a live hit",
                "0 stale waivers".to_string(),
            ));
        } else {
            rows.push(Row::fail(
                ROW_WAIVERS,
                "an allow-list waiver outlived the offender it excused",
                report.stale_waivers.join(" | "),
            ));
        }

        Verdict::of(rows)
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        report.push(prove_green(
            cx,
            self,
            "the real tree is clean under the denylist",
            &[ROW_SCAN, ROW_HITS, ROW_WAIVERS],
        ));

        // THE PLANT THE `std::fs` RUN COULD NOT SEE. `denylist::run` read its config, its crate
        // listing and every source file straight off the disk under `cx.root()`, so an overlay
        // changed nothing and the only way to move the gate was to check a whole second tree into
        // `xtask/fixtures/` and re-root onto it. Now the run reads the `Ctx`: this case renames
        // `[rules.source-denylist]` out of the config IN AN OVERLAY, and the gate that answered
        // "0 crates scanned" as OK answers RED on the tree it is actually pointed at. Delete the
        // `cx.read`/`cx.walk` routing and this case goes green while the fixture cases below stay
        // red, which is exactly the difference it is here to hold.
        let mut renamed = Overlay::new();
        renamed.set(
            "qa/construction.toml",
            "[rules.source-denylist-RENAMED]\nkinds = [\"plane\"]\npatterns = [\"libc\"]\n",
        );
        report.push(prove_red(
            cx,
            self,
            "the rule table renamed away IN THE OVERLAY is a red run, not a vacuous pass",
            &[ROW_SCAN],
            renamed,
            &["scanned"],
        ));

        // Two REAL red proofs, driven through `Gate::run` over fixture trees whose input is gone:
        // "0 crates scanned, 0 hits" printed as OK is a proof of nothing dressed as a proof of
        // purity. The renamed-table fixture carries a genuinely libc-dependent plane crate
        // underneath, so the vacuous pass would be hiding a real violation.
        for (label, fixture) in [
            (
                "vacuous config: the rule table was renamed away",
                "xtask/fixtures/renamed-rule-table",
            ),
            (
                "vacuous config: no crates/ directory",
                "xtask/fixtures/no-crates-dir",
            ),
        ] {
            report.push(match Ctx::at(cx.abs(fixture), cx.scratch()) {
                Ok(fixture_cx) => {
                    let verdict = crate::gates::execute(self, &fixture_cx);
                    Case {
                        name: label.to_string(),
                        covers: vec![ROW_SCAN.to_string()],
                        expected: Expect::Red {
                            naming: vec!["scanned".to_string()],
                        },
                        got: if verdict.red {
                            Expect::Red {
                                naming: verdict
                                    .rows
                                    .iter()
                                    .map(|r| format!("{} {}", r.title, r.detail))
                                    .collect(),
                            }
                        } else {
                            Expect::Green
                        },
                    }
                }
                Err(_) => Case {
                    name: label.to_string(),
                    covers: vec![ROW_SCAN.to_string()],
                    expected: Expect::Red {
                        naming: vec!["scanned".to_string()],
                    },
                    got: Expect::Skipped,
                },
            });
        }

        // THE HIT AND THE WAIVER, EACH THROUGH `Gate::run`, over one fixture tree that carries both
        // — a plane crate that depends directly on `libc`, and an allow-list entry waiving a
        // `reqwest` that is not there. Each case reads only its own row, so neither rule is
        // discharged by the other's red, and inverting either row's verdict turns its case green.
        for (label, row, naming) in [
            (
                "a pure plane crate reaching a banned crate is a RED row, not a printed warning",
                ROW_HITS,
                "libc",
            ),
            (
                "a waiver that has outlived its offender is a RED row",
                ROW_WAIVERS,
                "reqwest",
            ),
        ] {
            report.push(crate::gates::prove_rows_red_at(
                cx,
                self,
                label,
                &[row],
                "xtask/fixtures/dirty-plane",
                &[naming],
            ));
        }

        // The crate's own twelve-fixture battery (planted banned deps, own-src paths, via-narrowing
        // bypasses, phantom optional edges, stale waivers) proves the PREDICATE in both directions,
        // at a granularity no single tree can carry. It is driven here so `cargo xtask selftest`
        // runs it — and it COVERS NO ROW, because it never reaches `Gate::run`: the rows above are
        // proven by the cases above, and a battery result standing in for them is how a row keeps
        // its coverage after the row itself is gone.
        report.push(Case {
            name: "the twelve-fixture denylist battery agrees with the rules it stands behind"
                .to_string(),
            covers: Vec::new(),
            expected: Expect::Red {
                naming: vec!["libc".to_string()],
            },
            got: if selftest::run() {
                Expect::Red {
                    naming: vec!["libc".to_string(), "async-std".to_string()],
                }
            } else {
                Expect::Green
            },
        });

        report
    }
}
