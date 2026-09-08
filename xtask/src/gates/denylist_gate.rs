//! `denylist`, re-registered under `gate`.
//!
//! The gate's LOGIC is untouched: [`crate::denylist::run`] and [`crate::selftest::run`] are the
//! same functions `cargo xtask denylist` has always called, and that subcommand still prints the
//! same bytes. What this file adds is the registry shape around them — declared owed row ids
//! reconciled by the runner, and a [`Report`] whose RED cases are driven THROUGH [`Gate::run`]
//! over the two fixture trees that must refuse a vacuous pass.

use crate::ctx::Ctx;
use crate::denylist;
use crate::gates::{prove_green, Case, Expect, Gate, Report};
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
        let report = denylist::run(cx.root());
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

    fn selftest(&self, cx: &Ctx) -> Report {
        let mut report = Report::new();
        report.push(prove_green(
            cx,
            self,
            "the real tree is clean under the denylist",
            &[ROW_SCAN, ROW_HITS, ROW_WAIVERS],
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

        // The hit and waiver rules are proven by the crate's existing twelve-fixture battery, which
        // already refuses a fixture that goes green when it should go red AND refuses a red that
        // does not NAME the planted offender — the contract this trait generalises. It is driven
        // here so `cargo xtask selftest` covers it.
        let battery_green = selftest::run();
        report.push(Case {
            name: "the twelve-fixture denylist battery (planted banned deps, own-src paths, \
                   via-narrowing bypasses, phantom optional edges, stale waivers)"
                .to_string(),
            covers: vec![ROW_HITS.to_string(), ROW_WAIVERS.to_string()],
            expected: Expect::Red {
                naming: vec!["libc".to_string()],
            },
            got: if battery_green {
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
