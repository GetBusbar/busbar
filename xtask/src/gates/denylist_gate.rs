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

        // A GATE WHOSE OWN INPUT VANISHED MUST NOT ANSWER GREEN: zero crates scanned, any crate
        // skipped, or any defect reading the tree, is RED before the hit list is even consulted.
        // SCANNED AND SKIPPED ARE REPORTED APART: "5 crate(s) scanned" over five crates whose
        // closures were never found was a pass over nothing.
        if report.crates_scanned == 0
            || !report.crates_skipped.is_empty()
            || !report.defects.is_empty()
        {
            rows.push(Row::fail(
                ROW_SCAN,
                "the denylist scanned nothing, skipped a crate, or could not read its own input",
                format!(
                    "{} crate(s) scanned, {} skipped; defects: {}",
                    report.crates_scanned,
                    report.crates_skipped.len(),
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
                "the pure-kind crate list resolved and every crate of it was scanned",
                format!("{} crate(s) scanned, 0 skipped", report.crates_scanned),
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
                "every allow-list waiver and edge exemption still covers a live hit",
                "0 stale waivers, 0 stale edge exemptions".to_string(),
            ));
        } else {
            rows.push(Row::fail(
                ROW_WAIVERS,
                "an allow-list waiver or edge exemption outlived the offender it excused",
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

        // ZERO SCANNED IS RED, NEVER A PASS. The run that printed "5 crate(s) scanned" had found
        // none of the five in `cargo metadata` and skipped every closure. Here the resolve graph is
        // planted EMPTY, so every pure crate the walk matches is skipped: the row must say 0
        // scanned and name the skips, red. Count matched crates as scanned again and this goes
        // green.
        let mut empty_graph = Overlay::new();
        empty_graph.set_command(
            denylist::METADATA_KEY,
            r#"{"packages":[],"resolve":{"nodes":[]}}"#,
        );
        report.push(prove_red(
            cx,
            self,
            "a walk that scanned zero crates (every closure skipped) is a red run, not a pass",
            &[ROW_SCAN],
            empty_graph,
            &["0 crate(s) scanned", "skipped", "0 of"],
        ));

        // THE PINNED PLANES ARE THE CRATES THE DENYLIST JUDGES. With the base layer gone the walk
        // matches no pure crate at all, so the gate going red here is the proof it reads the
        // pinned checkouts and not just whatever is left on disk (ARCHITECT row 106 (A),
        // condition 3).
        report.push({
            let verdict = crate::gates::execute(self, &cx.without_base());
            Case {
                name: "the denylist over the tree WITHOUT the pinned planes' base layer is red"
                    .to_string(),
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
        });

        // A BANNED DEPENDENCY PLANTED IN A PINNED PLANE'S CHECKOUT IS RED. Two plants into the
        // first base-laid plane: a resolve-graph edge to `async-std` (the closure half, judged at
        // the checkout cargo resolved) and a `std::net` path in its laid `src/lib.rs` (the own-src
        // half). Neither banned name occurs anywhere else in the tree, so each case's naming is
        // carried only by its own plant. Point the closure walk back at the tree path and the
        // first goes green; drop the base layer from the source walk and the second does.
        let pinned = denylist::base_laid_pure_crates(cx);
        match pinned.first().cloned() {
            Some(plane) => {
                let mcx = cx.clone();
                let target = plane.clone();
                report.push(prove_red(
                    cx,
                    self,
                    "a banned crate in a pinned plane's resolved dependencies is a RED hit",
                    &[ROW_HITS],
                    move || {
                        let mut ov = Overlay::new();
                        if let Ok(mut meta) = denylist::workspace_metadata(&mcx) {
                            if plant_banned_dep(&mut meta, &target, "async-std") {
                                ov.set_command(denylist::METADATA_KEY, meta.to_string());
                            }
                        }
                        ov
                    },
                    &[plane.as_str(), "async-std"],
                ));
                let lib = format!("crates/{plane}/src/lib.rs");
                let mut src = Overlay::new();
                src.set(
                    &lib,
                    format!(
                        "{}\npub fn denylist_selftest_plant() {{ let _ = std::net::TcpStream::connect(\"x\"); }}\n",
                        cx.read(&lib).unwrap_or_default()
                    ),
                );
                report.push(prove_red(
                    cx,
                    self,
                    "a banned std path planted in a pinned plane's laid source is a RED hit",
                    &[ROW_HITS],
                    src,
                    &[plane.as_str(), "std::net"],
                ));
            }
            None => report.push(Case {
                name: "a banned dependency planted in a pinned plane's checkout is red".to_string(),
                covers: vec![ROW_HITS.to_string()],
                expected: Expect::Red {
                    naming: vec!["no pinned plane is laid by the base".to_string()],
                },
                got: Expect::Green,
            }),
        }

        // X-1206: A LINE THE READER CANNOT PLACE. The subset reader used to drop it in silence, so
        // the gate judged a config shorter than the file. A stray line planted into the real
        // config is now a red run naming the line.
        let mut stray = Overlay::new();
        stray.set(
            "qa/construction.toml",
            format!(
                "{}\nthis line is neither a header nor key = value\n",
                cx.read("qa/construction.toml").unwrap_or_default()
            ),
        );
        report.push(prove_red(
            cx,
            self,
            "a config line the reader cannot place is a red run, not a dropped line",
            &[ROW_SCAN],
            stray,
            &["does not read whole", "this line is neither a header"],
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

        // AN EDGE EXEMPTION CAN ITSELF BE WRONG, AND THE GATE HAS TO SAY SO.
        //
        // An exemption is the broader of the two exception shapes: it is keyed on `(dep, via)`, not
        // on a crate, so ONE entry suppresses findings in every pure kind at once and in crates
        // nobody had to enumerate. That is exactly why it cannot be the one exception nobody ever
        // has to defend again. It is held to the same both-ways floor the allow-list has — an
        // exemption that suppresses NO hit is RED — and this case proves it through `Gate::run`
        // rather than against a synthetic hit list: the REAL `qa/construction.toml`, plus one extra
        // exemption for an edge that is not in this tree, planted in an overlay.
        //
        // `wasi-libc-shim` is a crate no busbar target resolves. An exemption naming it rules on
        // nothing, so it must be reported — and if it were NOT, the next reviewer would read it as
        // a live, reviewed fact about how the pure kinds reach `libc`, which is the precise reading
        // that let four copies of one `cpufeatures` paragraph accumulate in the allow-list.
        if let Ok(real_config) = cx.read("qa/construction.toml") {
            let mut planted = Overlay::new();
            planted.set(
                "qa/construction.toml",
                format!(
                    "{real_config}\n\n[[rules.source-denylist.edge_exemptions]]\n\
                     dep = \"libc\"\n\
                     via = \"wasi-libc-shim\"\n\
                     symbols = [\"nothing-at-all\"]\n\
                     reason = \"a planted exemption for an edge no crate in this tree takes\"\n\
                     owner = \"the denylist gate selftest\"\n"
                ),
            );
            report.push(prove_red(
                cx,
                self,
                "an edge exemption that suppresses nothing is a RED row, same as a stale waiver",
                &[ROW_WAIVERS],
                planted,
                &["exemption", "wasi-libc-shim"],
            ));
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

/// Give `crate_name`'s pinned (`git+`) node in a `cargo metadata` answer a NORMAL edge to a
/// synthetic package named `banned`. `false` when the answer has no such pinned package, which
/// leaves the plant empty and the case without its naming.
fn plant_banned_dep(meta: &mut serde_json::Value, crate_name: &str, banned: &str) -> bool {
    let Some(pid) = meta["packages"].as_array().and_then(|ps| {
        ps.iter()
            .find(|p| {
                p["name"].as_str() == Some(crate_name)
                    && p["source"].as_str().is_some_and(|s| s.starts_with("git+"))
            })
            .and_then(|p| p["id"].as_str().map(str::to_string))
    }) else {
        return false;
    };
    let bid = format!("path+file:///denylist-selftest/{banned}#{banned}@0.0.0");
    let Some(nodes) = meta["resolve"]["nodes"].as_array_mut() else {
        return false;
    };
    let Some(node) = nodes
        .iter_mut()
        .find(|n| n["id"].as_str() == Some(pid.as_str()))
    else {
        return false;
    };
    let Some(deps) = node["deps"].as_array_mut() else {
        return false;
    };
    deps.push(serde_json::json!({
        "name": banned.replace('-', "_"),
        "pkg": bid,
        "dep_kinds": [{"kind": null, "target": null}],
    }));
    nodes.push(serde_json::json!({"id": bid, "deps": [], "features": []}));
    if let Some(ps) = meta["packages"].as_array_mut() {
        ps.push(serde_json::json!({
            "id": bid,
            "name": banned,
            "source": null,
            "manifest_path": format!("/denylist-selftest/{banned}/Cargo.toml"),
            "dependencies": [],
            "features": {},
        }));
    }
    true
}
