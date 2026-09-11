//! THE CONSTRUCTION GATE: how the tree is BUILT, measured against `docs/design/ARCHITECTURE.md`,
//! with ceilings the owner tightens in `qa/construction.toml`.
//!
//! The shadow oracle proves the code on HEAD is user-correct. Nothing else measures whether it is
//! well constructed: one function sends the upstream attempt, request-path functions are readable,
//! planes talk to the kernel through the ABI only, every installable seam is actually installed by
//! production, the neutral crates know no dialect, the request terminal has one set of doors, the
//! section 1.1 ceilings are spent by the call graph and not by the crate boundary. Each is an
//! invariant the design states and the code drifted from because no instrument watched it.
//!
//! WHAT MOVED IN THE CONVERSION, AND WHAT DID NOT.
//!
//! * Every rule's predicate, ceiling and `detail` wording is the Python's, unchanged — proven by
//!   `cargo xtask gate construction --parity -- bash scripts/construction-gate.sh --check`.
//! * The OWED SET IS DERIVED, from the ceilings file plus the plugin-kind crate directories, so a
//!   rule cannot be deleted with the ledger still reading green. The shell derived it from what
//!   the run happened to print, which is the opposite: a rule that stopped running removed its own
//!   expectation.
//! * The SELF-TEST NO LONGER COPIES THE TREE. `plant.py` tarred `crates/*/src`, every manifest,
//!   `scripts`, `qa` and the ledger machinery into a scratch directory, calibrated a fresh ceilings
//!   file to obtain a green baseline, planted into the copy and deleted it afterwards — a sequence
//!   with a hand-maintained `TOUCHED` list, a `mktemp` race it had to learn about, and a
//!   calibration step whose whole purpose was to undo the ceilings the gate exists to enforce. An
//!   overlay is per-plant by construction, so none of that machinery has anything to do.
//! * `--calibrate` is GONE, with the self-test that needed it. It existed to write a ceilings file
//!   whose every value equalled today's measurement; nothing else called it.
//!
//! Three inputs stay delegated, each to the instrument that owns its policy — see
//! [`external`].
//!
//! THE FILE NAME IS LOAD-BEARING, and the name is the CANONICAL one. This is
//! `gates/construction.rs` with its parts in `gates/construction/`, not
//! `gates/construction/mod.rs`, because the design-bindings resolver
//! ([`crate::gates::design_bindings::verify::xtask_gate_module`]) turns a `cargo xtask gate <name>`
//! citation into `xtask/src/gates/<name_with_underscores>.rs` FIRST and reaches for the directory
//! spelling only when that file is absent. Both spellings are derived from the gate name — a gate
//! still cannot be cited under a name the runner does not answer to — but only the flat one is the
//! path a citation resolves to without a fallback, and four Appendix B bindings cite this gate.

pub mod ceilings;
pub mod census;
pub mod external;
pub mod model;
pub mod rules;
pub mod rules2;
pub mod selftest;
pub mod tree;

use std::collections::BTreeMap;

use crate::ctx::Ctx;
use crate::gates::{Gate, Report};
use crate::ledger::{Row, Verdict};
use crate::toml_doc;

use model::{plain, CRow, Cfg};
use tree::{crate_name_of_dir, dirs_for_globs, Tree};

pub const CEILINGS: &str = "qa/construction.toml";

/// The three section 1.1 surface ceilings, each with the crates it sums and the words the row uses
/// for them. The figures live in `[gate.surface_ceilings]`; only the labels are here, because a
/// label is not a threshold.
const SURFACE: [(&str, &str, &str, &str, i64); 3] = [
    (
        "contract+caps",
        "contract_caps",
        "busbar-contract,busbar-caps",
        "the contract pair's plugin-visible surface",
        3500,
    ),
    (
        "grammar",
        "grammar",
        "busbar-grammar",
        "the closed span grammar's surface",
        500,
    ),
    (
        "contract-transport",
        "contract_transport",
        "busbar-contract-transport",
        "the transport-facing contract's surface",
        1000,
    ),
];

/// The two halves of the `forbid-unsafe` rule: the ceilings-file key listing the kinds each holds,
/// the key listing the tracked debt it ratchets, and the row-id prefix it emits under.
///
/// A RATCHETED ROW IS PASS BY CONSTRUCTION, and that is why this table is shared with
/// [`ConstructionGate::informational_ids`]. The rule measures `1` for a crate missing the attribute
/// and `0` for one carrying it, against a ceiling of `1` for every crate on `known_missing_*` — so
/// no plant can drive such a row red, and demanding a RED proof for it would be demanding a proof
/// of something that is not true. The self-test proves the ratchet instead: under the SAME plant
/// that reds every held crate of the kind, the tracked ones stay green.
pub const UNSAFE_HALVES: [(&str, &str, &str); 2] = [
    ("forbid_kinds", "known_missing_forbid", "forbid-unsafe"),
    ("deny_kinds", "known_missing_deny", "forbid-unsafe-deny"),
];

pub struct ConstructionGate;

impl ConstructionGate {
    pub fn cfg(cx: &Ctx) -> Result<Cfg, String> {
        let text = cx.read(CEILINGS)?;
        Ok(Cfg {
            doc: toml_doc::parse_str(&text)?,
        })
    }

    /// Every row id this gate can emit, derived from the ceilings file and the plugin-kind crate
    /// directories on disk — never a list maintained beside the rules.
    ///
    /// It reads the workspace the gate was BUILT against rather than the `Ctx` a run is handed,
    /// because [`Gate::owed`] is asked without one. That is sound for every caller this gate has
    /// (both share the workspace root) and it draws one boundary around the self-test: a plant may
    /// change any file, and may add a file to a crate, but may not add or remove a CRATE — doing
    /// so would move the owed set out from under the run reconciling against it.
    /// The owed rows this gate REPORTS and does not judge — see [`Gate::informational`]. Derived
    /// from the `forbid-unsafe` ratchet's own debt list rather than maintained beside it, so
    /// closing a debt moves its crate back under the RED proof in the same edit.
    ///
    /// The three `legacy-reach:<crate>` rows USED TO BE HERE and are not any more: a per-crate
    /// figure nothing could fail on let `busbar_substrate` sit twenty-one over it, passing, which
    /// is the whole of what the exemption bought. They gate now, and `ceiling-slack` holds them to
    /// the measurement from below.
    pub fn informational_ids(cx: &Ctx) -> Vec<String> {
        let mut ids = vec!["duplicate-dispatch".to_string()];
        if let Ok(cfg) = ConstructionGate::cfg(cx) {
            for (kinds_key, missing_key, prefix) in UNSAFE_HALVES {
                let (_, tracked) = ConstructionGate::unsafe_split(cx, &cfg, kinds_key, missing_key);
                ids.extend(tracked.iter().map(|c| format!("{prefix}:{c}")));
            }
        }
        ids
    }

    /// Split one half of the `forbid-unsafe` rule's crates into the ones the rule HOLDS to the
    /// attribute and the ones its ratchet TRACKS, both derived — the kinds from
    /// `[gate.plugin_kinds]`, the debt from the rule's own `known_missing_*` list, the membership
    /// from the crate directories on disk. Nothing here is a list maintained beside the rule, so
    /// closing a debt by deleting a name from the ceilings file moves that crate back under the
    /// rule and back under the self-test's RED proof in the same edit.
    pub fn unsafe_split(
        cx: &Ctx,
        cfg: &Cfg,
        kinds_key: &str,
        missing_key: &str,
    ) -> (Vec<String>, Vec<String>) {
        let Ok(rule) = cfg.rule("forbid-unsafe") else {
            return (Vec::new(), Vec::new());
        };
        let tracked_names = rule.list_of(missing_key);
        let mut here: Vec<String> = rule
            .list_of(kinds_key)
            .iter()
            .flat_map(|k| dirs_for_globs(cx, &cfg.kind_globs(k)))
            .map(|d| crate_name_of_dir(&d))
            .collect();
        here.sort();
        here.dedup();
        here.into_iter().partition(|c| !tracked_names.contains(c))
    }

    fn ids(cx: &Ctx) -> Result<Vec<String>, String> {
        let cfg = ConstructionGate::cfg(cx)?;
        let mut ids: Vec<String> = vec![
            "one-attempt-seam",
            "request-path-fn-size",
            "no-uninstalled-seam",
            "neutral-no-dialect",
            "single-terminal",
            "duplicate-dispatch",
            "token-sealed",
            "token-sealed:kernel-seal",
            "token-sealed:admit-token-mint",
            "teller-step-order",
            "one-teller-loop",
            "one-teller-loop:run_gauntlet",
            "no-response-escapes-audit",
            "terminal-doors-in-audit-step",
            "one-pick-site",
            "loc-ceilings:kernel",
            "loc-ceilings:caps-contract",
            "loc-ceilings:unit-total",
            "loc-ceilings:unit-verbs",
            "loc-ceilings:union",
            "lean-core",
            "no-default-bodies",
            "sealed-unit-traits",
            "hold-discipline:no-early-exit",
            "hold-discipline:no-catch-unwind-capture",
            "hold-discipline:no-join-abort",
            "hold-discipline:no-forget-or-drop",
            "hold-discipline:cancellation-before-await",
            "hold-escapes",
            "seal-sites",
            "kernel-seal-impls",
            "secret-carrier-debug",
            "no-escaped-newline-doc-comment",
            "unit-no-wall-clock",
            "ts-reads-the-clock",
            "ts-reads-the-clock:default-derive",
            "ts-reads-the-clock:second-clock",
            "unit-no-finding-ids",
            "plane-no-money",
            "one-pricing-site",
            "one-pricing-site:fee-fields",
            "legacy-reach",
            ceilings::ROW_ROSE,
            ceilings::ROW_SLACK,
            // UNCONDITIONAL, AND THAT IS THE ENTIRE POINT. Every id below this block is derived
            // from the same `Cfg` the rules read, so deleting a rule table deletes the obligation
            // to run it in the same edit. This one is a literal: `ceiling-census` is owed whatever
            // the config says, and it is the row that counts the tables the others come from.
            census::ROW_CENSUS,
            "no-test-doubles-in-production",
            "no-test-doubles-in-production:doubles",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        for crate_name in cfg.plane_crates()? {
            ids.push(format!("ports-only:{crate_name}"));
            ids.push(format!("ports-only-tests:{crate_name}"));
        }
        for (key, _) in cfg.doc.children("rules.loc-ceilings.kernel_files") {
            ids.push(format!("loc-ceilings:kernel:{key}"));
        }
        for (key, _) in cfg.doc.children("rules.legacy-reach.prefixes") {
            ids.push(format!("legacy-reach:{key}"));
        }

        let crates_of = |kinds: &[String]| -> Vec<String> {
            kinds
                .iter()
                .flat_map(|k| dirs_for_globs(cx, &cfg.kind_globs(k)))
                .map(|d| crate_name_of_dir(&d))
                .collect()
        };

        let manifest_kinds: Vec<String> = [
            "plane",
            "store",
            "pure_auth",
            "hook",
            "export",
            "secret",
            "egress_auth",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let manifest_crates = crates_of(&manifest_kinds);
        if manifest_crates.is_empty() {
            ids.push("manifest-allowlist".to_string());
        } else {
            ids.extend(
                manifest_crates
                    .iter()
                    .map(|c| format!("manifest-allowlist:{c}")),
            );
        }

        let denylist_crates = crates_of(&cfg.rule("source-denylist")?.list_of("kinds"));
        if denylist_crates.is_empty() {
            ids.push("source-denylist".to_string());
        } else {
            ids.extend(
                denylist_crates
                    .iter()
                    .map(|c| format!("source-denylist:{c}")),
            );
        }

        let unsafe_rule = cfg.rule("forbid-unsafe")?;
        for (kinds_key, prefix) in [
            ("forbid_kinds", "forbid-unsafe"),
            ("deny_kinds", "forbid-unsafe-deny"),
        ] {
            let here = crates_of(&unsafe_rule.list_of(kinds_key));
            if here.is_empty() {
                ids.push(prefix.to_string());
            } else {
                ids.extend(here.iter().map(|c| format!("{prefix}:{c}")));
            }
        }

        for (id, ..) in SURFACE {
            ids.push(format!("surface-ceiling:{id}"));
        }
        ids.sort();
        ids.dedup();
        Ok(ids)
    }

    /// Every measured row, in the order `rules.py::evaluate` produces them. A rule that could not
    /// run yields NO row rather than a guess, and the reconciliation turns that into
    /// "DID NOT RUN" — which is not a pass.
    pub fn measure(cx: &Ctx) -> Result<(Vec<CRow>, Vec<String>), String> {
        let cfg = ConstructionGate::cfg(cx)?;
        let tree = Tree::load(cx, &cfg.scan_roots()?, &cfg.test_path_fragments()?)?;
        let hits = external::purity_hits(cx);
        let denylist = external::denylist_hits(cx);

        let mut rows = Vec::new();
        let mut problems = Vec::new();
        let mut take = |what: &str, r: Result<Vec<CRow>, String>, rows: &mut Vec<CRow>| match r {
            Ok(v) => rows.extend(v),
            Err(e) => problems.push(format!("{what}: {e}")),
        };

        take(
            "one-attempt-seam",
            rules::one_attempt_seam(&tree, &cfg),
            &mut rows,
        );
        take(
            "request-path-fn-size",
            rules::request_path_fn_size(&tree, &cfg),
            &mut rows,
        );
        take("ports-only", rules::ports_only(&tree, &cfg), &mut rows);
        take(
            "no-uninstalled-seam",
            rules::no_uninstalled_seam(&tree, &cfg),
            &mut rows,
        );
        take(
            "neutral-no-dialect",
            rules::neutral_no_dialect(&cfg, hits.as_deref()),
            &mut rows,
        );
        take(
            "single-terminal",
            rules::single_terminal(&tree, &cfg),
            &mut rows,
        );
        take(
            "duplicate-dispatch",
            rules::duplicate_dispatch(&tree, &cfg),
            &mut rows,
        );
        take("token-sealed", rules::token_sealed(&tree, &cfg), &mut rows);
        take(
            "teller-step-order",
            rules::teller_step_order(&tree, &cfg),
            &mut rows,
        );
        take(
            "one-teller-loop",
            rules::one_teller_loop(&tree, &cfg),
            &mut rows,
        );
        take(
            "no-response-escapes-audit",
            rules::no_response_escapes_audit(&tree, &cfg),
            &mut rows,
        );
        take(
            "terminal-doors-in-audit-step",
            rules::terminal_doors_in_audit_step(&tree, &cfg),
            &mut rows,
        );
        take(
            "one-pick-site",
            rules::one_pick_site(&tree, &cfg),
            &mut rows,
        );
        take(
            "loc-ceilings",
            rules2::loc_ceilings(cx, &tree, &cfg),
            &mut rows,
        );
        take(
            "manifest-allowlist",
            rules2::manifest_allowlist(cx, &tree, &cfg),
            &mut rows,
        );
        take(
            "source-denylist",
            rules2::source_denylist(cx, &tree, &cfg, denylist.as_ref()),
            &mut rows,
        );
        take("lean-core", rules2::lean_core(cx, &tree, &cfg), &mut rows);
        take(
            "no-default-bodies",
            rules2::no_default_bodies(&tree, &cfg),
            &mut rows,
        );
        take(
            "sealed-unit-traits",
            rules2::sealed_unit_traits(&tree, &cfg),
            &mut rows,
        );
        take(
            "hold-discipline",
            rules2::hold_discipline(cx, &tree, &cfg),
            &mut rows,
        );
        take(
            "hold-escapes",
            rules2::hold_escapes(cx, &tree, &cfg),
            &mut rows,
        );
        take("seal-sites", rules2::seal_sites(cx, &tree, &cfg), &mut rows);
        take(
            "kernel-seal-impls",
            rules2::kernel_seal_impls(&tree, &cfg),
            &mut rows,
        );
        take(
            "forbid-unsafe",
            rules2::forbid_unsafe(cx, &tree, &cfg),
            &mut rows,
        );
        take(
            "secret-carrier-debug",
            rules2::secret_carrier_debug(&tree, &cfg),
            &mut rows,
        );
        take(
            "no-escaped-newline-doc-comment",
            rules2::no_escaped_newline_doc_comment(cx, &tree, &cfg),
            &mut rows,
        );
        take(
            "unit-no-wall-clock",
            rules2::unit_no_wall_clock(&tree, &cfg),
            &mut rows,
        );
        take(
            "ts-reads-the-clock",
            rules2::ts_reads_the_clock(&tree, &cfg),
            &mut rows,
        );
        take(
            "unit-no-finding-ids",
            rules2::unit_no_finding_ids(cx, &tree, &cfg),
            &mut rows,
        );
        take(
            "plane-no-money",
            rules2::plane_no_money(cx, &tree, &cfg),
            &mut rows,
        );
        take(
            "one-pricing-site",
            rules2::one_pricing_site(&tree, &cfg),
            &mut rows,
        );
        take("legacy-reach", rules2::legacy_reach(&tree, &cfg), &mut rows);
        take(
            "no-test-doubles-in-production",
            rules2::no_test_doubles_in_production(&tree, &cfg),
            &mut rows,
        );

        rows.extend(surface_rows(cx, &cfg));
        // LAST, AND IN THIS ORDER. `ceiling-slack` reads the OTHER ROWS' measurements rather than
        // re-deriving them, so it must see every row this run produced — including the three
        // surface rows above, which are the ones a re-measurement would be most likely to disagree
        // with, since they come from a subprocess.
        // ── THE SCAN-SET FLOOR ───────────────────────────────────────────────────────────────────
        // AN ABSENT SUBJECT IS RED, NOT PASS. Around eight rules print `vacuous: <path> does not
        // exist yet` and return PASS, so every one of them is a rule that reports green precisely
        // when it has nothing to read. That is the same shape as a glob narrowed to match nothing,
        // and it is the shape `structure-lint` (CANDIDATE_FLOOR = 200) and `workspace-deps`
        // (MIN_MEMBERS/MIN_INHERITED) each spend a floor to refuse.
        //
        // It is done HERE rather than at the ~18 sites so that a rule added tomorrow inherits it:
        // the `vacuous: ` prefix is the declaration, and this is the one place that scores it. A
        // row that legitimately has no subject must say so with a ceiling and a measurement, not by
        // passing on absence.
        //
        // Zero rows on this tree are vacuous, measured 2026-09-09, so this costs nothing today and
        // is entirely a guard on the direction of travel.
        // An INFORMATIONAL row is PASS by construction and its title carries `WARN ` — it is a
        // report, not a claim, so there is nothing for a floor to hold it to.
        for r in &mut rows {
            if r.detail.starts_with(model::VACUOUS)
                && !r.informational
                && r.status == crate::ledger::Status::Pass
            {
                r.status = crate::ledger::Status::Fail;
            }
        }

        // THE CENSUS BEFORE THE ROSE. It counts the rule tables the rest of the gate was derived
        // from, so a run that lost one says so next to the ceilings that went with it.
        rows.extend(census::ceiling_census(cx, &cfg));
        rows.extend(ceilings::ceiling_rose(cx));
        let slack = ceilings::ceiling_slack(&cfg, &rows);
        rows.extend(slack);
        Ok((rows, problems))
    }
}

/// The three surface ceilings, as ledger rows. The shell turned `loc-surface.py`'s exit code into
/// a row and nothing more; so does this, including the trailing space its `tr '\n' ' '` left on a
/// failing detail — a byte the parity comparison would otherwise flag.
fn surface_rows(cx: &Ctx, cfg: &Cfg) -> Vec<CRow> {
    let table = cfg.doc.table_or_empty("gate.surface_ceilings");
    let mut out = Vec::new();
    for (id, key, crates, what, default) in SURFACE {
        let limit = table.int_of(key).unwrap_or(default);
        let m = external::loc_surface(cx, crates, limit);
        let detail = if m.ok {
            format!("{what} is {} lines", m.total)
        } else {
            m.tail.clone()
        };
        out.push(plain(
            format!("surface-ceiling:{id}"),
            m.ok,
            format!("{what} stays under its ceiling"),
            detail,
            m.total.parse::<i64>().unwrap_or(-1),
            limit,
            vec![],
        ));
    }
    out
}

impl Gate for ConstructionGate {
    fn name(&self) -> &'static str {
        "construction"
    }

    fn owed(&self) -> Vec<String> {
        match Ctx::workspace().and_then(|cx| ConstructionGate::ids(&cx)) {
            Ok(ids) => ids,
            // A gate that cannot read its own ceilings file owes one row it will never emit, so
            // the reconciliation reports DID NOT RUN rather than an empty, vacuously green set.
            Err(_) => vec!["construction:ceilings-unreadable".to_string()],
        }
    }

    fn informational(&self) -> Vec<String> {
        match Ctx::workspace() {
            Ok(cx) => ConstructionGate::informational_ids(&cx),
            // No exemption from a tree that could not be opened: the coverage check then demands a
            // RED case for every owed row, which is the strict answer, not the lenient one.
            Err(_) => Vec::new(),
        }
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        match ConstructionGate::measure(cx) {
            Ok((rows, problems)) => {
                for p in &problems {
                    eprintln!("xtask gate construction: {p}");
                }
                Verdict::of(rows.iter().map(CRow::to_row).collect())
            }
            Err(e) => {
                eprintln!("xtask gate construction: {e}");
                Verdict::of(vec![Row::fail(
                    "construction:ceilings-unreadable",
                    "the construction gate could read neither its ceilings nor the tree",
                    e,
                )])
            }
        }
    }

    fn selftest(&self, cx: &Ctx) -> Report {
        selftest::run(self, cx)
    }

    /// THE PARITY TRANSLATOR, and it reads the legacy's OWN LEDGER FILE rather than its stdout.
    ///
    /// `scripts/construction-gate.sh` writes a ledger — but at a path of its own choosing
    /// (`$CONSTRUCTION_OUT/ledger.tsv`, default `target/construction/ledger.tsv`), because
    /// `measure()` exports `LEDGER` over whatever it was handed. So the harness's `$LEDGER` scratch
    /// file stays empty and the default "read `$LEDGER` back" arm would compare against nothing,
    /// which passes vacuously — the one outcome the harness exists to refuse.
    ///
    /// Its STDOUT cannot stand in either, and the reason is worth stating: `record()` prints a
    /// PASS row as `PASS  <id>  <title>` and prints its DETAIL nowhere. A translator built on
    /// stdout would therefore compare 103 empty detail columns against 103 real ones and call the
    /// difference a conversion defect.
    ///
    /// So the file is read, and the staleness the ledger module warns about is closed by
    /// [`Gate::legacy_env`]: the script is POINTED AT the harness's own per-run scratch directory,
    /// which is emptied before it runs. A script that dies before writing then leaves nothing to
    /// read, and the comparison is an error rather than a green over the previous run's rows.
    fn has_legacy_adapter(&self) -> bool {
        true
    }

    fn legacy_env(&self, scratch: &std::path::Path) -> Vec<(String, String)> {
        let out = legacy_out_dir(scratch);
        let _ = std::fs::remove_dir_all(&out);
        vec![("CONSTRUCTION_OUT".to_string(), out.display().to_string())]
    }

    fn legacy_rows(
        &self,
        _cx: &Ctx,
        runs: &[crate::parity::LegacyRun],
    ) -> Option<Result<Vec<Row>, String>> {
        let run = &runs[0];
        let ledger = legacy_out_dir(&run.scratch).join("ledger.tsv");
        Some(crate::ledger::read_leg(&ledger).map_err(|e| {
            format!(
                "{e} — `{}` exited {:?} without writing its ledger. That is 'the legacy could not \
                 run', never a parity green.",
                run.argv.join(" "),
                run.code
            )
        }))
    }
}

/// Where `scripts/construction-gate.sh` writes its ledger under a parity run: it takes
/// `$CONSTRUCTION_OUT` for its output directory, and the harness hands it a subdirectory of the
/// per-run scratch rather than letting it default to `target/construction/`. One derivation, read
/// by both the env the script is given and the path the translator reads back.
fn legacy_out_dir(scratch: &std::path::Path) -> std::path::PathBuf {
    scratch.join("construction")
}

/// The measured rows keyed by id, for the self-test's own arithmetic.
pub fn by_id(rows: &[CRow]) -> BTreeMap<&str, &CRow> {
    rows.iter().map(|r| (r.id.as_str(), r)).collect()
}
