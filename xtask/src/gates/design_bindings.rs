//! THE DESIGN BINDINGS GATE — "is what we built compliant with what we designed?"
//!
//! `docs/design/ARCHITECTURE.md` Appendix B is the one part of the design written as testable
//! rules: the PB-0 master rule plus one table row per binding. `qa/design-bindings.json` maps each
//! to the checks that prove it today. This gate does NOT run those checks; it proves that every
//! referenced check still EXISTS and that something it names actually COMPARES something, and it
//! records one ledger row per binding.
//!
//!   PASS   `mapped`: every referenced check exists AND compares something
//!   FAIL   `unproven`: checks are cited but nothing they name settles anything — a vanished ref,
//!          an oracle cell the pinned golden never recorded, a ref that asserts nothing
//!   SKIP   `unmapped`: a NAMED gap, with the suggested check in the detail column
//!
//! TWO POSTURES, ONE RECONCILIATION, and the difference is one flag rather than one script:
//!
//! * plain — a gap is REPORTED but does not turn the run red. Expressed as [`Gate::skip_allow`]:
//!   the allowlist is the set of bindings the COMMITTED ledger already records as `unmapped`, so
//!   only a gap somebody wrote down may skip. That is strictly narrower than the shell's, which
//!   allowed any SKIP whatsoever.
//! * `--strict` — every binding is owed with no allowlist, so any gap is red. This is what the
//!   1.6.0 DONE claim runs: DONE means no gap. It also runs REGEN-CLEAN first, because the rows it
//!   judges come out of the CACHED ledger and a stale cache hides a binding added to Appendix B.
//!
//! `--write` regenerates `qa/design-bindings.json` and `qa/DESIGN-BINDINGS.md` from Appendix B,
//! preserving hand-added `checks` entries. The conversion proved that regeneration byte-identical
//! to the Python's with `cmp` before the Python was deleted.

pub mod build;
pub mod json;
pub mod selftest;
pub mod tables;
pub mod verify;

use std::path::Path;

use crate::ctx::Ctx;
use crate::gates::{Gate, Report};
use crate::ledger::{Row, Status, Verdict};

use build::{ARCH_REL, CELLS_REL, GOLDEN_LEDGER_REL, OUT_JSON_REL, OUT_MD_REL};
use json::J;

pub struct DesignBindingsGate;

/// Everything a run reads, gathered once.
pub struct Inputs {
    pub ledger: J,
    pub cells: J,
    pub ctx: verify::Ctx,
}

impl DesignBindingsGate {
    pub fn inputs(cx: &Ctx) -> Result<Inputs, String> {
        let cells = match cx.read(CELLS_REL) {
            Ok(t) => json::parse(&t)?,
            // An absent cell corpus is an empty one, which is honest: nothing is proven by it.
            Err(_) => crate::jobj! { "cells" => J::Arr(vec![]) },
        };
        let ledger_text = cx
            .read(OUT_JSON_REL)
            .map_err(|e| format!("{e} -- run `cargo xtask gate design-bindings --write` first"))?;
        let ledger = json::parse(&ledger_text)?;
        let mut ctx = verify::Ctx::build(
            &cells,
            &cx.abs("crates"),
            cx.root(),
            &cx.abs(GOLDEN_LEDGER_REL),
        )?;
        if let Some(planted) = cx.overlay_command(NOTE_TABLE_KEY) {
            let table: Vec<(String, String)> = planted
                .split('\n')
                .filter_map(|l| l.split_once('\t'))
                .map(|(id, reason)| (id.to_string(), reason.to_string()))
                .collect();
            ctx.notes.clone_from(&table);
            ctx.unproven_by_note = table;
        }
        Ok(Inputs { ledger, cells, ctx })
    }

    /// Regenerate both ledger artifacts. Returns their text; the caller decides where they land, so
    /// a REGEN-CLEAN comparison never has to write into the tree it is checking.
    ///
    /// The verification context is passed IN rather than rebuilt: it indexes every test fn in
    /// `crates/` and closes the CI invocation graph, and a run that built it twice would spend most
    /// of its time proving the same two facts to itself.
    pub fn regenerate(cx: &Ctx, inputs: &Inputs) -> Result<(String, String), String> {
        let arch = cx.read(ARCH_REL)?;
        let doc = build::build(&arch, &inputs.cells, Some(&inputs.ledger), &inputs.ctx)?;
        Ok((build::to_json_text(&doc), build::render_md(&doc)))
    }

    /// `--write`, the one arm that touches the tree.
    pub fn write(cx: &Ctx) -> Result<String, String> {
        let inputs = DesignBindingsGate::inputs(cx)?;
        let (js, md) = DesignBindingsGate::regenerate(cx, &inputs)?;
        write_file(&cx.abs(OUT_JSON_REL), &js)?;
        write_file(&cx.abs(OUT_MD_REL), &md)?;
        Ok(format!(
            "wrote {} and {}",
            cx.abs(OUT_JSON_REL).display(),
            cx.abs(OUT_MD_REL).display()
        ))
    }

    /// The ids the COMMITTED ledger records as a named gap. Read without a `Ctx` because
    /// [`Gate::owed`] and [`Gate::skip_allow`] are asked without one; both describe the committed
    /// artifact, which is the same file every caller reads.
    fn committed(root: &Path) -> Option<J> {
        json::parse(&std::fs::read_to_string(root.join(OUT_JSON_REL)).ok()?).ok()
    }

    fn workspace_root() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| std::path::PathBuf::from("."))
    }

    fn binding_ids(pred: impl Fn(&J) -> bool) -> Vec<String> {
        let Some(doc) = DesignBindingsGate::committed(&DesignBindingsGate::workspace_root()) else {
            return Vec::new();
        };
        let empty: Vec<J> = Vec::new();
        doc.get("bindings")
            .and_then(J::as_array)
            .unwrap_or(&empty)
            .iter()
            .filter(|b| pred(b))
            .filter_map(|b| b.str_of("id").map(String::from))
            .collect()
    }
}

fn write_file(path: &Path, text: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    }
    std::fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))
}

/// The overlay key a self-test plants a NOTE TABLE under: `<binding id>\t<reason>` per line.
///
/// [`tables::UNPROVEN_BY_NOTE`] is EMPTY on HEAD -- the owner emptied it as each of the four
/// bindings it held gained a check that compares something -- and the rule that reads it is still
/// live. A rule whose table is empty is a rule no plant can reach, so "the ledger's own note calls
/// this binding UNPROVEN" was a refusal nothing proved: it could be switched off and every case
/// here stayed green. This is how the self-test restores one entry for the length of one run,
/// without an entry in the shipped table that would then be a fiction somebody has to maintain.
pub const NOTE_TABLE_KEY: &str = "design-bindings:unproven-by-note";

/// The row the REGEN-CLEAN guard writes. It is owed only under `--strict`, because plain `--check`
/// is the gap REPORT and a report on a slightly stale ledger is still a useful report; `--strict`
/// is the DONE claim, and that claim is about Appendix B, not about a cache of it.
pub const ROW_REGEN: &str = "design-bindings:regen-clean";
const REGEN_TITLE: &str = "the committed ledger is what Appendix B derives";
const REGEN_CLEAN_DETAIL: &str =
    "a fresh derivation from Appendix B reproduces both artifacts byte for byte";

impl Gate for DesignBindingsGate {
    fn name(&self) -> &'static str {
        "design-bindings"
    }

    fn owed(&self) -> Vec<String> {
        let mut ids = DesignBindingsGate::binding_ids(|_| true);
        if ids.is_empty() {
            // A ledger that could not be read owes one row it will never emit, so the
            // reconciliation says DID NOT RUN rather than passing over an empty set.
            return vec!["design-bindings:ledger-unreadable".to_string()];
        }
        ids.push(ROW_REGEN.to_string());
        ids
    }

    /// A NAMED gap may skip; nothing else may. The shell allowed any SKIP row through in its plain
    /// posture, so a binding that became a gap between two writes skipped silently; here the gap
    /// has to be in the committed ledger, which is a file somebody edits and a reviewer reads.
    fn skip_allow(&self) -> Vec<String> {
        DesignBindingsGate::binding_ids(|b| b.str_of("status") == Some("unmapped"))
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let inputs = match DesignBindingsGate::inputs(cx) {
            Ok(i) => i,
            Err(e) => {
                return Verdict::of(vec![Row::fail(
                    "design-bindings:ledger-unreadable",
                    "the design bindings ledger could not be read",
                    e,
                )])
            }
        };
        let mut rows: Vec<Row> = verify::verify_rows(&inputs.ledger, &inputs.ctx)
            .into_iter()
            .map(|(id, verdict, title, detail)| {
                Row::new(
                    Status::parse(&verdict).unwrap_or(Status::Fail),
                    id,
                    title,
                    detail,
                )
            })
            .collect();
        rows.push(regen_row(cx, &inputs));
        Verdict::of(rows)
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        selftest::run(self, cx)
    }

    /// THE PARITY TRANSLATOR. Run it as
    /// `cargo xtask gate design-bindings --parity -- bash scripts/design-bindings.sh --check --strict`.
    ///
    /// TWO THINGS THE DEFAULT ARM CANNOT DO HERE. First, `scripts/design-bindings.sh::run_check`
    /// exports `LEDGER` over whatever it was handed, at `$DESIGN_BINDINGS_WORK/ledger.tsv`, so the
    /// harness's own scratch file stays empty and every comparison below it would be vacuous. The
    /// file is read instead, and the staleness that invites is closed by [`Gate::legacy_env`]:
    /// the script is POINTED AT the harness's own per-run scratch directory, which is emptied
    /// before it runs, so a script that dies before writing leaves nothing to read rather than the
    /// previous healthy run's rows.
    ///
    /// Second, THE ROW SETS DIFFER BY ONE, and that difference is the conversion's one documented
    /// split. The shell computed REGEN-CLEAN in `regen_clean()`, OUTSIDE the ledger: it printed
    /// prose and folded its answer into the exit code, so the one check that says whether the
    /// judged rows are even the right rows was the one check nothing reconciled. Here it is
    /// `design-bindings:regen-clean`, an owed ledger row like every other. The translator reads the
    /// shell's own printed verdict back into that row — through the same constructor — so the two
    /// sides are compared on it rather than the comparison quietly skipping it.
    fn has_legacy_adapter(&self) -> bool {
        true
    }

    /// Point the script's work directory at the harness's per-run scratch, emptied first, so the
    /// ledger the translator reads back can only be the one THIS run wrote.
    fn legacy_env(&self, scratch: &std::path::Path) -> Vec<(String, String)> {
        let work = legacy_work_dir(scratch);
        let _ = std::fs::remove_dir_all(&work);
        vec![(
            "DESIGN_BINDINGS_WORK".to_string(),
            work.display().to_string(),
        )]
    }

    fn legacy_rows(
        &self,
        _cx: &Ctx,
        runs: &[crate::parity::LegacyRun],
    ) -> Option<Result<Vec<Row>, String>> {
        let run = &runs[0];
        let ledger = legacy_work_dir(&run.scratch).join("ledger.tsv");
        Some((|| {
            let mut rows = crate::ledger::read_leg(&ledger).map_err(|e| {
                format!(
                    "{e} — `{}` exited {:?} without writing its ledger. That is 'the legacy could \
                     not run', never a parity green.",
                    run.argv.join(" "),
                    run.code
                )
            })?;
            let clean = run
                .stdout
                .contains("REGEN-CLEAN: the committed ledger matches a fresh derivation");
            let saw_it = clean || run.stdout.contains("REGEN-CLEAN:");
            if !saw_it {
                return Err(format!(
                    "`{}` printed no REGEN-CLEAN verdict at all. Only `--check --strict` computes \
                     one, and a parity run that compares this gate's row set without it is \
                     comparing the wrong row set.",
                    run.argv.join(" ")
                ));
            }
            rows.push(if clean {
                Row::pass(ROW_REGEN, REGEN_TITLE, REGEN_CLEAN_DETAIL)
            } else {
                Row::fail(ROW_REGEN, REGEN_TITLE, "the committed ledger is stale")
            });
            Ok(rows)
        })())
    }
}

/// Where `scripts/design-bindings.sh` writes its ledger under a parity run: it takes
/// `$DESIGN_BINDINGS_WORK` for its work directory, and the harness hands it a subdirectory of the
/// per-run scratch rather than letting it default to `target/design-bindings/`. One derivation,
/// read by both the env the script is given and the path the translator reads back, so the two
/// cannot drift apart.
fn legacy_work_dir(scratch: &std::path::Path) -> std::path::PathBuf {
    scratch.join("design-bindings")
}

/// REGEN-CLEAN: is the committed ledger what a fresh derivation from Appendix B produces?
///
/// The regen is compared IN MEMORY and nothing here rewrites the committed ledger — a check that
/// repairs what it is checking has not checked anything.
pub fn regen_row(cx: &Ctx, inputs: &Inputs) -> Row {
    let title = REGEN_TITLE;
    let (js, md) = match DesignBindingsGate::regenerate(cx, inputs) {
        Ok(pair) => pair,
        Err(e) => {
            return Row::fail(
                ROW_REGEN,
                title,
                format!("the derivation from Appendix B FAILED -- {e}"),
            )
        }
    };
    let committed_js = cx.read(OUT_JSON_REL).unwrap_or_default();
    let committed_md = cx.read(OUT_MD_REL).unwrap_or_default();
    let mut stale = Vec::new();
    if committed_js != js {
        stale.push(OUT_JSON_REL);
    }
    if committed_md != md {
        stale.push(OUT_MD_REL);
    }
    if stale.is_empty() {
        return Row::pass(ROW_REGEN, title, REGEN_CLEAN_DETAIL);
    }
    Row::fail(
        ROW_REGEN,
        title,
        format!(
            "{} is NOT what Appendix B derives. --strict judges the rows in {OUT_JSON_REL}; if \
             that file is stale, a binding added to Appendix B is absent from every row it reads, \
             so it is unmapped, unproven, and green. Regenerate with `cargo xtask gate \
             design-bindings --write` and commit both artifacts.",
            stale.join(" and ")
        ),
    )
}
