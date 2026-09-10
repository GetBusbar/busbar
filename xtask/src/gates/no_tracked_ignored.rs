//! `cargo xtask gate no-tracked-ignored` — NO TRACKED PATH MAY MATCH THE TREE'S OWN IGNORE RULES.
//!
//! `.fix/kernel.rs.orig` (1,430 lines) and `.fix/units_llm.rs.orig` (4,096 lines) were `git add`ed
//! into a money commit as a pre-money-as-a-lookup snapshot of the llm root leg, even though
//! `/.fix/` is a `.gitignore` rule of this very tree (`.gitignore:17`) — reversing the earlier rule
//! that the scratch directory is scratch, not source. Git's own precedence let it happen: a path
//! that is already tracked is exempt from every ignore rule from that commit on, so the file stayed
//! live, reviewed and shipped while five other gates (loc-surface, census, structure-lint,
//! legacy-reach, forbid-unsafe) walked straight past it — every one of them either skips ignored
//! paths outright or skips a directory `.gitignore` names, on the working assumption that
//! "ignored" and "not source" are the same fact. They are not, once a path is tracked.
//!
//! THE SAME HOLE, ONE DIRECTORY UP. `xtask/src/gates/kind_isolation.rs`'s own selftest carries the
//! wider case in its own words: "a compiled source in a walker-skipped, gitignored directory is
//! source no rule has read" — a file the WALKER never lists, reached by a `#[path]` the compiler
//! still resolves. This gate is the narrower, git-native twin of that hazard: a path GIT ITSELF
//! tracks despite one of the tree's own `.gitignore` rules naming it. `git ls-files -ci
//! --exclude-standard` is the exact test — cached (tracked) paths, intersected with the ones
//! `--exclude-standard`'s ignore rules would otherwise exclude — and it is exactly what
//! [`crate::ctx::Ctx::tracked_ignored`] runs.
//!
//! One row: RED names every offending path, and a `.gitignore` rule of the tree matches every one
//! of them by construction of the query itself, so the row spells out the rule alongside the path
//! rather than trying to attribute one ignore line to one match.

use crate::ctx::{Ctx, Overlay};
use crate::gates::{prove_green, prove_red, Gate, Report};
use crate::ledger::{Row, Verdict};

pub const ROW_TRACKED_IGNORED: &str = "no-tracked-ignored:tracked";

pub struct NoTrackedIgnoredGate;

impl Gate for NoTrackedIgnoredGate {
    fn name(&self) -> &'static str {
        "no-tracked-ignored"
    }

    fn owed(&self) -> Vec<String> {
        vec![ROW_TRACKED_IGNORED.to_string()]
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let row = match cx.tracked_ignored() {
            Ok(offenders) if offenders.is_empty() => Row::pass(
                ROW_TRACKED_IGNORED,
                "no tracked path matches a .gitignore rule of this tree",
                "git ls-files -ci --exclude-standard named nothing",
            ),
            Ok(offenders) => Row::fail(
                ROW_TRACKED_IGNORED,
                "a tracked path matches a .gitignore rule of this tree",
                format!(
                    "{} path(s) tracked despite an ignore rule naming them (git ls-files -ci \
                     --exclude-standard): {} — tracking a path exempts it from every ignore rule \
                     from that commit on, so a scanner that trusts .gitignore to bound its scan \
                     never reads it again",
                    offenders.len(),
                    offenders.join(" | ")
                ),
            ),
            Err(why) => Row::fail(
                ROW_TRACKED_IGNORED,
                "git ls-files -ci --exclude-standard could not be read",
                why,
            ),
        };
        Verdict::of(vec![row])
    }

    fn selftest(&self, cx: &Ctx) -> Report {
        let mut report = Report::new();

        report.push(prove_green(
            cx,
            self,
            "this tree carries no tracked-and-ignored path",
            &[ROW_TRACKED_IGNORED],
        ));

        // THE PLANT: a tracked file under an ignored path, answered through the overlay command
        // `tracked_ignored` reads rather than a real `git add -f` — planting that FOR REAL would
        // be committing the exact hazard this row exists to refuse.
        let mut ov = Overlay::new();
        ov.set_command("git-ls-files-ci-exclude-standard", ".fix/kernel.rs.orig\n");
        report.push(prove_red(
            cx,
            self,
            "a tracked file under an ignored path is RED, naming the path and the ignore rule's own query",
            &[ROW_TRACKED_IGNORED],
            ov,
            &[".fix/kernel.rs.orig", "git ls-files -ci --exclude-standard"],
        ));

        // REMOVE IT: the same overlay key answering empty is green again, which is what makes the
        // red above a proof of THIS row and not of a gate wired to fail unconditionally. This is
        // the SAME overlay shape as the plant, with the tracked path taken back out — not the
        // first `prove_green` above, which never touches the command key at all.
        let mut removed = Overlay::new();
        removed.set_command("git-ls-files-ci-exclude-standard", "");
        report.push(prove_green(
            &cx.with_overlay(removed),
            self,
            "removing the tracked-and-ignored path clears the row",
            &[ROW_TRACKED_IGNORED],
        ));

        report
    }
}
