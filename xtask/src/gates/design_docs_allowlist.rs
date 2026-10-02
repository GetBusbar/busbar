//! `cargo xtask gate design-docs-allowlist` — `docs/design/` HOLDS THE SPEC, THE TODO AND THEIR
//! THREE COMPANIONS, AND NOTHING ELSE.
//!
//! OWNER-AGREED 2026-09-27. `docs/design/` had grown to well over a hundred files: parallel specs,
//! scratch reports, sweeps, ledgers, trackers, generated evidence — each written as "the" document
//! for its topic, several contradicting the spec, and forty-seven of them read by CI, so none could
//! be deleted without first being unwired. The rule that replaces them is one list:
//!
//! | path | what it is |
//! | --- | --- |
//! | `BUSBAR-1.6.0.md` | the spec — the design |
//! | `1.6.0-TODO.md` | the plan — the order of the work |
//! | `1.6.0-QUESTIONS.md` | what is open with the owner |
//! | `1.6.0-SLOT-LOG.md` | what each slot did |
//! | `1.6.0-PARKED/` | held work, one file per item |
//!
//! Generated data and evidence live under `qa/`; security records under `docs/security/`. A new
//! design topic is a section of the spec, not a new file beside it.
//!
//! Two rows:
//!
//! * `design-docs-allowlist:only-allowlisted` — every TRACKED path under `docs/design/` is on the
//!   list. RED names each stray. Tracked, because an untracked scratch file in a working tree is
//!   the author's business until it is added; the rule is about what the repository serves.
//! * `design-docs-allowlist:spec-present` — the spec and the TODO are both tracked. This is the
//!   floor: a listing that came back empty (a failed `git ls-files`, a moved directory) has no
//!   strays in it, and "nothing to object to" must never read as "the rule holds".

use std::collections::BTreeSet;

use crate::ctx::{Change, Ctx, Overlay};
use crate::gates::{prove_green, prove_red, Gate, Report};
use crate::ledger::{Row, Verdict};

pub const ROW_ONLY: &str = "design-docs-allowlist:only-allowlisted";
pub const ROW_SPEC: &str = "design-docs-allowlist:spec-present";

const DIR: &str = "docs/design/";

/// The files `docs/design/` may hold, by exact path.
pub const ALLOWED_FILES: &[&str] = &[
    "docs/design/BUSBAR-1.6.0.md",
    "docs/design/1.6.0-TODO.md",
    "docs/design/1.6.0-QUESTIONS.md",
    "docs/design/1.6.0-SLOT-LOG.md",
];

/// The one directory `docs/design/` may hold, and everything under it.
pub const ALLOWED_DIRS: &[&str] = &["docs/design/1.6.0-PARKED/"];

/// The two files whose absence means the listing, not the tree, is what came back empty.
const REQUIRED: &[&str] = &["docs/design/BUSBAR-1.6.0.md", "docs/design/1.6.0-TODO.md"];

pub struct DesignDocsAllowlistGate;

fn allowed(path: &str) -> bool {
    ALLOWED_FILES.contains(&path) || ALLOWED_DIRS.iter().any(|d| path.starts_with(d))
}

/// The overlay command that answers the `git ls-files` listing in a self-test, one path per line.
const LISTING_KEY: &str = "git-ls-files-docs-design";

/// Every tracked path under `docs/design/`, as `git ls-files` lists it (or as the overlay's
/// [`LISTING_KEY`] answers it), with the overlay's file claims laid on top: a planted file is
/// tracked, a removed one is not. That is what lets the self-test plant a stray without writing one
/// into the index.
fn tracked(cx: &Ctx) -> Result<BTreeSet<String>, String> {
    let listing = match cx.overlay_command(LISTING_KEY) {
        Some(planted) => planted.lines().map(str::to_string).collect(),
        None => cx.git_lines(&["ls-files", "--", DIR])?,
    };
    let mut out: BTreeSet<String> = listing
        .into_iter()
        .map(|p| p.trim().to_string())
        .filter(|p| p.starts_with(DIR))
        .collect();
    if let Some(ov) = cx.overlay() {
        for (path, change) in ov.changes() {
            let p = path.to_string_lossy().replace('\\', "/");
            if !p.starts_with(DIR) {
                continue;
            }
            match change {
                Change::Content(_) | Change::Unreadable(_) => {
                    out.insert(p);
                }
                Change::Absent => {
                    out.remove(&p);
                }
            }
        }
    }
    Ok(out)
}

impl Gate for DesignDocsAllowlistGate {
    fn name(&self) -> &'static str {
        "design-docs-allowlist"
    }

    fn owed(&self) -> Vec<String> {
        vec![ROW_ONLY.to_string(), ROW_SPEC.to_string()]
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let paths = match tracked(cx) {
            Ok(p) => p,
            Err(why) => {
                let title = "git ls-files could not list docs/design/";
                return Verdict::of(vec![
                    Row::fail(ROW_ONLY, title, why.clone()),
                    Row::fail(ROW_SPEC, title, why),
                ]);
            }
        };
        let missing: Vec<&str> = REQUIRED
            .iter()
            .copied()
            .filter(|r| !paths.contains(*r))
            .collect();
        let spec = if missing.is_empty() {
            Row::pass(
                ROW_SPEC,
                "the spec and the TODO are tracked",
                format!("{} tracked path(s) under {DIR}", paths.len()),
            )
        } else {
            Row::fail(
                ROW_SPEC,
                "the spec or the TODO is not tracked, so the listing proves nothing",
                format!(
                    "missing: {} — an empty or moved listing has no strays in it, which is not the \
                     same fact as a clean docs/design",
                    missing.join(" | ")
                ),
            )
        };
        let strays: Vec<&str> = paths
            .iter()
            .map(String::as_str)
            .filter(|p| !allowed(p))
            .collect();
        let only = if strays.is_empty() {
            Row::pass(
                ROW_ONLY,
                "docs/design holds only the allowlisted documents",
                format!(
                    "allowlist: {} and {}",
                    ALLOWED_FILES.join(", "),
                    ALLOWED_DIRS.join(", ")
                ),
            )
        } else {
            Row::fail(
                ROW_ONLY,
                "docs/design holds a file outside the allowlist",
                format!(
                    "{} stray path(s): {} — docs/design holds the spec, the TODO, \
                     QUESTIONS, SLOT-LOG and 1.6.0-PARKED/ only (owner, 2026-09-27). A design topic \
                     is a section of BUSBAR-1.6.0.md; generated data and evidence go under qa/.",
                    strays.len(),
                    strays.join(" | ")
                ),
            )
        };
        Verdict::of(vec![only, spec])
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();

        // THE BASELINE: the real listing with every stray taken out, answered through the listing
        // key. Asked over that rather than the real tree, so the proof holds on a tree the purge
        // has not reached yet and each red below is the plant's, not a standing one. (Removing the
        // strays as file claims would not do: the plants are judged against this baseline, and a
        // removal there makes every later plant "remove a path that is already absent".)
        let mut base_ov = Overlay::new();
        let kept: Vec<String> = tracked(cx)
            .map(|paths| paths.into_iter().filter(|p| allowed(p)).collect())
            .unwrap_or_default();
        base_ov.set_command(LISTING_KEY, kept.join("\n"));
        let base_cx = cx.with_overlay(base_ov.clone());
        let base = &base_cx;
        let on_base = |ov: Overlay| base_ov.layered(&ov);

        report.push(prove_green(
            base,
            self,
            "a docs/design holding only the allowlisted documents is green",
            &[ROW_ONLY, ROW_SPEC],
        ));

        let mut ov = Overlay::new();
        ov.set("docs/design/1.6.0-stray-report.md", "# a scratch report\n");
        report.push(prove_red(
            base,
            self,
            "a stray document planted in docs/design is RED, by name",
            &[ROW_ONLY],
            on_base(ov),
            &["1.6.0-stray-report.md"],
        ));

        // NEAR MISSES: an allowlisted NAME in a subdirectory, an allowlisted name with a suffix, and
        // a directory whose name merely begins with the allowed one. Each is a stray.
        let mut ov = Overlay::new();
        ov.set("docs/design/old/BUSBAR-1.6.0.md", "x\n");
        ov.set("docs/design/1.6.0-TODO.md.bak", "x\n");
        ov.set("docs/design/1.6.0-PARKED-2/a.md", "x\n");
        report.push(prove_red(
            base,
            self,
            "an allowlisted name in the wrong place, with a suffix, or a look-alike directory is a stray",
            &[ROW_ONLY],
            on_base(ov),
            &[
                "docs/design/old/BUSBAR-1.6.0.md",
                "docs/design/1.6.0-TODO.md.bak",
                "docs/design/1.6.0-PARKED-2/a.md",
            ],
        ));

        // THE DIRECTORY IS OPEN: anything under 1.6.0-PARKED/, at any depth, is allowed.
        let mut ov = Overlay::new();
        ov.set("docs/design/1.6.0-PARKED/new-item.md", "x\n");
        ov.set("docs/design/1.6.0-PARKED/sub/evidence.json", "{}\n");
        report.push(prove_green(
            &cx.with_overlay(on_base(ov)),
            self,
            "a new file under 1.6.0-PARKED/ is allowed",
            &[ROW_ONLY],
        ));

        // THE FLOOR: the spec gone from the listing is RED on its own row.
        let mut ov = Overlay::new();
        ov.remove("docs/design/BUSBAR-1.6.0.md");
        report.push(prove_red(
            base,
            self,
            "a listing without the spec proves nothing and is RED",
            &[ROW_SPEC],
            on_base(ov),
            &["BUSBAR-1.6.0.md"],
        ));

        report
    }
}

#[cfg(test)]
mod tests {
    use super::allowed;

    #[test]
    fn the_allowlist_is_exact() {
        for p in [
            "docs/design/BUSBAR-1.6.0.md",
            "docs/design/1.6.0-TODO.md",
            "docs/design/1.6.0-QUESTIONS.md",
            "docs/design/1.6.0-SLOT-LOG.md",
            "docs/design/1.6.0-PARKED/a.md",
            "docs/design/1.6.0-PARKED/x/y.json",
        ] {
            assert!(allowed(p), "{p}");
        }
        for p in [
            "docs/design/ARCHITECTURE.md",
            "docs/design/1.6.0-KICKOFF.md",
            "docs/design/1.6.0-TRACKER.md",
            "docs/design/1.6.0-TODO.md.bak",
            "docs/design/old/BUSBAR-1.6.0.md",
            "docs/design/1.6.0-PARKED",
            "docs/design/1.6.0-PARKED-2/a.md",
        ] {
            assert!(!allowed(p), "{p}");
        }
    }
}
