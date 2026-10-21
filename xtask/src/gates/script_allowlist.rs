//! `cargo xtask gate script-allowlist` — NO NEW PYTHON OR SHELL WITHOUT A WRITTEN REASON.
//!
//! OWNER 2026-10-02: "drop as much python ... as possible to rust" and "minimal to no .sh". A
//! product check or gate is `cargo xtask`; a release step is a check of ModernCI's branch files,
//! `.ci/dev.yaml` and `.ci/qa.yaml` (THE DESIGN Part 6, "BUSBAR-RELEASE RETIRED FROM BUSBAR",
//! l.3115-3132). Every `.py`, `.sh` and
//! `.bash` file still tracked here is listed in `qa/scripts-allowlist.toml` with a class (`port`,
//! `keep`, `external`, `retire`, `oracle-driver`) and a reason, and the list only shrinks: a port or a deletion
//! strikes its entry in the same commit.
//!
//! Four rows:
//!
//! * `script-allowlist:listed` — every tracked script is on the list. RED names each one that is
//!   not, so a new script cannot land without an entry a reviewer reads.
//! * `script-allowlist:entries-live` — every entry names a tracked file. A stale entry is RED, so a
//!   deleted or ported script cannot leave its permission behind for a namesake.
//! * `script-allowlist:reasons` — every entry has a known class and a reason of at least
//!   [`MIN_REASON`] characters, no path is listed twice, and no reason sends a script to a
//!   busbar-release home other than the parts THE DESIGN keeps there ([`KEPT_RELEASE_PARTS`]): the
//!   turnstile, the train, the ladder and the release half of its command line are retired (Part 6,
//!   l.3134-3146), so a port planned into them has nowhere to land.
//! * `script-allowlist:listing-floor` — the tracked listing holds the root `Cargo.toml`. A failed
//!   or empty `git ls-files` has no unlisted scripts in it, and "nothing to object to" must never
//!   read as "the rule holds".

use std::collections::{BTreeMap, BTreeSet};

use crate::ctx::{Change, Ctx, Overlay};
use crate::gates::{prove_green, prove_red, Gate, Report};
use crate::ledger::{Row, Verdict};
use crate::toml_doc;

pub const ROW_LISTED: &str = "script-allowlist:listed";
pub const ROW_LIVE: &str = "script-allowlist:entries-live";
pub const ROW_REASONS: &str = "script-allowlist:reasons";
pub const ROW_FLOOR: &str = "script-allowlist:listing-floor";

pub const ALLOWLIST: &str = "qa/scripts-allowlist.toml";

/// The suffixes this rule is about.
const SUFFIXES: [&str; 3] = [".py", ".sh", ".bash"];

/// The classes an entry may carry.
const CLASSES: [&str; 5] = ["port", "keep", "external", "retire", "oracle-driver"];

/// The shortest reason that is a reason rather than a shrug.
pub const MIN_REASON: usize = 30;

/// What busbar-release still is to busbar (THE DESIGN Part 6, l.3134-3142, "busbar-release stays, as
/// the tools repo"): the oracle and its fetch and golden-scope crates, the soak, the plugin fleet
/// generator and the GitHub door they call through. A reason may name these; any other
/// `busbar-release` home it names is a retired one.
pub const KEPT_RELEASE_PARTS: [&str; 7] = [
    "busbar-release-oracle",
    "busbar-release-fetch",
    "busbar-release-golden-scope",
    "busbar-release-soak",
    "busbar-release-plugin",
    "busbar-release plugin",
    "busbar-release-github",
];

/// Whether `reason` sends its script to a busbar-release home THE DESIGN retired: it names
/// `busbar-release` somewhere that is not one of [`KEPT_RELEASE_PARTS`].
pub fn names_retired_release_home(reason: &str) -> bool {
    let mut rest = reason.to_string();
    for kept in KEPT_RELEASE_PARTS {
        rest = rest.replace(kept, "");
    }
    rest.contains("busbar-release")
}

/// A file the listing must hold, or it is the listing that came back empty, not the tree.
const FLOOR_FILE: &str = "Cargo.toml";

/// The overlay command that answers the `git ls-files` listing in a self-test, one path per line.
const LISTING_KEY: &str = "git-ls-files-all";

pub struct ScriptAllowlistGate;

fn is_script(path: &str) -> bool {
    SUFFIXES.iter().any(|s| path.ends_with(s))
}

/// Every tracked path, as `git ls-files` lists it (or as the overlay's [`LISTING_KEY`] answers it),
/// with the overlay's file claims laid on top: a planted file is tracked, a removed one is not.
fn tracked(cx: &Ctx) -> Result<BTreeSet<String>, String> {
    let listing = match cx.overlay_command(LISTING_KEY) {
        Some(planted) => planted.lines().map(str::to_string).collect(),
        None => cx.git_lines(&["ls-files"])?,
    };
    let mut out: BTreeSet<String> = listing
        .into_iter()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect();
    if let Some(ov) = cx.overlay() {
        for (path, change) in ov.changes() {
            let p = path.to_string_lossy().replace('\\', "/");
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

/// One `[[script]]` entry as written.
#[derive(Debug, Clone)]
struct Entry {
    path: String,
    class: String,
    reason: String,
}

fn entries(cx: &Ctx) -> Result<Vec<Entry>, String> {
    let text = cx.read(ALLOWLIST)?;
    let doc = toml_doc::parse_str(&text).map_err(|e| format!("{ALLOWLIST}: {e}"))?;
    Ok(doc
        .array_of_tables("script")
        .into_iter()
        .map(|t| Entry {
            path: t.str_of("path").unwrap_or_default().to_string(),
            class: t.str_of("class").unwrap_or_default().to_string(),
            reason: t.str_of("reason").unwrap_or_default().to_string(),
        })
        .collect())
}

impl Gate for ScriptAllowlistGate {
    fn name(&self) -> &'static str {
        "script-allowlist"
    }

    fn owed(&self) -> Vec<String> {
        [ROW_LISTED, ROW_LIVE, ROW_REASONS, ROW_FLOOR]
            .iter()
            .map(|r| (*r).to_string())
            .collect()
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let all_rows = |title: &str, why: String| {
            Verdict::of(
                [ROW_LISTED, ROW_LIVE, ROW_REASONS, ROW_FLOOR]
                    .iter()
                    .map(|r| Row::fail(*r, title, why.clone()))
                    .collect(),
            )
        };
        let paths = match tracked(cx) {
            Ok(p) => p,
            Err(why) => return all_rows("git ls-files could not list the tree", why),
        };
        let list = match entries(cx) {
            Ok(l) => l,
            Err(why) => return all_rows("the script allowlist could not be read", why),
        };

        let floor = if paths.contains(FLOOR_FILE) {
            Row::pass(
                ROW_FLOOR,
                "the tracked listing holds the root Cargo.toml",
                format!("{} tracked path(s)", paths.len()),
            )
        } else {
            Row::fail(
                ROW_FLOOR,
                "the tracked listing does not hold the root Cargo.toml, so it proves nothing",
                format!(
                    "{FLOOR_FILE} is not in a listing of {} path(s): an empty or failed listing has \
                     no unlisted scripts in it, which is not the same fact as a clean tree",
                    paths.len()
                ),
            )
        };

        let listed: BTreeSet<&str> = list.iter().map(|e| e.path.as_str()).collect();
        let unlisted: Vec<&str> = paths
            .iter()
            .map(String::as_str)
            .filter(|p| is_script(p) && !listed.contains(p))
            .collect();
        let scripts = paths.iter().filter(|p| is_script(p)).count();
        let listed_row = if unlisted.is_empty() {
            Row::pass(
                ROW_LISTED,
                "every tracked script is on the allowlist",
                format!("{scripts} tracked script(s), {} entr(ies)", list.len()),
            )
        } else {
            Row::fail(
                ROW_LISTED,
                "a tracked script is not on the allowlist",
                format!(
                    "{} unlisted: {} — product checks and gates are `cargo xtask` (OWNER \
                     2026-10-02), release steps are checks of `.ci/dev.yaml` and `.ci/qa.yaml` \
                     (THE DESIGN Part 6). A script that must stay needs an entry in {ALLOWLIST} \
                     with its class and reason.",
                    unlisted.len(),
                    unlisted.join(" | ")
                ),
            )
        };

        let stale: Vec<&str> = list
            .iter()
            .map(|e| e.path.as_str())
            .filter(|p| !paths.contains(*p))
            .collect();
        let live_row = if stale.is_empty() {
            Row::pass(
                ROW_LIVE,
                "every allowlist entry names a tracked file",
                format!("{} entr(ies)", list.len()),
            )
        } else {
            Row::fail(
                ROW_LIVE,
                "an allowlist entry names a file that is not tracked",
                format!(
                    "{} stale: {} — strike the entry in the commit that ports or deletes the file, \
                     so its permission does not outlive it",
                    stale.len(),
                    stale.join(" | ")
                ),
            )
        };

        let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
        for e in &list {
            *seen.entry(e.path.as_str()).or_default() += 1;
        }
        let mut bad: Vec<String> = seen
            .iter()
            .filter(|(_, n)| **n > 1)
            .map(|(p, n)| format!("{p}: listed {n} times"))
            .collect();
        for e in &list {
            if e.path.is_empty() {
                bad.push("an entry with no path".to_string());
                continue;
            }
            if !is_script(&e.path) {
                bad.push(format!("{}: not a .py, .sh or .bash path", e.path));
            }
            if !CLASSES.contains(&e.class.as_str()) {
                bad.push(format!(
                    "{}: class `{}` is not one of {}",
                    e.path,
                    e.class,
                    CLASSES.join(", ")
                ));
            }
            if e.reason.trim().chars().count() < MIN_REASON {
                bad.push(format!(
                    "{}: reason `{}` is under {MIN_REASON} characters",
                    e.path,
                    e.reason.trim()
                ));
            }
            if names_retired_release_home(&e.reason) {
                bad.push(format!(
                    "{}: reason `{}` sends it to a retired busbar-release home; busbar-release keeps \
                     only {} (THE DESIGN Part 6), and a release step is a check of .ci/dev.yaml or \
                     .ci/qa.yaml",
                    e.path,
                    e.reason.trim(),
                    KEPT_RELEASE_PARTS.join(", ")
                ));
            }
        }
        let reasons_row = if bad.is_empty() {
            Row::pass(
                ROW_REASONS,
                "every entry has a known class and a reason",
                format!(
                    "{} entr(ies), classes {}",
                    list.len(),
                    CLASSES
                        .iter()
                        .map(|c| format!("{c} {}", list.iter().filter(|e| e.class == *c).count()))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            )
        } else {
            Row::fail(
                ROW_REASONS,
                "an allowlist entry has no class, an unknown class, a short reason, a retired \
                 busbar-release home or a duplicate",
                format!("{} problem(s): {}", bad.len(), bad.join(" | ")),
            )
        };

        Verdict::of(vec![listed_row, live_row, reasons_row, floor])
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();

        // THE BASELINE: a listing holding the root Cargo.toml, one script planted as a tracked file,
        // and an allowlist naming that one script. Planted over a fixed base rather than the real tree, so
        // each red below is the plant's and none is a standing one.
        let ok_entry = "[[script]]\npath = \"scripts/kept.sh\"\nclass = \"keep\"\n\
                        reason = \"a five-line runner entrypoint where Rust is worse\"\n";
        let mut base_ov = Overlay::new();
        base_ov.set_command(LISTING_KEY, format!("{FLOOR_FILE}\nREADME.md"));
        base_ov.set("scripts/kept.sh", "#!/bin/sh\nexec busbar \"$@\"\n");
        base_ov.set(ALLOWLIST, ok_entry);
        let base_cx = cx.with_overlay(base_ov.clone());
        let base = &base_cx;
        let on_base = |ov: Overlay| base_ov.layered(&ov);

        report.push(prove_green(
            base,
            self,
            "a tree whose every script is listed with a class and a reason is green",
            &[ROW_LISTED, ROW_LIVE, ROW_REASONS, ROW_FLOOR],
        ));

        let mut ov = Overlay::new();
        ov.set("scripts/new-gate.py", "print('a new python gate')\n");
        ov.set("testing/new-rig.sh", "#!/bin/sh\n");
        report.push(prove_red(
            base,
            self,
            "a new .py or .sh the allowlist does not name is RED, by name",
            &[ROW_LISTED],
            on_base(ov),
            &["scripts/new-gate.py", "testing/new-rig.sh"],
        ));

        let mut ov = Overlay::new();
        ov.set("scripts/x.bash", "echo\n");
        report.push(prove_red(
            base,
            self,
            "a .bash file is a script too",
            &[ROW_LISTED],
            on_base(ov),
            &["scripts/x.bash"],
        ));

        let mut ov = Overlay::new();
        ov.remove("scripts/kept.sh");
        report.push(prove_red(
            base,
            self,
            "an entry whose file was deleted or ported is RED until it is struck",
            &[ROW_LIVE],
            on_base(ov),
            &["scripts/kept.sh"],
        ));

        let mut ov = Overlay::new();
        ov.set(
            ALLOWLIST,
            format!(
                "{ok_entry}\n[[script]]\npath = \"scripts/kept.sh\"\nclass = \"keep\"\nreason = \"a five-line runner entrypoint where Rust is worse\"\n"
            ),
        );
        report.push(prove_red(
            base,
            self,
            "a path listed twice is RED",
            &[ROW_REASONS],
            on_base(ov),
            &["listed 2 times"],
        ));

        let mut ov = Overlay::new();
        ov.set(
            ALLOWLIST,
            "[[script]]\npath = \"scripts/kept.sh\"\nclass = \"later\"\nreason = \"x\"\n",
        );
        report.push(prove_red(
            base,
            self,
            "an unknown class and a reason that is not one are RED",
            &[ROW_REASONS],
            on_base(ov),
            &["class `later`", "under 30 characters"],
        ));

        let mut ov = Overlay::new();
        ov.set(
            ALLOWLIST,
            "[[script]]\npath = \"scripts/kept.sh\"\nclass = \"port\"\n\
             reason = \"post-publish channel checks: become a busbar-release subcommand\"\n",
        );
        report.push(prove_red(
            base,
            self,
            "a reason that ports a script into a retired busbar-release home is RED (row 163)",
            &[ROW_REASONS],
            on_base(ov),
            &["retired busbar-release home"],
        ));

        let mut ov = Overlay::new();
        ov.set(
            ALLOWLIST,
            "[[script]]\npath = \"scripts/kept.sh\"\nclass = \"oracle-driver\"\n\
             reason = \"an oracle cell driver: moves into busbar-release-oracle with a re-stamp\"\n",
        );
        let kept_cx = cx.with_overlay(on_base(ov));
        report.push(prove_green(
            &kept_cx,
            self,
            "a reason that names a part busbar-release keeps (the oracle) is green",
            &[ROW_REASONS],
        ));

        let mut ov = Overlay::new();
        ov.set_command(LISTING_KEY, "");
        report.push(prove_red(
            base,
            self,
            "an empty listing proves nothing and is RED",
            &[ROW_FLOOR],
            on_base(ov),
            &[FLOOR_FILE],
        ));

        report
    }
}

#[cfg(test)]
mod tests {
    use super::{is_script, names_retired_release_home};

    #[test]
    fn the_suffixes_are_exact() {
        for p in ["a.py", "scripts/b.sh", "c/d.bash"] {
            assert!(is_script(p), "{p}");
        }
        for p in ["a.pyc", "b.shtml", "c.rs", "d.mjs", "sh", "e.py.txt"] {
            assert!(!is_script(p), "{p}");
        }
    }

    #[test]
    fn a_reason_names_a_retired_release_home_only_outside_the_kept_parts() {
        // RED: the homes Part 6 retired.
        for r in [
            "post-publish channel checks: become a busbar-release subcommand",
            "becomes the ladder's release-binaries build in busbar-release",
            "the done verifier (busbar-release status reads its groups)",
            "moves into busbar-release-oracle and busbar-release ci",
        ] {
            assert!(names_retired_release_home(r), "{r}");
        }
        // GREEN: the parts busbar-release keeps, and a reason that names none.
        for r in [
            "moves into busbar-release-oracle, identical verdicts proven first",
            "folds into busbar-release plugin (the registry tool)",
            "becomes the release-binaries check of the dev -> qa move in .ci/dev.yaml",
        ] {
            assert!(!names_retired_release_home(r), "{r}");
        }
    }
}
