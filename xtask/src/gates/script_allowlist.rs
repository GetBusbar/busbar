//! `cargo xtask gate script-allowlist` — NO NEW PYTHON OR SHELL WITHOUT A WRITTEN REASON.
//!
//! OWNER 2026-10-02: "drop as much python ... as possible to rust" and "minimal to no .sh". A
//! product check or gate is `cargo xtask`; release tooling is busbar-release. Every `.py`, `.sh` and
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
//!   [`MIN_REASON`] characters, and no path is listed twice.
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
                    "{} unlisted: {} — product checks and gates are `cargo xtask`, release tooling \
                     is busbar-release (OWNER 2026-10-02). A script that must stay needs an entry in \
                     {ALLOWLIST} with its class and reason.",
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
                "an allowlist entry has no class, an unknown class, a short reason or a duplicate",
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
    use super::is_script;

    #[test]
    fn the_suffixes_are_exact() {
        for p in ["a.py", "scripts/b.sh", "c/d.bash"] {
            assert!(is_script(p), "{p}");
        }
        for p in ["a.pyc", "b.shtml", "c.rs", "d.mjs", "sh", "e.py.txt"] {
            assert!(!is_script(p), "{p}");
        }
    }
}
