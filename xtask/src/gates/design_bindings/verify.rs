//! EXISTENCE VERIFICATION: does anything a binding cites actually COMPARE something today?
//!
//! Nothing here executes a test. What it settles is the question a citation list cannot answer by
//! itself — and the four ways a citation can look green while proving nothing, each of which this
//! ledger was caught doing before the check existed:
//!
//! * a `test` ref naming a fn that was renamed away, or a BARE name two files both declare (delete
//!   the one the curation read and the citation stays green on its namesake);
//! * an `oracle-cell` the pinned golden never RECORDED — roughly a third of `cells.json` is surface
//!   the 1.5.5 binary never served, and those carry SKIP rows for ever;
//! * a `gate` or `lint` that exists on disk and that NOTHING INVOKES. Existence is not a
//!   comparison: a gate nobody runs has the evidentiary value of a gate nobody wrote;
//! * a binding whose OWN NOTE says the surface does not exist in `crates/`, carried as `mapped`
//!   because some other subsystem's test fn happened to match the ref by name.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::gates::design_bindings::build::family_of;
use crate::gates::design_bindings::json::J;
use crate::gates::design_bindings::tables;
use crate::rx::Regex;

const RUNNABLE_SUFFIXES: [&str; 6] = [".sh", ".py", ".mjs", ".js", ".ts", ".rb"];
const SEGMENT_RUNNER: &str = "scripts/qa-gate-run.sh";
pub const XTASK_GATE_DIR: &str = "xtask/src/gates";

/// THE LEDGER IS NEVER AN INVOKER OF ITSELF. The derivation names every gate the ledger cites, so
/// following it would let the ledger vouch for its own citations: every ref would read as "invoked"
/// because the ledger mentions it. A check whose evidence is its own claim has checked nothing.
///
/// The Python that carried the first entry of this list is gone with this commit, so the list is
/// one name: this gate's own module tree. The rule is about the ROLE, not the file, and the same
/// trap is one edit away from reopening. The Rust successor is safe by a second construction as
/// well: `.rs` is deliberately not a runnable suffix, so no module is ever opened looking for
/// further invocations.
const NOT_AN_INVOKER: [&str; 1] = ["xtask/src/gates/design_bindings"];

/// The module path a `cargo xtask gate <name>` invocation runs. Mechanical spellings, derived from
/// the gate name rather than maintained beside it, so a gate cannot be cited under a name the
/// runner does not answer to.
///
/// A GATE THAT GREW INTO A DIRECTORY IS STILL THAT GATE. Rust spells one module two ways, and the
/// bigger converted gates use the second: `config-schema` lives in `gates/config_schema/mod.rs`,
/// not `gates/config_schema.rs`, because its generator, classifier and scrape are three files. With
/// only the flat spelling resolvable, a binding citing a directory gate read as "the ref vanished"
/// — reddening the binding for a reason entirely about how the gate's source is laid out, which is
/// the same failure the citation rule exists to prevent, one refactor later.
///
/// The directory form is used ONLY when the flat file is absent, so nothing that resolves today
/// moves, and both spellings are still derived from the gate name alone.
pub fn xtask_gate_module(name: &str, root: &Path) -> String {
    let flat = format!("{XTASK_GATE_DIR}/{}.rs", name.replace('-', "_"));
    if !root.join(&flat).is_file() {
        let nested = format!("{XTASK_GATE_DIR}/{}/mod.rs", name.replace('-', "_"));
        if root.join(&nested).is_file() {
            return nested;
        }
    }
    flat
}

pub struct Ctx {
    /// test fn name -> the files that declare it under a test attribute, relative to the root.
    pub idx: BTreeMap<String, BTreeSet<String>>,
    pub cell_ids: BTreeSet<String>,
    pub recorded: BTreeSet<String>,
    pub fam_cells: BTreeMap<String, Vec<String>>,
    pub families: BTreeMap<String, usize>,
    pub root: PathBuf,
    pub ci: BTreeSet<String>,
    /// Overridable so a self-test can plant a note table without touching the shipped one.
    pub unproven_by_note: Vec<(String, String)>,
    pub notes: Vec<(String, String)>,
}

impl Ctx {
    pub fn build(cells_doc: &J, crates: &Path, root: &Path, ledger: &Path) -> Result<Ctx, String> {
        let empty: Vec<J> = Vec::new();
        let cells = cells_doc
            .get("cells")
            .and_then(J::as_array)
            .unwrap_or(&empty);
        let mut fam_cells: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut families: BTreeMap<String, usize> = BTreeMap::new();
        for c in cells {
            let fam = family_of(c);
            fam_cells
                .entry(fam.clone())
                .or_default()
                .push(c.str_of("id").unwrap_or("").to_string());
            *families.entry(fam).or_default() += 1;
        }
        Ok(Ctx {
            idx: if crates.exists() {
                test_index(crates, root)?
            } else {
                BTreeMap::new()
            },
            cell_ids: cells
                .iter()
                .map(|c| c.str_of("id").unwrap_or("").to_string())
                .collect(),
            recorded: golden_recorded(ledger),
            fam_cells,
            families,
            root: root.to_path_buf(),
            ci: ci_invoked_refs(root)?,
            unproven_by_note: tables::UNPROVEN_BY_NOTE
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            notes: tables::NOTES
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
        })
    }

    fn note_reason(&self, pb: &str) -> Option<&str> {
        self.unproven_by_note
            .iter()
            .find(|(k, _)| k == pb)
            .map(|(_, v)| v.as_str())
    }

    fn note(&self, pb: &str) -> Option<&str> {
        self.notes
            .iter()
            .find(|(k, _)| k == pb)
            .map(|(_, v)| v.as_str())
    }
}

/// fn name -> the files declaring it under a test attribute. The attribute may sit a few lines
/// above the `fn`, so the arming counter walks down through further attribute and blank lines and
/// gives up on anything else.
pub fn test_index(
    crates: &Path,
    root: &Path,
) -> Result<BTreeMap<String, BTreeSet<String>>, String> {
    let attr = Regex::new(r"^\s*#\[\s*(tokio::test|test|async_std::test|rstest|test_case)")?;
    let func = Regex::new(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z0-9_]+)")?;
    let mut idx: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut files = Vec::new();
    collect_rs(crates, &mut files);
    files.sort();
    for f in files {
        let rel = f
            .strip_prefix(root)
            .unwrap_or(&f)
            .to_string_lossy()
            .replace('\\', "/");
        if rel.contains("/target/") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&f) else {
            continue;
        };
        let mut armed = 0i32;
        for l in text.split('\n') {
            if attr.match_at(l.as_bytes(), 0).is_some() {
                armed = 8;
                continue;
            }
            if armed > 0 {
                if let Some(m) = func.match_at(l.as_bytes(), 0) {
                    if let Some(name) = m.str_of(l.as_bytes(), 1) {
                        idx.entry(name).or_default().insert(rel.clone());
                    }
                    armed = 0;
                } else if l.trim().starts_with("#[") || l.trim().is_empty() {
                    armed -= 1;
                } else {
                    armed = 0;
                }
            }
        }
    }
    Ok(idx)
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.filter_map(Result::ok) {
        let p = e.path();
        if p.is_dir() {
            collect_rs(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// The cell ids the pinned golden actually recorded a comparable answer for (status PASS). An
/// absent ledger yields an empty set, which is honest: nothing is proven.
pub fn golden_recorded(ledger: &Path) -> BTreeSet<String> {
    let Ok(text) = std::fs::read_to_string(ledger) else {
        return BTreeSet::new();
    };
    text.split('\n')
        .filter_map(|line| {
            let parts: Vec<&str> = line.split('\t').collect();
            (parts.len() >= 2 && parts[1] == "PASS").then(|| parts[0].to_string())
        })
        .collect()
}

/// A file's content with the lines that cannot run anything removed — comments and step `name:`
/// labels, stripped exactly as `scripts/full-gate.sh`'s own discovery strips them, because a script
/// named in a comment or in a step's human-readable title is being TALKED ABOUT, not run.
fn runnable_text(path: &Path) -> String {
    let Ok(text) = std::fs::read_to_string(path) else {
        return String::new();
    };
    strip_unrunnable(&text)
}

fn strip_unrunnable(text: &str) -> String {
    text.split('\n')
        .map(|l| {
            let t = l.trim_start_matches([' ', '\t']);
            if t.starts_with('#') {
                return "";
            }
            let t2 = t
                .strip_prefix('-')
                .unwrap_or(t)
                .trim_start_matches([' ', '\t']);
            if t2.starts_with("name:") {
                return "";
            }
            l
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Every script-shaped path CI actually invokes, closed TRANSITIVELY: a gate a workflow reaches
/// through a script the workflow runs is run by CI just as surely as one named in the workflow
/// itself. A gate MODULE is admitted only because an INVOCATION of it was seen, never because the
/// path was mentioned — which is why the two sets are built separately and unioned at the end
/// rather than `.rs` joining the runnable suffixes.
pub fn ci_invoked_refs(root: &Path) -> Result<BTreeSet<String>, String> {
    let path_token =
        Regex::new(r"(?:scripts|testing|qa|xtask)/(?:[A-Za-z0-9._+-]+/)*[A-Za-z0-9._+-]+")?;
    let gate_call = Regex::new(r"cargo[ \t]+xtask[ \t]+gate[ \t]+([a-z0-9][a-z0-9-]*)")?;
    let mut gate_modules: BTreeSet<String> = BTreeSet::new();

    let refs_in = |text: &str, gate_modules: &mut BTreeSet<String>| -> BTreeSet<String> {
        for m in gate_call.find_iter(text.as_bytes()) {
            if let Some(n) = m.str_of(text.as_bytes(), 1) {
                gate_modules.insert(xtask_gate_module(&n, root));
            }
        }
        path_token
            .find_iter(text.as_bytes())
            .iter()
            .filter_map(|m| m.str_of(text.as_bytes(), 0))
            .collect()
    };

    let wf_dir = root.join(".github").join("workflows");
    let mut workflow_files: Vec<PathBuf> = std::fs::read_dir(&wf_dir)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".yml") || n.ends_with(".yaml"))
        })
        .collect();
    workflow_files.sort();
    let workflows = workflow_files
        .iter()
        .map(|p| runnable_text(p))
        .collect::<Vec<_>>()
        .join("\n");

    let mut invoked = refs_in(&workflows, &mut gate_modules);
    let segments = root.join("qa").join("segments.toml");
    // The qa manifest is admitted ONLY when a workflow is seen driving its runner, so it cannot
    // vouch for itself.
    if invoked.contains(SEGMENT_RUNNER) && segments.is_file() {
        let text = runnable_text(&segments);
        invoked.extend(refs_in(&text, &mut gate_modules));
    }

    let mut frontier: BTreeSet<String> = invoked.clone();
    while !frontier.is_empty() {
        let mut next: BTreeSet<String> = BTreeSet::new();
        for r in &frontier {
            if NOT_AN_INVOKER.iter().any(|n| r.starts_with(n)) {
                continue;
            }
            let p = root.join(r);
            if p.is_file() && RUNNABLE_SUFFIXES.iter().any(|s| r.ends_with(s)) {
                let text = runnable_text(&p);
                next.extend(refs_in(&text, &mut gate_modules));
            }
        }
        frontier = next.difference(&invoked).cloned().collect();
        invoked.extend(frontier.iter().cloned());
    }

    // A path that is not executable is not invoked by anyone, however often it is named. A data
    // file READ by a script CI runs is an INPUT to a gate, not a gate.
    let mut out: BTreeSet<String> = invoked
        .into_iter()
        .filter(|r| RUNNABLE_SUFFIXES.iter().any(|s| r.ends_with(s)))
        .collect();
    out.extend(gate_modules);
    Ok(out)
}

/// Does this one check COMPARE anything today? The reason is written for the ledger's detail
/// column, so it names the ref and says why it settles nothing.
pub fn check_verdict(c: &J, ctx: &Ctx) -> (bool, String) {
    let k = c.str_of("kind").unwrap_or("?");
    let r = c.str_of("ref").unwrap_or("");
    if r.is_empty() {
        return (
            false,
            format!("{k}: no ref -- a check with nothing to compare against"),
        );
    }
    match k {
        "test" => {
            if let Some((path, name)) = r.rsplit_once("::") {
                if ctx.idx.get(name).is_some_and(|f| f.contains(path)) {
                    return (true, String::new());
                }
                return (
                    false,
                    format!("test:{r} (no test fn by that name is declared in that file)"),
                );
            }
            let files = ctx.idx.get(r);
            match files {
                None => (false, format!("test:{r}")),
                Some(f) if f.len() > 1 => (
                    false,
                    format!(
                        "test:{r} (declared under a test attribute in {} files -- {} -- so the ref \
                         names no particular test; cite it as path.rs::name)",
                        f.len(),
                        f.iter().cloned().collect::<Vec<_>>().join(", ")
                    ),
                ),
                Some(_) => (true, String::new()),
            }
        }
        "oracle-cell" => {
            if !ctx.cell_ids.contains(r) {
                return (false, format!("oracle-cell:{r}"));
            }
            if !ctx.recorded.contains(r) {
                return (
                    false,
                    format!("oracle-cell:{r} (in cells.json, but the golden never recorded it)"),
                );
            }
            (true, String::new())
        }
        "oracle-family" => {
            if ctx
                .fam_cells
                .get(r)
                .is_some_and(|ids| ids.iter().any(|i| ctx.recorded.contains(i)))
            {
                return (true, String::new());
            }
            if ctx.families.get(r).copied().unwrap_or(0) > 0 {
                return (
                    false,
                    format!(
                        "oracle-family:{r} (cells exist, but the golden recorded none of them)"
                    ),
                );
            }
            (false, format!("oracle-family:{r}"))
        }
        "lint" | "gate" | "script" | "conformance" => {
            if !ctx.root.join(r).exists() {
                return (false, format!("{k}:{r}"));
            }
            if !ctx.ci.contains(r) {
                return (
                    false,
                    format!(
                        "{k}:{r} (exists on disk, but nothing under .github/workflows invokes it, \
                         directly or through the qa segment manifest -- a gate nobody runs \
                         compares nothing)"
                    ),
                );
            }
            (true, String::new())
        }
        _ => (false, format!("{k}:{r} (unknown check kind)")),
    }
}

/// One binding's `(status, verdict, detail)`.
///
/// THE RULE THIS WHOLE FILE EXISTS FOR: a binding is only `mapped` when something it cites actually
/// compared something. A binding every one of whose checks is a golden SKIP, a vanished ref or a
/// ref that asserts nothing is `unproven`; `unmapped` stays the word for a NAMED gap.
pub fn binding_verdict(b: &J, ctx: &Ctx) -> (String, String, String) {
    let pb = b.str_of("id").unwrap_or("?");
    let empty: Vec<J> = Vec::new();
    let mapped: Vec<&J> = b
        .get("checks")
        .and_then(J::as_array)
        .unwrap_or(&empty)
        .iter()
        // AN EMPTY REF IS A BROKEN CITATION, NOT AN ABSENT ONE. This filter used to drop the
        // empty-ref checks as well, which sent a binding whose only citation claims `mapped` and
        // names nothing down the `unmapped` path -- a NAMED gap, SKIP, allowed. It is not a gap:
        // somebody wrote the citation down and left the ref blank. Dropping it here also made
        // `check_verdict`'s own empty-ref arm unreachable, so the refusal existed, read well, and
        // could never fire. The status test is the whole filter now and the ref is judged where
        // every other ref is judged.
        .filter(|c| c.str_of("status") == Some("mapped"))
        .collect();
    if mapped.is_empty() {
        let sug = b
            .str_of("suggestion")
            .filter(|s| !s.is_empty())
            .unwrap_or("no check proves this binding yet");
        return ("unmapped".into(), "SKIP".into(), format!("unmapped: {sug}"));
    }
    if let Some(reason) = ctx.note_reason(pb) {
        return (
            "unproven".into(),
            "FAIL".into(),
            format!(
                "UNPROVEN, by the ledger's own note: {}",
                ctx.note(pb).unwrap_or(reason)
            ),
        );
    }
    let (mut proving, mut broken) = (Vec::new(), Vec::new());
    for c in &mapped {
        let (ok, why) = check_verdict(c, ctx);
        if ok {
            proving.push(*c);
        } else {
            broken.push(why);
        }
    }
    if proving.is_empty() {
        return (
            "unproven".into(),
            "FAIL".into(),
            format!(
                "UNPROVEN: nothing this binding cites compares anything today -- {}",
                broken.join(", ")
            ),
        );
    }
    if !broken.is_empty() {
        return (
            "unproven".into(),
            "FAIL".into(),
            format!(
                "partly proven; a referenced check settles nothing: {}",
                broken.join(", ")
            ),
        );
    }
    (
        "mapped".into(),
        "PASS".into(),
        proving
            .iter()
            .map(|c| {
                format!(
                    "{}:{}",
                    c.str_of("kind").unwrap_or("?"),
                    c.str_of("ref").unwrap_or("")
                )
            })
            .collect::<Vec<_>>()
            .join(", "),
    )
}

/// Stamp every binding with the verdict its checks actually earn.
pub fn classify(bindings: &mut [J], ctx: &Ctx) {
    for b in bindings.iter_mut() {
        let (status, verdict, detail) = binding_verdict(b, ctx);
        b.set("status", J::Str(status));
        b.set("verdict", J::Str(verdict));
        b.set("verdict_detail", J::Str(detail));
    }
}

/// One row per binding: `(id, PASS|FAIL|SKIP, title, detail)`. Existence only; nothing is executed.
pub fn verify_rows(doc: &J, ctx: &Ctx) -> Vec<(String, String, String, String)> {
    let empty: Vec<J> = Vec::new();
    doc.get("bindings")
        .and_then(J::as_array)
        .unwrap_or(&empty)
        .iter()
        .map(|b| {
            let id = b.str_of("id").unwrap_or("").to_string();
            let full = format!("{id} {}", b.str_of("surface").unwrap_or(""));
            // `[:70]` in Python is 70 CHARACTERS, and several surfaces carry `—`.
            let title: String = full.chars().take(70).collect();
            let (_status, verdict, detail) = binding_verdict(b, ctx);
            (id, verdict, title, detail)
        })
        .collect()
}
