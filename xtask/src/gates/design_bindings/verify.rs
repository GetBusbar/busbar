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
    /// Every `fn` name and `.rs` stem under `crates/` and `xtask/` — the set a NOTE's named
    /// witness must resolve into. See [`symbol_index`].
    pub symbols: BTreeSet<String>,
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
            symbols: if crates.exists() {
                symbol_index(crates, &root.join("xtask"))
            } else {
                BTreeSet::new()
            },
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

/// fn name -> the files declaring it under a test attribute that RUNS: not `#[ignore]`d (a test
/// the runner skips compares nothing) and in a file the crate compiles (see [`module_is_declared`]).
/// The attribute may sit a few lines above the `fn`, so the arming counter walks down through
/// further attribute and blank lines and gives up on anything else.
pub fn test_index(
    crates: &Path,
    root: &Path,
) -> Result<BTreeMap<String, BTreeSet<String>>, String> {
    let mut idx: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut files = Vec::new();
    collect_rs(crates, &mut files);
    files.sort();
    let mut declared: BTreeMap<PathBuf, BTreeSet<String>> = BTreeMap::new();
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
        let names = running_tests(&text)?;
        if names.is_empty() || !module_is_declared(&f, &mut declared) {
            continue;
        }
        for name in names {
            idx.entry(name).or_default().insert(rel.clone());
        }
    }
    Ok(idx)
}

/// The fns of one source text that carry a test attribute and are not `#[ignore]`d.
pub fn running_tests(text: &str) -> Result<Vec<String>, String> {
    let attr = Regex::new(r"^\s*#\[\s*(tokio::test|test|async_std::test|rstest|test_case)")?;
    let func = Regex::new(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z0-9_]+)")?;
    let mut out = Vec::new();
    let (mut armed, mut is_test, mut ignored) = (0i32, false, false);
    for l in text.split('\n') {
        let t = l.trim();
        // `#[ignore]` / `#[ignore = "why"]` / `#[cfg_attr(..., ignore)]` before or after the test
        // attribute: the runner lists the test and skips it.
        let ignores = t.starts_with("#[ignore")
            || (t.starts_with("#[cfg_attr(")
                && t.trim_end_matches(']')
                    .trim_end_matches(')')
                    .ends_with("ignore"));
        if attr.match_at(l.as_bytes(), 0).is_some() {
            if armed == 0 {
                ignored = false;
            }
            armed = 8;
            is_test = true;
            ignored |= ignores;
            continue;
        }
        if ignores {
            if armed == 0 {
                (armed, is_test, ignored) = (8, false, false);
            }
            ignored = true;
            continue;
        }
        if armed > 0 {
            if let Some(m) = func.match_at(l.as_bytes(), 0) {
                if let Some(name) = m.str_of(l.as_bytes(), 1) {
                    if is_test && !ignored {
                        out.push(name);
                    }
                }
                armed = 0;
            } else if t.starts_with("#[") || t.is_empty() {
                armed -= 1;
            } else {
                armed = 0;
            }
            if armed == 0 {
                (is_test, ignored) = (false, false);
            }
        }
    }
    Ok(out)
}

/// Does the crate COMPILE this file? A file under a crate's `src/` is part of the build only when
/// some `mod <stem>;` (or a `#[path = "…/<stem>.rs"]`) names it somewhere in that crate; a test
/// written in a file nothing declares never runs. Crate roots, `src/bin/*` and anything outside
/// `src/` (integration tests, examples, benches are targets of their own) are compiled by cargo's
/// own discovery.
fn module_is_declared(file: &Path, cache: &mut BTreeMap<PathBuf, BTreeSet<String>>) -> bool {
    let comps: Vec<String> = file
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    let Some(src) = comps.iter().rposition(|c| c == "src") else {
        return true;
    };
    let stem = file.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    if src + 2 == comps.len() && (stem == "lib" || stem == "main")
        || comps.get(src + 1).is_some_and(|c| c == "bin")
    {
        return true;
    }
    let mut crate_dir = PathBuf::new();
    for c in &comps[..src] {
        crate_dir.push(c);
    }
    let names = cache.entry(crate_dir.clone()).or_insert_with(|| {
        let mut all = Vec::new();
        collect_rs(&crate_dir, &mut all);
        let mut names = BTreeSet::new();
        for f in all {
            let Ok(text) = std::fs::read_to_string(&f) else {
                continue;
            };
            for line in text.split('\n') {
                let t = line.trim_start();
                if let Some(rest) = t.strip_prefix("#[path") {
                    if let Some(q) = rest.split('"').nth(1) {
                        if let Some(n) = Path::new(q).file_stem().and_then(|s| s.to_str()) {
                            names.insert(n.to_string());
                        }
                    }
                }
                let t = t.strip_prefix("pub").map_or(t, |r| {
                    let r = r.trim_start();
                    if r.starts_with('(') {
                        r.split_once(')').map_or(r, |(_, a)| a.trim_start())
                    } else {
                        r
                    }
                });
                if let Some(rest) = t.strip_prefix("mod ") {
                    let name: String = rest
                        .trim_start()
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .collect();
                    if rest.trim_start()[name.len()..]
                        .trim_start()
                        .starts_with(';')
                    {
                        names.insert(name);
                    }
                }
            }
        }
        names
    });
    let wanted = if stem == "mod" {
        comps
            .get(comps.len().wrapping_sub(2))
            .map(String::as_str)
            .unwrap_or("")
    } else {
        stem
    };
    names.contains(wanted)
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
/// labels, because a script
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

    // THE PIPELINE RUNS EVERY REGISTERED GATE. ModernCI's `gates` check runs `cargo xtask gate
    // --all` on every move (`.ci/*.yaml`), so no workflow in this tree names them one by one. The
    // registry IS that list, so a gate module is invoked exactly when it is registered; a module
    // that is not registered is run by nothing and is still refused.
    for name in crate::gates::names() {
        gate_modules.insert(xtask_gate_module(name, root));
    }

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
                         directly or through a script one runs, and it is no registered \
                         gate the pipeline runs -- a gate nobody runs compares nothing)"
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

// ─── THE NOTE-WITNESS RULE ──────────────────────────────────────────────────────────────────────
//
// A NOTE IS EVIDENCE OR IT IS NOTHING, AND UNTIL NOW IT WAS NEITHER — IT WAS PROSE.
//
// `SEED` refs are verified: `check_verdict`'s `"test"` arm already refuses a ref naming a fn that
// was renamed away. `NOTES` are not. A note is the table that ADJUDICATES a binding — it is where
// "Resolved <date>" is written and where the reason a binding counts as proven is argued — and it
// carries test-function names in running prose, where no checker has ever looked.
//
// PB-58 is the instance that exposed the class. Its note closes:
//
//     "the behavioural half is where the behaviour is: admit.rs's
//      over_budget_refuses_with_no_charge_and_nothing_to_refund and meter.rs's
//      a_spend_past_the_reservation_is_carried_out_as_an_overdraft."
//
// The first resolves. The second is a `fn` in NO file in the tree, and has not been for as long as
// anyone has looked — the binding reads "Resolved" on the strength of a witness that does not
// exist. Nothing was lying; the citation simply rotted, silently, because the only thing joining
// the spelling to a real symbol was a human having once read it.
//
// THE RULE, AND WHY IT IS DRAWN HERE. A token in a note is owed a referent when it is shaped
// unmistakably like a Rust test name: lowercase, snake_case, FOUR OR MORE WORDS. It discharges by
// resolving to a `fn` declared anywhere in `crates/` or `xtask/`, or to a `.rs` file stem — notes
// legitimately name both, and a note pointing at `no_data_dir_neutrality.rs` is pointing at
// something a reader can open, which is the whole test.
//
// THE THRESHOLD IS MEASURED, NOT CHOSEN. Over the shipped table: at three-or-more words the scan
// flags `rejected_by_auth` (a synthetic outcome string), `idle_bound_applies` and
// `max_unit_duration` (a config key) — three false positives, because three-word snake_case is the
// house style for config keys and enum payloads. At four-or-more it flags ONE token, and that
// token is the real defect. The rule is deliberately silent about anything shorter: a gate that
// cries about config keys is a gate somebody switches off.
//
// FAILING CLOSED IS THE POINT. This cannot be satisfied by renaming the note. It is satisfied by
// the symbol existing, or by the note not claiming it.

/// Every `fn` name declared under `crates/` and `xtask/`, plus every `.rs` file stem — the set a
/// note's named witness may resolve into.
///
/// TEST-ONLY WOULD BE THE WRONG SET. [`test_index`] indexes fns carrying a test attribute, which is
/// right for a `SEED` ref that claims "this test proves it". A note is looser in what it may name —
/// a helper, a production fn, a file — and the defect being caught is a name that resolves to
/// NOTHING. Narrowing the haystack here would turn every prose mention of a production fn into a
/// failure, which is how a true rule acquires a waiver.
pub fn symbol_index(crates: &Path, xtask: &Path) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut files = Vec::new();
    collect_rs(crates, &mut files);
    collect_rs(xtask, &mut files);
    for f in files {
        if f.to_string_lossy().contains("/target/") {
            continue;
        }
        if let Some(stem) = f.file_stem().and_then(|s| s.to_str()) {
            out.insert(stem.to_string());
        }
        let Ok(text) = std::fs::read_to_string(&f) else {
            continue;
        };
        for (i, _) in text.match_indices("fn ") {
            // `fn` must be its own token: the preceding byte cannot continue an identifier, which
            // is what keeps `fn` inside a longer word from opening a declaration that is not one.
            if i > 0 {
                let p = text.as_bytes()[i - 1];
                if p.is_ascii_alphanumeric() || p == b'_' {
                    continue;
                }
            }
            let rest = &text[i + 3..];
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                out.insert(name);
            }
        }
    }
    out
}

/// Whether a token in a note is shaped unmistakably like a Rust test-function name, and therefore
/// owes a referent. Lowercase snake_case, four or more words, no edge underscore.
///
/// Hand-scanned rather than matched: the shape is three cheap predicates, and a regex here would
/// bet the rule on `{n,}` and `\b` support in the in-tree engine for no gain in clarity.
fn is_witness_shaped(tok: &str) -> bool {
    if tok.len() < 8 || tok.starts_with('_') || tok.ends_with('_') {
        return false;
    }
    if !tok.starts_with(|c: char| c.is_ascii_lowercase()) {
        return false;
    }
    if !tok
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    {
        return false;
    }
    tok.matches('_').count() >= 3
}

/// Split note prose into candidate identifier tokens. Anything that cannot appear inside a Rust
/// identifier ends a token, so `meter.rs's a_spend_past_…` yields `meter`, `rs`, `s` and the name.
fn tokens(text: &str) -> Vec<&str> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|t| !t.is_empty())
        .collect()
}

/// The repository roots a note's FILE citation starts with.
const PATH_ROOTS: &[&str] = &[
    "crates/",
    "xtask/",
    "scripts/",
    "qa/",
    "docs/",
    "testing/",
    "conformance/",
    ".ci/",
    ".github/",
];

/// Every FILE PATH a note cites: a run of path characters starting at a [`PATH_ROOTS`] root, with
/// a `:<line>` suffix and trailing sentence punctuation dropped. A run that touches `{` or `*` is a
/// pattern over paths, not a citation of one.
fn cited_paths(text: &str) -> Vec<&str> {
    let is_path = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '/' | '-');
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if !is_path(b[i] as char) {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && is_path(b[i] as char) {
            i += 1;
        }
        let pattern = |at: Option<&u8>| matches!(at, Some(b'{' | b'*'));
        if pattern(start.checked_sub(1).and_then(|p| b.get(p))) || pattern(b.get(i)) {
            continue;
        }
        let run = text[start..i].trim_end_matches(['.', '/', '-']);
        if run.len() > 4 && PATH_ROOTS.iter().any(|r| run.starts_with(r)) {
            out.push(run);
        }
    }
    out
}

/// Every `(binding, symbol)` a NOTE names as a witness that resolves to nothing in the tree: a
/// test-shaped name no `fn` or `.rs` stem answers, or a FILE PATH that is not on disk (X-1207: the
/// rule used to read identifier-shaped tokens only, so the note that motivated it, PB-58, cited
/// `crates/busbar-caps/src/decision.rs` for years after the crate was folded away).
///
/// Reads `ctx.notes`, which the self-test can replace through the existing
/// [`super::NOTE_TABLE_KEY`] overlay — so the rule is plantable without a shipped fiction.
pub fn note_witness_offenders(ctx: &Ctx) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for (pb, text) in &ctx.notes {
        let mut seen = BTreeSet::new();
        for tok in tokens(text) {
            if !is_witness_shaped(tok) || ctx.symbols.contains(tok) || !seen.insert(tok) {
                continue;
            }
            out.push((pb.clone(), tok.to_string()));
        }
        for path in cited_paths(text) {
            if seen.insert(path) && !ctx.root.join(path).exists() {
                out.push((pb.clone(), path.to_string()));
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod running_test_tests {
    use super::{running_tests, test_index};

    /// XE#13: an `#[ignore]`d test is listed by the runner and never run, so it proves nothing.
    #[test]
    fn an_ignored_test_is_not_a_running_test() {
        let src = "#[test]\nfn runs() {}\n#[test]\n#[ignore]\nfn skipped_after() {}\n\
                   #[ignore = \"slow\"]\n#[test]\nfn skipped_before() {}\n#[tokio::test]\nasync fn also_runs() {}\n";
        assert_eq!(running_tests(src).unwrap(), vec!["runs", "also_runs"]);
    }

    /// An ignore on one test does not leak to the next.
    #[test]
    fn an_ignore_does_not_leak_to_the_next_test() {
        let src = "#[test]\n#[ignore]\nfn a() {}\n#[test]\nfn b() {}\n";
        assert_eq!(running_tests(src).unwrap(), vec!["b"]);
    }

    /// XE#13: a test in a file no `mod` declares is never compiled; one that is declared counts.
    #[test]
    fn a_test_in_an_undeclared_module_is_not_indexed() {
        let root = std::env::temp_dir().join(format!("xtask-vb-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let src = root.join("crates/c/src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("lib.rs"), "#[cfg(test)]\nmod live;\n").unwrap();
        std::fs::write(src.join("live.rs"), "#[test]\nfn live_one() {}\n").unwrap();
        std::fs::write(src.join("orphan.rs"), "#[test]\nfn orphan_one() {}\n").unwrap();
        let idx = test_index(&root.join("crates"), &root).unwrap();
        let _ = std::fs::remove_dir_all(&root);
        assert!(idx.contains_key("live_one"), "{idx:?}");
        assert!(!idx.contains_key("orphan_one"), "{idx:?}");
    }
}

#[cfg(test)]
mod note_path_tests {
    use super::cited_paths;

    #[test]
    fn a_note_s_file_citations_are_read_and_patterns_are_not() {
        let note = "declared in crates/busbar-caps/src/decision.rs, constructed at \
                    crates/busbar-llm/src/unit/admit.rs:203. See qa/x.toml. Every \
                    crates/busbar-plane-*/Cargo.toml and crates/{a,b}/src is a pattern; \
                    admit.rs is a stem, not a path.";
        assert_eq!(
            cited_paths(note),
            vec![
                "crates/busbar-caps/src/decision.rs",
                "crates/busbar-llm/src/unit/admit.rs",
                "qa/x.toml"
            ]
        );
    }
}
