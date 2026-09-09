//! THE MERGE-BASE — WHAT THIS BRANCH INHERITED, AS AGAINST WHAT IT WROTE DOWN.
//!
//! > "if we slip once the whole effort is pointless." — owner, 2026-09-09
//!
//! THE LEDGER IS THE EVIDENCE, NEVER THE JUDGE. Every ratchet in this gate compares a measurement
//! against a number a human wrote in `qa/kind-isolation.toml`, and until this module the human
//! could write any number they liked in the same commit as the thing it excused. A red team proved
//! it end to end: a real `busbar-transport-tcp -> busbar-plane-llm` path dependency — a plane
//! compiled into a wire, the exact fusion this gate exists to make impossible — went GREEN by
//! appending nine lines that say out loud `verdict = "not-allowed"`, plus one `[[cell]]` count.
//! The rows were honest. The gate read them and agreed with them. Nothing asked where they came
//! from.
//!
//! So the ledger acquires a provenance, and the provenance is history:
//!
//! * A `[[dep]]` row may **RECORD** a not-allowed edge that already existed at the merge-base with
//!   the integration line. It may never **INTRODUCE** one. The subject of the check is the EDGE in
//!   the base's own manifests, not the row — so no row, no verdict word and no count changes the
//!   answer. Writing the row is how a pre-existing debt is described; it is not how a new one is
//!   authorised.
//! * A `[[cell]]`, `[[edge]]` or `[[disagreement]]` row that is **not in the base's copy of the
//!   file at all** is a ceiling minted on this branch. `ceiling-rose` cannot see one — it walks the
//!   numbers the BASE carries and asks whether they went up, so a key that is new has no `before`
//!   to compare against and is skipped in silence. A new row is a 0 -> N raise wearing the clothes
//!   of a first measurement, and it is refused here.
//!
//! A BASE THAT CANNOT BE ESTABLISHED IS RED, NEVER GREEN, on exactly the terms `ceiling-rose` sets:
//! "the branch has no history here" is the state a shallow clone is in, and a ratchet that switches
//! itself off on the runner where it is cheapest to switch off is not a ratchet.
//!
//! THE READING IS MEMOISED PER PROCESS because it is immutable: a commit's tree does not change
//! while the process runs. The self-test drives this gate ninety times, and ninety readings of
//! sixty manifests out of git is four minutes nobody attributes.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, OnceLock};

use crate::ctx::Ctx;
use crate::gates::construction::ceilings::base_ref;

use super::{deps_of, package_name, REGISTRY_FILE};

/// The base commit's answer to the two questions this gate asks of history.
#[derive(Debug, Clone, Default)]
pub struct Base {
    /// The commit itself, so every finding names the thing it was measured against.
    pub commit: String,
    /// `(from-package, to-package)` for every SHIPPED dependency edge the base's manifests declare.
    shipped: BTreeSet<(String, String)>,
    /// The same for the TEST half — `[dev-dependencies]` and its per-target forms.
    test: BTreeSet<(String, String)>,
    /// The base's own `qa/kind-isolation.toml`, verbatim. Empty when the base did not carry one,
    /// which is the state a branch that ADDS the ledger is in.
    pub registry: String,
    /// Did the base carry the ledger at all? Distinguishes "the file is new on this branch, so
    /// every row in it is new and that is the landing" from "the file lost every row".
    pub registry_present: bool,
}

impl Base {
    /// Does the base's build graph already carry this edge, in this half?
    pub fn has_edge(&self, from: &str, to: &str, half_word: &str) -> bool {
        let set = if half_word == "test" {
            &self.test
        } else {
            &self.shipped
        };
        set.contains(&(from.to_string(), to.to_string()))
    }
}

type Cache = Mutex<BTreeMap<String, Result<std::sync::Arc<Base>, String>>>;

fn cache() -> &'static Cache {
    static C: OnceLock<Cache> = OnceLock::new();
    C.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// THE BASE, READ ONCE PER (repository root, base commit).
///
/// Keyed by the root as well as the commit because a self-test may re-root a whole `Ctx` at a
/// fixture tree, and answering that run out of the real repository's cache would be answering a
/// different question than the one the case asked.
pub fn read(cx: &Ctx) -> Result<std::sync::Arc<Base>, String> {
    let commit = base_ref(cx)?;
    let key = format!("{}\u{0}{commit}", cx.root().display());
    if let Some(hit) = cache().lock().ok().and_then(|m| m.get(&key).cloned()) {
        return hit;
    }
    let built = build(cx, &commit).map(std::sync::Arc::new);
    if let Ok(mut m) = cache().lock() {
        m.insert(key, built.clone());
    }
    built
}

fn build(cx: &Ctx, commit: &str) -> Result<Base, String> {
    let listing = cx.git_lines(&["ls-tree", "-r", "--name-only", commit])?;
    // THE WORKSPACE'S OWN RENAMES AS THE BASE STATED THEM. A member that inherits reaches the
    // package the workspace named; reading the base's edges through THIS tree's rename table would
    // let a rename landed on this branch decide what history contained.
    let renames = crate::manifest::workspace_renames(&cx.git_show(commit, "Cargo.toml")?);
    let mut base = Base {
        commit: commit.to_string(),
        ..Base::default()
    };
    let mut read_any = false;
    for rel in &listing {
        if rel != "Cargo.toml" && !rel.ends_with("/Cargo.toml") {
            continue;
        }
        let Ok(text) = cx.git_show(commit, rel) else {
            continue;
        };
        read_any = true;
        // The same census refusal this gate applies to the working tree: a manifest with no
        // readable package name declares no crate's edges, so it contributes none. Here that is a
        // conservative reading in the safe direction — an edge history cannot be shown to have had
        // is an edge this branch is introducing.
        let Some(from) = package_name(&text) else {
            continue;
        };
        let (shipped, test) = deps_of(&text, &renames);
        for d in shipped {
            base.shipped.insert((from.clone(), d.pkg));
        }
        for d in test {
            base.test.insert((from.clone(), d.pkg));
        }
    }
    if !read_any {
        return Err(format!(
            "no Cargo.toml at all could be read out of {commit}: a base whose manifests cannot be \
             read is a base no edge can be shown to pre-date, and reporting nothing is not passing"
        ));
    }
    match cx.git_show(commit, REGISTRY_FILE) {
        Ok(t) => {
            base.registry = t;
            base.registry_present = true;
        }
        Err(_) => base.registry_present = false,
    }
    Ok(base)
}

/// The KEY SET of one `[[table]]` in a ledger text: the identifying fields of every row of that
/// table, in the order the table declares them.
///
/// Deliberately the row's IDENTITY and not its whole text: a `[[cell]]` whose count moved is a
/// raise, which is `ceiling-rose`'s subject, and a `[[cell]]` that did not exist is a MINT, which
/// is this module's. Reading whole rows would collapse the two and report the first as the second.
pub fn row_keys(text: &str, table: &str, id_fields: &[&str]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let header = format!("[[{table}]]");
    let mut cur: Option<BTreeMap<String, String>> = None;
    let flush = |cur: &mut Option<BTreeMap<String, String>>, out: &mut BTreeSet<String>| {
        if let Some(fields) = cur.take() {
            let key: Vec<String> = id_fields
                .iter()
                .map(|f| fields.get(*f).cloned().unwrap_or_default())
                .collect();
            out.insert(key.join(" \u{d7} "));
        }
    };
    for raw in text.lines() {
        let t = raw.trim();
        if t.starts_with("[[") {
            flush(&mut cur, &mut out);
            if t == header {
                cur = Some(BTreeMap::new());
            }
            continue;
        }
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let Some(fields) = cur.as_mut() else { continue };
        if let Some((k, v)) = t.split_once('=') {
            fields.insert(k.trim().to_string(), v.trim().trim_matches('"').to_string());
        }
    }
    flush(&mut cur, &mut out);
    out
}
