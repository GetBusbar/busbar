//! THE MERGE-BASE — WHAT THIS BRANCH INHERITED, AS AGAINST WHAT IT WROTE DOWN.
//!
//! > "if we slip once the whole effort is pointless." — owner, 2026-09-09
//!
//! THE LEDGER IS THE EVIDENCE, NEVER THE JUDGE. Every rule in this gate compares a measurement
//! against a row a human wrote in `qa/kind-isolation.toml`, and until this module the human could
//! write any row they liked in the same commit as the thing it excused. A red team proved
//! it end to end: a real `busbar-transport-tcp -> busbar-plane-llm` path dependency — a plane
//! compiled into a wire, the exact fusion this gate exists to make impossible — went GREEN by
//! appending nine lines that say out loud `verdict = "not-allowed"`, plus one `[[cell]]` row.
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
//! * A `[[cell]]`, `[[edge]]` or `[[instance]]` row that is **not in the base's copy of the file at
//!   all** is an edge allowance minted on this branch. The rows are presence only (size is not a CI
//!   check, owner 2026-10-02), so a row is the whole of what legitimises a cross-kind edge, and the
//!   mint rule is what refuses a branch legitimising a NEW edge by writing its row in the same
//!   commit as the coupling.
//!
//! A BASE THAT CANNOT BE ESTABLISHED IS RED, NEVER GREEN: "the branch has no history here" is the
//! state a shallow clone is in, and a rule that switches itself off on the runner where it is
//! cheapest to switch off is not a rule.
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
///
/// And by the base LEDGER when an overlay plants one (`git-show:<commit>:qa/kind-isolation.toml`):
/// a self-test that states "this row pre-dates the branch" plants the base's copy of the file, and
/// answering it out of an unplanted reading of the same commit — or leaving its planted copy in the
/// cache for the next case — would be answering a different question than the one asked.
pub fn read(cx: &Ctx) -> Result<std::sync::Arc<Base>, String> {
    let commit = base_ref(cx)?.sha;
    let planted_ledger = cx
        .overlay_command(&format!("git-show:{commit}:{REGISTRY_FILE}"))
        .map(|text| {
            use std::hash::{Hash, Hasher};
            let mut h = std::collections::hash_map::DefaultHasher::new();
            text.hash(&mut h);
            format!("{:016x}", h.finish())
        })
        .unwrap_or_default();
    let key = format!("{}\u{0}{commit}\u{0}{planted_ledger}", cx.root().display());
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
/// Deliberately the row's IDENTITY and not its whole text: a row whose other fields moved (a
/// `[[dep]]` count, a reworded `why`) is not a new row, and a row that did not exist is a MINT,
/// which is this module's subject. Reading whole rows would collapse the two and report the first
/// as the second.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctx::Overlay;
    use crate::gates::construction::ceilings::BASE_PIN_KEY;
    use std::path::Path;

    fn git(dir: &Path, args: &[&str]) -> String {
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args([
                "-c",
                "user.name=base",
                "-c",
                "user.email=base@selftest",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .output()
            .expect("git runs");
        assert!(out.status.success(), "git {args:?}: {out:?}");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// Q128 u82: a ledger the base's tree LISTS but `git show` cannot read is a base that cannot be
    /// established — `no-base`, RED — and never the "this branch adds the ledger" state that
    /// switches the mint rule off. RED on dev 0453923b9f: every read error set
    /// `registry_present = false`. The GREEN arms: a readable ledger is present, and a base whose
    /// tree has no ledger at all is the honest absent state.
    #[test]
    fn a_listed_ledger_the_base_cannot_show_is_no_base_and_never_an_absent_one() {
        let dir = std::env::temp_dir().join(format!(
            "xtask-base-registry-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("qa")).expect("the fixture repository");
        let manifest = "[package]\nname = \"planted\"\nversion = \"0.0.0\"\n";
        std::fs::write(dir.join("Cargo.toml"), manifest).expect("the manifest");
        std::fs::write(dir.join(REGISTRY_FILE), "# planted\n").expect("the ledger");
        git(&dir, &["init", "-q"]);
        git(&dir, &["add", "-A"]);
        git(&dir, &["commit", "-q", "-m", "with the ledger"]);
        let with = git(&dir, &["rev-parse", "HEAD"]);
        git(&dir, &["rm", "-q", REGISTRY_FILE]);
        git(&dir, &["commit", "-q", "-m", "without the ledger"]);
        let without = git(&dir, &["rev-parse", "HEAD"]);
        let cx = Ctx::at(&dir, dir.join("scratch")).expect("a fixture context");
        let pinned = |sha: &str, extra: &[(String, &str)]| {
            let mut ov = Overlay::new();
            ov.set_command(BASE_PIN_KEY, sha);
            for (k, v) in extra {
                ov.set_command(k.clone(), *v);
            }
            cx.with_overlay(ov)
        };

        // RED: the ref is planted, so `git show` answers only what the overlay plants — the
        // manifest, not the ledger the tree lists.
        let unreadable = pinned(
            &with,
            &[
                (format!("git-ref:{with}"), with.as_str()),
                (format!("git-show:{with}:Cargo.toml"), manifest),
            ],
        );
        let got = read(&unreadable);
        assert!(
            got.is_err(),
            "a listed ledger that cannot be read must be no-base, got registry_present = {:?}",
            got.map(|b| b.registry_present)
        );

        let readable = read(&pinned(&with, &[])).expect("a readable base");
        assert!(readable.registry_present);
        assert_eq!(readable.registry, "# planted\n");

        let absent = read(&pinned(&without, &[])).expect("a base with no ledger");
        assert!(!absent.registry_present);
        assert!(absent.registry.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
