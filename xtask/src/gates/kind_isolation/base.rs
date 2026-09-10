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
    // THE BASE'S LEDGER IS PART OF THE KEY, because a self-test may PLANT it: an overlay can answer
    // `git show <base>:qa/kind-isolation.toml` with a ledger that announces a crate history never
    // announced, which is how the door's cases drive an admission against a base the developer's
    // tree does not have. Keyed by root and commit alone, the first reading in the process would
    // answer every later case, planted or not — a fixture answered out of another fixture's cache.
    // The text is hashed rather than stored; an unplanted run reads the same bytes every time.
    let registry = cx.git_show(&commit, REGISTRY_FILE).ok();
    let fingerprint = {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        registry.hash(&mut h);
        h.finish()
    };
    let key = format!(
        "{}\u{0}{commit}\u{0}{fingerprint:016x}",
        cx.root().display()
    );
    if let Some(hit) = cache().lock().ok().and_then(|m| m.get(&key).cloned()) {
        return hit;
    }
    let built = build(cx, &commit, registry).map(std::sync::Arc::new);
    if let Ok(mut m) = cache().lock() {
        m.insert(key, built.clone());
    }
    built
}

fn build(cx: &Ctx, commit: &str, registry: Option<String>) -> Result<Base, String> {
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
    match registry {
        Some(t) => {
            base.registry = t;
            base.registry_present = true;
        }
        None => base.registry_present = false,
    }
    Ok(base)
}

/// THE BASE'S KEY SET, READ IN TODAY'S NAMES — [`row_keys`] with the `[[renamed]]` table applied.
///
/// Every key in the base's ledger is spelled in the name the BASE carried, so a crate renamed on
/// this branch has its rows looked up under a name history never had and every one of them comes
/// back MINTED. Four letters of an owner-ruled rename read as five ceilings invented from nothing.
///
/// The translation is the row's whole effect and its whole limit: `[[cell]]` and `[[disagreement]]`
/// are keyed by CRATE, so those keys move; `[[edge]]` is keyed by KIND, and a rename may not change
/// a kind, so those do not. Nothing is added to the set — a key the base did not carry under the
/// old name is still absent under the new one, and is still minted.
pub fn row_keys_as_now(
    text: &str,
    table: &str,
    id_fields: &[&str],
    renamed_to: &BTreeMap<&str, &str>,
) -> BTreeSet<String> {
    row_keys(text, table, id_fields)
        .into_iter()
        .map(|k| match k.split_once(" \u{d7} ") {
            Some((krate, rest)) if table != "edge" => match renamed_to.get(krate) {
                Some(now) => format!("{now} \u{d7} {rest}"),
                None => k,
            },
            _ => k,
        })
        .collect()
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    const LEDGER: &str = concat!(
        "[[cell]]\ncrate = \"busbar-secret-ref\"\nkind = \"api\"\ncount = \"3\"\n\n",
        "[[cell]]\ncrate = \"busbar-store-memory\"\nkind = \"api\"\ncount = \"1\"\n\n",
        "[[edge]]\nfrom = \"secret\"\nto = \"api\"\ncite = \"x\"\nwhy = \"x\"\ndrain = \"x\"\n",
    );

    fn renames() -> BTreeMap<&'static str, &'static str> {
        [("busbar-secret-ref", "busbar-secret-grammar")]
            .into_iter()
            .collect()
    }

    /// THE RENAME, READ FORWARD. The base's `[[cell]]` key is spelled in the OLD name; a branch
    /// that renamed the crate writes the new one, and without this translation those are two
    /// different keys and the second is MINTED — five ceilings invented by four letters.
    #[test]
    fn a_renamed_crates_base_rows_are_read_under_its_new_name() {
        let keys = super::row_keys_as_now(LEDGER, "cell", &["crate", "kind"], &renames());
        assert!(
            keys.contains("busbar-secret-grammar \u{d7} api"),
            "{keys:?}"
        );
        assert!(!keys.contains("busbar-secret-ref \u{d7} api"), "{keys:?}");
        // …AND NOTHING ELSE MOVES. A crate no row renames keeps the key it had.
        assert!(keys.contains("busbar-store-memory \u{d7} api"), "{keys:?}");
        assert_eq!(keys.len(), 2, "{keys:?}");
    }

    /// AN `[[edge]]` IS KEYED BY KIND, NOT BY CRATE, and a rename may not change a kind — so the
    /// class keys are left exactly alone. Translating them would be the table reaching past the
    /// thing it is about.
    #[test]
    fn an_edge_class_key_is_never_translated() {
        let keys = super::row_keys_as_now(LEDGER, "edge", &["from", "to"], &renames());
        assert!(keys.contains("secret \u{d7} api"), "{keys:?}");
        assert_eq!(keys.len(), 1, "{keys:?}");
    }

    /// WITH NO `[[renamed]]` ROW THE ANSWER IS THE UNTRANSLATED ONE, which is what every rule read
    /// before this table existed: the translation is opt-in, per row, by name.
    #[test]
    fn with_no_rename_row_the_key_set_is_the_bases_own() {
        let keys = super::row_keys_as_now(LEDGER, "cell", &["crate", "kind"], &BTreeMap::new());
        assert_eq!(
            keys,
            super::row_keys(LEDGER, "cell", &["crate", "kind"]),
            "{keys:?}"
        );
    }
}
