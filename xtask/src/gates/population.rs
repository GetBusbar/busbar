//! THE SCAN POPULATION — WHICH SOURCE A TEXT GATE IS ENTITLED TO CALL "THE TREE".
//!
//! Three gates (`settings-leak`, `response-header`, `blocking-ffi`) named their scan roots as
//! constants: a core root, a bin root, an LLM root, and two plane homes found by the resolver. That
//! list opened 280 of the tree's 725 non-test `.rs` files (audit D-4). Everything in
//! `busbar-substrate`, `busbar-substrate-values`, `api`, `busbar-voice`, every `*-codec` crate and
//! every `busbar-plane-*` crate was never read at all, and no row compared the root set with the
//! tree. A gate that says "no admin projection carries a raw settings bag" while never opening
//! three fifths of the crates is not making that claim about this repository; it is making it about
//! five directories, and the difference is invisible in a green report.
//!
//! So the population is DERIVED, not listed: every non-test `.rs` under `crates/`, in one walk,
//! with the count carried into the row detail. A crate added tomorrow is scanned tomorrow — there
//! is no list to forget to add it to.
//!
//! Two refusals come with it, because a derived population is only as good as the derivation:
//!
//! * [`Population::unreconciled`] — the scan RECONCILED AGAINST THE TRACKED SET (Law 8,
//!   docs/design/BUSBAR-1.6.0.md: "a census reports the LIST it scanned, not the count, and
//!   coverage is computed as the union of those lists reconciled against the whole"). The whole is
//!   every tracked path the same scope and filters admit ([`Ctx::tracked`]); a tracked file the
//!   walk did not read, or a file it read that nothing tracks, is refused BY NAME. This replaced a
//!   hand-kept count floor pinned at the measured value (last 948), which every change that added
//!   or removed a source file had to re-pin — so all of them conflicted on one line — and which,
//!   matched, still said nothing about WHICH files were read. "A roster maintained by hand is a
//!   defect with a date on it." An empty walk stays the walker's own refusal (`WalkError::Empty`).
//! * [`Population::drained`] — a crate that has a `src/` and contributed NOTHING. The
//!   reconciliation catches a file the scan went blind to; this catches a crate whose whole source
//!   left the tree while its manifest stayed.

use crate::ctx::{Coverage, Ctx, Overlay, SourceFile, WalkSpec};

/// The `.rs` under `crates/` that are not test scaffolding, plus the accounting to refuse a
/// population that cannot support a verdict.
pub struct Population {
    pub files: Vec<SourceFile>,
    /// Every crate directory under `crates/` that carries a manifest.
    pub crates: Vec<String>,
    /// Crates with a `src/` that contributed no file — see the module note.
    pub drained: Vec<String>,
    /// The scanned list reconciled against the tracked set — see the module note.
    pub coverage: Coverage,
}

impl Population {
    /// The scan is not the tracked set: a file owed went unread, or a file nobody tracks was read.
    pub fn unreconciled(&self) -> bool {
        !self.coverage.is_whole()
    }

    pub fn count(&self) -> usize {
        self.files.len()
    }

    /// The one sentence every gate's coverage row prints, pass or fail, so the reconciliation is
    /// in the ledger either way: a report that does not say what it opened cannot be read as a
    /// claim about the tree.
    pub fn census(&self) -> String {
        format!(
            "non-test .rs under crates/, across {} crate(s): {}",
            self.crates.len(),
            self.coverage.census()
        )
    }
}

/// The test scaffolding a source scan is not making claims about, by path.
const TEST_DIRS: [&str; 2] = ["/tests/", "/test_support/"];

/// THE BARE STEM IS THE SAME SPELLING WITHOUT THE UNDERSCORE, and leaving it out let test code
/// into three gates' idea of "the tree".
///
/// `#[cfg(test)] mod tests;` beside a `lib.rs` or a `mod.rs` puts the module in `tests.rs`. That
/// file ends with `/tests.rs`, not `_tests.rs`, so it matched neither suffix and sat in no `/tests/`
/// directory either — TWELVE files, in nine crates, scanned by `settings-leak`, `response-header`
/// and `blocking-ffi` as production source. It is not a hypothetical: `busbar-core-connector`'s TLS
/// battery used to be `crates/busbar-kernel/src/tests/tls_tests.rs` — excluded twice over — and the
/// #40 connection-security extraction rewrote it as `src/tests.rs`, at which point
/// `blocking-ffi:no-inline-ffi` went red naming `build_server_config(&tls, &resolver)` inside a
/// `#[tokio::test] async fn`. The rule is right and the finding was never about production code:
/// the scan set had quietly grown a test file.
///
/// NOT A LOOSENING, and measured: 762 -> 750 non-test files against a floor of 700, and every one of
/// the twelve is an out-of-line `#[cfg(test)] mod tests;` — code that does not exist in a release
/// build, checked one file at a time against the `#[cfg(test)]` on its own `mod` line. A
/// `test.rs`/`tests.rs` that a crate ships as production source would be a module named after the
/// thing it is not, and there is none in this tree.
fn is_test_file(rel: &str) -> bool {
    rel.ends_with("_test.rs")
        || rel.ends_with("_tests.rs")
        || rel.ends_with("/test.rs")
        || rel.ends_with("/tests.rs")
}

/// The walk, and the tracked set it is reconciled against, are both cut by this one spec.
fn scan_spec() -> WalkSpec {
    WalkSpec::new(["crates"]).ext("rs").exclude(TEST_DIRS)
}

/// Walk the tree for the population. `Err` — never a smaller answer — when `crates/` will not list:
/// a walk that failed and a tree that is clean produce the same empty hit set, and only one of them
/// is a pass.
pub fn source_population(cx: &Ctx) -> Result<Population, String> {
    let mut files: Vec<SourceFile> = cx
        .walk(&scan_spec())
        .map_err(|e| format!("crates/ would not list: {e}"))?
        .into_iter()
        .filter(|f| !is_test_file(&f.rel_str()))
        .collect();
    files.sort_by_key(SourceFile::rel_str);
    files.dedup_by_key(|f| f.rel_str());

    let whole: Vec<String> = cx
        .tracked(&scan_spec())
        .map_err(|e| format!("the tracked set under crates/ would not read: {e}"))?
        .into_iter()
        .filter(|p| !is_test_file(p))
        .collect();
    let coverage = Coverage::of(files.iter().map(SourceFile::rel_str), whole);

    let manifests = cx
        .walk(&WalkSpec::new(["crates"]).ext("toml"))
        .map_err(|e| format!("crates/ would not list its manifests: {e}"))?;
    let mut crates: Vec<String> = manifests
        .iter()
        .filter_map(|f| {
            let rel = f.rel_str();
            let parts: Vec<&str> = rel.split('/').collect();
            (parts.len() == 3 && parts[0] == "crates" && parts[2] == "Cargo.toml")
                .then(|| parts[1].to_string())
        })
        .collect();
    crates.sort();
    crates.dedup();

    let drained: Vec<String> = crates
        .iter()
        .filter(|name| {
            let src = format!("crates/{name}/src");
            cx.exists(&src)
                && !files
                    .iter()
                    .any(|f| f.rel_str().starts_with(&format!("{src}/")))
        })
        .cloned()
        .collect();

    Ok(Population {
        files,
        crates,
        drained,
        coverage,
    })
}

/// THE SELFTEST PLANT FOR THE RECONCILIATION: one tracked population file hidden from the walk
/// while the index still lists it, returned with its path so a case can require the refusal to
/// NAME it. The file is the last of a crate that has more than one, so the plant never drains a
/// crate and stays a coverage case, never a [`Population::drained`] one. It needs no re-pin when
/// the tree grows or shrinks: there is no count in it.
pub fn one_file_hidden(cx: &Ctx) -> Result<(Overlay, String), String> {
    let pop = source_population(cx)?;
    let crate_of = |rel: &str| rel.split('/').nth(1).unwrap_or_default().to_string();
    let mut kept = std::collections::BTreeSet::new();
    let mut removable: Vec<String> = pop
        .files
        .iter()
        .map(SourceFile::rel_str)
        .filter(|rel| !kept.insert(crate_of(rel)))
        .collect();
    let rel = removable
        .pop()
        .ok_or_else(|| "no crate holds a second source file to hide".to_string())?;
    let ov = cx.hide_from_scan([&rel])?;
    Ok((ov, rel))
}

#[cfg(test)]
mod tests {
    use super::{one_file_hidden, source_population};
    use crate::ctx::{Ctx, Overlay, INDEX_KEY};
    use std::path::PathBuf;

    /// A temp tree of two crates, `a` with three non-test `.rs` and `z` with ONE, and a context
    /// over it whose index is planted as `tracked` (a temp tree has no git index of its own).
    fn tree(tag: &str, untracked: Option<&str>) -> (PathBuf, Ctx) {
        let root = std::env::temp_dir().join(format!(
            "xtask-population-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let mut index = Vec::new();
        for (name, n) in [("a", 3), ("z", 1)] {
            let krate = root.join("crates").join(name);
            std::fs::create_dir_all(krate.join("src")).expect("src dir creates");
            std::fs::write(krate.join("Cargo.toml"), "[package]\n").expect("manifest write");
            index.push(format!("crates/{name}/Cargo.toml"));
            for i in 0..n {
                std::fs::write(krate.join("src").join(format!("f{i:04}.rs")), "// x\n")
                    .expect("seed write");
                index.push(format!("crates/{name}/src/f{i:04}.rs"));
            }
        }
        index.retain(|p| Some(p.as_str()) != untracked);
        let scratch = root.join(".fix").join("xtask");
        let mut ov = Overlay::new();
        ov.set_command(INDEX_KEY, index.join("\n"));
        let cx = Ctx::at(&root, &scratch)
            .expect("ctx opens over the temp root")
            .with_overlay(ov);
        (root, cx)
    }

    /// THE CONTROL: a walk that read exactly the tracked set is reconciled, and says so.
    #[test]
    fn a_population_that_is_the_tracked_set_is_reconciled() {
        let (root, cx) = tree("whole", None);
        let live = source_population(&cx).expect("the base tree reads");
        assert_eq!(live.count(), 4);
        assert!(!live.unreconciled(), "{}", live.census());
        assert!(live.drained.is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// THE RED ARM: one tracked file hidden from the walk is refused, BY NAME, and the plant
    /// drains no crate — never the single-file crate `z`.
    #[test]
    fn a_file_hidden_from_the_scan_is_refused_by_name() {
        let (root, cx) = tree("hidden", None);
        let (ov, rel) = one_file_hidden(&cx).expect("the hide plants");
        assert_eq!(rel, "crates/a/src/f0002.rs");
        let planted = source_population(&cx.with_overlay(ov)).expect("the planted tree reads");
        assert!(planted.unreconciled());
        assert_eq!(planted.coverage.missing, vec![rel.clone()]);
        assert!(planted.census().contains(&rel), "{}", planted.census());
        assert!(planted.drained.is_empty(), "{:?}", planted.drained);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// THE OTHER DIRECTION: a file the walk read that the index does not hold is refused by name.
    #[test]
    fn a_scanned_file_nothing_tracks_is_refused_by_name() {
        let (root, cx) = tree("extra", Some("crates/z/src/f0000.rs"));
        let pop = source_population(&cx).expect("the tree reads");
        assert!(pop.unreconciled());
        assert_eq!(
            pop.coverage.extra,
            vec!["crates/z/src/f0000.rs".to_string()]
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
