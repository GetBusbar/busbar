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
//! * [`Population::below_floor`] — the aggregate ratchet. It is not `> 0`: a walk that collapses to
//!   a handful of files reports no findings and reads exactly like a clean tree. The floor is a
//!   RATCHET pinned AT the measured count ([`FLOOR`], 941 on predev bd39476618), not a margin
//!   below it: one file fewer is refused until a reviewed diff re-measures. It is raised as the
//!   tree grows, never lowered to accommodate a scan that stopped finding things.
//! * [`Population::drained`] — a crate that has a `src/` and contributed NOTHING. The floor catches
//!   a tree that shrank; only this catches one crate quietly leaving the scan while the other files
//!   keep the total above the floor.

use crate::ctx::{Ctx, Overlay, SourceFile, WalkSpec};

/// The aggregate floor — A RATCHET. Measured at 941 non-test `.rs` files under `crates/` across 24
/// crates on predev bd39476618, and pinned AT that number (it was 700 against a population of 725,
/// then left standing while the tree grew, so 241 files could vanish with every row green). It was
/// first pinned at 948 on predev 5e672d125d; the egress-auth consolidation then removed 11 files
/// and added 4, and a floor above the count leaves every gate's floor row red on a clean tree. It
/// was re-pinned from 941 to 942 when predev grew by one file, which the selftest plant caught,
/// and back to 941 when #648 (q128-kernel-ledger) deleted `busbar-kernel-ledger/src/usage/series.rs`
/// — the one non-test file that merge removed, a reviewed removal and not a scan that went blind. A
/// drop below 941 is refused until a reviewed diff re-measures. The selftest plant
/// ([`one_file_short`]) cuts the live population to `FLOOR - 1` whatever its size, so predev
/// growing a file no longer forces a re-pin for the plant's sake. Lowering the floor is how a gate
/// stops reading the repository without saying so, so a diff that lowers it is the diff to refuse.
pub const FLOOR: usize = 941;

/// The `.rs` under `crates/` that are not test scaffolding, plus the accounting to refuse a
/// population that cannot support a verdict.
pub struct Population {
    pub files: Vec<SourceFile>,
    /// Every crate directory under `crates/` that carries a manifest.
    pub crates: Vec<String>,
    /// Crates with a `src/` that contributed no file — see the module note.
    pub drained: Vec<String>,
}

impl Population {
    pub fn below_floor(&self) -> bool {
        self.files.len() < FLOOR
    }

    pub fn count(&self) -> usize {
        self.files.len()
    }

    /// The one sentence every gate's floor row prints, so the count is in the ledger whether the
    /// row passed or failed: a report that does not say what it opened cannot be read as a claim
    /// about the tree.
    pub fn census(&self) -> String {
        format!(
            "{} non-test .rs file(s) under crates/, across {} crate(s), floor {FLOOR}",
            self.files.len(),
            self.crates.len()
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

/// Walk the tree for the population. `Err` — never a smaller answer — when `crates/` will not list:
/// a walk that failed and a tree that is clean produce the same empty hit set, and only one of them
/// is a pass.
pub fn source_population(cx: &Ctx) -> Result<Population, String> {
    let mut files: Vec<SourceFile> = cx
        .walk(&WalkSpec::new(["crates"]).ext("rs").exclude(TEST_DIRS))
        .map_err(|e| format!("crates/ would not list: {e}"))?
        .into_iter()
        .filter(|f| !is_test_file(&f.rel_str()))
        .collect();
    files.sort_by_key(SourceFile::rel_str);
    files.dedup_by_key(|f| f.rel_str());

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
    })
}

/// THE SELFTEST PLANT FOR THE FLOOR: the live population cut to exactly `FLOOR - 1`, however far
/// the tree has grown past [`FLOOR`] (see [`Overlay::below_floor`]). A fixed one-file cut went
/// green the day predev gained a file, and every open PR running the selftest had to re-pin the
/// floor by one; the computed cut lands one under the floor at any tree size. Each crate keeps its
/// first file out of the removable set, so no cut drains a crate and the plant stays a floor
/// case, never a [`Population::drained`] one. `Err` when the population cannot be read, already
/// sits under the floor, or holds too few removable files for the cut.
pub fn one_file_short(cx: &Ctx) -> Result<Overlay, String> {
    let pop = source_population(cx)?;
    let crate_of = |rel: &str| rel.split('/').nth(1).unwrap_or_default().to_string();
    let mut kept = std::collections::BTreeSet::new();
    let removable: Vec<&SourceFile> = pop
        .files
        .iter()
        .filter(|f| !kept.insert(crate_of(&f.rel_str())))
        .collect();
    Overlay::below_floor(pop.count(), FLOOR, removable.iter().rev().map(|f| &f.rel))
}

#[cfg(test)]
mod tests {
    use super::{one_file_short, source_population, FLOOR};
    use crate::ctx::Ctx;
    use std::path::PathBuf;

    /// A temp tree of two crates: `a` with `a_files` non-test `.rs` and `z` with ONE, which sorts
    /// last and so is the first file a reverse cut would reach.
    fn tree(tag: &str, a_files: usize) -> (PathBuf, Ctx) {
        let root = std::env::temp_dir().join(format!(
            "xtask-population-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        for (name, n) in [("a", a_files), ("z", 1)] {
            let krate = root.join("crates").join(name);
            std::fs::create_dir_all(krate.join("src")).expect("src dir creates");
            std::fs::write(krate.join("Cargo.toml"), "[package]\n").expect("manifest write");
            for i in 0..n {
                std::fs::write(krate.join("src").join(format!("f{i:04}.rs")), "// x\n")
                    .expect("seed write");
            }
        }
        let scratch = root.join(".fix").join("xtask");
        let cx = Ctx::at(&root, &scratch).expect("ctx opens over the temp root");
        (root, cx)
    }

    /// THE RED ARM: a population five files past its floor. A one-file cut leaves FLOOR + 4 and
    /// the floor row green; the plant lands at FLOOR - 1, refused, with no crate drained.
    #[test]
    fn a_population_grown_past_its_floor_is_cut_to_one_under_it() {
        let (root, cx) = tree("grown", FLOOR + 4);
        let live = source_population(&cx).expect("the base tree reads");
        assert_eq!(live.count(), FLOOR + 5);
        assert!(!live.below_floor() && live.drained.is_empty());

        let ov = one_file_short(&cx).expect("the cut plants");
        assert_eq!(ov.paths().count(), 6, "live - floor + 1 files are removed");
        let planted = source_population(&cx.with_overlay(ov)).expect("the planted tree reads");
        assert_eq!(planted.count(), FLOOR - 1);
        assert!(planted.below_floor());
        assert!(planted.drained.is_empty(), "the cut drained a crate: {:?}", planted.drained);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// THE CONTROL: a population exactly at its floor is green, and the cut there is one file —
    /// never the single-file crate `z`.
    #[test]
    fn a_population_at_its_floor_loses_one_file_and_drains_no_crate() {
        let (root, cx) = tree("at", FLOOR - 1);
        let live = source_population(&cx).expect("the base tree reads");
        assert_eq!(live.count(), FLOOR);
        assert!(!live.below_floor());

        let ov = one_file_short(&cx).expect("the cut plants");
        assert_eq!(ov.paths().count(), 1);
        assert!(ov.paths().all(|p| p.starts_with("crates/a")));
        let planted = source_population(&cx.with_overlay(ov)).expect("the planted tree reads");
        assert_eq!(planted.count(), FLOOR - 1);
        assert!(planted.drained.is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }
}
