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
//!   RATCHET, measured at [`FLOOR`] against the real count and raised as the tree grows, never
//!   lowered to accommodate a scan that stopped finding things.
//! * [`Population::drained`] — a crate that has a `src/` and contributed NOTHING. The floor catches
//!   a tree that shrank; only this catches one crate quietly leaving the scan while 700 other files
//!   keep the total comfortably above the floor.

use crate::ctx::{Ctx, SourceFile, WalkSpec};

/// The aggregate floor — A RATCHET. Measured at 725 non-test `.rs` files under `crates/` on the
/// 1.6.0 integration tree; set below that with room for a genuine consolidation, and raised when
/// the tree grows. Lowering it is how a gate stops reading the repository without saying so, so a
/// diff that lowers it is the diff to refuse.
pub const FLOOR: usize = 700;

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
/// and `blocking-ffi` as production source. It is not a hypothetical: `busbar-core-connsec`'s TLS
/// battery used to be `crates/busbar-kernel/src/tests/tls_tests.rs` — excluded twice over — and the
/// #40 connection-security extraction (029230dd7) rewrote it as `src/tests.rs`, at which point
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
