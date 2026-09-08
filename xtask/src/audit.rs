//! THE AUDIT LEDGER — the 1.6.0 audit's row store and its queries.
//!
//! Ported from `scripts/audit-ledger.py`. The register (`qa/audit-ledger.json`) and the report it
//! generates (`docs/design/AUDIT-STATUS.md`) STAY WHERE THEY ARE and stay byte-identical: this
//! module reads and writes them through [`crate::json_lite`], which reproduces
//! `json.dump(doc, fh, indent=1, ensure_ascii=False, sort_keys=False)` exactly, so `sync --write`
//! under the Rust produces the same 147KB the Python produced.
//!
//! Seven properties are the whole instrument, and each is a rule here rather than a convention:
//!
//! 1. **THE UNIVERSE IS EVERY TRACKED FILE.** Coverage is computed against `git ls-tree -r HEAD`,
//!    not against a hand-kept list, so a new crate cannot be silently uncovered. A file in no scope
//!    and on no excuse is RED.
//! 2. **A RESULT DESCRIBES ONE TREE.** Every round carries the SHA-256 of the `path<TAB>blob-oid`
//!    list of its scope's files at the audited commit. When the code moves the hash stops matching
//!    and the scope reads `stale` — the result EXPIRED, it did not pass. Staleness is checked
//!    THIRD, ahead of `in_progress`, `open`, `fixed` and `clean`, so no result kind can outrun it.
//! 3. **CLEAN IS TWO ZERO ROUNDS FROM DISTINCT AUDITORS AT THE CURRENT HASH.** One auditor finding
//!    nothing is `unconfirmed`, which is not a pass. The rounds list is APPEND-ONLY; `record` never
//!    edits or replaces a round, and `sync` carries the list across verbatim. An auditor is
//!    identified by [`auditor_identity`], not by the bytes typed: `alice`, `alice ` and `Alice` are
//!    ONE reader, and the two rounds must also be two DIFFERENT rounds.
//! 4. **`fixed` IS NOT SELF-CERTIFYING.** Stamping a fix re-hashes the scope to the fix commit, so
//!    the fixer's own pre-fix zero rounds cannot match the new hash — and a scope whose recorded
//!    HIGH or MEDIUM count is non-zero stays RED until SOMEBODY ELSE records a confirming zero round
//!    against the fixed tree. You cannot close your own finding by asserting you closed it, and the
//!    bar is the same HIGH/MEDIUM bar `--check` holds an open scope to.
//! 5. **AN UNREADABLE ENTRY IS RED, NEVER GUESSED.** A result outside the four known values, a
//!    `counts` that is not an object, an unknown severity, a negative or boolean count — each is
//!    `invalid`, and `invalid` can never fall through to `clean`. Every ROUND is held to the same
//!    bar as the record it belongs to, and the top-level record must BE the last round.
//! 6. **A RECORDED FINDING DOES NOT EXPIRE BECAUSE A LATER ROUND SAID `in_progress`.** The decisive
//!    record about a tree is the latest round that REACHED A VERDICT — `zero` or `findings`. A round
//!    that is merely running cannot outrank one that finished, so `record --result in_progress`
//!    cannot take a scope off the worklist or out of `--check`.
//! 7. **A TREE THAT CANNOT BE PRODUCED IS NOT A TREE THAT MATCHED.** When git cannot resolve the
//!    commit a record names, the anti-forgery rule is RED, never silent — see [`audited_tree_hash`].

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::json_lite::{self, Json, Obj};
use crate::sha256::Sha256;

pub const REGISTER_REL: &str = "qa/audit-ledger.json";
pub const REPORT_REL: &str = "docs/design/AUDIT-STATUS.md";

pub const SEVERITIES: [&str; 4] = ["HIGH", "MEDIUM", "LOW", "NIT"];
pub const RESULTS: [&str; 4] = ["zero", "findings", "in_progress", "unaudited"];

/// The order the totals table and the `--check` summary read in. It is a presentation order, and it
/// deliberately puts `clean` first and `invalid` last so a register going wrong reads bottom-up.
pub const STATUS_BARS: [&str; 8] = [
    "clean",
    "unconfirmed",
    "fixed",
    "in_progress",
    "stale",
    "open",
    "unaudited",
    "invalid",
];

/// The worklist order `next` ranks by: the entries that are wrong first, the entries that are
/// merely unfinished after, and the finished ones last.
pub const NEXT_ORDER: [&str; 7] = [
    "invalid",
    "open",
    "unaudited",
    "stale",
    "fixed",
    "unconfirmed",
    "clean",
];

pub fn next_why(status: &str) -> &'static str {
    match status {
        "invalid" => "the register entry is not readable -- an unknown result or severity",
        "open" => "findings recorded, no fix stamped",
        "unaudited" => "never audited",
        "stale" => "code changed since the audit",
        "fixed" => "findings fixed, owes a confirming round",
        "unconfirmed" => "one zero on this tree -- owes a second, independent zero",
        "clean" => "two auditors read this tree and both found nothing",
        _ => "a round is running against a recorded tree hash",
    }
}

/// Instrument/QA paths that are code too, and are audited as their own scopes. A harness that
/// decides whether the product is correct is exactly as worth auditing as the product.
const INSTRUMENT_PATHS: [&str; 7] = [
    "scripts",
    "qa",
    ".github/workflows",
    ".githooks",
    ".github/scripts",
    "assets/readme",
    "examples",
];

/// The crate whose `src/` is split, because its production code is two very different things.
const SPLIT_CRATE: &str = "busbar";

/// The register's own six-line preamble, regenerated on every `sync --write`.
const REGISTER_COMMENT: [&str; 6] = [
    "GENERATED scope list -- `cargo xtask ledger sync --write` derives it from the tree.",
    "Audit records (round/result/report/auditor/fixed_at/tree_hash) are hand-stamped by",
    "`record` and `fixed` and are preserved across sync.",
    "tree_hash = sha256 over the sorted `path<TAB>blob-oid` list of the scope's tracked files at",
    "the audited commit; when it stops matching the tree, the audit result has expired.",
    "status is DERIVED at report time, never stored. See docs/design/AUDIT-STATUS.md.",
];

/// Tracked files that are deliberately in no scope. Manifests are governed by workspace-deps-lint
/// and the construction gate, not by a code audit; the fixture trees are inputs to those gates.
///
/// `*` matches within one path segment and `**` spans segments — an excuse must cover exactly the
/// subtree it names and no more. Each top-level tree is named individually ON PURPOSE, so adding a
/// new one cannot inherit an excuse it was never granted.
///
/// This is a CONSTANT, not a read of the committed file, and `sync --write` regenerates the file's
/// copy from it. That is what makes an excuse a source edit somebody reviews rather than a line
/// somebody adds to a JSON file. `xtask/tests/readers.rs` pins it against the committed array.
pub const UNCOVERED_BY_DESIGN: &[(&str, &str)] = &[
    (
        "crates/*/Cargo.toml",
        "crate manifest -- governed by workspace-deps-lint, not a code audit",
    ),
    (
        "crates/*/Cargo.lock",
        "resolved lockfile -- governed by the build gates, not a code audit",
    ),
    (
        "crates/*/fixtures/**",
        "fixture inputs a crate's own gate reads; not shipped code",
    ),
    (
        "xtask/Cargo.toml",
        "crate manifest -- governed by workspace-deps-lint, not a code audit",
    ),
    (
        "xtask/fixtures/**",
        "fixture trees the workspace-deps gate builds against",
    ),
    (
        "docs/**",
        "design and reference prose -- governed by the doc gates, not a code audit",
    ),
    (
        "*.md",
        "top-level project prose -- governed by the doc and changelog gates",
    ),
    ("LICENSE", "licence text"),
    ("NOTICE", "attribution notice"),
    (
        "Cargo.toml",
        "workspace manifest -- governed by workspace-deps-lint",
    ),
    (
        "Cargo.lock",
        "resolved lockfile -- governed by the build gates",
    ),
    (
        "deny.toml",
        "cargo-deny policy -- governed by the supply-chain gate",
    ),
    (
        "rust-toolchain.toml",
        "pinned toolchain -- governed by the build gates",
    ),
    (
        "rustfmt.toml",
        "formatter settings -- governed by `cargo fmt --check`",
    ),
    ("codecov.yml", "coverage service settings"),
    (".cargo/**", "cargo invocation settings"),
    (".editorconfig", "editor settings"),
    (".gitignore", "vcs settings"),
    (".gitattributes", "vcs settings"),
    (".dockerignore", "container build context settings"),
    (".github/ISSUE_TEMPLATE/**", "issue forms -- prose"),
    (".github/*.md", "contribution prose"),
    (
        "Dockerfile",
        "container recipe -- governed by the image build gate",
    ),
    ("docker/**", "container-local sample config"),
    ("assets/*.png", "brand images"),
    (
        "org-profile/**",
        "the GitHub org profile -- prose and brand images",
    ),
    (
        "tests/migration-corpus/**",
        "captured historical configs the migration gate replays; inputs, not code",
    ),
    ("config.yaml", "the shipped sample deployment config"),
    ("plugins.yaml", "the shipped sample plugin manifest"),
    ("providers.yaml", "the shipped sample provider table"),
];

// ---------------------------------------------------------------------------------------------
// git
// ---------------------------------------------------------------------------------------------

/// The git reads the register rests on, always `-C <repo>` and never a `cd`.
pub struct Git {
    repo: std::path::PathBuf,
    /// See [`Git::reachable`]. Resolved at most once, and never from anything an overlay can move.
    reachable: std::sync::OnceLock<BTreeSet<String>>,
}

impl Git {
    pub fn new(repo: impl Into<std::path::PathBuf>) -> Git {
        Git {
            repo: repo.into(),
            reachable: std::sync::OnceLock::new(),
        }
    }

    pub fn repo(&self) -> &Path {
        &self.repo
    }

    pub fn run(&self, args: &[&str]) -> Result<String, String> {
        crate::gitp::git(&self.repo, args)
    }

    pub fn head(&self) -> Result<String, String> {
        Ok(self.run(&["rev-parse", "HEAD"])?.trim().to_string())
    }

    /// THE UNIVERSE: every tracked blob at `rev`, path -> blob oid. Blobs only — a submodule's
    /// `commit` entry is not a file this repository's audit can read.
    pub fn files_at(&self, rev: &str) -> Result<BTreeMap<String, String>, String> {
        let out = self.run(&["ls-tree", "-r", rev, "--full-tree"])?;
        let mut table = BTreeMap::new();
        for line in out.lines() {
            if line.is_empty() {
                continue;
            }
            let Some((meta, path)) = line.split_once('\t') else {
                continue;
            };
            let mut cols = meta.split_whitespace();
            let (_mode, kind, oid) = (cols.next(), cols.next(), cols.next());
            if kind == Some("blob") {
                if let Some(oid) = oid {
                    table.insert(path.to_string(), oid.to_string());
                }
            }
        }
        Ok(table)
    }

    /// THE TWO PIN NAMESPACES.
    ///
    /// `refs/audit-pins/*` is where a pin is written locally. `refs/backup/audit-pins/*` is where
    /// the mirror is PUSHED, and it is therefore the only one of the two that exists on a runner.
    pub const PIN_NAMESPACES: [&'static str; 2] = ["refs/audit-pins/", "refs/backup/audit-pins/"];

    /// THE AUDIT PINS, from BOTH namespaces.
    ///
    /// A round may legitimately name a commit that is not on the current line — a reading taken on
    /// a branch, a reading taken before a rebase — and the way to keep such a reading honest is to
    /// PIN the commit so it survives and is visible in `git for-each-ref`. A commit reachable from
    /// nowhere at all is a commit that will be garbage-collected, and a record whose tree can be
    /// collected is a record whose claim cannot be re-checked by anybody.
    ///
    /// THIS USED TO READ `refs/audit-pins/*` ONLY, AND THAT NAMESPACE IS LOCAL-ONLY. Neither
    /// `git clone` nor `actions/checkout` carries anything outside `refs/heads/*` and `refs/tags/*`
    /// — `git ls-remote origin 'refs/audit-pins/*'` returns nothing — so on the runner the pin set
    /// was EMPTY and `reachable()` degenerated to "an ancestor of HEAD". Measured on this base: 13
    /// of the 23 `audited_at` commits are not ancestors of HEAD and were green only because of pin
    /// refs that exist in one working copy on one laptop. In `ci.yml`'s blocking audit-ledger job
    /// all 13 would have been RED. The mirror was being pushed to `refs/backup/audit-pins/*`, a
    /// namespace this function never read.
    ///
    /// Reading both is half the fix; the other half is the workflows fetching the backup namespace
    /// before the job runs, which is why `ci.yml` and `keep-proof.yml` now carry
    /// `git fetch origin '+refs/backup/audit-pins/*:refs/audit-pins/*'`.
    pub fn audit_pins(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for ns in Self::PIN_NAMESPACES {
            if let Ok(text) = self.run(&["for-each-ref", "--format=%(refname)", ns]) {
                out.extend(
                    text.lines()
                        .map(str::trim)
                        .filter(|l| !l.is_empty())
                        .map(str::to_string),
                );
            }
        }
        out.sort();
        out.dedup();
        out
    }

    /// Is `commit` an ancestor of `of` (or the same commit)?
    ///
    /// A commit git cannot resolve is NOT an ancestor, and that is the same answer for the same
    /// reason: the tree it names cannot be produced from this repository. The two are distinguished
    /// in the finding's wording, never in the verdict.
    /// EVERY COMMIT REACHABLE FROM HEAD OR FROM AN AUDIT PIN, as one set, resolved ONCE per
    /// process.
    ///
    /// The obvious spelling -- `merge-base --is-ancestor` per record, then once per pin when that
    /// says no -- is one git process per question, and the self-test asks the whole register's
    /// worth of questions again for every planted case. With thirteen pins that is hundreds of
    /// processes per case and thousands per run, and it showed: `audit-ledger --selftest` spent
    /// eight seconds a case, almost all of it forking.
    ///
    /// One `rev-list` answers all of them. The set is memoised for the life of the process because
    /// its two inputs -- HEAD and the pin refs -- are exactly what an overlay CANNOT change: a
    /// plant may rewrite the register, which is the file this gate judges, but it cannot rewrite
    /// the repository's refs. A memo keyed on something a plant could move would be a stale
    /// reading rather than a fast one.
    pub fn reachable(&self) -> &BTreeSet<String> {
        self.reachable.get_or_init(|| {
            let mut argv: Vec<String> = vec!["rev-list".to_string(), "HEAD".to_string()];
            argv.extend(self.audit_pins());
            let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
            self.run(&refs)
                .map(|out| out.lines().map(str::trim).map(str::to_string).collect())
                .unwrap_or_default()
        })
    }

    pub fn is_ancestor(&self, commit: &str, of: &str) -> bool {
        self.run(&["merge-base", "--is-ancestor", commit, of])
            .is_ok()
    }

    pub fn resolves(&self, commit: &str) -> bool {
        self.run(&[
            "rev-parse",
            "--verify",
            "--quiet",
            &format!("{commit}^{{commit}}"),
        ])
        .is_ok()
    }

    pub fn commits_between(&self, old: &str, new: &str) -> Option<u64> {
        self.run(&["rev-list", "--count", &format!("{old}..{new}")])
            .ok()
            .and_then(|s| s.trim().parse().ok())
    }

    /// LOC per blob, through ONE `git cat-file --batch` process rather than one per file.
    ///
    /// A final unterminated line counts as a line, which is what `wc -l` does not do and what the
    /// Python does.
    ///
    /// **STREAMED, IN LOCKSTEP WITH THE WRITER**, through [`crate::gitp::ask`]. `cat-file --batch`
    /// answers while it is still being asked, and this call asks about EVERY TRACKED BLOB IN THE
    /// TREE at once: thousands of oids of requests and megabytes of file bodies of answers, in
    /// both directions, through pipes that hold 64 KiB on Linux and 16 KiB on macOS. Writing the
    /// whole request list and only then reading — which is what this did — wedged the parent and
    /// the child against each other's full pipe, at 4% CPU, indefinitely. It is the reason
    /// `cargo xtask gate --all` did not finish.
    ///
    /// Reading record by record also keeps MEMORY bounded: only one file's bytes are held at a
    /// time, and only long enough to count newlines in them, rather than a copy of the repository.
    ///
    /// TWO KINDS OF ODD RECORD, told apart on purpose. `<oid> missing` (and `<oid> ambiguous`) is
    /// a complete two-field answer git gives for an object it cannot resolve: the stream is still
    /// in sync, so it is SKIPPED and the rest of the batch is still counted. Anything else that
    /// does not parse means the stream itself is no longer where this thinks it is, and continuing
    /// would attribute one file's count to another file — so that ends the read.
    pub fn line_counts(&self, oids: &BTreeSet<String>) -> BTreeMap<String, usize> {
        let mut out = BTreeMap::new();
        if oids.is_empty() {
            return out;
        }
        let requests: Vec<u8> = oids
            .iter()
            .flat_map(|o| o.bytes().chain(std::iter::once(b'\n')))
            .collect();

        let answered = crate::gitp::ask(&self.repo, &["cat-file", "--batch"], requests, |r| {
            let mut counts = BTreeMap::new();
            let mut header = String::new();
            loop {
                header.clear();
                match r.read_line(&mut header) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
                let mut cols = header.split_whitespace();
                let (Some(oid), rest) = (cols.next(), (cols.next(), cols.next())) else {
                    break;
                };
                let (Some(_kind), Some(size)) = rest else {
                    // "<oid> missing" — a whole answer, not a desync. Ask about the next one.
                    if matches!(rest.0, Some("missing") | Some("ambiguous")) {
                        continue;
                    }
                    break;
                };
                let Ok(size) = size.parse::<usize>() else {
                    break;
                };
                // The body, plus the newline git writes after every record.
                let mut body = vec![0u8; size + 1];
                if r.read_exact(&mut body).is_err() {
                    break;
                }
                let body = &body[..size];
                let lines = body.iter().filter(|b| **b == b'\n').count()
                    + usize::from(!body.is_empty() && body.last() != Some(&b'\n'));
                counts.insert(oid.to_string(), lines);
            }
            counts
        });

        if let Ok(answered) = answered {
            out = answered.value;
        }
        out
    }
}

// ---------------------------------------------------------------------------------------------
// scopes
// ---------------------------------------------------------------------------------------------

/// A fresh scope, in the register's key order. `exclude` appears only when non-empty and `rounds`
/// only once a round has been recorded, which is exactly the shape the committed file carries.
fn scope(id: &str, kind: &str, exclude: &[String]) -> Json {
    let mut o = Obj::new();
    o.insert("id", Json::Str(id.to_string()));
    o.insert("kind", Json::Str(kind.to_string()));
    o.insert("paths", Json::Array(vec![Json::Str(id.to_string())]));
    o.insert("tree_hash", Json::Null);
    o.insert("audited_at", Json::Null);
    o.insert("round", Json::Null);
    o.insert("result", Json::Str("unaudited".to_string()));
    o.insert("counts", Json::Object(Obj::new()));
    o.insert("report", Json::Null);
    o.insert("auditor", Json::Null);
    o.insert("fixed_at", Json::Null);
    if !exclude.is_empty() {
        o.insert(
            "exclude",
            Json::Array(exclude.iter().map(|e| Json::Str(e.clone())).collect()),
        );
    }
    Json::Object(o)
}

/// DERIVE the scope list from the tree, so a new crate cannot be silently uncovered.
///
/// The order is production, then tests, then instruments — and within a crate, `src` before
/// `build.rs`. It is the committed file's order and a diff is only readable if it stays.
pub fn derive_scopes(root: &Path) -> Vec<Json> {
    let mut prod = Vec::new();
    let mut tests = Vec::new();
    let mut inst = Vec::new();

    let crates_dir = root.join("crates");
    if crates_dir.is_dir() {
        let mut entries: Vec<String> = std::fs::read_dir(&crates_dir)
            .map(|rd| {
                rd.filter_map(Result::ok)
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        entries.sort();
        for name in entries {
            let base = format!("crates/{name}");
            if !root.join(&base).join("Cargo.toml").exists() {
                continue;
            }
            if root.join(&base).join("src").is_dir() {
                if name == SPLIT_CRATE {
                    // The binary crate's production code is two very different things — the
                    // composition root and the entry point — and one scope over both would let a
                    // clean read of one stand in for the other.
                    prod.push(scope(&format!("{base}/src/root"), "production", &[]));
                    prod.push(scope(&format!("{base}/src/main.rs"), "production", &[]));
                } else {
                    prod.push(scope(
                        &format!("{base}/src"),
                        "production",
                        &[format!("{base}/src/tests")],
                    ));
                }
                if root.join(&base).join("src/tests").is_dir() {
                    tests.push(scope(&format!("{base}/src/tests"), "test", &[]));
                }
            }
            if root.join(&base).join("build.rs").exists() {
                prod.push(scope(&format!("{base}/build.rs"), "production", &[]));
            }
            for sub in ["tests", "benches"] {
                if root.join(&base).join(sub).is_dir() {
                    tests.push(scope(&format!("{base}/{sub}"), "test", &[]));
                }
            }
        }
    }

    if root.join("xtask/src").is_dir() {
        prod.push(scope(
            "xtask/src",
            "production",
            &["xtask/src/tests".to_string()],
        ));
    }
    if root.join("xtask/src/tests").is_dir() {
        tests.push(scope("xtask/src/tests", "test", &[]));
    }

    for p in INSTRUMENT_PATHS {
        if root.join(p).exists() {
            inst.push(scope(p, "instrument", &[]));
        }
    }
    // The loose files directly in `.github/` — the release target tables, the artifact contract,
    // the dependabot policy — decide what ships and to whom. Without a remainder scope they are
    // the one place a release-critical file could sit forever in no scope at all.
    if root.join(".github").exists() {
        let mut ex: Vec<String> = INSTRUMENT_PATHS
            .iter()
            .filter(|p| p.starts_with(".github/"))
            .map(|p| (*p).to_string())
            .collect();
        ex.push(".github/ISSUE_TEMPLATE".to_string());
        inst.push(scope(".github", "instrument", &ex));
    }

    let testing = root.join("testing");
    if testing.is_dir() {
        let mut rigs: Vec<String> = std::fs::read_dir(&testing)
            .map(|rd| {
                rd.filter_map(Result::ok)
                    .filter(|e| e.path().is_dir())
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        rigs.sort();
        for rig in &rigs {
            inst.push(scope(&format!("testing/{rig}"), "instrument", &[]));
        }
        inst.push(scope(
            "testing",
            "instrument",
            &rigs
                .iter()
                .map(|r| format!("testing/{r}"))
                .collect::<Vec<_>>(),
        ));
    }

    prod.extend(tests);
    prod.extend(inst);
    prod
}

fn under(path: &str, prefix: &str) -> bool {
    path == prefix || path.starts_with(&format!("{}/", prefix.trim_end_matches('/')))
}

fn str_list(v: &Json) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// The files a scope owns: everything under one of its `paths` and under none of its `exclude`s.
pub fn scope_files(sc: &Json, all: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let paths = str_list(sc.get("paths"));
    let excl = str_list(sc.get("exclude"));
    all.iter()
        .filter(|(p, _)| paths.iter().any(|x| under(p, x)) && !excl.iter().any(|e| under(p, e)))
        .map(|(p, o)| (p.clone(), o.clone()))
        .collect()
}

/// The scope's tree hash: sha256 over the SORTED `path<TAB>oid\n` list.
///
/// A scope that owns NO FILE hashes to `None`, never to the digest of the empty string. The two
/// readings — "this scope's files all hash to X" and "this scope has no files" — must not collapse,
/// because the second one can never be clean.
pub fn tree_hash(sc: &Json, all: &BTreeMap<String, String>) -> Option<String> {
    let owned = scope_files(sc, all);
    if owned.is_empty() {
        return None;
    }
    let mut h = Sha256::new();
    for (path, oid) in &owned {
        h.update(format!("{path}\t{oid}\n").as_bytes());
    }
    Some(h.hexdigest())
}

/// The hash the scope's files ACTUALLY had at the commit `rec` claims to have read. A record whose
/// stored hash disagrees with this was stamped against a tree it did not read.
///
/// AN UNRESOLVABLE COMMIT IS AN ERROR, NOT AN ABSENT ANSWER. The whole purpose of this rule is
/// catching a stamp against a tree nobody read; a commit git cannot produce — hand-written, rebased
/// away, pruned — is precisely the case it exists for, so it must reach the caller as a refusal it
/// has to handle rather than as a `None` that reads like "nothing to say". `Ok(None)` stays the
/// honest "the scope owned no file at that commit", which is a different sentence.
pub fn audited_tree_hash(sc: &Json, git: &Git) -> Result<Option<String>, String> {
    let Some(at) = record_at(sc) else {
        return Err("the record names no audited_at commit".to_string());
    };
    let files = git.files_at(at)?;
    Ok(tree_hash(sc, &files))
}

/// The commit a record — a scope's top-level record or one of its rounds — claims to have read.
pub fn record_at(rec: &Json) -> Option<&str> {
    rec.get("audited_at").as_str()
}

// ---------------------------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------------------------

/// ONE AUDITOR IDENTITY, from whatever bytes were typed into `--auditor`.
///
/// Surrounding and repeated whitespace collapse and the case folds, because `alice`, `alice ` and
/// `Alice` are one person who read the tree once. The whole of property 3 is that TWO PEOPLE read
/// it, and a rule that answers that question with `!=` over raw bytes answers a different question:
/// a trailing space is not a second reader. A name that is empty once normalised is NO identity at
/// all, so it can never be one of the two.
pub fn auditor_identity(v: &Json) -> Option<String> {
    let name = v
        .as_str()?
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    (!name.is_empty()).then_some(name)
}

/// One ZERO round standing at the current hash: WHO read it, and WHICH round it was.
pub struct Confirmation {
    pub auditor: String,
    pub round: Option<i64>,
}

/// The zero rounds that stand at the CURRENT hash, each with its normalised auditor identity.
///
/// A pre-`rounds` register counts as one confirmation, and only when the rounds scan produced none —
/// a legacy fallback that must not add a second voice to a register that already has one.
pub fn confirmations(sc: &Json, current_hash: Option<&str>) -> Vec<Confirmation> {
    let mut out = Vec::new();
    if let Some(rounds) = sc.get("rounds").as_array() {
        for r in rounds {
            if r.get("result").as_str() == Some("zero")
                && r.get("tree_hash").as_str() == current_hash
            {
                if let Some(auditor) = auditor_identity(r.get("auditor")) {
                    out.push(Confirmation {
                        auditor,
                        round: r.get("round").as_i64(),
                    });
                }
            }
        }
    }
    if out.is_empty()
        && sc.get("result").as_str() == Some("zero")
        && sc.get("tree_hash").as_str() == current_hash
    {
        if let Some(auditor) = auditor_identity(sc.get("auditor")) {
            out.push(Confirmation {
                auditor,
                round: sc.get("round").as_i64(),
            });
        }
    }
    out
}

/// The distinct auditor IDENTITIES whose zero rounds stand at the current hash.
pub fn confirming_auditors(sc: &Json, current_hash: Option<&str>) -> BTreeSet<String> {
    confirmations(sc, current_hash)
        .into_iter()
        .map(|c| c.auditor)
        .collect()
}

/// TWO ZERO ROUNDS FROM TWO PEOPLE — the bar `clean` is held to.
///
/// Both halves are required and neither implies the other. Two identities on one round is one
/// reading credited to two names; two rounds under one identity is one person reading twice. Only a
/// pair that differs in BOTH is a second, independent reading, and a round whose number cannot be
/// read cannot be shown to be a different round, so it does not count as one.
pub fn confirmed(sc: &Json, current_hash: Option<&str>) -> bool {
    let seen = confirmations(sc, current_hash);
    seen.iter().enumerate().any(|(i, a)| {
        seen[i + 1..].iter().any(|b| {
            a.auditor != b.auditor && matches!((a.round, b.round), (Some(x), Some(y)) if x != y)
        })
    })
}

/// The latest round that REACHED A VERDICT about the current tree — `zero` or `findings`.
///
/// `in_progress` and `unaudited` are not verdicts, they are notes that a reading is or is not
/// happening, and a note cannot outrank a finding. Without this, `record --result in_progress` over
/// a recorded HIGH finding erased it from every red rule and from the worklist at once.
pub fn decisive_round<'a>(sc: &'a Json, current_hash: Option<&str>) -> Option<&'a Json> {
    sc.get("rounds").as_array()?.iter().rev().find(|r| {
        matches!(r.get("result").as_str(), Some("zero" | "findings"))
            && r.get("tree_hash").as_str() == current_hash
    })
}

/// The findings that STAND against the current tree with no fix stamped, as the record that carries
/// their counts.
///
/// Three rungs, most specific first: the latest round that reached a verdict about THIS tree; the
/// latest round that reached a verdict about ANY tree; the scope's own record. Each rung is a
/// weaker claim than the one above it, and the status the caller derives weakens with it — the
/// first is `open`, the other two are `stale`.
pub fn open_findings<'a>(sc: &'a Json, current_hash: Option<&str>) -> Option<&'a Json> {
    if sc.get("fixed_at").truthy() {
        return None;
    }
    if let Some(round) = decisive_round(sc, current_hash) {
        return (round.get("result").as_str() == Some("findings")).then_some(round);
    }
    // NO ROUND REACHED A VERDICT ABOUT THIS TREE, so fall back to the latest verdict about ANY
    // tree. A finding recorded against an older tree has not been answered just because the tree
    // moved and a later `in_progress` note landed on top of it; it reads `stale`, which is a red
    // status, rather than vanishing. Without this, eight `findings`-then-`in_progress` scopes whose
    // trees had since moved stayed hidden from `--check` behind the top-level note.
    if let Some(round) = sc.get("rounds").as_array().and_then(|rs| {
        rs.iter()
            .rev()
            .find(|r| matches!(r.get("result").as_str(), Some("zero" | "findings")))
    }) {
        return (round.get("result").as_str() == Some("findings")).then_some(round);
    }
    // No round reached a verdict at all: the scope's own record is all there is, and when it says
    // `findings` it is still saying it — including when the tree has since moved (`stale`).
    (sc.get("result").as_str() == Some("findings")).then_some(sc)
}

/// The scope's DERIVED status. Never stored — a stored status is a status that stops being true.
pub fn status_of(sc: &Json, current_hash: Option<&str>) -> &'static str {
    let result = sc.get("result").as_str().unwrap_or("unaudited");
    // AN UNREADABLE RESULT IS THE ONE CASE WHERE GUESSING IS UNSAFE IN BOTH DIRECTIONS. It gets its
    // own status, `--check` is red on it, and it can never fall through to `clean`.
    if !RESULTS.contains(&result) {
        return "invalid";
    }
    // A STANDING FINDING SURVIVES A LATER `unaudited` OR `in_progress` RECORD. Both of those are
    // writable by `record`, and either one would otherwise return the scope to "never audited" or
    // "somebody is on it" over findings nobody fixed.
    let open = open_findings(sc, current_hash).is_some();
    if !open && (result == "unaudited" || sc.get("audited_at").as_str().is_none()) {
        return "unaudited";
    }
    // STALENESS SITS THIRD, ahead of every result kind. A result describes one tree; when the tree
    // moves the result expired, whatever it said.
    if sc.get("tree_hash").as_str() != current_hash {
        return "stale";
    }
    if open {
        return "open";
    }
    if result == "findings" {
        return if sc.get("fixed_at").truthy() {
            "fixed"
        } else {
            "open"
        };
    }
    if result == "in_progress" {
        return "in_progress";
    }
    if confirmed(sc, current_hash) {
        "clean"
    } else {
        "unconfirmed"
    }
}

/// The keys that MAKE a record — the ones `record` writes into the scope and into the round it
/// appends, in that order. The two copies are one statement, so they must agree byte for byte.
pub const RECORD_KEYS: [&str; 7] = [
    "round",
    "result",
    "auditor",
    "audited_at",
    "tree_hash",
    "counts",
    "report",
];

/// Every way ONE record — a scope's top-level record or one of its rounds — is unreadable.
fn record_problems(label: &str, rec: &Json, bad: &mut Vec<String>) {
    let res = rec.get("result").as_str().unwrap_or("unaudited");
    if !RESULTS.contains(&res) {
        bad.push(format!(
            "{label}: result {} is not one of {}",
            json_lite::py_repr_json(rec.get("result")),
            RESULTS.join(", ")
        ));
    }
    // A RECORD WITH NO AUDITOR AND NO REPORT IS AN ASSERTION WITH NOBODY BEHIND IT. `unaudited` is
    // the one result that is allowed to have neither, because it says nothing was read.
    if res != "unaudited" {
        for key in ["auditor", "report"] {
            let cited = rec.get(key);
            let named = cited.as_str().is_some_and(|s| !s.trim().is_empty());
            if !named {
                bad.push(format!(
                    "{label}: {key} is {}, and a {res} result must name one",
                    json_lite::py_repr_json(cited)
                ));
            }
        }
    }
    let counts = rec.get("counts");
    if !counts.truthy() {
        return;
    }
    let Some(counts) = counts.as_object() else {
        bad.push(format!(
            "{label}: counts is {}, want an object",
            json_lite::py_type_name(counts)
        ));
        return;
    };
    for (key, val) in counts.iter() {
        if !SEVERITIES.contains(&key) {
            bad.push(format!(
                "{label}: unknown severity {} in counts (want {})",
                json_lite::py_repr(key),
                SEVERITIES.join(", ")
            ));
        }
        // BOOLEANS AND NEGATIVES ARE NOT COUNTS. `HIGH: true` reads as 1 in Python and would
        // otherwise quietly hold a scope open, or worse, quietly let one close.
        let ok = matches!(val, Json::Int(n) if *n >= 0);
        if !ok {
            bad.push(format!(
                "{label}: severity {key} = {} is not a count",
                json_lite::py_repr_json(val)
            ));
        }
    }
}

/// Every way a register entry is unreadable, in scope order then `counts` order.
///
/// EVERY ROUND IS HELD TO THE SAME BAR AS THE SCOPE, and the scope's top-level record must BE the
/// last round. `clean` is computed from the rounds list, so a rounds list nothing validates is a
/// rounds list anybody can append a second auditor to; and a top-level record that has drifted from
/// the round it came from means one of the two is a hand edit, whichever one it is.
pub fn register_problems(doc: &Json) -> Vec<String> {
    let mut bad = Vec::new();
    let Some(scopes) = doc.get("scopes").as_array() else {
        return bad;
    };
    for sc in scopes {
        let sid = sc.get("id").as_str().unwrap_or("<no id>").to_string();
        record_problems(&sid, sc, &mut bad);

        let rounds = sc.get("rounds");
        if !rounds.truthy() {
            continue;
        }
        let Some(rounds) = rounds.as_array() else {
            bad.push(format!(
                "{sid}: rounds is {}, want an array",
                json_lite::py_type_name(rounds)
            ));
            continue;
        };
        for (i, r) in rounds.iter().enumerate() {
            let label = format!("{sid}: round[{i}]");
            if r.as_object().is_none() {
                bad.push(format!(
                    "{label} is {}, want an object",
                    json_lite::py_type_name(r)
                ));
                continue;
            }
            record_problems(&label, r, &mut bad);
            if !matches!(r.get("round"), Json::Int(n) if *n >= 0) {
                bad.push(format!(
                    "{label}: round {} is not a round number",
                    json_lite::py_repr_json(r.get("round"))
                ));
            }
            if r.get("audited_at").as_str().is_none() {
                bad.push(format!(
                    "{label}: audited_at is {}, and a round that names no commit names no tree",
                    json_lite::py_repr_json(r.get("audited_at"))
                ));
            }
        }
        if let Some(last) = rounds.last() {
            for key in RECORD_KEYS {
                if last.get(key) != sc.get(key) {
                    bad.push(format!(
                        "{sid}: the scope's {key} is {} but its last round's is {} -- the top-level \
                         record must BE the last round",
                        json_lite::py_repr_json(sc.get(key)),
                        json_lite::py_repr_json(last.get(key))
                    ));
                }
            }
        }
    }
    bad
}

/// Segment-wise glob. `*` NEVER crosses a `/`; `**` spans segments. An excuse must cover exactly
/// the subtree it names.
pub fn glob_match(path: &str, pattern: &str) -> bool {
    let pat: Vec<&str> = pattern.split('/').collect();
    let seg: Vec<&str> = path.split('/').collect();
    walk(&pat, &seg, 0, 0)
}

fn walk(pat: &[&str], seg: &[&str], mut pi: usize, mut si: usize) -> bool {
    while pi < pat.len() {
        if pat[pi] == "**" {
            if pi + 1 == pat.len() {
                return true;
            }
            return (si..=seg.len()).any(|k| walk(pat, seg, pi + 1, k));
        }
        if si >= seg.len() {
            return false;
        }
        if !fnmatch(seg[si], pat[pi]) {
            return false;
        }
        pi += 1;
        si += 1;
    }
    si == seg.len()
}

/// `fnmatch.fnmatchcase` over one path segment: `*`, `?`, `[seq]` and `[!seq]`, case-sensitive.
fn fnmatch(name: &str, pat: &str) -> bool {
    let n: Vec<char> = name.chars().collect();
    let p: Vec<char> = pat.chars().collect();
    fnm(&n, &p, 0, 0)
}

fn fnm(n: &[char], p: &[char], ni: usize, pi: usize) -> bool {
    if pi == p.len() {
        return ni == n.len();
    }
    match p[pi] {
        '*' => (ni..=n.len()).any(|k| fnm(n, p, k, pi + 1)),
        '?' => ni < n.len() && fnm(n, p, ni + 1, pi + 1),
        '[' => {
            let Some(close) = p[pi + 1..].iter().position(|c| *c == ']') else {
                return ni < n.len() && n[ni] == '[' && fnm(n, p, ni + 1, pi + 1);
            };
            let mut set = &p[pi + 1..pi + 1 + close];
            let negate = set.first() == Some(&'!');
            if negate {
                set = &set[1..];
            }
            if ni >= n.len() {
                return false;
            }
            let mut hit = false;
            let mut k = 0;
            while k < set.len() {
                if k + 2 < set.len() && set[k + 1] == '-' {
                    if set[k] <= n[ni] && n[ni] <= set[k + 2] {
                        hit = true;
                    }
                    k += 3;
                } else {
                    if set[k] == n[ni] {
                        hit = true;
                    }
                    k += 1;
                }
            }
            hit != negate && fnm(n, p, ni + 1, pi + 2 + close)
        }
        c => ni < n.len() && n[ni] == c && fnm(n, p, ni + 1, pi + 1),
    }
}

/// Tracked files belonging to NO scope and covered by no excuse. Coverage is incomplete while this
/// is non-empty, and incomplete coverage is RED.
pub fn coverage_gaps(doc: &Json, all: &BTreeMap<String, String>) -> Vec<String> {
    let mut owned: BTreeSet<&String> = BTreeSet::new();
    if let Some(scopes) = doc.get("scopes").as_array() {
        for sc in scopes {
            for p in scope_files(sc, all).keys() {
                if let Some((k, _)) = all.get_key_value(p) {
                    owned.insert(k);
                }
            }
        }
    }
    // THE EXCUSES COME FROM THE FILE, not from the constant. `--check` judges the register that is
    // committed; `sync --write` is what regenerates the list from source.
    let excused: Vec<String> = doc
        .get("uncovered_by_design")
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|e| e.get("glob").as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    all.keys()
        .filter(|p| !owned.contains(p) && !excused.iter().any(|g| glob_match(p, g)))
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------------------------------
// the document
// ---------------------------------------------------------------------------------------------

/// A fresh register document around `scopes`, with the preamble and the excuse list regenerated
/// from source.
pub fn new_doc(scopes: Vec<Json>) -> Json {
    let mut o = Obj::new();
    o.insert(
        "_comment",
        Json::Array(
            REGISTER_COMMENT
                .iter()
                .map(|s| Json::Str((*s).to_string()))
                .collect(),
        ),
    );
    o.insert(
        "uncovered_by_design",
        Json::Array(
            UNCOVERED_BY_DESIGN
                .iter()
                .map(|(g, r)| {
                    let mut e = Obj::new();
                    e.insert("glob", Json::Str((*g).to_string()));
                    e.insert("reason", Json::Str((*r).to_string()));
                    Json::Object(e)
                })
                .collect(),
        ),
    );
    o.insert("scopes", Json::Array(scopes));
    Json::Object(o)
}

pub fn load(path: &Path) -> Result<Json, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    json_lite::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// [`load`], with THE ONE ABSENCE THAT IS NOT AN ERROR told apart from every other failure.
///
/// A register that does not exist yet has recorded nothing about anything, so a caller deriving the
/// scope list from the tree is right to treat it as empty. A register that is PRESENT and cannot be
/// read is the opposite fact — something IS recorded and this tool cannot see it — and collapsing
/// the two lets one flipped byte read as a clean slate. Only `NotFound` takes the `None` arm; a
/// permission error, a directory where a file should be, and anything that will not parse are all
/// errors, because none of them means "nothing has been recorded".
pub fn load_optional(path: &Path) -> Result<Option<Json>, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => json_lite::parse(&text)
            .map(Some)
            .map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// THE SCOPE LIST, or the reason there is not one. A register that parses but carries no `scopes`
/// array is as unread as a register that does not parse: the readers all iterate that key, and an
/// absent or wrongly-typed one yields zero scopes, which is indistinguishable from a register about
/// a tree with nothing in it. Zero scopes is a refusal here so that it cannot be a clean bill of
/// health downstream.
pub fn scopes(doc: &Json) -> Result<&[Json], String> {
    match doc.get("scopes") {
        Json::Array(a) => Ok(a),
        Json::Null => Err(
            "the register carries no `scopes` list — a register that records no \
                           scope at all is unread, not clean"
                .to_string(),
        ),
        other => Err(format!(
            "the register's `scopes` is a {}, not a list — nothing can be counted from it",
            json_lite::py_type_name(other)
        )),
    }
}

/// Write the register the way Python wrote it, down to the single trailing newline.
pub fn save(path: &Path, doc: &Json) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    }
    std::fs::write(path, format!("{}\n", json_lite::dump_python(doc)))
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// The keys `sync` CARRIES ACROSS from an existing scope, in this order. Assigning an existing key
/// keeps its position; `rounds` does not exist in a freshly derived scope, so it lands last — which
/// is exactly where the committed register has it.
const PRESERVED: [&str; 9] = [
    "tree_hash",
    "audited_at",
    "round",
    "result",
    "counts",
    "report",
    "auditor",
    "fixed_at",
    "rounds",
];

/// Merge the derived scope list with the register's records. A scope whose path left the tree loses
/// its record with it — that is the `-` line `sync` prints, and it is deliberate: a record about
/// code that no longer exists is not evidence about this tree.
pub fn merge(derived: &[Json], existing: &[Json]) -> Vec<Json> {
    let by_id: BTreeMap<&str, &Json> = existing
        .iter()
        .filter_map(|s| s.get("id").as_str().map(|i| (i, s)))
        .collect();
    derived
        .iter()
        .map(|d| {
            let mut keep = d.clone();
            let Some(id) = d.get("id").as_str() else {
                return keep;
            };
            let Some(old) = by_id.get(id) else {
                return keep;
            };
            if let Some(o) = keep.as_object_mut() {
                for key in PRESERVED {
                    if let Some(v) = old.as_object().and_then(|oo| oo.get(key)) {
                        o.insert(key, v.clone());
                    }
                }
            }
            keep
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------
// derived rows, shared by status / next / check / the report
// ---------------------------------------------------------------------------------------------

pub struct RowView {
    pub scope: Json,
    pub id: String,
    pub kind: String,
    pub status: &'static str,
    pub current_hash: Option<String>,
    pub age: Option<u64>,
    pub loc: usize,
}

/// Every scope with its derived status, age and LOC. One pass over git, because 144 scopes times a
/// process each is the difference between a query and a coffee break.
pub fn rows(doc: &Json, git: &Git) -> Result<Vec<RowView>, String> {
    let all = git.files_at("HEAD")?;
    let head = git.head()?;
    let oids: BTreeSet<String> = all.values().cloned().collect();
    let loc_by_oid = git.line_counts(&oids);

    let mut out = Vec::new();
    for sc in scopes(doc)? {
        let current = tree_hash(sc, &all);
        let status = status_of(sc, current.as_deref());
        let age = sc
            .get("audited_at")
            .as_str()
            .and_then(|at| git.commits_between(at, &head));
        let loc = scope_files(sc, &all)
            .values()
            .map(|oid| loc_by_oid.get(oid).copied().unwrap_or(0))
            .sum();
        out.push(RowView {
            id: sc.get("id").as_str().unwrap_or("<no id>").to_string(),
            kind: sc.get("kind").as_str().unwrap_or("").to_string(),
            scope: sc.clone(),
            status,
            current_hash: current,
            age,
            loc,
        });
    }
    Ok(out)
}

/// The LOC and share of one status band over a row set. The denominator is floored at 1 so a tree
/// with no measured lines reports 0.0% rather than dividing by zero — and the caller that cares
/// about an empty tree checks the row count, which is the honest question.
pub fn bar(rows: &[&RowView], key: &str) -> (usize, f64) {
    let total: usize = rows.iter().map(|r| r.loc).sum();
    let total = total.max(1);
    let got: usize = rows.iter().filter(|r| r.status == key).map(|r| r.loc).sum();
    (got, 100.0 * got as f64 / total as f64)
}

pub fn production(rows: &[RowView]) -> Vec<&RowView> {
    rows.iter().filter(|r| r.kind == "production").collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// THE PIN ARM, PROVEN IN A THROWAWAY REPOSITORY.
    ///
    /// `audit-ledger:audited-at-reachable` accepts a commit an audit pin reaches. That arm cannot
    /// be planted through the gate's register overlay — an overlay can change what the register
    /// SAYS, not what refs the repository HAS — and creating a ref to plant against would be
    /// writing into the tree the developer is standing in. So the two git reads the rule is built
    /// out of are proven here instead, over a repository this test makes and owns: a commit on no
    /// branch is not an ancestor of HEAD, and pinning it under `refs/audit-pins/` is what makes it
    /// one.
    #[test]
    fn a_pinned_commit_is_reachable_and_an_unpinned_one_is_not() {
        let root = std::env::temp_dir().join(format!("xtask-audit-pins-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("the scratch repository directory is creatable");
        let git = Git::new(&root);
        let hooks = root.join("nohooks");
        std::fs::create_dir_all(&hooks).expect("the empty hooks directory is creatable");
        for args in [
            vec!["init", "-q"],
            vec!["config", "user.email", "audit@selftest"],
            vec!["config", "user.name", "audit"],
            vec!["config", "commit.gpgsign", "false"],
            vec![
                "config",
                "core.hooksPath",
                hooks.to_str().expect("utf-8 path"),
            ],
        ] {
            git.run(&args)
                .expect("the scratch repository is configurable");
        }
        std::fs::write(root.join("f.txt"), "base\n").expect("the scratch file is writable");
        git.run(&["add", "-A"]).expect("add");
        git.run(&["commit", "-qm", "base"]).expect("commit");
        let base = git.head().expect("HEAD resolves");

        // A commit made on a side branch and then abandoned: real, resolvable, on no branch the
        // line can see.
        git.run(&["checkout", "-q", "-b", "side"]).expect("branch");
        std::fs::write(root.join("g.txt"), "side\n").expect("the scratch file is writable");
        git.run(&["add", "-A"]).expect("add");
        git.run(&["commit", "-qm", "side"]).expect("commit");
        let side = git.head().expect("HEAD resolves");
        git.run(&["checkout", "-q", "master"])
            .or_else(|_| git.run(&["checkout", "-q", "main"]))
            .expect("back to the initial branch");
        git.run(&["branch", "-qD", "side"])
            .expect("the side branch is deleted");

        assert!(git.resolves(&side), "the abandoned commit still resolves");
        assert!(
            !git.is_ancestor(&side, &base),
            "and it is reachable from the line by nothing, which is the finding"
        );
        assert!(git.audit_pins().is_empty(), "no pin has been written yet");

        git.run(&["update-ref", "refs/audit-pins/reading-1", &side])
            .expect("the pin is writable");
        let pins = git.audit_pins();
        assert_eq!(pins, vec!["refs/audit-pins/reading-1".to_string()]);
        assert!(
            pins.iter().any(|p| git.is_ancestor(&side, p)),
            "a pinned commit is reachable, which is the whole of what the pin is for"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    const HASH: &str = "aaaa";
    const OLD: &str = "bbbb";

    fn scope(json: &str) -> Json {
        json_lite::parse(json).expect("the test fixture is valid JSON")
    }

    /// AN AUDITOR IS A PERSON, NOT A SPELLING. Before this, `clean` counted the same reader twice
    /// whenever the second round was typed with a capital or a stray space — the exact way one
    /// person's two readings become "two independent auditors".
    #[test]
    fn one_reader_typed_three_ways_is_one_identity() {
        let one = auditor_identity(&Json::Str("alice".into()));
        assert_eq!(one.as_deref(), Some("alice"));
        assert_eq!(auditor_identity(&Json::Str("alice ".into())), one);
        assert_eq!(auditor_identity(&Json::Str(" Alice".into())), one);
        assert_eq!(auditor_identity(&Json::Str("ALICE".into())), one);
        assert_eq!(
            auditor_identity(&Json::Str("Alice\tSmith".into())).as_deref(),
            Some("alice smith"),
            "internal whitespace collapses too, so `Alice  Smith` is not a second person"
        );
    }

    /// A NAME THAT IS NOT A NAME IS NOT AN IDENTITY. An empty or blank auditor must not become a
    /// confirming voice; it would let a round nobody signed count towards `clean`.
    #[test]
    fn a_blank_auditor_is_nobody() {
        assert_eq!(auditor_identity(&Json::Str(String::new())), None);
        assert_eq!(auditor_identity(&Json::Str("   ".into())), None);
        assert_eq!(auditor_identity(&Json::Null), None);
        assert_eq!(auditor_identity(&Json::Int(7)), None);
    }

    fn zero_rounds(a: &str, ra: i64, b: &str, rb: i64) -> Json {
        scope(&format!(
            r#"{{"result": "zero", "audited_at": "c0", "tree_hash": "{HASH}", "rounds": [
                 {{"round": {ra}, "result": "zero", "auditor": "{a}", "tree_hash": "{HASH}"}},
                 {{"round": {rb}, "result": "zero", "auditor": "{b}", "tree_hash": "{HASH}"}}
               ]}}"#
        ))
    }

    /// CLEAN IS TWO READINGS BY TWO PEOPLE, and each half of that is load-bearing on its own.
    #[test]
    fn clean_needs_a_distinct_identity_and_a_distinct_round() {
        let h = Some(HASH);
        assert!(confirmed(&zero_rounds("alice", 1, "bob", 2), h));
        assert!(
            !confirmed(&zero_rounds("alice", 1, "Alice ", 2), h),
            "one person reading twice is one reading, however the second round spells the name"
        );
        assert!(
            !confirmed(&zero_rounds("alice", 1, "bob", 1), h),
            "two names on ONE round is one reading credited to two people"
        );
        assert_eq!(
            status_of(&zero_rounds("alice", 1, "Alice ", 2), h),
            "unconfirmed",
            "and the derived status must say so, not fall through to clean"
        );
        assert_eq!(status_of(&zero_rounds("alice", 1, "bob", 2), h), "clean");
    }

    /// A ROUND WHOSE NUMBER CANNOT BE READ CANNOT BE SHOWN TO BE A SECOND ROUND, so it cannot be
    /// the second half of a confirmation.
    #[test]
    fn a_round_with_no_number_confirms_nothing() {
        let sc = scope(&format!(
            r#"{{"result": "zero", "tree_hash": "{HASH}", "rounds": [
                 {{"round": 1, "result": "zero", "auditor": "alice", "tree_hash": "{HASH}"}},
                 {{"result": "zero", "auditor": "bob", "tree_hash": "{HASH}"}}
               ]}}"#
        ));
        assert!(!confirmed(&sc, Some(HASH)));
    }

    /// H1, THE HOLE ITSELF. `record --result in_progress` overwrites the top-level record and wipes
    /// `counts` to `{}`. A note that a reading is happening must not erase the reading that
    /// finished: the scope stays OPEN and the severities still come from the round that found them.
    #[test]
    fn a_later_in_progress_note_cannot_erase_a_recorded_finding() {
        let sc = scope(&format!(
            r#"{{"round": 5, "result": "in_progress", "counts": {{}}, "audited_at": "c0",
                 "tree_hash": "{HASH}", "rounds": [
                   {{"round": 5, "result": "findings", "tree_hash": "{HASH}",
                     "counts": {{"HIGH": 1, "MEDIUM": 6}}}},
                   {{"round": 5, "result": "in_progress", "tree_hash": "{HASH}", "counts": {{}}}}
                 ]}}"#
        ));
        assert_eq!(status_of(&sc, Some(HASH)), "open");
        let found = open_findings(&sc, Some(HASH)).expect("the finding still stands");
        assert_eq!(found.get("counts").get("HIGH").as_i64(), Some(1));
        assert_eq!(found.get("round").as_i64(), Some(5));
    }

    /// A VERDICT ABOUT AN OLDER TREE IS STILL A VERDICT. When the code moved after the finding, no
    /// round is decisive about the tree in front of us — but the finding has not been answered, so
    /// it reads `stale` (a red status) rather than vanishing behind the `in_progress` note.
    #[test]
    fn a_finding_whose_tree_has_moved_goes_stale_not_silent() {
        let sc = scope(&format!(
            r#"{{"round": 5, "result": "in_progress", "counts": {{}}, "audited_at": "c0",
                 "tree_hash": "{OLD}", "rounds": [
                   {{"round": 5, "result": "findings", "tree_hash": "{OLD}",
                     "counts": {{"HIGH": 1}}}},
                   {{"round": 5, "result": "in_progress", "tree_hash": "{OLD}", "counts": {{}}}}
                 ]}}"#
        ));
        assert_eq!(status_of(&sc, Some(HASH)), "stale");
        let found = open_findings(&sc, Some(HASH)).expect("nobody answered the finding");
        assert_eq!(found.get("counts").get("HIGH").as_i64(), Some(1));
    }

    /// A LATER `zero` IS a verdict, and it DOES supersede the finding. The fallback must not
    /// resurrect a finding somebody has since re-read and closed.
    #[test]
    fn a_later_zero_round_does_supersede_the_finding() {
        let sc = scope(&format!(
            r#"{{"round": 6, "result": "zero", "counts": {{}}, "audited_at": "c0",
                 "tree_hash": "{HASH}", "rounds": [
                   {{"round": 5, "result": "findings", "tree_hash": "{OLD}",
                     "counts": {{"HIGH": 1}}}},
                   {{"round": 6, "result": "zero", "auditor": "alice", "tree_hash": "{HASH}"}}
                 ]}}"#
        ));
        assert_eq!(open_findings(&sc, Some(HASH)), None);
        assert_eq!(status_of(&sc, Some(HASH)), "unconfirmed");
    }

    /// `unaudited` IS A NOTE TOO. Recording it over a finding must not return the scope to "never
    /// audited", which is how a HIGH walks off the worklist without anybody reading anything.
    #[test]
    fn a_later_unaudited_note_cannot_erase_a_recorded_finding_either() {
        let sc = scope(&format!(
            r#"{{"round": 2, "result": "unaudited", "counts": {{}},
                 "tree_hash": "{HASH}", "rounds": [
                   {{"round": 1, "result": "findings", "tree_hash": "{HASH}",
                     "counts": {{"MEDIUM": 2}}}},
                   {{"round": 2, "result": "unaudited", "tree_hash": "{HASH}", "counts": {{}}}}
                 ]}}"#
        ));
        assert_eq!(status_of(&sc, Some(HASH)), "open");
    }

    /// A STAMPED FIX CLOSES THE FINDING for the purposes of `open` — the owed rule, not this one,
    /// is what then demands somebody else confirm it.
    #[test]
    fn a_stamped_fix_is_no_longer_open() {
        let sc = scope(&format!(
            r#"{{"round": 1, "result": "findings", "counts": {{"HIGH": 1}}, "audited_at": "c0",
                 "fixed_at": "c1", "tree_hash": "{HASH}", "rounds": [
                   {{"round": 1, "result": "findings", "tree_hash": "{HASH}",
                     "counts": {{"HIGH": 1}}}}
                 ]}}"#
        ));
        assert_eq!(open_findings(&sc, Some(HASH)), None);
        assert_eq!(status_of(&sc, Some(HASH)), "fixed");
    }

    /// AN UNREADABLE RESULT CAN NEVER FALL THROUGH TO ANYTHING, including to `open` via the new
    /// fallback. It gets its own status and `--check` is red on it.
    #[test]
    fn an_unknown_result_is_invalid_and_stays_invalid() {
        let sc = scope(&format!(r#"{{"result": "passed", "tree_hash": "{HASH}"}}"#));
        assert_eq!(status_of(&sc, Some(HASH)), "invalid");
    }
}
