//! AN EXTRACTED PLANE IS THE TREE BUSBAR HELD (ARCHITECT ruling on #1072).
//!
//! A plane leaves this tree for its own repository by COPYING the crate as dev held it, then deleting
//! it here. Two ways that copy can silently lose work, and this test is red on both:
//!
//! * THE COPY DRIFTED: a file in the repository at the recorded commit differs from the crate busbar
//!   held at the recorded base, beyond the reviewed extraction edits named here (a path rewritten
//!   for the new home, the cdylib twin replacing an example, a file the repository adds).
//! * DEV MOVED ON: a commit after the base changed the crate in this tree (a fix landing on dev
//!   while the extraction was open, then deleted with the crate). Only the deletion itself may
//!   follow the base; anything else is work the copy does not hold.
//!
//! The comparison is against the repository commit the copy was made at (`rev`), fetched here and
//! never skipped: the plane goes on changing in its own repository, and that is not drift.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

/// One extraction: where the crate lived here, the busbar commit its copy was taken from, and the
/// repository commit holding that copy, with the edits the extraction made and reviewed.
struct Extraction {
    /// The crate's directory in this tree (deleted by the extraction).
    crate_dir: &'static str,
    /// The repository it left for.
    repo: &'static str,
    /// The logic crate's directory in that repository.
    repo_dir: &'static str,
    /// The busbar commit whose `crate_dir` was copied.
    base: &'static str,
    /// The repository commit holding the copy.
    rev: &'static str,
    /// Files present on both sides whose content the extraction changed, and why.
    edited: &'static [(&'static str, &'static str)],
    /// Files of the crate that moved out of the logic crate (`from`, the repository path that holds
    /// them now, why).
    moved: &'static [(&'static str, &'static str, &'static str)],
    /// Files the repository's logic crate adds, and why.
    added: &'static [(&'static str, &'static str)],
}

const EXTRACTIONS: &[Extraction] = &[Extraction {
    crate_dir: "crates/busbar-plane-streaming",
    repo: "https://github.com/GetBusbar/busbar-plane-streaming",
    repo_dir: "plane-streaming",
    base: "faa7d5bc8f5d01ca9ebfb4bef3fa6debd4f44a78",
    rev: "55f953f3a450cfc4a1624f809dc4c69e06aa3243",
    edited: &[
        (
            "Cargo.toml",
            "the plugin workspace's manifest: dependencies `{ workspace = true }` and busbar-contract \
             by git rev at .busbar-ref, not path dependencies into this tree",
        ),
        (
            "src/door.rs",
            "the module doc names the cdylib twin (`busbar-plane-streaming-plugin`) that now \
             exports the door, not the deleted `examples/streaming_door.rs`",
        ),
        (
            "src/codec/ir/codec/tests.rs",
            "the captured response.done fixture is read from busbar's checkout at .busbar-ref \
             (BUSBAR_CHECKOUT, unset is a failure), not by a relative path into this tree",
        ),
    ],
    moved: &[
        (
            "tests/conformance.rs",
            "plane-streaming-plugin/tests/both_ways.rs",
            "the door's op-by-op both-ways script runs in the cdylib twin, against its dropped image",
        ),
        (
            "examples/streaming_door.rs",
            "plane-streaming-plugin/src/lib.rs",
            "the dropped-in door is the cdylib twin crate, not an example",
        ),
    ],
    added: &[(
        "declares.json",
        "the plugin's declares section, which a dropped-in copy signs (a repository plugin's own)",
    )],
}];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask has a parent")
        .to_path_buf()
}

fn git(dir: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let out = Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .map_err(|e| format!("git {args:?}: {e}"))?;
    if out.status.success() {
        Ok(out.stdout)
    } else {
        Err(format!(
            "git {args:?} ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

fn text(b: Vec<u8>) -> String {
    String::from_utf8_lossy(&b).into_owned()
}

/// A repository the test reads: busbar's own checkout (paths from its root), or a fetched store.
enum Repo<'a> {
    /// This checkout, run from its root.
    Checkout(&'a Path),
    /// A bare store, always named by `--git-dir`. It lives under this checkout's `target/`, inside
    /// busbar's work tree, so git's discovery from that directory finds BUSBAR's repository: the
    /// fetch lands in busbar's object store and every path is read under the `target/...` prefix,
    /// which holds nothing, so the copy reads as empty.
    Store(&'a Path),
}

impl Repo<'_> {
    fn git(&self, args: &[&str]) -> Result<Vec<u8>, String> {
        match self {
            Repo::Checkout(dir) => git(dir, args),
            Repo::Store(dir) => {
                let flag = format!("--git-dir={}", dir.display());
                let mut all = vec![flag.as_str()];
                all.extend_from_slice(args);
                git(dir, &all)
            }
        }
    }
}

/// Every file under `dir` at `rev` in `repo`, by path relative to `dir` (`.` is the whole tree).
fn tree(repo: &Repo, rev: &str, dir: &str) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let names = text(repo.git(&["ls-tree", "-r", "--name-only", rev, "--", dir])?);
    let mut out = BTreeMap::new();
    for name in names.lines().filter(|l| !l.is_empty()) {
        let rel = name
            .strip_prefix(&format!("{dir}/"))
            .unwrap_or(name)
            .to_string();
        out.insert(rel, repo.git(&["show", &format!("{rev}:{name}")])?);
    }
    Ok(out)
}

/// The findings of one comparison: `base` (the crate as busbar held it), `copy` (the repository's
/// logic crate at `rev`) and `elsewhere` (every other path of the repository at `rev`).
fn compare(
    e: &Extraction,
    base: &BTreeMap<String, Vec<u8>>,
    copy: &BTreeMap<String, Vec<u8>>,
    elsewhere: &BTreeMap<String, Vec<u8>>,
) -> Vec<String> {
    let edited: BTreeMap<&str, &str> = e.edited.iter().copied().collect();
    let added: BTreeMap<&str, &str> = e.added.iter().copied().collect();
    let moved: BTreeMap<&str, &str> = e.moved.iter().map(|(f, t, _)| (*f, *t)).collect();
    let mut bad = Vec::new();
    for (path, bytes) in base {
        if let Some(to) = moved.get(path.as_str()) {
            if !elsewhere.contains_key(*to) {
                bad.push(format!(
                    "{path} moved to {to}, which the repository does not hold"
                ));
            }
            if copy.contains_key(path) {
                bad.push(format!(
                    "{path} is named moved but the logic crate still holds it"
                ));
            }
            continue;
        }
        match copy.get(path) {
            None => bad.push(format!("{path} is in busbar's crate and not in the copy")),
            Some(c) if c == bytes && edited.contains_key(path.as_str()) => bad.push(format!(
                "{path} is named an extraction edit but is identical: strike the entry"
            )),
            Some(c) if c != bytes && !edited.contains_key(path.as_str()) => bad.push(format!(
                "{path} differs from busbar's crate at {} and is no reviewed extraction edit",
                e.base
            )),
            Some(_) => {}
        }
    }
    for path in copy.keys() {
        if !base.contains_key(path) && !added.contains_key(path.as_str()) {
            bad.push(format!(
                "{path} is in the copy and was never in busbar's crate"
            ));
        }
    }
    for path in added.keys() {
        if !copy.contains_key(*path) {
            bad.push(format!(
                "{path} is named added but the copy does not hold it"
            ));
        }
    }
    bad
}

/// A bare store at `dir`, made if absent. Bare and named by `--git-dir` (see `Repo::Store`).
fn store(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|err| format!("{}: {err}", dir.display()))?;
    if !dir.join("HEAD").is_file() {
        let path = dir.display().to_string();
        git(dir, &["init", "-q", "--bare", &path])?;
    }
    Ok(())
}

/// `what` (a commit, or a ref the source names) from `url` into the store at `dir`, shallow.
fn fetch_into(dir: &Path, url: &str, what: &str) -> Result<(), String> {
    store(dir)?;
    let repo = Repo::Store(dir);
    if repo
        .git(&["cat-file", "-e", &format!("{what}^{{commit}}")])
        .is_err()
    {
        repo.git(&["fetch", "-q", "--depth", "1", url, what])?;
    }
    Ok(())
}

/// The repository at `rev`, fetched into a store in this checkout's target directory.
fn fetch(e: &Extraction) -> Result<PathBuf, String> {
    let name = e.repo.rsplit('/').next().unwrap_or("repo");
    let dir = root()
        .join("target")
        .join("extracted-planes")
        .join(format!("{name}.git"));
    fetch_into(&dir, e.repo, e.rev)?;
    Ok(dir)
}

#[test]
fn an_extracted_plane_is_the_tree_busbar_held() {
    let here = root();
    for e in EXTRACTIONS {
        // DEV MOVED ON: after the base, only the crate's deletion may touch it.
        git(
            &here,
            &["cat-file", "-e", &format!("{}^{{commit}}", e.base)],
        )
        .unwrap_or_else(|err| {
            panic!(
                "{}: the copy's base {} is not in this checkout's history: {err}",
                e.crate_dir, e.base
            )
        });
        let after = text(
            git(
                &here,
                &[
                    "log",
                    "--format=%H",
                    "--no-merges",
                    &format!("{}..HEAD", e.base),
                    "--",
                    e.crate_dir,
                ],
            )
            .expect("git log over the crate after the base"),
        );
        for commit in after.lines().filter(|l| !l.is_empty()) {
            let kinds = text(
                git(
                    &here,
                    &[
                        "diff-tree",
                        "--no-commit-id",
                        "-r",
                        "--name-status",
                        commit,
                        "--",
                        e.crate_dir,
                    ],
                )
                .expect("git diff-tree"),
            );
            let kept: Vec<&str> = kinds.lines().filter(|l| !l.starts_with('D')).collect();
            assert!(
                kept.is_empty(),
                "{}: {commit} changed the crate after the copy's base {} (only its deletion may \
                 follow the base), so the extracted copy does not hold it; re-copy from a dev \
                 that contains it:\n{}",
                e.crate_dir,
                e.base,
                kept.join("\n")
            );
        }
        // THE COPY DRIFTED: the repository at `rev` against the crate at `base`.
        let base =
            tree(&Repo::Checkout(&here), e.base, e.crate_dir).expect("busbar's crate at the base");
        assert!(!base.is_empty(), "{}: no files at {}", e.crate_dir, e.base);
        let repo = fetch(e).unwrap_or_else(|err| {
            panic!("{}: fetching {} at {}: {err}", e.crate_dir, e.repo, e.rev)
        });
        let copy = tree(&Repo::Store(&repo), e.rev, e.repo_dir).expect("the copy at rev");
        let elsewhere = tree(&Repo::Store(&repo), e.rev, ".").expect("the repository at rev");
        let bad = compare(e, &base, &copy, &elsewhere);
        assert!(
            bad.is_empty(),
            "{} at {} is not {} as busbar held it at {}:\n{}",
            e.repo,
            e.rev,
            e.crate_dir,
            e.base,
            bad.join("\n")
        );
    }
}

/// RED: the comparison sees every way a copy can be wrong (a changed file, a dropped file, a stray
/// file, an edit entry that is stale), and passes a faithful copy.
#[test]
fn the_comparison_refuses_a_drifted_copy() {
    let e = &EXTRACTIONS[0];
    let mut base = BTreeMap::new();
    base.insert("src/lib.rs".to_string(), b"lib".to_vec());
    base.insert("Cargo.toml".to_string(), b"busbar manifest".to_vec());
    base.insert("src/door.rs".to_string(), b"door".to_vec());
    base.insert("src/codec/ir/codec/tests.rs".to_string(), b"t".to_vec());
    base.insert("tests/conformance.rs".to_string(), b"c".to_vec());
    base.insert("examples/streaming_door.rs".to_string(), b"x".to_vec());
    let mut elsewhere = BTreeMap::new();
    elsewhere.insert(
        "plane-streaming-plugin/tests/both_ways.rs".to_string(),
        b"c".to_vec(),
    );
    elsewhere.insert(
        "plane-streaming-plugin/src/lib.rs".to_string(),
        b"x".to_vec(),
    );
    let faithful = |base: &BTreeMap<String, Vec<u8>>| {
        let mut c: BTreeMap<String, Vec<u8>> = base
            .iter()
            .filter(|(k, _)| !k.starts_with("tests/") && !k.starts_with("examples/"))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (path, _) in e.edited {
            c.insert((*path).to_string(), b"edited".to_vec());
        }
        c.insert("declares.json".to_string(), b"{}".to_vec());
        c
    };
    assert!(compare(e, &base, &faithful(&base), &elsewhere).is_empty());

    let mut changed = faithful(&base);
    changed.insert("src/lib.rs".to_string(), b"lib, changed".to_vec());
    assert_eq!(compare(e, &base, &changed, &elsewhere).len(), 1);

    let mut dropped = faithful(&base);
    dropped.remove("src/lib.rs");
    assert_eq!(compare(e, &base, &dropped, &elsewhere).len(), 1);

    let mut stray = faithful(&base);
    stray.insert("src/new.rs".to_string(), b"n".to_vec());
    assert_eq!(compare(e, &base, &stray, &elsewhere).len(), 1);

    let mut stale = faithful(&base);
    stale.insert("src/door.rs".to_string(), b"door".to_vec());
    assert_eq!(compare(e, &base, &stale, &elsewhere).len(), 1);
}

/// RED: a store under this checkout's `target/` is its own repository. The comparison once read a
/// fetched copy through git's discovery from that directory, which found busbar's repository
/// instead: every file of the plane read as "not in the copy". Here a one-file repository is
/// fetched into such a store and its tree must come back whole.
#[test]
fn a_store_inside_the_checkout_reads_the_fetched_tree_not_busbars() {
    let scratch = root()
        .join("target")
        .join("extracted-planes")
        .join(format!("selftest-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    let src = scratch.join("src");
    std::fs::create_dir_all(src.join("plane")).expect("the source's directory");
    std::fs::write(src.join("plane").join("lib.rs"), b"held").expect("the source's file");
    let src_path = src.display().to_string();
    git(&src, &["init", "-q", &src_path]).expect("git init the source");
    git(&src, &["add", "plane/lib.rs"]).expect("git add");
    git(
        &src,
        &[
            "-c",
            "user.name=extracted-planes",
            "-c",
            "user.email=extracted-planes@invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "-q",
            "-m",
            "one file",
        ],
    )
    .expect("git commit");
    let rev = text(git(&src, &["rev-parse", "HEAD"]).expect("the source's head"));
    let rev = rev.trim();

    let dir = scratch.join("copy.git");
    fetch_into(&dir, &format!("file://{src_path}"), "HEAD").expect("fetch into the store");
    let copy = tree(&Repo::Store(&dir), rev, "plane").expect("the fetched copy");
    assert_eq!(
        copy.into_iter().collect::<Vec<_>>(),
        vec![("lib.rs".to_string(), b"held".to_vec())],
        "the store read something other than the tree it fetched"
    );
    let whole = tree(&Repo::Store(&dir), rev, ".").expect("the fetched repository");
    assert_eq!(whole.keys().collect::<Vec<_>>(), vec!["plane/lib.rs"]);
    let _ = std::fs::remove_dir_all(&scratch);
}
