//! `Ctx` — the shared context every gate reads the tree through, and the overlay that lets a
//! self-test plant a violation without a scratch copy, a restore step or a hand-maintained
//! `TOUCHED` list (the fragile half of `scripts/construction-gate/plant.py`). An overlay is *by
//! construction* per-plant: `with_overlay` returns a new `Ctx` and never mutates the base, so
//! plants cannot stack and "exactly one FAIL row" can never be produced by a leftover.
//!
//! [`WalkSpec`] reproduces the tree's dominant `find` idiom
//! (`find crates -name '*.rs' -not -path '*/tests/*' | sort`) including the sort, several gates'
//! outputs being order-sensitive — and including the two things `find` gets wrong:
//! a missing root is silently dropped, and an empty result reads exactly like a clean tree. Here a
//! missing root is [`WalkError::MissingRoot`] and a result under [`WalkSpec::min_files`] is
//! [`WalkError::BelowFloor`]. The floor is not optional decoration; it is the single most repeated
//! fix in the shell gates it replaces.
//!
//! It also gets one thing `find` never knew: the walk HONOURS THE TREE'S OWN IGNORE RULES
//! ([`Ctx::drop_ignored`]). A scan set that includes whatever a build, a cache or an editor left
//! behind is a gate that goes red on a byte nobody wrote — `testing/shadow-oracle/__pycache__` is
//! the case that proved it — and a gate that reds for a reason unrelated to its rule is how a
//! runner earns a `|| true`. The two refusals are unaffected: they are evaluated around the filter,
//! not through it, so an ignore rule that swallowed a scan set trips the floor.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use crate::gitp;
use crate::scan;

/// What an overlay says about one path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// The file's bytes, as the gate must see them.
    Content(String),
    /// The file is absent, whatever the real tree says.
    Absent,
    /// The path IS there — a walk lists it — and reading it FAILS.
    ///
    /// It is a third state because "absent" and "unreadable" are two different claims and the gates
    /// answer them differently: an absent input is often a tree that legitimately has not got one,
    /// while an input that is listed and will not read is an input the rule cannot measure and must
    /// refuse. Every gate that treats a read error as "found nothing" is a gate that goes green on
    /// a corrupt tree, and there was no fixture in the harness that could plant one.
    Unreadable(String),
}

/// A per-plant view of the tree: path overrides plus canned outputs for the few derived inputs
/// (today `cargo metadata`) a gate cannot read as a file.
#[derive(Debug, Clone, Default)]
pub struct Overlay {
    files: BTreeMap<PathBuf, Change>,
    commands: BTreeMap<String, String>,
}

impl Overlay {
    pub fn new() -> Overlay {
        Overlay::default()
    }

    pub fn set(&mut self, rel: impl AsRef<Path>, content: impl Into<String>) {
        self.files
            .insert(rel.as_ref().to_path_buf(), Change::Content(content.into()));
    }

    pub fn remove(&mut self, rel: impl AsRef<Path>) {
        self.files
            .insert(rel.as_ref().to_path_buf(), Change::Absent);
    }

    /// The path stays in every walk and every read of it fails with `why`.
    pub fn unreadable(&mut self, rel: impl AsRef<Path>, why: impl Into<String>) {
        self.files
            .insert(rel.as_ref().to_path_buf(), Change::Unreadable(why.into()));
    }

    /// Override a derived input keyed by a stable string (e.g. `cargo-metadata:xtask/Cargo.toml`).
    pub fn set_command(&mut self, key: impl Into<String>, stdout: impl Into<String>) {
        self.commands.insert(key.into(), stdout.into());
    }

    pub fn paths(&self) -> impl Iterator<Item = &PathBuf> {
        self.files.keys()
    }

    /// A derived input this overlay stands in for, by its key.
    pub fn command(&self, key: &str) -> Option<&String> {
        self.commands.get(key)
    }
}

/// A planted edit. `apply` reads through the [`Ctx`] it is given, so an edit is always expressed
/// against what the gate would otherwise have seen.
#[derive(Debug, Clone)]
pub enum Edit {
    Append(String),
    Replace(String),
    Create(String),
    Delete,
}

impl Edit {
    pub fn apply(&self, cx: &Ctx, rel: impl AsRef<Path>, ov: &mut Overlay) -> Result<(), String> {
        let rel = rel.as_ref();
        match self {
            Edit::Append(s) => {
                let mut base = cx.read(rel)?;
                base.push_str(s);
                ov.set(rel, base);
            }
            Edit::Replace(s) => {
                cx.read(rel)?;
                ov.set(rel, s.clone());
            }
            Edit::Create(s) => {
                if cx.exists(rel) {
                    return Err(format!(
                        "{}: Create planted over a file that already exists",
                        rel.display()
                    ));
                }
                ov.set(rel, s.clone());
            }
            Edit::Delete => {
                if !cx.exists(rel) {
                    return Err(format!(
                        "{}: Delete planted over a file that is already absent",
                        rel.display()
                    ));
                }
                ov.remove(rel);
            }
        }
        Ok(())
    }
}

/// A file the walk yielded.
#[derive(Debug, Clone)]
pub struct SourceFile {
    /// Path relative to the workspace root, `/`-separated in its string form.
    pub rel: PathBuf,
    pub abs: PathBuf,
    pub text: String,
}

impl SourceFile {
    pub fn rel_str(&self) -> String {
        self.rel.to_string_lossy().replace('\\', "/")
    }

    /// The file's production lines, through the one scanner.
    pub fn production_lines(&self) -> Vec<(usize, String)> {
        scan::production_lines(&self.text)
    }
}

#[derive(Debug, Clone, Default)]
pub struct WalkSpec {
    roots: Vec<String>,
    ext: Option<String>,
    exclude: Vec<String>,
    min_files: usize,
}

impl WalkSpec {
    pub fn new<I, S>(roots: I) -> WalkSpec
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        WalkSpec {
            roots: roots.into_iter().map(Into::into).collect(),
            ..WalkSpec::default()
        }
    }

    pub fn ext(mut self, ext: impl Into<String>) -> WalkSpec {
        self.ext = Some(ext.into());
        self
    }

    /// Path fragments matched against the `/`-prefixed relative path, the `-not -path '*/tests/*'`
    /// half of the idiom.
    pub fn exclude<I, S>(mut self, fragments: I) -> WalkSpec
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.exclude.extend(fragments.into_iter().map(Into::into));
        self
    }

    /// The denominator floor. A walk that yields fewer files than this is an error, not a pass.
    pub fn min_files(mut self, n: usize) -> WalkSpec {
        self.min_files = n;
        self
    }

    pub fn roots(&self) -> &[String] {
        &self.roots
    }
}

#[derive(Debug, Clone)]
pub enum WalkError {
    MissingRoot {
        root: String,
    },
    BelowFloor {
        found: usize,
        floor: usize,
        roots: Vec<String>,
    },
    Io {
        path: PathBuf,
        message: String,
    },
}

impl fmt::Display for WalkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WalkError::MissingRoot { root } => write!(
                f,
                "walk root `{root}` does not exist. `find` drops a missing root silently and then \
                 scans nothing of it, and zero is the passing answer to every ban — so a root that \
                 moved is an error here, never a narrower scan."
            ),
            WalkError::BelowFloor {
                found,
                floor,
                roots,
            } => write!(
                f,
                "walk over [{}] yielded {found} file(s), under its floor of {floor}. An empty or \
                 shrunken scan reads exactly like a clean tree; it is not one.",
                roots.join(", ")
            ),
            WalkError::Io { path, message } => write!(f, "walk {}: {message}", path.display()),
        }
    }
}

/// Environment the gates read, captured once so a gate never reaches for `std::env` itself.
#[derive(Debug, Clone, Default)]
pub struct Env {
    pub github_step_summary: Option<PathBuf>,
    pub runner_temp: Option<PathBuf>,
    pub report_only: bool,
    /// `--write`: the gate REGENERATES the artefact it otherwise only diffs. A generator's write
    /// arm and its drift arm are the same derivation, so they cannot disagree; what the flag
    /// changes is whether the answer is compared or committed.
    pub write: bool,
    /// `CONFIG_SCHEMA_BASELINE_REF` — which git ref the config-schema gate's additive-only check
    /// reads its baseline from. Captured here rather than read by the gate because
    /// `scripts/verify-1.6.0-done.sh` refuses a DONE run that sets it, and a variable a gate reads
    /// straight out of the process environment is one no runner can see it reading.
    pub config_baseline_ref: Option<String>,
    /// `CONFIG_SCHEMA_BOOTSTRAP` — that gate's declared, one-run escape from having no baseline at
    /// all. Declared, never inferred; it announces itself and it is not a pass.
    pub config_bootstrap: bool,
    /// `BUSBAR_GATE_BASE_REF` — THE ONE VARIABLE THAT SAYS WHICH COMMIT IS "THE BASE".
    ///
    /// Every ratchet in this binary that asks history a question asks it of ONE resolver,
    /// [`crate::gates::construction::ceilings::base_ref`], and this is the only thing that moves
    /// it. Captured here on exactly the terms `config_baseline_ref` is captured on: a variable a
    /// gate reads straight out of the process environment is one no runner can see it reading, and
    /// `scripts/verify-1.6.0-done.sh` refuses a DONE run that sets it for the same reason it
    /// refuses the other repointing variables — a run pointed at a base of the operator's choosing
    /// is not a run measured against the pinned reference.
    ///
    /// Empty is UNSET rather than "the empty ref": an exported-but-blank variable in a CI shell is
    /// the ordinary way a variable is not set, and reading it as a ref would make every such run
    /// refuse for a reason nobody wrote down.
    pub gate_base_ref: Option<String>,
}

impl Env {
    fn capture() -> Env {
        Env {
            github_step_summary: std::env::var_os("GITHUB_STEP_SUMMARY").map(PathBuf::from),
            runner_temp: std::env::var_os("RUNNER_TEMP").map(PathBuf::from),
            report_only: false,
            write: false,
            config_baseline_ref: std::env::var("CONFIG_SCHEMA_BASELINE_REF")
                .ok()
                .filter(|s| !s.is_empty()),
            config_bootstrap: std::env::var("CONFIG_SCHEMA_BOOTSTRAP").as_deref() == Ok("1"),
            gate_base_ref: std::env::var("BUSBAR_GATE_BASE_REF")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.trim().to_string()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Ctx {
    root: PathBuf,
    overlay: Option<Arc<Overlay>>,
    scratch: PathBuf,
    env: Env,
}

impl Ctx {
    /// Open a context over `root`, proving the scratch directory writable BY WRITING A BYTE rather
    /// than by asking the filesystem whether it thinks it is writable.
    pub fn new(root: impl Into<PathBuf>) -> Result<Ctx, String> {
        let root = root.into();
        let scratch = root.join(".fix").join("xtask");
        std::fs::create_dir_all(&scratch)
            .map_err(|e| format!("scratch {}: {e}", scratch.display()))?;
        // A UNIQUE probe per opener: two contexts opening at once must not race each other's
        // cleanup and report an unwritable scratch dir that is perfectly writable.
        let probe = scratch.join(format!(
            ".writable-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&probe, b"x").map_err(|e| format!("scratch {}: {e}", probe.display()))?;
        std::fs::remove_file(&probe).map_err(|e| format!("scratch {}: {e}", probe.display()))?;
        Ok(Ctx {
            root,
            overlay: None,
            scratch,
            env: Env::capture(),
        })
    }

    /// A context over `root` whose scratch dir is somewhere else — for driving a gate over a
    /// fixture tree without writing a byte into it.
    pub fn at(root: impl Into<PathBuf>, scratch: impl Into<PathBuf>) -> Result<Ctx, String> {
        let scratch = scratch.into();
        std::fs::create_dir_all(&scratch)
            .map_err(|e| format!("scratch {}: {e}", scratch.display()))?;
        Ok(Ctx {
            root: root.into(),
            overlay: None,
            scratch,
            env: Env::capture(),
        })
    }

    /// The workspace root, from `xtask/Cargo.toml`'s own directory's parent.
    pub fn workspace() -> Result<Ctx, String> {
        Ctx::new(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .ok_or("xtask/Cargo.toml has no parent directory")?
                .to_path_buf(),
        )
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn scratch(&self) -> &Path {
        &self.scratch
    }

    pub fn env(&self) -> &Env {
        &self.env
    }

    pub fn report_only(mut self, yes: bool) -> Ctx {
        self.env.report_only = yes;
        self
    }

    pub fn write_mode(mut self, yes: bool) -> Ctx {
        self.env.write = yes;
        self
    }

    /// A FRESH context whose base is the one named here, as `BUSBAR_GATE_BASE_REF` would have
    /// named it. This is how the self-test drives the base seam: the variable is captured once, in
    /// [`Env::capture`], so a case that wants a different base cannot set it in the process — two
    /// cases running in the same binary would then be reading each other's environment — and asks
    /// for a context instead.
    pub fn with_base_ref(mut self, r: Option<String>) -> Ctx {
        self.env.gate_base_ref = r;
        self
    }

    /// A FRESH context with this overlay. The base is untouched.
    pub fn with_overlay(&self, overlay: Overlay) -> Ctx {
        Ctx {
            overlay: Some(Arc::new(overlay)),
            ..self.clone()
        }
    }

    pub fn overlay(&self) -> Option<&Overlay> {
        self.overlay.as_deref()
    }

    /// A canned derived input, when one has been planted. The gates that delegate a measurement to
    /// another instrument read it through here, so a self-test can plant that instrument's ANSWER
    /// — an overlay lives in this process and a subprocess cannot see it.
    pub fn overlay_command(&self, key: &str) -> Option<String> {
        self.overlay().and_then(|o| o.command(key)).cloned()
    }

    pub fn abs(&self, rel: impl AsRef<Path>) -> PathBuf {
        self.root.join(rel)
    }

    /// Read a file, consulting the overlay first.
    pub fn read(&self, rel: impl AsRef<Path>) -> Result<String, String> {
        let rel = rel.as_ref();
        if let Some(ov) = self.overlay() {
            match ov.files.get(rel) {
                Some(Change::Content(c)) => return Ok(c.clone()),
                Some(Change::Absent) => {
                    return Err(format!("{}: absent (overlay)", rel.display()));
                }
                Some(Change::Unreadable(why)) => {
                    return Err(format!("{}: {why} (overlay)", rel.display()));
                }
                None => {}
            }
        }
        std::fs::read_to_string(self.abs(rel)).map_err(|e| format!("{}: {e}", rel.display()))
    }

    pub fn exists(&self, rel: impl AsRef<Path>) -> bool {
        let rel = rel.as_ref();
        if let Some(ov) = self.overlay() {
            match ov.files.get(rel) {
                Some(Change::Content(_)) => return true,
                // An unreadable file IS on disk; it is the READ that fails, not the stat.
                Some(Change::Unreadable(_)) => return true,
                Some(Change::Absent) => return false,
                None => {}
            }
        }
        self.abs(rel).exists()
    }

    /// The repo walk. Sorted, floor-checked, missing-root-checked, overlay-aware.
    pub fn walk(&self, spec: &WalkSpec) -> Result<Vec<SourceFile>, WalkError> {
        let kept = self.list(spec)?;
        let mut out = Vec::new();
        for rel in kept {
            let text = self.read(&rel).map_err(|message| WalkError::Io {
                path: rel.clone(),
                message,
            })?;
            out.push(SourceFile {
                abs: self.abs(&rel),
                rel,
                text,
            });
        }
        out.sort_by_key(SourceFile::rel_str);

        if out.len() < spec.min_files {
            return Err(WalkError::BelowFloor {
                found: out.len(),
                floor: spec.min_files,
                roots: spec.roots.clone(),
            });
        }
        Ok(out)
    }

    /// THE WALK WITHOUT THE READ — the same roots, the same overlay, the same ignore rules, the
    /// same ext and exclude filters, sorted, and NO floor.
    ///
    /// It exists because a caller that wants EVERY file a crate ships cannot ask [`Self::walk`] for
    /// it: `walk` reads each path as UTF-8 and a repository is entitled to carry a `.gz` or a
    /// `.png`. A caller that must SKIP those and still be able to NAME the ones it skipped needs
    /// the list before the read, which is this. The floor stays with `walk` because the floor is a
    /// property of a scan set, and a list is not yet one.
    pub fn list(&self, spec: &WalkSpec) -> Result<Vec<PathBuf>, WalkError> {
        let mut rels: Vec<PathBuf> = Vec::new();
        for root in &spec.roots {
            let abs = self.abs(root);
            let overlay_adds_it = self
                .overlay()
                .map(|ov| {
                    ov.paths()
                        .any(|p| p.to_string_lossy().starts_with(&format!("{root}/")))
                })
                .unwrap_or(false);
            if !abs.exists() && !overlay_adds_it {
                return Err(WalkError::MissingRoot { root: root.clone() });
            }
            collect(&abs, &self.root, &mut rels)?;
        }

        if let Some(ov) = self.overlay() {
            for (path, change) in &ov.files {
                let s = path.to_string_lossy().replace('\\', "/");
                // `.` IS THE WHOLE TREE, AND A PLANT INTO A DIRECTORY THAT DOES NOT EXIST YET IS
                // STILL UNDER IT. A gate that walks the repository for every manifest — the census
                // `kind-isolation:registry` runs — is proven by planting `vendor/…/Cargo.toml`,
                // and the prefix test `"vendor/…".starts_with("./")` is false, so the plant would
                // have been filtered out of the very walk it exists to be found by.
                let under_a_root = spec
                    .roots
                    .iter()
                    .any(|r| r == "." || s.starts_with(&format!("{r}/")) || &s == r);
                match change {
                    Change::Absent => rels.retain(|p| p != path),
                    Change::Unreadable(_) | Change::Content(_) => {
                        if under_a_root && !rels.contains(path) {
                            rels.push(path.clone());
                        }
                    }
                }
            }
        }

        let mut kept: Vec<PathBuf> = Vec::new();
        for rel in rels {
            let s = rel.to_string_lossy().replace('\\', "/");
            if let Some(ext) = &spec.ext {
                if !s.ends_with(&format!(".{ext}")) {
                    continue;
                }
            }
            let probe = format!("/{s}");
            if spec
                .exclude
                .iter()
                .any(|frag| probe.contains(frag.as_str()))
            {
                continue;
            }
            kept.push(rel);
        }
        let mut kept = self.drop_ignored(kept);
        kept.sort();
        Ok(kept)
    }

    /// Drop the paths the working tree's own ignore rules exclude.
    ///
    /// `find` has no idea what `.gitignore` says, so a walk that reproduced it exactly read
    /// whatever a build, a cache or an editor happened to leave in the tree — and a gate whose scan
    /// set includes `__pycache__/*.pyc` fails on a byte nobody wrote and nobody can fix by editing
    /// source. That is not a stricter gate; it is a gate that goes red for a reason unrelated to the
    /// rule, which is how a runner earns a `|| true`.
    ///
    /// Two refusals stay exactly where they were: a MISSING ROOT and a set BELOW ITS FLOOR are
    /// still errors, and the floor is applied AFTER this filter, so an ignore rule that swallowed
    /// the scan set is caught by the floor rather than reported as a clean tree.
    ///
    /// AN UNUSABLE IGNORE ORACLE FILTERS NOTHING. Over a throwaway fixture tree there is no
    /// repository to ask, and a `git` that cannot answer must leave the walk WIDER rather than
    /// narrower: the failure direction of this helper is "a ban scanned a file it need not have",
    /// never "a ban stopped scanning".
    ///
    /// AN OVERLAY PLANT IS FILTERED ON THE SAME TERMS as a file on disk, and that is not an
    /// oversight. The overlay exists to show a gate the tree a real commit would show it; a plant
    /// into an ignored path is a file CI would never see, so a gate that went red on one would be
    /// proven by a fixture the rule cannot encounter. It is also what makes this filter provable
    /// at all — the self-test plants an ignored file and requires the gate to stay green.
    /// THE IGNORE FILTER, EXPOSED — for the one rule whose subject IS the ignore list rather than
    /// its effect.
    ///
    /// [`Ctx::drop_ignored`] uses this to keep a build artefact out of a scan set, which is the
    /// right answer for every rule that reads source. It is the WRONG answer for a file the
    /// compiler links: `crates/*/src/target/leak.rs` is dropped by the walker and by the bare
    /// `target/` in `.gitignore`, and compiled anyway. A rule that wants to say so has to be able
    /// to ask which paths the filter claims, so it can ask that question of the COMPILED set.
    ///
    /// A tracked path is never reported by `git check-ignore` (it consults the index), so the
    /// answer is exactly the population that is both ignored and live.
    pub fn ignored(&self, rels: &[String]) -> std::collections::BTreeSet<String> {
        gitp::check_ignore(&self.root, rels)
            .unwrap_or_default()
            .into_iter()
            .collect()
    }

    fn drop_ignored(&self, rels: Vec<PathBuf>) -> Vec<PathBuf> {
        let asked: Vec<String> = rels
            .iter()
            .map(|r| r.to_string_lossy().replace('\\', "/"))
            .collect();
        let Ok(ignored) = gitp::check_ignore(&self.root, &asked) else {
            return rels;
        };
        if ignored.is_empty() {
            return rels;
        }
        let ignored: std::collections::BTreeSet<String> = ignored.into_iter().collect();
        rels.into_iter()
            .filter(|r| !ignored.contains(&r.to_string_lossy().replace('\\', "/")))
            .collect()
    }

    /// Write the overlaid view of `paths` into `dest`, for the gates not yet converted that must
    /// still shell out over a tree on disk.
    pub fn materialize(&self, dest: &Path, paths: &[&str]) -> Result<(), String> {
        for rel in paths {
            let content = self.read(rel)?;
            let target = dest.join(rel);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("{}: {e}", parent.display()))?;
            }
            std::fs::write(&target, content).map_err(|e| format!("{}: {e}", target.display()))?;
        }
        Ok(())
    }

    /// `git`, as a process, always `-C <root>`, never a `cd`.
    pub fn git(&self, args: &[&str]) -> Result<String, String> {
        gitp::git(&self.root, args)
    }

    pub fn git_lines(&self, args: &[&str]) -> Result<Vec<String>, String> {
        gitp::git_lines(&self.root, args)
    }

    /// Does `r` name a commit this repository can resolve?
    ///
    /// SYNTHETIC REFS ARE DECLARED, NOT DISCOVERED. An overlay may plant `git-ref:<r>` to describe
    /// a ref that does not exist in the real repository, which is what lets the config-schema
    /// gate's self-test drive its baseline arms — a ref that does not resolve, a ref that resolves
    /// and carries no snapshot, a ref carrying a PLANTED baseline — without writing an object, a
    /// branch or a commit into the tree the developer is standing in. `"1"` resolves, anything else
    /// does not.
    ///
    /// A ref the overlay says nothing about is asked of git, so the ordinary run is unaffected.
    pub fn git_ref_resolves(&self, r: &str) -> bool {
        if let Some(planted) = self.planted_ref(r) {
            return planted == "1";
        }
        gitp::git(
            &self.root,
            &[
                "rev-parse",
                "--verify",
                "--quiet",
                &format!("{r}^{{commit}}"),
            ],
        )
        .is_ok()
    }

    /// `git show <r>:<path>` — the bytes `path` had at `r`, never the working tree's.
    ///
    /// THE BASELINE IS READ FROM A REF FOR A REASON: rewriting the committed snapshot must not be
    /// able to launder a break, so the additive check's left-hand side comes from history and not
    /// from the file the same commit is free to edit.
    ///
    /// A SYNTHETIC REF IS ANSWERED ENTIRELY FROM THE OVERLAY. When `git-ref:<r>` is planted, this
    /// ref is the self-test's and git is never consulted: an overlay that planted the ref but no
    /// `git-show:<r>:<path>` is describing a ref that RESOLVES AND CARRIES NO SUCH FILE, which is
    /// the arm that used to be a free bypass and must stay reachable in a test. Falling through to
    /// the real repository there would answer with the real HEAD's snapshot and quietly turn that
    /// case green.
    pub fn git_show(&self, r: &str, path: &str) -> Result<String, String> {
        let key = format!("git-show:{r}:{path}");
        if let Some(ov) = self.overlay() {
            if let Some(out) = ov.commands.get(&key) {
                return Ok(out.clone());
            }
        }
        if self.planted_ref(r).is_some() {
            return Err(format!(
                "ref '{r}' resolves but carries no {path} (planted)"
            ));
        }
        gitp::git(&self.root, &["show", &format!("{r}:{path}")])
    }

    /// The overlay's answer for `git-ref:<r>`, if it planted one.
    fn planted_ref(&self, r: &str) -> Option<&str> {
        self.overlay()?
            .commands
            .get(&format!("git-ref:{r}"))
            .map(String::as_str)
    }

    /// Run a command and REFUSE to hand back stdout on a non-zero status. The shell's
    /// `h=$(scan "$f") || true` discarded its producer's exit status, so a broken scanner produced
    /// empty output for every file and read as "no findings" gate-wide.
    pub fn run_checked(&self, program: &str, args: &[String]) -> Result<String, String> {
        let out = Command::new(program)
            .args(args)
            .current_dir(&self.root)
            .output()
            .map_err(|e| format!("{program}: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "{program} {} exited {}: {}",
                args.join(" "),
                out.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        String::from_utf8(out.stdout).map_err(|e| format!("{program}: non-utf8 stdout: {e}"))
    }

    /// `cargo tree -e no-dev … -f {p}`, overlay-overridable on the same terms as
    /// [`Ctx::cargo_metadata`].
    ///
    /// THE RESOLVE IS SEPARATED FROM THE COUNT, and that separation is the whole point.
    /// `cargo tree … 2>/dev/null | grep -c` folded four different things into the number 0: the
    /// crate is absent (the answer a ban wants), cargo is not installed, a feature name in the
    /// argument list no longer exists, and the workspace does not build. Three of those are
    /// failures and all three printed the ban's PASS with the diagnostic already discarded. So a
    /// non-zero status is an `Err`, and so is a tree that resolved and named NO PACKAGE AT ALL —
    /// "absent" is exactly the claim an unresolved tree fakes.
    pub fn cargo_tree(&self, args: &[&str]) -> Result<String, String> {
        let key = format!("cargo-tree:{}", args.join(" "));
        if let Some(ov) = self.overlay() {
            if let Some(out) = ov.commands.get(&key) {
                return if out.trim().is_empty() {
                    Err(format!(
                        "`cargo tree {}` resolved and named no package at all. A tree with no \
                         packages in it carries no crate, and carrying no crate is the passing \
                         answer to every dependency ban.",
                        args.join(" ")
                    ))
                } else {
                    Ok(out.clone())
                };
            }
        }
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
        let mut argv: Vec<String> = vec!["tree".into(), "-e".into(), "no-dev".into()];
        argv.extend(args.iter().map(|a| (*a).to_string()));
        argv.push("-f".into());
        argv.push("{p}".into());
        let out = self.run_checked(&cargo, &argv)?;
        if out.trim().is_empty() {
            return Err(format!(
                "`cargo tree {}` resolved and named no package at all. A tree with no packages in \
                 it carries no crate, and carrying no crate is the passing answer to every \
                 dependency ban.",
                args.join(" ")
            ));
        }
        Ok(out)
    }

    /// `cargo metadata` for one manifest, overlay-overridable so a self-test can plant a dependency
    /// closure without a fixture workspace.
    pub fn cargo_metadata(&self, manifest_rel: &str) -> Result<String, String> {
        let key = format!("cargo-metadata:{manifest_rel}");
        if let Some(ov) = self.overlay() {
            if let Some(out) = ov.commands.get(&key) {
                return Ok(out.clone());
            }
        }
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
        self.run_checked(
            &cargo,
            &[
                "metadata".to_string(),
                "--format-version".to_string(),
                "1".to_string(),
                "--manifest-path".to_string(),
                self.abs(manifest_rel).display().to_string(),
            ],
        )
    }
}

fn collect(dir: &Path, root: &Path, out: &mut Vec<PathBuf>) -> Result<(), WalkError> {
    if dir.is_file() {
        if let Ok(rel) = dir.strip_prefix(root) {
            out.push(rel.to_path_buf());
        }
        return Ok(());
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Ok(());
    };
    let mut entries: Vec<PathBuf> = rd.filter_map(|e| e.ok()).map(|e| e.path()).collect();
    entries.sort();
    for path in entries {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name == "target" || name == ".git" {
            continue;
        }
        if path.is_dir() {
            collect(&path, root, out)?;
        } else if let Ok(rel) = path.strip_prefix(root) {
            out.push(rel.to_path_buf());
        }
    }
    Ok(())
}
