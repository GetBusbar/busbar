//! `cargo xtask ship` — THE ONE COMMAND A LANE RUNS WHEN ITS SLICE IS READY.
//!
//! It replaces the laptop-side `ship.sh` (BUSBAR-1.6.0.md Part 6, the PR flow) with the same
//! behaviour, step for step:
//!
//! 1. the branch must be `lane-*` (anything else, a detached HEAD included, exits 2 before any
//!    network or tree change);
//! 2. fetch `origin/predev` and merge it unless HEAD already contains it (a conflicting merge exits 3:
//!    resolve, commit, re-run);
//! 3. local pre-flight only, no build of the product: `cargo fmt --all`, `cargo metadata` (which
//!    refreshes `Cargo.lock`) and `cargo xtask gate abi-header --write`;
//! 4. commit what the pre-flight changed, tracked files only;
//! 5. push the branch;
//! 6. open the PR into `predev`, or reuse the open one for this head;
//! 7. enable GitHub auto-merge.
//!
//! Then the lane STOPS: CI (promote: preflight + hop, which builds and tests) is the proof and
//! auto-merge lands it on green. A red or conflicted PR comes back as an event; nobody polls.
//!
//! Every command goes through [`Shell`], so the decisions (the branch check, the already-up-to-date
//! path, PR reuse) are driven by tests over a scripted shell; [`RealShell`] is the only part that
//! touches git, cargo or `gh`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The repository every lane PR goes to, and the branch it targets.
pub const REPO: &str = "GetBusbar/busbar";
pub const BASE: &str = "predev";
/// The commit message of the pre-flight's own commit (ship.sh's, unchanged).
pub const PREFLIGHT_MSG: &str = "pre-flight: fmt / lock / abi header";

pub const USAGE: &str =
    "usage: cargo xtask [--root <worktree>] ship \"<PR title>\" [--body <file>]";

/// What one command answered.
#[derive(Debug, Clone, Default)]
pub struct Out {
    pub ok: bool,
    pub stdout: String,
    pub stderr: String,
}

/// The one door to the outside world: run `prog args…` in `dir` with extra `env`.
pub trait Shell {
    fn run(&mut self, dir: &Path, prog: &str, args: &[&str], env: &[(&str, String)]) -> Out;
}

/// The real thing: `std::process::Command`, stdin closed, output captured.
pub struct RealShell;

impl Shell for RealShell {
    fn run(&mut self, dir: &Path, prog: &str, args: &[&str], env: &[(&str, String)]) -> Out {
        let mut cmd = Command::new(prog);
        cmd.args(args).current_dir(dir).stdin(Stdio::null());
        for (k, v) in env {
            cmd.env(k, v);
        }
        match cmd.output() {
            Ok(o) => Out {
                ok: o.status.success(),
                stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
            },
            Err(e) => Out {
                ok: false,
                stdout: String::new(),
                stderr: format!("could not run `{prog}`: {e}"),
            },
        }
    }
}

/// The parsed arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opts {
    pub title: String,
    pub body: Option<PathBuf>,
}

pub fn parse(args: &[String]) -> Result<Opts, String> {
    let mut title = None;
    let mut body = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--body" => body = Some(PathBuf::from(it.next().ok_or("--body needs a file")?)),
            s if s.starts_with('-') => return Err(format!("unknown flag `{s}`")),
            s if title.is_none() => title = Some(s.to_string()),
            s => return Err(format!("unexpected argument `{s}`")),
        }
    }
    let title = title
        .filter(|t| !t.trim().is_empty())
        .ok_or("a PR title is required")?;
    Ok(Opts { title, body })
}

/// `cargo xtask ship …` over the workspace root (the current git tree, or `--root <worktree>`).
pub fn main(args: &[String]) -> i32 {
    let opts = match parse(args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("ship: {e}\n{USAGE}");
            return 2;
        }
    };
    let root = match crate::ctx::workspace_root() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("ship: {e}");
            return 3;
        }
    };
    let target = std::env::var("HOME")
        .map(|h| format!("{h}/.cache/busbar-xtask-target"))
        .unwrap_or_else(|_| "target/xtask".to_string());
    ship(
        &mut RealShell,
        &root,
        &opts,
        &target,
        &mut std::io::stdout(),
    )
}

/// The whole flow. Returns the exit code: 0 shipped, 1 a step failed, 2 not a lane branch,
/// 3 the merge of `origin/predev` conflicts.
pub fn ship(
    sh: &mut dyn Shell,
    w: &Path,
    o: &Opts,
    xtask_target: &str,
    log: &mut dyn Write,
) -> i32 {
    let say = |log: &mut dyn Write, s: &str| {
        let _ = writeln!(log, "{s}");
    };
    let git = |sh: &mut dyn Shell, args: &[&str]| sh.run(w, "git", args, &[]);
    let fail = |log: &mut dyn Write, what: &str, out: &Out| {
        let _ = writeln!(log, "ship: {what} failed\n{}{}", out.stdout, out.stderr);
        1
    };

    // 1. lane-* only.
    let head = git(sh, &["rev-parse", "--abbrev-ref", "HEAD"]);
    let branch = head.stdout.trim().to_string();
    if !head.ok || !branch.starts_with("lane-") {
        say(log, &format!("ship: branch must be lane-* (got {branch})"));
        return 2;
    }

    // 2. merge origin/predev unless HEAD already contains it.
    let f = git(sh, &["fetch", "-q", "origin", BASE]);
    if !f.ok {
        return fail(log, "git fetch origin predev", &f);
    }
    let upstream = format!("origin/{BASE}");
    if git(sh, &["merge-base", "--is-ancestor", &upstream, "HEAD"]).ok {
        say(
            log,
            &format!("ship: {branch} already contains {upstream}; no merge"),
        );
    } else if !git(sh, &["merge", "-q", "--no-edit", &upstream]).ok {
        say(
            log,
            "ship: merge of origin/predev conflicts; resolve, commit, re-run ship",
        );
        return 3;
    }

    // 3. local pre-flight (no product build).
    let env = [("CARGO_TARGET_DIR", xtask_target.to_string())];
    let steps: [(&[&str], &[(&str, String)]); 3] = [
        (&["fmt", "--all"], &[]),
        (&["metadata", "--format-version", "1"], &[]),
        (&["xtask", "gate", "abi-header", "--write"], &env),
    ];
    for (args, env) in steps {
        let r = sh.run(w, "cargo", args, env);
        if !r.ok {
            return fail(log, &format!("cargo {}", args.join(" ")), &r);
        }
    }

    // 4. commit the pre-flight's changes, tracked files only.
    let st = git(sh, &["status", "--porcelain", "--untracked-files=no"]);
    if !st.ok {
        return fail(log, "git status", &st);
    }
    if !st.stdout.trim().is_empty() {
        let a = git(sh, &["add", "-u"]);
        if !a.ok {
            return fail(log, "git add -u", &a);
        }
        let c = git(sh, &["commit", "-qm", PREFLIGHT_MSG]);
        if !c.ok {
            return fail(log, "git commit", &c);
        }
    }

    // 5. push.
    let p = git(sh, &["push", "-q", "-u", "origin", &branch]);
    if !p.ok {
        return fail(log, "git push", &p);
    }

    // 6. reuse the open PR for this head, or open one into predev.
    let gh = |sh: &mut dyn Shell, args: &[&str]| sh.run(w, "gh", args, &[]);
    let l = gh(
        sh,
        &[
            "pr",
            "list",
            "-R",
            REPO,
            "--head",
            &branch,
            "--state",
            "open",
            "--json",
            "number",
            "--jq",
            ".[0].number",
        ],
    );
    if !l.ok {
        return fail(log, "gh pr list", &l);
    }
    let mut number = l.stdout.trim().to_string();
    if number.is_empty() {
        let body_path = o.body.as_ref().map(|b| b.to_string_lossy().into_owned());
        let mut args = vec![
            "pr", "create", "-R", REPO, "-B", BASE, "-H", &branch, "-t", &o.title,
        ];
        match &body_path {
            Some(b) => args.extend(["-F", b.as_str()]),
            None => args.extend(["-b", o.title.as_str()]),
        }
        let c = gh(sh, &args);
        if !c.ok {
            return fail(log, "gh pr create", &c);
        }
        number = pr_number(&c.stdout).unwrap_or_default();
        if number.is_empty() {
            return fail(log, "reading the new PR's number", &c);
        }
    }

    // 7. auto-merge; a failure here (already enabled, already merged) is not the lane's problem.
    let _ = gh(
        sh,
        &["pr", "merge", &number, "-R", REPO, "--auto", "--merge"],
    );
    say(
        log,
        &format!("SHIPPED {branch} -> PR #{number} (auto-merge on). Stop here: CI is the proof; a red comes back as a task."),
    );
    0
}

/// `gh pr create` prints the PR's URL; the number is its last path segment.
pub fn pr_number(stdout: &str) -> Option<String> {
    let last = stdout
        .trim()
        .lines()
        .last()?
        .trim()
        .rsplit('/')
        .next()?
        .to_string();
    (!last.is_empty() && last.bytes().all(|b| b.is_ascii_digit())).then_some(last)
}
