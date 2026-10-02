//! `cargo xtask ship` over a SCRIPTED shell: every git / cargo / gh call is recorded and answered
//! from a table, so the flow's decisions are pinned without a network, a remote or a build.
//!
//! The two that matter most: a branch that is not `lane-*` stops before ANY fetch, push or PR
//! (exit 2), and a branch that already contains origin/predev is never merged into.

use std::path::Path;
use xtask::ship::{self, Opts, Out, Shell};

/// Answers each command by the first rule whose prefix matches `prog args…`; unmatched commands
/// succeed with empty output. Every call is recorded as one string.
struct Scripted {
    rules: Vec<(&'static str, bool, &'static str)>,
    calls: Vec<String>,
}

impl Scripted {
    fn new(rules: &[(&'static str, bool, &'static str)]) -> Self {
        Scripted {
            rules: rules.to_vec(),
            calls: Vec::new(),
        }
    }
    fn ran(&self, prefix: &str) -> bool {
        self.calls.iter().any(|c| c.starts_with(prefix))
    }
}

impl Shell for Scripted {
    fn run(&mut self, _dir: &Path, prog: &str, args: &[&str], _env: &[(&str, String)]) -> Out {
        let line = format!("{prog} {}", args.join(" "));
        self.calls.push(line.clone());
        for (prefix, ok, stdout) in &self.rules {
            if line.starts_with(prefix) {
                return Out {
                    ok: *ok,
                    stdout: (*stdout).to_string(),
                    stderr: String::new(),
                };
            }
        }
        Out {
            ok: true,
            ..Out::default()
        }
    }
}

fn opts() -> Opts {
    Opts {
        title: "LANE X: a slice".into(),
        body: None,
    }
}

fn drive(sh: &mut Scripted) -> (i32, String) {
    let mut log = Vec::new();
    let code = ship::ship(sh, Path::new("/w"), &opts(), "/t", &mut log);
    (code, String::from_utf8(log).unwrap())
}

#[test]
fn a_branch_that_is_not_lane_star_exits_2_before_any_fetch_push_or_pr() {
    for head in ["predev", "main", "HEAD", "train/cg-62", "my-lane-x"] {
        let mut sh = Scripted::new(&[("git rev-parse --abbrev-ref HEAD", true, "")]);
        sh.rules[0].2 = Box::leak(format!("{head}\n").into_boxed_str());
        let (code, log) = drive(&mut sh);
        assert_eq!(code, 2, "{head}: {log}");
        assert!(
            log.contains(&format!("branch must be lane-* (got {head})")),
            "{log}"
        );
        assert_eq!(
            sh.calls,
            vec!["git rev-parse --abbrev-ref HEAD"],
            "{head} ran more than the check"
        );
    }
}

#[test]
fn a_failed_head_read_is_not_a_lane_branch_either() {
    let mut sh = Scripted::new(&[("git rev-parse", false, "")]);
    assert_eq!(drive(&mut sh).0, 2);
    assert!(!sh.ran("git fetch"));
}

#[test]
fn already_up_to_date_never_merges_and_reuses_the_open_pr() {
    let mut sh = Scripted::new(&[
        ("git rev-parse --abbrev-ref HEAD", true, "lane-r7-ship\n"),
        ("git merge-base --is-ancestor origin/predev HEAD", true, ""),
        ("git status", true, ""),
        ("gh pr list", true, "212\n"),
    ]);
    let (code, log) = drive(&mut sh);
    assert_eq!(code, 0, "{log}");
    assert!(log.contains("already contains origin/predev"), "{log}");
    assert!(
        !sh.ran("git merge -q"),
        "merged into an up-to-date branch: {:?}",
        sh.calls
    );
    assert!(
        !sh.ran("git commit"),
        "a clean pre-flight committed: {:?}",
        sh.calls
    );
    assert!(
        !sh.ran("gh pr create"),
        "opened a second PR: {:?}",
        sh.calls
    );
    assert!(sh.ran("git push -q -u origin lane-r7-ship"));
    assert!(sh.ran("gh pr merge 212 -R GetBusbar/busbar --auto --merge"));
    assert!(log.contains("SHIPPED lane-r7-ship -> PR #212"), "{log}");
}

#[test]
fn behind_predev_merges_commits_the_preflight_and_opens_the_pr() {
    let mut sh = Scripted::new(&[
        ("git rev-parse --abbrev-ref HEAD", true, "lane-x\n"),
        ("git merge-base", false, ""),
        ("git status", true, " M Cargo.lock\n"),
        ("gh pr list", true, "\n"),
        (
            "gh pr create",
            true,
            "https://github.com/GetBusbar/busbar/pull/314\n",
        ),
    ]);
    let (code, log) = drive(&mut sh);
    assert_eq!(code, 0, "{log}");
    let pos = |p: &str| {
        sh.calls
            .iter()
            .position(|c| c.starts_with(p))
            .unwrap_or_else(|| panic!("no {p}"))
    };
    assert!(pos("git merge -q --no-edit origin/predev") < pos("cargo fmt --all"));
    assert!(pos("cargo xtask gate abi-header --write") < pos("git add -u"));
    assert!(pos("git commit -qm pre-flight: fmt / lock / abi header") < pos("git push"));
    assert!(sh.ran("gh pr create -R GetBusbar/busbar -B predev -H lane-x -t LANE X: a slice -b LANE X: a slice"));
    assert!(sh.ran("gh pr merge 314 "));
}

#[test]
fn a_conflicting_merge_exits_3_and_pushes_nothing() {
    let mut sh = Scripted::new(&[
        ("git rev-parse --abbrev-ref HEAD", true, "lane-x\n"),
        ("git merge-base", false, ""),
        ("git merge -q", false, ""),
    ]);
    let (code, log) = drive(&mut sh);
    assert_eq!(code, 3, "{log}");
    assert!(!sh.ran("cargo") && !sh.ran("git push") && !sh.ran("gh "));
}

#[test]
fn arguments_and_the_pr_number() {
    let a = |v: &[&str]| ship::parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>());
    assert_eq!(
        a(&["T", "--body", "b.md"]).unwrap().body.unwrap().to_str(),
        Some("b.md")
    );
    assert!(a(&[]).is_err());
    assert!(a(&["T", "--bogus"]).is_err());
    assert!(a(&["T", "U"]).is_err());
    assert_eq!(
        ship::pr_number("https://github.com/GetBusbar/busbar/pull/7\n").as_deref(),
        Some("7")
    );
    assert_eq!(ship::pr_number("no url"), None);
}
