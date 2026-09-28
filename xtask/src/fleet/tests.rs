//! `cargo xtask fleet`: the render is a pure function of the registry and the templates, and the
//! checker goes RED, naming the repo and the file, on every kind of drift it owns. The checker runs
//! over a planted [`Remote`], so each case is a green control plus exactly one defect.

use std::cell::RefCell;
use std::collections::BTreeMap;

use serde_json::Value;

use super::check::{busbar_revs, check, contract_abi_of, Finding};
use super::registry::{parse, Fleet};
use super::remote::Remote;
use super::render::{apply_region, fill, region_of, render, Mode, Templates};
use crate::ctx::Ctx;

const PIN: &str = "0123456789abcdef0123456789abcdef01234567";

fn templates() -> Templates {
    Templates::load(&Ctx::workspace().expect("workspace")).expect("the fleet templates load")
}

fn registry() -> Fleet {
    let text = Ctx::workspace().unwrap().read("plugins.yaml").unwrap();
    parse(&text).expect("the committed plugins.yaml parses as a fleet")
}

/// A two-repo fleet whose names conform, so the control is green.
fn fixture() -> Fleet {
    parse(&format!(
        r#"
fleet:
  busbar_ref: "{PIN} 1.6.0"
  name_pattern: "^busbar-(store|secret|auth|hook|export|plane|transport)-[a-z0-9]+(-[a-z0-9]+)*$"
  branches: [dev, qa, main]
plugins:
  - repo: busbar-store-alpha
    kind: store
    alias: alpha
    crate: busbar-store-alpha-plugin
    service: none
    description: "The alpha store."
    declares: "store-alpha/declares.json"
  - repo: busbar-hook-beta
    kind: hook
    alias: beta
    crate: beta-hook
    service: none
    released: false
    description: "The beta hook."
    manifest_name: "busbar-beta"
    lib_only: true
    needs_prompt: "rw"
    declares: "declares.json"
    keep:
      - .github/workflows/docker.yml
"#
    ))
    .expect("fixture parses")
}

/// A repo as the checker sees it, planted file by file.
#[derive(Default, Clone)]
struct Repo {
    files: BTreeMap<String, String>,
    branches: Vec<String>,
    protection: BTreeMap<String, Value>,
}

#[derive(Default)]
struct Fake {
    repos: RefCell<BTreeMap<String, Repo>>,
    unreadable: Vec<String>,
}

impl Remote for Fake {
    fn files(&self, repo: &str, _b: &str) -> Result<Vec<String>, String> {
        if self.unreadable.iter().any(|r| r == repo) {
            return Err("HTTP 401: Bad credentials".into());
        }
        Ok(self.repos.borrow()[repo].files.keys().cloned().collect())
    }
    fn read(&self, repo: &str, _b: &str, path: &str) -> Result<Option<String>, String> {
        Ok(self.repos.borrow()[repo].files.get(path).cloned())
    }
    fn branches(&self, repo: &str) -> Result<Vec<String>, String> {
        if self.unreadable.iter().any(|r| r == repo) {
            return Err("HTTP 401: Bad credentials".into());
        }
        Ok(self.repos.borrow()[repo].branches.clone())
    }
    fn protection(&self, repo: &str, b: &str) -> Result<Option<Value>, String> {
        Ok(self.repos.borrow()[repo].protection.get(b).cloned())
    }
}

/// GitHub's GET shape of a protection whose PUT body is `spec`.
fn as_github_reports(spec: &Value) -> Value {
    let mut v = spec.clone();
    for k in [
        "enforce_admins",
        "required_linear_history",
        "allow_force_pushes",
        "allow_deletions",
        "block_creations",
        "required_conversation_resolution",
        "lock_branch",
        "allow_fork_syncing",
    ] {
        let on = v[k].clone();
        v[k] = serde_json::json!({ "enabled": on, "url": "https://api.github.com/x" });
    }
    v["required_status_checks"]["checks"] = serde_json::json!([]);
    v["url"] = Value::String("https://api.github.com/x".into());
    v
}

/// Every repo exactly as the render and the policy say: the GREEN control.
fn conforming(fleet: &Fleet, t: &Templates) -> Fake {
    let spec = t.protection_json().unwrap();
    let mut repos = BTreeMap::new();
    for p in &fleet.plugins {
        let mut r = Repo {
            branches: vec!["dev".into(), "qa".into(), "main".into()],
            ..Default::default()
        };
        for b in &r.branches.clone() {
            r.protection.insert(b.clone(), as_github_reports(&spec));
        }
        for f in render(fleet, p, t).unwrap() {
            let text = match f.mode {
                Mode::Whole => f.content,
                Mode::Region => format!("{}\nThe plugin's own README body.\n", f.content),
            };
            r.files.insert(f.path, text);
        }
        r.files.insert(
            "Cargo.toml".into(),
            format!("[workspace]\n[workspace.dependencies]\nbusbar-contract = {{ git = \"https://github.com/GetBusbar/busbar\", rev = \"{PIN}\" }}\n"),
        );
        r.files.insert(
            p.declares.clone(),
            r#"{"contract_abi": {"min": 4, "max": 4}}"#.into(),
        );
        for k in &p.keep {
            r.files.insert(k.clone(), "name: kept\n".into());
        }
        repos.insert(p.repo.clone(), r);
    }
    Fake {
        repos: RefCell::new(repos),
        unreadable: vec![],
    }
}

fn run(fleet: &Fleet, t: &Templates, fake: &Fake) -> Vec<Finding> {
    check(fleet, t, fake, &[])
}

fn one(findings: &[Finding], repo: &str, subject: &str, needle: &str) {
    assert!(
        findings
            .iter()
            .any(|f| f.repo == repo && f.subject == subject && f.reason.contains(needle)),
        "expected a finding for {repo} {subject} containing {needle:?}; got {findings:#?}"
    );
}

#[test]
fn the_committed_registry_renders_every_repo_with_every_placeholder_filled() {
    let (fleet, t) = (registry(), templates());
    assert!(!fleet.plugins.is_empty());
    for p in &fleet.plugins {
        let files = render(&fleet, p, &t).unwrap_or_else(|e| panic!("{}: {e}", p.repo));
        for f in &files {
            assert!(
                !f.content.contains("@@"),
                "{} {}: an unfilled placeholder",
                p.repo,
                f.path
            );
        }
        let ci = &files
            .iter()
            .find(|f| f.path == ".github/workflows/ci.yml")
            .unwrap()
            .content;
        assert!(
            ci.contains(&format!(
                "GetBusbar/busbar/.github/workflows/plugin-ci.yml@{}\n",
                fleet.pin_sha
            )),
            "{}: the CI caller takes plugin-ci.yml at the fleet pin",
            p.repo
        );
        // Each caller is a THIN file: the logic lives in busbar's reusable workflows.
        for f in files
            .iter()
            .filter(|f| f.path.starts_with(".github/workflows/"))
        {
            let body = f
                .content
                .lines()
                .filter(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty())
                .count();
            assert!(
                body <= 60,
                "{} {} is {body} lines of YAML: not a thin caller",
                p.repo,
                f.path
            );
        }
    }
}

#[test]
fn the_render_is_a_pure_function_of_the_registry_and_the_templates() {
    let (fleet, t) = (fixture(), templates());
    let a = render(&fleet, &fleet.plugins[0], &t).unwrap();
    let b = render(&fleet, &fleet.plugins[0], &t).unwrap();
    assert_eq!(a, b);
    let paths: Vec<&str> = a.iter().map(|f| f.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            ".busbar-ref",
            ".github/workflows/ci.yml",
            ".github/workflows/consumer-verify.yml",
            ".github/workflows/release.yml",
            ".github/workflows/repin.yml",
            "LICENSE",
            "README.md",
            "clippy.toml",
            "deny.toml",
            "rust-toolchain.toml",
        ]
    );
    assert_eq!(a[0].content, format!("{PIN} 1.6.0\n"));
    // Moving the pin moves every caller's ref, and nothing else about the caller.
    let mut moved = fleet.clone();
    moved.pin_sha = "fedcba9876543210fedcba9876543210fedcba98".into();
    let c = render(&moved, &moved.plugins[0], &t).unwrap();
    let ci_a = &a
        .iter()
        .find(|f| f.path == ".github/workflows/ci.yml")
        .unwrap()
        .content;
    let ci_c = &c
        .iter()
        .find(|f| f.path == ".github/workflows/ci.yml")
        .unwrap()
        .content;
    assert_eq!(ci_a.replace(PIN, &moved.pin_sha), *ci_c);
    // An unreleased plugin has no daily consumer check (nothing published to download).
    assert!(!render(&fleet, &fleet.plugins[1], &t)
        .unwrap()
        .iter()
        .any(|f| f.path.ends_with("consumer-verify.yml")));
    // The hook's release inputs carry its own identity, quoted.
    let rel = render(&fleet, &fleet.plugins[1], &t).unwrap();
    let rel = &rel
        .iter()
        .find(|f| f.path == ".github/workflows/release.yml")
        .unwrap()
        .content;
    assert!(
        rel.contains("manifest_name: busbar-beta\n")
            && rel.contains("needs_prompt: \"rw\"\n")
            && rel.contains("lib_only: true\n"),
        "{rel}"
    );
}

#[test]
fn a_placeholder_the_render_does_not_define_is_an_error_not_an_empty_string() {
    let vars = vec![("pin", PIN.to_string())];
    assert_eq!(
        fill("x.yml@@@pin@@\n", &vars, "t").unwrap(),
        format!("x.yml@{PIN}\n")
    );
    assert!(fill("@@nope@@", &vars, "t")
        .unwrap_err()
        .contains("unknown placeholder `@@nope@@`"));
    assert!(fill("a @@pin", &vars, "t")
        .unwrap_err()
        .contains("unterminated"));
}

#[test]
fn the_readme_region_is_replaced_in_place_and_the_readme_body_stays_the_repos() {
    let region = "<!-- fleet:header:begin x -->\n# r\n<!-- fleet:header:end -->\n";
    let fresh = apply_region(Some("# old title\n\nBody text.\n"), region);
    assert_eq!(fresh, format!("{region}\nBody text.\n"));
    assert_eq!(region_of(&fresh), Some(region));
    let again = apply_region(Some(&fresh.replace("# r", "# edited")), region);
    assert_eq!(
        again, fresh,
        "a re-apply restores the region and keeps the body"
    );
    assert_eq!(apply_region(None, region), region);
}

#[test]
fn a_conforming_fleet_is_green() {
    let (fleet, t) = (fixture(), templates());
    let findings = run(&fleet, &t, &conforming(&fleet, &t));
    assert!(findings.is_empty(), "{findings:#?}");
}

#[test]
fn every_kind_of_drift_is_red_and_names_the_repo_and_the_file() {
    let (fleet, t) = (fixture(), templates());
    let a = "busbar-store-alpha";
    let plant = |edit: &dyn Fn(&mut Repo)| {
        let fake = conforming(&fleet, &t);
        edit(fake.repos.borrow_mut().get_mut(a).unwrap());
        run(&fleet, &t, &fake)
    };

    let f = plant(&|r| {
        let ci = r.files[".github/workflows/ci.yml"]
            .replace("busbar_checkout: false", "busbar_checkout: true");
        r.files.insert(".github/workflows/ci.yml".into(), ci);
    });
    one(&f, a, ".github/workflows/ci.yml", "differs from the render");

    let f = plant(&|r| {
        r.files.insert(
            ".busbar-ref".into(),
            "8b7b6473f47f8d37ae60839c74cfe6a9b64a1dc9 1.6.0\n".into(),
        );
    });
    one(&f, a, ".busbar-ref", "the fleet pin is");

    let f = plant(&|r| {
        r.files.insert("store-alpha/Cargo.toml".into(),
            "busbar-contract = { git = \"https://github.com/GetBusbar/busbar\", rev = \"8b7b6473f47f8d37ae60839c74cfe6a9b64a1dc9\" }\n".into());
    });
    one(&f, a, "store-alpha/Cargo.toml", "not the fleet pin");

    let f = plant(&|r| r.branches.push("ci/rust-cache-workspaces".into()));
    one(&f, a, "branch ci/rust-cache-workspaces", "stale");

    let f = plant(&|r| r.branches.retain(|b| b != "qa"));
    one(&f, a, "branch qa", "missing");

    let f = plant(&|r| {
        r.protection.get_mut("dev").unwrap()["required_pull_request_reviews"]
            ["required_approving_review_count"] = Value::from(0);
    });
    one(
        &f,
        a,
        "protection dev",
        "differs from .github/fleet/protection.json",
    );

    let f = plant(&|r| {
        r.protection.remove("main");
    });
    one(&f, a, "protection main", "unprotected");

    let f = plant(&|r| {
        r.files.insert(
            ".github/workflows/release-on-upstream.yml".into(),
            "name: old\n".into(),
        );
    });
    one(
        &f,
        a,
        ".github/workflows/release-on-upstream.yml",
        "unmanaged",
    );

    let f = plant(&|r| {
        r.files.remove(".github/workflows/repin.yml");
    });
    one(&f, a, ".github/workflows/repin.yml", "missing");

    let f = plant(&|r| {
        let readme = r.files["README.md"].replace("The alpha store.", "An edited description.");
        r.files.insert("README.md".into(), readme);
    });
    one(&f, a, "README.md", "managed header region differs");

    let f = plant(&|r| {
        r.files
            .insert("store-alpha/declares.json".into(), "{}".into());
    });
    one(
        &f,
        a,
        "store-alpha/declares.json",
        "states no `contract_abi` range",
    );

    // Each plant is ONE finding: the checker does not smear one defect across rows.
    let f = plant(&|r| r.branches.push("fix/old".into()));
    assert_eq!(f.len(), 1, "{f:#?}");
}

#[test]
fn what_the_repo_owns_is_not_drift() {
    let (fleet, t) = (fixture(), templates());
    let fake = conforming(&fleet, &t);
    {
        let mut repos = fake.repos.borrow_mut();
        let r = repos.get_mut("busbar-store-alpha").unwrap();
        let readme = r.files["README.md"].replace(
            "The plugin's own README body.",
            "Rewritten body, not the fleet's.",
        );
        r.files.insert("README.md".into(), readme);
        r.files
            .insert("store-alpha/src/lib.rs".into(), "pub fn x() {}\n".into());
    }
    // The hook KEEPS its docker workflow (planted by `conforming`): not drift.
    assert!(run(&fleet, &t, &fake).is_empty());
}

#[test]
fn a_repo_named_outside_the_pattern_or_for_another_kind_is_red() {
    let t = templates();
    let mut fleet = fixture();
    fleet.plugins[0].repo = "store-alpha".into();
    let fake = conforming(&fleet, &t);
    one(
        &run(&fleet, &t, &fake),
        "store-alpha",
        "name",
        "does not match the fleet name pattern",
    );

    let mut fleet = fixture();
    fleet.plugins[0].repo = "busbar-hook-alpha".into();
    let fake = conforming(&fleet, &t);
    one(
        &run(&fleet, &t, &fake),
        "busbar-hook-alpha",
        "name",
        "kind:store plugin but is not named busbar-store-",
    );
}

#[test]
fn a_repo_the_checker_cannot_read_is_red_not_skipped() {
    let (fleet, t) = (fixture(), templates());
    let mut fake = conforming(&fleet, &t);
    fake.unreadable.push("busbar-hook-beta".into());
    let f = run(&fleet, &t, &fake);
    one(&f, "busbar-hook-beta", "branches", "could not list");
    one(&f, "busbar-hook-beta", "dev", "could not list files");
}

#[test]
fn the_manifest_rev_reader_and_the_declares_reader() {
    assert_eq!(
        busbar_revs("a = { git = \"https://github.com/GetBusbar/busbar\", rev = \"abc\" }\n# b = { git = \"https://github.com/GetBusbar/busbar\" }\nc = { git = \"https://github.com/GetBusbar/busbar\", branch = \"x\" }\n"),
        vec!["abc".to_string(), "<none>".to_string()]
    );
    assert_eq!(
        contract_abi_of(r#"{"contract_abi":{"min":2,"max":4},"metrics":[]}"#),
        Ok((2, 4))
    );
    assert!(contract_abi_of(r#"{"contract_abi":{"min":5,"max":4}}"#)
        .unwrap_err()
        .contains("empty range"));
    assert!(contract_abi_of("{}").is_err());
}

#[test]
fn a_registry_without_the_pin_policy_or_with_a_short_pin_is_refused() {
    assert!(parse("plugins:\n  - repo: x\n")
        .unwrap_err()
        .contains("no `fleet:` block"));
    let short = "fleet:\n  busbar_ref: \"0123456 1.6.0\"\n  name_pattern: \"^x$\"\n  branches: [dev]\nplugins:\n  - repo: x\n";
    assert!(parse(short)
        .unwrap_err()
        .contains("not a full 40-hex commit"));
}
