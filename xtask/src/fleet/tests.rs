//! `cargo xtask fleet`: the render is a pure function of the registry and the templates, and the
//! checker goes RED, naming the repo and the file, on every kind of drift it owns. The checker runs
//! over a planted [`Remote`], so each case is a green control plus exactly one defect.

use std::cell::RefCell;
use std::collections::BTreeMap;

use serde_json::Value;

use super::check::{busbar_revs, check, contract_abi_of, Finding};
use super::registry::{parse, Fleet};
use super::remote::{Remote, Settings};
use super::render::{
    apply_readme, apply_region, fill, readme_headings, readme_skeleton, region_of, render,
    restructure, rust_version_of, Mode, Templates,
};
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
    crate: busbar-hook-beta-plugin
    service: none
    released: false
    description: "The beta hook."
    manifest_name: "busbar-beta"
    lib_only: true
    needs_prompt: "rw"
    declares: "hook-beta/declares.json"
    keep:
      - .github/workflows/docker.yml
      - Dockerfile
      - docker/
"#
    ))
    .expect("fixture parses")
}

/// A repo as the checker sees it, planted file by file.
#[derive(Clone)]
struct Repo {
    files: BTreeMap<String, String>,
    branches: Vec<String>,
    protection: BTreeMap<String, Value>,
    settings: Settings,
    /// No commits at all (GitHub's 409 "Git Repository is empty").
    empty: bool,
}

impl Default for Repo {
    /// The fleet norm's settings: public, Apache-2.0, `dev` the default branch.
    fn default() -> Repo {
        Repo {
            files: BTreeMap::new(),
            branches: Vec::new(),
            protection: BTreeMap::new(),
            empty: false,
            settings: Settings {
                visibility: "public".into(),
                license: "Apache-2.0".into(),
                default_branch: "dev".into(),
            },
        }
    }
}

#[derive(Default)]
struct Fake {
    repos: RefCell<BTreeMap<String, Repo>>,
    unreadable: Vec<String>,
}

impl Remote for Fake {
    fn is_empty(&self, repo: &str) -> Result<bool, String> {
        if self.unreadable.iter().any(|r| r == repo) {
            return Err("HTTP 401: Bad credentials".into());
        }
        Ok(self.repos.borrow()[repo].empty)
    }
    fn settings(&self, repo: &str) -> Result<Settings, String> {
        if self.unreadable.iter().any(|r| r == repo) {
            return Err("HTTP 401: Bad credentials".into());
        }
        Ok(self.repos.borrow()[repo].settings.clone())
    }
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
        let skeleton = readme_skeleton(fleet, p, t).unwrap();
        for f in render(fleet, p, t).unwrap() {
            let text = match f.mode {
                Mode::Whole => f.content,
                Mode::Region => format!(
                    "{}\n{}",
                    f.content,
                    skeleton.replacen(
                        "## What it is for\n",
                        "## What it is for\n\nThe plugin's own README body.\n",
                        1
                    )
                ),
            };
            r.files.insert(f.path, text);
        }
        // The two twin crate dirs, and the lock: the repo's own.
        for d in p.crate_dirs() {
            r.files.insert(
                format!("{d}/Cargo.toml"),
                "[package]\nedition.workspace = true\n".into(),
            );
            r.files.insert(format!("{d}/src/lib.rs"), "\n".into());
        }
        r.files.insert("Cargo.lock".into(), "version = 4\n".into());
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

/// The RED findings (a skip is printed, never red).
fn run(fleet: &Fleet, t: &Templates, fake: &Fake) -> Vec<Finding> {
    check(fleet, t, fake, &[])
        .into_iter()
        .filter(|f| !f.skip)
        .collect()
}

/// The skips alone.
fn skips(fleet: &Fleet, t: &Templates, fake: &Fake) -> Vec<Finding> {
    check(fleet, t, fake, &[])
        .into_iter()
        .filter(|f| f.skip)
        .collect()
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
            ".gitignore",
            ".mailmap",
            "CODE_OF_CONDUCT.md",
            "CONTRIBUTING.md",
            "Cargo.toml",
            "LICENSE",
            "NOTICE",
            "README.md",
            "SECURITY.md",
            "clippy.toml",
            "codecov.yml",
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
            "Rewritten body, not the fleet's.\n\n### A subsection of its own\n\nMore prose.",
        );
        r.files.insert("README.md".into(), readme);
        r.files
            .insert("store-alpha/src/lib.rs".into(), "pub fn x() {}\n".into());
        r.files.insert(
            "store-alpha-plugin/tests/conformance.rs".into(),
            "#[test]\nfn t() {}\n".into(),
        );
        let hook = repos.get_mut("busbar-hook-beta").unwrap();
        hook.files
            .insert("Dockerfile".into(), "FROM scratch\n".into());
        hook.files
            .insert("docker/entry.sh".into(), "#!/bin/sh\n".into());
    }
    // The hook KEEPS its docker workflow (planted by `conforming`) and its top-level Dockerfile and
    // docker/ (declared in its `keep`): not drift.
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

#[test]
fn every_skeleton_file_is_rendered_and_its_drift_is_red() {
    let (fleet, t) = (fixture(), templates());
    let a = "busbar-store-alpha";
    let plant = |edit: &dyn Fn(&mut Repo)| {
        let fake = conforming(&fleet, &t);
        edit(fake.repos.borrow_mut().get_mut(a).unwrap());
        run(&fleet, &t, &fake)
    };
    for path in [
        ".gitignore",
        ".mailmap",
        "Cargo.toml",
        "NOTICE",
        "codecov.yml",
        "SECURITY.md",
        "CONTRIBUTING.md",
        "CODE_OF_CONDUCT.md",
    ] {
        let f = plant(&|r| {
            let edited = format!("{}# a repo's own edit\n", r.files[path]);
            r.files.insert(path.into(), edited);
        });
        one(&f, a, path, "differs from the render");
        let f = plant(&|r| {
            r.files.remove(path);
        });
        one(&f, a, path, "missing (the render owns it)");
    }
    // The workspace manifest is the twin's: the two crate dirs, the shared package, the pin.
    let files = render(&fleet, &fleet.plugins[0], &t).unwrap();
    let ws = &files
        .iter()
        .find(|f| f.path == "Cargo.toml")
        .unwrap()
        .content;
    assert!(
        ws.contains("members = [\n    \"store-alpha\",\n    \"store-alpha-plugin\",\n]\n")
            && ws.contains("[workspace.package]\n")
            && ws.contains(&format!(
                "rust-version = \"{}\"\n",
                rust_version_of(&t.channel).unwrap()
            ))
            && busbar_revs(ws) == vec![PIN.to_string(), PIN.to_string()],
        "{ws}"
    );
    // A declared `.gitignore` line and `NOTICE` credit are the entry's; the rest is the fleet's.
    let mut declared = fleet.clone();
    declared.plugins[0].gitignore = vec!["busbar-governance.db*".into()];
    declared.plugins[0].notice = vec!["It links x.".into()];
    let files = render(&declared, &declared.plugins[0], &t).unwrap();
    let gi = &files
        .iter()
        .find(|f| f.path == ".gitignore")
        .unwrap()
        .content;
    assert!(
        gi.ends_with("/target\n/mutants.out*\nbusbar-governance.db*\n"),
        "{gi}"
    );
    let notice = &files.iter().find(|f| f.path == "NOTICE").unwrap().content;
    assert!(
        notice.starts_with("busbar-store-alpha\n")
            && notice.ends_with("(https://getbusbar.com).\n\nIt links x.\n"),
        "{notice}"
    );
    let plain = render(&fleet, &fleet.plugins[0], &t).unwrap();
    let gi = &plain
        .iter()
        .find(|f| f.path == ".gitignore")
        .unwrap()
        .content;
    assert!(gi.ends_with("/mutants.out*\n"), "{gi}");
}

#[test]
fn a_top_level_path_outside_the_twin_shape_is_red() {
    let (fleet, t) = (fixture(), templates());
    let a = "busbar-store-alpha";
    let plant = |edit: &dyn Fn(&mut Repo)| {
        let fake = conforming(&fleet, &t);
        edit(fake.repos.borrow_mut().get_mut(a).unwrap());
        run(&fleet, &t, &fake)
    };
    // (a) a top-level file or dir the render does not write and the entry does not keep.
    let f = plant(&|r| {
        r.files.insert("RELEASING.md".into(), "notes\n".into());
    });
    one(&f, a, "RELEASING.md", "unmanaged top-level path");
    assert_eq!(f.len(), 1, "{f:#?}");
    let f = plant(&|r| {
        r.files.insert("bench/run.py".into(), "print()\n".into());
    });
    one(&f, a, "bench", "unmanaged top-level path");
    // A kept top-level path is the hook's, not the store's: `keep` is per entry.
    let f = plant(&|r| {
        r.files.insert("Dockerfile".into(), "FROM scratch\n".into());
    });
    one(&f, a, "Dockerfile", "unmanaged top-level path");
    // ...and anything under .github/ the render does not produce, not just workflows and scripts.
    let f = plant(&|r| {
        r.files
            .insert(".github/dependabot.yml".into(), "version: 2\n".into());
    });
    one(&f, a, ".github/dependabot.yml", "unmanaged");
}

#[test]
fn crate_dirs_other_than_the_two_twin_dirs_are_red() {
    let (fleet, t) = (fixture(), templates());
    let a = "busbar-store-alpha";
    let plant = |edit: &dyn Fn(&mut Repo)| {
        let fake = conforming(&fleet, &t);
        edit(fake.repos.borrow_mut().get_mut(a).unwrap());
        run(&fleet, &t, &fake)
    };
    // (b) a crate dir named after the repo, not <kind>-<name>: the wrong dir AND the missing one.
    let f = plant(&|r| {
        let moved: Vec<(String, String)> = r
            .files
            .iter()
            .filter(|(k, _)| k.starts_with("store-alpha/"))
            .map(|(k, v)| {
                (
                    k.replacen("store-alpha/", "busbar-store-alpha/", 1),
                    v.clone(),
                )
            })
            .collect();
        r.files.retain(|k, _| !k.starts_with("store-alpha/"));
        r.files.extend(moved);
    });
    one(
        &f,
        a,
        "busbar-store-alpha/",
        "a crate dir outside the twin layout",
    );
    one(&f, a, "store-alpha/", "missing: the twin crate dir");
    // A single crate at the repo root: no crate dirs, and its src/ is unmanaged.
    let f = plant(&|r| {
        r.files.retain(|k, _| !k.starts_with("store-alpha"));
        r.files.insert("src/lib.rs".into(), "\n".into());
    });
    one(&f, a, "store-alpha/", "missing");
    one(&f, a, "store-alpha-plugin/", "missing");
    one(&f, a, "src", "unmanaged top-level path");
    // A third crate dir.
    let f = plant(&|r| {
        r.files
            .insert("store-alpha-extra/Cargo.toml".into(), "[package]\n".into());
    });
    one(
        &f,
        a,
        "store-alpha-extra/",
        "a crate dir outside the twin layout",
    );
    assert_eq!(f.len(), 1, "{f:#?}");
    // The cdylib crate is <repo>-plugin.
    let mut single = fixture();
    single.plugins[0].crate_name = "busbar-store-alpha".into();
    let fake = conforming(&single, &t);
    let f = run(&single, &t, &fake);
    one(&f, a, "crate", "a twin's is `busbar-store-alpha-plugin`");
}

#[test]
fn settings_outside_the_fleet_norm_are_red() {
    let (fleet, t) = (fixture(), templates());
    let a = "busbar-store-alpha";
    let plant = |edit: &dyn Fn(&mut Repo)| {
        let fake = conforming(&fleet, &t);
        edit(fake.repos.borrow_mut().get_mut(a).unwrap());
        run(&fleet, &t, &fake)
    };
    // (c) visibility, license, default branch: each alone is exactly one finding.
    let f = plant(&|r| r.settings.visibility = "private".into());
    one(
        &f,
        a,
        "visibility",
        "is `private`, the fleet norm is `public`",
    );
    assert_eq!(f.len(), 1, "{f:#?}");
    let f = plant(&|r| r.settings.license = "MIT".into());
    one(&f, a, "license", "is `MIT`, the fleet norm is `Apache-2.0`");
    assert_eq!(f.len(), 1, "{f:#?}");
    let f = plant(&|r| r.settings.license = "none".into());
    one(&f, a, "license", "is `none`");
    let f = plant(&|r| r.settings.default_branch = "main".into());
    one(
        &f,
        a,
        "default branch",
        "is `main`, the fleet norm is `dev`",
    );
    assert_eq!(f.len(), 1, "{f:#?}");
    // Settings that cannot be read are a finding, not a pass.
    let mut fake = conforming(&fleet, &t);
    fake.unreadable.push(a.into());
    one(&run(&fleet, &t, &fake), a, "settings", "could not read");
}

#[test]
fn a_readme_off_the_section_skeleton_is_red_and_sync_restructures_it_without_dropping_prose() {
    let (fleet, t) = (fixture(), templates());
    let a = "busbar-store-alpha";
    let p = &fleet.plugins[0];
    let skeleton = readme_skeleton(&fleet, p, &t).unwrap();
    let want = readme_headings(&skeleton);
    assert_eq!(
        want,
        [
            "## What it is for",
            "## Config",
            "## Build",
            "## Tests",
            "## License"
        ]
    );
    let plant = |edit: &dyn Fn(&mut Repo)| {
        let fake = conforming(&fleet, &t);
        edit(fake.repos.borrow_mut().get_mut(a).unwrap());
        run(&fleet, &t, &fake)
    };
    let f = plant(&|r| {
        let readme = r.files["README.md"].replace("## Tests\n", "## Testing notes\n");
        r.files.insert("README.md".into(), readme);
    });
    one(&f, a, "README.md", "the section skeleton differs");
    let f = plant(&|r| {
        let readme = format!("{}\n# A second title\n", r.files["README.md"]);
        r.files.insert("README.md".into(), readme);
    });
    one(&f, a, "README.md", "the section skeleton differs");
    // A heading inside a code fence is not a section.
    let f = plant(&|r| {
        let readme = r.files["README.md"].replace(
            "## Build\n",
            "## Build\n\n```bash\n# a shell comment\n## another\n```\n",
        );
        r.files.insert("README.md".into(), readme);
    });
    assert!(f.is_empty(), "{f:#?}");

    // The restructure: a README written before the skeleton becomes the skeleton, every line kept.
    let region = &render(&fleet, p, &t)
        .unwrap()
        .into_iter()
        .find(|f| f.path == "README.md")
        .unwrap()
        .content;
    let old = "# busbar-store-alpha\n\nIntro prose.\n\n## Versioning\n\nSemver.\n\n## Configuration\n\n```yaml\n# not a heading\nstore: alpha\n```\n\n## Testing\n\nRun it.\n\n## Design\n\nWhy.\n";
    let new = apply_readme(Some(old), region, &skeleton);
    assert_eq!(readme_headings(&new), want, "{new}");
    for kept in [
        "Intro prose.",
        "### Versioning",
        "Semver.",
        "# not a heading",
        "store: alpha",
        "Run it.",
        "### Design",
        "Why.",
    ] {
        assert!(new.contains(kept), "{kept:?} dropped:\n{new}");
    }
    // Design sat under Testing, so it stays in Tests; Versioning sat before any skeleton section.
    let tests_at = new.find("## Tests").unwrap();
    assert!(new.find("### Design").unwrap() > tests_at);
    assert!(new.find("### Versioning").unwrap() < new.find("## Config").unwrap());
    // A section the README has no text for takes the skeleton's default body.
    assert!(
        new.contains("## License\n\nApache-2.0. See [LICENSE](LICENSE).\n"),
        "{new}"
    );
    // Idempotent: restructuring a restructured README changes nothing.
    assert_eq!(apply_readme(Some(&new), region, &skeleton), new);
    // A fresh repo: the region and the skeleton's defaults.
    let fresh = apply_readme(None, region, &skeleton);
    assert_eq!(readme_headings(&fresh), want);
    assert_eq!(restructure("", &skeleton), restructure("\n\n", &skeleton));
}

#[test]
fn the_committed_registry_is_all_twins() {
    let (fleet, t) = (registry(), templates());
    // The repos registered before their crates moved in are pending; the rest are not.
    let pending = [
        "busbar-plane-llm",
        "busbar-plane-mcp",
        "busbar-plane-a2a",
        "busbar-plane-streaming",
        "busbar-plane-decisions",
        "busbar-transport-http",
        "busbar-transport-ws",
        "busbar-transport-stdio",
        "busbar-transport-grpc",
        "busbar-hook-ranking",
        "busbar-store-memory",
    ];
    for repo in pending {
        let p = fleet.plugin(repo).unwrap_or_else(|e| panic!("{e}"));
        assert!(p.pending_crate && !p.released, "{repo}");
    }
    assert!(!fleet.plugin("busbar-transport-tcp").unwrap().pending_crate);
    assert_eq!(
        fleet.plugins.iter().filter(|p| p.pending_crate).count(),
        pending.len()
    );
    // Every repo's render has the same shape: the same paths (the daily consumer check only once a
    // plugin has released), each workspace over its own two twin crate dirs.
    let shape = |p: &super::registry::Plugin| -> Vec<String> {
        render(&fleet, p, &t)
            .unwrap()
            .into_iter()
            .map(|f| f.path)
            .filter(|x| !x.ends_with("consumer-verify.yml"))
            .collect()
    };
    let first = shape(&fleet.plugins[0]);
    for p in &fleet.plugins {
        assert_eq!(
            shape(p),
            first,
            "{}: not a twin of {}",
            p.repo,
            fleet.plugins[0].repo
        );
        let ws = render(&fleet, p, &t).unwrap();
        let ws = &ws.iter().find(|f| f.path == "Cargo.toml").unwrap().content;
        let [logic, cdylib] = p.crate_dirs();
        assert!(
            ws.contains(&format!("    \"{logic}\",\n    \"{cdylib}\",\n")),
            "{}: {ws}",
            p.repo
        );
    }
    // The new repos are twins in the registry too: <repo>-plugin, declares in the logic crate.
    for p in fleet
        .plugins
        .iter()
        .filter(|p| p.pending_crate || p.repo.starts_with("busbar-transport-"))
    {
        assert_eq!(p.crate_name, format!("{}-plugin", p.repo));
        assert_eq!(p.declares, format!("{}/declares.json", p.stem()));
    }
}

#[test]
fn the_workspace_rust_version_is_the_toolchain_channels_minor() {
    assert_eq!(rust_version_of("1.98.0").unwrap(), "1.98");
    assert_eq!(rust_version_of("1.98").unwrap(), "1.98");
    assert!(rust_version_of("stable").is_err());
    assert!(rust_version_of("nightly-2026-01-01").is_err());
}

#[test]
fn a_pending_crate_repo_is_skipped_with_its_reason_and_a_non_pending_empty_repo_is_red() {
    let t = templates();
    let a = "busbar-store-alpha";
    let empty = |fleet: &Fleet| {
        let fake = conforming(fleet, &t);
        {
            let mut repos = fake.repos.borrow_mut();
            let r = repos.get_mut(a).unwrap();
            r.files.clear();
            r.branches.clear();
            r.protection.clear();
            r.settings.default_branch = "main".into();
            r.empty = true;
        }
        fake
    };
    // RED ARM: an EMPTY repo that is NOT pending is drift, not a skip.
    let fleet = fixture();
    let fake = empty(&fleet);
    let f = run(&fleet, &t, &fake);
    one(&f, a, "branch dev", "missing");
    one(&f, a, ".github/workflows/ci.yml", "missing");
    one(&f, a, "store-alpha/", "missing");
    assert!(skips(&fleet, &t, &fake).is_empty());

    // The same empty repo, pending: one skip naming the reason, nothing red.
    let mut pending = fixture();
    pending.plugins[0].pending_crate = true;
    let fake = empty(&pending);
    assert!(
        run(&pending, &t, &fake).is_empty(),
        "{:#?}",
        run(&pending, &t, &fake)
    );
    let s = skips(&pending, &t, &fake);
    assert_eq!(s.len(), 1, "{s:#?}");
    assert!(
        s[0].repo == a && s[0].reason.contains("pending-crate") && s[0].reason.contains("empty")
    );

    // Seeded (the render is in) but no crates yet: the crate dirs and declares skip; the render and
    // every other check still hold it.
    let fake = conforming(&pending, &t);
    {
        let mut repos = fake.repos.borrow_mut();
        let r = repos.get_mut(a).unwrap();
        r.files.retain(|k, _| !k.starts_with("store-alpha"));
    }
    assert!(
        run(&pending, &t, &fake).is_empty(),
        "{:#?}",
        run(&pending, &t, &fake)
    );
    let s: Vec<String> = skips(&pending, &t, &fake)
        .into_iter()
        .map(|x| x.subject)
        .collect();
    assert_eq!(
        s,
        [
            "store-alpha-plugin/",
            "store-alpha/",
            "store-alpha/declares.json"
        ]
    );
    {
        let mut repos = fake.repos.borrow_mut();
        let r = repos.get_mut(a).unwrap();
        r.files.remove(".mailmap");
    }
    one(
        &run(&pending, &t, &fake),
        a,
        ".mailmap",
        "missing (the render owns it)",
    );

    // Pending but the crates are in: the flag is stale, RED.
    let fake = conforming(&pending, &t);
    one(&run(&pending, &t, &fake), a, "pending_crate", "stale");

    // An unreadable pending repo is RED, never a silent skip.
    let mut fake = empty(&pending);
    fake.unreadable.push(a.into());
    one(&run(&pending, &t, &fake), a, "repo", "could not read");
}

#[test]
fn contributing_describes_the_layout_the_repo_really_has() {
    let (fleet, t) = (registry(), templates());
    let contributing = |repo: &str| {
        let p = fleet.plugin(repo).unwrap();
        render(&fleet, p, &t)
            .unwrap()
            .into_iter()
            .find(|f| f.path == "CONTRIBUTING.md")
            .unwrap()
            .content
    };
    // A single-crate hook repo (its cdylib crate IS the repo) is not told it is a workspace.
    for repo in ["busbar-hook-headroom", "busbar-hook-webrequest"] {
        let c = contributing(repo);
        assert!(c.contains("single crate at the repo root"), "{repo}: {c}");
        assert!(!c.contains("two-crate"), "{repo}: {c}");
    }
    let twin = contributing("busbar-store-sqlite");
    assert!(twin.contains("two-crate Cargo workspace"), "{twin}");
    assert!(twin.contains("`store-sqlite/`") && twin.contains("`store-sqlite-plugin/`"));
}

#[test]
fn an_export_sinks_registry_alias_is_its_module_name() {
    // The dropped-in tarball resolves under the operator's `module:` spelling, exactly like the
    // linked row, only if the packed alias IS that module name.
    let fleet = registry();
    for (repo, module) in [
        ("busbar-export-file", "request-log-file"),
        ("busbar-export-webhook", "request-log-webhook"),
    ] {
        assert_eq!(fleet.plugin(repo).unwrap().alias, module, "{repo}");
    }
}
