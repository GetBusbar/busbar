//! `fleet sync`: make each repo match the render and the policy. It pushes `dev` ONLY and never
//! touches `qa` or `main`: those are locked by the org ruleset and seeded by the ARCHITECT in an
//! owner-approved window (an orphan commit holding the README "not yet released; development is on
//! dev", LICENSE and .github/dependabot.yml). A missing release branch is REPORTED, never created
//! from `dev`, because that would be an unreviewed release. The classic protection
//! (`.github/fleet/protection.json`) is applied to `dev` alone. It NEVER creates a repo and never
//! changes a repo setting: an EMPTY registered repo (created by hand) is seeded by pushing `dev`
//! first and alone, which GitHub makes the default branch by itself. It never overwrites a root
//! `Cargo.toml` that is not a twin's (a repo whose crates are not the two twin crate dirs needs its
//! code moved first); that repo is reported. A branch outside the release set is deleted only when it is
//! FULLY MERGED into `dev`, `qa` or `main` (GitHub's compare says it is behind or identical); an
//! unmerged branch is reported and never touched.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::ctx::Ctx;
use crate::fleet::check::DEV;
use crate::fleet::registry::{Fleet, Plugin};
use crate::fleet::remote::{gh, ORG};
use crate::fleet::render::{apply_readme, readme_skeleton, render, Mode, Templates};

/// One repo's outcome, printed as a row.
#[derive(Debug, Default)]
pub struct Outcome {
    pub repo: String,
    pub dev_sha: String,
    pub committed: bool,
    /// The repo itself was created by this run.
    pub seeded: bool,
    /// Release branches the repo lacks: reported, never created.
    pub missing: Vec<String>,
    pub deleted: Vec<String>,
    pub left: Vec<String>,
    pub errors: Vec<String>,
}

fn git(dir: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .map_err(|e| format!("git {}: {e}", args.join(" ")))?;
    if !out.status.success() {
        return Err(format!(
            "git -C {} {}: {}",
            dir.display(),
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn gh_ok(args: &[&str]) -> Result<String, String> {
    let (ok, out, err) = gh(args)?;
    if ok {
        Ok(out)
    } else {
        Err(format!("gh {}: {}", args.join(" "), err.trim()))
    }
}

pub fn sync(
    cx: &Ctx,
    fleet: &Fleet,
    t: &Templates,
    only: &[String],
    workdir: &str,
    dry_run: bool,
) -> Result<i32, String> {
    std::fs::create_dir_all(workdir).map_err(|e| format!("{workdir}: {e}"))?;
    let repin = cx.abs("scripts/fleet/repin.sh");
    let mut outcomes = Vec::new();
    for p in fleet
        .plugins
        .iter()
        .filter(|p| only.is_empty() || only.contains(&p.repo))
    {
        let mut o = Outcome {
            repo: p.repo.clone(),
            ..Default::default()
        };
        if let Err(e) = sync_repo(fleet, t, p, Path::new(workdir), &repin, dry_run, &mut o) {
            o.errors.push(e);
        }
        outcomes.push(o);
    }
    println!("\nrepo\tdev\tseeded\tcommitted\tmissing release branches\tdeleted\tleft (unmerged)\terrors");
    let mut failed = false;
    for o in &outcomes {
        failed |= !o.errors.is_empty();
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            o.repo,
            if o.dev_sha.is_empty() {
                "-"
            } else {
                &o.dev_sha
            },
            o.seeded,
            o.committed,
            join(&o.missing),
            join(&o.deleted),
            join(&o.left),
            join(&o.errors)
        );
    }
    Ok(if failed { 1 } else { 0 })
}

/// The release branches (`fleet.branches`) the repo lacks. Sync reports them and never creates one:
/// a branch cut from `dev` would be an unreviewed release.
pub fn missing_release_branches(fleet: &Fleet, existing: &[String]) -> Vec<String> {
    fleet
        .branches
        .iter()
        .filter(|b| !existing.contains(b))
        .cloned()
        .collect()
}

fn join(v: &[String]) -> String {
    if v.is_empty() {
        "-".to_string()
    } else {
        v.join(",")
    }
}

fn sync_repo(
    fleet: &Fleet,
    t: &Templates,
    p: &Plugin,
    workdir: &Path,
    repin: &Path,
    dry_run: bool,
    o: &mut Outcome,
) -> Result<(), String> {
    let repo = &p.repo;
    let dir: PathBuf = workdir.join(repo);
    let url = format!("https://github.com/{ORG}/{repo}.git");
    if !dir.join(".git").exists() {
        let st = Command::new("git")
            .args(["clone", "-q", &url])
            .arg(&dir)
            .status()
            .map_err(|e| format!("git clone {url}: {e}"))?;
        if !st.success() {
            return Err(format!("git clone {url} failed"));
        }
    }
    git(&dir, &["remote", "set-url", "origin", &url])?;
    git(&dir, &["fetch", "-q", "--prune", "origin"])?;
    let has_dev = git(
        &dir,
        &[
            "rev-parse",
            "--verify",
            "-q",
            &format!("refs/remotes/origin/{DEV}"),
        ],
    )
    .is_ok();
    if has_dev {
        // The workdir clone is the sync's own: whatever an earlier (dry) run left in it is
        // discarded, and the render starts from the remote's dev.
        git(&dir, &["reset", "-q", "--hard"])?;
        git(&dir, &["clean", "-q", "-fd"])?;
        git(
            &dir,
            &["checkout", "-q", "-B", DEV, &format!("origin/{DEV}")],
        )?;
    } else if git(&dir, &["branch", "-r"])?.trim().is_empty() {
        // An EMPTY repo (created by hand; sync never creates a repo or changes a setting): dev starts
        // as an orphan and is the FIRST and only branch this run pushes, so GitHub makes it the
        // default branch by itself. qa and main are the ARCHITECT's to seed.
        git(&dir, &["checkout", "-q", "--orphan", DEV])?;
        o.seeded = true;
        git(&dir, &["clean", "-q", "-fd"])?;
    } else {
        return Err(format!(
            "{repo} has branches but no `{DEV}`; not seeding over them"
        ));
    }

    // 1. The render, and nothing unmanaged beside it.
    let files = render(fleet, p, t)?;
    let skeleton = readme_skeleton(fleet, p, t)?;
    let twin = p
        .crate_dirs()
        .iter()
        .all(|d| dir.join(d).join("Cargo.toml").is_file());
    for r in &files {
        let path = dir.join(&r.path);
        if r.path == "Cargo.toml" && path.is_file() && !twin {
            o.errors.push(format!(
                "Cargo.toml left as is: the crates are not the twin crate dirs `{}/` + `{}/` (move the code first)",
                p.crate_dirs()[0],
                p.crate_dirs()[1]
            ));
            continue;
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
        let text = match r.mode {
            Mode::Whole => r.content.clone(),
            Mode::Region => apply_readme(
                std::fs::read_to_string(&path).ok().as_deref(),
                &r.content,
                &skeleton,
            ),
        };
        std::fs::write(&path, text).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    let tracked = git(&dir, &["ls-files", ".github"])?;
    for path in tracked.lines().filter(|l| !l.is_empty()) {
        if !files.iter().any(|r| r.path == path) && !p.keep.iter().any(|k| k == path) {
            git(&dir, &["rm", "-q", "--", path])?;
        }
    }
    // 2. The pin: every place that names it moves together. AFTER the render, because repin.sh ends
    // with pin-check.sh, which also holds every caller's reusable-workflow ref to the pin: an old
    // caller still taking a workflow `@dev` would fail it.
    // Always run: the render has already written `.busbar-ref`, so the record cannot say whether the
    // manifests and the lock moved; repin.sh is a no-op when they already name the pin. A repo with
    // no Cargo.lock has no crates yet (a seed): nothing is resolved, so there is nothing to move.
    if dir.join("Cargo.lock").is_file() {
        let st = Command::new("bash")
            .arg(repin)
            .args([&fleet.pin_sha, &fleet.pin_version])
            .current_dir(&dir)
            .status()
            .map_err(|e| format!("repin: {e}"))?;
        if !st.success() {
            return Err("scripts/fleet/repin.sh failed".to_string());
        }
    }

    git(&dir, &["add", "-A"])?;
    let staged = git(&dir, &["diff", "--cached", "--name-status"])?;
    if !staged.is_empty() {
        println!("== {repo}: dev changes\n{staged}");
        if !dry_run {
            let msg = format!(
                "fleet: busbar's render (plugins.yaml + .github/fleet/) at busbar {} {}\n\n\
                 The CI, release and repin callers take busbar's reusable workflows at the pin; the whole\n\
                 skeleton (workspace manifest, toolchain, lint config, LICENSE, NOTICE, community files,\n\
                 README header and sections) is the fleet's. Rendered by `cargo xtask fleet sync`.",
                &fleet.pin_sha[..12],
                fleet.pin_version
            );
            git(&dir, &["commit", "-q", "-m", &msg])?;
            git(
                &dir,
                &["push", "-q", "origin", &format!("HEAD:refs/heads/{DEV}")],
            )?;
            o.committed = true;
        }
    }
    if !o.committed && dry_run && !has_dev {
        return Ok(());
    }
    o.dev_sha = git(&dir, &["rev-parse", "HEAD"])?;

    // 3. Release branches: a missing one is reported, never created (not from dev: that would be an
    // unreviewed release).
    let branches: Vec<String> = gh_ok(&[
        "api",
        "--paginate",
        &format!("repos/{ORG}/{repo}/branches?per_page=100"),
        "--jq",
        ".[].name",
    ])?
    .lines()
    .map(str::to_string)
    .collect();
    o.missing = missing_release_branches(fleet, &branches);
    for b in &o.missing {
        println!(
            "== {repo}: release branch `{b}` is missing; the ARCHITECT seeds it, sync never does"
        );
    }

    // 4. The one protection, on dev alone: main and qa are locked by the org ruleset.
    let spec = t.protection_json()?;
    let body = std::env::temp_dir().join(format!("fleet-protection-{repo}.json"));
    std::fs::write(&body, spec.to_string()).map_err(|e| format!("{}: {e}", body.display()))?;
    if !dry_run {
        gh_ok(&[
            "api",
            "-X",
            "PUT",
            &format!("repos/{ORG}/{repo}/branches/{DEV}/protection"),
            "--input",
            &body.to_string_lossy(),
        ])?;
    }
    let _ = std::fs::remove_file(&body);

    // 5. Stale branches: delete a fully merged one; report an unmerged one.
    for b in branches.iter().filter(|b| !fleet.branches.contains(b)) {
        let mut merged_into = None;
        for base in &fleet.branches {
            if !branches.contains(base) {
                continue;
            }
            let status = gh_ok(&[
                "api",
                &format!("repos/{ORG}/{repo}/compare/{base}...{b}"),
                "--jq",
                ".status",
            ])?;
            if matches!(status.trim(), "behind" | "identical") {
                merged_into = Some(base.clone());
                break;
            }
        }
        match merged_into {
            Some(base) => {
                if !dry_run {
                    gh_ok(&[
                        "api",
                        "-X",
                        "DELETE",
                        &format!("repos/{ORG}/{repo}/git/refs/heads/{b}"),
                    ])?;
                }
                o.deleted.push(format!("{b}(in {base})"));
            }
            None => o.left.push(b.clone()),
        }
    }
    Ok(())
}
