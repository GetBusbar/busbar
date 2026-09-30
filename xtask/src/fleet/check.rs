//! `fleet check`: every repo against its render and the fleet policy. A finding names the repo and
//! the subject (a file path, a branch, `name`); any finding is exit 1. A repo that could not be READ
//! is a finding too: a check that could not look has ruled nothing out.

use std::collections::BTreeSet;

use crate::ere::Ere;
use crate::fleet::registry::{Fleet, Plugin};
use crate::fleet::remote::{normalize_protection, normalize_spec, Remote};
use crate::fleet::render::{readme_headings, readme_skeleton, region_of, render, Mode, Templates};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Finding {
    pub repo: String,
    pub subject: String,
    pub reason: String,
}

fn f(repo: &str, subject: &str, reason: impl Into<String>) -> Finding {
    Finding {
        repo: repo.to_string(),
        subject: subject.to_string(),
        reason: reason.into(),
    }
}

/// The branch the render is compared on.
pub const DEV: &str = "dev";

/// Where a file the render does not produce is drift unless the entry keeps it.
const OWNED_DIRS: &[&str] = &[".github/"];

/// Top-level paths a repo holds that the render does not write: generated, and the repo's own.
const GENERATED: &[&str] = &["Cargo.lock"];

/// THE FLEET NORM for a plugin repo's own settings.
pub const NORM_VISIBILITY: &str = "public";
pub const NORM_LICENSE: &str = "Apache-2.0";

/// Whether the entry's `keep` declares the top-level path `top` (the path itself, or anything under
/// it).
fn keeps_top(p: &Plugin, top: &str) -> bool {
    p.keep
        .iter()
        .any(|k| k.trim_end_matches('/') == top || k.starts_with(&format!("{top}/")))
}

pub fn check(fleet: &Fleet, t: &Templates, remote: &dyn Remote, only: &[String]) -> Vec<Finding> {
    let mut out = Vec::new();
    let spec = match t.protection_json() {
        Ok(s) => normalize_spec(&s),
        Err(e) => return vec![f("-", ".github/fleet/protection.json", e)],
    };
    for p in fleet
        .plugins
        .iter()
        .filter(|p| only.is_empty() || only.contains(&p.repo))
    {
        check_repo(fleet, t, &spec, remote, p, &mut out);
    }
    out.sort();
    out.dedup();
    out
}

fn check_repo(
    fleet: &Fleet,
    t: &Templates,
    spec: &serde_json::Value,
    remote: &dyn Remote,
    p: &Plugin,
    out: &mut Vec<Finding>,
) {
    let repo = p.repo.as_str();

    // NAME: busbar-<kind>-<name>, and <kind> is this entry's own kind.
    match Ere::new(&fleet.name_pattern) {
        Ok(rx) if !rx.is_match(repo) => out.push(f(
            repo,
            "name",
            format!(
                "`{repo}` does not match the fleet name pattern {}",
                fleet.name_pattern
            ),
        )),
        Ok(_) if !repo.starts_with(&format!("busbar-{}-", p.kind)) => out.push(f(
            repo,
            "name",
            format!(
                "`{repo}` is a kind:{} plugin but is not named busbar-{}-<name>",
                p.kind, p.kind
            ),
        )),
        Ok(_) => {}
        Err(e) => out.push(f(repo, "name", format!("fleet name_pattern: {e}"))),
    }

    // BRANCHES: exactly the release branches, each with the one protection.
    match remote.branches(repo) {
        Err(e) => out.push(f(repo, "branches", format!("could not list: {e}"))),
        Ok(names) => {
            let have: BTreeSet<&str> = names.iter().map(String::as_str).collect();
            for b in &fleet.branches {
                if !have.contains(b.as_str()) {
                    out.push(f(
                        repo,
                        &format!("branch {b}"),
                        "missing (a release branch every plugin repo has)",
                    ));
                }
            }
            for b in &names {
                if !fleet.branches.contains(b) {
                    out.push(f(
                        repo,
                        &format!("branch {b}"),
                        "stale: not a release branch",
                    ));
                }
            }
            for b in fleet.branches.iter().filter(|b| have.contains(b.as_str())) {
                match remote.protection(repo, b) {
                    Err(e) => out.push(f(
                        repo,
                        &format!("protection {b}"),
                        format!("could not read: {e}"),
                    )),
                    Ok(None) => out.push(f(repo, &format!("protection {b}"), "unprotected")),
                    Ok(Some(got)) => {
                        let got = normalize_protection(&got);
                        if &got != spec {
                            out.push(f(
                                repo,
                                &format!("protection {b}"),
                                format!("differs from .github/fleet/protection.json: have {got}"),
                            ));
                        }
                    }
                }
            }
        }
    }

    // SETTINGS: public, Apache-2.0, `dev` the default branch.
    match remote.settings(repo) {
        Err(e) => out.push(f(repo, "settings", format!("could not read: {e}"))),
        Ok(s) => {
            for (what, have, norm) in [
                ("visibility", s.visibility.as_str(), NORM_VISIBILITY),
                ("license", s.license.as_str(), NORM_LICENSE),
                ("default branch", s.default_branch.as_str(), DEV),
            ] {
                if have != norm {
                    out.push(f(
                        repo,
                        what,
                        format!("is `{have}`, the fleet norm is `{norm}`"),
                    ));
                }
            }
        }
    }

    // FILES on dev: the render, the pin in every manifest, nothing unmanaged under .github/.
    let rendered = match render(fleet, p, t) {
        Ok(r) => r,
        Err(e) => {
            out.push(f(repo, "render", e));
            return;
        }
    };
    let files = match remote.files(repo, DEV) {
        Ok(fs) => fs,
        Err(e) => {
            out.push(f(repo, "dev", format!("could not list files: {e}")));
            return;
        }
    };
    for r in &rendered {
        match remote.read(repo, DEV, &r.path) {
            Err(e) => out.push(f(repo, &r.path, format!("could not read: {e}"))),
            Ok(None) => out.push(f(repo, &r.path, "missing (the render owns it)")),
            Ok(Some(text)) => {
                let same = match r.mode {
                    Mode::Whole => text == r.content,
                    Mode::Region => region_of(&text) == Some(r.content.as_str()),
                };
                if !same {
                    let what = if r.path == ".busbar-ref" {
                        format!(
                            "is {:?}, the fleet pin is {:?}",
                            text.trim(),
                            fleet.busbar_ref().trim()
                        )
                    } else if r.mode == Mode::Region {
                        "the managed header region differs from the render".to_string()
                    } else {
                        "differs from the render".to_string()
                    };
                    out.push(f(repo, &r.path, what));
                }
            }
        }
    }
    let owned: BTreeSet<&str> = rendered.iter().map(|r| r.path.as_str()).collect();
    for path in &files {
        if OWNED_DIRS.iter().any(|d| path.starts_with(d))
            && !owned.contains(path.as_str())
            && !p.keep.iter().any(|k| k == path)
        {
            out.push(f(
                repo,
                path,
                "unmanaged: not rendered by the fleet and not in the entry's `keep`",
            ));
        }
    }
    check_shape(p, &rendered, &files, out);
    match (
        remote.read(repo, DEV, "README.md"),
        readme_skeleton(fleet, p, t),
    ) {
        (Ok(Some(text)), Ok(skeleton)) => {
            let want = readme_headings(&skeleton);
            let have = readme_headings(&text);
            if have != want {
                out.push(f(
                    repo,
                    "README.md",
                    format!("the section skeleton differs: have {have:?}, the fleet's is {want:?}"),
                ));
            }
        }
        (_, Err(e)) => out.push(f(repo, "README.md", e)),
        // Unreadable or missing: already a finding from the render comparison above.
        _ => {}
    }
    for m in files
        .iter()
        .filter(|x| x.as_str() == "Cargo.toml" || x.ends_with("/Cargo.toml"))
    {
        match remote.read(repo, DEV, m) {
            Err(e) => out.push(f(repo, m, format!("could not read: {e}"))),
            Ok(None) => {}
            Ok(Some(text)) => {
                for rev in busbar_revs(&text) {
                    if rev != fleet.pin_sha {
                        out.push(f(
                            repo,
                            m,
                            format!(
                                "names busbar at rev {rev}, not the fleet pin {}",
                                fleet.pin_sha
                            ),
                        ));
                    }
                }
            }
        }
    }
    match remote.read(repo, DEV, &p.declares) {
        Err(e) => out.push(f(repo, &p.declares, format!("could not read: {e}"))),
        Ok(None) => out.push(f(
            repo,
            &p.declares,
            "missing: the declares file that states the plugin's contract-ABI range",
        )),
        Ok(Some(text)) => {
            if let Err(e) = contract_abi_of(&text) {
                out.push(f(repo, &p.declares, e));
            }
        }
    }
}

/// THE TWIN SHAPE: every top-level path is the render's, one of the two crate dirs
/// (`<kind>-<name>/`, `<kind>-<name>-plugin/`), generated (`Cargo.lock`) or kept by the entry; both
/// crate dirs exist; the cdylib crate is `<repo>-plugin`.
fn check_shape(
    p: &Plugin,
    rendered: &[crate::fleet::render::Rendered],
    files: &[String],
    out: &mut Vec<Finding>,
) {
    let repo = p.repo.as_str();
    let crate_dirs = p.crate_dirs();
    let rendered_tops: BTreeSet<&str> = rendered
        .iter()
        .filter_map(|r| r.path.split('/').next())
        .collect();
    let have: BTreeSet<&str> = files.iter().map(String::as_str).collect();
    let tops: BTreeSet<&str> = files.iter().filter_map(|x| x.split('/').next()).collect();
    for top in tops {
        if rendered_tops.contains(top)
            || crate_dirs.iter().any(|d| d == top)
            || GENERATED.contains(&top)
            || keeps_top(p, top)
        {
            continue;
        }
        if have.contains(format!("{top}/Cargo.toml").as_str()) {
            out.push(f(
                repo,
                &format!("{top}/"),
                format!(
                    "a crate dir outside the twin layout: a plugin repo's crates are exactly `{}/` and `{}/`",
                    crate_dirs[0], crate_dirs[1]
                ),
            ));
        } else {
            out.push(f(
                repo,
                top,
                "unmanaged top-level path: not rendered, not one of the two crate dirs, not in the entry's `keep`",
            ));
        }
    }
    for d in &crate_dirs {
        if !have.contains(format!("{d}/Cargo.toml").as_str()) {
            out.push(f(
                repo,
                &format!("{d}/"),
                format!(
                    "missing: the twin crate dir (`{}/` the logic, `{}/` the cdylib)",
                    crate_dirs[0], crate_dirs[1]
                ),
            ));
        }
    }
    let want = format!("{repo}-plugin");
    if p.crate_name != want {
        out.push(f(
            repo,
            "crate",
            format!(
                "the cdylib crate is `{}`; a twin's is `{want}` in `{}/`",
                p.crate_name, crate_dirs[1]
            ),
        ));
    }
}

/// The `contract_abi` range a declares file states: `{"contract_abi": {"min": N, "max": M}}`, N <= M.
pub fn contract_abi_of(declares: &str) -> Result<(u64, u64), String> {
    let v: serde_json::Value =
        serde_json::from_str(declares).map_err(|e| format!("is not JSON: {e}"))?;
    let r = v
        .get("contract_abi")
        .ok_or("states no `contract_abi` range (the loader cannot hold the plugin to one)")?;
    match (
        r.get("min").and_then(serde_json::Value::as_u64),
        r.get("max").and_then(serde_json::Value::as_u64),
    ) {
        (Some(lo), Some(hi)) if lo <= hi => Ok((lo, hi)),
        (Some(lo), Some(hi)) => Err(format!("`contract_abi` v{lo}..=v{hi} is an empty range")),
        _ => Err("`contract_abi` must be {\"min\": <int>, \"max\": <int>}".to_string()),
    }
}

/// The `rev = "..."` of every line naming the busbar git source (a line naming it with no rev
/// yields `<none>`, which never equals a pin).
pub fn busbar_revs(manifest: &str) -> Vec<String> {
    manifest
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .filter(|l| {
            l.contains("\"https://github.com/GetBusbar/busbar\"")
                || l.contains("\"https://github.com/GetBusbar/busbar.git\"")
        })
        .map(|l| {
            l.split("rev")
                .nth(1)
                .and_then(|r| r.split('"').nth(1))
                .map(str::to_string)
                .unwrap_or_else(|| "<none>".to_string())
        })
        .collect()
}

/// Print the verdict; the exit code.
pub fn report(fleet: &Fleet, only: &[String], findings: &[Finding]) -> i32 {
    let n = fleet
        .plugins
        .iter()
        .filter(|p| only.is_empty() || only.contains(&p.repo))
        .count();
    if findings.is_empty() {
        println!(
            "fleet check: GREEN — {n} repo(s) match the render and the fleet policy (pin {})",
            fleet.pin_sha
        );
        return 0;
    }
    for x in findings {
        println!("DRIFT {} {}: {}", x.repo, x.subject, x.reason);
    }
    let repos: BTreeSet<&str> = findings.iter().map(|x| x.repo.as_str()).collect();
    println!(
        "fleet check: RED — {} finding(s) in {} of {n} repo(s)",
        findings.len(),
        repos.len()
    );
    1
}
