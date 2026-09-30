//! `cargo xtask fleet` — THE PLUGIN FLEET, held to ONE render.
//!
//! Every first-party plugin lives in its own repo (owner ruling: one repo per plugin), and the repos
//! drifted the way copies drift: four different busbar pins, five shapes of the same pin check, a
//! macOS leg on some and not others, stale branches by the dozen, protection on `main` only. The fix
//! is at the root: what a plugin repo's skeleton IS (owner, 2026-09-30: "25 repos that are TWINS") —
//! CI, release, repin, toolchain, lint config, workspace manifest, .gitignore, .mailmap, LICENSE,
//! NOTICE, community files, the README header and its section headings — is a pure function of
//! `plugins.yaml` plus the templates in `.github/fleet/`, and the CI
//! logic itself lives once, in busbar's reusable workflows (`plugin-ci.yml`, `plugin-release.yml`,
//! `plugin-repin.yml`, `plugin-conformance.yml`), taken by each repo at the busbar commit it pins.
//!
//! * `fleet render <repo> [--out <dir>]` — the files the render owns in that repo (printed, or
//!   written under `<dir>`). Nothing but `plugins.yaml` and the templates goes in.
//! * `fleet check [--repo <repo>]...` — every registered repo's `dev` against its render, plus: the
//!   release branches (`fleet.branches`) exist with IDENTICAL protection (`.github/fleet/protection.json`),
//!   no other branch remains, `.busbar-ref` and every manifest's busbar rev are the fleet pin, the
//!   repo is named `busbar-<kind>-<name>` for its own kind, no file under `.github/` exists that the
//!   render does not produce or the entry does not `keep`, every top-level path is the render's, one
//!   of the two crate dirs (`<kind>-<name>/`, `<kind>-<name>-plugin/`), `Cargo.lock` or kept, both
//!   crate dirs exist, the README carries the skeleton's sections, and the repo is public,
//!   Apache-2.0 and defaults to `dev`. Any drift exits 1, one
//!   line per finding naming the repo and the file (or branch). Reads GitHub through `gh`.
//! * `fleet sync [--repo <repo>]... [--workdir <dir>] [--dry-run]` — applies the render to each
//!   repo's `dev` (seeding an EMPTY registered repo by pushing `dev` first; it never creates a repo
//!   or changes a repo setting; moving the pin with scripts/fleet/repin.sh), commits and
//!   pushes `dev` ONLY, creates a missing release branch from `dev`, applies the protection, and
//!   lists every other branch: one fully merged into `dev`, `qa` or `main` is deleted, an unmerged
//!   one is reported and never touched.
//!
//! The logic is split so that everything that DECIDES is a pure function over data a test can plant
//! (the registry, the render, the checker over a [`remote::Remote`]); only `remote::Gh` and `sync`
//! touch the network or a clone.

pub mod check;
pub mod registry;
pub mod remote;
pub mod render;
pub mod sync;

use crate::ctx::Ctx;

pub const USAGE: &str = "usage: cargo xtask fleet render <repo> [--out <dir>]
       cargo xtask fleet check [--repo <repo>]...
       cargo xtask fleet sync [--repo <repo>]... [--workdir <dir>] [--dry-run]";

pub fn main(cx: &Ctx, args: &[String]) -> i32 {
    match run(cx, args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("fleet: {e}");
            2
        }
    }
}

fn run(cx: &Ctx, args: &[String]) -> Result<i32, String> {
    let fleet = registry::load(cx)?;
    let templates = render::Templates::load(cx)?;
    let (cmd, rest) = args.split_first().ok_or_else(|| USAGE.to_string())?;
    let mut repos = Vec::new();
    let mut out = None;
    let mut workdir = None;
    let mut dry_run = false;
    let mut positional = Vec::new();
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--repo" => repos.push(it.next().ok_or("--repo needs a value")?.clone()),
            "--out" => out = Some(it.next().ok_or("--out needs a value")?.clone()),
            "--workdir" => workdir = Some(it.next().ok_or("--workdir needs a value")?.clone()),
            "--dry-run" => dry_run = true,
            s if s.starts_with('-') => return Err(format!("unknown flag `{s}`\n{USAGE}")),
            s => positional.push(s.to_string()),
        }
    }
    for r in &repos {
        fleet.plugin(r)?;
    }
    match cmd.as_str() {
        "render" => {
            let [repo] = positional.as_slice() else {
                return Err(format!("render takes exactly one repo\n{USAGE}"));
            };
            let files = render::render(&fleet, fleet.plugin(repo)?, &templates)?;
            match out {
                Some(dir) => {
                    // NOT A `Ctx::write_file` HAZARD despite `cx` being in scope: `--out <dir>` is
                    // an arbitrary CLI argument (a satellite plugin repo's own checkout, never
                    // this tree) and is never resolved through `cx.abs`/`cx.root` — a fleet
                    // render never writes under, or is ever read back through, THIS `Ctx`.
                    let skeleton =
                        render::readme_skeleton(&fleet, fleet.plugin(repo)?, &templates)?;
                    for f in &files {
                        let p = std::path::Path::new(&dir).join(&f.path);
                        if let Some(parent) = p.parent() {
                            std::fs::create_dir_all(parent)
                                .map_err(|e| format!("{}: {e}", parent.display()))?;
                        }
                        let text = match f.mode {
                            render::Mode::Whole => f.content.clone(),
                            render::Mode::Region => render::apply_readme(
                                std::fs::read_to_string(&p).ok().as_deref(),
                                &f.content,
                                &skeleton,
                            ),
                        };
                        std::fs::write(&p, text.as_bytes())
                            .map_err(|e| format!("{}: {e}", p.display()))?;
                        println!("wrote {}", p.display());
                    }
                }
                None => {
                    for f in &files {
                        let how = match f.mode {
                            render::Mode::Whole => "whole file",
                            render::Mode::Region => "managed region",
                        };
                        println!("==> {} ({how})\n{}", f.path, f.content);
                    }
                }
            }
            Ok(0)
        }
        "check" => {
            if !positional.is_empty() {
                return Err(format!("check takes no positional arguments\n{USAGE}"));
            }
            let findings = check::check(&fleet, &templates, &remote::Gh, &repos);
            Ok(check::report(&fleet, &repos, &findings))
        }
        "sync" => {
            if !positional.is_empty() {
                return Err(format!("sync takes no positional arguments\n{USAGE}"));
            }
            let workdir = workdir
                .unwrap_or_else(|| cx.scratch().join("fleet").to_string_lossy().into_owned());
            sync::sync(cx, &fleet, &templates, &repos, &workdir, dry_run)
        }
        other => Err(format!("unknown fleet command `{other}`\n{USAGE}")),
    }
}

#[cfg(test)]
#[path = "fleet/tests.rs"]
mod tests;
