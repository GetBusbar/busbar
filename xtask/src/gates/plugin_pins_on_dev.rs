//! `cargo xtask gate plugin-pins-on-dev` — EVERY PLUGIN REV THIS TREE PINS IS REACHABLE FROM THAT
//! PLUGIN REPO'S `dev` BRANCH.
//!
//! The root `Cargo.toml` pulls each moved-out plugin as one git dependency at one commit
//! (`[workspace.dependencies] name = { git = "https://github.com/GetBusbar/<repo>", rev = "<sha>" }`).
//! A rev that lives only on a side branch (a stopgap, an unmerged PR head) builds today and then
//! vanishes the day that branch is deleted or force-pushed; busbar's pin would point at nothing.
//! So a pin is only a pin when `dev` of that repo already contains it.
//!
//! THE MEASUREMENT. For each distinct GetBusbar plugin repo named by a git dependency, fetch its
//! `dev` into a bare cache repo under `target/plugin-pins-on-dev/` (reused across runs):
//! `git fetch --filter=blob:none --no-tags <url> dev`, then ask
//! `git merge-base --is-ancestor <rev> FETCH_HEAD`. Exit 0 is reachable; exit 1 is a rev `dev` does
//! not contain; any other status (the rev is unknown to `dev`'s history altogether) is the same
//! refusal.
//!
//! FAIL CLOSED (Law 10). A fetch that fails is RED and names the repo and git's own words — never
//! a skipped repo, never a green built on the cache of an earlier run: the fetch is repeated every
//! run, and its failure is the verdict.
//!
//! ONE ROW. The ledger's owed set is a fixed list of ids (`Gate::owed`; a row nobody owes is
//! refused), and a plugin roster that moves cannot be a fixed list, so the rule is the id and the
//! moving part is the detail: the row names every pinned plugin repo, and RED names each repo that
//! failed and why. The `busbar_ref` pin in `plugins.yaml` pins busbar itself, not a plugin rev, so
//! it is not read here.
//!
//! THE SELFTEST uses no network: the overlay command [`REMOTE_BASE_KEY`] rewrites every
//! `https://github.com/GetBusbar/<repo>` to `<base>/<repo>`, a local git repo built for the case.

use std::path::{Path, PathBuf};

use crate::ctx::{Ctx, Overlay};
use crate::gates::{prove_green, prove_red, Gate, Report};
use crate::gitp;
use crate::ledger::{Row, Verdict};
use crate::toml_lite;

pub const ROW_PINS: &str = "plugin-pins-on-dev:pins";

/// The overlay command that points the fetch at a local directory of repos (selftest only).
pub const REMOTE_BASE_KEY: &str = "plugin-pins-remote-base";

const ORG_PREFIX: &str = "https://github.com/GetBusbar/";

#[derive(Default)]
pub struct PluginPinsOnDevGate {
    /// The local directory of repos the selftest's own instance fetches from. The gate that proves
    /// itself carries this on the INSTANCE, so the unplanted baseline and every plant read the same
    /// remote whatever overlay or base layer a case runs under.
    remote: Option<String>,
}

/// One GetBusbar git dependency: dependency name, repo URL as written, and the rev it pins (`None`
/// when it pins nothing: a `branch =` or `tag =` or no selector at all).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Pin {
    dep: String,
    url: String,
    rev: Option<String>,
    /// What the dependency names instead of a rev, for the refusal (`branch = "dev"`).
    floating: Option<String>,
}

/// Every GetBusbar git dependency of `[workspace.dependencies]`, in all the spellings TOML has for
/// it: an inline table (`name = { git = '…', rev = '…' }`, either quote), a dotted table
/// (`[workspace.dependencies.name]`) and dotted keys (`name.git = "…"`). A dependency with no
/// `rev` is returned too, because skipping it is how a branch-tracking dependency goes unchecked.
fn pins(manifest: &str) -> Vec<Pin> {
    use std::collections::BTreeMap;
    let doc = toml_lite::parse_text(manifest);
    let mut deps: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    for (dep, raw) in &doc.table("workspace.dependencies").entries {
        match toml_lite::inline_table(raw) {
            Some(items) => {
                let m = deps.entry(dep.clone()).or_default();
                for (k, v) in items {
                    m.insert(k, toml_lite::string_value(&v));
                }
            }
            None => {
                if let Some((name, key)) = dep.split_once('.') {
                    deps.entry(name.to_string())
                        .or_default()
                        .insert(key.to_string(), toml_lite::string_value(raw));
                }
            }
        }
    }
    for (path, table) in &doc.tables {
        let Some(name) = path.strip_prefix("workspace.dependencies.") else {
            continue;
        };
        let m = deps.entry(name.to_string()).or_default();
        for (k, v) in &table.entries {
            m.insert(k.clone(), toml_lite::string_value(v));
        }
    }
    let mut out = Vec::new();
    for (dep, kv) in deps {
        let Some(url) = kv.get("git").filter(|u| u.starts_with(ORG_PREFIX)) else {
            continue;
        };
        let floating = ["branch", "tag"]
            .iter()
            .find_map(|k| kv.get(*k).map(|v| format!("{k} = \"{v}\"")));
        out.push(Pin {
            dep,
            url: url.clone(),
            rev: kv.get("rev").cloned(),
            floating,
        });
    }
    out
}

fn remote_base(cx: &Ctx, own: Option<&str>) -> Option<String> {
    cx.overlay_command(REMOTE_BASE_KEY)
        .or_else(|| own.map(str::to_string))
        .or_else(|| cx.base().and_then(|b| b.command(REMOTE_BASE_KEY)).cloned())
}

/// The URL actually fetched: the pinned one, or the local stand-in under the selftest's base.
fn fetch_url(cx: &Ctx, own: Option<&str>, url: &str) -> String {
    match remote_base(cx, own) {
        Some(base) => {
            let repo = url.trim_start_matches(ORG_PREFIX).trim_end_matches(".git");
            format!("{}/{repo}", base.trim_end_matches('/'))
        }
        None => url.to_string(),
    }
}

fn cache_dir(cx: &Ctx, fetched_url: &str) -> PathBuf {
    let key: String = fetched_url
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    cx.abs("target/plugin-pins-on-dev").join(key)
}

/// Fetch `dev` into the bare cache repo, or say why it could not be.
fn fetch_dev(cache: &Path, url: &str) -> Result<(), String> {
    if !cache.join("HEAD").exists() {
        std::fs::create_dir_all(cache).map_err(|e| format!("{}: {e}", cache.display()))?;
        gitp::git(cache, &["init", "--bare", "-q"])?;
    }
    gitp::git(
        cache,
        &["fetch", "-q", "--filter=blob:none", "--no-tags", url, "dev"],
    )
    .map(|_| ())
}

/// `Ok(true)` reachable, `Ok(false)` not an ancestor of `dev`, `Err` could not ask.
fn reachable(cache: &Path, rev: &str) -> Result<bool, String> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(cache)
        .args(["merge-base", "--is-ancestor", rev, "FETCH_HEAD"])
        .output()
        .map_err(|e| format!("git merge-base: {e}"))?;
    match out.status.code() {
        Some(0) => Ok(true),
        // 1 is "not an ancestor"; 128 is a rev dev's history does not contain at all.
        Some(1) | Some(128) => Ok(false),
        other => Err(format!(
            "git merge-base exited {}: {}",
            other.unwrap_or(-1),
            String::from_utf8_lossy(&out.stderr).trim()
        )),
    }
}

impl Gate for PluginPinsOnDevGate {
    fn name(&self) -> &'static str {
        "plugin-pins-on-dev"
    }

    fn owed(&self) -> Vec<String> {
        vec![ROW_PINS.to_string()]
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let manifest = match cx.read("Cargo.toml") {
            Ok(m) => m,
            Err(why) => {
                return Verdict::of(vec![Row::fail(
                    ROW_PINS,
                    "the root Cargo.toml could not be read",
                    why,
                )])
            }
        };
        let pinned = pins(&manifest);
        if pinned.is_empty() {
            return Verdict::of(vec![Row::fail(
                ROW_PINS,
                "no pinned GetBusbar plugin git dependency was found",
                "[workspace.dependencies] names none; a gate that read zero pins would be green \
                 about nothing",
            )]);
        }

        // ONE FETCH AT A TIME: the cases of a battery run in parallel and share the bare cache and
        // its FETCH_HEAD, and two fetches into one repo refuse each other.
        static FETCH: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _one_at_a_time = FETCH.lock().unwrap_or_else(|e| e.into_inner());

        let mut repos: Vec<&str> = pinned.iter().map(|p| p.url.as_str()).collect();
        repos.sort_unstable();
        repos.dedup();

        let mut fetched: std::collections::BTreeMap<&str, Result<PathBuf, String>> =
            std::collections::BTreeMap::new();
        for url in repos {
            let real = fetch_url(cx, self.remote.as_deref(), url);
            let cache = cache_dir(cx, &real);
            let got = fetch_dev(&cache, &real).map(|()| cache);
            fetched.insert(url, got);
        }

        let mut bad = Vec::new();
        let mut ok = Vec::new();
        for p in &pinned {
            let repo = p.url.trim_start_matches(ORG_PREFIX);
            let Some(rev) = p.rev.as_deref() else {
                bad.push(format!(
                    "{repo} ({}): pins no rev ({}) — a dependency that follows a moving ref is \
                     not a pin; name the merged commit with `rev =`",
                    p.dep,
                    p.floating.as_deref().unwrap_or("no branch, tag or rev")
                ));
                continue;
            };
            match &fetched[p.url.as_str()] {
                Err(why) => bad.push(format!(
                    "{repo} ({}): could not fetch dev, so the pin {} is unproven: {why}",
                    p.dep, rev
                )),
                Ok(cache) => match reachable(cache, rev) {
                    Ok(true) => ok.push(format!("{repo}@{}", &rev[..rev.len().min(12)])),
                    Ok(false) => bad.push(format!(
                        "{repo} ({}): rev {} is not reachable from dev",
                        p.dep, rev
                    )),
                    Err(why) => bad.push(format!(
                        "{repo} ({}): could not test rev {}: {why}",
                        p.dep, rev
                    )),
                },
            }
        }

        let row = if bad.is_empty() {
            Row::pass(
                ROW_PINS,
                "every pinned plugin rev is reachable from its repo's dev",
                format!(
                    "{} pin(s) checked with git merge-base --is-ancestor <rev> FETCH_HEAD: {}",
                    ok.len(),
                    ok.join(" | ")
                ),
            )
        } else {
            Row::fail(
                ROW_PINS,
                "a pinned plugin rev is not provably on its repo's dev",
                format!(
                    "{} of {} pin(s) failed: {} — merge the rev into that repo's dev and repin \
                     to the merged commit",
                    bad.len(),
                    pinned.len(),
                    bad.join(" | ")
                ),
            )
        };
        Verdict::of(vec![row])
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        let fake = match FakeRemote::build() {
            Ok(f) => f,
            Err(why) => {
                // The scaffold itself failed: surface it as a RED case that names the cause.
                report.push(prove_red(
                    cx,
                    self,
                    format!("the selftest's local remote could not be built: {why}"),
                    &[ROW_PINS],
                    Overlay::new(),
                    &[ROW_PINS],
                ));
                return report;
            }
        };

        let manifest = |sha: &str| {
            format!(
                "[workspace.dependencies]\nzz-fake-plugin = {{ git = \"{ORG_PREFIX}zz-fake-plugin\", rev = \"{sha}\" }}\n"
            )
        };

        // THE GATE UNDER PROOF CARRIES THE REMOTE ITSELF, so the unplanted baseline and every plant
        // fetch the same local repo whatever overlay or base layer the case runs under.
        let gate: &'a PluginPinsOnDevGate = Box::leak(Box::new(PluginPinsOnDevGate {
            remote: Some(fake.base.display().to_string()),
        }));

        // BASE: the dev rev. Baseline and green both read it.
        let mut base = Overlay::new();
        base.set("Cargo.toml", manifest(&fake.dev_sha));
        let cx = cx.with_base(base);

        report.push(prove_green(
            &cx,
            gate,
            "a rev on the remote's dev is GREEN",
            &[ROW_PINS],
        ));

        // PLANT (a): a rev that exists only on a side branch.
        let mut side = Overlay::new();
        side.set("Cargo.toml", manifest(&fake.side_sha));
        report.push(prove_red(
            &cx,
            gate,
            "a rev only on a side branch is RED, naming the repo and the rev",
            &[ROW_PINS],
            side,
            &[
                "zz-fake-plugin",
                fake.side_sha.as_str(),
                "not reachable from dev",
            ],
        ));

        // PLANT (b): the remote cannot be fetched at all. Fail closed, naming the repo.
        let mut gone = Overlay::new();
        gone.set_command(
            REMOTE_BASE_KEY,
            fake.base.join("no-such-remote-dir").display().to_string(),
        );
        report.push(prove_red(
            &cx,
            gate,
            "a repo whose dev cannot be fetched is RED, never skipped",
            &[ROW_PINS],
            gone,
            &["zz-fake-plugin", "could not fetch dev"],
        ));

        // PLANTS (c-e): the three spellings a pin can hide in.
        let unknown = "0000000000000000000000000000000000000001";
        let mut single = Overlay::new();
        single.set(
            "Cargo.toml",
            format!(
                "[workspace.dependencies]\nzz-fake-plugin = {{ git = '{ORG_PREFIX}zz-fake-plugin', rev = '{unknown}' }}\n"
            ),
        );
        report.push(prove_red(
            &cx,
            gate,
            "a single-quoted pin with a rev dev does not contain is RED",
            &[ROW_PINS],
            single,
            &["zz-fake-plugin", "not reachable from dev"],
        ));
        let mut dotted = Overlay::new();
        dotted.set(
            "Cargo.toml",
            format!(
                "[workspace.dependencies.zz-fake-plugin]\ngit = \"{ORG_PREFIX}zz-fake-plugin\"\nrev = \"{}\"\n",
                fake.side_sha
            ),
        );
        report.push(prove_red(
            &cx,
            gate,
            "a pin written as a [workspace.dependencies.<name>] table is read, and RED when off dev",
            &[ROW_PINS],
            dotted,
            &["zz-fake-plugin", "not reachable from dev"],
        ));
        let mut floating = Overlay::new();
        floating.set(
            "Cargo.toml",
            format!(
                "[workspace.dependencies]\nzz-fake-plugin = {{ git = \"{ORG_PREFIX}zz-fake-plugin\", branch = \"dev\" }}\n"
            ),
        );
        report.push(prove_red(
            &cx,
            gate,
            "a GetBusbar git dependency that follows a branch and pins no rev is RED, never skipped",
            &[ROW_PINS],
            floating,
            &["zz-fake-plugin", "pins no rev"],
        ));

        report
    }
}

/// A local stand-in for a plugin repo (left on disk: the cases run after `selftest` returns, and the
/// next build clears it): `dev` carries one commit, a side branch carries another.
struct FakeRemote {
    base: PathBuf,
    dev_sha: String,
    side_sha: String,
}

impl FakeRemote {
    fn build() -> Result<FakeRemote, String> {
        let base = std::env::temp_dir().join(format!("xtask-pins-on-dev-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let repo = base.join("zz-fake-plugin");
        std::fs::create_dir_all(&repo).map_err(|e| format!("{}: {e}", repo.display()))?;
        let g = |args: &[&str]| {
            let mut full = vec![
                "-c",
                "user.name=selftest",
                "-c",
                "user.email=selftest@example.invalid",
                "-c",
                "commit.gpgsign=false",
            ];
            full.extend_from_slice(args);
            gitp::git(&repo, &full)
        };
        g(&["init", "-q", "-b", "dev"])?;
        g(&["commit", "-q", "--allow-empty", "-m", "on dev"])?;
        let dev_sha = g(&["rev-parse", "HEAD"])?.trim().to_string();
        g(&["checkout", "-q", "-b", "side"])?;
        g(&["commit", "-q", "--allow-empty", "-m", "side only"])?;
        let side_sha = g(&["rev-parse", "HEAD"])?.trim().to_string();
        g(&["checkout", "-q", "dev"])?;
        Ok(FakeRemote {
            base,
            dev_sha,
            side_sha,
        })
    }
}
