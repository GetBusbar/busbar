//! plugin-ci.yml's "does the repo have its crates yet" step (`id: crates`, on the linux AND the
//! macOS leg), run as the runner runs it: the step's own `run:` text, read out of the committed
//! workflow, executed by bash in a fixture plugin checkout. Not a copy of the logic: the text CI runs.
//!
//! THE HOLE THIS HOLDS SHUT (hook-webrequest #24 merged broken through it): the step read ANY
//! `cargo metadata` failure, a broken manifest included, as "no crates yet", set `present=false`,
//! and every build, test and conformance step after it skipped while the leg went green. The
//! no-crates pass is plugins.yaml's `pending_crate: true` for this repo and nothing else's; any other
//! failure to read the workspace is RED, with cargo's error in the log (BUSBAR-1.6.0.md Law 0: an
//! instrument that cannot produce a NO is not a check; Law 10: a proof must not point at something
//! that never runs).

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;
use xtask::yaml_lite;

const REPO: &str = "busbar-hook-fixture";

/// The committed workflow, compiled in: this test is rebuilt whenever the workflow changes.
const PLUGIN_CI: &str = include_str!("../../.github/workflows/plugin-ci.yml");

/// The `id: crates` step of each leg, as the runner reads the workflow.
fn crates_steps() -> Vec<(&'static str, Value)> {
    let wf = yaml_lite::parse_structure(PLUGIN_CI).expect("plugin-ci.yml parses");
    ["linux", "macos"]
        .into_iter()
        .map(|job| {
            let steps = wf["jobs"][job]["steps"]
                .as_array()
                .unwrap_or_else(|| panic!("plugin-ci.yml jobs.{job} has no steps"));
            let step = steps
                .iter()
                .find(|s| s["id"] == "crates")
                .unwrap_or_else(|| panic!("plugin-ci.yml jobs.{job} has no `id: crates` step"))
                .clone();
            (job, step)
        })
        .collect()
}

/// What the plugin checkout's root holds.
#[derive(Clone, Copy)]
enum Manifest {
    /// No Cargo.toml at all.
    Absent,
    /// A one-package workspace cargo reads.
    Valid,
    /// A Cargo.toml that is not TOML.
    Unparseable,
    /// A workspace naming a member that is not there.
    MissingMember,
}

/// What plugins.yaml at the pin says about the repo under test.
#[derive(Clone, Copy)]
enum Entry {
    Pending,
    NotPending,
    Unregistered,
}

struct Outcome {
    ok: bool,
    output: String,
    log: String,
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "plugin-ci-crates-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// A registry whose neighbours on BOTH sides are pending, so a lookup that leaks one entry's
/// `pending_crate` into the next is caught.
fn registry(entry: Entry) -> String {
    let mine = match entry {
        Entry::Pending => format!("  - repo: {REPO}\n    kind: hook\n    pending_crate: true\n"),
        Entry::NotPending => format!("  - repo: {REPO}\n    kind: hook\n    released: true\n"),
        Entry::Unregistered => String::new(),
    };
    format!(
        "fleet:\n  busbar_ref: \"x 1.6.0\"\n  branches: [dev, qa, main]\nplugins:\n  \
         - repo: busbar-hook-before\n    kind: hook\n    pending_crate: true\n\
         {mine}  - repo: busbar-hook-after\n    kind: hook\n    pending_crate: true\n"
    )
}

fn run_step(step: &Value, tag: &str, manifest: Manifest, entry: Entry, lang: &str) -> Outcome {
    let script = step["run"]
        .as_str()
        .expect("the crates step has a run: script");
    let root = scratch(tag);
    let plugin = root.join("plugin");
    std::fs::create_dir_all(plugin.join("src")).unwrap();
    std::fs::write(plugin.join("src/lib.rs"), "").unwrap();
    let toml = match manifest {
        Manifest::Absent => None,
        Manifest::Valid => Some(
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n",
        ),
        Manifest::Unparseable => Some("[package\nname = \"fixture\"\nversion = \n"),
        Manifest::MissingMember => Some("[workspace]\nresolver = \"2\"\nmembers = [\"gone\"]\n"),
    };
    if let Some(t) = toml {
        std::fs::write(plugin.join("Cargo.toml"), t).unwrap();
    }
    let reg = root.join("busbar").join("plugins.yaml");
    std::fs::create_dir_all(reg.parent().unwrap()).unwrap();
    std::fs::write(&reg, registry(entry)).unwrap();
    let gh_out = root.join("github_output");
    std::fs::write(&gh_out, "").unwrap();

    // `cargo` as the runner has it: on PATH. The binary running this build is the one to use.
    let cargo_dir = Path::new(env!("CARGO")).parent().unwrap().to_path_buf();
    let path = std::env::join_paths(std::iter::once(cargo_dir).chain(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    )))
    .unwrap();
    let out = Command::new("bash")
        .args(["--noprofile", "--norc", "-eo", "pipefail", "-c", script])
        .current_dir(plugin)
        .env("PATH", path)
        .env("GITHUB_WORKSPACE", &root)
        .env("GITHUB_OUTPUT", &gh_out)
        .env("GITHUB_REPOSITORY", format!("GetBusbar/{REPO}"))
        .env("PLUGIN_LANG", lang)
        .env("REGISTRY", reg)
        .output()
        .expect("bash runs");
    let outcome = Outcome {
        ok: out.status.success(),
        output: std::fs::read_to_string(&gh_out).unwrap_or_default(),
        log: format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    };
    let _ = std::fs::remove_dir_all(&root);
    outcome
}

fn present(o: &Outcome) -> Option<&str> {
    o.output
        .lines()
        .filter_map(|l| l.strip_prefix("present="))
        .next_back()
}

/// A failure to read the workspace in a repo plugins.yaml does NOT mark pending_crate is RED on
/// both legs, and the log carries cargo's own error. THE PLANTED CASE: before this, each of these
/// set `present=false` and exited 0, and the leg skipped every build and test and went green.
#[test]
fn a_broken_workspace_outside_pending_crate_is_red_with_the_error_shown() {
    for (job, step) in crates_steps() {
        for (what, manifest, entry, needle) in [
            (
                "an unparseable Cargo.toml",
                Manifest::Unparseable,
                Entry::NotPending,
                "Cargo.toml",
            ),
            (
                "a workspace naming a missing member",
                Manifest::MissingMember,
                Entry::NotPending,
                "gone",
            ),
            (
                "no Cargo.toml at all",
                Manifest::Absent,
                Entry::NotPending,
                "Cargo.toml",
            ),
            (
                "an unparseable Cargo.toml in an unregistered repo",
                Manifest::Unparseable,
                Entry::Unregistered,
                "Cargo.toml",
            ),
        ] {
            let o = run_step(&step, job, manifest, entry, "rust");
            assert!(
                !o.ok,
                "{job}: {what}, not pending_crate, passed the crates step (output {:?}):\n{}",
                o.output, o.log
            );
            assert_ne!(
                present(&o),
                Some("false"),
                "{job}: {what} was recorded as `no crates yet`:\n{}",
                o.log
            );
            assert!(
                o.log.contains("::error::") && o.log.contains(needle),
                "{job}: {what} went red without the error shown (want `::error::` and `{needle}`):\n{}",
                o.log
            );
        }
    }
}

/// The pass the step exists for still holds: a repo plugins.yaml marks pending_crate, whose crates
/// have not moved in (no manifest, or a seeded one cargo cannot read yet), is `present=false` and
/// green; a readable workspace is `present=true` whether or not the flag is still set; a C plugin
/// has no Cargo workspace by design and its proof is the C path.
#[test]
fn the_pending_crate_pass_and_a_real_workspace_still_hold() {
    for (job, step) in crates_steps() {
        for (what, manifest, entry, lang, want) in [
            (
                "pending, no Cargo.toml",
                Manifest::Absent,
                Entry::Pending,
                "rust",
                "false",
            ),
            (
                "pending, an unreadable seeded manifest",
                Manifest::Unparseable,
                Entry::Pending,
                "rust",
                "false",
            ),
            (
                "a readable workspace",
                Manifest::Valid,
                Entry::NotPending,
                "rust",
                "true",
            ),
            (
                "a readable workspace, pending flag stale",
                Manifest::Valid,
                Entry::Pending,
                "rust",
                "true",
            ),
            (
                "a C plugin (no Cargo workspace by design)",
                Manifest::Absent,
                Entry::NotPending,
                "c",
                "false",
            ),
        ] {
            let o = run_step(&step, job, manifest, entry, lang);
            assert!(o.ok, "{job}: {what} went red:\n{}", o.log);
            assert_eq!(
                present(&o),
                Some(want),
                "{job}: {what}: want present={want}, output {:?}:\n{}",
                o.output,
                o.log
            );
        }
    }
}
