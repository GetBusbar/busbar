// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A REAL `kind: store` PLUGIN, LOADED OVER THE REAL C ABI — the fixture every durability claim in
//! this crate is judged against.
//!
//! ## Why a store double will not do
//!
//! The `Store` trait's durable methods are DEFAULTED to accept-and-keep-nothing, so a write's
//! `Ok(())` is worthless as evidence. That is a deliberate compatibility posture and it has a sharp
//! edge: `DynStore` — the `dyn Store` the engine holds for EVERY plugin-loaded backend — inherits
//! those defaults for any method the plugin ABI does not carry a variant for. This release already
//! paid for that once, with an ABI that carried four store methods while the trait carried ten:
//! every task and call-log write through the path a customer actually takes was accepted and
//! silently discarded, while each backend crate's own unit tests passed, because they never crossed
//! the ABI.
//!
//! So durability is proven the only way it can be: a real `dlopen` of a real cdylib, a write, the
//! handle DROPPED so the library unloads, a second `dlopen`, and a read back.
//!
//! ## Absence and staleness cannot reach an assertion — cargo is asked, not guessed
//!
//! A "skip: cdylib not built" line is how the coverage that would have caught the four-method ABI
//! silently stops running — the run stays green and nobody reads the line. And a STALE artifact is
//! worse than an absent one: it answers every write `Ok(())` and every read empty, which is
//! byte-for-byte the signature of the defect this fixture exists to catch, so it would produce a
//! failure indistinguishable from a real regression — and, in the other direction, an artifact
//! built BEFORE a regression produces a PASS while the shipped ABI is broken.
//!
//! Neither reading is survivable, so neither is left to a heuristic. `cargo test -p busbar-kernel`
//! does NOT emit this cdylib on its own — a `[dev-dependencies]` edge is satisfied with the crate's
//! RLIB and cargo never produces the `.so`/`.dylib`, because nothing in the build graph consumes it
//! (the load is by path at runtime, which cargo cannot see). So the fixture BUILDS it, once per
//! process, and lets cargo — not a timestamp comparison — decide whether anything needed rebuilding:
//!
//!   1. if the conventional artifact is already at `<target>/<profile>/` and no watched source is
//!      newer than it, use it. That is the CI path (`cargo build -p busbar-store-example-plugin`
//!      before `cargo test`), and it costs nothing;
//!   2. otherwise run that build into `<target>/<profile>/plugin-fixtures/`, a target directory of
//!      this fixture's own, and load what cargo reports. A dedicated directory is what keeps the
//!      nested build from thrashing the outer one: building the plugin package directly resolves
//!      features differently from `cargo test -p busbar-kernel`, and sharing one directory made the
//!      two invalidate each other's `busbar-kernel` on every alternation (MEASURED: 83s of
//!      recompilation per alternation). It also removes any question of contending for the outer
//!      target directory's lock.
//!
//! Because step 2 is always available, the timestamp check in step 1 is only ever an optimisation
//! gate: a false "stale" costs one cheap, correct rebuild instead of producing a wrong RED. That is
//! what lets the watched set be generous rather than minimal.
//!
//! `BUSBAR_NO_FIXTURE_BUILD=1` turns step 2 off, for a hermetic runner that forbids a nested cargo.
//! The artifact must then be prebuilt, and a missing or stale one fails loudly naming the EXACT
//! command — profile included, derived from where this test binary is actually running.

use busbar_api::Store;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

/// The crates whose sources decide what the cdylib DOES across the ABI: the plugin itself, the SDK
/// it is written against, the ABI header both sides compile to, the crate that declares the `Store`
/// trait it implements, and the contract types that trait is spelled in. A change to any of them can
/// move the artifact's behaviour, and the four-method defect lived in the third.
const WATCHED_CRATES: &[&str] = &[
    "store-example-plugin",
    "plugin-sdk",
    "busbar-plugin",
    "api",
    "busbar-contract",
];

/// The cdylib path, resolved (and built if needed) exactly ONCE per test process. The batteries run
/// in parallel; without this they would each invoke cargo and serialise on cargo's own lock.
static CDYLIB: OnceLock<PathBuf> = OnceLock::new();

/// Locate the `busbar-store-example-plugin` cdylib, building it if it is absent or stale.
///
/// Derived from THIS TEST BINARY's own path (`<target>/<profile>/deps/<bin>`) rather than a
/// hard-coded `target/debug`, so it is correct under `--release`, under a custom `CARGO_TARGET_DIR`,
/// and under a workspace built into a shared target directory.
pub fn example_store_cdylib() -> PathBuf {
    CDYLIB.get_or_init(resolve_cdylib).clone()
}

/// `<target>/<profile>` for the running test binary, and the profile DIRECTORY name (`debug`,
/// `release`, or a custom profile's own directory).
fn profile_dir() -> (PathBuf, String) {
    let exe = std::env::current_exe().expect("the test binary knows its own path");
    let dir = exe
        .parent()
        .and_then(|deps| deps.parent())
        .expect("<target>/<profile>/deps/<test-binary>")
        .to_path_buf();
    let profile = dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "debug".into());
    (dir, profile)
}

/// The workspace root, from this crate's manifest dir (`<workspace>/crates/busbar-kernel`).
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|c| c.parent())
        .expect("<workspace>/crates/busbar-kernel")
        .to_path_buf()
}

/// The `cargo build` argument that selects `profile`, and the human spelling of the whole command.
/// `cargo test --release` needs `cargo build --release`, which is why this is derived rather than
/// written down: a message naming the wrong profile sends a reader to rebuild the artifact they
/// already have.
fn profile_args(profile: &str) -> Vec<String> {
    match profile {
        "debug" => Vec::new(),
        "release" => vec!["--release".into()],
        other => vec!["--profile".into(), other.into()],
    }
}

fn build_command(profile: &str) -> String {
    let mut words = vec!["cargo".to_string(), "build".to_string()];
    words.extend(profile_args(profile));
    words.extend(["-p".to_string(), "busbar-store-example-plugin".to_string()]);
    words.join(" ")
}

/// The first watched source modified after `built`, if any. Returns the file so a message can name
/// it — "something is stale" sends a reader hunting; naming the file does not.
fn newer_source_than(built: std::time::SystemTime) -> Option<PathBuf> {
    let crates = workspace_root().join("crates");
    WATCHED_CRATES
        .iter()
        .find_map(|crate_dir| newest_source_under(&crates.join(crate_dir), built))
}

fn resolve_cdylib() -> PathBuf {
    let (profile_dir, profile) = profile_dir();
    let name = busbar_plugin_loader::plugin_library_filename("busbar_store_example_plugin");

    // 1. The conventional artifact, when a prior `cargo build -p busbar-store-example-plugin` left
    //    one and nothing watched has moved since. This is the CI path and it builds nothing.
    let prebuilt = profile_dir.join(&name);
    let prebuilt_age = std::fs::metadata(&prebuilt).and_then(|m| m.modified()).ok();
    if prebuilt_age.is_some_and(|built| newer_source_than(built).is_none()) {
        return prebuilt;
    }

    if std::env::var_os("BUSBAR_NO_FIXTURE_BUILD").is_some() {
        let why = match prebuilt_age {
            None => format!("is not built at {}", prebuilt.display()),
            Some(built) => format!(
                "at {} is STALE — {} is newer than the artifact",
                prebuilt.display(),
                newer_source_than(built)
                    .unwrap_or_else(|| PathBuf::from("<a watched source>"))
                    .display()
            ),
        };
        panic!(
            "the busbar-store-example-plugin cdylib {why}, and BUSBAR_NO_FIXTURE_BUILD is set so \
             this fixture may not build it. The batteries that load it cross the REAL plugin C ABI \
             on purpose — the defect they exist to catch (an ABI that carried four store methods \
             and discarded every write through it) is invisible to any in-process double, and a \
             STALE cdylib keeps nothing and reports success, which is that same defect's signature \
             — so they refuse to skip and they refuse to judge. Run exactly this, from the \
             workspace root, with the same CARGO_TARGET_DIR this run used:\n    {}",
            build_command(&profile)
        );
    }

    // 2. Build it ourselves, into a target directory of this fixture's own, and let cargo decide
    //    what actually needed doing.
    let fixture_target = profile_dir.join("plugin-fixtures");
    build_fixture(&fixture_target, &profile);
    let built = fixture_target.join(&profile).join(&name);
    assert!(
        built.exists(),
        "`{}` reported success but produced no cdylib at {}. The batteries that load it cross the \
         REAL plugin C ABI on purpose and refuse to skip; a fixture that cannot produce its own \
         artifact must say so rather than judge the wrong tree.",
        build_command(&profile),
        built.display()
    );
    built
}

/// Run the plugin build into `target_dir`, failing loudly with cargo's own words.
///
/// `CARGO` is the cargo that launched this test run, so a toolchain-pinned run builds the fixture
/// with the same toolchain it built everything else with. `CARGO_TARGET_DIR` is set (not inherited)
/// and `CARGO_BUILD_TARGET_DIR` removed, so an outer target-directory setting cannot redirect this
/// build away from where the caller then looks for it.
fn build_fixture(target_dir: &Path, profile: &str) {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let out = std::process::Command::new(&cargo)
        .current_dir(workspace_root())
        .arg("build")
        .args(profile_args(profile))
        .args(["-p", "busbar-store-example-plugin"])
        .env("CARGO_TARGET_DIR", target_dir)
        .env_remove("CARGO_BUILD_TARGET_DIR")
        .output()
        .unwrap_or_else(|e| {
            panic!(
                "could not run `{}` to build the plugin cdylib this fixture loads: {e}. Set \
                 BUSBAR_NO_FIXTURE_BUILD=1 and prebuild it if this runner forbids a nested cargo.",
                build_command(profile)
            )
        });
    assert!(
        out.status.success(),
        "`{}` FAILED (status {:?}) while building the cdylib these batteries dlopen. This is a \
         BUILD failure, not a durability failure, and it must not be read as one — judging a \
         cdylib that was never produced would mean judging the wrong tree.\nstdout:\n{}\nstderr:\n{}",
        build_command(profile),
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The first `.rs` or `Cargo.toml` under `root` modified after `built`, if any.
///
/// A directory it cannot read counts as CHANGED rather than unchanged: the answer this function
/// exists to give is "can the artifact still be trusted", and "I could not look" is not a yes. It
/// used to `?` out of the whole walk on the first unreadable directory, which returned `None` —
/// "nothing is newer" — from a walk that had not finished looking.
fn newest_source_under(root: &Path, built: std::time::SystemTime) -> Option<PathBuf> {
    if !root.exists() {
        return Some(root.to_path_buf());
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return Some(dir);
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                // `target/` under a crate dir is build output, not source; it is always newer.
                if p.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                stack.push(p);
                continue;
            }
            let is_source = p.extension().is_some_and(|e| e == "rs")
                || p.file_name().is_some_and(|n| n == "Cargo.toml");
            if is_source
                && entry
                    .metadata()
                    .and_then(|m| m.modified())
                    .is_ok_and(|m| m > built)
            {
                return Some(p);
            }
        }
    }
    None
}

/// A PRIVATE durable file for one test, and the plugin config that selects the fixture's on-disk
/// mode. Per-test and per-thread, so the parallel harness cannot make two tests share a ledger.
pub fn durable_cfg(tag: &str) -> (PathBuf, String) {
    let dir = super::scratch_dir(&format!(
        "busbar-durable-store-{}-{tag}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let file = dir.join("durable.json");
    let _ = std::fs::remove_file(&file);
    let cfg = serde_json::json!({ "durable_path": file.to_string_lossy() }).to_string();
    (file, cfg)
}

/// Open the plugin over the ABI. Each call is a fresh `dlopen` + `busbar_open` — a restart, or a
/// second node of a fleet, depending on what the caller is asking about.
pub fn open_plugin(cfg: &str) -> Arc<dyn Store> {
    let path = example_store_cdylib();
    Arc::from(
        busbar_plugin_loader::load_store(&path, cfg)
            .expect("load busbar-store-example-plugin over the real plugin C ABI"),
    )
}
