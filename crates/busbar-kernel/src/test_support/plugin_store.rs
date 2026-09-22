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
//! ## Absence and staleness are both hard failures, with different messages
//!
//! A "skip: cdylib not built" line is how the coverage that would have caught the four-method ABI
//! silently stops running — the run stays green and nobody reads the line. And a STALE artifact is
//! worse than an absent one: it answers every write `Ok(())` and every read empty, which is
//! byte-for-byte the signature of the defect this fixture exists to catch, so it produces a failure
//! indistinguishable from a real regression — and, in the other direction, an artifact built BEFORE
//! a regression produces a PASS while the shipped ABI is broken. Neither reading is survivable, so
//! neither reaches an assertion.
//!
//! A `[dev-dependencies]` edge on the plugin crate does NOT solve this: cargo satisfies that edge
//! with the crate's RLIB and never emits the cdylib, because nothing in the build graph consumes it
//! — the load is by path at runtime, which cargo cannot see.

use busbar_api::Store;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Locate the `busbar-store-example-plugin` cdylib, failing loudly if it is absent or stale.
///
/// Derived from THIS TEST BINARY's own path (`<target>/<profile>/deps/<bin>`) rather than a
/// hard-coded `target/debug`, so it is correct under `--release`, under a custom `CARGO_TARGET_DIR`,
/// and under a workspace built into a shared target directory.
///
/// This does not BUILD the artifact, deliberately: shelling out to cargo from inside a test would
/// contend for the target-directory lock the running `cargo test` already holds.
pub fn example_store_cdylib() -> PathBuf {
    let exe = std::env::current_exe().expect("the test binary knows its own path");
    let profile_dir = exe
        .parent()
        .and_then(|deps| deps.parent())
        .expect("<target>/<profile>/deps/<test-binary>")
        .to_path_buf();
    let name = busbar_plugin_loader::plugin_library_filename("busbar_store_example_plugin");
    let path = profile_dir.join(&name);
    assert!(
        path.exists(),
        "the busbar-store-example-plugin cdylib is not built at {}. The batteries that load it \
         cross the REAL plugin C ABI on purpose — the defect they exist to catch (an ABI that \
         carried four store methods and discarded every write through it) is invisible to any \
         in-process double — so they refuse to skip. Build it: `cargo build -p \
         busbar-store-example-plugin`.",
        path.display()
    );

    // The crates whose sources decide what the cdylib DOES across the ABI: the plugin itself, the
    // SDK it is written against, and the ABI header both sides compile to. A change to any of the
    // three can move the artifact's behaviour, and the four-method defect lived in the last one.
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|c| c.parent())
        .expect("<workspace>/crates/busbar")
        .to_path_buf();
    let built = std::fs::metadata(&path)
        .and_then(|m| m.modified())
        .expect("the cdylib's build time");
    for crate_dir in ["store-example-plugin", "plugin-sdk", "busbar-plugin"] {
        let root = workspace.join("crates").join(crate_dir);
        if let Some(newer) = newest_source_under(&root, built) {
            panic!(
                "the busbar-store-example-plugin cdylib at {} is STALE — {} is newer than the \
                 artifact. THIS IS NOT A DURABILITY FAILURE, and it must not be read as one: a \
                 stale cdylib keeps nothing and reports success, which is exactly what the ABI \
                 defect this fixture hunts looks like, so judging it would mean judging the wrong \
                 tree. Rebuild first: `cargo build -p busbar-store-example-plugin`.",
                path.display(),
                newer.display()
            );
        }
    }
    path
}

/// The first `.rs` or `Cargo.toml` under `root` modified after `built`, if any. Returns the file so
/// the panic can name it — "something is stale" sends a reader hunting; naming the file does not.
fn newest_source_under(root: &Path, built: std::time::SystemTime) -> Option<PathBuf> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).ok()?.flatten() {
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
