// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! TEST ONLY: the fake-call store harness, shared by this crate's own tests and the kernel's minting
//! tests (`busbar-kernel`'s `src/tests/members/plugin_loader/`). Those tests live in the kernel
//! because they mint the `Grant<AdminVerb>` the verb seam takes, and minting is legal only there.
//!
//! Compiled under `cfg(test)` (this crate's own tests) and under the `test-support` feature, which
//! only the kernel's `[dev-dependencies]` edge turns on; never in a shipped build. The items it
//! drives (`wire_up_raw`, `DynStore::new`, `stage::load_library_from_bytes`, the private
//! `load_dyn_store_from_bytes_at_abi`) keep their normal visibility: this module is their
//! descendant and reaches them as such, and exposes only the thin entry points below.

use crate::DynStore;
use busbar_contract::abi::cold::STATUS_OK;
use std::os::raw::c_void;

/// The store both-ways proof's `cdylib` crate name (`[package.metadata.busbar.both-ways]` `store`),
/// exported by `build.rs`: this module compiles without the dev-dependencies `both_ways` names.
const STORE_PROOF_CRATE: &str = env!("BUSBAR_BOTH_WAYS_STORE");

/// The golden artifact names this crate's tests locate on disk, read from
/// `tests/fixtures/plugin_artifacts.txt` (data, not code: the loader names no plugin instance).
const PLUGIN_ARTIFACTS: &str = include_str!("../../tests/fixtures/plugin_artifacts.txt");

/// One artifact name from [`PLUGIN_ARTIFACTS`], by key. Panics on a missing key: a fixture that
/// lost a row must fail the test that needed it, never hand it an empty name.
pub fn artifact(key: &str) -> &'static str {
    PLUGIN_ARTIFACTS
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .find_map(|l| {
            let (k, v) = l.split_once('=')?;
            (k.trim() == key).then(|| v.trim())
        })
        .unwrap_or_else(|| panic!("tests/fixtures/plugin_artifacts.txt has no `{key}` row"))
}

/// The published sqlite store tarball, fetched by pinned digest into the oracle cache by
/// `testing/shadow-oracle/fetch-plugin.sh`. `None` when the cache is cold — the script downloads on
/// demand and a unit test must not, so this reads the cache the oracle already fills.
pub fn cached_published_store_tarball() -> Option<std::path::PathBuf> {
    let asset_triple = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "aarch64-apple-darwin",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        ("linux", "aarch64") => "aarch64-unknown-linux-gnu",
        ("linux", "x86_64") => "x86_64-unknown-linux-gnu",
        _ => return None,
    };
    let root = match std::env::var_os("BUSBAR_ORACLE_CACHE") {
        Some(dir) => std::path::PathBuf::from(dir),
        None => std::path::PathBuf::from(std::env::var_os("HOME")?).join(".cache/busbar-oracle"),
    };
    let versions = std::fs::read_dir(
        root.join("plugins")
            .join(artifact("published_store_plugin_id")),
    )
    .ok()?;
    versions
        .flatten()
        .filter_map(|tag| {
            std::fs::read_dir(tag.path())
                .ok()?
                .flatten()
                .map(|e| e.path())
                .find(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.contains(asset_triple) && n.ends_with(".tar.gz"))
                })
        })
        .max()
}

/// (status, body) the fake `busbar_call` returns for the NEXT call.
///
/// PROCESS-GLOBAL, not `thread_local!`, and that is a correctness requirement rather than a style
/// choice: `busbar_call` runs on a loader-owned worker thread (see `ffi_thread`), never on the
/// caller's, so a thread-local set by the test would be invisible to the fake and it would answer
/// `(STATUS_OK, b"")` — decoding as "EOF while parsing a value", which is how this fixture failed
/// when the worker pool landed. A real plugin may not assume caller-thread affinity either, so the
/// fake should not model one.
///
/// The `Mutex` here guards the VALUE, and nothing more. It does NOT make "set, then call" atomic:
/// a test that sets the answer and then makes the call has released this lock in between, so a
/// second test's setup lands in the gap and the first test's call reads the second test's answer.
/// The claim it used to carry is what `FAKE_CALL_IN_USE` actually provides.
static FAKE_CALL: std::sync::Mutex<(i32, &'static [u8])> = std::sync::Mutex::new((STATUS_OK, b""));

/// What makes the fake a per-test instrument rather than a shared variable: a test that touches the
/// fake takes this and does not give it back until the test is over, so its answer is still the one
/// standing when its calls arrive.
///
/// Held for the TEST, not for the `with` closure. The set and the call it answers are separate
/// statements in every one of these tests, and the whole defect is another test's set landing
/// between them — a lock released at the end of `set` closes no gap at all. libtest runs each test
/// on its own thread and drops that thread's locals when the test ends, which is exactly the extent
/// wanted: the next test to reach for the fake waits for this one to finish.
#[cfg(test)]
static FAKE_CALL_IN_USE: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
thread_local! {
    /// This test's hold on the fake, taken on first use and released when the test's thread ends.
    static FAKE_CALL_HOLD: std::cell::RefCell<Option<std::sync::MutexGuard<'static, ()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Set the answer the fake `busbar_call` gives next. Named `with`-style so the call sites that used
/// the `thread_local!` API read the same.
#[cfg(test)]
pub(crate) struct FakeCall;
#[cfg(test)]
impl FakeCall {
    pub(crate) fn with<R>(&self, f: impl FnOnce(&FakeCallCell) -> R) -> R {
        FAKE_CALL_HOLD.with(|held| {
            let mut held = held.borrow_mut();
            if held.is_none() {
                *held = Some(FAKE_CALL_IN_USE.lock().unwrap_or_else(|p| p.into_inner()));
            }
        });
        f(&FakeCallCell)
    }
}
#[cfg(test)]
pub(crate) struct FakeCallCell;
#[cfg(test)]
impl FakeCallCell {
    pub(crate) fn set(&self, v: (i32, &'static [u8])) {
        *FAKE_CALL.lock().unwrap_or_else(|p| p.into_inner()) = v;
    }
}

/// The answer the fake is currently holding, read WITHOUT taking `FAKE_CALL_IN_USE`.
///
/// `busbar_call` runs on a loader-owned worker thread, which is not the test's thread and must
/// never queue behind a test's hold on the fake — that would be the calls waiting on the very lock
/// that exists to keep them answering the right test.
pub(crate) fn fake_call_answer() -> (i32, &'static [u8]) {
    *FAKE_CALL.lock().unwrap_or_else(|p| p.into_inner())
}

#[cfg(test)]
#[allow(non_upper_case_globals)]
pub(crate) const FAKE_CALL_HANDLE: FakeCall = FakeCall;

/// A fake `busbar_call`: allocate a buffer holding the chosen body and return the chosen status.
/// Mimics the plugin side (plugin allocates, engine frees via `busbar_free`).
pub(crate) unsafe extern "C-unwind" fn fake_call(
    _handle: *mut c_void,
    _req: *const u8,
    _req_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let (status, body) = fake_call_answer();
    if body.is_empty() {
        *out = std::ptr::null_mut();
        *out_len = 0;
    } else {
        // Allocate with the SAME shape `fake_free` frees: a boxed slice leaked to a raw ptr.
        let boxed: Box<[u8]> = body.to_vec().into_boxed_slice();
        let len = boxed.len();
        *out = Box::into_raw(boxed) as *mut u8;
        *out_len = len;
    }
    status
}

/// Free a buffer `fake_call` allocated (reconstruct the boxed slice and drop it).
pub(crate) unsafe extern "C-unwind" fn fake_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len != 0 {
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)));
    }
}

/// The store both-ways proof's cdylib for the tests below that need a real `kind: store` image to
/// stage and wire (never store-specific durability). Under `CI` a missing cdylib is a HARD failure:
/// it is this crate's own dev-dependency, so `cargo test` always builds it, and its absence means a
/// broken pipeline rather than a machine without a sibling checkout.
pub(crate) fn store_proof_plugin_path() -> Option<std::path::PathBuf> {
    let candidate = store_proof_candidate();
    if candidate.is_none() && std::env::var_os("CI").is_some() {
        panic!(
            "the store both-ways proof's cdylib is not built under CI: `cargo test` must build {} \
             (checked both the uplifted target dir and target/deps). Refusing to silently skip the \
             over-the-ABI coverage of the kind:store dlopen seam.",
            STORE_PROOF_CRATE
        );
    }
    candidate
}

/// The store both-ways proof's cdylib (`[package.metadata.busbar.both-ways]` `store`), if built —
/// the newest of the uplifted `<profile_dir>/<name>` copy and the raw `<profile_dir>/deps/<name>`
/// output (a scoped `cargo test -p` only produces the latter). No CI policy here; the callers own that.
pub(crate) fn store_proof_candidate() -> Option<std::path::PathBuf> {
    newest_cdylib(STORE_PROOF_CRATE)
}

/// The newest built `cdylib` of `crate_snake` in this target dir: the uplifted `<profile_dir>/<name>`
/// copy or the raw `<profile_dir>/deps/<name>` output, whichever was written last.
fn newest_cdylib(crate_snake: &str) -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let profile_dir = exe.parent()?.parent()?;
    let name = crate::plugin_library_filename(crate_snake);
    let uplifted = profile_dir.join(&name);
    let raw = profile_dir.join("deps").join(&name);
    [uplifted, raw]
        .into_iter()
        .filter_map(|p| {
            std::fs::metadata(&p)
                .and_then(|m| m.modified())
                .ok()
                .map(|mtime| (p, mtime))
        })
        .max_by_key(|(_, mtime)| *mtime)
        .map(|(p, _)| p)
}

/// A `DynStore` over the in-tree store proof with the `call`/`free` seam faked (the tests'
/// `dyn_proof_store_with_fake_call`), bound to a chosen payload schema, so a test can hold the
/// PUBLISHED one (v2) rather than the schema this binary was built against.
pub fn dyn_proof_store_with_fake_call_at_abi(abi_version: u32) -> Option<DynStore> {
    let path = store_proof_plugin_path()?;
    let bytes = std::fs::read(&path).expect("read the in-tree store proof's cdylib");
    let (lib, staged) = crate::stage::load_library_from_bytes(&bytes, "fake-call-example")
        .expect("stage the in-tree store proof for the fake-call harness");
    let mut raw = crate::wire_up_raw(
        lib,
        "{}",
        "fake-call-example".to_string(),
        busbar_contract::abi::cold::kind::STORE,
        busbar_contract::abi::cold::kind::STORE,
        Some(staged),
    )
    .expect("wire up raw");
    raw.call = fake_call;
    raw.free = fake_free;
    Some(DynStore::new(raw, abi_version))
}

/// The crate-private `load_dyn_store_from_bytes_at_abi`: a `DynStore` loaded from verified library
/// bytes at a named payload schema, before the public entry point boxes it away.
pub fn load_dyn_store_from_bytes_at_abi(
    bytes: &[u8],
    cfg_json: &str,
    display: &str,
    manifest_kind: &str,
    abi_version: u32,
) -> Result<DynStore, String> {
    crate::load_dyn_store_from_bytes_at_abi(bytes, cfg_json, display, manifest_kind, abi_version)
}
