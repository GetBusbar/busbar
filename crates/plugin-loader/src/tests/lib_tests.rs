// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/plugin-loader/src/lib.rs`.

use super::*;

/// Locate the REAL `busbar-store-sqlite-plugin` cdylib built from a SIBLING checkout of
/// `GetBusbar/store-sqlite` (a workspace at `../store-sqlite` relative to this repo, matching the
/// sibling-checkout convention already used for headroom-hook/webrequest-hook and every other
/// extracted plugin). store-sqlite now lives entirely in its own repo — there is no in-tree
/// `kind: store` plugin left to fake, so these LOADER-mechanism tests (TOCTOU-safe loading,
/// hot-swap coexistence, staged-file lifecycle, denylist-fallback classification — never
/// sqlite-specific behavior, which is that repo's own job, covered by its own
/// `store-sqlite-plugin/tests/e2e.rs`) exercise the REAL plugin instead of a fixture. Returns
/// `None` if the sibling checkout isn't present or hasn't been built — local iteration without
/// the sibling checked out skips cleanly.
///
/// CI HARDENING: `.github/workflows/dev-gate.yml` checks out `../store-sqlite` as a sibling and
/// runs `cargo build --release` there before running this workspace's tests, so under that
/// workflow's `CI` env var the cdylib MUST be present — its absence there is a broken pipeline,
/// a HARD FAILURE here rather than a silent skip, so this coverage cannot quietly vanish. The
/// lightweight per-push `ci.yml` does NOT check out this sibling (it stays fast), so these tests
/// skip there — real coverage runs on every push to `dev`/`*-dev` via `dev-gate.yml` instead.
fn store_fixture_plugin_path() -> Option<std::path::PathBuf> {
    let candidate = {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")); // .../busbarAI/crates/plugin-loader
        let sibling_root = manifest_dir.join("../../../store-sqlite"); // sibling of busbarAI
        let name = plugin_library_filename("busbar_store_sqlite_plugin");
        let candidate = sibling_root.join("target/release").join(&name);
        candidate.exists().then_some(candidate)
    };
    if candidate.is_none()
        && std::env::var_os("CI").is_some()
        && std::env::var_os("DEV_GATE").is_some()
    {
        panic!(
            "the store-sqlite-plugin cdylib is not built from the ../store-sqlite sibling \
                 checkout under dev-gate.yml: refusing to silently skip loader-mechanism coverage \
                 of the kind:store dlopen seam."
        );
    }
    candidate
}

/// A fresh, unique `db_path` config for the real store-sqlite-plugin fixture, so concurrent
/// tests in this binary never share a SQLite file. Every one of these tests used to pass `"{}"`
/// (the plugin's own documented "must work" empty-config default), which resolves to the
/// FIXED relative path `busbar-governance.db` in the test process's cwd — under `cargo test`'s
/// default parallel execution, every such test collided on the SAME file: `list_keys()`
/// assertions failed because a concurrent test had already written keys to it, and `wire_up_raw`
/// itself failed outright with a real SQLite `disk I/O error` under lock contention between
/// concurrent opens — reproducible under `DEV_GATE=1 cargo test --release -p
/// busbar-plugin-loader`.
///
/// These files are deliberately NOT deleted by the test that creates them — a test can't know
/// when it's safe to remove its own db file (the store may still be open, or a sibling process
/// under `-j`-parallel `cargo test` invocations may share the same `$TMPDIR`), and CI runners
/// are ephemeral (wiped between runs) so this never accumulates there. On a long-lived local
/// dev machine it CAN accumulate across many `cargo test` invocations (observed: 174 files,
/// ~14MB) — self-cleans that by opportunistically sweeping this
/// process's OWN prior runs' files (matched by name pattern, not PID liveness — simpler and
/// good enough for a `$TMPDIR` nuisance, not a correctness concern) older than an hour, once
/// per test-binary invocation.
fn unique_sqlite_cfg(name: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Once;
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    static SWEEP_ONCE: Once = Once::new();
    SWEEP_ONCE.call_once(|| {
        let cutoff = std::time::Duration::from_secs(3600);
        let now = std::time::SystemTime::now();
        let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if !name.starts_with("busbar-plugin-loader-test-") || !name.ends_with(".db") {
                continue;
            }
            let Ok(meta) = entry.metadata() else { continue };
            let Ok(modified) = meta.modified() else {
                continue;
            };
            if now.duration_since(modified).unwrap_or_default() > cutoff {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    });
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "busbar-plugin-loader-test-{}-{name}-{n}.db",
        std::process::id()
    ));
    serde_json::json!({ "db_path": path.to_string_lossy() }).to_string()
}

/// A non-plugin library (or a missing file) is refused with a clear error, never a crash.
#[test]
fn refuses_non_plugin() {
    let err = match load_store(Path::new("/definitely/not/a/plugin.so"), "{}") {
        Err(e) => e,
        Ok(_) => panic!("a missing library must not load"),
    };
    assert!(err.contains("failed to load plugin"), "got: {err}");
}

/// `validate_plugin` accepts the real store-sqlite-plugin cdylib (ABI v1) without constructing a
/// store, and `inventory` finds it (and any sibling plugins) in the target directory as valid.
#[test]
fn validate_and_inventory() {
    let Some(path) = store_fixture_plugin_path() else {
        eprintln!("skip: store-sqlite-plugin cdylib not built (run `cargo build --release -p busbar-store-sqlite-plugin` in a sibling ../store-sqlite checkout)");
        return;
    };
    assert_eq!(validate_plugin(&path).expect("validate"), TRANSPORT_VERSION);

    let dir = path.parent().unwrap();
    let inv = inventory(dir);
    let fixture = inv
        .iter()
        .find(|p| p.file.contains("busbar_store_sqlite_plugin"))
        .expect("sibling store-sqlite-plugin in inventory");
    assert!(fixture.valid);
    assert_eq!(fixture.abi_version, Some(TRANSPORT_VERSION));
    assert!(fixture.error.is_none());
}

/// `inventory` of a missing directory is empty, not an error.
#[test]
fn inventory_missing_dir_is_empty() {
    assert!(inventory(Path::new("/no/such/plugins/dir")).is_empty());
}

/// `intern_name` reuses the SAME allocation for repeated sightings of the same name (that's the
/// whole point - bounding the leak to one per distinct name), while two DIFFERENT names get
/// distinct interned strings. Checked via pointer identity, not just string equality, since two
/// equal-but-differently-allocated `&'static str`s would defeat the interning claim silently.
#[test]
fn intern_name_reuses_the_same_allocation_for_a_repeated_name() {
    let a1 = intern_name("plugin-a-unique-for-this-test");
    let a2 = intern_name("plugin-a-unique-for-this-test");
    assert_eq!(
        a1.as_ptr(),
        a2.as_ptr(),
        "the same name must reuse the SAME leaked allocation, not leak a fresh one each call"
    );
    let b = intern_name("plugin-b-unique-for-this-test");
    assert_ne!(
        a1.as_ptr(),
        b.as_ptr(),
        "a different name is a different allocation"
    );
    assert_eq!(b, "plugin-b-unique-for-this-test");
}

#[test]
fn is_library_file_matches_only_this_platforms_extension() {
    let expected_ext = if cfg!(target_os = "windows") {
        ".dll"
    } else if cfg!(target_os = "macos") {
        ".dylib"
    } else {
        ".so"
    };
    assert!(is_library_file(&format!("libfoo{expected_ext}")));
    assert!(!is_library_file("libfoo.txt"));
    assert!(!is_library_file("libfoo"));
    assert!(!is_library_file("README.md"));
    // The "only" in this test's name wasn't actually proven before: an implementation
    // accepting every platform's library extension everywhere (e.g. `.dylib` on Linux too)
    // would have passed the assertions above unchanged. Explicitly assert the OTHER platforms'
    // extensions are rejected on THIS platform.
    for other_ext in [".dll", ".dylib", ".so"] {
        if other_ext == expected_ext {
            continue;
        }
        assert!(
            !is_library_file(&format!("libfoo{other_ext}")),
            "a foreign platform's library extension ({other_ext}) must be rejected on this \
                 platform (expects {expected_ext})"
        );
    }
}

/// `list_plugin_files` lists only library-extension files, sorted, and NEVER dlopens anything
/// (so it must return real filenames even for a garbage/non-plugin library file that would fail
/// `validate_plugin`).
#[test]
fn list_plugin_files_filters_to_libraries_only_and_sorts() {
    let dir = std::env::temp_dir().join(format!(
        "busbar-list-plugin-files-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let ext = if cfg!(target_os = "windows") {
        ".dll"
    } else if cfg!(target_os = "macos") {
        ".dylib"
    } else {
        ".so"
    };
    std::fs::write(dir.join(format!("zzz{ext}")), b"not a real library").unwrap();
    std::fs::write(dir.join(format!("aaa{ext}")), b"not a real library either").unwrap();
    std::fs::write(dir.join("readme.txt"), b"not a library at all").unwrap();
    let files = list_plugin_files(&dir);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        files,
        vec![format!("aaa{ext}"), format!("zzz{ext}")],
        "only library-extension files, sorted, no dlopen (garbage bytes never rejected here)"
    );
}

/// THE EXTENSION MATCH FOLLOWS THE FILESYSTEM'S CASE RULE, and the two rules are opposites.
///
/// This scan is what `GET /admin/plugins` renders, so a file it skips is a plugin an operator is
/// told is not installed. On NTFS `FOO.DLL` and `foo.dll` are ONE file and `LoadLibrary` opens
/// either, so a case-sensitive `ends_with(".dll")` hides a plugin that is genuinely there — and
/// uppercase extensions are exactly what a Windows build system or an unzip hands over. On unix the
/// extension is part of the name, `.SO` is a different file the loader would not resolve, and
/// claiming it is a library would be the mirror-image error. So the assertion is per platform
/// rather than one shared expectation, because the correct answers genuinely differ.
#[test]
fn the_library_extension_match_uses_this_filesystems_case_rule() {
    let dir = std::env::temp_dir().join(format!(
        "busbar-libext-case-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let upper = if cfg!(target_os = "windows") {
        "shouty.DLL"
    } else if cfg!(target_os = "macos") {
        "shouty.DYLIB"
    } else {
        "shouty.SO"
    };
    std::fs::write(dir.join(upper), b"not a real library").unwrap();
    let files = list_plugin_files(&dir);
    let _ = std::fs::remove_dir_all(&dir);

    #[cfg(target_os = "windows")]
    assert_eq!(
        files,
        vec![upper.to_string()],
        "NTFS is case-insensitive: an uppercase extension names a loadable DLL and must be listed"
    );
    #[cfg(not(target_os = "windows"))]
    assert!(
        files.is_empty(),
        "unix filenames are case-sensitive: {upper} is not the library the loader would resolve, so \
         it must not be reported as one (got {files:?})"
    );
}

/// `inventory` reports BOTH a real valid plugin AND a garbage same-extension file in the same
/// directory, correctly distinguishing valid=true/false rather than silently dropping the
/// invalid one or crashing on it.
#[test]
fn inventory_reports_valid_and_invalid_libraries_in_the_same_directory() {
    let Some(real_plugin) = store_fixture_plugin_path() else {
        eprintln!("skip: store-sqlite-plugin cdylib not built (run `cargo build --release -p busbar-store-sqlite-plugin` in a sibling ../store-sqlite checkout)");
        return;
    };
    let dir = std::env::temp_dir().join(format!(
        "busbar-inventory-mixed-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let ext = if cfg!(target_os = "windows") {
        ".dll"
    } else if cfg!(target_os = "macos") {
        ".dylib"
    } else {
        ".so"
    };
    std::fs::copy(&real_plugin, dir.join(format!("real{ext}"))).unwrap();
    std::fs::write(dir.join(format!("garbage{ext}")), b"not a real library").unwrap();
    std::fs::write(dir.join("readme.txt"), b"ignored: not a library extension").unwrap();
    let mut items = inventory(&dir);
    let _ = std::fs::remove_dir_all(&dir);
    items.sort_by(|a, b| a.file.cmp(&b.file));
    assert_eq!(
        items.len(),
        2,
        "readme.txt must be excluded entirely: {items:?}"
    );
    let garbage = items
        .iter()
        .find(|i| i.file.starts_with("garbage"))
        .unwrap();
    assert!(!garbage.valid);
    assert!(garbage.error.is_some());
    let real = items.iter().find(|i| i.file.starts_with("real")).unwrap();
    assert!(real.valid, "the real plugin must validate: {real:?}");
    assert_eq!(real.abi_version, Some(TRANSPORT_VERSION));
}

/// `wire_up_raw`'s two independent kind gates must BOTH fire, and must fire for the RIGHT
/// reason: exported-vs-expected (the ABI seam calling this as the wrong kind) and
/// exported-vs-manifest (the signed manifest disagreeing with what the library actually
/// exports) are two different attacks and must not be conflatable into one check.
#[test]
fn wire_up_raw_rejects_a_kind_mismatch_against_the_seam_and_the_manifest() {
    let Some(store_plugin) = store_fixture_plugin_path() else {
        eprintln!("skip: store-sqlite-plugin cdylib not built (run `cargo build --release -p busbar-store-sqlite-plugin` in a sibling ../store-sqlite checkout)");
        return;
    };
    let bytes = std::fs::read(&store_plugin).expect("read sibling store-sqlite-plugin cdylib");

    // Seam mismatch: a real STORE library loaded through the SECRET entry point (expected_kind
    // = secret, exported_kind = store) must be refused, naming both kinds. Both kind-check
    // guards run BEFORE `busbar_open`/real backing construction, so an empty `"{}"` config here
    // never actually reaches sqlite today — but `unique_sqlite_cfg` costs nothing and removes
    // the latent risk of this test starting to collide with sibling tests on the shared
    // `busbar-governance.db` default path if that check ordering ever changes.
    let Err(err) = load_secret_from_bytes(
        &bytes,
        &unique_sqlite_cfg("kind-mismatch-seam"),
        "kind-mismatch-seam",
        abi_kind::STORE,
    ) else {
        panic!("a store library must not load as a secret module");
    };
    assert!(err.contains("store"), "must name the exported kind: {err}");
    assert!(err.contains("secret"), "must name the expected kind: {err}");

    // Manifest mismatch: expected_kind matches exported_kind (both store), but the signed
    // manifest_kind lies about it — must still be refused.
    let Err(err) = load_store_from_bytes(
        &bytes,
        &unique_sqlite_cfg("kind-mismatch-manifest"),
        "kind-mismatch-manifest",
        "secret",
    ) else {
        panic!("an exported-store/manifest-secret disagreement must be refused");
    };
    assert!(
        err.contains("kind mismatch"),
        "must name it as a manifest disagreement, not a seam mismatch: {err}"
    );
}

#[test]
fn plugin_library_filename_matches_this_platforms_naming_convention() {
    let name = plugin_library_filename("busbar_foo_plugin");
    if cfg!(target_os = "windows") {
        assert_eq!(name, "busbar_foo_plugin.dll");
    } else if cfg!(target_os = "macos") {
        assert_eq!(name, "libbusbar_foo_plugin.dylib");
    } else {
        assert_eq!(name, "libbusbar_foo_plugin.so");
    }
}

/// The response-length cap accepts a normal reply and REFUSES an over-cap length before any
/// allocation — defense-in-depth against a plugin declaring a huge `out_len` and OOMing the engine.
#[test]
fn response_len_cap_refuses_oversized() {
    assert!(response_len_ok(0, "p").is_ok());
    assert!(response_len_ok(1024, "p").is_ok());
    assert!(
        response_len_ok(MAX_PLUGIN_RESPONSE_LEN, "p").is_ok(),
        "the exact cap is allowed"
    );
    let err = response_len_ok(MAX_PLUGIN_RESPONSE_LEN + 1, "sqlite").unwrap_err();
    assert!(err.contains("oversized response"), "got {err}");
    assert!(err.contains("sqlite"), "names the offending plugin: {err}");
}

/// Pins the length cap on the `busbar_open` error path, mirroring `response_len_ok`'s on the
/// `busbar_call` path. Covered as a unit test rather than over the ABI: there is no fake-open
/// seam (`dyn_store_with_fake_call` only patches `call` on an already-opened `DynStore`), and
/// the failure mode of an unchecked length is an out-of-bounds read, not a clean assertion
/// failure.
#[test]
fn open_err_is_readable_refuses_an_oversized_length() {
    assert!(
        !open_err_is_readable(false, MAX_PLUGIN_RESPONSE_LEN + 1),
        "an over-cap length must be refused"
    );
    assert!(
        !open_err_is_readable(true, 64),
        "a null err pointer is never readable"
    );
    assert!(
        !open_err_is_readable(false, 0),
        "a zero length carries no message"
    );
    assert!(
        open_err_is_readable(false, 64),
        "a sane, non-null, in-cap length is readable"
    );
    assert!(
        open_err_is_readable(false, MAX_PLUGIN_RESPONSE_LEN),
        "the exact cap is allowed, matching response_len_ok"
    );
}

/// TOCTOU-safe load: `load_store_from_bytes` loads EXACTLY the bytes handed to it — the same bytes
/// the caller hash/signature-verified — and exercises the store over the ABI to prove the load is
/// live. This is the path the engine boot uses so the verified bytes and the loaded bytes are one
/// and the same, with no path re-read in between.
#[test]
fn load_store_from_bytes_loads_the_given_bytes() {
    let Some(path) = store_fixture_plugin_path() else {
        eprintln!("skip: store-sqlite-plugin cdylib not built (run `cargo build --release -p busbar-store-sqlite-plugin` in a sibling ../store-sqlite checkout)");
        return;
    };
    let bytes = std::fs::read(&path).expect("read sibling store-sqlite-plugin cdylib");
    let store = load_store_from_bytes(
        &bytes,
        &unique_sqlite_cfg("fixture-from-bytes"),
        "fixture-from-bytes",
        "store",
    )
    .expect("load from verified bytes");
    let key = VirtualKey {
        id: "vk_b".into(),
        generation_hash: "h".into(),
        name: "b".into(),
        allowed_scopes: Some(vec![busbar_api::ScopeRef::pool("p")]),
        enabled: true,
        created_at: 1,
        group: None,
        labels: std::collections::BTreeMap::new(),
        expires_at: None,
        deleted_at: None,
        revision: 1,
    };
    store.put_key(&key).expect("put_key over from-bytes load");
    assert_eq!(
        store.get_key("vk_b").expect("get").expect("present").id,
        "vk_b"
    );
}

/// The TOCTOU guarantee, demonstrated end-to-end: verify a set of bytes, then SWAP the on-disk file
/// at the original path for hostile content — and the from-bytes load is UNAFFECTED, because it
/// never re-reads that path. Under the old `verify(path)` + `load_store(path)` shape this swap would
/// have loaded the attacker's file; here the loaded library is the verified `bytes`, full stop.
#[test]
fn on_disk_swap_after_verify_does_not_change_what_loads() {
    let Some(path) = store_fixture_plugin_path() else {
        eprintln!("skip: store-sqlite-plugin cdylib not built (run `cargo build --release -p busbar-store-sqlite-plugin` in a sibling ../store-sqlite checkout)");
        return;
    };
    // "Verify" step: read the good bytes (in the engine these are hash/signature-checked here).
    let verified = std::fs::read(&path).expect("read good cdylib");

    // Attacker swaps the file at `path` for junk AFTER we verified — a classic TOCTOU swap.
    let dir = std::env::temp_dir().join(format!("busbar-toctou-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let victim = dir.join(plugin_library_filename("busbar_store_sqlite_plugin"));
    std::fs::write(&victim, &verified).unwrap();
    // Confirm loading the victim PATH would pick up whatever is on disk...
    std::fs::write(&victim, b"\x7fELF hostile junk, not a plugin").unwrap();
    assert!(
        load_store(&victim, &unique_sqlite_cfg("toctou-victim")).is_err(),
        "the swapped-in junk is not a loadable plugin (path load sees the swap)"
    );
    // ..but the from-bytes load, fed the bytes we verified BEFORE the swap, loads fine.
    let store = load_store_from_bytes(&verified, &unique_sqlite_cfg("toctou"), "toctou", "store")
        .expect("verified bytes still load despite the on-disk swap");
    assert!(store.list_keys().expect("list over the ABI").is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

/// No leaked artifact + unload-then-remove ordering: after a from-bytes load's store DROPS,
/// nothing of the load remains on disk. On Linux the load is a memfd (zero disk files by
/// construction); on macOS/Windows the staged file inside the per-process private directory is
/// removed when the store drops — and because `DynStore` declares `_lib` before `_backing`, the
/// library unloads BEFORE the staged file is removed (the order Windows requires: a mapped
/// DLL's file cannot be deleted).
///
/// Every `busbar-plugins-<pid>-*` staging directory currently in the temp dir. The prefix is
/// keyed on the process id, which every test in this binary shares, so this set is only
/// meaningful as a before/after DIFFERENCE, never as an absolute count.
fn staging_dirs_for_this_process() -> std::collections::BTreeSet<std::path::PathBuf> {
    let prefix = format!("busbar-plugins-{}-", std::process::id());
    std::fs::read_dir(std::env::temp_dir())
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| n.starts_with(&prefix))
        })
        .map(|e| e.path())
        .collect()
}

/// Asserts on THIS load's own staged path, not a process-wide count of
/// `busbar-plugins-<pid>-*` entries. The count was the wrong instrument twice over: FLAKY,
/// because a concurrent test in this binary stages or releases files between the two samples
/// (this test failed ~2/5 under a loaded run); and WEAK, because `after <= before` still passes
/// while this load's file leaks, as long as some other test's file went away in the same
/// window. The exact path is immune to concurrency and actually fails when the artifact leaks.
#[test]
fn from_bytes_load_leaves_no_artifact_after_drop() {
    let Some(path) = store_fixture_plugin_path() else {
        eprintln!("skip: store-sqlite-plugin cdylib not built (run `cargo build --release -p busbar-store-sqlite-plugin` in a sibling ../store-sqlite checkout)");
        return;
    };
    let bytes = std::fs::read(&path).expect("read sibling store-sqlite-plugin cdylib");
    // Snapshot before the load, so the memfd branch below can assert on what THIS load created
    // rather than on a process-wide total that a concurrent test contributes to.
    let before = staging_dirs_for_this_process();
    let staged: Option<std::path::PathBuf> = {
        let store = load_dyn_store_from_bytes(
            &bytes,
            &unique_sqlite_cfg("no-leak-check"),
            "no-leak-check",
            "store",
        )
        .expect("load from bytes");
        assert!(store.list_keys().expect("list").is_empty());
        let staged = store.staged_path().map(std::path::Path::to_path_buf);
        // While the store is ALIVE the backing must exist — otherwise the post-drop assertion
        // below would be vacuous (nothing to remove) and would pass on a leak.
        if let Some(p) = &staged {
            assert!(
                p.is_file(),
                "the staged backing must exist while the store is alive: {}",
                p.display()
            );
        }
        staged
    }; // store drops here -> library unloads, then the staged backing is released.

    match staged {
        // macOS/Windows (and the Linux memfd fallback): the file this load staged is gone.
        Some(p) => assert!(
            !p.exists(),
            "a from-bytes load must remove its OWN staged file when the store drops, but {} \
                 still exists",
            p.display()
        ),
        // Linux memfd: zero disk files by construction, so there was never a path to remove.
        // There is no path to assert on here, so this is the one branch that has to look at the
        // directory. It compares against a snapshot taken BEFORE the load rather than asserting
        // an absolute count of zero: the `busbar-plugins-<pid>-*` prefix is keyed on the PROCESS
        // id, which every test in this binary shares, so an absolute count sees any staging
        // directory a concurrently-running test happens to own and fails on it. That is the
        // exact flake this test's own doc comment says the path-based assertion replaced -- but
        // the replacement only reached the `Some(p)` branch, and this is the branch Linux CI
        // always takes, so the fix landed everywhere except where it was needed. Observed
        // failing this way on qa-gate run 31094255293 having passed twice on the same commit.
        None => {
            let after = staging_dirs_for_this_process();
            let created: Vec<_> = after.difference(&before).collect();
            assert!(
                created.is_empty(),
                "a memfd load reports no staged path, so it must have created no staging \
                     directory either, but these appeared: {created:?}"
            );
        }
    }
}

/// HOT-SWAP LIFECYCLE (1.5.0): the load-bearing safety property behind a live plugin reload — a
/// NEW instance is loaded ALONGSIDE the old (both libraries mapped at once), the OLD instance is
/// then dropped (as an old App snapshot's last in-flight request drains), and the NEW instance
/// keeps serving. Because each instance OWNS its `Library` (`RawPlugin._lib`), dropping the old
/// instance unmaps ONLY the old library — the new one is untouched — and its staged backing is
/// released, while nothing of the new load is disturbed. This is exactly the drop order a
/// `handle.swap` relies on: instance → close handle → `_lib` unmaps → `_backing` removed.
#[test]
fn hot_swap_old_and_new_coexist_then_old_unmaps_new_keeps_serving() {
    let Some(path) = store_fixture_plugin_path() else {
        eprintln!("skip: store-sqlite-plugin cdylib not built (run `cargo build --release -p busbar-store-sqlite-plugin` in a sibling ../store-sqlite checkout)");
        return;
    };
    let bytes = std::fs::read(&path).expect("read sibling store-sqlite-plugin cdylib");

    // The OLD instance is serving; write a key so we can prove instance IDENTITY across the swap.
    // Load via `load_dyn_store_from_bytes` (as the fixed sibling
    // `from_bytes_load_leaves_no_artifact_after_drop` does) so each generation's OWN
    // `staged_path()` is reachable — asserting on it, not a process-wide directory count that a
    // concurrent test in this binary can shift in either direction between samples.
    let old = load_dyn_store_from_bytes(&bytes, &unique_sqlite_cfg("old-gen"), "old-gen", "store")
        .expect("load OLD");
    let old_path = old.staged_path().map(std::path::Path::to_path_buf);
    if let Some(p) = &old_path {
        assert!(p.is_file(), "OLD's staged backing must exist while alive");
    }
    let key = busbar_api::VirtualKey {
        id: "vk_old".into(),
        generation_hash: "h".into(),
        name: "old".into(),
        allowed_scopes: Some(vec![busbar_api::ScopeRef::pool("p")]),
        enabled: true,
        created_at: 1,
        group: None,
        labels: std::collections::BTreeMap::new(),
        expires_at: None,
        deleted_at: None,
        revision: 1,
    };
    old.put_key(&key).expect("old put");

    // Load the NEW instance ALONGSIDE the old — both libraries are mapped simultaneously. On
    // macOS/Windows this is two staged files at once; on Linux two memfds (no disk).
    let new = load_dyn_store_from_bytes(&bytes, &unique_sqlite_cfg("new-gen"), "new-gen", "store")
        .expect("load NEW alongside OLD");
    let new_path = new.staged_path().map(std::path::Path::to_path_buf);
    if let (Some(op), Some(np)) = (&old_path, &new_path) {
        assert!(
            op.is_file() && np.is_file(),
            "both generations must be simultaneously mapped: old={} new={}",
            op.display(),
            np.display()
        );
        assert_ne!(op, np, "each generation stages its OWN file");
    }
    // The NEW instance is a DISTINCT on-disk SQLite backend (each generation gets its own
    // `unique_sqlite_cfg()` db_path): it does NOT see the old key. Because each generation has a
    // genuinely separate backing file, this is real proof that NEW is a second, independent
    // load — not a cached alias of the first.
    assert!(
        new.get_key("vk_old").expect("new get").is_none(),
        "the new instance's own db_path must be a real, separate backend — not aliasing OLD's"
    );

    // Drop the OLD instance (the old snapshot drained): its library unmaps, its staged file
    // goes — and ONLY its file: the new one must be untouched, which a process-wide count could
    // never express (a leaked old file would be indistinguishable from a released one as long
    // as some unrelated concurrent test released a file in the same window).
    drop(old);
    if let Some(p) = &old_path {
        assert!(
            !p.exists(),
            "OLD's staged file must be removed on drop: {}",
            p.display()
        );
    }
    if let Some(p) = &new_path {
        assert!(
            p.is_file(),
            "NEW's staged file must be UNTOUCHED by OLD's drop: {}",
            p.display()
        );
    }

    // The NEW instance keeps serving with no restart — its library was untouched by the old drop.
    new.put_key(&busbar_api::VirtualKey {
        id: "vk_new".into(),
        generation_hash: "h".into(),
        name: "new".into(),
        allowed_scopes: Some(vec![busbar_api::ScopeRef::pool("p")]),
        enabled: true,
        created_at: 2,
        group: None,
        labels: std::collections::BTreeMap::new(),
        expires_at: None,
        deleted_at: None,
        revision: 1,
    })
    .expect("new keeps serving after old unmaps");
    assert_eq!(
        new.get_key("vk_new")
            .expect("new get2")
            .expect("present")
            .id,
        "vk_new"
    );

    // Drop the NEW instance too: its own file goes as well.
    drop(new);
    if let Some(p) = &new_path {
        assert!(
            !p.exists(),
            "NEW's staged file must be removed on drop: {}",
            p.display()
        );
    }
}

/// NO LEAK ACROSS REPEATED RELOADS (1.5.0): loading + dropping a from-bytes instance many times
/// (the repeated-hot-reload case) must return to the SAME staged-file count each cycle — every
/// generation's library unmaps and its staged backing is released when the instance drops, so
/// there is no unbounded mmap/file accumulation across reloads. This is the drop-counter-balances
/// property proven at the loader seam (the engine-level proof is that the old App snapshot drops).
#[test]
fn repeated_reloads_do_not_leak_staged_libraries() {
    let Some(path) = store_fixture_plugin_path() else {
        eprintln!("skip: store-sqlite-plugin cdylib not built (run `cargo build --release -p busbar-store-sqlite-plugin` in a sibling ../store-sqlite checkout)");
        return;
    };
    let bytes = std::fs::read(&path).expect("read sibling store-sqlite-plugin cdylib");
    // Per-cycle own path, not a process-wide count: a concurrent test staging or releasing a
    // file in this binary between samples can move the count in either direction, hiding a real
    // leak or reporting a false one. Collect this run's own paths and assert each is gone after
    // its own drop, and that no two cycles reused the same path.
    let mut seen = std::collections::HashSet::new();
    for i in 0..16 {
        let s = load_dyn_store_from_bytes(
            &bytes,
            &unique_sqlite_cfg(&format!("reload-{i}")),
            &format!("reload-{i}"),
            "store",
        )
        .unwrap_or_else(|e| panic!("reload {i} load: {e}"));
        assert!(s.list_keys().expect("list").is_empty());
        let staged = s.staged_path().map(std::path::Path::to_path_buf);
        if let Some(p) = &staged {
            assert!(
                p.is_file(),
                "cycle {i}'s staged backing must exist while alive"
            );
            assert!(
                seen.insert(p.clone()),
                "cycle {i} reused a staged path from an earlier cycle: {}",
                p.display()
            );
        }
        drop(s);
        if let Some(p) = &staged {
            assert!(
                !p.exists(),
                "reload cycle {i} leaked its staged library: {}",
                p.display()
            );
        }
    }
}

/// On Linux the from-bytes load is a MEMFD load: it must not create ANY file in the temp base
/// (the zero-disk property the spec requires on Linux).
#[cfg(target_os = "linux")]
#[test]
fn linux_from_bytes_load_touches_no_disk() {
    let Some(path) = store_fixture_plugin_path() else {
        eprintln!("skip: store-sqlite-plugin cdylib not built (run `cargo build --release -p busbar-store-sqlite-plugin` in a sibling ../store-sqlite checkout)");
        return;
    };
    let bytes = std::fs::read(&path).expect("read sibling store-sqlite-plugin cdylib");
    // The actual claim ("a memfd load reports no staged path"), not a directory census: a
    // process-wide count is quiet here only because the common Linux path never touches disk in
    // the first place, but the instrument is the same flawed one the sibling tests above moved
    // away from — a concurrent test staging a file on the non-memfd fallback path between the
    // two samples would have made this assertion fail for a reason unrelated to THIS load.
    let store = load_dyn_store_from_bytes(
        &bytes,
        &unique_sqlite_cfg("memfd-check"),
        "memfd-check",
        "store",
    )
    .expect("memfd load");
    assert!(store.list_keys().expect("list").is_empty());
    assert!(
        store.staged_path().is_none(),
        "a Linux memfd load must report no staged path"
    );
}

// ── The denylist fallback keys on the OUT-OF-BAND ABI status, not on
// plugin-controlled body text ─────────────────────────────────────────────────────────────
//
// The regression uses a FAKE `busbar_call` whose returned (status, body) is chosen per-test via a
// thread-local, wired into a genuine `RawPlugin` built on a real loaded `Library` (so the whole
// `list_denylist` → `transport_call_status` → classification path runs end to end). We swap ONLY the
// `call` fn pointer; the real `open`/`free`/`close`/handle from the loaded store fixture stay valid.

/// (status, body) the fake `busbar_call` returns for the NEXT call.
///
/// PROCESS-GLOBAL, not `thread_local!`, and that is a correctness requirement rather than a style
/// choice: `busbar_call` runs on a loader-owned worker thread (see `ffi_thread`), never on the
/// caller's, so a thread-local set by the test would be invisible to the fake and it would answer
/// `(STATUS_OK, b"")` — decoding as "EOF while parsing a value", which is how this fixture failed
/// when the worker pool landed. A real plugin may not assume caller-thread affinity either, so the
/// fake should not model one.
///
/// The `Mutex` also serializes the tests that use it. They already could not run concurrently (they
/// share one global fake), and the loader test binary runs them in parallel, so the lock is what
/// makes "set, then call" atomic per test rather than a race between two tests' setups.
static FAKE_CALL: std::sync::Mutex<(i32, &'static [u8])> = std::sync::Mutex::new((STATUS_OK, b""));

/// Set the answer the fake `busbar_call` gives next. Named `with`-style so the call sites that used
/// the `thread_local!` API read the same.
struct FakeCall;
impl FakeCall {
    fn with<R>(&self, f: impl FnOnce(&FakeCallCell) -> R) -> R {
        f(&FakeCallCell)
    }
}
struct FakeCallCell;
impl FakeCallCell {
    fn set(&self, v: (i32, &'static [u8])) {
        *FAKE_CALL.lock().unwrap_or_else(|p| p.into_inner()) = v;
    }
    fn get(&self) -> (i32, &'static [u8]) {
        *FAKE_CALL.lock().unwrap_or_else(|p| p.into_inner())
    }
}
#[allow(non_upper_case_globals)]
const FAKE_CALL_HANDLE: FakeCall = FakeCall;

/// A fake `busbar_call`: allocate a buffer holding the thread-local body and return the
/// thread-local status. Mimics the plugin side (plugin allocates, engine frees via `busbar_free`).
unsafe extern "C-unwind" fn fake_call(
    _handle: *mut c_void,
    _req: *const u8,
    _req_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let (status, body) = FAKE_CALL_HANDLE.with(|c| c.get());
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
unsafe extern "C-unwind" fn fake_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len != 0 {
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)));
    }
}

/// Build a `DynStore` whose `call` is `fake_call`, reusing a real loaded store's `Library`/handle/
/// `close` (so `RawPlugin` is genuinely valid) but our fake `free` to match `fake_call`'s allocator.
fn dyn_store_with_fake_call() -> Option<DynStore> {
    let path = store_fixture_plugin_path()?;
    // Stage a genuine `RawPlugin` (real `Library` + handle + `close`), then splice in our fake
    // `call`/`free` so the response's (status, body) is what the test chooses.
    let bytes = std::fs::read(&path).expect("read sibling store-sqlite-plugin cdylib");
    // `.expect`, NOT `.ok()?`: the ONLY sanctioned reason these revocation guards may skip is
    // "the cdylib was never built" — which `store_fixture_plugin_path` already turns into a hard
    // panic under CI. A STAGING failure is a different thing entirely, and swallowing it into a
    // `None` would let the whole revocation fail-open suite self-disable while the run stayed
    // green.
    let (lib, staged) = stage::load_library_from_bytes(&bytes, "fake-call-store")
        .expect("stage the sibling store-sqlite-plugin cdylib for the fake-call harness");
    let mut raw = wire_up_raw(
        lib,
        &unique_sqlite_cfg("fake-call-store"),
        "fake-call-store".to_string(),
        abi_kind::STORE,
        abi_kind::STORE,
        Some(staged),
    )
    .expect("wire up raw");
    // Override the call + free seam so responses come from `fake_call` (freed by `fake_free`).
    raw.call = fake_call;
    raw.free = fake_free;
    Some(DynStore { raw })
}

/// (1) A GENUINE unsupported-variant signal — the (rebuilt) SDK returns the crisp
/// `STATUS_UNSUPPORTED` when it cannot deserialize the `ListDenylist` request enum — falls back to
/// an EMPTY denylist so a store predating the variant still BOOTS. The body text is irrelevant.
#[test]
fn denylist_unsupported_status_falls_back_empty() {
    let Some(store) = dyn_store_with_fake_call() else {
        eprintln!("skip: store-sqlite-plugin cdylib not built (run `cargo build --release -p busbar-store-sqlite-plugin` in a sibling ../store-sqlite checkout)");
        return;
    };
    FAKE_CALL_HANDLE.with(|c| {
        c.set((
            STATUS_UNSUPPORTED,
            b"malformed request JSON: unknown variant `ListDenylist`",
        ))
    });
    let out = store.list_denylist();
    assert_eq!(
        out.expect("unsupported variant must boot with an empty denylist"),
        Vec::<String>::new(),
    );
}

/// (1b) LEGACY v1-SDK interop, keyed on the shape the v1 SDK ACTUALLY emits. Every generation of
/// the v1 SDK spelled an undecodable request variant
/// `Err((format!("malformed request JSON: {e}"), true))` + `write_buf` → a NON-EMPTY
/// `STATUS_PROTOCOL`. That is what must boot with an empty denylist.
#[test]
fn denylist_legacy_v1_decode_failure_falls_back_empty() {
    let Some(store) = dyn_store_with_fake_call() else {
        eprintln!("skip: store-sqlite-plugin cdylib not built (run `cargo build --release -p busbar-store-sqlite-plugin` in a sibling ../store-sqlite checkout)");
        return;
    };
    FAKE_CALL_HANDLE.with(|c| {
        c.set((
            STATUS_PROTOCOL,
            b"malformed request JSON: unknown variant `ListDenylist`, expected one of `PutKey`",
        ))
    });
    assert_eq!(
        store
            .list_denylist()
            .expect("the real v1 decode-failure shape must boot with an empty denylist"),
        Vec::<String>::new(),
    );
}

/// THE CLASS TEST for the revocation fail-open. It enumerates every way a store plugin of ANY
/// SDK generation can CRASH or violate the protocol, and asserts that NONE of them can empty the
/// denylist. The discriminator that decides this is `TransportError::from_status`, so one function
/// has to be wrong for any row here to flip — there is no per-op patch to keep in sync.
///
/// The row that motivated it: an EMPTY-buffer `STATUS_PROTOCOL`. A v1 SDK mapped a CAUGHT PANIC to
/// exactly that (`Err(_) => STATUS_PROTOCOL`, no `write_buf`), as does a null handle, as does the
/// CURRENT SDK's `call_boundary` on a caller-protocol violation. Classifying it as the legacy
/// unsupported signal meant a pre-`STATUS_PANIC` store plugin that panicked inside `list_denylist`
/// hydrated an EMPTY denylist and every revoked signed token was accepted again.
#[test]
fn no_plugin_crash_shape_can_empty_the_denylist() {
    let Some(store) = dyn_store_with_fake_call() else {
        eprintln!("skip: store-sqlite-plugin cdylib not built (run `cargo build --release -p busbar-store-sqlite-plugin` in a sibling ../store-sqlite checkout)");
        return;
    };
    // (status, body, what the shape IS) — every one must FAIL CLOSED.
    let crashes: &[(i32, &'static [u8], &str)] = &[
        (
            STATUS_PROTOCOL,
            b"",
            "v1-SDK caught panic / null handle / current-SDK protocol violation (bare status)",
        ),
        (STATUS_PANIC, b"plugin panicked", "current-SDK caught panic"),
        (
            STATUS_PROTOCOL,
            b"null request pointer",
            "v1-SDK caller-protocol violation with a message",
        ),
        (
            busbar_plugin_abi::STATUS_ERR,
            b"backend read failed: unknown variant of corruption",
            "real backend error whose text mimics a decode failure",
        ),
        (99, b"novel status", "a status this engine has never seen"),
    ];
    for (status, body, what) in crashes {
        FAKE_CALL_HANDLE.with(|c| c.set((*status, body)));
        assert!(
            store.list_denylist().is_err(),
            "{what}: must fail CLOSED, never hydrate an empty denylist"
        );
        FAKE_CALL_HANDLE.with(|c| c.set((*status, body)));
        assert!(
            store.list_audit_tail(8).is_err(),
            "{what}: must not silently degrade the audit tail"
        );
        FAKE_CALL_HANDLE.with(|c| c.set((*status, body)));
        assert!(
            store.append_audit(&audit_fixture()).is_err(),
            "{what}: must not be swallowed as 'this store has no durable audit'"
        );
    }
    // Positive control: the TWO shapes that ARE the unsupported signal still open the fallback, so
    // this test cannot pass by simply refusing every fallback.
    for (status, body, what) in [
        (STATUS_UNSUPPORTED, &b"unsupported variant"[..], "crisp"),
        (
            STATUS_PROTOCOL,
            &b"malformed request JSON: unknown variant `ListDenylist`"[..],
            "legacy v1",
        ),
    ] {
        FAKE_CALL_HANDLE.with(|c| c.set((status, body)));
        assert_eq!(
            store
                .list_denylist()
                .unwrap_or_else(|e| panic!("{what} unsupported signal must fall back: {}", e.0)),
            Vec::<String>::new(),
        );
    }
}

/// The CURRENT SDK returns a BARE `STATUS_PROTOCOL` — no buffer — for a null handle or a null
/// request pointer, and its own comment calls that "a caller-protocol violation, not an old-SDK
/// signal". Pin that the loader agrees, so the two halves of the design cannot drift apart again.
#[test]
fn current_sdk_bare_protocol_is_not_unsupported() {
    assert!(
            !TransportError::from_status(STATUS_PROTOCOL, "", "p").is_unsupported(),
            "a bare STATUS_PROTOCOL is what busbar_plugin_sdk::boundary::call_boundary returns for a \
             caller-protocol violation; treating it as 'unsupported' opens the safe-default fallback"
        );
}

/// A minimal audit record for the crash-shape sweep.
fn audit_fixture() -> AuditRecord {
    AuditRecord {
        seq: 1,
        ts: 2,
        action: "plugin.install".into(),
        resource: "plugin:1".into(),
        outcome: "applied".into(),
        principal: "admin".into(),
        prev_hash: String::new(),
        hash: "h".into(),
    }
}

/// (2) THE CLOSED FAIL-OPEN: a real backend error (`STATUS_ERR`) whose BODY happens to contain the
/// string "unknown variant" must NOT be misclassified as old-SDK. Under the former substring match
/// this hydrated an empty denylist (accepting revoked tokens); now it PROPAGATES → boot fails CLOSED.
#[test]
fn denylist_backend_error_with_unknown_variant_text_propagates() {
    let Some(store) = dyn_store_with_fake_call() else {
        eprintln!("skip: store-sqlite-plugin cdylib not built (run `cargo build --release -p busbar-store-sqlite-plugin` in a sibling ../store-sqlite checkout)");
        return;
    };
    // A crafted / coincidental backend error: STATUS_ERR, but the body contains "unknown variant".
    FAKE_CALL_HANDLE.with(|c| {
        c.set((
            busbar_plugin_abi::STATUS_ERR,
            b"backend read failed: table 'denylist' reported unknown variant of corruption",
        ))
    });
    let err = store
        .list_denylist()
        .expect_err("a STATUS_ERR must fail CLOSED even when its text contains 'unknown variant'");
    assert!(
        err.0.contains("unknown variant"),
        "the propagated error keeps the backend message: {}",
        err.0
    );
}

/// `list_audit_tail`: a real backend error (`STATUS_ERR`) must PROPAGATE, not be masked as an
/// old-SDK unsupported-variant signal and silently re-issued as a full `list_audit`. Before the fix
/// the bare `Err(_)` fallback swallowed EVERY error into the full-list path, hiding a store fault
/// (and doing extra work against a store that just failed). Now only `STATUS_PROTOCOL` falls back.
#[test]
fn audit_tail_backend_error_propagates_not_masked_by_fallback() {
    let Some(store) = dyn_store_with_fake_call() else {
        eprintln!("skip: store-sqlite-plugin cdylib not built (run `cargo build --release -p busbar-store-sqlite-plugin` in a sibling ../store-sqlite checkout)");
        return;
    };
    FAKE_CALL_HANDLE.with(|c| {
        c.set((
            busbar_plugin_abi::STATUS_ERR,
            b"backend read failed: audit table I/O error",
        ))
    });
    let err = store
        .list_audit_tail(10)
        .expect_err("a STATUS_ERR from the store must propagate, not fall back to list_audit");
    assert!(
        err.0.contains("audit table I/O error"),
        "the propagated error keeps the backend message: {}",
        err.0
    );
}

// ── Class-level loader discrimination harness: the SAME matrix of injected
// statuses × the three fallback-bearing methods, driven through the real
// `call_raw_status` → `TransportError::from_status` → `is_unsupported()` path. A new
// fallback-bearing method inherits this coverage the moment it keys on `is_unsupported()`. ────

/// THE REGRESSION GUARD: a plugin PANIC on `ListDenylist` arrives as `STATUS_PANIC` → `Fault`,
/// `is_unsupported()` is false, so `list_denylist` fails CLOSED (Err) — it does NOT silently return
/// `Ok(vec![])`. Under the earlier taxonomy a panic returned `STATUS_PROTOCOL` and was misread as
/// old-SDK, hydrating an EMPTY revocation denylist (accepting revoked tokens). Now structurally
/// impossible: STATUS_PANIC and STATUS_UNSUPPORTED are different integers → different kinds.
#[test]
fn panic_in_list_denylist_fails_closed_not_empty() {
    let Some(store) = dyn_store_with_fake_call() else {
        eprintln!("skip: store-sqlite-plugin cdylib not built (run `cargo build --release -p busbar-store-sqlite-plugin` in a sibling ../store-sqlite checkout)");
        return;
    };
    FAKE_CALL_HANDLE.with(|c| {
        c.set((
            STATUS_PANIC,
            b"plugin panicked (caught at the export boundary)",
        ))
    });
    let err = store
        .list_denylist()
        .expect_err("a plugin PANIC must fail CLOSED, never hydrate an empty denylist");
    assert!(
        !err.0.is_empty(),
        "the propagated fault carries the panic message"
    );
}

/// The full status matrix on `list_denylist`: UNSUPPORTED → empty fallback; PANIC → Err (fault);
/// backend ERR → Err; protocol-with-message → Err. Only the deliberate unsupported signal empties.
#[test]
fn denylist_status_matrix() {
    let Some(store) = dyn_store_with_fake_call() else {
        eprintln!("skip: store-sqlite-plugin cdylib not built (run `cargo build --release -p busbar-store-sqlite-plugin` in a sibling ../store-sqlite checkout)");
        return;
    };
    FAKE_CALL_HANDLE.with(|c| c.set((STATUS_UNSUPPORTED, b"unsupported variant")));
    assert_eq!(
        store.list_denylist().expect("unsupported → empty"),
        Vec::<String>::new()
    );

    FAKE_CALL_HANDLE.with(|c| c.set((STATUS_PANIC, b"panicked")));
    assert!(store.list_denylist().is_err(), "panic → fail closed");

    FAKE_CALL_HANDLE.with(|c| c.set((STATUS_PROTOCOL, b"null handle")));
    assert!(
        store.list_denylist().is_err(),
        "protocol-with-message → propagate (a caller violation, not old-SDK)"
    );
}

/// The same matrix for `append_audit`: UNSUPPORTED → Ok(()) (best-effort, RAM ring holds it); a
/// PANIC → Err (a store crash on audit-write must surface, never be silently swallowed).
#[test]
fn append_audit_status_matrix() {
    let Some(store) = dyn_store_with_fake_call() else {
        eprintln!("skip: store-sqlite-plugin cdylib not built (run `cargo build --release -p busbar-store-sqlite-plugin` in a sibling ../store-sqlite checkout)");
        return;
    };
    let rec = AuditRecord {
        seq: 1,
        ts: 2,
        action: "plugin.install".into(),
        resource: "plugin:1".into(),
        outcome: "applied".into(),
        principal: "admin".into(),
        prev_hash: String::new(),
        hash: "h".into(),
    };
    FAKE_CALL_HANDLE.with(|c| c.set((STATUS_UNSUPPORTED, b"no durable audit")));
    store
        .append_audit(&rec)
        .expect("unsupported → best-effort Ok(())");

    FAKE_CALL_HANDLE.with(|c| c.set((STATUS_PANIC, b"panicked")));
    assert!(
        store.append_audit(&rec).is_err(),
        "a panic on audit-write must surface, never be swallowed as unsupported"
    );
}

/// Direct classification proof (no FFI) of the total status → semantic-kind map. EXACTLY TWO shapes
/// are the unsupported signal: the crisp `STATUS_UNSUPPORTED`, and the legacy v1 decode failure (a
/// `STATUS_PROTOCOL` carrying `LEGACY_V1_UNDECODABLE_PREFIX`). A PANIC, a backend error (even one
/// whose text says "unknown variant"), a BARE protocol violation, an unknown status, and every
/// engine-internal error are NOT unsupported.
#[test]
fn transport_error_classification() {
    // The two unsupported signals: the crisp code, and the shape the v1 SDK really emitted.
    assert!(TransportError::from_status(STATUS_UNSUPPORTED, "unsupported", "p").is_unsupported());
    assert!(TransportError::from_status(
        STATUS_PROTOCOL,
        "malformed request JSON: unknown variant `ListDenylist`",
        "p"
    )
    .is_unsupported());

    // A PANIC is a Fault, NEVER unsupported — this is what keeps a crash from opening the fallback.
    assert!(!TransportError::from_status(STATUS_PANIC, "panicked", "p").is_unsupported());
    // A backend error whose body contains "unknown variant" is NOT unsupported.
    assert!(
        !TransportError::from_status(busbar_plugin_abi::STATUS_ERR, "unknown variant", "p")
            .is_unsupported()
    );
    // A BARE STATUS_PROTOCOL — null handle, null request pointer, or a v1-SDK caught panic — is a
    // caller-protocol violation, NOT unsupported. Reading it as unsupported is the inversion that
    // reopens the revocation fail-open.
    assert!(!TransportError::from_status(STATUS_PROTOCOL, "", "p").is_unsupported());
    // Nor is a STATUS_PROTOCOL carrying any OTHER message.
    assert!(!TransportError::from_status(STATUS_PROTOCOL, "null handle", "p").is_unsupported());
    // An unknown status defaults to Fault (propagate), never unsupported.
    assert!(!TransportError::from_status(99, "novel status", "p").is_unsupported());
    // An engine-internal error is always Fault.
    assert!(!TransportError::engine("plugin response decode failed".into()).is_unsupported());
    // A bare status still produces a diagnosable message naming the plugin and the status.
    let m = TransportError::from_status(STATUS_PROTOCOL, "", "libstore.so").message;
    assert!(m.contains("libstore.so") && m.contains("-1"), "{m}");
}

/// `kind: secret` is the one plugin kind with no other over-the-ABI test coverage. Locate the
/// hermetic `busbar-secret-example-plugin` cdylib, mirroring `store_fixture_plugin_path` above — CI
/// (`cargo test --workspace`) always builds it, so a missing cdylib there is a hard failure, not
/// a silent skip.
/// Checks BOTH the "uplifted" `<profile_dir>/<name>` copy and the raw `<profile_dir>/deps/<name>`
/// compiler output — a SCOPED `cargo test -p busbar-plugin-loader` (what dev-gate.yml's final
/// step runs) does not uplift the cdylib to the top-level profile dir, only to `target/deps`,
/// so checking only `profile_dir` silently found nothing even though the cdylib really was
/// built. Same fix already applied to `store_fixture_plugin_path` above and `hook_plugin_path`
/// in `hook.rs`.
fn secret_example_plugin_path() -> Option<std::path::PathBuf> {
    let candidate = (|| {
        let exe = std::env::current_exe().ok()?;
        let profile_dir = exe.parent()?.parent()?;
        let name = plugin_library_filename("busbar_secret_example_plugin");
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
    })();
    if candidate.is_none() && std::env::var_os("CI").is_some() {
        panic!(
            "the secret example plugin cdylib is not built under CI: `cargo test --workspace` \
                 must build busbar_secret_example_plugin (checked both the uplifted target dir and \
                 target/deps). Refusing to silently skip the only over-the-ABI coverage of the \
                 DynSecret dlopen seam."
        );
    }
    candidate
}

/// End-to-end: load the REAL secret-example-plugin cdylib over the C ABI and exercise
/// `SecretModule::resolve` through the `DynSecret` wrapper — a hit, a miss (fail-closed, never an
/// empty `Ok`), and a reference whose `settings` carries no `key` at all.
#[test]
fn load_and_exercise_secret_example_plugin() {
    let Some(path) = secret_example_plugin_path() else {
        eprintln!("skip: secret example plugin cdylib not built (run under --workspace)");
        return;
    };
    let bytes = std::fs::read(&path).expect("read secret example plugin cdylib");
    let module = load_secret_from_bytes(
        &bytes,
        r#"{"map": {"db-password": "hunter2"}}"#,
        "secret-example",
        "secret",
    )
    .expect("load secret example plugin over the ABI");

    let mut settings = serde_json::Map::new();
    settings.insert(
        "key".to_string(),
        serde_json::Value::String("db-password".into()),
    );
    let bytes = module.resolve(&settings).expect("known key resolves");
    assert_eq!(bytes, b"hunter2");

    let mut miss = serde_json::Map::new();
    miss.insert(
        "key".to_string(),
        serde_json::Value::String("no-such-key".into()),
    );
    assert!(
        module.resolve(&miss).is_err(),
        "an unknown key must fail closed, never resolve empty"
    );

    assert!(
        module.resolve(&serde_json::Map::new()).is_err(),
        "settings with no `key` field must fail closed"
    );
}

/// Locate the hermetic `busbar-export-example-plugin` cdylib, mirroring
/// `secret_example_plugin_path` above (see its doc for the uplifted-vs-`deps` rationale). CI
/// (`cargo test --workspace`) always builds it, so a missing cdylib there is a hard failure, not a
/// silent skip — it is the only over-the-ABI coverage of the `DynExport` dlopen seam.
fn export_example_plugin_path() -> Option<std::path::PathBuf> {
    let candidate = (|| {
        let exe = std::env::current_exe().ok()?;
        let profile_dir = exe.parent()?.parent()?;
        let name = plugin_library_filename("busbar_export_example_plugin");
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
    })();
    if candidate.is_none() && std::env::var_os("CI").is_some() {
        panic!(
            "the export example plugin cdylib is not built under CI: `cargo test --workspace` \
                 must build busbar_export_example_plugin (checked both the uplifted target dir and \
                 target/deps). Refusing to silently skip the only over-the-ABI coverage of the \
                 DynExport dlopen seam."
        );
    }
    candidate
}

/// END-TO-END over the REAL export-example-plugin cdylib: load it through the loader (which queries
/// `Streams` once at load), assert it reports `[Metrics]`, then `Deliver` a metrics batch and
/// assert the sink acks `Delivered` (an `Ok(())`). This is the exact seam the engine's
/// observability export will consume: verified bytes in, a `DynExport` out.
#[test]
fn load_and_exercise_export_example_plugin() {
    use busbar_plugin_abi::export::ExportStream;
    let Some(path) = export_example_plugin_path() else {
        eprintln!("skip: export example plugin cdylib not built (run under --workspace)");
        return;
    };
    let bytes = std::fs::read(&path).expect("read export example plugin cdylib");
    let sink = export::load_export_from_bytes(&bytes, "{}", "export-example", "export")
        .expect("load export example plugin over the ABI");

    // Streams was queried once at load and reports exactly [Metrics].
    assert_eq!(sink.streams(), &[ExportStream::Metrics]);

    // A delivery for the declared stream acks Delivered (Ok).
    sink.deliver(
        ExportStream::Metrics,
        &serde_json::json!({"samples": [{"name": "reqs", "value": 1}]}),
    )
    .expect("deliver returns Delivered");
}

// ── A2A TASK DURABILITY OVER THE REAL PLUGIN PATH ───────────────────────────────────────────────
//
// The three row types are imported HERE rather than taken from `use super::*`, so this test
// compiles unchanged against a `plugin-loader` that does not yet know them. That is not tidiness:
// it is what let this test be run RED against the pre-fix ABI and watched to report the task
// missing after the restart, instead of failing to build and proving nothing.
//
// The only shape of test that can see the defect these overrides close. `busbar-plugin-abi`'s
// `StoreRequest` had NO variant for any of the ten A2A-task / MCP-call-log ops and `DynStore`
// overrode none of them, so a store loaded as a plugin — which is BOTH deployment paths, file-drop
// and runtime install — fell through to the trait's accept-and-keep-nothing defaults. `put_task`
// discarded the task and returned `Ok(())`. Every store crate's own unit tests passed the whole
// time, because they never cross the ABI.

/// Locate the hermetic in-tree `busbar-store-example-plugin` cdylib. Mirrors
/// `secret_example_plugin_path`/`export_example_plugin_path`, including checking BOTH the uplifted
/// `<profile_dir>/<name>` copy and the raw `<profile_dir>/deps/<name>` compiler output (a scoped
/// `cargo test -p busbar-plugin-loader` only produces the latter).
///
/// Under `CI` a missing cdylib is a HARD failure. Unlike the sqlite fixture this plugin is an
/// in-tree workspace member that `cargo test --workspace` always builds, so its absence means a
/// broken pipeline — and a silent skip here would restore exactly the situation this test exists to
/// end: a green run that proved nothing about durability.
use busbar_api::{McpCallRecord, PlaneDisposition, TaskEventRow, TaskRow};

// ── the loader test speaks TYPED rows; the ABI speaks NEUTRAL kind-tagged plane records ──────────
//
// The fourteen protocol-named `Store` methods were deleted in the 1.6.0 14→8 collapse, so this suite
// exercises the ONLY durable-plane surface there is: the eight neutral verbs. These free helpers
// build the kind-tagged `PlaneRecord` envelope for a typed row and decode a body back, so the test
// bodies stay readable while every call still crosses the real plugin ABI as a neutral verb — the
// exact surface a deployment takes. The `kind` strings match the reference `impl Store` in
// `store-example-plugin` verbatim.

fn task_record(t: &TaskRow) -> PlaneRecord {
    PlaneRecord {
        kind: "task".into(),
        id: t.task_id.clone(),
        parent: None,
        seq: 0,
        ts: t.updated_at,
        disposition: if matches!(
            t.state.as_str(),
            "completed" | "failed" | "canceled" | "rejected"
        ) {
            PlaneDisposition::Terminal
        } else {
            PlaneDisposition::Active
        },
        body: serde_json::to_vec(t).unwrap(),
    }
}

fn event_record(e: &TaskEventRow) -> PlaneRecord {
    PlaneRecord {
        kind: "task_event".into(),
        id: e.task_id.clone(),
        parent: Some(e.task_id.clone()),
        seq: e.seq,
        ts: e.ts,
        disposition: PlaneDisposition::Active,
        body: serde_json::to_vec(e).unwrap(),
    }
}

fn call_record(c: &McpCallRecord) -> PlaneRecord {
    PlaneRecord {
        kind: "call".into(),
        id: c.principal.clone(),
        parent: Some(c.principal.clone()),
        seq: c.seq,
        ts: c.ts,
        disposition: PlaneDisposition::Active,
        body: serde_json::to_vec(c).unwrap(),
    }
}

fn n_get_task(s: &dyn busbar_api::Store, id: &str) -> StoreResult<Option<TaskRow>> {
    Ok(s.get_plane_record("task", id)?
        .map(|b| serde_json::from_slice(&b).unwrap()))
}
fn n_list_tasks(s: &dyn busbar_api::Store) -> StoreResult<Vec<TaskRow>> {
    Ok(s.list_plane_records("task", &PlaneSelector::All)?
        .iter()
        .map(|b| serde_json::from_slice(b).unwrap())
        .collect())
}
fn n_list_task_events(s: &dyn busbar_api::Store, id: &str) -> StoreResult<Vec<TaskEventRow>> {
    Ok(
        s.list_plane_records("task_event", &PlaneSelector::Parent(id.into()))?
            .iter()
            .map(|b| serde_json::from_slice(b).unwrap())
            .collect(),
    )
}
fn n_list_mcp_calls(s: &dyn busbar_api::Store, p: &str) -> StoreResult<Vec<McpCallRecord>> {
    Ok(
        s.list_plane_records("call", &PlaneSelector::Parent(p.into()))?
            .iter()
            .map(|b| serde_json::from_slice(b).unwrap())
            .collect(),
    )
}
fn n_list_call_principals(s: &dyn busbar_api::Store) -> StoreResult<Vec<String>> {
    s.list_plane_record_parents("call")
}

fn store_example_plugin_path() -> Option<std::path::PathBuf> {
    let candidate = (|| {
        let exe = std::env::current_exe().ok()?;
        let profile_dir = exe.parent()?.parent()?;
        let name = plugin_library_filename("busbar_store_example_plugin");
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
    })();
    if candidate.is_none() && std::env::var_os("CI").is_some() {
        panic!(
            "the store example plugin cdylib is not built under CI: `cargo test --workspace` must \
             build busbar_store_example_plugin (checked both the uplifted target dir and \
             target/deps). Refusing to silently skip the ONLY end-to-end proof that a task written \
             through a plugin store survives a restart."
        );
    }
    candidate
}

/// A `TaskRow` with every field set to something distinguishable, so a round trip that drops or
/// transposes a field fails rather than passing on a mostly-empty row.
fn sample_task_row(task_id: &str, state: &str, updated_at: u64) -> TaskRow {
    TaskRow {
        task_id: task_id.to_string(),
        context_id: "ctx-42".into(),
        principal: "vk_owner".into(),
        direction: "inbound".into(),
        state: state.to_string(),
        agent_id: "agent-7".into(),
        artifact_cursor: 3,
        push_callback: "https://example.invalid/hook".into(),
        created_at: 1_000,
        updated_at,
    }
}

/// THE TEST. Load the store as a PLUGIN, write a task (plus its provenance chain and an MCP call
/// record), then RESTART the plugin — drop the handle, unload the library, `dlopen` it again and
/// `busbar_open` a fresh instance whose only possible source of state is the bytes on disk — and
/// read everything back over the same ABI.
///
/// Against the ABI as it stood before the ten variants were added this fails at the first
/// assertion: `get_task` returns `None`, because `DynStore` never sent the write anywhere.
#[test]
fn task_state_written_through_a_plugin_store_survives_a_restart() {
    let Some(lib) = store_example_plugin_path() else {
        eprintln!("skip: store example plugin cdylib not built (run under --workspace)");
        return;
    };
    // A private file for this test's own durable state; `load_store` passes it to the plugin's
    // `open`, which is what selects the fixture's file-backed mode.
    let dir = std::env::temp_dir().join(format!(
        "busbar-task-durability-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).expect("create durable dir");
    let state_file = dir.join("durable.json");
    let cfg = serde_json::json!({ "durable_path": state_file.to_string_lossy() }).to_string();

    let task = sample_task_row("task-abc", "input-required", 2_000);
    let event = TaskEventRow {
        task_id: "task-abc".into(),
        seq: 1,
        ts: 1_500,
        kind: "task.submitted".into(),
        context_id: "ctx-42".into(),
        principal: "vk_owner".into(),
        agent_id: "agent-7".into(),
        state: "submitted".into(),
        request_id: "req-9".into(),
        prev_hash: String::new(),
        hash: "deadbeef".into(),
    };
    let call = McpCallRecord {
        principal: "vk_owner".into(),
        seq: 1,
        ts: 1_600,
        server: "srv".into(),
        tool: "srv_echo".into(),
        outcome: "dispatched".into(),
        reason: String::new(),
        tool_digest: "sha256:aaa".into(),
        pin_generation: 4,
        request_id: "req-9".into(),
        prev_hash: String::new(),
        hash: "cafebabe".into(),
    };

    // ── BEFORE THE RESTART: write through the plugin, and assert NOTHING ──────────────────────
    //
    // Deliberately no read-back here. The failure this test exists to show is the one AFTER the
    // restart, and an assertion in this block would fire first and report a same-process symptom
    // instead — which is exactly what happened on the first red run. The same-handle round trip is
    // its own test below, so that diagnostic is not lost, it just does not pre-empt this one.
    {
        let store = load_store(&lib, &cfg).expect("load store example plugin over the ABI");
        store
            .upsert_plane_record(&task_record(&task))
            .expect("upsert task");
        store
            .append_plane_record(&event_record(&event))
            .expect("append task_event");
        store
            .append_plane_record(&call_record(&call))
            .expect("append call");
        // Dropping the box closes the plugin handle and unloads the library. Everything the plugin
        // held in memory goes with it.
    }

    // ── THE RESTART: a fresh dlopen and a fresh `busbar_open` ─────────────────────────────────
    let store = load_store(&lib, &cfg).expect("re-load store example plugin after the restart");

    assert_eq!(
        n_get_task(store.as_ref(), "task-abc").expect("get_task after restart"),
        Some(task.clone()),
        "THE WHOLE POINT: a task written through the plugin ABI must still be there after a \
         restart. `None` here is the production defect — `put_task` reported success and the \
         engine kept nothing."
    );
    assert_eq!(
        n_list_tasks(store.as_ref()).expect("list_tasks after restart"),
        vec![task.clone()]
    );
    assert_eq!(
        n_list_task_events(store.as_ref(), "task-abc").expect("list_task_events after restart"),
        vec![event],
        "the provenance chain must survive with `hash`/`prev_hash` verbatim"
    );
    assert_eq!(
        n_list_mcp_calls(store.as_ref(), "vk_owner").expect("list_mcp_calls after restart"),
        vec![call]
    );
    assert_eq!(
        n_list_call_principals(store.as_ref()).expect("list_mcp_call_principals after restart"),
        vec!["vk_owner".to_string()],
        "the boot enumeration must find the principal whose chain this process never saw written"
    );

    // ── the two retention ops, which return a COUNT rather than `Ok(0)` from a defaulted no-op ──
    assert_eq!(
        store.purge_plane_records_before("task", 3_000).expect("purge_tasks_before"),
        0,
        "an `input-required` task is NEVER purged by age — it is exactly the row waiting on a human"
    );
    let terminal = sample_task_row("task-done", "completed", 2_000);
    store
        .upsert_plane_record(&task_record(&terminal))
        .expect("put_task terminal");
    assert_eq!(
        store
            .purge_plane_records_before("task", 3_000)
            .expect("purge_tasks_before"),
        1,
        "the TERMINAL row is purged, and the count comes from the plugin, not a default"
    );
    assert_eq!(
        store
            .purge_plane_records_before("call", 2_000)
            .expect("purge_mcp_calls_before"),
        1
    );

    // The purge is durable too: a third open sees the compacted state.
    drop(store);
    let store = load_store(&lib, &cfg).expect("re-load after the purge");
    assert_eq!(
        n_list_tasks(store.as_ref()).expect("list_tasks").len(),
        1,
        "the purge must have been written through, not just applied in the plugin's memory"
    );
    assert!(n_list_mcp_calls(store.as_ref(), "vk_owner")
        .expect("list_mcp_calls")
        .is_empty());

    drop(store);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The same-handle round trip, split out of the durability test so that a failure there names the
/// RESTART rather than being pre-empted by a same-process symptom. This is the narrower claim: a
/// task written through the plugin ABI is readable back through the plugin ABI at all.
#[test]
fn a_task_written_through_a_plugin_store_is_readable_back_through_it() {
    let Some(lib) = store_example_plugin_path() else {
        eprintln!("skip: store example plugin cdylib not built (run under --workspace)");
        return;
    };
    let dir = std::env::temp_dir().join(format!(
        "busbar-task-roundtrip-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).expect("create durable dir");
    let cfg = serde_json::json!({ "durable_path": dir.join("durable.json").to_string_lossy() })
        .to_string();

    let store = load_store(&lib, &cfg).expect("load store example plugin over the ABI");
    let task = sample_task_row("task-rt", "working", 5_000);
    store
        .upsert_plane_record(&task_record(&task))
        .expect("put_task");
    assert_eq!(
        n_get_task(store.as_ref(), "task-rt").expect("get_task"),
        Some(task),
        "`put_task` returned Ok — the task must actually be there. `None` means the write was \
         discarded at the ABI and the success was a lie."
    );
    drop(store);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Every `Store` trait method has a `StoreRequest` variant AND a `DynStore` override — checked by
/// PARSING THE SOURCE, because neither gap is a compile error.
///
/// A missing `StoreRequest` variant is invisible to the compiler (the trait has a default), and a
/// missing `DynStore` override is invisible for the same reason: `impl Store for DynStore` compiles
/// perfectly while silently inheriting an accept-and-keep-nothing default for an op the backend
/// implements. That is precisely how ten methods reached `dev` with the engine dropping every write
/// over the deployment path, and it was found by accident rather than by any check. This is the
/// check.
///
/// Source parsing is admittedly crude, and it is the honest tool for the job: there is no runtime
/// reflection over a Rust trait, and a `#[deny]`-style compile-time proof would need a proc macro
/// owning both the trait and the enum. The failure mode of a parser that drifts is a FALSE ALARM
/// naming the method it could not find, which is a loud, cheap thing to fix — the opposite of the
/// silent pass it replaces.
#[test]
fn every_store_trait_method_has_an_abi_variant_and_a_dynstore_override() {
    fn snake(camel: &str) -> String {
        let mut out = String::new();
        for (i, c) in camel.char_indices() {
            if c.is_uppercase() && i > 0 {
                out.push('_');
            }
            out.extend(c.to_lowercase());
        }
        out
    }

    let trait_src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../api/src/store.rs"));
    let abi_src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../plugin-abi/src/lib.rs"
    ));
    let loader_src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"));

    // The trait's methods: `fn <name>` at exactly four spaces of indent, after `pub trait Store`.
    let trait_body = trait_src
        .split_once("pub trait Store")
        .expect("the Store trait")
        .1;
    let methods: Vec<&str> = trait_body
        .lines()
        .filter_map(|l| l.strip_prefix("    fn "))
        .filter_map(|l| l.split(['(', '<', ' ']).next())
        .collect();
    assert!(
        methods.len() > 30,
        "the trait parser found only {} methods — it has drifted from the source shape and would \
         pass vacuously: {methods:?}",
        methods.len()
    );

    // The wire enum's variants, snake_cased back to the method name they mirror one-to-one.
    let enum_body = abi_src
        .split_once("pub enum StoreRequest {")
        .expect("the StoreRequest enum")
        .1
        .split_once("\n}\n")
        .expect("the end of StoreRequest")
        .0;
    let variants: Vec<String> = enum_body
        .lines()
        .filter_map(|l| l.strip_prefix("    "))
        .filter(|l| l.starts_with(|c: char| c.is_uppercase()))
        .filter_map(|l| l.split(['(', '{', ',', ' ']).next())
        .map(snake)
        .collect();
    // The enum parser's own sanity check is deliberately NOT a count. A count floor here would be
    // measuring the very thing this test reports on, so a tree that is genuinely missing variants
    // fails with "the parser has drifted" — misdirection, and observed on this test's first red
    // run. Anchor on variants that have existed since v1 instead: if those parse, the parser works,
    // and any absence below is a real absence.
    for anchor in ["put_key", "list_denylist", "lookup_credential_secret"] {
        assert!(
            variants.iter().any(|v| v == anchor),
            "the enum parser did not find `{anchor}`, which has always been there — the parser has \
             drifted from the source shape and every check below would pass vacuously: {variants:?}"
        );
    }

    // `DynStore`'s overrides.
    let dynstore_body = loader_src
        .split_once("impl Store for DynStore {")
        .expect("impl Store for DynStore")
        .1;
    let overrides: Vec<&str> = dynstore_body
        .lines()
        .filter_map(|l| l.strip_prefix("    fn "))
        .filter_map(|l| l.split(['(', '<', ' ']).next())
        .collect();

    let missing_variant: Vec<&&str> = methods
        .iter()
        .filter(|m| !variants.iter().any(|v| v == *m))
        .collect();
    assert!(
        missing_variant.is_empty(),
        "these `Store` methods have NO `StoreRequest` variant, so a plugin store can never be \
         asked to perform them and the trait's default silently answers instead: {missing_variant:?}"
    );

    let missing_override: Vec<&&str> = methods.iter().filter(|m| !overrides.contains(*m)).collect();
    assert!(
        missing_override.is_empty(),
        "these `Store` methods are NOT overridden by `DynStore`, so every plugin-loaded backend \
         silently inherits the trait default for them — the write is discarded and reports \
         success: {missing_override:?}"
    );
}

// ── ALREADY-SIGNED PLUGINS MUST KEEP WORKING ────────────────────────────────────────────────────
//
// Adding the ten variants is only additive if a plugin built against an SDK that predates them
// still loads and still behaves EXACTLY as it did. That plugin cannot decode `PutTask`, so its
// `store_dispatch` answers the undecodable-request signal, and `DynStore` must turn that into the
// trait default the engine would have received before any of this existed — never an error, and
// never a boot failure.
//
// This uses the IN-TREE example plugin rather than the sibling sqlite fixture the denylist
// fallback tests use, so it runs on every machine and in every job instead of skipping wherever a
// sibling checkout is absent. A compatibility promise that only gets checked where somebody happens
// to have cloned a second repo is not a checked promise.

/// A `DynStore` over the in-tree store example plugin with the `call`/`free` seam faked, so a test
/// chooses the exact `(status, body)` an old plugin would have returned. Mirrors
/// [`dyn_store_with_fake_call`], which is pinned to the sibling sqlite fixture.
fn dyn_example_store_with_fake_call() -> Option<DynStore> {
    let path = store_example_plugin_path()?;
    let bytes = std::fs::read(&path).expect("read the in-tree store example plugin cdylib");
    let (lib, staged) = stage::load_library_from_bytes(&bytes, "fake-call-example")
        .expect("stage the in-tree store example plugin for the fake-call harness");
    let mut raw = wire_up_raw(
        lib,
        "{}",
        "fake-call-example".to_string(),
        abi_kind::STORE,
        abi_kind::STORE,
        Some(staged),
    )
    .expect("wire up raw");
    raw.call = fake_call;
    raw.free = fake_free;
    Some(DynStore { raw })
}

/// Run `op` against a store whose seam returns `(status, body)`, once per shape.
fn under_old_plugin_shapes<T: std::fmt::Debug + PartialEq>(
    store: &DynStore,
    op: impl Fn(&DynStore) -> StoreResult<T>,
    expected: T,
    what: &str,
) {
    // The two shapes an undecodable request has ever had on the wire: the current SDK's crisp
    // `STATUS_UNSUPPORTED`, and the v1 SDK's `STATUS_PROTOCOL` carrying the `malformed request
    // JSON:` body. Both mean "this plugin predates the variant".
    let shapes: &[(i32, &'static [u8], &str)] = &[
        (
            STATUS_UNSUPPORTED,
            b"malformed request JSON: unknown variant",
            "a current-SDK plugin rebuilt before the task variants existed",
        ),
        (
            STATUS_PROTOCOL,
            b"malformed request JSON: unknown variant `PutTask`, expected one of `PutKey`",
            "a v1-SDK plugin, the shape every v1 generation actually emitted",
        ),
    ];
    for (status, body, who) in shapes {
        FAKE_CALL_HANDLE.with(|c| c.set((*status, *body)));
        let out = op(store).unwrap_or_else(|e| {
            panic!(
                "`{what}` against {who} returned an ERROR ({e:?}). An already-signed plugin that \
                 cannot decode the request must get the pre-existing trait default, not a failure \
                 — anything else breaks a plugin that was working before this change landed."
            )
        });
        assert_eq!(
            out, expected,
            "`{what}` against {who} must answer exactly the trait default the engine got before \
             these variants existed"
        );
    }
}

/// A plugin that predates all ten variants keeps working: every new op degrades to the SAME
/// accept-and-keep-nothing default the engine took from the trait before the ABI carried them.
#[test]
fn a_plugin_predating_the_task_variants_still_gets_the_pre_existing_defaults() {
    let Some(store) = dyn_example_store_with_fake_call() else {
        eprintln!("skip: store example plugin cdylib not built (run under --workspace)");
        return;
    };
    let task = sample_task_row("task-old", "working", 1);
    let event = TaskEventRow {
        task_id: "task-old".into(),
        seq: 1,
        ts: 1,
        kind: "task.submitted".into(),
        context_id: "ctx".into(),
        principal: "vk".into(),
        agent_id: "a".into(),
        state: "submitted".into(),
        request_id: "r".into(),
        prev_hash: String::new(),
        hash: "h".into(),
    };
    let call = McpCallRecord {
        principal: "vk".into(),
        seq: 1,
        ts: 1,
        server: "s".into(),
        tool: "t".into(),
        outcome: "dispatched".into(),
        reason: String::new(),
        tool_digest: "sha256:a".into(),
        pin_generation: 1,
        request_id: "r".into(),
        prev_hash: String::new(),
        hash: "h".into(),
    };

    under_old_plugin_shapes(
        &store,
        |s| s.upsert_plane_record(&task_record(&task)),
        (),
        "upsert task",
    );
    under_old_plugin_shapes(&store, |s| n_get_task(s, "task-old"), None, "get_task");
    under_old_plugin_shapes(&store, |s| n_list_tasks(s), Vec::new(), "list_tasks");
    under_old_plugin_shapes(
        &store,
        |s| s.purge_plane_records_before("task", 9),
        0,
        "purge_tasks_before",
    );
    under_old_plugin_shapes(
        &store,
        |s| s.append_plane_record(&event_record(&event)),
        (),
        "append_task_event",
    );
    under_old_plugin_shapes(
        &store,
        |s| n_list_task_events(s, "task-old"),
        Vec::new(),
        "list_task_events",
    );
    under_old_plugin_shapes(
        &store,
        |s| s.append_plane_record(&call_record(&call)),
        (),
        "append_mcp_call",
    );
    under_old_plugin_shapes(
        &store,
        |s| n_list_mcp_calls(s, "vk"),
        Vec::new(),
        "list_mcp_calls",
    );
    under_old_plugin_shapes(
        &store,
        |s| n_list_call_principals(s),
        Vec::new(),
        "list_mcp_call_principals",
    );
    under_old_plugin_shapes(
        &store,
        |s| s.purge_plane_records_before("call", 9),
        0,
        "purge_mcp_calls_before",
    );
}

/// The other half of the same promise, and the one that keeps the fallback honest: NOTHING except
/// the undecodable-request signal is defaulted. A real backend error, a caught panic and a
/// caller-protocol violation all PROPAGATE, so a genuine durability failure can never be laundered
/// into "the plugin is just old" — which would report a discarded task as success all over again,
/// this time with the variants present.
#[test]
fn no_plugin_failure_shape_can_launder_a_dropped_task_into_success() {
    let Some(store) = dyn_example_store_with_fake_call() else {
        eprintln!("skip: store example plugin cdylib not built (run under --workspace)");
        return;
    };
    let task = sample_task_row("task-err", "working", 1);
    let failures: &[(i32, &'static [u8], &str)] = &[
        (STATUS_ERR, b"disk full", "a real backend error"),
        (STATUS_PANIC, b"panicked in put_task", "a caught panic"),
        (
            STATUS_PROTOCOL,
            b"",
            "a bare STATUS_PROTOCOL — a v1 caught panic, a null handle, or a caller-protocol \
             violation",
        ),
        (99, b"", "an unknown status from a future or broken plugin"),
    ];
    for (status, body, what) in failures {
        FAKE_CALL_HANDLE.with(|c| c.set((*status, *body)));
        assert!(
            store.upsert_plane_record(&task_record(&task)).is_err(),
            "`put_task` must FAIL on {what}: silently returning Ok is the exact defect these \
             variants were added to close"
        );
        FAKE_CALL_HANDLE.with(|c| c.set((*status, *body)));
        assert!(
            n_get_task(&store, "task-err").is_err(),
            "`get_task` must FAIL on {what}, never answer `None` — 'the task is gone' and 'the \
             backend is broken' are different answers"
        );
        FAKE_CALL_HANDLE.with(|c| c.set((*status, *body)));
        assert!(
            store
                .append_plane_record(&event_record(&event_free_probe()))
                .is_err(),
            "`append_task_event` must FAIL on {what}"
        );
        FAKE_CALL_HANDLE.with(|c| c.set((*status, *body)));
        assert!(
            n_list_task_events(&store, "task-err").is_err(),
            "`list_task_events` must FAIL on {what}"
        );
        FAKE_CALL_HANDLE.with(|c| c.set((*status, *body)));
        assert!(
            store.purge_plane_records_before("task", 9).is_err(),
            "`purge_tasks_before` must FAIL on {what}, never report 0 purged"
        );
    }
}

/// A throwaway `TaskEventRow` for the failure-shape sweep, where the contents are irrelevant.
fn event_free_probe() -> TaskEventRow {
    TaskEventRow {
        task_id: "task-err".into(),
        seq: 1,
        ts: 1,
        kind: "task.submitted".into(),
        context_id: "ctx".into(),
        principal: "vk".into(),
        agent_id: "a".into(),
        state: "submitted".into(),
        request_id: "r".into(),
        prev_hash: String::new(),
        hash: "h".into(),
    }
}
