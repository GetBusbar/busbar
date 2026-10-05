// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/plugin-loader/src/lib.rs`.

use super::*;
use busbar_contract::abi::cold::{
    STATUS_PANIC, STATUS_PROTOCOL, STATUS_UNSUPPORTED, TRANSPORT_VERSION,
};

/// The 1.5.5 store payload schema (v2). No loaded plugin states it since THE DESIGN §11.8 (the
/// registry refuses it at boot, ruling C21/ABI-o1); the store adapter's shim suites bind an adapter
/// at it to pin the schema-keyed shim rule.
const PUBLISHED_STORE_SCHEMA: u32 = 2;

/// The REAL JSON-lane plugin the loader-MECHANISM tests below dlopen (validation, inventory, the kind
/// gates): the export row of `[package.metadata.busbar.both-ways]`, the request-log file sink's
/// `cdylib`, one of the two sinks still on that lane (M6-COLD-DELETE residue). Under CI a missing
/// cdylib is a hard failure ([`super::both_ways::cdylib`] asserts it), never a silent skip.
fn json_lane_plugin_path() -> Option<std::path::PathBuf> {
    super::both_ways::cdylib(super::both_ways::fixture("export").0)
}

/// `validate_plugin` accepts the real JSON-lane fixture cdylib (ABI v1) without constructing an
/// instance, and `inventory` finds it in a plugins directory as valid.
///
/// The directory is a fresh one holding a copy of the fixture, not the fixture's own directory: the
/// in-tree fixture lives in cargo's profile dir (or its `deps/`), where `inventory` would dlopen
/// every proc-macro and dependency dylib cargo put there.
#[test]
fn validate_and_inventory() {
    let Some(path) = json_lane_plugin_path() else {
        eprintln!("skip: the export sink cdylib is not built");
        return;
    };
    assert_eq!(validate_plugin(&path).expect("validate"), TRANSPORT_VERSION);

    let file = path.file_name().unwrap().to_owned();
    let dir = std::env::temp_dir().join(format!(
        "busbar-validate-inventory-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::copy(&path, dir.join(&file)).unwrap();
    let inv = inventory(&dir);
    let _ = std::fs::remove_dir_all(&dir);
    let fixture = inv
        .iter()
        .find(|p| std::ffi::OsStr::new(&p.file) == file)
        .expect("the JSON-lane fixture in inventory");
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
    let Some(real_plugin) = json_lane_plugin_path() else {
        eprintln!("skip: the export sink cdylib is not built");
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
    let Some(export_plugin) = json_lane_plugin_path() else {
        eprintln!("skip: the export sink cdylib is not built");
        return;
    };
    let bytes = std::fs::read(&export_plugin).expect("read the JSON-lane fixture cdylib");

    // Seam mismatch: a real EXPORT library loaded through the AUTH entry point (expected_kind =
    // auth, exported_kind = export) must be refused, naming both kinds. Both kind-check guards run
    // BEFORE `busbar_open`, so the empty config never reaches the sink.
    let Err(err) = auth::load_login_image(
        Image::Bytes(&bytes),
        "{}",
        "kind-mismatch-seam",
        busbar_contract::abi::mechanism::kind::EXPORT,
    ) else {
        panic!("an export library must not load as an auth module");
    };
    assert!(err.contains("export"), "must name the exported kind: {err}");
    assert!(err.contains("auth"), "must name the expected kind: {err}");

    // Manifest mismatch: expected_kind matches exported_kind (both export), but the signed
    // manifest_kind lies about it — must still be refused.
    let Err(err) = export::load_export_from_bytes(&bytes, "{}", "kind-mismatch-manifest", "auth")
    else {
        panic!("an exported-export/manifest-auth disagreement must be refused");
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
    let err = response_len_ok(MAX_PLUGIN_RESPONSE_LEN + 1, "the-plugin").unwrap_err();
    assert!(err.contains("oversized response"), "got {err}");
    assert!(
        err.contains("the-plugin"),
        "names the offending plugin: {err}"
    );
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
    assert!(!TransportError::from_status(
        busbar_contract::abi::cold::STATUS_ERR,
        "unknown variant",
        "p"
    )
    .is_unsupported());
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

/// END-TO-END over the export kind's REAL sink `cdylib` (the export row of
/// `[package.metadata.busbar.both-ways]` — the request-log file sink, built from its own repo): load
/// it through the loader (which queries `Streams` once at load), assert it reports `[Logs]`, then
/// `Deliver` a request-log line and assert the sink acks (an `Ok(())`). This is the exact seam the
/// engine's observability export consumes: verified bytes in, a `DynExport` out. Under CI a missing
/// cdylib is a hard failure ([`super::both_ways::cdylib`] asserts it), never a silent skip.
#[test]
fn load_and_exercise_export_plugin() {
    use busbar_contract::abi::export::ExportStream;
    let Some(path) = super::both_ways::cdylib(super::both_ways::fixture("export").0) else {
        eprintln!("skip: the export sink cdylib is not built");
        return;
    };
    let bytes = std::fs::read(&path).expect("read the export sink cdylib");
    let sink = export::load_export_from_bytes(&bytes, "{}", "export-sink", "export")
        .expect("load the export sink over the ABI");

    // Streams was queried once at load and reports exactly [Logs].
    assert_eq!(sink.streams(), &[ExportStream::Logs]);

    // A delivery for the declared stream acks (Ok).
    sink.deliver(
        ExportStream::Logs,
        &serde_json::json!({"status": 200, "model": "m"}),
    )
    .expect("deliver acks");
}

/// `validate_plugin` must UNLOAD on a plugin worker, not on the caller's thread.
///
/// It `dlopen`s to run the ABI handshake and then has to unmap again. An implicit drop of the
/// `Library` local does that `dlclose` on the CALLER's thread, which runs the image's `.fini_array`
/// there; a `.fini_array` that touches a plugin-side `thread_local!` with a destructor arms the
/// plugin's `pthread_key` on that thread, and when that thread retires (libtest spawns and retires
/// one per test; Tokio does the same with blocking workers) `__nptl_deallocate_tsd` calls the
/// destructor inside the image validation just unmapped. That is the exact crash `ffi_thread`
/// exists to make impossible, and this admin-facing path — `GET /admin/plugins` inventory and the
/// upload vet — is reached per scrape, not once per boot.
///
/// The routed-unload COUNT is the assertion because the return value cannot see any of this: a
/// caller-thread unload validates just as successfully as a worker unload, right up until a thread
/// exits.
#[test]
fn validate_plugin_unloads_on_a_worker_not_the_callers_thread() {
    let Some(path) = json_lane_plugin_path() else {
        eprintln!("skip: the export sink cdylib is not built");
        return;
    };
    let before = UNLOADS_ON_WORKER.with(std::cell::Cell::get);
    validate_plugin(&path).expect("the JSON-lane fixture validates");
    let after = UNLOADS_ON_WORKER.with(std::cell::Cell::get);
    assert!(
        after > before,
        "validate_plugin unloaded the library WITHOUT routing it through dlclose_on_worker, so the \
         image's .fini_array ran on the caller's thread"
    );
}

// ── A failing open that still published a handle ────────────────────────────────────────────────

/// What the stub `busbar_close` below saw. A process-global because a `CloseFn` is a bare `extern`
/// fn pointer with no captured state, exactly like the real ABI's.
mod failed_open_reclaim {
    use std::os::raw::c_void;
    use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
    use std::sync::{Mutex, MutexGuard};

    pub static CLOSED_WITH: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
    pub static CLOSE_CALLS: AtomicUsize = AtomicUsize::new(0);

    /// The three tests below share the process-global counters above (see the doc comment on this
    /// module: a `CloseFn` is a bare `extern` fn pointer with no captured state, so the stubs have
    /// nowhere else to record what they saw). `cargo test` runs tests from the same binary
    /// concurrently on separate threads by default, so without serializing access here, one test's
    /// `reset()` or `fetch_add` can interleave with another's read, corrupting counts that look
    /// like a production double-close but are actually a test race. Every test below must hold this
    /// lock for its full body, from `reset()` through its final assertion.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    pub fn lock() -> MutexGuard<'static, ()> {
        TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// A plugin `busbar_close` that records the handle it was handed.
    pub unsafe extern "C-unwind" fn record(handle: *mut c_void) {
        CLOSED_WITH.store(handle, Ordering::SeqCst);
        CLOSE_CALLS.fetch_add(1, Ordering::SeqCst);
    }

    /// A plugin `busbar_close` that panics — a bad destructor across the ABI.
    pub unsafe extern "C-unwind" fn explode(_handle: *mut c_void) {
        CLOSE_CALLS.fetch_add(1, Ordering::SeqCst);
        panic!("a plugin destructor went wrong");
    }

    pub fn reset() {
        CLOSED_WITH.store(std::ptr::null_mut(), Ordering::SeqCst);
        CLOSE_CALLS.store(0, Ordering::SeqCst);
    }
}

/// A non-SDK plugin may publish a handle AND answer a failure status — nothing in the ABI forbids
/// it. The load still fails closed, but the instance it constructed must be reclaimed rather than
/// left running with nobody holding it.
#[test]
fn a_failed_open_that_published_a_handle_still_closes_the_instance() {
    use failed_open_reclaim as stub;
    let _guard = stub::lock();
    stub::reset();
    let handle = &mut 7u8 as *mut u8 as *mut std::os::raw::c_void;

    assert!(
        reclaim_failed_open(stub::record, "acme-store-plugin", handle),
        "a published handle is reclaimed"
    );
    assert_eq!(
        stub::CLOSE_CALLS.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "closed exactly once"
    );
    assert_eq!(
        stub::CLOSED_WITH.load(std::sync::atomic::Ordering::SeqCst),
        handle,
        "closed the handle the plugin published, not some other pointer"
    );
}

/// The well-behaved failure — no handle published — hands `close` nothing. Asking a plugin to free
/// what it never allocated is its own bug.
#[test]
fn a_failed_open_with_no_handle_closes_nothing() {
    use failed_open_reclaim as stub;
    let _guard = stub::lock();
    stub::reset();
    assert!(!reclaim_failed_open(
        stub::record,
        "acme-store-plugin",
        std::ptr::null_mut()
    ));
    assert_eq!(
        stub::CLOSE_CALLS.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}

/// A `close` that panics while reclaiming is contained the same way every other crossing is: the
/// handle leaks, the engine lives, and the load still returns its own error.
#[test]
fn a_panicking_close_during_reclaim_does_not_take_the_engine_down() {
    use failed_open_reclaim as stub;
    let _guard = stub::lock();
    stub::reset();
    let handle = &mut 9u8 as *mut u8 as *mut std::os::raw::c_void;
    assert!(reclaim_failed_open(
        stub::explode,
        "acme-store-plugin",
        handle
    ));
    assert_eq!(
        stub::CLOSE_CALLS.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "it was attempted"
    );
}

#[path = "ffi_guard_tests.rs"]
mod ffi_guard_tests;
#[path = "store_adapter_migration_tests.rs"]
mod store_adapter_migration_tests;
#[path = "store_adapter_tests.rs"]
mod store_adapter_tests;
