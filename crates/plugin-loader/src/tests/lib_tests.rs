// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/plugin-loader/src/lib.rs`.

use super::*;
use busbar_contract::abi::cold::TRANSPORT_VERSION;

/// The 1.5.5 store payload schema (v2). No loaded plugin states it since THE DESIGN §11.8 (the
/// registry refuses it at boot, ruling C21/ABI-o1); the store adapter's shim suites bind an adapter
/// at it to pin the schema-keyed shim rule.
const PUBLISHED_STORE_SCHEMA: u32 = 2;

/// The REAL plugin the loader-MECHANISM tests below dlopen (validation, inventory): the example
/// plane's `cdylib` (`export_plane!`), which answers the frozen handshake symbols
/// [`validate_plugin`] reads (HOT-lane residue). Under CI a missing cdylib is a hard failure
/// ([`super::both_ways::cdylib`] asserts it), never a silent skip.
fn handshake_plugin_path() -> Option<std::path::PathBuf> {
    super::both_ways::cdylib("busbar_plugin_example_plane")
}

/// `validate_plugin` accepts the real handshake fixture cdylib (transport version 1) without constructing an
/// instance, and `inventory` finds it in a plugins directory as valid.
///
/// The directory is a fresh one holding a copy of the fixture, not the fixture's own directory: the
/// in-tree fixture lives in cargo's profile dir (or its `deps/`), where `inventory` would dlopen
/// every proc-macro and dependency dylib cargo put there.
#[test]
fn validate_and_inventory() {
    let Some(path) = handshake_plugin_path() else {
        eprintln!("skip: the example plane cdylib is not built");
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
        .expect("the handshake fixture in inventory");
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
    let Some(real_plugin) = handshake_plugin_path() else {
        eprintln!("skip: the example plane cdylib is not built");
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

/// NO LEGACY LOADING at the loader-mechanism paths (THE DESIGN §11.8, ruling C21/ABI-o1): a library
/// with no `busbar_plugin_door` that states a JSON-contract kind by its `busbar_plugin_kind` symbol
/// alone is a 1.5.5-era plugin. The symbol only CLASSIFIES it: the upload vet refuses it and the
/// plugins inventory lists it invalid, each naming the missing door and the rebuild. (No JSON-lane
/// kind gate is left to admit it: a library loads only through its door.)
///
/// RED against a loader that takes a kind symbol on its word: every handshake and kind check
/// passes, so the vet answers `Ok` and the inventory lists it valid.
#[test]
fn a_door_less_json_contract_library_is_refused_naming_the_rebuild() {
    let Some(path) = super::both_ways::example_cdylib("json_contract_auth") else {
        eprintln!("skip: the json_contract_auth example cdylib is not built");
        return;
    };
    let names_the_rebuild = |why: &str| {
        assert!(
            why.contains("busbar_plugin_door"),
            "names the missing door: {why}"
        );
        assert!(why.contains("'auth'"), "names the kind it states: {why}");
        assert!(
            why.contains(crate::dispatch::load::REBUILD),
            "names the rebuild: {why}"
        );
    };

    // The upload vet.
    let vet = validate_plugin(&path).expect_err("the upload vet refuses a door-less library");
    names_the_rebuild(&vet);

    // The plugins inventory.
    let file = path.file_name().unwrap().to_owned();
    let dir = std::env::temp_dir().join(format!(
        "busbar-inventory-json-contract-{}-{}",
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
    let listed = inv
        .iter()
        .find(|p| std::ffi::OsStr::new(&p.file) == file)
        .expect("the door-less library is listed");
    assert!(!listed.valid, "listed invalid: {listed:?}");
    assert_eq!(listed.abi_version, None, "{listed:?}");
    names_the_rebuild(listed.error.as_deref().expect("listed with its refusal"));
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
    let Some(path) = handshake_plugin_path() else {
        eprintln!("skip: the example plane cdylib is not built");
        return;
    };
    let before = UNLOADS_ON_WORKER.with(std::cell::Cell::get);
    validate_plugin(&path).expect("the handshake fixture validates");
    let after = UNLOADS_ON_WORKER.with(std::cell::Cell::get);
    assert!(
        after > before,
        "validate_plugin unloaded the library WITHOUT routing it through dlclose_on_worker, so the \
         image's .fini_array ran on the caller's thread"
    );
}

#[path = "ffi_guard_tests.rs"]
mod ffi_guard_tests;
#[path = "store_adapter_tests.rs"]
mod store_adapter_tests;
