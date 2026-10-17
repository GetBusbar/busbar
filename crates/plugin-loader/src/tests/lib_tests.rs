// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/plugin-loader/src/lib.rs`.

use super::*;

/// The 1.5.5 store payload schema (v2). No loaded plugin states it since THE DESIGN §11.8 (the
/// registry refuses it at boot, ruling C21/ABI-o1); the store adapter's shim suites bind an adapter
/// at it to pin the schema-keyed shim rule.
const PUBLISHED_STORE_SCHEMA: u32 = 2;

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
/// (so it must return real filenames even for a garbage/non-plugin library file no loader would
/// take).
#[test]
fn list_plugin_files_filters_to_libraries_only_and_sorts() {
    let dir = std::env::temp_dir().join(format!(
        "busbar-list-plugin-files-{}-{}",
        std::process::id(),
        {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            format!(
                "{}-{}-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos()),
                line!(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            )
        }
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
    let dir = std::env::temp_dir().join(format!("busbar-libext-case-{}-{}", std::process::id(), {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        format!(
            "{}-{}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos()),
            line!(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        )
    }));
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

#[path = "ffi_guard_tests.rs"]
mod ffi_guard_tests;
#[path = "no_silent_skip_tests.rs"]
mod no_silent_skip_tests;
#[path = "store_adapter_tests.rs"]
mod store_adapter_tests;
