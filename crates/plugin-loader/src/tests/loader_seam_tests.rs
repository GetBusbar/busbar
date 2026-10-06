// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The loader's own crossings, pinned against in-test fakes rather than a built fixture: the bounded
//! `busbar_plugin_kind()` read, and what the panic guard can — and measurably cannot — catch.

use crate::{kind_from_ptr, MAX_PLUGIN_KIND_LEN};

// ── The kind string: the one plugin buffer with no length ─────────────────────────────────────

/// A well-formed kind reads back as itself.
#[test]
fn a_nul_terminated_kind_reads_back() {
    // SAFETY: a NUL-terminated literal.
    assert_eq!(
        unsafe { kind_from_ptr(c"store".as_ptr().cast(), "k") }.as_deref(),
        Ok("store")
    );
}

/// A kind with no NUL inside the cap is refused, never walked until some zero byte turns up.
///
/// The buffer below DOES end in a NUL (so the phase-start reader, an unbounded `CStr::from_ptr`,
/// can run it without undefined behaviour and accepts a 64-byte "kind"); the bounded reader must
/// refuse it having read no more than the cap.
#[test]
fn a_kind_with_no_nul_inside_the_cap_is_refused() {
    let mut long = vec![b'a'; 64];
    long.push(0);
    // SAFETY: `long` is NUL-terminated, so every read either reader makes is in bounds.
    let got = unsafe { kind_from_ptr(long.as_ptr(), "k") };
    assert!(
        got.as_ref().is_err_and(|e| e.contains("no NUL terminator")),
        "a 64-byte kind must be refused, got {got:?}"
    );
}

/// The cap is exact: `MAX_PLUGIN_KIND_LEN` bytes load, one more does not.
#[test]
fn the_kind_cap_is_exact() {
    let at_cap: Vec<u8> = std::iter::repeat_n(b'k', MAX_PLUGIN_KIND_LEN)
        .chain([0])
        .collect();
    let over: Vec<u8> = std::iter::repeat_n(b'k', MAX_PLUGIN_KIND_LEN + 1)
        .chain([0])
        .collect();
    // SAFETY: both are NUL-terminated.
    unsafe {
        assert!(kind_from_ptr(at_cap.as_ptr(), "k").is_ok());
        assert!(kind_from_ptr(over.as_ptr(), "k").is_err());
        assert!(kind_from_ptr(std::ptr::null(), "k").is_err());
    }
}

// ── What the panic guard can catch ────────────────────────────────────────────────────────────

/// The env var that turns [`foreign_panic_child`] from a no-op into the child half of
/// [`a_dlopened_plugins_own_panic_aborts_rather_than_reaching_ffi_guard`].
const FOREIGN_PANIC_LIB: &str = "BUSBAR_TEST_FOREIGN_PANIC_LIB";

/// A panic raised by THIS process's runtime and unwound through an `extern "C-unwind"` fn pointer is
/// caught and becomes `Err` — the half of `ffi_guard`'s contract that does hold.
#[test]
fn ffi_guard_catches_a_panic_from_this_runtime() {
    extern "C-unwind" fn boom() -> i32 {
        panic!("same-runtime panic")
    }
    let f: extern "C-unwind" fn() -> i32 = boom;
    assert!(crate::ffi_guard("same-runtime", "call", || f()).is_err());
}

/// THE MEASUREMENT behind `ffi_guard`'s doc. A cdylib with its own copy of std panics out of an
/// `extern "C-unwind"` export (no SDK catch in the way) and the host calls it through `ffi_guard`.
/// The guard does not return: the host runtime sees a foreign exception and the process ABORTS. It
/// runs in a child process because the outcome being asserted is the death of the process.
#[test]
fn a_dlopened_plugins_own_panic_aborts_rather_than_reaching_ffi_guard() {
    let dir = std::env::temp_dir().join(format!("busbar-foreign-panic-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("boom.rs");
    std::fs::write(
        &src,
        "#[no_mangle]\npub extern \"C-unwind\" fn boom() -> i32 { panic!(\"plugin-side panic\") }\n",
    )
    .unwrap();
    let lib = dir.join(format!(
        "{}boom{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    ));
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let built = std::process::Command::new(rustc)
        .args(["--edition", "2021", "--crate-type", "cdylib", "-o"])
        .arg(&lib)
        .arg(&src)
        .output()
        .expect("rustc is on PATH wherever `cargo test` runs");
    assert!(
        built.status.success(),
        "building the foreign-runtime fixture failed: {}",
        String::from_utf8_lossy(&built.stderr)
    );

    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "loader_seam_tests::foreign_panic_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(FOREIGN_PANIC_LIB, &lib)
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let stdout = String::from_utf8_lossy(&child.stdout);
    let stderr = String::from_utf8_lossy(&child.stderr);
    assert!(
        stdout.contains("CHILD-REACHED-THE-CALL"),
        "the child never reached the crossing; stdout: {stdout} stderr: {stderr}"
    );
    assert!(
        !stdout.contains("FFI-GUARD-RETURNED"),
        "ffi_guard RETURNED for a dlopened plugin's own panic — the runtime now catches foreign \
         Rust panics, and ffi_guard's doc (which says it cannot) is wrong: stdout: {stdout}"
    );
    assert!(
        !child.status.success(),
        "the child must die: {:?}",
        child.status
    );
    #[cfg(unix)]
    assert!(
        stderr.contains("cannot catch foreign exceptions"),
        "the abort must be the foreign-exception abort, stderr: {stderr}"
    );
}

/// Child half of the test above. Ignored so it runs only when the parent asks for it by name.
#[test]
#[ignore = "child process of a_dlopened_plugins_own_panic_aborts_rather_than_reaching_ffi_guard"]
fn foreign_panic_child() {
    let Some(path) = std::env::var_os(FOREIGN_PANIC_LIB) else {
        return;
    };
    // SAFETY: the fixture the parent just built; `boom` has exactly this signature.
    let lib = unsafe { libloading::Library::new(&path) }.expect("load the foreign-runtime fixture");
    let boom = unsafe { lib.get::<extern "C-unwind" fn() -> i32>(b"boom\0") }.expect("boom");
    println!("CHILD-REACHED-THE-CALL");
    let got = crate::ffi_guard("foreign", "call", || boom());
    println!("FFI-GUARD-RETURNED {:?}", got.is_err());
}
