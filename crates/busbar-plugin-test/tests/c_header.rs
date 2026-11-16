// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-HEADER (ABI-MIN3-INTERFACE §14): The C header: static asserts, the C fixture's admit arm, the arena arm and
//! the full-table nested arm (rounds 11, 20, 22). The secret-c arm runs in its repo.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

// W1-A13: the generator, the compiler step, the C fixture, its C host and the cc job script live with the header
// (busbar-plugin-abi/tests/c_header/); the cc job runs these arms on every CI target with its own CC.
#[path = "../../busbar-plugin-abi/tests/c_header/asserts.rs"]
mod asserts;
#[path = "../../busbar-plugin-abi/tests/c_header/cc.rs"]
pub(crate) mod cc;

/// One `_Static_assert` per size, alignment, offset and constant, read from the Rust items, compiles with the
/// header under `cc -std=c11 -Wall -Werror`; so does the C fixture, built from the header alone.
#[test]
fn the_static_asserts_compile_with_the_header() {
    let file = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("c_header_asserts.c");
    std::fs::write(&file, asserts::generate()).expect("the assert file is written");
    cc::cc(
        "c_header_asserts.o",
        &[file.to_str().expect("a UTF-8 path")],
        false,
    );
    cc::cc("c_header_fixture.o", &["fixture.c"], false);
}

/// The C fixture built from the header alone as a shared library for this host (its stamp's `target` is the
/// host's `<arch>-<os>-<env>`), with the same compiler and flags as `cc`, plus `-shared -fPIC`.
#[cfg(unix)]
fn fixture_library() -> std::path::PathBuf {
    let abi =
        std::path::PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../busbar-plugin-abi"));
    let target = busbar_plugin_abi::stamp::target_now();
    let end = target.iter().position(|&b| b == 0).unwrap_or(target.len());
    let target = std::str::from_utf8(&target[..end]).expect("an ASCII target");
    let out =
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("libbusbar_secret_c_fixture.so");
    let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
    let run = std::process::Command::new(&compiler)
        .args(["-std=c11", "-Wall", "-Werror", "-shared", "-fPIC", "-I"])
        .arg(abi.join("include"))
        .arg(format!("-DBB_FIXTURE_TARGET=\"{target}\""))
        .arg(abi.join("tests/c_header/fixture.c"))
        .arg("-o")
        .arg(&out)
        .output()
        .unwrap_or_else(|e| panic!("C-HEADER needs a C compiler ({compiler:?}, set CC): {e}"));
    assert!(
        run.status.success(),
        "{compiler:?} -shared -fPIC fixture.c failed:\n{}{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    out
}

/// W1-L1, the admit arm: the C fixture, built from the header alone, is admitted as a dropped-in secret plugin
/// through the loader's own `admit` (signed, staged and opened as production does) on the default backend with no
/// operator setting of any kind: its stamp `crypto = "external"` passes on `busbar_crypto::EXTERNAL_PLUGINS`
/// alone. The same bytes again answer the resident image; a manifest whose former names are not the header's is
/// refused `DoorStampMismatch`.
#[test]
#[cfg(unix)]
fn the_c_fixture_is_admitted_as_a_dropped_in_secret_plugin() {
    use busbar_plugin_abi::types::KindCode;
    use busbar_plugin_loader::refusal::RefusalCode;
    use busbar_plugin_loader::test_host::{admit_bytes, test_manifest};

    assert!(
        busbar_contract::crypto::EXTERNAL_PLUGINS,
        "the default backend admits external plugins"
    );
    let bytes = std::fs::read(fixture_library()).expect("the fixture library");
    let manifest = test_manifest(&bytes, &["secret-c"]).expect("the fixture's own stamp scans");
    let admitted = admit_bytes(&bytes, &manifest).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(admitted.identity(), "busbar-secret-c-fixture");
    assert_eq!(admitted.kind(), KindCode::Secret);
    assert_eq!(&admitted.stamp.crypto, b"external");
    assert!(admitted.sha256().is_some(), "a dropped-in image");

    let again = admit_bytes(&bytes, &manifest).unwrap_or_else(|r| panic!("{r}"));
    assert!(
        std::sync::Arc::ptr_eq(&admitted.image, &again.image),
        "identical bytes answer the resident image"
    );

    let renamed = test_manifest(&bytes, &["secret-d"]).expect("scans");
    let refused = admit_bytes(&bytes, &renamed).expect_err("the header states secret-c");
    assert_eq!(
        (refused.code, refused.field),
        (RefusalCode::DoorStampMismatch, "former_names")
    );
}

/// The drive half of the admit arm (describe with D_REF_SCHEMA, open, resolve, `bb_fail` zeroing, cancel, close,
/// `module: secret-c`) runs through `Registry::add`/`open_secret` and the H1 driver: owned by W1-L2, the last of
/// its contributors (WBS rule 10).
#[test]
#[ignore = "owner: W1-L2"]
fn the_c_fixture_admits_and_runs_every_entry() {
    todo!("owner: W1-L2 (C-HEADER: the registry and driver drive the admitted fixture)")
}

#[test]
#[ignore = "owner: W1-H1"]
fn arena_outputs_never_overlap_and_are_zero_after_the_entry() {
    todo!("owner: W1-H1 (C-HEADER)")
}

#[test]
#[ignore = "owner: W1-H1"]
fn the_full_table_nested_arm() {
    todo!("owner: W1-H1 (C-HEADER)")
}
