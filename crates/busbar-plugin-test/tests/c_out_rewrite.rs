// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-OUT-REWRITE (ABI-MIN3-INTERFACE §14): A plugin rewrites `out.ptr`/`cap`: the host keeps its own OutBuf
//! authority.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).
//!
//! W1-H1: only a C plugin can rewrite the raw channel, so the fixture is C, built from `busbar_plugin.h` alone
//! (busbar-plugin-abi/tests/c_header/out_rewrite.c) as a shared library, admitted through the loader's own
//! `admit` (as C-HEADER's admit arm admits fixture.c) and driven through busbar-ffi's safe host API with the real
//! `HOST` (its `grow` is the host's). What the authority means is IF §2 (`RawOut` "carries no authority: the host
//! keeps the real pointer, capacity and max_out in its own OutBuf and rewrites `ptr`/`cap` on `grow`") and §5
//! (`grow` "rewrites out.ptr/out.cap from host state"): the answer is read from the host's buffer, never through
//! the plugin's pointer; `grow` judges the host's max_out and buffer, never the plugin's `cap`; and a successful
//! `grow` hands the plugin the host's pointer and capacity back.

#[cfg(unix)]
use busbar_plugin_abi::secret::tag::VALUE;
#[cfg(unix)]
use busbar_plugin_abi::types::Status;

/// The fixture built from the header alone as a shared library for this host (its stamp's `target` is the host's
/// `<arch>-<os>-<env>`), with `$CC` (default `cc`) under `-std=c11 -Wall -Werror -shared -fPIC`; built once.
#[cfg(unix)]
fn fixture_library() -> &'static [u8] {
    static BYTES: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    BYTES.get_or_init(|| {
        let abi =
            std::path::PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../busbar-plugin-abi"));
        let target = busbar_plugin_abi::stamp::target_now();
        let end = target.iter().position(|&b| b == 0).unwrap_or(target.len());
        let target = std::str::from_utf8(&target[..end]).expect("an ASCII target");
        let out = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join("libbusbar_out_rewrite_c_fixture.so");
        let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
        let run = std::process::Command::new(&compiler)
            .args(["-std=c11", "-Wall", "-Werror", "-shared", "-fPIC", "-I"])
            .arg(abi.join("include"))
            .arg(format!("-DBB_FIXTURE_TARGET=\"{target}\""))
            .arg(abi.join("tests/c_header/out_rewrite.c"))
            .arg("-o")
            .arg(&out)
            .output()
            .unwrap_or_else(|e| {
                panic!("C-OUT-REWRITE needs a C compiler ({compiler:?}, set CC): {e}")
            });
        assert!(
            run.status.success(),
            "{compiler:?} -shared -fPIC out_rewrite.c failed:\n{}{}",
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&run.stderr)
        );
        std::fs::read(&out).expect("the fixture library")
    })
}

/// Admits the fixture, opens an instance and resolves `{"name":"<name>"}` on a 4 KiB lease with max_out 1 MiB
/// (the fixture's FIXTURE_MAX_OUT): the final status and the answer's records as the host's buffer holds them.
#[cfg(unix)]
fn resolve(name: &str) -> (Status, Vec<(u16, Vec<u8>)>) {
    use busbar_plugin_abi::host_side::HOST;
    use busbar_plugin_abi::plugin::__rt::host::{ChainBufs, OpenAnswer, OutLease, Started};
    use busbar_plugin_abi::plugin::__rt::kind as marker;
    use busbar_plugin_abi::records::Records;
    use busbar_plugin_loader::test_native::{admit_bytes, test_manifest};

    let lease = || OutLease::new(vec![0; 4096], 1 << 20).expect("a free ACTIVE slot");
    let bytes = fixture_library();
    let manifest = test_manifest(bytes, &["out-rewrite-c"]).expect("the fixture's own stamp scans");
    let admitted = admit_bytes(bytes, &manifest, "busbar-out-rewrite-c-fixture")
        .unwrap_or_else(|r| panic!("{r}"));
    let mut out = lease();
    let OpenAnswer::Done(Status::OK, Some(inst)) =
        admitted
            .plugin()
            .open::<marker::Secret>(&HOST, b"{}".to_vec(), 0, &mut out)
    else {
        panic!("open answers OK with INSTANCE");
    };
    drop(out);

    let mut out = lease();
    let mut bufs = ChainBufs::new();
    let at = bufs.push(format!("{{\"name\":\"{name}\"}}").into_bytes());
    let status = match inst.start(
        busbar_plugin_abi::secret::slot::resolve,
        bufs,
        |bufs, cross| busbar_plugin_abi::secret::pack::resolve(0, bufs.get(at), cross),
        &mut out,
    ) {
        Started::Done(status) => status,
        Started::Need(_) => panic!("the C fixture never NEEDs"),
    };
    let records = out.with_answer(|bytes| {
        Records::new(bytes)
            .map(|rec| match rec {
                Ok(rec) => (rec.tag, rec.body.to_vec()),
                Err(e) => panic!("the answer is not framed: {e:?}"),
            })
            .collect()
    });
    (status, records)
}

/// The two clauses that hold on the branch: the answer comes from the host's buffer, and `grow` ignores the
/// plugin's `cap`. The third (a successful `grow` restores the host's ptr/cap) is the ignored arm's.
#[test]
#[cfg(unix)]
fn a_rewritten_out_ptr_or_cap_never_reaches_the_answer() {
    let (status, answer) = resolve("ptr");
    assert_eq!(status, Status::OK);
    assert_eq!(
        answer,
        [(VALUE, b"kept".to_vec())],
        "the host reads the answer from its own buffer, never through the plugin's pointer"
    );

    let (status, answer) = resolve("cap");
    assert_eq!(status, Status::OK);
    assert_eq!(
        answer,
        [(VALUE, vec![0, 1])],
        "grow refuses past the host's max_out under a cap of SIZE_MAX, and grants what the host buffer holds"
    );
}

#[test]
#[cfg(unix)]
#[ignore = "blocked: busbar-ffi host::grow answers true without rewriting out.ptr/out.cap when the ACTIVE buffer \
            already holds len + need (crates/busbar-ffi/src/host.rs:214-216, the `want <= top.buf.len()` branch), \
            against IF §5 grow \"rewrites out.ptr/out.cap from host state\"; the fix (repoint before that return) is \
            in owner-pinned busbar-ffi (CODEOWNERS), not this lane; re-checked 2026-11-16"]
fn a_rewritten_out_ptr_or_cap_is_ignored() {
    let (status, answer) = resolve("ptr");
    assert_eq!(status, Status::OK);
    assert_eq!(answer, [(VALUE, b"kept".to_vec())]);

    let (status, answer) = resolve("cap");
    assert_eq!(status, Status::OK);
    assert_eq!(answer, [(VALUE, vec![0, 1])]);

    let (status, answer) = resolve("regrow");
    assert_eq!(status, Status::OK);
    assert_eq!(
        answer,
        [(VALUE, vec![1, 1, 1])],
        "grow answers true and hands back the host's pointer and capacity over the plugin's rewrite"
    );
}
