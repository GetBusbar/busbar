// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-HEADER's compiler step (ABI-MIN3-INTERFACE §7.8, §14; owner W1-A13). The case files of
//! busbar-plugin-test pull this in with `#[path]`; the C sources sit beside it and the cc job (`cc.sh`) runs
//! the same arms on every CI target with its own `CC`.

use std::path::PathBuf;
use std::process::Command;

/// Runs `$CC` (default `cc`) as `-std=c11 -Wall -Werror` with `busbar-plugin-abi/include` on the include path
/// over `sources`, each either a file name in this directory or an absolute path, and writes `out` under the
/// test target's scratch directory: an object with `link` false, else an executable. A compiler warning or
/// error fails the calling test with the compiler's own output.
pub fn cc(out: &str, sources: &[&str], link: bool) -> PathBuf {
    let abi = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../busbar-plugin-abi"));
    let here = abi.join("tests/c_header");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(out);
    let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
    let mut cmd = Command::new(&compiler);
    cmd.args(["-std=c11", "-Wall", "-Werror", "-I"])
        .arg(abi.join("include"));
    if !link {
        cmd.arg("-c");
    }
    for source in sources {
        cmd.arg(here.join(source));
    }
    let run = cmd
        .arg("-o")
        .arg(&out)
        .output()
        .unwrap_or_else(|e| panic!("C-HEADER needs a C compiler ({compiler:?}, set CC): {e}"));
    assert!(
        run.status.success(),
        "{compiler:?} -std=c11 -Wall -Werror failed on {sources:?}:\n{}{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    out
}
