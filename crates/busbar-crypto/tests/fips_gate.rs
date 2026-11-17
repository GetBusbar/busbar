// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-FIPS-GATE, the facade arm (IF §5.2 round 13, §14 C-UNAVAILABLE; WBS W0-H0B), and the round-21
//! `fill_checked` arm on a stub backend (IF §5.2, §17 round-21 assignments).
//!
//! The facade's own source is built against `fixtures/fips_gate/backend.rs`, a deny-list stub in the
//! CRYPTO-SEAM style, in a scratch workspace under this target's tmp dir. The scratch manifest names
//! the stub as the facade's `busbar-crypto-backend` by path: the swap a private build makes with
//! `[patch]`, without the git source a `[patch]` must resolve (the build runs offline). Asserted:
//! - the stub as written (`API = 3`, `EXTERNAL_PLUGINS = false`) builds;
//! - the same stub keeping `API = 1`, or not defining `EXTERNAL_PLUGINS`, fails to compile at the
//!   facade's contract block, so a backend that never heard of the gate cannot admit by omission;
//! - the same stub not defining `VALIDATION` (feature `missing`) fails to compile with the error
//!   located in src/contract.rs (DES crypto-seam r3 §3), and linked, the facade's
//!   `validated_mode` is false because the stub states no validation (ADMIN-API-1.6-ONE-MODEL §10.1:
//!   derived from `VALIDATION.is_some()` alone, never from the backend's name);
//! - linked, the facade states the stub's `EXTERNAL_PLUGINS`, `supports("EXTERNAL_PLUGINS")` answers
//!   from that const (the stub's own `supports` says true for it), and `fill_checked` forwards the
//!   backend's `SelfTest`/`Rng` while `fill` keeps answering `RngError`;
//! - with the facade's `conformance` feature alone, the suite builds over the stub, a refused optional
//!   site stays in the process-global `conformance::refusals()` after its check panics, and
//!   `conformance::CONTRACT_PIN` is ci/crypto-api.pin's last line, verbatim (DES-3 sign-off).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn here() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// Writes the scratch workspace (the facade's source over the stub) and returns its directory.
fn workspace() -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("fips-gate");
    let backend = dir.join("backend");
    std::fs::create_dir_all(&backend).unwrap();
    let fixtures = here().join("fixtures/fips_gate");
    let facade = format!(
        r#"[package]
name = "busbar-crypto"
version = "1.6.0"
edition = "2021"
publish = false
autobins = false
autoexamples = false
autotests = false
autobenches = false

[lib]
path = '{lib}'

[[bin]]
name = "probe"
path = '{probe}'

[dependencies]
busbar-crypto-backend = {{ path = "backend" }}
zeroize = {{ version = "1", default-features = false }}

[features]
tls = []
test-support = []
api1 = ["busbar-crypto-backend/api1"]
api2 = ["busbar-crypto-backend/api2"]
silent = ["busbar-crypto-backend/silent"]
missing = ["busbar-crypto-backend/missing"]
conformance = []

[workspace]
"#,
        lib = here().join("src/lib.rs").display(),
        probe = fixtures.join("probe.rs").display(),
    );
    let stub = format!(
        r#"[package]
name = "busbar-crypto-backend"
version = "0.0.0-stub"
edition = "2021"
publish = false
autobins = false
autoexamples = false
autotests = false
autobenches = false

[lib]
path = '{lib}'

[features]
api1 = []
api2 = []
silent = []
missing = []
"#,
        lib = fixtures.join("backend.rs").display(),
    );
    std::fs::write(dir.join("Cargo.toml"), facade).unwrap();
    std::fs::write(backend.join("Cargo.toml"), stub).unwrap();
    dir
}

/// `cargo <args>` on the scratch workspace, offline, with the stub's `fill` answering `fill`.
fn cargo(dir: &Path, args: &[&str], fill: &str) -> Output {
    Command::new(env!("CARGO"))
        .args(args)
        .args(["--offline", "--quiet", "--manifest-path"])
        .arg(dir.join("Cargo.toml"))
        .arg("--target-dir")
        .arg(dir.join("target"))
        .env("BUSBAR_STUB_FILL", fill)
        .output()
        .expect("run cargo")
}

fn shown(o: &Output) -> String {
    format!(
        "{}\n--- stdout\n{}\n--- stderr\n{}",
        o.status,
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn fails_with(o: &Output, needle: &str) -> bool {
    !o.status.success() && String::from_utf8_lossy(&o.stderr).contains(needle)
}

/// Whether `o` failed with an error that names `item` and whose location (the `-->` line under it)
/// is in `file`: the refusal comes from that file, not merely from some file naming the item.
fn fails_in(o: &Output, file: &str, item: &str) -> bool {
    if o.status.success() {
        return false;
    }
    let mut naming = false;
    for line in String::from_utf8_lossy(&o.stderr).lines() {
        if line.starts_with("error") {
            naming = line.contains(item);
        } else if let Some(at) = line.trim_start().strip_prefix("--> ") {
            // `<path>:<line>:<col>`
            let path = at.rsplitn(3, ':').nth(2).unwrap_or(at);
            if naming && path.ends_with(file) {
                return true;
            }
            naming = false;
        }
    }
    false
}

/// The 1.6.0 contract's refusal of any other API (ADMIN-API-1.6-ONE-MODEL CA-17).
const API_REFUSAL: &str = "busbar-crypto-backend API must be 3 (the 1.6.0 contract: VALIDATION and the checked operations); update the backend";

#[test]
fn c_fips_gate_and_fill_checked_on_a_stub_backend() {
    let dir = workspace();

    let control = cargo(&dir, &["check"], "");
    assert!(
        control.status.success(),
        "the deny-list stub as written (API = 3, EXTERNAL_PLUGINS = false) must build:\n{}",
        shown(&control)
    );

    let stale = cargo(&dir, &["check", "--features", "api1"], "");
    assert!(
        fails_with(&stale, API_REFUSAL),
        "a backend that keeps API = 1 must fail to compile at the contract block:\n{}",
        shown(&stale)
    );

    let stale_api2 = cargo(&dir, &["check", "--features", "api2"], "");
    assert!(
        fails_with(&stale_api2, API_REFUSAL),
        "a backend that keeps API = 2 must fail to compile at the contract block:\n{}",
        shown(&stale_api2)
    );

    let silent = cargo(&dir, &["check", "--features", "silent"], "");
    assert!(
        fails_with(&silent, "EXTERNAL_PLUGINS"),
        "a backend that does not define EXTERNAL_PLUGINS must fail to compile:\n{}",
        shown(&silent)
    );

    // `VALIDATION` is required by contract.rs itself: the error must be located there, not only in a
    // facade file that happens to read it.
    let missing = cargo(&dir, &["check", "--features", "missing"], "");
    assert!(
        fails_in(&missing, "src/contract.rs", "VALIDATION"),
        "a backend that does not state VALIDATION must fail to compile at src/contract.rs:\n{}",
        shown(&missing)
    );

    let probe = |checked: &str| {
        format!(
            "fill_checked={checked}\nfill=Err(RngError)\nexternal_plugins=false\n\
             supports_external_plugins=false\nsupports_md5=false\nbackend=stub\nchecked_hash=Err(Provider(ProviderUnavailable))\n\
             validation=None\nvalidated_mode=false\n"
        )
    };
    for (fill, checked) in [
        ("crngt", r#"Err(SelfTest("crngt"))"#),
        ("rng", "Err(Rng(RngError))"),
    ] {
        let run = cargo(&dir, &["run", "--bin", "probe"], fill);
        let want = probe(checked);
        assert!(
            run.status.success() && String::from_utf8_lossy(&run.stdout) == want,
            "BUSBAR_STUB_FILL={fill}: want\n{want}got\n{}",
            shown(&run)
        );
    }

    // The conformance suite builds with `conformance` alone (no tls, no test-support on the backend).
    // Run one check that refuses an optional site (SHA-1, site 5) and then fails: the refusal stays in
    // the process-global counter, as it does when a harness runs each check as its own test. The
    // facade states the pin line verbatim.
    let pin = std::fs::read_to_string(here().join("../../ci/crypto-api.pin"))
        .expect("ci/crypto-api.pin is readable");
    let pin_line = pin
        .lines()
        .rfind(|l| !l.trim().is_empty())
        .expect("ci/crypto-api.pin records a contract");
    let run = cargo(
        &dir,
        &["run", "--bin", "probe", "--features", "conformance"],
        "rng",
    );
    let want = format!(
        "{}refusals=[5]\ncontract_pin={pin_line}\n",
        probe("Err(Rng(RngError))")
    );
    assert!(
        run.status.success() && String::from_utf8_lossy(&run.stdout) == want,
        "conformance over the stub: want\n{want}got\n{}",
        shown(&run)
    );
}
