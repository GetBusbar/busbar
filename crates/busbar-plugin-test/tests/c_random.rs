// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-RANDOM (ABI-MIN3-INTERFACE §14): the host's `random`. The length bounds of its body are W1-H0's (merged).
//! The compile-fail bounds of the safe `Host::random::<N>` and the failing-backend arm (the facade's test-support
//! stub: `random` returns `Err(Rng)` and the arena holds no zero-filled result) need A2's safe API and `HOST`, so
//! they are W1-A2's, not H0's (W1-H0 handoff, design hole 1). W1-A2 runs the safe layer over a vtable answering
//! what host_vt answers when `fill_checked` fails; the same run through host_vt over the stub backend
//! (busbar#262) is `the_arena_holds_no_zero_filled_result_through_host_vt`.
//!
//! WBS rule 10: each ignored arm waits for the task that lands the last piece it needs; that task writes the
//! arm's body and un-ignores it in its own MR (red first, then green). Arms of tasks merged before W1-T1 run now.

use std::path::Path;
use std::process::{Command, Output};

use busbar_plugin_abi::fail::{failed, Fail};
use busbar_plugin_abi::host::{crypto_status, CryptoErr, CryptoRet, Ctx, Host, HostExt, HostFns};
use busbar_plugin_abi::types::Status;

/// The probe: the edges 1 and 65,536 build; feature `zero` or `over` adds the out-of-range call.
const PROBE: &str = r#"use busbar_plugin_abi::host::{Host, HostExt, HostFns};
static HOST: Host = Host::new(0, HostFns {
    now: None, mono: None, random: None, crypto: None, log: None, log_level: None, grow: None,
    deployment: None, service: None,
});
fn main() {
    let _ = HOST.random::<1>();
    let _ = HOST.random::<65_536>();
    #[cfg(feature = "zero")]
    let _ = HOST.random::<0>();
    #[cfg(feature = "over")]
    let _ = HOST.random::<65_537>();
}
"#;

fn shown(o: &Output) -> String {
    format!(
        "{}\n--- stdout\n{}\n--- stderr\n{}",
        o.status,
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

/// `random::<0>` and `random::<65_537>` are compile errors (IF §5.1: the `const` assert in the body). A scratch
/// crate over this tree's busbar-plugin-abi (default features) is built offline with the workspace's lock, the
/// fips_gate.rs pattern; `cargo build`, not `check`, because the assert fires at monomorphisation.
#[test]
fn random_0_and_65_537_fail_to_compile() {
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("c-random-bounds");
    std::fs::create_dir_all(dir.join("src")).unwrap();
    let manifest = format!(
        "[package]\nname = \"c-random-bounds\"\nversion = \"0.0.0\"\nedition = \"2021\"\npublish = false\n\n\
         [dependencies]\nbusbar-plugin-abi = {{ path = '{}' }}\n\n[features]\nzero = []\nover = []\n\n[workspace]\n",
        here.join("../busbar-plugin-abi").display()
    );
    std::fs::write(dir.join("Cargo.toml"), manifest).unwrap();
    std::fs::copy(here.join("../../Cargo.lock"), dir.join("Cargo.lock")).unwrap();
    std::fs::write(dir.join("src/main.rs"), PROBE).unwrap();
    let build = |features: &[&str]| {
        Command::new(env!("CARGO"))
            .args(["build", "--offline", "--quiet", "--manifest-path"])
            .arg(dir.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(dir.join("target"))
            .args(features)
            .output()
            .expect("run cargo")
    };
    let edges = build(&[]);
    assert!(
        edges.status.success(),
        "random::<1> and random::<65_536> must build:\n{}",
        shown(&edges)
    );
    for feature in ["zero", "over"] {
        let out = build(&["--features", feature]);
        assert!(
            !out.status.success() && String::from_utf8_lossy(&out.stderr).contains("E0080"),
            "feature {feature}: an out-of-range N must fail to compile (E0080):\n{}",
            shown(&out)
        );
    }
}

/// What host_vt's `random` answers when the backend's `fill_checked` fails (a DRBG or self-test failure, §5.2):
/// RNG with `out` EMPTY.
extern "C" fn failed_fill(ctx: Ctx<'_>, _len: usize) -> CryptoRet<'_> {
    CryptoRet::empty(ctx, crypto_status::RNG)
}

static FAILING: Host = Host::new(
    0,
    HostFns {
        now: None,
        mono: None,
        random: Some(failed_fill),
        crypto: None,
        log: None,
        log_level: None,
        grow: None,
        deployment: None,
        service: None,
    },
);

#[test]
fn a_failing_backend_answers_err_rng_with_no_zero_filled_array() {
    assert_eq!(
        FAILING.random::<32>(),
        Err(CryptoErr::Rng),
        "never Ok([0; 32])"
    );
    assert_eq!(FAILING.random_vec(32), Err(CryptoErr::Rng));
    let mut buf = [0xA5u8; 32];
    assert_eq!(FAILING.random_into(&mut buf), Err(CryptoErr::Rng));
    assert_eq!(
        buf, [0; 32],
        "on Err the buffer is zeroed and holds nothing usable"
    );
    let fail = Fail::from(CryptoErr::Rng);
    assert_eq!(
        (fail.status(), fail.code()),
        (Status::FAILED, failed::F_UNAVAILABLE)
    );
}

/// The same failure produced by host_vt itself over the CRYPTO-SEAM stub (`BUSBAR_STUB_FILL=rng|crngt`, busbar#262;
/// the scratch build is `c_unavailable::stub_host_vt`): inside an entry, `random` answers RNG and lends nothing
/// (`out` EMPTY), the safe layer answers `Err(Rng)` from `random`, `random_vec` and `random_into` (whose buffer is
/// left zeroed, nothing usable), and the arena holds no zero-filled result: two HMAC outputs lent around the failed
/// `random(32)` in one scope sit back to back. The control run (`fill` filling) lends the stub's 32 bytes between
/// them, so the probe reaches the backend; outside an entry `random` answers RNG whatever the backend says.
#[test]
fn the_arena_holds_no_zero_filled_result_through_host_vt() {
    let (ok, rng) = (crypto_status::OK, crypto_status::RNG);
    for (fill, random, safe, into, buf, gap) in [
        ("", format!("{ok}/32"), "Ok(true)", "Ok(())", "5a", 32),
        ("rng", format!("{rng}/0"), "Err(Rng)", "Err(Rng)", "zero", 0),
        (
            "crngt",
            format!("{rng}/0"),
            "Err(Rng)",
            "Err(Rng)",
            "zero",
            0,
        ),
    ] {
        let got = crate::c_unavailable::stub_host_vt::probe("random", fill, "1000");
        let want = format!(
            "outside={rng}/0\n\
             random={random}\n\
             random32={safe}\n\
             random_vec={safe}\n\
             random_into={into} buf={buf}\n\
             arena_gap=Some({gap})\n\
             host_panic=0\n\
             entry=ran\n"
        );
        assert_eq!(got, want, "BUSBAR_STUB_FILL={fill:?}");
    }
    let fail = Fail::from(CryptoErr::Rng);
    assert_eq!(
        (fail.status(), fail.code()),
        (Status::FAILED, failed::F_UNAVAILABLE)
    );
}
