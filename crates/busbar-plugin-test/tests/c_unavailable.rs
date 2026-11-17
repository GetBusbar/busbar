// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-UNAVAILABLE (ABI-MIN3-INTERFACE §14): The facade's test-support stub backend: unsupported algs,
//! `EXTERNAL_PLUGINS`, stamp crypto; C-FIPS-GATE's admit arm (round 13). C-FIPS-GATE's facade build arm is
//! W0-H0B's contract test. W1-A2 runs the safe layer over a vtable answering what host_vt answers for an alg the
//! backend's `supports` refuses (UNAVAILABLE, `Error::Unsupported`); the run through host_vt itself over the stub
//! backend (busbar#262) is `unsupported_algs_through_host_vt_on_the_stub_backend`, on the scratch build in
//! [`stub_host_vt`], which C-RANDOM and C-CRYPTO-SELFTEST share.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

use busbar_plugin_abi::fail::{refused, Fail};
use busbar_plugin_abi::host::{
    alg, crypto_status, CryptoErr, CryptoReq, CryptoRet, Ctx, Hash, Host, HostExt, HostFns, Key,
};
use busbar_plugin_abi::types::Status;

/// The CRYPTO-SEAM deny list the stub states (`supports` false for MD5 and RSA_OAEP_SHA1): those two algs answer
/// UNAVAILABLE; any other request is outside this case and answers INVALID.
extern "C" fn deny_list<'e>(ctx: Ctx<'e>, req: &CryptoReq<'_>) -> CryptoRet<'e> {
    let status = match req.alg {
        alg::MD5 | alg::RSA_OAEP_SHA1_ENCRYPT => crypto_status::UNAVAILABLE,
        _ => crypto_status::INVALID,
    };
    CryptoRet::empty(ctx, status)
}

static STUB: Host = Host::new(
    0,
    HostFns {
        now: None,
        mono: None,
        random: None,
        crypto: Some(deny_list),
        log: None,
        log_level: None,
        grow: None,
        deployment: None,
        migrate_admit: None,
    },
);

#[test]
fn stub_backend_unsupported_algs_answer_unavailable() {
    let md5 = STUB.digest(Hash::Md5, b"password");
    assert_eq!(md5.err(), Some(CryptoErr::Unavailable));
    let oaep = STUB.rsa_oaep_sha1_encrypt(Key::SpkiDer(b"spki"), b"password");
    assert_eq!(oaep, Err(CryptoErr::Unavailable));
    // The plugin's `?`: the REFUSED R_UNSUPPORTED verdict, never FAILED (UNAVAILABLE keeps one meaning, §5.2).
    let fail = Fail::from(CryptoErr::Unavailable);
    assert_eq!(
        (fail.status(), fail.code()),
        (Status::REFUSED, refused::R_UNSUPPORTED)
    );
}

/// The same answers from host_vt itself over the CRYPTO-SEAM stub backend (busbar#262): `supports` is false for
/// MD5, RSA_OAEP_SHA1 and DTLS_SRTP, the facade's MD5 and RSA-OAEP-SHA1 are the stub's deliberate refusal of
/// exactly those algs, and through `HOST` inside an entry MD5 and RSA_OAEP_SHA1_ENCRYPT answer UNAVAILABLE with
/// `out` EMPTY (the safe layer's `Err(Unavailable)`) while HMAC_SHA256 answers OK in the same run, and no host
/// fault counter moves.
#[test]
fn unsupported_algs_through_host_vt_on_the_stub_backend() {
    let got = stub_host_vt::probe("unavailable", "", "1000");
    let (rng, unavailable) = (crypto_status::RNG, crypto_status::UNAVAILABLE);
    let want = format!(
        "outside={rng}/0\n\
         supports=md5:false rsa_oaep_sha1:false dtls_srtp:false hmac_key_short:true\n\
         facade_md5=Unsupported(MD5, stub)\n\
         facade_oaep=Unsupported(RSA_OAEP_SHA1, stub)\n\
         md5={unavailable}/0\n\
         md5_safe=Err(Unavailable)\n\
         oaep={unavailable}/0\n\
         oaep_safe=Err(Unavailable)\n\
         hmac=Ok(true)\n\
         self_test=0 host_panic=0\n\
         entry=ran\n"
    );
    assert_eq!(got, want, "host_vt over the stub backend");
    // The plugin's `?` on that answer: REFUSED R_UNSUPPORTED, never FAILED.
    let fail = Fail::from(CryptoErr::Unavailable);
    assert_eq!(
        (fail.status(), fail.code()),
        (Status::REFUSED, refused::R_UNSUPPORTED)
    );
}

/// busbar#262: the real `HOST` (host_vt) over the CRYPTO-SEAM stub backend, shared by C-RANDOM, C-UNAVAILABLE
/// and C-CRYPTO-SELFTEST (a)-(c). host_vt only runs over the stub in a scratch build: the root `[patch]` on the
/// backend's git URL cannot resolve offline, so (the tests/fips_gate.rs pattern) the scratch workspace builds
/// busbar-plugin-abi's and the facade's own sources as packages of their names, with busbar-ffi[host] by path
/// and the stub (`crates/busbar-crypto/fixtures/fips_gate/backend.rs`) named as the facade's
/// `busbar-crypto-backend` by path, offline, on the workspace's lock. The probe
/// (`tests/fixtures/host_vt_probe.rs`) makes every call inside one `entry::guard` entry and prints one line per
/// answer.
pub(crate) mod stub_host_vt {
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::OnceLock;

    fn here() -> &'static Path {
        Path::new(env!("CARGO_MANIFEST_DIR"))
    }

    /// Writes the scratch workspace once per process (the arms run in parallel and share its target dir,
    /// which cargo's lock serialises) and returns its directory.
    fn workspace() -> &'static Path {
        static DIR: OnceLock<PathBuf> = OnceLock::new();
        DIR.get_or_init(|| {
            let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("host-vt-stub");
            for sub in ["abi", "facade", "backend"] {
                std::fs::create_dir_all(dir.join(sub)).unwrap();
            }
            let crates = here().join("..");
            let probe = format!(
                r#"[package]
name = "host-vt-stub-probe"
version = "0.0.0"
edition = "2024"
publish = false
autobins = false
autoexamples = false
autotests = false
autobenches = false

[[bin]]
name = "probe"
path = '{probe}'

[dependencies]
busbar-plugin-abi = {{ path = "abi" }}
busbar-crypto = {{ path = "facade" }}

[workspace]
"#,
                probe = here().join("tests/fixtures/host_vt_probe.rs").display(),
            );
            let abi = format!(
                r#"[package]
name = "busbar-plugin-abi"
version = "1.6.0"
edition = "2024"
publish = false
autobins = false
autoexamples = false
autotests = false
autobenches = false

[lib]
name = "busbar_plugin_abi"
path = '{lib}'

[dependencies]
zerocopy = {{ version = "0.8", features = ["derive"] }}
busbar-ffi = {{ path = '{ffi}', features = ["host"] }}
busbar-crypto = {{ path = "../facade" }}
aho-corasick = "1"
arc-swap = "1"
base64 = "0.22"
percent-encoding = "2.3.2"
hex = "0.4.3"
crossbeam-queue = {{ version = "0.3", default-features = false, features = ["std"] }}
zeroize = "1"

[features]
default = ["host"]
host = []
memio = []
"#,
                lib = crates.join("busbar-plugin-abi/src/lib.rs").display(),
                ffi = crates.join("busbar-ffi").display(),
            );
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

[dependencies]
busbar-crypto-backend = {{ path = "../backend" }}
zeroize = {{ version = "1", default-features = false }}

[features]
tls = []
test-support = []
"#,
                lib = crates.join("busbar-crypto/src/lib.rs").display(),
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
                lib = crates
                    .join("busbar-crypto/fixtures/fips_gate/backend.rs")
                    .display(),
            );
            std::fs::write(dir.join("Cargo.toml"), probe).unwrap();
            std::fs::write(dir.join("abi/Cargo.toml"), abi).unwrap();
            std::fs::write(dir.join("facade/Cargo.toml"), facade).unwrap();
            std::fs::write(dir.join("backend/Cargo.toml"), stub).unwrap();
            std::fs::copy(here().join("../../Cargo.lock"), dir.join("Cargo.lock")).unwrap();
            dir
        })
    }

    /// Runs the probe in `mode` with the stub's `fill` answering `fill` (`BUSBAR_STUB_FILL`: "" fills, `rng`
    /// fails the generator, `crngt` fails its self-test) and hmac_sha256 / ECDSA P-256 signing each succeeding
    /// `pct_after` times before `SelfTest("pct")` (`BUSBAR_STUB_PCT_AFTER`); its stdout, after a clean exit.
    pub(crate) fn probe(mode: &str, fill: &str, pct_after: &str) -> String {
        let dir = workspace();
        let run = Command::new(env!("CARGO"))
            .args([
                "run",
                "--offline",
                "--quiet",
                "--bin",
                "probe",
                "--manifest-path",
            ])
            .arg(dir.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(dir.join("target"))
            .arg("--")
            .arg(mode)
            .env("BUSBAR_STUB_FILL", fill)
            .env("BUSBAR_STUB_PCT_AFTER", pct_after)
            .output()
            .expect("run cargo");
        assert!(
            run.status.success(),
            "the host_vt probe ({mode}, BUSBAR_STUB_FILL={fill:?}, BUSBAR_STUB_PCT_AFTER={pct_after}) must \
             build and exit cleanly (no panic, no abort):\n{}\n--- stdout\n{}\n--- stderr\n{}",
            run.status,
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&run.stderr)
        );
        String::from_utf8_lossy(&run.stdout).into_owned()
    }
}

/// W1-L1, C-FIPS-GATE's admit arm: admit's step 6 decides from the facade's two answers and nothing else. With a
/// deny-list stub backend stating `EXTERNAL_PLUGINS = false`, a `crypto = "external"` image is refused `Crypto`,
/// and a stamp naming a backend other than `BACKEND` is refused `Crypto`; on the linked facade, "external" admits
/// exactly when `busbar_crypto::EXTERNAL_PLUGINS` says so.
#[test]
fn admit_refuses_external_without_external_plugins_and_a_foreign_backend() {
    use busbar_plugin_loader::admit::{crypto_gate, CryptoFacts};
    use busbar_plugin_loader::refusal::RefusalCode;

    let stub = CryptoFacts {
        external_plugins: false,
        backend: "fips-stub",
        plugin_host: false,
    };
    let refused = crypto_gate("external", false, &stub).expect_err("EXTERNAL_PLUGINS = false");
    assert_eq!(
        (
            refused.code,
            refused.field,
            refused.have.as_str(),
            refused.want.as_str()
        ),
        (RefusalCode::Crypto, "crypto", "external", "fips-stub")
    );
    assert!(refused
        .named("busbar-secret-c")
        .to_string()
        .contains("is a non-Rust plugin (crypto: external)"));
    let with_host = CryptoFacts {
        plugin_host: true,
        ..stub
    };
    let foreign = crypto_gate("aws-lc", true, &with_host).expect_err("not BACKEND");
    assert_eq!(
        (foreign.code, foreign.have.as_str(), foreign.want.as_str()),
        (RefusalCode::Crypto, "aws-lc", "fips-stub")
    );
    assert!(crypto_gate("fips-stub", true, &with_host).is_ok());
    assert!(crypto_gate("host", false, &stub).is_ok());

    assert_eq!(
        (
            CryptoFacts::FACADE.external_plugins,
            CryptoFacts::FACADE.backend
        ),
        (
            busbar_contract::crypto::EXTERNAL_PLUGINS,
            busbar_contract::crypto::BACKEND
        )
    );
    assert_eq!(
        crypto_gate("external", false, &CryptoFacts::FACADE).is_ok(),
        busbar_contract::crypto::EXTERNAL_PLUGINS
    );
}
