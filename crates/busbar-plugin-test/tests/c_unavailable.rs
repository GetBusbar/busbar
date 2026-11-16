// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-UNAVAILABLE (ABI-MIN3-INTERFACE §14): The facade's test-support stub backend: unsupported algs,
//! `EXTERNAL_PLUGINS`, stamp crypto; C-FIPS-GATE's admit arm (round 13). C-FIPS-GATE's facade build arm is
//! W0-H0B's contract test. W1-A2 runs the safe layer over a vtable answering what host_vt answers for an alg the
//! backend's `supports` refuses (UNAVAILABLE, `Error::Unsupported`); the run through host_vt over the stub
//! backend is busbar#262.
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

/// The same answers from host_vt itself over the CRYPTO-SEAM stub backend (busbar#262).
#[test]
#[ignore = "owner: busbar#262 (host_vt over the stub backend)"]
fn unsupported_algs_through_host_vt_on_the_stub_backend() {
    todo!("owner: busbar#262 (C-UNAVAILABLE)")
}

#[test]
#[ignore = "owner: W1-L1"]
fn admit_refuses_external_without_external_plugins_and_a_foreign_backend() {
    todo!("owner: W1-L1 (C-UNAVAILABLE)")
}
