// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The ABI-only byte owner and its result/sink boundaries must share the contract's custody.
#![forbid(unsafe_code)]

use busbar_plugin_abi::need::{need, SecretHandle};
use busbar_plugin_abi::secure::{SecureVec, Tail};

#[cfg(target_os = "linux")]
use busbar_plugin_test::canary_scan::{WipeProof, CANARY_LEN, OFFSET, PAYLOAD_LEN};

#[cfg(target_os = "linux")]
#[global_allocator]
static ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[test]
fn sdk_secure_custody_surface_and_identity() {
    fn secret(_: need::NeedFut<'static, SecureVec>) {}
    secret(need::secret(SecretHandle(1)));
    fn read_surface(conn: &need::Conn, bytes: &mut SecureVec) {
        fn read(_: need::NeedFut<'_, SecureVec>) {}
        read(need::read(conn, 128));
        drop(need::read_into(conn, 128, bytes));
    }
    let _ = read_surface;
    let contract = busbar_contract::secure::SecureString::from("credential").into_bytes();
    let bytes: SecureVec = contract;
    let contract: busbar_contract::secure::SecureVec = bytes;
    assert_eq!(contract.as_slice(), b"credential");
    let fetched = need::Fetched {
        status: 200,
        headers: vec![("set-cookie".into(), SecureVec::from(&b"session"[..]))],
        body: SecureVec::from(&b"token"[..]),
    };
    let body: SecureVec = fetched.body;
    let headers: Vec<(String, SecureVec)> = fetched.headers;
    drop(headers);
    assert_eq!(body.as_slice(), b"token");
    for done in [need::Done::Secret(body), need::Done::Read(SecureVec::new())] {
        match done {
            need::Done::Secret(bytes) => assert_eq!(bytes.as_slice(), b"token"),
            need::Done::Read(bytes) => assert!(bytes.is_empty()),
            _ => panic!("unexpected result"),
        }
    }
}

#[test]
fn failed_and_panicking_read_loans_preserve_the_live_prefix() {
    for tail in [Tail::Wipe, Tail::Trusted] {
        let mut bytes = SecureVec::from(&b"prefix"[..]);
        let result = bytes.read_into(32, tail, |loan| {
            loan.fill(7);
            Err(std::io::ErrorKind::Interrupted.into())
        });
        assert!(result.expect("allocation").is_err());
        assert_eq!(bytes.as_slice(), b"prefix");
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = bytes.read_into(32, tail, |loan| {
                loan.fill(9);
                panic!("reader panicked");
            });
        }));
        assert!(panic.is_err());
        assert_eq!(bytes.as_slice(), b"prefix");
    }
}

#[cfg(target_os = "linux")]
fn payload(proof: &WipeProof) -> SecureVec {
    let mut bytes = SecureVec::zeroed(PAYLOAD_LEN);
    proof.write_canary(&mut bytes[OFFSET..OFFSET + CANARY_LEN]);
    bytes
}

#[cfg(target_os = "linux")]
#[test]
fn growing_sdk_scratch_wipes_released_blocks_and_drop() {
    let proof = WipeProof::new();
    let mut bytes = payload(&proof);
    bytes.extend_from_slice(&[0; 1024]);
    bytes.extend_from_slice(&[0; 2048]);
    drop(bytes);
    proof.assert_absent("SDK scratch growth and drop");
}

#[cfg(target_os = "linux")]
#[test]
fn fetched_field_moves_keep_independent_wiping_owners() {
    let proof = WipeProof::new();
    let fetched = need::Fetched {
        status: 200,
        headers: vec![("set-cookie".into(), payload(&proof))],
        body: payload(&proof),
    };
    let body = fetched.body;
    drop(fetched.headers);
    drop(body);
    proof.assert_absent("FETCH body and header owners");
}

#[cfg(target_os = "linux")]
#[test]
fn sdk_unwind_wipes_uncommitted_read_loan() {
    for tail in [Tail::Wipe, Tail::Trusted] {
        let proof = WipeProof::new();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut bytes = SecureVec::new();
            let _ = bytes.read_into(PAYLOAD_LEN, tail, |loan| {
                proof.write_canary(&mut loan[OFFSET..OFFSET + CANARY_LEN]);
                panic!("reader panicked");
            });
        }));
        assert!(panic.is_err());
        proof.assert_absent("SDK abandoned read loan");
    }
}
