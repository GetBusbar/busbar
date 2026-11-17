// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Owned auth inputs, shared secrets and service results are wiped on every exit (Q24, UNSAFE-MIN
//! §4.4). Each owned buffer in turn carries a fresh canary; it leaves by success, failure,
//! cancellation, unwinding, its last shared owner, a clone's drop, a late send or a transfer; then a
//! scan of this process's memory must not find the canary. Wherever an owner is still alive part-way,
//! the canary must still be found. Linux only (A23).
#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use busbar_contract::auth_calls::FieldsRequest;
use busbar_contract::secure::SecureVec;
use busbar_contract::services::Stored;
use busbar_contract::Secret;

#[allow(dead_code)]
#[path = "../../busbar-plugin-test/src/canary_scan.rs"]
mod canary_scan;

use canary_scan::WipeProof;

/// The shipped allocator, so the scan reads what production would leave behind.
#[global_allocator]
static ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// A request whose input `field` holds `secret` (its only copy); every other input is plain. The
/// caller credential, when it is the field, is the secret moved into a shared `Secret`.
fn fields_request(field: &str, secret: &str) -> FieldsRequest {
    let pick = |name: &str, plain: &str| {
        if field == name {
            secret.to_owned()
        } else {
            plain.to_owned()
        }
    };
    FieldsRequest {
        point: busbar_contract::abi::auth::AuthPoint::HeadBody,
        conn: 1,
        unit: 2,
        body: Some(pick("body", "private-body").into_bytes()),
        method: pick("method", "private-method").into_bytes(),
        authority: pick("authority", "private-authority"),
        path: pick("path", "/private-path").into_bytes(),
        query: Some(pick("query", "credential=private-query").into_bytes()),
        timestamp: 0,
        headers: vec![(
            pick("header-name", "private-name").into_bytes(),
            pick("header-value", "private-value").into_bytes(),
        )],
        caller_credential: (field == "caller-credential")
            .then(|| Secret::new(secret.as_bytes().to_vec()).share()),
        extensions: pick("extensions", "private-extensions").into_bytes(),
    }
}

fn returned<T>(_owned: T, fail: bool) -> Result<(), ()> {
    if fail {
        Err(())
    } else {
        Ok(())
    }
}

fn cancel<T>(owned: T, proof: &mut WipeProof) {
    let mut pending = Box::pin(async move {
        let owned = owned;
        std::future::pending::<()>().await;
        drop(owned);
    });
    assert_eq!(
        pending
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    );
    proof.assert_held("pending still owns its bytes");
    drop(pending);
}

#[test]
fn the_scan_distinguishes_plain_and_zeroized_buffers() {
    let proof = WipeProof::new();
    let plain = proof.payload().to_vec();
    drop(plain);
    assert!(
        proof.canary_copies("a plain buffer") >= 1,
        "a plain buffer's freed bytes must be found"
    );
    let proof = WipeProof::new();
    let wiped = SecureVec::from(proof.payload().to_vec());
    drop(wiped);
    proof.assert_absent("a SecureVec");
}

#[test]
fn outbound_auth_inputs_wipe_on_success_failure_cancel_unwind_and_last_owner_drop() {
    for field in [
        "body",
        "method",
        "authority",
        "path",
        "query",
        "header-name",
        "header-value",
        "extensions",
        "caller-credential",
    ] {
        for exit in [
            "return", "failure", "cancel", "unwind", "shared", "transfer",
        ] {
            let what = format!("{field} on {exit}");
            let mut proof = WipeProof::text();
            let staging = proof.text_payload();
            let mut request = fields_request(field, &staging);
            drop(staging);
            match exit {
                "cancel" => cancel(request, &mut proof),
                "unwind" => {
                    assert!(std::panic::catch_unwind(move || {
                        let _request = request;
                        panic!("auth-input-owner-unwind fixture");
                    })
                    .is_err());
                }
                "shared" => {
                    let first = Arc::new(request);
                    let last = Arc::clone(&first);
                    drop(first);
                    proof.assert_held("the last shared owner still holds the inputs");
                    drop(last);
                }
                "transfer" => {
                    let next = FieldsRequest {
                        point: request.point,
                        conn: request.conn,
                        unit: request.unit,
                        body: std::mem::take(&mut request.body),
                        method: std::mem::take(&mut request.method),
                        authority: std::mem::take(&mut request.authority),
                        path: std::mem::take(&mut request.path),
                        query: std::mem::take(&mut request.query),
                        timestamp: request.timestamp,
                        headers: std::mem::take(&mut request.headers),
                        caller_credential: std::mem::take(&mut request.caller_credential),
                        extensions: std::mem::take(&mut request.extensions),
                    };
                    drop(request);
                    proof.assert_held("the next owner still holds the inputs");
                    drop(next);
                }
                _ => assert_eq!(
                    returned(request, exit == "failure").is_err(),
                    exit == "failure"
                ),
            }
            proof.assert_absent(&what);
        }
    }
}

busbar_contract::own_seal!(Own);

/// SINGLE-PATH SP-AU6: a `SharedSecret`'s handles share one buffer; it stays intact while any
/// handle lives and is wiped, by `Secret`'s own `Drop`, when the last one drops.
#[test]
fn shared_secret_wiped_on_last_drop() {
    let mut proof = WipeProof::new();
    let staging = proof.payload();
    let first = Secret::<Vec<u8>, Own>::held(staging.to_vec()).share();
    let others: Vec<_> = (0..3).map(|_| first.clone()).collect();
    let last = first.clone();
    drop(first);
    drop(others);
    assert_eq!(
        last.expose_own(&Own::here()).as_slice(),
        staging.as_slice(),
        "the bytes stay intact while any handle lives"
    );
    drop(staging);
    proof.assert_held("a handle remains, so the one buffer is still held");
    drop(last);
    proof.assert_absent("the last handle's drop wipes the one buffer before it is freed");
}

#[test]
fn service_result_bytes_wipe_after_clone_cancel_forget_failure_unwind_and_transfer() {
    for exit in [
        "return", "failure", "cancel", "unwind", "shared", "clone", "transfer", "late",
    ] {
        let mut proof = WipeProof::new();
        let mut stored = Stored::ready(1);
        stored.bytes = proof.payload().to_vec();
        if exit == "clone" {
            let clone = stored.clone();
            drop(stored);
            stored = clone;
        }
        match exit {
            "cancel" => cancel(stored, &mut proof),
            "unwind" => {
                assert!(std::panic::catch_unwind(move || {
                    let _stored = stored;
                    panic!("service-result-owner-unwind fixture");
                })
                .is_err());
            }
            "shared" => {
                let first = Arc::new(stored);
                let last = Arc::clone(&first);
                drop(first);
                proof.assert_held("the last shared owner still holds the result");
                drop(last);
            }
            "transfer" => {
                let mut next = Stored::ready(stored.value);
                next.bytes = std::mem::take(&mut stored.bytes);
                drop(stored);
                proof.assert_held("the next owner still holds the result");
                drop(next);
            }
            "late" => {
                let (tx, rx) = std::sync::mpsc::channel();
                drop(rx);
                drop(tx.send(stored));
            }
            _ => assert_eq!(
                returned(stored, exit == "failure").is_err(),
                exit == "failure"
            ),
        }
        proof.assert_absent(exit);
    }
}

#[test]
fn a_stored_result_never_debug_prints_its_payload() {
    let mut stored = Stored::ready(1);
    stored.bytes = b"private-service-credential".to_vec();
    let shown = format!("{stored:?}");
    assert!(!shown.contains("private-service-credential"), "{shown}");
    assert!(shown.contains("<redacted>"), "{shown}");
}
