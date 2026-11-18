// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Owned exchange-request bytes are wiped on every exit (Q24, UNSAFE-MIN §4.4). Each buffer in turn
//! carries a fresh canary; the request leaves by return, failure, cancellation, a clone's drop, its
//! last shared owner, a transfer or unwinding, or is framed into (or refused by) an exchange; then a
//! scan of this process's memory must not find the canary. Wherever an owner is still alive
//! part-way, the canary must still be found. Linux only (A23).
#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use busbar_contract::abi::sdk::exchange::{Exchange, Request};
use busbar_contract::secure::SecureVec;

use busbar_contract::canary_scan::WipeProof;

/// The shipped allocator, so the scan reads what production would leave behind.
#[global_allocator]
static ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Field {
    Method,
    Target,
    Name,
    Value,
    Body,
}

/// A request whose `field` holds `secret` (its only copy); every other buffer is plain.
fn request(field: Field, secret: &[u8]) -> Request {
    let pick = |name: Field, plain: &[u8]| {
        if field == name {
            secret.to_vec()
        } else {
            plain.to_vec()
        }
    };
    Request {
        method: pick(Field::Method, b"private-method"),
        target: pick(Field::Target, b"/private-target?credential=private-query"),
        fields: vec![(
            pick(Field::Name, b"private-name"),
            pick(Field::Value, b"private-value"),
        )],
        body: pick(Field::Body, br#"{"credential":"private-body"}"#),
        timeout_ms: Request::default().timeout_ms,
    }
}

#[derive(Clone, Copy, Debug)]
enum Exit {
    Return,
    Failure,
    Cancel,
    Clone,
    Shared,
    Transfer,
    Panic,
}

fn returned(_request: Request, fail: bool) -> Result<(), ()> {
    if fail {
        Err(())
    } else {
        Ok(())
    }
}

#[test]
fn the_scan_distinguishes_plain_and_wiped_vectors() {
    let proof = WipeProof::new();
    let plain = proof.payload().to_vec();
    drop(plain);
    assert!(
        proof.canary_copies("a plain vector") >= 1,
        "a plain vector's freed bytes must be found"
    );

    let proof = WipeProof::new();
    let wiped = SecureVec::from(proof.payload().to_vec());
    drop(wiped);
    proof.assert_absent("a SecureVec");
}

/// Every request buffer in turn leaves by `exit`. Each exit is its own test (its own process under
/// nextest), so the per-case memory scans never add up past one test's deadline.
fn request_payloads_wipe_on(exit: Exit) {
    for field in [
        Field::Method,
        Field::Target,
        Field::Name,
        Field::Value,
        Field::Body,
    ] {
        let what = format!("{field:?} on {exit:?}");
        let mut proof = WipeProof::text();
        let staging = proof.text_payload();
        let mut request = request(field, staging.as_bytes());
        drop(staging);
        if matches!(exit, Exit::Clone) {
            let clone = request.clone();
            drop(request);
            request = clone;
        }
        match exit {
            Exit::Panic => {
                let unwound = std::panic::catch_unwind(move || {
                    let _request = request;
                    panic!("request-owner-unwind fixture");
                });
                assert!(unwound.is_err());
            }
            Exit::Cancel => {
                let mut pending = Box::pin(async move {
                    let request = request;
                    std::future::pending::<()>().await;
                    drop(request);
                });
                assert_eq!(
                    pending
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop())),
                    Poll::Pending
                );
                proof.assert_held("the pending future still owns the request");
                drop(pending);
            }
            Exit::Shared => {
                let shared = Arc::new(request);
                let last = Arc::clone(&shared);
                drop(shared);
                proof.assert_held("the last shared owner still holds the request");
                drop(last);
            }
            Exit::Transfer => {
                let final_owner = Request {
                    method: std::mem::take(&mut request.method),
                    target: std::mem::take(&mut request.target),
                    fields: std::mem::take(&mut request.fields),
                    body: std::mem::take(&mut request.body),
                    timeout_ms: request.timeout_ms,
                };
                drop(request);
                proof.assert_held("the final owner still holds the request");
                drop(final_owner);
            }
            _ => {
                let fail = matches!(exit, Exit::Failure);
                assert_eq!(returned(request, fail).is_err(), fail);
            }
        }
        proof.assert_absent(&what);
    }
}

#[test]
fn request_payloads_wipe_on_return() {
    request_payloads_wipe_on(Exit::Return);
}

#[test]
fn request_payloads_wipe_on_failure() {
    request_payloads_wipe_on(Exit::Failure);
}

#[test]
fn request_payloads_wipe_on_cancel() {
    request_payloads_wipe_on(Exit::Cancel);
}

#[test]
fn request_payloads_wipe_on_a_clone_drop() {
    request_payloads_wipe_on(Exit::Clone);
}

#[test]
fn request_payloads_wipe_on_the_last_shared_owner_drop() {
    request_payloads_wipe_on(Exit::Shared);
}

#[test]
fn request_payloads_wipe_on_transfer() {
    request_payloads_wipe_on(Exit::Transfer);
}

#[test]
fn request_payloads_wipe_on_unwinding() {
    request_payloads_wipe_on(Exit::Panic);
}

#[test]
fn framing_transfers_the_body_without_releasing_it_before_the_exchange_owner() {
    let mut proof = WipeProof::text();
    let staging = proof.text_payload();
    let request = request(Field::Body, staging.as_bytes());
    drop(staging);
    let exchange = Exchange::request(request).expect("the request frames");
    proof.assert_held("the exchange owns the framed body");
    drop(exchange);
    proof.assert_absent("the exchange owner's drop");
}

#[test]
fn a_refused_request_wipes_the_body_it_never_sent() {
    let proof = WipeProof::text();
    let staging = proof.text_payload();
    let mut request = request(Field::Body, staging.as_bytes());
    drop(staging);
    request.fields[0].0.insert(0, b':');
    assert!(Exchange::request(request).is_err());
    proof.assert_absent("a refused request");
}
