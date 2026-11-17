// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Owned invoke-request strings, JSON member names and extras included, are wiped on every exit
//! (Q24, UNSAFE-MIN §4.4). Each string in turn carries a fresh canary; the request leaves by return,
//! failure, cancellation, a clone's drop, its last shared owner or a transfer to a final owner; then
//! a scan of this process's memory must not find the canary. Wherever an owner is still alive
//! part-way, the canary must still be found. Linux only (A23).
#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use busbar_contract::ir::invoke::InvokeReq;
use serde_json::{Map, Value};

#[allow(dead_code)]
#[path = "../../busbar-plugin-test/src/canary_scan.rs"]
mod canary_scan;

use canary_scan::WipeProof;

/// The shipped allocator, so the scan reads what production would leave behind.
#[global_allocator]
static ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// A request whose string `field` holds `secret` (its only copy); every other string is plain.
fn request(field: &str, secret: &str) -> InvokeReq {
    let pick = |name: &str, plain: &str| {
        if field == name {
            secret.to_owned()
        } else {
            plain.to_owned()
        }
    };
    let mut nested = Map::new();
    nested.insert(
        pick("nested-name", "private-nested-name"),
        Value::String(pick("nested-value", "private-nested-value")),
    );
    let mut arguments = Map::new();
    arguments.insert(
        pick("argument-name", "private-argument-name"),
        Value::Array(vec![
            Value::String(pick("argument-value", "private-argument-value")),
            Value::Object(nested),
        ]),
    );
    InvokeReq {
        tool: pick("tool", "private-tool"),
        arguments: Value::Object(arguments),
        extra: [(
            pick("extra-source", "private-source"),
            [(
                pick("extra-name", "private-extra-name"),
                Value::String(pick("extra-value", "private-extra-value")),
            )]
            .into_iter()
            .collect(),
        )]
        .into_iter()
        .collect(),
    }
}

fn returned(_request: InvokeReq, fail: bool) -> Result<(), ()> {
    if fail {
        Err(())
    } else {
        Ok(())
    }
}

#[test]
fn the_scan_distinguishes_plain_and_wiped_strings() {
    let proof = WipeProof::text();
    let plain = proof.text_payload().as_str().to_owned();
    drop(plain);
    assert!(
        proof.canary_copies("a plain string") >= 1,
        "a plain string's freed bytes must be found"
    );

    let proof = WipeProof::text();
    let wiped =
        busbar_contract::secure::SecureString::from(proof.text_payload().as_str().to_owned());
    drop(wiped);
    proof.assert_absent("a SecureString");
}

#[test]
fn invoke_request_strings_are_wiped_on_return_failure_cancel_and_last_owner_drop() {
    for name in [
        "tool",
        "argument-name",
        "argument-value",
        "nested-name",
        "nested-value",
        "extra-source",
        "extra-name",
        "extra-value",
    ] {
        for exit in ["return", "failure", "cancel", "clone", "shared", "transfer"] {
            let what = format!("{name} on {exit}");
            let mut proof = WipeProof::text();
            let staging = proof.text_payload();
            let mut request = request(name, &staging);
            drop(staging);
            if exit == "clone" {
                let clone = request.clone();
                drop(request);
                request = clone;
            }
            match exit {
                "cancel" => {
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
                "shared" => {
                    let shared = Arc::new(request);
                    let last = Arc::clone(&shared);
                    drop(shared);
                    proof.assert_held("the last shared owner still holds the request");
                    drop(last);
                }
                "transfer" => {
                    let final_owner = InvokeReq {
                        tool: std::mem::take(&mut request.tool),
                        arguments: std::mem::take(&mut request.arguments),
                        extra: std::mem::take(&mut request.extra),
                    };
                    drop(request);
                    proof.assert_held("the final owner still holds the request");
                    drop(final_owner);
                }
                _ => {
                    assert_eq!(
                        returned(request, exit == "failure").is_err(),
                        exit == "failure"
                    );
                }
            }
            proof.assert_absent(&what);
        }
    }
}
