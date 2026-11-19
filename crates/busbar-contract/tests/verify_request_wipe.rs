// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Owned verifier bytes are wiped on every exit (Q24, UNSAFE-MIN §4.4). Each field in turn carries a
//! fresh canary; the request leaves by return, by failure or by cancelling the pending future that
//! owns it; then a scan of this process's memory must not find the canary. While the future is
//! pending the canary must still be found: the verifier still owns its bytes. Linux only (A23).
#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

use std::future::Future;
use std::task::{Context, Poll, Waker};

use busbar_contract::auth_calls::VerifyRequest;
use busbar_contract::route::AuthPoint;

use busbar_contract::canary_scan::WipeProof;

/// The shipped allocator, so the scan reads what production would leave behind.
#[global_allocator]
static ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// A request whose `field` holds `secret` (its only copy); every other field is plain text.
fn request(field: &str, secret: &str) -> VerifyRequest {
    let pick = |name: &str, plain: &str| {
        if field == name {
            secret.to_owned()
        } else {
            plain.to_owned()
        }
    };
    VerifyRequest {
        point: AuthPoint::HeadBody,
        conn: 7,
        unit: 8,
        credential: None,
        lines: vec![(pick("line", "private-header"), b"v".to_vec().into())],
        peer: Some(pick("peer", "private-peer").into_bytes()),
        body: Some(pick("body", "private-body").into_bytes()),
        method: pick("method", "POST"),
        authority: pick("authority", "private.example"),
        path: pick("path", "/private-path"),
        query: Some(pick("query", "credential=private-query")),
        timestamp: 0,
    }
}

fn returned(_request: VerifyRequest, fail: bool) -> Result<(), ()> {
    if fail {
        Err(())
    } else {
        Ok(())
    }
}

#[test]
fn verifier_owned_buffers_are_wiped_on_return_failure_and_pending_cancellation() {
    for field in [
        "body",
        "path",
        "query",
        "peer",
        "authority",
        "method",
        "line",
    ] {
        for exit in ["return", "failure", "cancel"] {
            let what = format!("{field} on {exit}");
            let mut proof = WipeProof::text();
            let staging = proof.text_payload();
            let request = request(field, &staging);
            drop(staging);
            if exit == "cancel" {
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
                proof.assert_held("the pending verifier still owns its bytes");
                drop(pending);
            } else {
                assert_eq!(
                    returned(request, exit == "failure").is_err(),
                    exit == "failure"
                );
            }
            proof.assert_absent(&what);
        }
    }
}
