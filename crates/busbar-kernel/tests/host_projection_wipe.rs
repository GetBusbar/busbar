// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A host projection borrows the arena the plane projected into (whose custody the kernel's
//! arena tests pin); the only bytes it owns are a lossy copy of text that was not UTF-8. Those
//! are wiped wherever the projection ends (Q24, UNSAFE-MIN §4.4): each owned string in turn carries
//! a fresh canary, the projection ends by return, failure, cancellation, a clone's drop, replacement
//! or a transfer, and a scan of this process's memory must not find the canary. Wherever an owner is
//! still alive part-way, the canary must still be found. Linux only (A23).
#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

use std::borrow::Cow;
use std::future::Future;
use std::task::{Context, Poll, Waker};

use busbar_kernel::plane_driver::Projection;

#[allow(dead_code)]
#[path = "../../busbar-plugin-test/src/canary_scan.rs"]
mod canary_scan;

use canary_scan::WipeProof;

/// The shipped allocator, so the scan reads what production would leave behind.
#[global_allocator]
static ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// A projection whose owned string `field` holds `secret` (its only copy); every other owned string
/// is plain. `field` "none" plants nothing.
fn projection(field: &str, secret: &str) -> Projection<'static> {
    let owned = |name: &str, plain: &str| -> Cow<'static, str> {
        if field == name {
            Cow::Owned(secret.to_owned())
        } else {
            Cow::Owned(plain.to_owned())
        }
    };
    Projection {
        pool: owned("pool", "private-pool"),
        dialect: owned("dialect", "private-dialect"),
        message_count: 1,
        total_chars: 12,
        max_tokens: Some(7),
        has_tools: true,
        stream: false,
        text_complete: true,
        system: Some(owned("system", "private-system")),
        turns: vec![(
            owned("author", "private-author"),
            owned("text", "private-text"),
        )],
        end_user: Some(owned("end-user", "private-user")),
        rewritten: Some(b"private-rewrite".as_slice()),
        session: Some(b"private-session".as_slice()),
        projected: Some(b"private-projection".as_slice()),
        rewrite_not_applicable: false,
    }
}

fn returned(_view: Projection<'_>, fail: bool) -> Result<(), ()> {
    if fail {
        Err(())
    } else {
        Ok(())
    }
}

#[test]
fn the_scan_distinguishes_plain_and_wiped_payloads() {
    let proof = WipeProof::new();
    let plain = proof.payload().to_vec();
    drop(plain);
    assert!(
        proof.canary_copies("a plain payload") >= 1,
        "a plain payload's freed bytes must be found"
    );

    let proof = WipeProof::new();
    let mut wiped = proof.payload().to_vec();
    zeroize::Zeroize::zeroize(&mut wiped);
    drop(wiped);
    proof.assert_absent("a zeroized payload");
}

#[test]
fn host_projection_payloads_wipe_on_return_error_cancel_clone_replacement_and_transfer() {
    for name in ["pool", "dialect", "system", "author", "text", "end-user"] {
        for exit in [
            "return", "failure", "cancel", "clone", "replace", "transfer",
        ] {
            let what = format!("{name} on {exit}");
            let mut proof = WipeProof::text();
            let staging = proof.text_payload();
            let mut view = projection(name, &staging);
            drop(staging);
            if exit == "clone" {
                let clone = view.clone();
                drop(view);
                view = clone;
            }
            match exit {
                "cancel" => {
                    let mut pending = Box::pin(async move {
                        let view = view;
                        std::future::pending::<()>().await;
                        drop(view);
                    });
                    assert_eq!(
                        pending
                            .as_mut()
                            .poll(&mut Context::from_waker(Waker::noop())),
                        Poll::Pending
                    );
                    proof.assert_held("the pending future still owns the projection");
                    drop(pending);
                }
                "replace" => {
                    view = projection("none", "");
                    assert_eq!(view.projected, Some(b"private-projection".as_slice()));
                    drop(view);
                }
                "transfer" => {
                    let final_owner = std::mem::replace(&mut view, projection("none", ""));
                    drop(view);
                    proof.assert_held("the final owner still holds the projection");
                    drop(final_owner);
                }
                _ => {
                    assert_eq!(
                        returned(view, exit == "failure").is_err(),
                        exit == "failure"
                    );
                }
            }
            proof.assert_absent(&what);
        }
    }
}
