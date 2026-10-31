// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Observe owned verifier bytes before their allocation is released, never after free.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::future::Future;
use std::task::{Context, Poll, Waker};

use busbar_contract::abi::auth::AuthPoint;
use busbar_contract::auth_calls::VerifyRequest;

thread_local! {
    static WATCH: Cell<Option<(*mut u8, usize)>> = const { Cell::new(None) };
    static WIPED: Cell<Option<bool>> = const { Cell::new(None) };
}

struct InspectBeforeFree;

// SAFETY: allocations are forwarded unchanged to System. The deallocator observes only the
// initialized prefix registered by this thread, while that allocation still belongs to it.
unsafe impl GlobalAlloc for InspectBeforeFree {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the allocator caller supplies a valid layout.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let _ = WATCH.try_with(|watch| {
            if let Some((watched, len)) = watch.get().filter(|(watched, _)| *watched == pointer) {
                watch.set(None);
                let wiped = len <= layout.size()
                    && (0..len).all(|index| {
                        // SAFETY: this is the watched live allocation, before System.dealloc.
                        // Only bytes initialized by the original Vec/String are read; no spare
                        // capacity or freed memory is inspected, and reads allocate nothing.
                        unsafe { watched.add(index).read_volatile() == 0 }
                    });
                let _ = WIPED.try_with(|result| result.set(Some(wiped)));
            }
        });
        // SAFETY: pointer and layout are the allocator caller's matching allocation.
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: InspectBeforeFree = InspectBeforeFree;

fn request() -> VerifyRequest {
    VerifyRequest {
        point: AuthPoint::HeadBody,
        conn: 7,
        unit: 8,
        credential: None,
        lines: Vec::new(),
        peer: Some(b"private-peer".to_vec()),
        body: Some(b"private-body".to_vec()),
        method: "POST".to_string(),
        authority: "private.example".to_string(),
        path: "/private-path".to_string(),
        query: Some("credential=private-query".to_string()),
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
    for field in ["body", "path", "query", "peer", "authority"] {
        for exit in ["return", "failure", "cancel"] {
            let request = request();
            let bytes = match field {
                "body" => request.body.as_deref().unwrap(),
                "path" => request.path.as_bytes(),
                "query" => request.query.as_deref().unwrap().as_bytes(),
                "peer" => request.peer.as_deref().unwrap(),
                "authority" => request.authority.as_bytes(),
                _ => unreachable!(),
            };
            WATCH.with(|watch| watch.set(Some((bytes.as_ptr().cast_mut(), bytes.len()))));
            WIPED.with(|result| result.set(None));
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
                assert_eq!(
                    WIPED.with(Cell::get),
                    None,
                    "the pending verifier still owns its bytes"
                );
                drop(pending);
            } else {
                assert_eq!(
                    returned(request, exit == "failure").is_err(),
                    exit == "failure"
                );
            }
            assert_eq!(WIPED.with(Cell::get), Some(true), "{field} on {exit}");
        }
    }
}
