// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Observe registered initialized auth inputs and service results before their allocation is freed.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use busbar_contract::auth_calls::FieldsRequest;
use busbar_contract::services::Stored;
use zeroize::Zeroizing;

thread_local! {
    static WATCH: Cell<Option<(usize, usize)>> = const { Cell::new(None) };
    static WIPED: Cell<Option<bool>> = const { Cell::new(None) };
}

struct InspectBeforeFree;

// SAFETY: allocations are forwarded unchanged to System. The observer reads only the initialized
// prefix registered by this thread, before forwarding that same live allocation to System.
unsafe impl GlobalAlloc for InspectBeforeFree {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the allocator caller supplies a valid layout.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let _ = WATCH.try_with(|watch| {
            if let Some((_, len)) = watch
                .get()
                .filter(|(address, _)| *address == pointer.addr())
            {
                watch.set(None);
                let wiped = len <= layout.size()
                    && (0..len).all(|index| {
                        // SAFETY: registration identified initialized Vec contents. This matching
                        // live allocation has not been freed. Read through dealloc's current
                        // owning pointer, not the shared registration borrow. No padding or
                        // spare capacity is read.
                        unsafe { pointer.add(index).read_volatile() == 0 }
                    });
                let _ = WIPED.try_with(|result| result.set(Some(wiped)));
            }
        });
        // SAFETY: pointer and layout describe the allocator caller's live allocation.
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: InspectBeforeFree = InspectBeforeFree;

fn watch(bytes: &[u8]) {
    assert!(!bytes.is_empty());
    WATCH.with(|watched| {
        assert!(watched.get().is_none());
        watched.set(Some((bytes.as_ptr().addr(), bytes.len())));
    });
    WIPED.with(|result| result.set(None));
}

fn fields_request() -> FieldsRequest {
    FieldsRequest {
        point: busbar_contract::abi::auth::AuthPoint::HeadBody,
        conn: 1,
        unit: 2,
        body: Some(b"private-body".to_vec()),
        method: b"private-method".to_vec(),
        authority: "private-authority".into(),
        path: b"/private-path".to_vec(),
        query: Some(b"credential=private-query".to_vec()),
        timestamp: 0,
        headers: vec![(b"private-name".to_vec(), b"private-value".to_vec())],
        caller_credential: None,
        extensions: b"private-extensions".to_vec(),
    }
}

fn input_bytes<'a>(request: &'a FieldsRequest, field: &str) -> &'a [u8] {
    match field {
        "body" => request.body.as_deref().unwrap(),
        "method" => &request.method,
        "authority" => request.authority.as_bytes(),
        "path" => &request.path,
        "query" => request.query.as_deref().unwrap(),
        "header-name" => &request.headers[0].0,
        "header-value" => &request.headers[0].1,
        "extensions" => &request.extensions,
        _ => unreachable!(),
    }
}

fn returned<T>(_owned: T, fail: bool) -> Result<(), ()> {
    if fail {
        Err(())
    } else {
        Ok(())
    }
}

fn cancel<T>(owned: T) {
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
    assert_eq!(WIPED.with(Cell::get), None, "pending still owns its bytes");
    drop(pending);
}

#[test]
fn the_live_payload_observer_distinguishes_plain_and_zeroized_buffers() {
    let plain = b"plain-initialized-control".to_vec();
    watch(&plain);
    drop(plain);
    assert_eq!(WIPED.with(Cell::get), Some(false));
    let wiped = Zeroizing::new(b"wiped-initialized-control".to_vec());
    watch(&wiped);
    drop(wiped);
    assert_eq!(WIPED.with(Cell::get), Some(true));
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
    ] {
        for exit in [
            "return", "failure", "cancel", "unwind", "shared", "transfer",
        ] {
            let mut request = fields_request();
            watch(input_bytes(&request, field));
            match exit {
                "cancel" => cancel(request),
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
                    assert_eq!(WIPED.with(Cell::get), None);
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
                    assert_eq!(WIPED.with(Cell::get), None);
                    drop(next);
                }
                _ => assert_eq!(
                    returned(request, exit == "failure").is_err(),
                    exit == "failure"
                ),
            }
            assert_eq!(WIPED.with(Cell::get), Some(true), "{field} on {exit}");
        }
    }
}

#[test]
fn service_result_bytes_wipe_after_clone_cancel_forget_failure_unwind_and_transfer() {
    for exit in [
        "return", "failure", "cancel", "unwind", "shared", "clone", "transfer", "late",
    ] {
        let mut stored = Stored::ready(1);
        stored.bytes = b"private-service-credential".to_vec();
        if exit == "clone" {
            let clone = stored.clone();
            drop(stored);
            stored = clone;
        }
        watch(&stored.bytes);
        match exit {
            "cancel" => cancel(stored),
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
                assert_eq!(WIPED.with(Cell::get), None);
                drop(last);
            }
            "transfer" => {
                let mut next = Stored::ready(stored.value);
                next.bytes = std::mem::take(&mut stored.bytes);
                drop(stored);
                assert_eq!(WIPED.with(Cell::get), None);
                drop(next);
            }
            "late" => {
                // A completion whose receiver disappeared drops the still-owned result.
                let (tx, rx) = std::sync::mpsc::channel();
                drop(rx);
                drop(tx.send(stored));
            }
            _ => assert_eq!(
                returned(stored, exit == "failure").is_err(),
                exit == "failure"
            ),
        }
        assert_eq!(WIPED.with(Cell::get), Some(true), "{exit}");
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
