// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Observe registered, initialized request bytes while their allocation is still live.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use busbar_contract::abi::sdk::exchange::{Exchange, Request};
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

fn request() -> Request {
    Request {
        method: b"private-method".to_vec(),
        target: b"/private-target?credential=private-query".to_vec(),
        fields: vec![(b"private-name".to_vec(), b"private-value".to_vec())],
        body: br#"{"credential":"private-body"}"#.to_vec(),
        timeout_ms: Request::default().timeout_ms,
    }
}

#[derive(Clone, Copy, Debug)]
enum Field {
    Method,
    Target,
    Name,
    Value,
    Body,
}

impl Field {
    fn bytes(self, request: &Request) -> &[u8] {
        match self {
            Self::Method => &request.method,
            Self::Target => &request.target,
            Self::Name => &request.fields[0].0,
            Self::Value => &request.fields[0].1,
            Self::Body => &request.body,
        }
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
fn the_registered_payload_witness_distinguishes_plain_and_wiped_vectors() {
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
fn request_payloads_wipe_on_return_failure_cancel_clone_and_last_owner_drop() {
    for field in [
        Field::Method,
        Field::Target,
        Field::Name,
        Field::Value,
        Field::Body,
    ] {
        for exit in [
            Exit::Return,
            Exit::Failure,
            Exit::Cancel,
            Exit::Clone,
            Exit::Shared,
            Exit::Transfer,
            Exit::Panic,
        ] {
            let mut request = request();
            if matches!(exit, Exit::Clone) {
                let clone = request.clone();
                drop(request);
                request = clone;
            }
            watch(field.bytes(&request));
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
                    assert_eq!(WIPED.with(Cell::get), None);
                    drop(pending);
                }
                Exit::Shared => {
                    let shared = Arc::new(request);
                    let last = Arc::clone(&shared);
                    drop(shared);
                    assert_eq!(WIPED.with(Cell::get), None);
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
                    assert_eq!(WIPED.with(Cell::get), None);
                    drop(final_owner);
                }
                _ => {
                    let fail = matches!(exit, Exit::Failure);
                    assert_eq!(returned(request, fail).is_err(), fail);
                }
            }
            assert_eq!(WIPED.with(Cell::get), Some(true), "{field:?} on {exit:?}");
        }
    }
}

#[test]
fn framing_transfers_the_body_without_releasing_it_before_the_exchange_owner() {
    let request = request();
    watch(&request.body);
    let exchange = Exchange::request(request).expect("the request frames");
    assert_eq!(WIPED.with(Cell::get), None);
    drop(exchange);
    assert_eq!(WIPED.with(Cell::get), Some(true));
}

#[test]
fn a_refused_request_wipes_the_body_it_never_sent() {
    let mut request = request();
    request.fields[0].0.insert(0, b':');
    watch(&request.body);
    assert!(Exchange::request(request).is_err());
    assert_eq!(WIPED.with(Cell::get), Some(true));
}
