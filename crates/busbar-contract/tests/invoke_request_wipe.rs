// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Observe only registered, initialized request strings before their allocation is released.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use busbar_contract::ir::invoke::InvokeReq;
use serde_json::{json, Value};

thread_local! {
    static WATCH: Cell<Option<(*mut u8, usize)>> = const { Cell::new(None) };
    static WIPED: Cell<Option<bool>> = const { Cell::new(None) };
}

struct InspectBeforeFree;

// SAFETY: allocations are forwarded unchanged to System. Only the initialized string prefix
// registered by this thread is observed, while its matching allocation still belongs to it.
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
                        // SAFETY: these bytes were initialized String contents when registered,
                        // and the matching live allocation has not yet reached System.dealloc.
                        // No spare capacity, allocation padding, or freed memory is read.
                        unsafe { watched.add(index).read_volatile() == 0 }
                    });
                let _ = WIPED.try_with(|result| result.set(Some(wiped)));
            }
        });
        // SAFETY: pointer and layout match the allocator caller's live allocation.
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: InspectBeforeFree = InspectBeforeFree;

fn watch(bytes: &[u8]) {
    assert!(!bytes.is_empty());
    WATCH.with(|watched| watched.set(Some((bytes.as_ptr().cast_mut(), bytes.len()))));
    WIPED.with(|result| result.set(None));
}

fn request() -> InvokeReq {
    InvokeReq {
        tool: "private-tool".to_string(),
        arguments: json!({
            "private-argument-name": [
                "private-argument-value",
                {"private-nested-name": "private-nested-value"}
            ]
        }),
        extra: [(
            "private-source".to_string(),
            [(
                "private-extra-name".to_string(),
                Value::String("private-extra-value".to_string()),
            )]
            .into_iter()
            .collect(),
        )]
        .into_iter()
        .collect(),
    }
}

fn field<'a>(request: &'a InvokeReq, name: &str) -> &'a [u8] {
    let arguments = request.arguments.as_object().unwrap();
    let nested = arguments["private-argument-name"][1].as_object().unwrap();
    let extras = &request.extra["private-source"];
    match name {
        "tool" => request.tool.as_bytes(),
        "argument-name" => arguments.keys().next().unwrap().as_bytes(),
        "argument-value" => arguments["private-argument-name"][0]
            .as_str()
            .unwrap()
            .as_bytes(),
        "nested-name" => nested.keys().next().unwrap().as_bytes(),
        "nested-value" => nested["private-nested-name"].as_str().unwrap().as_bytes(),
        "extra-source" => request.extra.keys().next().unwrap().as_bytes(),
        "extra-name" => extras.keys().next().unwrap().as_bytes(),
        "extra-value" => extras["private-extra-name"].as_str().unwrap().as_bytes(),
        _ => unreachable!(),
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
fn the_registered_payload_witness_distinguishes_plain_and_wiped_strings() {
    let plain = "plain-initialized-control".to_string();
    watch(plain.as_bytes());
    drop(plain);
    assert_eq!(WIPED.with(Cell::get), Some(false));

    let wiped = zeroize::Zeroizing::new("wiped-initialized-control".to_string());
    watch(wiped.as_bytes());
    drop(wiped);
    assert_eq!(WIPED.with(Cell::get), Some(true));
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
            let mut request = request();
            if exit == "clone" {
                let clone = request.clone();
                drop(request);
                request = clone;
            }
            watch(field(&request, name));
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
                    assert_eq!(WIPED.with(Cell::get), None);
                    drop(pending);
                }
                "shared" => {
                    let shared = Arc::new(request);
                    let last = Arc::clone(&shared);
                    drop(shared);
                    assert_eq!(WIPED.with(Cell::get), None);
                    drop(last);
                }
                "transfer" => {
                    let final_owner = InvokeReq {
                        tool: std::mem::take(&mut request.tool),
                        arguments: std::mem::take(&mut request.arguments),
                        extra: std::mem::take(&mut request.extra),
                    };
                    drop(request);
                    assert_eq!(WIPED.with(Cell::get), None);
                    drop(final_owner);
                }
                _ => {
                    assert_eq!(
                        returned(request, exit == "failure").is_err(),
                        exit == "failure"
                    );
                }
            }
            assert_eq!(WIPED.with(Cell::get), Some(true), "{name} on {exit}");
        }
    }
}
