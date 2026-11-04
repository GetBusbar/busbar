// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A field block must never reallocate after it starts copying credential values.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use hyper::header::{HeaderMap, HeaderValue};

busbar_contract::hyper_io!(hyper::body::Bytes);

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    static REALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

struct Counting;

fn count(counter: &'static std::thread::LocalKey<Cell<usize>>) {
    let _ = COUNTING.try_with(|active| {
        if active.get() {
            let _ = counter.try_with(|value| value.set(value.get() + 1));
        }
    });
}

// SAFETY: every allocation operation delegates unchanged to System; no payload is read.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count(&ALLOCATIONS);
        // SAFETY: the caller provides a valid allocation layout.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: the caller provides the live allocation and its original layout.
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        count(&REALLOCATIONS);
        // SAFETY: the caller provides the live allocation, its layout and a valid new size.
        unsafe { System.realloc(pointer, layout, size) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn measured(headers: &HeaderMap, also: &[&str]) -> (Vec<u8>, usize, usize) {
    ALLOCATIONS.with(|value| value.set(0));
    REALLOCATIONS.with(|value| value.set(0));
    COUNTING.with(|active| active.set(true));
    let block = hyper_io::field_block(headers, also);
    COUNTING.with(|active| active.set(false));
    (
        block,
        ALLOCATIONS.with(Cell::get),
        REALLOCATIONS.with(Cell::get),
    )
}

#[test]
fn credential_fields_are_copied_once_without_releasing_intermediate_buffers() {
    let credential = format!("Bearer {}", "secret-credential".repeat(128));
    let mut headers = HeaderMap::new();
    headers.insert("authorization", HeaderValue::from_str(&credential).unwrap());
    headers.append("x-visible", HeaderValue::from_static("first"));
    headers.append("x-visible", HeaderValue::from_static("second"));
    headers.insert("connection", HeaderValue::from_static("x-hop"));
    headers.insert("x-hop", HeaderValue::from_static("omit nominated"));
    headers.insert("x-exclude", HeaderValue::from_static("omit explicitly"));
    headers.insert("content-length", HeaderValue::from_static("42"));

    let (block, allocations, reallocations) = measured(&headers, &["x-exclude"]);
    assert_eq!(allocations, 1, "the complete field block needs one owner");
    assert_eq!(
        reallocations, 0,
        "growth can abandon an unwiped credential copy"
    );
    assert_eq!(
        block,
        format!("authorization: {credential}\r\nx-visible: first\r\nx-visible: second\r\n")
            .as_bytes(),
        "sizing preserves values, repeated-field order and filtering"
    );
}

#[test]
fn an_entirely_filtered_field_block_allocates_nothing() {
    let mut headers = HeaderMap::new();
    headers.insert("connection", HeaderValue::from_static("x-hop"));
    headers.insert("x-hop", HeaderValue::from_static("omit nominated"));
    headers.insert("content-length", HeaderValue::from_static("0"));
    let (block, allocations, reallocations) = measured(&headers, &[]);
    assert!(block.is_empty());
    assert_eq!((allocations, reallocations), (0, 0));
}
