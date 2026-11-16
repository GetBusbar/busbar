// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A field block must never reallocate after it starts copying credential values.

use std::sync::Mutex;

use hyper::header::{HeaderMap, HeaderValue};
use stats_alloc::StatsAlloc;
#[cfg(target_env = "msvc")]
use std::alloc::System as Base;
#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc as Base;

busbar_contract::hyper_io!(hyper::body::Bytes);

/// The shipped allocator (jemalloc), counted process-wide by `stats_alloc`.
#[global_allocator]
static ALLOCATOR: StatsAlloc<Base> = StatsAlloc::new(Base);

/// One measurement at a time: the counts are process-wide, so two tests must not overlap.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

fn measured(headers: &HeaderMap, also: &[&str]) -> (Vec<u8>, usize, usize) {
    let _alone = ONE_AT_A_TIME.lock().unwrap_or_else(|p| p.into_inner());
    let before = ALLOCATOR.stats();
    let block = hyper_io::field_block(headers, also);
    let after = ALLOCATOR.stats();
    (
        block,
        after.allocations - before.allocations,
        after.reallocations - before.reallocations,
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
