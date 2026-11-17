// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Every JSON-RPC producer allocates only its final output, even with heavy escaping (moved here from
//! `protocol_producer_custody.rs`, whose wipe proofs run on plain jemalloc). The count is
//! `stats_alloc`'s over the shipped allocator, process-wide (UNSAFE-MIN §4.4); this binary holds this
//! one test, so nothing else allocates while a producer is measured.
#![forbid(unsafe_code)]

use stats_alloc::{Region, StatsAlloc};
#[cfg(target_env = "msvc")]
use std::alloc::System as Base;
#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc as Base;

use busbar_contract::{json, jsonrpc};

/// The shipped allocator (jemalloc), counted process-wide by `stats_alloc`.
#[global_allocator]
static ALLOCATOR: StatsAlloc<Base> = StatsAlloc::new(Base);

fn measured_output(write: impl FnOnce() -> Vec<u8>) -> Vec<u8> {
    let region = Region::new(&ALLOCATOR);
    let out = write();
    let change = region.change();
    assert_eq!(change.allocations, 1, "only the final output is allocated");
    assert_eq!(change.reallocations, 0, "no payload allocation grows");
    out
}

#[test]
fn every_jsonrpc_producer_allocates_only_its_final_output_even_with_heavy_escaping() {
    const ID: &[u8] = br#""private-id""#;
    const BODY: &[u8] = br#"{"credential":"private-body"}"#;
    let text = "private\u{0}\n\r\t\"\\雪".repeat(4096);
    let result = measured_output(|| jsonrpc::result_bytes(ID, BODY));
    let request = measured_output(|| jsonrpc::request_bytes(ID, &text, Some(BODY)));
    let notification = measured_output(|| jsonrpc::notification_bytes(&text, Some(BODY)));
    let error = measured_output(|| jsonrpc::error_bytes(ID, i64::MIN, &text, Some(BODY)));
    let id: json::Value = json::parse_value(ID).unwrap();
    let body: json::Value = json::parse_value(BODY).unwrap();
    for (out, expected) in [
        (
            result,
            json::json!({"id": id, "jsonrpc": "2.0", "result": body}),
        ),
        (
            request,
            json::json!({"id": id, "jsonrpc": "2.0", "method": text, "params": body}),
        ),
        (
            notification,
            json::json!({"jsonrpc": "2.0", "method": text, "params": body}),
        ),
        (
            error,
            json::json!({"error": {"code": i64::MIN, "data": body, "message": text}, "id": id, "jsonrpc": "2.0"}),
        ),
    ] {
        assert_eq!(out, json::to_vec(&expected).unwrap());
    }
}
