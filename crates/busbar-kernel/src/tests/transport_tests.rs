// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/transport.rs` — the third axis.
//!
//! These are axis tests, not cell tests: what is being asserted is that the axis is a bounded label
//! and that framing a codec is genuinely inert, because the whole claim of this step is that the
//! seam costs nothing before anything depends on it.

use crate::handlers::request_handler;
use crate::operation::Operation;
use crate::transport::*;

#[test]
fn names_are_stable_and_distinct() {
    let names: Vec<_> = Transport::ALL.iter().map(|t| t.name()).collect();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), names.len(), "transport names must be unique");
    assert_eq!(Transport::Http.name(), "http");
    assert_eq!(Transport::JsonRpc.name(), "jsonrpc");
    assert_eq!(Transport::HttpJson.name(), "http+json");
    assert_eq!(Transport::Grpc.name(), "grpc");
}

// `the_a2a_legs_are_named_by_the_planes_wire_formats` MOVED to
// `tests/plane_dispatch_cross_plane.rs`: it asserts `wire_format_names("a2a")` against the REAL a2a
// plane's declared wire formats, which needs the real roster registered — an integration-test
// target, never this `#[cfg(test)]` unit module (see that file's header).

/// FRAMING IS IDENTITY ON `Http`, AND THE CODEC IS UNTOUCHED. The framed cell hands back the very
/// codec it was given — same operation, same vtable — so nothing a codec does can depend on having
/// been framed. That is what makes "the codec never learns the transport" a fact rather than a
/// convention.
#[test]
fn framing_carries_the_codec_through_unchanged() {
    // The residual-default protocol: the one a request no dialect claimed is spoken in, read off the
    // registry rather than named here.
    let protocol = crate::proto::registry::residual_default_protocol()
        .expect("a residual-default protocol is registered");
    let rh = request_handler(protocol).unwrap_or_else(|| panic!("{protocol} is registered"));
    let codec = rh
        .operation_handler(Operation::CHAT)
        .unwrap_or_else(|| panic!("{protocol} serves chat"));
    let framed = crate::handlers::frame(Transport::Http, Operation::CHAT, codec);

    assert_eq!(framed.operation, Operation::CHAT);
    assert_eq!(framed.transport(), Transport::Http);
    assert_eq!(framed.name(), Operation::CHAT.name());
    assert_eq!(framed.transport().name(), "http");
    // The codec is the SAME object, not a wrapper around it.
    assert!(std::ptr::eq(
        std::ptr::from_ref::<dyn crate::handlers::OperationHandler>(framed.op_handler).cast::<u8>(),
        std::ptr::from_ref::<dyn crate::handlers::OperationHandler>(codec).cast::<u8>(),
    ));
    // And every capability the engine reads off the cell still answers exactly as the bare codec
    // does: framing added no behaviour.
    assert_eq!(framed.streaming(), codec.streaming());
    assert_eq!(framed.taps_nonstream_usage(), codec.taps_usage());
}

/// EVERY PROTOCOL IN THE MATRIX STILL FRAMES ON `Http`. Every registered protocol, each framed
/// through its own registered codec for every verb it declares. The point of keeping this unchanged
/// when the axis grew two variants is that the split was NOT a relabelling of what was already
/// there: these cells ride the same variant, with the same name, that they rode before the
/// agent-protocol legs existed. The protocols are read off the registry, not listed here, so a
/// protocol added to it is framed the day it lands.
#[test]
fn all_seven_protocols_frame_over_http() {
    let decls = crate::proto::registry::registry().decls();
    assert_eq!(
        decls.len(),
        7,
        "core's test binary registers seven protocols; an empty registry would pass vacuously"
    );
    let mut cells = 0;
    for decl in decls {
        let protocol = decl.name;
        assert!(!decl.verbs.is_empty(), "{protocol} declares no verb");
        for &operation in decl.verbs {
            let rh =
                request_handler(protocol).unwrap_or_else(|| panic!("{protocol} is registered"));
            let codec = rh
                .operation_handler(operation)
                .unwrap_or_else(|| panic!("{protocol} serves {}", operation.name()));
            let framed = crate::handlers::frame(Transport::Http, operation, codec);
            assert_eq!(framed.transport(), Transport::Http, "{protocol}");
            assert_eq!(framed.operation, operation, "{protocol}");
            cells += 1;
        }
    }
    assert!(
        cells >= decls.len(),
        "every protocol framed at least one cell"
    );
}
