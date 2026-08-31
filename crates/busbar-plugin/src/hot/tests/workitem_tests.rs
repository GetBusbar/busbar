// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-plugin/src/hot/workitem.rs`.

use super::*;

#[test]
fn workitem_can_represent_request_response() {
    let req = b"hello";
    let wi = WorkItem::new(
        InboundHandle::finite_buffer(req),
        EmitHandle::new(EmitKind::Reply, 42),
    );
    assert_eq!(wi.inbound.kind, InboundKind::FiniteBuffer);
    assert_eq!(wi.inbound.len, req.len());
    assert_eq!(wi.emit.kind, EmitKind::Reply);
}

#[test]
fn workitem_can_represent_absent_inbound_and_emit() {
    // The reserved pull-class shape: host-initiated, reply-less. The keystone MUST express it
    // now so adding that carrier later is an append-only bump, not a reshape.
    let wi = WorkItem::new(InboundHandle::absent(), EmitHandle::absent());
    assert_eq!(wi.inbound.kind, InboundKind::Absent);
    assert_eq!(wi.emit.kind, EmitKind::Absent);
    assert!(wi.inbound.ptr.is_null());
}

#[test]
fn workitem_can_represent_duplex_session() {
    // Independent in/out: a streamed inbound and an unsolicited push.
    let wi = WorkItem::new(
        InboundHandle::stream(7),
        EmitHandle::new(EmitKind::Unsolicited, 9),
    );
    assert_eq!(wi.inbound.kind, InboundKind::Stream);
    assert_eq!(wi.inbound.id, 7);
    assert_eq!(wi.emit.kind, EmitKind::Unsolicited);
    assert_eq!(wi.emit.id, 9);
}

#[test]
fn all_reserved_kinds_are_declared() {
    // Witness: every reserved tag exists from day one (compile-time exhaustiveness).
    for k in [
        InboundKind::Absent,
        InboundKind::FiniteBuffer,
        InboundKind::Stream,
    ] {
        let _ = k as u8;
    }
    for k in [
        EmitKind::Absent,
        EmitKind::Reply,
        EmitKind::Stream,
        EmitKind::Unsolicited,
    ] {
        let _ = k as u8;
    }
}
