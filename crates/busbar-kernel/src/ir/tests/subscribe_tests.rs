// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/ir/subscribe.rs`.

use super::*;
use crate::ir::facts::{ContentItem, IrFacts};
use crate::operation::Operation;

/// A subscription target: an opaque resource URI the IR carries verbatim.
const TARGET: &str = "resource://inbox";

#[test]
fn subscribe_projects_target_name_and_never_streams() {
    let req = SubscribeReq {
        intent: SubscribeIntent::Register,
        target: TARGET.into(),
        extra: Default::default(),
    };
    assert_eq!(IrFacts::verb(&req), Operation::SUBSCRIBE);
    // Registering is answered once — it is NOT a stream.
    assert!(!IrFacts::wants_stream(&req));
    let items = req.content();
    assert_eq!(items.len(), 1);
    assert!(matches!(items[0], ContentItem::Text { .. }));
    assert_eq!(items[0].screenable_text(), TARGET);
    assert_eq!(req.shape().text_chars, TARGET.len());
    // The same projection holds for a deregister — one shape, one intent field.
    let dereg = SubscribeReq {
        intent: SubscribeIntent::Deregister,
        target: TARGET.into(),
        extra: Default::default(),
    };
    assert_eq!(dereg.content()[0].screenable_text(), TARGET);
}
