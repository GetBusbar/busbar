// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SINGLE-PATH SP-P9: the body a rewrite leaves is copied once, out of the plane's arena, and
//! that copy becomes the unit's body; it is not copied again into the unit. Counted by the
//! dev-only stage probes (`busbar_contract::stage_probe`).

use super::*;
use busbar_contract::stage_probe::{Derive, Scope};

#[tokio::test]
async fn rewritten_body_copied_once() {
    let (_, g) = gate(None);
    let hooks = bound(
        vec![(
            Duration::from_millis(500),
            Arc::new(Rewriter {
                name: "rewriter",
                refuses_failed_rewrite: false,
            }),
        )],
        vec![(0, g)],
    );
    let r = rig_with_hooks(
        Way::Double,
        BufferCaps::default(),
        Book::default(),
        Some(hooks),
    );
    let (steps, far, caller) = (
        TestUnits::passing(),
        Far::new(&["ok"], &[b"done"]),
        Caller::default(),
    );
    let units = r
        .driver
        .unit(&steps, &far, &caller, arrival("/call", b"user:hello"), 0);

    let scope = Scope::open();
    assert!(matches!(drive(&units).await, Outcome::Completed));

    assert_eq!(r.projects().len(), 2, "the view, then the rewrite");
    let sent = far.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0].body, b"user:COMPRESSED",
        "the attempt carries the body the rewrite left"
    );
    assert_eq!(
        scope.count(Derive::ProjectCopy),
        1,
        "the rewritten body is copied out of the arena once and moved into the unit"
    );
}
