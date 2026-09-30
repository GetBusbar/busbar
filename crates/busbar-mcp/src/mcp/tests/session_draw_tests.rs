// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn owner() -> Owner {
    Owner {
        principal: "p".into(),
        credential: "k".into(),
    }
}

/// RED (reviewer follow-up 3): the host CSPRNG is the only source. A failed host draw mints
/// nothing, and nothing else is drawn from in its place.
#[test]
fn red_a_failed_host_draw_mints_no_session() {
    let failing = SessionServe::drawing_from(|_| false);
    assert_eq!(
        failing.mint(&owner(), Revision::R2025_11_25, Carriage::Endpoint, 0),
        None
    );
    assert!(lock(&failing.table).is_empty());
    let working = SessionServe::drawing_from(|out| {
        out.fill(0x5a);
        true
    });
    let id = working
        .mint(&owner(), Revision::R2025_11_25, Carriage::Endpoint, 0)
        .expect("a working draw mints");
    assert_eq!(id, "5a".repeat(16));
}
