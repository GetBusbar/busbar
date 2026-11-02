// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn a_resolved_lookup_is_returned_untouched() {
    let found =
        registered(|| Some(("entry", "cfg"))).expect("a lookup that resolved must not be refused");
    assert_eq!(found, ("entry", "cfg"));
}
