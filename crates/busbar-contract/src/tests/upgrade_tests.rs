// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MIGRATE-ON-BOOT r41 §9 C1 reds (l) and (p): on the upgrade boot of an unstamped config, the
//! loader's unknown-module refusal carries the generic "upgrade to 1.5.5 first" line.

use super::*;

/// (l) and (p): an unstamped `module: redis` (1.5.5 itself refused that retired name) is the
/// loader's unknown-module refusal, and on the upgrade boot it says to upgrade to 1.5.5 first and
/// to back up every store, with the docs anchor. A stamped boot's refusal is the loader's alone.
#[test]
fn an_unknown_module_on_the_upgrade_boot_carries_the_upgrade_line() {
    let refusal = "store.module: no store plugin named or aliased 'redis' is installed";
    let unstamped = unknown_module_on(refusal.to_owned(), true);
    assert!(unstamped.starts_with(refusal), "{unstamped}");
    assert!(unstamped.ends_with(UPGRADE_FIRST), "{unstamped}");
    for part in [
        "upgrade to 1.5.5 first",
        "back up every store before you do",
        "docs/migration-1.6, Before you start",
    ] {
        assert!(unstamped.contains(part), "{part}: {unstamped}");
    }
    assert_eq!(unknown_module_on(refusal.to_owned(), false), refusal);
    mark_unstamped();
    assert_eq!(unknown_module(refusal.to_owned()), unstamped);
}
