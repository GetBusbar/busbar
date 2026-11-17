// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn precedence_follows_semver_section_11() {
    assert!(!version_at_least("1.6.0-rc.1", "1.6.0"));
    assert!(version_at_least("1.6.0-rc.10", "1.6.0-rc.2"));
    assert!(version_at_least("1.6.0-rc.02", "1.6.0-rc.2"));
    assert!(!version_at_least("1.6.0-alpha", "1.6.0-alpha.1"));
    assert!(!version_at_least("1.6.0-1", "1.6.0-alpha"));
    assert!(version_at_least("1.6.0+b1", "1.6.0+b2"));
    assert!(version_at_least("1.6.0", ""));
    assert!(!version_at_least("1.6", "1.0.0"));
    assert!(!version_at_least("1.6.0", "v1.0.0"));
}

#[test]
fn authored_floors_refuse_empty_or_foreign_identifiers() {
    for good in ["1.6.0", "1.6.0-rc.1", "1.6.0-rc.1+build.7", "0001.0.0"] {
        assert!(valid_authored(good), "{good}");
    }
    for bad in [
        "1.6.0-",
        "1.6.0-rc..1",
        "1.6.0-rc_1",
        "1.6.0+",
        "v1.6.0",
        "1.6",
    ] {
        assert!(!valid_authored(bad), "{bad}");
    }
    assert!(
        version_at_least("1.6.0-rc_2", "1.6.0-rc_1"),
        "a stored legacy value still reads"
    );
}
