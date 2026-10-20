// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn only(attr: &str) -> bool {
    parse_attr(attr).expect("a cfg attribute").is_test_only()
}

fn needs_test(attr: &str) -> bool {
    parse_attr(attr).expect("a cfg attribute").requires_test()
}

#[test]
fn any_test_with_a_shipping_feature_is_not_test_only() {
    // `root-admin` is on the binary's default line.
    assert!(!only("#[cfg(any(test, feature = \"root-admin\"))]"));
    assert!(!needs_test("#[cfg(any(test, feature = \"root-admin\"))]"));
    assert!(!only(
        "#[cfg(any(feature = \"test-support\", feature = \"root-admin\"))]"
    ));
    assert!(!only(
        "#[cfg(any(test, feature = \"test-support\", feature = \"root-admin\"))]"
    ));
    assert!(!only("#[cfg(any(test, unix))]"));
}

#[test]
fn any_test_with_only_test_only_arms_stays_test_only() {
    for f in TEST_ONLY_FEATURES {
        let attr = format!("#[cfg(any(test, feature = \"{f}\"))]");
        assert!(only(&attr), "{attr}");
        assert!(needs_test(&attr), "{attr}");
    }
    assert!(only(
        "#[cfg(any(test, feature = \"test-support\", feature = \"conformance\"))]"
    ));
    assert!(only("#[cfg( any( test , feature = \"test-seal\" ) )]"));
}

#[test]
fn all_with_test_and_bare_test_stay_test_only() {
    assert!(only("#[cfg(test)]"));
    assert!(only("#[cfg(all(test, feature = \"root-admin\"))]"));
    assert!(only("#[cfg(all(test, not(target_env = \"musl\")))]"));
    assert!(only(
        "#[cfg(all(unix, any(test, feature = \"test-harness\")))]"
    ));
}

#[test]
fn not_is_the_shipping_arm() {
    assert!(!only("#[cfg(not(test))]"));
    assert!(!only("#[cfg(any(test, not(test)))]"));
    assert!(!only("#[cfg(all(not(test), unix))]"));
}

#[test]
fn a_bare_feature_is_test_only_but_does_not_require_test() {
    assert!(only("#[cfg(feature = \"test-support\")]"));
    assert!(!needs_test("#[cfg(feature = \"test-support\")]"));
    assert!(!only("#[cfg(feature = \"root-admin\")]"));
}

#[test]
fn the_declared_list_names_no_default_feature() {
    for f in TEST_ONLY_FEATURES {
        assert!(!["root-admin", "openapi-schema"].contains(f), "{f}");
    }
}
