// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::{per_target, release_asset_for};

#[test]
fn a_pin_names_its_release_asset_for_a_target() {
    let a = release_asset_for("Acme/busbar-store-stub@v1.6.0", "x86_64-unknown-linux-gnu")
        .expect("a pin");
    assert_eq!(
        a.filename,
        "busbar-store-stub-1.6.0-x86_64-unknown-linux-gnu.tar.gz"
    );
    assert_eq!(
        a.url,
        "https://github.com/Acme/busbar-store-stub/releases/download/v1.6.0/\
         busbar-store-stub-1.6.0-x86_64-unknown-linux-gnu.tar.gz"
    );
    for bad in [
        "Acme/busbar-store-stub",
        "busbar-store-stub@v1",
        "/x@v1",
        "a/b/c@v1",
    ] {
        assert!(release_asset_for(bad, "t").is_none(), "{bad}");
    }
}

/// The asset's file name is joined under a staging directory, so a tag can never make it more
/// than one plain path component.
#[test]
fn a_tag_never_makes_the_asset_name_leave_its_directory() {
    for bad in [
        "Acme/busbar-store-stub@v1/../../escape",
        "Acme/busbar-store-stub@v1/x",
        "Acme/busbar-store-stub@../v1",
        "Acme/busbar-store-stub@v1\\..\\escape",
    ] {
        assert!(release_asset_for(bad, "t").is_none(), "{bad}");
    }
    assert!(release_asset_for("Acme/busbar-store-stub@v1.6.0", "t").is_some());
}

#[test]
fn only_a_github_pins_own_url_falls_back_to_the_per_target_asset() {
    let url = "https://github.com/Acme/busbar-store-stub/releases/download/v1.6.0/busbar-store-stub.tar.gz";
    let other = per_target(url).expect("a GitHub pin's URL");
    assert!(
        other.starts_with(
            "https://github.com/Acme/busbar-store-stub/releases/download/v1.6.0/busbar-store-stub-1.6.0-"
        ) && other.ends_with(".tar.gz"),
        "{other}"
    );
    for not in [
        "https://example.com/Acme/busbar-store-stub/releases/download/v1.6.0/busbar-store-stub.tar.gz",
        "https://github.com/Acme/busbar-store-stub/releases/download/v1.6.0/other.tar.gz",
        "https://github.com/Acme/busbar-store-stub/archive/v1.6.0.tar.gz",
    ] {
        assert!(per_target(not).is_none(), "{not}");
    }
}
