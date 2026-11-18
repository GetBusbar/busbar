// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A checkpoint's names are shared, not copied (GROUP-records K1b): cloning the records that hold
//! them allocates nothing, where the `String` fields they replaced allocated once each. The
//! `String` control below is the old shape, measured in the same run.

use busbar_contract::abi::sdk::test_support::watch::Watch;
use busbar_contract::kept::off_path::text;
use busbar_kernel::governance::unit_checkpoint::partitions::{ClassSet, SessionOrigin};
use busbar_kernel::governance::unit_checkpoint::UnitTarget;

#[global_allocator]
static A: Watch = Watch::new();

/// The shape these records had: one `String` per name.
#[derive(Clone)]
struct Old {
    instance: String,
    lane: String,
    provider: Option<String>,
}

#[test]
fn cloning_the_name_records_allocates_nothing_where_the_strings_allocated() {
    let old = Old {
        instance: "native".into(),
        lane: "native\u{1f}".into(),
        provider: Some("openai".into()),
    };
    let origin = SessionOrigin {
        instance: text("native"),
        lane: text("native\u{1f}"),
        provider: Some(text("openai")),
    };
    let target = UnitTarget {
        bucket: text("group-a"),
        window: 3,
        group: Some(text("g")),
    };
    let classes = ClassSet::from(["tokens.in", "tokens.out"]);

    let before = A.armed_here(b"", || drop(std::hint::black_box(old.clone())));
    assert_eq!(
        before.allocs, 3,
        "the String shape: one allocation per name"
    );

    let after = A.armed_here(b"", || {
        drop(std::hint::black_box(origin.clone()));
        drop(std::hint::black_box(target.clone()));
        drop(std::hint::black_box(classes.clone()));
    });
    assert_eq!(
        after.allocs, 0,
        "the shared shape: a clone shares every name"
    );
    assert!(classes.contains("tokens.out") && !classes.contains("tokens"));
}
