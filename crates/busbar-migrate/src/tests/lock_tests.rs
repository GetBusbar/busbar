// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! 5L: one holder per config directory; a dead holder's new file is swept.

use std::time::Duration;

use super::*;
use crate::scratch::Scratch;

#[test]
fn a_second_holder_waits_and_is_refused_past_the_bound() {
    let scratch = Scratch::new();
    let path = scratch.config("listen: x\n");
    let held = Held::take(&path).expect("first holder");
    let refused = Held::take_within(&path, Duration::from_millis(300))
        .err()
        .expect("blocked");
    assert_eq!(refused.word(), "CONFIG");
    assert!(
        refused.to_string().contains("another busbar is upgrading"),
        "{refused}"
    );
    drop(held);
    assert!(Held::take_within(&path, Duration::from_millis(300)).is_ok());
}

#[test]
fn the_holder_sweeps_only_new_files_a_dead_holder_left() {
    let scratch = Scratch::new();
    let path = scratch.config("listen: x\n");
    for name in [
        "config.yaml.busbar-new.77",
        "config.yaml.1.5.5",
        "other.yaml.busbar-new.77",
    ] {
        std::fs::write(scratch.dir().join(name), "x").unwrap();
    }
    let _held = Held::take(&path).unwrap();
    assert_eq!(
        scratch.names(),
        [
            "config.yaml",
            "config.yaml.1.5.5",
            "config.yaml.busbar-lock",
            "other.yaml.busbar-new.77"
        ]
    );
}
