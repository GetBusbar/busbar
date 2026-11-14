// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A served transport entry names no layer.

use super::*;
use crate::support::{Knobs, TestDoor};

#[test]
fn an_entry_that_names_no_layer_is_served() {
    let door = TestDoor::new("msg", &["msg", "msgs"], &[], Knobs::default());
    assert_eq!(unlayered(&door), Ok(()));
}

#[test]
fn unlayered_refuses_a_door_that_names_a_layer() {
    let door = TestDoor::new("over", &["over"], &["under"], Knobs::default());
    let refused = unlayered(&door).expect_err("a door over a layer is not served");
    assert!(
        refused.contains("transport `over` names a transport it composes over"),
        "{refused}"
    );
}
