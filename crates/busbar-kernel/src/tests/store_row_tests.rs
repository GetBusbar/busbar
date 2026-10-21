// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A store crate's `linked::STORE` in either shape reads as the one row the root installs (status
//! rows 159 and 194): the door-function row as it is, the `MACRO_DOOR` row as the door function it
//! names.

use super::{LinkedStore, LinkedStoreDoor, StoreRow};
use crate::test_support::store_double;

const BY_FN: LinkedStore = StoreRow(store_double::STORE).linked();
const BY_MACRO: LinkedStore = StoreRow::<LinkedStoreDoor>((
    store_double::STORE.0,
    store_double::STORE.1,
    store_double::MACRO_DOOR,
    store_double::STORE.3,
))
.linked();

#[test]
fn a_store_row_reads_alike_by_door_function_or_by_macro_door() {
    assert_eq!(
        (BY_FN.0, BY_FN.1, BY_FN.3),
        (BY_MACRO.0, BY_MACRO.1, BY_MACRO.3)
    );
    assert_eq!(BY_FN.2 as usize, BY_MACRO.2 as usize, "one door function");
    assert_eq!(BY_FN.2 as usize, store_double::door as *const () as usize);
}
