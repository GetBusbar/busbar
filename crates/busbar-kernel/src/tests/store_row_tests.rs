// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A store crate's `linked::STORE` reads as the one row the root installs (status rows 159 and
//! 194): the expand step's `StoreRow` wrapper and `LinkedStoreDoor` name hand back the row as it
//! is, its `MACRO_DOOR` naming the door function.

use super::{LinkedStore, LinkedStoreDoor, StoreRow};
use crate::test_support::store_double;

const BY_ROW: LinkedStore = StoreRow(store_double::STORE).linked();
const BY_MACRO: LinkedStore = StoreRow::<LinkedStoreDoor>((
    store_double::STORE.0,
    store_double::STORE.1,
    store_double::MACRO_DOOR,
    store_double::STORE.3,
))
.linked();

#[test]
fn a_store_row_reads_alike_by_row_or_by_macro_door() {
    assert_eq!(
        (BY_ROW.0, BY_ROW.1, BY_ROW.3),
        (BY_MACRO.0, BY_MACRO.1, BY_MACRO.3)
    );
    assert_eq!(
        BY_ROW.2.door_fn() as usize,
        BY_MACRO.2.door_fn() as usize,
        "one door function"
    );
    assert_eq!(BY_ROW.2.door_fn() as usize, store_double::door as usize);
}
