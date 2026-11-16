// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-EGRESS-CLASS (ABI-MIN3-INTERFACE §14): Stated egress classes are judged; two classes on one instance get two
//! PoolKeys; a class above 4 is INVALID.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-C1A; blocked (re-checked on dev 2026-11-16): the MIN-3 Need path is busbar-core-connector need.rs HostNeeds (it does not use the old FramerDoor) and needs a HostNeeds harness (custody, records, directory and binder doubles, a scripted NeedIo and Resolve) that busbar-core-connector does not have yet; and HostNeeds::fetch pools nothing (one hyper conn per FETCH, need/exchange.rs), so 'two PoolKeys' for the OPEN_WEB and DEFAULT FETCHes has no key to observe (C1's pool-first FETCH). The class > 4 clause is the driver's decode (C-NEED-DECODE, green here)"]
fn stated_classes_are_judged() {
    todo!("owner: W1-C1A (C-EGRESS-CLASS)")
}
