// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-SCHEME (ABI-MIN3-INTERFACE §14): Plaintext `http://` FETCH by stated class (lib.rs:211-213).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-C1A (blocked: plaintext http FETCH by stated class is judged in busbar-core-connector (need/policy.rs admit_fetch), not a dev-dependency of this crate; the old lib.rs:211-213 rule it cites is superseded by transport_verdict)"]
fn plaintext_fetch_by_class() {
    todo!("owner: W1-C1A (C-SCHEME)")
}
