// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-SCHEME (ABI-MIN3-INTERFACE §14): Plaintext `http://` FETCH by stated class (lib.rs:211-213).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-C1A; blocked (re-checked on dev 2026-11-16): HostNeeds::fetch (busbar-core-connector need.rs) gates plaintext only by transport_verdict over the caller's Accept and never applies the guard's scheme_admits(class, secure), which TRANSPORT-SECURITY-POLICY §1 keeps (both must admit), so a plaintext OPEN_WEB FETCH under accept: plaintext is admitted and the refusal clause is red (the admitted classes read as under accept: plaintext); the arm then moves into busbar-core-connector beside HostNeeds, with a HostNeeds harness (custody, records, directory and binder doubles, a scripted NeedIo and Resolve) that busbar-core-connector does not have yet"]
fn plaintext_fetch_by_class() {
    todo!("owner: W1-C1A (C-SCHEME)")
}
