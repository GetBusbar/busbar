// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-LIFT (ABI-MIN3-INTERFACE §14): Literal credentials lifted to references before any write (canary scan of
//! reports, logs and audit).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "blocked: needs the secret-vault and auth-ldap 1.5.5 fixtures and the C-MIGRATE harness (busbar-migrate settle.rs LIFT) plus a boot; not a dev-dependency of this crate"]
fn literal_credentials_are_lifted() {
    todo!("blocked: needs the secret-vault and auth-ldap 1.5.5 fixtures and the C-MIGRATE harness (busbar-migrate settle.rs LIFT) plus a boot; not a dev-dependency of this crate (C-LIFT)")
}
