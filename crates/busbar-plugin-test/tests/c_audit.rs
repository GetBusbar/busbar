// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-AUDIT (ABI-MIN3-INTERFACE §14): Each AUDIT verdict lands on the audit chain under the verified principal;
//! invalid rows dropped.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "re-checked 2026-11-16: partial cover in busbar-kernel (port_money_tests.rs:250 a verdict lands under the principal and an unknown verdict is refused; port_serve_tests.rs:558 rows written under the principal) keeps this ignored. Missing: a malformed AUDIT (action outside [a-z0-9_.:]{1,64}, resource over 256 bytes) is not dropped and audited as plane_audit_invalid (the name exists nowhere; port_session.rs ends the session with Violation::BadAudit and port_money.rs write_audit refuses only an empty action), no 16-row cap, and the plane audit actions are not in AUDIT_ACTIONS (crates/busbar-kernel/src/audit/auditlog.rs:280). OUTSTANDING row 5 (K8A tail)"]
fn audit_verdicts_land_under_the_verified_principal() {
    todo!("owner: W1-K8A (C-AUDIT)")
}
