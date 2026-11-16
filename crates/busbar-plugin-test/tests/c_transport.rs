// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-TRANSPORT (ABI-MIN3-INTERFACE §14): TRANSPORT-SECURITY-POLICY §8 tests 1-15 (replaces C-TLS-REFUSED, rule
//! 14). Test 11 is W1-X1's source check. The generic ENDPOINT match is `FakeNeeds::undeclared`, run by every suite.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K7"]
fn transport_plaintext_refused_at_check() {
    todo!("owner: W1-K7 (C-TRANSPORT)")
}

#[test]
#[ignore = "owner: W1-K7"]
fn transport_no_loopback_exemption() {
    todo!("owner: W1-K7 (C-TRANSPORT)")
}

#[test]
#[ignore = "owner: W1-C1A"]
fn transport_no_unix_exemption() {
    todo!("owner: W1-C1A (C-TRANSPORT)")
}

#[test]
#[ignore = "owner: W1-C1A"]
fn transport_in_process_needs_nothing() {
    todo!("owner: W1-C1A (C-TRANSPORT)")
}

#[test]
#[ignore = "owner: W1-C1A"]
fn transport_accept_plaintext_visible() {
    todo!("owner: W1-C1A (C-TRANSPORT)")
}

#[test]
#[ignore = "owner: W1-K8C"]
fn admin_dry_run_runtime_transport_and_health() {
    todo!("owner: W1-K8C (C-TRANSPORT)")
}

#[test]
#[ignore = "owner: W1-C1A"]
fn transport_accept_unverified_tls() {
    todo!("owner: W1-C1A (C-TRANSPORT)")
}

#[test]
#[ignore = "owner: W1-K7"]
fn transport_setting_validation() {
    todo!("owner: W1-K7 (C-TRANSPORT)")
}

#[test]
#[ignore = "owner: W1-C1A"]
fn transport_need_time_authoritative() {
    todo!("owner: W1-C1A (C-TRANSPORT)")
}

#[test]
#[ignore = "owner: W1-C1A"]
fn transport_verify_options() {
    todo!("owner: W1-C1A (C-TRANSPORT)")
}

#[test]
#[ignore = "owner: W1-L2"]
fn endpoint_record_decode() {
    todo!("owner: W1-L2 (C-TRANSPORT)")
}

#[test]
#[ignore = "owner: W1-X1"]
fn transport_source_checks() {
    todo!("owner: W1-X1 (C-TRANSPORT)")
}

#[test]
#[ignore = "owner: W1-K8C"]
fn audit_actions_catalogue() {
    todo!("owner: W1-K8C (C-TRANSPORT)")
}

#[test]
#[ignore = "owner: W1-K9"]
fn upgrade_from_155_shape_carries_acceptance() {
    todo!("owner: W1-K9 (C-TRANSPORT)")
}

#[test]
#[ignore = "owner: W1-C1A"]
fn transport_instance_client_dial() {
    todo!("owner: W1-C1A (C-TRANSPORT)")
}

#[test]
#[ignore = "owner: W1-C1A"]
fn transport_undeclared_acceptance_kept() {
    todo!("owner: W1-C1A (C-TRANSPORT)")
}
