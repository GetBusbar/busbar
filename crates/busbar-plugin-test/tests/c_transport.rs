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

/// TRANSPORT-SECURITY-POLICY §8 test 7, the config arms (W1-K7): a missing, empty or placeholder `reason`, a
/// `reason` over 256 characters or with a newline, an `accept` that is not `plaintext`/`unverified_tls` (or an
/// empty or repeated list) and an unknown key each refuse the load with BUSBAR-3163 naming the key; a valid
/// acceptance becomes the instance's `InstanceLimits.accept`. The unused-acceptance arm needs the instance's
/// declared ENDPOINTs, so it is judged at `check` (W1-L2's refusal), not at parse.
#[test]
fn transport_setting_validation() {
    use busbar_kernel::config::min3::parse_min3;
    use busbar_kernel::config::{deploy_from_yaml_str, resolve, Grammar};
    use busbar_plugin_abi::host_side::caller::Accept;
    let deploy = |block: &str| {
        let yaml = format!(
            "providers: {{}}\nmodels: {{}}\nstore:\n  module: postgres\n  insecure_transport: {block}\n"
        );
        deploy_from_yaml_str(&yaml, &Grammar::empty())
            .unwrap_or_else(|e| panic!("{block}: `insecure_transport` is config grammar: {e}"))
    };
    let long = format!("{{ accept: plaintext, reason: \"{}\" }}", "x".repeat(257));
    for (block, key) in [
        ("{ accept: plaintext }", "reason"),
        ("{ accept: plaintext, reason: \"\" }", "reason"),
        (
            "{ accept: plaintext, reason: \"<why this is acceptable>\" }",
            "reason",
        ),
        (long.as_str(), "reason"),
        ("{ accept: plaintext, reason: \"two\\nlines\" }", "reason"),
        ("{ accept: yes, reason: \"legacy db\" }", "accept"),
        ("{ accept: [], reason: \"legacy db\" }", "accept"),
        (
            "{ accept: [plaintext, plaintext], reason: \"legacy db\" }",
            "accept",
        ),
        (
            "{ accept: plaintext, reason: \"legacy db\", until: 2027 }",
            "until",
        ),
    ] {
        let refused = parse_min3(&deploy(block)).err().expect(block);
        let want = format!("BUSBAR-3163: store.insecure_transport.{key}");
        assert!(
            refused.iter().any(|r| r.starts_with(&want)),
            "{block}: {refused:?}"
        );
    }

    let ok = deploy("{ accept: [plaintext, unverified_tls], reason: \"pg sidecar, INFRA-142\" }");
    let cfg = resolve(&ok, &Default::default()).expect("a valid acceptance loads");
    assert_eq!(
        busbar_kernel::appbuild::instance_limits(&cfg, "store", "store").accept,
        Accept(Accept::PLAINTEXT | Accept::UNVERIFIED_TLS)
    );
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
