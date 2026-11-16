// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-FAIL-FACTS (ABI-MIN3-INTERFACE §14): FAIL then exactly the stated FACTs, the bytes zeroed, and each adapter's
//! `PortError::Failed` facts (round 21).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

/// The shim arm (W1-A3): a FAILED Fail with both facts answers FAIL then exactly FACT(1, 30), FACT(2, 503).
#[test]
fn the_shim_writes_fail_then_its_facts() {
    use busbar_plugin_abi::fail::{fact, failed};
    use busbar_plugin_abi::records::{tag, FailRec};

    use crate::bridge_fixture::{self as fx, Status};

    let instance = fx::instance();
    let mut lease = fx::lease();
    assert!(matches!(
        fx::start(&instance, b"fail-facts", &mut lease),
        fx::Started::Done(Status::FAILED)
    ));
    assert_eq!(fx::tags(&lease), [tag::FAIL, tag::FACT, tag::FACT]);
    assert_eq!(
        fx::facts(&lease),
        [
            (fact::FACT_RETRY_AFTER_S, 30),
            (fact::FACT_BACKEND_STATUS, 503)
        ]
    );
    let answer = fx::answer(&lease);
    let fail = &answer[0].1;
    let head = core::mem::size_of::<FailRec>();
    assert_eq!(&fail[..4], &Status::FAILED.0.to_le_bytes());
    assert_eq!(&fail[4..8], &failed::F_UPSTREAM.to_le_bytes());
    assert_eq!(&fail[head..], b"the backend said 503");
}

#[test]
#[ignore = "owner: W1-H1"]
fn hand_written_bad_fact_answers_fault() {
    todo!("owner: W1-H1 (C-FAIL-FACTS)")
}

#[test]
#[ignore = "owner: W1-L3"]
fn store_adapter_maps_the_facts() {
    todo!("owner: W1-L3 (C-FAIL-FACTS)")
}

#[test]
#[ignore = "owner: W1-L4"]
fn secret_adapter_maps_the_facts() {
    todo!("owner: W1-L4 (C-FAIL-FACTS)")
}

#[test]
#[ignore = "owner: W1-L5"]
fn auth_adapter_maps_the_facts() {
    todo!("owner: W1-L5 (C-FAIL-FACTS)")
}

#[test]
#[ignore = "owner: W1-L6"]
fn hook_adapter_maps_the_facts() {
    todo!("owner: W1-L6 (C-FAIL-FACTS)")
}

#[test]
#[ignore = "owner: W1-L7"]
fn export_adapter_maps_the_facts() {
    todo!("owner: W1-L7 (C-FAIL-FACTS)")
}

#[test]
#[ignore = "owner: W1-L8"]
fn plane_admin_maps_the_facts() {
    todo!("owner: W1-L8 (C-FAIL-FACTS)")
}

#[test]
#[ignore = "owner: W1-K3"]
fn retry_policy_honours_retry_after() {
    todo!("owner: W1-K3 (C-FAIL-FACTS)")
}
