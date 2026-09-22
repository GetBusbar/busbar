// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FIXTURE'S OWN LEDGER PROOF — the fixture host is what a plane's money-path tests read their
//! verdict off, so its `requests` counter must MOVE when the Admit door is driven. Before these
//! tests the counter was write-never: every `ledger_usage(key).requests` read back 0 whether the
//! plane charged once, twice, or not at all, so a double-charging plane passed its own billing test.
//! Two admissions must read back two fees; an ungoverned host, and a request presenting no key, must
//! read back nothing at all.

use super::{FixtureHost, LedgerUsage};
use crate::plane_host::AdmissionHost;
use busbar_api::{PlaneRequestCtx, VirtualKey};
use std::sync::Arc;

const PROTO: &str = "test-proto";

fn ctx(key_id: &str) -> PlaneRequestCtx {
    PlaneRequestCtx {
        key: Some(Arc::new(VirtualKey {
            id: key_id.to_string(),
            name: key_id.to_string(),
            ..Default::default()
        })),
    }
}

fn requests_for(host: &FixtureHost, key_id: &str) -> u64 {
    host.ledger_usage(key_id).map_or(0, |u| u.requests)
}

#[test]
fn two_admissions_charge_two_request_fees() {
    let host = FixtureHost::new().governed();
    let gov = ctx("vk-payer");
    let started = std::time::Instant::now();

    assert_eq!(
        requests_for(&host, "vk-payer"),
        0,
        "a key that has not been admitted owes nothing"
    );

    host.admission_door(&gov, PROTO, "pool", started, 0)
        .expect("the fixture door admits");
    assert_eq!(
        requests_for(&host, "vk-payer"),
        1,
        "one admission is one billable request"
    );

    host.admission_check(&gov, PROTO, "pool", 0)
        .expect("the fixture check admits");
    assert_eq!(
        requests_for(&host, "vk-payer"),
        2,
        "a second admission is a SECOND billable request — a plane that runs the door twice for one \
         request reads back two fees here"
    );

    // The fee is the only thing Admit moves: the token ledger is the Meter step's to write.
    assert_eq!(
        host.ledger_usage("vk-payer"),
        Some(LedgerUsage {
            tokens: 0,
            requests: 2
        }),
        "the Admit step charges the per-request fee and no tokens"
    );
}

#[test]
fn the_fee_lands_on_the_presenting_key_only() {
    let host = FixtureHost::new().governed();
    let started = std::time::Instant::now();

    host.admission_door(&ctx("vk-a"), PROTO, "pool", started, 0)
        .expect("the fixture door admits");
    host.admission_door(&ctx("vk-b"), PROTO, "pool", started, 0)
        .expect("the fixture door admits");
    host.admission_door(&ctx("vk-b"), PROTO, "pool", started, 0)
        .expect("the fixture door admits");

    assert_eq!(requests_for(&host, "vk-a"), 1, "vk-a presented once");
    assert_eq!(requests_for(&host, "vk-b"), 2, "vk-b presented twice");
}

#[test]
fn an_ungoverned_host_and_a_keyless_request_are_charged_nothing() {
    // Governance off: there is no ledger to bill, exactly as an ungoverned deployment.
    let ungoverned = FixtureHost::new();
    ungoverned
        .admission_door(
            &ctx("vk-payer"),
            PROTO,
            "pool",
            std::time::Instant::now(),
            0,
        )
        .expect("the fixture door admits");
    assert_eq!(
        ungoverned.ledger_usage("vk-payer"),
        None,
        "an ungoverned host materialises no ledger row"
    );

    // Governed, but the request carries no resolved key: nobody to charge.
    let governed = FixtureHost::new().governed();
    governed
        .admission_check(&PlaneRequestCtx::default(), PROTO, "pool", 0)
        .expect("the fixture check admits");
    assert!(
        governed.ledger_usage("vk-payer").is_none(),
        "a keyless request charges no key"
    );
}
