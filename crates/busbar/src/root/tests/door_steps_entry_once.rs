// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SINGLE-PATH SP-V1: verify resolves a unit's named plane entry once; approve judges the grant
//! over verify's answer instead of re-scanning the section's entries for the same name. Counted
//! by the dev-only stage probe (`Derive::EntryResolve`) on the actual door steps.

use super::{downgrade_book, pools, DOWNGRADE_SECTION};
use busbar_contract::caps::{Dial, PrincipalId};
use busbar_contract::ids::OpClassId;
use busbar_contract::plane::codes::ROUTE_DIRECT;
use busbar_contract::stage_probe::{Derive, Scope};
use busbar_kernel::plane_driver::DriverSteps as _;
use busbar_kernel::test_hooks::tokens::grant;
use std::sync::Arc;

#[tokio::test(flavor = "current_thread")]
async fn entry_resolved_once() {
    let (app, key) = downgrade_book(Vec::new(), None).await;
    let pools = pools(DOWNGRADE_SECTION);
    let facts = super::super::door_facts(
        busbar_kernel::plane_driver::dispatch::LaneQualifier::parse("p").unwrap(),
        &["model"],
        &[],
        &[],
        "door",
        Vec::new(),
    );
    let principal = PrincipalId::new(key.id.as_str());
    let steps = super::super::DoorSteps::new(
        &facts,
        &pools,
        Arc::new(|_: &str| None),
        Arc::clone(&app),
        None,
        super::super::DoorCaller {
            principal: principal.clone(),
            key: Some(Arc::clone(&key)),
            open: false,
            arrived: 0,
            records: None,
            depth: 0,
            credential: None,
            ticket: None,
        },
    );
    let ctx = busbar_kernel::teller::UnitCtx {
        call: busbar_contract::caps::CallId::UNBOUND,
        key: busbar_contract::UnitKey::new(1),
        origin: busbar_contract::caps::OriginKind::Client,
        session: None,
        generation: busbar_kernel::registry::Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    };

    let scope = Scope::open();
    steps.decoded(&ctx, OpClassId::new("op"), ROUTE_DIRECT, Some(b"big"));
    let destinations = steps
        .verify(&grant::<Dial>(), &ctx, &principal)
        .expect("the named entry verifies");
    assert!(
        steps.approve(&ctx, &principal, &destinations).is_ok(),
        "the key is granted the entry it names"
    );

    assert_eq!(
        steps.routed(),
        Some((String::new(), vec!["big".to_owned()])),
        "the direct route walks its one entry"
    );
    assert_eq!(
        scope.count(Derive::EntryResolve),
        1,
        "verify resolves the named entry once; approve reads verify's answer and does not \
         re-scan the section's entries"
    );
}
