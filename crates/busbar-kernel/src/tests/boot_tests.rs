// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE BOOT HYDRATION attaches the kernel's durable trust record to the configured store (THE
//! DESIGN §11.12: "the demotion record is durable"), whatever planes are linked: no plane hook
//! has to remember it.

use std::sync::Arc;

use crate::test_support::durable_store::{durable_cfg, open_durable};
use crate::test_support::record_calls::RecordCalls;
use crate::test_support::TestApp;
use crate::trust::book::RulingRow;
use crate::trust::DemotionRecord;

#[test]
fn boot_hydration_makes_the_trust_record_durable_on_the_configured_store() {
    let (_file, cfg) = durable_cfg("boot-trust-sink");
    let store = open_durable(&cfg);
    let gov = Arc::new(
        crate::governance::GovState::new(store.clone(), None).expect("a governance store"),
    );
    gov.attach_store_calls(RecordCalls::over(store));
    let app = TestApp::new().governance(gov).build();
    crate::boot::hydrate_all(&app).expect("boot hydrates");

    let decision = RulingRow {
        instance: "inst".to_string(),
        counterparty: "upstream".to_string(),
        item: None,
        approved: Some("sha256:pinned".to_string()),
        declared: None,
    };
    app.demotion_record
        .keep_decision(&decision, 1)
        .expect("the store keeps the decision");
    app.demotion_record
        .record("inst\u{1f}upstream", "quarantined", 1);

    // A RESTART: a fresh record over the same store reads back what the booted process kept.
    let restarted = DemotionRecord::default();
    restarted.set_sink(crate::store::plane_view::PlaneStoreView::narrow(
        RecordCalls::over(open_durable(&cfg)),
    ));
    assert_eq!(
        restarted.decisions().expect("the store reads"),
        vec![decision],
        "an operator's trust decision outlives the process"
    );
    let demoted = restarted.read().expect("the store reads");
    assert_eq!(demoted.len(), 1, "a demotion outlives the process");
    assert_eq!(demoted[0].upstream, "inst\u{1f}upstream");
}
