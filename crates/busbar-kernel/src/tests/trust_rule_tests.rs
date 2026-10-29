// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OPERATOR'S DECISION NEVER PINS WHAT WAS NOT VERIFIED. A plane that fetched a counterparty's
//! document and could not verify it sights it under the placeholder `"unverified"` (no fingerprint
//! is ever that word), so a pinned counterparty drifts and an unpinned one stays new. An approval
//! approves what was SEEN and verified: the generic `POST /api/v1/admin/trust/approve` (no expected
//! fingerprint) and a plane's typed verb (`trust.decide`, with or without one) are the same
//! decision, and both refuse to pin the placeholder (the website's a2a.md:265, "the same decision").

use std::sync::Arc;

use busbar_contract::abi::host::service as svc;
use busbar_contract::services::{Caller, HostServices, Later, Ran, Stored, TrustKeyRef};

use super::{InstanceFacts, KernelServices};
use crate::trust::book::{Distrust, Ruling, TrustFacts};
use crate::trust::reverify::Policy;
use crate::trust::section::TrustEntry;

/// The word a plane sights a document under when it could not verify it.
const UNVERIFIED: &str = "unverified";

fn caller() -> Caller {
    Caller {
        instance: Arc::from("inst"),
        plugin: Arc::from("the-plane"),
        kind: busbar_contract::abi::mechanism::KindCode::Plane,
    }
}

/// A kernel with instance `inst` declaring counterparty `cp` with no pin of its own.
fn kernel() -> KernelServices {
    let k = KernelServices::new();
    k.admit(
        "inst",
        InstanceFacts {
            trust: vec![(
                "cp".to_string(),
                TrustEntry {
                    pin: None,
                    policy: Policy {
                        ttl_ms: 0,
                        recovery_backoff_ms: 0,
                    },
                    approved: Default::default(),
                },
            )],
            ..InstanceFacts::default()
        },
    )
    .expect("admitted");
    k
}

fn sight(k: &KernelServices, hash: &str) -> Stored {
    let later: Later = Box::new(|_| {});
    match k.trust_sight(&caller(), "cp", hash, later) {
        Ran::Now(s) => s,
        Ran::Later => panic!("no durable record: the sighting answers now"),
    }
}

fn served(k: &KernelServices) -> Result<(), Distrust> {
    k.trust_judge(
        "inst",
        &TrustFacts {
            counterparty: "cp",
            item: None,
            digest: None,
        },
    )
}

fn pinned(k: &KernelServices) -> Option<String> {
    k.trust_rows()
        .into_iter()
        .find(|r| r.key() == "inst/cp")
        .and_then(|r| r.approved)
}

#[test]
fn generic_approve_never_pins_an_unverified_sighting() {
    let k = kernel();
    assert_eq!(sight(&k, UNVERIFIED).value, svc::TRUST_NEW);

    // RED: the generic verb states no expected fingerprint and used to pin the placeholder.
    assert!(
        k.trust_rule("inst/cp", Ruling::Approve).is_err(),
        "the generic approve refuses a sighting that failed verification"
    );
    assert_eq!(pinned(&k), None, "nothing is pinned");
    assert!(served(&k).is_err(), "and nothing serves");

    // The typed verb is the same decision, with or without the placeholder stated.
    let key = TrustKeyRef {
        counterparty: "cp",
        item: None,
    };
    for expected in [None, Some(UNVERIFIED)] {
        let decided = k.trust_decide(&caller(), key, expected, true);
        assert_eq!(
            decided.value,
            svc::UNDECIDED_UNPINNED,
            "expected {expected:?}: the typed approve refuses it too"
        );
        assert_eq!(pinned(&k), None);
    }

    // A verified sighting after it is approvable as ever.
    assert_eq!(sight(&k, "fp").value, svc::TRUST_NEW);
    let row = k
        .trust_rule("inst/cp", Ruling::Approve)
        .expect("approvable");
    assert_eq!(row.approved.as_deref(), Some("fp"));
    assert_eq!(served(&k), Ok(()));

    // Once pinned, an unverified sighting drifts it, and approving that is refused as well: the
    // quarantine is not lifted onto a document nobody verified.
    assert_eq!(sight(&k, UNVERIFIED).value, svc::TRUST_DRIFTED);
    assert!(k.trust_rule("inst/cp", Ruling::Approve).is_err());
    assert_eq!(pinned(&k).as_deref(), Some("fp"), "the pin stands");
    assert_eq!(served(&k), Err(Distrust::Quarantined));
}
