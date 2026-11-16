// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! The boot walk over `Registry::boot_plan` (ABI-MIN3-INTERFACE §11.2 `BootPlan`, §12.10 item 4; W2-BOOT):
//! the C-BOOT-ORDER walk arm and the C-DEPLOYMENT-ID (f) re-check arm, over a recording registry double.

use std::sync::Mutex;

use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_plugin_loader::instance::{BootPhase, BootPlan, OpenError};

use super::boot_walk::{deployment_bytes, walk, BootRefused, BootSteps};

const ID: [u8; 16] = *b"deployment-id-16";

#[derive(Clone, Debug, PartialEq, Eq)]
enum Event {
    /// An open, with the deployment id the instance could read while it opened.
    Open(u32, Option<[u8; 16]>),
    /// A DRY_RUN check, with the deployment id the instance could read while it checked.
    Check(u32, Option<[u8; 16]>),
    Deployment(u32),
    Publish([u8; 16]),
}

/// A registry double: every open and check is recorded with what `deployment_id()` would answer at that moment.
#[derive(Default)]
struct Recording {
    events: Mutex<Vec<Event>>,
    published: Mutex<Option<[u8; 16]>>,
    /// The store index and the secret indices its open asks for through SECRET: open fails if one is not open yet.
    store_needs: Option<(u32, Vec<u32>)>,
    refuse_open: Option<u32>,
    refuse_check: Option<u32>,
}

fn refusal(index: u32) -> OpenError {
    OpenError::Config {
        code: 7,
        text: format!("instance {index} refused"),
        error: None,
    }
}

impl Recording {
    fn seen(&self) -> Option<[u8; 16]> {
        *self.published.lock().unwrap()
    }
    fn events(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
    }
    fn opened_before(&self, index: u32) -> bool {
        self.events
            .lock()
            .unwrap()
            .iter()
            .any(|event| matches!(event, Event::Open(opened, _) if *opened == index))
    }
}

impl BootSteps for Recording {
    type Opened = u32;

    fn open(&self, index: u32) -> BoxFut<'_, Result<u32, OpenError>> {
        Box::pin(async move {
            if let Some((store, needs)) = &self.store_needs {
                if *store == index && !needs.iter().all(|secret| self.opened_before(*secret)) {
                    return Err(OpenError::Failed {
                        code: 9,
                        text: "SECRET need found no open secret instance".into(),
                        error: None,
                    });
                }
            }
            self.events
                .lock()
                .unwrap()
                .push(Event::Open(index, self.seen()));
            if self.refuse_open == Some(index) {
                return Err(refusal(index));
            }
            Ok(index)
        })
    }

    fn check(&self, index: u32) -> BoxFut<'_, Result<(), OpenError>> {
        Box::pin(async move {
            self.events
                .lock()
                .unwrap()
                .push(Event::Check(index, self.seen()));
            if self.refuse_check == Some(index) {
                return Err(refusal(index));
            }
            Ok(())
        })
    }

    fn deployment<'a>(&'a self, store: &'a u32) -> BoxFut<'a, Result<[u8; 16], String>> {
        Box::pin(async move {
            self.events.lock().unwrap().push(Event::Deployment(*store));
            Ok(ID)
        })
    }

    fn publish(&self, id: [u8; 16]) {
        self.events.lock().unwrap().push(Event::Publish(id));
        *self.published.lock().unwrap() = Some(id);
    }
}

/// r6 test (g): secret 1 references secret 0, the store (2) references secret 1. The plan the registry computes is
/// 0, 1 (2a, dependencies first), 2 (2b), then the rest kind by kind (3, 4).
fn chained_plan() -> BootPlan {
    BootPlan {
        steps: vec![
            (0, BootPhase::StoreSecrets),
            (1, BootPhase::StoreSecrets),
            (2, BootPhase::Store),
            (3, BootPhase::Rest),
            (4, BootPhase::Rest),
        ],
    }
}

/// C-BOOT-ORDER walk arm: every step opens before the next starts, in plan order, so the store's SECRET Need
/// finds both secret instances open; every 2c instance opens after the store.
#[tokio::test]
async fn secrets_open_before_their_store_and_the_rest_after_it() {
    let steps = Recording {
        store_needs: Some((2, vec![0, 1])),
        ..Recording::default()
    };
    let booted = walk(&chained_plan(), &steps).await.expect("boot");
    let order: Vec<u32> = steps
        .events()
        .iter()
        .filter_map(|event| match event {
            Event::Open(index, _) => Some(*index),
            _ => None,
        })
        .collect();
    assert_eq!(order, [0, 1, 2, 3, 4]);
    let walked: Vec<(u32, BootPhase)> = booted
        .opened
        .iter()
        .map(|(index, phase, _)| (*index, *phase))
        .collect();
    assert_eq!(walked, chained_plan().steps);
    assert_eq!(booted.deployment, ID);
}

/// C-DEPLOYMENT-ID (f): 2a and 2b open and check with no deployment id; after the store opens the id is read
/// through it and published once, then every 2a/2b instance is re-checked in plan order and sees it, all before
/// the first 2c open. Nothing is re-opened.
#[tokio::test]
async fn the_2a_and_2b_recheck_sees_the_id_before_any_2c_open() {
    let steps = Recording::default();
    walk(&chained_plan(), &steps).await.expect("boot");
    assert_eq!(
        steps.events(),
        [
            Event::Open(0, None),
            Event::Open(1, None),
            Event::Open(2, None),
            Event::Deployment(2),
            Event::Publish(ID),
            Event::Check(0, Some(ID)),
            Event::Check(1, Some(ID)),
            Event::Check(2, Some(ID)),
            Event::Open(3, Some(ID)),
            Event::Open(4, Some(ID)),
        ]
    );
}

/// C-DEPLOYMENT-ID (f): a 2b instance whose re-check refuses (a wrong install binding) refuses the boot with its
/// own text, naming the instance, and no 2c instance opens.
#[tokio::test]
async fn a_refused_recheck_refuses_the_boot_before_any_2c_open() {
    let steps = Recording {
        refuse_check: Some(2),
        ..Recording::default()
    };
    let refused = walk(&chained_plan(), &steps).await.err().expect("refused");
    assert!(
        matches!(refused, BootRefused::Recheck { index: 2, .. }),
        "{refused:?}"
    );
    assert!(
        refused.to_string().contains("instance 2 refused"),
        "{refused}"
    );
    assert!(!steps.opened_before(3) && !steps.opened_before(4));
}

/// A refused 2a open refuses the boot there: the store never opens and no deployment id is read or published.
#[tokio::test]
async fn a_refused_open_stops_the_walk_at_that_step() {
    let steps = Recording {
        refuse_open: Some(1),
        ..Recording::default()
    };
    let refused = walk(&chained_plan(), &steps).await.err().expect("refused");
    assert!(
        matches!(
            refused,
            BootRefused::Open {
                index: 1,
                phase: BootPhase::StoreSecrets,
                ..
            }
        ),
        "{refused:?}"
    );
    assert_eq!(steps.events(), [Event::Open(0, None), Event::Open(1, None)]);
}

/// A boot with nothing after the store still reaches the deployment point: the id is published and 2a/2b are
/// re-checked, so `deployment_id()` is set before the node serves.
#[tokio::test]
async fn a_plan_without_2c_still_publishes_and_rechecks() {
    let steps = Recording::default();
    let plan = BootPlan {
        steps: vec![(0, BootPhase::StoreSecrets), (1, BootPhase::Store)],
    };
    walk(&plan, &steps).await.expect("boot");
    assert_eq!(
        steps.events(),
        [
            Event::Open(0, None),
            Event::Open(1, None),
            Event::Deployment(1),
            Event::Publish(ID),
            Event::Check(0, Some(ID)),
            Event::Check(1, Some(ID)),
        ]
    );
}

/// The deployment point sits between the last 2b and the first 2c step; a plan whose phases are not in that
/// order (or with no store, or two) cannot place it and is refused before anything opens.
#[tokio::test]
async fn a_plan_out_of_phase_order_opens_nothing() {
    for steps in [
        vec![(0, BootPhase::Store), (1, BootPhase::StoreSecrets)],
        vec![(0, BootPhase::Rest), (1, BootPhase::Store)],
        vec![(0, BootPhase::StoreSecrets), (1, BootPhase::Rest)],
        vec![(0, BootPhase::Store), (1, BootPhase::Store)],
        vec![(0, BootPhase::Store), (0, BootPhase::Rest)],
    ] {
        let recording = Recording::default();
        let refused = walk(&BootPlan { steps }, &recording)
            .await
            .err()
            .expect("refused");
        assert!(matches!(refused, BootRefused::Plan(_)), "{refused:?}");
        assert!(recording.events().is_empty());
    }
}

/// The kernel's boot identity keeps the id as `dep_` + 32 hex (boot_identity.rs); the host reads the 16 bytes.
#[test]
fn deployment_bytes_reads_the_kept_identity() {
    let text = format!("dep_{}", hex::encode(ID));
    assert_eq!(deployment_bytes(&text), Ok(ID));
    assert!(deployment_bytes(&hex::encode(ID)).is_err());
    assert!(deployment_bytes("dep_00").is_err());
    assert!(deployment_bytes(&format!("dep_{}", "0".repeat(32))).is_err());
}
