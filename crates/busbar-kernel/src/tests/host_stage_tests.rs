// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

trait ReadyAdmission {
    fn admit_ready(
        &self,
        instance: &str,
        facts: crate::host_services::InstanceFacts,
    ) -> Result<(), crate::host_services::AdmitRefused>;
}
impl ReadyAdmission for crate::host_services::KernelServices {
    fn admit_ready(
        &self,
        instance: &str,
        facts: crate::host_services::InstanceFacts,
    ) -> Result<(), crate::host_services::AdmitRefused> {
        futures::FutureExt::now_or_never(self.admit(instance, facts))
            .expect("in-memory fixture admission finishes in one poll")
    }
}
use std::sync::atomic::{AtomicU64, Ordering};

use super::tests::{caller, verdict_now as now};
use super::*;

fn services(clock: &Arc<AtomicU64>) -> KernelServices {
    let c = Arc::clone(clock);
    let s = KernelServices::new().with_wall_clock(Arc::new(move || c.load(Ordering::SeqCst)));
    s.admit_ready("inst", InstanceFacts::default()).unwrap();
    s.admit_ready("other", InstanceFacts::default()).unwrap();
    s
}

fn answered() -> (Later, tokio::sync::oneshot::Receiver<Stored>) {
    let (tx, rx) = tokio::sync::oneshot::channel();
    (
        Box::new(move |s| {
            let _sent = tx.send(s);
        }),
        rx,
    )
}

#[tokio::test]
async fn verify_is_the_callers_own_cache_hit_lead_or_follow() {
    let clock = Arc::new(AtomicU64::new(1_000));
    let s = services(&clock);
    let me = caller("inst");
    assert_eq!(
        now(s.verify_lookup(&me, b"card", answered().0)).value,
        svc::VERIFY_LEAD
    );
    let (later, follower) = answered();
    assert!(matches!(s.verify_lookup(&me, b"card", later), Ran::Later));
    assert_eq!(
        s.verify_store(&me, b"card", b"ok", 0).outcome,
        Outcome::Ready
    );
    let followed = follower.await.unwrap();
    assert_eq!(
        (followed.value, followed.bytes.as_slice()),
        (svc::VERIFY_FOLLOW, &b"ok"[..])
    );
    let hit = now(s.verify_lookup(&me, b"card", answered().0));
    assert_eq!(
        (hit.value, hit.bytes.as_slice()),
        (svc::VERIFY_HIT, &b"ok"[..])
    );

    assert_eq!(
        now(s.verify_lookup(&caller("other"), b"card", answered().0)).value,
        svc::VERIFY_LEAD
    );
}

#[test]
fn verify_from_an_instance_never_admitted_is_refused() {
    let s = services(&Arc::new(AtomicU64::new(0)));
    let stranger = caller("stranger");
    let r = now(s.verify_lookup(&stranger, b"k", Box::new(|_| {})));
    assert_eq!((r.outcome, r.error), (Outcome::Refused, NOT_ADMITTED));
    let r = s.verify_store(&stranger, b"k", b"v", 0);
    assert_eq!((r.outcome, r.error), (Outcome::Refused, NOT_ADMITTED));
}

#[tokio::test]
async fn the_verify_tick_hands_a_lapsed_lead_to_a_follower() {
    let clock = Arc::new(AtomicU64::new(0));
    let s = services(&clock);
    let me = caller("inst");
    let _ = now(s.verify_lookup(&me, b"k", answered().0));
    let (later, follower) = answered();
    assert!(matches!(s.verify_lookup(&me, b"k", later), Ran::Later));
    clock.store(crate::host_verify::LEAD_MS, Ordering::SeqCst);
    s.verify_tick();
    assert_eq!(follower.await.unwrap().value, svc::VERIFY_LEAD);
}
