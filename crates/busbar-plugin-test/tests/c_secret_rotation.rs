// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! DES-454 r3.1 custody arms (core #454): the cell-gated leader (§3.1, T20) and the successor's seed overlay
//! (§4.2, T30). Both drive custody's miss-path probe, so they run with the conformance feature beside C-SCRUB-HIT.

use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use busbar_contract::secret_ref::{SecretRef, SourceReference};
use busbar_contract::secure::SecureVec;
use busbar_kernel::custody::{source_id, CustodyKey, Probe, RoundValues, SecretCustody};
use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_plugin_abi::host_side::scrub::Scrub;
use tokio::sync::Notify;

use crate::c_scrub_hit::fixture::{caller, source, template, Fixture, Vault};

const A: &str = "alpha-7Q2x-rotate";
const B: &str = "bravo-9K4m-rotate";
const C: &str = "charlie-3T8p-rotate";
const SEEDED: &str = "seeded-4Kq9z-fill";

fn masked(scrub: &Scrub, value: &str) -> bool {
    !scrub
        .text(&format!("token {value} rejected"))
        .contains(value)
}

/// Parks the first leading miss after it arms, until released.
struct Park {
    armed: Arc<AtomicBool>,
    parked: Arc<Notify>,
    release: Arc<Notify>,
}

impl Park {
    fn install(fx: &Fixture, publish_first: bool) -> Self {
        let park = Park {
            armed: Arc::new(AtomicBool::new(true)),
            parked: Arc::new(Notify::new()),
            release: Arc::new(Notify::new()),
        };
        let (armed, parked, release) = (
            Arc::clone(&park.armed),
            Arc::clone(&park.parked),
            Arc::clone(&park.release),
        );
        fx.custody.set_probe(Some(Probe {
            park: Arc::new(move |_: CustodyKey| -> BoxFut<'static, ()> {
                if !armed.swap(false, Ordering::SeqCst) {
                    return Box::pin(async {});
                }
                let (parked, release) = (Arc::clone(&parked), Arc::clone(&release));
                Box::pin(async move {
                    parked.notify_one();
                    release.notified().await;
                })
            }),
            publish_first,
        }));
        park
    }
}

fn id_of(reference: &SecretRef) -> [u8; 32] {
    source_id(reference.source().expect("a source reference")).expect("encodes")
}

/// The fill sources of a template, in the order custody fetches them.
fn fills(reference: &SecretRef) -> Vec<SourceReference> {
    let wanted = RefCell::new(Vec::new());
    let asked = |fill: &SecretRef| -> Result<busbar_contract::Secret<String>, ()> {
        if let Some(source) = fill.source() {
            wanted.borrow_mut().push(source.clone());
        }
        Ok(busbar_contract::Secret::new(String::new()))
    };
    reference
        .resolve_template_typed(&asked)
        .expect("a template");
    wanted.into_inner()
}

fn round(id: [u8; 32], value: &str, lease: Option<Duration>) -> RoundValues {
    let mut values = RoundValues::default();
    values.insert(
        id,
        Arc::new(SecureVec::from(value.as_bytes())),
        lease.map(|lease| Instant::now() + lease),
    );
    values
}

/// T20 (DES-454 §3.1, PM D4): a first-miss leader parked across a seed is superseded. It neither registers nor
/// publishes, so the seeded B stays the published value and stays masked after a later C registration (a stale
/// A registered after B would have shifted B out at C).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stale_leader_parked_across_a_seed_neither_registers_nor_publishes() {
    let fx = Fixture::new();
    let vault = Vault::new(&[("db", A)], Some(60));
    fx.source("vault", 900, Arc::clone(&vault));
    let scrub = fx.instance(1);
    let reference = source("vault", "db");
    fx.bind(1, 1, reference.clone());
    let park = Park::install(&fx, false);

    let custody = Arc::clone(&fx.custody);
    let stale = tokio::spawn(async move { custody.resolve(&caller(1), 1).await });
    park.parked.notified().await;

    vault.set("db", B);
    fx.custody.seed(
        1,
        round(id_of(&reference), B, Some(Duration::from_secs(60))),
    );
    let custody = Arc::clone(&fx.custody);
    let fresh = tokio::spawn(async move { custody.resolve(&caller(1), 1).await });
    let fresh = tokio::time::timeout(Duration::from_secs(5), fresh)
        .await
        .expect("the seeded miss leads its own cell while the stale leader is parked")
        .expect("joins")
        .expect("resolves");
    assert_eq!(fresh.as_slice(), B.as_bytes());

    park.release.notify_one();
    let stale = stale.await.expect("joins").expect("resolves");
    assert_eq!(
        stale.as_slice(),
        A.as_bytes(),
        "the stale leader answers its own waiters only"
    );
    let published = fx.custody.resolve(&caller(1), 1).await.expect("hit");
    assert_eq!(
        published.as_slice(),
        B.as_bytes(),
        "the stale leader did not publish"
    );
    assert_eq!(fx.custody.generation(&caller(1), 1), 1);
    assert_eq!(fx.resolved(1), 1, "the stale leader did not register");
    assert!(masked(&scrub, B));

    fx.custody.unseed(1);
    vault.set("db", C);
    fx.advance(61);
    let renewed = fx.custody.resolve(&caller(1), 1).await.expect("C");
    assert_eq!(renewed.as_slice(), C.as_bytes());
    assert!(
        masked(&scrub, B) && masked(&scrub, C),
        "B is the previous generation after C"
    );
}

/// T30 (DES-454 §4.2, A N2 / B N3): a successor's first Need for a seeded handle takes the seeded value and
/// fill with no fetch, and registers them in the successor's scrub set before it publishes. The publish-first
/// control shows the probe can see the wrong order.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_seeded_first_need_registers_value_and_fills_before_it_publishes() {
    for publish_first in [false, true] {
        let fx = Fixture::new();
        let env = Vault::new(&[("TOKEN", "live-env-8Hn2p-fill")], None);
        fx.source("env", 60, Arc::clone(&env));
        let scrub = fx.instance(2);
        let reference = template("Bearer ${TOKEN}");
        fx.bind(2, 1, reference.clone());
        let fill = fills(&reference).pop().expect("one fill");
        let fill_id = source_id(&fill).expect("encodes");
        fx.custody.seed(2, round(fill_id, SEEDED, None));
        let park = Park::install(&fx, publish_first);

        let custody = Arc::clone(&fx.custody);
        let first = tokio::spawn(async move { custody.resolve(&caller(2), 1).await });
        park.parked.notified().await;
        let rendered = format!("Bearer {SEEDED}");
        if publish_first {
            assert_eq!(fx.custody.generation(&caller(2), 1), 1);
            assert!(
                !masked(&scrub, SEEDED),
                "publish-first must leak the seeded fill for this case to see the wrong order"
            );
        } else {
            assert_eq!(
                fx.custody.generation(&caller(2), 1),
                0,
                "nothing is published before register"
            );
        }
        park.release.notify_one();
        let value = first.await.expect("joins").expect("resolves");
        assert_eq!(value.as_slice(), rendered.as_bytes());
        assert_eq!(env.calls(), 0, "the seeded fill is not fetched");
        assert!(masked(&scrub, SEEDED) && masked(&scrub, &rendered));
        assert_eq!(fx.resolved(2), 1);
        fx.custody.unseed(2);
    }
}
